#!/usr/bin/env python3
"""
Knowledge Base Ingestion Script for AI Cyber Security War Room.

Loads MITRE ATT&CK techniques, SOC remediation playbooks, and investigation guides,
chunks content where appropriate, utilizes precomputed 384-d vector embeddings when available
(or lazy-loads EmbeddingService if needed), and stores them into PostgreSQL using pgvector.
Ensures strictly idempotent ingestion by validating database state and (document_id, chunk_index).
"""

import sys
import os
import json
import logging
from typing import List, Dict, Any, Optional

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.database import SessionLocal, engine, Base
from backend.app.models.knowledge import KnowledgeEmbedding
from sqlalchemy import text
from sqlalchemy.orm import Session

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s")
logger = logging.getLogger("ingest_knowledge")


def chunk_text(text_content: str, max_chunk_size: int = 500, overlap: int = 80) -> List[str]:
    """
    Split text into logical chunks. For short descriptions, returns a single chunk.
    For longer documents, splits on sentences or word boundaries with overlap.
    """
    cleaned = " ".join(text_content.strip().split())
    if len(cleaned) <= max_chunk_size:
        return [cleaned]

    words = cleaned.split(" ")
    chunks = []
    current_words = []
    current_len = 0

    for word in words:
        current_words.append(word)
        current_len += len(word) + 1
        if current_len >= max_chunk_size:
            chunk_str = " ".join(current_words)
            chunks.append(chunk_str)
            overlap_words = []
            overlap_len = 0
            for w in reversed(current_words):
                if overlap_len + len(w) + 1 <= overlap:
                    overlap_words.insert(0, w)
                    overlap_len += len(w) + 1
                else:
                    break
            current_words = overlap_words
            current_len = overlap_len

    if current_words:
        chunks.append(" ".join(current_words))

    return chunks


def load_knowledge_files(data_dir: str) -> List[Dict[str, Any]]:
    """Load all json knowledge files from data directory."""
    documents = []
    if not os.path.exists(data_dir):
        logger.warning(f"Knowledge directory '{data_dir}' not found.")
        return documents

    for filename in sorted(os.listdir(data_dir)):
        if filename.endswith(".json") and not filename.startswith("precomputed"):
            file_path = os.path.join(data_dir, filename)
            try:
                with open(file_path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                    if isinstance(data, list):
                        documents.extend(data)
                        logger.info(f"Loaded {len(data)} documents from {filename}")
                    elif isinstance(data, dict):
                        documents.append(data)
                        logger.info(f"Loaded 1 document from {filename}")
            except Exception as e:
                logger.error(f"Failed to load {filename}: {e}")

    return documents


def ingest_knowledge(db: Optional[Session] = None) -> Dict[str, Any]:
    """
    Main ingestion workflow.
    Guarantees idempotency and 512MiB RAM compliance via precomputed embedding cache.
    """
    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    knowledge_dir = os.path.join(base_dir, "data", "knowledge")
    cache_path = os.path.join(knowledge_dir, "precomputed_embeddings.json")

    # Load documents to determine chunk set
    docs = load_knowledge_files(knowledge_dir)
    if not docs:
        logger.warning("No knowledge documents found to ingest.")
        return {"status": "empty", "inserted": 0, "skipped": 0}

    # Prepare document chunk list
    chunked_tasks = []
    for doc in docs:
        doc_id = doc.get("document_id")
        title = doc.get("title", "Untitled Knowledge Document")
        source = doc.get("source", "SOC Knowledge Base")
        source_type = doc.get("source_type", "knowledge")
        technique_id = doc.get("technique_id")
        raw_content = doc.get("content", "")

        if not raw_content:
            continue

        chunks = chunk_text(raw_content)
        for idx, chunk in enumerate(chunks):
            chunked_tasks.append({
                "doc_id": doc_id,
                "title": title,
                "source": source,
                "source_type": source_type,
                "technique_id": technique_id,
                "chunk_index": idx,
                "total_chunks": len(chunks),
                "content": chunk,
            })

    total_expected = len(chunked_tasks)

    # Manage session
    own_session = False
    if db is None:
        try:
            with engine.connect() as conn:
                conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector;"))
                conn.commit()
            Base.metadata.create_all(bind=engine)
        except Exception as e:
            logger.debug(f"pgvector / metadata check notice: {e}")
        db = SessionLocal()
        own_session = True

    try:
        # Check current database state for idempotency (Requirement 5)
        existing_count = db.query(KnowledgeEmbedding).count()
        if existing_count >= total_expected and total_expected > 0:
            logger.info(
                f"Knowledge base already contains {existing_count} chunks (expected {total_expected}). Ingestion skipped (idempotent)."
            )
            return {
                "status": "already_ingested",
                "inserted": 0,
                "skipped": existing_count,
                "total": existing_count
            }

        # Load precomputed embeddings cache
        precomputed_cache = {}
        if os.path.exists(cache_path):
            try:
                with open(cache_path, "r", encoding="utf-8") as f:
                    precomputed_cache = json.load(f)
                logger.info(f"Loaded {len(precomputed_cache)} precomputed embeddings from cache.")
            except Exception as e:
                logger.warning(f"Could not read precomputed embeddings cache: {e}")

        inserted_count = 0
        skipped_count = 0

        for item in chunked_tasks:
            doc_id = item["doc_id"]
            idx = item["chunk_index"]

            # Idempotency check per chunk
            existing = db.query(KnowledgeEmbedding.id).filter(
                KnowledgeEmbedding.document_id == doc_id,
                KnowledgeEmbedding.chunk_index == idx
            ).first()

            if existing:
                skipped_count += 1
                continue

            # Retrieve embedding from cache, or fallback to lazy embedding service
            cache_key = f"{doc_id}::{idx}"
            if cache_key in precomputed_cache:
                embedding_vector = precomputed_cache[cache_key]["embedding"]
            else:
                # Lazy import avoids loading heavy ML packages during application startup
                from backend.app.services.embedding_service import embedding_service
                logger.info(f"Generating live embedding for {cache_key}...")
                embedding_vector = embedding_service.generate_embedding(
                    f"{item['title']}. {item['content']}"
                )

            metadata = {
                "document_id": doc_id,
                "chunk_index": idx,
                "total_chunks": item["total_chunks"],
                "source": item["source"],
                "source_type": item["source_type"],
                "technique_id": item["technique_id"],
                "title": item["title"]
            }

            record = KnowledgeEmbedding(
                document_id=doc_id,
                title=item["title"],
                source=item["source"],
                source_type=item["source_type"],
                technique_id=item["technique_id"],
                chunk_index=idx,
                content=item["content"],
                embedding=embedding_vector,
                metadata_json=metadata
            )
            db.add(record)
            inserted_count += 1

            if inserted_count % 10 == 0:
                db.commit()

        db.commit()
        total_in_db = db.query(KnowledgeEmbedding).count()
        logger.info("==================================================")
        logger.info("KNOWLEDGE BASE INGESTION COMPLETE")
        logger.info(f"New chunks inserted:  {inserted_count}")
        logger.info(f"Existing skipped:      {skipped_count}")
        logger.info(f"Total chunks in DB:    {total_in_db}")
        logger.info("==================================================")

        return {
            "status": "success",
            "inserted": inserted_count,
            "skipped": skipped_count,
            "total": total_in_db
        }

    except Exception as e:
        db.rollback()
        logger.error(f"Ingestion failed with error: {e}", exc_info=True)
        raise
    finally:
        if own_session:
            db.close()


if __name__ == "__main__":
    ingest_knowledge()
