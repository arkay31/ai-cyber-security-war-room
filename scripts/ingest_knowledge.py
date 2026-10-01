#!/usr/bin/env python3
"""
Knowledge Base Ingestion Script for AI Cyber Security War Room.

Loads MITRE ATT&CK techniques, SOC remediation playbooks, and investigation guides,
chunks content where appropriate, generates 384-d dense vector embeddings via EmbeddingService,
and stores them into PostgreSQL using pgvector.
Avoids duplicate ingestion by tracking (document_id, chunk_index).
"""

import sys
import os
import json
import logging
from typing import List, Dict, Any

# Ensure project root is in sys.path
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.app.database import SessionLocal, engine, Base
from backend.app.models.knowledge import KnowledgeEmbedding
from backend.app.services.embedding_service import embedding_service
from sqlalchemy import text

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

    # Split by sentences or spaces
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
            # Overlap: keep last few words
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
        if filename.endswith(".json"):
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


def ingest_knowledge():
    """Main ingestion workflow."""
    logger.info("Initializing database and ensuring pgvector extension...")
    with engine.connect() as conn:
        conn.execute(text("CREATE EXTENSION IF NOT EXISTS vector;"))
        conn.commit()

    Base.metadata.create_all(bind=engine)

    base_dir = os.path.abspath(os.path.join(os.path.dirname(__file__), ".."))
    knowledge_dir = os.path.join(base_dir, "data", "knowledge")

    docs = load_knowledge_files(knowledge_dir)
    if not docs:
        logger.error("No knowledge documents found to ingest!")
        return

    logger.info(f"Processing {len(docs)} knowledge documents...")

    db = SessionLocal()
    inserted_count = 0
    skipped_count = 0

    try:
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
                # Check for existing entry to prevent duplicates
                existing = db.query(KnowledgeEmbedding).filter(
                    KnowledgeEmbedding.document_id == doc_id,
                    KnowledgeEmbedding.chunk_index == idx
                ).first()

                if existing:
                    skipped_count += 1
                    continue

                # Generate embedding
                embedding_vector = embedding_service.generate_embedding(
                    f"{title}. {chunk}"
                )

                metadata = {
                    "document_id": doc_id,
                    "chunk_index": idx,
                    "total_chunks": len(chunks),
                    "source": source,
                    "source_type": source_type,
                    "technique_id": technique_id,
                    "title": title
                }

                record = KnowledgeEmbedding(
                    document_id=doc_id,
                    title=title,
                    source=source,
                    source_type=source_type,
                    technique_id=technique_id,
                    chunk_index=idx,
                    content=chunk,
                    embedding=embedding_vector,
                    metadata_json=metadata
                )
                db.add(record)
                inserted_count += 1

        db.commit()
        total_in_db = db.query(KnowledgeEmbedding).count()
        logger.info("==================================================")
        logger.info("KNOWLEDGE BASE INGESTION COMPLETE")
        logger.info(f"New chunks inserted:  {inserted_count}")
        logger.info(f"Existing skipped:      {skipped_count}")
        logger.info(f"Total chunks in DB:    {total_in_db}")
        logger.info("==================================================")

    except Exception as e:
        db.rollback()
        logger.error(f"Ingestion failed with error: {e}", exc_info=True)
        raise
    finally:
        db.close()


if __name__ == "__main__":
    ingest_knowledge()
