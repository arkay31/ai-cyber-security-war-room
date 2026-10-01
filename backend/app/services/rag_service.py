import logging
from typing import List, Dict, Any, Optional
from sqlalchemy.orm import Session
from sqlalchemy import select, and_

from backend.app.models.knowledge import KnowledgeEmbedding
from backend.app.services.embedding_service import embedding_service

logger = logging.getLogger(__name__)


class RAGService:
    """
    Retrieval-Augmented Generation (RAG) Service backed by PostgreSQL + pgvector.
    Performs dense semantic vector similarity retrieval of MITRE ATT&CK techniques,
    SOC playbooks, and investigation guidance.
    """

    def __init__(self):
        self.embedding_service = embedding_service

    def retrieve_relevant_evidence(
        self,
        query: str,
        db: Session,
        top_k: int = 5,
        source_type: Optional[str] = None,
        technique_id: Optional[str] = None,
        min_similarity: float = 0.20
    ) -> List[Dict[str, Any]]:
        """
        Accept an investigation query, generate embedding, perform pgvector cosine similarity search,
        and return deduplicated top-k evidence documents with similarity scores.
        """
        if not query or not query.strip():
            return []

        # 1. Generate query embedding
        query_vector = self.embedding_service.generate_embedding(query)

        # 2. Build pgvector query using cosine distance (<=>)
        # Cosine distance = 1 - cosine_similarity
        distance_col = KnowledgeEmbedding.embedding.cosine_distance(query_vector).label("distance")

        stmt = db.query(KnowledgeEmbedding, distance_col)

        filters = []
        if source_type:
            filters.append(KnowledgeEmbedding.source_type == source_type)
        if technique_id:
            filters.append(KnowledgeEmbedding.technique_id == technique_id)

        if filters:
            stmt = stmt.filter(and_(*filters))

        # Order by distance ascending (most similar first)
        # Fetch slightly more to account for chunk deduplication
        raw_results = stmt.order_by(distance_col.asc()).limit(top_k * 2).all()

        # 3. Deduplicate and format results
        seen_documents = set()
        evidence_list = []

        for record, distance in raw_results:
            doc_key = record.document_id
            if doc_key in seen_documents:
                continue
            seen_documents.add(doc_key)

            # Cosine similarity calculation
            similarity = max(0.0, 1.0 - float(distance))
            if similarity < min_similarity:
                continue

            evidence_list.append({
                "document_id": record.document_id,
                "title": record.title,
                "source": record.source,
                "source_type": record.source_type,
                "technique_id": record.technique_id,
                "chunk_index": record.chunk_index,
                "similarity_score": round(similarity, 4),
                "content": record.content,
            })

            if len(evidence_list) >= top_k:
                break

        return evidence_list

    def retrieve_for_incident(
        self,
        incident_title: str,
        summary: Optional[str],
        event_types: List[str],
        mitre_ids: List[str],
        db: Session,
        top_k: int = 5
    ) -> List[Dict[str, Any]]:
        """
        Construct a contextual investigation query from incident telemetry,
        and retrieve the most relevant playbooks and MITRE guidance from pgvector.
        """
        query_parts = [incident_title]
        if summary:
            query_parts.append(summary)
        if event_types:
            query_parts.append(f"Observed event types: {', '.join(set(event_types))}")
        if mitre_ids:
            query_parts.append(f"Associated MITRE techniques: {', '.join(mitre_ids)}")

        full_query = ". ".join(query_parts)
        return self.retrieve_relevant_evidence(full_query, db, top_k=top_k)


rag_service = RAGService()
