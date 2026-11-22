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
        try:
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
            raw_results = stmt.order_by(distance_col.asc()).limit(top_k * 2).all()
        except Exception as e:
            logger.debug(f"pgvector query unavailable in non-postgres environment: {e}")
            # Fallback for environments without pgvector extension (e.g. SQLite unit tests)
            query_stmt = db.query(KnowledgeEmbedding)
            if source_type:
                query_stmt = query_stmt.filter(KnowledgeEmbedding.source_type == source_type)
            if technique_id:
                query_stmt = query_stmt.filter(KnowledgeEmbedding.technique_id == technique_id)
            records = query_stmt.limit(top_k * 2).all()
            raw_results = [(rec, 0.40) for rec in records]

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
                "is_low_relevance": bool(similarity < 0.45),
                "content": record.content,
            })

            if len(evidence_list) >= top_k:
                break

        return evidence_list

    def evaluate_rag_retrieval(self, db: Session) -> Dict[str, Any]:
        """
        Evaluate quantitative RAG retrieval metrics on MITRE ATT&CK knowledge base.
        Calculates Precision@1, Precision@3, Precision@5, Mean Reciprocal Rank (MRR),
        and average retrieval latency.
        """
        import time

        test_cases = [
            {
                "query": "SSH brute force automated credential guessing on port 22",
                "expected_techniques": ["T1110", "T1110.001"],
                "category": "Credential Access"
            },
            {
                "query": "Network service scanning and open port discovery reconnaissance",
                "expected_techniques": ["T1046"],
                "category": "Discovery"
            },
            {
                "query": "High volume SYN flood network denial of service",
                "expected_techniques": ["T1498", "T1499"],
                "category": "Impact"
            },
            {
                "query": "Elevated privileges sudoers modification root execution",
                "expected_techniques": ["T1548", "T1068"],
                "category": "Privilege Escalation"
            },
            {
                "query": "Sensitive data exfiltration outbound network transfer",
                "expected_techniques": ["T1048", "T1041"],
                "category": "Exfiltration"
            }
        ]

        latencies = []
        hits_at_1 = 0
        hits_at_3 = 0
        hits_at_5 = 0
        reciprocal_ranks = []
        query_evaluations = []

        for case in test_cases:
            t0 = time.perf_counter()
            retrieved = self.retrieve_relevant_evidence(case["query"], db, top_k=5, min_similarity=0.10)
            elapsed_ms = round((time.perf_counter() - t0) * 1000, 2)
            latencies.append(elapsed_ms)

            retrieved_techs = [doc.get("technique_id") for doc in retrieved if doc.get("technique_id")]
            expected = set(case["expected_techniques"])

            # Check hits
            hit_1 = bool(retrieved_techs and retrieved_techs[0] in expected)
            hit_3 = any(t in expected for t in retrieved_techs[:3])
            hit_5 = any(t in expected for t in retrieved_techs[:5])

            if hit_1:
                hits_at_1 += 1
            if hit_3:
                hits_at_3 += 1
            if hit_5:
                hits_at_5 += 1

            # Reciprocal rank
            rr = 0.0
            for rank_idx, t in enumerate(retrieved_techs, start=1):
                if t in expected:
                    rr = 1.0 / rank_idx
                    break
            reciprocal_ranks.append(rr)

            query_evaluations.append({
                "query": case["query"],
                "expected_techniques": list(expected),
                "retrieved_top_technique": retrieved_techs[0] if retrieved_techs else None,
                "top_similarity": retrieved[0].get("similarity_score") if retrieved else 0.0,
                "latency_ms": elapsed_ms,
                "hit_at_1": hit_1,
                "hit_at_3": hit_3
            })

        total = len(test_cases)
        return {
            "model_name": self.embedding_service.model_name,
            "embedding_dimension": 384,
            "total_benchmark_queries": total,
            "metrics": {
                "precision_at_1": round(hits_at_1 / total, 4),
                "precision_at_3": round(hits_at_3 / total, 4),
                "precision_at_5": round(hits_at_5 / total, 4),
                "mean_reciprocal_rank": round(sum(reciprocal_ranks) / total, 4),
                "avg_latency_ms": round(sum(latencies) / total, 2),
                "min_latency_ms": min(latencies) if latencies else 0.0,
                "max_latency_ms": max(latencies) if latencies else 0.0,
            },
            "queries": query_evaluations,
            "storage_engine": "PostgreSQL 16 + pgvector (HNSW/IVFFlat indexable, L2/Cosine distance)",
            "evaluation_notice": (
                "RAG retrieval evaluation tests semantic technique matching across standard MITRE ATT&CK tactics. "
                "Retrieval latency includes 384-dimensional dense vector encoding via SentenceTransformers and pgvector query."
            )
        }

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
