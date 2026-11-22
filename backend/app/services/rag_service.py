import logging
import re
import time
from typing import List, Dict, Any, Optional

from sqlalchemy.orm import Session

from backend.app.models.knowledge import KnowledgeEmbedding

logger = logging.getLogger(__name__)

STOPWORDS = {
    "the", "a", "an", "and", "or", "to", "of", "in", "on",
    "for", "with", "from", "by", "is", "are", "was", "were",
    "this", "that", "it", "as", "at", "be", "has", "have",
    "had", "when", "what", "how", "into", "their", "they"
}


class RAGService:
    """
    Lightweight lexical retrieval for security knowledge.
    Does not load PyTorch or SentenceTransformer.
    """

    def _tokens(self, text: str) -> set:
        words = re.findall(r"[a-z0-9.]+", (text or "").lower())
        return {
            word for word in words
            if len(word) > 1 and word not in STOPWORDS
        }

    def _score(self, query: str, record: KnowledgeEmbedding) -> float:
        query_tokens = self._tokens(query)

        if not query_tokens:
            return 0.0

        title_tokens = self._tokens(record.title or "")
        content_tokens = self._tokens(record.content or "")
        technique_tokens = self._tokens(record.technique_id or "")

        title_matches = query_tokens & title_tokens
        content_matches = query_tokens & content_tokens
        technique_matches = query_tokens & technique_tokens

        weighted_matches = (
            2.0 * len(title_matches)
            + len(content_matches)
            + 3.0 * len(technique_matches)
        )

        denominator = 2.0 * len(query_tokens)

        score = weighted_matches / denominator

        normalized_query = " ".join(query.lower().split())
        normalized_content = " ".join(
            (record.content or "").lower().split()
        )

        if normalized_query and normalized_query in normalized_content:
            score += 0.15

        return min(score, 1.0)

    def retrieve_relevant_evidence(
        self,
        query: str,
        db: Session,
        top_k: int = 5,
        source_type: Optional[str] = None,
        technique_id: Optional[str] = None,
        min_similarity: float = 0.20
    ) -> List[Dict[str, Any]]:

        if not query or not query.strip():
            return []

        stmt = db.query(KnowledgeEmbedding)

        if source_type:
            stmt = stmt.filter(
                KnowledgeEmbedding.source_type == source_type
            )

        if technique_id:
            stmt = stmt.filter(
                KnowledgeEmbedding.technique_id == technique_id
            )

        records = stmt.all()

        scored_records = []

        for record in records:
            score = self._score(query, record)

            if score >= min_similarity:
                scored_records.append((record, score))

        scored_records.sort(
            key=lambda item: item[1],
            reverse=True
        )

        evidence_list = []
        seen_documents = set()

        for record, score in scored_records:
            if record.document_id in seen_documents:
                continue

            seen_documents.add(record.document_id)

            evidence_list.append({
                "document_id": record.document_id,
                "title": record.title,
                "source": record.source,
                "source_type": record.source_type,
                "technique_id": record.technique_id,
                "chunk_index": record.chunk_index,
                "similarity_score": round(score, 4),
                "is_low_relevance": bool(score < 0.45),
                "content": record.content,
            })

            if len(evidence_list) >= top_k:
                break

        return evidence_list

    def evaluate_rag_retrieval(self, db: Session) -> Dict[str, Any]:
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
        hits_at_1 = hits_at_3 = hits_at_5 = 0
        reciprocal_ranks = []
        query_evaluations = []

        for case in test_cases:
            t0 = time.perf_counter()

            retrieved = self.retrieve_relevant_evidence(
                case["query"], db, top_k=5, min_similarity=0.10
            )

            elapsed_ms = round(
                (time.perf_counter() - t0) * 1000, 2
            )
            latencies.append(elapsed_ms)

            retrieved_techs = [
                doc.get("technique_id")
                for doc in retrieved
                if doc.get("technique_id")
            ]

            expected = set(case["expected_techniques"])

            hit_1 = bool(
                retrieved_techs and retrieved_techs[0] in expected
            )
            hit_3 = any(t in expected for t in retrieved_techs[:3])
            hit_5 = any(t in expected for t in retrieved_techs[:5])

            hits_at_1 += int(hit_1)
            hits_at_3 += int(hit_3)
            hits_at_5 += int(hit_5)

            rr = 0.0
            for rank_idx, technique in enumerate(retrieved_techs, 1):
                if technique in expected:
                    rr = 1.0 / rank_idx
                    break

            reciprocal_ranks.append(rr)

            query_evaluations.append({
                "query": case["query"],
                "expected_techniques": list(expected),
                "retrieved_top_technique": (
                    retrieved_techs[0] if retrieved_techs else None
                ),
                "top_similarity": (
                    retrieved[0]["similarity_score"] if retrieved else 0.0
                ),
                "latency_ms": elapsed_ms,
                "hit_at_1": hit_1,
                "hit_at_3": hit_3
            })

        total = len(test_cases)

        return {
            "model_name": "keyword-retrieval",
            "embedding_dimension": None,
            "retrieval_method": "lexical_keyword_matching",
            "total_benchmark_queries": total,
            "metrics": {
                "precision_at_1": round(hits_at_1 / total, 4),
                "precision_at_3": round(hits_at_3 / total, 4),
                "precision_at_5": round(hits_at_5 / total, 4),
                "mean_reciprocal_rank": round(
                    sum(reciprocal_ranks) / total, 4
                ),
                "avg_latency_ms": round(sum(latencies) / total, 2),
                "min_latency_ms": min(latencies),
                "max_latency_ms": max(latencies),
            },
            "queries": query_evaluations,
            "storage_engine": "PostgreSQL + SQLAlchemy",
            "evaluation_notice": (
                "Lexical keyword retrieval; scores are lexical relevance "
                "scores, not cosine similarity."
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

        query_parts = [incident_title]

        if summary:
            query_parts.append(summary)

        if event_types:
            query_parts.append(
                f"Observed event types: {', '.join(set(event_types))}"
            )

        if mitre_ids:
            query_parts.append(
                f"Associated MITRE techniques: {', '.join(mitre_ids)}"
            )

        return self.retrieve_relevant_evidence(
            ". ".join(query_parts),
            db,
            top_k=top_k
        )


rag_service = RAGService()
