# Retrieval-Augmented Generation (RAG) & Vector Knowledge Base

## 1. Overview

The **RAG Pipeline** grounds the platform's AI investigations in authoritative cybersecurity intelligence and internal SOC standard operating procedures. By combining **PostgreSQL + pgvector** with local dense vector embeddings, the system retrieves relevant MITRE ATT&CK detection notes and remediation playbooks before generating an investigation report.

```
[ Incident Telemetry + MITRE IDs ]
                 │
                 ▼
[ Query Synthesis & Vectorization ]
     (all-MiniLM-L6-v2, 384-d)
                 │
                 ▼
[ pgvector Cosine Search (<=>) ]
     (knowledge_embeddings table)
                 │
                 ▼
[ Top-k Relevant Knowledge Chunks ]
  (MITRE Context + SOC Playbooks)
                 │
                 ▼
[ Structured Prompt Augmentation ]
                 │
                 ▼
[ Ollama Local LLM (Llama 3) ]
                 │
                 ▼
[ Structured Investigation + Evidence Citations ]
```

---

## 2. Knowledge Base Architecture

The knowledge corpus resides in [`data/knowledge/`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/data/knowledge/) and consists of three curated, verified datasets:

1. **Official MITRE ATT&CK Corpus (`mitre_attack_corpus.json`)**:
   - Comprehensive technical documentation for Enterprise ATT&CK techniques:
     - `T1110`: Brute Force (Password Spraying, Credential Stuffing)
     - `T1046`: Network Service Discovery (Port Scanning, Banner Grabbing)
     - `T1078`: Valid Accounts (Compromised Credentials, Lateral Movement)
     - `T1068`: Exploitation for Privilege Escalation (Sudo/Setuid abuse)
     - `T1005`: Data from Local System (Sensitive File Staging)
     - `T1041`: Exfiltration Over C2 Channel (Data Theft via Encrypted/Alternate Protocols)
   - Contains tactic classifications, technical descriptions, detection telemetry recommendations, and official mitigations.

2. **SOC Remediation Playbooks (`soc_playbooks.json`)**:
   - Step-by-step incident response procedures for Tier 1/Tier 2 analysts:
     - Identification and verification criteria
     - Immediate containment steps (host quarantine, IP blocking, session revocation)
     - Eradication and remediation instructions
     - Evidence preservation requirements

3. **Investigation Guides (`investigation_guides.json`)**:
   - Triage rules and false positive indicators:
     - Differentiating legitimate administrative activity from unauthorized privilege escalation
     - Assessing outbound data volume anomalies vs legitimate backups
     - Credential validation and user verification protocols

---

## 3. Embedding Service (`EmbeddingService`)

Implemented in [`backend/app/services/embedding_service.py`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/backend/app/services/embedding_service.py):

- **Model**: `sentence-transformers/all-MiniLM-L6-v2` (running 100% locally via PyTorch / Apple Silicon Metal / CPU).
- **Embedding Dimensions**: 384.
- **Normalization**: All output vectors are L2-normalized to ensure cosine distance equivalence with Euclidean operations.
- **Configurability**: Configurable via `EMBEDDING_MODEL` environment variable. Does not require proprietary APIs or external cloud keys.
- **Batch Processing**: Supports batch embedding generation for high-throughput ingestion.

---

## 4. Ingestion Engine (`scripts/ingest_knowledge.py`)

Knowledge ingestion is automated and fully reproducible:

```bash
PYTHONPATH=. backend/venv/bin/python scripts/ingest_knowledge.py
```

### Ingestion Properties:
1. **Idempotence**: Checks the `knowledge_embeddings` table by `document_id` and `chunk_index` before inserting to avoid duplicates.
2. **Chunking**: Splits long playbook sections into discrete semantic chunks (~200–500 tokens) preserving title and technique metadata.
3. **Storage**: Writes directly to PostgreSQL using SQLAlchemy 2.0 and the `pgvector` vector type:
   ```sql
   CREATE TABLE knowledge_embeddings (
       id UUID PRIMARY KEY,
       document_id VARCHAR(100),
       source VARCHAR(255),
       source_type VARCHAR(50),
       technique_id VARCHAR(20),
       title VARCHAR(255),
       chunk_index INTEGER,
       content TEXT,
       embedding VECTOR(384),
       created_at TIMESTAMP
   );
   ```

---

## 5. RAG Retrieval Service (`RAGService`)

Implemented in [`backend/app/services/rag_service.py`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/backend/app/services/rag_service.py):

### Retrieval Workflow:
1. **Query Construction**: Accepts an investigation query string synthesized from incident telemetry.
2. **Vectorization**: Transforms the query string into a 384-dimensional query vector via `EmbeddingService`.
3. **Similarity Search**: Queries PostgreSQL using the pgvector `<=>` cosine distance operator:
   ```python
   stmt = (
       select(
           KnowledgeEmbedding.document_id,
           KnowledgeEmbedding.title,
           KnowledgeEmbedding.content,
           KnowledgeEmbedding.technique_id,
           KnowledgeEmbedding.source_type,
           (1.0 - KnowledgeEmbedding.embedding.cosine_distance(query_vector)).label("similarity")
       )
       .order_by(KnowledgeEmbedding.embedding.cosine_distance(query_vector))
       .limit(top_k * 2)
   )
   ```
4. **Deduplication**: Filters out duplicate chunks originating from the same document ID to ensure diversity of evidence.
5. **Top-k Output**: Returns structured `EvidenceItem` objects containing source, title, technique ID, similarity score, and excerpt text.

---

## 6. Integration with Ollama Local LLM

When an analyst triggers an investigation (`POST /api/incidents/{id}/investigate`):

1. **Context Compilation**:
   - Chronological event timeline
   - XGBoost predictions & confidence
   - Isolation Forest anomaly scores
   - Transparent risk score breakdown
   - Top-3 retrieved RAG evidence chunks with source citations
2. **Local Inference**:
   - Calls Ollama at `http://localhost:11434` with model `llama3:latest`.
   - Forces structured JSON output matching `StructuredInvestigation`.
3. **Strict Fallback Guarantee**:
   - If Ollama is offline or times out, the system returns status `LLM_UNAVAILABLE` and presents the rule-based investigation.
   - The analysis method is explicitly marked as `LLM_RAG`, `LLM`, or `RULE_BASED`. The platform **never** labels rule-based fallbacks as LLM outputs.
