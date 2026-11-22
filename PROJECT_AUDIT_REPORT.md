# PROJECT AUDIT REPORT: AEGIS ONE – AI CYBER SECURITY WAR ROOM
**Autonomous Tier-2 AI Security Operations Center & Incident Investigation Platform**

- **Project:** Aegis One – AI Cyber Security War Room
- **Audit Date:** November 21, 2026
- **Auditor:** Senior AI Engineer, Full-Stack Architect & DevOps Security Reviewer
- **Target Role:** AI Engineer Fresher – Tech Mahindra & Top AI/ML Cyber Engineering Roles
- **Repository Location:** `/Users/rakshitkapoor/Desktop/ai-cyber-security-war-room`
- **Current Operating Status:** 100% Operational (PostgreSQL 16 pgvector UP, FastAPI Backend UP, Next.js 16 Turbopack UP, 42/42 Backend Tests Passed)

---

## 1. Executive Summary

A comprehensive architectural, algorithmic, security, and full-stack audit was performed on the **Aegis One – AI Cyber Security War Room** codebase.

The system represents an enterprise-grade AI-assisted Security Operations Center (SOC) designed to solve the critical alert fatigue problem faced by Tier-1 and Tier-2 security analysts. Rather than simply wrapping a large language model with basic prompts, Aegis One implements an end-to-end defense-in-depth pipeline:

$$\text{Raw Telemetry Ingestion} \longrightarrow \text{Supervised ML (XGBoost)} \longrightarrow \text{Unsupervised Anomaly (Isolation Forest)} \longrightarrow \text{Risk Scoring} \longrightarrow \text{Sliding-Window Correlation} \longrightarrow \text{MITRE ATT\&CK Mapping} \longrightarrow \text{pgvector RAG Retrieval} \longrightarrow \text{Tier-2 AI Synthesis} \longrightarrow \text{HITL User Verification} \longrightarrow \text{Controlled Response Engine} \longrightarrow \text{Immutable Audit Trail}$$

The overall architecture is mathematically sound, cleanly modularized, and backed by a 42-test automated suite. However, this audit has identified several architectural gaps, technical debt items, deployment blockers, and opportunities for ML enhancements required to elevate this project to production readiness and make it an undeniable asset in technical interviews.

---

## 2. Comprehensive Component Inventory & Current Implementation Status

| Component | Technical Implementation | Current Status | Verification Details |
| :--- | :--- | :--- | :--- |
| **Supervised Threat Classifier** | XGBoost (`XGBClassifier`) with 20 engineered network flow features | **Functional** (Dev Baseline) | Evaluates multi-class attack categories (`BENIGN`, `PortScan`, `DDoS`, `DoS`, `Brute Force`, `Bot`, `Web Attack`, `Infiltration`). Achieves 99.89% on development split. Needs feature importance and SHAP explanations. |
| **Unsupervised Anomaly Detector** | Scikit-Learn `IsolationForest` ($N=150$, contamination=0.08) | **Functional** (Dev Baseline) | Trained strictly on normal (`BENIGN`) traffic. Calibrated threshold ($0.55$) on validation split; evaluated on unseen test data ($F_1 = 0.941$). |
| **Feature Preprocessor** | `CICIDSPreprocessor` (`backend/app/ml/preprocessor.py`) | **Functional** | Normalizes flow duration, packet lengths, inter-arrival times (IAT), SYN/ACK flags, and window sizes. Handles NaNs/infs. |
| **Risk Scoring Engine** | `RiskEngine` (`backend/app/services/risk_engine.py`) | **Functional** | Deterministic 4-factor formula: $0.30 \times \text{ML} + 0.25 \times \text{Anomaly} + 0.25 \times \text{Severity} + 0.20 \times \text{AssetContext}$. Maps to discrete tiers (`LOW`, `MEDIUM`, `HIGH`, `CRITICAL`). |
| **Incident Correlation Engine** | `CorrelationEngine` (`backend/app/services/correlation_engine.py`) | **Functional** | 30-minute sliding window correlation across Source IP, Target User, and Hostname. Aggregates multi-stage attack chains (e.g., Brute Force $\to$ Privilege Escalation). |
| **MITRE ATT&CK Integration** | `MitreService` (`backend/app/services/mitre_service.py`) | **Functional** | Database-backed official ATT&CK technique catalog (12 core techniques across Enterprise matrix). Deterministic mapping and automated incident linking. |
| **Knowledge Base & RAG** | `RAGService` (`backend/app/services/rag_service.py`) | **Functional** | Dense vector similarity retrieval using PostgreSQL `pgvector` with cosine distance operator (`<=>`). 384-dimensional dense embeddings. |
| **Embedding Service** | `EmbeddingService` (`backend/app/services/embedding_service.py`) | **Functional** | Lazy loads `sentence-transformers` (`all-MiniLM-L6-v2`). Generates normalized $L_2$ unit vectors. |
| **LLM Inference Engine** | `LLMService` (`backend/app/services/llm_service.py`) | **Functional** (Local Ollama Only) | Connects to local Ollama (`llama3:latest`) at `http://localhost:11434`. Includes JSON regex sanitizer and truncation repair. Lacks hosted cloud provider abstraction. |
| **Autonomous AI Analyst** | `AIAnalystService` (`backend/app/services/ai_analyst.py`) | **Functional** | Assembles telemetry, ML predictions, MITRE techniques, and pgvector RAG playbooks into structured prompt. Transparent `RULE_BASED` fallback when LLM is offline. |
| **Human-in-the-Loop (HITL)** | `VerificationRequest` (`backend/app/routes/verification.py`) | **Functional** | Generates non-technical user challenge with 16-hex token, 4-digit PIN authentication, expiration timer, and denial-triggered risk escalation. |
| **Controlled Response Engine** | `ResponseEngine` (`backend/app/services/response_engine.py`) | **Functional** | One-way state machine (`PENDING` $\to$ `EXECUTED` / `REJECTED`). Duplicate submission prevention. Generates simulated telemetry hashes (`ACL-DROP-`, `EDR-ISO-`, etc.). |
| **Forensic Audit Trail** | `AuditLog` (`backend/app/models/audit_log.py`) | **Functional** | Immutable PostgreSQL log storing timestamp, actor, action, incident ID, and detailed JSON payload. |
| **Frontend Application** | Next.js 16.3.1 (React 19, Turbopack, Tailwind CSS 4) | **Functional** | Operational pages: `/` (Dashboard), `/incidents`, `/ai-analyst`, `/attack-graph` (React Flow), `/analytics` (Recharts), `/reports`, `/threat-intelligence`, `/verify/[challengeId]`. |
| **Database Container** | Docker `pgvector/pgvector:pg16` | **Functional** | Container `warroom-postgres` running on `localhost:5432` with persistent volumes and vector extension. |

---

## 3. Discrepancy Analysis: Documentation vs. Actual Codebase

1. **Dataset Representation Disclosure:**
   - *Documentation:* References training on the CICIDS2017 benchmark dataset.
   - *Actual Codebase:* Currently trains on a curated, stratified development sample (`data/raw/cicids2017_sample.csv`).
   - *Audit Finding:* While academically defensible for local execution and rapid iteration, technical interviewers at Tech Mahindra will probe whether the model was trained on the full 50GB PCAP dataset or a development sample. The documentation must explicitly and proudly disclose the **two-tier evaluation methodology** (Development Baseline vs. Production Research Benchmark) to demonstrate scientific integrity.

2. **Dependencies & Requirements Completeness:**
   - *Documentation:* Claims full support for `sentence-transformers`, `torch`, and SHAP explanations.
   - *Actual Codebase:* `backend/requirements.txt` previously omitted `sentence-transformers` and `shap`, causing lazy-import dependencies that were installed manually in the virtual environment but not tracked in version control.
   - *Correction Required:* Explicitly update `backend/requirements.txt` to include `sentence-transformers>=3.0.0` and `shap>=0.45.0`.

3. **LLM Provider Architecture & Cloud Deployment Barrier:**
   - *Documentation:* Suggests the system can run anywhere.
   - *Actual Codebase:* Hardcoded to `http://localhost:11434` (local Ollama). If deployed to Vercel/Render, the backend cannot reach Ollama on the developer's MacBook Air.
   - *Correction Required:* Implement a polymorphic `LLMProvider` interface supporting both local Ollama and hosted providers (OpenAI / Groq / Anthropic) selectable via environment variable `LLM_PROVIDER=ollama|openai|groq`.

4. **Environment Isolation on macOS:**
   - *Issue Identified:* `node_modules` was previously evicted by macOS iCloud "Optimize Mac Storage" on `~/Desktop` (`SF_DATALESS` flag `0x40000000`).
   - *Current State:* `node_modules` is now shielded using `node_modules.nosync`. However, `backend/venv` is still directly in `backend/venv` and vulnerable to similar background eviction by macOS FileProvider.
   - *Correction Required:* Shield `backend/venv` with `backend/venv.nosync` and symlink.

---

## 4. Incomplete Features, Placeholders & Improvement Opportunities

### Machine Learning (Phase 2):
- **Feature Importance & Interpretability:** The XGBoost model calculates predictions and class probabilities, but does not persist global feature importances or return local feature contribution weights to the frontend.
- **SHAP Integration:** TreeSHAP / KernelSHAP can explain *why* a particular network packet was classified as an attack (e.g. high `Flow Packets/s` or non-standard `Destination Port`).
- **Evaluation Artifacts:** Confusion matrices and classification reports are printed to the console during training but not saved as structured visual or JSON artifacts in `models/evaluation/`.

### AI Analyst & RAG (Phases 3 & 4):
- **Pydantic Response Validation:** The AI Analyst currently parses JSON via regex and dict manipulation, but does not strictly validate the output against a Pydantic `InvestigationResultSchema` with field-level constraints.
- **RAG Evaluation Metrics:** The retrieval pipeline returns documents, but does not measure or log quantitative RAG metrics such as **Precision@K**, **Retrieval Latency**, or **Source Attribution Relevance**.
- **Low-Relevance Guardrails:** When similarity is low, the prompt should explicitly inject an anti-hallucination directive informing the LLM that no high-confidence playbooks match this event.

### Production Readiness & Public Deployment (Phases 5, 9 & 10):
- **Hosted LLM API Integration:** Support OpenAI (`gpt-4o-mini`) and Groq (`llama-3.3-70b-versatile`) as cloud inference engines for public demonstration.
- **Demo Mode for Interviewers:** A dedicated "Interactive Demo Mode" banner allowing interviewers to inject pre-configured attack scenarios (Brute Force, Port Scan, DDoS, Privilege Escalation) with one click without registering or logging in.
- **Deployment Manifests:** Production Dockerfile, Render `render.yaml`, and Vercel configuration files with clear environment variable documentation.

---

## 5. Security & Risk Assessment

1. **Secret Management:** Currently, secrets are managed via `backend/.env` and `.env.local`. Git status confirms these files are not tracked in Git. A comprehensive `.env.example` must be provided.
2. **CORS Hardening:** Configured for `localhost:3000` and `127.0.0.1:3000`. For public deployment, `CORS_ORIGINS` must dynamically allow the production Vercel frontend domain.
3. **Simulated Action Safety:** All response actions (`BLOCK_SOURCE_IP`, `ISOLATE_HOST`, etc.) execute exclusively in `SIMULATION` mode, returning synthetic command hashes and device receipts without touching real network interfaces. This is secure and compliant with academic safety rules.
4. **SQL Injection:** Queries utilize SQLAlchemy ORM parameterized statements and pgvector vector distance operators, preventing raw string concatenation SQL injections.

---

## 6. Action Plan & Roadmap for Subsequent Phases

1. **Phase 2 (ML Enhancements):** Add feature importance logging, generate confusion matrices and evaluation reports in `models/evaluation/`, add SHAP local explanations, and update training scripts.
2. **Phase 3 (Advanced AI Analyst):** Implement Pydantic schema validation for LLM outputs, anti-hallucination guardrails, and feature-influence summaries.
3. **Phase 4 (RAG Enhancements):** Implement quantitative RAG metrics (Precision@K, Latency), low-relevance guardrails, and generate `docs/RAG_ARCHITECTURE.md`.
4. **Phase 5 (LLM Provider Architecture):** Create provider abstraction supporting Ollama, OpenAI, and Groq with automatic fallback.
5. **Phase 6 (HITL & Response Engine):** Enhance state machine verification and audit trail reporting.
6. **Phase 7 (Frontend Polish):** Add Demo Mode buttons, model explanation cards, and visual feature importance charts.
7. **Phase 8 (Testing & QA):** Expand automated pytest suite to cover new ML explanations, provider switching, and RAG metrics.
8. **Phase 9 (Security Review):** Create `.env.example` and harden CORS/rate-limiting.
9. **Phase 10 & 11 (Deployment & Demo):** Create Render and Vercel configs, seed sample events, and test live deployment.
10. **Phase 12 (Documentation & Interview Prep):** Produce comprehensive documentation and a targeted Tech Mahindra interview guide (`docs/INTERVIEW_PREPARATION.md`).
