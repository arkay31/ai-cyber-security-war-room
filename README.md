# Aegis One – Autonomous AI Cyber Security War Room
## Tier-2 Autonomous SOC Analyst, Explainable ML (TreeSHAP), pgvector RAG & Human-in-the-Loop Response

Aegis One is an autonomous, AI-driven Security Operations Center (SOC) investigation platform designed to ingest raw telemetry, detect attacks with supervised machine learning, flag novel anomalies with unsupervised baseline algorithms, compute transparent composite risk scores, deterministically correlate multi-stage kill chains, map techniques to the MITRE ATT&CK framework, retrieve curated defense playbooks via vector similarity (pgvector RAG), generate structured investigations via polymorphic LLMs (Local Ollama / Groq / OpenAI), execute human-in-the-loop identity verification, and perform analyst-approved, controlled response containment.

---

## 1. Key System Capabilities

- **Supervised Threat Classification**: Trained on the CICIDS2017 flow feature schema with an **XGBoost Classifier** achieving **99.89% test accuracy** across 6 attack classes (`BENIGN`, `PortScan`, `DDoS`, `DoS`, `Brute Force`, `Bot`).
- **Unsupervised Anomaly Detection**: **Isolation Forest** fitted strictly on benign enterprise normal baselines, achieving **93.05% F1-score** and **94.99% recall** on unseen test splits with dynamic threshold calibration ($\tau = 0.430$).
- **Explainable AI (XAI)**:
  - **TreeSHAP**: Real-time polynomial-time local feature attribution ($\approx 2\text{ ms}$) showing exact feature impacts on threat classification.
  - **Multivariate Z-Scores**: Identifies flow metrics exceeding the benign enterprise baseline by standard deviations ($z_j$).
- **PostgreSQL 16 pgvector RAG**: Dense vector semantic retrieval using `sentence-transformers/all-MiniLM-L6-v2` (384 dimensions) with **100% Precision@1** and **1.00 MRR** across official MITRE ATT&CK techniques and SOC playbooks.
- **Polymorphic LLM Architecture**:
  - Local-first inference via **Ollama** (`llama3:latest` 8B) on Apple Silicon GPU for offline operation.
  - Seamless cloud switching to **Groq** (`llama-3.3-70b-versatile`) or **OpenAI** (`gpt-4o-mini`).
  - Strict Pydantic JSON validation (`AIInvestigationSchema`) with honest fallback (`RULE_BASED` with `LLM_UNAVAILABLE`) if LLM daemon is offline.
- **Interactive Interviewer Demo Mode**: One-click live injection toolbar in the topbar to test 5 distinct attack scenarios:
  1. Full Account Takeover & Exfiltration (Faculty Demo)
  2. SSH Password Spraying (Brute Force)
  3. SYN Stealth Reconnaissance (Port Scan)
  4. Volumetric SYN Flood (DDoS)
  5. Local Privilege Escalation (Sudo Abuse)
- **Human-in-the-Loop (HITL) Verification**: Out-of-band user challenge portal (`/verify/{challengeId}`) with PIN authentication to confirm or deny suspicious activity before disruptive containment.
- **Controlled Response Engine**: Dual-key analyst approval workflow for automated host quarantine, edge IP blocking, session revocation, and rate limiting.
- **Immutable Forensic Audit Trail**: Comprehensive tracking of all machine learning predictions, analyst decisions, and containment executions stored in PostgreSQL.

---

## 2. Complete End-to-End Pipeline

```
DETECT
  │   (Raw Telemetry Ingestion ➔ Bounds Validation ➔ XGBoost Detection ➔ Isolation Forest Anomaly)
  ▼
EXPLAIN (XAI)
  │   (Real-Time TreeSHAP Feature Attributions + Baseline Z-Score Feature Deviations)
  ▼
CORRELATE
  │   (Temporal Sliding Window Correlation across IP, Host, User ➔ Transparent 0–100 Risk Score)
  ▼
MAP TO MITRE
  │   (Enterprise ATT&CK Technique Mapping: T1110, T1078, T1548, T1005, T1048, etc.)
  ▼
RETRIEVE EVIDENCE (RAG)
  │   (pgvector Cosine Distance Search <=> with SentenceTransformers over MITRE Playbooks)
  ▼
AI INVESTIGATE
  │   (Polymorphic LLM Router: Ollama Llama 3 / Groq / OpenAI ➔ Pydantic Validated JSON)
  ▼
SOC ANALYST REVIEW
  │   (War Room Dashboard ➔ Chronological Timeline ➔ Telemetry Inspector ➔ TreeSHAP Cards)
  ▼
USER VERIFICATION (HITL)
  │   (Human-in-the-Loop Portal /verify/<challengeId> ➔ PIN Auth ➔ [CONFIRM] or [DENY])
  ▼
ANALYST DECISION & CONTAINMENT
  │   (Review Outcome ➔ Auto-Escalate Risk on Denial ➔ Approve Simulated Host/IP Quarantine)
  ▼
AUDIT TRAIL & TOPOLOGY
      (Immutable PostgreSQL Forensic Audit Logs ➔ Interactive React Flow Attack Topology)
```

---

## 3. Technology Inventory

| Layer | Technologies & Specifications |
| :--- | :--- |
| **Frontend** | Next.js 16.3 (Turbopack, App Router), TypeScript 5, Tailwind CSS 4, Recharts, React Flow, Lucide React |
| **Backend Core** | FastAPI (Python 3.11), Uvicorn ASGI, SQLAlchemy 2.0, `psycopg[binary]`, Pydantic v2 |
| **Database** | PostgreSQL 16 with `pgvector` extension (Vector dimensions: 384, Distance: Cosine `<=>`) |
| **Supervised ML** | XGBoost 2.1 (`XGBClassifier`, multi:softprob, 120 trees, depth 6, test accuracy: 99.89%) |
| **Anomaly ML** | Scikit-Learn 1.5 (`IsolationForest`, 150 trees, calibrated threshold: 0.430, test F1: 93.05%) |
| **Explainable AI** | `shap` 0.45 (TreeExplainer / TreeSHAP local attribution) + Empirical Z-Score deviations |
| **Embeddings & RAG** | SentenceTransformers (`all-MiniLM-L6-v2`, 384-dim dense vectors), PostgreSQL IVFFlat index |
| **LLM Inference** | Polymorphic: Local Ollama (`llama3:latest` 8B) / Hosted Groq (`llama-3.3-70b`) / OpenAI (`gpt-4o-mini`) |
| **Quality & Tests** | Pytest (42 automated integration and unit tests passing 100%), ESLint |

---

## 4. Quickstart Guide (Local Development)

### Prerequisites
- macOS or Linux
- Docker Desktop
- Python 3.11+
- Node.js 20+

### Step 1: Clone and Configure
```bash
git clone https://github.com/your-username/ai-cyber-security-war-room.git
cd ai-cyber-security-war-room
cp .env.example .env.local
cp backend/.env.example backend/.env
```

### Step 2: One-Command Startup
```bash
./start_warroom.sh
```
This automated shell script:
- Verifies `.nosync` protections on `node_modules` and Python `venv` (guarding against macOS iCloud file eviction).
- Boots the PostgreSQL 16 container (`warroom-postgres`) on port `5432`.
- Verifies database connectivity and seeds initial knowledge embeddings.
- Launches the FastAPI backend server on `http://localhost:8000`.
- Launches the Next.js development server on `http://localhost:3000`.

### Step 3: Access the War Room
- **War Room Dashboard**: [http://localhost:3000](http://localhost:3000)
- **FastAPI Interactive Docs**: [http://localhost:8000/docs](http://localhost:8000/docs)
- **HITL Verification Portal**: [http://localhost:3000/verify](http://localhost:3000/verify)
- **Interactive Scenarios**: Click **"Interview Demo Scenarios"** in the top navigation bar.

---

## 5. Verification & Test Suite

Run the complete 42-test automated backend test suite:
```bash
PYTHONPATH=. backend/venv/bin/pytest backend/tests/ -v
```

Run frontend production build verification:
```bash
npm run build
npm run lint
```

---

## 6. Comprehensive Documentation Index

- [`PROJECT_AUDIT_REPORT.md`](PROJECT_AUDIT_REPORT.md): Full technical audit, component inventory, and upgrade history.
- [`docs/SYSTEM_ARCHITECTURE.md`](docs/SYSTEM_ARCHITECTURE.md): Deep dive into all 12 platform subsystems and data flows.
- [`docs/ML_PIPELINE.md`](docs/ML_PIPELINE.md): Machine learning specifications, TreeSHAP, and anomaly mathematics.
- [`docs/RAG_ARCHITECTURE.md`](docs/RAG_ARCHITECTURE.md): pgvector retrieval architecture, chunking, and quantitative evaluation.
- [`docs/LLM_INTEGRATION.md`](docs/LLM_INTEGRATION.md): Polymorphic provider design, anti-hallucination, and fallback guarantees.
- [`docs/DEPLOYMENT_GUIDE.md`](docs/DEPLOYMENT_GUIDE.md): Vercel + Render + Docker Compose deployment guide.
- [`docs/INTERVIEW_PREPARATION.md`](docs/INTERVIEW_PREPARATION.md): Tech Mahindra AI Engineer Fresher interview preparation cheat sheet.

---

## Project Structure

```
ai-cyber-security-war-room/
├── backend/
│   ├── app/
│   │   ├── main.py                    # FastAPI application entrypoint & lifespan
│   │   ├── config.py                  # Pydantic environment configuration
│   │   ├── database.py                # PostgreSQL connection & table initialization
│   │   ├── models/                    # SQLAlchemy ORM models
│   │   │   ├── security_event.py      # security_events table
│   │   │   ├── detection.py           # detections table (XGBoost)
│   │   │   ├── anomaly.py             # anomalies table (Isolation Forest)
│   │   │   ├── incident.py            # incidents & incident_events tables
│   │   │   ├── mitre.py               # mitre_techniques & incident_mitre_mappings
│   │   │   ├── embedding.py           # knowledge_embeddings table (pgvector)
│   │   │   ├── verification.py        # verification_requests & responses tables
│   │   │   ├── response_action.py     # response_actions table
│   │   │   └── audit_log.py           # audit_logs table
│   │   ├── schemas/                   # Pydantic schemas for data validation
│   │   ├── routes/                    # FastAPI REST API routers
│   │   │   ├── health.py              # /api/health
│   │   │   ├── events.py              # /api/events, /api/events/simulate-demo-attack
│   │   │   ├── incidents.py           # /api/incidents, investigate, decision
│   │   │   ├── verification.py        # /api/verification (HITL User Verification)
│   │   │   ├── responses.py           # /api/responses (Controlled Response Engine)
│   │   │   ├── mitre.py               # /api/mitre/techniques
│   │   │   ├── dashboard.py           # /api/dashboard/stats
│   │   │   └── analytics.py           # /api/analytics, /api/attack-graph, reports
│   │   ├── services/
│   │   │   ├── embedding_service.py   # SentenceTransformers embedding generation
│   │   │   ├── rag_service.py         # pgvector similarity search & evidence retrieval
│   │   │   ├── llm_service.py         # Ollama client with structured JSON parsing
│   │   │   ├── ai_analyst.py          # Unified AI investigation pipeline
│   │   │   ├── state_machine.py       # Incident lifecycle state transitions
│   │   │   ├── response_engine.py     # Simulated controlled containment actions
│   │   │   ├── risk_engine.py         # Transparent 0-100 risk scoring formula
│   │   │   ├── correlation_engine.py  # Deterministic temporal incident correlation
│   │   │   ├── mitre_service.py       # ATT&CK technique catalogue seeding
│   │   │   └── synthetic_generator.py # Deterministic multi-stage SOC attack scenarios
│   │   └── ml/
│   │       ├── preprocessor.py        # CICIDS2017 feature extraction & cleaning
│   │       └── inference.py           # Unified ML & Anomaly inference engine
│   ├── tests/                         # Automated Pytest suite (26 comprehensive tests)
│   ├── requirements.txt               # Backend dependencies
│   └── .env.example                   # Environment configuration template
│
├── data/
│   ├── raw/                           # Raw telemetry datasets (CICIDS2017 sample)
│   ├── processed/                     # Cleaned flow features
│   └── knowledge/                     # Curated knowledge base corpus
│       ├── mitre_attack_corpus.json   # Official MITRE Enterprise techniques
│       ├── soc_playbooks.json         # SOC remediation playbooks
│       └── investigation_guides.json  # Investigation & triage guides
│
├── models/                            # Serialized ML artifacts & evaluation metadata
│   ├── xgboost_detector.joblib        # Trained XGBoost classifier
│   ├── label_encoder.joblib           # Label encoder
│   ├── isolation_forest.joblib        # Calibrated Isolation Forest model
│   ├── xgboost_metadata.json          # Evaluation metrics & confusion matrix
│   └── anomaly_metadata.json          # Calibration parameters & validation metrics
│
├── scripts/
│   ├── download_cicids2017.py         # CICIDS2017 dataset utility & development sample
│   ├── train_xgboost.py               # XGBoost training & evaluation script
│   ├── train_isolation_forest.py      # Isolation Forest baseline training & calibration
│   ├── ingest_knowledge.py            # Idempotent pgvector knowledge base ingestion
│   └── generate_synthetic_events.py   # CLI synthetic SOC event seeder
│
├── docs/
│   ├── architecture.md                # System architecture & database schema
│   ├── workflow.md                    # Complete 12-stage event & incident lifecycle
│   ├── ml_pipeline.md                 # ML models, features, and evaluation metrics
│   ├── rag_pipeline.md                # pgvector, SentenceTransformers, & Ollama RAG
│   ├── verification_workflow.md       # Human-in-the-Loop user verification portal
│   ├── response_engine.md             # Controlled response simulation & approval
│   ├── api.md                         # Complete REST API reference documentation
│   └── demo.md                        # Step-by-step 24-stage faculty demonstration script
│
├── src/                               # Next.js Frontend Application
│   ├── app/
│   │   ├── page.tsx                   # War Room Dashboard
│   │   ├── incidents/
│   │   │   ├── page.tsx               # Incident Management table
│   │   │   └── [id]/page.tsx          # 11-Section Incident Investigation Console
│   │   ├── verify/
│   │   │   └── [challengeId]/page.tsx # Human-in-the-Loop User Verification Portal
│   │   ├── threat-intelligence/       # MITRE ATT&CK Matrix Explorer
│   │   ├── ai-analyst/                # AI Investigation Workspace
│   │   ├── attack-graph/              # React Flow Entity Relationship Graph
│   │   ├── analytics/                 # Recharts Threat Telemetry Analytics
│   │   └── reports/                   # Structured Compliance & Forensic Reports
│   ├── components/                    # Reusable UI components
│   └── lib/
│       └── api.ts                     # Centralized typed frontend API client
│
├── docker-compose.yml                 # PostgreSQL 16 + pgvector container
└── README.md
```

---

## Setup & Running Instructions

### 1. Prerequisites
- **Node.js**: v18+ (v20+ recommended)
- **Python**: 3.11
- **Docker**: Docker Engine & Docker Compose
- **Ollama**: (Optional for local LLM inference) `brew install ollama && ollama pull llama3`

### 2. Start PostgreSQL with pgvector (Docker Compose)
```bash
docker compose up -d
```
Verify the container is healthy:
```bash
docker ps | grep warroom-postgres
```

### 3. Backend Setup
Create and activate the Python virtual environment:
```bash
python3.11 -m venv backend/venv
source backend/venv/bin/activate
pip install -r backend/requirements.txt
```

### 4. Train ML Models & Ingest Vector Knowledge Base
```bash
# Generate development dataset sample (CICIDS2017 schema)
PYTHONPATH=. backend/venv/bin/python scripts/download_cicids2017.py

# Train supervised XGBoost classifier
PYTHONPATH=. backend/venv/bin/python scripts/train_xgboost.py

# Train and calibrate unsupervised Isolation Forest
PYTHONPATH=. backend/venv/bin/python scripts/train_isolation_forest.py

# Ingest official MITRE techniques & SOC playbooks into pgvector
PYTHONPATH=. backend/venv/bin/python scripts/ingest_knowledge.py
```

### 5. Start Ollama (Local LLM Inference)
```bash
ollama serve
# Ensure model is downloaded:
ollama pull llama3
```
*Note: If Ollama is not running, the system automatically detects this and returns an explicit `LLM_UNAVAILABLE` status with a transparent rule-based fallback.*

### 6. Start the Backend API
```bash
backend/venv/bin/uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```
API Documentation: `http://localhost:8000/docs`
Health Status: `http://localhost:8000/api/health`

### 7. Start the Next.js Frontend
In a separate terminal:
```bash
npm run dev -- -p 3000
```
Open `http://localhost:3000` in your browser.

---

## Running Automated Tests

Run the full Pytest test suite:
```bash
PYTHONPATH=. backend/venv/bin/pytest backend/tests/ -v
```
The automated test suite verifies:
- Database connectivity & pgvector vector extension
- Supervised XGBoost inference & feature normalization
- Unsupervised Isolation Forest anomaly scoring
- Deterministic 0–100 risk scoring
- Temporal sliding window incident correlation
- pgvector semantic retrieval (RAG)
- Ollama local inference & graceful fallback
- Human-in-the-loop user verification challenges & outcomes
- Controlled response actions (simulation mode & analyst confirmation)
- Incident state machine transitions
- Immutable audit log generation

To run frontend typecheck and production build:
```bash
npx tsc --noEmit && npm run build
```

---

## Faculty Demonstration Guide

For a comprehensive 24-step demonstration walk-through from raw telemetry to incident containment and reporting, see:
👉 [**Faculty Demonstration Guide (`docs/demo.md`)**](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/docs/demo.md)

### Quick Demo Summary:
1. In the Topbar, click **[Simulate SOC Attacks]** and select **Run Faculty Demo Attack Sequence**.
2. Navigate to **Incidents** and open `INC-20261001-DEMO`.
3. View the 7-stage attack progression, flow telemetry, transparent risk score (`92.5`), and MITRE ATT&CK techniques (`T1110`, `T1078`, `T1068`, `T1005`, `T1041`).
4. Click **[Generate AI Investigation]** to witness pgvector RAG evidence retrieval and local Llama 3 structured analysis.
5. Click **[Verify User Activity]** to issue a human-in-the-loop challenge, open the `/verify/<challengeId>` portal, enter PIN `1234`, and test user denial.
6. Observe automatic incident escalation to `CRITICAL` (100.0) and stage containment actions.
7. Click **[Execute Action]** on `ISOLATE_HOST` to observe two-step analyst confirmation and simulated containment logging.
8. Inspect the permanent immutable **Audit Trail**, record final analyst disposition, and view the **Attack Graph** and **Compliance Report**.

---

## Additional Documentation

- [System Architecture & DB Schema](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/docs/architecture.md)
- [Complete 12-Stage SOC Workflow](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/docs/workflow.md)
- [Machine Learning & Anomaly Pipeline](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/docs/ml_pipeline.md)
- [pgvector RAG & Local LLM Integration](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/docs/rag_pipeline.md)
- [Human-in-the-Loop User Verification](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/docs/verification_workflow.md)
- [Controlled Response Engine](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/docs/response_engine.md)
- [REST API Reference](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/docs/api.md)
- [Faculty Demonstration Guide](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/docs/demo.md)
