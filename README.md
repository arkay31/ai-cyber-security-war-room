# AI Cyber Security War Room

An autonomous, AI-assisted Security Operations Center (SOC) and Incident Investigation platform designed to ingest raw telemetry, detect attacks with supervised machine learning, flag anomalies with unsupervised algorithms, compute transparent risk scores, deterministically correlate multi-stage attack chains, map techniques to the MITRE ATT&CK framework, retrieve curated defense playbooks via vector similarity (pgvector RAG), generate structured investigations via local LLMs (Ollama), execute human-in-the-loop identity verification, and perform analyst-approved, controlled response containment.

---

## Complete End-to-End Pipeline

```
DETECT
  │   (Raw Telemetry Ingestion ➔ Normalization ➔ XGBoost Detection ➔ Isolation Forest Anomaly)
  ▼
CORRELATE
  │   (Temporal Sliding Window Correlation across IP, Host, User ➔ Transparent 0–100 Risk Score)
  ▼
MAP TO MITRE
  │   (Enterprise ATT&CK Technique Mapping: T1110, T1078, T1068, T1005, T1041, etc.)
  ▼
RETRIEVE EVIDENCE
  │   (pgvector Similarity Search with SentenceTransformers over Official MITRE Corpus & Playbooks)
  ▼
AI INVESTIGATE
  │   (Ollama Local Inference via Llama 3 ➔ Structured Investigation JSON + Evidence Citations)
  ▼
SOC ANALYST REVIEW
  │   (War Room Dashboard ➔ Chronological Timeline ➔ Telemetry Inspector ➔ MITRE Cards)
  ▼
USER VERIFICATION WHEN REQUIRED
  │   (Human-in-the-Loop Portal /verify/<challengeId> ➔ PIN Auth ➔ [CONFIRM] or [DENY])
  ▼
ANALYST DECISION
  │   (Review Verification Outcome ➔ Auto-Escalate Risk on Denial ➔ Triage Incident Disposition)
  ▼
CONTROLLED RESPONSE
  │   (Analyst-Approved Simulated Containment: Isolate Host, Block IP, Revoke Session)
  ▼
AUDIT TRAIL
  │   (Immutable PostgreSQL Forensic Audit Logs for Every System and Human Action)
  ▼
DASHBOARD / REPORT
      (Interactive React Flow Attack Topology, Recharts Analytics, Formal Compliance PDF Reports)
```

---

## Tech Stack

### Frontend Application:
- **Framework**: Next.js 16.3 (App Router, Turbopack)
- **Language**: TypeScript 5
- **Styling**: Tailwind CSS 4 (Cybersecurity Dark SOC Theme)
- **Visualizations**: Recharts (Threat Timeline & Telemetry Distributions)
- **Topology Graph**: React Flow (Interactive Incident-Entity-MITRE Graph)
- **Icons**: Lucide React

### Backend Core:
- **Framework**: FastAPI (Python 3.11)
- **ASGI Server**: Uvicorn
- **ORM & Database**: SQLAlchemy 2.0 with PostgreSQL 16 & `pgvector`
- **Validation**: Pydantic v2
- **Testing**: Pytest & FastAPI TestClient

### Machine Learning & AI:
- **Supervised ML**: XGBoost (`XGBClassifier`) for attack classification (Accuracy: 99.89% on development set)
- **Anomaly Detection**: Scikit-Learn (`IsolationForest`) for baseline deviation
- **Vector Embeddings**: SentenceTransformers (`all-MiniLM-L6-v2`, 384 dimensions)
- **Vector Database**: PostgreSQL 16 with `pgvector` extension
- **Local LLM Inference**: Ollama (`http://localhost:11434`, `llama3:latest`) with structured JSON enforcement and graceful fallback (`LLM_UNAVAILABLE`)

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
