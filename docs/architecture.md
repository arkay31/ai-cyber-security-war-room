# AI Cyber Security War Room - Architecture Documentation

## 1. System Overview

The **AI Cyber Security War Room** is an autonomous, AI-assisted Security Operations Center (SOC) and Incident Investigation platform designed to ingest raw network/endpoint telemetry, detect attacks with supervised machine learning, flag anomalies with unsupervised algorithms, compute transparent risk scores, deterministically correlate multi-stage attack chains, map techniques to the MITRE ATT&CK framework, retrieve curated defense playbooks via vector similarity (RAG), generate structured investigations via local LLMs (Ollama), execute human-in-the-loop identity verification, and perform analyst-approved, controlled response containment.

---

## 2. End-to-End Pipeline Architecture

```
                    SECURITY TELEMETRY
                             │
              ┌──────────────┴──────────────┐
              │                             │
       CSV / Flow Data             Synthetic SOC Scenarios
       (CICIDS2017)                (Multi-Stage Attacks)
              │                             │
              └──────────────┬──────────────┘
                             │
                     INGESTION LAYER
                    FastAPI Endpoints
                             │
                      NORMALIZATION
                    Pydantic Schemas
                             │
              ┌──────────────┴──────────────┐
              │                             │
      THREAT DETECTION              ANOMALY DETECTION
      XGBoost Classifier             Isolation Forest
              │                             │
              └──────────────┬──────────────┘
                             │
                        RISK ENGINE
                 Deterministic 0–100 Score
                             │
                    INCIDENT CORRELATION
                 Sliding Temporal Windows
                             │
              ┌──────────────┴──────────────┐
              │                             │
       MITRE ATT&CK                    POSTGRESQL
       Technique Mapping               + pgvector
              │                             │
              └──────────────┬──────────────┘
                             │
                   RAG RETRIEVAL ENGINE
               SentenceTransformers + pgvector
                             │
                   LOCAL LLM INFERENCE
                    Ollama (Llama 3)
                             │
                   AI INVESTIGATION REPORT
              (Structured JSON + Evidence Citations)
                             │
                    SOC ANALYST REVIEW
                             │
              ┌──────────────┴──────────────┐
              │                             │
      DIRECT CONTAINMENT            USER VERIFICATION
      (Analyst Approved)         (Local /verify/ Portal)
              │                             │
              │                      [ CONFIRM / DENY ]
              │                             │
              └──────────────┬──────────────┘
                             │
                 CONTROLLED RESPONSE ENGINE
               (Simulated Host/IP Actions)
                             │
                    AUDIT LOG TRAIL
                (Immutable PostgreSQL Records)
                             │
                    WAR ROOM DASHBOARD
```

---

## 3. Technology Stack

### Frontend Application
- **Framework**: Next.js 16.3 (App Router, Turbopack)
- **Language**: TypeScript 5
- **Styling**: Tailwind CSS 4 (Cybersecurity Dark SOC Theme)
- **Visualizations**: Recharts (Timeline & Telemetry Distributions)
- **Graph Topology**: React Flow (Interactive Incident-Entity-MITRE Graph)
- **Icons**: Lucide React

### Backend Core
- **Framework**: FastAPI (Python 3.11)
- **ASGI Server**: Uvicorn
- **ORM & Data Layer**: SQLAlchemy 2.0 with PostgreSQL 16 & `pgvector`
- **Validation**: Pydantic v2
- **Testing**: Pytest & FastAPI TestClient

### Machine Learning & Knowledge Base
- **Supervised Classifier**: XGBoost (`XGBClassifier`, 99.89% development test accuracy)
- **Unsupervised Anomaly Detector**: Scikit-Learn (`IsolationForest`, calibrated threshold)
- **Vector Embeddings**: SentenceTransformers (`all-MiniLM-L6-v2`, 384-dimensional dense vectors)
- **Vector Database**: PostgreSQL 16 `pgvector` extension (`<=>` cosine distance index)
- **Local LLM Engine**: Ollama running `llama3:latest` (or any user-configured model) with structured JSON enforcement and graceful fallback

---

## 4. Component Interaction Diagram

```
[ Frontend: Next.js ] ──HTTP/REST──► [ Backend: FastAPI ]
                                             │
                       ┌─────────────────────┼─────────────────────┐
                       ▼                     ▼                     ▼
               [ ML Preprocessor ]    [ Postgres 16 ]      [ Ollama Engine ]
                       │              - security_events    - llama3:latest
                       ▼              - detections         - Local GPU/Metal
               [ XGBoost & IF ]       - anomalies          - Structured Output
                       │              - incidents
                       ▼              - mitre_techniques
               [ Risk Engine ]        - knowledge_embeddings (pgvector)
                       │              - verification_requests
                       ▼              - response_actions
               [ Correlation ]        - audit_logs
```

---

## 5. PostgreSQL + pgvector Database Schema

### 1. `security_events`
Stores raw and normalized security telemetry events:
- `id` (UUID PK): Unique event ID.
- `timestamp` (DateTime): Event occurrence timestamp.
- `source_ip` (String): Originating IP address.
- `destination_ip` (String): Target IP address.
- `source_port` (Integer): Source port.
- `destination_port` (Integer): Destination port.
- `protocol` (String): TCP, UDP, ICMP.
- `user` (String, nullable): Associated user account.
- `hostname` (String, nullable): Affected host or endpoint.
- `event_type` (String): Event category (e.g., `failed_login`, `port_scan`, `sudo_escalation`).
- `severity` (String): LOW, MEDIUM, HIGH, CRITICAL.
- `raw_data` (JSON): 20 numerical flow features for ML preprocessing.

### 2. `detections`
Records supervised XGBoost inferences:
- `id` (UUID PK): Detection record ID.
- `event_id` (UUID FK -> `security_events.id`): Associated event.
- `predicted_class` (String): Classified threat category.
- `confidence` (Float): Softmax confidence score (0.00 to 1.00).
- `created_at` (DateTime): Inference timestamp.

### 3. `anomalies`
Records unsupervised Isolation Forest inferences:
- `id` (UUID PK): Anomaly record ID.
- `event_id` (UUID FK -> `security_events.id`): Associated event.
- `anomaly_score` (Float): Calibrated outlier score (0.00 to 1.00).
- `is_anomalous` (Boolean): Flag indicating threshold breach (> 0.55).
- `created_at` (DateTime): Inference timestamp.

### 4. `incidents`
Represents correlated multi-stage attack incidents:
- `id` (UUID PK): Incident record ID.
- `incident_id` (String): Human-readable identifier (e.g., `INC-20261001-A1B2`).
- `title` (String): High-level attack title.
- `severity` (String): LOW, MEDIUM, HIGH, CRITICAL.
- `risk_score` (Float): Deterministic composite risk (0 to 100).
- `status` (String): Incident state (e.g., `NEW`, `INVESTIGATING`, `AWAITING_USER_VERIFICATION`, `CONTAINED`, `RESOLVED`).
- `summary` (Text): Synthesis or AI investigation summary.
- `created_at` (DateTime): Initial correlation timestamp.
- `updated_at` (DateTime): Last activity timestamp.

### 5. `incident_events`
Association table linking events to correlated incidents:
- `incident_id` (UUID FK -> `incidents.id`): Parent incident.
- `event_id` (UUID FK -> `security_events.id`): Correlated event.

### 6. `mitre_techniques`
Catalogue of Enterprise ATT&CK techniques:
- `id` (String PK): MITRE Technique ID (e.g., `T1110`).
- `name` (String): Technique name (e.g., `Brute Force`).
- `tactic` (String): Parent tactic (e.g., `Credential Access`).
- `description` (Text): Technical description and impact.

### 7. `incident_mitre_mappings`
Association table linking incidents to mapped MITRE techniques:
- `incident_id` (UUID FK -> `incidents.id`): Incident reference.
- `technique_id` (String FK -> `mitre_techniques.id`): Technique reference.

### 8. `knowledge_embeddings` (pgvector)
Vector store for RAG playbooks and MITRE documentation:
- `id` (UUID PK): Chunk identifier.
- `document_id` (String): Source document identifier.
- `source` (String): Originating file or dataset (e.g., `mitre_attack_corpus.json`).
- `source_type` (String): `mitre_technique`, `playbook`, or `investigation_guide`.
- `technique_id` (String, nullable): Associated MITRE ID if applicable.
- `title` (String): Chunk title.
- `chunk_index` (Integer): Sequential chunk index.
- `content` (Text): Chunk text content.
- `embedding` (Vector(384)): 384-dimensional dense vector generated via `all-MiniLM-L6-v2`.
- `created_at` (DateTime): Ingestion timestamp.

### 9. `verification_requests`
Tracks human-in-the-loop user verification challenges:
- `id` (UUID PK): Request ID.
- `incident_id` (UUID FK -> `incidents.id`): Parent incident.
- `user_id` (String): Identity under challenge.
- `challenge_id` (String Unique): Secure challenge token.
- `status` (String): `PENDING`, `CONFIRMED`, `DENIED`, `EXPIRED`.
- `activity_summary` (Text): Safe, non-technical description of suspicious activity.
- `requested_by` (String): Analyst or system initiator.
- `delivery_method` (String): `DEMO_PORTAL`, `EMAIL`, `PUSH_SIMULATION`.
- `created_at` (DateTime): Creation timestamp.
- `expires_at` (DateTime): Expiration timestamp (15 minutes).

### 10. `verification_responses`
Records authenticated user responses to challenges:
- `id` (UUID PK): Response ID.
- `verification_request_id` (UUID FK -> `verification_requests.id`): Request reference.
- `response` (String): `YES_IT_WAS_ME` or `NO_I_DID_NOT_DO_THIS`.
- `authenticated` (Boolean): PIN/password authentication status.
- `verification_method` (String): Verification channel used.
- `responded_at` (DateTime): Response timestamp.

### 11. `response_actions`
Tracks analyst-approved response and containment actions:
- `id` (UUID PK): Action ID.
- `incident_id` (UUID FK -> `incidents.id`): Target incident.
- `action_type` (String): `BLOCK_SOURCE_IP`, `ISOLATE_HOST`, `REVOKE_USER_SESSION`, `FORENSIC_SNAPSHOT`, `DISABLE_ACCOUNT`.
- `target` (String): Target IP, hostname, or username.
- `reason` (Text): Analyst rationale.
- `status` (String): `PENDING`, `APPROVED`, `EXECUTED`, `REJECTED`, `FAILED`.
- `analyst_id` (String): Authorizing analyst.
- `is_simulated` (Boolean): Simulation flag (strictly True for safety).
- `execution_log` (Text): Execution outcome details.
- `created_at` (DateTime): Proposal timestamp.
- `executed_at` (DateTime, nullable): Execution timestamp.

### 12. `audit_logs`
Forensic audit trail of all automated and human actions:
- `id` (UUID PK): Audit log record ID.
- `timestamp` (DateTime): Action timestamp.
- `action` (String): Action identifier (e.g., `INCIDENT_CREATED`, `USER_DENIED`, `RESPONSE_EXECUTED`).
- `user_id` (String): Actor (analyst username or `SYSTEM`).
- `incident_id` (String, nullable): Associated incident identifier.
- `details` (JSON): Contextual payload and state delta.
