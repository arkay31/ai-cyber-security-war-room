# End-to-End SOC Workflow & Incident Lifecycle

This document describes the complete 12-stage operational lifecycle of an event in the **AI Cyber Security War Room**, from initial telemetry ingestion to final containment, audit logging, and incident closure.

---

## The 12-Stage Lifecycle

```
[ STAGE 1: INGESTION & NORMALIZATION ]
                 │
                 ▼
[ STAGE 2: SUPERVISED THREAT DETECTION (XGBoost) ]
                 │
                 ▼
[ STAGE 3: UNSUPERVISED ANOMALY DETECTION (Isolation Forest) ]
                 │
                 ▼
[ STAGE 4: TRANSPARENT RISK SCORING (0-100) ]
                 │
                 ▼
[ STAGE 5: DETERMINISTIC INCIDENT CORRELATION ]
                 │
                 ▼
[ STAGE 6: MITRE ATT&CK TECHNIQUE MAPPING ]
                 │
                 ▼
[ STAGE 7: RETRIEVAL-AUGMENTED GENERATION (pgvector RAG) ]
                 │
                 ▼
[ STAGE 8: STRUCTURED AI INVESTIGATION (Ollama Llama 3) ]
                 │
                 ▼
[ STAGE 9: SOC ANALYST REVIEW & TRIAGE ]
                 │
                 ▼
[ STAGE 10: HUMAN-IN-THE-LOOP USER VERIFICATION ]
                 │
                 ▼
[ STAGE 11: CONTROLLED RESPONSE CONTAINMENT ]
                 │
                 ▼
[ STAGE 12: FORENSIC AUDIT TRAIL & INCIDENT RESOLUTION ]
```

---

## Detailed Stage Breakdown

### Stage 1: Ingestion & Normalization
- **Input**: Raw network flow telemetry (e.g. CICIDS2017 format) or endpoint system events ingested via `POST /api/events` or `POST /api/events/bulk`.
- **Normalization**: Validated using Pydantic schemas (`SecurityEventCreate`). Field names are cleaned, stripping leading/trailing whitespace. Flow telemetry is parsed into 20 standardized numeric features (packet length stats, flow duration, inter-arrival times, TCP flags, window sizes). Missing values and infinite values (`inf`, `-inf`) are sanitized into standard numeric floats.
- **Persistence**: Event record written to the `security_events` table in PostgreSQL.

### Stage 2: Supervised Threat Detection (XGBoost)
- **Model**: Multi-class `XGBClassifier` trained on network flow telemetry.
- **Inference**: Evaluates the 20-dimensional flow feature vector.
- **Output**: Class prediction (`BENIGN`, `PortScan`, `DDoS`, `DoS`, `Brute Force`, `Bot`) and a calibrated softmax probability confidence score `[0.0, 1.0]`.
- **Persistence**: Written to the `detections` table, linked to the `event_id`.

### Stage 3: Unsupervised Anomaly Detection (Isolation Forest)
- **Model**: `IsolationForest` calibrated strictly on baseline benign traffic patterns.
- **Inference**: Measures the isolation path length of the flow vector. Outliers in high-dimensional space receive higher anomaly scores.
- **Output**: Anomaly score scaled to `[0.0, 1.0]`, with an anomaly threshold of `0.55`.
- **Persistence**: Written to the `anomalies` table, linked to the `event_id`.

### Stage 4: Transparent Risk Scoring (0–100 Formula)
- **Objective**: Provide an explainable, auditable risk score rather than an opaque black-box metric.
- **Mathematical Formula**:
  $$\text{Risk Score} = \min(100, (w_1 \cdot C_{\text{ML}} + w_2 \cdot S_{\text{anomaly}} + w_3 \cdot S_{\text{severity}} + w_4 \cdot A_{\text{asset}}) \times 100)$$
  Where:
  - $w_1 = 0.30$ (Supervised ML confidence)
  - $w_2 = 0.25$ (Unsupervised anomaly score)
  - $w_3 = 0.25$ (Event base severity: LOW=0.25, MED=0.50, HIGH=0.75, CRIT=1.00)
  - $w_4 = 0.20$ (Asset criticality: e.g. domain controller = 1.00, prod server = 0.75, workstation = 0.25)
- **Severity Mapping**:
  - `0 - 24`: LOW
  - `25 - 49`: MEDIUM
  - `50 - 74`: HIGH
  - `75 - 100`: CRITICAL

### Stage 5: Deterministic Incident Correlation
- **Mechanism**: Temporal sliding window (default 30 minutes).
- **Correlation Pivots**: Events are grouped into multi-stage attack chains if they share:
  1. Identical `source_ip` (adversary origin), OR
  2. Identical `destination_ip` / `hostname` (target asset), OR
  3. Identical `user` account within the sliding time window.
- **Outcome**: Existing active incident is updated with new events and recalculated max risk score, or a new `Incident` record is created in state `NEW`.

### Stage 6: MITRE ATT&CK Technique Mapping
- **Catalogue**: Seeded Enterprise ATT&CK techniques stored in `mitre_techniques`.
- **Deterministic Association**: Event types and classifications are mapped to specific technique IDs:
  - `port_scan` ➔ **T1046** (Network Service Discovery)
  - `failed_login` / `brute_force` ➔ **T1110** (Brute Force)
  - `successful_login` ➔ **T1078** (Valid Accounts)
  - `sudo_escalation` ➔ **T1068** (Exploitation for Privilege Escalation)
  - `sensitive_data_access` ➔ **T1005** (Data from Local System)
  - `c2_exfiltration` ➔ **T1041** (Exfiltration Over C2 Channel)
- **Persistence**: Recorded in `incident_mitre_mappings`.

### Stage 7: Retrieval-Augmented Generation (pgvector RAG)
- **Embedding Model**: Local `SentenceTransformer('all-MiniLM-L6-v2')` generating 384-dimensional dense vectors.
- **Search Query**: Synthesized from incident title, mapped MITRE technique names, observed event types, and target host.
- **Vector Search**: PostgreSQL query using the pgvector `<=>` cosine distance operator:
  ```sql
  SELECT document_id, title, content, technique_id, source_type,
         1.0 - (embedding <=> :query_vec) AS similarity
  FROM knowledge_embeddings
  ORDER BY embedding <=> :query_vec ASC
  LIMIT 5;
  ```
- **Output**: Top relevant chunks deduplicated by `document_id`, providing official MITRE detection guidance, triage playbooks, and containment procedures.

### Stage 8: Structured AI Investigation (Ollama Llama 3)
- **LLM Engine**: Ollama running locally (`http://localhost:11434`), default model `llama3:latest`.
- **System Prompt**: Enforces strict SOC analyst persona, cautious investigative language ("likely", "evidence suggests"), and JSON schema output.
- **Context Provided**: Incident metadata, chronological event telemetry, XGBoost classification, Isolation Forest score, transparent risk factors, and the retrieved RAG playbooks.
- **Structured Fields**:
  - `incident_summary`
  - `observed_evidence`
  - `likely_attack_pattern`
  - `mitre_techniques`
  - `root_cause_hypothesis`
  - `confidence`
  - `investigation_steps`
  - `prioritized_recommendations`
  - `evidence_references`
  - `analyst_warning`
- **Fallback**: If Ollama is offline or times out, the backend returns status `LLM_UNAVAILABLE` and presents the rule-based investigation. Fallback output is **never** mislabeled as LLM output.

### Stage 9: SOC Analyst Review & Triage
- The human analyst reviews the complete investigation in the Next.js War Room UI (`/incidents/[id]`):
  - Incident header & risk score breakdown
  - Timeline of chronological events
  - Telemetry inspector & flow parameters
  - MITRE ATT&CK technique matrix cards
  - AI Analyst structured findings & RAG citations
- Analyst can transition incident status: `NEW` ➔ `INVESTIGATING`.

### Stage 10: Human-in-the-Loop User Verification
- **Scenario**: When anomalous activity involves valid credentials or unexpected privilege escalation (e.g. `jdoe` executing `sudo su` or logging in from an external IP), the analyst clicks **[Verify User]**.
- **Challenge Creation**:
  - Generates a secure challenge token (UUID) expiring in 15 minutes.
  - Generates a safe, non-technical activity description for the user.
  - Incident transitions to `AWAITING_USER_VERIFICATION`.
- **User Portal**: The user accesses `/verify/[challengeId]` on their device (or via QR code in demo mode).
- **Authentication**: User authenticates (e.g. demo PIN `1234`).
- **User Responses & Outcomes**:
  - **YES, IT WAS ME**:
    - Status transitions to `USER_CONFIRMED`.
    - Incident remains open for analyst review.
    - Analyst options: `[MARK AS LEGITIMATE]` (resolves as authorized) or `[CONTINUE INVESTIGATION]` (flags possible coercion or policy violation).
  - **NO, I DID NOT DO THIS**:
    - Status transitions to `USER_DENIED`.
    - Incident priority/risk auto-escalates to `CRITICAL` (100.0).
    - Platform automatically stages immediate containment recommendations (Revoke Session, Isolate Host).
  - **EXPIRED**:
    - If user does not respond within 15 minutes, challenge expires (`VERIFICATION_EXPIRED`). Analyst is alerted that activity is unverified.

### Stage 11: Controlled Response Containment
- **Safety Policy**: For academic safety, all response actions are **strictly simulated**. No destructive real-world commands are executed against host systems or real firewalls.
- **Available Actions**:
  - `BLOCK_SOURCE_IP`: Simulates edge firewall drop rule.
  - `ISOLATE_HOST`: Simulates endpoint network quarantine.
  - `REVOKE_USER_SESSION`: Simulates identity provider token revocation.
  - `FORENSIC_SNAPSHOT`: Simulates memory/disk capture.
  - `DISABLE_ACCOUNT`: Simulates directory service account lock.
- **Analyst Two-Step Authorization**:
  1. Analyst reviews recommended action and enters rationale.
  2. Modal requires explicit `[CONFIRM ACTION]` or `[CANCEL]`. AI alone cannot execute response actions.
- **Execution**: Status moves from `PENDING` ➔ `EXECUTED`. An immutable response log is recorded.

### Stage 12: Forensic Audit Trail & Incident Resolution
- **Audit Logging**: Every transition, user verification response, and analyst action generates an immutable record in `audit_logs`:
  - `INCIDENT_CREATED`
  - `AI_INVESTIGATION_GENERATED`
  - `VERIFICATION_REQUESTED`
  - `USER_CONFIRMED` / `USER_DENIED`
  - `ANALYST_APPROVED_ACTION`
  - `RESPONSE_EXECUTED`
  - `INCIDENT_RESOLVED`
- **Resolution**: Analyst selects final disposition (`CONFIRMED_INCIDENT`, `FALSE_POSITIVE`, or `RESOLVED`) and enters closing notes. Incident lifecycle is archived.
