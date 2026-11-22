# Aegis One System Architecture Specification
## Autonomous AI Cyber Security War Room

This document provides a comprehensive technical overview of the 12 interconnected subsystems comprising **Aegis One – AI Cyber Security War Room**.

---

## 1. Architectural Topology

```
+---------------------------------------------------------------------------------------------------+
|                                      INGESTION & TELEMETRY LAYER                                   |
|  Syslog, Zeek/Bro NetFlow, Suricata Alerts, CloudTrail JSON, Host Auth Logs, Synthetic Generator  |
+-------------------------------------------------+-------------------------------------------------+
                                                  |
                                                  v
+---------------------------------------------------------------------------------------------------+
|                                    DETECTION & ENSEMBLE ENGINE                                    |
|   +------------------------------------+             +----------------------------------------+   |
|   |   Supervised XGBoost Classifier    |             |   Unsupervised Isolation Forest        |   |
|   |   (Attack Category & Confidence)   |             |   (Outlier Anomaly Score & Deviation)  |   |
|   +-----------------+------------------+             +-------------------+--------------------+   |
|                     |                                                    |                        |
|                     +------------------------+---------------------------+                        |
+----------------------------------------------|----------------------------------------------------+
                                               v
+---------------------------------------------------------------------------------------------------+
|                                  EXPLAINABLE AI (XAI) SUBSYSTEM                                   |
|       * TreeSHAP Local Feature Attribution      * Feature Z-Score Baseline Deviation ($\sigma$)   |
+----------------------------------------------+----------------------------------------------------+
                                               |
                                               v
+---------------------------------------------------------------------------------------------------+
|                               RISK SCORING & INCIDENT CORRELATION                                 |
|  * Multi-Factor Risk Engine (0-100)  * Sliding Window (30m) Entity Clustering (IP, Host, User)   |
+----------------------------------------------+----------------------------------------------------+
                                               |
                                               v
+---------------------------------------------------------------------------------------------------+
|                               MITRE ATT&CK & PGVECTOR RAG RETRIEVAL                               |
|   * MITRE Enterprise Matrix Tactic/Technique Mapping (T1110, T1046, T1498, T1548, T1048)         |
|   * PostgreSQL 16 pgvector Cosine Distance Search (<=>) over SOC Playbooks & Guidelines          |
+----------------------------------------------+----------------------------------------------------+
                                               |
                                               v
+---------------------------------------------------------------------------------------------------+
|                                   AUTONOMOUS AI ANALYST SERVICE                                   |
|   * Structured Context Prompt Synthesis (Telemetry + TreeSHAP + Z-Scores + pgvector Playbooks)    |
|   * Polymorphic Provider Router: Local Ollama (Llama 3 8B) / Hosted APIs (OpenAI, Groq)           |
|   * Pydantic Schema Validation & Fail-Safe Rule-Based Fallback (Zero Disguise Guarantee)         |
+----------------------------------------------+----------------------------------------------------+
                                               |
                                               v
+---------------------------------------------------------------------------------------------------+
|                                   HUMAN-IN-THE-LOOP VERIFICATION                                  |
|   * Out-of-band Portal (/verify/[challengeId]) * 6-Digit PIN Authentication * CONFIRM / DENY      |
|   * Automatic Risk Escalation & Incident State Machine Transition                                 |
+----------------------------------------------+----------------------------------------------------+
                                               |
                                               v
+---------------------------------------------------------------------------------------------------+
|                                  CONTROLLED RESPONSE & REMEDIATION                                |
|   * Dual-Key Analyst Approval Workflow  * Simulated Actions: Block IP, Isolate Host, Revoke Token |
|   * Immutable PostgreSQL Audit Trail Logging                                                      |
+---------------------------------------------------------------------------------------------------+
```

---

## 2. Detailed Subsystem Specifications

### Subsystem 1: Ingestion & Telemetry Normalization
- Converts diverse raw JSON payloads into uniform `SecurityEvent` models.
- Preprocesses network features through `CICIDSPreprocessor` with zero-failure bounds enforcement.

### Subsystem 2: Supervised Threat Classifier (XGBoost)
- Predicts attack class across 6 canonical categories (`BENIGN`, `PortScan`, `DDoS`, `DoS`, `Brute Force`, `Bot`).
- Yields calibrated softmax probability confidence scores.

### Subsystem 3: Unsupervised Anomaly Detector (Isolation Forest)
- Fitted exclusively on normal enterprise baseline traffic.
- Separates statistical novelties with calibrated decision threshold $\tau = 0.430$.

### Subsystem 4: Local Explainable AI Engine (TreeSHAP)
- Computes mathematical feature attributions explaining which telemetry features drove model decisions.
- Computes baseline $z$-score deviations identifying which flow metrics exceeded the normal envelope.

### Subsystem 5: Multi-Factor Risk Scoring Engine
Calculates transparent Composite Risk Scores ($0.0 - 100.0$):
$$\text{Risk Score} = 0.40 \cdot \text{Severity} + 0.35 \cdot \text{XGBoost Conf} + 0.25 \cdot \text{Anomaly Score} + \text{Escalation Bonus}$$

### Subsystem 6: Temporal Incident Correlation
- Employs a 30-minute sliding window.
- Clusters events matching common source IP, target user, or target host into unified `Incident` records.

### Subsystem 7: MITRE ATT&CK Matrix Mapping
- Maps raw detections to official Enterprise ATT&CK techniques (e.g. T1110 Brute Force, T1046 Network Service Discovery).

### Subsystem 8: Vector Knowledge Retrieval (pgvector RAG)
- Uses SentenceTransformers `all-MiniLM-L6-v2` (384 dimensions).
- Performs sub-20ms cosine distance retrieval from PostgreSQL `knowledge_embeddings` table.

### Subsystem 9: Autonomous AI Analyst Service
- Assembles an information-dense prompt combining telemetry, TreeSHAP attributions, and retrieved playbooks.
- Generates structured incident explanations validated via Pydantic schemas.

### Subsystem 10: Polymorphic LLM Router
- Supports offline local inference (`LLM_PROVIDER=ollama`) and cloud inference (`LLM_PROVIDER=openai` or `groq`).
- Enforces strict labeling: `LLM_RAG`, `LLM`, or honest fallback `RULE_BASED` with `LLM_UNAVAILABLE`.

### Subsystem 11: Human-in-the-Loop Identity Verification
- Generates secure challenge tokens (`/verify/{challenge_id}`).
- Users confirm or deny actions with PIN verification. Denials instantly escalate incident risk to CRITICAL.

### Subsystem 12: Controlled Response & Audit Trail
- Enforces state machine transitions: `NEW` $\to$ `INVESTIGATING` $\to$ `AWAITING_USER_VERIFICATION` $\to$ `CONTAINED` $\to$ `RESOLVED`.
- Logs every analyst click, LLM prompt, and containment action into immutable `audit_logs` table.
