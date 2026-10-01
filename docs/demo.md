# Faculty Demonstration Guide & Step-by-Step Script

This document provides a complete, 24-step demonstration script for faculty and evaluators to witness the entire autonomous SOC pipeline:
$$\text{DETECT} \longrightarrow \text{CORRELATE} \longrightarrow \text{MITRE MAP} \longrightarrow \text{RAG RETRIEVE} \longrightarrow \text{AI INVESTIGATE} \longrightarrow \text{SOC REVIEW} \longrightarrow \text{USER VERIFY} \longrightarrow \text{CONTROLLED RESPONSE} \longrightarrow \text{AUDIT} \longrightarrow \text{REPORT}$$

---

## 1. Pre-Flight Verification Checklist

Before inviting faculty to observe, verify that all underlying services are active:

```bash
# 1. Verify PostgreSQL + pgvector is healthy
docker ps | grep warroom-postgres

# 2. Verify Ollama local inference is running with llama3
curl -s http://localhost:11434/api/tags | grep llama3

# 3. Verify knowledge base embeddings are ingested (should return 42 chunks)
PYTHONPATH=. backend/venv/bin/python -c "
from backend.app.database import SessionLocal
from backend.app.models.embedding import KnowledgeEmbedding
db = SessionLocal()
print('Ingested Chunks:', db.query(KnowledgeEmbedding).count())
db.close()
"

# 4. Verify Backend API health
curl -s http://localhost:8000/api/health | jq .status
# Expected: "healthy"

# 5. Verify Frontend is accessible
curl -s http://localhost:3000 | grep -q "AI Cyber Security War Room" && echo "Frontend Ready"
```

---

## 2. Step-by-Step 24-Step Demonstration Script

### Step 1: War Room Dashboard Tour
- **URL**: `http://localhost:3000`
- **Action**: Open the main dashboard in Chrome or Safari.
- **Talking Points**:
  - Point to the live system health indicator in the top right (`All Systems Operational`).
  - Point to the primary metric cards: `Total Events Ingested`, `Correlated Incidents`, `Active Threats`, `Anomalies Flagged`.
  - Highlight the model performance badges: `XGBoost — Development: 99.89%` and `Isolation Forest: Calibrated Baseline`.
  - Point out that there is zero mock data; all charts and tables are wired directly to the PostgreSQL database.

---

### Step 2: Architectural Overview
- **Action**: Briefly show the 11-stage pipeline diagram in `docs/architecture.md`.
- **Talking Points**:
  - Explain that the platform solves the "alert fatigue" problem by correlating isolated raw telemetry events into unified multi-stage attack incidents using temporal sliding windows and MITRE ATT&CK mapping.

---

### Step 3: Trigger the Multi-Stage Attack Scenario
- **Action**: In the top navigation bar, click the red button **[Simulate SOC Attacks]** and select **Run Faculty Demo Attack Sequence** (or dispatch `POST /api/events/simulate-demo-attack`).
- **Talking Points**:
  - This injects a deterministic 7-event multi-stage kill chain representing an external adversary attacking production infrastructure.

---

### Step 4: Observe Event Ingestion & Normalization
- **URL**: `http://localhost:3000` ➔ Scroll to Recent Events (or navigate to `/incidents`).
- **Talking Points**:
  - Show the 7 distinct events ingested in chronological order:
    1. `failed_login`: SSH brute force attempt from `198.51.100.45` to `srv-app-prod01`.
    2. `failed_login`: Second failed attempt.
    3. `successful_login`: Valid authentication for account `jdoe`.
    4. `sudo_escalation`: Execution of `sudo su -` to elevate privileges to root.
    5. `sensitive_data_access`: Querying `/var/data/customers.db`.
    6. `suspicious_connection`: Outbound connection to external C2 `203.0.113.88:4444`.
    7. `c2_exfiltration`: High-volume data egress (45 MB).

---

### Step 5: Supervised Classification & Anomaly Detection
- **Action**: Inspect the telemetry details on the event rows.
- **Talking Points**:
  - Point out the XGBoost classification: `Brute Force` on failed logins, `PortScan` on reconnaissance, and `Bot` on exfiltration.
  - Point out the Isolation Forest anomaly score: Normal logins score ~`0.22`, whereas the off-hours privilege escalation and C2 traffic score ~`0.78` (exceeding the `0.55` contamination threshold).

---

### Step 6: Transparent Risk Scoring
- **Action**: Point to the calculated Risk Score on the resulting incident.
- **Talking Points**:
  - Explain that the risk score is **not** an arbitrary number.
  - Show the transparent mathematical formula:
    $$\text{Risk} = (0.30 \times C_{\text{ML}} + 0.25 \times S_{\text{anomaly}} + 0.25 \times S_{\text{severity}} + 0.20 \times A_{\text{asset}}) \times 100$$
  - Because `srv-app-prod01` is an asset of high criticality (weight 0.75) and multiple critical events occurred, the composite score reaches **92.5 (CRITICAL)**.

---

### Step 7: Incident Correlation
- **URL**: `http://localhost:3000/incidents`
- **Action**: Click on the newly generated incident: `INC-20261001-DEMO` (*Multi-Stage Compromise on srv-app-prod01*).
- **Talking Points**:
  - The correlation engine deterministically grouped all 7 events into a single incident because they occurred within the 30-minute sliding window and shared the same target host (`srv-app-prod01`), user (`jdoe`), and adversary IP (`198.51.100.45`).

---

### Step 8: Incident Details & Timeline
- **URL**: `http://localhost:3000/incidents/[id]`
- **Action**: Walk through the top sections of the Incident Investigation page:
  - Header with Severity badge, Status badge, and Max Risk Score.
  - Downward chronological Attack Timeline showing progression from initial access to exfiltration.
  - Flow Telemetry Inspector showing the underlying 20 network flow metrics.

---

### Step 9: MITRE ATT&CK Mapping
- **Action**: Scroll to the **MITRE ATT&CK Techniques** section on the incident page.
- **Talking Points**:
  - Point to the mapped techniques:
    - **T1110**: Brute Force (Credential Access)
    - **T1078**: Valid Accounts (Defense Evasion / Initial Access)
    - **T1068**: Exploitation for Privilege Escalation (Privilege Escalation)
    - **T1005**: Data from Local System (Collection)
    - **T1041**: Exfiltration Over C2 Channel (Exfiltration)

---

### Step 10: Trigger AI Investigation
- **Action**: Scroll to the **AI Copilot Investigation** section and click **[Generate AI Investigation]**.
- **Talking Points**:
  - Explain that this triggers two distinct AI systems:
    1. A **pgvector semantic similarity search** across the local vector knowledge base.
    2. A **local Ollama LLM** (`llama3:latest`) running directly on the machine's GPU.

---

### Step 11: Real pgvector Semantic Evidence Retrieval
- **Action**: Scroll to the **Retrieved Evidence & Playbooks (pgvector RAG)** section.
- **Talking Points**:
  - Show that the evidence is **not hardcoded**; it was retrieved dynamically from the `knowledge_embeddings` table in PostgreSQL.
  - Point out the cosine similarity scores (e.g. `0.884` for Privilege Escalation, `0.871` for Exfiltration Over C2).
  - Show the source citations (`mitre_attack_corpus.json` and `soc_playbooks.json`).

---

### Step 12: Structured Local LLM Analysis
- **Action**: Inspect the structured response card labeled **LLM_RAG** (or **LLM**).
- **Talking Points**:
  - Emphasize that the LLM output is strictly structured:
    - *Incident Summary*
    - *Observed Evidence*
    - *Likely Attack Pattern*
    - *Root Cause Hypothesis*
    - *Confidence Score* (e.g. 0.95)
    - *Prioritized Recommendations*
  - Emphasize that if Ollama were offline, the system would return `LLM_UNAVAILABLE` and provide the rule-based fallback, with transparent labeling.

---

### Step 13: Initiate Human-in-the-Loop User Verification
- **Action**: Scroll to the **User Verification** card. Point out that the incident involves valid credentials for user `jdoe`.
- **Action**: Click the blue button: **[Verify User Activity]**.
- **Talking Points**:
  - Explain the SOC dilemma: Did employee `jdoe` run maintenance, or was `jdoe` compromised? Rather than guessing, the analyst dispatches a verification challenge.

---

### Step 14: Challenge Creation & Safe Summary
- **Action**: Point out that the incident status has transitioned to `AWAITING_USER_VERIFICATION`.
- **Talking Points**:
  - Show the generated challenge token and safe, non-technical summary:
    > *"Privilege escalation attempt detected on server srv-app-prod01 (originating IP: 198.51.100.45)..."*
  - Point out the 15-minute expiration timer.

---

### Step 15: Open User Verification Portal
- **Action**: Click **[Open Demo User Portal]** (or copy the `/verify/<challengeId>` link into a new tab / phone).
- **Talking Points**:
  - Show the user-facing security verification portal.
  - Explain that this portal is decoupled from the SOC console and is accessible to end-users via SMS, push notification, or email.

---

### Step 16: User Authentication
- **Action**: On the verification page, enter the demo PIN: `1234` and click **Unlock Verification**.
- **Talking Points**:
  - Authentication ensures that an unauthorized party with physical access to the unlocked screen cannot tamper with the response.

---

### Step 17: Demonstrate User Confirmation (Outcome A)
- **Action**: Explain: *"First, let's see what happens if the user confirms: 'Yes, it was me'."*
- **Action**: Click **[YES, IT WAS ME]**.
- **Action**: Return to the Incident Details page and refresh (or observe status update).
- **Talking Points**:
  - Point out that the incident status is now `USER_CONFIRMED`.
  - **Crucial Architectural Point**: The incident **does not automatically close**. An attacker could have coerced the employee.
  - Show the two analyst options: **[Mark as Legitimate]** or **[Continue Investigation]**.

---

### Step 18: Demonstrate User Denial (Outcome B - The Compromise Scenario)
- **Action**: In the demo challenge or a fresh scenario, click **[NO, I DID NOT DO THIS]**.
- **Action**: Return to the Incident Details page.
- **Talking Points**:
  - The status immediately updates to `USER_DENIED`.
  - The incident severity is pinned to **CRITICAL** and risk score is **100.0**.
  - The platform automatically stages urgent containment actions:
    1. `ISOLATE_HOST` for `srv-app-prod01`
    2. `REVOKE_USER_SESSION` for `jdoe`
    3. `BLOCK_SOURCE_IP` for `198.51.100.45`

---

### Step 19: Controlled Response Engine (Analyst-in-the-Loop)
- **Action**: Scroll to the **Controlled Response Actions** section.
- **Talking Points**:
  - Highlight that the AI **cannot** unilaterally execute destructive response actions.
  - All actions require human analyst authorization.
  - Point out that the system operates in **Simulation Mode** for academic safety—no actual local network interfaces or macOS firewalls will be severed.

---

### Step 20: Two-Step Analyst Authorization
- **Action**: On the `ISOLATE_HOST` action row, click **[Execute Action]**.
- **Action**: Review the modal, type analyst rationale: *"Confirmed credential compromise by user denial"*, and click **[Confirm Execution]**.
- **Talking Points**:
  - Show the resulting badge: `EXECUTED` (Simulated).
  - Show the execution log output:
    > `[SIMULATED] Host srv-app-prod01 isolated via EDR agent. All non-management traffic dropped.`

---

### Step 21: Verify Immutable Audit Trail
- **Action**: Scroll to the **Audit Trail & Timeline** section at the bottom of the incident page.
- **Talking Points**:
  - Walk faculty through the chronological, tamper-evident audit records:
    1. `INCIDENT_CREATED` (Automated Correlation Engine)
    2. `AI_INVESTIGATION_GENERATED` (pgvector RAG + Ollama)
    3. `VERIFICATION_REQUESTED` (Analyst `soc_analyst`)
    4. `USER_DENIED` (User `jdoe` via verification portal)
    5. `ANALYST_APPROVED_ACTION` (`ISOLATE_HOST`)
    6. `RESPONSE_EXECUTED` (Controlled Response Engine)

---

### Step 22: Analyst Resolution Decision
- **Action**: In the **Analyst Decision** panel, select `CONTAINED` (or `RESOLVED`), enter closing remarks: *"Attacker blocked, host isolated, identity revoked. Forensic snapshot captured for investigation."*, and click **[Record Decision]**.
- **Talking Points**:
  - The incident state machine updates the record to `CONTAINED`. The incident is successfully handled.

---

### Step 23: Explore Attack Topology Graph
- **URL**: `http://localhost:3000/attack-graph`
- **Action**: Navigate to the Attack Graph page.
- **Talking Points**:
  - Show the interactive React Flow graph visualizing:
    - Adversary IP node (`198.51.100.45`)
    - Incident node (`INC-20261001-DEMO`)
    - Target host node (`srv-app-prod01`)
    - Compromised user node (`jdoe`)
    - Connected MITRE technique nodes (`T1110`, `T1078`, `T1068`, `T1005`, `T1041`)
  - Demonstrate dragging nodes and inspecting properties.

---

### Step 24: Compliance & Post-Incident Report Export
- **URL**: `http://localhost:3000/reports`
- **Action**: Navigate to the Reports tab.
- **Talking Points**:
  - Show the auto-generated Post-Incident Forensic Report for `INC-20261001-DEMO`.
  - Highlight the included sections: Executive Summary, Chronological Timeline, Technical Indicators of Compromise (IoCs), User Verification Logs, Response Execution History, and Regulatory Compliance Audit Trail.
  - Demonstrate clicking **[Print / Export PDF]**.
