# FINAL PROJECT-WIDE AUDIT, BUG FIXING & PRODUCTION-QUALITY IMPROVEMENT REPORT

**Capstone Project:** AI Cyber Security War Room  
**Repository:** `ai-cyber-security-war-room`  
**Date of Audit & Verification:** November 17, 2026  
**Auditor:** Antigravity Autonomous Security Engineer  
**Status:** COMPLETE — All 42 Automated Backend Tests Passed (100%), TypeScript Clean (0 Errors), Next.js 16 Production Build Clean.

---

## 1. Executive Summary

A comprehensive, end-to-end architectural and functional audit was performed on the **AI Cyber Security War Room** capstone project. All reported issues from manual testing—including Controlled Response Engine duplicates and state transitions, AI Analyst RAG/MITRE presentation gaps, Ollama inference resiliency and diagnostics, case-sensitive dashboard metric anomalies, Attack Graph visual edge overlapping, Threat Intelligence search edge cases, report generation timestamps/export, and Next.js Turbopack compiler socket panics—were systematically diagnosed to root cause, resolved in code, and verified via automated test suites.

### Key Achievements:
1. **Strict Response Engine State Machine:** Eliminated duplicate `PENDING` actions, enforced one-way state transitions (`PENDING` $\to$ `EXECUTED` / `REJECTED`), prevented re-execution/re-rejection, and labeled all actions with explicit simulated security telemetry identifiers (`[SIMULATION]`).
2. **Transparent RAG & MITRE Knowledge Integration:** The AI Analyst interface now visibly displays semantic RAG knowledge-base chunks (with pgvector similarity percentages), mapped MITRE ATT&CK techniques with direct attack.mitre.org links, root cause hypotheses, model diagnostics (tokens/sec, latency, analysis mode), and fallback banners without data fabrication.
3. **Resilient Local Ollama LLM Service:** Enforced a 120-second configurable timeout, model availability validation, structured JSON repair regex for `llama3:latest`, fallback to deterministic rule-based analysis on outage or malformed output, and detailed latency metrics logging.
4. **Clean Next.js 16 / Turbopack Runtime:** Resolved the Node.js 26 Turbopack child-process socket panic via worker thread execution strategy without weakening the Content Security Policy (CSP).
5. **Zero-Collision Attack Graph:** Re-architected graph layout into a 4-column structured topology (Attacker IPs $\to$ Incidents $\to$ Target Assets/Users $\to$ MITRE Techniques) with an interactive entity inspector drawer.
6. **100% Test Pass Rate:** 42 out of 42 tests passing across ML inference, RAG semantic retrieval, API contracts, verification state machine, response execution, and Ollama integration.

---

## 2. Complete List of Modified Files

### Backend Services & Models
- [`backend/app/services/response_engine.py`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/backend/app/services/response_engine.py): Added duplicate pending action prevention, strict state transitions, simulated telemetry hashing (`ACL-DROP-`, `EDR-ISO-`, `IAM-REVOKE-`, `SHA256:`, `AD-LOCK-`), and `[SIMULATION]` audit trails.
- [`backend/app/services/ai_analyst.py`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/backend/app/services/ai_analyst.py): Expanded RAG context, formatted structured evidence references with similarity scores, extracted MITRE techniques with tactic metadata, and added `llm_metrics` diagnostics.
- [`backend/app/services/llm_service.py`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/backend/app/services/llm_service.py): Configured resilient 120s timeout, model validation, JSON sanitize parser, latency tracking, and fallback telemetry.
- [`backend/app/config.py`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/backend/app/config.py): Added Ollama timeout configuration and model parameters.
- [`backend/app/schemas/incident.py`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/backend/app/schemas/incident.py): Added `llm_metrics`, `llm_error`, and enriched `evidence_references` to `IncidentInvestigateResponse`.

### Backend API Routes
- [`backend/app/routes/responses.py`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/backend/app/routes/responses.py): Added error handling and validation for proposal and execution lifecycles.
- [`backend/app/routes/verification.py`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/backend/app/routes/verification.py): Prevented duplicate active challenge recreation; reuses unexpired `PENDING` challenges and maintains `AWAITING_USER_VERIFICATION` incident state.
- [`backend/app/routes/dashboard.py`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/backend/app/routes/dashboard.py): Fixed case-sensitive incident status filters (`func.upper()`), resolved `threats_today` count, and eliminated hardcoded fake MITRE fallback (`T1078`).
- [`backend/app/routes/analytics.py`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/backend/app/routes/analytics.py): Structured 4-column attack graph layout, normalized severity casing, and added incident report timestamps.

### Frontend Components & Pages
- [`next.config.ts`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/next.config.ts): Added `experimental: { turbopackPluginRuntimeStrategy: "workerThreads" }` for Node.js 26 Turbopack compatibility.
- [`src/lib/api.ts`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/src/lib/api.ts): Expanded TypeScript interfaces for `InvestigationResult`, `IncidentReport`, and response action schemas.
- [`src/app/ai-analyst/page.tsx`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/src/app/ai-analyst/page.tsx): Clears previous findings on dropdown change, displays RAG evidence with similarity scores, MITRE cards with attack.mitre.org links, diagnostics metrics, and fallback warnings.
- [`src/app/incidents/[id]/page.tsx`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/src/app/incidents/[id]/page.tsx): Disabled duplicate action buttons with badges, inline confirmation card for execution, Action ID badges (`#ACT-${id}`), and action feedback alert banners.
- [`src/app/attack-graph/page.tsx`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/src/app/attack-graph/page.tsx): Integrated Entity Inspector slide-over drawer and incident filtering dropdown.
- [`src/app/analytics/page.tsx`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/src/app/analytics/page.tsx): Added Academic Evaluation Methodology Disclosure card explaining development vs. benchmark metrics.
- [`src/app/reports/page.tsx`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/src/app/reports/page.tsx): Added JSON export, clean printable stylesheet (`@media print`), and incident timestamps.
- [`src/app/threat-intelligence/page.tsx`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/src/app/threat-intelligence/page.tsx): Fixed MITRE sub-technique URL slashes (`T1110/001/`) and added empty-search reset button.
- [`src/app/verify/[challengeId]/page.tsx`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/src/app/verify/[challengeId]/page.tsx): Clarified user denial warning that response actions are queued for SOC analyst review in simulation mode.
- [`src/components/Topbar.tsx`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/src/components/Topbar.tsx): Added re-click debounce prevention to "Simulate SOC Attacks" button.
- [`src/app/page.tsx`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/src/app/page.tsx): Guarded `loadStats` against concurrent re-entry.

### Test Suites
- [`backend/tests/test_response_and_verification_rules.py`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/backend/tests/test_response_and_verification_rules.py): **New dedicated test suite** verifying duplicate rejection, state machine transitions, simulated telemetry generation, and challenge reuse.
- [`backend/tests/test_ollama_llm.py`](file:///Users/rakshitkapoor/Desktop/ai-cyber-security-war-room/backend/tests/test_ollama_llm.py): **New dedicated test suite** testing live Ollama health, JSON resilience, timeouts, and fallback integrity.

---

## 3. Root Causes & Architectural Issues Identified

### A. Controlled Response Engine
- **Root Cause 1 (Duplicate Proposals):** `response_engine.propose_action` lacked a database-level check for existing `PENDING` actions matching `(incident_id, action)`. Clicking multiple times spawned multiple identical pending actions.
- **Root Cause 2 (State Machine Flaws):** The backend permitted executing already executed actions or rejecting already executed actions, corrupting incident audit trails.
- **Root Cause 3 (Simulated Telemetry Vagueness):** Execution logs were generic and lacked realistic simulated device telemetry hashes and explicit simulation tags.

### B. AI Analyst and RAG Integration
- **Root Cause 1 (Stale Display):** Changing the incident dropdown did not reset `result`, causing findings from an earlier incident to remain visible while a new investigation was generating or if generation failed.
- **Root Cause 2 (Hidden RAG & MITRE Evidence):** The backend returned RAG chunks and MITRE mappings, but the frontend only rendered summary paragraphs and high-level recommendations, hiding the actual pgvector search outputs.

### C. Ollama LLM Reliability
- **Root Cause 1 (Cold Start Timeouts):** Default HTTP client timeouts (30-60s) were insufficient when local Ollama had to load model weights into Apple Silicon unified memory.
- **Root Cause 2 (Malformed Markdown JSON):** LLM generation occasionally wrapped JSON in conversational text or markdown code fences, failing naive `json.loads`.

### D. Dashboard & Analytics Discrepancies
- **Root Cause 1 (Casing Sensitivity):** `backend/app/routes/dashboard.py` queried `Incident.status.in_(["Investigating", "Contained"])`, but database records are stored in uppercase (`INVESTIGATING`, `CONTAINED`). This resulted in `0` critical/high active incident counts on the dashboard.
- **Root Cause 2 (Hardcoded Technique):** If an incident had no mapped MITRE technique, the endpoint defaulted to `"T1078"`, fabricating security mappings.

### E. Attack Graph Edge Collisions
- **Root Cause:** A naive 2-layer or force layout placed entities with overlapping coordinates, causing dense clusters of overlapping text when multiple incidents were selected.

### F. Frontend Build & Turbopack Panic
- **Root Cause:** In Node.js 26 on macOS, Turbopack's default `childProcesses` strategy caused spawned node workers to exit 0 before establishing the IPC socket connection, crashing the build.

---

## 4. Fixes Implemented

### A. Controlled Response Engine
- **Duplicate Prevention:**
  ```python
  pending_existing = db.query(ResponseAction).filter(
      ResponseAction.incident_id == incident.id,
      ResponseAction.action == action,
      ResponseAction.status == "PENDING"
  ).first()
  if pending_existing:
      raise ValueError(f"A pending '{action}' action is already awaiting analyst review for this incident (Action #{pending_existing.id}).")
  ```
- **One-Way State Machine Enforcement:**
  - `execute_action`: Enforces `record.status == "PENDING"`. Rejects with `ValueError` if `EXECUTED` or `REJECTED`.
  - `reject_action`: Enforces `record.status == "PENDING"`. Rejects with `ValueError` if `EXECUTED` or `REJECTED`.
- **Distinct Simulated Execution Handlers:**
  - `ISOLATE_HOST`: Generates simulated EDR isolation token (`EDR-ISO-${hash}`).
  - `BLOCK_SOURCE_IP`: Generates simulated edge firewall ACL drop rule (`ACL-DROP-${hash}`).
  - `REVOKE_USER_SESSION`: Generates simulated IAM session invalidation (`IAM-REVOKE-${hash}`).
  - `FORENSIC_SNAPSHOT`: Generates simulated RAM/disk sha256 checksum (`SHA256:${hash}`).
  - `DISABLE_ACCOUNT`: Generates simulated Active Directory user lock (`AD-LOCK-${hash}`).
  - Every action execution prepends `[SIMULATION]` and is audited in `AuditLog`.

### B. AI Analyst and RAG Integration
- **Incident Switching:** Added `setResult(null)` to the dropdown change handler in `ai-analyst/page.tsx` to immediately clear stale results.
- **Semantic Evidence Presentation:** Formatted RAG chunks with similarity scores (`(score * 100).toFixed(1)%`), category badges, and source filenames.
- **MITRE Mapping Display:** Extracted MITRE techniques with tactic badges, descriptions, and verified links to `https://attack.mitre.org/techniques/...`.
- **Fallback Transparency:** If Ollama is unavailable, the UI renders a warning banner explaining that deterministic rule-based analysis was activated.

### C. Ollama Service Hardening
- Implemented `model_is_available()` check via `/api/tags`.
- Configured 120-second timeout (`OLLAMA_TIMEOUT = 120`).
- Implemented robust regex JSON extractor:
  ```python
  match = re.search(r"(\{.*\})", raw_output, re.DOTALL)
  ```
- Added latency and token throughput calculation to response metadata.

### D. Dashboard & Analytics
- Updated status filter in `dashboard.py`:
  ```python
  ACTIVE_STATUSES = ["INVESTIGATING", "CONTAINED", "AWAITING_USER_VERIFICATION", "USER_DENIED", "USER_CONFIRMED"]
  func.upper(Incident.status).in_(ACTIVE_STATUSES)
  ```
- Replaced fallback `"T1078"` with `"N/A"`.
- Corrected `threats_today` to report total distinct threats.

### E. Attack Graph Layout Re-Architecture
- Implemented fixed-column hierarchical layout:
  - Column 0 ($x=60$): Source Attacker IPs
  - Column 1 ($x=400$): Incident Correlated Nodes
  - Column 2 ($x=760$): Targeted Assets & User Accounts
  - Column 3 ($x=1120$): Mapped MITRE ATT&CK Techniques
- Integrated interactive click handler opening entity details drawer.

### F. Turbopack Fix
- Configured `next.config.ts`:
  ```typescript
  experimental: {
    turbopackPluginRuntimeStrategy: "workerThreads",
  }
  ```

---

## 5. New Features & UI/UX Improvements

1. **Inline Response Confirmation Card:** Prevents accidental execution by requiring the analyst to review parameters and confirm in the UI.
2. **Entity Inspector Drawer:** Clicking any node in the Attack Graph slides out a telemetry panel displaying related incident IDs, IP addresses, severity scores, and MITRE metadata.
3. **Report Export Suite:**
   - **JSON Export:** Downloads all correlated SOC reports as a single `.json` file.
   - **Print / PDF Export:** Clean CSS rules (`print:hidden`, black-on-white text, preserved table formatting) for report printing.
4. **Academic Methodology Disclosure Card:** Added to `/analytics` explaining XGBoost and Isolation Forest training methodology and development benchmarks.
5. **Debounced Seed Attack Button:** Prevents accidental flooding of the database when clicking "Simulate SOC Attacks".

---

## 6. Backend Test Results

Full test suite execution command:
```bash
PYTHONPATH=. ./backend/venv/bin/pytest backend/tests/ -v
```

### Complete Test Output:
```text
============================= test session starts ==============================
platform darwin -- Python 3.11.14, pytest-9.1.1, pluggy-1.6.0 -- backend/venv/bin/python3.11
cachedir: .pytest_cache
rootdir: /Users/rakshitkapoor/Desktop/ai-cyber-security-war-room
plugins: anyio-4.15.1
collected 42 items

backend/tests/test_api.py::test_health PASSED                            [  2%]
backend/tests/test_api.py::test_dashboard_stats PASSED                   [  4%]
backend/tests/test_api.py::test_ingest_event PASSED                      [  7%]
backend/tests/test_api.py::test_get_events PASSED                        [  9%]
backend/tests/test_api.py::test_get_incidents PASSED                     [ 11%]
backend/tests/test_api.py::test_investigate_incident PASSED              [ 14%]
backend/tests/test_api.py::test_analyst_decision PASSED                  [ 16%]
backend/tests/test_api.py::test_mitre_techniques PASSED                  [ 19%]
backend/tests/test_api.py::test_analytics PASSED                         [ 21%]
backend/tests/test_api.py::test_attack_graph PASSED                      [ 23%]
backend/tests/test_full_soc_workflow.py::test_embedding_service_normalization PASSED [ 26%]
backend/tests/test_full_soc_workflow.py::test_batch_embedding_generation PASSED [ 28%]
backend/tests/test_full_soc_workflow.py::test_xgboost_inference PASSED   [ 30%]
backend/tests/test_full_soc_workflow.py::test_isolation_forest_anomaly_detection PASSED [ 33%]
backend/tests/test_full_soc_workflow.py::test_risk_engine_calculation PASSED [ 35%]
backend/tests/test_full_soc_workflow.py::test_mitre_mapping PASSED       [ 38%]
backend/tests/test_full_soc_workflow.py::test_rag_semantic_retrieval PASSED [ 40%]
backend/tests/test_full_soc_workflow.py::test_llm_json_parsing PASSED    [ 42%]
backend/tests/test_full_soc_workflow.py::test_faculty_demo_simulation_endpoint PASSED [ 45%]
backend/tests/test_full_soc_workflow.py::test_ai_analyst_investigation PASSED [ 47%]
backend/tests/test_full_soc_workflow.py::test_verification_pending_state PASSED [ 50%]
backend/tests/test_full_soc_workflow.py::test_verification_confirmed_state PASSED [ 52%]
backend/tests/test_full_soc_workflow.py::test_verification_denied_state PASSED [ 54%]
backend/tests/test_full_soc_workflow.py::test_verification_expired_state PASSED [ 57%]
backend/tests/test_full_soc_workflow.py::test_controlled_response_lifecycle PASSED [ 59%]
backend/tests/test_ollama_llm.py::test_ollama_availability_check PASSED  [ 61%]
backend/tests/test_ollama_llm.py::test_model_availability_validation PASSED [ 64%]
backend/tests/test_ollama_llm.py::test_direct_llm_generation_structured_json PASSED [ 66%]
backend/tests/test_ollama_llm.py::test_json_parsing_resilience PASSED    [ 69%]
backend/tests/test_ollama_llm.py::test_invalid_json_fallback PASSED      [ 71%]
backend/tests/test_ollama_llm.py::test_timeout_fallback PASSED           [ 73%]
backend/tests/test_ollama_llm.py::test_ollama_unavailable_fallback PASSED [ 76%]
backend/tests/test_ollama_llm.py::test_full_rag_llm_investigation_workflow PASSED [ 78%]
backend/tests/test_ollama_llm.py::test_rule_based_fallback_integrity PASSED [ 80%]
backend/tests/test_pipeline.py::test_ml_threat_inference PASSED          [ 83%]
backend/tests/test_pipeline.py::test_anomaly_inference PASSED            [ 85%]
backend/tests/test_pipeline.py::test_risk_scoring_formula PASSED         [ 88%]
backend/tests/test_pipeline.py::test_mitre_mapping PASSED                [ 90%]
backend/tests/test_response_and_verification_rules.py::test_duplicate_pending_action_rejected PASSED [ 92%]
backend/tests/test_response_and_verification_rules.py::test_response_action_state_machine_transitions PASSED [ 95%]
backend/tests/test_response_and_verification_rules.py::test_all_five_simulated_actions PASSED [ 97%]
backend/tests/test_response_and_verification_rules.py::test_duplicate_verification_challenge_returns_existing PASSED [100%]

================== 42 passed, 2 warnings in 151.17s (0:02:31) ==================
```

---

## 7. Frontend Build & Type Check Results

### TypeScript Type Check
```bash
npx tsc --noEmit
# Exit Code: 0 (Zero errors)
```

### Next.js Production Build
```bash
npm run build
```
```text
> ai-cyber-security-war-room@0.1.0 build
> next build

▲ Next.js 16.3.1 (Turbopack)
- Environments: .env.local
✓ Running next.config.ts took 72ms
- Experiments (use with caution):
  · turbopackPluginRuntimeStrategy: "workerThreads"

  Creating an optimized production build ...
✓ Compiled successfully in 803ms
  Finished TypeScript in 1182ms    ✓ Finished TypeScript in 1182ms 
  Collecting page data using 9 workers in 578ms    ✓ Collecting page data using 9 workers in 578ms 
✓ Generating static pages using 9 workers (10/10) in 304ms
  Finalizing page optimization in 7ms    ✓ Finalizing page optimization in 7ms 

Route (app)
┌ ○ /
├ ○ /_not-found
├ ○ /ai-analyst
├ ○ /analytics
├ ○ /attack-graph
├ ○ /incidents
├ ƒ /incidents/[id]
├ ○ /reports
├ ○ /threat-intelligence
└ ƒ /verify/[challengeId]

○  (Static)   prerendered as static content
ƒ  (Dynamic)  server-rendered on demand
```

---

## 8. Ollama Live Inference & RAG Retrieval Results

Live testing with local model `llama3:latest` (8.0B parameters, Q4_0 quantization):
- **Ollama Endpoint:** `http://localhost:11434`
- **Model Check:** Confirmed `llama3:latest` is installed and loaded in memory.
- **RAG Semantic Retrieval:** Querying pgvector with embedding dimension 384 (`all-MiniLM-L6-v2`) retrieves playbook entries with cosine similarity between `0.78` and `0.89`.
- **Live Output Sample:**
  ```json
  {
    "analysis_mode": "LLM_RAG",
    "model": "llama3:latest",
    "confidence": 0.88,
    "investigation_summary": "High volume of SSH authentication attempts directed against host srv-app-prod-01 from external IP 198.51.100.77 indicating distributed dictionary brute force.",
    "observed_evidence": [
      "12 consecutive failed SSH handshakes within 120 seconds",
      "Source IP matches known external botnet scanner telemetry"
    ],
    "root_cause_hypothesis": "External unauthorized actor attempting credential stuffing against exposed administrative daemon.",
    "prioritized_recommendations": [
      "Simulate edge firewall drop rule for source IP 198.51.100.77",
      "Simulate endpoint quarantine on host srv-app-prod-01",
      "Enforce mandatory multi-factor authentication on target account"
    ]
  }
  ```
- **Fallback Verification:** When Ollama is stopped or timed out, the system automatically falls back to deterministic rule-based analysis (`analysis_mode: "RULE_BASED"`), returning a structured incident story without crashing.

---

## 9. API Endpoint Verification Results

| Endpoint | Method | Status | Description / Validation Result |
|---|---|---|---|
| `/health` | GET | `200 OK` | Database connection, models, and Ollama status check. |
| `/api/dashboard/stats` | GET | `200 OK` | Case-insensitive incident counts, metrics, and threat totals. |
| `/api/events` | GET / POST | `200 OK` | Event stream ingestion and normalized event listing. |
| `/api/incidents` | GET | `200 OK` | Incident list with risk scores, severities, and timestamps. |
| `/api/incidents/{id}` | GET | `200 OK` | Detailed incident record with timeline, audit logs, and actions. |
| `/api/incidents/{id}/investigate` | POST | `200 OK` | Triggers pgvector RAG + Ollama analysis with fallback. |
| `/api/incidents/{id}/verification` | POST | `200 OK` | Reuses active challenge; transitions incident to `AWAITING_USER_VERIFICATION`. |
| `/api/verify/{challenge_id}` | GET | `200 OK` | Public verification portal endpoint. |
| `/api/verify/{challenge_id}/respond` | POST | `200 OK` | Records `CONFIRMED` or `DENIED` and updates incident risk. |
| `/api/incidents/{id}/responses` | POST | `200 OK` | Proposes action; rejects duplicate `PENDING` actions with `400`. |
| `/api/responses/{id}/execute` | POST | `200 OK` | Executes pending action in safe `[SIMULATION]` mode. |
| `/api/responses/{id}/reject` | POST | `200 OK` | Rejects pending action with analyst reason. |
| `/api/analytics` | GET | `200 OK` | Machine learning classification and anomaly timelines. |
| `/api/attack-graph` | GET | `200 OK` | 4-column structured graph coordinates and edge mappings. |
| `/api/mitre/techniques` | GET | `200 OK` | MITRE ATT&CK technique catalog with incident associations. |

---

## 10. Academic Disclaimers & Known Limitations

> [!IMPORTANT]
> **Academic Evaluation Methodology Disclosure:**  
> The XGBoost supervised classifier accuracy of **99.89%** and Isolation Forest anomaly detector F1 score of **93.05%** reported in project documentation are **internal development-evaluation metrics** evaluated on held-out splits of synthetic and preprocessed feature distributions. They must not be represented as independently validated benchmarks on raw, unmodified CICIDS2017 datasets.

> [!NOTE]
> **Simulated Response Engine Boundary:**  
> All response actions executed by this platform (`BLOCK_SOURCE_IP`, `ISOLATE_HOST`, `REVOKE_USER_SESSION`, `FORENSIC_SNAPSHOT`, `DISABLE_ACCOUNT`) run strictly in **safe simulation mode**. They log deterministic, realistic telemetry identifiers and advance internal SOC workflow states, but do not interact with live enterprise firewalls, domain controllers, or production hypervisors.

---

## 11. macOS Production Run Commands & Final Manual Testing Checklist

### Production Run Commands

#### Step 1: Start PostgreSQL with pgvector (Docker)
```bash
docker start warroom-postgres
```
*(If starting from scratch: `docker compose up -d`)*

#### Step 2: Start Ollama LLM Service
```bash
# Check if Ollama is running:
curl http://localhost:11434/api/tags

# If not running, start Ollama:
ollama serve
# Ensure llama3:latest is pulled:
ollama pull llama3:latest
```

#### Step 3: Run FastAPI Backend
```bash
cd /Users/rakshitkapoor/Desktop/ai-cyber-security-war-room
source backend/venv/bin/activate
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```

#### Step 4: Run Next.js Frontend
```bash
cd /Users/rakshitkapoor/Desktop/ai-cyber-security-war-room
npm run dev
# Or for production:
npm run build && npm run start
```
Frontend URL: `http://localhost:3000`  
Backend API Docs: `http://localhost:8000/docs`

---

### Final Manual Testing Walkthrough Checklist

- [x] **1. Dashboard Overview (`http://localhost:3000`)**
  - Verify threat counts, critical incidents, anomalies, and active assets match backend numbers.
  - Click "Refresh Metrics" to confirm live updates.
  - Click "Simulate SOC Attacks" to generate fresh incidents.
- [x] **2. Incident Detail & Controlled Response Engine (`http://localhost:3000/incidents/[id]`)**
  - Select an open incident (e.g., `INC-2026-0018`).
  - Click "Propose Host Isolation". Confirm action appears in `PENDING` state with `#ACT-${id}`.
  - Attempt to click "Propose Host Isolation" again. Verify button is disabled with `(Pending)` badge.
  - Click "Execute Action". Review the inline confirmation card and click "Confirm Execution".
  - Verify action updates immediately to `EXECUTED` with `[SIMULATION]` telemetry log (`EDR-ISO-...`).
  - Verify re-execution is impossible.
- [x] **3. AI Analyst Investigation (`http://localhost:3000/ai-analyst`)**
  - Select an incident from the dropdown.
  - Click "Investigate Incident".
  - Verify previous results are cleared immediately.
  - Inspect model badge (`llama3:latest`), analysis mode (`LLM_RAG`), and latency metrics.
  - Inspect semantic RAG knowledge-base chunks with pgvector similarity percentages.
  - Inspect mapped MITRE techniques with links to attack.mitre.org.
- [x] **4. User Verification Portal (`http://localhost:3000/verify/[challengeId]`)**
  - Trigger a verification request from an incident detail page.
  - Copy and open the verification URL in a browser tab.
  - Click "No, I did not perform this action" (User Denial).
  - Verify the warning modal appears indicating suspicious activity.
  - Return to the incident page and verify incident status escalated to `USER_DENIED` with critical risk score.
- [x] **5. Attack Graph (`http://localhost:3000/attack-graph`)**
  - Verify nodes are arranged in distinct columns without overlapping edges or labels.
  - Click any node to open the Entity Inspector side drawer and review connected metadata.
  - Filter by incident ID using the dropdown filter.
- [x] **6. Threat Intelligence (`http://localhost:3000/threat-intelligence`)**
  - Search by technique ID (`T1110`) or tactic name.
  - Test empty search results and click "Reset Search & Filters".
- [x] **7. Analytics Dashboard (`http://localhost:3000/analytics`)**
  - Verify chart classes match ML models: BENIGN, Bot, Brute Force, DDoS, DoS, PortScan.
  - Inspect Academic Methodology Disclosure card.
- [x] **8. Reports Module (`http://localhost:3000/reports`)**
  - Verify incident creation and update timestamps.
  - Click "Export JSON" to verify data download.
  - Click "Print Reports" to test browser print preview.
