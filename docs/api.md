# API Reference Documentation

Base URL: `http://localhost:8000`
Interactive Swagger / OpenAPI Docs: `http://localhost:8000/docs`

---

## 1. System Health & Status

### `GET /api/health`
Retrieves the operational status of database connectivity, ML models, and subsystem readiness.

#### Response (`200 OK`):
```json
{
  "status": "healthy",
  "database": "connected",
  "pgvector": "enabled",
  "models": {
    "xgboost": "loaded",
    "isolation_forest": "loaded",
    "embedding_service": "loaded"
  },
  "ollama": {
    "status": "available",
    "model": "llama3:latest",
    "base_url": "http://localhost:11434"
  },
  "timestamp": "2026-10-01T14:30:00Z"
}
```

---

## 2. Dashboard Analytics

### `GET /api/dashboard/stats`
Returns aggregated high-level security metrics, attack distribution, and time-series telemetry.

#### Response (`200 OK`):
```json
{
  "total_events": 154,
  "total_incidents": 4,
  "critical_incidents": 1,
  "high_incidents": 2,
  "medium_incidents": 1,
  "low_incidents": 0,
  "active_threats": 2,
  "anomalies_detected": 18,
  "system_status": "MONITORING",
  "recent_timeline": [
    {
      "timestamp": "2026-10-01T14:00:00Z",
      "threats": 4,
      "anomalies": 2
    }
  ]
}
```

---

## 3. Security Events & Telemetry

### `GET /api/events`
Returns a paginated list of security events with attached XGBoost detections and Isolation Forest anomaly scores.
- Query Parameters:
  - `skip` (int, default: 0)
  - `limit` (int, default: 50)
  - `severity` (string, optional)
  - `event_type` (string, optional)

### `GET /api/events/{id}`
Returns full telemetry details, flow parameters, and ML inferences for a single event.

### `POST /api/events`
Ingests a single raw security event, applies XGBoost classification and Isolation Forest anomaly scoring, computes the risk score, correlates with active incidents, and maps MITRE techniques.

#### Request Body:
```json
{
  "timestamp": "2026-10-01T14:15:00Z",
  "source_ip": "198.51.100.45",
  "destination_ip": "10.0.0.15",
  "source_port": 54122,
  "destination_port": 22,
  "protocol": "TCP",
  "user": "jdoe",
  "hostname": "srv-app-prod01",
  "event_type": "failed_login",
  "severity": "HIGH",
  "raw_data": {
    "Destination Port": 22,
    "Flow Duration": 45000,
    "Total Fwd Packets": 12,
    "Total Backward Packets": 10,
    "Total Length of Fwd Packets": 1500,
    "Total Length of Bwd Packets": 2000,
    "Fwd Packet Length Mean": 125.0,
    "Bwd Packet Length Mean": 200.0,
    "Flow Bytes/s": 77777.7,
    "Flow Packets/s": 488.8,
    "Flow IAT Mean": 2142.8,
    "Flow IAT Std": 500.0,
    "Fwd Header Length": 384,
    "Bwd Header Length": 320,
    "Packet Length Mean": 159.0,
    "Packet Length Std": 85.0,
    "SYN Flag Count": 1,
    "ACK Flag Count": 1,
    "Average Packet Size": 165.0,
    "Init_Win_bytes_forward": 29200
  }
}
```

### `POST /api/events/bulk`
Ingests an array of security events in a single batch.

### `POST /api/events/simulate-demo-attack`
Injects the deterministic 7-event multi-stage faculty demonstration scenario (`198.51.100.45` targeting `srv-app-prod01` and user `jdoe`).

#### Response (`200 OK`):
```json
{
  "message": "Faculty demo attack sequence generated and ingested successfully",
  "incident_id": "INC-20261001-DEMO",
  "events_ingested": 7,
  "correlated_incident_id": "3f829a...",
  "risk_score": 92.5
}
```

### `POST /api/events/synthetic/seed`
Seeds 3 synthetic SOC multi-stage scenarios into the database (Brute Force to Exfiltration, Port Scan to Process Injection, Unusual Login to Privilege Escalation).

---

## 4. Correlated Incidents & AI Investigation

### `GET /api/incidents`
Lists all multi-stage incidents with aggregated risk scores, status, and event counts.

### `GET /api/incidents/{id}`
Returns complete incident context:
- Incident metadata & status
- Chronological event timeline
- Correlated security events with flow metrics
- Mapped MITRE ATT&CK techniques
- Existing AI investigation report
- Active user verification status
- Staged response actions
- Associated audit log history

### `POST /api/incidents/{id}/investigate`
Triggers an autonomous investigation using the local RAG knowledge base (pgvector) and local Ollama LLM (Llama 3).

#### Response (`200 OK`):
```json
{
  "incident_id": "INC-20261001-DEMO",
  "analysis_method": "LLM_RAG",
  "investigation": {
    "incident_summary": "Multi-stage attack involving credential brute forcing, privilege escalation, and data exfiltration.",
    "observed_evidence": [
      "Multiple failed SSH logins from 198.51.100.45 followed by authentication success.",
      "Privilege escalation via sudo su by user jdoe on srv-app-prod01.",
      "Suspicious outbound C2 beaconing on port 4444."
    ],
    "likely_attack_pattern": "External Credential Access followed by Host Privilege Escalation and Exfiltration",
    "mitre_techniques": ["T1110", "T1078", "T1068", "T1005", "T1041"],
    "root_cause_hypothesis": "Compromised SSH credentials for account jdoe.",
    "confidence": 0.95,
    "investigation_steps": [
      "Verify whether user jdoe authorized the privilege escalation.",
      "Inspect network egress logs for destination IP 203.0.113.88."
    ],
    "prioritized_recommendations": [
      "Isolate host srv-app-prod01 immediately.",
      "Revoke active sessions and force password reset for user jdoe.",
      "Block adversary IP 198.51.100.45 at the perimeter firewall."
    ],
    "evidence_references": [
      "DOC-MITRE-T1068: Exploitation for Privilege Escalation",
      "PLAYBOOK-PRIV-ESC: SOC Playbook - Privilege Escalation"
    ],
    "analyst_warning": "High probability of data exfiltration. Rapid containment recommended."
  },
  "retrieved_evidence": [
    {
      "source": "mitre_attack_corpus.json",
      "title": "Exploitation for Privilege Escalation",
      "technique_id": "T1068",
      "similarity": 0.884,
      "text": "Adversaries may exploit software vulnerabilities in an attempt to elevate privileges..."
    }
  ]
}
```

### `POST /api/incidents/{id}/decision`
Allows the SOC analyst to record a final triage or resolution decision.

#### Request Body:
```json
{
  "status": "CONTAINED",
  "analyst_id": "soc_analyst",
  "notes": "User confirmed unauthorized access. Host isolated and user session terminated."
}
```

---

## 5. Human-in-the-Loop User Verification

### `POST /api/verification/request`
Generates a user verification challenge for a specific incident.

#### Request Body:
```json
{
  "incident_id": "3f829a...",
  "user_id": "jdoe",
  "activity_summary": "Privilege escalation attempt detected on server srv-app-prod01.",
  "requested_by": "soc_analyst",
  "delivery_method": "DEMO_PORTAL"
}
```

### `GET /api/verification/{challenge_id}`
Retrieves challenge details for rendering the verification page.

### `POST /api/verification/{challenge_id}/respond`
Submits the user's response to the verification challenge.

#### Request Body:
```json
{
  "response": "NO_I_DID_NOT_DO_THIS",
  "pin": "1234",
  "verification_method": "DEMO_PORTAL"
}
```

#### Response (`200 OK`):
```json
{
  "status": "DENIED",
  "message": "Response recorded. Incident priority escalated to CRITICAL.",
  "incident_status": "USER_DENIED"
}
```

### `GET /api/verification/incident/{incident_id}`
Returns the active verification request and response history for a given incident.

---

## 6. Controlled Response Engine

### `GET /api/responses/actions`
Lists all proposed and executed response actions.
- Query Parameter: `incident_id` (UUID, optional)

### `POST /api/responses/actions`
Stages a response action for analyst review.

#### Request Body:
```json
{
  "incident_id": "3f829a...",
  "action_type": "ISOLATE_HOST",
  "target": "srv-app-prod01",
  "reason": "Suspicious privilege escalation and data staging detected.",
  "analyst_id": "soc_analyst"
}
```

### `POST /api/responses/actions/{action_id}/execute`
Executes an approved response action in simulation mode.

#### Response (`200 OK`):
```json
{
  "id": "c1f7b8...",
  "action_type": "ISOLATE_HOST",
  "target": "srv-app-prod01",
  "status": "EXECUTED",
  "is_simulated": true,
  "execution_log": "[SIMULATED] Host srv-app-prod01 isolated via EDR agent. All non-management traffic dropped.",
  "executed_at": "2026-10-01T14:40:00Z"
}
```

---

## 7. Threat Intelligence & MITRE ATT&CK

### `GET /api/mitre/techniques`
Returns the Enterprise ATT&CK matrix technique catalogue with active mapped incident counts.

---

## 8. Analytics & Visualizations

### `GET /api/analytics`
Returns aggregate threat metrics, attack category distributions, anomaly trends, and risk score distributions.

### `GET /api/attack-graph`
Returns nodes and edges formatted for React Flow, connecting adversary IPs, incidents, target assets, compromised users, and MITRE techniques.

### `GET /api/reports`
Returns formal, structured compliance and incident post-mortem reports.
