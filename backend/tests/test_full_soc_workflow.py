import pytest
import datetime
from fastapi.testclient import TestClient
from sqlalchemy.orm import Session

from backend.app.main import app
from backend.app.database import SessionLocal
from backend.app.ml.inference import inference_engine
from backend.app.services.risk_engine import risk_engine
from backend.app.services.mitre_service import MitreService
from backend.app.services.embedding_service import embedding_service
from backend.app.services.rag_service import rag_service
from backend.app.services.llm_service import llm_service
from backend.app.services.ai_analyst import ai_analyst
from backend.app.services.response_engine import response_engine
from backend.app.services.synthetic_generator import SyntheticGenerator
from backend.app.models.incident import Incident
from backend.app.models.security_event import SecurityEvent
from backend.app.models.audit_log import AuditLog
from backend.app.models.verification import VerificationRequest, VerificationResponse
from backend.app.models.response_action import ResponseAction

client = TestClient(app)


# ============================================================
# 1. Ingestion & Normalization Tests
# ============================================================
def test_embedding_service_normalization():
    """Verify text input normalization and embedding generation."""
    raw = "  Suspicious   SSH \n brute   force   "
    normalized = embedding_service.normalize_input(raw)
    assert normalized == "Suspicious SSH brute force"

    # Single embedding
    emb = embedding_service.generate_embedding(normalized)
    assert isinstance(emb, list)
    assert len(emb) == 384
    # Check unit normalization (L2 norm ~ 1.0)
    norm = sum(x ** 2 for x in emb) ** 0.5
    assert abs(norm - 1.0) < 0.05


def test_batch_embedding_generation():
    texts = ["Test document 1", "Test document 2", ""]
    embs = embedding_service.batch_generate_embeddings(texts)
    assert len(embs) == 3
    assert len(embs[0]) == 384
    assert len(embs[1]) == 384


# ============================================================
# 2. Machine Learning Tests (XGBoost & Isolation Forest)
# ============================================================
def test_xgboost_inference():
    """Verify supervised classification for known attack signatures."""
    payload = {
        "Destination Port": 22,
        "Flow Duration": 1200,
        "Total Fwd Packets": 12,
        "Total Backward Packets": 8,
    }
    pred = inference_engine.predict_threat(payload)
    assert "predicted_class" in pred
    assert "confidence" in pred
    assert pred["model_name"] in ["xgboost_detector", "XGBoost Intrusion Detection"]
    assert 0.0 <= pred["confidence"] <= 1.0


def test_isolation_forest_anomaly_detection():
    """Verify unsupervised anomaly detection and thresholding."""
    payload = {
        "Destination Port": 443,
        "Flow Duration": 95000,
        "Total Length of Fwd Packets": 15000000.0,
    }
    anom = inference_engine.predict_anomaly(payload)
    assert "anomaly_score" in anom
    assert "is_anomalous" in anom
    assert isinstance(anom["is_anomalous"], bool)
    assert anom["model_name"] in ["isolation_forest", "Isolation Forest Anomaly Detector"]


# ============================================================
# 3. Risk Engine & MITRE Mapping Tests
# ============================================================
def test_risk_engine_calculation():
    event_risk = risk_engine.calculate_event_risk(
        {"severity": "critical", "user": "root"},
        {"predicted_class": "Brute Force", "confidence": 0.95},
        {"anomaly_score": 0.88}
    )
    assert event_risk["risk_score"] > 60
    assert event_risk["severity"] in ["HIGH", "CRITICAL"]

    inc_risk = risk_engine.calculate_incident_risk([event_risk], mitre_count=2)
    assert inc_risk["risk_score"] >= event_risk["risk_score"]


def test_mitre_mapping():
    techs = MitreService.map_event_to_techniques("failed_login", "Brute Force")
    assert "T1110" in techs

    techs_recon = MitreService.map_event_to_techniques("port_scan", "PortScan")
    assert "T1046" in techs_recon


# ============================================================
# 4. RAG Retrieval from pgvector Tests
# ============================================================
def test_rag_semantic_retrieval():
    """Verify pgvector semantic vector search retrieves relevant evidence."""
    with SessionLocal() as db:
        query = "repeated failed authentication password guessing brute force"
        results = rag_service.retrieve_relevant_evidence(query, db, top_k=3)
        assert len(results) > 0
        top = results[0]
        assert "document_id" in top
        assert "title" in top
        assert "similarity_score" in top
        assert "content" in top
        assert top["similarity_score"] > 0.0


# ============================================================
# 5. LLM Response Parsing & Status Labeling Tests
# ============================================================
def test_llm_json_parsing():
    raw_markdown_json = """Here is the analysis:
```json
{
  "incident_summary": "Test summary",
  "confidence": 0.92,
  "observed_evidence": ["Evidence 1"]
}
```
"""
    parsed = llm_service._parse_json_safely(raw_markdown_json)
    assert parsed is not None
    assert parsed["confidence"] == 0.92
    assert parsed["incident_summary"] == "Test summary"


# ============================================================
# 6. Faculty Demo Attack Simulation & End-to-End Workflow
# ============================================================
def test_faculty_demo_simulation_endpoint():
    """Trigger the 7-event faculty demo scenario via API."""
    res = client.post("/api/events/simulate-demo-attack")
    assert res.status_code == 201
    data = res.json()
    assert data["status"] == "success"
    assert data["events_count"] == 7
    assert data["incident_id"] is not None
    assert data["db_id"] is not None


def test_ai_analyst_investigation():
    """Verify AI Analyst investigation executes and produces labeled output."""
    with SessionLocal() as db:
        inc = db.query(Incident).filter(Incident.hostname == "sec-ops-srv01").order_by(Incident.id.desc()).first()
        assert inc is not None

        res = ai_analyst.investigate(db, inc.id)
        assert res["status"] == "completed"
        assert res["analysis_mode"] in ["LLM_RAG", "LLM", "RULE_BASED"]
        assert res["llm_status"] in ["LLM_RAG", "LLM", "LLM_UNAVAILABLE"]
        assert "incident_summary" in res
        assert len(res["investigation_steps"]) > 0
        assert len(res["prioritized_recommendations"]) > 0


# ============================================================
# 7. User Verification Workflow Tests (4 States: PENDING, CONFIRMED, DENIED, EXPIRED)
# ============================================================
def test_verification_pending_state():
    """Test 1: Verification challenge in PENDING state."""
    with SessionLocal() as db:
        inc = db.query(Incident).first()
        assert inc is not None
        inc_id = inc.id

    # 1. Create verification challenge
    v_res = client.post(f"/api/incidents/{inc_id}/verification", json={
        "user_id": "mjackson",
        "activity_summary": "Test login verification challenge",
        "delivery_method": "DEMO_PORTAL",
        "expires_in_minutes": 15
    })
    assert v_res.status_code == 200
    v_data = v_res.json()
    assert v_data["status"] == "PENDING"
    challenge_id = v_data["challenge_id"]

    # 2. Public challenge retrieval
    pub_res = client.get(f"/api/verify/{challenge_id}")
    assert pub_res.status_code == 200
    pub_data = pub_res.json()
    assert pub_data["challenge_id"] == challenge_id
    assert pub_data["status"] == "PENDING"
    assert pub_data["is_expired"] is False

    # 3. Incident state reflects AWAITING_USER_VERIFICATION
    inc_detail = client.get(f"/api/incidents/{inc_id}").json()
    assert inc_detail["status"] == "AWAITING_USER_VERIFICATION"
    assert inc_detail["verification_requests"][0]["status"] == "PENDING"


def test_verification_confirmed_state():
    """Test 2: Verification challenge in CONFIRMED state with analyst review."""
    with SessionLocal() as db:
        inc = db.query(Incident).first()
        inc_id = inc.id

    # 1. Create challenge
    v_res = client.post(f"/api/incidents/{inc_id}/verification", json={
        "user_id": "mjackson",
        "activity_summary": "Testing confirmation flow",
        "delivery_method": "DEMO_PORTAL",
        "expires_in_minutes": 15
    })
    c_id = v_res.json()["challenge_id"]

    # 2. User confirms
    resp_res = client.post(f"/api/verify/{c_id}/respond", json={
        "response": "CONFIRMED",
        "verification_method": "DEMO_PORTAL"
    })
    assert resp_res.status_code == 200
    assert resp_res.json()["status"] == "CONFIRMED"

    # 3. Verify incident state transitioned to USER_CONFIRMED and remains open
    inc_detail = client.get(f"/api/incidents/{inc_id}").json()
    assert inc_detail["status"] == "USER_CONFIRMED"
    assert inc_detail["verification_requests"][0]["status"] == "CONFIRMED"

    # 4. Analyst reviews and marks as legitimate (FALSE_POSITIVE)
    dec_res = client.post(f"/api/incidents/{inc_id}/decision", json={
        "status": "FALSE_POSITIVE",
        "action_notes": "Marked legitimate following user confirmation.",
        "actor": "lead_analyst"
    })
    assert dec_res.status_code == 200
    assert dec_res.json()["status"] == "FALSE_POSITIVE"


def test_verification_denied_state():
    """Test 3: Verification challenge in DENIED state with risk escalation."""
    with SessionLocal() as db:
        inc = db.query(Incident).first()
        inc_id = inc.id

    # 1. Create challenge
    v_res = client.post(f"/api/incidents/{inc_id}/verification", json={
        "user_id": "mjackson",
        "activity_summary": "Testing denial compromise flow",
        "delivery_method": "DEMO_PORTAL",
        "expires_in_minutes": 15
    })
    c_id = v_res.json()["challenge_id"]

    # 2. User denies
    resp_res = client.post(f"/api/verify/{c_id}/respond", json={
        "response": "DENIED",
        "verification_method": "DEMO_PORTAL"
    })
    assert resp_res.status_code == 200
    assert resp_res.json()["status"] == "DENIED"

    # 3. Verify incident escalated to CRITICAL and 100.0 risk score
    inc_detail = client.get(f"/api/incidents/{inc_id}").json()
    assert inc_detail["status"] == "USER_DENIED"
    assert inc_detail["severity"] == "CRITICAL"
    assert inc_detail["risk_score"] == 100.0
    assert inc_detail["verification_requests"][0]["status"] == "DENIED"


def test_verification_expired_state():
    """Test 4: Verification challenge in EXPIRED state."""
    with SessionLocal() as db:
        inc = db.query(Incident).first()
        inc_id = inc.id

    # 1. Create challenge
    v_res = client.post(f"/api/incidents/{inc_id}/verification", json={
        "user_id": "mjackson",
        "activity_summary": "Testing expiration flow",
        "delivery_method": "DEMO_PORTAL",
        "expires_in_minutes": 15
    })
    c_id = v_res.json()["challenge_id"]

    # 2. Artificially set expires_at in the past
    with SessionLocal() as db:
        from backend.app.models.verification import VerificationRequest
        vr = db.query(VerificationRequest).filter(VerificationRequest.challenge_id == c_id).first()
        vr.expires_at = datetime.datetime.utcnow() - datetime.timedelta(minutes=10)
        db.commit()

    # 3. Check public challenge endpoint detects expiration
    pub_res = client.get(f"/api/verify/{c_id}")
    assert pub_res.status_code == 200
    pub_data = pub_res.json()
    assert pub_data["status"] == "EXPIRED"
    assert pub_data["is_expired"] is True

    # 4. Check incident detail detects expiration
    inc_detail = client.get(f"/api/incidents/{inc_id}").json()
    assert inc_detail["status"] == "VERIFICATION_EXPIRED"
    assert inc_detail["verification_requests"][0]["status"] == "EXPIRED"

    # 5. Responding to expired challenge must fail with HTTP 400
    fail_res = client.post(f"/api/verify/{c_id}/respond", json={
        "response": "CONFIRMED",
        "verification_method": "DEMO_PORTAL"
    })
    assert fail_res.status_code == 400
    assert "expired" in fail_res.json()["detail"].lower()


# ============================================================
# 8. Controlled Response Engine Tests
# ============================================================
def test_controlled_response_lifecycle():
    """Test response proposal -> analyst execution in safe simulation mode."""
    with SessionLocal() as db:
        inc = db.query(Incident).first()
        inc_id = inc.id

    # 1. Propose action
    prop_res = client.post(f"/api/incidents/{inc_id}/responses", json={
        "action": "ISOLATE_HOST",
        "reason": "Test simulated host quarantine",
        "analyst_id": "lead_analyst"
    })
    assert prop_res.status_code == 200
    action_data = prop_res.json()
    assert action_data["status"] == "PENDING"
    assert action_data["action"] == "ISOLATE_HOST"
    action_id = action_data["id"]

    # 2. Execute action
    exec_res = client.post(f"/api/responses/{action_id}/execute", json={
        "analyst_id": "lead_analyst",
        "notes": "Analyst confirmation provided in test"
    })
    assert exec_res.status_code == 200
    exec_data = exec_res.json()
    assert exec_data["status"] == "EXECUTED"
    assert "[SIMULATION]" in exec_data["execution_log"]

    # 3. Verify incident state transitioned to CONTAINED
    inc_detail = client.get(f"/api/incidents/{inc_id}").json()
    assert inc_detail["status"].upper() == "CONTAINED"

    # 4. Verify audit trail has RESPONSE_EXECUTED entry
    audit_actions = [a["action"] for a in inc_detail["audit_logs"]]
    assert "RESPONSE_EXECUTED" in audit_actions
