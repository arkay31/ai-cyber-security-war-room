import pytest
import datetime
from fastapi.testclient import TestClient

from backend.app.main import app
from backend.app.database import SessionLocal
from backend.app.models.incident import Incident
from backend.app.models.response_action import ResponseAction
from backend.app.models.verification import VerificationRequest

client = TestClient(app)


def _get_or_create_test_incident():
    """Retrieve or create a dedicated test incident so we do not mutate main SOC demo incidents."""
    with SessionLocal() as db:
        inc = db.query(Incident).filter(Incident.incident_id == "INC-TEST-9999").first()
        if not inc:
            inc = Incident(
                incident_id="INC-TEST-9999",
                title="Automated Rule Verification Incident",
                severity="HIGH",
                status="INVESTIGATING",
                risk_score=75.0,
                source_ip="198.51.100.42",
                hostname="srv-app-prod-01",
                user="testuser_soc",
                summary="Automated test incident for rules verification",
            )
            db.add(inc)
            db.commit()
            db.refresh(inc)
        return inc.id


def test_duplicate_pending_action_rejected():
    """Verify that proposing an identical response action while one is PENDING raises 400."""
    inc_id = _get_or_create_test_incident()

    # Clean up any existing actions for this specific type to ensure clean state
    with SessionLocal() as db:
        db.query(ResponseAction).filter(
            ResponseAction.incident_id == inc_id,
            ResponseAction.action == "BLOCK_SOURCE_IP",
            ResponseAction.status == "PENDING"
        ).delete()
        db.commit()

    # Propose first action
    r1 = client.post(f"/api/incidents/{inc_id}/responses", json={
        "action": "BLOCK_SOURCE_IP",
        "reason": "Firewall block for testing duplicates",
        "analyst_id": "test_analyst"
    })
    assert r1.status_code == 200, f"Failed proposing initial action: {r1.text}"
    data1 = r1.json()
    action_id = data1["id"]
    assert data1["status"] == "PENDING"

    # Attempt to propose the duplicate action
    r2 = client.post(f"/api/incidents/{inc_id}/responses", json={
        "action": "BLOCK_SOURCE_IP",
        "reason": "Accidental duplicate click",
        "analyst_id": "test_analyst"
    })
    assert r2.status_code == 400
    assert "already awaiting analyst review" in r2.json()["detail"].lower()

    # Clean up the pending action by rejecting it
    client.post(f"/api/responses/{action_id}/reject", json={
        "analyst_id": "test_analyst",
        "notes": "Cleaning up test action"
    })


def test_response_action_state_machine_transitions():
    """Verify state transitions: PENDING -> EXECUTED (cannot re-execute or reject), and PENDING -> REJECTED."""
    inc_id = _get_or_create_test_incident()

    # Clean up existing actions of this type
    with SessionLocal() as db:
        db.query(ResponseAction).filter(
            ResponseAction.incident_id == inc_id,
            ResponseAction.action == "ISOLATE_HOST",
            ResponseAction.status == "PENDING"
        ).delete()
        db.commit()

    # 1. Propose ISOLATE_HOST
    r = client.post(f"/api/incidents/{inc_id}/responses", json={
        "action": "ISOLATE_HOST",
        "reason": "Testing state machine transitions",
        "analyst_id": "test_analyst"
    })
    assert r.status_code == 200
    act_id_1 = r.json()["id"]

    # 2. Execute it -> EXECUTED
    exec_res = client.post(f"/api/responses/{act_id_1}/execute", json={
        "analyst_id": "test_analyst",
        "notes": "Confirmed containment execution"
    })
    assert exec_res.status_code == 200
    assert exec_res.json()["status"] == "EXECUTED"

    # 3. Attempt to re-execute -> MUST FAIL (HTTP 400)
    re_exec = client.post(f"/api/responses/{act_id_1}/execute", json={
        "analyst_id": "test_analyst",
        "notes": "Invalid re-execution attempt"
    })
    assert re_exec.status_code == 400
    assert "already been executed" in re_exec.json()["detail"].lower()

    # 4. Attempt to reject already executed action -> MUST FAIL (HTTP 400)
    re_reject = client.post(f"/api/responses/{act_id_1}/reject", json={
        "analyst_id": "test_analyst",
        "notes": "Invalid reject attempt on executed action"
    })
    assert re_reject.status_code == 400
    assert "already been executed and cannot be rejected" in re_reject.json()["detail"].lower()

    # 5. Propose a second action to test REJECTED transition
    with SessionLocal() as db:
        db.query(ResponseAction).filter(
            ResponseAction.incident_id == inc_id,
            ResponseAction.action == "DISABLE_ACCOUNT",
            ResponseAction.status == "PENDING"
        ).delete()
        db.commit()

    r2 = client.post(f"/api/incidents/{inc_id}/responses", json={
        "action": "DISABLE_ACCOUNT",
        "reason": "Testing rejection flow",
        "analyst_id": "test_analyst"
    })
    assert r2.status_code == 200
    act_id_2 = r2.json()["id"]

    # 6. Reject it -> REJECTED
    reject_res = client.post(f"/api/responses/{act_id_2}/reject", json={
        "analyst_id": "test_analyst",
        "notes": "Analyst declined this action"
    })
    assert reject_res.status_code == 200
    assert reject_res.json()["status"] == "REJECTED"

    # 7. Attempt to execute the rejected action -> MUST FAIL (HTTP 400)
    exec_rejected = client.post(f"/api/responses/{act_id_2}/execute", json={
        "analyst_id": "test_analyst",
        "notes": "Invalid execute on rejected action"
    })
    assert exec_rejected.status_code == 400
    assert "was rejected and cannot be executed" in exec_rejected.json()["detail"].lower()

    # 8. Attempt to reject the rejected action again -> MUST FAIL (HTTP 400)
    re_reject2 = client.post(f"/api/responses/{act_id_2}/reject", json={
        "analyst_id": "test_analyst",
        "notes": "Invalid re-rejection"
    })
    assert re_reject2.status_code == 400
    assert "already been rejected" in re_reject2.json()["detail"].lower()


def test_all_five_simulated_actions():
    """Verify that all 5 simulated actions execute properly and include simulation telemetry identifiers."""
    inc_id = _get_or_create_test_incident()

    actions_to_test = [
        ("ISOLATE_HOST", "EDR-ISO-"),
        ("BLOCK_SOURCE_IP", "ACL-DROP-"),
        ("REVOKE_USER_SESSION", "IAM-REVOKE-"),
        ("FORENSIC_SNAPSHOT", "SHA256:"),
        ("DISABLE_ACCOUNT", "AD-LOCK-"),
    ]

    for action_name, expected_telemetry in actions_to_test:
        # Clean up any pending
        with SessionLocal() as db:
            db.query(ResponseAction).filter(
                ResponseAction.incident_id == inc_id,
                ResponseAction.action == action_name,
                ResponseAction.status == "PENDING"
            ).delete()
            db.commit()

        # Propose
        prop = client.post(f"/api/incidents/{inc_id}/responses", json={
            "action": action_name,
            "reason": f"Verifying {action_name} simulation telemetry",
            "analyst_id": "telemetry_test_analyst"
        })
        assert prop.status_code == 200, f"Failed proposing {action_name}: {prop.text}"
        act_id = prop.json()["id"]

        # Execute
        exec_res = client.post(f"/api/responses/{act_id}/execute", json={
            "analyst_id": "telemetry_test_analyst",
            "notes": "Executing action for simulation check"
        })
        assert exec_res.status_code == 200, f"Failed executing {action_name}: {exec_res.text}"
        log = exec_res.json()["execution_log"]
        assert "[SIMULATION]" in log, f"Simulation tag missing in {action_name} log"
        assert expected_telemetry in log, f"Expected telemetry identifier {expected_telemetry} missing in {action_name} log"


def test_duplicate_verification_challenge_returns_existing():
    """Verify that requesting verification when an active PENDING challenge exists returns the existing challenge."""
    inc_id = _get_or_create_test_incident()

    # Create challenge 1
    v1 = client.post(f"/api/incidents/{inc_id}/verification", json={
        "user_id": "test_verification_user",
        "activity_summary": "Initial verification challenge creation",
        "delivery_method": "DEMO_PORTAL",
        "expires_in_minutes": 20
    })
    assert v1.status_code == 200
    c1_id = v1.json()["challenge_id"]
    assert v1.json()["status"] == "PENDING"

    # Request challenge 2 while challenge 1 is still pending
    v2 = client.post(f"/api/incidents/{inc_id}/verification", json={
        "user_id": "test_verification_user",
        "activity_summary": "Second verification challenge attempt",
        "delivery_method": "DEMO_PORTAL",
        "expires_in_minutes": 20
    })
    assert v2.status_code == 200
    # Must return the SAME challenge ID rather than creating a duplicate or breaking the active token
    assert v2.json()["challenge_id"] == c1_id
    assert v2.json()["status"] == "PENDING"

    # Clean up test verification challenges
    with SessionLocal() as db:
        db.query(VerificationRequest).filter(VerificationRequest.incident_id == inc_id).delete()
        db.commit()
