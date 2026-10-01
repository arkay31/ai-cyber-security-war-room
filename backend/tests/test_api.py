import pytest
from fastapi.testclient import TestClient
from backend.app.main import app

client = TestClient(app)


def test_health():
    res = client.get("/api/health")
    assert res.status_code == 200
    data = res.json()
    assert data["status"] == "healthy"
    assert data["database"] == "ok"


def test_dashboard_stats():
    res = client.get("/api/dashboard/stats")
    assert res.status_code == 200
    data = res.json()
    assert "total_security_events" in data
    assert "threats_today" in data
    assert "critical_incidents" in data
    assert "threat_activity" in data
    assert "recent_incidents" in data
    assert isinstance(data["recent_incidents"], list)


def test_ingest_event():
    payload = {
        "source_ip": "172.16.0.44",
        "destination_ip": "10.0.0.99",
        "source_port": 51234,
        "destination_port": 80,
        "protocol": "TCP",
        "event_type": "port_scan",
        "severity": "high",
        "hostname": "test-host",
        "raw_data": {
            "Destination Port": 80,
            "Flow Duration": 150
        }
    }
    res = client.post("/api/events", json=payload)
    assert res.status_code == 201
    data = res.json()
    assert data["source_ip"] == "172.16.0.44"
    assert len(data["detections"]) > 0
    assert len(data["anomalies"]) > 0


def test_get_events():
    res = client.get("/api/events?limit=10")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) > 0


def test_get_incidents():
    res = client.get("/api/incidents")
    assert res.status_code == 200
    data = res.json()
    assert isinstance(data, list)
    assert len(data) > 0

    first_incident = data[0]
    inc_id = first_incident["incident_id"]

    # Test incident details
    detail_res = client.get(f"/api/incidents/{inc_id}")
    assert detail_res.status_code == 200
    detail = detail_res.json()
    assert "timeline" in detail
    assert "events" in detail
    assert "mitre_details" in detail
    assert "evidence" in detail


def test_investigate_incident():
    res = client.get("/api/incidents")
    inc_id = res.json()[0]["incident_id"]

    inv_res = client.post(f"/api/incidents/{inc_id}/investigate")
    assert inv_res.status_code == 200
    inv = inv_res.json()
    assert inv["incident_id"] == inc_id
    assert "investigation_summary" in inv
    assert len(inv["recommended_steps"]) > 0


def test_analyst_decision():
    res = client.get("/api/incidents")
    inc_id = res.json()[0]["incident_id"]

    dec_res = client.post(
        f"/api/incidents/{inc_id}/decision",
        json={
            "status": "Contained",
            "action_notes": "Host quarantined from network segment.",
            "actor": "lead_soc_analyst"
        }
    )
    assert dec_res.status_code == 200
    assert dec_res.json()["status"] == "Contained"


def test_mitre_techniques():
    res = client.get("/api/mitre/techniques")
    assert res.status_code == 200
    techs = res.json()
    assert len(techs) > 0
    assert any(t["technique_id"] == "T1110" for t in techs)


def test_analytics():
    res = client.get("/api/analytics")
    assert res.status_code == 200
    data = res.json()
    assert "attacks_by_type" in data
    assert "severity_distribution" in data
    assert "confidence_distribution" in data


def test_attack_graph():
    res = client.get("/api/attack-graph")
    assert res.status_code == 200
    data = res.json()
    assert "nodes" in data
    assert "edges" in data
