import os
import socket

# Check if PostgreSQL is reachable before any database module imports
if "TEST_DATABASE_URL" not in os.environ:
    s = socket.socket()
    try:
        s.settimeout(0.3)
        s.connect(("127.0.0.1", 5432))
        s.close()
    except Exception:
        os.environ["TEST_DATABASE_URL"] = "sqlite:///:memory:"

import pytest
from backend.app.database import engine, Base, SessionLocal
from backend.app.services.mitre_service import MitreService
from backend.app.models.incident import Incident, IncidentEvent
from backend.app.models.security_event import SecurityEvent
from scripts.ingest_knowledge import ingest_knowledge


@pytest.fixture(scope="session", autouse=True)
def setup_test_database():
    Base.metadata.create_all(bind=engine)

    # Pre-seed MITRE techniques and a sample incident for test suites
    with SessionLocal() as session:
        MitreService.seed_techniques(session)
        ingest_knowledge(db=session)

        existing_inc = session.query(Incident).filter(Incident.incident_id == "INC-DEMO-001").first()
        if not existing_inc:
            inc = Incident(
                incident_id="INC-DEMO-001",
                title="Brute Force Authentication Breach",
                severity="HIGH",
                status="Investigating",
                risk_score=85.0,
                source_ip="192.168.1.50",
                hostname="auth-srv-01",
                user="admin",
                summary="Repeated credential stuffing attempts observed."
            )
            session.add(inc)
            session.commit()
            session.refresh(inc)

            ev = SecurityEvent(
                source_ip="192.168.1.50",
                destination_ip="10.0.0.1",
                source_port=54321,
                destination_port=22,
                protocol="TCP",
                event_type="brute_force",
                severity="HIGH",
                hostname="auth-srv-01",
                raw_data={"Destination Port": 22}
            )
            session.add(ev)
            session.commit()
            session.refresh(ev)

            link = IncidentEvent(incident_id=inc.id, event_id=ev.id)
            session.add(link)
            session.commit()

    yield
