import datetime
from typing import List, Dict, Any
from sqlalchemy.orm import Session

from sqlalchemy import desc
from backend.app.models.security_event import SecurityEvent
from backend.app.models.incident import Incident
from backend.app.ml.inference import inference_engine
from backend.app.models.detection import Detection
from backend.app.models.anomaly import Anomaly
from backend.app.services.correlation_engine import correlation_engine


class SyntheticGenerator:
    """
    Generates realistic, clearly labeled synthetic SOC events and multi-stage attack scenarios.
    """

    @staticmethod
    def create_scenario_1(base_time: datetime.datetime) -> List[Dict[str, Any]]:
        """
        SCENARIO 1:
        Brute Force -> Account Compromise -> Privilege Escalation -> Data Access -> Possible Exfiltration
        Attacker: 198.51.100.42 (External)
        Victim: finance-srv01 (10.0.1.15)
        Target Account: jsmith -> root
        """
        events = []
        t = base_time

        # Step 1: Brute Force SSH attempts (10:01)
        for i in range(5):
            events.append({
                "timestamp": t + datetime.timedelta(seconds=15 * i),
                "source_ip": "198.51.100.42",
                "destination_ip": "10.0.1.15",
                "source_port": 49152 + i,
                "destination_port": 22,
                "protocol": "SSH",
                "user": "jsmith",
                "hostname": "finance-srv01",
                "event_type": "failed_login",
                "severity": "high",
                "raw_data": {
                    "synthetic": True,
                    "scenario": "Scenario 1: Brute Force to Exfiltration",
                    "attempt_number": i + 1,
                    "auth_method": "password",
                    "failure_reason": "invalid_credentials",
                    "Destination Port": 22,
                    "Flow Duration": 1200,
                    "Total Fwd Packets": 12,
                    "Total Backward Packets": 8,
                }
            })

        # Step 2: Successful Account Compromise (10:03)
        t = t + datetime.timedelta(minutes=2)
        events.append({
            "timestamp": t,
            "source_ip": "198.51.100.42",
            "destination_ip": "10.0.1.15",
            "source_port": 49160,
            "destination_port": 22,
            "protocol": "SSH",
            "user": "jsmith",
            "hostname": "finance-srv01",
            "event_type": "successful_login",
            "severity": "medium",
            "raw_data": {
                "synthetic": True,
                "scenario": "Scenario 1: Brute Force to Exfiltration",
                "auth_method": "password",
                "session_id": "ssh-sess-9912",
                "geo_location": "External/Suspicious ASN",
                "Destination Port": 22,
            }
        })

        # Step 3: Privilege Escalation (10:05)
        t = t + datetime.timedelta(minutes=2)
        events.append({
            "timestamp": t,
            "source_ip": "198.51.100.42",
            "destination_ip": "10.0.1.15",
            "source_port": 49160,
            "destination_port": 22,
            "protocol": "SSH",
            "user": "root",
            "hostname": "finance-srv01",
            "event_type": "privilege_escalation",
            "severity": "critical",
            "raw_data": {
                "synthetic": True,
                "scenario": "Scenario 1: Brute Force to Exfiltration",
                "command": "sudo -u root /bin/bash",
                "mechanism": "CVE-2021-3156 sudoers exploitation",
                "parent_process": "sshd",
                "spawned_process": "/bin/bash",
            }
        })

        # Step 4: Sensitive Data Access / Collection (10:07)
        t = t + datetime.timedelta(minutes=2)
        events.append({
            "timestamp": t,
            "source_ip": "198.51.100.42",
            "destination_ip": "10.0.1.15",
            "source_port": 49160,
            "destination_port": 22,
            "protocol": "SSH",
            "user": "root",
            "hostname": "finance-srv01",
            "event_type": "sensitive_file_access",
            "severity": "critical",
            "raw_data": {
                "synthetic": True,
                "scenario": "Scenario 1: Brute Force to Exfiltration",
                "target_path": "/var/finance/payroll_q3_2026.csv.enc",
                "bytes_read": 14582910,
                "action": "tar -czf /tmp/exfil.tgz /var/finance/*",
            }
        })

        # Step 5: Unusual Outbound Exfiltration (10:10)
        t = t + datetime.timedelta(minutes=3)
        events.append({
            "timestamp": t,
            "source_ip": "10.0.1.15",
            "destination_ip": "203.0.113.88",
            "source_port": 58210,
            "destination_port": 443,
            "protocol": "HTTPS",
            "user": "root",
            "hostname": "finance-srv01",
            "event_type": "unusual_outbound_traffic",
            "severity": "critical",
            "raw_data": {
                "synthetic": True,
                "scenario": "Scenario 1: Brute Force to Exfiltration",
                "bytes_sent": 14600000,
                "destination_host": "dropzone.attacker-c2.net",
                "Total Length of Fwd Packets": 14600000.0,
                "Flow Duration": 45000,
                "Destination Port": 443,
            }
        })

        return events

    @staticmethod
    def create_scenario_2(base_time: datetime.datetime) -> List[Dict[str, Any]]:
        """
        SCENARIO 2:
        Port Scan -> Service Discovery -> Suspicious Process
        Attacker: 203.0.113.19 (External)
        Victim: web-dmz-02 (10.0.2.20)
        """
        events = []
        t = base_time - datetime.timedelta(minutes=45)

        # Step 1: Port Scan across multiple destination ports
        for p in [21, 22, 80, 443, 8080, 8443, 3306]:
            events.append({
                "timestamp": t + datetime.timedelta(seconds=p % 10),
                "source_ip": "203.0.113.19",
                "destination_ip": "10.0.2.20",
                "source_port": 50000 + p,
                "destination_port": p,
                "protocol": "TCP",
                "user": None,
                "hostname": "web-dmz-02",
                "event_type": "port_scan",
                "severity": "medium",
                "raw_data": {
                    "synthetic": True,
                    "scenario": "Scenario 2: Port Scan to Suspicious Process",
                    "scan_type": "SYN Stealth Scan",
                    "Destination Port": p,
                    "Flow Duration": 200,
                    "Total Fwd Packets": 2,
                    "Total Backward Packets": 0,
                    "SYN Flag Count": 1,
                }
            })

        # Step 2: Web Service Discovery / Probe
        t = t + datetime.timedelta(minutes=4)
        events.append({
            "timestamp": t,
            "source_ip": "203.0.113.19",
            "destination_ip": "10.0.2.20",
            "source_port": 51200,
            "destination_port": 8080,
            "protocol": "HTTP",
            "user": "www-data",
            "hostname": "web-dmz-02",
            "event_type": "reconnaissance",
            "severity": "high",
            "raw_data": {
                "synthetic": True,
                "scenario": "Scenario 2: Port Scan to Suspicious Process",
                "url": "/api/v1/debug/env",
                "user_agent": "sqlmap/1.7#dev",
                "http_status": 200,
                "Destination Port": 8080,
            }
        })

        # Step 3: Suspicious Process Spawning
        t = t + datetime.timedelta(minutes=3)
        events.append({
            "timestamp": t,
            "source_ip": "203.0.113.19",
            "destination_ip": "10.0.2.20",
            "source_port": 51201,
            "destination_port": 8080,
            "protocol": "HTTP",
            "user": "www-data",
            "hostname": "web-dmz-02",
            "event_type": "suspicious_process",
            "severity": "high",
            "raw_data": {
                "synthetic": True,
                "scenario": "Scenario 2: Port Scan to Suspicious Process",
                "parent_process": "node /app/server.js",
                "command": "python3 -c 'import pty; pty.spawn(\"/bin/sh\")'",
                "pid": 9841,
            }
        })

        return events

    @staticmethod
    def create_scenario_3(base_time: datetime.datetime) -> List[Dict[str, Any]]:
        """
        SCENARIO 3:
        Suspicious Login -> Privilege Escalation -> Sensitive File Access
        Attacker: 192.168.4.110 (Internal Lateral or VPN)
        Victim: db-primary (10.0.3.50)
        User: dba_admin
        """
        events = []
        t = base_time - datetime.timedelta(minutes=20)

        # Step 1: Unusual Login from non-whitelisted subnet
        events.append({
            "timestamp": t,
            "source_ip": "192.168.4.110",
            "destination_ip": "10.0.3.50",
            "source_port": 55100,
            "destination_port": 3306,
            "protocol": "MySQL",
            "user": "dba_admin",
            "hostname": "db-primary",
            "event_type": "unusual_login",
            "severity": "high",
            "raw_data": {
                "synthetic": True,
                "scenario": "Scenario 3: Internal Privilege Escalation",
                "anomaly_note": "Login outside standard operational shift (off-hours)",
                "client_ip_origin": "Subnet 4 (Guest/BYOD VLAN)",
                "Destination Port": 3306,
            }
        })

        # Step 2: Privilege Escalation to DBA superuser
        t = t + datetime.timedelta(minutes=3)
        events.append({
            "timestamp": t,
            "source_ip": "192.168.4.110",
            "destination_ip": "10.0.3.50",
            "source_port": 55100,
            "destination_port": 3306,
            "protocol": "MySQL",
            "user": "dba_admin",
            "hostname": "db-primary",
            "event_type": "privilege_escalation",
            "severity": "critical",
            "raw_data": {
                "synthetic": True,
                "scenario": "Scenario 3: Internal Privilege Escalation",
                "statement": "GRANT ALL PRIVILEGES ON *.* TO 'dba_admin'@'%' WITH GRANT OPTION;",
                "affected_rows": 1,
            }
        })

        # Step 3: Dump Sensitive Database Tables
        t = t + datetime.timedelta(minutes=2)
        events.append({
            "timestamp": t,
            "source_ip": "192.168.4.110",
            "destination_ip": "10.0.3.50",
            "source_port": 55100,
            "destination_port": 3306,
            "protocol": "MySQL",
            "user": "dba_admin",
            "hostname": "db-primary",
            "event_type": "sensitive_file_access",
            "severity": "critical",
            "raw_data": {
                "synthetic": True,
                "scenario": "Scenario 3: Internal Privilege Escalation",
                "target": "customer_pii_vault",
                "rows_exported": 850000,
                "destination_file": "/tmp/dump_pii_2026.sql",
            }
        })

        return events

    @staticmethod
    def ingest_events(db: Session, event_dicts: List[Dict[str, Any]]) -> List[SecurityEvent]:
        """
        Ingest, normalize, detect, anomaly-score, and correlate a batch of events.
        """
        created_events = []
        for edata in event_dicts:
            event = SecurityEvent(
                timestamp=edata.get("timestamp", datetime.datetime.utcnow()),
                source_ip=edata["source_ip"],
                destination_ip=edata["destination_ip"],
                source_port=edata.get("source_port"),
                destination_port=edata.get("destination_port"),
                protocol=edata.get("protocol", "TCP"),
                user=edata.get("user"),
                hostname=edata.get("hostname"),
                event_type=edata["event_type"],
                severity=edata.get("severity", "medium"),
                raw_data=edata.get("raw_data", {}),
                created_at=datetime.datetime.utcnow(),
            )
            db.add(event)
            db.flush()

            # Run ML classification
            ml_pred = inference_engine.predict_threat(edata)
            detection = Detection(
                event_id=event.id,
                model_name=ml_pred["model_name"],
                predicted_class=ml_pred["predicted_class"],
                confidence=ml_pred["confidence"],
                created_at=datetime.datetime.utcnow()
            )
            db.add(detection)

            # Run Anomaly detection
            anom_res = inference_engine.predict_anomaly(edata)
            anomaly = Anomaly(
                event_id=event.id,
                anomaly_score=anom_res["anomaly_score"],
                is_anomalous=anom_res["is_anomalous"],
                model_name=anom_res["model_name"],
                created_at=datetime.datetime.utcnow()
            )
            db.add(anomaly)
            db.flush()

            # Run correlation
            correlation_engine.correlate_event(db, event, detection, anomaly)
            created_events.append(event)

        db.commit()
        return created_events

    @staticmethod
    def create_faculty_demo_scenario(base_time: datetime.datetime) -> List[Dict[str, Any]]:
        """
        DETERMINISTIC FACULTY DEMO SCENARIO:
        ACCOUNT TAKEOVER + PRIVILEGED ACCESS + SENSITIVE DATA ACCESS

        7-Step Attack Sequence:
        1. Failed login (SSH brute force attempt 1)
        2. Failed login (SSH brute force attempt 2)
        3. Failed login (SSH brute force attempt 3)
        4. Successful login (Account compromise of user mjackson)
        5. Privileged command (sudo privilege escalation to root)
        6. Sensitive file access (customer_vault.csv archive staging)
        7. Unusual outbound traffic (High-volume C2 egress / exfiltration)
        """
        events = []
        t = base_time
        attacker_ip = "198.51.100.77"
        target_ip = "10.0.1.25"
        target_host = "sec-ops-srv01"
        target_user = "mjackson"

        # 1. Failed login (attempt 1)
        events.append({
            "timestamp": t,
            "source_ip": attacker_ip,
            "destination_ip": target_ip,
            "source_port": 50120,
            "destination_port": 22,
            "protocol": "SSH",
            "user": target_user,
            "hostname": target_host,
            "event_type": "failed_login",
            "severity": "medium",
            "raw_data": {
                "synthetic": True,
                "scenario": "Faculty Demo: Account Takeover to Exfiltration",
                "step": 1,
                "description": "Authentication failure for user mjackson from external IP",
                "Destination Port": 22,
                "Flow Duration": 450,
                "Total Fwd Packets": 6,
                "Total Backward Packets": 4,
            }
        })

        # 2. Failed login (attempt 2)
        t = t + datetime.timedelta(seconds=12)
        events.append({
            "timestamp": t,
            "source_ip": attacker_ip,
            "destination_ip": target_ip,
            "source_port": 50121,
            "destination_port": 22,
            "protocol": "SSH",
            "user": target_user,
            "hostname": target_host,
            "event_type": "failed_login",
            "severity": "medium",
            "raw_data": {
                "synthetic": True,
                "scenario": "Faculty Demo: Account Takeover to Exfiltration",
                "step": 2,
                "description": "Repeated authentication failure for user mjackson",
                "Destination Port": 22,
                "Flow Duration": 520,
                "Total Fwd Packets": 6,
                "Total Backward Packets": 4,
            }
        })

        # 3. Failed login (attempt 3)
        t = t + datetime.timedelta(seconds=14)
        events.append({
            "timestamp": t,
            "source_ip": attacker_ip,
            "destination_ip": target_ip,
            "source_port": 50122,
            "destination_port": 22,
            "protocol": "SSH",
            "user": target_user,
            "hostname": target_host,
            "event_type": "failed_login",
            "severity": "high",
            "raw_data": {
                "synthetic": True,
                "scenario": "Faculty Demo: Account Takeover to Exfiltration",
                "step": 3,
                "description": "Third authentication failure within 30 seconds - threshold reached",
                "Destination Port": 22,
                "Flow Duration": 610,
                "Total Fwd Packets": 8,
                "Total Backward Packets": 4,
            }
        })

        # 4. Successful login
        t = t + datetime.timedelta(seconds=20)
        events.append({
            "timestamp": t,
            "source_ip": attacker_ip,
            "destination_ip": target_ip,
            "source_port": 50125,
            "destination_port": 22,
            "protocol": "SSH",
            "user": target_user,
            "hostname": target_host,
            "event_type": "successful_login",
            "severity": "medium",
            "raw_data": {
                "synthetic": True,
                "scenario": "Faculty Demo: Account Takeover to Exfiltration",
                "step": 4,
                "description": "Successful SSH session established for mjackson after repeated failures",
                "auth_method": "password",
                "session_id": "ssh-sess-8890",
                "Destination Port": 22,
            }
        })

        # 5. Privileged command
        t = t + datetime.timedelta(seconds=25)
        events.append({
            "timestamp": t,
            "source_ip": attacker_ip,
            "destination_ip": target_ip,
            "source_port": 50125,
            "destination_port": 22,
            "protocol": "SSH",
            "user": "root",
            "hostname": target_host,
            "event_type": "privilege_escalation",
            "severity": "critical",
            "raw_data": {
                "synthetic": True,
                "scenario": "Faculty Demo: Account Takeover to Exfiltration",
                "step": 5,
                "command": "sudo -u root /bin/bash",
                "mechanism": "sudoers abuse / CVE-2021-3156 exploitation",
                "parent_pid": 4120,
                "child_shell": "/bin/bash",
            }
        })

        # 6. Sensitive file access
        t = t + datetime.timedelta(seconds=25)
        events.append({
            "timestamp": t,
            "source_ip": attacker_ip,
            "destination_ip": target_ip,
            "source_port": 50125,
            "destination_port": 22,
            "protocol": "SSH",
            "user": "root",
            "hostname": target_host,
            "event_type": "sensitive_file_access",
            "severity": "critical",
            "raw_data": {
                "synthetic": True,
                "scenario": "Faculty Demo: Account Takeover to Exfiltration",
                "step": 6,
                "target_file": "/var/data/customer_vault.csv.enc",
                "action": "tar -czf /tmp/vault_backup.tar.gz /var/data/customer_vault.csv.enc",
                "bytes_read": 15420000,
            }
        })

        # 7. Unusual outbound traffic
        t = t + datetime.timedelta(seconds=30)
        events.append({
            "timestamp": t,
            "source_ip": target_ip,
            "destination_ip": "198.51.100.99",
            "source_port": 59120,
            "destination_port": 443,
            "protocol": "HTTPS",
            "user": "root",
            "hostname": target_host,
            "event_type": "unusual_outbound_traffic",
            "severity": "critical",
            "raw_data": {
                "synthetic": True,
                "scenario": "Faculty Demo: Account Takeover to Exfiltration",
                "step": 7,
                "bytes_sent": 15500000,
                "destination_host": "dropzone.c2-exfil-node.net",
                "Total Length of Fwd Packets": 15500000.0,
                "Flow Duration": 52000,
                "Destination Port": 443,
            }
        })

        return events

    @classmethod
    def seed_faculty_demo(cls, db: Session) -> Dict[str, Any]:
        """Inject the deterministic 7-event faculty demo attack scenario and return correlated incident."""
        now = datetime.datetime.utcnow()
        demo_events = cls.create_faculty_demo_scenario(now - datetime.timedelta(minutes=5))
        ingested = cls.ingest_events(db, demo_events)

        # Retrieve the latest correlated incident
        latest_incident = (
            db.query(Incident)
            .filter(Incident.hostname == "sec-ops-srv01")
            .order_by(desc(Incident.updated_at))
            .first()
        )

        return {
            "status": "success",
            "scenario": "ACCOUNT TAKEOVER + PRIVILEGED ACCESS + SENSITIVE DATA ACCESS",
            "events_count": len(ingested),
            "incident_id": latest_incident.incident_id if latest_incident else None,
            "db_id": latest_incident.id if latest_incident else None,
            "risk_score": latest_incident.risk_score if latest_incident else 0.0,
            "severity": latest_incident.severity if latest_incident else "CRITICAL",
        }

    @classmethod
    def seed_all_scenarios(cls, db: Session) -> Dict[str, int]:
        """Seed all 3 attack scenarios into database."""
        now = datetime.datetime.utcnow()
        sc1 = cls.create_scenario_1(now - datetime.timedelta(minutes=10))
        sc2 = cls.create_scenario_2(now - datetime.timedelta(minutes=30))
        sc3 = cls.create_scenario_3(now - datetime.timedelta(minutes=5))

        all_events = sc1 + sc2 + sc3
        ingested = cls.ingest_events(db, all_events)
        return {
            "scenario_1_events": len(sc1),
            "scenario_2_events": len(sc2),
            "scenario_3_events": len(sc3),
            "total_events_seeded": len(ingested),
        }
