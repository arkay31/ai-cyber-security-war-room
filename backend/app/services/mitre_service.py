import logging
from typing import List, Dict, Optional
from sqlalchemy.orm import Session
from backend.app.models.mitre import MitreTechnique, IncidentMitreMapping

logger = logging.getLogger(__name__)

# Official Enterprise ATT&CK techniques catalogue
OFFICIAL_MITRE_TECHNIQUES = [
    {
        "technique_id": "T1110",
        "name": "Brute Force",
        "tactic": "Credential Access",
        "description": "Adversaries may use brute force techniques to attempt access to accounts when passwords or password hashes are unknown. Techniques include password guessing, password spraying, and credential stuffing.",
        "external_id": "T1110"
    },
    {
        "technique_id": "T1046",
        "name": "Network Service Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may attempt to get a listing of services running on remote hosts and local network infrastructure, typically via port scanners to identify vulnerable applications and open ports.",
        "external_id": "T1046"
    },
    {
        "technique_id": "T1078",
        "name": "Valid Accounts",
        "tactic": "Initial Access",
        "description": "Adversaries may obtain and abuse credentials of existing accounts as a means of gaining Initial Access, Persistence, Privilege Escalation, or Defense Evasion.",
        "external_id": "T1078"
    },
    {
        "technique_id": "T1190",
        "name": "Exploit Public-Facing Application",
        "tactic": "Initial Access",
        "description": "Adversaries may attempt to exploit vulnerabilities in Internet-facing software (such as SQL injection, XSS, or RCE) to cause unexpected execution and compromise host systems.",
        "external_id": "T1190"
    },
    {
        "technique_id": "T1068",
        "name": "Exploitation for Privilege Escalation",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may exploit software vulnerabilities in an operating system or local software to elevate privileges from unprivileged user to root or SYSTEM.",
        "external_id": "T1068"
    },
    {
        "technique_id": "T1059",
        "name": "Command and Scripting Interpreter",
        "tactic": "Execution",
        "description": "Adversaries may abuse command and script interpreters (such as PowerShell, Bash, Python, or Cmd) to execute commands, scripts, or malicious payloads.",
        "external_id": "T1059"
    },
    {
        "technique_id": "T1083",
        "name": "File and Directory Discovery",
        "tactic": "Discovery",
        "description": "Adversaries may enumerate files and directories or search in specific locations for sensitive data, credentials, and configuration files.",
        "external_id": "T1083"
    },
    {
        "technique_id": "T1005",
        "name": "Data from Local System",
        "tactic": "Collection",
        "description": "Adversaries may search for and harvest sensitive files, intellectual property, credentials, or proprietary source code from local system storage.",
        "external_id": "T1005"
    },
    {
        "technique_id": "T1041",
        "name": "Exfiltration Over C2 Channel",
        "tactic": "Exfiltration",
        "description": "Adversaries may steal data by exfiltrating it over an existing command and control channel rather than creating a separate data egress tunnel.",
        "external_id": "T1041"
    },
    {
        "technique_id": "T1021",
        "name": "Remote Services / Lateral Movement",
        "tactic": "Lateral Movement",
        "description": "Adversaries may use valid credentials to log into remote services (such as SSH, RDP, SMB) to move laterally through the enterprise network.",
        "external_id": "T1021"
    },
    {
        "technique_id": "T1498",
        "name": "Network Denial of Service",
        "tactic": "Impact",
        "description": "Adversaries may perform Network Denial of Service (DoS/DDoS) attacks to degrade or block the availability of targeted servers, applications, or infrastructure.",
        "external_id": "T1498"
    },
    {
        "technique_id": "T1055",
        "name": "Process Injection",
        "tactic": "Privilege Escalation",
        "description": "Adversaries may inject code into processes in order to evade process-based defenses as well as possibly elevate privileges.",
        "external_id": "T1055"
    }
]

# Deterministic mapping from event types and ML prediction classes to MITRE Technique IDs
EVENT_TYPE_TO_MITRE = {
    "brute_force": ["T1110"],
    "failed_login": ["T1110"],
    "port_scan": ["T1046"],
    "reconnaissance": ["T1046"],
    "successful_login": ["T1078"],
    "unusual_login": ["T1078"],
    "account_compromise": ["T1078"],
    "web_attack": ["T1190"],
    "sql_injection": ["T1190"],
    "privilege_escalation": ["T1068"],
    "suspicious_process": ["T1059"],
    "powershell_execution": ["T1059"],
    "file_discovery": ["T1083"],
    "file_access": ["T1083"],
    "sensitive_file_access": ["T1005"],
    "data_collection": ["T1005"],
    "unusual_outbound_traffic": ["T1041"],
    "data_exfiltration": ["T1041"],
    "lateral_movement": ["T1021"],
    "remote_login": ["T1021"],
    "dos": ["T1498"],
    "ddos": ["T1498"],
    "botnet": ["T1041", "T1498"],
}

DETECTION_CLASS_TO_MITRE = {
    "DDoS": ["T1498"],
    "DoS": ["T1498"],
    "PortScan": ["T1046"],
    "Bot": ["T1041", "T1498"],
    "Infiltration": ["T1068", "T1021"],
    "Web Attack": ["T1190"],
    "Brute Force": ["T1110"],
}


class MitreService:
    @staticmethod
    def seed_techniques(db: Session) -> int:
        """Seed official MITRE techniques into database if not present."""
        count = 0
        for tech_data in OFFICIAL_MITRE_TECHNIQUES:
            existing = db.query(MitreTechnique).filter(
                MitreTechnique.technique_id == tech_data["technique_id"]
            ).first()
            if not existing:
                tech = MitreTechnique(
                    technique_id=tech_data["technique_id"],
                    name=tech_data["name"],
                    description=tech_data["description"],
                    tactic=tech_data["tactic"],
                    external_id=tech_data["external_id"],
                )
                db.add(tech)
                count += 1
        if count > 0:
            db.commit()
            logger.info(f"Seeded {count} MITRE ATT&CK techniques.")
        return count

    @staticmethod
    def get_techniques(db: Session) -> List[MitreTechnique]:
        return db.query(MitreTechnique).order_by(MitreTechnique.tactic, MitreTechnique.technique_id).all()

    @staticmethod
    def map_event_to_techniques(event_type: str, prediction_class: Optional[str] = None) -> List[str]:
        """Deterministic mapping from event and detection to MITRE technique IDs."""
        matched = set()
        normalized_event = event_type.lower().strip()
        if normalized_event in EVENT_TYPE_TO_MITRE:
            matched.update(EVENT_TYPE_TO_MITRE[normalized_event])

        if prediction_class:
            for key, t_ids in DETECTION_CLASS_TO_MITRE.items():
                if key.lower() in prediction_class.lower():
                    matched.update(t_ids)

        return sorted(list(matched))

    @staticmethod
    def link_incident_techniques(db: Session, incident_id: int, technique_ids: List[str]):
        """Link an incident to MITRE technique records in the database."""
        for tid in technique_ids:
            tech = db.query(MitreTechnique).filter(MitreTechnique.technique_id == tid).first()
            if tech:
                existing_map = db.query(IncidentMitreMapping).filter(
                    IncidentMitreMapping.incident_id == incident_id,
                    IncidentMitreMapping.technique_id == tech.id
                ).first()
                if not existing_map:
                    mapping = IncidentMitreMapping(
                        incident_id=incident_id,
                        technique_id=tech.id,
                        confidence=0.95
                    )
                    db.add(mapping)
        db.commit()
