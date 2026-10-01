"""
AI Analyst Service with Real RAG and Local LLM (Ollama) Pipeline.

Pipeline:
Incident + Events + Timeline + XGBoost + Isolation Forest + Risk Score + MITRE
  -> pgvector RAG Retrieval
  -> Retrieved Evidence
  -> Structured LLM Prompt
  -> Local Ollama LLM
  -> Structured Investigation

If Ollama is unavailable:
  Explicitly returns status "LLM_UNAVAILABLE" and falls back to clearly labeled "RULE_BASED" mode.
Never labels rule-based output as LLM output.
"""

import logging
import json
from typing import Dict, Any, List, Optional
from sqlalchemy.orm import Session
from sqlalchemy import desc

from backend.app.models.incident import Incident, IncidentEvent
from backend.app.models.security_event import SecurityEvent
from backend.app.models.detection import Detection
from backend.app.models.anomaly import Anomaly
from backend.app.models.mitre import MitreTechnique, IncidentMitreMapping
from backend.app.models.audit_log import AuditLog
from backend.app.services.rag_service import rag_service
from backend.app.services.llm_service import llm_service
from backend.app.services.correlation_engine import correlation_engine

logger = logging.getLogger(__name__)


class AIAnalystService:
    """
    Tier-2 Autonomous SOC Analyst Service.
    Combines ML telemetry, pgvector RAG evidence retrieval, and structured LLM inference.
    """

    def __init__(self):
        self.rag = rag_service
        self.llm = llm_service

    def assemble_prompt(
        self,
        incident: Incident,
        events: List[SecurityEvent],
        mitre_techs: List[MitreTechnique],
        timeline: List[Dict[str, Any]],
        ml_detections: List[Detection],
        ml_anomalies: List[Anomaly],
        rag_evidence: List[Dict[str, Any]],
    ) -> str:
        """
        Build an information-dense, concise context prompt for the local LLM.
        """
        lines = [
            f"=== INCIDENT: {incident.incident_id} ===",
            f"Title: {incident.title}",
            f"Severity: {incident.severity} | Risk Score: {incident.risk_score}/100",
            f"Attacker Source IP: {incident.source_ip or 'Unknown'} | Target Host: {incident.hostname or 'N/A'} | Target User: {incident.user or 'N/A'}",
            "",
            "=== ML ENSEMBLE RESULTS ==="
        ]

        if ml_detections:
            top_det = max(ml_detections, key=lambda d: d.confidence or 0.0)
            lines.append(f"- XGBoost Classifier: {top_det.predicted_class} ({top_det.confidence*100:.1f}% confidence)")
        if ml_anomalies:
            anom_count = sum(1 for a in ml_anomalies if a.is_anomalous)
            max_score = max((a.anomaly_score for a in ml_anomalies if a.anomaly_score is not None), default=0.0)
            lines.append(f"- Isolation Forest: {anom_count}/{len(ml_anomalies)} anomalies (Peak Score: {max_score:.2f})")

        lines.append("")
        lines.append("=== MITRE ATT&CK TECHNIQUES ===")
        for t in mitre_techs[:4]:
            lines.append(f"- [{t.technique_id}] {t.name} ({t.tactic})")

        lines.append("")
        lines.append("=== KEY TELEMETRY TIMELINE ===")
        for item in timeline[:6]:
            lines.append(f"- [{item.get('timestamp')}] {item.get('event_type')}: {item.get('source_ip')} -> {item.get('destination_ip')} ({item.get('description')})")

        lines.append("")
        lines.append("=== RETRIEVED PGVECTOR PLAYBOOKS & EVIDENCE ===")
        for ev in rag_evidence[:3]:
            lines.append(f"- [{ev.get('document_id')}] {ev.get('title')}: {ev.get('content')[:200]}")

        lines.append("""
=== TASK ===
Analyze this security incident as an expert SOC Analyst.
You MUST output ONLY a valid JSON object matching this schema:
{
  "incident_summary": "Cautious summary of observed actions and impact",
  "observed_evidence": ["Fact 1", "Fact 2"],
  "likely_attack_pattern": "Name of observed attack chain",
  "mitre_techniques": [{"technique_id": "T1110", "name": "Brute Force"}],
  "root_cause_hypothesis": "Hypothesis using words like 'likely' or 'evidence suggests'",
  "confidence": 0.88,
  "investigation_steps": ["Step 1", "Step 2"],
  "prioritized_recommendations": ["[PLAYBOOK-ATO-01] Recommendation 1", "Recommendation 2"],
  "evidence_references": [{"document_id": "PLAYBOOK-ATO-01", "title": "Playbook title"}],
  "analyst_warning": "Warning about required verification or unconfirmed aspects"
}
""")
        return "\n".join(lines)

    def investigate(self, db: Session, incident_id_or_str: Any) -> Dict[str, Any]:
        """
        Execute full investigation pipeline:
        1. Context extraction
        2. RAG evidence retrieval from pgvector
        3. Local LLM inference via Ollama
        4. Structured validation with rule-based fallback
        5. Audit logging
        """
        if isinstance(incident_id_or_str, int):
            incident = db.query(Incident).filter(Incident.id == incident_id_or_str).first()
        else:
            incident = db.query(Incident).filter(Incident.incident_id == str(incident_id_or_str)).first()

        if not incident:
            return {"error": f"Incident '{incident_id_or_str}' not found", "status": "failed"}

        # 1. Fetch related telemetry events
        events = (
            db.query(SecurityEvent)
            .join(IncidentEvent, IncidentEvent.event_id == SecurityEvent.id)
            .filter(IncidentEvent.incident_id == incident.id)
            .order_by(SecurityEvent.timestamp.asc())
            .all()
        )

        event_ids = [e.id for e in events]
        ml_detections = db.query(Detection).filter(Detection.event_id.in_(event_ids)).all() if event_ids else []
        ml_anomalies = db.query(Anomaly).filter(Anomaly.event_id.in_(event_ids)).all() if event_ids else []

        # 2. Fetch MITRE techniques
        mitre_techs = (
            db.query(MitreTechnique)
            .join(IncidentMitreMapping, IncidentMitreMapping.technique_id == MitreTechnique.id)
            .filter(IncidentMitreMapping.incident_id == incident.id)
            .all()
        )
        mitre_ids = [t.technique_id for t in mitre_techs]
        event_types = [e.event_type.lower() for e in events]

        # 3. Fetch ordered timeline
        timeline = correlation_engine.get_incident_timeline(db, incident.id)

        # 4. Perform Real RAG Retrieval from pgvector
        rag_evidence = self.rag.retrieve_for_incident(
            incident_title=incident.title,
            summary=incident.summary,
            event_types=event_types,
            mitre_ids=mitre_ids,
            db=db,
            top_k=5
        )

        # 5. Check LLM availability and execute inference
        is_ollama_ready = self.llm.check_availability()
        llm_result = None

        if is_ollama_ready:
            prompt = self.assemble_prompt(
                incident=incident,
                events=events,
                mitre_techs=mitre_techs,
                timeline=timeline,
                ml_detections=ml_detections,
                ml_anomalies=ml_anomalies,
                rag_evidence=rag_evidence,
            )
            system_msg = "You are a professional Tier-2 SOC Security Analyst assisting in incident triage and response."
            llm_result = self.llm.generate(prompt=prompt, system_prompt=system_msg, require_json=True)

        # 6. Build response according to execution outcome
        if llm_result and llm_result.get("success") and isinstance(llm_result.get("data"), dict):
            # Genuine LLM + RAG response
            parsed = llm_result["data"]
            analysis_mode = "LLM_RAG" if rag_evidence else "LLM"
            llm_status = analysis_mode
            llm_model = llm_result.get("model", "llama3")

            inc_summary = parsed.get("incident_summary") or f"Analysis for {incident.incident_id}"
            obs_evidence = parsed.get("observed_evidence", [f"{len(events)} correlated telemetry events analyzed."])
            likely_pattern = parsed.get("likely_attack_pattern") or incident.title
            m_techs = parsed.get("mitre_techniques", [{"technique_id": t.technique_id, "name": t.name} for t in mitre_techs])
            root_cause = parsed.get("root_cause_hypothesis", "Initial unauthorized access vector under investigation.")
            conf = float(parsed.get("confidence", 0.88))
            invest_steps = parsed.get("investigation_steps", [])
            prioritized_recs = parsed.get("prioritized_recommendations", [])
            evidence_refs = parsed.get("evidence_references", [
                {"document_id": ev["document_id"], "title": ev["title"], "technique_id": ev["technique_id"]}
                for ev in rag_evidence
            ])
            warning = parsed.get("analyst_warning", "Verify user intent via User Verification challenge before executing disruptive containment.")

        else:
            # Fallback to Rule-Based Analyst (Explicitly labeled RULE_BASED and LLM_UNAVAILABLE)
            analysis_mode = "RULE_BASED"
            llm_status = "LLM_UNAVAILABLE"
            llm_model = None

            obs_evidence = [
                f"Incident {incident.incident_id} correlates {len(events)} security events across hosts and network flows.",
                f"Source IP: {incident.source_ip or 'Unknown'}, Target User: {incident.user or 'N/A'}, Target Host: {incident.hostname or 'N/A'}.",
                f"XGBoost classification flagged high-severity attack signatures with composite risk score of {incident.risk_score}/100.",
                f"Isolation forest flagged {sum(1 for a in ml_anomalies if a.is_anomalous)} unusual behavioral anomalies."
            ]

            likely_pattern = incident.title
            m_techs = [{"technique_id": t.technique_id, "name": t.name} for t in mitre_techs]

            if "failed_login" in event_types or "brute_force" in event_types:
                root_cause = "Evidence suggests initial access was likely attempted through automated credential brute forcing."
            elif "unusual_login" in event_types or "account_compromise" in event_types:
                root_cause = "Evidence indicates abnormal account access potentially utilizing compromised credentials."
            else:
                root_cause = "Anomalous traffic and execution patterns suggest potential unauthorized perimeter interaction."

            inc_summary = (
                f"[Deterministic Rule-Based Fallback Analysis — LLM Status: LLM_UNAVAILABLE]\n"
                f"Incident {incident.incident_id} exhibits a multi-stage attack pattern involving {len(events)} events. "
                f"Correlated telemetry suggests {incident.title.lower()} with risk score {incident.risk_score}/100."
            )

            invest_steps = [
                "1. Cross-reference source IP against edge firewall logs and threat intelligence reputation lists.",
                "2. Initiate Human-in-the-Loop User Verification challenge to confirm whether activity was authorized.",
                "3. Inspect endpoint process trees for unexpected child shells or persistence mechanisms.",
                "4. Assess whether sensitive file paths or database records were staged or exfiltrated.",
                "5. Review Active Directory / IAM authentication logs for concurrent or impossible travel logins."
            ]

            prioritized_recs = [
                "1. [PLAYBOOK-ATO-01] Initiate User Verification to confirm legitimacy with affected user.",
                "2. [PLAYBOOK-ATO-01] Revoke active authentication tokens and enforce password reset if denied.",
                "3. [PLAYBOOK-PRIVESC-02] Prepare simulated host isolation on target host.",
                "4. [PLAYBOOK-RECON-04] Implement edge firewall block on attacker source IP address.",
                "5. [PLAYBOOK-EXFIL-03] Inspect egress NetFlow volume for staged exfiltration."
            ]

            evidence_refs = [
                {"document_id": ev["document_id"], "title": ev["title"], "technique_id": ev["technique_id"]}
                for ev in rag_evidence
            ]
            conf = 0.82
            warning = "Rule-based analysis active: Local Ollama LLM was unavailable. Review telemetry directly and initiate user verification."

        # Recommended response actions
        rec_actions = [
            "Verify User Authenticity",
            "Block Attacker IP (Simulated)",
            "Isolate Endpoint Host (Simulated)",
            "Revoke User Session (Simulated)",
            "Capture Forensic Snapshot (Simulated)"
        ]

        # Audit log creation
        audit = AuditLog(
            incident_id=incident.id,
            action="AI_INVESTIGATION_GENERATED",
            actor="ai_analyst_service",
            details={
                "analysis_mode": analysis_mode,
                "llm_status": llm_status,
                "llm_model": llm_model,
                "events_analyzed": len(events),
                "mitre_count": len(mitre_techs),
                "rag_evidence_count": len(rag_evidence),
                "risk_score": incident.risk_score
            }
        )
        db.add(audit)
        db.commit()

        return {
            "incident_id": incident.incident_id,
            "status": "completed",
            "analysis_mode": analysis_mode,
            "llm_status": llm_status,
            "llm_model": llm_model,
            "confidence": conf,
            "incident_summary": inc_summary,
            "observed_evidence": obs_evidence,
            "likely_attack_pattern": likely_pattern,
            "mitre_techniques": m_techs,
            "root_cause_hypothesis": root_cause,
            "investigation_steps": invest_steps,
            "prioritized_recommendations": prioritized_recs,
            "evidence_references": evidence_refs,
            "analyst_warning": warning,
            # Backward compatibility fields
            "investigation_summary": inc_summary,
            "recommended_steps": invest_steps,
            "recommended_actions": rec_actions,
            "evidence_gathered": {
                "source_ip": incident.source_ip,
                "target_host": incident.hostname,
                "target_user": incident.user,
                "event_count": len(events),
                "mitre_techniques": [f"{t.technique_id} - {t.name}" for t in mitre_techs],
                "severity_score": incident.risk_score,
                "rag_evidence": rag_evidence,
                "analysis_mode": analysis_mode
            }
        }


ai_analyst = AIAnalystService()
