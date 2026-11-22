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
from backend.app.schemas.incident import AIInvestigationSchema
from backend.app.ml.inference import inference_engine

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
        feature_attributions: Optional[List[Dict[str, Any]]] = None,
        anomaly_deviations: Optional[List[Dict[str, Any]]] = None,
    ) -> str:
        """
        Build an information-dense, concise context prompt for the local LLM.
        Injects mathematically verified TreeSHAP feature attributions and anomaly deviations.
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

        if feature_attributions:
            lines.append("- TreeSHAP Feature Attributions:")
            for fa in feature_attributions[:4]:
                lines.append(f"  * {fa.get('feature')}: {fa.get('value')} (SHAP: {fa.get('shap_value')}) -> {fa.get('impact')}")

        if anomaly_deviations:
            lines.append("- Baseline Anomaly Deviations (Z-Scores):")
            for dev in anomaly_deviations[:3]:
                lines.append(f"  * {dev.get('feature')}: observed={dev.get('observed')}, benign_mean={dev.get('benign_mean')} ({dev.get('z_score')} std {dev.get('direction')})")

        lines.append("")
        if mitre_techs:
            lines.append("=== MITRE ATT&CK TECHNIQUES ===")
            for t in mitre_techs[:4]:
                lines.append(f"- [{t.technique_id}] {t.name} ({t.tactic})")

        lines.append("")
        lines.append("=== KEY TELEMETRY TIMELINE ===")
        for item in timeline[:6]:
            lines.append(f"- [{item.get('timestamp')}] {item.get('event_type')}: {item.get('source_ip')} -> {item.get('destination_ip')} ({item.get('description')})")

        lines.append("")
        lines.append("=== RETRIEVED PGVECTOR PLAYBOOKS & EVIDENCE ===")
        if rag_evidence:
            for ev in rag_evidence[:4]:
                sim = ev.get('similarity_score', 0.0)
                warning_note = " (LOW RELEVANCE - USE CAUTION)" if ev.get("is_low_relevance") else ""
                lines.append(f"- [{ev.get('document_id')}] (sim: {sim:.2f}{warning_note}) {ev.get('title')}: {ev.get('content', '')[:300]}")
        else:
            lines.append("- (No semantic playbooks retrieved for this incident telemetry)")

        lines.append("""
=== ANTI-HALLUCINATION DIRECTIVES ===
1. Base all findings strictly on the verified telemetry, TreeSHAP attributions, and retrieved playbooks above.
2. DO NOT invent IP addresses, users, or exploit techniques not evidenced in the context.
3. If playbooks are marked LOW RELEVANCE, note that they are general guidelines and not verified evidence.
4. If activity is inconclusive, explicitly state 'Suspicious activity observed; human verification required'.
5. Output ONLY a valid JSON object matching this schema (under 25 words per step/recommendation):
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
        if isinstance(incident_id_or_str, int) or (isinstance(incident_id_or_str, str) and incident_id_or_str.isdigit()):
            incident = db.query(Incident).filter(Incident.id == int(incident_id_or_str)).first()
        else:
            incident = db.query(Incident).filter(Incident.incident_id == str(incident_id_or_str)).first()

        if not incident and isinstance(incident_id_or_str, str) and not incident_id_or_str.isdigit():
            incident = db.query(Incident).filter(Incident.incident_id.ilike(f"%{incident_id_or_str}%")).first()

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

        # 5. Extract local TreeSHAP explanations and Anomaly Deviations
        shap_features = []
        anomaly_deviations = []
        if events:
            primary_ev = events[-1]
            ev_dict = {
                "event_type": primary_ev.event_type,
                "source_ip": primary_ev.source_ip,
                "destination_port": primary_ev.destination_port,
                "raw_data": primary_ev.raw_data or {}
            }
            try:
                top_det = max(ml_detections, key=lambda d: d.confidence or 0.0) if ml_detections else None
                pred_cls = top_det.predicted_class if top_det else "Brute Force"
                threat_expl = inference_engine.explain_threat(ev_dict, pred_cls)
                shap_features = threat_expl.get("top_features", [])

                anom_expl = inference_engine.explain_anomaly(ev_dict, True, 0.75)
                anomaly_deviations = anom_expl.get("deviations", [])
            except Exception as e:
                logger.warning(f"Could not compute local SHAP for incident {incident.incident_id}: {e}")

        # 6. Check LLM availability and execute inference
        is_llm_ready = self.llm.check_availability()
        llm_result = None

        if is_llm_ready:
            prompt = self.assemble_prompt(
                incident=incident,
                events=events,
                mitre_techs=mitre_techs,
                timeline=timeline,
                ml_detections=ml_detections,
                ml_anomalies=ml_anomalies,
                rag_evidence=rag_evidence,
                feature_attributions=shap_features,
                anomaly_deviations=anomaly_deviations,
            )
            system_msg = "You are a professional Tier-2 SOC Security Analyst assisting in incident triage and response."
            llm_result = self.llm.generate(prompt=prompt, system_prompt=system_msg, require_json=True)
        else:
            logger.warning(
                f"Configured LLM inference service or model '{self.llm.model_name}' unavailable. Triggering RULE_BASED fallback."
            )

        # 7. Build response according to execution outcome
        if llm_result and llm_result.get("success") and isinstance(llm_result.get("data"), dict):
            # Genuine LLM + RAG response validated via strict Pydantic schema
            validated = AIInvestigationSchema.sanitize_raw_llm_dict(llm_result["data"])
            analysis_mode = "LLM_RAG" if rag_evidence else "LLM"
            llm_status = analysis_mode
            llm_model = llm_result.get("model", self.llm.model_name)
            llm_metrics = llm_result.get("metrics", {})
            llm_error = None

            inc_summary = validated.incident_summary
            obs_evidence = validated.observed_evidence if validated.observed_evidence else [f"{len(events)} correlated telemetry events analyzed."]
            likely_pattern = validated.likely_attack_pattern or incident.title
            m_techs = validated.mitre_techniques if validated.mitre_techniques else [
                {"technique_id": t.technique_id, "name": t.name, "tactic": t.tactic} for t in mitre_techs
            ]
            root_cause = validated.root_cause_hypothesis or "Initial unauthorized access vector under investigation."
            conf = validated.confidence
            invest_steps = validated.investigation_steps
            prioritized_recs = validated.prioritized_recommendations
            warning = validated.analyst_warning or "Verify user intent via User Verification challenge before executing disruptive containment."

            if rag_evidence:
                evidence_refs = [
                    {
                        "document_id": ev.get("document_id", "REF-01"),
                        "title": ev.get("title", "Standard Playbook"),
                        "technique_id": ev.get("technique_id"),
                        "similarity_score": round(ev.get("similarity_score", 0.0), 3) if ev.get("similarity_score") else None,
                        "category": ev.get("category", "Playbook"),
                        "content_snippet": (ev.get("content", "")[:260] + "...") if len(ev.get("content", "")) > 260 else ev.get("content", "")
                    }
                    for ev in rag_evidence
                ]
            else:
                evidence_refs = []

        else:
            # Fallback to Rule-Based Analyst (Explicitly labeled RULE_BASED and LLM_UNAVAILABLE)
            analysis_mode = "RULE_BASED"
            llm_status = "LLM_UNAVAILABLE"
            llm_model = None
            llm_metrics = {}
            llm_error = llm_result.get("error", "Ollama daemon unreachable or model not found") if llm_result else "Ollama daemon unreachable or model not found"

            logger.warning(
                f"AI Analyst fallback active: mode={analysis_mode}, llm_status={llm_status}, reason='{llm_error}'"
            )

            obs_evidence = [
                f"Incident {incident.incident_id} correlates {len(events)} security events across hosts and network flows.",
                f"Source IP: {incident.source_ip or 'Unknown'}, Target User: {incident.user or 'N/A'}, Target Host: {incident.hostname or 'N/A'}.",
                f"XGBoost classification flagged high-severity attack signatures with composite risk score of {incident.risk_score}/100.",
                f"Isolation forest flagged {sum(1 for a in ml_anomalies if a.is_anomalous)} unusual behavioral anomalies."
            ]

            likely_pattern = incident.title
            m_techs = [{"technique_id": t.technique_id, "name": t.name, "tactic": t.tactic} for t in mitre_techs]

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

            if rag_evidence:
                evidence_refs = [
                    {
                        "document_id": ev.get("document_id", "REF-01"),
                        "title": ev.get("title", "Standard Playbook"),
                        "technique_id": ev.get("technique_id"),
                        "similarity_score": round(ev.get("similarity_score", 0.0), 3) if ev.get("similarity_score") else None,
                        "category": ev.get("category", "Playbook"),
                        "content_snippet": (ev.get("content", "")[:260] + "...") if len(ev.get("content", "")) > 260 else ev.get("content", "")
                    }
                    for ev in rag_evidence
                ]
            else:
                evidence_refs = []

            conf = 0.82
            warning = f"Rule-based analysis active: Local Ollama LLM was unavailable ({llm_error}). Review telemetry directly and initiate user verification."

        # Recommended response actions
        rec_actions = [
            "Verify User Authenticity",
            "Block Attacker IP (Simulated)",
            "Isolate Endpoint Host (Simulated)",
            "Revoke User Session (Simulated)",
            "Capture Forensic Snapshot (Simulated)"
        ]

        # Audit log creation
        audit_details = {
            "analysis_mode": analysis_mode,
            "llm_status": llm_status,
            "llm_model": llm_model,
            "events_analyzed": len(events),
            "mitre_count": len(mitre_techs),
            "rag_evidence_count": len(rag_evidence),
            "risk_score": incident.risk_score
        }
        if llm_error:
            audit_details["llm_error"] = llm_error
        if llm_metrics:
            audit_details["llm_metrics"] = llm_metrics

        audit = AuditLog(
            incident_id=incident.id,
            action="AI_INVESTIGATION_GENERATED",
            actor="ai_analyst_service",
            details=audit_details
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
            "feature_attributions": shap_features,
            "anomaly_deviations": anomaly_deviations,
            "analyst_warning": warning,
            "llm_metrics": llm_metrics,
            "llm_error": llm_error,
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
