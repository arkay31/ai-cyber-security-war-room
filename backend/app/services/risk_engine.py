from typing import Dict, Any, Optional, List


class RiskEngine:
    """
    Transparent, configurable risk scoring engine for security events and incidents.
    Calculates a deterministic 0-100 risk score based on ML confidence, anomaly score,
    event severity, asset/user criticality, and multi-stage correlation context.
    """

    SEVERITY_SCORES = {
        "critical": 100.0,
        "high": 75.0,
        "medium": 50.0,
        "low": 20.0,
        "informational": 5.0,
    }

    CRITICAL_TARGETS = {
        "admin", "root", "administrator", "system", "finance", "dbadmin",
        "domain-controller", "dc01", "db-prod", "database", "api-gateway", "auth-server"
    }

    @staticmethod
    def calculate_event_risk(
        event_dict: Dict[str, Any],
        ml_prediction: Optional[Dict[str, Any]] = None,
        anomaly_result: Optional[Dict[str, Any]] = None,
    ) -> Dict[str, Any]:
        """
        Calculate transparent risk score for a single event.
        Returns: { 'risk_score': float, 'severity': str, 'factors': dict }
        """
        # 1. Supervised ML Detection Component (weight 0.30)
        ml_score = 0.0
        ml_class = "BENIGN"
        ml_conf = 0.0
        if ml_prediction:
            ml_class = ml_prediction.get("predicted_class", "BENIGN")
            ml_conf = float(ml_prediction.get("confidence", 0.0))
            if ml_class != "BENIGN":
                ml_score = ml_conf * 100.0
            else:
                ml_score = 5.0

        # 2. Anomaly Detection Component (weight 0.25)
        anomaly_score = 0.0
        if anomaly_result:
            anomaly_score = float(anomaly_result.get("anomaly_score", 0.0)) * 100.0

        # 3. Event Severity Component (weight 0.25)
        raw_sev = str(event_dict.get("severity", "medium")).lower()
        severity_score = RiskEngine.SEVERITY_SCORES.get(raw_sev, 50.0)

        # 4. Asset / User Context Component (weight 0.20)
        user = str(event_dict.get("user") or "").lower()
        hostname = str(event_dict.get("hostname") or "").lower()
        is_critical_user = any(crit in user for crit in RiskEngine.CRITICAL_TARGETS if crit)
        is_critical_host = any(crit in hostname for crit in RiskEngine.CRITICAL_TARGETS if crit)
        asset_score = 90.0 if (is_critical_user or is_critical_host) else 35.0

        # Weighted composition
        calculated = (
            0.30 * ml_score +
            0.25 * anomaly_score +
            0.25 * severity_score +
            0.20 * asset_score
        )

        final_score = round(min(max(calculated, 0.0), 100.0), 1)

        # Map to discrete severity tier
        if final_score >= 75.0:
            severity = "CRITICAL"
        elif final_score >= 50.0:
            severity = "HIGH"
        elif final_score >= 25.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "risk_score": final_score,
            "severity": severity,
            "factors": {
                "ml_component": round(ml_score, 1),
                "anomaly_component": round(anomaly_score, 1),
                "severity_component": round(severity_score, 1),
                "asset_context_component": round(asset_score, 1),
                "formula": "0.30*ML + 0.25*Anomaly + 0.25*Severity + 0.20*AssetContext"
            }
        }

    @staticmethod
    def calculate_incident_risk(
        events: List[Dict[str, Any]],
        mitre_count: int = 0
    ) -> Dict[str, Any]:
        """
        Calculate overall aggregated risk score for an incident spanning multiple correlated events.
        """
        if not events:
            return {"risk_score": 20.0, "severity": "LOW"}

        event_risks = [e.get("risk_score", 50.0) for e in events]
        max_risk = max(event_risks)
        avg_risk = sum(event_risks) / len(event_risks)

        # Progression bonus for multi-stage attack chains
        stage_boost = min(len(events) * 3.0, 15.0)
        mitre_boost = min(mitre_count * 4.0, 15.0)

        # Aggregate: 60% max event risk + 40% average event risk + progression bonus
        aggregated = (0.60 * max_risk) + (0.40 * avg_risk) + stage_boost + mitre_boost
        final_score = round(min(max(aggregated, 0.0), 100.0), 1)

        if final_score >= 75.0:
            severity = "CRITICAL"
        elif final_score >= 50.0:
            severity = "HIGH"
        elif final_score >= 25.0:
            severity = "MEDIUM"
        else:
            severity = "LOW"

        return {
            "risk_score": final_score,
            "severity": severity,
            "max_event_risk": max_risk,
            "event_count": len(events),
            "mitre_count": mitre_count
        }


risk_engine = RiskEngine()
