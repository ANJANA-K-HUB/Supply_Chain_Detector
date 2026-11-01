class RiskAggregator:
    @staticmethod
    def calculate_overall_risk(codebert_score: float, gnn_risk: float, vulnerability_count: int, static_risk_score: float = 0.0) -> dict:
        """
        Aggregates scores from CodeBERT, GNN, vulnerabilities, and static analysis 
        into a single unified risk score, Low/Medium/High tier, and detailed XAI reasons.
        """
        w_codebert = 0.3
        w_gnn = 0.3
        w_vuln = 0.3
        w_static = 0.1

        normalized_vuln_score = min(float(vulnerability_count) / 10.0, 1.0)

        aggregate_score = (
            (codebert_score * w_codebert) +
            (gnn_risk * w_gnn) +
            (normalized_vuln_score * w_vuln) +
            (static_risk_score * w_static)
        )

        reasons = []

        # Determine Tier and build XAI reasons dynamically
        if aggregate_score > 0.6 or vulnerability_count > 3:
            tier = "High"
            summary = "Critical security risks detected across dependencies and code structure. Immediate action recommended."
            if vulnerability_count > 3:
                reasons.append(f"High vulnerability count detected ({vulnerability_count} active vulnerabilities).")
            if codebert_score > 0.5:
                reasons.append(f"Elevated semantic code risk score ({codebert_score}) indicating potentially dangerous code patterns.")
            if gnn_risk > 0.5:
                reasons.append(f"Severe cascading structural risk score ({gnn_risk}) propagating through dependency graphs.")
        elif aggregate_score > 0.3 or vulnerability_count > 0:
            tier = "Medium"
            summary = "Moderate risk level identified. Review flagged components and dependency paths."
            if vulnerability_count > 0:
                reasons.append(f"Contains {vulnerability_count} known vulnerability/vulnerabilities.")
            reasons.append(f"Moderate semantic ({codebert_score}) or structural ({gnn_risk}) indicators observed.")
        else:
            tier = "Low"
            summary = "Repository appears secure with low anomaly likelihood across evaluated components."
            reasons.append("All semantic and structural scores remain within safe thresholds.")
            reasons.append(f"No critical vulnerabilities found (count: {vulnerability_count}).")

        return {
            "aggregate_score": round(aggregate_score, 4),
            "risk_tier": tier,
            "summary": summary,
            "xai_explanation": {
                "risk_level": tier,
                "score": round(aggregate_score, 4),
                "reasons": reasons
            },
            "breakdown": {
                "codebert_score": codebert_score,
                "gnn_risk": gnn_risk,
                "vulnerability_count": vulnerability_count,
                "static_risk_score": static_risk_score
            }
        }