import datetime

class SecurityReportGenerator:
    @staticmethod
    def generate_report(repo_name: str, comprehensive_risk_result: dict, affected_dependencies: list = None) -> dict:
        """
        Compiles detected risks, XAI reasons, affected components, and 
        recommended actions into a structured AI-assisted security report.
        """
        if affected_dependencies is None:
            affected_dependencies = []

        risk_tier = comprehensive_risk_result.get("risk_tier", "Low")
        aggregate_score = comprehensive_risk_result.get("aggregate_score", 0.0)
        summary = comprehensive_risk_result.get("summary", "")
        xai_explanation = comprehensive_risk_result.get("xai_explanation", {})
        breakdown = comprehensive_risk_result.get("breakdown", {})

        # Generate custom recommended actions based on the evaluated risk tier
        recommendations = []
        if risk_tier == "High":
            recommendations = [
                "Immediately patch or remove flagged high-severity vulnerabilities.",
                "Audit direct and indirect dependency trees in Neo4j to isolate cascading failure points.",
                "Review code snippets flagged by CodeBERT for insecure system calls or execution risks."
            ]
        elif risk_tier == "Medium":
            recommendations = [
                "Schedule updates for outdated or moderately risky dependencies.",
                "Inspect code patterns flagged for moderate semantic anomalies.",
                "Monitor dependency graph paths for unexpected version shifts."
            ]
        else:
            recommendations = [
                "No immediate action required. Continue routine dependency monitoring.",
                "Maintain standard code review practices before publishing new releases."
            ]

        return {
            "report_metadata": {
                "repository": repo_name,
                "generated_at": datetime.datetime.utcnow().isoformat() + "Z",
                "generator": "AI-Based Software Supply-Chain Attack Detection System"
            },
            "executive_summary": {
                "overall_risk_tier": risk_tier,
                "aggregate_risk_score": aggregate_score,
                "assessment_summary": summary
            },
            "explainable_ai_insights": xai_explanation,
            "risk_breakdown": breakdown,
            "affected_components": affected_dependencies,
            "recommended_actions": recommendations
        }