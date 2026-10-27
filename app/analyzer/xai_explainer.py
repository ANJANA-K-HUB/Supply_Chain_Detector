class XAIExplainer:
    @staticmethod
    def explain_codebert(score: float, snippet: str) -> dict:
        """Generates explanations for CodeBERT semantic analysis."""
        reasons = []
        
        if score > 0.7:
            risk_level = "High"
            reasons.append("High semantic risk score detected based on code patterns.")
        elif score > 0.4:
            risk_level = "Medium"
            reasons.append("Moderate risk patterns identified in semantic representation.")
        else:
            risk_level = "Low"
            reasons.append("Code pattern appears safe with low anomaly likelihood.")

        # Simple static keyword checks to enrich explanation
        suspicious_keywords = ["eval", "exec", "pickle", "subprocess", "os.system", "requests.get"]
        found_keywords = [kw for kw in suspicious_keywords if kw in snippet]
        
        if found_keywords:
            reasons.append(f"Potentially sensitive or high-privilege functions found: {', '.join(found_keywords)}.")

        return {
            "risk_level": risk_level,
            "score": score,
            "reasons": reasons
        }

    @staticmethod
    def explain_gnn(propagated_scores: list) -> dict:
        """Generates explanations for GNN structural risk propagation."""
        explanations = []
        max_risk = max(propagated_scores) if propagated_scores else 0.0

        if max_risk > 0.6:
            overall_status = "High Structural Risk"
            explanations.append("High risk propagated from heavily connected or vulnerable neighbor nodes in the dependency graph.")
        elif max_risk > 0.3:
            overall_status = "Moderate Structural Risk"
            explanations.append("Moderate risk bleeding through dependency linkages.")
        else:
            overall_status = "Low Structural Risk"
            explanations.append("Dependency neighborhood shows stable and low-risk propagation characteristics.")

        return {
            "overall_structural_status": overall_status,
            "max_propagated_risk": max_risk,
            "explanations": explanations
        }