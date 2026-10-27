from fastapi import FastAPI, HTTPException
from neo4j import GraphDatabase
from pydantic import BaseModel
from typing import List, Optional
from app.utils.integration import analyze_github_repository
from app.analyzer.xai_explainer import XAIExplainer

# Import your modular AI analyzers
from app.analyzer.codebert_analyzer import CodeBERTAnalyzer
from app.analyzer.gnn_analyzer import GNNAnalyzer

app = FastAPI(
    title="AI-Driven Software Supply-Chain Security Analyzer",
    description="API backend integrating Neo4j dependency graphs, CodeBERT semantic analysis, and GNN risk propagation.",
    version="1.0.0"
)

# Lazy-load AI analyzers on startup to save memory and initialization time
codebert_analyzer = None
gnn_analyzer = None

@app.on_event("startup")
def load_ai_models():
    global codebert_analyzer, gnn_analyzer
    print("Loading AI analyzers into memory...")
    codebert_analyzer = CodeBERTAnalyzer()
    gnn_analyzer = GNNAnalyzer(feature_dim=4)
    print("AI analyzers loaded successfully!")

# Define request body models
class RepoRequest(BaseModel):
    repo_url: str

class CodeAnalysisRequest(BaseModel):
    code_snippet: str

class GNNAnalysisRequest(BaseModel):
    node_features: List[List[float]]
    adjacency_matrix: List[List[float]]

@app.post("/analyze-repo")
def analyze_repo_endpoint(payload: RepoRequest):
    try:
        result = analyze_github_repository(payload.repo_url)
        return {"status": "success", "data": result}
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))
    
# Neo4j connection configuration
URI = "neo4j://127.0.0.1:7687"
AUTH = ("neo4j", "Anjana#99")  # Update with your actual password if different

def get_neo4j_driver():
    return GraphDatabase.driver(URI, auth=AUTH)

# Pydantic models for response validation
class DependencyModel(BaseModel):
    name: str
    version: str
    is_vulnerable: Optional[bool] = False
    vuln_count: Optional[int] = 0
    latest_vuln_summary: Optional[str] = "None"

@app.get("/")
def read_root():
    return {
        "message": "Welcome to the Supply-Chain Security Analyzer API!",
        "status": "Active",
        "docs_url": "/docs"
    }

@app.get("/dependencies", response_model=List[DependencyModel])
def get_dependencies():
    """
    Fetches all dependency nodes and their vulnerability statuses from Neo4j.
    """
    try:
        with get_neo4j_driver() as driver:
            with driver.session() as session:
                result = session.run(
                    """
                    MATCH (d:Dependency)
                    RETURN d.name AS name, 
                           d.version AS version, 
                           d.is_vulnerable AS is_vulnerable, 
                           d.vuln_count AS vuln_count, 
                           d.latest_vuln_summary AS latest_vuln_summary
                    """
                )
                dependencies = []
                for record in result:
                    dependencies.append({
                        "name": record["name"],
                        "version": record["version"],
                        "is_vulnerable": record["is_vulnerable"] if record["is_vulnerable"] is not None else False,
                        "vuln_count": record["vuln_count"] if record["vuln_count"] is not None else 0,
                        "latest_vuln_summary": record["latest_vuln_summary"] if record["latest_vuln_summary"] is not None else "None"
                    })
                return dependencies
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"Database error: {str(e)}")


# --- NEW AI ANALYZER ENDPOINTS ---


@app.post("/analyze/codebert")
def analyze_code_semantic(request: CodeAnalysisRequest):
    """
    Endpoint to analyze a source code snippet using CodeBERT embeddings and XAI insights.
    """
    if not codebert_analyzer:
        raise HTTPException(status_code=500, detail="CodeBERT model not initialized.")
    
    try:
        # Get raw analysis result (assuming it returns a dict or includes a 'semantic_risk_score' or similar float)
        result = codebert_analyzer.analyze_snippet_risk(request.code_snippet)
        
        # Extract risk score safely from result (adjust key if your analyzer uses a different key name)
        score = result.get("semantic_risk_score", 0.0) if isinstance(result, dict) else float(result)
        
        # Run through XAI Explainer
        xai_explanation = XAIExplainer.explain_codebert(score, request.code_snippet)
        
        return {
            "module": "CodeBERT",
            "analysis": result,
            "xai_explanation": xai_explanation
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))

@app.post("/analyze/gnn")
def analyze_graph_structure(request: GNNAnalysisRequest):
    """
    Endpoint to evaluate cascading dependency risks using the GNN analyzer and XAI insights.
    """
    if not gnn_analyzer:
        raise HTTPException(status_code=500, detail="GNN model not initialized.")
    
    try:
        # Get raw analysis result from GNN
        result = gnn_analyzer.evaluate_graph_risks(request.node_features, request.adjacency_matrix)
        
        # Extract propagated scores safely (adjust key if your GNN output uses a different key name)
        if isinstance(result, dict):
            propagated_scores = result.get("propagated_risk_scores", [])
        else:
            propagated_scores = list(result)
            
        # Run through XAI Explainer
        xai_explanation = XAIExplainer.explain_gnn(propagated_scores)
        
        return {
            "module": "GNN",
            "analysis": result,
            "xai_explanation": xai_explanation
        }
    except Exception as e:
        raise HTTPException(status_code=500, detail=str(e))