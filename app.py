from fastapi import FastAPI, HTTPException
from neo4j import GraphDatabase
from pydantic import BaseModel
from typing import List, Optional

app = FastAPI(
    title="AI-Driven Software Supply-Chain Security Analyzer",
    description="API for querying dependency graphs and vulnerability statuses from Neo4j.",
    version="1.0.0"
)

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
    return {"message": "Welcome to the Supply-Chain Security Analyzer API!"}

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