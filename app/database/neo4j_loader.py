from neo4j import GraphDatabase
import networkx as nx

# 1. Database Connection Credentials 
URI = "neo4j://127.0.0.1:7687"
AUTH = ("neo4j", "Anjana#99")  # Your Neo4j password

def save_graph_to_neo4j(tx, project_name, dependencies):
    """
    Cypher query to create the project node and dependency nodes 
    with vulnerability and PyPI behavior attributes attached.
    """
    # Create the root project node
    tx.run("MERGE (p:Project {name: $project_name})", project_name=project_name)
    
    # Create dependency nodes and connect them to the project
    for dep in dependencies:
        tx.run(
            """
            MATCH (p:Project {name: $project_name})
            MERGE (d:Dependency {name: $dep_name})
            ON CREATE SET d.version = $version, 
                          d.constraint = $constraint,
                          d.is_vulnerable = $is_vulnerable,
                          d.vuln_count = $vuln_count,
                          d.latest_vuln_summary = $latest_vuln_summary,
                          d.exists_on_pypi = $exists_on_pypi,
                          d.pypi_author = $pypi_author,
                          d.release_count = $release_count
            ON MATCH SET d.version = $version, 
                         d.constraint = $constraint,
                         d.is_vulnerable = $is_vulnerable,
                         d.vuln_count = $vuln_count,
                         d.latest_vuln_summary = $latest_vuln_summary,
                         d.exists_on_pypi = $exists_on_pypi,
                         d.pypi_author = $pypi_author,
                         d.release_count = $release_count
            MERGE (p)-[:HAS_DEPENDENCY]->(d)
            """,
            project_name=project_name,
            dep_name = dep.get("name") or dep.get("package") or "unknown-dependency",
            version=dep.get("version", ""),
            constraint=dep.get("constraint", ""),
            is_vulnerable=dep.get("is_vulnerable", False),
            vuln_count=dep.get("vuln_count", 0),
            latest_vuln_summary=dep.get("latest_vuln_summary", "None"),
            exists_on_pypi=dep.get("exists_on_pypi", True),
            pypi_author=dep.get("pypi_author") or "Unknown",
            release_count=dep.get("release_count", 0)
        )

# --- Test run simulation ---
if __name__ == "__main__":
    # Sample parsed dependencies with vulnerability & behavior data
    sample_deps = [
        {
            "name": "requests", 
            "version": "2.31.0", 
            "constraint": "==",
            "is_vulnerable": False,
            "vuln_count": 0,
            "latest_vuln_summary": "None",
            "exists_on_pypi": True,
            "pypi_author": "Kenneth Reitz",
            "release_count": 70
        },
        {
            "name": "fastapi", 
            "version": "0.100.0", 
            "constraint": ">=",
            "is_vulnerable": False,
            "vuln_count": 0,
            "latest_vuln_summary": "None",
            "exists_on_pypi": True,
            "pypi_author": "Tiangolo",
            "release_count": 120
        }
    ]
    project_name = "SamplePythonApp"

    print("Attempting to connect to Neo4j database...")
    try:
        with GraphDatabase.driver(URI, auth=AUTH) as driver:
            with driver.session() as session:
                session.execute_write(save_graph_to_neo4j, project_name, sample_deps)
        print("Successfully saved enhanced dependency graph into Neo4j!")
    except Exception as e:
        print(f"Connection Note: Make sure Neo4j is running locally. Error: {e}")