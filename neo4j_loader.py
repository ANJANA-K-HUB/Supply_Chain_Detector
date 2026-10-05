from neo4j import GraphDatabase
import networkx as nx

# 1. Database Connection Credentials 
# (You will need Neo4j Desktop or Neo4j Aura running locally on your computer)
URI = "neo4j://127.0.0.1:7687"
AUTH = ("neo4j", "Anjana#99")  # Replace with your actual Neo4j password

def save_graph_to_neo4j(tx, project_name, dependencies):
    """
    Cypher query to create the project node and dependency nodes 
    with a relationship between them.
    """
    # Create the root project node
    tx.run("MERGE (p:Project {name: $project_name})", project_name=project_name)
    
    # Create dependency nodes and connect them to the project
    for dep in dependencies:
        tx.run(
            """
            MATCH (p:Project {name: $project_name})
            MERGE (d:Dependency {name: $dep_name})
            ON CREATE SET d.version = $version, d.constraint = $constraint
            MERGE (p)-[:HAS_DEPENDENCY]->(d)
            """,
            project_name=project_name,
            dep_name=dep["name"],
            version=dep["version"],
            constraint=dep["constraint"]
        )

# --- Test run simulation ---
if __name__ == "__main__":
    # Sample parsed dependencies from Step 1
    sample_deps = [
        {"name": "requests", "version": "2.31.0", "constraint": "=="},
        {"name": "fastapi", "version": "0.100.0", "constraint": ">="}
    ]
    project_name = "SamplePythonApp"

    print("Attempting to connect to Neo4j database...")
    try:
        with GraphDatabase.driver(URI, auth=AUTH) as driver:
            with driver.session() as session:
                session.execute_write(save_graph_to_neo4j, project_name, sample_deps)
        print("Successfully saved dependency graph into Neo4j!")
    except Exception as e:
        print(f"Connection Note: Make sure Neo4j is running locally. Error: {e}")