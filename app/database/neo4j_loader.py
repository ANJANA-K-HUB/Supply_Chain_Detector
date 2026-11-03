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
            constraint=dep.get("constraint", "=="),
            is_vulnerable=dep.get("is_vulnerable", False),
            vuln_count=dep.get("vuln_count", 0),
            latest_vuln_summary=dep.get("latest_vuln_summary", "None"),
            exists_on_pypi=dep.get("exists_on_pypi", True),
            pypi_author=dep.get("pypi_author") or "Unknown",
            release_count=dep.get("release_count", 0)
        )

def save_parsed_dependencies_to_neo4j(project_name, parsed_dependencies, vulnerable_components):
    """
    Helper wrapper used by main.py to convert plain string dependencies (e.g. 'numpy==1.24.0')
    into detailed dictionaries and save them directly to Neo4j.
    """
    formatted_deps = []
    for dep_str in parsed_dependencies:
        # Handle requirements format (name==version or name>=version) or npm (name@version)
        if "==" in dep_str:
            name, ver = dep_str.split("==", 1)
            constraint = "=="
        elif ">=" in dep_str:
            name, ver = dep_str.split(">=", 1)
            constraint = ">="
        elif "@" in dep_str:
            name, ver = dep_str.split("@", 1)
            constraint = "@"
        else:
            name, ver = dep_str, "latest"
            constraint = "=="
            
        name = name.strip()
        ver = ver.strip()
        
        is_vuln = any(dep_str.lower() in v.lower() or name.lower() in v.lower() for v in vulnerable_components)
        
        formatted_deps.append({
            "name": name,
            "version": ver,
            "constraint": constraint,
            "is_vulnerable": is_vuln,
            "vuln_count": 1 if is_vuln else 0,
            "latest_vuln_summary": "Known vulnerable package version." if is_vuln else "None",
            "exists_on_pypi": True,
            "pypi_author": "Unknown",
            "release_count": 10
        })

    try:
        with GraphDatabase.driver(URI, auth=AUTH) as driver:
            with driver.session() as session:
                session.execute_write(save_graph_to_neo4j, project_name, formatted_deps)
        print(f"Successfully saved enhanced dependency graph for {project_name} into Neo4j!")
    except Exception as e:
        print(f"Neo4j connection error in loader: {e}")

# --- Test run simulation ---
if __name__ == "__main__":
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