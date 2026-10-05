from neo4j import GraphDatabase
import requests

# Neo4j connection details (use your actual password)
URI = "neo4j://127.0.0.1:7687"
AUTH = ("neo4j", "Anjana#99")  # Replace with your actual password

def get_all_dependencies(tx):
    """Fetches all dependencies stored in the Neo4j database."""
    result = tx.run("MATCH (d:Dependency) RETURN d.name AS name, d.version AS version")
    return [{"name": record["name"], "version": record["version"]} for record in result]

def update_dependency_vulnerabilities(tx, package_name, version, vulnerabilities):
    """Updates a dependency node in Neo4j with its vulnerability status."""
    has_vuln = len(vulnerabilities) > 0
    vuln_count = len(vulnerabilities)
    # Get a summary string of the first vulnerability if it exists
    vuln_summary = vulnerabilities[0].get("summary", "Unknown vulnerability") if has_vuln else "None"

    tx.run(
        """
        MATCH (d:Dependency {name: $name, version: $version})
        SET d.is_vulnerable = $has_vuln,
            d.vuln_count = $vuln_count,
            d.latest_vuln_summary = $vuln_summary
        """,
        name=package_name,
        version=version,
        has_vuln=has_vuln,
        vuln_count=vuln_count,
        vuln_summary=vuln_summary
    )

def check_osv_api(package_name, version):
    """Queries OSV.dev for a package version."""
    url = "https://api.osv.dev/v1/query"
    payload = {
        "package": {"name": package_name, "ecosystem": "PyPI"},
        "version": version
    }
    try:
        response = requests.post(url, json=payload)
        if response.status_code == 200:
            return response.json().get("vulns", [])
    except Exception as e:
        print(f"API Error for {package_name}: {e}")
    return []

if __name__ == "__main__":
    print("Connecting to Neo4j to fetch dependencies...")
    try:
        with GraphDatabase.driver(URI, auth=AUTH) as driver:
            with driver.session() as session:
                # 1. Fetch dependencies from Neo4j
                deps = session.execute_read(get_all_dependencies)
                print(f"Found {len(deps)} dependency nodes in Neo4j. Scanning via OSV API...")

                # 2. Scan each dependency using OSV and update Neo4j
                for dep in deps:
                    name = dep["name"]
                    version = dep["version"]
                    print(f"Checking {name} ({version})...")
                    
                    vulns = check_osv_api(name, version)
                    
                    # 3. Update database with findings
                    session.execute_write(update_dependency_vulnerabilities, name, version, vulns)
                    print(f" -> Updated Neo4j: {len(vulns)} vulnerabilities found.")

        print("\n✅ Sync complete! All dependency nodes updated with vulnerability status in Neo4j.")

    except Exception as e:
        print(f"Connection or execution error: {e}")