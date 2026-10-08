import os
import shutil
from neo4j import GraphDatabase
from github_loader import fetch_dependencies_from_github, download_repo_zip
from parser import parse_requirements_txt
from neo4j_loader import URI, AUTH, save_graph_to_neo4j
from vulnerability_checker import check_package_vulnerability
from behavior_analyzer import analyze_package_behavior
from code_analyzer import analyze_source_code

def analyze_github_repository(repo_url: str):
    """
    Pipeline: 
    1. Fetch dependencies -> Parse -> Check Vulnerabilities -> Analyze PyPI Behavior -> Save to Neo4j
    2. Download Repo Source Code -> Scan Python files (excluding venv) for code-level security issues
    """
    print(f"[*] Fetching dependencies from: {repo_url}")
    filename, file_content = fetch_dependencies_from_github(repo_url)
    
    temp_dep_file = f"temp_{filename}"
    with open(temp_dep_file, "w", encoding="utf-8") as f:
        f.write(file_content)
        
    repo_source_dir = None
    try:
        # Step A: Dependency, Vulnerability & Behavior Analysis
        print(f"[*] Parsing dependencies from {filename}...")
        dependencies = parse_requirements_txt(temp_dep_file)
        
        print(f"[*] Checking vulnerabilities and PyPI behavior for {len(dependencies)} packages...")
        for dep in dependencies:
            version = dep["version"]
            if version == "latest":
                version = "" 
                
            # 1. OSV Vulnerability Check
            vulns = check_package_vulnerability(dep["name"], version)
            if vulns:
                latest_vuln = vulns[0]
                summary = latest_vuln.get("summary") or latest_vuln.get("details", "No summary provided")
                if len(summary) > 150:
                    summary = summary[:147] + "..."
                    
                dep.update({
                    "is_vulnerable": True,
                    "vuln_count": len(vulns),
                    "latest_vuln_summary": summary
                })
            else:
                dep.update({
                    "is_vulnerable": False,
                    "vuln_count": 0,
                    "latest_vuln_summary": "None"
                })
                
            # 2. PyPI Package Behavior & Metadata Analysis
            behavior = analyze_package_behavior(dep["name"], version if version else None)
            dep.update({
                "exists_on_pypi": behavior["exists_on_pypi"],
                "pypi_author": behavior["author"],
                "release_count": behavior["release_count"],
                "behavior_risks": behavior["risk_indicators"]
            })
            
        # Robust project name extraction (strips /tree/main, .git, trailing slashes)
        clean_url = repo_url.rstrip("/")
        if "/tree/" in clean_url:
            clean_url = clean_url.split("/tree/")[0]
        elif "/blob/" in clean_url:
            clean_url = clean_url.split("/blob/")[0]
        if clean_url.endswith(".git"):
            clean_url = clean_url[:-4]
        project_name = clean_url.split("/")[-1]
        
        print(f"[*] Saving enhanced graph for project '{project_name}' to Neo4j...")
        with GraphDatabase.driver(URI, auth=AUTH) as driver:
            with driver.session() as session:
                session.execute_write(save_graph_to_neo4j, project_name, dependencies)
                
        # Step B: Code-Level Security Analysis
        print("[*] Downloading repository source code for code analysis...")
        repo_source_dir = download_repo_zip(repo_url)
        
        code_findings = []
        ignored_dirs = {".env", "venv", "env", ".git", "__pycache__", "site-packages"}
        
        print("[*] Scanning source files (.py) for security risks...")
        for root, dirs, files in os.walk(repo_source_dir):
            dirs[:] = [d for d in dirs if d not in ignored_dirs]
            
            for file in files:
                if file.endswith(".py"):
                    full_path = os.path.join(root, file)
                    relative_path = os.path.relpath(full_path, repo_source_dir)
                    
                    file_findings = analyze_source_code(full_path)
                    if file_findings:
                        code_findings.append({
                            "file": relative_path,
                            "issues": file_findings
                        })
                        
        return {
            "status": "success",
            "repo_url": repo_url,
            "project_name": project_name,
            "dependency_file_used": filename,
            "dependencies_analyzed": len(dependencies),
            "dependencies_found": dependencies,
            "code_analysis_findings": code_findings
        }
        
    finally:
        if os.path.exists(temp_dep_file):
            os.remove(temp_dep_file)
        if repo_source_dir and os.path.exists(os.path.dirname(repo_source_dir)):
            shutil.rmtree(os.path.dirname(repo_source_dir), ignore_errors=True)