import json
import os
import networkx as nx

def parse_requirements_txt(file_path):
    """Parses a Python requirements.txt file."""
    dependencies = []
    with open(file_path, 'r', encoding='utf-8') as f:
        for line in f:
            line = line.strip()
            if not line or line.startswith('#'):
                continue
            # Handle version specifiers
            for delim in ['==', '>=', '<=', '>', '<', '~=']:
                if delim in line:
                    name, version = line.split(delim, 1)
                    dependencies.append({"name": name.strip(), "version": version.strip(), "constraint": delim})
                    break
            else:
                dependencies.append({"name": line, "version": "latest", "constraint": "none"})
    return dependencies

def parse_package_json(file_path):
    """Parses a Node.js package.json file."""
    dependencies = []
    with open(file_path, 'r', encoding='utf-8') as f:
        data = json.load(f)
        # Combine dependencies and devDependencies if they exist
        all_deps = {}
        all_deps.update(data.get("dependencies", {}))
        all_deps.update(data.get("devDependencies", {}))
        
        for name, version in all_deps.items():
            dependencies.append({"name": name, "version": version, "constraint": "json"})
    return dependencies

def build_dependency_graph(project_name, dependencies):
    """
    Builds a directed dependency graph using NetworkX 
    to represent direct relationships.
    """
    G = nx.DiGraph()
    G.add_node(project_name, type="root_project")
    
    for dep in dependencies:
        dep_name = dep["name"]
        G.add_node(dep_name, type="dependency", version=dep["version"])
        # Create a directed edge from the project to the dependency
        G.add_edge(project_name, dep_name, relationship="direct")
        
    return G

# --- Test run ---
if __name__ == "__main__":
    # Create sample files for testing
    with open("requirements.txt", "w") as f:
        f.write("requests==2.31.0\nfastapi>=0.100.0\n")
        
    # Run the parser
    deps = parse_requirements_txt("requirements.txt")
    graph = build_dependency_graph("SamplePythonApp", deps)
    
    print(f"Graph successfully built for 'SamplePythonApp'!")
    print(f"Total Nodes: {graph.number_of_nodes()}")
    print(f"Nodes and data: {list(graph.nodes(data=True))}")