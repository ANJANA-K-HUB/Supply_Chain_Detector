import ast
import re
import os

# Regex patterns to detect hardcoded secrets or sensitive keys
SECRET_PATTERNS = [
    re.compile(r"api[_-]?key\s*=\s*['\"'][a-zA-Z0-9_\-]{16,}['\"']", re.IGNORECASE),
    re.compile(r"password\s*=\s*['\"'].+['\"']", re.IGNORECASE),
    re.compile(r"secret[_-]?token\s*=\s*['\"'].+['\"']", re.IGNORECASE),
    re.compile(r"bearer\s+[a-zA-Z0-9_\-\.]{20,}", re.IGNORECASE)
]

class SecurityVisitor(ast.NodeVisitor):
    """AST Visitor to scan Python code for dangerous functions and practices."""
    def __init__(self):
        self.findings = []

    def visit_Call(self, node):
        # Check for dangerous function calls like eval() or exec()
        if isinstance(node.func, ast.Name):
            if node.func.id in ["eval", "exec"]:
                self.findings.append({
                    "type": "Dangerous Function",
                    "severity": "High",
                    "message": f"Use of unsafe built-in function '{node.func.id}()' detected at line {node.lineno}."
                })
        
        # Check for subprocess with shell=True
        elif isinstance(node.func, ast.Attribute) and node.func.attr == "Popen" or node.func.attr == "run":
            for keyword in node.keywords:
                if keyword.arg == "shell" and isinstance(keyword.value, ast.Constant) and keyword.value.value is True:
                    self.findings.append({
                        "type": "Command Injection Risk",
                        "severity": "Medium",
                        "message": f"Subprocess executed with 'shell=True' at line {node.lineno}."
                    })
        
        self.generic_visit(node)

def analyze_source_code(file_path: str):
    """
    Scans a Python source file for code-level vulnerabilities, hardcoded secrets, and unsafe patterns.
    """
    findings = []
    
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            content = f.read()
            
        # 1. Check for hardcoded secrets via Regex
        for line_num, line in enumerate(content.splitlines(), start=1):
            for pattern in SECRET_PATTERNS:
                if pattern.search(line):
                    findings.append({
                        "type": "Hardcoded Secret",
                        "severity": "Critical",
                        "message": f"Potential hardcoded secret or API key found at line {line_num}."
                    })
                    
        # 2. Check for syntax-level risks using AST
        tree = ast.parse(content, filename=file_path)
        visitor = SecurityVisitor()
        visitor.visit(tree)
        findings.extend(visitor.findings)
        
    except SyntaxError as se:
        findings.append({
            "type": "Syntax Error",
            "severity": "Low",
            "message": f"Could not parse file due to syntax error: {se}"
        })
    except Exception as e:
        print(f"Error analyzing code file {file_path}: {e}")
        
    return findings