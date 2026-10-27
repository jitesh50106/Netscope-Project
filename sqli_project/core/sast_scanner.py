"""
Static Application Security Testing (SAST) Engine for CWE-89 (SQL Injection).
Analyzes Python web application source code using Abstract Syntax Trees (AST).
Detects insecure dynamic SQL construction patterns and verifies prepared statements.
"""

import ast
from typing import List, Dict, Any, Optional

class SQLiASTVisitor(ast.NodeVisitor):
    """AST Visitor that inspects database query calls for injection vulnerabilities."""

    def __init__(self, source_lines: List[str]):
        self.source_lines = source_lines
        self.findings: List[Dict[str, Any]] = []
        self.assigned_insecure_vars: Dict[str, Dict[str, Any]] = {}
        self.assigned_constant_vars: Dict[str, Dict[str, Any]] = {}

    def visit_Assign(self, node: ast.Assign):
        """Track variable assignments that build SQL strings insecurely or statically."""
        # Check if the right-hand side is an insecure string construction
        insecure_type = self._detect_insecure_string(node.value)
        if insecure_type:
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.assigned_insecure_vars[target.id] = {
                        "lineno": node.lineno,
                        "type": insecure_type,
                        "node": node
                    }
        elif isinstance(node.value, ast.Constant) and isinstance(node.value.value, str):
            for target in node.targets:
                if isinstance(target, ast.Name):
                    self.assigned_constant_vars[target.id] = {
                        "lineno": node.lineno,
                        "value": node.value.value,
                        "node": node
                    }
        self.generic_visit(node)

    def visit_Call(self, node: ast.Call):
        """Inspect function calls to detect cursor.execute / db.execute patterns."""
        call_name = self._get_call_name(node)

        # Look for standard database execute methods
        if call_name and any(call_name.endswith(suffix) for suffix in (".execute", ".executemany", "execute")):
            if node.args:
                first_arg = node.args[0]
                has_params = len(node.args) > 1 or any(kw.arg in ("params", "parameters") for kw in node.keywords)

                # Check 1: Insecure string directly inside execute()
                direct_insecure = self._detect_insecure_string(first_arg)
                if direct_insecure:
                    self._record_finding(
                        node=node,
                        vuln_type=direct_insecure,
                        severity="CRITICAL",
                        is_secure=False,
                        details=f"Insecure dynamic SQL generated using {direct_insecure} inside database call."
                    )
                    self.generic_visit(node)
                    return

                # Check 2: Passing a variable previously constructed insecurely
                if isinstance(first_arg, ast.Name) and first_arg.id in self.assigned_insecure_vars:
                    origin = self.assigned_insecure_vars[first_arg.id]
                    self._record_finding(
                        node=node,
                        vuln_type=f"Tainted Variable '{first_arg.id}' ({origin['type']})",
                        severity="CRITICAL",
                        is_secure=False,
                        details=f"Query variable '{first_arg.id}' assigned at line {origin['lineno']} using insecure {origin['type']} is passed to database executor."
                    )
                    self.generic_visit(node)
                    return

                # Check 3: Secure Parameterized Query (direct constant or constant variable)
                is_constant_str = (
                    (isinstance(first_arg, ast.Constant) and isinstance(first_arg.value, str)) or
                    (isinstance(first_arg, ast.Name) and first_arg.id in self.assigned_constant_vars)
                )

                if is_constant_str:
                    if has_params:
                        self._record_finding(
                            node=node,
                            vuln_type="Parameterized Query (Prepared Statement)",
                            severity="SECURE",
                            is_secure=True,
                            details="Query uses immutable template string with parameter placeholder separation."
                        )
                    else:
                        # Static constant query with no parameters
                        self._record_finding(
                            node=node,
                            vuln_type="Static Constant SQL (Safe)",
                            severity="INFO",
                            is_secure=True,
                            details="Query is a static constant string without parameters."
                        )

        self.generic_visit(node)

    def _detect_insecure_string(self, node: ast.AST) -> Optional[str]:
        """Examine AST node to detect formatted or concatenated strings."""
        # 1. Python f-string (JoinedStr)
        if isinstance(node, ast.JoinedStr):
            return "f-string formatting (ast.JoinedStr)"

        # 2. String Concatenation using '+'
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Add):
            return "String concatenation '+' operator"

        # 3. Legacy '%' String Formatting
        if isinstance(node, ast.BinOp) and isinstance(node.op, ast.Mod):
            return "Legacy '%' string formatting operator"

        # 4. str.format() Call
        if isinstance(node, ast.Call):
            if isinstance(node.func, ast.Attribute) and node.func.attr == "format":
                return "str.format() method invocation"

        return None

    def _get_call_name(self, node: ast.Call) -> Optional[str]:
        """Extract full dotted name from call AST node."""
        if isinstance(node.func, ast.Attribute):
            obj_name = ""
            if isinstance(node.func.value, ast.Name):
                obj_name = node.func.value.id
            return f"{obj_name}.{node.func.attr}" if obj_name else f".{node.func.attr}"
        elif isinstance(node.func, ast.Name):
            return node.func.id
        return None

    def _record_finding(self, node: ast.AST, vuln_type: str, severity: str, is_secure: bool, details: str):
        lineno = getattr(node, "lineno", 1)
        col_offset = getattr(node, "col_offset", 0)

        code_snippet = ""
        if 1 <= lineno <= len(self.source_lines):
            code_snippet = self.source_lines[lineno - 1].strip()

        # Generate automated patch suggestion
        remediation_patch = ""
        if not is_secure:
            remediation_patch = "cursor.execute(\"SELECT ... WHERE column = ?\", (param,))"

        self.findings.append({
            "line_number": lineno,
            "column_offset": col_offset,
            "severity": severity,
            "is_secure": is_secure,
            "cwe_id": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command" if not is_secure else "CWE-None (Compliant)",
            "rule_id": "SEC-SAST-SQLI-01" if not is_secure else "SEC-SAST-SAFE-01",
            "vulnerability_type": vuln_type,
            "code_snippet": code_snippet,
            "details": details,
            "remediation_guidance": "Migrate from dynamic string composition to database-native parameter binding (prepared statements) or use an Object-Relational Mapper (ORM)." if not is_secure else "Code follows parameterized query standards.",
            "recommended_patch": remediation_patch
        })


class SASTScanner:
    """Orchestrates static analysis scans across source code strings or files."""

    @classmethod
    def scan_code(cls, source_code: str) -> Dict[str, Any]:
        """
        Parse and audit Python source code for SQL injection vulnerabilities.
        """
        source_lines = source_code.splitlines()
        try:
            tree = ast.parse(source_code)
        except SyntaxError as e:
            return {
                "status": "SYNTAX_ERROR",
                "error_message": f"Syntax error at line {e.lineno}: {e.msg}",
                "findings": [],
                "summary": {
                    "total_checks": 0,
                    "critical_vulnerabilities": 0,
                    "secure_patterns": 0,
                    "safety_score": 0
                }
            }

        visitor = SQLiASTVisitor(source_lines)
        visitor.visit(tree)

        critical_count = sum(1 for f in visitor.findings if f["severity"] == "CRITICAL")
        secure_count = sum(1 for f in visitor.findings if f["severity"] in ("SECURE", "INFO"))
        total = len(visitor.findings)

        # Calculate security posture score (0 - 100)
        if total == 0:
            score = 100
        else:
            score = max(0, 100 - (critical_count * 50))

        return {
            "status": "COMPLETED",
            "findings": visitor.findings,
            "summary": {
                "total_inspected_calls": total,
                "critical_vulnerabilities": critical_count,
                "secure_patterns": secure_count,
                "safety_score": score,
                "grade": "A (SECURE)" if critical_count == 0 else "F (HIGH RISK)"
            }
        }
