"""
SQL Query Lexical Analyzer & Token Differential Engine.
Provides academic explanation of SQL Injection at the Lexical and Syntactic Grammar levels.
Demonstrates the 'Code vs Data' duality failure in unparameterized SQL.
"""

import re
from typing import List, Dict, Any, Tuple

# Standard SQL Keywords
SQL_KEYWORDS = {
    "SELECT", "FROM", "WHERE", "AND", "OR", "NOT", "LIKE", "IN", "IS", "NULL",
    "UNION", "ALL", "JOIN", "INNER", "LEFT", "RIGHT", "ON", "GROUP", "BY",
    "ORDER", "HAVING", "LIMIT", "OFFSET", "INSERT", "INTO", "VALUES", "UPDATE",
    "SET", "DELETE", "DROP", "TABLE", "CREATE", "ALTER", "CASE", "WHEN", "THEN",
    "ELSE", "END", "EXISTS", "BETWEEN", "AS", "DISTINCT", "COUNT", "SUM", "AVG"
}

# Token specification regular expressions
TOKEN_SPECIFICATION = [
    ("COMMENT",             r"(--[^\n]*|/\*[\s\S]*?\*/)"),
    ("STRING_LITERAL",      r"('(?:''|[^'])*'|\"(?:\"\"|[^\"])*\")"),
    ("NUMERIC_LITERAL",     r"\b\d+(\.\d+)?\b"),
    ("PARAMETER_MARKER",    r"\?"),
    ("OPERATOR",            r"(=|!=|<>|<=|>=|<|>|\+|\|\||/|\*)"),
    ("PUNCTUATION",         r"([,;()])"),
    ("WORD",                r"[a-zA-Z_][a-zA-Z0-9_]*"),
    ("WHITESPACE",          r"\s+"),
    ("MISMATCH",            r"."),
]

TOKEN_REGEX = re.compile("|".join(f"(?P<{pair[0]}>{pair[1]})" for pair in TOKEN_SPECIFICATION))

class QueryAnalyzer:
    """Performs lexical tokenization and structural anomaly detection on SQL queries."""

    @classmethod
    def tokenize(cls, sql_text: str) -> List[Dict[str, Any]]:
        """
        Tokenize raw SQL string into semantic lexical components.
        """
        tokens: List[Dict[str, Any]] = []
        
        for match in TOKEN_REGEX.finditer(sql_text):
            kind = match.lastgroup
            val = match.group()
            
            if kind == "WHITESPACE":
                continue
            elif kind == "WORD":
                if val.upper() in SQL_KEYWORDS:
                    kind = "KEYWORD"
                else:
                    kind = "IDENTIFIER"
            elif kind == "MISMATCH":
                kind = "SPECIAL_CHAR"
                
            tokens.append({
                "type": kind,
                "value": val,
                "start": match.start(),
                "end": match.end(),
                "is_injection_sensitive": kind in ("OPERATOR", "COMMENT", "KEYWORD") and val.upper() in {"OR", "UNION", "--", "/*", "=", ";"}
            })
            
        return tokens

    @classmethod
    def compare_query_structures(cls, vulnerable_sql: str, parameterized_template: str, bound_params: Dict[str, Any]) -> Dict[str, Any]:
        """
        Compares dynamic concatenated SQL vs parameterized SQL at the grammar token level.
        Produces academic evaluation of token count, injection points, and AST grammar stability.
        """
        vuln_tokens = cls.tokenize(vulnerable_sql)
        param_tokens = cls.tokenize(parameterized_template)

        # Count token distributions
        vuln_counts = cls._count_token_types(vuln_tokens)
        param_counts = cls._count_token_types(param_tokens)

        # Detect grammar mutations (e.g. injected comments or unexpected operators)
        injected_anomalies = []
        for t in vuln_tokens:
            if t["type"] == "COMMENT":
                injected_anomalies.append(f"Syntactic truncation via comment token: '{t['value']}'")
            elif t["type"] == "KEYWORD" and t["value"].upper() in {"OR", "UNION", "DROP"}:
                injected_anomalies.append(f"Grammar logic alteration via keyword token: '{t['value']}'")
            elif t["type"] == "OPERATOR" and t["value"] == "=":
                injected_anomalies.append(f"Boolean predicate mutation via operator token: '='")

        anomaly_detected = len(injected_anomalies) > 0

        return {
            "vulnerable_mode": {
                "constructed_sql": vulnerable_sql,
                "token_count": len(vuln_tokens),
                "token_stream": vuln_tokens,
                "token_distribution": vuln_counts,
                "grammar_mutations_detected": injected_anomalies,
                "structural_stability": "COMPROMISED (Dynamic Lexing Permitted Command Mutation)" if anomaly_detected else "NORMAL"
            },
            "mitigated_mode": {
                "query_template": parameterized_template,
                "bound_parameters": bound_params,
                "token_count": len(param_tokens),
                "token_stream": param_tokens,
                "token_distribution": param_counts,
                "structural_stability": "IMMUTABLE (Pre-compiled AST Separates Syntax from Parameters)"
            },
            "theoretical_verdict": {
                "code_vs_data_integrity": "VIOLATED in Dynamic SQL; PRESERVED in Parameterized SQL",
                "compiler_theory_note": "In the parameterized model, the SQL execution plan is generated and fixed before parameter binding. Parameter contents are transferred through typed variables without triggering the SQL lexical parser."
            }
        }

    @staticmethod
    def _count_token_types(tokens: List[Dict[str, Any]]) -> Dict[str, int]:
        counts: Dict[str, int] = {}
        for t in tokens:
            t_type = t["type"]
            counts[t_type] = counts.get(t_type, 0) + 1
        return counts
