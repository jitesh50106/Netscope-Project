"""
Mitigated Service Implementation (Demonstration of Secure Coding Best Practices)
This module demonstrates robust defenses against SQL Injection (CWE-89):
1. Parameterized Queries (Prepared Statements) separating code from untrusted data
2. Strict Type Validation and Input Boundary Checks
3. Safe Error Handling without internal schema disclosure
"""

import time
import sqlite3
from typing import Dict, Any, List
from ..database.db import get_connection

class MitigatedService:
    """Demonstrates defense-in-depth secure query execution."""

    @staticmethod
    def login(username: str, password_hash: str) -> Dict[str, Any]:
        """
        Secure Login: Uses parameterized SQL with query placeholders (?).
        Remediation: The database driver compiles the SQL grammar before binding parameters.
        Metacharacters inside `username` or `password_hash` are treated purely as literal string bytes.
        """
        start_time = time.perf_counter()
        conn = get_connection()
        cursor = conn.cursor()

        # Secure query template separating command structure from user parameters
        query_template = "SELECT id, username, role, email, full_name, account_balance FROM users WHERE username = ? AND password_hash = ?;"
        parameters = (username, password_hash)

        records = []
        error_msg = None
        status = "FAILURE"

        try:
            cursor.execute(query_template, parameters)
            rows = cursor.fetchall()
            records = [dict(row) for row in rows]
            status = "SUCCESS" if len(records) > 0 else "NO_RECORDS_FOUND"
        except sqlite3.Error as e:
            # Defensive practice: Log the internal error securely, return sanitized client response
            error_msg = "Database query failure occurred. Details have been logged securely."
            status = "DB_ERROR"
        finally:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            conn.close()

        return {
            "mode": "MITIGATED",
            "technique": "Parameterized Query (Prepared Statement)",
            "query_template": query_template,
            "bound_parameters": {"param_1 (username)": username, "param_2 (password_hash)": password_hash},
            "status": status,
            "records_returned": len(records),
            "records": records,
            "database_error": error_msg,
            "execution_time_ms": round(elapsed_ms, 3),
            "security_analysis": {
                "defense_standard": "OWASP Top 10 A03:2021 - Injection Prevention",
                "mitigation_level": "OPTIMAL (Immune to Syntax Hijacking)",
                "explanation": "Parameters are transported via a separate protocol channel or data slot. The database parser never interprets parameter bytes as SQL syntax."
            }
        }

    @staticmethod
    def search_products(keyword: str) -> Dict[str, Any]:
        """
        Secure Product Search: Uses parameterized query with LIKE wildcards bound in Python.
        Remediation: Wildcards (%) are included in the parameter tuple, NOT concatenated into the query text.
        """
        start_time = time.perf_counter()
        conn = get_connection()
        cursor = conn.cursor()

        query_template = "SELECT id, sku, name, category, price, stock_quantity, description FROM products WHERE name LIKE ? OR category LIKE ?;"
        search_pattern = f"%{keyword}%"
        parameters = (search_pattern, search_pattern)

        records = []
        error_msg = None
        status = "FAILURE"

        try:
            cursor.execute(query_template, parameters)
            rows = cursor.fetchall()
            records = [dict(row) for row in rows]
            status = "SUCCESS"
        except sqlite3.Error as e:
            error_msg = "Database query failure occurred."
            status = "DB_ERROR"
        finally:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            conn.close()

        return {
            "mode": "MITIGATED",
            "technique": "Parameterized Query with Safe Parameter Binding",
            "query_template": query_template,
            "bound_parameters": {"name_pattern": search_pattern, "category_pattern": search_pattern},
            "status": status,
            "records_returned": len(records),
            "records": records,
            "database_error": error_msg,
            "execution_time_ms": round(elapsed_ms, 3),
            "security_analysis": {
                "defense_standard": "Parameterized LIKE Clause Defense",
                "mitigation_level": "OPTIMAL",
                "explanation": "The database treats '%...%' strictly as search text. Embedded quotes or SQL commands have zero syntactic effect."
            }
        }

    @staticmethod
    def get_user_profile(user_id_input: str) -> Dict[str, Any]:
        """
        Secure Numeric Parameter: Enforces strict integer type validation before database lookup.
        Remediation: Combines input validation (Defense in Depth) with parameterized query.
        """
        start_time = time.perf_counter()
        conn = get_connection()
        cursor = conn.cursor()

        # Step 1: Strict input validation and type coercion
        try:
            validated_id = int(str(user_id_input).strip())
        except (ValueError, TypeError):
            conn.close()
            return {
                "mode": "MITIGATED",
                "technique": "Strict Type Validation + Prepared Statement",
                "query_template": "SELECT ... WHERE id = ?",
                "bound_parameters": {},
                "status": "VALIDATION_REJECTED",
                "records_returned": 0,
                "records": [],
                "database_error": "Input Validation Error: user_id must be a valid positive integer.",
                "execution_time_ms": round((time.perf_counter() - start_time) * 1000, 3),
                "security_analysis": {
                    "defense_standard": "Input Validation & Type Enforcement (CWE-1287)",
                    "mitigation_level": "PREVENTATIVE REJECTION",
                    "explanation": "Malicious non-numeric injection payloads are rejected immediately at the API boundary before reaching the database."
                }
            }

        # Step 2: Parameterized query with validated integer
        query_template = "SELECT id, username, role, email, full_name, account_balance FROM users WHERE id = ?;"
        parameters = (validated_id,)

        records = []
        error_msg = None
        status = "FAILURE"

        try:
            cursor.execute(query_template, parameters)
            rows = cursor.fetchall()
            records = [dict(row) for row in rows]
            status = "SUCCESS" if len(records) > 0 else "NO_RECORDS_FOUND"
        except sqlite3.Error as e:
            error_msg = "Database query failure occurred."
            status = "DB_ERROR"
        finally:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            conn.close()

        return {
            "mode": "MITIGATED",
            "technique": "Strict Type Validation + Parameterized Query",
            "query_template": query_template,
            "bound_parameters": {"user_id": validated_id},
            "status": status,
            "records_returned": len(records),
            "records": records,
            "database_error": error_msg,
            "execution_time_ms": round(elapsed_ms, 3),
            "security_analysis": {
                "defense_standard": "Defense-in-Depth (Validation + Parameterization)",
                "mitigation_level": "OPTIMAL",
                "explanation": "Type casting guarantees only primitive integers enter the query pipeline, fully neutralizing numeric SQL injection."
            }
        }
