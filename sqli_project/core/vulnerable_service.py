"""
Vulnerable Service Implementation (Demonstration of Insecure Coding Practices)
WARNING: For educational demonstration and defensive research only.
This module demonstrates insecure SQL query construction using direct string concatenation.
"""

import time
import sqlite3
from typing import Dict, Any, List
from ..database.db import get_connection

class VulnerableService:
    """Demonstrates vulnerable database query patterns susceptible to CWE-89."""

    @staticmethod
    def login(username: str, password_hash: str) -> Dict[str, Any]:
        """
        Insecure Login: Concatenates user input directly into SQL command string.
        Vulnerability: String concatenation allows user data to break out of literal boundaries.
        """
        start_time = time.perf_counter()
        conn = get_connection()
        cursor = conn.cursor()

        # Insecure query generation using Python f-string
        raw_query = f"SELECT id, username, role, email, full_name, account_balance FROM users WHERE username = '{username}' AND password_hash = '{password_hash}';"

        records = []
        error_msg = None
        status = "FAILURE"

        try:
            cursor.execute(raw_query)
            rows = cursor.fetchall()
            records = [dict(row) for row in rows]
            status = "SUCCESS" if len(records) > 0 else "NO_RECORDS_FOUND"
        except sqlite3.Error as e:
            error_msg = str(e)
            status = "SQL_ERROR"
        finally:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            conn.close()

        return {
            "mode": "VULNERABLE",
            "technique": "Direct String Concatenation (Insecure)",
            "constructed_query": raw_query,
            "status": status,
            "records_returned": len(records),
            "records": records,
            "database_error": error_msg,
            "execution_time_ms": round(elapsed_ms, 3),
            "security_analysis": {
                "cwe_id": "CWE-89: Improper Neutralization of Special Elements used in an SQL Command",
                "risk_level": "CRITICAL",
                "vulnerability_root_cause": "The interpreter cannot distinguish between user-supplied data and developer-intended SQL command syntax."
            }
        }

    @staticmethod
    def search_products(keyword: str) -> Dict[str, Any]:
        """
        Insecure Product Search: Concatenates search query directly into LIKE clause.
        Vulnerability: Allows altering WHERE conditions, UNION-based data extraction, or syntax termination.
        """
        start_time = time.perf_counter()
        conn = get_connection()
        cursor = conn.cursor()

        raw_query = f"SELECT id, sku, name, category, price, stock_quantity, description FROM products WHERE name LIKE '%{keyword}%' OR category LIKE '%{keyword}%';"

        records = []
        error_msg = None
        status = "FAILURE"

        try:
            cursor.execute(raw_query)
            rows = cursor.fetchall()
            records = [dict(row) for row in rows]
            status = "SUCCESS"
        except sqlite3.Error as e:
            error_msg = str(e)
            status = "SQL_ERROR"
        finally:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            conn.close()

        return {
            "mode": "VULNERABLE",
            "technique": "Direct String Concatenation (Insecure)",
            "constructed_query": raw_query,
            "status": status,
            "records_returned": len(records),
            "records": records,
            "database_error": error_msg,
            "execution_time_ms": round(elapsed_ms, 3),
            "security_analysis": {
                "cwe_id": "CWE-89: SQL Injection in Search Filter",
                "risk_level": "CRITICAL",
                "vulnerability_root_cause": "Wildcard LIKE clause without parameter binding allows unescaped quote injection."
            }
        }

    @staticmethod
    def get_user_profile(user_id: str) -> Dict[str, Any]:
        """
        Insecure Numeric Parameter: Unvalidated user ID concatenated directly into query.
        Vulnerability: Numeric SQL injection requires no quotes to manipulate query logic.
        """
        start_time = time.perf_counter()
        conn = get_connection()
        cursor = conn.cursor()

        raw_query = f"SELECT id, username, role, email, full_name, account_balance FROM users WHERE id = {user_id};"

        records = []
        error_msg = None
        status = "FAILURE"

        try:
            cursor.execute(raw_query)
            rows = cursor.fetchall()
            records = [dict(row) for row in rows]
            status = "SUCCESS" if len(records) > 0 else "NO_RECORDS_FOUND"
        except sqlite3.Error as e:
            error_msg = str(e)
            status = "SQL_ERROR"
        finally:
            elapsed_ms = (time.perf_counter() - start_time) * 1000
            conn.close()

        return {
            "mode": "VULNERABLE",
            "technique": "Direct Numeric Concatenation (Insecure)",
            "constructed_query": raw_query,
            "status": status,
            "records_returned": len(records),
            "records": records,
            "database_error": error_msg,
            "execution_time_ms": round(elapsed_ms, 3),
            "security_analysis": {
                "cwe_id": "CWE-89: Numeric SQL Injection",
                "risk_level": "CRITICAL",
                "vulnerability_root_cause": "Numeric values concatenated without type verification or binding."
            }
        }
