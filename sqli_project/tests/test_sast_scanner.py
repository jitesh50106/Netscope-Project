"""
Unit tests for AST-based Static Application Security Testing (SAST) Scanner.
Verifies detection accuracy for various CWE-89 injection patterns and secure coding practices.
"""

import unittest
from sqli_project.core.sast_scanner import SASTScanner

class TestSASTScanner(unittest.TestCase):

    def test_detect_fstring_injection(self):
        code = """
def login(username, pwd):
    cursor = db.cursor()
    cursor.execute(f"SELECT * FROM users WHERE user = '{username}'")
"""
        report = SASTScanner.scan_code(code)
        self.assertEqual(report["status"], "COMPLETED")
        self.assertEqual(report["summary"]["critical_vulnerabilities"], 1)
        self.assertEqual(report["findings"][0]["severity"], "CRITICAL")
        self.assertIn("f-string", report["findings"][0]["vulnerability_type"])

    def test_detect_string_concatenation_injection(self):
        code = """
def search(term):
    cursor = db.cursor()
    sql = "SELECT * FROM items WHERE name = '" + term + "'"
    cursor.execute(sql)
"""
        report = SASTScanner.scan_code(code)
        self.assertEqual(report["status"], "COMPLETED")
        self.assertEqual(report["summary"]["critical_vulnerabilities"], 1)
        self.assertIn("Tainted Variable", report["findings"][0]["vulnerability_type"])

    def test_detect_percent_format_injection(self):
        code = """
def lookup(uid):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM accounts WHERE id = %s" % uid)
"""
        report = SASTScanner.scan_code(code)
        self.assertEqual(report["status"], "COMPLETED")
        self.assertEqual(report["summary"]["critical_vulnerabilities"], 1)
        self.assertIn("Legacy '%'", report["findings"][0]["vulnerability_type"])

    def test_verify_parameterized_query_compliance(self):
        code = """
def safe_login(username, pwd):
    cursor = db.cursor()
    cursor.execute("SELECT * FROM users WHERE user = ? AND pass = ?", (username, pwd))
"""
        report = SASTScanner.scan_code(code)
        self.assertEqual(report["status"], "COMPLETED")
        self.assertEqual(report["summary"]["critical_vulnerabilities"], 0)
        self.assertEqual(report["summary"]["secure_patterns"], 1)
        self.assertEqual(report["summary"]["safety_score"], 100)
        self.assertEqual(report["findings"][0]["severity"], "SECURE")

    def test_syntax_error_handling(self):
        invalid_code = "def broken_code( : invalid"
        report = SASTScanner.scan_code(invalid_code)
        self.assertEqual(report["status"], "SYNTAX_ERROR")

if __name__ == "__main__":
    unittest.main()
