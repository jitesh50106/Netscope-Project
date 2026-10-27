"""
Integration tests for FastAPI REST endpoints.
"""

import unittest
from fastapi.testclient import TestClient
from sqli_project.server.app import app
from sqli_project.database.db import init_db, reset_db

class TestServerAPI(unittest.TestCase):

    @classmethod
    def setUpClass(cls):
        init_db()
        reset_db()
        cls.client = TestClient(app)


    def test_meta_endpoint(self):
        response = self.client.get("/api/project/meta")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("CWE-89", data["cwe"])

    def test_sast_presets_endpoint(self):
        response = self.client.get("/api/sast/presets")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreater(len(data["presets"]), 0)

    def test_lab_login_vulnerable(self):
        payload = {"username": "admin' --", "password": "x", "mode": "vulnerable"}
        response = self.client.post("/api/lab/login", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["execution"]["status"], "SUCCESS")

    def test_lab_login_mitigated(self):
        payload = {"username": "admin' --", "password": "x", "mode": "mitigated"}
        response = self.client.post("/api/lab/login", json=payload)
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["execution"]["status"], "NO_RECORDS_FOUND")

    def test_sast_scan_endpoint(self):
        code = "cursor.execute(f'SELECT * FROM users WHERE name = \"{name}\"')"
        response = self.client.post("/api/sast/scan", json={"code": code})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertEqual(data["summary"]["critical_vulnerabilities"], 1)

    def test_tokenize_endpoint(self):
        sql = "SELECT * FROM users WHERE id = 1"
        response = self.client.post("/api/lab/tokenize", json={"sql": sql})
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertGreater(data["token_count"], 0)

if __name__ == "__main__":
    unittest.main()
