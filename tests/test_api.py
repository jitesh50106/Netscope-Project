"""Unit tests for FastAPI endpoints."""

import unittest
from starlette.testclient import TestClient
from server.app import app


class TestApiEndpoints(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(app)

    def test_get_system_info(self):
        response = self.client.get("/api/info")
        self.assertEqual(response.status_code, 200)
        data = response.json()
        self.assertIn("local_ip", data)
        self.assertIn("hostname", data)
        self.assertIn("default_subnet", data)

    def test_serve_index_html(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn("text/html", response.headers.get("content-type", ""))
        self.assertIn("NETSCOPE", response.text)

    def test_get_history(self):
        response = self.client.get("/api/history")
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.json(), list)

    def test_scan_lifecycle(self):
        payload = {
            "target": "127.0.0.1",
            "port_selection": "custom",
            "custom_ports": "135",
            "ping_discovery": False,
            "banner_grab": False,
            "resolve_dns": False,
            "timeout": 0.2,
            "threads": 10,
            "max_hosts": 10,
        }
        res_post = self.client.post("/api/scan", json=payload)
        self.assertEqual(res_post.status_code, 200)
        data = res_post.json()
        job_id = data["job_id"]
        self.assertEqual(data["status"], "started")

        res_get = self.client.get(f"/api/scan/{job_id}")
        self.assertEqual(res_get.status_code, 200)
        report = res_get.json()
        self.assertEqual(report["job_id"], job_id)

        res_csv = self.client.get(f"/api/scan/{job_id}/export/csv")
        self.assertEqual(res_csv.status_code, 200)
        self.assertIn("text/csv", res_csv.headers.get("content-type", ""))

        res_json = self.client.get(f"/api/scan/{job_id}/export/json")
        self.assertEqual(res_json.status_code, 200)
        self.assertIn("application/json", res_json.headers.get("content-type", ""))

        res_html = self.client.get(f"/api/scan/{job_id}/export/html")
        self.assertEqual(res_html.status_code, 200)
        self.assertIn("text/html", res_html.headers.get("content-type", ""))
        self.assertIn("EXECUTIVE SECURITY AUDIT REPORT", res_html.text)


if __name__ == "__main__":
    unittest.main()
