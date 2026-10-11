"""Fast contract tests for the local web interface."""

import unittest
from web_app.app import app


class TestWebApp(unittest.TestCase):
    def setUp(self):
        self.client = app.test_client()

    def test_status_endpoint(self):
        response = self.client.get("/api/status")
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["status"], "ok")

    def test_home_serves_interface(self):
        response = self.client.get("/")
        self.assertEqual(response.status_code, 200)
        self.assertIn(b"Sherlock", response.data)

    def test_search_rejects_empty_username(self):
        response = self.client.post("/api/search", json={"usernames": "  "})
        self.assertEqual(response.status_code, 400)
        self.assertIn("username", response.get_json()["error"].lower())

    def test_search_rejects_invalid_timeout_and_proxy(self):
        timeout_response = self.client.post("/api/search", json={"usernames": "ada", "timeout": 999})
        proxy_response = self.client.post("/api/search", json={"usernames": "ada", "proxy": "file:///tmp/proxy"})
        self.assertEqual(timeout_response.status_code, 400)
        self.assertEqual(proxy_response.status_code, 400)

    def test_sites_returns_local_catalogue(self):
        response = self.client.get("/api/sites")
        payload = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertGreater(payload["total"], 300)
        self.assertEqual(payload["total"], len(payload["sites"]))

    def test_osint_framework_endpoint(self):
        response = self.client.get("/api/osint-framework")
        payload = response.get_json()
        self.assertEqual(response.status_code, 200)
        self.assertIn("categories", payload)
        self.assertGreaterEqual(len(payload["categories"]), 5)


if __name__ == "__main__":
    unittest.main()
