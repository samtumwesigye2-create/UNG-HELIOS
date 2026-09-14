import os
import unittest

from fastapi.testclient import TestClient

os.environ.setdefault("HELIOS_ADMIN_KEY", "unit-admin-key")
os.environ.setdefault("HELIOS_OPERATOR_KEY", "unit-operator-key")
os.environ.setdefault("HELIOS_UI_SESSION_SECRET", "unit-session-secret")

from dashboard import app


client = TestClient(app)


class TestConsoleSecurity(unittest.TestCase):
    def test_admin_secret_never_appears_in_browser_assets(self):
        secret = os.environ["HELIOS_ADMIN_KEY"]
        for path in ("/", "/static/helios-dashboard.js", "/static/helios-dashboard.css"):
            response = client.get(path)
            self.assertEqual(response.status_code, 200)
            self.assertNotIn(secret, response.text)

    def test_privileged_ui_action_requires_operator_session(self):
        response = client.post("/ui-api/services/example/deactivate")
        self.assertIn(response.status_code, (401, 403))

    def test_operator_login_sets_httponly_cookie(self):
        response = client.post("/ui-api/operator/login", json={"operator_key": "unit-operator-key"})
        self.assertEqual(response.status_code, 200)
        cookie = response.headers.get("set-cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=strict", cookie)

    def test_operator_session_can_deactivate_service(self):
        login = client.post("/ui-api/operator/login", json={"operator_key": "unit-operator-key"})
        self.assertEqual(login.status_code, 200)
        response = client.post("/ui-api/services/example/deactivate")
        self.assertNotEqual(response.status_code, 401)
        self.assertNotEqual(response.status_code, 403)


if __name__ == "__main__":
    unittest.main()
