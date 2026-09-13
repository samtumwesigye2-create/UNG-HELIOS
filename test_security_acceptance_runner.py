import os
import unittest
from unittest.mock import patch

os.environ.setdefault("HELIOS_URL", "http://example.invalid")
os.environ.setdefault("HELIOS_ADMIN_KEY", "test-admin")
os.environ.setdefault("SENDER_KEY", "test-sender")

import security_acceptance_runner as runner


class SecurityAcceptanceRunnerTests(unittest.TestCase):
    def test_register_reactivates_existing_service(self):
        calls = []

        def fake_admin(method, path, body=None):
            calls.append((method, path, body))
            return 200, "{}"

        with patch.object(runner, "admin", side_effect=fake_admin):
            status, _ = runner.register("svc-1", "key-1")

        self.assertEqual(status, 200)
        self.assertEqual(calls[0][1], "/admin/register")
        self.assertEqual(calls[1][1], "/admin/reactivate/svc-1")

    def test_wait_for_health_retries_transient_failure(self):
        responses = [(502, "bad"), (200, '{"status":"ok"}')]
        with patch.object(runner, "request", side_effect=responses), patch.object(runner.time, "sleep"):
            self.assertTrue(runner.wait_for_health(attempts=2, delay=0))


if __name__ == "__main__":
    unittest.main()
