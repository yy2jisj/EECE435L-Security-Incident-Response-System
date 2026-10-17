"""Assignment dependency, transaction guarantees and incident regression coverage."""

from unittest.mock import Mock, patch

import requests

from api_test_case import ApiTestCase
from common.db import fetch_all, fetch_one, get_connection
from common.errors import ApiError
from incident_service.app import app
from notification_service.app import app as notifications_app

ROOT = "/Youssef-Al-Hajj-Youness/incidents"
NOTIFICATIONS = "/Youssef-Al-Hajj-Youness/notifications"


class IncidentApiTests(ApiTestCase):
    def setUp(self):
        super().setUp()
        self.client = app.test_client()
        self.asset_id = self.create_asset()
        self.body = {
            "title": "Suspicious server activity", "description": "Unexpected remote login.",
            "category": "Unauthorized Access", "severity_level": "High",
            "reporter_id": self.reporter_id, "asset_id": self.asset_id,
        }
        response = self.client.post(ROOT, headers=self.reporter, json=self.body)
        self.assertEqual(response.status_code, 201, response.get_json())
        self.incident_id = response.get_json()["data"]["incident_id"]
        self.path = f"{ROOT}/{self.incident_id}"

    def assign(self, analyst_id=None, headers=None):
        return self.client.put(self.path + "/assign", headers=headers or self.admin,
                               json={"analyst_id": self.analyst_id if analyst_id is None else analyst_id})

    def assignment_state(self):
        return (
            fetch_one("SELECT assigned_analyst_id FROM incidents WHERE incident_id = ?",
                      (self.incident_id,)),
            fetch_all("SELECT * FROM notifications"),
            fetch_all("SELECT * FROM logs WHERE related_service IN ('incidents', 'notifications')"),
        )

    def test_real_http_assignment_precedes_write_and_notifies_atomically(self):
        self.serve_users()
        real_get = requests.get

        def inspect_http(url, **kwargs):
            self.assertTrue(url.endswith("/users"))
            self.assertEqual(kwargs["headers"], self.admin)
            self.assertEqual(kwargs["timeout"], 5)
            write_connection.assert_not_called()
            return real_get(url, **kwargs)

        with patch("incident_service.app.get_connection", wraps=get_connection) as write_connection:
            with patch("common.service_client.requests.get", side_effect=inspect_http) as http:
                response = self.assign()
            self.assertEqual(http.call_count, 1)
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertEqual(response.get_json()["data"]["assigned_analyst_id"], self.analyst_id)
        notifications = notifications_app.test_client()
        history = notifications.get(f"{NOTIFICATIONS}/user/{self.analyst_id}", headers=self.analyst)
        self.assertEqual(history.status_code, 200)
        notification = history.get_json()["data"][0]
        self.assertEqual(notification["notification_type"], "Incident Assignment")
        self.assertEqual(notification["status"], "Unread")
        self.assertEqual(notification["severity_level"], "High")
        self.assertEqual(fetch_one("SELECT incident_id FROM notifications")["incident_id"], self.incident_id)
        logs = fetch_all("SELECT action FROM logs WHERE action IN ('Incident assigned', 'Notification created')")
        self.assertEqual({row["action"] for row in logs}, {"Incident assigned", "Notification created"})
        before = self.assignment_state()
        self.assertEqual(self.assign().status_code, 200)
        self.assertEqual(self.assignment_state(), before)  # No duplicate notification or audit.
        read = notifications.put(f"{NOTIFICATIONS}/{notification['notification_id']}/read", headers=self.analyst)
        self.assertEqual(read.status_code, 200)
        self.assertTrue(read.get_json()["data"]["read_date"])

    def test_http_rejects_missing_wrong_role_and_inactive_analysts(self):
        self.serve_users()
        with get_connection() as conn:
            missing_id = conn.execute("SELECT MAX(user_id) + 1 FROM users").fetchone()[0]
        before = self.assignment_state()
        for user_id, expected in ((missing_id, 404), (self.reporter_id, 400)):
            with self.subTest(user_id=user_id):
                self.assertEqual(self.assign(user_id).status_code, expected)
                self.assertEqual(self.assignment_state(), before)
        with get_connection() as conn:
            conn.execute("UPDATE users SET account_status = 'Inactive' WHERE user_id = ?", (self.analyst_id,))
        self.assertEqual(self.assign().status_code, 400)
        self.assertEqual(self.assignment_state(), before)

    def test_dependency_failures_return_503_without_writes(self):
        before = self.assignment_state()
        failures = [requests.ConnectionError("offline"), requests.Timeout("timed out")]
        failures += [Mock(status_code=code) for code in (401, 403, 500)]
        failures += [Mock(status_code=200, json=Mock(return_value=payload)) for payload in (
            [], {"status": "error"}, {"status": "success", "data": None},
            {"status": "success", "data": [{}]},
            {"status": "success", "data": [{"user_id": self.analyst_id, "role": "Security Analyst"}]},
        )]
        failures.append(Mock(status_code=200, json=Mock(side_effect=ValueError("invalid JSON"))))
        for failure in failures:
            with self.subTest(failure=type(failure).__name__):
                options = {"side_effect": failure} if isinstance(failure, Exception) else {"return_value": failure}
                with patch("common.service_client.requests.get", **options):
                    with patch("incident_service.app.get_connection", wraps=get_connection) as write_connection:
                        response = self.assign()
                        write_connection.assert_not_called()
                self.assertEqual(response.status_code, 503, response.get_json())
                self.assertEqual(self.assignment_state(), before)

    def test_assignment_rechecks_user_and_rolls_back_notification_failure(self):
        self.serve_users()
        real_get = requests.get

        def deactivate_after_http(*args, **kwargs):
            response = real_get(*args, **kwargs)
            with get_connection() as conn:
                conn.execute("UPDATE users SET account_status = 'Inactive' WHERE user_id = ?", (self.analyst_id,))
            return response

        before = self.assignment_state()
        with patch("common.service_client.requests.get", side_effect=deactivate_after_http):
            self.assertEqual(self.assign().status_code, 400)
        self.assertEqual(self.assignment_state(), before)
        with get_connection() as conn:
            conn.execute("UPDATE users SET account_status = 'Active' WHERE user_id = ?", (self.analyst_id,))
        with patch("incident_service.app.notifications.insert_notification", side_effect=ApiError("Insert failed", 503)):
            self.assertEqual(self.assign().status_code, 503)
        self.assertEqual(self.assignment_state(), before)

    def test_assignment_auth_and_validation_do_not_call_dependency(self):
        with patch("common.service_client.requests.get") as http:
            self.assertEqual(self.assign(headers=self.reporter).status_code, 403)
            self.assertEqual(self.assign(analyst_id=True).status_code, 400)
            response = self.client.put(ROOT + "/999999/assign", headers=self.admin,
                                       json={"analyst_id": self.analyst_id})
            self.assertEqual(response.status_code, 404)
            http.assert_not_called()

    def test_incident_validation_scoped_access_notes_and_lifecycle(self):
        for changes in ({"title": " "}, {"severity_level": "Urgent"}, {"asset_id": True}):
            response = self.client.post(ROOT, headers=self.reporter, json=dict(self.body, **changes))
            self.assertEqual(response.status_code, 400)
        missing = dict(self.body)
        del missing["description"]
        self.assertEqual(self.client.post(ROOT, headers=self.reporter, json=missing).status_code, 400)
        self.assertEqual(self.client.get(self.path).status_code, 401)
        self.assertEqual(self.client.get(self.path, headers=self.analyst).status_code, 403)
        self.assertEqual(self.client.get(ROOT, headers=self.reporter).status_code, 403)
        self.assertEqual(self.client.get(self.path, headers=self.reporter).status_code, 200)
        self.assertEqual(self.client.get(ROOT, headers=self.auditor).status_code, 200)
        self.assertEqual(self.client.put(self.path + "/status", headers=self.admin,
                                         json={"status": "Closed"}).status_code, 409)
        self.serve_users()
        self.assertEqual(self.assign().status_code, 200)
        note = self.client.post(self.path + "/notes", headers=self.analyst,
                                json={"note_content": "Reviewed access logs."})
        self.assertEqual(note.status_code, 201)
        resolution_date = None
        for status in ("Under Investigation", "Mitigated", "Resolved", "Closed"):
            response = self.client.put(self.path + "/status", headers=self.analyst, json={"status": status})
            self.assertEqual(response.status_code, 200, response.get_json())
            if status == "Resolved":
                resolution_date = response.get_json()["data"]["resolution_date"]
                self.assertTrue(resolution_date)
        saved = self.client.get(self.path, headers=self.auditor).get_json()["data"]
        self.assertEqual(saved["status"], "Closed")
        self.assertEqual(saved["resolution_date"], resolution_date)
        self.assertEqual(saved["investigation_notes"], [note.get_json()["data"]])
        asset = self.assets.get(f"/assets/{self.asset_id}/AdamYahya", headers=self.analyst)
        self.assertEqual(asset.status_code, 200)
        self.assertEqual(asset.get_json()["data"]["related_incidents"][0]["incident_id"], self.incident_id)
