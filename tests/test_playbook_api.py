"""Focused Service 9 workflow, validation and authorization regression tests."""

from datetime import datetime, timedelta, timezone

from api_test_case import ApiTestCase
from common.db import fetch_all, fetch_one, get_connection
from playbook_service.app import app

PREFIX = "/Youssef-Al-Hajj-Youness"
ROOT = PREFIX + "/playbooks"


class PlaybookApiTests(ApiTestCase):
    def setUp(self):
        super().setUp()
        self.client = app.test_client()
        self.body = {"playbook_name": "Unauthorized Access Response",
                     "description": "Contain, investigate and recover.",
                     "incident_category": "Unauthorized Access", "severity_level": "High"}

    def create(self):
        response = self.client.post(ROOT, headers=self.admin, json=self.body)
        self.assertEqual(response.status_code, 201, response.get_json())
        return response.get_json()["data"]

    def add_action(self, playbook_id, step):
        response = self.client.post(f"{ROOT}/{playbook_id}/actions", headers=self.analyst,
                                    json={"action_description": f"Response step {step}", "step_number": step})
        self.assertEqual(response.status_code, 201, response.get_json())
        return response.get_json()["data"]

    def test_ordered_actions_progress_completion_and_history_survive_deletion(self):
        playbook = self.create()
        self.assertEqual(playbook["created_by"], self.admin_id)
        self.assertTrue(playbook["created_at"])
        self.assertEqual(playbook["response_actions"], [])
        self.create()
        self.assertEqual(len(self.client.get(ROOT, headers=self.auditor).get_json()["data"]), 2)
        path = f"{ROOT}/{playbook['playbook_id']}"
        second = self.add_action(playbook["playbook_id"], 2)
        first = self.add_action(playbook["playbook_id"], 1)
        self.assertEqual(first["status"], "Pending")
        action_path = f"{PREFIX}/actions/{first['action_id']}/status"
        progress = self.client.put(action_path, headers=self.analyst,
                                    json={"status": "In Progress", "assigned_user_id": self.analyst_id})
        self.assertEqual(progress.status_code, 200)
        self.assertEqual(progress.get_json()["data"]["assigned_user_id"], self.analyst_id)
        completed = self.client.put(action_path, headers=self.analyst, json={"status": "Completed"})
        self.assertEqual(completed.status_code, 200)
        self.assertEqual(completed.get_json()["data"]["completion_date"],
                         datetime.now(timezone.utc).date().isoformat())
        saved = self.client.get(path, headers=self.auditor).get_json()["data"]
        self.assertEqual([a["action_id"] for a in saved["response_actions"]], [first["action_id"], second["action_id"]])
        history = saved["action_history"]
        self.assertEqual([h["status"] for h in history if h["action_id"] == first["action_id"]],
                         ["Pending", "In Progress", "Completed"])
        self.assertEqual(self.client.put(action_path, headers=self.analyst,
                                         json={"status": "Completed"}).status_code, 200)
        self.assertEqual(self.client.get(path, headers=self.auditor).get_json()["data"]["action_history"], history)
        self.assertEqual(self.client.delete(path, headers=self.admin).status_code, 200)
        self.assertEqual(self.client.get(path, headers=self.admin).status_code, 404)
        self.assertEqual(fetch_all("SELECT * FROM response_actions WHERE playbook_id = ?",
                                   (playbook["playbook_id"],)), [])
        self.assertEqual(fetch_all("SELECT * FROM response_action_history WHERE playbook_id = ? ORDER BY history_id",
                                   (playbook["playbook_id"],)), history)
        self.assertIsNotNone(fetch_one("SELECT * FROM logs WHERE action = 'Playbook deleted'"))

    def test_validation_preserves_action_and_history(self):
        invalid = dict(self.body)
        del invalid["incident_category"]
        self.assertEqual(self.client.post(ROOT, headers=self.admin, json=invalid).status_code, 400)
        self.assertEqual(self.client.post(ROOT, headers=self.admin,
                                          json=dict(self.body, severity_level="Urgent")).status_code, 400)
        playbook = self.create()
        action = self.add_action(playbook["playbook_id"], 1)
        path = f"{ROOT}/{playbook['playbook_id']}"
        self.assertEqual(self.client.post(path + "/actions", headers=self.admin,
                                          json={"action_description": "Duplicate", "step_number": 1}).status_code, 409)
        future = (datetime.now(timezone.utc).date() + timedelta(days=1)).isoformat()
        before = self.client.get(path, headers=self.admin).get_json()["data"]
        for body in ({"status": "Completed", "completion_date": "2026-02-30"},
                     {"status": "Completed", "completion_date": future},
                     {"status": "Completed", "completion_date": None},
                     {"status": "Pending", "completion_date": "2020-01-01"},
                     {"assigned_user_id": True}, {"status": "Closed"}, {}):
            with self.subTest(body=body):
                response = self.client.put(f"{PREFIX}/actions/{action['action_id']}/status",
                                           headers=self.analyst, json=body)
                self.assertEqual(response.status_code, 400, response.get_json())
                self.assertEqual(self.client.get(path, headers=self.admin).get_json()["data"], before)

    def test_rbac_and_shared_account_checks(self):
        self.assertEqual(self.client.get(ROOT).status_code, 401)
        self.assertEqual(self.client.get(ROOT, headers=self.reporter).status_code, 403)
        self.assertEqual(self.client.post(ROOT, headers=self.analyst, json=self.body).status_code, 403)
        playbook = self.create()
        path = f"{ROOT}/{playbook['playbook_id']}"
        for headers in (self.analyst, self.auditor, self.reporter):
            self.assertEqual(self.client.delete(path, headers=headers).status_code, 403)
        self.assertEqual(self.client.post(path + "/actions", headers=self.auditor,
                                          json={"action_description": "Denied", "step_number": 1}).status_code, 403)
        with get_connection() as conn:
            conn.execute("UPDATE users SET account_status = 'Inactive' WHERE user_id = ?", (self.analyst_id,))
        self.assertEqual(self.client.get(path, headers=self.analyst).status_code, 403)
        self.assertEqual(self.client.get(path, headers=self.auditor).status_code, 200)
