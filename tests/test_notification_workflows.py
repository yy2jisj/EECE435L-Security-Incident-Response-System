import time

from common import config
from common.db import execute, fetch_all, fetch_one, get_connection
from notification_service import repository
from tests.test_notification_api import NotificationApiCase


class NotificationWorkflowTests(NotificationApiCase):
    def test_read_transition_timestamp_persistence_and_repeat(self):
        row = self.create()
        path = f"/notifications/{row['notification_id']}/read"
        before = fetch_one("SELECT * FROM notifications WHERE notification_id=?", (row["notification_id"],))
        self.assertEqual(before["is_read"], 0)
        self.assertIsNone(before["read_date"])
        response = self.client.put(path, headers=self.employee)
        self.assertEqual(response.status_code, 200)
        after = fetch_one("SELECT * FROM notifications WHERE notification_id=?", (row["notification_id"],))
        self.assertEqual(after["is_read"], 1)
        self.assertIsNotNone(after["read_date"])
        self.assertEqual(after["created_at"], before["created_at"])
        time.sleep(1.05)
        repeated = self.client.put(path, headers=self.admin).get_json()["data"]
        self.assertEqual(repeated["read_date"], after["read_date"])
        self.assertEqual(self.client.get(path.removesuffix("/read"),
                                        headers=self.employee).get_json()["data"]["status"], "Read")

    def test_read_denials_do_not_mutate(self):
        row = self.create()
        path = f"/notifications/{row['notification_id']}/read"
        for headers, status in (({}, 401), (self.other, 403), (self.analyst, 403), (self.auditor, 403)):
            self.assert_error(self.client.put(path, headers=headers), status)
        self.assert_error(self.client.put("/notifications/99999/read", headers=self.admin), 404)
        self.assertEqual(repository.get_by_id(row["notification_id"])["status"], "Unread")

    def dataset(self):
        analyst_id = self.people["analyst"]["user_id"]
        rows = [self.create(), self.create(notification_type="System Notification", severity_level="Low"),
                self.create(user_id=analyst_id, notification_type="Threat Alert", severity_level="Critical"),
                self.create(user_id=analyst_id, notification_type="Security Alert", severity_level="Medium"),
                self.create(user_id=self.people["other"]["user_id"],
                            notification_type="Vulnerability Alert", severity_level="High")]
        for row in (rows[1], rows[3]):
            self.client.put(f"/notifications/{row['notification_id']}/read", headers=self.admin)
        return rows

    def test_search_each_combination_and_empty_results(self):
        rows = self.dataset()
        cases = [({"user_id": rows[0]["user_id"]}, [0, 1]),
                 ({"notification_type": "Security Alert"}, [0, 3]),
                 ({"severity_level": "High"}, [0, 4]), ({"status": "Unread"}, [0, 2, 4]),
                 ({"notification_type": "Security Alert", "status": "Read"}, [3]),
                 ({"user_id": rows[2]["user_id"], "severity_level": "Critical"}, [2]),
                 ({"notification_type": "Security Alert", "severity_level": "Low"}, []),
                 ({"user_id": rows[0]["user_id"], "notification_type": "Security Alert",
                   "severity_level": "High", "status": "Unread"}, [0])]
        for query, indices in cases:
            with self.subTest(query=query):
                response = self.client.get("/notifications/search", headers=self.admin, query_string=query)
                self.assertEqual(response.status_code, 200, response.get_json())
                self.assertEqual([r["notification_id"] for r in response.get_json()["data"]],
                                 [rows[i]["notification_id"] for i in indices])

    def test_search_invalid_filters(self):
        for query, status in (({}, 400), ({"unknown": "High"}, 400), ({"status": "Seen"}, 400),
                              ({"severity_level": "Urgent"}, 400), ({"user_id": "abc"}, 400),
                              ({"user_id": "99999"}, 404), ({"notification_type": "Other"}, 400),
                              ({"status": "", "severity_level": "High"}, 400),
                              ({"user_id": "9223372036854775808"}, 400),
                              ([('status', 'Read'), ('status', 'Unread')], 400),
                              ({"notification_type": "' OR 1=1 --"}, 400)):
            with self.subTest(query=query):
                self.assert_error(self.client.get("/notifications/search", headers=self.admin,
                                                   query_string=query), status)

    def test_search_role_scope(self):
        self.dataset()
        for headers in (self.admin, self.auditor, self.analyst):
            response = self.client.get("/notifications/search?status=Unread", headers=headers)
            self.assertEqual(response.status_code, 200)
            if headers == self.analyst:
                self.assertEqual(len(response.get_json()["data"]), 1)
                self.assertEqual(response.get_json()["data"][0]["user_id"],
                                 self.people["analyst"]["user_id"])
        self.assert_error(self.client.get("/notifications/search?status=Unread", headers=self.employee), 403)
        self.assert_error(self.client.get("/notifications/search?user_id=1", headers=self.analyst), 403)

    def test_full_role_matrix(self):
        for label, headers, allowed in (("admin", self.admin, [201, 200, 200, 200, 200, 200]),
                                        ("analyst", self.analyst, [403, 200, 200, 200, 200, 403]),
                                        ("employee", self.employee, [403, 200, 200, 200, 403, 403]),
                                        ("auditor", self.auditor, [403, 200, 200, 403, 200, 403])):
            recipient = self.people["analyst" if label == "analyst" else "employee"]["user_id"]
            row = self.create(user_id=recipient)
            path = f"/notifications/{row['notification_id']}"
            calls = [("POST", "/notifications", {"json": self.payload()}),
                     ("GET", f"/notifications/user/{recipient}", {}), ("GET", path, {}),
                     ("PUT", path + "/read", {}), ("GET", "/notifications/search?status=Unread", {}),
                     ("DELETE", path, {})]
            for (method, url, kwargs), expected in zip(calls, allowed):
                with self.subTest(role=label, method=method, url=url):
                    response = self.client.open(url, method=method, headers=headers, **kwargs)
                    self.assertEqual(response.status_code, expected, response.get_json())

    def test_delete_persists_and_preserves_user(self):
        row = self.create()
        path = f"/notifications/{row['notification_id']}"
        for headers in (self.employee, self.analyst, self.auditor):
            self.assert_error(self.client.delete(path, headers=headers), 403)
            self.assertIsNotNone(repository.get_by_id(row["notification_id"]))
        self.assertEqual(self.client.delete(path, headers=self.admin).status_code, 200)
        self.assertIsNone(repository.get_by_id(row["notification_id"]))
        self.assertIsNotNone(fetch_one("SELECT * FROM users WHERE user_id=?", (row["user_id"],)))
        self.assert_error(self.client.get(path, headers=self.admin), 404)
        self.assert_error(self.client.delete(path, headers=self.admin), 404)

    def test_service1_user_deletion_keeps_original_cascade(self):
        row = self.create()
        response = self.users.delete(f"/users/{row['user_id']}", headers=self.admin)
        self.assertEqual(response.status_code, 200, response.get_json())
        self.assertIsNone(repository.get_by_id(row["notification_id"]))
        self.assertEqual(fetch_one("SELECT COUNT(*) AS n FROM users")["n"], 4)

    def test_real_token_reloads_role_status_and_deleted_account(self):
        row = self.create()
        path = f"/notifications/{row['notification_id']}"
        user_id = row["user_id"]
        execute("UPDATE users SET account_status='Suspended' WHERE user_id=?", (user_id,))
        self.assert_error(self.client.get(path, headers=self.employee), 403)
        execute("UPDATE users SET account_status='Active', role=? WHERE user_id=?",
                (config.ROLE_AUDITOR, user_id))
        self.assert_error(self.client.put(path + "/read", headers=self.employee), 403)
        self.assertEqual(self.client.get(path, headers=self.employee).status_code, 200)
        execute("DELETE FROM users WHERE user_id=?", (user_id,))
        self.assert_error(self.client.get(path, headers=self.employee), 401)

    def test_permission_violations_are_audited(self):
        self.assert_error(self.client.post("/notifications", headers=self.employee, json=self.payload()), 403)
        logs = fetch_all("SELECT * FROM logs WHERE related_service='notifications'")
        self.assertTrue(any(row["action"] == "Unauthorized access attempt" and
                            row["user_id"] == self.people["employee"]["user_id"] for row in logs))
