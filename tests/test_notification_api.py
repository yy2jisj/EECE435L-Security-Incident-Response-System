import tempfile
import unittest
from pathlib import Path

from common import config
from common.db import init_schema
from database.init_db import ADMIN_PASSWORD, create_default_admin
from database.migrate_notifications import migrate_notifications
from notification_service.app import app
from user_service.app import app as users_app


class NotificationApiTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.old_database = config.DB_PATH
        config.DB_PATH = str(Path(self.directory.name) / "test.db")
        init_schema()
        migrate_notifications()
        create_default_admin()
        self.client = app.test_client()
        self.users = users_app.test_client()
        self.admin = self.login("admin", ADMIN_PASSWORD)
        self.employee_id, self.employee = self.register("employee", config.ROLE_USER)
        self.body = {"user_id": self.employee_id, "title": "Security Alert",
                     "message": "Suspicious activity detected.",
                     "notification_type": "Security Alert", "severity_level": "High"}

    def tearDown(self):
        config.DB_PATH = self.old_database
        self.directory.cleanup()

    def login(self, username, password):
        response = self.users.post("/users/login", json={"username": username, "password": password})
        self.assertEqual(response.status_code, 200)
        return {"Authorization": "Bearer " + response.get_json()["data"]["token"]}

    def register(self, username, role):
        response = self.users.post("/users/register", headers=self.admin, json={
            "full_name": "Test User", "username": username, "email": username + "@example.com",
            "password": "TestPassword435!", "department": "IT", "role": role})
        self.assertEqual(response.status_code, 201)
        return response.get_json()["data"]["user_id"], self.login(username, "TestPassword435!")

    def create(self):
        response = self.client.post("/notifications", headers=self.admin, json=self.body)
        self.assertEqual(response.status_code, 201)
        return response.get_json()["data"]

    def test_create_and_retrieve(self):
        notification = self.create()
        self.assertEqual(notification["status"], "Unread")
        self.assertIsNone(notification["read_date"])
        self.assertTrue(notification["created_at"])
        response = self.client.get(f"/notifications/{notification['notification_id']}", headers=self.employee)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["data"], notification)

    def test_user_history_and_empty_history(self):
        self.create()
        self.create()
        response = self.client.get(f"/notifications/user/{self.employee_id}", headers=self.employee)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.get_json()["data"]), 2)
        empty = self.client.get("/notifications/user/1", headers=self.admin)
        self.assertEqual(empty.status_code, 200)
        self.assertEqual(empty.get_json()["data"], [])

    def test_read_preserves_dates(self):
        notification = self.create()
        path = f"/notifications/{notification['notification_id']}/read"
        first = self.client.put(path, headers=self.employee)
        self.assertEqual(first.status_code, 200)
        data = first.get_json()["data"]
        self.assertEqual(data["status"], "Read")
        self.assertTrue(data["read_date"])
        self.assertEqual(data["created_at"], notification["created_at"])
        repeated = self.client.put(path, headers=self.employee)
        self.assertEqual(repeated.get_json()["data"]["read_date"], data["read_date"])
        saved = self.client.get(path.removesuffix("/read"), headers=self.employee)
        self.assertEqual(saved.get_json()["data"], data)

    def test_search_filters(self):
        notification = self.create()
        second = dict(self.body, notification_type="System Notification", severity_level="Low")
        self.assertEqual(self.client.post("/notifications", headers=self.admin, json=second).status_code, 201)
        for filters in ({"user_id": self.employee_id}, {"notification_type": "Security Alert"},
                        {"severity_level": "High"}, {"status": "Unread"},
                        {"notification_type": "Security Alert", "severity_level": "High", "status": "Unread"}):
            response = self.client.get("/notifications/search", headers=self.admin, query_string=filters)
            self.assertEqual(response.status_code, 200)
            self.assertIn(notification["notification_id"], [n["notification_id"] for n in response.get_json()["data"]])
        empty = self.client.get("/notifications/search?severity_level=Critical", headers=self.admin)
        self.assertEqual(empty.get_json()["data"], [])
        self.assertEqual(self.client.get("/notifications/search?status=Seen", headers=self.admin).status_code, 400)

    def test_missing_and_invalid_input(self):
        self.assertEqual(self.client.post("/notifications", headers=self.admin).status_code, 400)
        for field in self.body:
            body = dict(self.body)
            del body[field]
            self.assertEqual(self.client.post("/notifications", headers=self.admin, json=body).status_code, 400)
        for changes, expected in (({"user_id": 99999}, 404), ({"user_id": True}, 400),
                                  ({"notification_type": "Other"}, 400), ({"severity_level": "Urgent"}, 400),
                                  ({"title": " "}, 400), ({"status": "Read"}, 400)):
            response = self.client.post("/notifications", headers=self.admin, json=dict(self.body, **changes))
            self.assertEqual(response.status_code, expected)
            self.assertEqual(response.get_json()["status"], "error")

    def test_missing_records_and_invalid_id(self):
        self.assertEqual(self.client.get("/notifications/99999", headers=self.admin).status_code, 404)
        self.assertEqual(self.client.get("/notifications/user/99999", headers=self.admin).status_code, 404)
        self.assertEqual(self.client.put("/notifications/99999/read", headers=self.admin).status_code, 404)
        self.assertEqual(self.client.delete("/notifications/99999", headers=self.admin).status_code, 404)
        self.assertEqual(self.client.get("/notifications/abc", headers=self.admin).status_code, 400)

    def test_authentication_ownership_and_role_permissions(self):
        notification = self.create()
        path = f"/notifications/{notification['notification_id']}"
        self.assertEqual(self.client.get(path).status_code, 401)
        self.assertEqual(self.client.get(path, headers={"Authorization": "Bearer invalid"}).status_code, 401)
        self.assertEqual(self.client.get("/notifications/user/1", headers=self.employee).status_code, 403)
        self.assertEqual(self.client.get("/notifications/search?status=Unread", headers=self.employee).status_code, 403)
        for role in (config.ROLE_ANALYST, config.ROLE_AUDITOR):
            user_id, headers = self.register("analyst" if role == config.ROLE_ANALYST else "auditor", role)
            self.assertEqual(self.client.post("/notifications", headers=headers, json=self.body).status_code, 403)
            self.assertEqual(self.client.delete(path, headers=headers).status_code, 403)
            self.assertEqual(self.client.get("/notifications/search?status=Unread", headers=headers).status_code, 200)
            if role == config.ROLE_ANALYST:
                self.assertEqual(self.client.get(path, headers=headers).status_code, 403)
                assigned = self.client.post("/notifications", headers=self.admin, json=dict(self.body, user_id=user_id))
                assigned_path = f"/notifications/{assigned.get_json()['data']['notification_id']}"
                self.assertEqual(self.client.put(assigned_path + "/read", headers=headers).status_code, 200)
            else:
                self.assertEqual(self.client.get(path, headers=headers).status_code, 200)
                self.assertEqual(self.client.put(path + "/read", headers=headers).status_code, 403)

    def test_only_admin_can_create_and_delete(self):
        self.assertEqual(self.client.post("/notifications", headers=self.employee, json=self.body).status_code, 403)
        notification = self.create()
        path = f"/notifications/{notification['notification_id']}"
        self.assertEqual(self.client.delete(path, headers=self.employee).status_code, 403)
        self.assertEqual(self.client.get(path, headers=self.admin).status_code, 200)
        self.assertEqual(self.client.delete(path, headers=self.admin).status_code, 200)
        self.assertEqual(self.client.get(path, headers=self.admin).status_code, 404)
        self.assertEqual(self.users.get("/users/employee", headers=self.employee).status_code, 200)


if __name__ == "__main__":
    unittest.main()
