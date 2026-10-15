"""Disposable SQLite database and actual Service 1 logins for tests."""

import secrets
import tempfile
import unittest
from pathlib import Path

from common import config
from common.db import init_schema
from database.init_db import create_default_admin, ADMIN_PASSWORD
from database.migrate_notifications import migrate_notifications
from user_service.app import app as users_app


class DatabaseTest(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.old_path = config.DB_PATH
        config.DB_PATH = str(Path(self.temp.name) / "test.db")
        self.addCleanup(self.restore_database)
        init_schema()
        migrate_notifications()
        create_default_admin()
        self.users = users_app.test_client()
        self.admin = self.login("admin", ADMIN_PASSWORD)
        self.people = {}
        for label, role in (("employee", config.ROLE_USER), ("other", config.ROLE_USER),
                            ("analyst", config.ROLE_ANALYST), ("auditor", config.ROLE_AUDITOR)):
            password = "Qa435L!" + secrets.token_hex(8)
            response = self.users.post("/users/register", headers=self.admin, json={
                "full_name": f"QA {label}", "username": f"qa_{label}",
                "email": f"{label}@example.com", "password": password,
                "department": "QA", "role": role,
            })
            self.assertEqual(response.status_code, 201, response.get_json())
            self.people[label] = response.get_json()["data"]
            setattr(self, label, self.login(f"qa_{label}", password))

    def restore_database(self):
        config.DB_PATH = self.old_path
        self.temp.cleanup()

    def login(self, username, password):
        response = self.users.post("/users/login", json={"username": username, "password": password})
        self.assertEqual(response.status_code, 200, response.get_json())
        return {"Authorization": "Bearer " + response.get_json()["data"]["token"]}

    def payload(self, **changes):
        data = {"user_id": self.people["employee"]["user_id"], "title": "Security Alert",
                "message": "Suspicious activity was detected.",
                "notification_type": "Security Alert", "severity_level": "High"}
        data.update(changes)
        return data
