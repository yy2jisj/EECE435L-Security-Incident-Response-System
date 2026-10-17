"""Isolated API fixtures: real Service 1 authentication and a temporary database."""

import os
import tempfile
import threading
import unittest
from pathlib import Path
from unittest.mock import patch

from werkzeug.serving import WSGIRequestHandler, make_server

from asset_service.app import app as assets_app
from common import config
from common.db import init_schema
from database.init_db import ADMIN_PASSWORD, create_default_admin
from user_service.app import app as users_app


class QuietHandler(WSGIRequestHandler):
    def log_request(self, code="-", size="-"):
        pass


class ApiTestCase(unittest.TestCase):
    def setUp(self):
        directory = tempfile.TemporaryDirectory()
        self.addCleanup(directory.cleanup)
        database = patch.object(config, "DB_PATH", str(Path(directory.name) / "test.db"))
        database.start()
        self.addCleanup(database.stop)
        init_schema()
        create_default_admin()
        self.users = users_app.test_client()
        self.admin_id, self.admin = self.login("admin", ADMIN_PASSWORD)
        self.reporter_id, self.reporter = self.register("reporter", config.ROLE_USER)
        self.analyst_id, self.analyst = self.register("analyst", config.ROLE_ANALYST)
        self.auditor_id, self.auditor = self.register("auditor", config.ROLE_AUDITOR)

    def login(self, username, password):
        response = self.users.post("/users/login", json={"username": username, "password": password})
        self.assertEqual(response.status_code, 200, response.get_json())
        data = response.get_json()["data"]
        return data["user"]["user_id"], {"Authorization": "Bearer " + data["token"]}

    def register(self, username, role):
        password = "TemporaryFixture435!"
        response = self.users.post("/users/register", headers=self.admin, json={
            "full_name": "Fixture User", "username": username,
            "email": username + "@example.test", "password": password,
            "department": "Security", "role": role,
        })
        self.assertEqual(response.status_code, 201, response.get_json())
        return self.login(username, password)

    def create_asset(self):
        self.assets = assets_app.test_client()
        response = self.assets.post("/assets", headers=self.admin, json={
            "asset_name": "Fixture server", "asset_type": "Server",
            "ip_address": "192.0.2.10", "department": "Security",
            "owner_id": self.reporter_id, "criticality_level": "High",
        })
        self.assertEqual(response.status_code, 201, response.get_json())
        return response.get_json()["data"]["asset_id"]

    def serve_users(self):
        """Run Service 1 over real loopback HTTP; never touch the normal port/DB."""
        server = make_server("127.0.0.1", 0, users_app, threaded=True,
                             request_handler=QuietHandler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()

        def stop():
            server.shutdown()
            server.server_close()
            thread.join(timeout=5)

        self.addCleanup(stop)
        setting = patch.dict(os.environ, {
            "USERS_SERVICE_URL": f"http://127.0.0.1:{server.server_port}",
        })
        setting.start()
        self.addCleanup(setting.stop)
