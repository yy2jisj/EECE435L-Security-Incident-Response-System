import tempfile
import unittest
from pathlib import Path

from common import config
from common.db import init_schema
from database.init_db import ADMIN_PASSWORD, create_default_admin
from user_service.app import app


class Service1Tests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.old_database = config.DB_PATH
        config.DB_PATH = str(Path(self.directory.name) / "test.db")
        init_schema()
        create_default_admin()
        self.client = app.test_client()

    def tearDown(self):
        config.DB_PATH = self.old_database
        self.directory.cleanup()

    def test_login(self):
        response = self.client.post("/users/login/AdamYahya", json={"username": "admin", "password": ADMIN_PASSWORD})
        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.get_json()["data"]["token"])
        wrong = self.client.post("/users/login/AdamYahya", json={"username": "admin", "password": "wrong"})
        self.assertEqual(wrong.status_code, 401)

    def test_register_retrieve_update_and_delete(self):
        body = {"full_name": "Test Student", "username": "student", "email": "student@example.com",
                "password": "TestPassword435!", "department": "Engineering"}
        response = self.client.post("/users/register/AdamYahya", json=body)
        self.assertEqual(response.status_code, 201)
        user_id = response.get_json()["data"]["user_id"]
        login = self.client.post("/users/login/AdamYahya", json={"username": "student", "password": body["password"]})
        self.assertEqual(login.status_code, 200)
        employee = {"Authorization": "Bearer " + login.get_json()["data"]["token"]}
        self.assertEqual(self.client.get("/users/student/AdamYahya", headers=employee).status_code, 200)
        self.assertEqual(self.client.get("/users/AdamYahya", headers=employee).status_code, 403)
        updated = self.client.put(f"/users/{user_id}/AdamYahya", headers=employee, json={"department": "IT"})
        self.assertEqual(updated.status_code, 200)
        self.assertEqual(updated.get_json()["data"]["department"], "IT")
        login = self.client.post("/users/login/AdamYahya", json={"username": "admin", "password": ADMIN_PASSWORD})
        admin = {"Authorization": "Bearer " + login.get_json()["data"]["token"]}
        self.assertEqual(self.client.get("/users/AdamYahya", headers=admin).status_code, 200)
        self.assertEqual(self.client.delete(f"/users/{user_id}/AdamYahya", headers=admin).status_code, 200)
        self.assertEqual(self.client.get("/users/student/AdamYahya", headers=admin).status_code, 404)


if __name__ == "__main__":
    unittest.main()
