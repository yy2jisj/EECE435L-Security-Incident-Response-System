from common import config
from common.db import fetch_one
from tests.support import DatabaseTest


class Service1RegressionTests(DatabaseTest):
    def test_registration_login_password_and_validation(self):
        user = self.people["employee"]
        stored = fetch_one("SELECT password_hash,last_login FROM users WHERE user_id=?", (user["user_id"],))
        self.assertTrue(stored["password_hash"].startswith("scrypt:"))
        self.assertIsNotNone(stored["last_login"])
        wrong = self.users.post("/users/login", json={"username": user["username"], "password": "wrong"})
        self.assertEqual(wrong.status_code, 401)
        data = {"full_name": "Duplicate", "username": user["username"], "email": "new@example.com",
                "password": "NotARealCredential435!", "department": "QA"}
        self.assertEqual(self.users.post("/users/register", json=data).status_code, 409)
        data.update(username="new_account", email="bad_email")
        self.assertEqual(self.users.post("/users/register", json=data).status_code, 400)

    def test_retrieval_permissions_and_profile_update(self):
        for headers, expected in ((self.admin, 200), (self.auditor, 200),
                                  (self.employee, 403), (self.analyst, 403), ({}, 401)):
            self.assertEqual(self.users.get("/users", headers=headers).status_code, expected)
        own = self.people["employee"]
        self.assertEqual(self.users.get(f"/users/{own['username']}", headers=self.employee).status_code, 200)
        self.assertEqual(self.users.get("/users/qa_other", headers=self.employee).status_code, 403)
        self.assertEqual(self.users.get("/users/nobody", headers=self.admin).status_code, 404)
        response = self.users.put(f"/users/{own['user_id']}", headers=self.employee,
                                  json={"department": "Updated QA"})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(fetch_one("SELECT department FROM users WHERE user_id=?",
                                  (own["user_id"],))["department"], "Updated QA")
        self.assertEqual(self.users.put(f"/users/{self.people['other']['user_id']}", headers=self.employee,
                                        json={"department": "Forbidden"}).status_code, 403)

    def test_delete_authorization_and_persistence(self):
        user_id = self.people["other"]["user_id"]
        for headers, expected in (({}, 401), (self.employee, 403), (self.analyst, 403), (self.auditor, 403)):
            self.assertEqual(self.users.delete(f"/users/{user_id}", headers=headers).status_code, expected)
        self.assertEqual(self.users.delete(f"/users/{user_id}", headers=self.admin).status_code, 200)
        self.assertIsNone(fetch_one("SELECT * FROM users WHERE user_id=?", (user_id,)))
        self.assertEqual(self.users.delete(f"/users/{user_id}", headers=self.admin).status_code, 404)
