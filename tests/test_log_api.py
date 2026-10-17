from common.db import fetch_all
from log_service.app import app
from api_test_case import ApiTestCase

ROOT = "/leen-abdallah/logs"


class LogApiTests(ApiTestCase):
    def setUp(self):
        super().setUp()
        self.client = app.test_client()
        self.employee = self.reporter
        self.body = {"user_id": self.analyst_id, "action": "Incident created",
                     "description": "Analyst opened incident 4",
                     "severity_level": "Information", "related_service": "incidents"}

    def create(self, **changes):
        response = self.client.post(ROOT, headers=self.admin, json={**self.body, **changes})
        self.assertEqual(response.status_code, 201, response.get_json())
        return response.get_json()["data"]

    # ---- create ----

    def test_admin_creates_log(self):
        log = self.create()
        self.assertEqual(log["user_id"], self.analyst_id)
        self.assertEqual(log["action"], "Incident created")
        self.assertEqual(log["severity_level"], "Information")
        self.assertEqual(log["related_service"], "incidents")
        self.assertTrue(log["timestamp"])

    def test_severity_is_case_insensitive(self):
        self.assertEqual(self.create(severity_level="critical")["severity_level"], "Critical")

    def test_create_is_stored_in_database(self):
        log = self.create()
        rows = fetch_all("SELECT * FROM logs WHERE log_id = ?", (log["log_id"],))
        self.assertEqual(rows[0]["description"], "Analyst opened incident 4")

    def test_create_rejects_bad_input(self):
        bad_bodies = [
            {}, {**self.body, "extra": "x"},
            {**self.body, "user_id": None}, {**self.body, "user_id": "1"},
            {**self.body, "user_id": True}, {**self.body, "user_id": 0},
            {**self.body, "user_id": 10 ** 30}, {**self.body, "user_id": 9999},
            {**self.body, "action": ""}, {**self.body, "action": "x" * 101},
            {**self.body, "description": "  "}, {**self.body, "description": "x" * 501},
            {**self.body, "severity_level": "Severe"},
            {**self.body, "related_service": ""}, {**self.body, "related_service": "x" * 51},
            {**self.body, "action": 5},
        ]
        for body in bad_bodies:
            response = self.client.post(ROOT, headers=self.admin, json=body)
            self.assertEqual(response.status_code, 400, body)

    def test_create_rejects_missing_field(self):
        for field in self.body:
            body = {key: value for key, value in self.body.items() if key != field}
            response = self.client.post(ROOT, headers=self.admin, json=body)
            self.assertEqual(response.status_code, 400, field)
            self.assertIn(field, response.get_json()["message"])

    def test_only_admin_creates(self):
        for headers in (self.analyst, self.auditor, self.employee):
            response = self.client.post(ROOT, headers=headers, json=self.body)
            self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.post(ROOT, json=self.body).status_code, 401)

    def test_create_rejects_unusable_bodies(self):
        for body in ([], [self.body], "text", 5):
            response = self.client.post(ROOT, headers=self.admin, json=body)
            self.assertEqual(response.status_code, 400, body)
        response = self.client.post(ROOT, headers=self.admin, data="not json",
                                    content_type="text/plain")
        self.assertEqual(response.status_code, 400)
        response = self.client.post(ROOT, headers=self.admin, data="{broken",
                                    content_type="application/json")
        self.assertEqual(response.status_code, 400)

    def test_create_rejects_wrongly_typed_values(self):
        for changes in ({"user_id": 1.0}, {"user_id": [1]}, {"user_id": {"id": 1}},
                        {"severity_level": 5}, {"severity_level": None},
                        {"description": ["x"]}, {"related_service": 7}):
            response = self.client.post(ROOT, headers=self.admin,
                                        json={**self.body, **changes})
            self.assertEqual(response.status_code, 400, changes)

    def test_client_cannot_set_id_or_timestamp(self):
        for field, value in (("log_id", 999), ("timestamp", "2000-01-01 00:00:00")):
            response = self.client.post(ROOT, headers=self.admin,
                                        json={**self.body, field: value})
            self.assertEqual(response.status_code, 400, field)
            self.assertIn(field, response.get_json()["message"])

    def test_text_is_trimmed_and_control_characters_rejected(self):
        log = self.create(action="  Role changed  ", related_service=" users ")
        self.assertEqual(log["action"], "Role changed")
        self.assertEqual(log["related_service"], "users")
        for text in ("line\nbreak", "tab\there", "null\x00byte"):
            response = self.client.post(ROOT, headers=self.admin,
                                        json={**self.body, "description": text})
            self.assertEqual(response.status_code, 400, repr(text))

    def test_text_at_the_length_limits_is_accepted(self):
        log = self.create(action="a" * 100, description="d" * 500,
                          related_service="s" * 50)
        self.assertEqual(len(log["action"]), 100)
        self.assertEqual(len(log["description"]), 500)

    def test_unicode_text_is_stored_unchanged(self):
        log = self.create(description="تسجيل دخول – échec de connexion ✓")
        self.assertEqual(self.client.get(f"{ROOT}/{log['log_id']}", headers=self.admin)
                         .get_json()["data"]["description"],
                         "تسجيل دخول – échec de connexion ✓")

    def test_identical_logs_are_both_kept(self):
        first, second = self.create(), self.create()
        self.assertNotEqual(first["log_id"], second["log_id"])

    def test_every_severity_level_is_accepted(self):
        for level in ("Information", "Warning", "Error", "Critical"):
            self.assertEqual(self.create(severity_level=level)["severity_level"], level)

    def test_failed_create_stores_nothing(self):
        before = len(fetch_all("SELECT 1 FROM logs"))
        self.client.post(ROOT, headers=self.admin, json={**self.body, "user_id": 9999})
        self.client.post(ROOT, headers=self.admin, json={**self.body, "severity_level": "x"})
        self.assertEqual(len(fetch_all("SELECT 1 FROM logs")), before)

    def test_invalid_or_malformed_token_is_401(self):
        for header in ("Bearer not.a.token", "Bearer ", "Basic abc", "garbage"):
            response = self.client.get(ROOT, headers={"Authorization": header})
            self.assertEqual(response.status_code, 401, header)

    # ---- logs cannot be changed ----

    def test_logs_cannot_be_updated_through_the_api(self):
        log = self.create()
        for method in ("put", "patch", "post"):
            response = getattr(self.client, method)(
                f"{ROOT}/{log['log_id']}", headers=self.admin, json={"action": "x"})
            self.assertEqual(response.status_code, 405, method)
        for method in ("put", "patch"):
            self.assertEqual(getattr(self.client, method)(
                ROOT, headers=self.admin, json={"action": "x"}).status_code, 405)

    def test_database_refuses_to_modify_a_log(self):
        import sqlite3
        from common.db import execute
        log = self.create()
        for column, value in (("description", "changed"), ("action", "changed"),
                              ("severity_level", "Critical"), ("timestamp", "2000-01-01")):
            with self.assertRaises(sqlite3.DatabaseError):
                execute(f"UPDATE logs SET {column} = ? WHERE log_id = ?",
                        (value, log["log_id"]))
        self.assertEqual(self.client.get(f"{ROOT}/{log['log_id']}", headers=self.admin)
                         .get_json()["data"], log)

    # ---- retrieve all ----

    def test_admin_and_auditor_list_logs(self):
        created = self.create()
        for headers in (self.admin, self.auditor):
            response = self.client.get(ROOT, headers=headers)
            self.assertEqual(response.status_code, 200)
            ids = [log["log_id"] for log in response.get_json()["data"]]
            self.assertIn(created["log_id"], ids)
            self.assertEqual(ids, sorted(ids))

    def test_analyst_and_employee_cannot_list(self):
        for headers in (self.analyst, self.employee):
            self.assertEqual(self.client.get(ROOT, headers=headers).status_code, 403)
        self.assertEqual(self.client.get(ROOT).status_code, 401)

    # ---- retrieve one ----

    def test_admin_auditor_and_analyst_get_one(self):
        created = self.create()
        for headers in (self.admin, self.auditor, self.analyst):
            response = self.client.get(f"{ROOT}/{created['log_id']}", headers=headers)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["data"], created)

    def test_employee_cannot_get_one(self):
        created = self.create()
        response = self.client.get(f"{ROOT}/{created['log_id']}", headers=self.employee)
        self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.get(f"{ROOT}/{created['log_id']}").status_code, 401)

    def test_get_unknown_log_is_404(self):
        self.assertEqual(self.client.get(ROOT + "/99999", headers=self.admin).status_code, 404)

    def test_get_invalid_log_id_is_400(self):
        for bad in ("abc", "0", "-1", "1.5", "99999999999999999999999", "٣", "1%20", "1e3"):
            response = self.client.get(f"{ROOT}/{bad}", headers=self.admin)
            self.assertEqual(response.status_code, 400, bad)

    # ---- permission violations are audited ----

    def test_denied_access_is_logged(self):
        self.client.get(ROOT, headers=self.analyst)
        rows = fetch_all("SELECT * FROM logs WHERE related_service = 'logs' "
                         "AND severity_level = 'Warning'")
        self.assertTrue(rows)
        self.assertEqual(rows[-1]["user_id"], self.analyst_id)

    def test_routes_live_under_student_name(self):
        self.assertEqual(self.client.get("/logs", headers=self.admin).status_code, 404)
