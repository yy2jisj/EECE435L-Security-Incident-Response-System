import sqlite3

from common.db import execute, fetch_all
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


class LogSearchAndDeleteTests(ApiTestCase):
    """Search, logs by user and delete, using logs with known dates."""

    def setUp(self):
        super().setUp()
        self.client = app.test_client()
        self.employee = self.reporter
        self.employee_id = self.reporter_id
        # earlier tests rows (logins, registrations) are removed so counts are exact
        execute("DELETE FROM logs")
        self.a = self.seed(self.analyst_id, "Incident created", "Information",
                           "incidents", "2026-01-05 23:59:59")
        self.b = self.seed(self.analyst_id, "Incident updated", "Warning",
                           "incidents", "2026-01-06 00:00:00")
        self.c = self.seed(self.auditor_id, "Failed login", "Error",
                           "users", "2026-01-06 12:30:00")
        self.d = self.seed(self.admin_id, "Threat deleted", "Critical",
                           "threats", "2026-02-01 08:00:00")
        self.e = self.seed(self.admin_id, "Rate 100%_done", "Information",
                           "reports", "2026-02-01 09:00:00")

    def seed(self, user_id, action, severity, service, timestamp):
        return execute(
            "INSERT INTO logs (user_id, action, description, severity_level, "
            "related_service, timestamp) VALUES (?, ?, ?, ?, ?, ?)",
            (user_id, action, action + " description", severity, service, timestamp))

    def ids(self, response):
        self.assertEqual(response.status_code, 200, response.get_json())
        return [log["log_id"] for log in response.get_json()["data"]]

    def search(self, query, headers=None):
        return self.client.get(ROOT + "/search" + query, headers=headers or self.admin)

    # ---- search: each filter ----

    def test_search_by_user(self):
        self.assertEqual(self.ids(self.search(f"?user_id={self.analyst_id}")), [self.a, self.b])
        self.assertEqual(self.ids(self.search(f"?user_id={self.admin_id}")), [self.d, self.e])

    def test_search_by_date_uses_the_whole_day(self):
        self.assertEqual(self.ids(self.search("?date=2026-01-05")), [self.a])
        self.assertEqual(self.ids(self.search("?date=2026-01-06")), [self.b, self.c])
        self.assertEqual(self.ids(self.search("?date=2026-02-01")), [self.d, self.e])

    def test_search_by_action_matches_part_of_the_text_ignoring_case(self):
        self.assertEqual(self.ids(self.search("?action=incident")), [self.a, self.b])
        self.assertEqual(self.ids(self.search("?action=FAILED")), [self.c])
        self.assertEqual(self.ids(self.search("?action=d%20l")), [self.c])

    def test_search_by_severity_ignores_case(self):
        self.assertEqual(self.ids(self.search("?severity_level=Critical")), [self.d])
        self.assertEqual(self.ids(self.search("?severity_level=information")), [self.a, self.e])
        self.assertEqual(self.ids(self.search("?severity_level=WARNING")), [self.b])

    def test_search_by_related_service_matches_part_of_the_text(self):
        self.assertEqual(self.ids(self.search("?related_service=incidents")), [self.a, self.b])
        self.assertEqual(self.ids(self.search("?related_service=THREAT")), [self.d])
        self.assertEqual(self.ids(self.search("?related_service=s")),
                         [self.a, self.b, self.c, self.d, self.e])

    # ---- search: combinations ----

    def test_filters_combine_with_and(self):
        self.assertEqual(self.ids(self.search(
            f"?user_id={self.analyst_id}&date=2026-01-06")), [self.b])
        self.assertEqual(self.ids(self.search(
            "?severity_level=Information&related_service=incidents")), [self.a])
        self.assertEqual(self.ids(self.search(
            f"?user_id={self.analyst_id}&date=2026-01-06&action=updated"
            "&severity_level=Warning&related_service=incidents")), [self.b])

    def test_search_with_no_match_is_an_empty_200(self):
        for query in ("?user_id=9999", "?date=2030-01-01", "?action=nothing",
                      f"?user_id={self.analyst_id}&severity_level=Critical"):
            response = self.search(query)
            self.assertEqual(self.ids(response), [], query)
            self.assertEqual(response.get_json()["message"], "0 log(s) found")

    def test_search_message_reports_the_count(self):
        self.assertEqual(self.search("?date=2026-01-06").get_json()["message"],
                         "2 log(s) found")

    # ---- search: wildcards and injection are plain text ----

    def test_percent_and_underscore_are_plain_text(self):
        self.assertEqual(self.ids(self.search("?action=100%25")), [self.e])
        self.assertEqual(self.ids(self.search("?action=%25_d")), [self.e])
        self.assertEqual(self.ids(self.search("?action=%25")), [self.e])
        self.assertEqual(self.ids(self.search("?action=_")), [self.e])
        self.assertEqual(self.ids(self.search("?related_service=%25")), [])

    def test_sql_injection_text_matches_nothing_and_harms_nothing(self):
        for text in ("' OR '1'='1", "'; DROP TABLE logs; --", "x' UNION SELECT 1 --"):
            self.assertEqual(self.ids(self.search("?action=" + text)), [], text)
            self.assertEqual(self.ids(self.search("?related_service=" + text)), [], text)
        self.assertEqual(len(fetch_all("SELECT 1 FROM logs")), 5)

    # ---- search: input validation ----

    def test_search_needs_at_least_one_filter(self):
        for query in ("", "?", "?action=", "?action=%20%20", "?user_id=&date="):
            self.assertEqual(self.search(query).status_code, 400, query)

    def test_search_rejects_unknown_parameters(self):
        for query in ("?name=x", "?action=a&bogus=1", "?log_id=1", "?id=1"):
            response = self.search(query)
            self.assertEqual(response.status_code, 400, query)
        self.assertIn("Allowed", self.search("?x=1").get_json()["message"])

    def test_search_rejects_bad_user_id(self):
        for bad in ("abc", "0", "-1", "1.5", "1e3", "99999999999999999999999", "%D9%A3"):
            self.assertEqual(self.search("?user_id=" + bad).status_code, 400, bad)

    def test_search_rejects_bad_dates(self):
        for bad in ("2026-13-01", "2026-02-30", "01-02-2026", "2026-1-1", "20260101",
                    "yesterday", "2026-01-01T10:00:00", "2026/01/01", "0000-00-00",
                    "2026-W01-1", "2026-001", "２０２６-01-01"):
            response = self.search("?date=" + bad)
            self.assertEqual(response.status_code, 400, bad)
            self.assertIn("date", response.get_json()["message"])

    def test_search_trims_spaces_around_values(self):
        self.assertEqual(self.ids(self.search("?date=%202026-01-05%20")), [self.a])

    def test_search_rejects_bad_severity_and_long_text(self):
        self.assertEqual(self.search("?severity_level=Severe").status_code, 400)
        self.assertEqual(self.search("?action=" + "a" * 101).status_code, 400)
        self.assertEqual(self.search("?related_service=" + "a" * 51).status_code, 400)
        self.assertEqual(self.search("?action=a%0Ab").status_code, 400)

    def test_search_accepts_text_at_the_limits(self):
        self.assertEqual(self.ids(self.search("?action=" + "a" * 100)), [])
        self.assertEqual(self.ids(self.search("?related_service=" + "a" * 50)), [])

    def test_repeated_parameter_uses_the_first_value(self):
        self.assertEqual(self.ids(self.search("?severity_level=Critical&severity_level=Warning")),
                         [self.d])

    def test_search_includes_logs_created_through_the_api(self):
        response = self.client.post(ROOT, headers=self.admin, json={
            "user_id": self.employee_id, "action": "Asset modified",
            "description": "Server renamed", "severity_level": "Information",
            "related_service": "assets"})
        new_id = response.get_json()["data"]["log_id"]
        self.assertEqual(self.ids(self.search(f"?user_id={self.employee_id}")), [new_id])

    # ---- search: roles ----

    def test_search_roles(self):
        for headers in (self.admin, self.auditor, self.analyst):
            self.assertEqual(self.ids(self.search("?date=2026-01-06", headers)),
                             [self.b, self.c])
        self.assertEqual(self.search("?date=2026-01-06", self.employee).status_code, 403)
        self.assertEqual(self.client.get(ROOT + "/search?date=2026-01-06").status_code, 401)

    def test_search_is_not_read_as_a_log_id(self):
        # a log named "search" is impossible: the route is matched before /<log_id>
        response = self.client.get(ROOT + "/search", headers=self.admin)
        self.assertEqual(response.status_code, 400)
        self.assertIn("search parameter", response.get_json()["message"])

    # ---- logs by user ----

    def test_logs_by_user_returns_only_that_users_logs(self):
        self.assertEqual(self.ids(self.client.get(
            f"{ROOT}/user/{self.analyst_id}", headers=self.admin)), [self.a, self.b])
        self.assertEqual(self.ids(self.client.get(
            f"{ROOT}/user/{self.auditor_id}", headers=self.auditor)), [self.c])
        self.assertEqual(self.ids(self.client.get(
            f"{ROOT}/user/{self.admin_id}", headers=self.admin)), [self.d, self.e])

    def test_logs_by_user_returns_full_records(self):
        data = self.client.get(f"{ROOT}/user/{self.auditor_id}",
                               headers=self.admin).get_json()["data"]
        self.assertEqual(data, [{
            "log_id": self.c, "user_id": self.auditor_id, "action": "Failed login",
            "description": "Failed login description", "timestamp": "2026-01-06 12:30:00",
            "severity_level": "Error", "related_service": "users"}])

    def test_user_without_logs_gets_an_empty_list(self):
        response = self.client.get(f"{ROOT}/user/{self.employee_id}", headers=self.admin)
        self.assertEqual(self.ids(response), [])
        self.assertEqual(response.get_json()["message"],
                         f"0 log(s) found for user {self.employee_id}")

    def test_unknown_user_is_404(self):
        self.assertEqual(self.client.get(f"{ROOT}/user/9999",
                                         headers=self.admin).status_code, 404)

    def test_logs_by_user_rejects_bad_ids(self):
        for bad in ("abc", "0", "-1", "1.5", "99999999999999999999999", "%D9%A3", "1e3"):
            response = self.client.get(f"{ROOT}/user/{bad}", headers=self.admin)
            self.assertEqual(response.status_code, 400, bad)

    def test_logs_by_user_roles(self):
        url = f"{ROOT}/user/{self.analyst_id}"
        for headers in (self.admin, self.auditor):
            self.assertEqual(self.client.get(url, headers=headers).status_code, 200)
        for headers in (self.analyst, self.employee):
            self.assertEqual(self.client.get(url, headers=headers).status_code, 403)
        self.assertEqual(self.client.get(url).status_code, 401)

    def test_new_logs_appear_for_the_user(self):
        new_id = self.client.post(ROOT, headers=self.admin, json={
            "user_id": self.employee_id, "action": "Password changed",
            "description": "x", "severity_level": "Warning",
            "related_service": "users"}).get_json()["data"]["log_id"]
        self.assertEqual(self.ids(self.client.get(
            f"{ROOT}/user/{self.employee_id}", headers=self.admin)), [new_id])

    def test_deleted_users_logs_are_kept_without_a_user(self):
        deleted = self.users.delete(f"/users/{self.analyst_id}/AdamYahya", headers=self.admin)
        self.assertEqual(deleted.status_code, 200, deleted.get_json())
        self.assertEqual(self.client.get(f"{ROOT}/user/{self.analyst_id}",
                                         headers=self.admin).status_code, 404)
        kept = self.client.get(f"{ROOT}/{self.a}", headers=self.admin).get_json()["data"]
        self.assertIsNone(kept["user_id"])
        self.assertEqual(kept["action"], "Incident created")

    # ---- delete ----

    def test_admin_deletes_a_log(self):
        response = self.client.delete(f"{ROOT}/{self.a}", headers=self.admin)
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.get_json()["message"], "Log deleted successfully")
        self.assertEqual(self.client.get(f"{ROOT}/{self.a}", headers=self.admin).status_code, 404)
        self.assertEqual(fetch_all("SELECT 1 FROM logs WHERE log_id = ?", (self.a,)), [])

    def test_deleted_log_disappears_everywhere_and_others_stay(self):
        self.client.delete(f"{ROOT}/{self.b}", headers=self.admin)
        self.assertNotIn(self.b, self.ids(self.client.get(ROOT, headers=self.admin)))
        self.assertEqual(self.ids(self.search("?date=2026-01-06")), [self.c])
        self.assertEqual(self.ids(self.client.get(
            f"{ROOT}/user/{self.analyst_id}", headers=self.admin)), [self.a])
        for kept in (self.a, self.c, self.d, self.e):
            self.assertEqual(self.client.get(f"{ROOT}/{kept}", headers=self.admin).status_code, 200)

    def test_deleting_a_log_is_itself_logged(self):
        self.client.delete(f"{ROOT}/{self.c}", headers=self.admin)
        rows = fetch_all("SELECT * FROM logs WHERE action = 'Log deleted'")
        self.assertEqual(len(rows), 1)
        self.assertEqual(rows[0]["user_id"], self.admin_id)
        self.assertEqual(rows[0]["severity_level"], "Warning")
        self.assertEqual(rows[0]["related_service"], "logs")
        self.assertIn(f"Log {self.c}", rows[0]["description"])
        self.assertGreater(rows[0]["log_id"], self.e)

    def test_deleted_id_is_not_reused(self):
        self.client.delete(f"{ROOT}/{self.e}", headers=self.admin)
        new_id = self.client.post(ROOT, headers=self.admin, json={
            "user_id": self.admin_id, "action": "a", "description": "d",
            "severity_level": "Information", "related_service": "s"}
        ).get_json()["data"]["log_id"]
        self.assertGreater(new_id, self.e)

    def test_deleting_twice_or_an_unknown_log_is_404(self):
        self.assertEqual(self.client.delete(f"{ROOT}/{self.a}", headers=self.admin).status_code, 200)
        self.assertEqual(self.client.delete(f"{ROOT}/{self.a}", headers=self.admin).status_code, 404)
        self.assertEqual(self.client.delete(ROOT + "/99999", headers=self.admin).status_code, 404)
        self.assertEqual(len(fetch_all("SELECT 1 FROM logs WHERE action = 'Log deleted'")), 1)

    def test_delete_rejects_bad_ids(self):
        for bad in ("abc", "0", "-1", "1.5", "99999999999999999999999", "%D9%A3", "1e3"):
            response = self.client.delete(f"{ROOT}/{bad}", headers=self.admin)
            self.assertEqual(response.status_code, 400, bad)
        self.assertEqual(len(fetch_all("SELECT 1 FROM logs")), 5)

    def test_only_admin_can_delete(self):
        for headers in (self.analyst, self.auditor, self.employee):
            response = self.client.delete(f"{ROOT}/{self.a}", headers=headers)
            self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.delete(f"{ROOT}/{self.a}").status_code, 401)
        self.assertEqual(self.client.get(f"{ROOT}/{self.a}", headers=self.admin).status_code, 200)

    def test_refused_delete_is_logged_against_the_caller(self):
        self.client.delete(f"{ROOT}/{self.a}", headers=self.analyst)
        self.client.delete(f"{ROOT}/{self.a}", headers=self.employee)
        rows = fetch_all("SELECT * FROM logs WHERE related_service = 'logs' "
                         "AND severity_level = 'Warning'")
        self.assertEqual([row["user_id"] for row in rows],
                         [self.analyst_id, self.employee_id])
        self.assertEqual(fetch_all("SELECT 1 FROM logs WHERE action = 'Log deleted'"), [])

    def test_delete_without_an_id_is_not_allowed(self):
        self.assertEqual(self.client.delete(ROOT, headers=self.admin).status_code, 405)
        self.assertEqual(len(fetch_all("SELECT 1 FROM logs")), 5)

    def test_admin_can_delete_the_record_of_a_deletion(self):
        self.client.delete(f"{ROOT}/{self.a}", headers=self.admin)
        record = fetch_all("SELECT log_id FROM logs WHERE action = 'Log deleted'")[0]["log_id"]
        self.assertEqual(self.client.delete(f"{ROOT}/{record}", headers=self.admin).status_code, 200)
        # deleting it wrote a new record, so one deletion record always remains
        self.assertEqual(len(fetch_all("SELECT 1 FROM logs WHERE action = 'Log deleted'")), 1)
