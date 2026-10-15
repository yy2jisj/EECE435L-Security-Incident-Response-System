from common.db import fetch_all, fetch_one
from notification_service.app import app
from tests.support import DatabaseTest


class NotificationApiTests(DatabaseTest):
    def setUp(self):
        super().setUp()
        self.client = app.test_client()

    def create(self, **changes):
        response = self.client.post("/notifications", headers=self.admin, json=self.payload(**changes))
        self.assertEqual(response.status_code, 201, response.get_json())
        return response.get_json()["data"]

    def assert_error(self, response, status):
        self.assertEqual(response.status_code, status, response.get_json())
        self.assertEqual(response.get_json()["status"], "error")
        self.assertTrue(response.get_json()["message"])

    def test_create_persists_multiple_notifications(self):
        first = self.create()
        second = self.create(notification_type="Threat Alert", severity_level="Critical")
        self.assertNotEqual(first["notification_id"], second["notification_id"])
        rows = fetch_all("SELECT * FROM notifications ORDER BY notification_id")
        self.assertEqual(len(rows), 2)
        self.assertEqual(rows[0]["is_read"], 0)
        self.assertIsNone(rows[0]["read_date"])
        self.assertEqual(rows[0]["created_at"], first["created_at"])

    def test_each_required_field_and_unexpected_metadata(self):
        for field in self.payload():
            data = self.payload()
            del data[field]
            with self.subTest(field=field):
                self.assert_error(self.client.post("/notifications", headers=self.admin, json=data), 400)
        for field in ("status", "created_at", "read_date", "incident_id", "severity"):
            with self.subTest(field=field):
                self.assert_error(self.client.post("/notifications", headers=self.admin,
                                                   json=self.payload(**{field: "unexpected"})), 400)
        self.assertEqual(fetch_one("SELECT COUNT(*) AS n FROM notifications")["n"], 0)

    def test_missing_malformed_and_non_object_body(self):
        for body in (None, "{", "[]", "null", "{}", '"hello"'):
            with self.subTest(body=body):
                self.assert_error(self.client.post("/notifications", headers=self.admin,
                                                   data=body, content_type="application/json"), 400)

    def test_create_invalid_values_do_not_persist(self):
        for changes, status in (({"user_id": 99999}, 404), ({"user_id": True}, 400),
                                ({"user_id": -1}, 400), ({"user_id": 1.5}, 400),
                                ({"user_id": "1"}, 400), ({"user_id": 2**63}, 400),
                                ({"title": " "}, 400), ({"message": None}, 400),
                                ({"title": []}, 400), ({"message": "a\x00b"}, 400),
                                ({"notification_type": "Other"}, 400),
                                ({"notification_type": {}}, 400),
                                ({"severity_level": "Urgent"}, 400), ({"severity_level": []}, 400)):
            with self.subTest(changes=changes):
                self.assert_error(self.client.post("/notifications", headers=self.admin,
                                                   json=self.payload(**changes)), status)
        self.assertEqual(fetch_one("SELECT COUNT(*) AS n FROM notifications")["n"], 0)

    def test_all_types_severities_and_text_boundaries(self):
        from notification_service.models import NOTIFICATION_TYPES, SEVERITIES
        for kind in NOTIFICATION_TYPES:
            for level in SEVERITIES:
                self.create(notification_type=kind, severity_level=level)
        row = self.create(title="a" * 255, message="a" * 4000,
                          notification_type=" security alert ", severity_level=" high ")
        self.assertEqual(row["notification_type"], "Security Alert")
        self.assertEqual(row["severity_level"], "High")
        for changes in ({"title": "a" * 256}, {"message": "a" * 4001}):
            self.assert_error(self.client.post("/notifications", headers=self.admin,
                                               json=self.payload(**changes)), 400)

    def test_retrieve_user_empty_missing_and_ownership(self):
        first = self.create()
        second = self.create(title="Second")
        employee_id = first["user_id"]
        for headers in (self.admin, self.auditor, self.employee):
            response = self.client.get(f"/notifications/user/{employee_id}", headers=headers)
            self.assertEqual(response.status_code, 200)
            self.assertEqual([n["notification_id"] for n in response.get_json()["data"]],
                             [first["notification_id"], second["notification_id"]])
        for headers in (self.other, self.analyst):
            self.assert_error(self.client.get(f"/notifications/user/{employee_id}", headers=headers), 403)
        other_id = self.people["other"]["user_id"]
        self.assertEqual(self.client.get(f"/notifications/user/{other_id}",
                                        headers=self.admin).get_json()["data"], [])
        self.assert_error(self.client.get("/notifications/user/99999", headers=self.admin), 404)

    def test_specific_access_and_missing_privacy(self):
        row = self.create()
        path = f"/notifications/{row['notification_id']}"
        for headers in (self.admin, self.employee, self.auditor):
            self.assertEqual(self.client.get(path, headers=headers).status_code, 200)
        for headers in (self.other, self.analyst):
            self.assert_error(self.client.get(path, headers=headers), 403)
            self.assert_error(self.client.get("/notifications/99999", headers=headers), 403)
        self.assert_error(self.client.get("/notifications/99999", headers=self.admin), 404)

    def test_authentication_and_create_roles(self):
        for headers, status in (({}, 401), ({"Authorization": "Bearer invalid"}, 401),
                                (self.employee, 403), (self.analyst, 403), (self.auditor, 403)):
            self.assert_error(self.client.post("/notifications", headers=headers,
                                               json=self.payload()), status)
        self.assert_error(self.client.get("/notifications/1"), 401)

    def test_malformed_ids_return_json_errors(self):
        for value in ("0", "-1", "abc", "1.5", "9223372036854775808", "9" * 5000):
            for path in (f"/notifications/{value}", f"/notifications/user/{value}"):
                with self.subTest(path=path[:80]):
                    self.assert_error(self.client.get(path, headers=self.admin), 400)
        self.assert_error(self.client.patch("/notifications/1", headers=self.admin), 405)

    def test_sql_text_is_stored_as_data(self):
        message = "'; DROP TABLE users; --"
        row = self.create(message=message)
        self.assertEqual(row["message"], message)
        self.assertEqual(fetch_one("SELECT COUNT(*) AS n FROM users")["n"], 5)
