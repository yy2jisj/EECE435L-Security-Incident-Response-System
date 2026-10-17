import tempfile
import unittest
from pathlib import Path

from common import config
from common.db import fetch_all, init_schema
from database.init_db import ADMIN_PASSWORD, create_default_admin
from threat_service.app import app
from user_service.app import app as users_app


class ThreatApiTests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.old_database = config.DB_PATH
        config.DB_PATH = str(Path(self.directory.name) / "test.db")
        init_schema()
        create_default_admin()
        self.client = app.test_client()
        self.users = users_app.test_client()
        self.admin = self.login("admin", ADMIN_PASSWORD)
        self.analyst = self.register("analyst1", config.ROLE_ANALYST)
        self.auditor = self.register("auditor1", config.ROLE_AUDITOR)
        self.employee = self.register("employee1", config.ROLE_USER)
        self.body = {"threat_type": "IP Address", "threat_value": "192.168.1.5",
                     "description": "Port scanner", "severity_level": "High",
                     "source": "AbuseIPDB"}

    def tearDown(self):
        config.DB_PATH = self.old_database
        self.directory.cleanup()

    def login(self, username, password):
        response = self.users.post("/users/login",
                                   json={"username": username, "password": password})
        self.assertEqual(response.status_code, 200)
        return {"Authorization": "Bearer " + response.get_json()["data"]["token"]}

    def register(self, username, role):
        response = self.users.post("/users/register", headers=self.admin, json={
            "full_name": "Test User", "username": username,
            "email": username + "@example.com", "password": "TestPassword435!",
            "department": "IT", "role": role})
        self.assertEqual(response.status_code, 201)
        return self.login(username, "TestPassword435!")

    def add(self, **changes):
        response = self.client.post("/threats", headers=self.admin,
                                    json={**self.body, **changes})
        self.assertEqual(response.status_code, 201)
        return response.get_json()["data"]

    def add_samples(self):
        self.add()
        self.add(threat_type="Domain", threat_value="evil.example.com",
                 severity_level="Critical", source="OSINT feed")
        self.add(threat_type="File Hash", threat_value="d41d8cd98f00b204e9800998ecf8427e",
                 severity_level="Low", source="VirusTotal")

    # ---- add ----
    def test_admin_adds_threat(self):
        threat = self.add(threat_type="domain", threat_value="Evil.Example.com",
                          severity_level="critical")
        self.assertEqual(threat["threat_type"], "Domain")
        self.assertEqual(threat["threat_value"], "evil.example.com")
        self.assertEqual(threat["severity_level"], "Critical")
        self.assertTrue(threat["date_added"])
        self.assertTrue(threat["threat_id"])

    def test_duplicate_threat_is_rejected(self):
        self.add()
        response = self.client.post("/threats", headers=self.admin, json=self.body)
        self.assertEqual(response.status_code, 409)
        # same value with different case still counts as the same domain
        self.add(threat_type="Domain", threat_value="evil.com")
        duplicate = self.client.post("/threats", headers=self.admin, json={
            **self.body, "threat_type": "Domain", "threat_value": "EVIL.com"})
        self.assertEqual(duplicate.status_code, 409)
        # the same value under another type is a different indicator
        self.add(threat_type="Other", threat_value="192.168.1.5")

    def test_free_text_duplicates_ignore_case(self):
        self.add(threat_type="Malware Signature", threat_value="Trojan.X")
        for value in ("trojan.x", "TROJAN.X"):
            response = self.client.post("/threats", headers=self.admin, json={
                **self.body, "threat_type": "Malware Signature", "threat_value": value})
            self.assertEqual(response.status_code, 409, msg=value)
        self.assertEqual(len(self.client.get("/threats", headers=self.admin).get_json()["data"]), 1)

    def test_out_of_range_ids_are_rejected(self):
        too_big = str(2 ** 63)
        for response in (
            self.client.get(f"/threats/{too_big}", headers=self.admin),
            self.client.put(f"/threats/{too_big}", headers=self.admin, json={"source": "x"}),
            self.client.delete(f"/threats/{too_big}", headers=self.admin),
            self.client.get("/threats/" + "9" * 40, headers=self.admin),
        ):
            self.assertEqual(response.status_code, 400)
        # the largest valid number is simply "not found"
        self.assertEqual(
            self.client.get(f"/threats/{2 ** 63 - 1}", headers=self.admin).status_code, 404)

    def test_add_validation(self):
        bad_bodies = [
            {"threat_value": "999.1.1.1"},
            {"threat_type": "Domain", "threat_value": "not a domain"},
            {"threat_type": "File Hash", "threat_value": "xyz"},
            {"threat_type": "Bogus"},
            {"severity_level": "Urgent"},
            {"description": ""},
            {"extra_field": "x"},
        ]
        for changes in bad_bodies:
            response = self.client.post("/threats", headers=self.admin,
                                        json={**self.body, **changes})
            self.assertEqual(response.status_code, 400, msg=changes)
        missing = dict(self.body)
        del missing["source"]
        self.assertEqual(
            self.client.post("/threats", headers=self.admin, json=missing).status_code, 400)
        self.assertEqual(
            self.client.post("/threats", headers=self.admin, json={}).status_code, 400)
        self.assertEqual(self.client.get("/threats", headers=self.admin).get_json()["data"], [])

    def test_only_admin_can_add(self):
        for headers in (self.analyst, self.auditor, self.employee):
            response = self.client.post("/threats", headers=headers, json=self.body)
            self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.post("/threats", json=self.body).status_code, 401)
        bad_token = {"Authorization": "Bearer garbage"}
        self.assertEqual(
            self.client.post("/threats", headers=bad_token, json=self.body).status_code, 401)

    # ---- read ----
    def test_get_all_roles(self):
        self.add_samples()
        for headers in (self.admin, self.analyst, self.auditor):
            response = self.client.get("/threats", headers=headers)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(len(response.get_json()["data"]), 3)
        self.assertEqual(self.client.get("/threats", headers=self.employee).status_code, 403)
        self.assertEqual(self.client.get("/threats").status_code, 401)

    def test_get_one(self):
        threat = self.add()
        for headers in (self.admin, self.analyst, self.auditor):
            response = self.client.get(f"/threats/{threat['threat_id']}", headers=headers)
            self.assertEqual(response.status_code, 200)
            self.assertEqual(response.get_json()["data"], threat)
        self.assertEqual(
            self.client.get(f"/threats/{threat['threat_id']}",
                            headers=self.employee).status_code, 403)
        self.assertEqual(self.client.get("/threats/999", headers=self.admin).status_code, 404)
        for bad_id in ("abc", "0", "-1"):
            self.assertEqual(
                self.client.get(f"/threats/{bad_id}", headers=self.admin).status_code, 400)

    # ---- search ----
    def search(self, query, headers=None):
        return self.client.get("/threats/search?" + query, headers=headers or self.admin)

    def test_search_filters(self):
        self.add_samples()
        cases = {
            "threat_type=domain": 1,
            "severity_level=high": 1,
            "threat_value=192.168": 1,
            "source=virus": 1,
            "threat_type=Domain&severity_level=Critical": 1,
            "threat_type=Domain&severity_level=Low": 0,
            "source=zzz": 0,
        }
        for query, expected in cases.items():
            response = self.search(query)
            self.assertEqual(response.status_code, 200, msg=query)
            self.assertEqual(len(response.get_json()["data"]), expected, msg=query)

    def test_search_treats_wildcards_as_text(self):
        self.add_samples()
        self.assertEqual(len(self.search("threat_value=%25").get_json()["data"]), 0)
        self.assertEqual(len(self.search("source=_").get_json()["data"]), 0)

    def test_search_validation_and_roles(self):
        self.add_samples()
        self.assertEqual(self.search("").status_code, 400)
        self.assertEqual(self.search("severity_level=x").status_code, 400)
        self.assertEqual(self.search("threat_type=x").status_code, 400)
        self.assertEqual(self.search("foo=1").status_code, 400)
        self.assertEqual(self.search("source=a", self.analyst).status_code, 200)
        self.assertEqual(self.search("source=a", self.auditor).status_code, 403)
        self.assertEqual(self.search("source=a", self.employee).status_code, 403)

    # ---- update ----
    def test_update_threat(self):
        threat = self.add()
        path = f"/threats/{threat['threat_id']}"
        response = self.client.put(path, headers=self.admin, json={
            "description": "Updated", "severity_level": "critical", "source": "New source"})
        self.assertEqual(response.status_code, 200)
        data = response.get_json()["data"]
        self.assertEqual(data["description"], "Updated")
        self.assertEqual(data["severity_level"], "Critical")
        self.assertEqual(data["source"], "New source")
        # type, value and date are unchanged
        self.assertEqual(data["threat_type"], threat["threat_type"])
        self.assertEqual(data["threat_value"], threat["threat_value"])
        self.assertEqual(data["date_added"], threat["date_added"])
        # a partial update only changes the given field
        partial = self.client.put(path, headers=self.admin, json={"severity_level": "Low"})
        self.assertEqual(partial.get_json()["data"]["severity_level"], "Low")
        self.assertEqual(partial.get_json()["data"]["description"], "Updated")

    def test_update_validation(self):
        threat = self.add()
        path = f"/threats/{threat['threat_id']}"
        for body in ({"threat_type": "Domain"}, {"threat_value": "1.1.1.1"},
                     {"severity_level": "Urgent"}, {"description": ""},
                     {"source": " "}, {}):
            response = self.client.put(path, headers=self.admin, json=body)
            self.assertEqual(response.status_code, 400, msg=body)
        unchanged = self.client.get(path, headers=self.admin).get_json()["data"]
        self.assertEqual(unchanged, threat)
        self.assertEqual(
            self.client.put("/threats/999", headers=self.admin,
                            json={"source": "x"}).status_code, 404)
        self.assertEqual(
            self.client.put("/threats/abc", headers=self.admin,
                            json={"source": "x"}).status_code, 400)

    def test_only_admin_can_update(self):
        threat = self.add()
        path = f"/threats/{threat['threat_id']}"
        for headers in (self.analyst, self.auditor, self.employee):
            response = self.client.put(path, headers=headers, json={"source": "x"})
            self.assertEqual(response.status_code, 403)
        self.assertEqual(self.client.put(path, json={"source": "x"}).status_code, 401)
        self.assertEqual(
            self.client.get(path, headers=self.admin).get_json()["data"]["source"], "AbuseIPDB")

    # ---- delete ----
    def test_admin_deletes_threat(self):
        threat = self.add()
        path = f"/threats/{threat['threat_id']}"
        self.assertEqual(self.client.delete(path, headers=self.admin).status_code, 200)
        self.assertEqual(self.client.get(path, headers=self.admin).status_code, 404)
        self.assertEqual(self.client.delete(path, headers=self.admin).status_code, 404)
        self.assertEqual(
            self.client.delete("/threats/abc", headers=self.admin).status_code, 400)

    def test_only_admin_can_delete(self):
        threat = self.add()
        path = f"/threats/{threat['threat_id']}"
        for headers in (self.analyst, self.auditor, self.employee):
            self.assertEqual(self.client.delete(path, headers=headers).status_code, 403)
        self.assertEqual(self.client.delete(path).status_code, 401)
        self.assertEqual(self.client.get(path, headers=self.admin).status_code, 200)

    # ---- audit trail ----
    def test_actions_are_audit_logged(self):
        threat = self.add()
        path = f"/threats/{threat['threat_id']}"
        self.client.put(path, headers=self.admin, json={"source": "x"})
        self.client.delete(path, headers=self.employee)
        self.client.delete(path, headers=self.admin)
        logs = fetch_all("SELECT action, severity_level FROM logs "
                         "WHERE related_service = 'threats'")
        actions = [(log["action"], log["severity_level"]) for log in logs]
        self.assertIn(("Threat added", "Information"), actions)
        self.assertIn(("Threat updated", "Information"), actions)
        self.assertIn(("Threat deleted", "Warning"), actions)
        self.assertIn(("Unauthorized access attempt", "Warning"), actions)


if __name__ == "__main__":
    unittest.main()
