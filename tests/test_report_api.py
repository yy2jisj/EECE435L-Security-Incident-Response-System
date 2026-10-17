"""Report service: data is collected from the other services over HTTP."""

import os
import threading
from unittest.mock import patch

from werkzeug.serving import make_server

from api_test_case import ApiTestCase, QuietHandler
from asset_service.app import app as assets_app
from common.db import execute, fetch_all, fetch_one
from incident_service.app import app as incidents_app
from log_service.app import app as logs_app
from report_service.app import app
from threat_service.app import app as threats_app
from user_service.app import app as users_app
from vulnerability_service.app import app as vulnerabilities_app

ROOT = "/leen-abdallah/reports"
INCIDENTS = "/Youssef-Al-Hajj-Youness/incidents"
THREATS = "/leen-abdallah/threats"


class ReportApiTests(ApiTestCase):
    def setUp(self):
        super().setUp()
        self.client = app.test_client()
        self.serve_all()
        self.add_assets()
        self.add_incidents()
        self.add_threats()
        self.add_vulnerabilities()

    # ---- fixtures ----
    def serve_all(self):
        """Run the six source services over real loopback HTTP."""
        urls = {}
        for name, application in (("USERS", users_app), ("ASSETS", assets_app),
                                  ("INCIDENTS", incidents_app), ("THREATS", threats_app),
                                  ("VULNERABILITIES", vulnerabilities_app),
                                  ("LOGS", logs_app)):
            server = make_server("127.0.0.1", 0, application, threaded=True,
                                 request_handler=QuietHandler)
            thread = threading.Thread(target=server.serve_forever, daemon=True)
            thread.start()
            self.addCleanup(lambda s=server, t=thread: (s.shutdown(), s.server_close(), t.join(5)))
            urls[name + "_SERVICE_URL"] = f"http://127.0.0.1:{server.server_port}"
        setting = patch.dict(os.environ, urls)
        setting.start()
        self.addCleanup(setting.stop)

    def add_assets(self):
        self.create_asset()                       # a High criticality Server
        response = assets_app.test_client().post("/assets/AdamYahya", headers=self.admin, json={
            "asset_name": "Core DB", "asset_type": "Database", "ip_address": "192.0.2.20",
            "department": "Security", "owner_id": self.reporter_id,
            "criticality_level": "Critical"})
        self.assertEqual(response.status_code, 201, response.get_json())

    def add_incidents(self):
        client = incidents_app.test_client()
        for severity in ("High", "Critical", "Low"):
            response = client.post(INCIDENTS, headers=self.reporter, json={
                "title": f"{severity} incident", "description": "Something happened.",
                "category": "Malware", "severity_level": severity,
                "reporter_id": self.reporter_id, "asset_id": 1})
            self.assertEqual(response.status_code, 201, response.get_json())
        execute("UPDATE incidents SET status = 'Closed' WHERE incident_id = 3")

    def add_threats(self):
        client = threats_app.test_client()
        for threat_type, value, severity, source in (
                ("IP Address", "192.0.2.50", "Critical", "AbuseIPDB"),
                ("Domain", "evil.example.com", "High", "OSINT feed"),
                ("File Hash", "d41d8cd98f00b204e9800998ecf8427e", "Low", "VirusTotal")):
            response = client.post(THREATS, headers=self.admin, json={
                "threat_type": threat_type, "threat_value": value, "description": "d",
                "severity_level": severity, "source": source})
            self.assertEqual(response.status_code, 201, response.get_json())

    def add_vulnerabilities(self):
        for index, (severity, status, score) in enumerate(
                (("Critical", "Open", 9.8), ("Critical", "Closed", 9.1), ("High", "Open", 7.5))):
            execute(
                "INSERT INTO vulnerabilities (title, description, cve_id, cvss_score, "
                "severity_level, asset_id, discovery_source, status) "
                "VALUES (?, ?, ?, ?, ?, 1, 'scan', ?)",
                (f"vuln {index}", "d", f"CVE-2026-{index}", score, severity, status))

    def report(self, name, headers=None):
        return self.client.get(f"{ROOT}/{name}", headers=headers or self.admin)

    def data(self, name):
        response = self.report(name)
        self.assertEqual(response.status_code, 200, response.get_json())
        return response.get_json()["data"]

    # ---- reports built from the other services ----
    def test_summary_collects_from_services(self):
        data = self.data("summary")
        self.assertEqual(data["users"], 4)
        self.assertEqual(data["assets"], 2)
        self.assertEqual(data["total_incidents"], 3)
        self.assertEqual(data["open_incidents"], 2)
        self.assertEqual(data["total_threats"], 3)
        self.assertEqual(data["critical_threats"], 1)

    def test_incident_report(self):
        data = self.data("incidents")
        self.assertEqual(data["total_incidents"], 3)
        self.assertEqual(data["open_incidents"], 2)
        self.assertEqual(data["incidents_by_severity"],
                         {"Low": 1, "Medium": 0, "High": 1, "Critical": 1})
        self.assertEqual(data["incidents_by_status"],
                         {"Open": 2, "Under Investigation": 0, "Mitigated": 0,
                          "Resolved": 0, "Closed": 1})

    def test_asset_report(self):
        data = self.data("assets")
        self.assertEqual(data["total_assets"], 2)
        self.assertEqual(data["critical_assets"], 1)
        self.assertEqual(data["assets_by_type"]["Server"], 1)
        self.assertEqual(data["assets_by_type"]["Database"], 1)
        self.assertEqual(sum(data["assets_by_type"].values()), 2)
        self.assertEqual(data["assets_by_criticality"],
                         {"Low": 0, "Medium": 0, "High": 1, "Critical": 1})

    def test_threat_report(self):
        data = self.data("threats")
        self.assertEqual(data["total_threats"], 3)
        self.assertEqual(data["critical_threats"], 1)
        self.assertEqual(data["threats_by_severity"],
                         {"Low": 1, "Medium": 0, "High": 1, "Critical": 1})
        self.assertEqual(data["threats_by_type"],
                         {"IP Address": 1, "Domain": 1, "File Hash": 1,
                          "Malware Signature": 0, "Other": 0})
        # newest first (all added today, so the highest id comes first)
        self.assertEqual([t["threat_id"] for t in data["recent_threats"]], [3, 2, 1])
        self.assertEqual(data["recent_threats"][0]["threat_value"],
                         "d41d8cd98f00b204e9800998ecf8427e")

    def test_recent_threats_are_limited_to_five(self):
        client = threats_app.test_client()
        for number in range(5):
            client.post(THREATS, headers=self.admin, json={
                "threat_type": "Other", "threat_value": f"indicator-{number}",
                "description": "d", "severity_level": "Low", "source": "s"})
        data = self.data("threats")
        self.assertEqual(data["total_threats"], 8)
        self.assertEqual(len(data["recent_threats"]), 5)

    def test_reports_match_the_database(self):
        summary = self.data("summary")
        for field, table in (("users", "users"), ("assets", "assets"),
                             ("total_incidents", "incidents"), ("total_threats", "threats")):
            stored = fetch_one(f"SELECT COUNT(*) AS total FROM {table}")["total"]
            self.assertEqual(summary[field], stored, field)

    # ---- vulnerability and activity reports (also collected from their services) ----
    def test_vulnerability_report(self):
        data = self.data("vulnerabilities")
        self.assertEqual(data["total_vulnerabilities"], 3)
        self.assertEqual(data["critical_vulnerabilities"], 2)
        self.assertEqual(data["vulnerabilities_by_severity"],
                         {"Low": 0, "Medium": 0, "High": 1, "Critical": 2})
        self.assertEqual(data["vulnerabilities_by_status"]["Open"], 2)
        self.assertEqual(data["vulnerabilities_by_status"]["Closed"], 1)
        self.assertEqual([v["cvss_score"] for v in data["top_critical_vulnerabilities"]],
                         [9.8, 9.1])

    def test_vulnerability_report_matches_the_database(self):
        data = self.data("vulnerabilities")
        for field, query in (
                ("total_vulnerabilities", "SELECT COUNT(*) AS total FROM vulnerabilities"),
                ("critical_vulnerabilities", "SELECT COUNT(*) AS total FROM vulnerabilities "
                                             "WHERE severity_level = 'Critical'")):
            self.assertEqual(data[field], fetch_one(query)["total"], field)
        self.assertEqual(sum(data["vulnerabilities_by_severity"].values()), 3)
        self.assertEqual(sum(data["vulnerabilities_by_status"].values()), 3)
        self.assertEqual(data["top_critical_vulnerabilities"][0]["cve_id"], "CVE-2026-0")
        self.assertEqual(set(data["top_critical_vulnerabilities"][0]),
                         {"vulnerability_id", "title", "cve_id", "cvss_score", "status",
                          "asset_id"})

    def test_activity_report_matches_the_logs(self):
        self.users.post("/users/login/AdamYahya", json={"username": "admin", "password": "wrong"})
        data = self.data("activity")
        stored = fetch_one("SELECT COUNT(*) AS total FROM logs")["total"]
        failed = fetch_one(
            "SELECT COUNT(*) AS total FROM logs WHERE action = 'Failed login'")["total"]
        successful = fetch_one(
            "SELECT COUNT(*) AS total FROM logs WHERE action = 'Successful login'")["total"]
        self.assertEqual(data["total_activities"], stored)
        self.assertEqual(data["failed_logins"], failed)
        self.assertEqual(data["successful_logins"], successful)
        self.assertGreaterEqual(failed, 1)
        self.assertEqual(data["login_attempts"],
                         data["successful_logins"] + data["failed_logins"])
        totals = [action["total"] for action in data["most_performed_actions"]]
        self.assertEqual(totals, sorted(totals, reverse=True))

    def test_most_performed_actions_match_a_database_count(self):
        data = self.data("activity")
        rows = fetch_all("SELECT action, COUNT(*) AS total FROM logs "
                         "GROUP BY action ORDER BY total DESC, action LIMIT 5")
        self.assertEqual(data["most_performed_actions"], rows)
        self.assertLessEqual(len(data["most_performed_actions"]), 5)

    def test_recent_activities_are_the_newest_logs_first(self):
        data = self.data("activity")
        newest = fetch_all("SELECT log_id FROM logs ORDER BY log_id DESC LIMIT 5")
        self.assertEqual([a["log_id"] for a in data["recent_activities"]],
                         [row["log_id"] for row in newest])
        self.assertEqual(set(data["recent_activities"][0]),
                         {"log_id", "user_id", "action", "severity_level",
                          "related_service", "timestamp"})

    def test_new_logs_appear_in_the_activity_report(self):
        before = self.data("activity")["total_activities"]
        response = logs_app.test_client().post("/leen-abdallah/logs", headers=self.admin, json={
            "user_id": self.analyst_id, "action": "Custom audit event",
            "description": "created for the report test", "severity_level": "Warning",
            "related_service": "reports"})
        self.assertEqual(response.status_code, 201)
        data = self.data("activity")
        self.assertEqual(data["total_activities"], before + 1)
        self.assertEqual(data["recent_activities"][0]["action"], "Custom audit event")

    def test_deleted_logs_leave_the_activity_report(self):
        before = self.data("activity")["total_activities"]
        logs_app.test_client().delete("/leen-abdallah/logs/1", headers=self.admin)
        # one log removed, one "Log deleted" log added
        self.assertEqual(self.data("activity")["total_activities"], before)

    def test_reports_work_with_no_data(self):
        for table in ("vulnerabilities", "incidents", "threats", "assets"):
            execute(f"DELETE FROM {table}")
        execute("DELETE FROM logs")
        self.assertEqual(self.data("vulnerabilities")["total_vulnerabilities"], 0)
        self.assertEqual(self.data("vulnerabilities")["top_critical_vulnerabilities"], [])
        self.assertEqual(self.data("threats")["recent_threats"], [])
        self.assertEqual(self.data("threats")["total_threats"], 0)
        self.assertEqual(self.data("incidents")["total_incidents"], 0)
        self.assertEqual(self.data("assets")["total_assets"], 0)
        activity = self.data("activity")
        self.assertEqual(activity["total_activities"], 0)
        self.assertEqual(activity["most_performed_actions"], [])
        self.assertEqual(activity["recent_activities"], [])

    def test_activity_report_is_the_same_for_admin_and_auditor(self):
        first = self.report("activity", self.admin).get_json()["data"]
        second = self.report("activity", self.auditor).get_json()["data"]
        for key in first:
            if key != "generated_at":
                self.assertEqual(first[key], second[key], key)

    # ---- access control ----
    def test_admin_and_auditor_can_generate_every_report(self):
        for name in ("summary", "incidents", "assets", "threats", "vulnerabilities", "activity"):
            for headers in (self.admin, self.auditor):
                self.assertEqual(self.report(name, headers).status_code, 200, name)

    def test_other_roles_and_anonymous_users_are_refused(self):
        for name in ("summary", "incidents", "assets", "threats", "vulnerabilities", "activity"):
            for headers in (self.analyst, self.reporter):
                self.assertEqual(self.report(name, headers).status_code, 403, name)
            self.assertEqual(self.client.get(f"{ROOT}/{name}").status_code, 401, name)

    def test_routes_live_under_the_student_name(self):
        rules = [rule.rule for rule in app.url_map.iter_rules() if rule.endpoint != "static"]
        self.assertEqual(len(rules), 6)
        self.assertTrue(all(rule.startswith(ROOT) for rule in rules))
        self.assertEqual(self.client.get("/reports/summary", headers=self.admin).status_code, 404)

    # ---- the other services are required ----
    def test_unavailable_service_gives_503(self):
        with patch.dict(os.environ, {"THREATS_SERVICE_URL": "http://127.0.0.1:1"}):
            for name in ("summary", "threats"):
                response = self.report(name)
                self.assertEqual(response.status_code, 503, name)
                self.assertIn("threats service is unavailable", response.get_json()["message"])
            # reports that do not need the threat service still work
            self.assertEqual(self.report("incidents").status_code, 200)

    def test_every_source_service_is_required(self):
        needs = {"USERS": ("summary",), "ASSETS": ("summary", "assets"),
                 "INCIDENTS": ("summary", "incidents"),
                 "VULNERABILITIES": ("vulnerabilities",), "LOGS": ("activity",)}
        for service, reports in needs.items():
            with patch.dict(os.environ, {service + "_SERVICE_URL": "http://127.0.0.1:1"}):
                for name in reports:
                    response = self.report(name)
                    self.assertEqual(response.status_code, 503, (service, name))
                    self.assertIn("service is unavailable", response.get_json()["message"])

    def test_a_suspended_auditor_cannot_generate_reports(self):
        execute("UPDATE users SET account_status = 'Suspended' WHERE user_id = ?",
                (self.auditor_id,))
        self.assertEqual(self.report("activity", self.auditor).status_code, 403)
