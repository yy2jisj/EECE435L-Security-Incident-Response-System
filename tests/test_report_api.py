"""Report service: data is collected from the other services over HTTP."""

import os
import threading
from unittest.mock import patch

from werkzeug.serving import make_server

from api_test_case import ApiTestCase, QuietHandler
from asset_service.app import app as assets_app
from common.db import execute, fetch_one
from incident_service.app import app as incidents_app
from report_service.app import app
from threat_service.app import app as threats_app
from user_service.app import app as users_app

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
        """Run the four source services over real loopback HTTP."""
        urls = {}
        for name, application in (("USERS", users_app), ("ASSETS", assets_app),
                                  ("INCIDENTS", incidents_app), ("THREATS", threats_app)):
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
        response = assets_app.test_client().post("/assets", headers=self.admin, json={
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

    # ---- reports built from tables (services not available yet) ----
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

    def test_activity_report_matches_the_logs(self):
        self.users.post("/users/login", json={"username": "admin", "password": "wrong"})
        data = self.data("activity")
        stored = fetch_one("SELECT COUNT(*) AS total FROM logs")["total"]
        failed = fetch_one(
            "SELECT COUNT(*) AS total FROM logs WHERE action = 'Failed login'")["total"]
        self.assertEqual(data["total_activities"], stored)
        self.assertEqual(data["failed_logins"], failed)
        self.assertGreaterEqual(failed, 1)
        self.assertEqual(data["login_attempts"],
                         data["successful_logins"] + data["failed_logins"])
        totals = [action["total"] for action in data["most_performed_actions"]]
        self.assertEqual(totals, sorted(totals, reverse=True))

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
