"""Execute the new collection definitions and check implemented API coverage."""

import json
import re
from pathlib import Path
from urllib.parse import urlsplit

from api_test_case import ApiTestCase
from incident_service.app import app as incidents_app
from notification_service.app import app as notifications_app
from playbook_service.app import app as playbooks_app

COLLECTION = Path(__file__).resolve().parents[1] / "postman" / "Security Incident System.postman_collection.json"


class PostmanCollectionTests(ApiTestCase):
    def test_all_new_requests_execute_and_cover_every_implemented_api(self):
        collection = json.loads(COLLECTION.read_text(encoding="utf-8"))
        folders = collection["item"][2:]
        self.assertEqual([folder["name"] for folder in folders], [
            "Service 3 - Incident Management", "Service 8 - Notification Service",
            "Service 9 - Security Playbooks and Response Automation",
        ])
        variables = {item["key"]: item.get("value", "") for item in collection["variable"]}
        for key in ("admin_token", "analyst_token", "reporter_token", "auditor_token",
                    "reporter_id", "analyst_id", "asset_id", "incident_id",
                    "notification_id", "playbook_id", "action_id"):
            self.assertEqual(variables[key], "", key)
        variables.update(reporter_id=self.reporter_id, analyst_id=self.analyst_id, asset_id=self.create_asset())
        for role in ("admin", "analyst", "reporter", "auditor"):
            variables[role + "_token"] = getattr(self, role)["Authorization"].removeprefix("Bearer ")
        self.serve_users()

        def substitute(value):
            return re.sub(r"\{\{([^{}]+)\}\}", lambda m: str(variables[m[1]]), value)

        for folder, application in zip(folders, (incidents_app, notifications_app, playbooks_app)):
            client = application.test_client()
            seen = set()
            self.assertEqual(len(folder["item"]), 6)
            for item in folder["item"]:
                with self.subTest(request=item["name"]):
                    request = item["request"]
                    self.assertTrue(request["description"].strip())
                    url = urlsplit(substitute(request["url"]))
                    self.assertTrue(url.path.startswith("/Youssef-Al-Hajj-Youness/"))
                    method = request["method"]
                    adapter = application.url_map.bind("localhost")
                    endpoint, _ = adapter.match(url.path, method=method)
                    seen.add((method, endpoint))
                    auth = request["auth"]
                    self.assertEqual(auth["type"], "bearer")
                    headers = {h["key"]: substitute(h["value"]) for h in request["header"]}
                    headers["Authorization"] = "Bearer " + substitute(auth["bearer"][0]["value"])
                    body = json.loads(substitute(request["body"]["raw"])) if "body" in request else None
                    response = client.open(url.path + ("?" + url.query if url.query else ""),
                                           method=method, headers=headers, json=body)
                    self.assertEqual(response.status_code, 201 if method == "POST" else 200,
                                     response.get_json())
                    self.assertEqual(response.get_json()["status"], "success")
                    data = response.get_json()["data"]
                    if method == "POST":
                        for key in ("incident_id", "notification_id", "playbook_id", "action_id"):
                            if key in data:
                                variables[key] = data[key]
            implemented = {(method, rule.endpoint) for rule in application.url_map.iter_rules()
                           if rule.endpoint != "static" for method in rule.methods - {"HEAD", "OPTIONS"}}
            self.assertEqual(seen, implemented)

    def test_notification_legacy_routes_are_not_registered(self):
        rules = [rule.rule for rule in notifications_app.url_map.iter_rules() if rule.endpoint != "static"]
        self.assertEqual(len(rules), 6)
        self.assertTrue(all(rule.startswith("/Youssef-Al-Hajj-Youness/notifications") for rule in rules))
        self.assertEqual(notifications_app.test_client().get("/notifications", headers=self.admin).status_code, 404)
