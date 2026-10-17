"""Run the Service 5 Postman requests against the real apps and check what they promise.

Every request in the collection is sent in order. The expected status is read from
the request's own test script, so the collection and the API cannot drift apart.
"""

import json
import re
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import parse_qsl, urlsplit

from api_test_case import ApiTestCase
from database.init_db import ADMIN_PASSWORD
from log_service.app import app as logs_app

COLLECTION = Path(__file__).resolve().parents[1] / "postman" / "Security Incident System.postman_collection.json"
FOLDER = "Service 5 – Security Audit Logging"
PASSWORD = "TemporaryFixture435!"


def requests_in(node):
    for item in node["item"]:
        if "item" in item:
            yield from requests_in(item)
        else:
            yield item


class LogPostmanTests(ApiTestCase):
    def setUp(self):
        super().setUp()
        collection = json.loads(COLLECTION.read_text(encoding="utf-8"))
        self.folder = next(i for i in collection["item"] if i["name"] == FOLDER)
        self.variables = {v["key"]: v.get("value", "") for v in collection["variable"]}
        self.variables.update(
            adminPassword=ADMIN_PASSWORD, analystUsername="analyst", analystPassword=PASSWORD,
            auditorUsername="auditor", auditorPassword=PASSWORD,
            recipientUsername="reporter", recipientPassword=PASSWORD,
            baseURL="http://users", logsURL="http://logs")
        self.apps = {"users": self.users, "logs": logs_app.test_client()}

    def substitute(self, text):
        return re.sub(r"\{\{([^{}]+)\}\}", lambda m: str(self.variables[m[1]]), text)

    def run_script(self, item, kind):
        """Do what the Postman scripts do to variables (only the parts we rely on)."""
        for event in item.get("event", []):
            if event["listen"] == kind == "prerequest":
                code = "\n".join(event["script"]["exec"])
                if "emptyLogUsername" in code:
                    self.variables["emptyLogUsername"] = "logs_empty_test"
                if "todayDate" in code:
                    self.variables["todayDate"] = datetime.now(timezone.utc).date().isoformat()

    def store(self, item, data):
        code = "\n".join(next(e for e in item["event"] if e["listen"] == "test")["script"]["exec"])
        for name, expression in re.findall(r'collectionVariables\.set\("(\w+)", (.+?)\);', code):
            if expression.startswith("pm.response.json().data."):
                value = data
                for part in expression.removeprefix("pm.response.json().data.").split("."):
                    value = value[part]
            else:
                # result.token, result.user.user_id, log.log_id
                value = data
                for part in expression.split(".")[1:]:
                    value = value[part]
            self.variables[name] = value

    def test_every_request_gets_the_status_its_test_expects(self):
        seen = set()
        count = 0
        for item in requests_in(self.folder):
            with self.subTest(request=item["name"]):
                self.run_script(item, "prerequest")
                request = item["request"]
                self.assertTrue(request["description"].strip())
                url = urlsplit(self.substitute(request["url"]["raw"]))
                client = self.apps[url.hostname]
                headers = {}
                if "auth" in request:
                    headers["Authorization"] = "Bearer " + self.substitute(
                        request["auth"]["bearer"][0]["value"])
                kwargs = {}
                if "body" in request:
                    kwargs = {"data": self.substitute(request["body"]["raw"]),
                              "content_type": "application/json"}
                response = client.open(url.path, method=request["method"], headers=headers,
                                       query_string=parse_qsl(url.query), **kwargs)
                script = "\n".join(next(e for e in item["event"] if e["listen"] == "test")["script"]["exec"])
                expected = int(re.search(r"Status code is (\d+)", script)[1])
                self.assertEqual(response.status_code, expected, response.get_json())
                if response.status_code < 300:
                    self.store(item, response.get_json()["data"])
                if url.hostname == "logs":
                    rule, _ = logs_app.url_map.bind("localhost").match(
                        url.path, method=request["method"]) if expected != 405 else (None, None)
                    seen.add((request["method"], rule))
                count += 1
        self.assertGreaterEqual(count, 80)
        implemented = {(method, rule.endpoint) for rule in logs_app.url_map.iter_rules()
                       if rule.endpoint != "static" for method in rule.methods - {"HEAD", "OPTIONS"}}
        self.assertEqual(seen - {("PUT", None), ("DELETE", None)}, implemented)

    def test_collection_has_the_variables_it_uses(self):
        text = json.dumps(self.folder, ensure_ascii=False)
        used = set(re.findall(r"\{\{([^{}$]+)\}\}", text))
        defined = {"logsURL", "logId", "deleteLogId", "adminUserId", "analystUserId",
                   "auditorUserId", "employeeUserId", "emptyLogUserId", "emptyLogUsername",
                   "todayDate", "baseURL", "invalidToken", "adminToken", "analystToken",
                   "auditorToken", "employeeToken", "adminPassword", "analystPassword",
                   "auditorPassword", "recipientPassword", "analystUsername",
                   "auditorUsername", "recipientUsername"}
        collection = json.loads(COLLECTION.read_text(encoding="utf-8"))
        in_collection = {v["key"] for v in collection["variable"]}
        self.assertEqual(used - defined, set())
        self.assertEqual(used - in_collection, set())

    def test_routes_use_the_student_name_and_each_request_is_described(self):
        for item in requests_in(self.folder):
            request = item["request"]
            raw = request["url"]["raw"]
            self.assertTrue("/leen-abdallah/logs" in raw or "/users/" in raw, raw)
            self.assertIn("Implemented by: Leen Abdallah", request["description"])

    def test_collection_is_one_valid_json_document_with_unique_folder_names(self):
        collection = json.loads(COLLECTION.read_text(encoding="utf-8"))
        names = [item["name"] for item in collection["item"]]
        self.assertEqual(len(names), len(set(names)))
        for expected in ("Service 4 – Threat Intelligence", FOLDER,
                         "Service 6 – Security Reports", "Service 3 - Incident Management"):
            self.assertIn(expected, names)
        self.assertEqual(COLLECTION.read_text(encoding="utf-8").count('"variable"'), 1)
