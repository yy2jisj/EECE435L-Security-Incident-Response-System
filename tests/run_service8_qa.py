"""Run real HTTP scenarios and save request/response plus SQLite evidence outside Git.

Usage: python -m tests.run_service8_qa --output C:\path\outside\repository
Add --keep-running to leave both services available for Postman.
"""

import argparse
import csv
import json
import os
from pathlib import Path
import secrets
import sqlite3
import subprocess
import sys
import time

import requests

ROOT = Path(__file__).resolve().parents[1]


class LiveQA:
    def __init__(self, output):
        self.output = output
        self.database = output / "service8-live.db"
        if self.database.exists():
            raise RuntimeError("Use a new output folder: this runner never overwrites an existing database")
        self.env = dict(os.environ, DB_PATH=str(self.database), SECRET_KEY=secrets.token_hex(32),
                        ADMIN_PASSWORD="Qa435L!" + secrets.token_hex(10))
        self.processes = []
        self.handles = []
        self.records = []
        self.tokens = {}
        self.people = {}
        self.passwords = {}

    def start(self):
        for module, port in (("user_service.app", 5001), ("notification_service.app", 5008)):
            handle = open(self.output / f"{module}.log", "a", encoding="utf-8")
            self.handles.append(handle)
            process = subprocess.Popen([sys.executable, "-m", module], cwd=ROOT, env=self.env,
                                       stdout=handle, stderr=handle,
                                       creationflags=getattr(subprocess, "CREATE_NO_WINDOW", 0))
            self.processes.append(process)
            for attempt in range(50):
                if process.poll() is not None:
                    raise RuntimeError(f"{module} could not start; check its log")
                try:
                    response = requests.get(f"http://127.0.0.1:{port}/", timeout=0.3)
                    if response.status_code == 404:
                        break
                except requests.RequestException:
                    time.sleep(0.1)
            else:
                raise RuntimeError(f"{module} did not become ready")

    def stop(self):
        for process in self.processes:
            process.terminate()
            process.wait(timeout=10)
        self.processes.clear()
        for handle in self.handles:
            handle.close()
        self.handles.clear()

    def rows(self):
        with sqlite3.connect(self.database) as conn:
            conn.row_factory = sqlite3.Row
            return [dict(row) for row in conn.execute("SELECT * FROM notifications ORDER BY notification_id")]

    def call(self, test_id, method, path, expected, role="admin", body=None, change="unchanged",
             check=None, expected_response="Project JSON response with expected status", raw=None):
        before = self.rows()
        headers = {} if role == "none" else {"Authorization": "Bearer " + self.tokens.get(role, "invalid")}
        kwargs = {"json": body} if body is not None else {}
        if raw is not None:
            kwargs = {"data": raw, "headers": dict(headers, **{"Content-Type": "application/json"})}
        else:
            kwargs["headers"] = headers
        response = requests.request(method, "http://127.0.0.1:5008" + path, timeout=5, **kwargs)
        data = response.json()
        after = self.rows()
        db_ok = {"unchanged": before == after, "insert": len(after) == len(before) + 1,
                 "delete": len(after) == len(before) - 1, "read": len(before) == len(after)}[change]
        if change == "read":
            target = int(path.split("/")[2])
            old = next(row for row in before if row["notification_id"] == target)
            new = next(row for row in after if row["notification_id"] == target)
            db_ok = db_ok and new["is_read"] == 1 and new["read_date"] is not None
            db_ok = db_ok and old["created_at"] == new["created_at"]
        passed = response.status_code == expected and db_ok
        passed = passed and data.get("status") == ("error" if expected >= 400 else "success")
        if check is not None:
            passed = passed and bool(check(data))
        record = {"test_id": test_id, "endpoint": f"{method} {path}", "role": role,
                  "scenario": expected_response, "precondition": "Service 1 login; database_before below",
                  "input": body if raw is None else raw, "expected_http_status": expected,
                  "expected_response": expected_response, "actual_http_status": response.status_code,
                  "response": data, "expected_database_change": change,
                  "database_before": before, "database_after": after,
                  "actual_result": "PASS" if passed else "FAIL"}
        self.records.append(record)
        print(f"{test_id}: expected {expected}, actual {response.status_code}, DB {change}: {record['actual_result']}")
        return data.get("data")

    def setup_people(self):
        response = requests.post("http://127.0.0.1:5001/users/login", json={
            "username": "admin", "password": self.env["ADMIN_PASSWORD"]}, timeout=5)
        assert response.status_code == 200
        self.tokens["admin"] = response.json()["data"]["token"]
        self.people["admin"] = response.json()["data"]["user"]
        for role, stored in (("employee", "Regular User"), ("other", "Regular User"),
                             ("analyst", "Security Analyst"), ("auditor", "Auditor")):
            self.passwords[role] = "Qa435L!" + secrets.token_hex(8)
            response = requests.post("http://127.0.0.1:5001/users/register",
                headers={"Authorization": "Bearer " + self.tokens["admin"]}, json={
                    "full_name": f"Service 8 QA {role}", "username": f"s8_{role}",
                    "email": f"s8_{role}@example.com", "password": self.passwords[role],
                    "department": "Security QA", "role": stored}, timeout=5)
            assert response.status_code == 201, response.text
            self.people[role] = response.json()["data"]
            login = requests.post("http://127.0.0.1:5001/users/login", json={
                "username": f"s8_{role}", "password": self.passwords[role]}, timeout=5)
            assert login.status_code == 200
            self.tokens[role] = login.json()["data"]["token"]

    def run(self):
        payload = {"user_id": self.people["employee"]["user_id"], "title": "Security Alert",
                   "message": "Suspicious activity detected on the QA workstation.",
                   "notification_type": "Security Alert", "severity_level": "High"}
        create = lambda ident, **changes: self.call(ident, "POST", "/notifications", 201,
            body=dict(payload, **changes), change="insert", expected_response="One persisted Unread notification",
            check=lambda d: d["data"]["status"] == "Unread" and d["data"]["read_date"] is None)
        first = create("S8-CREATE-01")
        create("S8-CREATE-02", notification_type="System Notification", severity_level="Low")
        self.call("S8-CREATE-03", "POST", "/notifications", 400, expected_response="Missing JSON body rejected")
        for ident, field in ((4, "user_id"), (6, "title"), (7, "message"),
                             (8, "notification_type"), (10, "severity_level")):
            body = dict(payload)
            del body[field]
            self.call(f"S8-CREATE-{ident:02}", "POST", "/notifications", 400, body=body,
                      expected_response=f"Missing {field} rejected")
        for ident, changes, expected in ((5, {"user_id": 99999}, 404),
                                         (9, {"notification_type": "Random Message"}, 400),
                                         (11, {"severity_level": "Urgent"}, 400)):
            self.call(f"S8-CREATE-{ident:02}", "POST", "/notifications", expected,
                      body=dict(payload, **changes), expected_response="Invalid input rejected without insert")
        for ident, role, expected in ((12, "none", 401), (13, "employee", 403)):
            self.call(f"S8-CREATE-{ident:02}", "POST", "/notifications", expected, role=role, body=payload,
                      expected_response="Unauthorized creation rejected")
        nid = first["notification_id"]
        uid = first["user_id"]
        self.call("S8-CREATE-14", "GET", f"/notifications/{nid}", 200,
                  check=lambda d: d["data"] == first, expected_response="Inserted data persisted exactly")
        for ident, role, target, expected, count in ((1,"admin",uid,200,2),(2,"admin",uid,200,2),
                (3,"admin",self.people["other"]["user_id"],200,0),(4,"admin",99999,404,None),
                (5,"employee",uid,200,2),(6,"other",uid,403,None),
                (7,"analyst",self.people["analyst"]["user_id"],200,0),(8,"auditor",uid,200,2)):
            self.call(f"S8-USER-{ident:02}", "GET", f"/notifications/user/{target}", expected, role=role,
                      check=(lambda d, n=count: len(d["data"]) == n) if count is not None else None,
                      expected_response=f"Recipient history; expected count {count}" if count is not None else "Access/error response")
        for ident, target, role, expected in ((1,nid,"admin",200),(2,99999,"admin",404),
                                             (3,nid,"none",401),(4,nid,"other",403)):
            self.call(f"S8-GET-{ident:02}", "GET", f"/notifications/{target}", expected, role=role,
                      expected_response="Specific notification or appropriate access/not-found error")
        read_path = f"/notifications/{nid}/read"
        for ident in (1, 2, 3, 4):
            self.call(f"S8-READ-{ident:02}", "PUT", read_path, 200, role="employee",
                      change="read" if ident == 1 else "unchanged",
                      check=lambda d: d["data"]["status"] == "Read" and bool(d["data"]["read_date"])
                                      and d["data"]["created_at"] == first["created_at"],
                      expected_response="Read persisted, timestamp present, creation date preserved")
        for ident, target, role, expected in ((5,99999,"admin",404),(6,nid,"none",401),(7,nid,"other",403)):
            self.call(f"S8-READ-{ident:02}", "PUT", f"/notifications/{target}/read", expected, role=role,
                      expected_response="Invalid/unauthorized read does not mutate")
        time.sleep(1.05)
        self.call("S8-READ-08", "PUT", read_path, 200, role="employee",
                  expected_response="Already-read request preserves first read timestamp")
        analyst_id = self.people["analyst"]["user_id"]
        create("S8-DATA-01", user_id=analyst_id, notification_type="Threat Alert", severity_level="Critical")
        analyst_security = create("S8-DATA-02", user_id=analyst_id, severity_level="Medium")
        create("S8-DATA-03", user_id=self.people["other"]["user_id"],
               notification_type="Vulnerability Alert", severity_level="High")
        create("S8-DATA-04", user_id=analyst_id, notification_type="Incident Assignment", severity_level="High")
        self.call("S8-DATA-05", "PUT", f"/notifications/{analyst_security['notification_id']}/read",
                  200, role="analyst", change="read", expected_response="Analyst reads assigned notification")
        queries = [("user_id="+str(uid),2), ("notification_type=Security%20Alert",2),
                   ("severity_level=High",3), ("status=Unread",4),
                   ("notification_type=Security%20Alert&status=Read",2),
                   ("notification_type=Security%20Alert&severity_level=Low",0)]
        for ident, (query, count) in enumerate(queries, 1):
            self.call(f"S8-SEARCH-{ident:02}", "GET", "/notifications/search?"+query, 200,
                      check=lambda d, n=count: len(d["data"]) == n,
                      expected_response=f"Filtered SQL result contains {count} matching rows")
        self.call("S8-SEARCH-07", "GET", "/notifications/search?status=Seen", 400,
                  expected_response="Unsupported status rejected")
        for ident, role, expected, count in ((8,"admin",200,4),(9,"analyst",200,2),
                                             (10,"auditor",200,4),(11,"employee",403,None)):
            self.call(f"S8-SEARCH-{ident:02}", "GET", "/notifications/search?status=Unread", expected,
                      role=role, check=(lambda d, n=count: len(d["data"]) == n) if count is not None else None,
                      expected_response=f"Search permission and scope for {role}")
        self.stop()
        self.start()
        self.call("S8-RESTART-01", "GET", f"/notifications/{nid}", 200, role="employee",
                  check=lambda d: d["data"]["status"] == "Read" and bool(d["data"]["read_date"]),
                  expected_response="Read status and date survive both service restarts")
        for ident, role in ((4,"analyst"),(5,"employee"),(6,"auditor")):
            self.call(f"S8-DELETE-{ident:02}", "DELETE", f"/notifications/{nid}", 403, role=role,
                      expected_response="Non-administrator deletion rejected; row remains")
        self.call("S8-DELETE-01", "DELETE", f"/notifications/{nid}", 200, change="delete",
                  expected_response="Admin deletes exactly one notification")
        self.call("S8-DELETE-02", "GET", f"/notifications/{nid}", 404,
                  expected_response="Deleted row absent from DB and retrieval")
        self.call("S8-DELETE-03", "DELETE", f"/notifications/{nid}", 404,
                  expected_response="Deleting absent notification returns 404")
        for ident, path, expected in ((1,"/notifications/abc",400), (2,"/notifications/9223372036854775808",400),
                (3,"/notifications/search?severity_level=Urgent",400),
                (4,"/notifications/search?user_id=99999",404),
                (5,"/notifications/search?notification_type=Other",400),
                (6,"/notifications/search?status=Read&status=Unread",400)):
            self.call(f"S8-EXTRA-{ident:02}", "GET", path, expected, expected_response="Malformed input rejected")
        self.call("S8-EXTRA-07", "POST", "/notifications", 400, raw="{",
                  expected_response="Malformed JSON rejected")
        self.call("S8-EXTRA-08", "GET", "/notifications/search?status=Unread", 401, role="invalid",
                  expected_response="Invalid bearer token rejected")

    def save(self):
        (self.output / "http-results.json").write_text(json.dumps(self.records, indent=2), encoding="utf-8")
        columns = ["test_id", "endpoint", "scenario", "precondition", "input", "expected_http_status",
                   "expected_response", "expected_database_change", "actual_http_status", "actual_result"]
        with open(self.output / "qa-matrix.csv", "w", newline="", encoding="utf-8") as handle:
            writer = csv.DictWriter(handle, fieldnames=columns, extrasaction="ignore")
            writer.writeheader()
            writer.writerows(self.records)
        variables = {"baseURL": "http://127.0.0.1:5001", "notificationURL": "http://127.0.0.1:5008",
                     "adminPassword": self.env["ADMIN_PASSWORD"], "recipientPassword": self.passwords.get("employee", ""),
                     "recipientUsername": "s8_employee", "recipientId": self.people.get("employee", {}).get("user_id", ""),
                     "emptyUserId": self.people.get("auditor", {}).get("user_id", ""),
                     "analystUsername": "s8_analyst", "analystPassword": self.passwords.get("analyst", ""),
                     "auditorUsername": "s8_auditor", "auditorPassword": self.passwords.get("auditor", "")}
        for role, token in self.tokens.items():
            variables[role + "Token"] = token
        environment = {"name": "Service 8 local QA (private, do not commit)",
                       "values": [{"key": k, "value": str(v), "enabled": True,
                                   "type": "secret" if "Password" in k or "Token" in k else "default"}
                                  for k, v in variables.items()]}
        (self.output / "local.postman_environment.json").write_text(json.dumps(environment, indent=2), encoding="utf-8")
        with sqlite3.connect(self.database) as conn:
            structure = {"columns": conn.execute("PRAGMA table_info(notifications)").fetchall(),
                         "foreign_keys": conn.execute("PRAGMA foreign_key_list(notifications)").fetchall(),
                         "foreign_key_check": conn.execute("PRAGMA foreign_key_check").fetchall(),
                         "integrity_check": conn.execute("PRAGMA integrity_check").fetchall()}
        (self.output / "database-verification.json").write_text(json.dumps(structure, indent=2), encoding="utf-8")
        summary = {"total": len(self.records), "passed": sum(r["actual_result"] == "PASS" for r in self.records),
                   "failed": sum(r["actual_result"] == "FAIL" for r in self.records), "skipped": 0,
                   "process_ids": [p.pid for p in self.processes]}
        (self.output / "summary.json").write_text(json.dumps(summary, indent=2), encoding="utf-8")
        print(json.dumps(summary))
        return summary


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    parser.add_argument("--keep-running", action="store_true")
    args = parser.parse_args()
    output = args.output.resolve()
    if output == ROOT or ROOT in output.parents:
        parser.error("Evidence must be outside the Git repository")
    output.mkdir(parents=True, exist_ok=True)
    qa = LiveQA(output)
    try:
        subprocess.run([sys.executable, "-m", "database.init_db"], cwd=ROOT, env=qa.env, check=True)
        qa.start()
        qa.setup_people()
        qa.run()
    finally:
        summary = qa.save()
        if not args.keep_running or summary["failed"]:
            qa.stop()
    if summary["failed"]:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
