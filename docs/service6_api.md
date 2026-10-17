# Service 6: Security Reports

Implemented by Leen Abdallah.

Service 6 generates read-only security reports. It never changes data. Only the
Security Administrator and the Auditor can generate reports.

## Run

The report service collects its data from the other services, so those must be
running too. From the project root with the virtual environment active:

```bash
python -m database.init_db
python -m user_service.app        # 5001
python -m asset_service.app       # 5002
python -m incident_service.app    # 5003
python -m threat_service.app      # 5004
python -m log_service.app         # 5005
python -m vulnerability_service.app  # 5007
python -m report_service.app      # 5006
```

Log in with `POST http://127.0.0.1:5001/users/login/AdamYahya` and send
`Authorization: Bearer <token>`. Every route lives under `/leen-abdallah/reports`.

## Where the data comes from

| Report data | Source | How |
|---|---|---|
| Users | Service 1 | `GET /users/AdamYahya` over HTTP |
| Assets | Service 2 | `GET /assets/AdamYahya` over HTTP |
| Incidents | Service 3 | `GET /Youssef-Al-Hajj-Youness/incidents` over HTTP |
| Threats | Service 4 | `GET /leen-abdallah/threats` over HTTP |
| Vulnerabilities | Service 7 | `GET /vulnerabilities/AdamYahya` over HTTP |
| Activity | Service 5 | `GET /leen-abdallah/logs` over HTTP |

The caller's own token is forwarded to the other services, so a report only
contains what the caller is allowed to see there. The URL of each service
defaults to `http://127.0.0.1:<port>` and can be overridden with
`USERS_SERVICE_URL`, `ASSETS_SERVICE_URL`, `INCIDENTS_SERVICE_URL`,
`THREATS_SERVICE_URL`, `VULNERABILITIES_SERVICE_URL` and `LOGS_SERVICE_URL`. If a source service is down or refuses the request, the
report returns `503`. Statistics are computed from the records the services
return, and every breakdown lists all known categories (with 0 when empty), so
the shape of a report never changes. Each report includes `generated_at` (UTC).

## Responses

Success: `{"status": "success", "message": "...", "data": {...}}`.
Error: `{"status": "error", "message": "..."}`.

## Endpoints and access

| Method and path | Security Administrator | Auditor | Security Analyst | Regular User |
|---|---|---|---|---|
| GET /leen-abdallah/reports/summary | yes | yes | no | no |
| GET /leen-abdallah/reports/incidents | yes | yes | no | no |
| GET /leen-abdallah/reports/assets | yes | yes | no | no |
| GET /leen-abdallah/reports/threats | yes | yes | no | no |
| GET /leen-abdallah/reports/vulnerabilities | yes | yes | no | no |
| GET /leen-abdallah/reports/activity | yes | yes | no | no |

None of the routes takes a request body or parameters.

## 1. Security Summary Report

`GET /leen-abdallah/reports/summary` returns an overview: number of users and
assets, total and open incidents, and total and critical threats. An incident is
open until it is `Resolved` or `Closed`.

Response `200`:

```json
{
  "data": {
    "assets": 2,
    "critical_threats": 2,
    "generated_at": "2026-10-17 12:04:16",
    "open_incidents": 2,
    "total_incidents": 3,
    "total_threats": 3,
    "users": 4
  },
  "message": "Security summary report generated successfully",
  "status": "success"
}
```

## 2. Incident Report

`GET /leen-abdallah/reports/incidents` returns the total, the open incidents, the
incidents by severity and the incidents by status.

Response `200`:

```json
{
  "data": {
    "generated_at": "2026-10-17 12:04:16",
    "incidents_by_severity": {
      "Critical": 1,
      "High": 1,
      "Low": 1,
      "Medium": 0
    },
    "incidents_by_status": {
      "Closed": 1,
      "Mitigated": 0,
      "Open": 1,
      "Resolved": 0,
      "Under Investigation": 1
    },
    "open_incidents": 2,
    "total_incidents": 3
  },
  "message": "Incident report generated successfully",
  "status": "success"
}
```

## 3. Asset Report

`GET /leen-abdallah/reports/assets` returns the total, the critical assets, the
assets by type and the assets by criticality.

Response `200`:

```json
{
  "data": {
    "assets_by_criticality": {
      "Critical": 1,
      "High": 1,
      "Low": 0,
      "Medium": 0
    },
    "assets_by_type": {
      "Application": 0,
      "Cloud Resource": 0,
      "Database": 1,
      "Network Device": 0,
      "Server": 1,
      "Workstation": 0
    },
    "critical_assets": 1,
    "generated_at": "2026-10-17 12:04:16",
    "total_assets": 2
  },
  "message": "Asset report generated successfully",
  "status": "success"
}
```

## 4. Threat Report

`GET /leen-abdallah/reports/threats` returns the total, the critical threats, the
threats by severity, the threats by type and the 5 most recently added threats
(newest first).

Response `200`:

```json
{
  "data": {
    "critical_threats": 2,
    "generated_at": "2026-10-17 12:04:16",
    "recent_threats": [
      {
        "date_added": "2026-10-17",
        "severity_level": "Low",
        "source": "VirusTotal",
        "threat_id": 3,
        "threat_type": "File Hash",
        "threat_value": "d41d8cd98f00b204e9800998ecf8427e"
      },
      {
        "date_added": "2026-10-17",
        "severity_level": "Critical",
        "source": "OSINT feed",
        "threat_id": 2,
        "threat_type": "Domain",
        "threat_value": "evil.example.com"
      },
      {
        "date_added": "2026-10-17",
        "severity_level": "Critical",
        "source": "AbuseIPDB + SOC",
        "threat_id": 1,
        "threat_type": "IP Address",
        "threat_value": "192.168.1.5"
      }
    ],
    "threats_by_severity": {
      "Critical": 2,
      "High": 0,
      "Low": 1,
      "Medium": 0
    },
    "threats_by_type": {
      "Domain": 1,
      "File Hash": 1,
      "IP Address": 1,
      "Malware Signature": 0,
      "Other": 0
    },
    "total_threats": 3
  },
  "message": "Threat report generated successfully",
  "status": "success"
}
```

## 5. Vulnerability Report

`GET /leen-abdallah/reports/vulnerabilities` returns the total, the critical
count, the vulnerabilities by severity and by status, and the critical
vulnerabilities with the highest CVSS score first (at most 10).

Response `200`:

```json
{
  "data": {
    "critical_vulnerabilities": 2,
    "generated_at": "2026-10-17 12:04:16",
    "top_critical_vulnerabilities": [
      {
        "asset_id": 1,
        "cve_id": "CVE-2026-1000",
        "cvss_score": 9.8,
        "status": "Open",
        "title": "Vulnerability 1",
        "vulnerability_id": 1
      },
      {
        "asset_id": 1,
        "cve_id": "CVE-2026-1002",
        "cvss_score": 9.1,
        "status": "Closed",
        "title": "Vulnerability 3",
        "vulnerability_id": 3
      }
    ],
    "total_vulnerabilities": 3,
    "vulnerabilities_by_severity": {
      "Critical": 2,
      "High": 1,
      "Low": 0,
      "Medium": 0
    },
    "vulnerabilities_by_status": {
      "Closed": 1,
      "In Progress": 1,
      "Open": 1,
      "Resolved": 0,
      "Under Investigation": 0
    }
  },
  "message": "Vulnerability report generated successfully",
  "status": "success"
}
```

## 6. Activity Report

`GET /leen-abdallah/reports/activity` analyses the audit logs, which it reads from
the Security Audit Logging Service (Service 5). It returns the total number of log
records, the login attempts (successful plus failed), the successful and failed
logins, the 5 most performed actions (ties are ordered by action name) and the 5
most recent activities (newest first). A refused login for an inactive or
suspended account also counts as a failed login.

Response `200`:

```json
{
  "data": {
    "failed_logins": 1,
    "generated_at": "2026-10-17 19:50:50",
    "login_attempts": 3,
    "most_performed_actions": [
      {
        "action": "Successful login",
        "total": 2
      },
      {
        "action": "Threat added",
        "total": 2
      },
      {
        "action": "Unauthorized access attempt",
        "total": 2
      },
      {
        "action": "User created",
        "total": 2
      },
      {
        "action": "Failed login",
        "total": 1
      }
    ],
    "recent_activities": [
      {
        "action": "Unauthorized access attempt",
        "log_id": 9,
        "related_service": "reports",
        "severity_level": "Warning",
        "timestamp": "2026-10-17 19:50:50",
        "user_id": 2
      },
      {
        "action": "Successful login",
        "log_id": 8,
        "related_service": "users",
        "severity_level": "Information",
        "timestamp": "2026-10-17 19:50:50",
        "user_id": 2
      },
      {
        "action": "Unauthorized access attempt",
        "log_id": 7,
        "related_service": "threats",
        "severity_level": "Warning",
        "timestamp": "2026-10-17 19:50:50",
        "user_id": null
      },
      {
        "action": "Threat added",
        "log_id": 6,
        "related_service": "threats",
        "severity_level": "Information",
        "timestamp": "2026-10-17 19:50:50",
        "user_id": 1
      },
      {
        "action": "Threat added",
        "log_id": 5,
        "related_service": "threats",
        "severity_level": "Information",
        "timestamp": "2026-10-17 19:50:50",
        "user_id": 1
      }
    ],
    "successful_logins": 2,
    "total_activities": 9
  },
  "message": "Activity report generated successfully",
  "status": "success"
}
```

## Error responses

| Status | When | Example message |
|---|---|---|
| 401 | No token | `Authentication required: send 'Authorization: Bearer <token>'` |
| 401 | Invalid or expired token | `Invalid authentication token` |
| 403 | Analyst or Regular User | `User does not have permission to perform this operation` |
| 404 | The report does not exist | `Resource not found` |
| 405 | Any method other than GET | `Method not allowed for this endpoint` |
| 503 | A source service is down or refuses the request | `The assets service is unavailable` |

Every 401 and 403 is written to the audit log as `Unauthorized access attempt`
(severity Warning). Generating a report does not add a log entry, so the activity
report always matches the stored log records.

## Tests

```bash
python -m unittest discover -s tests -p "test_report_api.py" -v
```

The tests start the source services over real HTTP and check every number
against the records that were created and against the database. The Postman
folder **Service 6 – Security Reports** in
`postman/Security Incident System.postman_collection.json` covers every route
and role.
