# Security Incident Management System

Nine Flask microservices for managing security incidents. They share one SQLite database and use JWT role-based access control.

## Services

| # | Service | Port |
|---|---|---|
| 1 | Users and Authentication | 5001 |
| 2 | Assets | 5002 |
| 3 | Incidents | 5003 |
| 4 | Threat Intelligence | 5004 |
| 5 | Audit Logging | 5005 |
| 6 | Reports | 5006 |
| 7 | Vulnerabilities | 5007 |
| 8 | Notifications | 5008 |
| 9 | Playbooks | 5009 |

## Setup

```bash
python -m venv venv && source venv/bin/activate
pip install -r requirements.txt
python -m database.init_db
```

## Run

Start each service in its own terminal, with Service 1 first:

```bash
python -m user_service.app
python -m asset_service.app
python -m incident_service.app
python -m threat_service.app
python -m log_service.app
python -m report_service.app
python -m vulnerability_service.app
python -m notification_service.app
python -m playbook_service.app
```

## Auth

Log in at Service 1 to get a token (valid for 60 minutes). Send it on every other request:

```
Authorization: Bearer <token>
```

Roles: Security Administrator, Security Analyst, Regular User, Auditor.

## Docs and tests

- API docs: `docs/`
- Postman collection: `postman/`

## Authors

Adam Yahya (1, 2, 7) · Leen Abdallah (4, 5, 6) · Youssef Al Hajj Youness (3, 8, 9)