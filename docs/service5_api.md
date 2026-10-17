# Service 5: Security Audit Logging

Implemented by Leen Abdallah.

Service 5 records and tracks security-related activity so that administrators
and auditors can review what happened in the system. It uses the shared SQLite
database and the Service 1 Bearer JWT. The other services write their events into
the same `logs` table (login attempts, user, incident, asset and threat changes,
role changes and permission violations); this service lets authorised users create,
read, search and delete those records.

## Run

From the project root with the virtual environment active:

```bash
python -m database.init_db
python -m user_service.app        # port 5001, for logging in
python -m log_service.app         # port 5005
```

Log in with `POST http://127.0.0.1:5001/users/login/AdamYahya` and send
`Authorization: Bearer <token>` with every request. Every route lives under
`/leen-abdallah/logs`.

## Responses

Success: `{"status": "success", "message": "...", "data": ...}`.
Error: `{"status": "error", "message": "..."}` with the HTTP status code below.

## Endpoints and access

| Method and path | Security Administrator | Auditor | Security Analyst | Regular User | Success |
|---|---|---|---|---|---|
| POST /leen-abdallah/logs | yes | no | no | no | 201 |
| GET /leen-abdallah/logs | yes | yes | no | no | 200 |
| GET /leen-abdallah/logs/{id} | yes | yes | yes | no | 200 |
| GET /leen-abdallah/logs/search | yes | yes | yes | no | 200 |
| GET /leen-abdallah/logs/user/{user_id} | yes | yes | no | no | 200 |
| DELETE /leen-abdallah/logs/{id} | yes | no | no | no | 200 |

There is no update route: logs cannot be modified after they are created.

## Log record

| Field | Description |
|---|---|
| log_id | Generated ID |
| user_id | The user the activity belongs to (becomes `null` if that user is deleted later; the log is kept) |
| action | Short name of what was done, for example `Failed login` (max 100 characters) |
| description | What happened (max 500 characters) |
| timestamp | Date and time the log was created (UTC, `YYYY-MM-DD HH:MM:SS`), set by the system |
| severity_level | `Information`, `Warning`, `Error` or `Critical` |
| related_service | The service the event came from, for example `incidents` (max 50 characters) |

## Validation

| Rule | Detail |
|---|---|
| Required fields | `user_id`, `action`, `description`, `severity_level`, `related_service`. Unknown fields are rejected, so the id and timestamp cannot be set by the client. |
| user_id | A positive whole number (not text) that belongs to an existing user. |
| Severity | Case-insensitive. Stored as `Information`, `Warning` and so on. |
| Text fields | Trimmed. Control characters (new lines, tabs) are rejected. |
| IDs in the URL | Must be a positive whole number no larger than 9223372036854775807. |
| Protection | The database refuses any change to a stored log, so the original information is preserved. Only an administrator can delete a log. |

## Events that generate logs

| Event | Action | Severity | Written by |
|---|---|---|---|
| Successful login | `Successful login` | Information | users |
| Failed login | `Failed login` | Warning | users |
| User created, updated, deleted | `User created`, `User updated`, `User deleted` | Information / Warning | users |
| Threat added, updated, deleted | `Threat added`, `Threat updated`, `Threat deleted` | Information / Warning | threats |
| Unauthorized access (401, 403) | `Unauthorized access attempt` | Warning | every service |
| A log is deleted | `Log deleted` | Warning | logs |
| Anything an administrator records by hand | any | any | `POST /leen-abdallah/logs` |

## 1. Create Log Record

`POST /leen-abdallah/logs` (Security Administrator)

Request body:

```json
{
  "user_id": 2,
  "action": "Incident created",
  "description": "Analyst opened incident 4",
  "severity_level": "Information",
  "related_service": "incidents"
}
```

Response `201`:

```json
{
  "data": {
    "action": "Incident created",
    "description": "Analyst opened incident 4",
    "log_id": 1,
    "related_service": "incidents",
    "severity_level": "Information",
    "timestamp": "2026-10-17 19:35:32",
    "user_id": 2
  },
  "message": "Log created successfully",
  "status": "success"
}
```

## 2. Retrieve All Logs

`GET /leen-abdallah/logs` (Security Administrator, Auditor)

Returns every log, oldest first. Response `200`:

```json
{
  "data": [
    {
      "action": "Incident created",
      "description": "Analyst opened incident 4",
      "log_id": 1,
      "related_service": "incidents",
      "severity_level": "Information",
      "timestamp": "2026-10-17 19:35:32",
      "user_id": 2
    },
    {
      "action": "Failed login",
      "description": "Failed login example",
      "log_id": 2,
      "related_service": "users",
      "severity_level": "Warning",
      "timestamp": "2026-10-17 19:35:32",
      "user_id": 3
    },
    {
      "action": "Threat deleted",
      "description": "Threat deleted example",
      "log_id": 3,
      "related_service": "threats",
      "severity_level": "Critical",
      "timestamp": "2026-10-17 19:35:32",
      "user_id": 1
    },
    {
      "action": "Incident updated",
      "description": "Incident 4 set to Resolved",
      "log_id": 4,
      "related_service": "incidents",
      "severity_level": "Warning",
      "timestamp": "2026-10-17 19:35:32",
      "user_id": 2
    }
  ],
  "message": "Logs retrieved successfully",
  "status": "success"
}
```

## 3. Retrieve Specific Log

`GET /leen-abdallah/logs/{id}` (Security Administrator, Auditor, Security Analyst)

Response `200`:

```json
{
  "data": {
    "action": "Incident created",
    "description": "Analyst opened incident 4",
    "log_id": 1,
    "related_service": "incidents",
    "severity_level": "Information",
    "timestamp": "2026-10-17 19:35:32",
    "user_id": 2
  },
  "message": "Log retrieved successfully",
  "status": "success"
}
```

An id that does not exist returns `404`:

```json
{
  "message": "Log not found",
  "status": "error"
}
```

An id that is not a positive whole number returns `400`:

```json
{
  "message": "log id must be a positive whole number",
  "status": "error"
}
```

## 4. Search Logs

`GET /leen-abdallah/logs/search` (Security Administrator, Auditor, Security Analyst)

| Parameter | Matching |
|---|---|
| `user_id` | Exact user |
| `date` | The whole day, written `YYYY-MM-DD` (compared with the date part of the timestamp, UTC) |
| `action` | Contains the text, ignoring case |
| `severity_level` | Exact level, ignoring case |
| `related_service` | Contains the text, ignoring case |

Filters can be combined and all of them must match. At least one filter is
required. `%` and `_` are matched as normal characters, not as wildcards.
A search with no results returns `200` with an empty list.

`GET /leen-abdallah/logs/search?user_id=2`

```json
{
  "data": [
    {
      "action": "Incident created",
      "description": "Analyst opened incident 4",
      "log_id": 1,
      "related_service": "incidents",
      "severity_level": "Information",
      "timestamp": "2026-10-17 19:35:32",
      "user_id": 2
    },
    {
      "action": "Incident updated",
      "description": "Incident 4 set to Resolved",
      "log_id": 4,
      "related_service": "incidents",
      "severity_level": "Warning",
      "timestamp": "2026-10-17 19:35:32",
      "user_id": 2
    }
  ],
  "message": "2 log(s) found",
  "status": "success"
}
```

`GET /leen-abdallah/logs/search?user_id=2&severity_level=Warning&related_service=incidents`

```json
{
  "data": [
    {
      "action": "Incident updated",
      "description": "Incident 4 set to Resolved",
      "log_id": 4,
      "related_service": "incidents",
      "severity_level": "Warning",
      "timestamp": "2026-10-17 19:35:32",
      "user_id": 2
    }
  ],
  "message": "1 log(s) found",
  "status": "success"
}
```

`GET /leen-abdallah/logs/search?action=nothing`

```json
{
  "data": [],
  "message": "0 log(s) found",
  "status": "success"
}
```

## 5. Retrieve Logs By User

`GET /leen-abdallah/logs/user/{user_id}` (Security Administrator, Auditor)

Returns the logs whose `user_id` equals the id in the URL. A user that exists but
has no logs gets an empty list. An unknown user gets `404`.

`GET /leen-abdallah/logs/user/2`

```json
{
  "data": [
    {
      "action": "Incident created",
      "description": "Analyst opened incident 4",
      "log_id": 1,
      "related_service": "incidents",
      "severity_level": "Information",
      "timestamp": "2026-10-17 19:35:32",
      "user_id": 2
    },
    {
      "action": "Incident updated",
      "description": "Incident 4 set to Resolved",
      "log_id": 4,
      "related_service": "incidents",
      "severity_level": "Warning",
      "timestamp": "2026-10-17 19:35:32",
      "user_id": 2
    }
  ],
  "message": "2 log(s) found for user 2",
  "status": "success"
}
```

`GET /leen-abdallah/logs/user/4` (a user with no logs)

```json
{
  "data": [],
  "message": "0 log(s) found for user 4",
  "status": "success"
}
```

## 6. Delete Logs

`DELETE /leen-abdallah/logs/{id}` (Security Administrator)

Response `200`:

```json
{
  "data": null,
  "message": "Log deleted successfully",
  "status": "success"
}
```

The deletion is recorded as a new `Log deleted` log (Warning). An analyst,
auditor or regular user gets `403` and the attempt is logged:

```json
{
  "message": "User does not have permission to perform this operation",
  "status": "error"
}
```

## Error responses

| Status | When | Example message |
|---|---|---|
| 400 | Missing field | `Missing required fields: user_id, description, severity_level, related_service` |
| 400 | Invalid severity | `severity_level must be one of: Information, Warning, Error, Critical` |
| 400 | `user_id` does not exist | `user_id does not match any existing user` |
| 400 | Unknown field in the body | `Unknown fields: timestamp` |
| 400 | Search without parameters | `Provide at least one search parameter: user_id, date, action, severity_level, related_service` |
| 400 | Unknown search parameter | `Unknown search parameters: foo. Allowed: user_id, date, action, severity_level, related_service` |
| 400 | Invalid search date | `date must be a valid date in YYYY-MM-DD format` |
| 400 | ID is not a positive whole number | `log id must be a positive whole number` |
| 400 | ID is too large | `log id is too large` |
| 401 | No token | `Authentication required: send 'Authorization: Bearer <token>'` |
| 401 | Invalid or expired token | `Invalid authentication token` |
| 403 | The role is not allowed to use the route | `User does not have permission to perform this operation` |
| 404 | Log or user does not exist | `Log not found` |
| 405 | Update, or delete without an id | `Method not allowed for this endpoint` |

Every 401 and 403 is written to the audit log as `Unauthorized access attempt`
(severity Warning).

## Tests

```bash
python -m unittest discover -s tests -p "test_log_api.py" -v
python -m unittest discover -s tests -p "test_log_postman.py" -v
```

The Postman folder **Service 5 – Security Audit Logging** in
`postman/Security Incident System.postman_collection.json` covers every route
and role. Run the logs and users services first, then run the folder.
