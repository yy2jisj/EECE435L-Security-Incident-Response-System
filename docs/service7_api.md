# Service 7: Vulnerability Management

Implemented by Adam Yahya.

Service 7 records known software vulnerabilities (CVEs) found on assets and
tracks them from discovery to closure. It uses the shared SQLite database and the
Service 1 Bearer JWT. Service 6 reads from it to build the vulnerability report.
Changes and refused requests are written to the audit log.

## Run

From the project root with the virtual environment active:

```bash
python -m database.init_db
python -m user_service.app             # port 5001, for logging in
python -m asset_service.app            # port 5002, vulnerabilities belong to assets
python -m vulnerability_service.app    # port 5007
```

Base URL: `http://127.0.0.1:5007`. Send `Authorization: Bearer <token>` with every
request.

## Responses

Success: `{"status": "success", "message": "...", "data": ...}`.
Error: `{"status": "error", "message": "..."}` with the HTTP status code below.

## Endpoints and access

| API | Method and path | Security Administrator | Security Analyst | Auditor | Regular User | Success |
|---|---|---|---|---|---|---|
| Add Vulnerability | POST /vulnerabilities/AdamYahya | yes | no | no | no | 201 |
| Get All Vulnerabilities | GET /vulnerabilities/AdamYahya | yes | yes | yes | no | 200 |
| Get Vulnerability | GET /vulnerabilities/{id}/AdamYahya | yes | yes | yes | no | 200 |
| Search Vulnerabilities | GET /vulnerabilities/search/AdamYahya | yes | yes | yes | no | 200 |
| Update Vulnerability | PUT /vulnerabilities/{id}/AdamYahya | yes | yes | no | no | 200 |
| Delete Vulnerability | DELETE /vulnerabilities/{id}/AdamYahya | yes | no | no | no | 200 |

## Vulnerability record

| Field | Description |
|---|---|
| vulnerability_id | Generated ID |
| title | Short title (max 150 characters) |
| description | What the vulnerability is (max 2000 characters) |
| cve_id | `CVE-YYYY-NNNN` (4 or more digits), stored in upper case |
| cvss_score | Number from 0.0 to 10.0 |
| severity_level | `Low`, `Medium`, `High` or `Critical`, must match the score |
| asset_id | The affected asset (must exist) |
| asset_name | Name of that asset, filled in by the service |
| discovery_source | How it was found, for example a scanner name (max 100 characters) |
| status | `Open`, `Under Investigation`, `In Progress`, `Resolved` or `Closed` |
| creation_date | Date it was recorded, set by the system |
| resolution_date | `YYYY-MM-DD`, `null` until resolved or closed |

## Rules

| Rule | Detail |
|---|---|
| Severity from score | 0.0 to 3.9 is Low, 4.0 to 6.9 Medium, 7.0 to 8.9 High, 9.0 to 10.0 Critical. A mismatch is rejected. |
| Unique per asset | The same CVE cannot be recorded twice for the same asset. |
| Status order | New vulnerabilities are `Open`. Status moves one step at a time: Open, Under Investigation, In Progress, Resolved, Closed. Skipping or going back is rejected. |
| Resolution date | Allowed only when the status is Resolved or Closed, and not before the creation date. Moving to Resolved sets today's date if none is given. |
| Other | Enumerated values are case-insensitive. Text is trimmed and control characters are rejected. Unknown fields are rejected. |

## Errors common to every route

| Status | When | Message |
|---|---|---|
| 401 | No, invalid or expired token | `Authentication required: send 'Authorization: Bearer <token>'` / `Invalid authentication token` |
| 403 | Role is not allowed | `User does not have permission to perform this operation` |
| 405 | Wrong HTTP method | `Method not allowed for this endpoint` |

Every 401 and 403 is written to the audit log as `Unauthorized access attempt`.

## 1. Add Vulnerability

- **Purpose:** record a vulnerability found on an asset.
- **Method and endpoint:** `POST /vulnerabilities/AdamYahya`
- **Access:** Security Administrator.
- **Parameters:** none.

Request body (all fields required; status is always `Open`):

```json
{
  "title": "OpenSSL buffer overflow",
  "description": "Remote code execution in the TLS handshake",
  "cve_id": "CVE-2024-12345",
  "cvss_score": 9.8,
  "severity_level": "Critical",
  "asset_id": 1,
  "discovery_source": "Nessus"
}
```

Response `201`:

```json
{
  "data": {
    "asset_id": 1,
    "asset_name": "Web Server 1",
    "creation_date": "2026-10-17",
    "cve_id": "CVE-2024-12345",
    "cvss_score": 9.8,
    "description": "Remote code execution in the TLS handshake",
    "discovery_source": "Nessus",
    "resolution_date": null,
    "severity_level": "Critical",
    "status": "Open",
    "title": "OpenSSL buffer overflow",
    "vulnerability_id": 1
  },
  "message": "Vulnerability created successfully",
  "status": "success"
}
```

| Status | When | Message |
|---|---|---|
| 400 | Missing, unknown or invalid field | `Missing required fields: cve_id` / `cve_id must look like CVE-2024-12345` / `cvss_score must be between 0.0 and 10.0` / `severity_level High does not match cvss_score 9.8 (this score means Critical)` / `asset_id does not match any existing asset` |
| 409 | CVE already recorded for this asset | `This CVE is already recorded for this asset` |

## 2. Get All Vulnerabilities

- **Purpose:** list every vulnerability.
- **Method and endpoint:** `GET /vulnerabilities/AdamYahya`
- **Access:** Security Administrator, Security Analyst, Auditor.
- **Parameters:** none. No request body.

Response `200`: `data` is a list of vulnerability records ordered by id, message
`Vulnerabilities retrieved successfully`. Only the common errors apply.

## 3. Get Vulnerability

- **Purpose:** return one vulnerability.
- **Method and endpoint:** `GET /vulnerabilities/{vulnerability_id}/AdamYahya`
- **Access:** Security Administrator, Security Analyst, Auditor.
- **Parameters:** `vulnerability_id` in the URL, a positive whole number.

Response `200`: `data` is one vulnerability record, message
`Vulnerability retrieved successfully`.

| Status | When | Message |
|---|---|---|
| 400 | Id is not a positive whole number | `vulnerability id must be a positive whole number` |
| 404 | No such vulnerability | `Vulnerability not found` |

## 4. Search Vulnerabilities

- **Purpose:** find vulnerabilities by CVE, severity, asset or status.
- **Method and endpoint:** `GET /vulnerabilities/search/AdamYahya`
- **Access:** Security Administrator, Security Analyst, Auditor.
- **Parameters** (query string, at least one, all exact matches):

| Parameter | Value |
|---|---|
| `cve_id` | For example `CVE-2024-12345` (not case sensitive) |
| `severity_level` | `Low`, `Medium`, `High` or `Critical` |
| `asset_id` | A positive whole number |
| `status` | One of the five statuses |

`GET /vulnerabilities/search/AdamYahya?severity_level=Critical&status=Open`

Response `200`: `data` is a list of matches, message `2 vulnerability(ies) found`.
No match returns `200` with an empty list.

| Status | When | Message |
|---|---|---|
| 400 | No parameter, unknown parameter, or an invalid value | `Provide at least one search parameter: cve_id, severity_level, asset_id, status` / `cve_id must look like CVE-2024-12345` |

## 5. Update Vulnerability

- **Purpose:** edit a vulnerability or move it forward in its life cycle.
- **Method and endpoint:** `PUT /vulnerabilities/{vulnerability_id}/AdamYahya`
- **Access:** Security Administrator, Security Analyst.
- **Parameters:** `vulnerability_id` in the URL.

Request body: at least one of `description`, `cvss_score`, `severity_level`,
`status`, `resolution_date`. CVE, asset and title cannot be changed.

```json
{ "status": "Under Investigation" }
```

Response `200`: `data` is the updated record, message `Vulnerability updated successfully`.

| Status | When | Message |
|---|---|---|
| 400 | Bad id, empty body, unknown field, invalid value | `Unknown fields: cve_id` |
| 400 | Status skips a step or goes back | `Invalid status change from Open to Resolved. The next status must be Under Investigation` |
| 400 | Closed vulnerability | `A Closed vulnerability cannot change status any more` |
| 400 | Severity and score disagree | `severity_level Low does not match cvss_score 9.8 (this score means Critical)` |
| 400 | Bad resolution date | `resolution_date can only be set when the status is Resolved or Closed` |
| 400 | Nothing changes | `Nothing to update, the values are the same` |
| 404 | No such vulnerability | `Vulnerability not found` |

## 6. Delete Vulnerability

- **Purpose:** remove a vulnerability record.
- **Method and endpoint:** `DELETE /vulnerabilities/{vulnerability_id}/AdamYahya`
- **Access:** Security Administrator.
- **Parameters:** `vulnerability_id` in the URL. No request body.

Response `200`: `{"data": null, "message": "Vulnerability deleted successfully", "status": "success"}`

| Status | When | Message |
|---|---|---|
| 400 | Id is not a positive whole number | `vulnerability id must be a positive whole number` |
| 404 | No such vulnerability | `Vulnerability not found` |

## How the main APIs work

**Add Vulnerability.** The model checks the CVE format, the CVSS range and that
the severity level matches the score (for example 9.8 must be Critical). The
service then checks the asset exists and that the CVE is not already recorded
for it; a database unique constraint on (CVE, asset) catches two requests that
arrive at the same time. The status is always set to `Open`.

**Update Vulnerability.** Several rules are checked together on the final result:
the status may only move one step along Open, Under Investigation, In Progress,
Resolved, Closed; changing the score or the severity re-checks that the two still
agree; and a resolution date is accepted only for Resolved or Closed records.
Moving to Resolved without a date fills in today's date. Both administrators and
analysts can update, because analysts do the investigation work.

**Search Vulnerabilities.** Every filter is validated like the stored value (for
example the CVE must have the CVE format) and then matched exactly with query
parameters. Filters combine with AND, which lets an analyst ask for "all Critical
vulnerabilities that are still Open".

## Tests

Every route and role is covered by the Postman folder **Service 7** in
`postman/Security Incident System.postman_collection.json`. Screenshots are in
`screenshots/service7/`.
