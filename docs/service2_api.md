# Service 2: Asset Management

Implemented by Adam Yahya.

Service 2 keeps the inventory of IT assets (servers, workstations, databases,
applications, network devices and cloud resources) that incidents and
vulnerabilities refer to. It uses the shared SQLite database and the Service 1
Bearer JWT. Changes and refused requests are written to the audit log.

## Run

From the project root with the virtual environment active:

```bash
python -m database.init_db
python -m user_service.app        # port 5001, for logging in
python -m asset_service.app       # port 5002
```

Base URL: `http://127.0.0.1:5002`. Log in with
`POST http://127.0.0.1:5001/users/login/AdamYahya` and send
`Authorization: Bearer <token>` with every request.

## Responses

Success: `{"status": "success", "message": "...", "data": ...}`.
Error: `{"status": "error", "message": "..."}` with the HTTP status code below.

## Endpoints and access

| API | Method and path | Security Administrator | Auditor | Security Analyst | Regular User | Success |
|---|---|---|---|---|---|---|
| Add Asset | POST /assets/AdamYahya | yes | no | no | no | 201 |
| Get All Assets | GET /assets/AdamYahya | yes | yes | no | no | 200 |
| Get Asset | GET /assets/{asset_id}/AdamYahya | yes | yes | yes | no | 200 |
| Search Assets | GET /assets/search/AdamYahya | yes | yes | yes | no | 200 |
| Update Asset | PUT /assets/{asset_id}/AdamYahya | yes | no | no | no | 200 |
| Delete Asset | DELETE /assets/{asset_id}/AdamYahya | yes | no | no | no | 200 |

## Asset record

| Field | Description |
|---|---|
| asset_id | Generated ID |
| asset_name | Name (max 100 characters) |
| asset_type | `Server`, `Workstation`, `Database`, `Application`, `Network Device` or `Cloud Resource` |
| ip_address | A valid IPv4 or IPv6 address |
| operating_system | Optional (max 100 characters) |
| department | Department that uses the asset (max 100 characters) |
| owner_id | `user_id` of an existing user |
| owner_name | Full name of the owner, filled in by the service |
| location | Optional (max 100 characters) |
| criticality_level | `Low`, `Medium`, `High` or `Critical` |
| status | `Active` (default), `Inactive` or `Under Maintenance` |
| created_at | Creation time (UTC), set by the system |

Enumerated values are case-insensitive and stored with the spelling above. Text
is trimmed and control characters are rejected. Unknown fields are rejected.

## Errors common to every route

| Status | When | Message |
|---|---|---|
| 401 | No, invalid or expired token | `Authentication required: send 'Authorization: Bearer <token>'` / `Token has expired, please log in again` |
| 403 | Role is not allowed | `User does not have permission to perform this operation` |
| 405 | Wrong HTTP method | `Method not allowed for this endpoint` |

Every 401 and 403 is written to the audit log as `Unauthorized access attempt`.

## 1. Add Asset

- **Purpose:** register a new asset.
- **Method and endpoint:** `POST /assets/AdamYahya`
- **Access:** Security Administrator.
- **Parameters:** none.

Request body:

| Field | Required |
|---|---|
| asset_name, asset_type, ip_address, department, owner_id, criticality_level | yes |
| operating_system, location, status | no |

```json
{
  "asset_name": "Web Server 1",
  "asset_type": "Server",
  "ip_address": "10.0.0.5",
  "department": "IT",
  "owner_id": 1,
  "criticality_level": "High",
  "operating_system": "Ubuntu 22.04",
  "location": "Data Center A"
}
```

Response `201`:

```json
{
  "data": {
    "asset_id": 1,
    "asset_name": "Web Server 1",
    "asset_type": "Server",
    "created_at": "2026-10-17 19:40:00",
    "criticality_level": "High",
    "department": "IT",
    "ip_address": "10.0.0.5",
    "location": "Data Center A",
    "operating_system": "Ubuntu 22.04",
    "owner_id": 1,
    "owner_name": "Adam Yahya",
    "status": "Active"
  },
  "message": "Asset created successfully",
  "status": "success"
}
```

| Status | When | Message |
|---|---|---|
| 400 | Missing, unknown or invalid field | `Missing required fields: ip_address` / `ip_address is not a valid IP address` / `asset_type must be one of: Server, Workstation, ...` / `owner_id does not match any existing user` |

## 2. Get All Assets

- **Purpose:** list every asset.
- **Method and endpoint:** `GET /assets/AdamYahya`
- **Access:** Security Administrator, Auditor.
- **Parameters:** none. No request body.

Response `200`: `data` is a list of asset records ordered by `asset_id`, message
`Assets retrieved successfully`. Only the common errors above apply.

## 3. Get Asset

- **Purpose:** return one asset together with the incidents and vulnerabilities
  linked to it.
- **Method and endpoint:** `GET /assets/{asset_id}/AdamYahya`
- **Access:** Security Administrator, Auditor, Security Analyst.
- **Parameters:** `asset_id` in the URL, a positive whole number.

Response `200`:

```json
{
  "data": {
    "asset_id": 1,
    "asset_name": "Web Server 1",
    "criticality_level": "High",
    "status": "Active",
    "related_incidents": [
      {
        "incident_id": 2,
        "title": "Suspicious login",
        "severity_level": "High",
        "status": "Open",
        "creation_date": "2026-10-17"
      }
    ],
    "related_vulnerabilities": [
      {
        "vulnerability_id": 1,
        "title": "OpenSSL buffer overflow",
        "cve_id": "CVE-2024-12345",
        "severity_level": "Critical",
        "status": "Open"
      }
    ]
  },
  "message": "Asset retrieved successfully",
  "status": "success"
}
```

(The full asset fields from the record table are also returned; they are shortened here.)

| Status | When | Message |
|---|---|---|
| 400 | Id is not a positive whole number | `asset id must be a positive whole number` |
| 404 | No such asset | `Asset not found` |

## 4. Search Assets

- **Purpose:** find assets by one or more attributes.
- **Method and endpoint:** `GET /assets/search/AdamYahya`
- **Access:** Security Administrator, Auditor, Security Analyst.
- **Parameters** (query string, at least one):

| Parameter | Matching |
|---|---|
| `asset_name` | Contains the text, ignoring case |
| `department` | Contains the text, ignoring case |
| `asset_type` | Exact type |
| `ip_address` | Exact address |
| `criticality_level` | Exact level |

Filters can be combined and all of them must match. No request body.

`GET /assets/search/AdamYahya?asset_type=Server&criticality_level=High`

Response `200`: `data` is a list of matching assets, message `1 asset(s) found`.
No match returns `200` with an empty list.

| Status | When | Message |
|---|---|---|
| 400 | No parameter, unknown parameter, or an invalid value | `Provide at least one search parameter: asset_name, asset_type, ip_address, department, criticality_level` / `ip_address is not a valid IP address` |

## 5. Update Asset

- **Purpose:** change an asset.
- **Method and endpoint:** `PUT /assets/{asset_id}/AdamYahya`
- **Access:** Security Administrator.
- **Parameters:** `asset_id` in the URL.

Request body: at least one of `asset_name`, `owner_id`, `department`,
`criticality_level`, `status`. Type and IP address cannot be changed.

```json
{ "criticality_level": "Critical", "status": "Under Maintenance" }
```

Response `200`: `data` is the updated asset, message `Asset updated successfully`.

| Status | When | Message |
|---|---|---|
| 400 | Bad id, empty body, unknown field, invalid value, unknown owner | `Unknown fields: ip_address` / `owner_id does not match any existing user` |
| 404 | No such asset | `Asset not found` |

## 6. Delete Asset

- **Purpose:** remove an asset.
- **Method and endpoint:** `DELETE /assets/{asset_id}/AdamYahya`
- **Access:** Security Administrator.
- **Parameters:** `asset_id` in the URL. No request body.

Response `200`: `{"data": null, "message": "Asset deleted successfully", "status": "success"}`

| Status | When | Message |
|---|---|---|
| 400 | Id is not a positive whole number | `asset id must be a positive whole number` |
| 404 | No such asset | `Asset not found` |
| 409 | Incidents or vulnerabilities still refer to it | `Asset is still referenced by incidents or vulnerabilities and cannot be deleted` |

## How the main APIs work

**Add Asset.** The `Asset` model validates every field before saving: the IP
address is parsed with Python's `ipaddress` module, enumerated fields are matched
to the allowed list, and the service checks that `owner_id` is a real user so no
asset is left without an owner. The new row is read back (with the owner's name
joined in) and returned, and an `Asset created` log is written.

**Get Asset.** The asset is loaded together with the incidents and
vulnerabilities that point to it, so an analyst sees the whole security picture
of one asset in a single call.

**Search Assets.** Name and department use partial, case-insensitive matching;
type, IP and criticality are exact. The values go to the database as query
parameters, never inside the SQL text, so search input cannot inject SQL. The
route is declared before `/assets/{asset_id}` so that `search` is not read as an id.

## Tests

Every route and role is covered by the Postman folder **Service 2** in
`postman/Security Incident System.postman_collection.json`. Screenshots are in
`screenshots/service2/`.
