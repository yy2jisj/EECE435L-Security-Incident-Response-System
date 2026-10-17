# Service 4: Threat Intelligence

Implemented by Leen Abdallah.

Service 4 keeps a database of known threats (malicious IP addresses, suspicious
domains, file hashes, malware signatures and other indicators) that analysts use
during incident investigation. It uses the shared SQLite database and the
Service 1 Bearer JWT. Permission violations are written to the audit log.

## Run

From the project root with the virtual environment active:

```bash
python -m database.init_db
python -m user_service.app        # port 5001, for logging in
python -m threat_service.app      # port 5004
```

Log in with `POST http://127.0.0.1:5001/users/login/AdamYahya` and send
`Authorization: Bearer <token>` with every request. Every route lives under
`/leen-abdallah/threats`.

## Responses

Success: `{"status": "success", "message": "...", "data": ...}`.
Error: `{"status": "error", "message": "..."}` with the HTTP status code below.

## Endpoints and access

| Method and path | Security Administrator | Security Analyst | Auditor | Regular User | Success |
|---|---|---|---|---|---|
| POST /leen-abdallah/threats | yes | no | no | no | 201 |
| GET /leen-abdallah/threats | yes | yes | yes | no | 200 |
| GET /leen-abdallah/threats/{id} | yes | yes | yes | no | 200 |
| GET /leen-abdallah/threats/search | yes | yes | no | no | 200 |
| PUT /leen-abdallah/threats/{id} | yes | no | no | no | 200 |
| DELETE /leen-abdallah/threats/{id} | yes | no | no | no | 200 |

## Threat record

| Field | Description |
|---|---|
| threat_id | Generated ID |
| threat_type | `IP Address`, `Domain`, `File Hash`, `Malware Signature` or `Other` |
| threat_value | The indicator (checked against the type, see Validation) |
| description | What the threat is (max 500 characters) |
| severity_level | `Low`, `Medium`, `High` or `Critical` |
| source | Where the intelligence came from (max 100 characters) |
| date_added | Date the record was created (YYYY-MM-DD) |

## Validation

| Rule | Detail |
|---|---|
| Required fields | `threat_type`, `threat_value`, `description`, `severity_level`, `source`. Unknown fields are rejected. |
| Threat type and severity | Case-insensitive. Stored as `IP Address`, `High` and so on. |
| IP Address | Valid IPv4 or IPv6 address. |
| Domain | Valid domain name (letters, digits, hyphens, at least one dot). Stored in lower case. |
| File Hash | MD5 (32), SHA-1 (40) or SHA-256 (64) hexadecimal characters. Stored in lower case. |
| Malware Signature, Other | Free text, up to 255 characters. |
| Uniqueness | The same `threat_type` and `threat_value` cannot be added twice (409). The value is compared ignoring upper and lower case. |
| IDs in the URL | Must be a positive whole number no larger than 9223372036854775807. |

## 1. Add Threat Indicator

`POST /leen-abdallah/threats` (Security Administrator)

Request body:

```json
{
  "threat_type": "IP Address",
  "threat_value": "192.168.1.5",
  "description": "Port scanner",
  "severity_level": "High",
  "source": "AbuseIPDB"
}
```

Response `201`:

```json
{
  "data": {
    "date_added": "2026-10-17",
    "description": "Port scanner",
    "severity_level": "High",
    "source": "AbuseIPDB",
    "threat_id": 1,
    "threat_type": "IP Address",
    "threat_value": "192.168.1.5"
  },
  "message": "Threat added successfully",
  "status": "success"
}
```

Other examples that were added: a Critical domain (`evil.example.com`), a Low file
hash (`d41d8cd98f00b204e9800998ecf8427e`) and a Medium malware signature
(`Trojan.Win32.Agent`).

## 2. Retrieve All Threat Indicators

`GET /leen-abdallah/threats` (Administrator, Analyst, Auditor)

Returns every threat, ordered by `threat_id`. Response `200` (first two records shown):

```json
{
  "data": [
    {
      "date_added": "2026-10-17",
      "description": "Port scanner",
      "severity_level": "High",
      "source": "AbuseIPDB",
      "threat_id": 1,
      "threat_type": "IP Address",
      "threat_value": "192.168.1.5"
    },
    {
      "date_added": "2026-10-17",
      "description": "Phishing site",
      "severity_level": "Critical",
      "source": "OSINT feed",
      "threat_id": 2,
      "threat_type": "Domain",
      "threat_value": "evil.example.com"
    }
  ],
  "message": "Threats retrieved successfully",
  "status": "success"
}
```

## 3. Retrieve Specific Threat Indicator

`GET /leen-abdallah/threats/{id}` (Administrator, Analyst, Auditor)

Response `200`:

```json
{
  "data": {
    "date_added": "2026-10-17",
    "description": "Port scanner",
    "severity_level": "High",
    "source": "AbuseIPDB",
    "threat_id": 1,
    "threat_type": "IP Address",
    "threat_value": "192.168.1.5"
  },
  "message": "Threat retrieved successfully",
  "status": "success"
}
```

A threat that does not exist returns `404`:

```json
{
  "message": "Threat not found",
  "status": "error"
}
```

## 4. Search Threat Indicators

`GET /leen-abdallah/threats/search` (Administrator, Analyst)

Query parameters (at least one is required, filters are combined with AND):

| Parameter | Matching |
|---|---|
| threat_type | Exact, case-insensitive |
| severity_level | Exact, case-insensitive |
| threat_value | Part of the value, ignoring case |
| source | Part of the text, ignoring case |

Example: `GET /leen-abdallah/threats/search?threat_type=Domain` returns `200`:

```json
{
  "data": [
    {
      "date_added": "2026-10-17",
      "description": "Phishing site",
      "severity_level": "Critical",
      "source": "OSINT feed",
      "threat_id": 2,
      "threat_type": "Domain",
      "threat_value": "evil.example.com"
    }
  ],
  "message": "1 threat(s) found",
  "status": "success"
}
```

Searching with no matching record still returns `200` with an empty list
(`"message": "0 threat(s) found"`).

## 5. Update Threat Information

`PUT /leen-abdallah/threats/{id}` (Security Administrator)

Only `description`, `severity_level` and `source` can be changed, and any one of
them can be sent alone. The type and value identify the indicator, so sending
them is rejected. Values are validated like when adding a threat.

Request body:

```json
{
  "description": "Updated: scanning SSH",
  "severity_level": "Critical",
  "source": "AbuseIPDB + SOC"
}
```

Response `200`:

```json
{
  "data": {
    "date_added": "2026-10-17",
    "description": "Updated: scanning SSH",
    "severity_level": "Critical",
    "source": "AbuseIPDB + SOC",
    "threat_id": 1,
    "threat_type": "IP Address",
    "threat_value": "192.168.1.5"
  },
  "message": "Threat updated successfully",
  "status": "success"
}
```

## 6. Delete Threat Indicator

`DELETE /leen-abdallah/threats/{id}` (Security Administrator)

Response `200`:

```json
{
  "data": null,
  "message": "Threat deleted successfully",
  "status": "success"
}
```

## Error responses

| Status | When | Example message |
|---|---|---|
| 400 | Missing, unknown or invalid field | `Missing required fields: threat_value, description, severity_level, source` |
| 400 | Invalid IP address | `threat_value is not a valid IP address` |
| 400 | Invalid domain | `threat_value is not a valid domain name` |
| 400 | Invalid file hash | `threat_value is not a valid file hash (expected 32, 40 or 64 hexadecimal characters)` |
| 400 | Invalid severity | `severity_level must be one of: Low, Medium, High, Critical` |
| 400 | Unknown field in the body | `Unknown fields: extra` |
| 400 | Update tries to change the type or value | `Unknown fields: threat_value` |
| 400 | Search without parameters | `Provide at least one search parameter: threat_type, threat_value, severity_level, source` |
| 400 | Unknown search parameter | `Unknown search parameters: foo. Allowed: threat_type, threat_value, severity_level, source` |
| 400 | ID is not a positive whole number | `threat id must be a positive whole number` |
| 400 | ID is too large | `threat id is too large` |
| 401 | No token | `Authentication required: send 'Authorization: Bearer <token>'` |
| 401 | Invalid or expired token | `Invalid authentication token` |
| 403 | The role is not allowed to use the route | `User does not have permission to perform this operation` |
| 404 | Threat does not exist, or unknown path | `Threat not found` |
| 409 | Same type and value already exists | `A threat with the same type and value already exists` |

Every 401 and 403 is written to the audit log as `Unauthorized access attempt`
(severity Warning). Adding, updating and deleting a threat are logged as
`Threat added`, `Threat updated` and `Threat deleted`.

## Tests

```bash
python -m unittest tests.test_threat_model tests.test_threat_api -v
```

The Postman folder **Service 4 – Threat Intelligence** in
`postman/Security Incident System.postman_collection.json` covers every route
and role.
