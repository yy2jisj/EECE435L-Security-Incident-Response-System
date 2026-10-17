# Service 3 analyst assignment dependency

All incident endpoints use `/Youssef-Al-Hajj-Youness/incidents` and the existing
Service 1 Bearer JWT. The complete request list is in the Postman collection.

`PUT /Youssef-Al-Hajj-Youness/incidents/{incident_id}/assign` accepts
`{"analyst_id": <existing user ID>}` and requires a Security Administrator.
The ID must be a positive JSON integer. Service 3 first validates the incident,
then calls Service 1's administrator-only `GET /users` over HTTP using the
caller's Authorization header. Service 1 currently exposes a username lookup
and a user directory, rather than a user-ID lookup, so Service 3 selects the
requested ID from that directory. It requires an existing, Active Security
Analyst. Missing users return 404; wrong roles or inactive accounts return 400.

The shared HTTP client uses a five-second timeout. Connection errors, timeouts,
unexpected HTTP statuses and malformed responses return 503 without changing
the incident, notifications or assignment audit records. The URL defaults to
`http://127.0.0.1:5001`; `USERS_SERVICE_URL` overrides it.

The HTTP check completes before `BEGIN IMMEDIATE`. Inside the existing shared
database transaction, Service 3 rechecks the incident and local user to protect
against deletion, deactivation or role changes between the API response and
the write. Assignment, notification insertion and both audit entries still
commit or roll back together. Notification creation remains in that transaction.
Assigning the same analyst again still validates through Service 1 but does not
create duplicate notifications or audit entries.

Creation, scoped reads, investigation notes and the lifecycle remain unchanged:
Open → Under Investigation → Mitigated → Resolved → Closed. The resolution date
is set on resolution and retained on closure.
