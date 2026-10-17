# Services 3, 8 and 9 collection guide

`postman/Security Incident System.postman_collection.json` preserves the existing
Service 1 and Service 2 folders and adds these folders, each with six requests:

- Service 3 - Incident Management
- Service 8 - Notification Service
- Service 9 - Security Playbooks and Response Automation

Every new request describes its purpose, role, input, success status and relevant
error behavior. All 18 URLs include `/Youssef-Al-Hajj-Youness`. The collection is
prepared for later manual use; no screenshots or Postman execution are part of
this change.

## Variables

| Variables | Value source |
|---|---|
| `service1_base_url`, `service2_base_url`, `service3_base_url`, `service8_base_url`, `service9_base_url` | Default localhost ports 5001, 5002, 5003, 5008 and 5009; no trailing slash |
| `admin_token`, `analyst_token`, `reporter_token`, `auditor_token` | Corresponding Service 1 login `data.token`, without the Bearer prefix |
| `reporter_id`, `analyst_id` | Actual Service 1 user IDs; reporter is Regular User, analyst is Active Security Analyst |
| `asset_id` | Existing Service 2 asset ID |
| `incident_id` | Service 3 creation response `data.incident_id` |
| `notification_id` | Service 8 creation response or a notification from recipient history |
| `playbook_id`, `action_id` | Service 9 creation responses |
| `severity_level` | Default High; Low, Medium, High or Critical |
| `incident_status` | Default Under Investigation; advance through Mitigated, Resolved and Closed in order |
| `action_status` | Default In Progress; Pending, In Progress or Completed |
| `notification_type` | Default Security Alert; use Incident Assignment for Service 3 generated notifications |
| `notification_status` | Default Unread; use Read after acknowledgement |
| `step_number` | Default 1; use distinct positive integers for additional actions |

All new ID and token variables are deliberately empty. Fill them from real
responses locally; do not commit credentials or populated environments. Numeric
relationship variables appear unquoted in JSON bodies. The preserved Service
1/2 requests retain their original variables; the new snake_case variables do
not replace or rename Adam's variables. No credentials, token capture scripts or
generated example responses were added.

## Request dependencies

Service 3 needs an existing reporter and asset. Incident creation supplies the
ID for retrieval, assignment, status and notes. Assignment requires Service 1
reachable at the server-side `USERS_SERVICE_URL` (default port 5001); changing a
Postman base URL does not change that server-side setting. It forwards the
administrator's token to `GET /users` before beginning its write transaction.
Assignment and notification creation still share one atomic transaction.

Service 8 samples target `analyst_id` with `analyst_token` for ownership. Recipient
history also returns the automatic assignment notification; select its ID for
retrieval and marking as Read. Manual creation returns a separate notification
ID. Search combines recipient, type, severity and read status with AND; adjust
the type/status variables to the record being examined. Delete requires Admin.
To examine a Regular User recipient, use that user's ID and token consistently.

Service 9 creation supplies `playbook_id`. Adding actions supplies `action_id`;
change the step number for each action. Retrieval returns actions in step order
and execution history. The update request assigns the analyst and sets the
chosen status. With Completed, omitting `completion_date` records today's UTC
date. An explicit date may be added as a YYYY-MM-DD string and must not be in the
future. Reopening clears that date. Playbook deletion removes live actions and
preserves database history, so inspect API history before deletion and retained
history in the database afterwards.

## Automated verification

The collection regression test substitutes real temporary-database IDs and
tokens, sends all 18 new request definitions through the Flask applications, and
checks that they cover every implemented route. The assignment check reaches a
temporary Service 1 HTTP listener on an ephemeral loopback port. Separate tests
cover validation, ownership, RBAC, lifecycle, dependency failure, transaction
rollback, ordered actions, completion dates and retained history. Tests leave
normal service ports and the user's database untouched.
