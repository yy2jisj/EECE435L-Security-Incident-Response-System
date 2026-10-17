"""Service 9 REST API, implemented by Youssef Al Hajj Youness.

Run after `python -m database.init_db` with `python -m playbook_service.app`.
All routes require the existing Service 1 Bearer JWT and return the shared
status/message/data envelope. Validation, authentication, permission, missing
resource and conflict errors use HTTP 400, 401, 403, 404 and 409 respectively.
"""

from flask import Flask, g

from common import config
from common.audit import log_event
from common.auth import roles_required
from common.db import get_connection
from common.errors import ApiError, register_error_handlers, success_response
from common.validators import check_fields, get_json_body
from playbook_service import repository
from playbook_service.models import Playbook, ResponseAction, action_update, playbook_id
from user_service import repository as users

SERVICE = "playbooks"
ROUTE_PREFIX = "/Youssef-Al-Hajj-Youness"
BASE_ROUTE = ROUTE_PREFIX + "/playbooks"
READ_ROLES = (config.ROLE_ADMIN, config.ROLE_ANALYST, config.ROLE_AUDITOR)

app = Flask(__name__)
register_error_handlers(app)


def find_playbook(value, conn):
    item = repository.get_by_id(playbook_id(value), conn)
    if item is None:
        raise ApiError("Playbook not found", 404)
    return item


@app.post(BASE_ROUTE)
@roles_required(config.ROLE_ADMIN, service=SERVICE)
def create_playbook():
    """Create a playbook (201); administrator only.

    JSON: playbook_name, description, incident_category, severity_level.
    Creator and creation time are server controlled. Returns the playbook
    with empty response_actions and action_history lists.
    """
    data = get_json_body()
    check_fields(data, required=["playbook_name", "description", "incident_category",
                                 "severity_level"])
    playbook = Playbook(**data)
    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        new_id = repository.insert_playbook(playbook, g.current_user["user_id"], conn)
        log_event(g.current_user["user_id"], "Playbook created",
                  f"Playbook {new_id} created for category {playbook.incident_category}, "
                  f"severity {playbook.severity_level}", "Information", SERVICE, conn)
        item = repository.get_by_id(new_id, conn)
    return success_response("Playbook created successfully", item, 201)


@app.get(BASE_ROUTE)
@roles_required(*READ_ROLES, service=SERVICE)
def get_all_playbooks():
    """Return playbook metadata (200); administrator, analyst or auditor."""
    return success_response("Playbooks retrieved successfully", repository.get_all())


@app.get(BASE_ROUTE + "/<item_id>")
@roles_required(*READ_ROLES, service=SERVICE)
def get_playbook(item_id):
    """Return metadata, ordered response_actions and action_history (200)."""
    with get_connection() as conn:
        conn.execute("BEGIN")
        item = find_playbook(item_id, conn)
    return success_response("Playbook retrieved successfully", item)


@app.post(BASE_ROUTE + "/<item_id>/actions")
@roles_required(config.ROLE_ADMIN, config.ROLE_ANALYST, service=SERVICE)
def add_response_action(item_id):
    """Add an ordered step (201); administrator or analyst.

    JSON: action_description, step_number (positive integer, unique within
    the playbook). Returns a Pending, unassigned action with no completion
    date. Duplicate step numbers return 409. Retrieval sorts by step number;
    gaps are allowed and no automated action is executed.
    """
    data = get_json_body()
    check_fields(data, required=["action_description", "step_number"])
    action = ResponseAction(**data)
    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        item = find_playbook(item_id, conn)
        if repository.step_exists(item["playbook_id"], action.step_number, conn):
            raise ApiError("Step number already exists in this playbook", 409)
        new_id = repository.insert_action(item["playbook_id"], action, conn)
        repository.record_action_history(new_id, g.current_user["user_id"], conn)
        log_event(g.current_user["user_id"], "Response action added",
                  f"Action {new_id} added to playbook {item['playbook_id']} "
                  f"at step {action.step_number}", "Information", SERVICE, conn)
        saved = repository.get_action(new_id, conn)
    return success_response("Response action added successfully", saved, 201)


@app.put(ROUTE_PREFIX + "/actions/<item_id>/status")
@roles_required(config.ROLE_ADMIN, config.ROLE_ANALYST, service=SERVICE)
def update_response_action_status(item_id):
    """Update progress (200); administrator or analyst.

    JSON: at least one of status (Pending, In Progress, Completed),
    assigned_user_id (existing active user's integer ID, or null to unassign),
    completion_date (YYYY-MM-DD). Completion defaults to today's UTC date;
    explicit dates must not be in the future. Reopening clears the date.
    Unchanged requests preserve history and dates. No ownership restriction
    or incident status change is specified by Service 9.
    """
    data = get_json_body()
    check_fields(data, allowed=["status", "assigned_user_id", "completion_date"])
    action_id = playbook_id(item_id, "action id")
    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        item = repository.get_action(action_id, conn)
        if item is None:
            raise ApiError("Response action not found", 404)
        fields = action_update(data, item)
        if data.get("assigned_user_id") is not None:
            assigned = users.get_by_id(fields["assigned_user_id"], conn)
            if assigned is None:
                raise ApiError("Assigned user not found", 404)
            if assigned["account_status"] != "Active":
                raise ApiError("Assigned user must have an active account", 400)
        if any(item[name] != value for name, value in fields.items()):
            repository.update_action(action_id, fields, conn)
            repository.record_action_history(action_id, g.current_user["user_id"], conn)
            log_event(g.current_user["user_id"], "Response action updated",
                      f"Action {action_id}: status {item['status']} -> {fields['status']}; "
                      f"assigned user {item['assigned_user_id']} -> {fields['assigned_user_id']}; "
                      f"completion date {item['completion_date']} -> {fields['completion_date']}",
                      "Information", SERVICE, conn)
        saved = repository.get_action(action_id, conn)
    return success_response("Response action updated successfully", saved)


@app.delete(BASE_ROUTE + "/<item_id>")
@roles_required(config.ROLE_ADMIN, service=SERVICE)
def delete_playbook(item_id):
    """Delete a playbook and its actions (200); administrator only.

    Execution history and audit records survive deletion. Users, incidents,
    assets and notifications are unaffected. Missing playbooks return 404.
    """
    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        item = find_playbook(item_id, conn)
        repository.delete_playbook(item["playbook_id"], conn)
        log_event(g.current_user["user_id"], "Playbook deleted",
                  f"Playbook {item['playbook_id']} and its response actions deleted; "
                  "execution history retained", "Warning", SERVICE, conn)
    return success_response("Playbook deleted successfully")


if __name__ == "__main__":
    app.run(port=config.PORTS[SERVICE])
