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
from playbook_service.models import Playbook, playbook_id

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
