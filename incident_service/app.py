from flask import Flask, g, request

from asset_service import repository as assets
from common import config
from common.audit import log_event
from common.auth import deny, roles_required
from common.db import get_connection
from common.errors import ApiError, error_response, register_error_handlers, success_response
from common.validators import check_fields, choice, get_json_body
from incident_service import repository
from incident_service.models import (
    NEXT_STATUS, STATUSES, Incident, incident_id, investigation_note,
)
from user_service import repository as users

SERVICE = "incidents"
BASE_ROUTE = "/Youssef-Al-Hajj-Youness/incidents"

app = Flask(__name__)
register_error_handlers(app)


class IncidentAccessError(ApiError):
    """Defer permission logging until a write transaction has rolled back."""

    def __init__(self, message):
        super().__init__(message, 403)


@app.errorhandler(IncidentAccessError)
def handle_incident_access_error(error):
    log_event(g.current_user["user_id"], "Unauthorized access attempt",
              f"{request.method} {request.path}: {error.message}", "Warning", SERVICE)
    return error_response(error.message, error.status_code)


def find_incident(value, conn=None):
    """Employees see their reports; analysts see their assigned incidents."""
    item = repository.get_by_id(incident_id(value), conn)
    caller = g.current_user
    if caller["role"] == config.ROLE_USER:
        if item is None or item["reporter_id"] != caller["user_id"]:
            raise IncidentAccessError("You can only view your own submitted incidents")
    if caller["role"] == config.ROLE_ANALYST:
        if item is None or item["assigned_analyst_id"] != caller["user_id"]:
            raise IncidentAccessError("You can only access incidents assigned to you")
    if item is None:
        raise ApiError("Incident not found", 404)
    return item


@app.post(BASE_ROUTE)
@roles_required(config.ROLE_ADMIN, config.ROLE_USER, service=SERVICE)
def create_incident():
    """Report an incident. Implemented by: Youssef Al Hajj Youness."""
    data = get_json_body()
    check_fields(data, required=["title", "description", "category", "severity_level",
                                 "reporter_id", "asset_id"])
    incident = Incident(**data)
    caller = g.current_user
    if caller["role"] == config.ROLE_USER and incident.reporter_id != caller["user_id"]:
        deny(caller, "You can only report incidents as yourself", SERVICE)

    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if users.get_by_id(incident.reporter_id, conn) is None:
            raise ApiError("Reporter not found", 404)
        if assets.get_by_id(incident.asset_id, conn) is None:
            raise ApiError("Asset not found", 404)
        new_id = repository.insert_incident(incident, conn)
        log_event(caller["user_id"], "Incident created",
                  f"Incident {new_id} reported by user {incident.reporter_id} "
                  f"for asset {incident.asset_id}", "Information", SERVICE, conn)
        item = repository.get_by_id(new_id, conn)
    return success_response("Incident created successfully", item, 201)


@app.get(BASE_ROUTE)
@roles_required(config.ROLE_ADMIN, config.ROLE_AUDITOR, service=SERVICE)
def get_all_incidents():
    """Retrieve all incidents. Implemented by: Youssef Al Hajj Youness."""
    return success_response("Incidents retrieved successfully", repository.get_all())


@app.get(BASE_ROUTE + "/<item_id>")
@roles_required(*config.ALL_ROLES, service=SERVICE)
def get_incident(item_id):
    """Retrieve an incident and its notes. Implemented by: Youssef Al Hajj Youness."""
    return success_response("Incident retrieved successfully", find_incident(item_id))


@app.put(BASE_ROUTE + "/<item_id>/status")
@roles_required(config.ROLE_ADMIN, config.ROLE_ANALYST, service=SERVICE)
def update_incident_status(item_id):
    """Advance one lifecycle step. Implemented by: Youssef Al Hajj Youness."""
    data = get_json_body()
    check_fields(data, required=["status"])
    status = choice(data["status"], "status", STATUSES)
    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        item = find_incident(item_id, conn)
        if NEXT_STATUS.get(item["status"]) != status:
            raise ApiError(f"Cannot change incident status from {item['status']} to {status}", 409)
        repository.update_status(item["incident_id"], status, conn)
        log_event(g.current_user["user_id"], "Incident status updated",
                  f"Incident {item['incident_id']}: {item['status']} -> {status}",
                  "Information", SERVICE, conn)
        updated = repository.get_by_id(item["incident_id"], conn)
    return success_response("Incident status updated successfully", updated)


@app.post(BASE_ROUTE + "/<item_id>/notes")
@roles_required(config.ROLE_ADMIN, config.ROLE_ANALYST, service=SERVICE)
def add_investigation_note(item_id):
    """Add a note as the caller. Implemented by: Youssef Al Hajj Youness."""
    data = get_json_body()
    check_fields(data, required=["note_content"])
    content = investigation_note(data["note_content"])
    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        item = find_incident(item_id, conn)
        note = repository.insert_note(item["incident_id"], g.current_user["user_id"],
                                      content, conn)
        log_event(g.current_user["user_id"], "Investigation note added",
                  f"Note {note['note_id']} added to incident {item['incident_id']}",
                  "Information", SERVICE, conn)
    return success_response("Investigation note added successfully", note, 201)


if __name__ == "__main__":
    app.run(port=config.PORTS[SERVICE])
