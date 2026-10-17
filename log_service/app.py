import sqlite3

from flask import Flask, g

from common import config
from common.audit import log_event
from common.auth import roles_required
from common.errors import ApiError, ValidationError, register_error_handlers, success_response
from common.validators import (
    check_fields, choice, clean_text, get_json_body, read_filters,
)
from log_service import repository
from log_service.models import SEVERITY_LEVELS, AuditLog, search_date
from log_service.models import log_id as log_id_from_url
from log_service.models import user_id as user_id_from_url

SERVICE = "logs"
BASE_ROUTE = "/leen-abdallah/logs"
SEARCH_PARAMETERS = ("user_id", "date", "action", "severity_level", "related_service")

app = Flask(__name__)
register_error_handlers(app)


@app.post(BASE_ROUTE)
@roles_required(config.ROLE_ADMIN, service=SERVICE)
def create_log():
    """Create an audit log record (Security Administrator only).

    The log id and timestamp are set by the system. Logs cannot be changed later.

    Implemented by: Leen Abdallah
    """
    data = get_json_body()
    check_fields(
        data,
        required=["user_id", "action", "description", "severity_level",
                  "related_service"],
    )
    log = AuditLog(
        data["user_id"], data["action"], data["description"],
        data["severity_level"], data["related_service"],
    )

    if not repository.user_exists(log.user_id):
        raise ValidationError("user_id does not match any existing user")

    try:
        new_id = repository.insert_log(log)
    except sqlite3.IntegrityError:
        # the user was deleted between the check and the insert
        raise ValidationError("user_id does not match any existing user")

    return success_response("Log created successfully", repository.get_by_id(new_id), 201)


@app.get(BASE_ROUTE + "/search")
@roles_required(config.ROLE_ADMIN, config.ROLE_AUDITOR, config.ROLE_ANALYST,
                service=SERVICE)
def search_logs():
    """Search logs by user, date, action, severity level and/or related service.

    Filters can be combined. Action and related service match part of the text.
    This route is declared before the /<log_id> route so "search" is not read as an id.

    Implemented by: Leen Abdallah
    """
    filters = read_filters(SEARCH_PARAMETERS)
    # check each filter the same way as when creating a log
    if "user_id" in filters:
        filters["user_id"] = user_id_from_url(filters["user_id"])
    if "date" in filters:
        filters["date"] = search_date(filters["date"])
    if "action" in filters:
        filters["action"] = clean_text(filters["action"], "action", 100)
    if "severity_level" in filters:
        filters["severity_level"] = choice(
            filters["severity_level"], "severity_level", SEVERITY_LEVELS)
    if "related_service" in filters:
        filters["related_service"] = clean_text(
            filters["related_service"], "related_service", 50)

    logs = repository.search(filters)
    return success_response(f"{len(logs)} log(s) found", logs)


@app.get(BASE_ROUTE + "/user/<user_id>")
@roles_required(config.ROLE_ADMIN, config.ROLE_AUDITOR, service=SERVICE)
def get_logs_by_user(user_id):
    """Return every log written for one user (Administrator and Auditor).

    A user with no logs gives an empty list; an unknown user gives 404.

    Implemented by: Leen Abdallah
    """
    user_id = user_id_from_url(user_id)
    if not repository.user_exists(user_id):
        raise ApiError("User not found", 404)
    logs = repository.get_by_user(user_id)
    return success_response(f"{len(logs)} log(s) found for user {user_id}", logs)


@app.get(BASE_ROUTE)
@roles_required(config.ROLE_ADMIN, config.ROLE_AUDITOR, service=SERVICE)
def get_all_logs():
    """Return every audit log (Administrator and Auditor).

    Implemented by: Leen Abdallah
    """
    return success_response("Logs retrieved successfully", repository.get_all())


@app.get(BASE_ROUTE + "/<log_id>")
@roles_required(config.ROLE_ADMIN, config.ROLE_AUDITOR, config.ROLE_ANALYST,
                service=SERVICE)
def get_log(log_id):
    """Return one audit log (Administrator, Auditor and Analyst).

    Implemented by: Leen Abdallah
    """
    log_id = log_id_from_url(log_id)
    log = repository.get_by_id(log_id)
    if log is None:
        raise ApiError("Log not found", 404)
    return success_response("Log retrieved successfully", log)


@app.delete(BASE_ROUTE + "/<log_id>")
@roles_required(config.ROLE_ADMIN, service=SERVICE)
def delete_log(log_id):
    """Delete an audit log (Security Administrator only).

    The deletion itself is recorded as a new log, so it can be traced.

    Implemented by: Leen Abdallah
    """
    caller = g.current_user
    log_id = log_id_from_url(log_id)

    log = repository.get_by_id(log_id)
    if log is None:
        raise ApiError("Log not found", 404)

    repository.delete_log(log_id)
    log_event(caller["user_id"], "Log deleted",
              f"Log {log_id} ('{log['action']}', {log['related_service']}) deleted",
              "Warning", SERVICE)
    return success_response("Log deleted successfully")


if __name__ == "__main__":
    app.run(port=config.PORTS["logs"])
