import sqlite3

from flask import Flask, g

from common import config
from common.auth import roles_required
from common.errors import ApiError, ValidationError, register_error_handlers, success_response
from common.validators import check_fields, get_json_body
from log_service import repository
from log_service.models import AuditLog
from log_service.models import log_id as log_id_from_url

SERVICE = "logs"
BASE_ROUTE = "/leen-abdallah/logs"

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


if __name__ == "__main__":
    app.run(port=config.PORTS["logs"])
