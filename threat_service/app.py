import sqlite3

from flask import Flask, g

from common import config
from common.audit import log_event
from common.auth import roles_required
from common.errors import ApiError, register_error_handlers, success_response
from common.validators import check_fields, get_json_body
from threat_service import repository
from threat_service.models import Threat

SERVICE = "threats"

app = Flask(__name__)
register_error_handlers(app)


@app.post("/threats")
@roles_required(config.ROLE_ADMIN, service=SERVICE)
def add_threat():
    """Add a new threat indicator (Security Administrator only).

    Implemented by: Leen Abdallah
    """
    caller = g.current_user
    data = get_json_body()
    check_fields(
        data,
        required=["threat_type", "threat_value", "description",
                  "severity_level", "source"],
    )
    threat = Threat(
        data["threat_type"], data["threat_value"], data["description"],
        data["severity_level"], data["source"],
    )

    # the same type and value can only be stored once
    if repository.find_duplicate(threat.threat_type, threat.threat_value):
        raise ApiError("A threat with the same type and value already exists", 409)

    try:
        new_id = repository.insert_threat(threat)
    except sqlite3.IntegrityError:
        # another request added the same indicator at the same moment
        raise ApiError("A threat with the same type and value already exists", 409)

    log_event(caller["user_id"], "Threat added",
              f"Threat {threat.threat_type} '{threat.threat_value}' (id {new_id}) "
              f"added with severity {threat.severity_level}", "Information", SERVICE)
    return success_response("Threat added successfully",
                            repository.get_by_id(new_id), 201)


if __name__ == "__main__":
    app.run(port=config.PORTS["threats"])
