import sqlite3

from flask import Flask, g

from common import config
from common.audit import log_event
from common.auth import roles_required
from common.errors import ApiError, register_error_handlers, success_response
from common.validators import (
    check_fields, choice, clean_text, get_json_body, read_filters,
)
from threat_service import repository
from threat_service.models import SEVERITY_LEVELS, THREAT_TYPES, Threat
from threat_service.models import threat_id as threat_id_from_url

SERVICE = "threats"
SEARCH_PARAMETERS = ("threat_type", "threat_value", "severity_level", "source")

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


@app.get("/threats/search")
@roles_required(config.ROLE_ADMIN, config.ROLE_ANALYST, service=SERVICE)
def search_threats():
    """Search threats by type, value, severity level or source.

    Filters can be combined. Value and source match part of the text.
    This route is declared before /threats/<threat_id> so "search" is not read as an id.

    Implemented by: Leen Abdallah
    """
    filters = read_filters(SEARCH_PARAMETERS)
    # check each filter the same way as when adding a threat
    if "threat_type" in filters:
        filters["threat_type"] = choice(filters["threat_type"], "threat_type", THREAT_TYPES)
    if "severity_level" in filters:
        filters["severity_level"] = choice(
            filters["severity_level"], "severity_level", SEVERITY_LEVELS)
    if "threat_value" in filters:
        filters["threat_value"] = clean_text(filters["threat_value"], "threat_value", 255)
    if "source" in filters:
        filters["source"] = clean_text(filters["source"], "source", 100)

    threats = repository.search(filters)
    return success_response(f"{len(threats)} threat(s) found", threats)


@app.get("/threats")
@roles_required(config.ROLE_ADMIN, config.ROLE_ANALYST, config.ROLE_AUDITOR,
                service=SERVICE)
def get_all_threats():
    """Return every threat indicator (Administrator, Analyst and Auditor).

    Implemented by: Leen Abdallah
    """
    return success_response("Threats retrieved successfully", repository.get_all())


@app.get("/threats/<threat_id>")
@roles_required(config.ROLE_ADMIN, config.ROLE_ANALYST, config.ROLE_AUDITOR,
                service=SERVICE)
def get_threat(threat_id):
    """Return one threat indicator (Administrator, Analyst and Auditor).

    Implemented by: Leen Abdallah
    """
    threat_id = threat_id_from_url(threat_id)
    threat = repository.get_by_id(threat_id)
    if threat is None:
        raise ApiError("Threat not found", 404)
    return success_response("Threat retrieved successfully", threat)


@app.put("/threats/<threat_id>")
@roles_required(config.ROLE_ADMIN, service=SERVICE)
def update_threat(threat_id):
    """Update the description, severity level and/or source of a threat.

    The threat type and value identify the indicator, so they cannot be changed.
    (Security Administrator only.)

    Implemented by: Leen Abdallah
    """
    caller = g.current_user
    threat_id = threat_id_from_url(threat_id)

    data = get_json_body()
    check_fields(data, allowed=["description", "severity_level", "source"])

    if repository.get_by_id(threat_id) is None:
        raise ApiError("Threat not found", 404)

    # check each field the same way as when adding a threat
    fields = {}
    if "description" in data:
        fields["description"] = clean_text(data["description"], "description", 500)
    if "severity_level" in data:
        fields["severity_level"] = choice(
            data["severity_level"], "severity_level", SEVERITY_LEVELS)
    if "source" in data:
        fields["source"] = clean_text(data["source"], "source", 100)

    repository.update_threat(threat_id, fields)
    log_event(caller["user_id"], "Threat updated",
              f"Threat {threat_id} updated fields: {', '.join(fields)}",
              "Information", SERVICE)
    return success_response("Threat updated successfully", repository.get_by_id(threat_id))


@app.delete("/threats/<threat_id>")
@roles_required(config.ROLE_ADMIN, service=SERVICE)
def delete_threat(threat_id):
    """Delete a threat indicator (Security Administrator only).

    Implemented by: Leen Abdallah
    """
    caller = g.current_user
    threat_id = threat_id_from_url(threat_id)

    threat = repository.get_by_id(threat_id)
    if threat is None:
        raise ApiError("Threat not found", 404)

    repository.delete_threat(threat_id)
    log_event(caller["user_id"], "Threat deleted",
              f"Threat {threat['threat_type']} '{threat['threat_value']}' "
              f"(id {threat_id}) deleted", "Warning", SERVICE)
    return success_response("Threat deleted successfully")


if __name__ == "__main__":
    app.run(port=config.PORTS["threats"])
