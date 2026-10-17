import sqlite3

from flask import Flask, g

from common import config
from common.audit import log_event
from common.auth import roles_required
from common.errors import ApiError, ValidationError, register_error_handlers, success_response
from common.validators import (
    check_fields, choice, clean_text, get_json_body, parse_id, read_filters, validate_ip,
)
from asset_service import repository
from asset_service.models import (
    ASSET_STATUSES, ASSET_TYPES, CRITICALITY_LEVELS, Asset, check_owner_id,
)

SERVICE = "assets"
SEARCH_PARAMETERS = ("asset_name", "asset_type", "ip_address", "department",
                     "criticality_level")

app = Flask(__name__)
register_error_handlers(app)


def check_owner_exists(owner_id):
    """Refuse an owner_id that does not belong to a real user."""
    if not repository.owner_exists(owner_id):
        raise ValidationError("owner_id does not match any existing user")


@app.post("/assets/AdamYahya")
@roles_required(config.ROLE_ADMIN, service=SERVICE)
def add_asset():
    """Add a new asset (Security Administrator only).

    Implemented by: Adam Yahya
    """
    caller = g.current_user
    data = get_json_body()
    check_fields(
        data,
        required=["asset_name", "asset_type", "ip_address", "department",
                  "owner_id", "criticality_level"],
        allowed=["operating_system", "location", "status"],
    )
    asset = Asset(
        data["asset_name"], data["asset_type"], data["ip_address"],
        data["department"], data["owner_id"], data["criticality_level"],
        data.get("operating_system"), data.get("location"),
        data.get("status", "Active"),
    )
    check_owner_exists(asset.owner_id)

    new_id = repository.insert_asset(asset)
    log_event(caller["user_id"], "Asset created",
              f"Asset '{asset.asset_name}' (id {new_id}) created with "
              f"criticality {asset.criticality_level}", "Information", SERVICE)
    return success_response("Asset created successfully",
                            repository.get_by_id(new_id), 201)


@app.get("/assets/search/AdamYahya")
@roles_required(config.ROLE_ADMIN, config.ROLE_ANALYST, config.ROLE_AUDITOR,
                service=SERVICE)
def search_assets():
    """Search assets by name, type, IP address, department or criticality.

    Filters can be combined. Name and department match part of the text.
    This route is declared before /assets/<asset_id> so "search" is not read as an id.

    Implemented by: Adam Yahya
    """
    filters = read_filters(SEARCH_PARAMETERS)
    # check each filter the same way as when creating an asset
    if "asset_name" in filters:
        filters["asset_name"] = clean_text(filters["asset_name"], "asset_name", 100)
    if "department" in filters:
        filters["department"] = clean_text(filters["department"], "department", 100)
    if "asset_type" in filters:
        filters["asset_type"] = choice(filters["asset_type"], "asset_type", ASSET_TYPES)
    if "ip_address" in filters:
        filters["ip_address"] = validate_ip(filters["ip_address"])
    if "criticality_level" in filters:
        filters["criticality_level"] = choice(
            filters["criticality_level"], "criticality_level", CRITICALITY_LEVELS)

    assets = repository.search(filters)
    return success_response(f"{len(assets)} asset(s) found", assets)


@app.get("/assets/AdamYahya")
@roles_required(config.ROLE_ADMIN, config.ROLE_AUDITOR, service=SERVICE)
def get_all_assets():
    """Return every asset (Security Administrator and Auditor only).

    Implemented by: Adam Yahya
    """
    return success_response("Assets retrieved successfully", repository.get_all())


@app.get("/assets/<asset_id>/AdamYahya")
@roles_required(config.ROLE_ADMIN, config.ROLE_ANALYST, config.ROLE_AUDITOR,
                service=SERVICE)
def get_asset(asset_id):
    """Return one asset with its related incidents and vulnerabilities.

    Implemented by: Adam Yahya
    """
    asset_id = parse_id(asset_id, "asset id")
    asset = repository.get_by_id(asset_id)
    if asset is None:
        raise ApiError("Asset not found", 404)
    asset["related_incidents"] = repository.get_incidents(asset_id)
    asset["related_vulnerabilities"] = repository.get_vulnerabilities(asset_id)
    return success_response("Asset retrieved successfully", asset)


@app.put("/assets/<asset_id>/AdamYahya")
@roles_required(config.ROLE_ADMIN, service=SERVICE)
def update_asset(asset_id):
    """Update asset_name, owner_id, department, criticality_level and/or status.

    Implemented by: Adam Yahya
    """
    caller = g.current_user
    asset_id = parse_id(asset_id, "asset id")

    data = get_json_body()
    check_fields(data, allowed=["asset_name", "owner_id", "department",
                                "criticality_level", "status"])

    if repository.get_by_id(asset_id) is None:
        raise ApiError("Asset not found", 404)

    fields = {}
    if "asset_name" in data:
        fields["asset_name"] = clean_text(data["asset_name"], "asset_name", 100)
    if "owner_id" in data:
        fields["owner_id"] = check_owner_id(data["owner_id"])
        check_owner_exists(fields["owner_id"])
    if "department" in data:
        fields["department"] = clean_text(data["department"], "department", 100)
    if "criticality_level" in data:
        fields["criticality_level"] = choice(
            data["criticality_level"], "criticality_level", CRITICALITY_LEVELS)
    if "status" in data:
        fields["status"] = choice(data["status"], "status", ASSET_STATUSES)

    repository.update_asset(asset_id, fields)
    log_event(caller["user_id"], "Asset updated",
              f"Asset {asset_id} updated fields: {', '.join(fields)}",
              "Information", SERVICE)
    return success_response("Asset updated successfully", repository.get_by_id(asset_id))


@app.delete("/assets/<asset_id>/AdamYahya")
@roles_required(config.ROLE_ADMIN, service=SERVICE)
def delete_asset(asset_id):
    """Delete an asset (Security Administrator only).

    Implemented by: Adam Yahya
    """
    caller = g.current_user
    asset_id = parse_id(asset_id, "asset id")

    asset = repository.get_by_id(asset_id)
    if asset is None:
        raise ApiError("Asset not found", 404)

    try:
        repository.delete_asset(asset_id)
    except sqlite3.IntegrityError:
        raise ApiError(
            "Asset is still referenced by incidents or vulnerabilities "
            "and cannot be deleted", 409)

    log_event(caller["user_id"], "Asset deleted",
              f"Asset '{asset['asset_name']}' (id {asset_id}) deleted",
              "Warning", SERVICE)
    return success_response("Asset deleted successfully")


if __name__ == "__main__":
    app.run(port=config.PORTS["assets"])
