from common.db import execute, fetch_all, fetch_one

# the owner's name comes from the users table
SELECT_ASSET = (
    "SELECT a.asset_id, a.asset_name, a.asset_type, a.ip_address, "
    "a.operating_system, a.department, a.owner_id, u.full_name AS owner_name, "
    "a.location, a.criticality_level, a.status, a.created_at "
    "FROM assets a JOIN users u ON u.user_id = a.owner_id"
)


def owner_exists(owner_id):
    row = fetch_one("SELECT user_id FROM users WHERE user_id = ?", (owner_id,))
    return row is not None


def insert_asset(asset):
    """Save a validated Asset and return its new asset_id."""
    return execute(
        "INSERT INTO assets (asset_name, asset_type, ip_address, operating_system, "
        "department, owner_id, location, criticality_level, status) "
        "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
        (asset.asset_name, asset.asset_type, asset.ip_address,
         asset.operating_system, asset.department, asset.owner_id,
         asset.location, asset.criticality_level, asset.status),
    )


def get_by_id(asset_id):
    return fetch_one(SELECT_ASSET + " WHERE a.asset_id = ?", (asset_id,))


def get_all():
    return fetch_all(SELECT_ASSET + " ORDER BY a.asset_id")


def get_incidents(asset_id):
    return fetch_all(
        "SELECT incident_id, title, severity_level, status, creation_date "
        "FROM incidents WHERE asset_id = ?", (asset_id,))


def get_vulnerabilities(asset_id):
    return fetch_all(
        "SELECT vulnerability_id, title, cve_id, severity_level, status "
        "FROM vulnerabilities WHERE asset_id = ?", (asset_id,))


def search(filters):
    """Find assets matching every filter that was given."""
    query = SELECT_ASSET + " WHERE 1 = 1"
    params = []

    # name and department can match part of the text, the others must match exactly
    if "asset_name" in filters:
        query += " AND a.asset_name LIKE ?"
        params.append("%" + filters["asset_name"] + "%")
    if "department" in filters:
        query += " AND a.department LIKE ?"
        params.append("%" + filters["department"] + "%")
    if "asset_type" in filters:
        query += " AND a.asset_type = ?"
        params.append(filters["asset_type"])
    if "ip_address" in filters:
        query += " AND a.ip_address = ?"
        params.append(filters["ip_address"])
    if "criticality_level" in filters:
        query += " AND a.criticality_level = ?"
        params.append(filters["criticality_level"])

    query += " ORDER BY a.asset_id"
    return fetch_all(query, tuple(params))


def update_asset(asset_id, fields):
    """Update the given fields. The column names come from our own code only."""
    columns = ", ".join(f"{name} = ?" for name in fields)
    execute(f"UPDATE assets SET {columns} WHERE asset_id = ?",
            (*fields.values(), asset_id))


def delete_asset(asset_id):
    return execute("DELETE FROM assets WHERE asset_id = ?", (asset_id,))
