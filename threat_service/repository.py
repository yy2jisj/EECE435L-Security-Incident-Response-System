from common.db import execute, fetch_all, fetch_one

SELECT_THREAT = (
    "SELECT threat_id, threat_type, threat_value, description, severity_level, "
    "source, date_added FROM threats"
)


def _like(text):
    """Build a 'contains' pattern, treating % and _ in the text as normal characters."""
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return "%" + escaped + "%"


def insert_threat(threat):
    """Save a validated Threat and return its new threat_id.

    :raises sqlite3.IntegrityError: if the same type and value already exist.
    """
    return execute(
        "INSERT INTO threats (threat_type, threat_value, description, "
        "severity_level, source) VALUES (?, ?, ?, ?, ?)",
        (threat.threat_type, threat.threat_value, threat.description,
         threat.severity_level, threat.source),
    )


def get_by_id(threat_id, conn=None):
    return fetch_one(SELECT_THREAT + " WHERE threat_id = ?", (threat_id,), conn)


def get_all():
    return fetch_all(SELECT_THREAT + " ORDER BY threat_id")


def find_duplicate(threat_type, threat_value):
    """Return the existing threat with this type and value, or None.

    The value is compared ignoring upper and lower case, so "Trojan.X" and
    "trojan.x" count as the same indicator.
    """
    return fetch_one(
        SELECT_THREAT + " WHERE threat_type = ? AND LOWER(threat_value) = LOWER(?)",
        (threat_type, threat_value),
    )


def search(filters):
    """Find threats matching every filter that was given.

    Type and severity must match exactly. Value and source match part of the text.
    """
    query = SELECT_THREAT + " WHERE 1 = 1"
    params = []

    if "threat_type" in filters:
        query += " AND threat_type = ?"
        params.append(filters["threat_type"])
    if "severity_level" in filters:
        query += " AND severity_level = ?"
        params.append(filters["severity_level"])
    if "threat_value" in filters:
        query += " AND threat_value LIKE ? ESCAPE '\\'"
        params.append(_like(filters["threat_value"]))
    if "source" in filters:
        query += " AND source LIKE ? ESCAPE '\\'"
        params.append(_like(filters["source"]))

    query += " ORDER BY threat_id"
    return fetch_all(query, tuple(params))


def update_threat(threat_id, fields):
    """Update the given fields. The column names come from our own code only."""
    columns = ", ".join(f"{name} = ?" for name in fields)
    execute(f"UPDATE threats SET {columns} WHERE threat_id = ?",
            (*fields.values(), threat_id))


def delete_threat(threat_id):
    """Delete a threat and return the number of rows removed."""
    return execute("DELETE FROM threats WHERE threat_id = ?", (threat_id,))
