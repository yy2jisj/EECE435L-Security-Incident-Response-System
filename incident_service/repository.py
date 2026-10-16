"""Incident and investigation-note queries on the existing shared database."""

from common.db import execute, fetch_all, fetch_one

PUBLIC_COLUMNS = (
    "incident_id, title, description, category, severity_level, reporter_id, "
    "asset_id, assigned_analyst_id, status, creation_date, resolution_date"
)


def insert_incident(incident, conn):
    return execute(
        "INSERT INTO incidents "
        "(title, description, category, severity_level, reporter_id, asset_id) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (incident.title, incident.description, incident.category,
         incident.severity_level, incident.reporter_id, incident.asset_id), conn,
    )


def get_by_id(incident_id, conn=None):
    item = fetch_one(f"SELECT {PUBLIC_COLUMNS} FROM incidents WHERE incident_id = ?",
                     (incident_id,), conn)
    if item is not None:
        item["investigation_notes"] = fetch_all(
            "SELECT note_id, incident_id, analyst_id, note_content, created_at "
            "FROM investigation_notes WHERE incident_id = ? ORDER BY note_id",
            (incident_id,), conn,
        )
    return item


def get_all():
    return fetch_all(f"SELECT {PUBLIC_COLUMNS} FROM incidents ORDER BY incident_id")


def update_status(incident_id, status, conn):
    """Stamp the resolution date on resolution and preserve it when closing."""
    execute(
        "UPDATE incidents SET status = ?, resolution_date = "
        "CASE WHEN ? = 'Resolved' THEN date('now') ELSE resolution_date END "
        "WHERE incident_id = ?", (status, status, incident_id), conn,
    )


def assign_analyst(incident_id, analyst_id, conn):
    execute("UPDATE incidents SET assigned_analyst_id = ? WHERE incident_id = ?",
            (analyst_id, incident_id), conn)


def insert_note(incident_id, analyst_id, note_content, conn):
    new_id = execute(
        "INSERT INTO investigation_notes (incident_id, analyst_id, note_content) "
        "VALUES (?, ?, ?)", (incident_id, analyst_id, note_content), conn,
    )
    return fetch_one(
        "SELECT note_id, incident_id, analyst_id, note_content, created_at "
        "FROM investigation_notes WHERE note_id = ?", (new_id,), conn,
    )
