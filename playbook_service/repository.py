"""Parameterized Service 9 queries on the shared application database."""

from common.db import execute, fetch_all, fetch_one

PLAYBOOK_COLUMNS = (
    "playbook_id, playbook_name, description, incident_category, severity_level, "
    "created_by, created_at"
)
ACTION_COLUMNS = (
    "action_id, playbook_id, action_description, step_number, status, "
    "assigned_user_id, completion_date"
)


def insert_playbook(playbook, created_by, conn):
    return execute(
        "INSERT INTO playbooks "
        "(playbook_name, description, incident_category, severity_level, created_by) "
        "VALUES (?, ?, ?, ?, ?)",
        (playbook.playbook_name, playbook.description, playbook.incident_category,
         playbook.severity_level, created_by), conn,
    )


def get_all(conn=None):
    return fetch_all(f"SELECT {PLAYBOOK_COLUMNS} FROM playbooks ORDER BY playbook_id", conn=conn)


def get_by_id(item_id, conn):
    item = fetch_one(f"SELECT {PLAYBOOK_COLUMNS} FROM playbooks WHERE playbook_id = ?",
                     (item_id,), conn)
    if item is not None:
        item["response_actions"] = fetch_all(
            f"SELECT {ACTION_COLUMNS} FROM response_actions "
            "WHERE playbook_id = ? ORDER BY step_number, action_id", (item_id,), conn,
        )
        item["action_history"] = fetch_all(
            "SELECT * FROM response_action_history WHERE playbook_id = ? ORDER BY history_id",
            (item_id,), conn,
        )
    return item


def delete_playbook(item_id, conn):
    execute("DELETE FROM playbooks WHERE playbook_id = ?", (item_id,), conn)
