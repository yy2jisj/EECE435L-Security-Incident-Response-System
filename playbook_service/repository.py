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


def step_exists(item_id, step_number, conn):
    return fetch_one("SELECT action_id FROM response_actions "
                     "WHERE playbook_id = ? AND step_number = ?",
                     (item_id, step_number), conn) is not None


def insert_action(item_id, action, conn):
    return execute(
        "INSERT INTO response_actions (playbook_id, action_description, step_number) "
        "VALUES (?, ?, ?)", (item_id, action.action_description, action.step_number), conn,
    )


def get_action(action_id, conn):
    return fetch_one(f"SELECT {ACTION_COLUMNS} FROM response_actions WHERE action_id = ?",
                     (action_id,), conn)


def update_action(action_id, fields, conn):
    execute(
        "UPDATE response_actions SET status = ?, assigned_user_id = ?, "
        "completion_date = ?, updated_at = datetime('now') WHERE action_id = ?",
        (fields["status"], fields["assigned_user_id"], fields["completion_date"], action_id), conn,
    )


def record_action_history(action_id, changed_by, conn):
    """Keep a state snapshot even after the live action/playbook is deleted."""
    execute(
        "INSERT INTO response_action_history "
        "(action_id, playbook_id, action_description, step_number, status, "
        "assigned_user_id, completion_date, changed_by) "
        "SELECT action_id, playbook_id, action_description, step_number, status, "
        "assigned_user_id, completion_date, ? FROM response_actions WHERE action_id = ?",
        (changed_by, action_id), conn,
    )
