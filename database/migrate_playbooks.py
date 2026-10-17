"""Upgrade the original Service 9 placeholder tables without replacing other data."""

from common import config
from common.db import get_connection, init_schema


def _create_upgrade_table(conn, name):
    with open(config.SCHEMA_PATH, encoding="utf-8") as source:
        schema = source.read()
    start = schema.index(f"CREATE TABLE IF NOT EXISTS {name} (")
    statement = schema[start:schema.index(";", start)]
    statement = statement.replace(f"IF NOT EXISTS {name}", f"{name}_upgrade", 1)
    if name == "response_actions":
        statement = statement.replace("REFERENCES playbooks(", "REFERENCES playbooks_upgrade(")
    conn.execute(statement)


def migrate_playbooks():
    """Keep legacy IDs, titles, actions and dates; assign deterministic step order.

    The old schema stored no severity or required category. Legacy records use
    Low / Uncategorized until a suitable replacement playbook is created.
    Unknown legacy completion dates remain NULL rather than being fabricated.
    """
    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(playbooks)")}
        if "playbook_name" in columns and "severity_level" in columns:
            return

        _create_upgrade_table(conn, "playbooks")
        _create_upgrade_table(conn, "response_actions")
        conn.execute(
            "INSERT INTO playbooks_upgrade "
            "(playbook_id, playbook_name, description, incident_category, severity_level, "
            "created_by, created_at) "
            "SELECT playbook_id, title, description, "
            "COALESCE(NULLIF(trim(incident_category), ''), 'Uncategorized'), "
            "'Low', created_by, created_at FROM playbooks"
        )
        steps = {}
        for row in conn.execute("SELECT * FROM response_actions ORDER BY playbook_id, action_id"):
            number = steps.get(row["playbook_id"], 0) + 1
            steps[row["playbook_id"]] = number
            conn.execute(
                "INSERT INTO response_actions_upgrade "
                "(action_id, playbook_id, action_description, step_number, status, updated_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (row["action_id"], row["playbook_id"], row["action_description"],
                 number, row["status"], row["updated_at"]),
            )
            conn.execute(
                "INSERT INTO response_action_history "
                "(action_id, playbook_id, action_description, step_number, status, changed_at) "
                "VALUES (?, ?, ?, ?, ?, ?)",
                (row["action_id"], row["playbook_id"], row["action_description"],
                 number, row["status"], row["updated_at"]),
            )
        for name in ("response_actions", "playbooks"):
            sequence = conn.execute("SELECT seq FROM sqlite_sequence WHERE name = ?", (name,)).fetchone()
            if sequence is not None:
                upgraded = conn.execute("SELECT seq FROM sqlite_sequence WHERE name = ?",
                                        (name + "_upgrade",)).fetchone()
                if upgraded is None:
                    conn.execute("INSERT INTO sqlite_sequence (name, seq) VALUES (?, ?)",
                                 (name + "_upgrade", sequence["seq"]))
                else:
                    conn.execute("UPDATE sqlite_sequence SET seq = max(seq, ?) WHERE name = ?",
                                 (sequence["seq"], name + "_upgrade"))
            conn.execute(f"DROP TABLE {name}")
        conn.execute("ALTER TABLE playbooks_upgrade RENAME TO playbooks")
        conn.execute("ALTER TABLE response_actions_upgrade RENAME TO response_actions")


if __name__ == "__main__":
    init_schema()
    migrate_playbooks()
