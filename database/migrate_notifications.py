"""Add Service 8 fields without replacing existing notifications."""

from common.db import get_connection


def migrate_notifications():
    """Upgrade the original table; repeated runs preserve data and timestamps.

    Legacy records receive System Notification / Low compatibility defaults.
    Their historical read time is unknown, so read_date stays NULL.
    """
    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        columns = {row["name"] for row in conn.execute("PRAGMA table_info(notifications)")}
        additions = {
            "notification_type": "TEXT NOT NULL DEFAULT 'System Notification' "
                                 "CHECK (notification_type IN ('Incident Assignment', "
                                 "'Security Alert', 'System Notification', 'Threat Alert', "
                                 "'Vulnerability Alert'))",
            "severity_level": "TEXT NOT NULL DEFAULT 'Low' "
                              "CHECK (severity_level IN ('Low', 'Medium', 'High', 'Critical'))",
            "read_date": "TEXT",
        }
        for name, definition in additions.items():
            if name not in columns:
                conn.execute(f"ALTER TABLE notifications ADD COLUMN {name} {definition}")


if __name__ == "__main__":
    migrate_notifications()
