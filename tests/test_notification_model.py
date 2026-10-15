import sqlite3
import unittest

from common.db import fetch_one, get_connection
from common.errors import ApiError, ValidationError
from database.migrate_notifications import migrate_notifications
from notification_service.models import Notification, notification_id
from notification_service import repository
from tests.support import DatabaseTest


class NotificationModelTests(DatabaseTest):
    def test_insert_defaults_and_user_relationship(self):
        new_id = repository.insert_notification(Notification(**self.payload()))
        row = repository.get_by_id(new_id)
        self.assertEqual(row["status"], "Unread")
        self.assertIsNone(row["read_date"])
        self.assertIsNotNone(row["created_at"])
        self.assertEqual(row["user_id"], self.people["employee"]["user_id"])
        self.assertEqual(fetch_one("SELECT COUNT(*) AS n FROM notifications")["n"], 1)

    def test_invalid_recipient_does_not_insert(self):
        with self.assertRaises(ApiError):
            repository.insert_notification(Notification(**self.payload(user_id=99999)))
        self.assertEqual(fetch_one("SELECT COUNT(*) AS n FROM notifications")["n"], 0)

    def test_database_foreign_key_and_choices(self):
        for user_id, kind, severity in ((99999, "Security Alert", "High"),
                                       (1, "Unknown", "High"), (1, "Security Alert", "Urgent")):
            with self.subTest(user_id=user_id, kind=kind, severity=severity):
                with self.assertRaises(sqlite3.IntegrityError), get_connection() as conn:
                    conn.execute("INSERT INTO notifications "
                                 "(user_id,title,message,notification_type,severity_level) "
                                 "VALUES (?, 'Test', 'Test', ?, ?)", (user_id, kind, severity))

    def test_validation_boundaries(self):
        for changes in ({"user_id": True}, {"user_id": "2"}, {"title": " "},
                        {"message": []}, {"title": "a" * 256}, {"message": "a" * 4001},
                        {"notification_type": "Other"}, {"severity_level": "Urgent"}):
            with self.subTest(changes=changes), self.assertRaises(ValidationError):
                Notification(**self.payload(**changes))
        valid = Notification(**self.payload(title="a" * 255, message="a" * 4000))
        self.assertEqual(len(valid.message), 4000)
        self.assertEqual(notification_id("0" * 5000 + "1"), 1)
        for value in ("0", "-1", "1.1", "abc", "9223372036854775808", "9" * 5000):
            with self.subTest(value=value[:30]), self.assertRaises(ValidationError):
                notification_id(value)

    def test_populated_legacy_migration_is_repeatable(self):
        with get_connection() as conn:
            conn.execute("DROP TABLE notifications")
            conn.execute("CREATE TABLE notifications (notification_id INTEGER PRIMARY KEY, "
                         "user_id INTEGER NOT NULL REFERENCES users(user_id) ON DELETE CASCADE, "
                         "incident_id INTEGER REFERENCES incidents(incident_id) ON DELETE SET NULL, "
                         "title TEXT NOT NULL, message TEXT NOT NULL, is_read INTEGER DEFAULT 0, "
                         "created_at TEXT DEFAULT (datetime('now')))")
            conn.execute("INSERT INTO notifications VALUES "
                         "(41, 1, NULL, 'Legacy', 'Before upgrade', 1, '2025-01-01 12:00:00')")
        migrate_notifications()
        migrate_notifications()
        row = repository.get_by_id(41)
        self.assertEqual(row["status"], "Read")
        self.assertEqual(row["created_at"], "2025-01-01 12:00:00")
        self.assertIsNone(row["read_date"])
        self.assertEqual(row["notification_type"], "System Notification")
        self.assertEqual(row["severity_level"], "Low")

    def test_optional_incident_link_keeps_set_null_behavior(self):
        new_id = repository.insert_notification(Notification(**self.payload()))
        with get_connection() as conn:
            asset = conn.execute("INSERT INTO assets "
                                 "(asset_name,asset_type,ip_address,department,owner_id,criticality_level) "
                                 "VALUES ('QA server','Server','127.0.0.1','QA',1,'High')").lastrowid
            incident = conn.execute("INSERT INTO incidents "
                                    "(title,description,category,severity_level,reporter_id,asset_id) "
                                    "VALUES ('QA','Test','Other','High',1,?)", (asset,)).lastrowid
            conn.execute("UPDATE notifications SET incident_id=? WHERE notification_id=?", (incident, new_id))
            conn.execute("DELETE FROM incidents WHERE incident_id=?", (incident,))
        row = fetch_one("SELECT * FROM notifications WHERE notification_id=?", (new_id,))
        self.assertIsNone(row["incident_id"])
        self.assertEqual(row["is_read"], 0)


if __name__ == "__main__":
    unittest.main()
