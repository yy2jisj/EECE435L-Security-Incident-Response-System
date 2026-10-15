"""Parameterized notification queries on the existing shared database."""

import sqlite3

from common.db import execute, fetch_all, fetch_one, get_connection
from common.errors import ApiError

PUBLIC_COLUMNS = (
    "notification_id, user_id, title, message, notification_type, severity_level, "
    "CASE is_read WHEN 0 THEN 'Unread' ELSE 'Read' END AS status, created_at, read_date"
)


def insert_notification(notification):
    """Save a validated Notification and return its ID for API/future callers."""
    with get_connection() as conn:
        conn.execute("BEGIN IMMEDIATE")
        if fetch_one("SELECT user_id FROM users WHERE user_id = ?",
                     (notification.user_id,), conn) is None:
            raise ApiError("User not found", 404)
        try:
            return execute(
                "INSERT INTO notifications "
                "(user_id, title, message, notification_type, severity_level) VALUES (?, ?, ?, ?, ?)",
                (notification.user_id, notification.title, notification.message,
                 notification.notification_type, notification.severity_level), conn,
            )
        except sqlite3.IntegrityError:
            raise ApiError("Notification could not be saved", 409)


def get_by_id(notification_id):
    return fetch_one(f"SELECT {PUBLIC_COLUMNS} FROM notifications WHERE notification_id = ?",
                     (notification_id,))


def get_for_user(user_id):
    return fetch_all(f"SELECT {PUBLIC_COLUMNS} FROM notifications WHERE user_id = ? "
                     "ORDER BY notification_id", (user_id,))
