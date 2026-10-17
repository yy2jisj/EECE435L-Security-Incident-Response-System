from common.db import execute, fetch_all, fetch_one

SELECT_LOG = (
    "SELECT log_id, user_id, action, description, timestamp, severity_level, "
    "related_service FROM logs"
)


def insert_log(log):
    """Save a validated AuditLog and return its new log_id."""
    return execute(
        "INSERT INTO logs (user_id, action, description, severity_level, "
        "related_service) VALUES (?, ?, ?, ?, ?)",
        (log.user_id, log.action, log.description, log.severity_level,
         log.related_service),
    )


def get_by_id(log_id):
    return fetch_one(SELECT_LOG + " WHERE log_id = ?", (log_id,))


def get_all():
    return fetch_all(SELECT_LOG + " ORDER BY log_id")


def user_exists(user_id):
    return fetch_one("SELECT 1 FROM users WHERE user_id = ?", (user_id,)) is not None
