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


def get_by_user(user_id):
    return fetch_all(SELECT_LOG + " WHERE user_id = ? ORDER BY log_id", (user_id,))


def _like(text):
    """Build a 'contains' pattern, treating % and _ in the text as normal characters."""
    escaped = text.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return "%" + escaped + "%"


def search(filters):
    """Find logs matching every filter that was given.

    User, date and severity must match exactly (the date is compared with the
    day part of the timestamp). Action and related service match part of the text.
    """
    query = SELECT_LOG + " WHERE 1 = 1"
    params = []

    if "user_id" in filters:
        query += " AND user_id = ?"
        params.append(filters["user_id"])
    if "date" in filters:
        query += " AND date(timestamp) = ?"
        params.append(filters["date"])
    if "severity_level" in filters:
        query += " AND severity_level = ?"
        params.append(filters["severity_level"])
    if "action" in filters:
        query += " AND action LIKE ? ESCAPE '\\'"
        params.append(_like(filters["action"]))
    if "related_service" in filters:
        query += " AND related_service LIKE ? ESCAPE '\\'"
        params.append(_like(filters["related_service"]))

    query += " ORDER BY log_id"
    return fetch_all(query, tuple(params))


def delete_log(log_id):
    """Delete a log and return the number of rows removed."""
    return execute("DELETE FROM logs WHERE log_id = ?", (log_id,))
