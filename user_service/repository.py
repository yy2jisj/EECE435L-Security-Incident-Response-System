from common.db import execute, fetch_all, fetch_one

PUBLIC_COLUMNS = (
    "user_id, full_name, username, email, department, role, "
    "account_status, created_at, last_login"
)


def username_exists(username):
    row = fetch_one(
        "SELECT user_id FROM users WHERE username = ? COLLATE NOCASE", (username,)
    )
    return row is not None


def email_exists(email):
    row = fetch_one("SELECT user_id FROM users WHERE email = ?", (email,))
    return row is not None


def insert_user(user):
    """Save a validated User and return its new user_id."""
    return execute(
        "INSERT INTO users (full_name, username, email, password_hash, department, role) "
        "VALUES (?, ?, ?, ?, ?, ?)",
        (user.full_name, user.username, user.email, user.password_hash,
         user.department, user.role),
    )


def get_by_id(user_id, conn=None):
    return fetch_one(f"SELECT {PUBLIC_COLUMNS} FROM users WHERE user_id = ?", (user_id,), conn)


def find_for_login(identifier):
    """Find a user by username or email. This row includes password_hash."""
    return fetch_one(
        "SELECT * FROM users WHERE username = ? COLLATE NOCASE OR email = ?",
        (identifier, identifier.lower()),
    )


def update_last_login(user_id):
    execute("UPDATE users SET last_login = datetime('now') WHERE user_id = ?", (user_id,))


def get_by_username(username):
    return fetch_one(
        f"SELECT {PUBLIC_COLUMNS} FROM users WHERE username = ? COLLATE NOCASE",
        (username,),
    )


def get_all():
    return fetch_all(f"SELECT {PUBLIC_COLUMNS} FROM users ORDER BY user_id")


def email_taken_by_other(email, user_id):
    row = fetch_one(
        "SELECT user_id FROM users WHERE email = ? AND user_id != ?", (email, user_id)
    )
    return row is not None


def update_user(user_id, fields):
    """Update full_name, email and/or department. Column names come from code only."""
    columns = ", ".join(f"{name} = ?" for name in fields)
    execute(
        f"UPDATE users SET {columns} WHERE user_id = ?",
        (*fields.values(), user_id),
    )


def delete_user(user_id):
    return execute("DELETE FROM users WHERE user_id = ?", (user_id,))
