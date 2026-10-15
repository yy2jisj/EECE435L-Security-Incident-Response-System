"""Create the database, its tables and the default administrator.

Run from the project root:  python -m database.init_db
"""
import os

from werkzeug.security import generate_password_hash

from common import config
from common.db import get_connection, init_schema
#change password in env
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "Admin@1234")


def create_default_admin():
    """Create the 'admin' account if it does not exist yet."""
    with get_connection() as conn:
        conn.execute(
            "INSERT OR IGNORE INTO users "
            "(full_name, username, email, password_hash, department, role) "
            "VALUES (?, ?, ?, ?, ?, ?)",
            ("System Administrator", "admin", "admin@example.com",
             generate_password_hash(ADMIN_PASSWORD), "IT Security", config.ROLE_ADMIN),
        )


def main():
    """Create the schema in the database file and the default administrator."""
    init_schema()
    create_default_admin()
    print(f"Database ready at {config.DB_PATH}")


if __name__ == "__main__":
    main()
