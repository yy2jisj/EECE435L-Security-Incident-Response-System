"""Create the database and its tables.

Run from the project root:  python -m database.init_db
"""
from common import config
from common.db import init_schema


def main():
    """Create the schema in the database file."""
    init_schema()
    print(f"Database ready at {config.DB_PATH}")


if __name__ == "__main__":
    main()
