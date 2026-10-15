import sqlite3
from contextlib import contextmanager

from common import config


@contextmanager
def get_connection():
    conn = sqlite3.connect(config.DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    try:
        yield conn
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        conn.close()


def fetch_all(query, params=(), conn=None):
    """Run a SELECT and return every row as a list of dictionaries.

    :param query: SQL text with ``?`` placeholders.
    :param params: values for the placeholders.
    :param conn: optional open connection (to share one transaction).
    """
    if conn is not None:
        return [dict(row) for row in conn.execute(query, params).fetchall()]
    with get_connection() as own:
        return [dict(row) for row in own.execute(query, params).fetchall()]


def fetch_one(query, params=(), conn=None):
    """Run a SELECT and return the first row as a dictionary, or ``None``.

    :param query: SQL text with ``?`` placeholders.
    :param params: values for the placeholders.
    :param conn: optional open connection (to share one transaction).
    """
    if conn is not None:
        row = conn.execute(query, params).fetchone()
        return dict(row) if row else None
    with get_connection() as own:
        row = own.execute(query, params).fetchone()
        return dict(row) if row else None


def execute(query, params=(), conn=None):
    """Run an INSERT, UPDATE or DELETE.

    :param query: SQL text with ``?`` placeholders.
    :param params: values for the placeholders.
    :param conn: optional open connection (the caller then commits).
    :return: ``lastrowid`` for inserts, otherwise the number of rows changed.
    """
    if conn is not None:
        cursor = conn.execute(query, params)
        return cursor.lastrowid if cursor.lastrowid else cursor.rowcount
    with get_connection() as own:
        cursor = own.execute(query, params)
        return cursor.lastrowid if cursor.lastrowid else cursor.rowcount


def init_schema():
    with open(config.SCHEMA_PATH, encoding="utf-8") as schema_file:
        script = schema_file.read()
    conn = sqlite3.connect(config.DB_PATH, timeout=10)
    try:
        conn.execute("PRAGMA journal_mode = WAL")
        conn.executescript(script)
        conn.commit()
    finally:
        conn.close()
