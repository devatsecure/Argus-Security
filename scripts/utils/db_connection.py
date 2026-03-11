"""
Shared SQLite connection helper for audit_monitor and feedback_tracker.
Provides a context manager that opens a connection, yields (conn, cursor), commits on success, and closes.
"""

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Iterator


@contextmanager
def db_connection(db_path: str | Path) -> Iterator[tuple[sqlite3.Connection, sqlite3.Cursor]]:
    """
    Context manager for SQLite: connect, yield (conn, cursor), commit, then close.

    Usage:
        with db_connection(self.db_path) as (conn, cursor):
            cursor.execute(...)
    """
    conn = sqlite3.connect(str(db_path))
    try:
        cursor = conn.cursor()
        yield conn, cursor
        conn.commit()
    finally:
        conn.close()
