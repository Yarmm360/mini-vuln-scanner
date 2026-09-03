"""
database.py

SQLite persistence layer for MiniVuln Scanner: user accounts and scan history.

Uses plain sqlite3 (no ORM) to keep the project easy to read for a coursework
assignment. Each request gets its own connection (SQLite handles this fine for
a small single-file DB in a low-concurrency demo app).
"""

import sqlite3
import json
import datetime
import pathlib

DB_PATH = pathlib.Path(__file__).parent / "minivuln.db"

SCHEMA = """
CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT UNIQUE NOT NULL,
    email TEXT UNIQUE NOT NULL,
    password_hash TEXT NOT NULL,
    created_at TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id INTEGER NOT NULL,
    target TEXT NOT NULL,
    host TEXT NOT NULL,
    scanned_at TEXT NOT NULL,
    network_results TEXT,
    web_results TEXT,
    ssl_results TEXT,
    FOREIGN KEY (user_id) REFERENCES users (id)
);
"""


def get_db():
    """Open a new connection with row access by column name."""
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON")
    return conn


def init_db():
    """Create tables if they don't already exist. Safe to call on every startup."""
    conn = get_db()
    try:
        conn.executescript(SCHEMA)
        conn.commit()
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Users
# ---------------------------------------------------------------------------
def create_user(username: str, email: str, password_hash: str):
    conn = get_db()
    try:
        cur = conn.execute(
            "INSERT INTO users (username, email, password_hash, created_at) VALUES (?, ?, ?, ?)",
            (username, email, password_hash, datetime.datetime.utcnow().isoformat()),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_user_by_username(username: str):
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM users WHERE username = ?", (username,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_email(email: str):
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM users WHERE email = ?", (email,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_user_by_id(user_id: int):
    conn = get_db()
    try:
        row = conn.execute("SELECT * FROM users WHERE id = ?", (user_id,)).fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


# ---------------------------------------------------------------------------
# Scans
# ---------------------------------------------------------------------------
def save_scan(user_id: int, target: str, host: str, network_results, web_results, ssl_results):
    """Persist a completed scan for a user. Result dicts are stored as JSON text."""
    conn = get_db()
    try:
        cur = conn.execute(
            """INSERT INTO scans (user_id, target, host, scanned_at, network_results, web_results, ssl_results)
               VALUES (?, ?, ?, ?, ?, ?, ?)""",
            (
                user_id, target, host, datetime.datetime.utcnow().isoformat(),
                json.dumps(network_results) if network_results is not None else None,
                json.dumps(web_results) if web_results is not None else None,
                json.dumps(ssl_results) if ssl_results is not None else None,
            ),
        )
        conn.commit()
        return cur.lastrowid
    finally:
        conn.close()


def get_scans_for_user(user_id: int):
    """Return all scans for a user, most recent first, with JSON fields parsed back out."""
    conn = get_db()
    try:
        rows = conn.execute(
            "SELECT * FROM scans WHERE user_id = ? ORDER BY scanned_at DESC", (user_id,)
        ).fetchall()
        return [_parse_scan_row(r) for r in rows]
    finally:
        conn.close()


def get_scan_by_id(scan_id: int, user_id: int):
    """Fetch a single scan, scoped to the owning user (prevents viewing others' scans)."""
    conn = get_db()
    try:
        row = conn.execute(
            "SELECT * FROM scans WHERE id = ? AND user_id = ?", (scan_id, user_id)
        ).fetchone()
        return _parse_scan_row(row) if row else None
    finally:
        conn.close()


def _parse_scan_row(row):
    if row is None:
        return None
    d = dict(row)
    for field in ("network_results", "web_results", "ssl_results"):
        d[field] = json.loads(d[field]) if d[field] else None
    return d
