# ============================================================
# database.py — SQLite Database Handler
# Saves every request log permanently to a file (waf_logs.db)
# so logs survive server restarts.
# ============================================================

import sqlite3
from datetime import datetime

DB_FILE = "waf_logs.db"  # The database file created in your project folder


def init_db():
    """Creates the logs table if it doesn't exist yet."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS logs (
            id       INTEGER PRIMARY KEY AUTOINCREMENT,
            time     TEXT,
            ip       TEXT,
            payload  TEXT,
            threat   TEXT,
            severity TEXT,
            score    INTEGER,
            status   TEXT
        )
    """)
    conn.commit()
    conn.close()


def save_log(ip, payload, threat, severity, score, status):
    """Saves one request log entry to the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("""
        INSERT INTO logs (time, ip, payload, threat, severity, score, status)
        VALUES (?, ?, ?, ?, ?, ?, ?)
    """, (
        datetime.now().strftime("%H:%M:%S"),
        ip,
        payload[:120],
        threat,
        severity,
        score,
        status
    ))
    conn.commit()
    conn.close()


def get_logs(limit=50):
    """Fetches the most recent logs from the database."""
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row   # lets us access columns by name
    cursor = conn.cursor()
    cursor.execute("""
        SELECT * FROM logs
        ORDER BY id DESC
        LIMIT ?
    """, (limit,))
    rows = [dict(row) for row in cursor.fetchall()]
    conn.close()
    return rows


def get_stats():
    """Returns summary counts from the database."""
    conn = sqlite3.connect(DB_FILE)
    cursor = conn.cursor()
    cursor.execute("SELECT COUNT(*) FROM logs")
    total = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM logs WHERE status='BLOCKED'")
    blocked = cursor.fetchone()[0]
    cursor.execute("SELECT COUNT(*) FROM logs WHERE status='SUSPICIOUS'")
    warned = cursor.fetchone()[0]
    conn.close()
    return {
        "total":   total,
        "blocked": blocked,
        "warned":  warned,
        "allowed": total - blocked - warned
    }