# ============================================================
# database.py — SQLite Database Handler
# Includes full exception handling on all operations.
# ============================================================

import sqlite3
import logging
from datetime import datetime

DB_FILE = "waf_logs.db"


def init_db():
    """
    Creates the logs table if it doesn't exist.
    Raises an exception if the database cannot be created.
    """
    try:
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
    except sqlite3.Error as e:
        logging.error(f"Database init error: {e}")
        raise RuntimeError(f"Could not initialize database: {e}")
    except Exception as e:
        logging.error(f"Unexpected error during database init: {e}")
        raise


def save_log(ip, payload, threat, severity, score, status):
    """
    Saves one request log entry to the database.
    Silently logs errors without crashing the server.
    """
    try:
        # Validate and sanitize inputs
        ip       = str(ip)[:45]        if ip       else "unknown"
        payload  = str(payload)[:120]  if payload  else ""
        threat   = str(threat)[:100]   if threat   else "Unknown"
        severity = str(severity)[:20]  if severity else "NONE"
        status   = str(status)[:20]    if status   else "UNKNOWN"

        # Ensure score is an integer
        try:
            score = int(score)
        except (TypeError, ValueError):
            score = 0

        conn = sqlite3.connect(DB_FILE, timeout=10)
        cursor = conn.cursor()
        cursor.execute("""
            INSERT INTO logs (time, ip, payload, threat, severity, score, status)
            VALUES (?, ?, ?, ?, ?, ?, ?)
        """, (
            datetime.now().strftime("%H:%M:%S"),
            ip, payload, threat, severity, score, status
        ))
        conn.commit()
        conn.close()

    except sqlite3.OperationalError as e:
        logging.error(f"Database operational error in save_log: {e}")
        # Don't raise — server keeps running even if log fails
    except sqlite3.Error as e:
        logging.error(f"Database error in save_log: {e}")
    except Exception as e:
        logging.error(f"Unexpected error in save_log: {e}")


def get_logs(limit=50):
    """
    Fetches the most recent logs from the database.
    Returns empty list if database is unavailable.
    """
    try:
        # Validate limit
        try:
            limit = int(limit)
            if limit < 1 or limit > 1000:
                limit = 50
        except (TypeError, ValueError):
            limit = 50

        conn = sqlite3.connect(DB_FILE, timeout=10)
        conn.row_factory = sqlite3.Row
        cursor = conn.cursor()
        cursor.execute("""
            SELECT * FROM logs
            ORDER BY id DESC
            LIMIT ?
        """, (limit,))
        rows = [dict(row) for row in cursor.fetchall()]
        conn.close()
        return rows

    except sqlite3.OperationalError as e:
        logging.error(f"Database operational error in get_logs: {e}")
        return []  # Return empty list — dashboard shows "no requests"
    except sqlite3.Error as e:
        logging.error(f"Database error in get_logs: {e}")
        return []
    except Exception as e:
        logging.error(f"Unexpected error in get_logs: {e}")
        return []


def get_stats():
    """
    Returns summary counts from the database.
    Returns zeroed stats if database is unavailable.
    """
    default_stats = {"total": 0, "blocked": 0, "warned": 0, "allowed": 0}

    try:
        conn = sqlite3.connect(DB_FILE, timeout=10)
        cursor = conn.cursor()

        cursor.execute("SELECT COUNT(*) FROM logs")
        total = cursor.fetchone()[0] or 0

        cursor.execute("SELECT COUNT(*) FROM logs WHERE status='BLOCKED'")
        blocked = cursor.fetchone()[0] or 0

        cursor.execute("SELECT COUNT(*) FROM logs WHERE status='SUSPICIOUS'")
        warned = cursor.fetchone()[0] or 0

        conn.close()

        return {
            "total":   total,
            "blocked": blocked,
            "warned":  warned,
            "allowed": max(0, total - blocked - warned)
        }

    except sqlite3.OperationalError as e:
        logging.error(f"Database operational error in get_stats: {e}")
        return default_stats
    except sqlite3.Error as e:
        logging.error(f"Database error in get_stats: {e}")
        return default_stats
    except Exception as e:
        logging.error(f"Unexpected error in get_stats: {e}")
        return default_stats