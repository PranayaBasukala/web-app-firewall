# ============================================================
# app.py — ShieldWAF Main Server
# Full exception handling: rate limiting, payload guard,
# structured JSON logging, timeout protection, global handlers.
# ============================================================

from flask import Flask, request, jsonify, render_template
from waf import full_scan
from database import init_db, save_log, get_logs, get_stats
import logging
import traceback
import json
import time
import threading
from datetime import datetime, timezone
from collections import defaultdict

app = Flask(__name__)

# ============================================================
# STRUCTURED JSON LOGGER
# Writes structured JSON entries to waf_errors.log
# ============================================================

class JSONFormatter(logging.Formatter):
    def format(self, record):
        entry = {
            "timestamp": datetime.now(timezone.utc).isoformat(),
            "level":     record.levelname,
            "type":      getattr(record, "error_type", "GENERAL"),
            "message":   record.getMessage(),
            "ip":        getattr(record, "ip", "unknown"),
        }
        if record.exc_info:
            entry["traceback"] = self.formatException(record.exc_info)
        return json.dumps(entry)


# File handler — structured JSON
file_handler = logging.FileHandler("waf_errors.log")
file_handler.setLevel(logging.ERROR)
file_handler.setFormatter(JSONFormatter())

# Console handler — human-readable
console_handler = logging.StreamHandler()
console_handler.setLevel(logging.INFO)
console_handler.setFormatter(logging.Formatter("%(asctime)s [%(levelname)s] %(message)s"))

logger = logging.getLogger("shieldwaf")
logger.setLevel(logging.DEBUG)
logger.addHandler(file_handler)
logger.addHandler(console_handler)


def log_error(error_type, message, ip=None):
    """Helper to log structured errors with type and IP."""
    extra = {
        "error_type": error_type,
        "ip": ip or _get_ip()
    }
    logger.error(message, extra=extra)


def _get_ip():
    """Safely get client IP, even outside request context."""
    try:
        return request.remote_addr or "unknown"
    except RuntimeError:
        return "unknown"


# ============================================================
# DATABASE INITIALIZATION WITH EXCEPTION HANDLING
# ============================================================
try:
    init_db()
    logger.info("✅ Database initialized successfully.")
except Exception as e:
    logger.error(f"CRITICAL: Database failed to initialize: {e}")
    # Don't crash — app still runs, logs just won't be saved


# ============================================================
# RATE LIMITER
# Blocks IPs that exceed 30 requests per 60 seconds → 429
# ============================================================

_rate_data    = defaultdict(list)   # ip → [timestamps]
_rate_lock    = threading.Lock()     # thread-safe access

RATE_LIMIT    = 30   # max requests
RATE_WINDOW   = 60   # per seconds


def is_rate_limited(ip):
    """Returns True if IP has exceeded the rate limit."""
    now = time.time()
    with _rate_lock:
        # Keep only timestamps within the window
        _rate_data[ip] = [t for t in _rate_data[ip] if now - t < RATE_WINDOW]
        _rate_data[ip].append(now)
        return len(_rate_data[ip]) > RATE_LIMIT


@app.before_request
def enforce_rate_limit():
    ip = request.remote_addr or "unknown"
    if is_rate_limited(ip):
        log_error("RATE_LIMIT", f"IP {ip} exceeded {RATE_LIMIT} requests/{RATE_WINDOW}s", ip=ip)
        return jsonify({
            "error":   "Too Many Requests",
            "message": f"Rate limit exceeded. Max {RATE_LIMIT} requests per {RATE_WINDOW} seconds.",
            "code":    429
        }), 429


# ============================================================
# GLOBAL PAYLOAD SIZE GUARD
# Rejects any request body larger than 10KB → 413
# ============================================================

MAX_CONTENT_LENGTH     = 10 * 1024   # 10 KB
app.config["MAX_CONTENT_LENGTH"] = MAX_CONTENT_LENGTH


@app.errorhandler(413)
def payload_too_large(e):
    log_error("PAYLOAD_TOO_LARGE", f"Request body exceeded {MAX_CONTENT_LENGTH} bytes")
    return jsonify({
        "error":   "Payload Too Large",
        "message": f"Request body must be under {MAX_CONTENT_LENGTH // 1024}KB.",
        "code":    413
    }), 413


# ============================================================
# GLOBAL HTTP ERROR HANDLERS
# ============================================================

@app.errorhandler(400)
def bad_request(e):
    return jsonify({
        "error":   "Bad Request",
        "message": "The request could not be understood by the server.",
        "code":    400
    }), 400


@app.errorhandler(404)
def not_found(e):
    return jsonify({
        "error":   "Not Found",
        "message": "The requested resource does not exist.",
        "code":    404
    }), 404


@app.errorhandler(405)
def method_not_allowed(e):
    return jsonify({
        "error":   "Method Not Allowed",
        "message": "This HTTP method is not supported on this endpoint.",
        "code":    405
    }), 405


@app.errorhandler(500)
def internal_error(e):
    log_error("HTTP_500", f"Internal server error: {e}")
    return jsonify({
        "error":   "Internal Server Error",
        "message": "Something went wrong. The error has been logged.",
        "code":    500
    }), 500


@app.errorhandler(Exception)
def unhandled_exception(e):
    log_error("UNHANDLED_EXCEPTION", f"{type(e).__name__}: {e}\n{traceback.format_exc()}")
    return jsonify({
        "error":   "Unexpected Error",
        "message": "An unexpected error occurred. The error has been logged.",
        "code":    500
    }), 500


# ============================================================
# WAF SCAN WITH TIMEOUT PROTECTION
# Uses a background thread — if scan exceeds 3s, fail-safe blocks
# ============================================================

WAF_TIMEOUT_SECS = 3


def safe_scan(payload):
    """
    Runs full_scan() in a thread with a timeout.
    Returns result dict on success.
    Returns None on timeout or crash → caller should block request.
    """
    result_holder = [None]
    error_holder  = [None]

    def _scan():
        try:
            result_holder[0] = full_scan(payload)
        except Exception as e:
            error_holder[0] = e

    t = threading.Thread(target=_scan, daemon=True)
    t.start()
    t.join(timeout=WAF_TIMEOUT_SECS)

    if t.is_alive():
        # Thread still running — timeout exceeded
        log_error("WAF_TIMEOUT", f"Scan timed out after {WAF_TIMEOUT_SECS}s for payload: {payload[:80]}")
        return None

    if error_holder[0] is not None:
        log_error("WAF_CRASH", f"Scan threw exception: {error_holder[0]}")
        return None

    return result_holder[0]


# ============================================================
# ROUTES
# ============================================================

@app.route("/")
def home():
    try:
        return render_template("index.html")
    except Exception as e:
        log_error("RENDER_ERROR", f"Error rendering dashboard: {e}")
        return jsonify({
            "error":   "Dashboard Unavailable",
            "message": str(e)
        }), 500


@app.route("/api/logs")
def api_logs():
    try:
        logs = get_logs(50)
        return jsonify(logs)
    except Exception as e:
        log_error("DB_LOGS_ERROR", f"Error fetching logs: {e}")
        return jsonify({
            "error":   "Database Error",
            "message": "Could not retrieve logs. Database may be unavailable."
        }), 500


@app.route("/api/stats")
def api_stats():
    try:
        stats = get_stats()
        return jsonify(stats)
    except Exception as e:
        log_error("DB_STATS_ERROR", f"Error fetching stats: {e}")
        # Return zeroed stats so dashboard doesn't break
        return jsonify({
            "total":   0,
            "blocked": 0,
            "warned":  0,
            "allowed": 0,
            "error":   "Stats temporarily unavailable"
        }), 200


@app.route("/api/analyze", methods=["POST"])
def analyze():
    ip = request.remote_addr or "unknown"
    try:
        # ── Validate Content-Type ──────────────────────────────
        if not request.is_json:
            return jsonify({
                "error":   "Bad Request",
                "message": "Content-Type must be application/json",
                "code":    400
            }), 400

        # ── Parse JSON body ────────────────────────────────────
        data = request.get_json(silent=True)
        if data is None:
            return jsonify({
                "error":   "Bad Request",
                "message": "Invalid or malformed JSON in request body",
                "code":    400
            }), 400

        payload = data.get("payload", "")

        # ── Validate payload type ──────────────────────────────
        if not isinstance(payload, str):
            return jsonify({
                "error":   "Bad Request",
                "message": "Payload must be a string",
                "code":    400
            }), 400

        # ── Validate payload length ────────────────────────────
        if len(payload) > 5000:
            return jsonify({
                "error":   "Payload Too Large",
                "message": "Payload must be under 5000 characters",
                "code":    413
            }), 413

        # ── Run WAF Scan (with timeout protection) ─────────────
        result = safe_scan(payload)
        if result is None:
            return jsonify({
                "error":   "Scan Error",
                "message": "WAF engine error or timeout — request blocked for safety",
                "code":    500
            }), 500

        # ── Determine threat label ─────────────────────────────
        threat_label = result["threat"]
        if result["suspicious_flags"] and result["threat"] == "Clean":
            threat_label = result["suspicious_flags"][0]["reason"]

        # ── Save to database (non-fatal) ───────────────────────
        try:
            save_log(
                ip       = ip,
                payload  = payload,
                threat   = threat_label,
                severity = result["severity"],
                score    = result["score"],
                status   = result["status"]
            )
        except Exception as db_err:
            log_error("DB_SAVE_ERROR", f"Failed to save log: {db_err}", ip=ip)
            # Request still succeeds — DB failure is non-fatal

        return jsonify({
            "status":           result["status"],
            "threat":           result["threat"],
            "severity":         result["severity"],
            "score":            result["score"],
            "suspicious_score": result["suspicious_score"],
            "threats":          result["threats"],
            "suspicious_flags": result["suspicious_flags"],
            "is_attack":        result["is_attack"],
            "is_suspicious":    result["is_suspicious"]
        }), 200

    except Exception as e:
        log_error("ANALYZE_ERROR", f"Unhandled error in /api/analyze: {e}\n{traceback.format_exc()}", ip=ip)
        return jsonify({
            "error":   "Internal Error",
            "message": "Analysis failed unexpectedly. Error has been logged.",
            "code":    500
        }), 500


@app.route("/<path:url_path>", methods=["GET", "POST"])
def firewall_gate(url_path):
    ip = request.remote_addr or "unknown"
    try:
        full_path = url_path + "?" + request.query_string.decode("utf-8", errors="replace")

        # ── Run WAF Scan (with timeout protection) ─────────────
        result = safe_scan(full_path)
        if result is None:
            log_error("WAF_GATE_FAIL", f"Scan failed for URL: /{url_path}", ip=ip)
            return jsonify({
                "error":  "Scan Error",
                "reason": "WAF engine error — request blocked for safety"
            }), 403

        # ── Determine threat label ─────────────────────────────
        threat_label = result["threat"]
        if result["suspicious_flags"] and result["threat"] == "Clean":
            threat_label = result["suspicious_flags"][0]["reason"]

        # ── Save log (non-fatal) ───────────────────────────────
        try:
            save_log(
                ip       = ip,
                payload  = "/" + full_path,
                threat   = threat_label,
                severity = result["severity"],
                score    = result["score"],
                status   = result["status"]
            )
        except Exception as db_err:
            log_error("DB_SAVE_ERROR", f"Failed to save URL log: {db_err}", ip=ip)

        # ── Respond based on WAF decision ──────────────────────
        if result["status"] == "BLOCKED":
            return jsonify({
                "error":    "Blocked by WAF",
                "reason":   result["threat"],
                "severity": result["severity"],
                "score":    result["score"]
            }), 403

        if result["status"] == "SUSPICIOUS":
            return jsonify({
                "warning": "Request flagged as suspicious",
                "reason":  threat_label,
                "score":   result["score"]
            }), 200

        return jsonify({"message": "Allowed", "path": url_path}), 200

    except Exception as e:
        log_error("GATE_ERROR", f"Unhandled error in firewall_gate for '{url_path}': {e}\n{traceback.format_exc()}", ip=ip)
        # Fail-safe — block on any unknown error
        return jsonify({
            "error":  "Internal Error",
            "reason": "Request blocked due to internal error"
        }), 403


# ============================================================
# START
# ============================================================
if __name__ == "__main__":
    print("🛡️  ShieldWAF starting...")
    print("📋  Errors logged to: waf_errors.log  (structured JSON)")
    print(f"🚦  Rate limit: {RATE_LIMIT} requests per {RATE_WINDOW}s per IP")
    print(f"⏱️  WAF scan timeout: {WAF_TIMEOUT_SECS}s")
    print(f"📦  Max payload size: {MAX_CONTENT_LENGTH // 1024}KB")
    print("🌐  http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)