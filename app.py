# ============================================================
# app.py — WAF Server (Step 2: Smart Engine + Database)
# ============================================================

from flask import Flask, request, jsonify, render_template
from waf import scan          # our smart firewall engine
from database import init_db, save_log, get_logs, get_stats

app = Flask(__name__)

# Create the database table when server starts
init_db()

# ============================================================
# ROUTES
# ============================================================

@app.route("/")
def home():
    return render_template("index.html")


@app.route("/api/logs")
def api_logs():
    return jsonify(get_logs(50))


@app.route("/api/stats")
def api_stats():
    return jsonify(get_stats())


@app.route("/api/analyze", methods=["POST"])
def analyze():
    data    = request.get_json()
    payload = data.get("payload", "")
    ip      = request.remote_addr

    result = scan(payload)   # run through smart WAF engine

    save_log(
        ip       = ip,
        payload  = payload,
        threat   = result["threat"],
        severity = result["severity"],
        score    = result["score"],
        status   = result["status"]
    )

    return jsonify({
        "status":   result["status"],
        "threat":   result["threat"],
        "severity": result["severity"],
        "score":    result["score"],
        "threats":  result["threats"]
    })


@app.route("/<path:url_path>", methods=["GET", "POST"])
def firewall_gate(url_path):
    full   = url_path + "?" + request.query_string.decode("utf-8")
    ip     = request.remote_addr
    result = scan(full)

    save_log(
        ip       = ip,
        payload  = "/" + full,
        threat   = result["threat"],
        severity = result["severity"],
        score    = result["score"],
        status   = result["status"]
    )

    if result["status"] == "BLOCKED":
        return jsonify({
            "error":    "Blocked by WAF",
            "reason":   result["threat"],
            "severity": result["severity"],
            "score":    result["score"]
        }), 403

    return jsonify({"message": "Allowed", "path": url_path}), 200


# ============================================================
# START
# ============================================================

if __name__ == "__main__":
    print("🛡️  WAF v2 running with smart engine + database!")
    print("🌐  http://127.0.0.1:5000")
    app.run(host="0.0.0.0", port=5000, debug=True)