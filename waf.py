# ============================================================
# waf.py — Smart Firewall Engine
# Handles threat detection, scoring, and severity levels.
# app.py imports and uses this file.
# ============================================================

import re

# ============================================================
# THREAT RULES
# Each rule has:
#   - pattern   : the dangerous string to look for
#   - threat    : category name
#   - severity  : HIGH, MEDIUM, or LOW
#   - score     : how dangerous it is (1–10)
# ============================================================

RULES = [
    # --- SQL Injection ---
    {"pattern": r"(\bor\b\s+1\s*=\s*1)",       "threat": "SQL Injection", "severity": "HIGH",   "score": 9},
    {"pattern": r"union\s+select",               "threat": "SQL Injection", "severity": "HIGH",   "score": 10},
    {"pattern": r"drop\s+table",                 "threat": "SQL Injection", "severity": "HIGH",   "score": 10},
    {"pattern": r"insert\s+into",                "threat": "SQL Injection", "severity": "MEDIUM", "score": 6},
    {"pattern": r"(--|#|\/\*)",                  "threat": "SQL Injection", "severity": "MEDIUM", "score": 5},
    {"pattern": r"xp_cmdshell",                  "threat": "SQL Injection", "severity": "HIGH",   "score": 10},
    {"pattern": r"'\s*(or|and)\s*'",             "threat": "SQL Injection", "severity": "HIGH",   "score": 8},
    {"pattern": r"sleep\(\d+\)",                 "threat": "SQL Injection", "severity": "HIGH",   "score": 8},
    {"pattern": r"benchmark\(",                  "threat": "SQL Injection", "severity": "HIGH",   "score": 8},

    # --- XSS (Cross-Site Scripting) ---
    {"pattern": r"<script[\s>]",                 "threat": "XSS", "severity": "HIGH",   "score": 9},
    {"pattern": r"javascript\s*:",               "threat": "XSS", "severity": "HIGH",   "score": 9},
    {"pattern": r"on\w+\s*=",                    "threat": "XSS", "severity": "HIGH",   "score": 8},
    {"pattern": r"<iframe[\s>]",                 "threat": "XSS", "severity": "HIGH",   "score": 9},
    {"pattern": r"document\.cookie",             "threat": "XSS", "severity": "HIGH",   "score": 10},
    {"pattern": r"alert\s*\(",                   "threat": "XSS", "severity": "MEDIUM", "score": 6},
    {"pattern": r"<img[^>]+src\s*=\s*['\"]?x",  "threat": "XSS", "severity": "MEDIUM", "score": 6},

    # --- Path Traversal (LFI) ---
    {"pattern": r"\.\./",                        "threat": "Path Traversal", "severity": "HIGH",   "score": 8},
    {"pattern": r"\.\.%2f",                      "threat": "Path Traversal", "severity": "HIGH",   "score": 8},
    {"pattern": r"/etc/passwd",                  "threat": "Path Traversal", "severity": "HIGH",   "score": 10},
    {"pattern": r"/etc/shadow",                  "threat": "Path Traversal", "severity": "HIGH",   "score": 10},
    {"pattern": r"c:\\windows\\system32",        "threat": "Path Traversal", "severity": "HIGH",   "score": 9},

    # --- Remote Code Execution ---
    {"pattern": r"\bexec\s*\(",                  "threat": "RCE", "severity": "HIGH",   "score": 10},
    {"pattern": r"\beval\s*\(",                  "threat": "RCE", "severity": "HIGH",   "score": 10},
    {"pattern": r"system\s*\(",                  "threat": "RCE", "severity": "HIGH",   "score": 10},
    {"pattern": r"shell_exec\s*\(",              "threat": "RCE", "severity": "HIGH",   "score": 10},
    {"pattern": r"\|\s*whoami",                  "threat": "RCE", "severity": "HIGH",   "score": 9},
    {"pattern": r"&&\s*cat\s+",                  "threat": "RCE", "severity": "HIGH",   "score": 9},
    {"pattern": r";\s*(ls|dir|pwd)\b",           "threat": "RCE", "severity": "MEDIUM", "score": 7},

    # --- Brute Force Indicators ---
    {"pattern": r"(admin|root|administrator)\s*[:=]\s*\w+", "threat": "Brute Force", "severity": "MEDIUM", "score": 5},
    {"pattern": r"password\s*=\s*(admin|1234|password|root)", "threat": "Brute Force", "severity": "LOW", "score": 3},
]

# ============================================================
# SCORE THRESHOLDS
# Total score decides the final status
# ============================================================

THRESHOLD_BLOCK = 5   # score >= 5 → BLOCKED
THRESHOLD_WARN  = 2   # score 2–4  → SUSPICIOUS


# ============================================================
# MAIN SCAN FUNCTION
# Call this with any text. Returns a result dictionary.
# ============================================================

def scan(text):
    """
    Scans input text for threats.
    Returns a dict with:
      - status    : BLOCKED / SUSPICIOUS / ALLOWED
      - score     : total danger score
      - threats   : list of threats found
      - severity  : highest severity found
    """
    text_lower = text.lower()
    found      = []
    total_score = 0

    for rule in RULES:
        # re.search looks for the pattern anywhere in the text
        if re.search(rule["pattern"], text_lower, re.IGNORECASE):
            found.append({
                "threat":   rule["threat"],
                "severity": rule["severity"],
                "score":    rule["score"]
            })
            total_score += rule["score"]

    # Remove duplicate threat categories
    seen     = set()
    unique   = []
    for f in found:
        if f["threat"] not in seen:
            seen.add(f["threat"])
            unique.append(f)

    # Decide severity (worst found)
    if any(f["severity"] == "HIGH"   for f in found): severity = "HIGH"
    elif any(f["severity"] == "MEDIUM" for f in found): severity = "MEDIUM"
    elif found:                                          severity = "LOW"
    else:                                                severity = "NONE"

    # Decide final status based on score
    if total_score >= THRESHOLD_BLOCK:
        status = "BLOCKED"
    elif total_score >= THRESHOLD_WARN:
        status = "SUSPICIOUS"
    else:
        status = "ALLOWED"

    # Primary threat label (for the log table)
    primary = unique[0]["threat"] if unique else "Clean"

    return {
        "status":   status,
        "score":    total_score,
        "severity": severity,
        "threat":   primary,
        "threats":  unique,
        "clean":    len(found) == 0
    }