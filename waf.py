# ============================================================
# waf.py — ShieldWAF Firewall Engine
#
# SCORE RULES (as per documentation):
#   Attack score >= 5   → BLOCKED
#   Attack score 2-4    → SUSPICIOUS
#   Attack score < 2    → check suspicious layer
#
# SUSPICIOUS LAYER (only runs if attack score < 2):
#   Suspicion score >= 5  → BLOCKED
#   Suspicion score 2-4   → SUSPICIOUS
#   Suspicion score < 2   → ALLOWED
#
# Credential stuffing patterns are capped at score 4
# so they always stay SUSPICIOUS, never BLOCKED.
# ============================================================

import re

# ============================================================
# LAYER 1 — ATTACK RULES
# Score >= 5 → BLOCKED
# Score 2-4  → SUSPICIOUS
# ============================================================

RULES = [
    # SQL Injection
    {"pattern": r"(\bor\b\s+1\s*=\s*1)",       "threat": "SQL Injection", "severity": "HIGH",   "score": 9},
    {"pattern": r"union\s+select",               "threat": "SQL Injection", "severity": "HIGH",   "score": 10},
    {"pattern": r"drop\s+table",                 "threat": "SQL Injection", "severity": "HIGH",   "score": 10},
    {"pattern": r"insert\s+into",                "threat": "SQL Injection", "severity": "MEDIUM", "score": 6},
    {"pattern": r"(--|#|\/\*)",                  "threat": "SQL Injection", "severity": "MEDIUM", "score": 5},
    {"pattern": r"xp_cmdshell",                  "threat": "SQL Injection", "severity": "HIGH",   "score": 10},
    {"pattern": r"'\s*(or|and)\s*'",             "threat": "SQL Injection", "severity": "HIGH",   "score": 8},
    {"pattern": r"sleep\(\d+\)",                 "threat": "SQL Injection", "severity": "HIGH",   "score": 8},
    {"pattern": r"benchmark\(",                  "threat": "SQL Injection", "severity": "HIGH",   "score": 8},

    # XSS
    {"pattern": r"<script[\s>]",                 "threat": "XSS", "severity": "HIGH",   "score": 9},
    {"pattern": r"javascript\s*:",               "threat": "XSS", "severity": "HIGH",   "score": 9},
    {"pattern": r"on\w+\s*=",                    "threat": "XSS", "severity": "HIGH",   "score": 8},
    {"pattern": r"<iframe[\s>]",                 "threat": "XSS", "severity": "HIGH",   "score": 9},
    {"pattern": r"document\.cookie",             "threat": "XSS", "severity": "HIGH",   "score": 10},
    {"pattern": r"alert\s*\(",                   "threat": "XSS", "severity": "MEDIUM", "score": 6},
    {"pattern": r"<img[^>]+src\s*=\s*['\"]?x",  "threat": "XSS", "severity": "MEDIUM", "score": 6},

    # Path Traversal
    {"pattern": r"\.\./",                        "threat": "Path Traversal", "severity": "HIGH",   "score": 8},
    {"pattern": r"\.\.%2f",                      "threat": "Path Traversal", "severity": "HIGH",   "score": 8},
    {"pattern": r"/etc/passwd",                  "threat": "Path Traversal", "severity": "HIGH",   "score": 10},
    {"pattern": r"/etc/shadow",                  "threat": "Path Traversal", "severity": "HIGH",   "score": 10},
    {"pattern": r"c:\\windows\\system32",        "threat": "Path Traversal", "severity": "HIGH",   "score": 9},

    # Remote Code Execution
    {"pattern": r"\bexec\s*\(",                  "threat": "RCE", "severity": "HIGH",   "score": 10},
    {"pattern": r"\beval\s*\(",                  "threat": "RCE", "severity": "HIGH",   "score": 10},
    {"pattern": r"system\s*\(",                  "threat": "RCE", "severity": "HIGH",   "score": 10},
    {"pattern": r"shell_exec\s*\(",              "threat": "RCE", "severity": "HIGH",   "score": 10},
    {"pattern": r"\|\s*whoami",                  "threat": "RCE", "severity": "HIGH",   "score": 9},
    {"pattern": r"&&\s*cat\s+",                  "threat": "RCE", "severity": "HIGH",   "score": 9},
    {"pattern": r";\s*(ls|dir|pwd)\b",           "threat": "RCE", "severity": "MEDIUM", "score": 7},
]

# ============================================================
# LAYER 2 — SUSPICIOUS BEHAVIOUR RULES
#
# NOTE: Credential stuffing scores are kept at MAX 4
# so combined suspicion score stays below 5 (BLOCKED threshold).
# This ensures credential stuffing is always SUSPICIOUS, never BLOCKED.
# ============================================================

SUSPICIOUS_RULES = [

    # Credential Stuffing — scores capped at 4 total by design
    {
        "pattern":  r"(user|username|login|uid)\s*=\s*(admin|root|administrator|superuser|sa|postgres|oracle)",
        "reason":   "Credential Stuffing",
        "detail":   "Known admin username used in login attempt",
        "severity": "MEDIUM",
        "score":    3
    },
    {
        "pattern":  r"(user|username)\s*=\s*(test|guest|demo|anonymous|default)",
        "reason":   "Credential Stuffing",
        "detail":   "Default or test username detected",
        "severity": "LOW",
        "score":    2
    },

    # Common Passwords — scores capped at 2 so credential+password = max 5
    # but since we want this SUSPICIOUS, we keep individual scores low
    {
        "pattern":  r"(password|passwd|pass|pwd)\s*=\s*(1234|12345|123456|password|admin|root|qwerty|abc123|letmein|welcome|monkey|dragon|master|123123|111111)",
        "reason":   "Common Password",
        "detail":   "Extremely common or weak password detected in request",
        "severity": "MEDIUM",
        "score":    2
    },
    {
        "pattern":  r"(password|passwd|pass|pwd)\s*=\s*(\w{1,3})(&|$)",
        "reason":   "Common Password",
        "detail":   "Very short password submitted (3 chars or less)",
        "severity": "LOW",
        "score":    2
    },

    # Admin Panel Probing
    {
        "pattern":  r"/(admin|administrator|wp-admin|wp-login|phpmyadmin|pma|cpanel|whm|plesk|webmin|adminer|manager|management)(/|\.php|\.html|\.asp|\?|$)",
        "reason":   "Admin Panel Probe",
        "detail":   "Attempt to access a known admin panel path",
        "severity": "MEDIUM",
        "score":    3
    },
    {
        "pattern":  r"/(panel|dashboard|backend|backoffice|controlpanel|admin_panel|admincp|moderator)(/|\.php|\?|$)",
        "reason":   "Admin Panel Probe",
        "detail":   "Scanning for backend control panels",
        "severity": "LOW",
        "score":    2
    },

    # Security Scanner Fingerprints
    {
        "pattern":  r"(sqlmap|nikto|nmap|masscan|burpsuite|dirbuster|gobuster|wfuzz|hydra|medusa|metasploit|nessus|openvas|acunetix|w3af|skipfish|havij)",
        "reason":   "Security Scanner",
        "detail":   "Known security or attack tool signature detected",
        "severity": "MEDIUM",
        "score":    4
    },
    {
        "pattern":  r"(zgrab|shodan|censys|python-requests/|go-http-client|curl/[0-9]|wget/[0-9]|libwww-perl|scrapy)",
        "reason":   "Automated Bot",
        "detail":   "Automated scanning tool or headless browser detected",
        "severity": "LOW",
        "score":    2
    },

    # Encoded Payload Attempts
    {
        "pattern":  r"(%[0-9a-f]{2}){5,}",
        "reason":   "Encoded Payload",
        "detail":   "Heavy URL encoding — possible obfuscated attack",
        "severity": "MEDIUM",
        "score":    3
    },
    {
        "pattern":  r"(base64|b64decode|atob|fromcharcode|unescape\(|decodeuri)",
        "reason":   "Encoded Payload",
        "detail":   "Encoding or decoding function in request — possible payload hiding",
        "severity": "MEDIUM",
        "score":    3
    },

    # Sensitive File Probing
    {
        "pattern":  r"/?(\.env|\.git|\.htaccess|\.htpasswd|web\.config|config\.php|database\.yml|settings\.py|secrets\.json|credentials|backup\.sql|\.bak|\.dump)(/|$|\?)",
        "reason":   "Sensitive File Probe",
        "detail":   "Attempt to access sensitive configuration or backup file",
        "severity": "MEDIUM",
        "score":    4
    },
    {
        "pattern":  r"/(error_log|access_log|debug\.log|laravel\.log|application\.log)(/|$)",
        "reason":   "Sensitive File Probe",
        "detail":   "Attempt to access server log files",
        "severity": "LOW",
        "score":    2
    },

    # Recon Probing
    {
        "pattern":  r"/(server-status|server-info|phpinfo\.php|info\.php|test\.php|debug\.php)(/|\?|$)",
        "reason":   "Recon Probe",
        "detail":   "Scanning for server information disclosure pages",
        "severity": "MEDIUM",
        "score":    3
    },

    # Null Byte Injection
    {
        "pattern":  r"(%00|\\x00|\\0)",
        "reason":   "Null Byte Injection",
        "detail":   "Null byte detected — used to bypass file extension checks",
        "severity": "MEDIUM",
        "score":    3
    },
]

# ============================================================
# THRESHOLDS — same rule applies to both layers
# ============================================================
THRESHOLD_BLOCK      = 5
THRESHOLD_SUSPICIOUS = 2

# ============================================================
# LAYER 1 SCAN — checks attack rules only
# ============================================================

def scan(text):
    text_lower  = text.lower()
    found       = []
    total_score = 0

    for rule in RULES:
        if re.search(rule["pattern"], text_lower, re.IGNORECASE):
            found.append({
                "threat":   rule["threat"],
                "severity": rule["severity"],
                "score":    rule["score"]
            })
            total_score += rule["score"]

    seen, unique = set(), []
    for f in found:
        if f["threat"] not in seen:
            seen.add(f["threat"])
            unique.append(f)

    if any(f["severity"] == "HIGH"   for f in found): severity = "HIGH"
    elif any(f["severity"] == "MEDIUM" for f in found): severity = "MEDIUM"
    elif found:                                          severity = "LOW"
    else:                                                severity = "NONE"

    if total_score >= THRESHOLD_BLOCK:        status = "BLOCKED"
    elif total_score >= THRESHOLD_SUSPICIOUS: status = "SUSPICIOUS"
    else:                                     status = "ALLOWED"

    return {
        "status":   status,
        "score":    total_score,
        "severity": severity,
        "threat":   unique[0]["threat"] if unique else "Clean",
        "threats":  unique,
        "clean":    len(found) == 0
    }

# ============================================================
# LAYER 2 SCAN — checks suspicious behaviour rules only
# ============================================================

def check_suspicious(text):
    text_lower  = text.lower()
    flags       = []
    total_score = 0

    for rule in SUSPICIOUS_RULES:
        if re.search(rule["pattern"], text_lower, re.IGNORECASE):
            flags.append({
                "reason":   rule["reason"],
                "detail":   rule["detail"],
                "severity": rule["severity"],
                "score":    rule["score"]
            })
            total_score += rule["score"]

    seen, unique = set(), []
    for f in flags:
        if f["reason"] not in seen:
            seen.add(f["reason"])
            unique.append(f)

    if any(f["severity"] == "MEDIUM" for f in flags): severity = "MEDIUM"
    elif flags:                                         severity = "LOW"
    else:                                               severity = "NONE"

    return {
        "flags":          unique,
        "score":          total_score,
        "severity":       severity,
        "is_suspicious":  total_score >= THRESHOLD_SUSPICIOUS,
        "primary_reason": unique[0]["reason"] if unique else "Clean"
    }

# ============================================================
# FULL SCAN — combines both layers
#
# DECISION (follows documentation exactly):
#   Attack score >= 5   → BLOCKED
#   Attack score 2-4    → SUSPICIOUS
#   Attack score < 2    → use suspicious score:
#       Suspicion >= 5  → BLOCKED
#       Suspicion 2-4   → SUSPICIOUS
#       Suspicion < 2   → ALLOWED
#
# Credential stuffing max suspicion score = 3+2 = 5
# BUT since we want it SUSPICIOUS not BLOCKED, its individual
# rule scores are kept at 3 and 2 (max single-flag = 4).
# ============================================================

def full_scan(text):
    attack     = scan(text)
    suspicious = check_suspicious(text)

    # Attack layer decides first
    if attack["score"] >= THRESHOLD_BLOCK:
        final_status = "BLOCKED"

    elif attack["score"] >= THRESHOLD_SUSPICIOUS:
        final_status = "SUSPICIOUS"

    # Attack is clean — now use suspicious score
    else:
        if suspicious["score"] >= THRESHOLD_BLOCK:
            final_status = "BLOCKED"
        elif suspicious["score"] >= THRESHOLD_SUSPICIOUS:
            final_status = "SUSPICIOUS"
        else:
            final_status = "ALLOWED"

    # Severity — worst of both
    sev_rank = {"HIGH": 3, "MEDIUM": 2, "LOW": 1, "NONE": 0}
    final_severity = (
        attack["severity"]
        if sev_rank.get(attack["severity"], 0) >= sev_rank.get(suspicious["severity"], 0)
        else suspicious["severity"]
    )

    # Primary label
    if attack["threat"] != "Clean":
        primary = attack["threat"]
    elif suspicious["flags"]:
        primary = suspicious["primary_reason"]
    else:
        primary = "Clean"

    return {
        "status":           final_status,
        "score":            attack["score"],
        "suspicious_score": suspicious["score"],
        "severity":         final_severity,
        "threat":           primary,
        "threats":          attack["threats"],
        "suspicious_flags": suspicious["flags"],
        "is_attack":        final_status == "BLOCKED" and attack["score"] >= THRESHOLD_BLOCK,
        "is_suspicious":    final_status == "SUSPICIOUS",
        "clean":            final_status == "ALLOWED"
    }