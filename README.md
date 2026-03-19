# ShieldWAF - Web Application Firewall

A robust Web Application Firewall (WAF) built with Flask that protects web applications from common attack vectors including SQL Injection, XSS, Path Traversal, Remote Code Execution, and credential stuffing attacks.

## Features

### 🛡️ Multi-Layer Security

**Layer 1: Attack Detection**
- SQL Injection prevention
- Cross-Site Scripting (XSS) protection
- Path Traversal detection
- Remote Code Execution (RCE) prevention
- Scoring-based threat assessment (≥5 score = BLOCKED, 2-4 = SUSPICIOUS, <2 = ALLOWED)

**Layer 2: Suspicious Behavior Detection**
- Credential stuffing detection
- Additional behavioral analysis
- Suspicious activity flagging

### 📊 Rate Limiting
- Prevents brute force attacks
- 30 requests per 60 seconds per IP
- Returns 429 status code when limit exceeded

### 📝 Comprehensive Logging
- Structured JSON logging to `waf_errors.log`
- Database logging with SQLite
- Detailed error tracking with timestamps and IP addresses
- Console output for monitoring

### 🗄️ Database Integration
- SQLite database for event logging
- Attack statistics and history
- Log retrieval and analysis endpoints

### ⚡ Exception Handling
- Global error handlers
- Timeout protection
- Graceful degradation if components fail
- Detailed error tracking and reporting

### 🎨 Web Dashboard
- Real-time WAF status monitoring
- Attack visualization
- Log viewing interface

## Technology Stack

- **Backend**: Flask 3.0.3
- **Web Server**: Gunicorn 21.2.0
- **Database**: SQLite
- **Language**: Python 3.x

## Installation

### Prerequisites
- Python 3.x
- pip

### Setup

1. Clone the repository:
```bash
git clone <repository-url>
cd web-app-firewall
```

2.Create and activate a virtual environment:
```bash
python -m venv venv
source venv/bin/activate  # On Windows: venv\Scripts\activate
```

3.Install dependencies
```bash
pip install -r requirements.txt
```

### Requirements
Flask==3.0.3
Gunicorn==21.2.0
setuptools
