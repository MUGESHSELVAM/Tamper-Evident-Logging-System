from flask import Flask, request, render_template, redirect, send_file, session, jsonify, flash
from werkzeug.security import generate_password_hash, check_password_hash
from functools import wraps
import hashlib
import json
import time
import csv
import os
import re
from datetime import datetime

app = Flask(__name__)
app.secret_key = os.environ.get("SECRET_KEY", "dev_secret_key_change_in_prod!")

# Configuration
LOG_FILE = "logs.json"
ALERTS_FILE = "alerts.json"
MAX_LOG_SIZE = 1000000
RATE_LIMIT = {"attempts": 5, "window": 60}
# Admin password from environment variable (required for security)
ADMIN_PASSWORD = os.environ.get("ADMIN_PASSWORD", "dev_password_change_in_production")
if ADMIN_PASSWORD == "dev_password_change_in_production":
    print("⚠️  WARNING: ADMIN_PASSWORD not set. Using development default. Set ADMIN_PASSWORD environment variable for production.")
ADMIN_PASSWORD_HASH = generate_password_hash(ADMIN_PASSWORD)
IP_TRACKING = {}

# Initialization
def init_logs():
    """Initialize log and alerts files"""
    for file in [LOG_FILE, ALERTS_FILE]:
        try:
            with open(file, "r") as f:
                json.load(f)
        except:
            with open(file, "w") as f:
                json.dump([], f)

# Hash & Cryptography
def hash_data(data):
    """Generate SHA-256 hash"""
    return hashlib.sha256(data.encode()).hexdigest()

def sanitize_input(data, max_length=500):
    """Validate and sanitize input"""
    if not data or not isinstance(data, str) or len(data) > max_length:
        return None
    return re.sub(r'[<>"\']', '', data)

# Logging & Alerts
def add_log(event, description, ip, severity="INFO"):
    """Add log entry with hash chain validation"""
    try:
        event = sanitize_input(event, 50)
        description = sanitize_input(description, 500)
        
        if not event or not description:
            return False, "Invalid input"

        with open(LOG_FILE, "r") as f:
            logs = json.load(f)

        if os.path.getsize(LOG_FILE) > MAX_LOG_SIZE:
            return False, "Log file size exceeded"

        prev_hash = logs[-1]["hash"] if logs else "0"
        timestamp = datetime.now().isoformat()
        data = f"{timestamp}|{event}|{description}|{ip}|{severity}|{prev_hash}"
        current_hash = hash_data(data)

        log_entry = {
            "id": len(logs) + 1,
            "timestamp": timestamp,
            "event": event,
            "description": description,
            "ip": ip,
            "severity": severity,
            "prev_hash": prev_hash,
            "hash": current_hash
        }

        logs.append(log_entry)
        with open(LOG_FILE, "w") as f:
            json.dump(logs, f, indent=4)

        if severity in ["ALERT", "CRITICAL"]:
            create_alert(event, description, ip)

        return True, "Log added successfully"
    except Exception as e:
        return False, f"Error: {str(e)}"

def create_alert(event, description, ip):
    """Create real-time alert"""
    try:
        with open(ALERTS_FILE, "r") as f:
            alerts = json.load(f)

        alerts.append({
            "id": len(alerts) + 1,
            "timestamp": datetime.now().isoformat(),
            "event": event,
            "description": description,
            "ip": ip,
            "status": "ACTIVE",
            "acknowledged": False
        })

        with open(ALERTS_FILE, "w") as f:
            json.dump(alerts, f, indent=4)
    except Exception as e:
        print(f"Alert error: {str(e)}")

def verify_logs():
    """Verify log integrity with hash chain"""
    try:
        with open(LOG_FILE, "r") as f:
            logs = json.load(f)

        if not logs:
            return True, -1, "No logs to verify"

        for i in range(1, len(logs)):
            curr = logs[i]
            prev = logs[i-1]
            
            data = f"{curr['timestamp']}|{curr['event']}|{curr['description']}|{curr['ip']}|{curr.get('severity', 'INFO')}|{curr['prev_hash']}"
            recalculated = hash_data(data)

            if curr["prev_hash"] != prev["hash"] or curr["hash"] != recalculated:
                return False, i, f"Tampering detected at log #{i}"

        return True, -1, "All logs verified successfully"
    except Exception as e:
        return False, -1, f"Verification error: {str(e)}"

# Security & Authentication
def rate_limit_check(ip):
    """Check rate limiting to prevent brute force"""
    current_time = time.time()
    if ip not in IP_TRACKING:
        IP_TRACKING[ip] = []
    
    IP_TRACKING[ip] = [t for t in IP_TRACKING[ip] if current_time - t < RATE_LIMIT["window"]]
    
    if len(IP_TRACKING[ip]) >= RATE_LIMIT["attempts"]:
        return False
    
    IP_TRACKING[ip].append(current_time)
    return True

def login_required(f):
    """Decorator to require admin authentication"""
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if "admin" not in session:
            flash("Please log in to access this page", "warning")
            return redirect("/admin-login")
        return f(*args, **kwargs)
    return decorated_function

# Routes
@app.route("/")
def home():
    return render_template("index.html")

@app.route("/add", methods=["POST"])
def add():
    try:
        event = request.form.get("event", "").strip()
        desc = request.form.get("desc", "").strip()
        if not event or not desc:
            flash("Event and description required", "error")
            return redirect("/")
        success, msg = add_log(event, desc, request.remote_addr, "INFO")
        flash(("Log added successfully" if success else f"Error: {msg}"), "success" if success else "error")
        return redirect("/logs")
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
        return redirect("/")

@app.route("/logs")
def logs():
    try:
        with open(LOG_FILE, "r") as f:
            data = json.load(f)
        status, index, message = verify_logs()
        return render_template("logs.html", logs=data, status=status, index=index, 
                             message=message, total_logs=len(data))
    except Exception as e:
        flash(f"Error: {str(e)}", "error")
        return redirect("/")

@app.route("/export")
def export():
    try:
        with open(LOG_FILE, "r") as f:
            logs = json.load(f)
        filename = f"logs_export_{datetime.now().strftime('%Y%m%d_%H%M%S')}.csv"
        with open(filename, "w", newline="") as file:
            writer = csv.writer(file)
            writer.writerow(["ID", "Timestamp", "Event", "Description", "IP", "Severity", "Hash"])
            for log in logs:
                writer.writerow([log.get("id", ""), log["timestamp"], log["event"],
                               log["description"], log["ip"], log.get("severity", "INFO"), log["hash"]])
        return send_file(filename, as_attachment=True)
    except Exception as e:
        flash(f"Export error: {str(e)}", "error")
        return redirect("/logs")

@app.route("/logout")
def logout():
    session.pop("admin", None)
    add_log("AUTH", "Admin logged out", request.remote_addr, "INFO")
    flash("Logged out", "success")
    return redirect("/")

# Admin Routes
@app.route("/admin", methods=["GET", "POST"])
def admin():
    """Unified admin interface - login and monitoring dashboard"""
    if "admin" in session:
        # Show dashboard
        try:
            with open(LOG_FILE, "r") as f:
                logs = json.load(f)
            with open(ALERTS_FILE, "r") as f:
                alerts = json.load(f)
            status, index, message = verify_logs()
            active_alerts = [a for a in alerts if a["status"] == "ACTIVE"]
            return render_template("admin.html", logged_in=True, logs=logs[-20:], 
                                 alerts=active_alerts, total_logs=len(logs),
                                 integrity_status=status, integrity_message=message)
        except Exception as e:
            flash(f"Dashboard error: {str(e)}", "error")
            session.pop("admin", None)
            return redirect("/admin")
    
    if request.method == "POST":
        # Login attempt
        ip = request.remote_addr
        if not rate_limit_check(ip):
            add_log("ALERT", "Rate limit exceeded on admin login", ip, "CRITICAL")
            flash("Too many attempts. Try again later.", "error")
            return render_template("admin.html", logged_in=False)
        
        password = request.form.get("password", "")
        if check_password_hash(ADMIN_PASSWORD_HASH, password):
            session["admin"] = True
            add_log("AUTH", "Admin login successful", ip, "WARNING")
            flash("Login successful!", "success")
            return redirect("/admin")
        else:
            add_log("ALERT", "Failed admin login attempt", ip, "CRITICAL")
            flash("Invalid password", "error")
    
    return render_template("admin.html", logged_in=False)

# API Routes
@app.route("/api/alerts")
@login_required
def get_alerts():
    try:
        with open(ALERTS_FILE, "r") as f:
            alerts = json.load(f)
        active = [a for a in alerts if a["status"] == "ACTIVE" and not a["acknowledged"]]
        return jsonify({"success": True, "alerts": active})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/acknowledge-alert/<int:alert_id>", methods=["PUT"])
@login_required
def acknowledge_alert(alert_id):
    try:
        with open(ALERTS_FILE, "r") as f:
            alerts = json.load(f)
        for alert in alerts:
            if alert["id"] == alert_id:
                alert["acknowledged"] = True
                break
        with open(ALERTS_FILE, "w") as f:
            json.dump(alerts, f, indent=4)
        return jsonify({"success": True})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

@app.route("/api/logs/verified")
def get_verified_logs():
    try:
        status, index, message = verify_logs()
        with open(LOG_FILE, "r") as f:
            logs = json.load(f)
        return jsonify({"success": True, "integrity": status, "message": message, 
                       "total_logs": len(logs), "tamper_index": index if index != -1 else None})
    except Exception as e:
        return jsonify({"success": False, "error": str(e)}), 500

# Error Handling
@app.errorhandler(404)
def not_found(error):
    add_log("ALERT", f"404: {request.path}", request.remote_addr, "WARNING")
    return render_template("error.html", error_code=404, message="Page not found"), 404

@app.errorhandler(500)
def server_error(error):
    add_log("ALERT", f"500: {str(error)}", request.remote_addr, "CRITICAL")
    return render_template("error.html", error_code=500, message="Server error"), 500

if __name__ == "__main__":
    init_logs()
    app.run(debug=False, host="127.0.0.1", port=5000)