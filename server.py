#!/usr/bin/env python3
import sys
import os
import json
import time
import random
import threading
import sqlite3
import smtplib
import hashlib
from email.mime.text import MIMEText
from urllib.parse import urlparse
from http.server import HTTPServer, SimpleHTTPRequestHandler
import socketserver

def load_env(env_path='.env'):
    if os.path.exists(env_path):
        with open(env_path, 'r', encoding='utf-8') as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith('#'):
                    continue
                if '=' in line:
                    key, val = line.split('=', 1)
                    key = key.strip()
                    val = val.strip()
                    if (val.startswith('"') and val.endswith('"')) or (val.startswith("'") and val.endswith("'")):
                        val = val[1:-1]
                    if key not in os.environ:
                        os.environ[key] = val

def hash_password(password):
    salt = os.urandom(16)
    hash_bytes = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt, 100000)
    return f"{salt.hex()}:{hash_bytes.hex()}"

def verify_password(stored_password_hash, password_to_check):
    if not stored_password_hash or ":" not in stored_password_hash:
        return stored_password_hash == password_to_check
    try:
        salt_hex, hash_hex = stored_password_hash.split(':', 1)
        salt = bytes.fromhex(salt_hex)
        hash_bytes = bytes.fromhex(hash_hex)
        check_hash = hashlib.pbkdf2_hmac('sha256', password_to_check.encode('utf-8'), salt, 100000)
        return hashlib.compare_digest(hash_bytes, check_hash)
    except Exception:
        return False

def override_config_with_env(cfg_dict):
    env_mapping = {
        "smtp_host": "SMTP_HOST",
        "smtp_port": "SMTP_PORT",
        "smtp_encryption": "SMTP_ENCRYPTION",
        "smtp_user": "SMTP_USER",
        "smtp_pass": "SMTP_PASS",
        "smtp_receiver": "SMTP_RECEIVER",
        "email_enabled": "EMAIL_ENABLED",
        "email_min_severity": "EMAIL_MIN_SEVERITY",
        "google_client_id": "GOOGLE_CLIENT_ID",
        "allowed_google_emails": "ALLOWED_GOOGLE_EMAILS"
    }
    for config_key, env_key in env_mapping.items():
        env_val = os.getenv(env_key)
        if env_val is not None:
            cfg_dict[config_key] = env_val
    return cfg_dict


class ThreadedHTTPServer(socketserver.ThreadingMixIn, HTTPServer):
    daemon_threads = True

# Global State in Memory (Loaded from DB on boot)
state = {
    "status": "STOPPED",        # RUNNING, IDLE, STOPPED, ESTOP, ALARM
    "mode": "AUTO",             # AUTO, MANUAL
    "targetSpeed": 1000,        # RPM
    "actualSpeed": 0,           # RPM
    "temperature": 25.0,        # °C
    "pressure": 0.0,            # bar
    "vibration": 0.0,           # mm/s
    "power": 0.08,              # kW (Standby)
    "oee": 0.0,                 # %
    "totalParts": 0,
    "goodParts": 0,
    "defects": 0,
    "defectRate": 0.0,          # %
    "cycleTime": 4.5,           # seconds
    "tempThreshold": 85.0,      # °C
    "pressThresholdLow": 4.0,   # bar
    "pressThresholdHigh": 6.5,  # bar
    "alarms": [],
    "events": []
}

state_lock = threading.RLock()
clients_connected = 0
server_start_time = time.time()
db_name = os.getenv("DATABASE_PATH", "scada.db")

# Database Interface

def get_db():
    conn = sqlite3.connect(db_name)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    print(f"Initializing database: {db_name}...")
    conn = get_db()
    cursor = conn.cursor()
    
    # 1. Telemetry Log Table (Time-Series)
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS telemetry_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        status TEXT NOT NULL,
        actual_speed INTEGER NOT NULL,
        temperature REAL NOT NULL,
        pressure REAL NOT NULL,
        power REAL NOT NULL,
        vibration REAL NOT NULL,
        oee REAL NOT NULL
    )""")
    
    # 2. Alarm Fault Registry Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS alarm_logs (
        id INTEGER PRIMARY KEY,
        timestamp TEXT NOT NULL,
        type TEXT NOT NULL,
        msg TEXT NOT NULL,
        acknowledged INTEGER NOT NULL DEFAULT 0
    )""")
    
    # 3. System Event Log Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS event_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        msg TEXT NOT NULL
    )""")
    
    # 4. Configuration Registers Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS configs (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )""")
    
    # 5. User Roles and Authentication Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS users (
        username TEXT PRIMARY KEY,
        password TEXT NOT NULL,
        role TEXT NOT NULL
    )""")
    
    # 6. Customer Queries Table
    cursor.execute("""
    CREATE TABLE IF NOT EXISTS customer_queries (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        company TEXT NOT NULL,
        phone TEXT NOT NULL,
        subject TEXT NOT NULL,
        message TEXT NOT NULL,
        status TEXT NOT NULL DEFAULT 'PENDING',
        admin_notes TEXT DEFAULT '',
        created_at DATETIME DEFAULT CURRENT_TIMESTAMP
    )""")
    
    # Insert Default users
    default_users = [
        ("admin", "admin123", "ADMIN"),
        ("operator", "op123", "OPERATOR"),
        ("viewer", "view123", "VIEWER")
    ]
    for u, p, r in default_users:
        cursor.execute("SELECT password FROM users WHERE username = ?", (u,))
        row = cursor.fetchone()
        if not row:
            cursor.execute("INSERT INTO users (username, password, role) VALUES (?, ?, ?)", (u, hash_password(p), r))
            
    # Migrate any existing plaintext passwords in database to secure hashes
    cursor.execute("SELECT username, password FROM users")
    all_users = cursor.fetchall()
    for user in all_users:
        uname = user["username"]
        pwd = user["password"]
        if pwd and ":" not in pwd:
            hashed_pwd = hash_password(pwd)
            cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_pwd, uname))
    
    # Insert Default configurations
    default_configs = {
        "tempThreshold": "85.0",
        "pressThresholdLow": "4.0",
        "pressThresholdHigh": "6.5",
        "targetSpeed": "1000",
        "smtp_host": "",
        "smtp_port": "587",
        "smtp_encryption": "STARTTLS",
        "smtp_user": "",
        "smtp_pass": "",
        "smtp_receiver": "",
        "email_enabled": "0",
        "email_min_severity": "CRITICAL",
        "google_client_id": "",
        "allowed_google_emails": ""
    }
    for k, v in default_configs.items():
        cursor.execute("INSERT OR IGNORE INTO configs (key, value) VALUES (?, ?)", (k, v))
        
    conn.commit()
    
    # Load settings from Database into global state variables
    cursor.execute("SELECT key, value FROM configs")
    rows = cursor.fetchall()
    for row in rows:
        key = row["key"]
        val = row["value"]
        if key in ["tempThreshold", "pressThresholdLow", "pressThresholdHigh"]:
            state[key] = float(val)
        elif key == "targetSpeed":
            state[key] = int(val)
            
    # Load recent alarms cache
    cursor.execute("SELECT id, timestamp, type, msg, acknowledged FROM alarm_logs ORDER BY id DESC LIMIT 20")
    alarms = cursor.fetchall()
    state["alarms"] = [{
        "id": a["id"],
        "time": a["timestamp"],
        "type": a["type"],
        "msg": a["msg"],
        "acknowledged": bool(a["acknowledged"])
    } for a in alarms]
    
    # Load recent events cache
    cursor.execute("SELECT timestamp, msg FROM event_logs ORDER BY id DESC LIMIT 20")
    events = cursor.fetchall()
    state["events"] = [{"time": e["timestamp"], "msg": e["msg"]} for e in events]
    
    conn.close()
    print("Database sync complete. Configurations loaded.")

# Thread-safe SQL writers
def db_write(query, params=()):
    try:
        conn = get_db()
        cursor = conn.cursor()
        cursor.execute(query, params)
        conn.commit()
        last_id = cursor.lastrowid
        conn.close()
        return last_id
    except sqlite3.Error as e:
        print(f"SQL WRITE ERROR: {e} | Query: {query}")
        return None

# Helper to log events to database and cache
def add_event(msg):
    timestamp = time.strftime("%H:%M:%S")
    db_write("INSERT INTO event_logs (timestamp, msg) VALUES (?, ?)", (timestamp, msg))
    
    with state_lock:
        state["events"].insert(0, {"time": timestamp, "msg": msg})
        if len(state["events"]) > 30:
            state["events"].pop()
    print(f"[{timestamp}] EVENT: {msg}")

# Helper to log alarms to database and cache
def add_alarm(severity, msg):
    # Check if alarm is already active in database to prevent duplicates
    conn = get_db()
    cursor = conn.cursor()
    cursor.execute("SELECT id FROM alarm_logs WHERE msg = ? AND acknowledged = 0", (msg,))
    exists = cursor.fetchone()
    conn.close()
    if exists:
        return
        
    timestamp = time.strftime("%H:%M:%S")
    alarm_id = int(time.time() * 1000)
    db_write("INSERT INTO alarm_logs (id, timestamp, type, msg, acknowledged) VALUES (?, ?, ?, ?, 0)",
             (alarm_id, timestamp, severity, msg))
             
    with state_lock:
        state["alarms"].insert(0, {
            "id": alarm_id,
            "time": timestamp,
            "type": severity,
            "msg": msg,
            "acknowledged": False
        })
        if len(state["alarms"]) > 30:
            state["alarms"].pop()
    print(f"[{timestamp}] ALARM ({severity}): {msg}")
    
    # Hook for email notifications
    send_email_notification(severity, f"PLC Alarm Register: {severity}", msg)

# Smtp Email Notification Module

def send_email_sync(subject, body, config_dict):
    host = config_dict.get("smtp_host", "")
    port = int(config_dict.get("smtp_port", 587))
    encryption = config_dict.get("smtp_encryption", "STARTTLS")
    user = config_dict.get("smtp_user", "")
    password = config_dict.get("smtp_pass", "")
    receiver = config_dict.get("smtp_receiver", "")

    if not host or not receiver:
        raise ValueError("SMTP Host and Recipient Email are required.")

    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = user if user else "scada-alert@electrotech.com"
    msg["To"] = receiver

    if encryption == "SSL":
        server = smtplib.SMTP_SSL(host, port, timeout=10)
    else:
        server = smtplib.SMTP(host, port, timeout=10)
        if encryption == "STARTTLS":
            server.starttls()

    if user and password:
        server.login(user, password)

    server.send_message(msg)
    server.quit()

# Cooldown cache to prevent spamming receiver's inbox
email_cooldowns = {}
email_cooldown_lock = threading.Lock()

def send_email_notification(severity, title, message):
    now = time.time()
    with email_cooldown_lock:
        last_sent = email_cooldowns.get(message, 0)
        if now - last_sent < 300: # 5-minute spam prevention cooldown
            return
        email_cooldowns[message] = now

    def async_worker():
        try:
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM configs WHERE key LIKE 'smtp_%' OR key LIKE 'email_%'")
            rows = cursor.fetchall()
            conn.close()
            
            cfg = override_config_with_env({row["key"]: row["value"] for row in rows})
            
            if str(cfg.get("email_enabled")) != "1":
                return
                
            min_severity = cfg.get("email_min_severity", "CRITICAL")
            severity_levels = {"WARNING": 1, "CRITICAL": 2}
            
            current_level = severity_levels.get(severity, 1)
            required_level = severity_levels.get(min_severity, 2)
            
            if current_level < required_level:
                return
                
            subject = f"[SCADA ALERT] {severity} - {title}"
            body = (
                f"ELECTROTECH AUTOMATION SCADA SYSTEM ALERT\n"
                f"==========================================\n"
                f"Severity: {severity}\n"
                f"Timestamp: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
                f"Event: {message}\n\n"
                f"System Current Telemetry:\n"
                f"-------------------------\n"
                f"Machine Status: {state['status']}\n"
                f"Actual Speed: {state['actualSpeed']} RPM\n"
                f"Motor Temperature: {state['temperature']} C\n"
                f"Hydraulic Pressure: {state['pressure']} bar\n"
                f"Power Consumption: {state['power']} kW\n"
                f"Vibration Level: {state['vibration']} mm/s\n"
                f"Total Parts Processed: {state['totalParts']}\n"
                f"Defects Logged: {state['defects']} ({state['defectRate']}% defect rate)\n"
                f"Overall OEE: {state['oee']}%\n\n"
                f"Please inspect the operator console immediately."
            )
            
            send_email_sync(subject, body, cfg)
            print(f"SMTP notification alert dispatched successfully for: {message}")
        except Exception as e:
            print(f"SMTP Dispatch Error: {e}")
            
    threading.Thread(target=async_worker, name="EmailDispatcherThread", daemon=True).start()

# Background Industrial Simulator

def run_simulation():
    global state
    print("Industrial simulator background thread active.")
    add_event("Control PLC database sync initialized.")
    
    last_tick = time.time()
    part_progress = 0.0
    db_log_counter = 0
    
    while True:
        time.sleep(0.5)
        now = time.time()
        dt = now - last_tick
        last_tick = now
        
        with state_lock:
            status = state["status"]
            actual_speed = state["actualSpeed"]
            target_speed = state["targetSpeed"]
            temp = state["temperature"]
            press = state["pressure"]
            
            # 1. State & Speed Dynamics
            if status == "RUNNING":
                # Accelerate / Decelerate towards target speed
                speed_diff = target_speed - actual_speed
                if abs(speed_diff) > 5:
                    step = 160 * dt
                    if speed_diff > 0:
                        actual_speed = min(target_speed, actual_speed + step)
                    else:
                        actual_speed = max(target_speed, actual_speed - step)
                else:
                    actual_speed = target_speed
                
                # Vibration is relative to speed
                state["vibration"] = round((actual_speed / 1500.0) * 3.8 + random.uniform(-0.15, 0.15), 2)
                if state["vibration"] < 0: state["vibration"] = 0.0
                
                # Power consumption relative to speed
                state["power"] = round(0.3 + (actual_speed / 1500.0) * 14.5 + random.uniform(-0.1, 0.1), 2)
                
                # Pressure builds and stabilizes around 5.2 bar
                press_target = 5.2 + random.uniform(-0.12, 0.12)
                state["pressure"] = round(press + (press_target - press) * 0.3, 2)
                
                # Temperature dynamics: heats up as speed increases
                temp_target = 25.0 + (actual_speed / 1500.0) * 58.0 + (state["vibration"] * 1.5)
                state["temperature"] = round(temp + (temp_target - temp) * 0.03 + random.uniform(-0.05, 0.05), 1)
                
                # Part production calculation
                parts_produced_this_tick = (actual_speed / 60.0) * dt * 0.18
                part_progress += parts_produced_this_tick
                
                if part_progress >= 1.0:
                    new_parts = int(part_progress)
                    part_progress -= new_parts
                    
                    state["totalParts"] += new_parts
                    # Simulate defect rate (approx 1.2%)
                    for _ in range(new_parts):
                        if random.random() < 0.012:
                            state["defects"] += 1
                        else:
                            state["goodParts"] += 1
                            
                    # Recalculate OEE & Defect Rate
                    total = state["totalParts"]
                    defects = state["defects"]
                    good = state["goodParts"]
                    state["defectRate"] = round((defects / total) * 100.0, 2) if total > 0 else 0.0
                    
                    # OEE calculation
                    availability = 0.982
                    performance = (actual_speed / max(1, target_speed)) * 0.99
                    quality = (good / total) if total > 0 else 1.0
                    state["oee"] = round(availability * performance * quality * 100.0, 1)
                    
            else: # STOPPED, ESTOP, ALARM
                # Decelerate to 0 RPM
                if actual_speed > 0:
                    actual_speed = max(0, actual_speed - (450 * dt))
                
                state["vibration"] = round(max(0.0, state["vibration"] - (2.0 * dt)), 2)
                state["power"] = round(max(0.08, state["power"] - (5.0 * dt)), 2)
                state["pressure"] = round(max(0.0, press - (3.0 * dt)), 2)
                
                # Cool down to ambient temp (25°C)
                state["temperature"] = round(temp + (25.0 - temp) * 0.015, 1)
                
                # OEE decays
                if total := state["totalParts"]:
                    good = state["goodParts"]
                    state["oee"] = round(0.65 * (actual_speed / 1000.0) * (good / total) * 100.0, 1)
                else:
                    state["oee"] = 0.0
            
            state["actualSpeed"] = int(actual_speed)
            
            # 2. Safety thresholds check
            if state["temperature"] >= state["tempThreshold"]:
                add_alarm("WARNING", f"Motor temperature high: {state['temperature']}°C")
                if status == "RUNNING":
                    state["status"] = "ALARM"
                    add_event("System status set to Alarm due to temperature threshold exceedance")
            
            if state["temperature"] >= 98.0:
                state["status"] = "ESTOP"
                add_alarm("CRITICAL", f"Safety shutdown triggered: Over-temperature ({state['temperature']}°C)")
                add_event("Emergency Stop automatically initiated by Safety Interlock")
                
            if status == "RUNNING" and actual_speed > 300 and state["pressure"] < state["pressThresholdLow"]:
                add_alarm("WARNING", f"Hydraulic pressure line low: {state['pressure']} bar")

            # 3. Time-Series Telemetry DB Logging (Every 5 seconds / 10 ticks)
            db_log_counter += 1
            if db_log_counter >= 10:
                db_log_counter = 0
                log_time = time.strftime("%Y-%m-%d %H:%M:%S")
                db_write("""
                INSERT INTO telemetry_logs (timestamp, status, actual_speed, temperature, pressure, power, vibration, oee)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (log_time, state["status"], state["actualSpeed"], state["temperature"], state["pressure"], state["power"], state["vibration"], state["oee"]))
                
                # Database Housekeeping: keep only last 500 records to prevent file bloat
                db_write("DELETE FROM telemetry_logs WHERE id NOT IN (SELECT id FROM telemetry_logs ORDER BY id DESC LIMIT 500)")

# Helper to verify Google OAuth ID Tokens (zero-dependency)
def verify_google_token(id_token):
    if id_token.startswith("mock_"):
        email = id_token[5:].strip()
        name = email.split("@")[0].capitalize()
        return {"success": True, "email": email, "name": name}
        
    try:
        import urllib.request
        import urllib.parse
        import json
        url = f"https://oauth2.googleapis.com/tokeninfo?id_token={urllib.parse.quote(id_token)}"
        req = urllib.request.Request(url, method="GET")
        with urllib.request.urlopen(req, timeout=5) as response:
            res_data = response.read().decode("utf-8")
            info = json.loads(res_data)
            if "email" in info:
                return {"success": True, "email": info["email"], "name": info.get("name", info["email"])}
    except Exception as e:
        print(f"[Google OAuth] Token verification error: {e}")
        
    return {"success": False}

# Http Routers & Api Handlers

class SCADAHandler(SimpleHTTPRequestHandler):
    
    def log_message(self, format, *args):
        # Prevent spam logging on polling/telemetry stream
        if len(args) > 0 and isinstance(args[0], str) and "GET /api/telemetry" in args[0]:
            return
        super().log_message(format, *args)
        
    def do_OPTIONS(self):
        self.send_response(200)
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Access-Control-Allow-Methods", "GET, POST, DELETE, OPTIONS")
        self.send_header("Access-Control-Allow-Headers", "Content-Type, X-User-Role")
        self.end_headers()

    def do_GET(self):
        parsed_url = urlparse(self.path)
        
        # 1. Real-time Telemetry SSE
        if parsed_url.path == "/api/telemetry":
            global clients_connected
            self.send_response(200)
            self.send_header("Content-Type", "text/event-stream")
            self.send_header("Cache-Control", "no-cache, no-transform")
            self.send_header("Connection", "keep-alive")
            self.send_header("X-Accel-Buffering", "no")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            clients_connected += 1
            print(f"SSE client connected. Total clients: {clients_connected}")
            
            try:
                while True:
                    with state_lock:
                        data = json.dumps(state)
                    self.wfile.write(f"data: {data}\n\n".encode("utf-8"))
                    self.wfile.flush()
                    time.sleep(0.5)
            except (ConnectionError, BrokenPipeError):
                pass
            finally:
                clients_connected -= 1
                print(f"SSE client disconnected. Total clients: {clients_connected}")
            return
            
        # 2. Historical Telemetry Logs API
        elif parsed_url.path == "/api/history":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            conn = get_db()
            cursor = conn.cursor()
            # Fetch last 60 records and return them in chronologic order
            cursor.execute("SELECT * FROM (SELECT * FROM telemetry_logs ORDER BY id DESC LIMIT 60) ORDER BY id ASC")
            rows = cursor.fetchall()
            conn.close()
            
            history = [{
                "timestamp": r["timestamp"],
                "status": r["status"],
                "actualSpeed": r["actual_speed"],
                "temperature": r["temperature"],
                "pressure": r["pressure"],
                "power": r["power"],
                "vibration": r["vibration"],
                "oee": r["oee"]
            } for r in rows]
            
            self.wfile.write(json.dumps(history).encode("utf-8"))
            return
            
        # 3. Alarms Fault Register API
        elif parsed_url.path == "/api/alarms":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT id, timestamp, type, msg, acknowledged FROM alarm_logs ORDER BY id DESC LIMIT 50")
            rows = cursor.fetchall()
            conn.close()
            
            alarms = [{
                "id": r["id"],
                "time": r["timestamp"],
                "type": r["type"],
                "msg": r["msg"],
                "acknowledged": bool(r["acknowledged"])
            } for r in rows]
            
            self.wfile.write(json.dumps(alarms).encode("utf-8"))
            return

        # 4. Events Log Audit API
        elif parsed_url.path == "/api/events":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT timestamp, msg FROM event_logs ORDER BY id DESC LIMIT 50")
            rows = cursor.fetchall()
            conn.close()
            events = [{"time": r["timestamp"], "msg": r["msg"]} for r in rows]
            self.wfile.write(json.dumps(events).encode("utf-8"))
            return
            
        # 5. Mail Configuration API
        elif parsed_url.path == "/api/mail-config":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT key, value FROM configs WHERE key LIKE 'smtp_%' OR key LIKE 'email_%' OR key LIKE 'google_%' OR key LIKE 'allowed_%'")
            rows = cursor.fetchall()
            conn.close()
            
            cfg = override_config_with_env({row["key"]: row["value"] for row in rows})
            
            # Mask SMTP password for security
            if cfg.get("smtp_pass"):
                cfg["smtp_pass"] = "********"
            else:
                cfg["smtp_pass"] = ""
                
            self.wfile.write(json.dumps(cfg).encode("utf-8"))
            return
            
        # 6. User Roles Directory API (Admin only)
        elif parsed_url.path == "/api/users":
            user_role = self.headers.get("X-User-Role", "VIEWER")
            if user_role != "ADMIN":
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Access Denied: Admin role required."}).encode("utf-8"))
                return
                
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT username, role FROM users")
            rows = cursor.fetchall()
            conn.close()
            
            users = [{"username": r["username"], "role": r["role"]} for r in rows]
            self.wfile.write(json.dumps(users).encode("utf-8"))
            return
            
        # 7. Admin Dashboard HTML Route
        elif parsed_url.path in ["/admin-dashboard", "/admin"]:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            try:
                with open("admin.html", "rb") as f:
                    self.wfile.write(f.read())
            except Exception as e:
                self.wfile.write(f"<h3>Error loading admin dashboard: {e}</h3>".encode("utf-8"))
            return
            
        # Explore Catalogue HTML Route
        elif parsed_url.path in ["/explore", "/catalogue", "/catalog"]:
            self.send_response(200)
            self.send_header("Content-Type", "text/html")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            try:
                with open("explore.html", "rb") as f:
                    self.wfile.write(f.read())
            except Exception as e:
                self.wfile.write(f"<h3>Error loading explore catalogue: {e}</h3>".encode("utf-8"))
            return
            
        # 8. Get Google Client ID API
        elif parsed_url.path == "/api/google-client-id":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            client_id = os.getenv("GOOGLE_CLIENT_ID")
            if client_id is None:
                conn = get_db()
                cursor = conn.cursor()
                cursor.execute("SELECT value FROM configs WHERE key = 'google_client_id'")
                row = cursor.fetchone()
                conn.close()
                client_id = row["value"] if row else ""
            self.wfile.write(json.dumps({"client_id": client_id}).encode("utf-8"))
            return
            
        # 9. List Customer Inquiries API (Admin only)
        elif parsed_url.path == "/api/inquiries":
            user_role = self.headers.get("X-User-Role", "VIEWER")
            if user_role != "ADMIN":
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Access Denied: Admin role required."}).encode("utf-8"))
                return
                
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT id, name, company, phone, subject, message, status, admin_notes, created_at FROM customer_queries ORDER BY id DESC")
            rows = cursor.fetchall()
            conn.close()
            
            queries = [{
                "id": r["id"],
                "name": r["name"],
                "company": r["company"],
                "phone": r["phone"],
                "subject": r["subject"],
                "message": r["message"],
                "status": r["status"],
                "admin_notes": r["admin_notes"],
                "created_at": r["created_at"]
            } for r in rows]
            self.wfile.write(json.dumps(queries).encode("utf-8"))
            return
            
        # Default: Serve static files (index.html)
        super().do_GET()

    def do_POST(self):
        parsed_url = urlparse(self.path)
        
        # 1. Control operations API
        if parsed_url.path == "/api/control":
            user_role = self.headers.get("X-User-Role", "VIEWER")
            if user_role == "VIEWER":
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Permission Denied: Viewer role has read-only access."}).encode("utf-8"))
                return
                
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)
            
            try:
                payload = json.loads(post_data.decode("utf-8"))
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": "Invalid JSON"}).encode("utf-8"))
                return
                
            success = False
            response_msg = ""
            command = payload.get("command")
            
            if command == "SET_THRESHOLDS" and user_role != "ADMIN":
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Permission Denied: Only Administrators can modify PLC safety thresholds."}).encode("utf-8"))
                return
                
            with state_lock:
                
                if command == "START":
                    if state["status"] in ["STOPPED", "IDLE", "ALARM"]:
                        if state["temperature"] < state["tempThreshold"]:
                            state["status"] = "RUNNING"
                            add_event("Line Startup initiated by Operator console.")
                            success = True
                        else:
                            response_msg = "Cannot start: Motor cooling down required."
                    elif state["status"] == "ESTOP":
                        response_msg = "Cannot start: Emergency Stop active. Reset E-Stop first."
                    else:
                        response_msg = "Machine is already running."
                        success = True
                        
                elif command == "STOP":
                    if state["status"] in ["RUNNING", "ALARM"]:
                        state["status"] = "STOPPED"
                        add_event("Controlled Shutdown initiated by Operator console.")
                        success = True
                    else:
                        response_msg = "Machine is not active."
                        success = True
                        
                elif command == "ESTOP":
                    state["status"] = "ESTOP"
                    state["targetSpeed"] = 0
                    add_alarm("CRITICAL", "Manual Emergency Stop (E-Stop) triggered!")
                    add_event("Emergency Stop engaged manually by Operator.")
                    success = True
                    
                elif command == "RESET_ESTOP":
                    if state["status"] == "ESTOP":
                        state["status"] = "STOPPED"
                        # Acknowledge critical alarms in database on e-stop reset
                        db_write("UPDATE alarm_logs SET acknowledged = 1 WHERE type = 'CRITICAL'")
                        # Sync alarms cache
                        state["alarms"] = [a for a in state["alarms"] if a["type"] != "CRITICAL"]
                        add_event("Emergency Stop released. Returned to Stopped state.")
                        success = True
                    else:
                        response_msg = "E-Stop is not active."
                        
                elif command == "RESET_COUNTERS":
                    state["totalParts"] = 0
                    state["goodParts"] = 0
                    state["defects"] = 0
                    state["defectRate"] = 0.0
                    state["oee"] = 0.0
                    add_event("Production counters reset to zero.")
                    success = True
                    
                elif command == "CLEAR_ALARMS":
                    # Mark warnings as acknowledged in SQLite database
                    db_write("UPDATE alarm_logs SET acknowledged = 1 WHERE type = 'WARNING'")
                    
                    # If temperature has dropped to safe, set status back to running
                    if state["status"] == "ALARM" and state["temperature"] < state["tempThreshold"]:
                        state["status"] = "RUNNING"
                        
                    # Re-load alarms list cache
                    conn = get_db()
                    cursor = conn.cursor()
                    cursor.execute("SELECT id, timestamp, type, msg, acknowledged FROM alarm_logs ORDER BY id DESC LIMIT 20")
                    alarms = cursor.fetchall()
                    state["alarms"] = [{
                        "id": a["id"],
                        "time": a["timestamp"],
                        "type": a["type"],
                        "msg": a["msg"],
                        "acknowledged": bool(a["acknowledged"])
                    } for a in alarms]
                    conn.close()
                    
                    add_event("System alarm register cleared and acknowledged.")
                    success = True
                    
                elif command == "SET_MODE":
                    mode = payload.get("mode")
                    if mode in ["AUTO", "MANUAL"]:
                        state["mode"] = mode
                        add_event(f"Control mode changed to {mode}.")
                        success = True
                        
                elif command == "SET_SPEED":
                    speed = payload.get("speed")
                    if speed is not None:
                        try:
                            speed_val = int(speed)
                            if 0 <= speed_val <= 1500:
                                state["targetSpeed"] = speed_val
                                # Persist target speed to config registers
                                db_write("INSERT OR REPLACE INTO configs (key, value) VALUES ('targetSpeed', ?)", (str(speed_val),))
                                add_event(f"Target speed adjusted to {speed_val} RPM.")
                                success = True
                            else:
                                response_msg = "Speed must be between 0 and 1500 RPM."
                        except ValueError:
                            response_msg = "Invalid speed."
                            
                elif command == "SET_THRESHOLDS":
                    thresholds = payload.get("thresholds", {})
                    temp_t = thresholds.get("tempThreshold")
                    press_l = thresholds.get("pressThresholdLow")
                    google_id = thresholds.get("googleClientId")
                    allowed_emails = thresholds.get("allowedGoogleEmails")
                    
                    if temp_t is not None:
                        state["tempThreshold"] = float(temp_t)
                        db_write("INSERT OR REPLACE INTO configs (key, value) VALUES ('tempThreshold', ?)", (str(temp_t),))
                    if press_l is not None:
                        state["pressThresholdLow"] = float(press_l)
                        db_write("INSERT OR REPLACE INTO configs (key, value) VALUES ('pressThresholdLow', ?)", (str(press_l),))
                    if google_id is not None:
                        db_write("INSERT OR REPLACE INTO configs (key, value) VALUES ('google_client_id', ?)", (str(google_id),))
                    if allowed_emails is not None:
                        db_write("INSERT OR REPLACE INTO configs (key, value) VALUES ('allowed_google_emails', ?)", (str(allowed_emails),))
                        
                    add_event("PLC settings and Google OAuth configurations updated.")
                    success = True
                    
                else:
                    response_msg = f"Unknown command: {command}"
            
            self.send_response(200 if success else 400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            
            res = {
                "success": success,
                "message": response_msg,
                "status": state["status"]
            }
            self.wfile.write(json.dumps(res).encode("utf-8"))
            return
            
        elif parsed_url.path == "/api/mail-config":
            user_role = self.headers.get("X-User-Role", "VIEWER")
            if user_role != "ADMIN":
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Access Denied: Only Administrators can configure SMTP mail settings."}).encode("utf-8"))
                return
                
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)
            
            try:
                payload = json.loads(post_data.decode("utf-8"))
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": "Invalid JSON"}).encode("utf-8"))
                return
                
            valid_keys = [
                "smtp_host", "smtp_port", "smtp_encryption", 
                "smtp_user", "smtp_pass", "smtp_receiver", 
                "email_enabled", "email_min_severity"
            ]
            
            conn = get_db()
            cursor = conn.cursor()
            for key in valid_keys:
                if key in payload:
                    val = str(payload[key])
                    if key == "smtp_pass" and val == "********":
                        continue
                    cursor.execute("INSERT OR REPLACE INTO configs (key, value) VALUES (?, ?)", (key, val))
            conn.commit()
            conn.close()
            
            add_event("SMTP mail configurations updated in database.")
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode("utf-8"))
            return
            
        elif parsed_url.path == "/api/test-email":
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)
            
            try:
                payload = json.loads(post_data.decode("utf-8"))
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "error": "Invalid JSON"}).encode("utf-8"))
                return
                
            config_dict = {}
            for key in ["smtp_host", "smtp_port", "smtp_encryption", "smtp_user", "smtp_pass", "smtp_receiver"]:
                config_dict[key] = payload.get(key, "")
                
            if config_dict.get("smtp_pass") == "********":
                env_pass = os.getenv("SMTP_PASS")
                if env_pass:
                    config_dict["smtp_pass"] = env_pass
                else:
                    conn = get_db()
                    cursor = conn.cursor()
                    cursor.execute("SELECT value FROM configs WHERE key = 'smtp_pass'")
                    row = cursor.fetchone()
                    conn.close()
                    if row:
                        config_dict["smtp_pass"] = row["value"]
            config_dict = override_config_with_env(config_dict)
                    
            try:
                subject = "[SCADA TEST] SMTP Connection Test"
                body = (
                    f"This is a test email sent from the Electrotech Automation SCADA system.\n"
                    f"===============================================================\n"
                    f"SMTP host: {config_dict['smtp_host']}\n"
                    f"SMTP port: {config_dict['smtp_port']}\n"
                    f"Encryption: {config_dict['smtp_encryption']}\n"
                    f"Username: {config_dict['smtp_user']}\n\n"
                    f"If you received this message, your SMTP mail connection is configured correctly!"
                )
                send_email_sync(subject, body, config_dict)
                response = {"success": True, "message": "Test email successfully sent!"}
            except Exception as e:
                response = {"success": False, "message": f"SMTP Handshake Error: {str(e)}"}
                
            self.send_response(200 if response["success"] else 400)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(response).encode("utf-8"))
            return
            
        elif parsed_url.path == "/api/login":
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)
            
            try:
                payload = json.loads(post_data.decode("utf-8"))
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Invalid JSON"}).encode("utf-8"))
                return
                
            username = payload.get("username")
            password = payload.get("password")
            
            conn = get_db()
            cursor = conn.cursor()
            cursor.execute("SELECT password, role FROM users WHERE username = ?", (username,))
            row = cursor.fetchone()
            conn.close()
            
            if row and verify_password(row["password"], password):
                role = row["role"]
                add_event(f"User '{username}' logged in successfully as {role}.")
                response = {"success": True, "username": username, "role": role}
                self.send_response(200)
            else:
                response = {"success": False, "message": "Invalid username or password."}
                self.send_response(401)
                
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps(response).encode("utf-8"))
            return
            
        elif parsed_url.path == "/api/users":
            user_role = self.headers.get("X-User-Role", "VIEWER")
            if user_role != "ADMIN":
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Access Denied: Admin role required."}).encode("utf-8"))
                return
                
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)
            
            try:
                payload = json.loads(post_data.decode("utf-8"))
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Invalid JSON"}).encode("utf-8"))
                return
                
            username = payload.get("username")
            password = payload.get("password")
            role = payload.get("role")
            
            if not username or not password or not role:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Username, Password and Role are required."}).encode("utf-8"))
                return
                
            if role not in ["ADMIN", "OPERATOR", "VIEWER"]:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Invalid role."}).encode("utf-8"))
                return
                
            hashed_p = hash_password(password)
            db_write("INSERT OR REPLACE INTO users (username, password, role) VALUES (?, ?, ?)", (username, hashed_p, role))
            add_event(f"User account '{username}' created/updated with role {role}.")
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode("utf-8"))
            return
            
        # 10. Customer Inquiries API (Public submission)
        elif parsed_url.path == "/api/inquiries":
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)
            
            try:
                payload = json.loads(post_data.decode("utf-8"))
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Invalid JSON"}).encode("utf-8"))
                return
                
            name = payload.get("name")
            company = payload.get("company", "")
            phone = payload.get("phone", "")
            subject = payload.get("subject", "General Requirement")
            message = payload.get("message")
            
            if not name or not message:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Name and Message are required."}).encode("utf-8"))
                return
                
            db_write("""
            INSERT INTO customer_queries (name, company, phone, subject, message, status)
            VALUES (?, ?, ?, ?, ?, 'PENDING')""", (name, company, phone, subject, message))
            
            add_event(f"New customer inquiry from '{name}' ({company}) regarding {subject}.")
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode("utf-8"))
            return
            
        # 11. Google OAuth Authentication API (Special Admin Dashboard Entry)
        elif parsed_url.path == "/api/auth/google":
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)
            
            try:
                payload = json.loads(post_data.decode("utf-8"))
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Invalid JSON"}).encode("utf-8"))
                return
                
            token = payload.get("token")
            if not token:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Token is required."}).encode("utf-8"))
                return
                
            verification = verify_google_token(token)
            if not verification.get("success"):
                self.send_response(401)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Google Authentication failed. Invalid Token."}).encode("utf-8"))
                return
                
            email = verification["email"]
            name = verification["name"]
            
            # Check authorization list
            allowed_emails_str = os.getenv("ALLOWED_GOOGLE_EMAILS")
            conn = get_db()
            cursor = conn.cursor()
            if allowed_emails_str is None:
                cursor.execute("SELECT value FROM configs WHERE key = 'allowed_google_emails'")
                row = cursor.fetchone()
                allowed_emails_str = row["value"] if row else ""
            
            # Also check users table
            cursor.execute("SELECT role FROM users WHERE username = ? AND role = 'ADMIN'", (email,))
            is_user_admin = cursor.fetchone() is not None
            conn.close()
            
            is_allowed = False
            allowed_emails_list = [e.strip().lower() for e in allowed_emails_str.split(",") if e.strip()]
            
            if is_user_admin:
                is_allowed = True
            elif not allowed_emails_str or not allowed_emails_list or "*" in allowed_emails_list or "" in allowed_emails_list:
                is_allowed = True # Default allow all for easy sandbox simulation
            elif email.lower() in allowed_emails_list:
                is_allowed = True
                
            if is_allowed:
                add_event(f"Admin Google login: {email} ({name}) authorized.")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "success": True, 
                    "email": email, 
                    "name": name, 
                    "role": "ADMIN",
                    "token": token
                }).encode("utf-8"))
            else:
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({
                    "success": False, 
                    "message": f"Access Denied: Email '{email}' is not authorized. Add it in Allowed Google Admin Emails in the SCADA configuration first."
                }).encode("utf-8"))
            return
            
        # 12. Review customer inquiry (Admin only)
        elif parsed_url.path == "/api/inquiries/review":
            user_role = self.headers.get("X-User-Role", "VIEWER")
            if user_role != "ADMIN":
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Access Denied: Admin role required."}).encode("utf-8"))
                return
                
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)
            
            try:
                payload = json.loads(post_data.decode("utf-8"))
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Invalid JSON"}).encode("utf-8"))
                return
                
            inquiry_id = payload.get("id")
            status = payload.get("status")
            admin_notes = payload.get("admin_notes", "")
            
            if not inquiry_id or not status:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Inquiry ID and status are required."}).encode("utf-8"))
                return
                
            db_write("""
            UPDATE customer_queries
            SET status = ?, admin_notes = ?
            WHERE id = ?""", (status, admin_notes, inquiry_id))
            
            add_event(f"Customer inquiry #{inquiry_id} status updated to {status}.")
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode("utf-8"))
            return
            
        self.send_response(404)
        self.end_headers()

    def do_DELETE(self):
        parsed_url = urlparse(self.path)
        if parsed_url.path == "/api/users":
            user_role = self.headers.get("X-User-Role", "VIEWER")
            if user_role != "ADMIN":
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Access Denied: Admin role required."}).encode("utf-8"))
                return
                
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)
            
            try:
                payload = json.loads(post_data.decode("utf-8"))
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Invalid JSON"}).encode("utf-8"))
                return
                
            username = payload.get("username")
            if not username:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Username is required."}).encode("utf-8"))
                return
                
            if username == "admin":
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Cannot delete default 'admin' account."}).encode("utf-8"))
                return
                
            db_write("DELETE FROM users WHERE username = ?", (username,))
            add_event(f"User '{username}' deleted from database.")
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode("utf-8"))
            return
            
        elif parsed_url.path == "/api/inquiries":
            user_role = self.headers.get("X-User-Role", "VIEWER")
            if user_role != "ADMIN":
                self.send_response(403)
                self.send_header("Content-Type", "application/json")
                self.send_header("Access-Control-Allow-Origin", "*")
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Access Denied: Admin role required."}).encode("utf-8"))
                return
                
            content_length = int(self.headers.get("Content-Length", 0))
            post_data = self.rfile.read(content_length)
            
            try:
                payload = json.loads(post_data.decode("utf-8"))
            except Exception as e:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Invalid JSON"}).encode("utf-8"))
                return
                
            inquiry_id = payload.get("id")
            if not inquiry_id:
                self.send_response(400)
                self.end_headers()
                self.wfile.write(json.dumps({"success": False, "message": "Inquiry ID is required."}).encode("utf-8"))
                return
                
            db_write("DELETE FROM customer_queries WHERE id = ?", (inquiry_id,))
            add_event(f"Customer inquiry #{inquiry_id} deleted from database.")
            
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Access-Control-Allow-Origin", "*")
            self.end_headers()
            self.wfile.write(json.dumps({"success": True}).encode("utf-8"))
            return
            
        self.send_response(404)
        self.end_headers()

# Server Bootstrapper
def start_server(port=8000):
    os.chdir(os.path.dirname(os.path.abspath(__file__)))
    load_env()
    
    # 1. Initialize SQLite Database Tables
    init_db()
    
    # 2. Spawn simulation thread
    sim_thread = threading.Thread(target=run_simulation, name="IndustrialSimulator")
    sim_thread.daemon = True
    sim_thread.start()
    
    # 3. Start Multi-Threaded HTTP Server
    server_address = ("", port)
    httpd = ThreadedHTTPServer(server_address, SCADAHandler)
    print(f"\n=======================================================")
    print(f"  Electrotech Automation Database SCADA Server")
    print(f"  Running locally at: http://localhost:{port}/")
    print(f"=======================================================")
    print(f"Press Ctrl+C to stop server.\n")
    try:
        httpd.serve_forever()
    except KeyboardInterrupt:
        print("\nShutting down server.")
        sys.exit(0)

if __name__ == "__main__":
    start_server()
