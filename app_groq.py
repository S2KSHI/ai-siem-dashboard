from flask import Flask, jsonify, request, render_template
import os
import platform
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parent
LOCAL_CACHE_DIR = PROJECT_ROOT / ".cache"
LOCAL_CACHE_DIR.mkdir(exist_ok=True)
os.environ.setdefault("HOME", str(PROJECT_ROOT))
os.environ.setdefault("USERPROFILE", str(PROJECT_ROOT))
os.environ.setdefault("XDG_CACHE_HOME", str(LOCAL_CACHE_DIR))

import tensorflow as tf
import numpy as np
import psutil
import datetime
import sqlite3
from ollama_lib import OllamaClient
from scapy.all import sniff
from scapy.layers.inet import IP, TCP, UDP
import ipaddress
import threading
import requests
import re
from collections import deque
import time
import GPUtil
from huggingface_hub import hf_hub_download
from flask_socketio import SocketIO, emit

DISK_PATH = 'C:\\' if platform.system() == 'Windows' else '/'

_prev_net_io = psutil.net_io_counters()
_prev_net_time = time.time()

GROQ_API_KEY = os.getenv("GROQ_API_KEY", "")
GROQ_HEADERS = {
    "Authorization": f"Bearer {GROQ_API_KEY}",
    "Content-Type": "application/json"
} if GROQ_API_KEY else {}

app = Flask(__name__)
socketio = SocketIO(app, async_mode="threading", cors_allowed_origins="*")
metrics_task_lock = threading.Lock()
metrics_task_started = False

MODEL_PATH = 'SecIDS-CNN.h5'
MODEL_ID = "Keyven/SecIDS-CNN"
FILENAME = "SecIDS-CNN.h5"
HF_TOKEN = os.getenv("HF_TOKEN", "hf_XXX")

if not os.path.exists(MODEL_PATH):
    print("Downloading model from Hugging Face...")
    try:
        model_file = hf_hub_download(repo_id=MODEL_ID, filename=FILENAME, token=HF_TOKEN)
        model = tf.keras.models.load_model(model_file)
        model.save(MODEL_PATH)
        print("Model successfully downloaded and saved.")
    except Exception as e:
        print(f"Error downloading the model: {e}")
        model = None
else:
    print("Loading model from local storage...")
    model = tf.keras.models.load_model(MODEL_PATH)
    print("Model successfully loaded from local storage.")

ollama_client = OllamaClient(base_url="http://localhost:11434")

def get_db_connection():
    conn = sqlite3.connect('system_metrics.db', check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def initialize_database():
    with get_db_connection() as conn:
        conn.execute("""
            CREATE TABLE IF NOT EXISTS network_requests (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                ip TEXT, type TEXT, country TEXT, summary TEXT,
                blacklisted TEXT, attacks INTEGER, reports INTEGER,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_network_requests_timestamp ON network_requests (timestamp);")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                log TEXT
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_logs_timestamp ON logs (timestamp);")
        conn.execute("""
            CREATE TABLE IF NOT EXISTS metrics (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
                cpu REAL, memory REAL, disk REAL, network INTEGER
            );
        """)
        conn.execute("CREATE INDEX IF NOT EXISTS idx_metrics_timestamp ON metrics (timestamp);")
        conn.commit()

initialize_database()


def classify_resource_severity(value):
    if value >= 90:
        return "critical"
    if value >= 75:
        return "warning"
    return "normal"


def classify_log_severity(message):
    normalized = (message or "").lower()
    critical_terms = ("critical", "attack", "breach", "malware", "ransomware", "blacklisted", "blocked")
    warning_terms = ("warning", "suspicious", "error", "failed", "high system load", "timeout")
    if any(term in normalized for term in critical_terms):
        return "critical"
    if any(term in normalized for term in warning_terms):
        return "warning"
    return "info"


def classify_network_severity(entry):
    attacks = entry.get("attacks") or 0
    blacklisted = (entry.get("blacklisted") or "").lower() == "yes"
    if blacklisted or attacks >= 10:
        return "critical"
    if attacks > 0:
        return "warning"
    return "info"


def compute_alert_summary(cpu=None, memory=None, disk=None):
    with get_db_connection() as conn:
        log_rows = conn.execute("SELECT log FROM logs ORDER BY timestamp DESC LIMIT 100").fetchall()
        network_rows = conn.execute(
            "SELECT ip, blacklisted, attacks FROM network_requests ORDER BY timestamp DESC LIMIT 100"
        ).fetchall()

    logs_by_severity = {"critical": 0, "warning": 0, "info": 0}
    for row in log_rows:
        logs_by_severity[classify_log_severity(row["log"])] += 1

    network_by_severity = {"critical": 0, "warning": 0, "info": 0}
    for row in network_rows:
        severity = classify_network_severity(dict(row))
        network_by_severity[severity] += 1

    cpu = psutil.cpu_percent() if cpu is None else cpu
    memory = psutil.virtual_memory().percent if memory is None else memory
    disk = psutil.disk_usage(DISK_PATH).percent if disk is None else disk
    resource_severities = [
        classify_resource_severity(cpu),
        classify_resource_severity(memory),
        classify_resource_severity(disk),
    ]
    resource_score = "critical" if "critical" in resource_severities else "warning" if "warning" in resource_severities else "normal"

    return {
        "resource_state": resource_score,
        "resource_alerts": {
            "cpu": classify_resource_severity(cpu),
            "memory": classify_resource_severity(memory),
            "disk": classify_resource_severity(disk),
        },
        "logs": logs_by_severity,
        "network": network_by_severity,
        "totals": {
            "critical": logs_by_severity["critical"] + network_by_severity["critical"],
            "warning": logs_by_severity["warning"] + network_by_severity["warning"],
            "info": logs_by_severity["info"] + network_by_severity["info"],
        },
    }


def groq_enabled():
    return bool(GROQ_API_KEY)


def build_local_chat_response(user_message, cpu, memory, disk, logs, network_data):
    user_text = (user_message or "").lower()
    issues = []
    if cpu >= 85:
        issues.append(f"CPU is elevated at {cpu:.1f}%")
    if memory >= 80:
        issues.append(f"memory is elevated at {memory:.1f}%")
    if disk >= 90:
        issues.append(f"disk is elevated at {disk:.1f}%")

    network_count = len(network_data)
    recent_log_count = len(logs)

    greetings = ["hi", "hello", "hey", "hii", "helo", "howdy", "sup"]
    if any(word in user_text.strip() for word in greetings):
        return (
            "Hello! I'm your AI Security Operator. How can I help you today?\n\n"
            "Here's what I can do:\n"
            "1. System Summary - CPU, Memory & Disk health\n"
            "2. Network Review - Suspicious IPs & traffic\n"
            "3. Alerts Recap - Critical warnings & threats\n\n"
            "Just reply with 1, 2, or 3 to get started!"
        )

    if user_text.strip() == "1" or "system" in user_text or "cpu" in user_text or "memory" in user_text or "disk" in user_text:
        response = f"System Summary: CPU is at {cpu:.1f}%, Memory at {memory:.1f}%, Disk at {disk:.1f}%."
        if issues:
            response += " Issues detected: " + ", ".join(issues) + "."
        else:
            response += " Everything looks stable."
        response += "\n\nWhat else can I help with?\n1. System Summary\n2. Network Review\n3. Alerts Recap"
        return response

    if user_text.strip() == "2" or "network" in user_text or "ip" in user_text or "traffic" in user_text:
        latest = network_data[0] if network_data else None
        if latest:
            response = f"Network Review: {network_count} recent records. Latest IP: {latest.get('ip', 'unknown')} from {latest.get('country', 'unknown')}."
        else:
            response = "Network Review: No recent network activity detected."
        response += "\n\nWhat else can I help with?\n1. System Summary\n2. Network Review\n3. Alerts Recap"
        return response

    if user_text.strip() == "3" or "alert" in user_text or "log" in user_text or "warning" in user_text:
        latest_log = logs[0] if logs else None
        if latest_log:
            severity = classify_log_severity(latest_log)
            response = f"Alerts Recap: {recent_log_count} recent log entries. Latest is {severity}: {latest_log[:100]}"
        else:
            response = "Alerts Recap: No recent alerts found."
        response += "\n\nWhat else can I help with?\n1. System Summary\n2. Network Review\n3. Alerts Recap"
        return response

    return (
        f"Current status: CPU {cpu:.1f}%, Memory {memory:.1f}%, Disk {disk:.1f}%.\n\n"
        "What can I help you with?\n1. System Summary\n2. Network Review\n3. Alerts Recap"
    )


def get_ip_country(ip):
    try:
        if ":" in ip or ipaddress.ip_address(ip).is_private:
            return "Unverifiable"
        response = requests.get(f"https://geolocation-db.com/json/{ip}&position=true").json()
        country = response.get("country_name", "Unknown")
        city = response.get("city", "Unknown")
        state = response.get("state", "Unknown")
        return f"{country}, {city}, {state}"
    except (requests.RequestException, ValueError):
        return "Error"


MAX_NETWORK_REQUESTS = 1000
network_requests = deque(maxlen=MAX_NETWORK_REQUESTS)


@app.route('/system-info', methods=['GET'])
def system_info():
    try:
        cpu_freq = psutil.cpu_freq().current if psutil.cpu_freq() else 'N/A'
        cpu_cores = psutil.cpu_count(logical=False)
        cpu_usage = psutil.cpu_percent()
        memory = psutil.virtual_memory().total
        disk = psutil.disk_usage(DISK_PATH).total

        gpus = GPUtil.getGPUs()
        if gpus:
            gpu_usage = f"{gpus[0].load * 100:.2f}%"
            gpu_memory_used = f"{gpus[0].memoryUsed} MB"
            gpu_memory_total = f"{gpus[0].memoryTotal} MB"
        else:
            gpu_usage = "0.00%"
            gpu_memory_used = "0.0 MB"
            gpu_memory_total = "4096.0 MB"

        battery = psutil.sensors_battery()
        power_usage = battery.percent if battery else 'N/A'

        system_info_data = {
            "cpu_frequency": cpu_freq,
            "cpu_cores": cpu_cores,
            "cpu_usage": cpu_usage,
            "gpu_usage": gpu_usage,
            "gpu_memory_used": gpu_memory_used,
            "gpu_memory_total": gpu_memory_total,
            "power_usage": power_usage,
            "memory_total": memory,
            "disk_total": disk
        }
        print("System Info:", system_info_data)
        return jsonify(system_info_data)

    except Exception as e:
        print("Error retrieving system information:", e)
        return jsonify({"error": "Error retrieving system information"}), 500


def analyze_packet_with_cnn(packet_data):
    if model is None:
        return "unknown"
    prediction = model.predict(np.array([packet_data]))[0]
    return "suspicious" if prediction[1] > 0.5 else "normal"


def send_system_metrics():
    global _prev_net_io, _prev_net_time
    while True:
        cpu_usage = psutil.cpu_percent()
        memory_usage = psutil.virtual_memory().percent
        disk_usage = psutil.disk_usage(DISK_PATH).percent
        alert_summary = compute_alert_summary(cpu=cpu_usage, memory=memory_usage, disk=disk_usage)

        current_net_io = psutil.net_io_counters()
        current_time = time.time()
        elapsed = max(current_time - _prev_net_time, 0.01)
        bytes_sent_per_sec = (current_net_io.bytes_sent - _prev_net_io.bytes_sent) / elapsed
        bytes_recv_per_sec = (current_net_io.bytes_recv - _prev_net_io.bytes_recv) / elapsed
        _prev_net_io = current_net_io
        _prev_net_time = current_time

        socketio.emit('update_metrics', {
            'cpu_usage': cpu_usage,
            'memory_usage': memory_usage,
            'disk_usage': disk_usage,
            'cpu_frequency': psutil.cpu_freq().current if psutil.cpu_freq() else 0,
            'cpu_cores': psutil.cpu_count(),
            'gpu_usage': 'N/A',
            'gpu_memory_used': 'N/A',
            'gpu_memory_total': 'N/A',
            'power_usage': 'N/A',
            'memory_total': psutil.virtual_memory().total,
            'disk_total': psutil.disk_usage(DISK_PATH).total,
            'alerts': alert_summary,
            'net_sent_per_sec': round(bytes_sent_per_sec, 2),
            'net_recv_per_sec': round(bytes_recv_per_sec, 2),
            'net_total_sent': current_net_io.bytes_sent,
            'net_total_recv': current_net_io.bytes_recv
        })

        logs = fetch_recent_logs()
        network_data = fetch_recent_network_data()

        if groq_enabled():
            try:
                payload = {
                    "model": "llama-3.1-8b-instant",
                    "messages": [
                        {"role": "system", "content": f"System metrics: CPU: {cpu_usage}%, RAM: {memory_usage}%, Disk: {disk_usage}%."},
                        {"role": "user", "content": f"Logs: {logs}, Network: {network_data}"}
                    ]
                }
                response = requests.post(
                    "https://api.groq.com/openai/v1/chat/completions",
                    headers=GROQ_HEADERS,
                    json=payload,
                    timeout=8
                )
                response_data = response.json()
                assistant_message = response_data.get("choices", [{}])[0].get("message", {}).get("content", "No response")
                save_log(f"AI response: {assistant_message}")
            except requests.RequestException as e:
                print(f"Groq error: {e}")

        time.sleep(5)


def fetch_recent_logs():
    with get_db_connection() as conn:
        logs = conn.execute("SELECT log FROM logs ORDER BY timestamp DESC LIMIT 5").fetchall()
    return [log["log"] for log in logs]


def fetch_recent_network_data():
    with get_db_connection() as conn:
        network_data = conn.execute("SELECT ip, country, summary FROM network_requests ORDER BY timestamp DESC LIMIT 5").fetchall()
    return [{"ip": r["ip"], "country": r["country"], "summary": r["summary"]} for r in network_data]


@socketio.on('connect')
def handle_connect():
    print("Client connected")
    emit('alert_summary', compute_alert_summary())


@socketio.on('new_log')
def handle_new_log(log_data):
    socketio.emit('new_log', log_data)


@socketio.on('new_network_request')
def handle_new_network_request(network_data):
    socketio.emit('new_network_request', network_data)


def packet_callback(packet):
    if packet.haslayer(IP) and (packet.haslayer(TCP) or packet.haslayer(UDP)):
        ip = packet[IP].src
        summary = packet.summary()

        excluded_ips = {"144.76.114.3", "159.89.102.253"}
        if ip in excluded_ips or ipaddress.ip_address(ip).is_private or ":" in ip:
            country = "Local/IPv6 or excluded"
            is_blacklisted = False
            attacks = 0
            reports = 0
        else:
            country = get_ip_country(ip)
            blacklist_status = check_ip_blacklist_cached(ip)
            is_blacklisted = blacklist_status["blacklisted"]
            attacks = blacklist_status.get("attacks", 0)
            reports = blacklist_status.get("reports", 0)

        with get_db_connection() as conn:
            conn.execute("""
                INSERT INTO network_requests (ip, type, country, summary, blacklisted, attacks, reports)
                VALUES (?, ?, ?, ?, ?, ?, ?)
            """, (ip, "IPv4", country, summary, "Yes" if is_blacklisted else "No", attacks, reports))
            conn.commit()

        network_event = {
            "ip": ip, "type": "IPv4", "country": country, "summary": summary,
            "blacklisted": "Yes" if is_blacklisted else "No",
            "attacks": attacks, "reports": reports,
            "severity": classify_network_severity({
                "blacklisted": "Yes" if is_blacklisted else "No",
                "attacks": attacks,
            })
        }
        socketio.emit('new_network_request', network_event)
        socketio.emit('alert_summary', compute_alert_summary())
        log_message = f"Network packet from {ip} ({country}) - Blacklisted: {is_blacklisted}"
        save_log(log_message)
        if is_blacklisted:
            notify_ai(log_message)


@app.route('/logs', methods=['GET'])
def get_logs():
    page = int(request.args.get('page', 1))
    page_size = 50
    offset = (page - 1) * page_size
    query = request.args.get('query', '').strip()
    severity_filter = request.args.get('severity', '').strip().lower()
    sql = "SELECT timestamp, log FROM logs"
    params = []
    clauses = []
    if query:
        clauses.append("log LIKE ?")
        params.append(f"%{query}%")
    if clauses:
        sql += " WHERE " + " AND ".join(clauses)
    sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
    params.extend([page_size, offset])
    with get_db_connection() as conn:
        logs = conn.execute(sql, params).fetchall()

    serialized_logs = []
    for log in logs:
        severity = classify_log_severity(log["log"])
        if severity_filter and severity != severity_filter:
            continue
        serialized_logs.append({"timestamp": log["timestamp"], "log": log["log"], "severity": severity})
    return jsonify(serialized_logs)


@app.route('/search-logs', methods=['POST'])
def search_logs():
    search_term = request.json.get('query', '')
    with get_db_connection() as conn:
        logs = conn.execute("""
            SELECT timestamp, log FROM logs WHERE log LIKE ? ORDER BY timestamp DESC
        """, ('%' + search_term + '%',)).fetchall()
    return jsonify([{"timestamp": log["timestamp"], "log": log["log"], "severity": classify_log_severity(log["log"])} for log in logs])


def save_metrics(cpu, memory, disk, network):
    with get_db_connection() as conn:
        conn.execute("""
            INSERT INTO metrics (timestamp, cpu, memory, disk, network) VALUES (?, ?, ?, ?, ?)
        """, (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), cpu, memory, disk, network))
        conn.commit()


def save_log(log):
    with get_db_connection() as conn:
        conn.execute("""
            INSERT INTO logs (timestamp, log) VALUES (?, ?)
        """, (datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'), log))
        conn.commit()
    socketio.emit('new_log', {
        "timestamp": datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S'),
        "log": log,
        "severity": classify_log_severity(log)
    })
    socketio.emit('alert_summary', compute_alert_summary())


def notify_ai(message):
    short_prompt = f"{message}\nPlease answer briefly and concisely, maximum 1-2 sentences."
    try:
        response = ollama_client.generate(prompt=short_prompt)
        save_log(f"AI notification: {response}")
    except Exception as exc:
        save_log(f"AI notification unavailable: {exc}")


def analyze_metrics(cpu, memory, disk):
    if cpu > 85 or memory > 80 or disk > 90:
        message = f"Warning: High system load - CPU: {cpu}%, RAM: {memory}%, Disk: {disk}%."
        notify_ai(message)


@app.route('/')
def home():
    return render_template('index.html')


@app.route('/server-status', methods=['GET'])
def server_status():
    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent
    disk = psutil.disk_usage(DISK_PATH).percent
    print(f"CPU: {cpu}, Memory: {memory}, Disk: {disk}")
    save_metrics(cpu, memory, disk, 0)
    analyze_metrics(cpu, memory, disk)
    net_io = psutil.net_io_counters()
    return jsonify({
        "cpu_usage": cpu, "memory_usage": memory, "disk_usage": disk,
        "alerts": compute_alert_summary(cpu=cpu, memory=memory, disk=disk),
        "net_total_sent": net_io.bytes_sent,
        "net_total_recv": net_io.bytes_recv
    })


@app.route('/alert-summary', methods=['GET'])
def alert_summary():
    return jsonify(compute_alert_summary())


def check_ip_blacklist_cached(ip):
    with get_db_connection() as conn:
        result = conn.execute("SELECT blacklisted, attacks, reports FROM network_requests WHERE ip = ?", (ip,)).fetchone()
        if result:
            return {
                "blacklisted": result["blacklisted"] == "Yes",
                "attacks": result["attacks"],
                "reports": result["reports"]
            }
        url = f"http://api.blocklist.de/api.php?ip={ip}&format=json"
        try:
            response = requests.get(url)
            data = response.json() if response.status_code == 200 else {"blacklisted": False}
            blacklisted = data.get("attacks", 0) > 0
            attacks = data.get("attacks", 0)
            reports = data.get("reports", 0)
            conn.execute(
                "INSERT INTO network_requests (ip, blacklisted, attacks, reports) VALUES (?, ?, ?, ?)",
                (ip, "Yes" if blacklisted else "No", attacks, reports)
            )
            conn.commit()
            return {"blacklisted": blacklisted, "attacks": attacks, "reports": reports}
        except requests.RequestException:
            return {"blacklisted": False}


def extract_ip_from_message(message):
    ip_pattern = r'\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b'
    match = re.search(ip_pattern, message)
    return match.group(0) if match else None


@app.route('/chat', methods=['POST'])
def chat_with_groq():
    data = request.get_json()
    user_message = data.get('message', '')
    assistant_source = "local"

    cpu = psutil.cpu_percent(interval=1)
    memory = psutil.virtual_memory().percent
    disk = psutil.disk_usage(DISK_PATH).percent

    logs = fetch_recent_logs()
    network_data = fetch_recent_network_data()

    greetings = ["hi", "hello", "hey", "hii", "helo", "howdy", "sup","holla","hlo","greetings"]
    is_greeting = any(word == user_message.lower().strip() for word in greetings)

    if is_greeting:
        context_message = (
            "You are a friendly AI security assistant. "
            "The user just greeted you. Reply ONLY with this exact message, nothing else:\n\n"
            "Hello! I am your AI Security Operator. How can I help you today?\n\n"
            "Here is what I can do:\n"
            "1. System Summary - CPU, Memory and Disk health\n"
            "2. Network Review - Suspicious IPs and traffic\n"
            "3. Alerts Recap - Critical warnings and threats\n\n"
            "Just reply with 1, 2, or 3 to get started!"
        )
    else:
        context_message = (
            f"You are a friendly AI security assistant for a SIEM dashboard.\n"
            f"STRICT RULES:\n"
            f"- Keep reply under 4 sentences. Be friendly and clear.\n"
            f"- If user says '1' or asks about system: report CPU {cpu:.1f}%, Memory {memory:.1f}%, Disk {disk:.1f}% in plain English.\n"
            f"- If user says '2' or asks about network: summarize this data in plain English: {network_data}\n"
            f"- If user says '3' or asks about alerts: summarize this log data in plain English: {logs}\n"
            f"- After EVERY answer, end with:\n"
            f"  What else can I help with?\n"
            f"  1. System Summary\n"
            f"  2. Network Review\n"
            f"  3. Alerts Recap\n"
            f"- Never show raw data or JSON. Always explain in simple English.\n\n"
            f"User message: {user_message}"
        )

    payload = {
        "model": "llama-3.1-8b-instant",
        "messages": [{"role": "user", "content": context_message}]
    }

    assistant_message = None

    if groq_enabled():
        try:
            response = requests.post(
                "https://api.groq.com/openai/v1/chat/completions",
                headers=GROQ_HEADERS,
                json=payload,
                timeout=15
            )
            response_data = response.json()
            assistant_message = response_data.get("choices", [{}])[0].get("message", {}).get("content", "")
            assistant_source = "groq"
        except requests.RequestException as e:
            print("Groq error:", e)

    if not assistant_message:
        try:
            assistant_message = ollama_client.generate(prompt=context_message)
            assistant_source = "ollama"
        except Exception as exc:
            print("Ollama error:", exc)

    if not assistant_message:
        assistant_message = build_local_chat_response(user_message, cpu, memory, disk, logs, network_data)
        assistant_source = "local"

    save_log(f"User: {user_message}, AI: {assistant_message}")
    return jsonify({"response": assistant_message, "source": assistant_source})


@app.route('/network-requests', methods=['GET'])
def get_network_requests():
    try:
        page = int(request.args.get('page', 1))
        page_size = 50
        offset = (page - 1) * page_size
        query = request.args.get('query', '').strip()
        blacklisted_filter = request.args.get('blacklisted', '').strip().lower()
        severity_filter = request.args.get('severity', '').strip().lower()
        sql = "SELECT ip, type, country, summary, blacklisted, attacks, reports, timestamp FROM network_requests"
        params = []
        clauses = []
        if query:
            clauses.append("(ip LIKE ? OR country LIKE ? OR summary LIKE ?)")
            like_query = f"%{query}%"
            params.extend([like_query, like_query, like_query])
        if blacklisted_filter in {"yes", "no"}:
            clauses.append("blacklisted = ?")
            params.append("Yes" if blacklisted_filter == "yes" else "No")
        if clauses:
            sql += " WHERE " + " AND ".join(clauses)
        sql += " ORDER BY timestamp DESC LIMIT ? OFFSET ?"
        params.extend([page_size, offset])
        with get_db_connection() as conn:
            db_rows = conn.execute(sql, params).fetchall()
        data = []
        for row in db_rows:
            entry = dict(row)
            entry["severity"] = classify_network_severity(entry)
            if severity_filter and entry["severity"] != severity_filter:
                continue
            data.append(entry)
        return jsonify(data)
    except Exception as e:
        print(f"Network requests error: {e}")
        return jsonify({"error": "Error fetching network requests"}), 500


def start_sniffing():
    try:
        sniff(prn=packet_callback, store=0)
    except Exception as exc:
        save_log(f"Packet sniffing unavailable: {exc}")


def ensure_metrics_task():
    global metrics_task_started
    with metrics_task_lock:
        if not metrics_task_started:
            socketio.start_background_task(send_system_metrics)
            metrics_task_started = True


def start_background_services():
    ensure_metrics_task()
    sniffing_thread = threading.Thread(target=start_sniffing, daemon=True)
    sniffing_thread.start()


if __name__ == '__main__':
    start_background_services()
    socketio.run(app, debug=True, port=5000, use_reloader=False, allow_unsafe_werkzeug=True)