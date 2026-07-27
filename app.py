#!/usr/bin/env python3
"""
Mudassir Zone - Live CNIC Tracker & Sim Database 2026
Features: Pink Theme, Protected API Fetching, Admin Control, User Tracing Logs, HilltopAds Integration
"""

import os
import sqlite3
import requests
from datetime import datetime, timedelta
from flask import (
    Flask, request, jsonify, render_template_string, make_response
)

app = Flask(__name__)
app.secret_key = "mudassir-secret-pink-key-2026"

DB_FILE = "/tmp/mudassir_database.db"

# Master Credentials
ADMIN_USER = "malikmudasirkhar001@gmail.com"
ADMIN_PASS = "1111"

# HIDDEN API CONFIGURATION (Protected from client theft)
PROTECTED_API_BASE = "https://sim-api.fakcloud.tech/"

# Adsterra / HilltopAds Direct Links & VAST Video URL
VAST_AD_URL = "https://surefootedpause.com/dGmsFnzTd.GYNpvTZ/GSUh/EeIm/9bu/Z/UTlLkGPVTHcPyhNwjIEQ1/M/TBc/t/NDztIP2/METwURyIM/SiZUsOaUWH1kppdwDT0_xD"

def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def init_db():
    with get_db() as conn:
        conn.execute('''
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                email TEXT UNIQUE NOT NULL,
                password TEXT NOT NULL,
                created_at TEXT NOT NULL,
                validity_days INTEGER NOT NULL,
                expiry_date TEXT NOT NULL
            )
        ''')
        conn.execute('''
            CREATE TABLE IF NOT EXISTS trace_logs (
                id INTEGER PRIMARY KEY AUTOINCREMENT,
                user_email TEXT NOT NULL,
                target_query TEXT NOT NULL,
                timestamp TEXT NOT NULL,
                ip_address TEXT
            )
        ''')
        conn.commit()

with app.app_context():
    init_db()

# ----------------------------------------------------------------------------
# HILLTOPADS VERIFICATION ROUTE & ADS HEAD
# ----------------------------------------------------------------------------
HILLTOP_AD_HEAD = """
<meta name="1902dca9dec5be85e1ad2e0dbc933621e76d8332" content="1902dca9dec5be85e1ad2e0dbc933621e76d8332" />
<script>
(function(yufn){
var d = document,
    s = d.createElement('script'),
    l = d.scripts[d.scripts.length - 1];
s.settings = yufn || {};
s.src = "//surefootedpause.com/c.Dy9X6/bf2Q5YlHSIWZQp9KNpzyI/2UM/T_QDyLOYSq0E3jMIjHYmxKNCD/M-z-";
s.async = true;
s.referrerPolicy = 'no-referrer-when-downgrade';
l.parentNode.insertBefore(s, l);
})({})
</script>
"""

# ----------------------------------------------------------------------------
# FRONTEND ROUTE
# ----------------------------------------------------------------------------
@app.route('/')
def index():
    try:
        with open('index.html', 'r', encoding='utf-8') as f:
            return render_template_string(f.read())
    except FileNotFoundError:
        return "<h3>Error: 'index.html' not found!</h3>", 404

# ----------------------------------------------------------------------------
# PROTECTED API PROXY (Prevents API Key / Target Data Leakage)
# ----------------------------------------------------------------------------
@app.route('/api/protected/trace', methods=['GET'])
def protected_trace():
    query = request.args.get('q', '').strip()
    auth_role = request.cookies.get('session_role')
    user_email = request.cookies.get('session_auth')

    if not query:
        return jsonify({"success": False, "message": "Query parameter missing"}), 400

    # Log search data in Database for Admin Monitoring
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    log_user = user_email if user_email else "Guest / Free Access User"
    client_ip = request.remote_addr

    with get_db() as conn:
        conn.execute(
            'INSERT INTO trace_logs (user_email, target_query, timestamp, ip_address) VALUES (?, ?, ?, ?)',
            (log_user, query, now, client_ip)
        )
        conn.commit()

    # Call external API securely from backend
    try:
        api_res = requests.get(f"{PROTECTED_API_BASE}?q={query}", timeout=10)
        return jsonify(api_res.json())
    except Exception as e:
        return jsonify({"success": False, "message": "Server-side trace lookup failed"}), 500

# ----------------------------------------------------------------------------
# AUTHENTICATION API
# ----------------------------------------------------------------------------
@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({"success": False, "message": "All fields are required."}), 400

    if email == ADMIN_USER and password == ADMIN_PASS:
        resp = make_response(jsonify({"success": True, "role": "admin"}))
        resp.set_cookie('session_auth', 'admin_verified', httponly=True, samesite='Lax')
        resp.set_cookie('session_role', 'admin', httponly=False, samesite='Lax')
        return resp

    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
    if user and user['password'] == password:
        expiry_dt = datetime.strptime(user['expiry_date'], "%Y-%m-%d %H:%M:%S")
        if datetime.now() > expiry_dt:
            return jsonify({"success": False, "message": "Your account access has expired. Please contact Mudassir Support."}), 403
            
        resp = make_response(jsonify({"success": True, "role": "user"}))
        resp.set_cookie('session_auth', email, httponly=True, samesite='Lax')
        resp.set_cookie('session_role', 'user', httponly=False, samesite='Lax')
        return resp

    return jsonify({"success": False, "message": "Invalid login credentials."}), 401

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    resp = make_response(jsonify({"success": True}))
    resp.set_cookie('session_auth', '', expires=0)
    resp.set_cookie('session_role', '', expires=0)
    return resp

# ----------------------------------------------------------------------------
# ADMIN PANEL ROUTES
# ----------------------------------------------------------------------------
@app.route('/api/admin/users', methods=['GET'])
def admin_list_users():
    if request.cookies.get('session_role') != 'admin':
        return jsonify({"success": False, "message": "Access Denied"}), 403
        
    with get_db() as conn:
        users = conn.execute('SELECT id, email, password, created_at, validity_days, expiry_date FROM users ORDER BY id DESC').fetchall()
    
    user_list = []
    for u in users:
        expiry_dt = datetime.strptime(u['expiry_date'], "%Y-%m-%d %H:%M:%S")
        status = "Active" if datetime.now() < expiry_dt else "Expired"
        user_list.append({
            "id": u['id'],
            "email": u['email'],
            "password": u['password'],
            "created_at": u['created_at'],
            "validity_days": u['validity_days'],
            "expiry_date": u['expiry_date'],
            "status": status
        })
    return jsonify({"success": True, "users": user_list})

@app.route('/api/admin/trace_logs', methods=['GET'])
def admin_trace_logs():
    if request.cookies.get('session_role') != 'admin':
        return jsonify({"success": False, "message": "Access Denied"}), 403
        
    with get_db() as conn:
        logs = conn.execute('SELECT user_email, target_query, timestamp, ip_address FROM trace_logs ORDER BY id DESC LIMIT 500').fetchall()
        
    log_list = [{"user": l['user_email'], "target": l['target_query'], "time": l['timestamp'], "ip": l['ip_address']} for l in logs]
    return jsonify({"success": True, "logs": log_list})

@app.route('/api/admin/users/create', methods=['POST'])
def admin_create_user():
    if request.cookies.get('session_role') != 'admin':
        return jsonify({"success": False, "message": "Access Denied"}), 403
        
    data = request.get_json() or {}
    email = data.get('email', '').strip()
    password = data.get('password', '')
    days = data.get('days')

    if not email or not password or not days:
        return jsonify({"success": False, "message": "All fields are required."}), 400

    try:
        days_int = int(days)
    except ValueError:
        return jsonify({"success": False, "message": "Validity must be days integer."}), 400

    now = datetime.now()
    created_at = now.strftime("%Y-%m-%d %H:%M:%S")
    expiry_date = (now + timedelta(days=days_int)).strftime("%Y-%m-%d %H:%M:%S")

    try:
        with get_db() as conn:
            conn.execute(
                'INSERT INTO users (email, password, created_at, validity_days, expiry_date) VALUES (?, ?, ?, ?, ?)',
                (email, password, created_at, days_int, expiry_date)
            )
            conn.commit()
        return jsonify({"success": True, "message": "User access created successfully."})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "User with this email already exists."}), 409

@app.route('/api/admin/users/delete/<int:user_id>', methods=['DELETE'])
def admin_delete_user(user_id):
    if request.cookies.get('session_role') != 'admin':
        return jsonify({"success": False, "message": "Access Denied"}), 403
        
    with get_db() as conn:
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
    return jsonify({"success": True, "message": "User access removed."})

@app.route("/1902dca9dec5be85e1ad2e0dbc933621e76d8332")
@app.route("/1902dca9dec5be85e1ad2e0dbc933621e76d8332.txt")
def hilltopads_file():
    return "1902dca9dec5be85e1ad2e0dbc933621e76d8332"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
