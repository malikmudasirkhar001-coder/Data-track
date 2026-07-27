#!/usr/bin/env python3
"""
Mudassir Zone - Official CNIC & Sim Database Tracker
Features:
- Individual User Audit Logs & IP Detection
- Multi-Theme Support (Pink, Cyan, Purple)
- Protected Backend API Proxy
- Master Admin Control with Session Termination
- Signed Official PDF Engine Integration
"""

import os
import sqlite3
import requests
from datetime import datetime, timedelta
from flask import (
    Flask, request, jsonify, render_template_string, make_response
)

app = Flask(__name__)
app.secret_key = "mudassir-official-secure-key-2026"

DB_FILE = "/tmp/mudassir_official_db.db"

# Master Credentials
ADMIN_USER = "malikmudasirkhar001@gmail.com"
ADMIN_PASS = "1111"

# HIDDEN API CONFIGURATION
PROTECTED_API_BASE = "https://sim-api.fakcloud.tech/"

# Adsterra / HilltopAds Direct Link
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
                ip_address TEXT NOT NULL
            )
        ''')
        conn.commit()

with app.app_context():
    init_db()

# ----------------------------------------------------------------------------
# FRONTEND ROUTE
# ----------------------------------------------------------------------------
@app.route('/')
def index():
    try:
        with open('index.html', 'r', encoding='utf-8') as f:
            return render_template_string(f.read())
    except FileNotFoundError:
        return "<h3>Error: 'index.html' file not found!</h3>", 404

# ----------------------------------------------------------------------------
# PROTECTED API & USER TRACKING PROXY
# ----------------------------------------------------------------------------
@app.route('/api/protected/trace', methods=['GET'])
def protected_trace():
    query = request.args.get('q', '').strip()
    user_email = request.cookies.get('session_auth')
    auth_role = request.cookies.get('session_role')

    if not user_email:
        return jsonify({"success": False, "message": "Unauthorized access! Please login first."}), 401

    if not query:
        return jsonify({"success": False, "message": "Search query missing."}), 400

    # Capture User IP
    user_ip = request.headers.get('X-Forwarded-For', request.remote_addr)
    if user_ip and ',' in user_ip:
        user_ip = user_ip.split(',')[0].strip()

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

    # Store User Specific Search Record in Database
    with get_db() as conn:
        conn.execute(
            'INSERT INTO trace_logs (user_email, target_query, timestamp, ip_address) VALUES (?, ?, ?, ?)',
            (user_email, query, now, user_ip)
        )
        conn.commit()

    # Call Main API Proxy
    try:
        api_res = requests.get(f"{PROTECTED_API_BASE}?q={query}", timeout=10)
        return jsonify(api_res.json())
    except Exception as e:
        return jsonify({"success": False, "message": "Server-side search failed."}), 500

# ----------------------------------------------------------------------------
# AUTHENTICATION API
# ----------------------------------------------------------------------------
@app.route('/api/auth/login', methods=['POST'])
def api_login():
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')

    if not email or not password:
        return jsonify({"success": False, "message": "All fields are required."}), 400

    if email == ADMIN_USER and password == ADMIN_PASS:
        resp = make_response(jsonify({"success": True, "role": "admin", "email": email}))
        resp.set_cookie('session_auth', email, httponly=True, samesite='Lax')
        resp.set_cookie('session_role', 'admin', httponly=False, samesite='Lax')
        return resp

    with get_db() as conn:
        user = conn.execute('SELECT * FROM users WHERE email = ?', (email,)).fetchone()
        
    if user and user['password'] == password:
        expiry_dt = datetime.strptime(user['expiry_date'], "%Y-%m-%d %H:%M:%S")
        if datetime.now() > expiry_dt:
            return jsonify({"success": False, "message": "Your subscription has expired. Contact Mudassir Support."}), 403
            
        resp = make_response(jsonify({"success": True, "role": "user", "email": email}))
        resp.set_cookie('session_auth', email, httponly=True, samesite='Lax')
        resp.set_cookie('session_role', 'user', httponly=False, samesite='Lax')
        return resp

    return jsonify({"success": False, "message": "Invalid email or access key password."}), 401

@app.route('/api/auth/logout', methods=['POST'])
def api_logout():
    resp = make_response(jsonify({"success": True}))
    resp.set_cookie('session_auth', '', expires=0)
    resp.set_cookie('session_role', '', expires=0)
    return resp

# ----------------------------------------------------------------------------
# ADMIN AUDIT & USER MANAGEMENT ROUTES
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
        
        # Count total searches for each user
        search_count = conn.execute('SELECT COUNT(*) FROM trace_logs WHERE user_email = ?', (u['email'],)).fetchone()[0]
        
        user_list.append({
            "id": u['id'],
            "email": u['email'],
            "password": u['password'],
            "created_at": u['created_at'],
            "validity_days": u['validity_days'],
            "expiry_date": u['expiry_date'],
            "searches_done": search_count,
            "status": status
        })
    return jsonify({"success": True, "users": user_list})

@app.route('/api/admin/user_logs/<path:target_email>', methods=['GET'])
def admin_user_specific_logs(target_email):
    if request.cookies.get('session_role') != 'admin':
        return jsonify({"success": False, "message": "Access Denied"}), 403
        
    with get_db() as conn:
        logs = conn.execute(
            'SELECT target_query, timestamp, ip_address FROM trace_logs WHERE user_email = ? ORDER BY id DESC',
            (target_email,)
        ).fetchall()
        
    log_list = [{"query": l['target_query'], "time": l['timestamp'], "ip": l['ip_address']} for l in logs]
    return jsonify({"success": True, "email": target_email, "logs": log_list})

@app.route('/api/admin/users/create', methods=['POST'])
def admin_create_user():
    if request.cookies.get('session_role') != 'admin':
        return jsonify({"success": False, "message": "Access Denied"}), 403
        
    data = request.get_json() or {}
    email = data.get('email', '').strip().lower()
    password = data.get('password', '')
    days = data.get('days')

    if not email or not password or not days:
        return jsonify({"success": False, "message": "All fields are required."}), 400

    try:
        days_int = int(days)
    except ValueError:
        return jsonify({"success": False, "message": "Days must be an integer."}), 400

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
        return jsonify({"success": True, "message": "User provisioned successfully."})
    except sqlite3.IntegrityError:
        return jsonify({"success": False, "message": "This email already exists."}), 409

@app.route('/api/admin/users/delete/<int:user_id>', methods=['DELETE'])
def admin_delete_user(user_id):
    if request.cookies.get('session_role') != 'admin':
        return jsonify({"success": False, "message": "Access Denied"}), 403
        
    with get_db() as conn:
        conn.execute('DELETE FROM users WHERE id = ?', (user_id,))
        conn.commit()
    return jsonify({"success": True, "message": "User access revoked and deleted."})

@app.route("/1902dca9dec5be85e1ad2e0dbc933621e76d8332")
@app.route("/1902dca9dec5be85e1ad2e0dbc933621e76d8332.txt")
def hilltopads_file():
    return "1902dca9dec5be85e1ad2e0dbc933621e76d8332"

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=5000)
