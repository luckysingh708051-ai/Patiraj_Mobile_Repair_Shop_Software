import sqlite3
import os
import hashlib
import secrets
import hmac
import socket
from datetime import datetime
import json
from flask import Flask, request, jsonify, render_template_string, redirect, url_for, session, send_file

app = Flask(__name__)
app.secret_key = os.environ.get("FLASK_SECRET_KEY", "patiraj_repair_secret_key_2026_secured_salt_token")
DB_FILE = "mobile_repair_manager.db"

# -----------------------------------------------------------------------------
# DATABASE INITIALIZATION & SCHEMA
# -----------------------------------------------------------------------------
def get_db():
    conn = sqlite3.connect(DB_FILE)
    conn.row_factory = sqlite3.Row
    return conn

def hash_password(password: str, salt_hex: str = None) -> tuple[str, str]:
    if salt_hex is None:
        salt_bytes = secrets.token_bytes(32)
        salt_hex = salt_bytes.hex()
    else:
        salt_bytes = bytes.fromhex(salt_hex)
    pwd_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_bytes, 200_000)
    return pwd_hash.hex(), salt_hex

def verify_pwd(password: str, stored_hash_hex: str, salt_hex: str) -> bool:
    try:
        salt_bytes = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(stored_hash_hex)
        actual_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_bytes, 200_000)
        return hmac.compare_digest(expected_hash, actual_hash)
    except Exception:
        return False

def log_audit(action: str, entity_type: str = "", entity_id: str = "", details: str = ""):
    try:
        user_id = session.get("user_id")
        username = session.get("username", "system")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_db()
        conn.execute(
            "INSERT INTO audit_logs(timestamp, user_id, username, action, entity_type, entity_id, details) VALUES(?,?,?,?,?,?,?)",
            (now, user_id, username, action, entity_type, str(entity_id), details)
        )
        conn.commit()
        conn.close()
    except Exception:
        pass

def init_db():
    conn = get_db()
    cur = conn.cursor()
    cur.execute("PRAGMA foreign_keys = ON")
    cur.execute("PRAGMA journal_mode = WAL")

    cur.execute("""CREATE TABLE IF NOT EXISTS app_preferences (
        key TEXT PRIMARY KEY,
        value TEXT NOT NULL
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT UNIQUE NOT NULL,
        password_hash TEXT NOT NULL,
        salt TEXT NOT NULL,
        role TEXT NOT NULL DEFAULT 'admin',
        full_name TEXT DEFAULT '',
        created_at TEXT NOT NULL,
        last_login TEXT DEFAULT '',
        is_active INTEGER NOT NULL DEFAULT 1
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS audit_logs (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        timestamp TEXT NOT NULL,
        user_id INTEGER,
        username TEXT NOT NULL,
        action TEXT NOT NULL,
        entity_type TEXT DEFAULT '',
        entity_id TEXT DEFAULT '',
        details TEXT DEFAULT ''
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS parts (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        name TEXT NOT NULL,
        brand TEXT DEFAULT '',
        model TEXT DEFAULT '',
        compatible_models TEXT DEFAULT '',
        category TEXT DEFAULT '',
        quantity INTEGER NOT NULL DEFAULT 0,
        purchase_price REAL NOT NULL DEFAULT 0,
        selling_price REAL NOT NULL DEFAULT 0,
        low_stock INTEGER NOT NULL DEFAULT 2,
        supplier TEXT DEFAULT '',
        updated_at TEXT DEFAULT CURRENT_TIMESTAMP
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS stock_history (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        part_id INTEGER,
        action TEXT NOT NULL,
        quantity INTEGER NOT NULL,
        note TEXT DEFAULT '',
        sale_price REAL DEFAULT 0,
        purchase_price REAL DEFAULT 0,
        created_at TEXT NOT NULL,
        FOREIGN KEY(part_id) REFERENCES parts(id)
    )""")

    cur.execute("""CREATE TABLE IF NOT EXISTS phones (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        customer_name TEXT NOT NULL,
        customer_phone TEXT DEFAULT '',
        phone_model TEXT NOT NULL,
        problem TEXT DEFAULT '',
        work_required TEXT DEFAULT '',
        pending_reason TEXT DEFAULT '',
        estimated_charge REAL DEFAULT 0,
        repair_cost REAL DEFAULT 0,
        status TEXT DEFAULT 'Pending',
        received_date TEXT DEFAULT '',
        notes TEXT DEFAULT '',
        delivered_date TEXT DEFAULT ''
    )""")

    # Seed default admin if no users exist
    user_count = cur.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
    if user_count == 0:
        pwd_hash, salt = hash_password("Admin123")
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        cur.execute(
            "INSERT INTO users(username, password_hash, salt, role, full_name, created_at) VALUES(?,?,?,?,?,?)",
            ("admin", pwd_hash, salt, "admin", "Shop Owner", now)
        )

    conn.commit()
    conn.close()

try:
    init_db()
except Exception:
    pass

def get_local_ip():
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(0.5)
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
        s.close()
        if ip and not ip.startswith('127.'):
            return ip
    except Exception:
        pass

    try:
        hostname = socket.gethostname()
        ip = socket.gethostbyname(hostname)
        if ip and not ip.startswith('127.'):
            return ip
    except Exception:
        pass

    try:
        for info in socket.getaddrinfo(socket.gethostname(), None, socket.AF_INET):
            cand = info[4][0]
            if cand and not cand.startswith('127.'):
                return cand
    except Exception:
        pass

    return '127.0.0.1'

# -----------------------------------------------------------------------------
# HTML TEMPLATE (Mobile-First for Android & Windows Desktop HTML/CSS)
# -----------------------------------------------------------------------------
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="hi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <meta name="theme-color" content="#1e293b">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <meta name="apple-mobile-web-app-title" content="Patiraj Repair">
  <link rel="manifest" href="/manifest.json">
  <link rel="icon" type="image/svg+xml" href="/static/icon.svg">
  <link rel="apple-touch-icon" href="/static/icon.svg">
  <title>Patiraj Mobile Repair Shop - Manager</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700;800&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0f172a;
      --card: #1e293b;
      --border: #334155;
      --accent: #2563eb;
      --accent-hover: #1d4ed8;
      --success: #10b981;
      --warning: #f59e0b;
      --danger: #ef4444;
      --purple: #a855f7;
      --text: #f8fafc;
      --muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Outfit', sans-serif; -webkit-tap-highlight-color: transparent; }
    body { background: var(--bg); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; padding-bottom: 75px; }
    
    /* Header */
    header {
      background: rgba(30, 41, 59, 0.98); backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 50;
      padding: 10px 16px; display: flex; align-items: center; justify-content: space-between;
      gap: 10px;
    }
    .brand-title { display: flex; align-items: center; gap: 8px; min-width: 0; flex-shrink: 1; }
    .brand-icon { font-size: 1.3rem; flex-shrink: 0; }
    .brand-text { display: flex; align-items: baseline; gap: 8px; min-width: 0; }
    .brand-name {
      font-size: 1.12rem; font-weight: 700; color: #fff; letter-spacing: -0.2px;
      white-space: nowrap; overflow: hidden; text-overflow: ellipsis;
    }
    .brand-badge {
      font-size: 0.65rem; background: rgba(37, 99, 235, 0.2); color: #60a5fa;
      border: 1px solid rgba(37, 99, 235, 0.4); padding: 2px 7px; border-radius: 9999px; font-weight: 600;
      white-space: nowrap;
    }
    .header-actions { display: flex; align-items: center; gap: 8px; flex-shrink: 0; }
    .user-pill {
      display: flex; align-items: center; gap: 6px; font-size: 0.8rem; background: #0f172a;
      padding: 5px 11px; border-radius: 9999px; border: 1px solid var(--border);
      white-space: nowrap;
    }
    .btn-logout {
      color: #f87171; text-decoration: none; font-weight: 700; margin-left: 3px;
      background: rgba(239,68,68,0.15); padding: 2px 7px; border-radius: 6px; font-size: 0.74rem;
    }
    .btn-logout:hover { background: var(--danger); color: #fff; }
    .btn-header {
      background: #334155; color: #fff; border: none; padding: 6px 11px; border-radius: 7px;
      font-size: 0.78rem; font-weight: 600; cursor: pointer; text-decoration: none; display: inline-flex; align-items: center; gap: 5px;
      white-space: nowrap; transition: background 0.15s;
    }
    .btn-header:hover { background: #475569; }

    /* Top Nav Tabs */
    .top-nav {
      background: #1e293b; border-bottom: 1px solid var(--border);
      position: sticky; top: 54px; z-index: 40; overflow-x: auto; white-space: nowrap;
      scrollbar-width: none; -webkit-overflow-scrolling: touch;
    }
    .top-nav::-webkit-scrollbar { display: none; }
    .top-nav-inner { display: flex; padding: 6px 12px; gap: 6px; max-width: 1400px; margin: 0 auto; }
    .nav-tab {
      padding: 7px 13px; font-size: 0.82rem; font-weight: 600; color: var(--muted);
      cursor: pointer; border-radius: 8px; transition: all 0.15s ease; display: inline-flex; align-items: center; gap: 5px;
      white-space: nowrap; background: rgba(255,255,255,0.03); border: 1px solid transparent;
    }
    .nav-tab:hover { color: #fff; background: rgba(255,255,255,0.06); }
    .nav-tab.active { color: #fff; background: var(--accent); border-color: var(--accent); box-shadow: 0 2px 8px rgba(37,99,235,0.35); }

    /* Mobile Responsive Header */
    @media (max-width: 768px) {
      header {
        padding: 8px 10px;
        gap: 6px;
      }
      .brand-title { gap: 6px; }
      .brand-icon { font-size: 1.15rem; }
      .brand-name { font-size: 0.92rem; max-width: 155px; }
      .brand-badge { display: none; }
      .header-actions { gap: 4px; }
      .btn-header { padding: 5px 8px; font-size: 0.74rem; }
      .btn-header .btn-label { display: none; }
      .user-pill { padding: 4px 7px; font-size: 0.74rem; }
      .user-role-label { display: none; }
      .top-nav {
        top: 48px;
        background: #162032;
      }
      .top-nav-inner { padding: 5px 8px; gap: 5px; }
      .nav-tab { padding: 5px 10px; font-size: 0.76rem; border-radius: 20px; }
    }

    @media (min-width: 769px) {
      .bottom-nav { display: none !important; }
      body { padding-bottom: 0 !important; }
    }

    /* Bottom Nav Bar (Mobile) */
    .bottom-nav {
      position: fixed; bottom: 0; left: 0; right: 0; background: rgba(30, 41, 59, 0.98);
      border-top: 1px solid var(--border); display: flex; justify-content: space-around;
      padding: 7px 4px; z-index: 50; backdrop-filter: blur(10px);
    }
    .bottom-tab {
      display: flex; flex-direction: column; align-items: center; gap: 3px;
      color: var(--muted); font-size: 0.72rem; font-weight: 500; cursor: pointer; text-decoration: none; flex: 1;
    }
    .bottom-tab.active { color: var(--accent); font-weight: 700; }
    .bottom-tab-icon { font-size: 1.25rem; }

    /* Main Container */
    main { flex: 1; max-width: 1400px; width: 100%; margin: 0 auto; padding: 16px 14px; }
    
    /* Stats Grid */
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 10px; margin-bottom: 16px; }
    .stat-card {
      background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 13px 15px;
      box-shadow: 0 4px 16px rgba(0,0,0,0.15); transition: transform 0.15s;
    }
    .stat-card:hover { transform: translateY(-2px); }
    .stat-label { font-size: 0.73rem; font-weight: 600; text-transform: uppercase; color: var(--muted); margin-bottom: 4px; letter-spacing: 0.5px; }
    .stat-val { font-size: 1.35rem; font-weight: 700; color: #fff; }
    .stat-sub { font-size: 0.7rem; color: var(--muted); margin-top: 2px; }
    .accent-green { color: var(--success); }
    .accent-blue { color: var(--accent); }
    .accent-cyan { color: #06b6d4; }
    .accent-orange { color: var(--warning); }

    /* Action bar */
    .action-bar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; justify-content: space-between; margin-bottom: 12px; }
    .search-input {
      background: var(--card); border: 1px solid var(--border); color: var(--text); padding: 8px 12px;
      border-radius: 8px; font-size: 0.88rem; min-width: 180px; flex: 1; outline: none;
    }
    .search-input:focus { border-color: var(--accent); }
    .btn-primary {
      background: var(--accent); color: #fff; border: none; padding: 8px 14px; border-radius: 8px;
      font-weight: 600; font-size: 0.86rem; cursor: pointer; display: inline-flex; align-items: center; gap: 6px;
    }
    .btn-primary:active { background: var(--accent-hover); transform: scale(0.98); }
    .btn-secondary {
      background: #334155; color: #fff; border: none; padding: 8px 12px; border-radius: 8px;
      font-weight: 600; font-size: 0.85rem; cursor: pointer; display: inline-flex; align-items: center; gap: 6px;
    }
    .btn-secondary:hover { background: #475569; }
    .btn-danger {
      background: rgba(239,68,68,0.2); color: #f87171; border: 1px solid rgba(239,68,68,0.4);
      padding: 4px 8px; border-radius: 6px; font-size: 0.78rem; font-weight: 600; cursor: pointer;
    }
    .btn-danger:hover { background: var(--danger); color: #fff; }

    /* Filter pills */
    .filter-pills { display: flex; gap: 6px; overflow-x: auto; padding: 4px 0 10px 0; scrollbar-width: none; }
    .filter-pills::-webkit-scrollbar { display: none; }
    .pill {
      background: var(--card); border: 1px solid var(--border); color: var(--muted);
      padding: 6px 12px; border-radius: 20px; font-size: 0.8rem; font-weight: 600; cursor: pointer; white-space: nowrap;
    }
    .pill.active { background: var(--accent); color: #fff; border-color: var(--accent); }

    /* Tables & Cards */
    .table-container {
      background: var(--card); border: 1px solid var(--border); border-radius: 12px;
      overflow-x: auto; box-shadow: 0 4px 16px rgba(0,0,0,0.2); margin-bottom: 16px;
    }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem; }
    th { background: #162032; padding: 10px 12px; color: var(--muted); font-weight: 600; border-bottom: 1px solid var(--border); white-space: nowrap; }
    td { padding: 10px 12px; border-bottom: 1px solid rgba(51, 65, 85, 0.4); vertical-align: middle; }
    tr:hover td { background: rgba(255,255,255,0.02); }

    /* Modals */
    .modal-overlay {
      position: fixed; top: 0; left: 0; right: 0; bottom: 0; background: rgba(0,0,0,0.7);
      display: none; align-items: center; justify-content: center; z-index: 100; padding: 12px;
      backdrop-filter: blur(4px);
    }
    .modal-card {
      background: #1e293b; border: 1px solid var(--border); border-radius: 14px;
      width: 100%; max-width: 540px; max-height: 90vh; overflow-y: auto; padding: 22px;
      box-shadow: 0 20px 40px rgba(0,0,0,0.5);
    }
    .modal-hdr { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; border-bottom: 1px solid var(--border); padding-bottom: 10px; }
    .form-group { margin-bottom: 12px; }
    .form-group label { display: block; font-size: 0.78rem; font-weight: 600; color: var(--muted); margin-bottom: 4px; }
    .form-control {
      width: 100%; background: #0f172a; border: 1px solid var(--border); color: #fff;
      padding: 9px 12px; border-radius: 8px; font-size: 0.88rem; outline: none;
    }
    .form-control:focus { border-color: var(--accent); }
    .modal-actions { display: flex; justify-content: flex-end; gap: 8px; margin-top: 18px; padding-top: 12px; border-top: 1px solid var(--border); }

    /* Badges */
    .badge { padding: 3px 8px; border-radius: 6px; font-weight: 700; font-size: 0.74rem; display: inline-block; }
    .badge-pending { background: rgba(245,158,11,0.2); color: #fbbf24; }
    .badge-progress { background: rgba(59,130,246,0.2); color: #60a5fa; }
    .badge-waiting { background: rgba(244,63,94,0.2); color: #f43f5e; }
    .badge-ready { background: rgba(16,185,129,0.2); color: #34d399; }
    .badge-delivered { background: rgba(34,197,94,0.25); color: #4ade80; }

    /* Thermal Bill Paper Styling (Clean Print) */
    #bill-receipt-paper {
      background: #fff; color: #000; padding: 18px; border-radius: 8px; max-width: 380px; margin: 0 auto;
      font-family: 'Courier New', Courier, monospace; font-size: 0.85rem; line-height: 1.4;
      box-shadow: 0 4px 20px rgba(0,0,0,0.3);
    }
    #bill-receipt-paper h2 { text-align: center; font-size: 1.15rem; margin-bottom: 2px; }
    #bill-receipt-paper p { margin: 2px 0; }
    .receipt-divider { border-top: 1px dashed #000; margin: 8px 0; }
    .receipt-row { display: flex; justify-content: space-between; }

    @media print {
      body * { visibility: hidden; }
      #bill-receipt-paper, #bill-receipt-paper * { visibility: visible; }
      #bill-receipt-paper {
        position: fixed; left: 0; top: 0; width: 100% !important; max-width: 80mm !important;
        margin: 0 !important; padding: 6px !important; box-shadow: none !important;
      }
      .no-print { display: none !important; }
    }
  </style>
</head>
<body>
  <!-- Header -->
  <header class="no-print">
    <div class="brand-title">
      <span class="brand-icon">📱</span>
      <div class="brand-text">
        <h1 class="brand-name">Patiraj Mobile Repair</h1>
        <span class="brand-badge">PRO v2.0 • Web & Desktop</span>
      </div>
    </div>
    <div class="header-actions">
      <a href="/api/backup/download" class="btn-header" title="Download SQLite database backup">
        <span>💾</span><span class="btn-label">Backup</span>
      </a>
      <button class="btn-header" onclick="openRestoreModal()" title="Restore database file">
        <span>📥</span><span class="btn-label">Restore</span>
      </button>
      <div class="user-pill">
        <span>👤 {{ username }}<span class="user-role-label"> ({{ role }})</span></span>
        <a href="/logout" class="btn-logout" title="Sign Out">Exit</a>
      </div>
    </div>
  </header>

  <!-- Top Nav Tabs for Windows Desktop -->
  <div class="top-nav no-print">
    <div class="top-nav-inner">
      <div class="nav-tab active" onclick="switchTab('dashboard')" id="nav-dashboard">📊 Dashboard</div>
      <div class="nav-tab" onclick="switchTab('inventory')" id="nav-inventory">📦 Parts Inventory</div>
      <div class="nav-tab" onclick="switchTab('low_stock')" id="nav-low_stock">⚠️ Low Stock Watchlist</div>
      <div class="nav-tab" onclick="switchTab('stock_in_out')" id="nav-stock_in_out">🔄 Stock In / Out</div>
      <div class="nav-tab" onclick="switchTab('phones')" id="nav-phones">📱 Phone Repairs</div>
      <div class="nav-tab" onclick="switchTab('history')" id="nav-history">📜 Movement Log</div>
      <div class="nav-tab" onclick="switchTab('reports')" id="nav-reports">📈 Reports & Analytics</div>
      {% if role == 'admin' %}
      <div class="nav-tab" onclick="switchTab('users')" id="nav-users">👥 Staff & Users</div>
      <div class="nav-tab" onclick="switchTab('audit')" id="nav-audit">🛡️ Audit Logs</div>
      {% endif %}
    </div>
  </div>

  <main>
    <!-- 1. DASHBOARD TAB -->
    <section id="tab-dashboard">
      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-label">Today's Sale</div>
          <div class="stat-val accent-green" id="dash-today-sale">₹0.00</div>
          <div class="stat-sub">From sales & repairs</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Today's Profit</div>
          <div class="stat-val accent-blue" id="dash-today-profit">₹0.00</div>
          <div class="stat-sub">Net profit today</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Month's Profit</div>
          <div class="stat-val accent-cyan" id="dash-month-profit">₹0.00</div>
          <div class="stat-sub">Total month profit</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Total Stock</div>
          <div class="stat-val" style="color:#c084fc;" id="dash-total-parts">0 Parts</div>
          <div class="stat-sub" id="dash-total-units">0 units in stock</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Stock Valuation</div>
          <div class="stat-val" style="color:#38bdf8;" id="dash-stock-value">₹0.00</div>
          <div class="stat-sub">Total inventory cost</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Pending Repairs</div>
          <div class="stat-val" style="color:#f43f5e;" id="dash-pending-repairs">0 Phones</div>
          <div class="stat-sub">Under repair / waiting</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Ready to Deliver</div>
          <div class="stat-val" style="color:#34d399;" id="dash-ready-repairs">0 Phones</div>
          <div class="stat-sub">Repaired & waiting</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Low Stock</div>
          <div class="stat-val accent-orange" id="dash-low-stock">0</div>
          <div class="stat-sub">Items need restock</div>
        </div>
      </div>

      <!-- Active / Pending Repairs on Dashboard -->
      <div class="action-bar" style="margin-top:18px;">
        <div style="display:flex; align-items:center; gap:10px;">
          <h3 style="font-size:1.05rem; font-weight:700;">⏳ Phones Currently Under Repair</h3>
          <span id="dash-pending-badge" style="background:rgba(239,68,68,0.2); color:#f87171; padding:3px 10px; border-radius:12px; font-size:0.75rem; font-weight:600;">0 Pending</span>
        </div>
        <div style="display:flex; gap:8px;">
          <button class="btn-primary" onclick="openAddPhoneModal()" style="font-size:0.82rem; padding:7px 12px;">➕ New Repair Job</button>
          <button onclick="loadDashboardStats()" class="btn-secondary" style="font-size:0.82rem; padding:7px 12px;">🔄 Refresh</button>
        </div>
      </div>
      <div class="table-container" style="margin-bottom:22px;">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Customer</th>
              <th>Phone Model</th>
              <th>Problem</th>
              <th>Est. Charge</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="dash-pending-tbody">
            <tr><td colspan="7" style="text-align:center; padding:18px; color:var(--muted);">Loading pending repairs...</td></tr>
          </tbody>
        </table>
      </div>

      <!-- Sold Items & Repairs Records on Dashboard -->
      <div class="action-bar" style="margin-top:14px;">
        <h3 style="font-size:1.05rem; font-weight:700;">📊 Sold Items & Completed History</h3>
        <div style="display:flex; gap:6px; flex-wrap:wrap;">
          <select id="sold-period" class="search-input" style="min-width:115px; padding:6px 8px;" onchange="loadSoldRecords()">
            <option value="all" selected>All Time</option>
            <option value="day">Today Only</option>
            <option value="month">This Month</option>
            <option value="year">This Year</option>
          </select>
          <select id="sold-type" class="search-input" style="min-width:115px; padding:6px 8px;" onchange="loadSoldRecords()">
            <option value="all">All Sales & Repairs</option>
            <option value="part">Part Sales Only</option>
            <option value="repair">Repairs Only</option>
          </select>
          <input type="text" id="sold-search" class="search-input" placeholder="🔍 Search records..." style="min-width:140px; padding:6px 8px;" oninput="filterSoldTable()">
        </div>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Date / Time</th>
              <th>Type</th>
              <th>Item / Customer</th>
              <th>Model / Compatible</th>
              <th>Qty</th>
              <th>Sale (₹)</th>
              <th>Profit (₹)</th>
            </tr>
          </thead>
          <tbody id="sold-tbody">
            <tr><td colspan="7" style="text-align:center; padding:18px; color:var(--muted);">Loading records...</td></tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- 2. INVENTORY TAB (Full Parts CRUD) -->
    <section id="tab-inventory" style="display:none;">
      <div class="action-bar">
        <input type="text" id="parts-search" class="search-input" placeholder="🔍 Search name, brand, model, compatible..." oninput="loadParts()">
        <button class="btn-primary" onclick="openAddPartModal()">+ Add New Part</button>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Part Name</th>
              <th>Brand & Model</th>
              <th>Compatible Models</th>
              <th>Stock Qty</th>
              <th>Buy (₹)</th>
              <th>Sell (₹)</th>
              <th>Supplier</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="parts-tbody">
            <tr><td colspan="9" style="text-align:center; padding:18px; color:var(--muted);">Loading parts...</td></tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- 3. LOW STOCK WATCHLIST TAB -->
    <section id="tab-low_stock" style="display:none;">
      <div class="action-bar">
        <div>
          <h3 style="font-size:1.05rem; font-weight:700; color:#fbbf24;">⚠️ Low Stock Items (Restock Order Needed)</h3>
          <p style="font-size:0.8rem; color:var(--muted);">Yeh parts warning limit se kam hain, naya stock mangwane ke liye list check karein</p>
        </div>
        <button onclick="loadLowStock()" class="btn-secondary">🔄 Refresh</button>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Part Name</th>
              <th>Brand & Model</th>
              <th>Compatible Models</th>
              <th>In Stock</th>
              <th>Alert At</th>
              <th>Sell Price</th>
              <th>Supplier</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="low-stock-tbody">
            <tr><td colspan="9" style="text-align:center; padding:18px; color:var(--muted);">Loading low stock items...</td></tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- 4. STOCK IN / OUT TAB -->
    <section id="tab-stock_in_out" style="display:none;">
      <div style="max-width:540px; margin:0 auto; background:var(--card); border:1px solid var(--border); border-radius:14px; padding:20px; box-shadow:0 8px 24px rgba(0,0,0,0.25);">
        <h3 style="font-size:1.15rem; font-weight:700; margin-bottom:2px;">🔄 Stock In / Out Movement</h3>
        <p style="font-size:0.8rem; color:var(--muted); margin-bottom:14px;">Customer sale (OUT) ya supplier se new stock purchase (IN) record karein</p>

        <form id="stock-form" onsubmit="submitStockMovement(event)">
          <div class="form-group">
            <label>Select Part (Type to search instantly):</label>
            <input type="text" id="stock-search-part" class="form-control" placeholder="Type name, brand, or model to search..." oninput="filterStockParts()" autocomplete="off">
            <select id="stock-part-select" class="form-control" style="margin-top:6px;" onchange="onStockPartChange()" required>
              <option value="">-- Choose a part --</option>
            </select>
          </div>

          <div class="form-group">
            <label>Action Type:</label>
            <select id="stock-action" class="form-control" onchange="onStockActionChange()">
              <option value="Stock Out">Stock Out (Customer Sale / Repair Job)</option>
              <option value="Stock In">Stock In (Purchase / Supplier Restock)</option>
            </select>
          </div>

          <div class="form-group">
            <label>Quantity:</label>
            <input type="number" id="stock-qty" class="form-control" value="1" min="1" required>
          </div>

          <div class="form-group">
            <label id="stock-price-lbl">Selling Price / Unit (₹):</label>
            <input type="number" step="0.01" id="stock-price" class="form-control" required>
          </div>

          <div class="form-group">
            <label>Note / Reason:</label>
            <input type="text" id="stock-note" class="form-control" value="Customer Sale">
          </div>

          <button type="submit" class="btn-primary" style="width:100%; justify-content:center; padding:12px; font-size:0.95rem; margin-top:6px;">💾 Save Movement</button>
        </form>
      </div>
    </section>

    <!-- 5. PHONES TAB (Repairs Management with Multi-Status & Print) -->
    <section id="tab-phones" style="display:none;">
      <div class="action-bar">
        <input type="text" id="phones-search" class="search-input" placeholder="🔍 Search by customer, phone, model, problem..." oninput="loadPhones()">
        <button class="btn-primary" onclick="openAddPhoneModal()">➕ New Repair Job</button>
      </div>

      <!-- Status Filter Pills -->
      <div class="filter-pills">
        <div class="pill active" onclick="setPhoneFilter('all', this)">All Repairs</div>
        <div class="pill" onclick="setPhoneFilter('Pending', this)">⏳ Pending</div>
        <div class="pill" onclick="setPhoneFilter('In Progress', this)">🔧 In Progress</div>
        <div class="pill" onclick="setPhoneFilter('Waiting for Parts', this)">📦 Waiting Parts</div>
        <div class="pill" onclick="setPhoneFilter('Completed', this)">✅ Ready (Completed)</div>
        <div class="pill" onclick="setPhoneFilter('Delivered', this)">🚚 Delivered</div>
      </div>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Job #</th>
              <th>Customer</th>
              <th>Device Model</th>
              <th>Problem</th>
              <th>Est. Charge (₹)</th>
              <th>Status</th>
              <th>Received Date</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="phones-tbody">
            <tr><td colspan="8" style="text-align:center; padding:18px; color:var(--muted);">Loading repairs...</td></tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- 6. STOCK MOVEMENT LOG TAB -->
    <section id="tab-history" style="display:none;">
      <div class="action-bar">
        <input type="text" id="history-search" class="search-input" placeholder="🔍 Search stock history by part name or note..." oninput="loadHistory()">
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Date / Time</th>
              <th>Part Name</th>
              <th>Action</th>
              <th>Qty</th>
              <th>Price (₹)</th>
              <th>Note</th>
            </tr>
          </thead>
          <tbody id="history-tbody">
            <tr><td colspan="6" style="text-align:center; padding:18px; color:var(--muted);">Loading history...</td></tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- 7. REPORTS & ANALYTICS TAB -->
    <section id="tab-reports" style="display:none;">
      <div class="action-bar">
        <div style="display:flex; gap:8px; align-items:center;">
          <h3 style="font-size:1.05rem; font-weight:700;">📈 Sales, Cost & Profit Analytics</h3>
          <select id="report-period" class="search-input" style="min-width:130px; padding:6px 10px;" onchange="loadReports()">
            <option value="month" selected>This Month</option>
            <option value="day">Today Only</option>
            <option value="year">This Year</option>
            <option value="all">All Time</option>
          </select>
        </div>
        <button onclick="exportReportsCSV()" class="btn-primary" style="background:#059669;">📥 Export to CSV</button>
      </div>

      <div class="stats-grid">
        <div class="stat-card">
          <div class="stat-label">Total Revenue</div>
          <div class="stat-val accent-green" id="rep-tot-sales">₹0.00</div>
          <div class="stat-sub">Gross sales & repairs</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Total Cost</div>
          <div class="stat-val" style="color:#94a3b8;" id="rep-tot-cost">₹0.00</div>
          <div class="stat-sub">Purchase & repair expenses</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Net Profit</div>
          <div class="stat-val accent-blue" id="rep-tot-profit">₹0.00</div>
          <div class="stat-sub">Revenue minus costs</div>
        </div>
        <div class="stat-card">
          <div class="stat-label">Units Sold / Repaired</div>
          <div class="stat-val accent-cyan" id="rep-tot-units">0</div>
          <div class="stat-sub" id="rep-tot-breakdown">0 parts • 0 repairs</div>
        </div>
      </div>

      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Date</th>
              <th>Type</th>
              <th>Description / Customer</th>
              <th>Qty</th>
              <th>Total Sale (₹)</th>
              <th>Cost (₹)</th>
              <th>Net Profit (₹)</th>
            </tr>
          </thead>
          <tbody id="reports-tbody">
            <tr><td colspan="7" style="text-align:center; padding:18px; color:var(--muted);">Loading report data...</td></tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- 8. USER & STAFF ACCOUNTS TAB (Admin) -->
    <section id="tab-users" style="display:none;">
      <div class="action-bar">
        <div>
          <h3 style="font-size:1.05rem; font-weight:700;">👥 Staff & User Management</h3>
          <p style="font-size:0.8rem; color:var(--muted);">Dukaan ke technicians ya staff ke liye separate logins manage karein</p>
        </div>
        <button class="btn-primary" onclick="openAddUserModal()">+ Add New User</button>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Username</th>
              <th>Full Name</th>
              <th>Role</th>
              <th>Created Date</th>
              <th>Last Login</th>
              <th>Status</th>
              <th>Actions</th>
            </tr>
          </thead>
          <tbody id="users-tbody">
            <tr><td colspan="8" style="text-align:center; padding:18px; color:var(--muted);">Loading users...</td></tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- 9. SECURITY AUDIT LOGS TAB (Admin) -->
    <section id="tab-audit" style="display:none;">
      <div class="action-bar">
        <input type="text" id="audit-search" class="search-input" placeholder="🔍 Search audit logs by username, action, details..." oninput="loadAuditLogs()">
        <button onclick="loadAuditLogs()" class="btn-secondary">🔄 Refresh Logs</button>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Timestamp</th>
              <th>Username</th>
              <th>Action</th>
              <th>Target</th>
              <th>Details</th>
            </tr>
          </thead>
          <tbody id="audit-tbody">
            <tr><td colspan="5" style="text-align:center; padding:18px; color:var(--muted);">Loading audit trail...</td></tr>
          </tbody>
        </table>
      </div>
    </section>
  </main>

  <!-- Bottom Navigation Bar for Mobile -->
  <nav class="bottom-nav no-print">
    <div class="bottom-tab active" onclick="switchTab('dashboard')" id="btn-dash">
      <span class="bottom-tab-icon">📊</span>
      <span>Dashboard</span>
    </div>
    <div class="bottom-tab" onclick="switchTab('inventory')" id="btn-inv">
      <span class="bottom-tab-icon">📦</span>
      <span>Parts</span>
    </div>
    <div class="bottom-tab" onclick="switchTab('phones')" id="btn-phones">
      <span class="bottom-tab-icon">📱</span>
      <span>Repairs</span>
    </div>
    <div class="bottom-tab" onclick="switchTab('stock_in_out')" id="btn-stock">
      <span class="bottom-tab-icon">🔄</span>
      <span>Stock</span>
    </div>
    <div class="bottom-tab" onclick="switchTab('reports')" id="btn-rep">
      <span class="bottom-tab-icon">📈</span>
      <span>Reports</span>
    </div>
  </nav>

  <!-- ========================================================================= -->
  <!-- MODALS -->
  <!-- ========================================================================= -->

  <!-- Add Part Modal -->
  <div class="modal-overlay" id="addPartModal">
    <div class="modal-card">
      <div class="modal-hdr">
        <h3 style="font-size:1.1rem; font-weight:700;">+ Add New Inventory Part</h3>
        <button onclick="closeModal('addPartModal')" style="background:none; border:none; color:var(--muted); font-size:1.4rem; cursor:pointer;">&times;</button>
      </div>
      <form onsubmit="submitAddPart(event)">
        <div class="form-group">
          <label>Part Name:</label>
          <input type="text" id="part-name" class="form-control" required placeholder="e.g. Display Combo, Battery, Charging CC">
        </div>
        <div class="form-group">
          <label>Brand & Model:</label>
          <div style="display:flex; gap:6px;">
            <input type="text" id="part-brand" class="form-control" placeholder="Brand (e.g. Vivo)" required>
            <input type="text" id="part-model" class="form-control" placeholder="Model (e.g. Y20)" required>
          </div>
        </div>
        <div class="form-group">
          <label>Compatible / Works On Models:</label>
          <input type="text" id="part-compatible" class="form-control" placeholder="e.g. Y20G, Y12s, Y20A">
        </div>
        <div class="form-group">
          <label>Category:</label>
          <input type="text" id="part-category" class="form-control" placeholder="e.g. Display, Battery, IC, Speaker">
        </div>
        <div class="form-group">
          <label>Stock Qty & Low Stock Alert Limit:</label>
          <div style="display:flex; gap:6px;">
            <input type="number" id="part-qty" class="form-control" placeholder="Opening Qty" value="1" min="0" required>
            <input type="number" id="part-low" class="form-control" placeholder="Alert limit" value="2" min="1" required>
          </div>
        </div>
        <div class="form-group">
          <label>Purchase & Selling Price (₹):</label>
          <div style="display:flex; gap:6px;">
            <input type="number" step="0.01" id="part-purchase" class="form-control" placeholder="Buy Price" required>
            <input type="number" step="0.01" id="part-sell" class="form-control" placeholder="Sell Price" required>
          </div>
        </div>
        <div class="form-group">
          <label>Supplier Name / Dealer:</label>
          <input type="text" id="part-supplier" class="form-control" placeholder="e.g. Delhi Market / Lucky Spares">
        </div>
        <div class="modal-actions">
          <button type="button" class="btn-secondary" onclick="closeModal('addPartModal')">Cancel</button>
          <button type="submit" class="btn-primary">Save Part</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Edit Part Modal -->
  <div class="modal-overlay" id="editPartModal">
    <div class="modal-card">
      <div class="modal-hdr">
        <h3 style="font-size:1.1rem; font-weight:700;">✏️ Edit Inventory Part</h3>
        <button onclick="closeModal('editPartModal')" style="background:none; border:none; color:var(--muted); font-size:1.4rem; cursor:pointer;">&times;</button>
      </div>
      <form onsubmit="submitEditPart(event)">
        <input type="hidden" id="edit-part-id">
        <div class="form-group">
          <label>Part Name:</label>
          <input type="text" id="edit-part-name" class="form-control" required>
        </div>
        <div class="form-group">
          <label>Brand & Model:</label>
          <div style="display:flex; gap:6px;">
            <input type="text" id="edit-part-brand" class="form-control" placeholder="Brand" required>
            <input type="text" id="edit-part-model" class="form-control" placeholder="Model" required>
          </div>
        </div>
        <div class="form-group">
          <label>Compatible Models:</label>
          <input type="text" id="edit-part-compatible" class="form-control">
        </div>
        <div class="form-group">
          <label>Category:</label>
          <input type="text" id="edit-part-category" class="form-control">
        </div>
        <div class="form-group">
          <label>Current Stock Quantity & Low Alert:</label>
          <div style="display:flex; gap:6px;">
            <input type="number" id="edit-part-qty" class="form-control" required>
            <input type="number" id="edit-part-low" class="form-control" required>
          </div>
        </div>
        <div class="form-group">
          <label>Purchase & Selling Price (₹):</label>
          <div style="display:flex; gap:6px;">
            <input type="number" step="0.01" id="edit-part-purchase" class="form-control" required>
            <input type="number" step="0.01" id="edit-part-sell" class="form-control" required>
          </div>
        </div>
        <div class="form-group">
          <label>Supplier:</label>
          <input type="text" id="edit-part-supplier" class="form-control">
        </div>
        <div class="modal-actions">
          <button type="button" class="btn-secondary" onclick="closeModal('editPartModal')">Cancel</button>
          <button type="submit" class="btn-primary">Update Part</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Add Phone Repair Modal -->
  <div class="modal-overlay" id="addPhoneModal">
    <div class="modal-card">
      <div class="modal-hdr">
        <h3 style="font-size:1.1rem; font-weight:700;">📱 Add New Phone Repair Job</h3>
        <button onclick="closeModal('addPhoneModal')" style="background:none; border:none; color:var(--muted); font-size:1.4rem; cursor:pointer;">&times;</button>
      </div>
      <form onsubmit="submitAddPhone(event)">
        <div class="form-group">
          <label>Customer Name:</label>
          <input type="text" id="phone-cust-name" class="form-control" required placeholder="e.g. Ramesh Kumar">
        </div>
        <div class="form-group">
          <label>Customer Mobile Number:</label>
          <input type="tel" id="phone-cust-phone" class="form-control" placeholder="10-digit mobile number">
        </div>
        <div class="form-group">
          <label>Device Model:</label>
          <input type="text" id="phone-device-model" class="form-control" required placeholder="e.g. Vivo Y20 / Samsung M31">
        </div>
        <div class="form-group">
          <label>Reported Problem:</label>
          <input type="text" id="phone-problem" class="form-control" placeholder="e.g. Broken Display, Battery Drain, Not Charging">
        </div>
        <div class="form-group">
          <label>Work Required / Notes:</label>
          <input type="text" id="phone-work" class="form-control" placeholder="e.g. Replace OG Display Combo">
        </div>
        <div class="form-group">
          <label>Estimated Charge (₹) & Repair Cost (₹):</label>
          <div style="display:flex; gap:6px;">
            <input type="number" step="0.01" id="phone-est-charge" class="form-control" placeholder="Customer Charge (₹)" required>
            <input type="number" step="0.01" id="phone-cost" class="form-control" placeholder="Our Cost (₹)" value="0">
          </div>
        </div>
        <div class="form-group">
          <label>Status:</label>
          <select id="phone-status" class="form-control">
            <option value="Pending">Pending (Received)</option>
            <option value="In Progress">In Progress (Working)</option>
            <option value="Waiting for Parts">Waiting for Parts</option>
            <option value="Completed">Completed (Ready for Delivery)</option>
            <option value="Delivered">Delivered (Handed to Customer)</option>
          </select>
        </div>
        <div class="modal-actions">
          <button type="button" class="btn-secondary" onclick="closeModal('addPhoneModal')">Cancel</button>
          <button type="submit" class="btn-primary">Save Repair Job</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Edit Phone Repair Modal -->
  <div class="modal-overlay" id="editPhoneModal">
    <div class="modal-card">
      <div class="modal-hdr">
        <h3 style="font-size:1.1rem; font-weight:700;">✏️ Edit Phone Repair Job</h3>
        <button onclick="closeModal('editPhoneModal')" style="background:none; border:none; color:var(--muted); font-size:1.4rem; cursor:pointer;">&times;</button>
      </div>
      <form onsubmit="submitEditPhone(event)">
        <input type="hidden" id="edit-phone-id">
        <div class="form-group">
          <label>Customer Name:</label>
          <input type="text" id="edit-phone-cust" class="form-control" required>
        </div>
        <div class="form-group">
          <label>Mobile Number:</label>
          <input type="tel" id="edit-phone-mobile" class="form-control">
        </div>
        <div class="form-group">
          <label>Device Model:</label>
          <input type="text" id="edit-phone-model" class="form-control" required>
        </div>
        <div class="form-group">
          <label>Problem Description:</label>
          <input type="text" id="edit-phone-problem" class="form-control">
        </div>
        <div class="form-group">
          <label>Work Done / Required:</label>
          <input type="text" id="edit-phone-work" class="form-control">
        </div>
        <div class="form-group">
          <label>Estimated Charge (₹) & Repair Cost (₹):</label>
          <div style="display:flex; gap:6px;">
            <input type="number" step="0.01" id="edit-phone-charge" class="form-control" required>
            <input type="number" step="0.01" id="edit-phone-cost" class="form-control">
          </div>
        </div>
        <div class="form-group">
          <label>Repair Status:</label>
          <select id="edit-phone-status" class="form-control">
            <option value="Pending">Pending</option>
            <option value="In Progress">In Progress</option>
            <option value="Waiting for Parts">Waiting for Parts</option>
            <option value="Completed">Completed (Ready)</option>
            <option value="Delivered">Delivered</option>
          </select>
        </div>
        <div class="form-group">
          <label>Internal Notes:</label>
          <input type="text" id="edit-phone-notes" class="form-control">
        </div>
        <div class="modal-actions">
          <button type="button" class="btn-secondary" onclick="closeModal('editPhoneModal')">Cancel</button>
          <button type="submit" class="btn-primary">Update Job</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Customer Bill / Printable Thermal Receipt Modal -->
  <div class="modal-overlay" id="billModal">
    <div class="modal-card" style="max-width:440px;">
      <div class="modal-hdr no-print">
        <h3 style="font-size:1.1rem; font-weight:700;">🧾 Customer Receipt / Job Slip</h3>
        <button onclick="closeModal('billModal')" style="background:none; border:none; color:var(--muted); font-size:1.4rem; cursor:pointer;">&times;</button>
      </div>

      <!-- Printable Thermal Paper -->
      <div id="bill-receipt-paper">
        <h2>PATIRAJ MOBILE REPAIR SHOP</h2>
        <p style="text-align:center; font-size:0.75rem;">All Mobile Hardware & Software Service</p>
        <p style="text-align:center; font-size:0.72rem;">Trusted & Fast Mobile Repairing Center</p>
        <div class="receipt-divider"></div>
        <div class="receipt-row">
          <span>Job ID: <strong id="bill-id">#0</strong></span>
          <span id="bill-date">Date: --</span>
        </div>
        <div class="receipt-row">
          <span>Customer: <strong id="bill-cust">--</strong></span>
          <span id="bill-phone">Phone: --</span>
        </div>
        <div class="receipt-divider"></div>
        <p><strong>Device:</strong> <span id="bill-model">--</span></p>
        <p><strong>Problem:</strong> <span id="bill-problem">--</span></p>
        <p><strong>Work Done:</strong> <span id="bill-work">--</span></p>
        <p><strong>Status:</strong> <span id="bill-status">--</span></p>
        <div class="receipt-divider"></div>
        <div class="receipt-row" style="font-size:1.05rem; font-weight:bold; margin:6px 0;">
          <span>TOTAL CHARGES:</span>
          <span id="bill-amount">₹0.00</span>
        </div>
        <div class="receipt-divider"></div>
        <p style="font-size:0.68rem; text-align:center; color:#444;">
          * Note: Water damaged / dead sets checked at customer risk.<br>
          * No warranty on physical display breakage or water damage.<br>
          * Please bring this receipt while collecting your device.
        </p>
        <div style="margin-top:14px; display:flex; justify-content:space-between; font-size:0.7rem;">
          <span>Customer Sign: __________</span>
          <span>Shop Sign: __________</span>
        </div>
      </div>

      <!-- Modal Action Buttons -->
      <div class="modal-actions no-print" style="justify-content:space-between;">
        <button type="button" class="btn-secondary" onclick="closeModal('billModal')">Close</button>
        <div style="display:flex; gap:6px;">
          <button type="button" onclick="sendBillWhatsApp()" class="btn-primary" style="background:#25d366;">💬 WhatsApp</button>
          <button type="button" onclick="window.print()" class="btn-primary">🖨️ Print Slip</button>
        </div>
      </div>
    </div>
  </div>

  <!-- Add User Modal (Admin) -->
  <div class="modal-overlay" id="addUserModal">
    <div class="modal-card" style="max-width:440px;">
      <div class="modal-hdr">
        <h3 style="font-size:1.1rem; font-weight:700;">👤 Add New Staff / Technician</h3>
        <button onclick="closeModal('addUserModal')" style="background:none; border:none; color:var(--muted); font-size:1.4rem; cursor:pointer;">&times;</button>
      </div>
      <form onsubmit="submitAddUser(event)">
        <div class="form-group">
          <label>Username:</label>
          <input type="text" id="new-user-name" class="form-control" required placeholder="e.g. technician1">
        </div>
        <div class="form-group">
          <label>Full Name:</label>
          <input type="text" id="new-user-fullname" class="form-control" placeholder="e.g. Lucky Singh">
        </div>
        <div class="form-group">
          <label>Password:</label>
          <input type="password" id="new-user-pass" class="form-control" required placeholder="At least 6 characters">
        </div>
        <div class="form-group">
          <label>Role:</label>
          <select id="new-user-role" class="form-control">
            <option value="staff">Staff / Technician</option>
            <option value="admin">Administrator (Full Access)</option>
          </select>
        </div>
        <div class="modal-actions">
          <button type="button" class="btn-secondary" onclick="closeModal('addUserModal')">Cancel</button>
          <button type="submit" class="btn-primary">Create Account</button>
        </div>
      </form>
    </div>
  </div>

  <!-- Database Restore Modal -->
  <div class="modal-overlay" id="restoreModal">
    <div class="modal-card" style="max-width:440px;">
      <div class="modal-hdr">
        <h3 style="font-size:1.1rem; font-weight:700;">📥 Restore Database (.db)</h3>
        <button onclick="closeModal('restoreModal')" style="background:none; border:none; color:var(--muted); font-size:1.4rem; cursor:pointer;">&times;</button>
      </div>
      <form onsubmit="submitRestoreDB(event)">
        <p style="font-size:0.82rem; color:var(--muted); margin-bottom:12px;">Apni pehle se download ki gayi backup file (.db) select karke restore karein.</p>
        <div class="form-group">
          <input type="file" id="restore-file" accept=".db" class="form-control" required>
        </div>
        <div class="modal-actions">
          <button type="button" class="btn-secondary" onclick="closeModal('restoreModal')">Cancel</button>
          <button type="submit" class="btn-primary" style="background:var(--danger);">Restore Database</button>
        </div>
      </form>
    </div>
  </div>

  <!-- ========================================================================= -->
  <!-- JAVASCRIPT LOGIC -->
  <!-- ========================================================================= -->
  <script>
    let allPartsCache = [];
    let allPhonesCache = [];
    let soldRecordsCache = [];
    let currentPhoneFilter = 'all';
    let activeBillData = {};

    function showToast(message, isError = false) {
      let toast = document.getElementById('app-toast');
      if (!toast) {
        toast = document.createElement('div');
        toast.id = 'app-toast';
        toast.style.cssText = `
          position: fixed; top: 75px; right: 20px; z-index: 99999;
          background: #10b981; color: #fff; padding: 12px 20px; border-radius: 10px;
          font-weight: 600; font-size: 0.92rem; box-shadow: 0 10px 30px rgba(0,0,0,0.5);
          display: flex; align-items: center; gap: 8px; transform: translateY(-20px);
          opacity: 0; transition: all 0.25s cubic-bezier(0.16, 1, 0.3, 1);
          pointer-events: none; border: 1px solid rgba(255,255,255,0.2);
        `;
        document.body.appendChild(toast);
      }
      toast.style.background = isError ? '#ef4444' : '#10b981';
      toast.innerHTML = (isError ? '⚠️ ' : '✔ ') + message;
      toast.style.transform = 'translateY(0)';
      toast.style.opacity = '1';

      clearTimeout(toast._timer);
      toast._timer = setTimeout(() => {
        toast.style.transform = 'translateY(-20px)';
        toast.style.opacity = '0';
      }, 2500);
    }

    function switchTab(tabId) {
      const tabs = ['dashboard', 'inventory', 'low_stock', 'stock_in_out', 'phones', 'history', 'reports', 'users', 'audit'];
      
      // Update top nav
      document.querySelectorAll('.nav-tab').forEach(el => {
        el.classList.toggle('active', el.id === 'nav-' + tabId);
      });

      // Update bottom nav
      const bMap = {'dashboard':'btn-dash', 'inventory':'btn-inv', 'phones':'btn-phones', 'stock_in_out':'btn-stock', 'reports':'btn-rep'};
      document.querySelectorAll('.bottom-tab').forEach(b => b.classList.remove('active'));
      if (bMap[tabId] && document.getElementById(bMap[tabId])) {
        document.getElementById(bMap[tabId]).classList.add('active');
      }

      // Show tab section
      tabs.forEach(id => {
        const sec = document.getElementById('tab-' + id);
        if (sec) sec.style.display = (id === tabId) ? 'block' : 'none';
      });

      // Trigger data loader
      if (tabId === 'dashboard') loadDashboardStats();
      if (tabId === 'inventory') loadParts();
      if (tabId === 'low_stock') loadLowStock();
      if (tabId === 'stock_in_out') loadStockPartsList();
      if (tabId === 'phones') loadPhones();
      if (tabId === 'history') loadHistory();
      if (tabId === 'reports') loadReports();
      if (tabId === 'users') loadUsers();
      if (tabId === 'audit') loadAuditLogs();
    }

    // Modal helpers
    function openAddPartModal() { document.getElementById('addPartModal').style.display = 'flex'; }
    function openAddPhoneModal() { document.getElementById('addPhoneModal').style.display = 'flex'; }
    function openAddUserModal() { document.getElementById('addUserModal').style.display = 'flex'; }
    function openRestoreModal() { document.getElementById('restoreModal').style.display = 'flex'; }
    function closeModal(id) { document.getElementById(id).style.display = 'none'; }

    // -------------------------------------------------------------------------
    // DASHBOARD
    // -------------------------------------------------------------------------
    async function loadDashboardStats() {
      try {
        const res = await fetch('/api/dashboard_stats');
        const data = await res.json();
        
        document.getElementById('dash-today-sale').textContent = '₹' + Number(data.today_sale || 0).toLocaleString('en-IN', {minimumFractionDigits:2});
        document.getElementById('dash-today-profit').textContent = '₹' + Number(data.today_profit || 0).toLocaleString('en-IN', {minimumFractionDigits:2});
        document.getElementById('dash-month-profit').textContent = '₹' + Number(data.month_profit || 0).toLocaleString('en-IN', {minimumFractionDigits:2});
        
        document.getElementById('dash-total-parts').textContent = (data.total_parts || 0) + ' Parts';
        document.getElementById('dash-total-units').textContent = (data.total_units || 0) + ' units in stock';
        document.getElementById('dash-stock-value').textContent = '₹' + Number(data.stock_value || 0).toLocaleString('en-IN', {minimumFractionDigits:2});
        
        document.getElementById('dash-pending-repairs').textContent = (data.pending_repairs || 0) + ' Phones';
        document.getElementById('dash-ready-repairs').textContent = (data.ready_repairs || 0) + ' Ready';
        document.getElementById('dash-low-stock').textContent = data.low_stock_count || 0;

        const badge = document.getElementById('dash-pending-badge');
        if (badge) badge.textContent = (data.pending_repairs || 0) + ' Pending';

        renderDashPending(data.pending_phones || []);
      } catch (e) {
        console.error('Stats fetch error:', e);
      }
      loadSoldRecords();
    }

    function renderDashPending(phones) {
      const tbody = document.getElementById('dash-pending-tbody');
      if (!tbody) return;
      if (!phones || phones.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--muted); padding:18px;">✨ No phones currently under repair. All clear!</td></tr>';
        return;
      }
      tbody.innerHTML = phones.map(p => `
        <tr>
          <td><strong>#${p.id}</strong></td>
          <td><strong>${p.customer_name}</strong>${p.customer_phone ? `<br><span style="font-size:0.75rem; color:var(--muted);">📞 ${p.customer_phone}</span>` : ''}</td>
          <td><strong>${p.phone_model}</strong></td>
          <td><span style="color:#94a3b8;">${p.problem || '-'}</span></td>
          <td><strong style="color:#60a5fa;">₹${Number(p.estimated_charge || 0).toFixed(2)}</strong></td>
          <td><span class="badge ${getStatusBadgeClass(p.status)}">${p.status}</span></td>
          <td>
            <div style="display:flex; gap:4px;">
              <button onclick="deliverPhone(${p.id})" style="background:var(--success); color:#fff; border:none; padding:4px 8px; border-radius:5px; font-size:0.75rem; font-weight:600; cursor:pointer;">🚚 Deliver</button>
              <button onclick="openBillModalForJob(${p.id})" class="btn-secondary" style="font-size:0.75rem; padding:4px 7px;">🧾 Slip</button>
            </div>
          </td>
        </tr>
      `).join('');
    }

    async function loadSoldRecords() {
      const period = document.getElementById('sold-period').value;
      const type = document.getElementById('sold-type').value;
      const tbody = document.getElementById('sold-tbody');
      tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; padding:18px;">Fetching records...</td></tr>';
      try {
        const res = await fetch(`/api/sold_records?period=${period}&type=${type}`);
        soldRecordsCache = await res.json();
        renderSoldTable(soldRecordsCache);
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--danger);">Failed to load sales.</td></tr>';
      }
    }

    function renderSoldTable(records) {
      const tbody = document.getElementById('sold-tbody');
      if (!records || records.length === 0) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--muted); padding:20px;">No sales records found.</td></tr>';
        return;
      }
      tbody.innerHTML = records.map(r => `
        <tr>
          <td><span style="font-weight:600;">${r.datetime}</span></td>
          <td><span style="background:${r.type==='Part Sale'?'rgba(37,99,235,0.15)':'rgba(16,185,129,0.15)'}; color:${r.type==='Part Sale'?'#60a5fa':'#34d399'}; padding:2px 6px; border-radius:4px; font-size:0.75rem; font-weight:600;">${r.type}</span></td>
          <td><strong>${r.name}</strong></td>
          <td><span style="color:var(--muted);">${r.model || '-'}</span></td>
          <td><strong>${r.quantity}</strong></td>
          <td style="color:var(--text); font-weight:600;">₹${Number(r.sale_price).toFixed(2)}</td>
          <td style="color:var(--success); font-weight:700;">+₹${Number(r.profit).toFixed(2)}</td>
        </tr>
      `).join('');
    }

    function filterSoldTable() {
      const q = document.getElementById('sold-search').value.toLowerCase();
      const filtered = soldRecordsCache.filter(r => 
        (r.name && r.name.toLowerCase().includes(q)) ||
        (r.model && r.model.toLowerCase().includes(q)) ||
        (r.datetime && r.datetime.toLowerCase().includes(q))
      );
      renderSoldTable(filtered);
    }

    // -------------------------------------------------------------------------
    // PARTS INVENTORY (CRUD)
    // -------------------------------------------------------------------------
    async function loadParts() {
      const q = document.getElementById('parts-search').value;
      const tbody = document.getElementById('parts-tbody');
      try {
        const res = await fetch('/api/parts?q=' + encodeURIComponent(q));
        const parts = await res.json();
        allPartsCache = parts;
        if (parts.length === 0) {
          tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; color:var(--muted); padding:18px;">No parts found.</td></tr>';
          return;
        }
        tbody.innerHTML = parts.map(p => {
          const isLow = p.quantity <= (p.low_stock || 2);
          return `
            <tr>
              <td><strong>#${p.id}</strong></td>
              <td><strong>${p.name}</strong></td>
              <td>${p.brand} ${p.model}</td>
              <td><span style="color:#60a5fa; font-size:0.8rem;">${p.compatible_models || '-'}</span></td>
              <td><span style="font-weight:700; color:${isLow?'var(--danger)':'var(--success)'};">${p.quantity}</span> ${isLow ? '⚠️' : ''}</td>
              <td style="color:var(--muted);">₹${Number(p.purchase_price).toFixed(2)}</td>
              <td style="font-weight:600;">₹${Number(p.selling_price).toFixed(2)}</td>
              <td><span style="color:var(--muted); font-size:0.8rem;">${p.supplier || '-'}</span></td>
              <td>
                <div style="display:flex; gap:4px;">
                  <button onclick="quickStockOut(${p.id}, '${p.name.replace(/'/g, "\\'")}', ${p.selling_price})" class="btn-primary" style="padding:3px 7px; font-size:0.75rem;">⚡ Sell</button>
                  <button onclick="openEditPartModal(${p.id})" class="btn-secondary" style="padding:3px 7px; font-size:0.75rem;">✏️ Edit</button>
                  <button onclick="deletePart(${p.id}, '${p.name.replace(/'/g, "\\'")}')" class="btn-danger" style="padding:3px 7px; font-size:0.75rem;">🗑️</button>
                </div>
              </td>
            </tr>
          `;
        }).join('');
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; color:var(--danger);">Error loading parts.</td></tr>';
      }
    }

    async function submitAddPart(e) {
      e.preventDefault();
      const payload = {
        name: document.getElementById('part-name').value,
        brand: document.getElementById('part-brand').value,
        model: document.getElementById('part-model').value,
        compatible_models: document.getElementById('part-compatible').value,
        category: document.getElementById('part-category').value,
        quantity: parseInt(document.getElementById('part-qty').value || 0),
        low_stock: parseInt(document.getElementById('part-low').value || 2),
        purchase_price: parseFloat(document.getElementById('part-purchase').value || 0),
        selling_price: parseFloat(document.getElementById('part-sell').value || 0),
        supplier: document.getElementById('part-supplier').value
      };
      // Close modal immediately and show optimistic toast
      closeModal('addPartModal');
      document.getElementById('part-name').value = '';
      document.getElementById('part-brand').value = '';
      document.getElementById('part-model').value = '';
      document.getElementById('part-compatible').value = '';
      document.getElementById('part-category').value = '';
      document.getElementById('part-purchase').value = '';
      document.getElementById('part-sell').value = '';
      showToast('✔ Part added successfully to inventory!');

      try {
        const res = await fetch('/api/add_part', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.success) {
          loadParts();
          loadDashboardStats();
        } else {
          showToast('Error: ' + data.error, true);
        }
      } catch (err) {
        showToast('Network error saving part', true);
      }
    }

    function openEditPartModal(pid) {
      const p = allPartsCache.find(x => x.id === pid);
      if (!p) return;
      document.getElementById('edit-part-id').value = p.id;
      document.getElementById('edit-part-name').value = p.name;
      document.getElementById('edit-part-brand').value = p.brand;
      document.getElementById('edit-part-model').value = p.model;
      document.getElementById('edit-part-compatible').value = p.compatible_models || '';
      document.getElementById('edit-part-category').value = p.category || '';
      document.getElementById('edit-part-qty').value = p.quantity;
      document.getElementById('edit-part-low').value = p.low_stock || 2;
      document.getElementById('edit-part-purchase').value = p.purchase_price;
      document.getElementById('edit-part-sell').value = p.selling_price;
      document.getElementById('edit-part-supplier').value = p.supplier || '';
      document.getElementById('editPartModal').style.display = 'flex';
    }

    async function submitEditPart(e) {
      e.preventDefault();
      const payload = {
        id: parseInt(document.getElementById('edit-part-id').value),
        name: document.getElementById('edit-part-name').value,
        brand: document.getElementById('edit-part-brand').value,
        model: document.getElementById('edit-part-model').value,
        compatible_models: document.getElementById('edit-part-compatible').value,
        category: document.getElementById('edit-part-category').value,
        quantity: parseInt(document.getElementById('edit-part-qty').value),
        low_stock: parseInt(document.getElementById('edit-part-low').value),
        purchase_price: parseFloat(document.getElementById('edit-part-purchase').value),
        selling_price: parseFloat(document.getElementById('edit-part-sell').value),
        supplier: document.getElementById('edit-part-supplier').value
      };

      closeModal('editPartModal');
      showToast('✔ Part updated successfully!');

      try {
        const res = await fetch('/api/edit_part', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.success) {
          loadParts();
          loadDashboardStats();
        } else {
          showToast('Error: ' + data.error, true);
        }
      } catch (err) {
        showToast('Network error updating part', true);
      }
    }

    async function deletePart(pid, name) {
      if (!confirm(`Are you sure you want to delete part "${name}" (#${pid})?`)) return;
      showToast('Deleting part...');
      try {
        const res = await fetch('/api/delete_part', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({id: pid})
        });
        const data = await res.json();
        if (data.success) {
          showToast('Part deleted.');
          loadParts();
          loadDashboardStats();
        } else {
          showToast('Error: ' + data.error, true);
        }
      } catch (err) {
        showToast('Network error deleting part', true);
      }
    }

    // -------------------------------------------------------------------------
    // LOW STOCK TAB
    // -------------------------------------------------------------------------
    async function loadLowStock() {
      const tbody = document.getElementById('low-stock-tbody');
      try {
        const res = await fetch('/api/low_stock_parts');
        const list = await res.json();
        if (list.length === 0) {
          tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; color:var(--success); padding:20px;">✨ All parts are well-stocked! No items below alert limit.</td></tr>';
          return;
        }
        tbody.innerHTML = list.map(p => `
          <tr>
            <td><strong>#${p.id}</strong></td>
            <td><strong>${p.name}</strong></td>
            <td>${p.brand} ${p.model}</td>
            <td><span style="color:#60a5fa; font-size:0.8rem;">${p.compatible_models || '-'}</span></td>
            <td><span style="color:var(--danger); font-weight:700; font-size:1rem;">${p.quantity}</span></td>
            <td><span style="color:var(--muted);">${p.low_stock}</span></td>
            <td>₹${Number(p.selling_price).toFixed(2)}</td>
            <td>${p.supplier || '-'}</td>
            <td>
              <button onclick="quickRestock(${p.id}, '${p.name.replace(/'/g, "\\'")}', ${p.purchase_price})" class="btn-primary" style="padding:4px 9px; font-size:0.78rem;">⚡ Restock (+ Stock In)</button>
            </td>
          </tr>
        `).join('');
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="9" style="text-align:center; color:var(--danger);">Error loading low stock.</td></tr>';
      }
    }

    function quickRestock(id, name, buyPrice) {
      switchTab('stock_in_out');
      document.getElementById('stock-part-select').value = id;
      document.getElementById('stock-action').value = 'Stock In';
      document.getElementById('stock-price').value = buyPrice;
      document.getElementById('stock-qty').value = 5;
      document.getElementById('stock-note').value = 'Restock Purchase';
      onStockActionChange();
    }

    // -------------------------------------------------------------------------
    // STOCK IN / OUT
    // -------------------------------------------------------------------------
    async function loadStockPartsList() {
      const res = await fetch('/api/parts');
      allPartsCache = await res.json();
      populateStockDropdown(allPartsCache);
    }

    function populateStockDropdown(parts) {
      const select = document.getElementById('stock-part-select');
      select.innerHTML = '<option value="">-- Choose a part --</option>' + parts.map(p => {
        const comp = p.compatible_models ? ` [Works on: ${p.compatible_models}]` : '';
        return `<option value="${p.id}" data-sell="${p.selling_price}" data-buy="${p.purchase_price}" data-qty="${p.quantity}">${p.id} | ${p.name} | ${p.brand} ${p.model}${comp} (Stock: ${p.quantity})</option>`;
      }).join('');
    }

    function filterStockParts() {
      const q = document.getElementById('stock-search-part').value.toLowerCase().trim();
      if (!q) {
        populateStockDropdown(allPartsCache);
        return;
      }
      const tokens = q.split(' ');
      const matched = allPartsCache.filter(p => {
        const haystack = `${p.id} ${p.name} ${p.brand} ${p.model} ${p.compatible_models||''} ${p.category||''}`.toLowerCase();
        return tokens.every(t => haystack.includes(t));
      });
      populateStockDropdown(matched);
      if (matched.length > 0) {
        document.getElementById('stock-part-select').value = matched[0].id;
        onStockPartChange();
      }
    }

    function onStockPartChange() {
      const select = document.getElementById('stock-part-select');
      const opt = select.options[select.selectedIndex];
      if (!opt || !opt.value) return;
      const action = document.getElementById('stock-action').value;
      if (action === 'Stock Out') {
        document.getElementById('stock-price').value = opt.getAttribute('data-sell');
      } else {
        document.getElementById('stock-price').value = opt.getAttribute('data-buy');
      }
    }

    function onStockActionChange() {
      const action = document.getElementById('stock-action').value;
      const lbl = document.getElementById('stock-price-lbl');
      const note = document.getElementById('stock-note');
      if (action === 'Stock Out') {
        lbl.textContent = 'Selling Price / Unit (₹):';
        if (note.value === 'Purchased Stock' || !note.value) note.value = 'Customer Sale';
      } else {
        lbl.textContent = 'Purchase Price / Unit (₹):';
        if (note.value === 'Customer Sale' || !note.value) note.value = 'Purchased Stock';
      }
      onStockPartChange();
    }

    async function submitStockMovement(e) {
      e.preventDefault();
      const part_id = document.getElementById('stock-part-select').value;
      if (!part_id) {
        showToast('Please select a part first!', true);
        return;
      }
      const payload = {
        part_id: parseInt(part_id),
        action: document.getElementById('stock-action').value === 'Stock Out' ? 'OUT' : 'IN',
        quantity: parseInt(document.getElementById('stock-qty').value || 1),
        price: parseFloat(document.getElementById('stock-price').value || 0),
        note: document.getElementById('stock-note').value
      };

      // IMMEDIATELY switch to dashboard and clear form on click!
      switchTab('dashboard');
      document.getElementById('stock-form').reset();
      document.getElementById('stock-search-part').value = '';
      showToast('✔ Stock movement saved successfully!');

      try {
        const res = await fetch('/api/stock_movement', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.success) {
          loadStockPartsList();
          loadDashboardStats();
          loadParts();
        } else {
          showToast('Error: ' + data.error, true);
        }
      } catch (err) {
        showToast('Network error saving movement', true);
      }
    }

    function quickStockOut(id, name, price) {
      switchTab('stock_in_out');
      document.getElementById('stock-part-select').value = id;
      document.getElementById('stock-action').value = 'Stock Out';
      document.getElementById('stock-price').value = price;
      document.getElementById('stock-qty').value = 1;
      document.getElementById('stock-note').value = 'Customer Sale';
      onStockActionChange();
    }

    // -------------------------------------------------------------------------
    // PHONE REPAIRS (MULTI-STATUS & BILLING)
    // -------------------------------------------------------------------------
    function getStatusBadgeClass(st) {
      if (st === 'Delivered') return 'badge-delivered';
      if (st === 'Completed') return 'badge-ready';
      if (st === 'In Progress') return 'badge-progress';
      if (st === 'Waiting for Parts') return 'badge-waiting';
      return 'badge-pending';
    }

    function setPhoneFilter(filterName, btnEl) {
      currentPhoneFilter = filterName;
      document.querySelectorAll('.filter-pills .pill').forEach(p => p.classList.remove('active'));
      btnEl.classList.add('active');
      renderPhonesTable();
    }

    async function loadPhones() {
      const q = document.getElementById('phones-search').value;
      const tbody = document.getElementById('phones-tbody');
      try {
        const res = await fetch('/api/phones?q=' + encodeURIComponent(q));
        allPhonesCache = await res.json();
        renderPhonesTable();
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--danger);">Error loading phone repairs.</td></tr>';
      }
    }

    function renderPhonesTable() {
      const tbody = document.getElementById('phones-tbody');
      let filtered = allPhonesCache;
      if (currentPhoneFilter !== 'all') {
        filtered = allPhonesCache.filter(p => p.status === currentPhoneFilter);
      }

      if (filtered.length === 0) {
        tbody.innerHTML = `<tr><td colspan="8" style="text-align:center; color:var(--muted); padding:18px;">No repairs found for status "${currentPhoneFilter}".</td></tr>`;
        return;
      }

      tbody.innerHTML = filtered.map(p => `
        <tr>
          <td><strong>#${p.id}</strong></td>
          <td><strong>${p.customer_name}</strong>${p.customer_phone ? `<br><span style="font-size:0.75rem; color:var(--muted);">📞 ${p.customer_phone}</span>` : ''}</td>
          <td><strong>${p.phone_model}</strong></td>
          <td><span style="color:#94a3b8;">${p.problem || '-'}</span></td>
          <td><strong style="color:#60a5fa;">₹${Number(p.estimated_charge || 0).toFixed(2)}</strong></td>
          <td>
            <select onchange="updatePhoneStatus(${p.id}, this.value)" style="background:#0f172a; color:#fff; border:1px solid var(--border); padding:3px 6px; border-radius:5px; font-size:0.75rem; font-weight:600;">
              <option value="Pending" ${p.status==='Pending'?'selected':''}>⏳ Pending</option>
              <option value="In Progress" ${p.status==='In Progress'?'selected':''}>🔧 In Progress</option>
              <option value="Waiting for Parts" ${p.status==='Waiting for Parts'?'selected':''}>📦 Waiting Parts</option>
              <option value="Completed" ${p.status==='Completed'?'selected':''}>✅ Completed</option>
              <option value="Delivered" ${p.status==='Delivered'?'selected':''}>🚚 Delivered</option>
            </select>
          </td>
          <td style="color:var(--muted); font-size:0.8rem;">${p.received_date || '-'}</td>
          <td>
            <div style="display:flex; gap:4px;">
              <button onclick="openBillModalForJob(${p.id})" class="btn-primary" style="padding:3px 7px; font-size:0.75rem;">🧾 Slip</button>
              <button onclick="openEditPhoneModal(${p.id})" class="btn-secondary" style="padding:3px 7px; font-size:0.75rem;">✏️</button>
              ${p.status !== 'Delivered' ? `<button onclick="deliverPhone(${p.id})" style="background:var(--success); color:#fff; border:none; padding:3px 7px; border-radius:5px; font-size:0.75rem; font-weight:600; cursor:pointer;">🚚</button>` : ''}
              ${p.customer_phone ? `<button onclick="sendQuickWhatsApp(${p.id})" style="background:#25d366; color:#fff; border:none; padding:3px 7px; border-radius:5px; font-size:0.75rem; cursor:pointer;">💬</button>` : ''}
            </div>
          </td>
        </tr>
      `).join('');
    }

    async function submitAddPhone(e) {
      e.preventDefault();
      const payload = {
        customer_name: document.getElementById('phone-cust-name').value,
        customer_phone: document.getElementById('phone-cust-phone').value,
        phone_model: document.getElementById('phone-device-model').value,
        problem: document.getElementById('phone-problem').value,
        work_required: document.getElementById('phone-work').value,
        estimated_charge: parseFloat(document.getElementById('phone-est-charge').value || 0),
        repair_cost: parseFloat(document.getElementById('phone-cost').value || 0),
        status: document.getElementById('phone-status').value
      };
      // Close modal immediately and clear form
      closeModal('addPhoneModal');
      document.getElementById('phone-cust-name').value = '';
      document.getElementById('phone-cust-phone').value = '';
      document.getElementById('phone-device-model').value = '';
      document.getElementById('phone-problem').value = '';
      document.getElementById('phone-work').value = '';
      document.getElementById('phone-est-charge').value = '';
      document.getElementById('phone-cost').value = '0';
      showToast('✔ Phone Repair Job saved!');

      try {
        const res = await fetch('/api/add_phone', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.success) {
          loadPhones();
          loadDashboardStats();
        } else {
          showToast('Error: ' + data.error, true);
        }
      } catch (err) {
        showToast('Network error saving phone', true);
      }
    }

    function openEditPhoneModal(jid) {
      const p = allPhonesCache.find(x => x.id === jid);
      if (!p) return;
      document.getElementById('edit-phone-id').value = p.id;
      document.getElementById('edit-phone-cust').value = p.customer_name;
      document.getElementById('edit-phone-mobile').value = p.customer_phone || p.phone_number || '';
      document.getElementById('edit-phone-model').value = p.phone_model;
      document.getElementById('edit-phone-problem').value = p.problem || p.issue_description || '';
      document.getElementById('edit-phone-work').value = p.work_required || '';
      document.getElementById('edit-phone-charge').value = p.estimated_charge || 0;
      document.getElementById('edit-phone-cost').value = p.repair_cost || 0;
      document.getElementById('edit-phone-status').value = p.status || 'Pending';
      document.getElementById('edit-phone-notes').value = p.notes || '';
      document.getElementById('editPhoneModal').style.display = 'flex';
    }

    async function submitEditPhone(e) {
      e.preventDefault();
      const payload = {
        id: parseInt(document.getElementById('edit-phone-id').value),
        customer_name: document.getElementById('edit-phone-cust').value,
        customer_phone: document.getElementById('edit-phone-mobile').value,
        phone_model: document.getElementById('edit-phone-model').value,
        problem: document.getElementById('edit-phone-problem').value,
        work_required: document.getElementById('edit-phone-work').value,
        estimated_charge: parseFloat(document.getElementById('edit-phone-charge').value || 0),
        repair_cost: parseFloat(document.getElementById('edit-phone-cost').value || 0),
        status: document.getElementById('edit-phone-status').value,
        notes: document.getElementById('edit-phone-notes').value
      };

      closeModal('editPhoneModal');
      showToast('✔ Repair Job updated!');

      try {
        const res = await fetch('/api/edit_phone', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.success) {
          loadPhones();
          loadDashboardStats();
        } else {
          showToast('Error: ' + data.error, true);
        }
      } catch (err) {
        showToast('Network error updating phone', true);
      }
    }

    async function updatePhoneStatus(jid, newStatus) {
      showToast(`Status updated to ${newStatus}`);
      try {
        const res = await fetch('/api/update_phone_status', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({id: jid, status: newStatus})
        });
        const data = await res.json();
        if (data.success) {
          loadPhones();
          loadDashboardStats();
        } else {
          showToast('Error: ' + data.error, true);
        }
      } catch (err) {
        showToast('Error updating status', true);
      }
    }

    async function deliverPhone(id) {
      if (!confirm('Mark this phone as Delivered to customer?')) return;
      showToast('Marking as delivered...');
      try {
        const res = await fetch('/api/deliver_phone', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({id: id})
        });
        const data = await res.json();
        if (data.success) {
          showToast('✔ Phone marked as Delivered!');
          loadPhones();
          loadDashboardStats();
        } else {
          showToast('Error: ' + data.error, true);
        }
      } catch (err) {
        showToast('Error delivering phone', true);
      }
    }

    // Bill / Receipt Modal
    function openBillModalForJob(jid) {
      const p = allPhonesCache.find(x => x.id === jid) || {};
      activeBillData = p;
      document.getElementById('bill-id').textContent = '#' + (p.id || jid);
      document.getElementById('bill-date').textContent = p.received_date || new Date().toISOString().slice(0, 10);
      document.getElementById('bill-cust').textContent = p.customer_name || 'Customer';
      document.getElementById('bill-phone').textContent = p.customer_phone || p.phone_number || '-';
      document.getElementById('bill-model').textContent = p.phone_model || '-';
      document.getElementById('bill-problem').textContent = p.problem || p.issue_description || '-';
      document.getElementById('bill-work').textContent = p.work_required || 'General Servicing';
      document.getElementById('bill-status').textContent = p.status || 'Pending';
      document.getElementById('bill-amount').textContent = '₹' + Number(p.estimated_charge || 0).toFixed(2);
      document.getElementById('billModal').style.display = 'flex';
    }

    function sendBillWhatsApp() {
      const p = activeBillData;
      if (!p) return;
      const cleanPhone = (p.customer_phone || p.phone_number || '').replace(/\D/g, '');
      const msg = `नमस्ते ${p.customer_name || 'Customer'} जी,%0A%0A*PATIRAJ MOBILE REPAIR SHOP*%0AJob ID: #${p.id}%0ADevice: ${p.phone_model}%0AProblem: ${p.problem || '-'}%0AStatus: *${p.status}*%0ATotal Amount: *₹${Number(p.estimated_charge || 0).toFixed(2)}*%0A%0AAapka phone repair ho gaya hai. Kripya shop par aakar collect karein. Dhanyawad!`;
      const url = cleanPhone ? `https://wa.me/91${cleanPhone}?text=${msg}` : `https://wa.me/?text=${msg}`;
      window.open(url, '_blank');
    }

    function sendQuickWhatsApp(jid) {
      const p = allPhonesCache.find(x => x.id === jid);
      if (!p) return;
      activeBillData = p;
      sendBillWhatsApp();
    }

    // -------------------------------------------------------------------------
    // HISTORY
    // -------------------------------------------------------------------------
    async function loadHistory() {
      const q = document.getElementById('history-search').value;
      const tbody = document.getElementById('history-tbody');
      try {
        const res = await fetch('/api/history?q=' + encodeURIComponent(q));
        const hist = await res.json();
        if (hist.length === 0) {
          tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--muted); padding:18px;">No stock movement history found.</td></tr>';
          return;
        }
        tbody.innerHTML = hist.map(h => `
          <tr>
            <td>${h.created_at}</td>
            <td><strong>${h.name || '(Deleted Part)'}</strong></td>
            <td><span class="badge ${h.action==='OUT'?'badge-waiting':'badge-ready'}">${h.action}</span></td>
            <td><strong>${h.quantity}</strong></td>
            <td>₹${Number(h.action==='OUT'?h.sale_price:h.purchase_price).toFixed(2)}</td>
            <td><span style="color:var(--muted);">${h.note || '-'}</span></td>
          </tr>
        `).join('');
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--danger);">Error loading history.</td></tr>';
      }
    }

    // -------------------------------------------------------------------------
    // REPORTS & ANALYTICS
    // -------------------------------------------------------------------------
    let currentReportItems = [];

    async function loadReports() {
      const period = document.getElementById('report-period').value;
      const tbody = document.getElementById('reports-tbody');
      try {
        const res = await fetch('/api/reports_data?period=' + period);
        const data = await res.json();
        currentReportItems = data.items || [];

        document.getElementById('rep-tot-sales').textContent = '₹' + Number(data.total_sales || 0).toLocaleString('en-IN', {minimumFractionDigits:2});
        document.getElementById('rep-tot-cost').textContent = '₹' + Number(data.total_cost || 0).toLocaleString('en-IN', {minimumFractionDigits:2});
        document.getElementById('rep-tot-profit').textContent = '₹' + Number(data.total_profit || 0).toLocaleString('en-IN', {minimumFractionDigits:2});
        document.getElementById('rep-tot-units').textContent = (data.parts_count + data.repairs_count) + ' total';
        document.getElementById('rep-tot-breakdown').textContent = `${data.parts_count} parts sold • ${data.repairs_count} phones repaired`;

        if (currentReportItems.length === 0) {
          tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--muted); padding:20px;">No transactions recorded for this period.</td></tr>';
          return;
        }

        tbody.innerHTML = currentReportItems.map(item => `
          <tr>
            <td>${item.date}</td>
            <td><span class="badge ${item.type==='Part Sale'?'badge-progress':'badge-ready'}">${item.type}</span></td>
            <td><strong>${item.title}</strong></td>
            <td>${item.qty}</td>
            <td style="font-weight:600;">₹${Number(item.sale).toFixed(2)}</td>
            <td style="color:var(--muted);">₹${Number(item.cost).toFixed(2)}</td>
            <td style="color:var(--success); font-weight:700;">+₹${Number(item.profit).toFixed(2)}</td>
          </tr>
        `).join('');
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--danger);">Error loading report data.</td></tr>';
      }
    }

    function exportReportsCSV() {
      if (!currentReportItems || currentReportItems.length === 0) {
        showToast('No data available to export.', true);
        return;
      }
      let csv = 'Date,Type,Description,Qty,Total Sale,Total Cost,Net Profit\\n';
      currentReportItems.forEach(it => {
        const desc = (it.title || '').replace(/"/g, '""');
        csv += `"${it.date}","${it.type}","${desc}",${it.qty},${it.sale},${it.cost},${it.profit}\\n`;
      });
      const blob = new Blob([csv], {type: 'text/csv;charset=utf-8;'});
      const url = URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `patiraj_sales_report_${new Date().toISOString().slice(0,10)}.csv`;
      document.body.appendChild(a);
      a.click();
      document.body.removeChild(a);
    }

    // -------------------------------------------------------------------------
    // USERS (ADMIN)
    // -------------------------------------------------------------------------
    async function loadUsers() {
      const tbody = document.getElementById('users-tbody');
      if (!tbody) return;
      try {
        const res = await fetch('/api/users_list');
        const users = await res.json();
        if (users.length === 0) {
          tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--muted); padding:18px;">No users found.</td></tr>';
          return;
        }
        tbody.innerHTML = users.map(u => `
          <tr>
            <td><strong>#${u.id}</strong></td>
            <td><strong>${u.username}</strong></td>
            <td>${u.full_name || '-'}</td>
            <td><span class="badge ${u.role==='admin'?'badge-progress':'badge-ready'}">${u.role.toUpperCase()}</span></td>
            <td style="font-size:0.8rem; color:var(--muted);">${u.created_at}</td>
            <td style="font-size:0.8rem; color:var(--muted);">${u.last_login || 'Never'}</td>
            <td><span style="color:${u.is_active?'var(--success)':'var(--danger)'}; font-weight:700;">${u.is_active ? 'Active' : 'Disabled'}</span></td>
            <td>
              <div style="display:flex; gap:4px;">
                <button onclick="toggleUser(${u.id})" class="btn-secondary" style="padding:3px 7px; font-size:0.75rem;">${u.is_active?'Deactivate':'Activate'}</button>
                <button onclick="promptChangePassword(${u.id}, '${u.username}')" class="btn-primary" style="padding:3px 7px; font-size:0.75rem;">🔑 Pass</button>
              </div>
            </td>
          </tr>
        `).join('');
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--danger);">Error loading users.</td></tr>';
      }
    }

    async function submitAddUser(e) {
      e.preventDefault();
      const payload = {
        username: document.getElementById('new-user-name').value,
        full_name: document.getElementById('new-user-fullname').value,
        password: document.getElementById('new-user-pass').value,
        role: document.getElementById('new-user-role').value
      };
      closeModal('addUserModal');
      document.getElementById('new-user-name').value = '';
      document.getElementById('new-user-fullname').value = '';
      document.getElementById('new-user-pass').value = '';
      showToast('✔ Creating user account...');

      try {
        const res = await fetch('/api/add_user', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify(payload)
        });
        const data = await res.json();
        if (data.success) {
          showToast('✔ User account created successfully!');
          loadUsers();
        } else {
          showToast('Error: ' + data.error, true);
        }
      } catch (err) {
        showToast('Network error creating user', true);
      }
    }

    async function toggleUser(uid) {
      try {
        const res = await fetch('/api/toggle_user', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({id: uid})
        });
        const data = await res.json();
        if (data.success) {
          showToast('User status updated');
          loadUsers();
        } else {
          showToast('Error: ' + data.error, true);
        }
      } catch (err) {
        showToast('Network error updating user', true);
      }
    }

    async function promptChangePassword(uid, username) {
      const newPass = prompt(`Enter new password for "${username}":`);
      if (!newPass || newPass.length < 6) {
        if (newPass) showToast('Password must be at least 6 characters.', true);
        return;
      }
      try {
        const res = await fetch('/api/change_user_password', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({id: uid, password: newPass})
        });
        const data = await res.json();
        if (data.success) {
          showToast('✔ Password changed successfully!');
        } else {
          showToast('Error: ' + data.error, true);
        }
      } catch (err) {
        showToast('Network error updating password', true);
      }
    }

    // -------------------------------------------------------------------------
    // AUDIT LOGS (ADMIN)
    // -------------------------------------------------------------------------
    async function loadAuditLogs() {
      const q = document.getElementById('audit-search').value;
      const tbody = document.getElementById('audit-tbody');
      if (!tbody) return;
      try {
        const res = await fetch('/api/audit_logs?q=' + encodeURIComponent(q));
        const logs = await res.json();
        if (logs.length === 0) {
          tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--muted); padding:18px;">No audit records found.</td></tr>';
          return;
        }
        tbody.innerHTML = logs.map(l => `
          <tr>
            <td style="font-size:0.8rem; color:var(--muted);">${l.timestamp}</td>
            <td><strong>${l.username}</strong></td>
            <td><span class="badge badge-progress">${l.action}</span></td>
            <td>${l.entity_type || '-'} ${l.entity_id ? '#' + l.entity_id : ''}</td>
            <td><span style="color:#cbd5e1;">${l.details || '-'}</span></td>
          </tr>
        `).join('');
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="5" style="text-align:center; color:var(--danger);">Error loading audit logs.</td></tr>';
      }
    }

    // -------------------------------------------------------------------------
    // DATABASE RESTORE
    // -------------------------------------------------------------------------
    async function submitRestoreDB(e) {
      e.preventDefault();
      const fileInput = document.getElementById('restore-file');
      if (!fileInput.files.length) return showToast('Please choose a .db file!', true);
      if (!confirm('WARNING: Current database will be replaced with the uploaded backup. Continue?')) return;
      const formData = new FormData();
      formData.append('backup_file', fileInput.files[0]);
      try {
        const res = await fetch('/api/backup/upload', {
          method: 'POST',
          body: formData
        });
        if (res.ok) {
          showToast('✔ Database restored successfully! Reloading...');
          setTimeout(() => window.location.reload(), 1200);
        } else {
          showToast('Failed to restore database.', true);
        }
      } catch (err) {
        showToast('Error uploading file: ' + err, true);
      }
    }

    // PWA Service Worker Registration
    if ('serviceWorker' in navigator) {
      window.addEventListener('load', () => {
        navigator.serviceWorker.register('/sw.js').catch(err => console.log('SW fail', err));
      });
    }

    // Initial load
    loadDashboardStats();
  </script>
</body>
</html>
"""

# -----------------------------------------------------------------------------
# LOGIN TEMPLATE
# -----------------------------------------------------------------------------
LOGIN_TEMPLATE = """<!DOCTYPE html>
<html lang="hi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Login - Patiraj Mobile Repair Shop</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@400;600;700&display=swap" rel="stylesheet">
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Outfit', sans-serif; }
    body {
      background: #0f172a; color: #f8fafc; min-height: 100vh;
      display: flex; align-items: center; justify-content: center; padding: 16px;
    }
    .login-card {
      background: #1e293b; border: 1px solid #334155; border-radius: 16px;
      padding: 32px 28px; width: 100%; max-width: 400px; box-shadow: 0 10px 30px rgba(0,0,0,0.4);
    }
    .brand-hdr { text-align: center; margin-bottom: 24px; }
    .brand-hdr h1 { font-size: 1.35rem; font-weight: 700; color: #fff; margin-top: 8px; }
    .brand-hdr p { font-size: 0.85rem; color: #94a3b8; }
    .form-group { margin-bottom: 16px; }
    .form-group label { display: block; font-size: 0.82rem; font-weight: 600; color: #94a3b8; margin-bottom: 6px; }
    .form-control {
      width: 100%; background: #0f172a; border: 1px solid #334155; color: #fff;
      padding: 11px 14px; border-radius: 9px; font-size: 0.95rem; outline: none;
    }
    .form-control:focus { border-color: #2563eb; }
    .btn-submit {
      width: 100%; background: #2563eb; color: #fff; border: none; padding: 12px;
      border-radius: 9px; font-size: 1rem; font-weight: 600; cursor: pointer; margin-top: 8px;
    }
    .btn-submit:active { background: #1d4ed8; transform: scale(0.98); }
    .error-msg {
      background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3);
      color: #f87171; padding: 10px; border-radius: 8px; font-size: 0.85rem; margin-bottom: 16px; text-align: center;
    }
  </style>
</head>
<body>
  <div class="login-card">
    <div class="brand-hdr">
      <div style="font-size:2.4rem;">📱</div>
      <h1>Patiraj Mobile Repair</h1>
      <p>Secure Shop Management Portal</p>
    </div>
    {% if error %}
    <div class="error-msg">{{ error }}</div>
    {% endif %}
    <form method="POST" action="/login" id="loginForm">
      <div class="form-group">
        <label>Username:</label>
        <input type="text" name="username" id="username" class="form-control" required placeholder="Enter username" autofocus>
      </div>
      <div class="form-group">
        <label>Password:</label>
        <input type="password" name="password" id="password" class="form-control" required placeholder="••••••••">
      </div>
      <button type="submit" class="btn-submit">Sign In</button>
    </form>
  </div>
</body>
</html>
"""

# -----------------------------------------------------------------------------
# FLASK ROUTES
# -----------------------------------------------------------------------------
@app.route("/")
def index():
    if "user_id" not in session:
        return redirect(url_for("login"))
    local_ip = get_local_ip()
    return render_template_string(HTML_TEMPLATE, username=session.get("username", "Admin"), role=session.get("role", "admin"), local_ip=local_ip)

@app.route("/login", methods=["GET", "POST"])
def login():
    error = None
    if request.method == "POST":
        u = request.form.get("username", "").strip()
        p = request.form.get("password", "")
        conn = get_db()
        user = conn.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (u,)).fetchone()
        conn.close()
        if user and verify_pwd(p, user["password_hash"], user["salt"]):
            session["user_id"] = user["id"]
            session["username"] = user["username"]
            session["role"] = user["role"]
            log_audit("LOGIN_SUCCESS", "user", user["id"], f"User {u} logged in successfully.")
            return redirect(url_for("index"))
        log_audit("LOGIN_FAILED", "user", u, f"Failed login for username: {u}")
        error = "Invalid username or password. Please try again."
    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route("/logout")
def logout():
    log_audit("LOGOUT", "session", session.get("user_id", ""), "User logged out.")
    session.clear()
    return redirect(url_for("login"))

@app.route("/api/verify_login", methods=["POST"])
def api_verify_login():
    data = request.get_json() or {}
    u = data.get("username", "").strip()
    p = data.get("password", "")
    conn = get_db()
    user = conn.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (u,)).fetchone()
    conn.close()
    if user and verify_pwd(p, user["password_hash"], user["salt"]):
        return jsonify({"valid": True})
    return jsonify({"valid": False})

@app.route("/api/dashboard_stats")
def api_dashboard_stats():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    today_str = datetime.now().strftime("%Y-%m-%d")
    month_str = datetime.now().strftime("%Y-%m")

    today_sale = 0.0
    today_profit = 0.0
    month_profit = 0.0
    total_parts = 0
    total_units = 0
    stock_value = 0.0
    pending_repairs = 0
    ready_repairs = 0
    low_stock = 0
    pending_list = []

    try:
        conn = get_db()
        rep_today = conn.execute("""SELECT COALESCE(SUM(estimated_charge),0) s, 
                                    COALESCE(SUM(estimated_charge - COALESCE(repair_cost,0)),0) p 
                                    FROM phones WHERE status='Delivered' AND 
                                    (delivered_date=? OR (delivered_date='' AND received_date=?))""", (today_str, today_str)).fetchone()
        part_today = conn.execute("""SELECT COALESCE(SUM(h.quantity * CASE WHEN h.sale_price>0 THEN h.sale_price ELSE p.selling_price END),0) s, 
                                     COALESCE(SUM(h.quantity * ((CASE WHEN h.sale_price>0 THEN h.sale_price ELSE p.selling_price END) - (CASE WHEN h.purchase_price>0 THEN h.purchase_price ELSE p.purchase_price END))),0) p 
                                     FROM stock_history h LEFT JOIN parts p ON p.id=h.part_id 
                                     WHERE h.action='OUT' AND substr(h.created_at,1,10)=?""", (today_str,)).fetchone()

        rep_month = conn.execute("""SELECT COALESCE(SUM(estimated_charge - COALESCE(repair_cost,0)),0) p 
                                    FROM phones WHERE status='Delivered' AND 
                                    (substr(delivered_date,1,7)=? OR (delivered_date='' AND substr(received_date,1,7)=?))""", (month_str, month_str)).fetchone()
        part_month = conn.execute("""SELECT COALESCE(SUM(h.quantity * ((CASE WHEN h.sale_price>0 THEN h.sale_price ELSE p.selling_price END) - (CASE WHEN h.purchase_price>0 THEN h.purchase_price ELSE p.purchase_price END))),0) p 
                                     FROM stock_history h LEFT JOIN parts p ON p.id=h.part_id 
                                     WHERE h.action='OUT' AND substr(h.created_at,1,7)=?""", (month_str,)).fetchone()

        parts_summary = conn.execute("SELECT COUNT(*) c, COALESCE(SUM(quantity),0) q, COALESCE(SUM(quantity * purchase_price),0) v FROM parts").fetchone()
        if parts_summary:
            total_parts = parts_summary["c"] or 0
            total_units = parts_summary["q"] or 0
            stock_value = parts_summary["v"] or 0.0

        p_row = conn.execute("SELECT COUNT(*) c FROM phones WHERE status NOT IN ('Delivered')").fetchone()
        pending_repairs = p_row["c"] if p_row else 0

        r_row = conn.execute("SELECT COUNT(*) c FROM phones WHERE status='Completed'").fetchone()
        ready_repairs = r_row["c"] if r_row else 0

        low_row = conn.execute("SELECT COUNT(*) c FROM parts WHERE quantity <= low_stock").fetchone()
        low_stock = low_row["c"] if low_row else 0

        pending_rows = conn.execute("""SELECT id, customer_name, customer_phone, phone_model, problem, estimated_charge, status, received_date 
                                      FROM phones WHERE status NOT IN ('Delivered') ORDER BY id DESC LIMIT 20""").fetchall()
        for pr in pending_rows:
            pending_list.append({
                "id": pr["id"],
                "customer_name": pr["customer_name"],
                "customer_phone": pr["customer_phone"] or "",
                "phone_model": pr["phone_model"],
                "problem": pr["problem"] or "",
                "estimated_charge": float(pr["estimated_charge"] or 0),
                "status": pr["status"] or "Pending",
                "received_date": pr["received_date"] or ""
            })

        conn.close()

        today_sale = float((rep_today["s"] if rep_today else 0) + (part_today["s"] if part_today else 0))
        today_profit = float((rep_today["p"] if rep_today else 0) + (part_today["p"] if part_today else 0))
        month_profit = float((rep_month["p"] if rep_month else 0) + (part_month["p"] if part_month else 0))
    except Exception as ex:
        print("Error in api_dashboard_stats:", ex)

    return jsonify({
        "today_sale": float(today_sale),
        "today_profit": float(today_profit),
        "month_profit": float(month_profit),
        "total_parts": int(total_parts),
        "total_units": int(total_units),
        "stock_value": float(stock_value),
        "pending_repairs": int(pending_repairs),
        "ready_repairs": int(ready_repairs),
        "low_stock_count": int(low_stock),
        "pending_phones": pending_list
    })

@app.route("/api/sold_records")
def api_sold_records():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    stype = request.args.get("type", "all")
    period = request.args.get("period", "all")
    records = []

    try:
        conn = get_db()
        if stype in ("all", "part"):
            part_rows = conn.execute("""SELECT h.id, h.created_at, h.quantity, h.sale_price, h.purchase_price,
                                               p.name, p.brand, p.model, p.compatible_models, p.selling_price as p_sell, p.purchase_price as p_buy
                                        FROM stock_history h LEFT JOIN parts p ON p.id=h.part_id 
                                        WHERE h.action='OUT' ORDER BY h.id DESC LIMIT 300""").fetchall()
            for r in part_rows:
                sell_p = r["sale_price"] if r["sale_price"] > 0 else (r["p_sell"] or 0)
                buy_p = r["purchase_price"] if r["purchase_price"] > 0 else (r["p_buy"] or 0)
                qty = r["quantity"]
                sale_tot = sell_p * qty
                profit = sale_tot - (buy_p * qty)
                model_txt = r["model"] or ""
                if r["compatible_models"]:
                    model_txt += f" [{r['compatible_models']}]" if model_txt else r["compatible_models"]
                records.append({
                    "type": "Part Sale",
                    "datetime": r["created_at"] or "",
                    "name": r["name"] or "(Deleted Part)",
                    "model": f"{r['brand']} {model_txt}".strip(),
                    "quantity": qty,
                    "sale_price": float(sale_tot),
                    "profit": float(profit)
                })

        if stype in ("all", "repair"):
            phone_rows = conn.execute("""SELECT id, customer_name, customer_phone, phone_model, estimated_charge, 
                                                repair_cost, delivered_date, received_date 
                                         FROM phones WHERE status='Delivered' ORDER BY id DESC LIMIT 300""").fetchall()
            for r in phone_rows:
                dt = r["delivered_date"] or r["received_date"] or ""
                charge = r["estimated_charge"] or 0
                cost = r["repair_cost"] or 0
                records.append({
                    "type": "Phone Repair",
                    "datetime": dt,
                    "name": r["customer_name"] or "Customer",
                    "model": r["phone_model"] or "-",
                    "quantity": 1,
                    "sale_price": float(charge),
                    "profit": float(charge - cost)
                })

        conn.close()
    except Exception as ex:
        print("Error in api_sold_records:", ex)

    # Filter by period if requested
    today_str = datetime.now().strftime("%Y-%m-%d")
    month_str = datetime.now().strftime("%Y-%m")
    year_str = datetime.now().strftime("%Y")

    if period == "day":
        records = [r for r in records if (r.get("datetime") or "").startswith(today_str)]
    elif period == "month":
        records = [r for r in records if (r.get("datetime") or "").startswith(month_str)]
    elif period == "year":
        records = [r for r in records if (r.get("datetime") or "").startswith(year_str)]

    records.sort(key=lambda x: x["datetime"], reverse=True)
    return jsonify(records)

@app.route("/api/parts")
def api_parts():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    q = request.args.get("q", "").strip()
    conn = get_db()
    if q:
        pattern = f"%{q}%"
        rows = conn.execute("""SELECT * FROM parts WHERE name LIKE ? OR brand LIKE ? OR model LIKE ? OR compatible_models LIKE ? OR category LIKE ? OR supplier LIKE ? ORDER BY name""",
                            (pattern, pattern, pattern, pattern, pattern, pattern)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM parts ORDER BY name").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/add_part", methods=["POST"])
def api_add_part():
    if "user_id" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    data = request.get_json() or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify({"success": False, "error": "Part Name is required"}), 400
    try:
        qty = int(data.get("quantity", 0))
        buy = float(data.get("purchase_price", 0))
        sell = float(data.get("selling_price", 0))
        low = int(data.get("low_stock") or data.get("low_stock_threshold", 2))
        brand = (data.get("brand") or "").strip()
        model = (data.get("model") or "").strip()
        comp = (data.get("compatible_models") or "").strip()
        cat = (data.get("category") or "").strip()
        sup = (data.get("supplier") or "").strip()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db()
        conn.execute("""INSERT INTO parts(name, brand, model, compatible_models, category, quantity, purchase_price, selling_price, low_stock, supplier, updated_at)
                        VALUES(?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)""",
                     (name, brand, model, comp, cat, qty, buy, sell, low, sup, now))
        new_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        if qty > 0:
            conn.execute("INSERT INTO stock_history(part_id, action, quantity, note, sale_price, purchase_price, created_at) VALUES(?,?,?,?,?,?,?)",
                         (new_id, "IN", qty, "Opening stock", sell, buy, now))
        conn.commit()
        conn.close()
        log_audit("ADD_PART", "part", new_id, f"Added part: {name} ({brand} {model}) Qty: {qty}")
        return jsonify({"success": True, "id": new_id})
    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500

@app.route("/api/edit_part", methods=["POST"])
def api_edit_part():
    if "user_id" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    data = request.get_json() or {}
    pid = data.get("id")
    name = (data.get("name") or "").strip()
    if not pid or not name:
        return jsonify({"success": False, "error": "Part ID and Name are required"}), 400
    try:
        brand = (data.get("brand") or "").strip()
        model = (data.get("model") or "").strip()
        comp = (data.get("compatible_models") or "").strip()
        cat = (data.get("category") or "").strip()
        qty = int(data.get("quantity", 0))
        buy = float(data.get("purchase_price", 0))
        sell = float(data.get("selling_price", 0))
        low = int(data.get("low_stock", 2))
        sup = (data.get("supplier") or "").strip()
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

        conn = get_db()
        conn.execute("""UPDATE parts SET name=?, brand=?, model=?, compatible_models=?, category=?,
                               quantity=?, purchase_price=?, selling_price=?, low_stock=?, supplier=?, updated_at=?
                        WHERE id=?""",
                     (name, brand, model, comp, cat, qty, buy, sell, low, sup, now, pid))
        conn.commit()
        conn.close()
        log_audit("EDIT_PART", "part", pid, f"Updated part: {name} ({brand} {model})")
        return jsonify({"success": True})
    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500

@app.route("/api/delete_part", methods=["POST"])
def api_delete_part():
    if "user_id" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    data = request.get_json() or {}
    pid = data.get("id")
    if not pid:
        return jsonify({"success": False, "error": "Part ID required"}), 400
    try:
        conn = get_db()
        p = conn.execute("SELECT name FROM parts WHERE id=?", (pid,)).fetchone()
        pname = p["name"] if p else str(pid)
        conn.execute("DELETE FROM parts WHERE id=?", (pid,))
        conn.commit()
        conn.close()
        log_audit("DELETE_PART", "part", pid, f"Deleted part: {pname}")
        return jsonify({"success": True})
    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500

@app.route("/api/low_stock_parts")
def api_low_stock_parts():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    conn = get_db()
    rows = conn.execute("SELECT * FROM parts WHERE quantity <= low_stock ORDER BY quantity ASC").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/add_phone", methods=["POST"])
def api_add_phone():
    if "user_id" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    data = request.get_json() or {}
    cust = (data.get("customer_name") or "").strip()
    phone = (data.get("customer_phone") or data.get("phone_number") or "").strip()
    model = (data.get("phone_model") or data.get("model") or "").strip()
    problem = (data.get("problem") or data.get("issue_description") or "").strip()
    work = (data.get("work_required") or "").strip()
    chg = float(data.get("estimated_charge") or 0)
    cost = float(data.get("repair_cost") or 0)
    status = (data.get("status") or "Pending").strip()
    rcv_date = data.get("received_date") or datetime.now().strftime("%Y-%m-%d")
    notes = (data.get("notes") or "").strip()

    if not cust or not model:
        return jsonify({"success": False, "error": "Customer Name and Device Model are required"}), 400

    try:
        conn = get_db()
        conn.execute("""INSERT INTO phones(customer_name, customer_phone, phone_model, problem, work_required, pending_reason, estimated_charge, repair_cost, status, received_date, notes, delivered_date)
                        VALUES(?, ?, ?, ?, ?, '', ?, ?, ?, ?, ?, '')""",
                     (cust, phone, model, problem, work, chg, cost, status, rcv_date, notes))
        new_id = conn.execute("SELECT last_insert_rowid()").fetchone()[0]
        conn.commit()
        conn.close()
        log_audit("ADD_PHONE", "phone", new_id, f"Created repair #{new_id} for {cust} ({model})")
        return jsonify({"success": True, "id": new_id})
    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500

@app.route("/api/edit_phone", methods=["POST"])
def api_edit_phone():
    if "user_id" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    data = request.get_json() or {}
    jid = data.get("id")
    cust = (data.get("customer_name") or "").strip()
    model = (data.get("phone_model") or "").strip()
    if not jid or not cust or not model:
        return jsonify({"success": False, "error": "Job ID, Customer Name, and Model are required"}), 400
    try:
        phone = (data.get("customer_phone") or "").strip()
        problem = (data.get("problem") or "").strip()
        work = (data.get("work_required") or "").strip()
        chg = float(data.get("estimated_charge") or 0)
        cost = float(data.get("repair_cost") or 0)
        status = (data.get("status") or "Pending").strip()
        notes = (data.get("notes") or "").strip()

        conn = get_db()
        if status == "Delivered":
            now_date = datetime.now().strftime("%Y-%m-%d")
            conn.execute("""UPDATE phones SET customer_name=?, customer_phone=?, phone_model=?, problem=?,
                                   work_required=?, estimated_charge=?, repair_cost=?, status=?, notes=?,
                                   delivered_date = CASE WHEN delivered_date IS NULL OR delivered_date='' THEN ? ELSE delivered_date END
                            WHERE id=?""", (cust, phone, model, problem, work, chg, cost, status, notes, now_date, jid))
        else:
            conn.execute("""UPDATE phones SET customer_name=?, customer_phone=?, phone_model=?, problem=?,
                                   work_required=?, estimated_charge=?, repair_cost=?, status=?, notes=?
                            WHERE id=?""", (cust, phone, model, problem, work, chg, cost, status, notes, jid))
        conn.commit()
        conn.close()
        log_audit("EDIT_PHONE", "phone", jid, f"Updated repair #{jid} for {cust} ({model}) - Status: {status}")
        return jsonify({"success": True})
    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500

@app.route("/api/update_phone_status", methods=["POST"])
def api_update_phone_status():
    if "user_id" not in session:
        return jsonify({"success": False, "error": "Unauthorized"}), 401
    data = request.get_json() or {}
    jid = data.get("id")
    status = (data.get("status") or "Pending").strip()
    if not jid:
        return jsonify({"success": False, "error": "Job ID required"}), 400
    try:
        conn = get_db()
        if status == "Delivered":
            now_date = datetime.now().strftime("%Y-%m-%d")
            conn.execute("UPDATE phones SET status=?, delivered_date = CASE WHEN delivered_date IS NULL OR delivered_date='' THEN ? ELSE delivered_date END WHERE id=?",
                         (status, now_date, jid))
        else:
            conn.execute("UPDATE phones SET status=? WHERE id=?", (status, jid))
        conn.commit()
        conn.close()
        log_audit("PHONE_STATUS", "phone", jid, f"Changed repair #{jid} status to {status}")
        return jsonify({"success": True})
    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500

@app.route("/api/stock_movement", methods=["POST"])
def api_stock_movement():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json() or {}
    pid = data.get("part_id")
    act = data.get("action", "OUT")
    qty = int(data.get("quantity", 1))
    price = float(data.get("price", 0))
    note = data.get("note", "").strip()

    conn = get_db()
    p = conn.execute("SELECT * FROM parts WHERE id=?", (pid,)).fetchone()
    if not p:
        conn.close()
        return jsonify({"success": False, "error": "Part not found"}), 400

    if act == "OUT":
        if qty > p["quantity"]:
            conn.close()
            return jsonify({"success": False, "error": f"Only {p['quantity']} units available in stock!"}), 400
        new_qty = p["quantity"] - qty
        sale_p = price
        buy_p = p["purchase_price"]
    else:
        new_qty = p["quantity"] + qty
        sale_p = p["selling_price"]
        buy_p = price

    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn.execute("UPDATE parts SET quantity=?, updated_at=? WHERE id=?", (new_qty, now, pid))
    conn.execute("INSERT INTO stock_history(part_id, action, quantity, note, sale_price, purchase_price, created_at) VALUES(?,?,?,?,?,?,?)",
                 (pid, act, qty, note, sale_p, buy_p, now))
    conn.commit()
    conn.close()
    log_audit("STOCK_" + act, "part", pid, f"Stock {act} {qty} units of '{p['name']}' at ₹{price}")
    return jsonify({"success": True, "new_quantity": new_qty})

@app.route("/api/phones")
def api_phones():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    q = request.args.get("q", "").strip()
    conn = get_db()
    if q:
        pat = f"%{q}%"
        rows = conn.execute("""SELECT * FROM phones 
                               WHERE customer_name LIKE ? OR customer_phone LIKE ? OR phone_model LIKE ? OR problem LIKE ? 
                               ORDER BY id DESC""",
                            (pat, pat, pat, pat)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM phones ORDER BY id DESC LIMIT 150").fetchall()
    conn.close()
    result = []
    for r in rows:
        d = dict(r)
        d["phone_number"] = d.get("customer_phone", "")
        d["brand"] = ""
        d["model"] = d.get("phone_model", "")
        d["issue_description"] = d.get("problem", "")
        result.append(d)
    return jsonify(result)

@app.route("/api/deliver_phone", methods=["POST"])
def api_deliver_phone():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json() or {}
    job_id = data.get("id")
    now_date = datetime.now().strftime("%Y-%m-%d")
    conn = get_db()
    conn.execute("UPDATE phones SET status='Delivered', delivered_date=? WHERE id=?", (now_date, job_id))
    conn.commit()
    conn.close()
    log_audit("DELIVER_PHONE", "phone", job_id, f"Delivered repair job #{job_id}")
    return jsonify({"success": True})

@app.route("/api/history")
def api_history():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    q = request.args.get("q", "").strip()
    conn = get_db()
    if q:
        pat = f"%{q}%"
        rows = conn.execute("""SELECT h.*, p.name FROM stock_history h LEFT JOIN parts p ON p.id=h.part_id 
                               WHERE p.name LIKE ? OR h.note LIKE ? OR h.action LIKE ? 
                               ORDER BY h.id DESC LIMIT 200""", (pat, pat, pat)).fetchall()
    else:
        rows = conn.execute("""SELECT h.*, p.name FROM stock_history h LEFT JOIN parts p ON p.id=h.part_id 
                               ORDER BY h.id DESC LIMIT 200""").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/reports_data")
def api_reports_data():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    period = request.args.get("period", "month")
    today_str = datetime.now().strftime("%Y-%m-%d")
    month_str = datetime.now().strftime("%Y-%m")
    year_str = datetime.now().strftime("%Y")

    conn = get_db()
    rep_rows = conn.execute("SELECT id, customer_name, customer_phone, phone_model, estimated_charge, repair_cost, delivered_date, received_date FROM phones WHERE status='Delivered' ORDER BY id DESC").fetchall()
    part_rows = conn.execute("""SELECT h.id, h.created_at, h.quantity, h.sale_price, h.purchase_price,
                                       p.name, p.brand, p.model, p.compatible_models, p.selling_price as p_sell, p.purchase_price as p_buy
                                FROM stock_history h LEFT JOIN parts p ON p.id=h.part_id 
                                WHERE h.action='OUT' ORDER BY h.id DESC""").fetchall()
    conn.close()

    items = []
    for r in rep_rows:
        dt = r["delivered_date"] or r["received_date"] or ""
        sale = float(r["estimated_charge"] or 0)
        cost = float(r["repair_cost"] or 0)
        profit = sale - cost
        items.append({
            "type": "Phone Repair",
            "date": dt,
            "title": f"{r['customer_name']} - {r['phone_model']}",
            "qty": 1,
            "sale": sale,
            "cost": cost,
            "profit": profit
        })

    for p in part_rows:
        dt = (p["created_at"] or "")[:10]
        qty = int(p["quantity"] or 1)
        sell_p = p["sale_price"] if p["sale_price"] > 0 else (p["p_sell"] or 0)
        buy_p = p["purchase_price"] if p["purchase_price"] > 0 else (p["p_buy"] or 0)
        sale = float(sell_p * qty)
        cost = float(buy_p * qty)
        profit = sale - cost
        items.append({
            "type": "Part Sale",
            "date": dt,
            "title": f"{p['name']} ({p['brand']} {p['model'] or ''})",
            "qty": qty,
            "sale": sale,
            "cost": cost,
            "profit": profit
        })

    if period == "day":
        items = [i for i in items if i["date"].startswith(today_str)]
    elif period == "month":
        items = [i for i in items if i["date"].startswith(month_str)]
    elif period == "year":
        items = [i for i in items if i["date"].startswith(year_str)]

    total_sales = sum(i["sale"] for i in items)
    total_cost = sum(i["cost"] for i in items)
    total_profit = sum(i["profit"] for i in items)
    parts_count = sum(i["qty"] for i in items if i["type"] == "Part Sale")
    repairs_count = sum(1 for i in items if i["type"] == "Phone Repair")

    items.sort(key=lambda x: x["date"], reverse=True)
    return jsonify({
        "total_sales": total_sales,
        "total_cost": total_cost,
        "total_profit": total_profit,
        "parts_count": parts_count,
        "repairs_count": repairs_count,
        "items": items
    })

@app.route("/api/users_list")
def api_users_list():
    if "user_id" not in session or session.get("role") != "admin":
        return jsonify({"error": "Admin access required"}), 403
    conn = get_db()
    rows = conn.execute("SELECT id, username, role, full_name, created_at, last_login, is_active FROM users ORDER BY id").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/add_user", methods=["POST"])
def api_add_user():
    if "user_id" not in session or session.get("role") != "admin":
        return jsonify({"success": False, "error": "Admin access required"}), 403
    data = request.get_json() or {}
    u = (data.get("username") or "").strip()
    p = (data.get("password") or "").strip()
    role = (data.get("role") or "staff").strip()
    name = (data.get("full_name") or "").strip()
    if not u or not p:
        return jsonify({"success": False, "error": "Username and password required"}), 400
    try:
        pwd_hash, salt = hash_password(p)
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        conn = get_db()
        conn.execute("INSERT INTO users(username, password_hash, salt, role, full_name, created_at) VALUES(?,?,?,?,?,?)",
                     (u, pwd_hash, salt, role, name, now))
        conn.commit()
        conn.close()
        log_audit("ADD_USER", "user", u, f"Created {role} user: {u}")
        return jsonify({"success": True})
    except Exception as ex:
        return jsonify({"success": False, "error": str(ex)}), 500

@app.route("/api/toggle_user", methods=["POST"])
def api_toggle_user():
    if "user_id" not in session or session.get("role") != "admin":
        return jsonify({"success": False, "error": "Admin access required"}), 403
    data = request.get_json() or {}
    uid = data.get("id")
    if uid == session.get("user_id"):
        return jsonify({"success": False, "error": "Cannot deactivate your own account"}), 400
    conn = get_db()
    u = conn.execute("SELECT is_active, username FROM users WHERE id=?", (uid,)).fetchone()
    if not u:
        conn.close()
        return jsonify({"success": False, "error": "User not found"}), 404
    new_active = 0 if u["is_active"] == 1 else 1
    conn.execute("UPDATE users SET is_active=? WHERE id=?", (new_active, uid))
    conn.commit()
    conn.close()
    log_audit("TOGGLE_USER", "user", uid, f"Changed user {u['username']} active to {new_active}")
    return jsonify({"success": True, "is_active": new_active})

@app.route("/api/change_user_password", methods=["POST"])
def api_change_user_password():
    if "user_id" not in session or session.get("role") != "admin":
        return jsonify({"success": False, "error": "Admin access required"}), 403
    data = request.get_json() or {}
    uid = data.get("id")
    new_pwd = (data.get("password") or "").strip()
    if not uid or not new_pwd:
        return jsonify({"success": False, "error": "User ID and new password required"}), 400
    pwd_hash, salt = hash_password(new_pwd)
    conn = get_db()
    conn.execute("UPDATE users SET password_hash=?, salt=? WHERE id=?", (pwd_hash, salt, uid))
    conn.commit()
    conn.close()
    log_audit("CHANGE_PASSWORD", "user", uid, f"Reset password for user #{uid}")
    return jsonify({"success": True})

@app.route("/api/audit_logs")
def api_audit_logs():
    if "user_id" not in session or session.get("role") != "admin":
        return jsonify({"error": "Admin access required"}), 403
    q = request.args.get("q", "").strip()
    conn = get_db()
    if q:
        pat = f"%{q}%"
        rows = conn.execute("""SELECT * FROM audit_logs 
                               WHERE username LIKE ? OR action LIKE ? OR details LIKE ? 
                               ORDER BY id DESC LIMIT 200""", (pat, pat, pat)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM audit_logs ORDER BY id DESC LIMIT 200").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

@app.route("/api/backup/download")
def api_backup_download():
    if session.get("role") != "admin":
        return redirect(url_for("login"))
    if os.path.exists(DB_FILE):
        now_str = datetime.now().strftime("%Y%m%d_%H%M%S")
        return send_file(DB_FILE, as_attachment=True, download_name=f"mobile_repair_backup_{now_str}.db")
    return "Database file not found", 404

@app.route("/api/backup/upload", methods=["POST"])
def api_backup_upload():
    if session.get("role") != "admin":
        return jsonify({"error": "Admin required"}), 403
    if "backup_file" not in request.files:
        return jsonify({"error": "No file uploaded"}), 400
    f = request.files["backup_file"]
    if f.filename == "" or not f.filename.endswith(".db"):
        return jsonify({"error": "Please select a valid .db SQLite file"}), 400

    # Create safety backup of current db before replacing
    if os.path.exists(DB_FILE):
        bk_name = f"mobile_repair_manager_pre_restore_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
        try:
            import shutil
            shutil.copyfile(DB_FILE, bk_name)
        except Exception:
            pass

    f.save(DB_FILE)
    log_audit("DATABASE_RESTORE", "system", "", "Database restored from uploaded backup file")
    return jsonify({"success": True})

@app.route("/manifest.json")
def manifest():
    return jsonify({
        "name": "Patiraj Mobile Repair Shop",
        "short_name": "Patiraj Repair",
        "start_url": "/",
        "display": "standalone",
        "background_color": "#0f172a",
        "theme_color": "#1e293b",
        "description": "Smart Inventory, Repair Jobs & Billing Manager for Mobile Repair Shops",
        "icons": [
            {
                "src": "/static/icon.svg",
                "sizes": "192x192 512x512",
                "type": "image/svg+xml",
                "purpose": "any maskable"
            }
        ]
    })

@app.route("/sw.js")
def service_worker():
    sw_code = """
    const CACHE_NAME = 'patiraj-pwa-v2';
    self.addEventListener('install', (e) => {
        self.skipWaiting();
    });
    self.addEventListener('activate', (e) => {
        e.waitUntil(clients.claim());
    });
    self.addEventListener('fetch', (e) => {
        // Network first strategy
        e.respondWith(
            fetch(e.request).catch(() => caches.match(e.request))
        );
    });
    """
    from flask import Response
    return Response(sw_code, mimetype="application/javascript")

@app.route("/static/icon.svg")
def pwa_icon():
    svg_data = """<svg xmlns="http://www.w3.org/2000/svg" viewBox="0 0 512 512" width="512" height="512">
      <defs>
        <linearGradient id="g" x1="0%" y1="0%" x2="100%" y2="100%">
          <stop offset="0%" stop-color="#2563eb" />
          <stop offset="100%" stop-color="#1d4ed8" />
        </linearGradient>
      </defs>
      <rect width="512" height="512" rx="128" fill="url(#g)" />
      <!-- Mobile Frame -->
      <rect x="146" y="80" width="220" height="352" rx="32" fill="#0f172a" stroke="#60a5fa" stroke-width="12" />
      <!-- Screen Area -->
      <rect x="166" y="120" width="180" height="240" rx="12" fill="#1e293b" />
      <!-- Wrench & Screwdriver Tool Icon -->
      <path d="M216 200 L296 280 M296 200 L216 280" stroke="#38bdf8" stroke-width="18" stroke-linecap="round" />
      <circle cx="256" cy="392" r="14" fill="#38bdf8" />
      <rect x="236" y="98" width="40" height="6" rx="3" fill="#64748b" />
    </svg>"""
    from flask import Response
    return Response(svg_data, mimetype="image/svg+xml")

# -----------------------------------------------------------------------------
# APPLICATION ENTRYPOINT
# -----------------------------------------------------------------------------
if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    print(f"[*] Starting Patiraj Mobile Repair Shop Server on port {port}...")
    app.run(host="0.0.0.0", port=port, debug=False)
