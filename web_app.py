import os
import sys
import sqlite3
import hashlib
import hmac
import secrets
import socket
from datetime import datetime
from flask import Flask, request, jsonify, render_template_string, session, redirect, url_for

if hasattr(sys.stdout, 'reconfigure'):
    try:
        sys.stdout.reconfigure(encoding='utf-8')
    except Exception:
        pass

DB_FILE = os.path.join(os.path.dirname(os.path.abspath(__file__)), "mobile_repair_manager.db")

app = Flask(__name__)
app.secret_key = secrets.token_hex(32)

def get_db():
    conn = sqlite3.connect(DB_FILE, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def verify_pwd(password: str, stored_hash_hex: str, salt_hex: str) -> bool:
    try:
        salt_bytes = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(stored_hash_hex)
        actual_hash = hashlib.pbkdf2_hmac('sha256', password.encode('utf-8'), salt_bytes, 200_000)
        return hmac.compare_digest(expected_hash, actual_hash)
    except Exception:
        return False

def get_local_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    try:
        s.connect(('8.8.8.8', 80))
        ip = s.getsockname()[0]
    except Exception:
        ip = '127.0.0.1'
    finally:
        s.close()
    return ip

# -----------------------------------------------------------------------------
# HTML TEMPLATE (Mobile-First for Android & Windows Browser)
# -----------------------------------------------------------------------------
HTML_TEMPLATE = """<!DOCTYPE html>
<html lang="hi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <meta name="theme-color" content="#1e293b">
  <meta name="apple-mobile-web-app-capable" content="yes">
  <meta name="apple-mobile-web-app-status-bar-style" content="black-translucent">
  <title>Patiraj Mobile Repair Shop - Mobile & Web Manager</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
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
      --text: #f8fafc;
      --muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Outfit', sans-serif; -webkit-tap-highlight-color: transparent; }
    body { background: var(--bg); color: var(--text); min-height: 100vh; display: flex; flex-direction: column; padding-bottom: 70px; }
    
    /* Header */
    header {
      background: rgba(30, 41, 59, 0.95); backdrop-filter: blur(12px);
      border-bottom: 1px solid var(--border); position: sticky; top: 0; z-index: 50;
      padding: 12px 16px; display: flex; align-items: center; justify-content: space-between;
    }
    .brand { display: flex; align-items: center; gap: 8px; font-weight: 700; font-size: 1.05rem; color: #fff; }
    .brand-badge { background: linear-gradient(135deg, #2563eb, #8b5cf6); padding: 5px 8px; border-radius: 8px; font-size: 1rem; }
    .user-pill { display: flex; align-items: center; gap: 6px; font-size: 0.8rem; background: #0f172a; padding: 4px 10px; border-radius: 999px; border: 1px solid var(--border); }
    .btn-logout { color: var(--danger); text-decoration: none; font-weight: 600; margin-left: 4px; }

    /* Top Tabs for Windows / Tablets */
    .top-nav { background: var(--card); border-bottom: 1px solid var(--border); overflow-x: auto; white-space: nowrap; }
    .top-nav-inner { display: flex; max-width: 1200px; margin: 0 auto; padding: 0 10px; }
    .nav-tab {
      padding: 12px 14px; color: var(--muted); cursor: pointer; font-weight: 500; font-size: 0.88rem;
      border-bottom: 2px solid transparent; transition: all 0.2s; display: flex; align-items: center; gap: 6px;
    }
    .nav-tab.active { color: var(--accent); border-bottom-color: var(--accent); font-weight: 600; }

    /* Bottom Nav Bar for Android Mobile */
    .bottom-nav {
      position: fixed; bottom: 0; left: 0; right: 0; background: rgba(30, 41, 59, 0.98);
      backdrop-filter: blur(16px); border-top: 1px solid var(--border); display: flex;
      justify-content: space-around; padding: 8px 0; z-index: 60;
    }
    .bottom-tab {
      display: flex; flex-direction: column; align-items: center; gap: 3px;
      color: var(--muted); font-size: 0.72rem; font-weight: 500; cursor: pointer; text-decoration: none; flex: 1;
    }
    .bottom-tab.active { color: var(--accent); font-weight: 600; }
    .bottom-tab-icon { font-size: 1.25rem; }

    /* Main Container */
    main { flex: 1; max-width: 1200px; width: 100%; margin: 0 auto; padding: 16px 12px; }
    
    /* Stats Grid */
    .stats-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(160px, 1fr)); gap: 10px; margin-bottom: 16px; }
    .stat-card {
      background: var(--card); border: 1px solid var(--border); border-radius: 12px; padding: 14px;
      box-shadow: 0 4px 16px rgba(0,0,0,0.15);
    }
    .stat-label { font-size: 0.75rem; font-weight: 600; text-transform: uppercase; color: var(--muted); margin-bottom: 4px; }
    .stat-val { font-size: 1.4rem; font-weight: 700; color: #fff; }
    .stat-sub { font-size: 0.7rem; color: var(--muted); margin-top: 2px; }
    .accent-green { color: var(--success); }
    .accent-blue { color: var(--accent); }
    .accent-cyan { color: #06b6d4; }
    .accent-orange { color: var(--warning); }

    /* Action bar */
    .action-bar { display: flex; flex-wrap: wrap; gap: 8px; align-items: center; justify-content: space-between; margin-bottom: 12px; }
    .search-input {
      background: var(--card); border: 1px solid var(--border); color: var(--text); padding: 9px 12px;
      border-radius: 8px; font-size: 0.88rem; min-width: 200px; flex: 1; outline: none;
    }
    .search-input:focus { border-color: var(--accent); }
    .btn-primary {
      background: var(--accent); color: #fff; border: none; padding: 9px 14px; border-radius: 8px;
      font-weight: 600; font-size: 0.88rem; cursor: pointer; display: inline-flex; align-items: center; gap: 6px;
    }
    .btn-primary:active { background: var(--accent-hover); transform: scale(0.98); }

    /* Tables & Cards */
    .table-container {
      background: var(--card); border: 1px solid var(--border); border-radius: 12px;
      overflow-x: auto; box-shadow: 0 4px 16px rgba(0,0,0,0.2);
    }
    table { width: 100%; border-collapse: collapse; text-align: left; font-size: 0.85rem; }
    th { background: #162032; padding: 10px 12px; color: var(--muted); font-weight: 600; border-bottom: 1px solid var(--border); }
    td { padding: 10px 12px; border-bottom: 1px solid rgba(51, 65, 85, 0.4); }
    tr:hover td { background: rgba(255,255,255,0.02); }

    /* Form Controls */
    .form-group { margin-bottom: 12px; }
    .form-group label { display: block; font-size: 0.8rem; font-weight: 600; color: var(--muted); margin-bottom: 4px; }
    .form-control {
      width: 100%; background: #0f172a; border: 1px solid var(--border); color: var(--text);
      padding: 10px 12px; border-radius: 8px; font-size: 0.9rem; outline: none;
    }
    .form-control:focus { border-color: var(--accent); }

    /* Modals */
    .modal-overlay {
      position: fixed; inset: 0; background: rgba(0,0,0,0.7); backdrop-filter: blur(4px);
      display: none; align-items: center; justify-content: center; z-index: 100; padding: 14px;
    }
    .modal-card {
      background: var(--card); border: 1px solid var(--border); border-radius: 16px;
      width: 100%; max-width: 480px; padding: 20px; box-shadow: 0 20px 40px rgba(0,0,0,0.5);
    }
    .modal-hdr { display: flex; justify-content: space-between; align-items: center; margin-bottom: 14px; }
    .modal-actions { display: flex; gap: 8px; justify-content: flex-end; margin-top: 16px; }

    /* Info Pill */
    .info-banner {
      background: rgba(37, 99, 235, 0.12); border: 1px solid rgba(37, 99, 235, 0.3); border-radius: 10px;
      padding: 10px 12px; margin-bottom: 14px; display: flex; align-items: center; justify-content: space-between;
      font-size: 0.82rem;
    }
  </style>
</head>
<body>
  <!-- Header -->
  <header>
    <div class="brand">
      <span class="brand-badge">🔧</span>
      <span>PATIRAJ REPAIR SHOP</span>
    </div>
    <div class="user-pill">
      <span>👤 {{ username }}</span>
      <a href="/logout" class="btn-logout">Exit</a>
    </div>
  </header>

  <!-- Top Nav Tabs for Windows Desktop -->
  <div class="top-nav">
    <div class="top-nav-inner">
      <div class="nav-tab active" onclick="switchTab('dashboard')">📊 Dashboard</div>
      <div class="nav-tab" onclick="switchTab('inventory')">📦 Parts Inventory</div>
      <div class="nav-tab" onclick="switchTab('stock_in_out')">🔄 Stock In / Out</div>
      <div class="nav-tab" onclick="switchTab('phones')">📱 Phone Repairs</div>
      <div class="nav-tab" onclick="switchTab('history')">📈 Movement History</div>
    </div>
  </div>

  <main>
    <div class="info-banner">
      <span>📱 <strong>Android Mobile Link:</strong> <code>http://{{ local_ip }}:5000</code></span>
      <span style="color:var(--muted); font-size:0.75rem;">(Chrome Menu ➔ Add to Home screen)</span>
    </div>

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
          <div class="stat-label">Low Stock</div>
          <div class="stat-val accent-orange" id="dash-low-stock">0</div>
          <div class="stat-sub">Items need restock</div>
        </div>
      </div>

      <div class="action-bar" style="margin-top:14px;">
        <h3 style="font-size:1rem; font-weight:600;">📊 Sold Items Records</h3>
        <div style="display:flex; gap:6px; flex-wrap:wrap;">
          <select id="sold-period" class="search-input" style="min-width:110px; padding:6px 8px;" onchange="loadSoldRecords()">
            <option value="day">By Day / Date</option>
            <option value="month">By Month</option>
            <option value="year">By Year</option>
            <option value="all">All Time</option>
          </select>
          <select id="sold-type" class="search-input" style="min-width:110px; padding:6px 8px;" onchange="loadSoldRecords()">
            <option value="all">All Sales</option>
            <option value="part">Part Sales</option>
            <option value="repair">Repairs</option>
          </select>
          <input type="text" id="sold-search" class="search-input" placeholder="🔍 Search sales..." style="min-width:140px; padding:6px 8px;" oninput="filterSoldTable()">
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

    <!-- 2. INVENTORY TAB -->
    <section id="tab-inventory" style="display:none;">
      <div class="action-bar">
        <input type="text" id="parts-search" class="search-input" placeholder="🔍 Search name, brand, model, compatible..." oninput="loadParts()">
        <button class="btn-primary" onclick="openAddPartModal()">+ Add Part</button>
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>ID</th>
              <th>Part Name</th>
              <th>Brand & Model</th>
              <th>Works on / Compatible</th>
              <th>Qty</th>
              <th>Sell (₹)</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="parts-tbody">
            <tr><td colspan="7" style="text-align:center; padding:18px; color:var(--muted);">Loading parts...</td></tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- 3. STOCK IN / OUT TAB (With in-place searchable part selector) -->
    <section id="tab-stock_in_out" style="display:none;">
      <div style="max-width:540px; margin:0 auto; background:var(--card); border:1px solid var(--border); border-radius:14px; padding:18px; box-shadow:0 8px 24px rgba(0,0,0,0.25);">
        <h3 style="font-size:1.15rem; font-weight:700; margin-bottom:2px;">🔄 Stock In / Out Movement</h3>
        <p style="font-size:0.8rem; color:var(--muted); margin-bottom:14px;">Customer sale ya supplier restock record karein</p>

        <form id="stock-form" onsubmit="submitStockMovement(event)">
          <div class="form-group">
            <label>Select Part (Type directly to search):</label>
            <input type="text" id="stock-search-part" class="form-control" placeholder="Type name, brand, or model to search..." oninput="filterStockParts()" autocomplete="off">
            <select id="stock-part-select" class="form-control" style="margin-top:6px;" onchange="onStockPartChange()" required>
              <option value="">-- Choose a part --</option>
            </select>
          </div>

          <div class="form-group">
            <label>Action Type:</label>
            <select id="stock-action" class="form-control" onchange="onStockActionChange()">
              <option value="Stock Out">Stock Out (Customer Sale / Repair)</option>
              <option value="Stock In">Stock In (Purchase / Restock)</option>
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

    <!-- 4. PHONES TAB -->
    <section id="tab-phones" style="display:none;">
      <div class="action-bar">
        <input type="text" id="phones-search" class="search-input" placeholder="🔍 Search repairs by customer, model, IMEI..." oninput="loadPhones()">
      </div>
      <div class="table-container">
        <table>
          <thead>
            <tr>
              <th>Job #</th>
              <th>Customer</th>
              <th>Phone</th>
              <th>Device</th>
              <th>Issue</th>
              <th>Charge (₹)</th>
              <th>Status</th>
              <th>Action</th>
            </tr>
          </thead>
          <tbody id="phones-tbody">
            <tr><td colspan="8" style="text-align:center; padding:18px; color:var(--muted);">Loading repairs...</td></tr>
          </tbody>
        </table>
      </div>
    </section>

    <!-- 5. SALES & STOCK HISTORY TAB -->
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
  </main>

  <!-- Bottom Navigation Bar for Android Mobile -->
  <nav class="bottom-nav">
    <div class="bottom-tab active" onclick="switchTab('dashboard')" id="btn-dash">
      <span class="bottom-tab-icon">📊</span>
      <span>Dashboard</span>
    </div>
    <div class="bottom-tab" onclick="switchTab('inventory')" id="btn-inv">
      <span class="bottom-tab-icon">📦</span>
      <span>Parts</span>
    </div>
    <div class="bottom-tab" onclick="switchTab('stock_in_out')" id="btn-stock">
      <span class="bottom-tab-icon">🔄</span>
      <span>Stock In/Out</span>
    </div>
    <div class="bottom-tab" onclick="switchTab('phones')" id="btn-phones">
      <span class="bottom-tab-icon">📱</span>
      <span>Repairs</span>
    </div>
    <div class="bottom-tab" onclick="switchTab('history')" id="btn-hist">
      <span class="bottom-tab-icon">📈</span>
      <span>History</span>
    </div>
  </nav>

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
          <input type="text" id="part-name" class="form-control" required placeholder="e.g. Display Combo, Battery">
        </div>
        <div class="form-group">
          <label>Brand & Model:</label>
          <div style="display:flex; gap:6px;">
            <input type="text" id="part-brand" class="form-control" placeholder="Brand (Vivo)" required>
            <input type="text" id="part-model" class="form-control" placeholder="Model (Y20)" required>
          </div>
        </div>
        <div class="form-group">
          <label>Compatible / Use In Models:</label>
          <input type="text" id="part-compatible" class="form-control" placeholder="e.g. Y20G, Y12s, Y20A">
        </div>
        <div class="form-group">
          <label>Stock Qty & Low Alert:</label>
          <div style="display:flex; gap:6px;">
            <input type="number" id="part-qty" class="form-control" placeholder="Qty" value="1" min="0" required>
            <input type="number" id="part-low" class="form-control" placeholder="Alert at" value="2" min="1" required>
          </div>
        </div>
        <div class="form-group">
          <label>Purchase & Sell Price (₹):</label>
          <div style="display:flex; gap:6px;">
            <input type="number" step="0.01" id="part-purchase" class="form-control" placeholder="Buy Price" required>
            <input type="number" step="0.01" id="part-sell" class="form-control" placeholder="Sell Price" required>
          </div>
        </div>
        <div class="form-group">
          <label>Supplier:</label>
          <input type="text" id="part-supplier" class="form-control" placeholder="Supplier Name">
        </div>
        <div class="modal-actions">
          <button type="button" class="btn-primary" style="background:#334155;" onclick="closeModal('addPartModal')">Cancel</button>
          <button type="submit" class="btn-primary">Save Part</button>
        </div>
      </form>
    </div>
  </div>

  <script>
    let allPartsCache = [];
    let soldRecordsCache = [];

    function switchTab(tabId) {
      const tabs = ['dashboard', 'inventory', 'stock_in_out', 'phones', 'history'];
      const btnIds = ['btn-dash', 'btn-inv', 'btn-stock', 'btn-phones', 'btn-hist'];
      
      document.querySelectorAll('.nav-tab').forEach((el, idx) => {
        el.classList.toggle('active', tabs[idx] === tabId);
      });
      btnIds.forEach((bId, idx) => {
        document.getElementById(bId).classList.toggle('active', tabs[idx] === tabId);
      });
      tabs.forEach(id => {
        document.getElementById('tab-' + id).style.display = (id === tabId) ? 'block' : 'none';
      });

      if (tabId === 'dashboard') loadDashboardStats();
      if (tabId === 'inventory') loadParts();
      if (tabId === 'stock_in_out') loadStockPartsList();
      if (tabId === 'phones') loadPhones();
      if (tabId === 'history') loadHistory();
    }

    async function loadDashboardStats() {
      try {
        const res = await fetch('/api/dashboard_stats');
        const data = await res.json();
        document.getElementById('dash-today-sale').textContent = '₹' + data.today_sale.toLocaleString('en-IN', {minimumFractionDigits:2});
        document.getElementById('dash-today-profit').textContent = '₹' + data.today_profit.toLocaleString('en-IN', {minimumFractionDigits:2});
        document.getElementById('dash-month-profit').textContent = '₹' + data.month_profit.toLocaleString('en-IN', {minimumFractionDigits:2});
        document.getElementById('dash-low-stock').textContent = data.low_stock_count;
        loadSoldRecords();
      } catch (e) { console.error(e); }
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

    async function loadParts() {
      const q = document.getElementById('parts-search').value;
      const tbody = document.getElementById('parts-tbody');
      try {
        const res = await fetch('/api/parts?q=' + encodeURIComponent(q));
        const parts = await res.json();
        if (parts.length === 0) {
          tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--muted); padding:18px;">No parts found.</td></tr>';
          return;
        }
        tbody.innerHTML = parts.map(p => `
          <tr>
            <td>#${p.id}</td>
            <td><strong>${p.name}</strong></td>
            <td>${p.brand} ${p.model}</td>
            <td><span style="color:#60a5fa; font-size:0.8rem;">${p.compatible_models || '-'}</span></td>
            <td><span style="font-weight:700; color:${p.quantity<=p.low_stock_threshold?'var(--danger)':'var(--success)'};">${p.quantity}</span></td>
            <td style="font-weight:600;">₹${Number(p.selling_price).toFixed(2)}</td>
            <td>
              <button onclick="quickStockOut(${p.id}, '${p.name.replace(/'/g, "\\'")}', ${p.selling_price})" style="background:var(--accent); color:#fff; border:none; padding:4px 8px; border-radius:4px; font-size:0.75rem; cursor:pointer;">⚡ Sell</button>
            </td>
          </tr>
        `).join('');
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="7" style="text-align:center; color:var(--danger);">Error loading parts.</td></tr>';
      }
    }

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
      if (!part_id) return alert('Please choose a part!');
      const payload = {
        part_id: parseInt(part_id),
        action: document.getElementById('stock-action').value === 'Stock Out' ? 'OUT' : 'IN',
        quantity: parseInt(document.getElementById('stock-qty').value),
        price: parseFloat(document.getElementById('stock-price').value),
        note: document.getElementById('stock-note').value
      };
      const res = await fetch('/api/stock_movement', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (data.success) {
        alert('✔ Stock movement recorded successfully!');
        loadStockPartsList();
        loadDashboardStats();
        switchTab('dashboard');
      } else {
        alert('Error: ' + data.error);
      }
    }

    function quickStockOut(id, name, price) {
      switchTab('stock_in_out');
      document.getElementById('stock-part-select').value = id;
      document.getElementById('stock-action').value = 'Stock Out';
      document.getElementById('stock-price').value = price;
      document.getElementById('stock-qty').value = 1;
      document.getElementById('stock-note').value = 'Customer Sale';
    }

    async function loadPhones() {
      const q = document.getElementById('phones-search').value;
      const tbody = document.getElementById('phones-tbody');
      try {
        const res = await fetch('/api/phones?q=' + encodeURIComponent(q));
        const phones = await res.json();
        if (phones.length === 0) {
          tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--muted); padding:18px;">No phone repair jobs found.</td></tr>';
          return;
        }
        tbody.innerHTML = phones.map(p => `
          <tr>
            <td>#${p.id}</td>
            <td><strong>${p.customer_name}</strong></td>
            <td>${p.phone_number}</td>
            <td>${p.brand} ${p.model}</td>
            <td><span style="color:var(--muted);">${p.issue_description}</span></td>
            <td><strong>₹${Number(p.estimated_charge).toFixed(2)}</strong></td>
            <td><span style="background:${p.status==='Delivered'?'rgba(16,185,129,0.15)':'rgba(245,158,11,0.15)'}; color:${p.status==='Delivered'?'#34d399':'#fbbf24'}; padding:2px 6px; border-radius:4px; font-weight:600; font-size:0.75rem;">${p.status}</span></td>
            <td>
              ${p.status !== 'Delivered' ? `<button onclick="deliverPhone(${p.id})" style="background:var(--success); color:#fff; border:none; padding:4px 8px; border-radius:4px; font-size:0.75rem; cursor:pointer;">Deliver</button>` : '✔ Done'}
            </td>
          </tr>
        `).join('');
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="8" style="text-align:center; color:var(--danger);">Error loading phone repairs.</td></tr>';
      }
    }

    async function deliverPhone(id) {
      if (!confirm('Mark this phone as Delivered?')) return;
      const res = await fetch('/api/deliver_phone', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify({id: id})
      });
      const data = await res.json();
      if (data.success) {
        alert('Phone marked as Delivered!');
        loadPhones();
        loadDashboardStats();
      } else {
        alert('Error: ' + data.error);
      }
    }

    async function loadHistory() {
      const q = document.getElementById('history-search').value;
      const tbody = document.getElementById('history-tbody');
      try {
        const res = await fetch('/api/history?q=' + encodeURIComponent(q));
        const hist = await res.json();
        tbody.innerHTML = hist.map(h => `
          <tr>
            <td>${h.created_at}</td>
            <td><strong>${h.name || '(Deleted Part)'}</strong></td>
            <td><span style="background:${h.action==='OUT'?'rgba(239,68,68,0.15)':'rgba(16,185,129,0.15)'}; color:${h.action==='OUT'?'#f87171':'#34d399'}; padding:2px 6px; border-radius:4px; font-weight:700; font-size:0.75rem;">${h.action}</span></td>
            <td><strong>${h.quantity}</strong></td>
            <td>₹${Number(h.action==='OUT'?h.sale_price:h.purchase_price).toFixed(2)}</td>
            <td><span style="color:var(--muted);">${h.note || '-'}</span></td>
          </tr>
        `).join('');
      } catch (e) {
        tbody.innerHTML = '<tr><td colspan="6" style="text-align:center; color:var(--danger);">Error loading history.</td></tr>';
      }
    }

    function openAddPartModal() { document.getElementById('addPartModal').style.display = 'flex'; }
    function closeModal(id) { document.getElementById(id).style.display = 'none'; }

    async function submitAddPart(e) {
      e.preventDefault();
      const payload = {
        name: document.getElementById('part-name').value,
        brand: document.getElementById('part-brand').value,
        model: document.getElementById('part-model').value,
        compatible_models: document.getElementById('part-compatible').value,
        quantity: parseInt(document.getElementById('part-qty').value),
        low_stock_threshold: parseInt(document.getElementById('part-low').value),
        purchase_price: parseFloat(document.getElementById('part-purchase').value),
        selling_price: parseFloat(document.getElementById('part-sell').value),
        supplier: document.getElementById('part-supplier').value,
        category: ''
      };
      const res = await fetch('/api/add_part', {
        method: 'POST',
        headers: {'Content-Type': 'application/json'},
        body: JSON.stringify(payload)
      });
      const data = await res.json();
      if (data.success) {
        alert('Part added successfully!');
        closeModal('addPartModal');
        loadParts();
      } else {
        alert('Error: ' + data.error);
      }
    }

    loadDashboardStats();
  </script>
</body>
</html>
"""

LOGIN_TEMPLATE = """<!DOCTYPE html>
<html lang="hi">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0, maximum-scale=1.0, user-scalable=no">
  <title>Login - Patiraj Mobile Repair Shop</title>
  <link rel="preconnect" href="https://fonts.googleapis.com">
  <link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>
  <link href="https://fonts.googleapis.com/css2?family=Outfit:wght@300;400;500;600;700&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg: #0b1329;
      --card: #182238;
      --border: #283553;
      --accent: #2563eb;
      --text: #f8fafc;
      --muted: #94a3b8;
    }
    * { box-sizing: border-box; margin: 0; padding: 0; font-family: 'Outfit', sans-serif; }
    body {
      background: radial-gradient(circle at 50% 20%, #1e293b 0%, #0b1329 100%);
      color: var(--text); min-height: 100vh; display: flex; align-items: center; justify-content: center; padding: 16px;
    }
    .login-card {
      background: rgba(24, 34, 56, 0.95); backdrop-filter: blur(16px);
      border: 1px solid var(--border); border-radius: 20px; width: 100%; max-width: 400px;
      padding: 30px 24px; box-shadow: 0 25px 60px rgba(0,0,0,0.5);
    }
    .brand-icon {
      width: 52px; height: 52px; background: linear-gradient(135deg, #2563eb, #7c3aed);
      border-radius: 14px; display: flex; align-items: center; justify-content: center;
      font-size: 1.7rem; margin: 0 auto 14px auto; box-shadow: 0 8px 24px rgba(37,99,235,0.3);
    }
    h2 { text-align: center; font-size: 1.35rem; font-weight: 700; margin-bottom: 4px; }
    p.sub { text-align: center; color: var(--muted); font-size: 0.82rem; margin-bottom: 20px; }
    .form-group { margin-bottom: 16px; }
    label { display: block; font-size: 0.8rem; font-weight: 600; color: var(--muted); margin-bottom: 6px; }
    .input-box {
      width: 100%; background: #0f172a; border: 1px solid var(--border); color: #fff;
      padding: 12px 14px; border-radius: 10px; font-size: 0.95rem; outline: none;
    }
    .input-box:focus { border-color: var(--accent); }
    .btn-submit {
      width: 100%; background: linear-gradient(135deg, #2563eb, #1d4ed8); color: #fff; border: none;
      padding: 13px; border-radius: 10px; font-size: 1rem; font-weight: 600; cursor: pointer;
      margin-top: 10px; box-shadow: 0 4px 16px rgba(37,99,235,0.3);
    }
    .error-msg { background: rgba(239, 68, 68, 0.15); border: 1px solid rgba(239, 68, 68, 0.3); color: #f87171; padding: 10px; border-radius: 8px; font-size: 0.85rem; text-align: center; margin-bottom: 14px; }

    /* Save Password Modal */
    .save-modal {
      position: fixed; inset: 0; background: rgba(0,0,0,0.7); backdrop-filter: blur(5px);
      display: none; align-items: center; justify-content: center; z-index: 100; padding: 16px;
    }
    .save-card {
      background: #1e293b; border: 1px solid #334155; border-radius: 18px; width: 100%; max-width: 380px;
      padding: 22px; box-shadow: 0 25px 50px rgba(0,0,0,0.5); text-align: left;
    }
    .save-btns { display: flex; flex-direction: column; gap: 8px; margin-top: 16px; }
    .btn-save-opt {
      padding: 11px; border-radius: 8px; font-weight: 600; font-size: 0.9rem; cursor: pointer; border: none; text-align: center;
    }
    .btn-save-confirm { background: #2563eb; color: #fff; }
    .btn-save-notnow { background: #334155; color: #fff; }
    .btn-save-never { background: transparent; color: #94a3b8; border: 1px solid #334155; }
  </style>
</head>
<body>
  <div class="login-card">
    <div class="brand-icon">🔧</div>
    <h2>Patiraj Repair Shop</h2>
    <p class="sub">Sign in to manage inventory & sales</p>

    {% if error %}
      <div class="error-msg">{{ error }}</div>
    {% endif %}

    <form id="loginForm" method="POST" action="/login" onsubmit="handleLoginSubmit(event)">
      <div class="form-group">
        <label>Username</label>
        <input type="text" id="usernameInput" name="username" class="input-box" required placeholder="Enter username" autocomplete="username">
      </div>
      <div class="form-group">
        <label>Password</label>
        <input type="password" id="passwordInput" name="password" class="input-box" required placeholder="Enter password" autocomplete="current-password">
      </div>
      <button type="submit" class="btn-submit">Sign In to Dashboard</button>
    </form>
  </div>

  <!-- Save Password Popup Modal -->
  <div class="save-modal" id="savePasswordModal">
    <div class="save-card">
      <div style="display:flex; align-items:center; gap:10px; margin-bottom:12px;">
        <span style="font-size:1.6rem; background:#eff6ff; padding:6px 10px; border-radius:10px;">🔐</span>
        <div>
          <h3 style="font-size:1.1rem; font-weight:700;">Save Password?</h3>
          <span style="font-size:0.75rem; color:#60a5fa; font-weight:600;">Secure Credential Storage</span>
        </div>
      </div>
      <p style="font-size:0.95rem; font-weight:600; margin-bottom:6px;">Kya aap apna Username aur Password save karna chahte hain?</p>
      <p style="font-size:0.8rem; color:#94a3b8;">Agali baar login karte waqt username automatically pre-fill ho jayega.</p>

      <div class="save-btns">
        <button type="button" class="btn-save-opt btn-save-confirm" onclick="confirmSavePassword()">💾 Save</button>
        <button type="button" class="btn-save-opt btn-save-notnow" onclick="proceedWithoutSave()">Not Now</button>
        <button type="button" class="btn-save-opt btn-save-never" onclick="neverAskAgain()">Never Ask Again</button>
      </div>
    </div>
  </div>

  <script>
    window.addEventListener('DOMContentLoaded', () => {
      const savedUser = localStorage.getItem('patiraj_web_user');
      if (savedUser) {
        document.getElementById('usernameInput').value = savedUser;
      }
    });

    let pendingForm = false;

    async function handleLoginSubmit(e) {
      if (pendingForm) return;
      e.preventDefault();
      
      const u = document.getElementById('usernameInput').value.trim();
      const p = document.getElementById('passwordInput').value;

      try {
        const res = await fetch('/api/verify_login', {
          method: 'POST',
          headers: {'Content-Type': 'application/json'},
          body: JSON.stringify({username: u, password: p})
        });
        const data = await res.json();
        if (data.valid) {
          const neverAsk = localStorage.getItem('patiraj_web_never_ask') === '1';
          const alreadySaved = localStorage.getItem('patiraj_web_user') === u;
          if (!neverAsk && !alreadySaved) {
            document.getElementById('savePasswordModal').style.display = 'flex';
            return;
          }
          submitLogin();
        } else {
          submitLogin();
        }
      } catch (err) {
        submitLogin();
      }
    }

    function confirmSavePassword() {
      const u = document.getElementById('usernameInput').value.trim();
      localStorage.setItem('patiraj_web_user', u);
      submitLogin();
    }

    function proceedWithoutSave() {
      submitLogin();
    }

    function neverAskAgain() {
      localStorage.setItem('patiraj_web_never_ask', '1');
      submitLogin();
    }

    function submitLogin() {
      pendingForm = true;
      document.getElementById('loginForm').submit();
    }
  </script>
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
            return redirect(url_for("index"))
        error = "Invalid username or password. Please try again."
    return render_template_string(LOGIN_TEMPLATE, error=error)

@app.route("/logout")
def logout():
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
    conn = get_db()
    today_str = datetime.now().strftime("%Y-%m-%d")
    month_str = datetime.now().strftime("%Y-%m")

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

    low_stock = conn.execute("SELECT COUNT(*) c FROM parts WHERE quantity <= low_stock_threshold").fetchone()["c"]
    conn.close()

    today_sale = (rep_today["s"] or 0) + (part_today["s"] or 0)
    today_profit = (rep_today["p"] or 0) + (part_today["p"] or 0)
    month_profit = (rep_month["p"] or 0) + (part_month["p"] or 0)

    return jsonify({
        "today_sale": float(today_sale),
        "today_profit": float(today_profit),
        "month_profit": float(month_profit),
        "low_stock_count": int(low_stock)
    })

@app.route("/api/sold_records")
def api_sold_records():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    stype = request.args.get("type", "all")
    conn = get_db()
    records = []

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
        phone_rows = conn.execute("""SELECT id, customer_name, phone_number, brand, model, estimated_charge, 
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
                "model": f"{r['brand']} {r['model']}".strip(),
                "quantity": 1,
                "sale_price": float(charge),
                "profit": float(charge - cost)
            })

    conn.close()
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
        return jsonify({"error": "Unauthorized"}), 401
    data = request.get_json() or {}
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    conn = get_db()
    conn.execute("""INSERT INTO parts(name, brand, model, compatible_models, category, quantity, low_stock_threshold, purchase_price, selling_price, supplier, notes, created_at, updated_at)
                    VALUES(?, ?, ?, ?, '', ?, ?, ?, ?, ?, '', ?, ?)""",
                 (data["name"], data["brand"], data["model"], data.get("compatible_models", ""),
                  data["quantity"], data["low_stock_threshold"], data["purchase_price"], data["selling_price"], data.get("supplier", ""), now, now))
    conn.commit()
    conn.close()
    return jsonify({"success": True})

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
    return jsonify({"success": True, "new_quantity": new_qty})

@app.route("/api/phones")
def api_phones():
    if "user_id" not in session:
        return jsonify({"error": "Unauthorized"}), 401
    q = request.args.get("q", "").strip()
    conn = get_db()
    if q:
        pat = f"%{q}%"
        rows = conn.execute("""SELECT * FROM phones WHERE customer_name LIKE ? OR phone_number LIKE ? OR brand LIKE ? OR model LIKE ? OR imei LIKE ? OR issue_description LIKE ? ORDER BY id DESC""",
                            (pat, pat, pat, pat, pat, pat)).fetchall()
    else:
        rows = conn.execute("SELECT * FROM phones ORDER BY id DESC LIMIT 100").fetchall()
    conn.close()
    return jsonify([dict(r) for r in rows])

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

if __name__ == "__main__":
    local_ip = get_local_ip()
    print("=" * 60)
    print("PATIRAJ MOBILE REPAIR SHOP - WEB SERVER RUNNING")
    print(f">> Windows Browser Link: http://localhost:5000")
    print(f">> Android Mobile Link:  http://{local_ip}:5000")
    print("=" * 60)
    app.run(host="0.0.0.0", port=5000, debug=False)
