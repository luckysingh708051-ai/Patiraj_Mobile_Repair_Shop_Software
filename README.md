# 📱 Patiraj Mobile Repair Shop Manager (Secured Offline & Mobile Web App)

A complete, secure, and modern management software designed specifically for mobile repair shops, hardware technicians, and spare parts inventory tracking. 

Runs seamlessly on both **Windows Desktop (Native GUI)** and **Android Mobile (Touch-friendly Web App)** with real-time synchronized offline database.

---

## 🌟 Key Features

### 1. 🔐 High-Grade Security & Authentication
- **Secure Admin & Staff Login**: Protected pages and role-based permissions (RBAC).
- **Password Protection**: Hashed using **PBKDF2-HMAC-SHA256** with 200,000 iterations and cryptographic salts.
- **Save Credentials Popup**: Interactive modal asking user to securely save credentials on successful login (using **Windows DPAPI** machine/user locking on desktop & secure session on web).
- **Auto-Logout Security**: Automatic screen lock after 10 minutes of inactivity.
- **Audit Logs**: Records important actions (stock changes, logins, sales, part deletions).

### 2. 📦 Parts Inventory Management & Search
- Track spare parts: Name, Brand, Primary Model, **Compatible / Works on Models**, Category, Qty, and Low Stock Alerts.
- Dual pricing: Purchase Price (admin locked) and Selling Price.
- **Direct In-Place Part Search**: Select part dropdown allows typing directly to filter matching parts in real-time.

### 3. 🔄 Stock In / Out (Sales & Restock)
- Real-time stock movement tracking for customer sales and supplier restock.
- Instant price calculation and stock balance deduction.

### 4. 📊 Dashboard & Financial Analytics
- **Today's Sale** & **Today's Net Profit**.
- **Total Monthly Profit** calculation.
- **Filterable Sold Item Records**: Analyze sales history by **Day / Date**, **Month**, **Year**, or **All Time**.

### 5. 📱 Phone Repair Job Sheet Tracking
- Customer name, mobile number, device model, IMEI, issue description, estimated charges, and status (`Pending`, `In Progress`, `Delivered`).

### 6. 🌐 Cross-Platform Access (Windows + Android Mobile)
- **Windows Desktop App**: High-performance Native Tkinter GUI (`app.py`).
- **Android Mobile App**: Responsive, mobile-first Web interface (`web_app.py`).
  - Open `http://<YOUR_IP>:5000` on Android Chrome.
  - Tap **Add to Home screen** to install as a standalone mobile app!
  - Both Windows & Android stay synchronized with the same local SQLite database.

---

## 🚀 How to Run

### Option 1: Native Windows Desktop App
Double-click `run_windows.bat` or run:
```bash
python app.py
```

### Option 2: Web Server (for Android Phone & Browser)
Double-click `start_web_server.bat` or run:
```bash
python web_app.py
```
- **Windows Browser Link**: `http://localhost:5000`
- **Android Mobile Link**: `http://<YOUR_LOCAL_IP>:5000` (Make sure phone is connected to same Wi-Fi/Hotspot)

---

## 🛠️ Technology Stack
- **Desktop Frontend**: Python Tkinter (Modern styling)
- **Web & Mobile Frontend**: HTML5, Vanilla CSS, Responsive Mobile Design
- **Backend**: Python 3, Flask
- **Database**: SQLite3 (WAL Mode enabled)
- **Cryptography**: Windows DPAPI (`ctypes.windll.crypt32`), PBKDF2-HMAC-SHA256
