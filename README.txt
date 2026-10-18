PATIRAJ MOBILE REPAIR SHOP — Python + SQLite (Secured Edition)
=============================================================

Features
--------
- Secure Authentication: Password-protected login with PBKDF2-HMAC-SHA256 (200,000 rounds).
- Inactivity Auto-Lock: Automatically locks session after 10 minutes of idle time.
- Brute-Force Rate Limiting: Temporary 60-second lockout after 5 consecutive failed login attempts.
- Role-Based Access Control (RBAC):
    * Admin: Full access to financials, profits, user management, audit logs, and DB restore.
    * Staff / Technician: Inventory viewing/movement, repair tracking; sensitive profits and deletion restricted.
- Dashboard with Real-Time Metrics:
    * Today's Sale, Today's Profit (Repairs + Parts breakdown)
    * This Month's Sale, Total Profit in Month
    * Operational cards: Stock Inventory, Pending Phones, Completed Repairs, Low Stock Alert
- Comprehensive Sales History: Filter all sold parts and repairs by Day, Month, Year, and Type.
- Compatible Models Support: Map items/parts to multiple phone models with smart multi-model search.
- Parts Management: Add, edit, search, and stock audit.
- Stock In / Stock Out: Audited movement history with quantity and unit price validation.
- Pending Phone Jobs: Track customer, model, problem, work required, charge, cost, and delivery date.
- Security Audit Trail: Automated logging of logins, logouts, parts additions/edits/deletions, and repairs.
- Disaster Recovery: One-click Database Backup and verified Database Restore with emergency rollback snapshot.
- 100% Offline: No internet connection or external servers required.

Default Credentials
-------------------
Username: admin
Password: Admin123

* Important: Please change your password immediately after logging in by clicking the "🔑 Password" button in the top-right header!

Requirements
------------
- Windows 10/11
- Python 3.10+ (python.org installer)
- Tkinter & SQLite (included natively with Python standard installation)

Run
---
1. Double-click run_windows.bat, or open Command Prompt in this folder and run:
       python app.py
2. Log in using your credentials.
3. The database file mobile_repair_manager.db is encrypted/protected in the same folder.
