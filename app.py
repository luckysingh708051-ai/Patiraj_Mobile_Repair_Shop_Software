import sqlite3
import tkinter as tk
from tkinter import ttk, messagebox, filedialog
from datetime import datetime
import shutil
import os
import hashlib
import secrets
import hmac
import time
import base64
import ctypes
from ctypes import wintypes

class DATA_BLOB(ctypes.Structure):
    _fields_ = [("cbData", wintypes.DWORD), ("pbData", ctypes.POINTER(ctypes.c_byte))]

def encrypt_secret(secret_str: str) -> str:
    """Encrypts credentials using Windows DPAPI (machine & logged-in user locked)."""
    if not secret_str:
        return ""
    try:
        data_bytes = secret_str.encode("utf-8")
        in_blob = DATA_BLOB(len(data_bytes), ctypes.cast(ctypes.create_string_buffer(data_bytes), ctypes.POINTER(ctypes.c_byte)))
        out_blob = DATA_BLOB()
        if ctypes.windll.crypt32.CryptProtectData(ctypes.byref(in_blob), "PatirajRepairCredentials", None, None, None, 0, ctypes.byref(out_blob)):
            cipher_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
            ctypes.windll.kernel32.LocalFree(out_blob.pbData)
            return "DPAPI:" + base64.b64encode(cipher_bytes).decode("ascii")
    except Exception:
        pass
    # Resilient machine-salt fallback
    key = hashlib.sha256(b"Patiraj_Local_Machine_Secured_Token_" + os.environ.get("COMPUTERNAME", "PC").encode()).digest()
    xor_bytes = bytes([b ^ key[i % len(key)] for i, b in enumerate(secret_str.encode("utf-8"))])
    return "XOR:" + base64.b64encode(xor_bytes).decode("ascii")

def decrypt_secret(encrypted_str: str) -> str:
    """Decrypts credentials using Windows DPAPI or fallback cipher."""
    if not encrypted_str:
        return ""
    try:
        if encrypted_str.startswith("DPAPI:"):
            cipher_bytes = base64.b64decode(encrypted_str[6:].encode("ascii"))
            in_blob = DATA_BLOB(len(cipher_bytes), ctypes.cast(ctypes.create_string_buffer(cipher_bytes), ctypes.POINTER(ctypes.c_byte)))
            out_blob = DATA_BLOB()
            if ctypes.windll.crypt32.CryptUnprotectData(ctypes.byref(in_blob), None, None, None, None, 0, ctypes.byref(out_blob)):
                dec_bytes = ctypes.string_at(out_blob.pbData, out_blob.cbData)
                ctypes.windll.kernel32.LocalFree(out_blob.pbData)
                return dec_bytes.decode("utf-8", errors="replace")
        elif encrypted_str.startswith("XOR:"):
            xor_bytes = base64.b64decode(encrypted_str[4:].encode("ascii"))
            key = hashlib.sha256(b"Patiraj_Local_Machine_Secured_Token_" + os.environ.get("COMPUTERNAME", "PC").encode()).digest()
            dec_bytes = bytes([b ^ key[i % len(key)] for i, b in enumerate(xor_bytes)])
            return dec_bytes.decode("utf-8", errors="replace")
    except Exception:
        pass
    return ""

APP_TITLE = "Patiraj Mobile Repair Shop - Manager (Secured)"
DB_FILE = "mobile_repair_manager.db"

BG = "#f3f6fb"
NAV = "#17243a"
ACCENT = "#2563eb"
CARD = "#ffffff"
TEXT = "#172033"
MUTED = "#65728a"
DANGER = "#dc2626"
SUCCESS = "#16a34a"

# Security Configuration
PASSWORD_SALT_BYTES = 32
PASSWORD_HASH_ITERATIONS = 200_000
AUTO_LOGOUT_TIMEOUT_SECONDS = 600  # 10 minutes inactivity auto-lock
MAX_LOGIN_ATTEMPTS = 5
LOCKOUT_DURATION_SECONDS = 60

def hash_password(password: str, salt_hex: str = None) -> tuple[str, str]:
    """Hashes password with PBKDF2-HMAC-SHA256 and 200,000 iterations."""
    if salt_hex is None:
        salt_bytes = secrets.token_bytes(PASSWORD_SALT_BYTES)
        salt_hex = salt_bytes.hex()
    else:
        salt_bytes = bytes.fromhex(salt_hex)
    pwd_hash = hashlib.pbkdf2_hmac(
        'sha256',
        password.encode('utf-8'),
        salt_bytes,
        PASSWORD_HASH_ITERATIONS
    )
    return pwd_hash.hex(), salt_hex

def verify_password(password: str, stored_hash_hex: str, salt_hex: str) -> bool:
    """Constant-time verification of password hash."""
    try:
        salt_bytes = bytes.fromhex(salt_hex)
        expected_hash = bytes.fromhex(stored_hash_hex)
        actual_hash = hashlib.pbkdf2_hmac(
            'sha256',
            password.encode('utf-8'),
            salt_bytes,
            PASSWORD_HASH_ITERATIONS
        )
        return hmac.compare_digest(expected_hash, actual_hash)
    except Exception:
        return False

def validate_password_strength(password: str) -> tuple[bool, str]:
    if len(password) < 6:
        return False, "Password must be at least 6 characters long."
    if not any(c.isalpha() for c in password):
        return False, "Password must contain at least one letter."
    if not any(c.isdigit() for c in password):
        return False, "Password must contain at least one number."
    return True, ""

def make_password_entry_row(parent, var, width=28, bg=CARD):
    """Creates a unified password Entry box with the 👁️ Show / 🙈 Hide button neatly fitted inside the right edge."""
    container = tk.Frame(
        parent,
        bg="white",
        highlightbackground="#cbd5e1",
        highlightcolor="#2563eb",
        highlightthickness=1
    )

    entry = tk.Entry(
        container,
        textvariable=var,
        show="*",
        width=width,
        font=("Segoe UI", 10),
        bg="white",
        fg=TEXT,
        bd=0,
        relief="flat",
        insertbackground=TEXT
    )
    entry.pack(side="left", fill="both", expand=True, padx=(8, 2), pady=4)

    state = {"visible": False}

    def toggle():
        if state["visible"]:
            entry.config(show="*")
            btn.config(text="👁️ Show")
            state["visible"] = False
        else:
            entry.config(show="")
            btn.config(text="🙈 Hide")
            state["visible"] = True

    btn = tk.Button(
        container,
        text="👁️ Show",
        command=toggle,
        bg="#f1f5f9",
        fg="#475569",
        activebackground="#e2e8f0",
        activeforeground="#1e293b",
        relief="flat",
        bd=0,
        font=("Segoe UI", 8, "bold"),
        padx=7,
        pady=2,
        cursor="hand2"
    )
    btn.pack(side="right", padx=(2, 4), pady=3)

    def on_focus_in(e):
        container.config(highlightbackground="#2563eb", highlightcolor="#2563eb")

    def on_focus_out(e):
        container.config(highlightbackground="#cbd5e1", highlightcolor="#cbd5e1")

    entry.bind("<FocusIn>", on_focus_in)
    entry.bind("<FocusOut>", on_focus_out)

    return container, entry


class RepairManager:
    def __init__(self, root):
        self.root = root
        self.root.title(APP_TITLE)
        self.root.geometry("1260x780")
        self.root.minsize(1050, 660)
        self.root.configure(bg=BG)

        # Session & Security State
        self.current_user = None  # Dict of logged-in user
        self.last_activity_time = time.time()
        self.failed_attempts = 0
        self.lockout_until = 0

        self.conn = sqlite3.connect(DB_FILE)
        self.conn.row_factory = sqlite3.Row
        self.setup_db()
        self.style()

        # Inactivity auto-logout tracking
        self.root.bind_all("<Key>", self.reset_inactivity)
        self.root.bind_all("<Button>", self.reset_inactivity)
        self.root.bind_all("<Motion>", self.reset_inactivity)
        self.check_inactivity_timer()

        # Authentication Gate: Check if initial admin exists
        cur = self.conn.cursor()
        user_count = cur.execute("SELECT COUNT(*) n FROM users").fetchone()["n"]
        if user_count == 0:
            self.show_initial_setup()
        else:
            self.show_login_screen()

    def reset_inactivity(self, event=None):
        self.last_activity_time = time.time()

    def check_inactivity_timer(self):
        """Periodically checks if session has timed out due to inactivity."""
        if self.current_user and (time.time() - self.last_activity_time > AUTO_LOGOUT_TIMEOUT_SECONDS):
            self.log_audit("AUTO_LOGOUT", "session", self.current_user["id"], "Session auto-locked due to 10 min inactivity.")
            self.lock_screen(reason="Session timed out due to 10 minutes of inactivity.")
        self.root.after(5000, self.check_inactivity_timer)

    def log_audit(self, action: str, entity_type: str = "", entity_id: str = "", details: str = ""):
        """Secure server-side audit logger for compliance and tracking."""
        user_id = self.current_user["id"] if self.current_user else None
        username = self.current_user["username"] if self.current_user else "system"
        now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        try:
            self.conn.execute(
                "INSERT INTO audit_logs(timestamp, user_id, username, action, entity_type, entity_id, details) VALUES(?,?,?,?,?,?,?)",
                (now, user_id, username, action, entity_type, str(entity_id), details)
            )
            self.conn.commit()
        except Exception:
            pass

    def get_pref(self, key: str, default: str = "") -> str:
        try:
            row = self.conn.execute("SELECT value FROM app_preferences WHERE key = ?", (key,)).fetchone()
            return row["value"] if row else default
        except Exception:
            return default

    def set_pref(self, key: str, value: str):
        try:
            self.conn.execute("INSERT OR REPLACE INTO app_preferences(key, value) VALUES(?, ?)", (key, str(value)))
            self.conn.commit()
        except Exception:
            pass

    def delete_pref(self, key: str):
        try:
            self.conn.execute("DELETE FROM app_preferences WHERE key = ?", (key,))
            self.conn.commit()
        except Exception:
            pass

    def is_never_ask_save_login(self) -> bool:
        return self.get_pref("never_ask_save_login", "0") == "1"

    def set_never_ask_save_login(self, val: bool = True):
        self.set_pref("never_ask_save_login", "1" if val else "0")

    def save_login_credentials(self, username: str, password: str):
        self.set_pref("saved_login_user", username)
        self.set_pref("saved_login_pass", encrypt_secret(password))
        self.set_pref("has_saved_login", "1")

    def get_saved_login_credentials(self):
        if self.get_pref("has_saved_login", "0") == "1":
            user = self.get_pref("saved_login_user", "")
            enc_pass = self.get_pref("saved_login_pass", "")
            plain_pass = decrypt_secret(enc_pass)
            return user, plain_pass
        return "", ""

    def clear_saved_login_credentials(self):
        self.delete_pref("saved_login_user")
        self.delete_pref("saved_login_pass")
        self.set_pref("has_saved_login", "0")

    def setup_db(self):
        cur = self.conn.cursor()
        cur.execute("PRAGMA foreign_keys = ON")
        cur.execute("PRAGMA journal_mode = WAL")

        # App preferences table for settings & secure credentials
        cur.execute("""CREATE TABLE IF NOT EXISTS app_preferences (
            key TEXT PRIMARY KEY,
            value TEXT NOT NULL
        )""")

        # Users table for RBAC authentication
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

        # Audit logs table
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
            estimated_charge REAL NOT NULL DEFAULT 0,
            repair_cost REAL NOT NULL DEFAULT 0,
            status TEXT NOT NULL DEFAULT 'Pending',
            received_date TEXT NOT NULL,
            notes TEXT DEFAULT '',
            delivered_date TEXT DEFAULT ''
        )""")

        # Backward-compatible migrations
        migrations = [
            ("parts", "compatible_models", "TEXT DEFAULT ''"),
            ("stock_history", "sale_price", "REAL DEFAULT 0"),
            ("stock_history", "purchase_price", "REAL DEFAULT 0"),
            ("phones", "repair_cost", "REAL DEFAULT 0"),
        ]
        for table, col, col_type in migrations:
            try:
                cur.execute(f"ALTER TABLE {table} ADD COLUMN {col} {col_type}")
            except sqlite3.OperationalError:
                pass
        self.conn.commit()

    def style(self):
        s = ttk.Style()
        try: s.theme_use("clam")
        except tk.TclError: pass
        s.configure("Treeview", rowheight=28, font=("Segoe UI", 10), background="white", fieldbackground="white")
        s.configure("Treeview.Heading", font=("Segoe UI", 10, "bold"), background="#e8eef8")
        s.configure("TButton", font=("Segoe UI", 10), padding=7)
        s.configure("Accent.TButton", font=("Segoe UI", 10, "bold"), padding=8)
        s.configure("TEntry", padding=6)
        s.configure("TCombobox", padding=5)
        s.configure("TNotebook", background=BG)
        s.configure("TNotebook.Tab", font=("Segoe UI", 10, "bold"), padding=(14, 6))

    # =========================================================================
    # AUTHENTICATION & LOGIN UI
    # =========================================================================
    def show_initial_setup(self):
        """First-time setup for the Master Administrator account."""
        for w in self.root.winfo_children(): w.destroy()

        outer = tk.Frame(self.root, bg=BG)
        outer.place(relx=0.5, rely=0.5, anchor="center")

        box = tk.Frame(outer, bg=CARD, highlightbackground="#cbd5e1", highlightthickness=1, padx=35, pady=30)
        box.pack()

        tk.Label(box, text="🔐 Initial Security Setup", font=("Segoe UI", 18, "bold"), bg=CARD, fg=TEXT).pack(pady=(0, 4))
        tk.Label(box, text="Create Master Administrator account for Patiraj Mobile Repair Shop.", font=("Segoe UI", 9), bg=CARD, fg=MUTED).pack(pady=(0, 20))

        fields = [
            ("Admin Username:", "admin_user", "admin"),
            ("Full Name:", "admin_name", "Shop Owner"),
            ("Master Password:", "admin_pass", ""),
            ("Confirm Password:", "admin_pass2", "")
        ]
        vars_ = {}
        for lbl_text, key, def_val in fields:
            tk.Label(box, text=lbl_text, font=("Segoe UI", 10, "bold"), bg=CARD, fg=TEXT).pack(anchor="w", pady=(4, 2))
            v = tk.StringVar(value=def_val)
            vars_[key] = v
            if "pass" in key:
                pf, pe = make_password_entry_row(box, v, width=28, bg=CARD)
                pf.pack(fill="x", pady=(0, 8))
            else:
                ent = ttk.Entry(box, textvariable=v, font=("Segoe UI", 10))
                ent.pack(fill="x", pady=(0, 8), ipady=3)

        def create_admin():
            u = vars_["admin_user"].get().strip()
            name = vars_["admin_name"].get().strip()
            p1 = vars_["admin_pass"].get()
            p2 = vars_["admin_pass2"].get()

            if not u or not name:
                messagebox.showerror("Validation Error", "Username and Full Name are required.")
                return
            if not u.isalnum() and "_" not in u:
                messagebox.showerror("Validation Error", "Username can only contain letters, numbers, and underscores.")
                return
            if p1 != p2:
                messagebox.showerror("Password Mismatch", "Passwords do not match.")
                return

            valid, msg = validate_password_strength(p1)
            if not valid:
                messagebox.showerror("Weak Password", msg)
                return

            pwd_hash, salt = hash_password(p1)
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                self.conn.execute(
                    "INSERT INTO users(username, password_hash, salt, role, full_name, created_at) VALUES(?,?,?,?,?,?)",
                    (u, pwd_hash, salt, "admin", name, now)
                )
                self.conn.commit()
                self.log_audit("INITIAL_SETUP", "user", u, f"Master Admin '{u}' account created.")
                messagebox.showinfo("Setup Complete", "Administrator account created successfully! Please log in.")
                self.show_login_screen()
            except Exception as e:
                messagebox.showerror("Setup Error", "Failed to create administrator account. Please try again.")

        ttk.Button(box, text="Create Admin Account & Launch", command=create_admin).pack(fill="x", pady=(14, 0))

    def show_login_screen(self, lock_message=""):
        """Displays secure login dialog and blocks unauthorized access."""
        for w in self.root.winfo_children(): w.destroy()

        outer = tk.Frame(self.root, bg=BG)
        outer.place(relx=0.5, rely=0.5, anchor="center")

        box = tk.Frame(outer, bg=CARD, highlightbackground="#cbd5e1", highlightthickness=1, padx=38, pady=32)
        box.pack()

        tk.Label(box, text="🔧 PATIRAJ MOBILE REPAIR SHOP", font=("Segoe UI", 16, "bold"), bg=CARD, fg=TEXT).pack()
        tk.Label(box, text="Secure System Access", font=("Segoe UI", 10, "bold"), bg=CARD, fg=ACCENT).pack(pady=(2, 6))

        if lock_message:
            tk.Label(box, text=lock_message, font=("Segoe UI", 9, "bold"), bg="#fee2e2", fg=DANGER, padx=10, pady=4).pack(fill="x", pady=(0, 12))
        else:
            tk.Label(box, text="Please enter your credentials to unlock.", font=("Segoe UI", 9), bg=CARD, fg=MUTED).pack(pady=(0, 14))

        user_var = tk.StringVar()
        pass_var = tk.StringVar()

        saved_user, saved_pass = self.get_saved_login_credentials()
        if saved_user:
            user_var.set(saved_user)
        if saved_pass:
            pass_var.set(saved_pass)

        tk.Label(box, text="Username:", font=("Segoe UI", 10, "bold"), bg=CARD, fg=TEXT).pack(anchor="w")
        u_entry = ttk.Entry(box, textvariable=user_var, font=("Segoe UI", 10))
        u_entry.pack(fill="x", pady=(2, 10), ipady=3)

        tk.Label(box, text="Password:", font=("Segoe UI", 10, "bold"), bg=CARD, fg=TEXT).pack(anchor="w")
        p_frame, p_entry = make_password_entry_row(box, pass_var, width=26, bg=CARD)
        p_frame.pack(fill="x", pady=(2, 8 if saved_user else 14))

        status_lbl = tk.Label(box, text="", font=("Segoe UI", 9), bg=CARD, fg=DANGER)

        if saved_user:
            saved_bar = tk.Frame(box, bg=CARD)
            saved_bar.pack(fill="x", pady=(0, 10))
            tk.Label(saved_bar, text="💾 Saved credentials loaded", font=("Segoe UI", 8, "bold"), bg=CARD, fg=SUCCESS).pack(side="left")

            def forget_login():
                self.clear_saved_login_credentials()
                user_var.set("")
                pass_var.set("")
                saved_bar.destroy()
                p_frame.pack_configure(pady=(2, 14))
                status_lbl.config(text="Saved credentials removed.", fg=MUTED)

            tk.Button(
                saved_bar,
                text="Forget",
                command=forget_login,
                bg=CARD,
                fg="#94a3b8",
                activebackground=CARD,
                activeforeground=DANGER,
                relief="flat",
                bd=0,
                font=("Segoe UI", 8, "underline"),
                cursor="hand2"
            ).pack(side="right")

        status_lbl.pack(pady=(0, 8))

        if not saved_user:
            u_entry.focus()

        def attempt_login():
            now_ts = time.time()
            if now_ts < self.lockout_until:
                remaining = int(self.lockout_until - now_ts)
                status_lbl.config(text=f"Too many failed attempts. Locked for {remaining}s.")
                return

            u = user_var.get().strip()
            p = pass_var.get()
            if not u or not p:
                status_lbl.config(text="Please enter username and password.")
                return

            user = self.conn.execute("SELECT * FROM users WHERE username = ? AND is_active = 1", (u,)).fetchone()
            if user and verify_password(p, user["password_hash"], user["salt"]):
                self.failed_attempts = 0
                self.current_user = dict(user)
                now_str = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.conn.execute("UPDATE users SET last_login = ? WHERE id = ?", (now_str, user["id"]))
                self.conn.commit()
                self.log_audit("LOGIN_SUCCESS", "user", user["id"], f"User '{u}' logged in successfully.")
                self.last_activity_time = time.time()

                def proceed_to_app():
                    self.build_layout()
                    self.show_dashboard()

                saved_u, saved_p = self.get_saved_login_credentials()
                already_saved = (saved_u == u and saved_p == p)
                never_ask = self.is_never_ask_save_login()

                # Requirement 1 & 9: Only show popup on successful login, if not already saved and not 'Never Ask Again'
                if not already_saved and not never_ask:
                    self.show_save_credentials_popup(u, p, on_complete=proceed_to_app)
                else:
                    proceed_to_app()
            else:
                self.failed_attempts += 1
                self.log_audit("LOGIN_FAILED", "user", u, f"Failed login attempt for username '{u}'.")
                if self.failed_attempts >= MAX_LOGIN_ATTEMPTS:
                    self.lockout_until = time.time() + LOCKOUT_DURATION_SECONDS
                    status_lbl.config(text=f"Account locked! Wait {LOCKOUT_DURATION_SECONDS} seconds.")
                else:
                    rem = MAX_LOGIN_ATTEMPTS - self.failed_attempts
                    status_lbl.config(text=f"Invalid username or password! ({rem} attempts left)")

        btn = ttk.Button(box, text="🔓 Sign In / Unlock", command=attempt_login)
        btn.pack(fill="x", pady=(4, 0))
        p_entry.bind("<Return>", lambda e: attempt_login())
        u_entry.bind("<Return>", lambda e: attempt_login())

    def show_save_credentials_popup(self, username: str, password: str, on_complete=None):
        """Displays modern popup asking if user wants to save their credentials."""
        popup = tk.Toplevel(self.root)
        popup.title("Save Password?")
        popup.configure(bg=BG)
        popup.resizable(False, False)
        popup.transient(self.root)
        popup.grab_set()

        popup.update_idletasks()
        pw, ph = 430, 315
        rx = self.root.winfo_x() + (self.root.winfo_width() // 2) - (pw // 2)
        ry = self.root.winfo_y() + (self.root.winfo_height() // 2) - (ph // 2)
        popup.geometry(f"{pw}x{ph}+{max(10, rx)}+{max(10, ry)}")

        card = tk.Frame(popup, bg=CARD, highlightbackground="#cbd5e1", highlightthickness=1, padx=24, pady=20)
        card.pack(fill="both", expand=True, padx=12, pady=12)

        hdr = tk.Frame(card, bg=CARD)
        hdr.pack(fill="x", pady=(0, 10))

        badge = tk.Frame(hdr, bg="#eff6ff", highlightbackground="#bfdbfe", highlightthickness=1, width=42, height=42)
        badge.pack_propagate(False)
        badge.pack(side="left", padx=(0, 12))
        tk.Label(badge, text="🔐", font=("Segoe UI", 16), bg="#eff6ff").pack(expand=True)

        txt_frame = tk.Frame(hdr, bg=CARD)
        txt_frame.pack(side="left", fill="x", expand=True)
        tk.Label(txt_frame, text="Save Password?", font=("Segoe UI", 14, "bold"), bg=CARD, fg=TEXT).pack(anchor="w")
        tk.Label(txt_frame, text="Secure Credential Manager", font=("Segoe UI", 8, "bold"), bg=CARD, fg=ACCENT).pack(anchor="w")

        tk.Label(
            card,
            text="Kya aap apna Username aur Password save karna chahte hain?",
            font=("Segoe UI", 10, "bold"),
            bg=CARD,
            fg=TEXT,
            wraplength=360,
            justify="left"
        ).pack(anchor="w", pady=(2, 2))

        tk.Label(
            card,
            text="Agali baar login karte waqt username aur password automatically fill ho jayenge.",
            font=("Segoe UI", 8),
            bg=CARD,
            fg=MUTED,
            wraplength=360,
            justify="left"
        ).pack(anchor="w", pady=(0, 10))

        preview = tk.Frame(card, bg="#f8fafc", highlightbackground="#e2e8f0", highlightthickness=1, padx=12, pady=8)
        preview.pack(fill="x", pady=(0, 14))

        tk.Label(preview, text="👤 Username:", font=("Segoe UI", 8, "bold"), bg="#f8fafc", fg=MUTED).grid(row=0, column=0, sticky="w", pady=1)
        tk.Label(preview, text=username, font=("Segoe UI", 9, "bold"), bg="#f8fafc", fg=TEXT).grid(row=0, column=1, sticky="w", padx=8, pady=1)

        tk.Label(preview, text="🔑 Password:", font=("Segoe UI", 8, "bold"), bg="#f8fafc", fg=MUTED).grid(row=1, column=0, sticky="w", pady=1)
        tk.Label(preview, text="••••••••••••", font=("Segoe UI", 9, "bold"), bg="#f8fafc", fg="#64748b").grid(row=1, column=1, sticky="w", padx=8, pady=1)

        def close_and_proceed():
            try:
                popup.destroy()
            except Exception:
                pass
            if on_complete:
                on_complete()

        def on_save():
            self.save_login_credentials(username, password)
            self.log_audit("SAVE_CREDENTIALS", "user", username, "User saved login credentials securely via DPAPI.")
            close_and_proceed()

        def on_not_now():
            close_and_proceed()

        def on_never():
            self.set_never_ask_save_login(True)
            self.log_audit("NEVER_ASK_CREDENTIALS", "user", username, "User selected 'Never Ask Again' for save credentials.")
            close_and_proceed()

        btn_box = tk.Frame(card, bg=CARD)
        btn_box.pack(fill="x", pady=(0, 8))

        btn_save = tk.Button(
            btn_box,
            text="💾 Save",
            command=on_save,
            bg=ACCENT,
            fg="white",
            activebackground="#1d4ed8",
            activeforeground="white",
            relief="flat",
            bd=0,
            font=("Segoe UI", 10, "bold"),
            padx=16,
            pady=6,
            cursor="hand2"
        )
        btn_save.pack(side="left", fill="x", expand=True, padx=(0, 6))

        btn_not_now = tk.Button(
            btn_box,
            text="Not Now",
            command=on_not_now,
            bg="#f1f5f9",
            fg=TEXT,
            activebackground="#e2e8f0",
            activeforeground=TEXT,
            relief="flat",
            bd=0,
            font=("Segoe UI", 10),
            padx=14,
            pady=6,
            cursor="hand2"
        )
        btn_not_now.pack(side="left", fill="x", expand=True, padx=(6, 0))

        btn_never = tk.Button(
            card,
            text="Never Ask Again",
            command=on_never,
            bg=CARD,
            fg="#94a3b8",
            activebackground=CARD,
            activeforeground=DANGER,
            relief="flat",
            bd=0,
            font=("Segoe UI", 8, "underline"),
            cursor="hand2"
        )
        btn_never.pack(anchor="center", pady=(2, 0))

        popup.protocol("WM_DELETE_WINDOW", on_not_now)

    def lock_screen(self, reason="Screen locked by user."):
        """Locks the current session and returns to login gate."""
        self.current_user = None
        self.show_login_screen(lock_message=reason)

    def logout(self):
        if messagebox.askyesno("Confirm Logout", "Are you sure you want to log out of your session?"):
            if self.current_user:
                self.log_audit("LOGOUT", "user", self.current_user["id"], f"User '{self.current_user['username']}' logged out.")
            self.lock_screen(reason="Logged out successfully.")

    def show_web_links_dialog(self):
        """Displays Windows Browser link & Android Mobile link with automatic web server starter and diagnostics."""
        import socket
        import webbrowser
        import threading
        import subprocess
        import sys

        def get_best_ip():
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

        def is_server_listening(port=5000):
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            try:
                s.settimeout(0.4)
                return s.connect_ex(('127.0.0.1', port)) == 0
            except Exception:
                return False
            finally:
                s.close()

        def is_flask_installed():
            try:
                import flask
                return True
            except ImportError:
                return False

        server_error = [None]

        def start_bg_server():
            try:
                # Ensure current directory is in sys.path
                base_dir = os.path.dirname(os.path.abspath(__file__))
                if base_dir not in sys.path:
                    sys.path.insert(0, base_dir)
                import web_app
                web_app.app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
            except Exception as e:
                server_error[0] = str(e)

        # Trigger start if not listening
        if not is_server_listening(5000):
            if is_flask_installed():
                t = threading.Thread(target=start_bg_server, daemon=True)
                t.start()
                self._web_server_started = True

        ip = get_best_ip()
        win_url = "http://localhost:5000"
        mob_url = f"http://{ip}:5000"

        win = tk.Toplevel(self.root)
        win.title("Android & Windows Web Links - Server Manager")
        win.configure(bg=BG)
        win.resizable(False, False)
        win.transient(self.root)
        win.grab_set()

        card = tk.Frame(win, bg=CARD, highlightbackground="#cbd5e1", highlightthickness=1, padx=24, pady=20)
        card.pack(fill="both", expand=True, padx=14, pady=14)

        tk.Label(card, text="🌐 Mobile & Web Server Manager", font=("Segoe UI", 14, "bold"), bg=CARD, fg=TEXT).pack(anchor="w", pady=(0, 2))
        tk.Label(card, text="Aap is software ko apne Computer Browser aur Android Mobile dono par chala sakte hain.", font=("Segoe UI", 9), bg=CARD, fg=MUTED).pack(anchor="w", pady=(0, 10))

        # Status Banner
        status_frame = tk.Frame(card, bg="#f1f5f9", highlightbackground="#cbd5e1", highlightthickness=1, padx=12, pady=8)
        status_frame.pack(fill="x", pady=(0, 14))

        status_lbl = tk.Label(status_frame, text="🔍 Checking server status...", font=("Segoe UI", 9, "bold"), bg="#f1f5f9", fg=TEXT)
        status_lbl.pack(side="left")

        action_btn_holder = tk.Frame(status_frame, bg="#f1f5f9")
        action_btn_holder.pack(side="right")

        def copy_to_clipboard(text, btn, original_label):
            try:
                self.root.clipboard_clear()
                self.root.clipboard_append(text)
                btn.config(text="✓ Copied!")
                self.root.after(1500, lambda: btn.config(text=original_label))
            except Exception:
                pass

        def install_flask():
            win_msg = messagebox.askyesno("Install Flask", "Flask library install karne ke liye internet connection zaroori hai.\n\nKya aap Flask abhi install karna chahte hain?", parent=win)
            if not win_msg:
                return
            status_lbl.config(text="⏳ Installing Flask... Please wait...", fg=ACCENT)
            win.update_idletasks()

            def do_install():
                try:
                    res = subprocess.run([sys.executable, "-m", "pip", "install", "flask"], capture_output=True, text=True, timeout=120)
                    if res.returncode == 0:
                        self.root.after(0, lambda: [
                            messagebox.showinfo("Success", "Flask successfully install ho gaya! Ab server start kiya ja raha hai.", parent=win),
                            start_server_now()
                        ])
                    else:
                        self.root.after(0, lambda: messagebox.showerror("Install Error", f"Flask install nahi ho paya:\n{res.stderr[:300]}", parent=win))
                except Exception as ex:
                    self.root.after(0, lambda: messagebox.showerror("Error", f"Command run karne me error: {ex}", parent=win))
                self.root.after(500, update_status_ui)

            threading.Thread(target=do_install, daemon=True).start()

        def start_server_now():
            if not is_flask_installed():
                install_flask()
                return
            status_lbl.config(text="⏳ Server starting on port 5000...", fg=ACCENT)
            win.update_idletasks()
            t = threading.Thread(target=start_bg_server, daemon=True)
            t.start()
            self._web_server_started = True
            # Check after 1 second
            self.root.after(1200, update_status_ui)

        def update_status_ui():
            for w in action_btn_holder.winfo_children():
                w.destroy()

            listening = is_server_listening(5000)
            flask_ok = is_flask_installed()

            if listening:
                status_lbl.config(text="🟢 Web Server RUNNING (Port 5000 Active)", fg=SUCCESS)
                ttk.Button(action_btn_holder, text="🔄 Check Status", command=update_status_ui).pack(side="left")
            elif not flask_ok:
                status_lbl.config(text="🔴 Flask library missing! (Server cannot run)", fg=DANGER)
                ttk.Button(action_btn_holder, text="📦 Install Flask", command=install_flask).pack(side="left")
            else:
                err_text = f" ({server_error[0]})" if server_error[0] else ""
                status_lbl.config(text=f"🟡 Server Stopped / Starting{err_text}", fg="#d97706")
                ttk.Button(action_btn_holder, text="🚀 Start Server", command=start_server_now).pack(side="left")

        self.root.after(400, update_status_ui)

        # Windows Box
        w_box = tk.Frame(card, bg="#f8fafc", highlightbackground="#e2e8f0", highlightthickness=1, padx=12, pady=10)
        w_box.pack(fill="x", pady=(0, 10))
        tk.Label(w_box, text="💻 Windows Browser Link (Apne computer ke browser ke liye):", font=("Segoe UI", 9, "bold"), bg="#f8fafc", fg=TEXT).pack(anchor="w")
        w_row = tk.Frame(w_box, bg="#f8fafc")
        w_row.pack(fill="x", pady=(6, 0))
        tk.Label(w_row, text=win_url, font=("Consolas", 11, "bold"), bg="#f8fafc", fg=ACCENT).pack(side="left")

        def open_browser():
            if not is_server_listening(5000):
                if not is_flask_installed():
                    install_flask()
                    return
                start_server_now()
                self.root.after(1500, lambda: webbrowser.open(win_url))
            else:
                webbrowser.open(win_url)

        w_btn_row = tk.Frame(w_row, bg="#f8fafc")
        w_btn_row.pack(side="right")
        w_copy_btn = ttk.Button(w_btn_row, text="📋 Copy", command=lambda: copy_to_clipboard(win_url, w_copy_btn, "📋 Copy"))
        w_copy_btn.pack(side="left", padx=(0, 6))
        ttk.Button(w_btn_row, text="🌐 Open Browser", command=open_browser).pack(side="left")

        # Android Box
        m_box = tk.Frame(card, bg="#f8fafc", highlightbackground="#e2e8f0", highlightthickness=1, padx=12, pady=10)
        m_box.pack(fill="x", pady=(0, 14))
        tk.Label(m_box, text="📱 Android Mobile Link (Phone ke Chrome me kholein):", font=("Segoe UI", 9, "bold"), bg="#f8fafc", fg=TEXT).pack(anchor="w")
        m_row = tk.Frame(m_box, bg="#f8fafc")
        m_row.pack(fill="x", pady=(6, 0))
        tk.Label(m_row, text=mob_url, font=("Consolas", 11, "bold"), bg="#f8fafc", fg=SUCCESS).pack(side="left")
        m_copy_btn = ttk.Button(m_row, text="📋 Copy Mobile Link", command=lambda: copy_to_clipboard(mob_url, m_copy_btn, "📋 Copy Mobile Link"))
        m_copy_btn.pack(side="right")

        # Tip Box
        tip_box = tk.Frame(card, bg="#eff6ff", highlightbackground="#bfdbfe", highlightthickness=1, padx=12, pady=10)
        tip_box.pack(fill="x", pady=(0, 14))
        tk.Label(tip_box, text="📱 Mobile Connect Karne Ke 3 Aasan Steps:", font=("Segoe UI", 9, "bold"), bg="#eff6ff", fg="#1e40af").pack(anchor="w")
        tips_text = (
            "1. Computer aur Android Phone dono ko SAME Wi-Fi ya Mobile Hotspot se connect karein.\n"
            "2. Android Phone me Google Chrome kholein aur upar diya gaya Mobile Link daalein.\n"
            "3. Chrome me top-right (3 dots) par tap karke 'Add to Home screen' karein - ye app ban jayega!\n"
            "💡 Agar browser me link na khule, to 'start_web_server.bat' file par double click karke chalaayein."
        )
        tk.Label(tip_box, text=tips_text, font=("Segoe UI", 8), bg="#eff6ff", fg="#1e3a8a", justify="left").pack(anchor="w", pady=(4, 0))

        btn_row = tk.Frame(card, bg=CARD)
        btn_row.pack(fill="x")
        ttk.Button(btn_row, text="Close", command=win.destroy).pack(side="right")

    # =========================================================================
    # MAIN APPLICATION LAYOUT
    # =========================================================================
    def build_layout(self):
        for w in self.root.winfo_children(): w.destroy()

        header = tk.Frame(self.root, bg=CARD, height=66)
        header.pack(side="top", fill="x")

        # Left branding
        tk.Label(header, text="🔧  PATIRAJ MOBILE REPAIR SHOP", bg=CARD, fg=TEXT,
                 font=("Segoe UI", 16, "bold")).pack(side="left", padx=20, pady=16)

        # Right User Badge & Controls
        right_hdr = tk.Frame(header, bg=CARD)
        right_hdr.pack(side="right", padx=20, pady=14)

        u_name = self.current_user.get("full_name") or self.current_user.get("username", "User")
        role = self.current_user.get("role", "staff").upper()
        role_color = SUCCESS if role == "ADMIN" else ACCENT

        user_badge = tk.Frame(right_hdr, bg="#f1f5f9", highlightbackground="#cbd5e1", highlightthickness=1, padx=8, pady=4)
        user_badge.pack(side="left", padx=(0, 12))
        tk.Label(user_badge, text=f"👤 {u_name}", bg="#f1f5f9", fg=TEXT, font=("Segoe UI", 9, "bold")).pack(side="left")
        tk.Label(user_badge, text=f" [{role}]", bg="#f1f5f9", fg=role_color, font=("Segoe UI", 9, "bold")).pack(side="left")

        ttk.Button(right_hdr, text="🌐 Mobile/Web Link", command=self.show_web_links_dialog).pack(side="left", padx=3)
        ttk.Button(right_hdr, text="🔑 Password", command=self.change_password_dialog).pack(side="left", padx=3)
        ttk.Button(right_hdr, text="🔒 Lock", command=lambda: self.lock_screen("Screen locked.")).pack(side="left", padx=3)
        ttk.Button(right_hdr, text="🚪 Logout", command=self.logout).pack(side="left", padx=3)

        body = tk.Frame(self.root, bg=BG)
        body.pack(fill="both", expand=True)

        # Sidebar navigation
        self.sidebar = tk.Frame(body, bg=NAV, width=225)
        self.sidebar.pack(side="left", fill="y")
        self.sidebar.pack_propagate(False)

        tk.Label(self.sidebar, text="MAIN MENU", bg=NAV, fg="#9fb0cc",
                 font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=18, pady=(20, 8))

        nav_items = [
            ("Dashboard", self.show_dashboard),
            ("Parts Management", self.show_parts),
            ("Add New Part", self.add_part_dialog),
            ("Stock In / Out", self.stock_dialog),
            ("Low Stock", self.show_low_stock),
            ("Pending Phones", self.show_phones),
            ("Stock Reports", self.show_reports),
        ]

        # Admin only options
        if self.is_admin():
            nav_items.append(("Backup & Restore", self.show_backup_restore))
            nav_items.append(("User Accounts", self.show_user_management))
            nav_items.append(("Security Audit Logs", self.show_audit_logs))

        for label, command in nav_items:
            b = tk.Button(self.sidebar, text="  " + label, command=command, anchor="w",
                          bg=NAV, fg="white", activebackground="#2a3b59", activeforeground="white",
                          relief="flat", bd=0, font=("Segoe UI", 10), padx=13, pady=9, cursor="hand2")
            b.pack(fill="x", padx=8, pady=2)

        tk.Label(self.sidebar, text="v2.0 • Secured Offline DB", bg=NAV, fg="#9fb0cc",
                 font=("Segoe UI", 8)).pack(side="bottom", pady=12)

        self.content = tk.Frame(body, bg=BG)
        self.content.pack(side="left", fill="both", expand=True, padx=20, pady=16)

    def is_admin(self) -> bool:
        return bool(self.current_user and self.current_user.get("role") == "admin")

    def clear_content(self):
        for w in self.content.winfo_children():
            w.destroy()

    def title(self, text, subtitle="", action_btn=None):
        top_bar = tk.Frame(self.content, bg=BG)
        top_bar.pack(fill="x")
        left = tk.Frame(top_bar, bg=BG)
        left.pack(side="left", fill="x", expand=True)
        tk.Label(left, text=text, bg=BG, fg=TEXT, font=("Segoe UI", 20, "bold")).pack(anchor="w")
        if subtitle:
            self.lbl_subtitle = tk.Label(left, text=subtitle, bg=BG, fg=MUTED, font=("Segoe UI", 10))
            self.lbl_subtitle.pack(anchor="w", pady=(2, 10))
        else:
            self.lbl_subtitle = None
            tk.Frame(left, bg=BG, height=10).pack()
        if action_btn:
            btn_txt, btn_cmd = action_btn
            ttk.Button(top_bar, text=btn_txt, command=btn_cmd).pack(side="right", padx=5)

    def stat_card(self, parent, label, value, sub="", accent=None):
        card = tk.Frame(parent, bg=CARD, highlightbackground="#dce4ef", highlightthickness=1)
        if accent:
            stripe = tk.Frame(card, bg=accent, height=3)
            stripe.pack(side="top", fill="x")
        tk.Label(card, text=label, bg=CARD, fg=MUTED, font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=15, pady=(10, 2))
        val_fg = accent if accent else TEXT
        tk.Label(card, text=str(value), bg=CARD, fg=val_fg, font=("Segoe UI", 19, "bold")).pack(anchor="w", padx=15)
        if sub:
            tk.Label(card, text=sub, bg=CARD, fg=MUTED, font=("Segoe UI", 8)).pack(anchor="w", padx=15, pady=(2, 10))
        else:
            tk.Frame(card, bg=CARD, height=10).pack()
        return card

    # =========================================================================
    # DASHBOARD
    # =========================================================================
    def show_dashboard(self):
        self.clear_content()
        today_dt = datetime.now()
        today_str = today_dt.strftime("%Y-%m-%d")
        month_str = today_dt.strftime("%Y-%m")
        today_formatted = today_dt.strftime("%d %b %Y")
        month_name = today_dt.strftime("%B %Y")

        self.title("Dashboard", f"Business & Repair Overview • Today: {today_formatted} • Month: {month_name}",
                   action_btn=("⟳ Refresh", self.show_dashboard))
        cur = self.conn.cursor()

        # Operational Inventory Metrics
        total_parts = cur.execute("SELECT COUNT(*) n FROM parts").fetchone()["n"]
        total_qty = cur.execute("SELECT COALESCE(SUM(quantity),0) n FROM parts").fetchone()["n"]
        stock_value = cur.execute("SELECT COALESCE(SUM(quantity*purchase_price),0) n FROM parts").fetchone()["n"]
        low_count = cur.execute("SELECT COUNT(*) n FROM parts WHERE quantity <= low_stock").fetchone()["n"]
        pending = cur.execute("SELECT COUNT(*) n FROM phones WHERE status NOT IN ('Delivered')").fetchone()["n"]
        completed = cur.execute("SELECT COUNT(*) n FROM phones WHERE status='Completed'").fetchone()["n"]

        show_profits = self.is_admin()
        val_stock_value = f"₹{stock_value:,.2f}" if show_profits else f"{total_qty} units"

        # Row 1: Dynamic Financial & Sales Overview Cards (Syncs with Date / Month / Year selection)
        row1 = tk.Frame(self.content, bg=BG)
        row1.pack(fill="x", pady=(0, 10))

        def make_dynamic_card(parent, title, val, sub="", accent=None):
            card = tk.Frame(parent, bg=CARD, highlightbackground="#dce4ef", highlightthickness=1)
            if accent:
                stripe = tk.Frame(card, bg=accent, height=3)
                stripe.pack(side="top", fill="x")
            lbl_t = tk.Label(card, text=title, bg=CARD, fg=MUTED, font=("Segoe UI", 9, "bold"))
            lbl_t.pack(anchor="w", padx=15, pady=(10, 2))
            lbl_v = tk.Label(card, text=str(val), bg=CARD, fg=accent if accent else TEXT, font=("Segoe UI", 18, "bold"))
            lbl_v.pack(anchor="w", padx=15)
            lbl_s = tk.Label(card, text=sub, bg=CARD, fg=MUTED, font=("Segoe UI", 8))
            lbl_s.pack(anchor="w", padx=15, pady=(2, 10))
            return card, lbl_t, lbl_v, lbl_s

        card1_w, c1_title, c1_val, c1_sub = make_dynamic_card(row1, "Day Sale", "₹0.00", "Loading...", "#2563eb")
        card2_w, c2_title, c2_val, c2_sub = make_dynamic_card(row1, "Day Profit", "₹0.00", "Loading...", "#16a34a")
        card3_w, c3_title, c3_val, c3_sub = make_dynamic_card(row1, "Parts Sold", "0 units", "Loading...", "#7c3aed")
        card4_w, c4_title, c4_val, c4_sub = make_dynamic_card(row1, "Delivered Repairs", "0 phones", "Loading...", "#0d9488")

        for i, w in enumerate([card1_w, card2_w, card3_w, card4_w]):
            w.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
            row1.grid_columnconfigure(i, weight=1, uniform="fin_cards")

        # Row 2: Operational Cards
        row2 = tk.Frame(self.content, bg=BG)
        row2.pack(fill="x", pady=(0, 14))
        ops_cards = [
            ("Stock Inventory", val_stock_value, f"{total_qty} units in stock ({total_parts} items)", "#475569"),
            ("Pending Phones", pending, "Under repair / waiting for parts", "#e11d48"),
            ("Completed Repairs", completed, "Repaired & ready for customer delivery", "#0284c7"),
            ("Low Stock Items", low_count, "At or below alert threshold", "#d97706"),
        ]
        for i, (label, val, sub, acc) in enumerate(ops_cards):
            c = self.stat_card(row2, label, val, sub, accent=acc)
            c.grid(row=0, column=i, sticky="nsew", padx=(0 if i == 0 else 8, 0))
            row2.grid_columnconfigure(i, weight=1, uniform="ops_cards")

        # Row 3: Notebook Tabs
        notebook = ttk.Notebook(self.content)
        notebook.pack(fill="both", expand=True)

        # Tab 1: Sold Items Record (Day / Month / Year) - Primary Dashboard View
        tab_sold_history = tk.Frame(notebook, bg=CARD)
        notebook.add(tab_sold_history, text="  📜 Sold Items Record (Day / Month / Year)  ")

        def update_dashboard_stats(stats):
            p_type = stats["period_type"]
            sel_v = stats["selected_val"]
            disp_v = stats["display_period"]
            tot_s = stats["tot_sale"]
            tot_p = stats["tot_profit"]
            tot_parts = stats["tot_parts"]
            tot_rep = stats["tot_repairs"]
            p_sale = stats["parts_sale"]
            r_sale = stats["repairs_sale"]
            cnt = stats["count"]

            if p_type == "By Day / Date":
                prefix = "Day"
                sub_txt = f"Repairs: ₹{r_sale:,.0f} • Parts: ₹{p_sale:,.0f}"
                prof_sub = f"Net profit for date {sel_v}"
            elif p_type == "By Month":
                prefix = "Month"
                sub_txt = f"Repairs: ₹{r_sale:,.0f} • Parts: ₹{p_sale:,.0f}"
                prof_sub = f"Net profit for month {sel_v}"
            elif p_type == "By Year":
                prefix = "Year"
                sub_txt = f"Repairs: ₹{r_sale:,.0f} • Parts: ₹{p_sale:,.0f}"
                prof_sub = f"Net profit for year {sel_v}"
            else:
                prefix = "All-Time"
                sub_txt = f"Repairs: ₹{r_sale:,.0f} • Parts: ₹{p_sale:,.0f}"
                prof_sub = "Cumulative profit across all time"

            c1_title.config(text=f"{prefix} Sale ({sel_v})")
            c1_val.config(text=f"₹{tot_s:,.2f}")
            c1_sub.config(text=sub_txt)

            c2_title.config(text=f"{prefix} Profit ({sel_v})")
            c2_val.config(text=f"₹{tot_p:,.2f}" if self.is_admin() else "🔒 Admin Only")
            c2_sub.config(text=prof_sub if self.is_admin() else "Admin Only")

            c3_title.config(text=f"{prefix} Parts Sold")
            c3_val.config(text=f"{tot_parts} units")
            c3_sub.config(text=f"Parts sold for {sel_v}")

            c4_title.config(text=f"{prefix} Delivered Repairs")
            c4_val.config(text=f"{tot_rep} phones")
            c4_sub.config(text=f"Completed repairs for {sel_v}")

            if hasattr(self, "lbl_subtitle") and self.lbl_subtitle:
                self.lbl_subtitle.config(text=f"Business & Repair Overview • Active Filter: {disp_v} • Today: {today_formatted}")

            try:
                notebook.tab(tab_sold_history, text=f"  📜 Sold Items Record ({cnt} items)  ")
            except Exception:
                pass

        self.build_sales_history_view(tab_sold_history, is_compact=True, on_stats_updated=update_dashboard_stats)

        # Tab 2: Today's Completed Sales & Repairs
        tab_today = tk.Frame(notebook, bg=CARD)
        notebook.add(tab_today, text="  💰 Today's Delivered Repairs & Parts Sold  ")

        cols_today = ("time", "type", "item", "customer", "qty", "sale", "profit")
        tree_today = ttk.Treeview(tab_today, columns=cols_today, show="headings", height=8)
        headers_today = [
            ("time", "Time / Date", 110),
            ("type", "Type", 120),
            ("item", "Item / Phone Model", 210),
            ("customer", "Customer / Reason", 200),
            ("qty", "Qty", 65),
            ("sale", "Sale (₹)", 110),
            ("profit", "Profit (₹)", 110)
        ]
        for c, h, w in headers_today:
            tree_today.heading(c, text=h)
            tree_today.column(c, width=w, anchor="w")

        scroll_y_today = ttk.Scrollbar(tab_today, orient="vertical", command=tree_today.yview)
        tree_today.configure(yscrollcommand=scroll_y_today.set)
        tree_today.pack(side="left", fill="both", expand=True)
        scroll_y_today.pack(side="right", fill="y")

        delivered_phones_today = cur.execute("""
            SELECT * FROM phones 
            WHERE status = 'Delivered' AND (delivered_date = ? OR (delivered_date = '' AND received_date = ?))
            ORDER BY id DESC
        """, (today_str, today_str)).fetchall()
        for p in delivered_phones_today:
            cost = p["repair_cost"] or 0
            sale = p["estimated_charge"] or 0
            prof = sale - cost
            tree_today.insert("", "end", values=(
                p["delivered_date"] or today_str,
                "Phone Repair",
                p["phone_model"],
                f"{p['customer_name']} ({p['customer_phone']})" if p["customer_phone"] else p["customer_name"],
                "1",
                f"₹{sale:.2f}",
                f"₹{prof:.2f}" if self.is_admin() else "🔒"
            ))

        stock_out_today = cur.execute("""
            SELECT h.*, p.name, p.selling_price as p_sell, p.purchase_price as p_buy 
            FROM stock_history h
            LEFT JOIN parts p ON p.id = h.part_id
            WHERE h.action = 'OUT' AND substr(h.created_at, 1, 10) = ?
            ORDER BY h.id DESC
        """, (today_str,)).fetchall()
        for h in stock_out_today:
            s_price = h["sale_price"] if h["sale_price"] > 0 else (h["p_sell"] or 0)
            b_price = h["purchase_price"] if h["purchase_price"] > 0 else (h["p_buy"] or 0)
            sale = s_price * h["quantity"]
            cost = b_price * h["quantity"]
            prof = sale - cost
            time_part = h["created_at"][11:16] if len(h["created_at"]) >= 16 else today_str
            tree_today.insert("", "end", values=(
                time_part,
                "Part Sold (Out)",
                h["name"] or "(Deleted Part)",
                h["note"] or "Direct Sale",
                h["quantity"],
                f"₹{sale:.2f}",
                f"₹{prof:.2f}" if self.is_admin() else "🔒"
            ))

        tot_today = len(delivered_phones_today) + len(stock_out_today)
        notebook.tab(tab_today, text=f"  💰 Today's Delivered Repairs & Parts Sold ({tot_today})  ")

        # Tab 3: Low Stock Watchlist
        tab_low = tk.Frame(notebook, bg=CARD)
        notebook.add(tab_low, text=f"  ⚠️ Low Stock Watchlist ({low_count})  ")

        cols_low = ("name", "brand", "model", "compatible", "quantity", "low_stock", "sell")
        tree_low = ttk.Treeview(tab_low, columns=cols_low, show="headings", height=8)
        headers_low = [
            ("name", "Part Name", 190), ("brand", "Brand", 95), ("model", "Primary Model", 130),
            ("compatible", "Compatible / Use In Models", 200),
            ("quantity", "In Stock", 80), ("low_stock", "Alert At", 80),
            ("sell", "Sell Price", 95)
        ]
        for c, h, w in headers_low:
            tree_low.heading(c, text=h)
            tree_low.column(c, width=w, anchor="w")

        scroll_y_low = ttk.Scrollbar(tab_low, orient="vertical", command=tree_low.yview)
        tree_low.configure(yscrollcommand=scroll_y_low.set)
        tree_low.pack(side="left", fill="both", expand=True)
        scroll_y_low.pack(side="right", fill="y")

        for p in cur.execute("SELECT * FROM parts WHERE quantity <= low_stock ORDER BY quantity ASC LIMIT 30"):
            compat = p["compatible_models"] if ("compatible_models" in p.keys() and p["compatible_models"]) else "-"
            tree_low.insert("", "end", values=(
                p["name"], p["brand"], p["model"], compat, p["quantity"], p["low_stock"],
                f"₹{p['selling_price']:.2f}"
            ))

        notebook.select(tab_sold_history)

    def make_table(self, columns, headings, widths):
        wrap = tk.Frame(self.content, bg=BG)
        wrap.pack(fill="both", expand=True)
        tree = ttk.Treeview(wrap, columns=columns, show="headings")
        for c, h, w in zip(columns, headings, widths):
            tree.heading(c, text=h)
            tree.column(c, width=w, anchor="w")
        y = ttk.Scrollbar(wrap, orient="vertical", command=tree.yview)
        x = ttk.Scrollbar(wrap, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=y.set, xscrollcommand=x.set)
        tree.grid(row=0, column=0, sticky="nsew")
        y.grid(row=0, column=1, sticky="ns")
        x.grid(row=1, column=0, sticky="ew")
        wrap.rowconfigure(0, weight=1); wrap.columnconfigure(0, weight=1)
        return tree

    # =========================================================================
    # PARTS MANAGEMENT
    # =========================================================================
    def show_parts(self):
        self.clear_content()
        self.title("Parts Management", "View, search, edit and remove inventory items.")
        top = tk.Frame(self.content, bg=BG)
        top.pack(fill="x", pady=(0, 12))
        search_var = tk.StringVar()
        tk.Label(top, text="Search parts:", bg=BG, fg=TEXT, font=("Segoe UI", 10, "bold")).pack(side="left")
        ent = ttk.Entry(top, textvariable=search_var, width=32)
        ent.pack(side="left", padx=8)
        ttk.Button(top, text="Search", command=lambda: populate(search_var.get())).pack(side="left")
        ttk.Button(top, text="Show All", command=lambda: (search_var.set(""), populate(""))).pack(side="left", padx=6)
        ttk.Button(top, text="+ Add New Part", command=self.add_part_dialog).pack(side="right")

        cols = ("id", "name", "brand", "model", "compatible", "category", "quantity", "purchase", "selling", "supplier")
        headers = ("ID", "Part Name", "Brand", "Primary Model", "Compatible Models", "Category", "Qty", "Buy Price", "Sell Price", "Supplier")
        widths = (45, 160, 85, 115, 190, 105, 55, 85, 85, 120)

        tree = self.make_table(cols, headers, widths)

        def populate(q=""):
            for item in tree.get_children(): tree.delete(item)
            pattern = f"%{q.strip()}%"
            rows = self.conn.execute("""SELECT * FROM parts WHERE name LIKE ? OR brand LIKE ? OR model LIKE ? OR compatible_models LIKE ? OR category LIKE ? OR supplier LIKE ? ORDER BY name""",
                                     (pattern, pattern, pattern, pattern, pattern, pattern)).fetchall()
            for p in rows:
                compat = p["compatible_models"] if ("compatible_models" in p.keys() and p["compatible_models"]) else "-"
                buy_str = f'₹{p["purchase_price"]:.2f}' if self.is_admin() else "🔒"
                tree.insert("", "end", values=(p["id"], p["name"], p["brand"], p["model"], compat, p["category"], p["quantity"],
                                               buy_str, f'₹{p["selling_price"]:.2f}', p["supplier"]))

        def selected_id():
            sel = tree.selection()
            if not sel: messagebox.showwarning("Select item", "Please select a part first."); return None
            return tree.item(sel[0], "values")[0]

        def edit():
            pid = selected_id()
            if pid: self.add_part_dialog(int(pid))

        def delete():
            # RBAC: Only admin can delete parts
            if not self.is_admin():
                messagebox.showerror("Permission Denied", "Only administrators are permitted to delete parts from inventory.")
                return

            pid = selected_id()
            if not pid: return
            p_row = self.conn.execute("SELECT name FROM parts WHERE id = ?", (pid,)).fetchone()
            p_name = p_row["name"] if p_row else f"Part ID {pid}"

            if messagebox.askyesno("Confirm Permanent Deletion", f"Are you sure you want to delete '{p_name}'?\nThis action will be recorded in the audit log."):
                self.conn.execute("DELETE FROM parts WHERE id=?", (pid,))
                self.conn.commit()
                self.log_audit("DELETE_PART", "part", pid, f"Part '{p_name}' deleted from inventory.")
                populate(search_var.get())

        actions = tk.Frame(self.content, bg=BG)
        actions.pack(fill="x", pady=10)
        ttk.Button(actions, text="Edit Selected", command=edit).pack(side="left")
        if self.is_admin():
            ttk.Button(actions, text="🗑 Delete Selected (Admin)", command=delete).pack(side="left", padx=8)

        populate()
        ent.bind("<Return>", lambda e: populate(search_var.get()))

    def add_part_dialog(self, part_id=None):
        old = None
        if part_id:
            old = self.conn.execute("SELECT * FROM parts WHERE id=?", (part_id,)).fetchone()
            if not old: return

        win = tk.Toplevel(self.root)
        win.title("Edit Part" if old else "Add New Part")
        win.configure(bg=BG); win.resizable(False, False)
        win.transient(self.root); win.grab_set()

        tk.Label(win, text="Edit Part" if old else "Add New Part", bg=BG, fg=TEXT,
                 font=("Segoe UI", 16, "bold")).grid(row=0, column=0, columnspan=2, padx=20, pady=(16, 10), sticky="w")

        fields = [
            ("Part Name *", "name", ""),
            ("Brand", "brand", ""),
            ("Primary Mobile Model", "model", ""),
            ("Compatible / Use In Models", "compatible_models", "e.g. Note 7 / 7S / 8, Vivo Y11 / Y12 / Y15"),
            ("Category", "category", "Folder / PCB / Battery / IC"),
            ("Quantity", "quantity", "0"),
            ("Purchase Price (₹)", "purchase_price", "0"),
            ("Selling Price (₹)", "selling_price", "0"),
            ("Low Stock Alert At", "low_stock", "2"),
            ("Supplier", "supplier", "")
        ]
        vars_ = {}
        for r, (label, key, hint) in enumerate(fields, start=1):
            tk.Label(win, text=label, bg=BG, fg=TEXT, font=("Segoe UI", 10)).grid(row=r, column=0, padx=20, pady=4, sticky="w")
            val = str(old[key]) if old and key in old.keys() and old[key] is not None else (hint if not old else "")
            var = tk.StringVar(value=val)
            vars_[key] = var
            # RBAC: If not admin, disable modifying purchase price
            state = "normal"
            if key == "purchase_price" and not self.is_admin():
                state = "readonly"
            ttk.Entry(win, textvariable=var, width=38, state=state).grid(row=r, column=1, padx=20, pady=4)

        def save():
            try:
                name = vars_["name"].get().strip()
                if not name: raise ValueError("Part Name is required.")
                qty = int(vars_["quantity"].get())
                buy = float(vars_["purchase_price"].get() or 0)
                sell = float(vars_["selling_price"].get() or 0)
                low = int(vars_["low_stock"].get() or 0)
                if qty < 0 or buy < 0 or sell < 0 or low < 0:
                    raise ValueError("Quantity and prices cannot be negative.")

                vals = (name, vars_["brand"].get().strip(), vars_["model"].get().strip(),
                        vars_["compatible_models"].get().strip(), vars_["category"].get().strip(),
                        qty, buy, sell, low, vars_["supplier"].get().strip(),
                        datetime.now().strftime("%Y-%m-%d %H:%M:%S"))

                if old:
                    self.conn.execute("""UPDATE parts SET name=?,brand=?,model=?,compatible_models=?,category=?,quantity=?,purchase_price=?,
                        selling_price=?,low_stock=?,supplier=?,updated_at=? WHERE id=?""", vals + (part_id,))
                    self.log_audit("EDIT_PART", "part", part_id, f"Part '{name}' details updated.")
                else:
                    self.conn.execute("""INSERT INTO parts(name,brand,model,compatible_models,category,quantity,purchase_price,selling_price,low_stock,supplier,updated_at)
                        VALUES(?,?,?,?,?,?,?,?,?,?,?)""", vals)
                    new_id = self.conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                    if qty:
                        self.conn.execute("INSERT INTO stock_history(part_id,action,quantity,note,sale_price,purchase_price,created_at) VALUES(?,?,?,?,?,?,?)",
                                          (new_id, "IN", qty, "Opening stock", sell, buy, datetime.now().strftime("%Y-%m-%d %H:%M:%S")))
                    self.log_audit("ADD_PART", "part", new_id, f"New part '{name}' created with qty {qty}.")

                self.conn.commit()
                win.destroy()
                if hasattr(self, "show_parts"): self.show_parts()
                self.show_dashboard()
            except ValueError as e:
                messagebox.showerror("Input Validation Error", str(e), parent=win)
            except Exception:
                messagebox.showerror("Error", "Could not save part details. Please verify your inputs.", parent=win)

        btnrow = tk.Frame(win, bg=BG); btnrow.grid(row=len(fields)+1, column=0, columnspan=2, pady=16)
        ttk.Button(btnrow, text="Save Part", command=save).pack(side="left", padx=6)
        ttk.Button(btnrow, text="Cancel", command=win.destroy).pack(side="left", padx=6)

    # =========================================================================
    # STOCK IN / OUT
    # =========================================================================
    def stock_dialog(self):
        parts = self.conn.execute("SELECT * FROM parts ORDER BY name").fetchall()
        if not parts:
            messagebox.showinfo("No parts yet", "Please add a part first.")
            self.add_part_dialog()
            return
        parts_dict = {p["id"]: p for p in parts}
        win = tk.Toplevel(self.root)
        win.title("Stock In / Out")
        win.configure(bg=BG)
        win.resizable(False, False)
        win.transient(self.root)
        win.grab_set()

        hdr_frame = tk.Frame(win, bg=BG)
        hdr_frame.grid(row=0, column=0, columnspan=2, padx=20, pady=(16, 8), sticky="w")
        tk.Label(hdr_frame, text="Stock In / Out", bg=BG, fg=TEXT, font=("Segoe UI", 16, "bold")).pack(anchor="w")
        tk.Label(hdr_frame, text="Record inventory movement, customer sales, or restock", bg=BG, fg=MUTED, font=("Segoe UI", 9)).pack(anchor="w")

        def make_part_choice_str(p):
            compat_str = f' [Works on: {p["compatible_models"]}]' if ("compatible_models" in p.keys() and p["compatible_models"]) else ''
            return f'{p["id"]} | {p["name"]} | {p["brand"]} {p["model"]}{compat_str} (Stock: {p["quantity"]})'

        all_choices = [make_part_choice_str(p) for p in parts]

        part_var = tk.StringVar(value=all_choices[0])
        action_var = tk.StringVar(value="Stock Out")
        qty_var = tk.StringVar(value="1")
        price_var = tk.StringVar()
        note_var = tk.StringVar(value="Customer Sale")

        def get_selected_part():
            val = part_var.get().strip()
            if not val or val == "-- No matching parts --":
                return None
            if "|" in val:
                try:
                    pid = int(val.split("|")[0].strip())
                    if pid in parts_dict:
                        return parts_dict[pid]
                except Exception:
                    pass
            # If user typed search text directly into combobox without selecting dropdown
            q = val.lower()
            tokens = q.split()
            for p in parts:
                haystack = f"{p['name']} {p['brand']} {p['model']}".lower()
                if q in haystack:
                    part_var.set(make_part_choice_str(p))
                    return p
            if tokens:
                for p in parts:
                    compat = (p["compatible_models"] or "") if "compatible_models" in p.keys() else ""
                    haystack = f"{p['id']} {p['name']} {p['brand']} {p['model']} {compat} {p['category']}".lower()
                    if all(t in haystack for t in tokens):
                        part_var.set(make_part_choice_str(p))
                        return p
            return None

        def on_change(*args):
            p = get_selected_part()
            if not p:
                return
            if action_var.get() == "Stock Out":
                price_lbl.config(text="Selling Price / Unit (₹):")
                price_var.set(str(p["selling_price"]))
                if note_var.get() in ("", "Purchased Stock", "Supplier Restock"):
                    note_var.set("Customer Sale")
            else:
                price_lbl.config(text="Purchase Price / Unit (₹):")
                price_var.set(str(p["purchase_price"]) if self.is_admin() else "0")
                if note_var.get() in ("", "Customer Sale", "Repair Usage"):
                    note_var.set("Purchased Stock")

        # --- ROW 1: Part Dropdown with Direct In-Place Search ---
        tk.Label(win, text="Select Part:", bg=BG, fg=TEXT, font=("Segoe UI", 10, "bold")).grid(row=1, column=0, padx=20, pady=6, sticky="w")
        
        part_frame = tk.Frame(win, bg=BG)
        part_frame.grid(row=1, column=1, padx=20, pady=6, sticky="w")

        part_cb = ttk.Combobox(part_frame, textvariable=part_var, values=all_choices, width=54)
        part_cb.pack(fill="x")

        hint_lbl = tk.Label(part_frame, text="🔍 Type part name, brand, or model directly to search", bg=BG, fg=MUTED, font=("Segoe UI", 8))
        hint_lbl.pack(anchor="w", pady=(2, 0))

        def on_part_key_release(event):
            # Ignore standard navigation keys so arrow/tab navigation works normally
            if event.keysym in ("Up", "Down", "Left", "Right", "Return", "Tab", "Escape", "Shift_L", "Shift_R", "Control_L", "Control_R"):
                return
            q = part_cb.get().strip().lower()
            if not q:
                part_cb["values"] = all_choices
                hint_lbl.config(text="🔍 Type part name, brand, or model directly to search", fg=MUTED)
                return

            tokens = q.split()
            filtered = []
            for p in parts:
                compat = (p["compatible_models"] or "") if "compatible_models" in p.keys() else ""
                haystack = f"{p['id']} {p['name']} {p['brand']} {p['model']} {compat} {p['category']} {p['supplier']}".lower()
                if all(t in haystack for t in tokens):
                    filtered.append(make_part_choice_str(p))

            if filtered:
                part_cb["values"] = filtered
                hint_lbl.config(text=f"✔ {len(filtered)} matching part(s) found (press Down ↓ to browse)", fg=SUCCESS)
            else:
                part_cb["values"] = ["-- No matching parts --"]
                hint_lbl.config(text="⚠ No matching parts found", fg=DANGER)

        def on_part_return(event):
            p = get_selected_part()
            on_change()
            qty_entry.focus_set()
            qty_entry.selection_range(0, tk.END)

        def on_part_focus_in(event):
            part_cb.selection_range(0, tk.END)

        def on_part_selected(event):
            hint_lbl.config(text="🔍 Type part name, brand, or model directly to search", fg=MUTED)
            on_change()

        part_cb.bind("<KeyRelease>", on_part_key_release)
        part_cb.bind("<<ComboboxSelected>>", on_part_selected)
        part_cb.bind("<Return>", on_part_return)
        part_cb.bind("<FocusIn>", on_part_focus_in)
        part_cb.bind("<FocusOut>", lambda e: on_change())

        # Focus part combobox directly when dialog opens
        part_cb.focus_set()
        part_cb.selection_range(0, tk.END)

        # --- ROW 2: Action ---
        tk.Label(win, text="Action:", bg=BG, fg=TEXT).grid(row=2, column=0, padx=20, pady=6, sticky="w")
        act_cb = ttk.Combobox(win, textvariable=action_var, values=["Stock Out", "Stock In"], width=52, state="readonly")
        act_cb.grid(row=2, column=1, padx=20, pady=6, sticky="w")
        act_cb.bind("<<ComboboxSelected>>", on_change)

        # --- ROW 3: Quantity ---
        tk.Label(win, text="Quantity:", bg=BG, fg=TEXT).grid(row=3, column=0, padx=20, pady=6, sticky="w")
        qty_entry = ttk.Entry(win, textvariable=qty_var, width=54)
        qty_entry.grid(row=3, column=1, padx=20, pady=6, sticky="w")

        # --- ROW 4: Price ---
        price_lbl = tk.Label(win, text="Selling Price / Unit (₹):", bg=BG, fg=TEXT)
        price_lbl.grid(row=4, column=0, padx=20, pady=6, sticky="w")
        price_entry = ttk.Entry(win, textvariable=price_var, width=54)
        price_entry.grid(row=4, column=1, padx=20, pady=6, sticky="w")

        # --- ROW 5: Note / Reason ---
        tk.Label(win, text="Note / Reason:", bg=BG, fg=TEXT).grid(row=5, column=0, padx=20, pady=6, sticky="w")
        note_entry = ttk.Entry(win, textvariable=note_var, width=54)
        note_entry.grid(row=5, column=1, padx=20, pady=6, sticky="w")

        on_change()

        def save():
            try:
                p = get_selected_part()
                if not p:
                    raise ValueError("Please select a valid part from the list.")
                pid = p["id"]
                qty = int(qty_var.get())
                if qty <= 0:
                    raise ValueError("Quantity must be greater than zero.")
                unit_price = float(price_var.get() or 0)
                if unit_price < 0:
                    raise ValueError("Price cannot be negative.")

                if action_var.get() == "Stock Out":
                    if qty > p["quantity"]:
                        raise ValueError(f"Only {p['quantity']} unit(s) available in stock.")
                    new_qty = p["quantity"] - qty
                    act = "OUT"
                    sale_price = unit_price
                    purchase_price = p["purchase_price"]
                else:
                    new_qty = p["quantity"] + qty
                    act = "IN"
                    sale_price = p["selling_price"]
                    purchase_price = unit_price if self.is_admin() else p["purchase_price"]

                now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
                self.conn.execute("UPDATE parts SET quantity=?,updated_at=? WHERE id=?", (new_qty, now, pid))
                self.conn.execute("""INSERT INTO stock_history(part_id,action,quantity,note,sale_price,purchase_price,created_at) 
                                     VALUES(?,?,?,?,?,?,?)""",
                                  (pid, act, qty, note_var.get().strip(), sale_price, purchase_price, now))
                self.conn.commit()
                self.log_audit("STOCK_MOVEMENT", "part", pid, f"Action: {act}, Qty: {qty}, Part: {p['name']}, New Stock: {new_qty}")
                win.destroy()
                self.show_dashboard()
            except ValueError as e:
                messagebox.showerror("Validation Error", str(e), parent=win)
            except Exception:
                messagebox.showerror("Error", "Could not record stock movement.", parent=win)

        row = tk.Frame(win, bg=BG)
        row.grid(row=6, column=0, columnspan=2, pady=18)
        ttk.Button(row, text="Save Movement", command=save).pack(side="left", padx=6)
        ttk.Button(row, text="Cancel", command=win.destroy).pack(side="left", padx=6)

    def show_low_stock(self):
        self.clear_content(); self.title("Low Stock", "Items whose quantity is at or below their alert threshold.")
        cols = ("name", "brand", "model", "compatible", "category", "quantity", "low_stock", "sell", "supplier")
        headers = ("Part Name", "Brand", "Primary Model", "Compatible / Use In Models", "Category", "Qty", "Alert At", "Sell Price", "Supplier")
        widths = (170, 85, 115, 180, 105, 55, 70, 85, 120)

        tree = self.make_table(cols, headers, widths)
        rows = self.conn.execute("SELECT * FROM parts WHERE quantity <= low_stock ORDER BY quantity ASC").fetchall()
        for p in rows:
            compat = p["compatible_models"] if ("compatible_models" in p.keys() and p["compatible_models"]) else "-"
            tree.insert("", "end", values=(p["name"], p["brand"], p["model"], compat, p["category"], p["quantity"], p["low_stock"],
                                           f"₹{p['selling_price']:.2f}", p["supplier"]))
        if not rows:
            tk.Label(self.content, text="Great! No low-stock items right now.", bg=BG, fg=MUTED, font=("Segoe UI", 11)).pack(anchor="w", pady=12)

    # =========================================================================
    # PHONES MANAGEMENT
    # =========================================================================
    def show_phones(self):
        self.clear_content(); self.title("Pending & Completed Phones", "Track customer phones from receiving to repair and delivery.")
        top = tk.Frame(self.content, bg=BG); top.pack(fill="x", pady=(0, 10))
        ttk.Button(top, text="+ Add Phone Job", command=self.phone_dialog).pack(side="left")
        ttk.Button(top, text="Update Selected", command=lambda: edit_selected()).pack(side="left", padx=8)
        ttk.Button(top, text="✓ Mark Delivered", command=lambda: mark_delivered()).pack(side="left")
        filter_var = tk.StringVar(value="Not Delivered")
        tk.Label(top, text="Show:", bg=BG, fg=TEXT).pack(side="left", padx=(18, 5))
        combo = ttk.Combobox(top, textvariable=filter_var, values=["Not Delivered","All","Pending","In Repair","Waiting for Parts","On Hold","Completed","Delivered"], state="readonly", width=18)
        combo.pack(side="left")

        tree = self.make_table(("id","customer","phone","model","problem","work","received","status","charge","profit","reason"),
                               ("Job ID","Customer","Contact","Phone Model","Problem","Work Required","Received","Status","Charge (₹)","Profit (₹)","Pending Reason"),
                               (55,120,100,120,130,130,90,95,80,75,130))
        def populate(*args):
            for item in tree.get_children(): tree.delete(item)
            f = filter_var.get()
            if f == "All": rows = self.conn.execute("SELECT * FROM phones ORDER BY id DESC").fetchall()
            elif f == "Not Delivered": rows = self.conn.execute("SELECT * FROM phones WHERE status!='Delivered' ORDER BY id DESC").fetchall()
            else: rows = self.conn.execute("SELECT * FROM phones WHERE status=? ORDER BY id DESC", (f,)).fetchall()
            for p in rows:
                cost = p["repair_cost"] or 0
                charge = p["estimated_charge"] or 0
                prof = charge - cost
                tree.insert("", "end", values=(
                    p["id"], p["customer_name"], p["customer_phone"], p["phone_model"], p["problem"], p["work_required"],
                    p["received_date"], p["status"], f'₹{charge:.2f}',
                    f'₹{prof:.2f}' if self.is_admin() else "🔒",
                    p["pending_reason"]
                ))
        def get_id():
            sel = tree.selection()
            if not sel: messagebox.showwarning("Select phone", "Please select a phone job first."); return None
            return int(tree.item(sel[0], "values")[0])
        def edit_selected():
            jid = get_id()
            if jid: self.phone_dialog(jid)
        def mark_delivered():
            jid = get_id()
            if not jid: return
            phone = self.conn.execute("SELECT * FROM phones WHERE id=?", (jid,)).fetchone()
            if not phone: return
            if messagebox.askyesno("Confirm Delivery", f"Mark {phone['phone_model']} for {phone['customer_name']} as Delivered?\nTotal Charge: ₹{phone['estimated_charge']:.2f}"):
                now = datetime.now().strftime("%Y-%m-%d")
                self.conn.execute("UPDATE phones SET status='Delivered',delivered_date=? WHERE id=?", (now, jid))
                self.conn.commit()
                self.log_audit("DELIVER_PHONE", "phone", jid, f"Phone job #{jid} for {phone['customer_name']} marked Delivered (Charge: ₹{phone['estimated_charge']}).")
                messagebox.showinfo("Delivered", f"Phone marked as Delivered! Sale and Profit updated.")
                populate()
                self.show_dashboard()
        combo.bind("<<ComboboxSelected>>", populate)
        populate()

    def phone_dialog(self, job_id=None):
        old = self.conn.execute("SELECT * FROM phones WHERE id=?", (job_id,)).fetchone() if job_id else None
        win = tk.Toplevel(self.root); win.title("Edit Phone Job" if old else "Add Phone Job"); win.configure(bg=BG)
        win.resizable(False, False); win.transient(self.root); win.grab_set()
        tk.Label(win, text="Edit Phone Job" if old else "New Phone Job", bg=BG, fg=TEXT,
                 font=("Segoe UI", 16, "bold")).grid(row=0, column=0, columnspan=2, padx=20, pady=15, sticky="w")
        fields = [
            ("Customer Name *","customer_name",""),
            ("Customer Phone","customer_phone",""),
            ("Phone Model *","phone_model",""),
            ("Problem","problem",""),
            ("Work Required","work_required",""),
            ("Pending Reason","pending_reason",""),
            ("Estimated Charge (₹)","estimated_charge","0"),
            ("Repair Cost / Expense (₹)","repair_cost","0"),
            ("Status","status","Pending"),
            ("Received Date (YYYY-MM-DD)","received_date",datetime.now().strftime("%Y-%m-%d")),
            ("Notes","notes","")
        ]
        vars_ = {}
        for r,(label,key,default) in enumerate(fields,start=1):
            tk.Label(win,text=label,bg=BG,fg=TEXT,font=("Segoe UI", 10)).grid(row=r,column=0,padx=20,pady=4,sticky="w")
            val = str(old[key]) if old and old[key] is not None else default
            var = tk.StringVar(value=val); vars_[key] = var
            if key == "status":
                widget = ttk.Combobox(win,textvariable=var,values=["Pending","Checking","Waiting for Parts","In Repair","On Hold","Completed","Delivered"],state="readonly",width=33)
            else:
                state = "readonly" if key == "repair_cost" and not self.is_admin() else "normal"
                widget = ttk.Entry(win,textvariable=var,width=35,state=state)
            widget.grid(row=r,column=1,padx=20,pady=4)
        def save():
            try:
                customer = vars_["customer_name"].get().strip()
                model = vars_["phone_model"].get().strip()
                if not customer or not model: raise ValueError("Customer Name and Phone Model are required.")
                charge = float(vars_["estimated_charge"].get() or 0)
                cost = float(vars_["repair_cost"].get() or 0) if self.is_admin() else (old["repair_cost"] if old else 0)
                if charge < 0 or cost < 0: raise ValueError("Charge and Cost cannot be negative.")
                received = vars_["received_date"].get().strip()
                datetime.strptime(received, "%Y-%m-%d")
                status = vars_["status"].get()
                delivered_date = datetime.now().strftime("%Y-%m-%d") if status == "Delivered" else (old["delivered_date"] if old else "")
                vals = (customer, vars_["customer_phone"].get().strip(), model, vars_["problem"].get().strip(),
                        vars_["work_required"].get().strip(), vars_["pending_reason"].get().strip(), charge, cost,
                        status, received, vars_["notes"].get().strip(), delivered_date)
                if old:
                    self.conn.execute("""UPDATE phones SET customer_name=?,customer_phone=?,phone_model=?,problem=?,work_required=?,
                        pending_reason=?,estimated_charge=?,repair_cost=?,status=?,received_date=?,notes=?,delivered_date=? WHERE id=?""", vals+(job_id,))
                    self.log_audit("EDIT_PHONE", "phone", job_id, f"Updated job #{job_id} for {customer}.")
                else:
                    self.conn.execute("""INSERT INTO phones(customer_name,customer_phone,phone_model,problem,work_required,pending_reason,
                        estimated_charge,repair_cost,status,received_date,notes,delivered_date) VALUES(?,?,?,?,?,?,?,?,?,?,?,?)""", vals)
                    new_id = self.conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                    self.log_audit("ADD_PHONE", "phone", new_id, f"Created new job #{new_id} for {customer} ({model}).")
                self.conn.commit(); win.destroy()
                if hasattr(self, "show_phones"): self.show_phones()
                self.show_dashboard()
            except ValueError as e:
                messagebox.showerror("Validation Error", str(e), parent=win)
            except Exception:
                messagebox.showerror("Error", "Could not save phone job details.", parent=win)
        btn = tk.Frame(win,bg=BG); btn.grid(row=len(fields)+1,column=0,columnspan=2,pady=15)
        ttk.Button(btn,text="Save Job",command=save).pack(side="left",padx=6)
        ttk.Button(btn,text="Cancel",command=win.destroy).pack(side="left",padx=6)

    # =========================================================================
    # SOLD ITEMS HISTORY
    # =========================================================================
    def get_sold_records(self):
        cur = self.conn.cursor()
        records = []

        parts_rows = cur.execute("""
            SELECT h.*, p.name, p.brand, p.model, p.compatible_models,
                   p.selling_price as p_sell, p.purchase_price as p_buy
            FROM stock_history h
            LEFT JOIN parts p ON p.id = h.part_id
            WHERE h.action = 'OUT'
            ORDER BY h.id DESC
        """).fetchall()

        for h in parts_rows:
            dt_str = h["created_at"] or ""
            date_str = dt_str[:10] if len(dt_str) >= 10 else dt_str
            month_str = dt_str[:7] if len(dt_str) >= 7 else ""
            year_str = dt_str[:4] if len(dt_str) >= 4 else ""

            try:
                dt_obj = datetime.strptime(date_str, "%Y-%m-%d")
                day_fmt = dt_obj.strftime("%d %b %Y")
                month_fmt = dt_obj.strftime("%B %Y")
            except Exception:
                day_fmt = date_str
                month_fmt = month_str

            sell_p = h["sale_price"] if h["sale_price"] > 0 else (h["p_sell"] or 0)
            buy_p = h["purchase_price"] if h["purchase_price"] > 0 else (h["p_buy"] or 0)
            qty = h["quantity"]
            sale_tot = sell_p * qty
            cost_tot = buy_p * qty
            profit = sale_tot - cost_tot

            model_txt = h["model"] or ""
            if h["compatible_models"]:
                model_txt += f" [{h['compatible_models']}]" if model_txt else h["compatible_models"]

            records.append({
                "type": "Part Sale",
                "datetime": dt_str,
                "date": date_str,
                "day_fmt": day_fmt,
                "month": month_str,
                "month_fmt": month_fmt,
                "year": year_str,
                "item_name": h["name"] or "(Deleted Part)",
                "brand": h["brand"] or "",
                "models": model_txt or "-",
                "quantity": qty,
                "unit_price": sell_p,
                "sale": sale_tot,
                "cost": cost_tot,
                "profit": profit,
                "note": h["note"] or "Direct Sale"
            })

        phone_rows = cur.execute("""
            SELECT * FROM phones
            WHERE status = 'Delivered'
            ORDER BY id DESC
        """).fetchall()

        for p in phone_rows:
            dt_str = p["delivered_date"] or p["received_date"] or ""
            date_str = dt_str[:10] if len(dt_str) >= 10 else dt_str
            month_str = dt_str[:7] if len(dt_str) >= 7 else ""
            year_str = dt_str[:4] if len(dt_str) >= 4 else ""

            try:
                dt_obj = datetime.strptime(date_str, "%Y-%m-%d")
                day_fmt = dt_obj.strftime("%d %b %Y")
                month_fmt = dt_obj.strftime("%B %Y")
            except Exception:
                day_fmt = date_str
                month_fmt = month_str

            charge = p["estimated_charge"] or 0
            cost = p["repair_cost"] or 0
            profit = charge - cost
            cust_txt = f"{p['customer_name']} ({p['customer_phone']})" if p["customer_phone"] else p["customer_name"]

            records.append({
                "type": "Phone Repair",
                "datetime": dt_str + " 12:00:00",
                "date": date_str,
                "day_fmt": day_fmt,
                "month": month_str,
                "month_fmt": month_fmt,
                "year": year_str,
                "item_name": f"Repair: {p['phone_model']}",
                "brand": "",
                "models": p["phone_model"],
                "quantity": 1,
                "unit_price": charge,
                "sale": charge,
                "cost": cost,
                "profit": profit,
                "note": f"{cust_txt} • {p['problem'] or p['work_required'] or 'Service'}"
            })

        records.sort(key=lambda x: x["datetime"], reverse=True)
        return records

    def build_sales_history_view(self, parent, is_compact=False, on_stats_updated=None):
        all_records = self.get_sold_records()

        days_map = {}
        months_map = {}
        years_set = set()

        for r in all_records:
            if r["date"]:
                days_map[r["date"]] = f"{r['date']} ({r['day_fmt']})"
            if r["month"]:
                months_map[r["month"]] = f"{r['month']} ({r['month_fmt']})"
            if r["year"]:
                years_set.add(r["year"])

        now_dt = datetime.now()
        cur_day = now_dt.strftime("%Y-%m-%d")
        cur_month = now_dt.strftime("%Y-%m")
        cur_year = now_dt.strftime("%Y")
        if cur_day not in days_map:
            days_map[cur_day] = f"{cur_day} ({now_dt.strftime('%d %b %Y')})"
        if cur_month not in months_map:
            months_map[cur_month] = f"{cur_month} ({now_dt.strftime('%B %Y')})"
        years_set.add(cur_year)

        sorted_days = sorted(days_map.keys(), reverse=True)
        sorted_months = sorted(months_map.keys(), reverse=True)
        sorted_years = sorted(list(years_set), reverse=True)

        container = tk.Frame(parent, bg=CARD if is_compact else BG)
        container.pack(fill="both", expand=True, padx=6 if is_compact else 0, pady=6 if is_compact else 0)

        filter_bar = tk.Frame(container, bg=CARD if is_compact else BG)
        filter_bar.pack(fill="x", pady=(4, 8))

        period_var = tk.StringVar(value="By Day / Date")
        val_var = tk.StringVar()
        type_var = tk.StringVar(value="All Sales")
        search_var = tk.StringVar()

        tk.Label(filter_bar, text="Filter Period:", bg=CARD if is_compact else BG, fg=TEXT, font=("Segoe UI", 9, "bold")).pack(side="left", padx=(4, 4))
        period_cb = ttk.Combobox(filter_bar, textvariable=period_var, values=["By Day / Date", "By Month", "By Year", "All Time"], state="readonly", width=14)
        period_cb.pack(side="left", padx=(0, 6))

        val_cb = ttk.Combobox(filter_bar, textvariable=val_var, state="readonly", width=24)
        val_cb.pack(side="left", padx=(0, 8))

        tk.Label(filter_bar, text="Type:", bg=CARD if is_compact else BG, fg=TEXT, font=("Segoe UI", 9, "bold")).pack(side="left", padx=(4, 4))
        type_cb = ttk.Combobox(filter_bar, textvariable=type_var, values=["All Sales", "Parts Sold Only", "Phone Repairs Only"], state="readonly", width=16)
        type_cb.pack(side="left", padx=(0, 8))

        tk.Label(filter_bar, text="Search:", bg=CARD if is_compact else BG, fg=TEXT, font=("Segoe UI", 9, "bold")).pack(side="left", padx=(4, 4))
        search_ent = ttk.Entry(filter_bar, textvariable=search_var, width=18)
        search_ent.pack(side="left", padx=(0, 6))

        summary_frame = tk.Frame(container, bg="#f8fafc", highlightbackground="#e2e8f0", highlightthickness=1)
        summary_frame.pack(fill="x", pady=(0, 8), padx=2)

        lbl_qty = tk.Label(summary_frame, text="0 units", font=("Segoe UI", 11, "bold"), fg=TEXT, bg="#f8fafc")
        lbl_sales = tk.Label(summary_frame, text="₹0.00", font=("Segoe UI", 11, "bold"), fg="#2563eb", bg="#f8fafc")
        lbl_costs = tk.Label(summary_frame, text="₹0.00", font=("Segoe UI", 11, "bold"), fg="#64748b", bg="#f8fafc")
        lbl_profits = tk.Label(summary_frame, text="₹0.00", font=("Segoe UI", 11, "bold"), fg="#16a34a", bg="#f8fafc")

        cost_title = "📉 Total Cost:" if self.is_admin() else ""
        profit_title = "📈 Net Profit:" if self.is_admin() else ""

        tk.Label(summary_frame, text="📦 Items Sold:", font=("Segoe UI", 9, "bold"), fg=MUTED, bg="#f8fafc").pack(side="left", padx=(10, 4), pady=6)
        lbl_qty.pack(side="left", padx=(0, 16), pady=6)
        tk.Label(summary_frame, text="💰 Total Sales:", font=("Segoe UI", 9, "bold"), fg=MUTED, bg="#f8fafc").pack(side="left", padx=(4, 4), pady=6)
        lbl_sales.pack(side="left", padx=(0, 16), pady=6)
        if self.is_admin():
            tk.Label(summary_frame, text=cost_title, font=("Segoe UI", 9, "bold"), fg=MUTED, bg="#f8fafc").pack(side="left", padx=(4, 4), pady=6)
            lbl_costs.pack(side="left", padx=(0, 16), pady=6)
            tk.Label(summary_frame, text=profit_title, font=("Segoe UI", 9, "bold"), fg=MUTED, bg="#f8fafc").pack(side="left", padx=(4, 4), pady=6)
            lbl_profits.pack(side="left", padx=(0, 16), pady=6)

        cols = ("datetime", "day", "month", "year", "type", "item", "models", "qty", "unit_price", "sale", "profit", "note")
        headers = [
            ("datetime", "Date / Time", 115),
            ("day", "Day / Date", 95),
            ("month", "Month", 90),
            ("year", "Year", 55),
            ("type", "Type", 95),
            ("item", "Item / Part Name", 175),
            ("models", "Compatible / Models", 170),
            ("qty", "Qty", 50),
            ("unit_price", "Price (₹)", 85),
            ("sale", "Total Sale (₹)", 95),
            ("profit", "Profit (₹)", 90),
            ("note", "Customer / Reason", 170),
        ]

        table_wrap = tk.Frame(container, bg=CARD if is_compact else BG)
        table_wrap.pack(fill="both", expand=True)

        tree = ttk.Treeview(table_wrap, columns=cols, show="headings", height=8 if is_compact else 16)
        for c, h, w in headers:
            tree.heading(c, text=h)
            tree.column(c, width=w, anchor="w")

        sc_y = ttk.Scrollbar(table_wrap, orient="vertical", command=tree.yview)
        sc_x = ttk.Scrollbar(table_wrap, orient="horizontal", command=tree.xview)
        tree.configure(yscrollcommand=sc_y.set, xscrollcommand=sc_x.set)

        tree.grid(row=0, column=0, sticky="nsew")
        sc_y.grid(row=0, column=1, sticky="ns")
        sc_x.grid(row=1, column=0, sticky="ew")
        table_wrap.rowconfigure(0, weight=1)
        table_wrap.columnconfigure(0, weight=1)

        def on_period_change(*args):
            p = period_var.get()
            if p == "By Year":
                val_cb.config(values=sorted_years, state="readonly")
                val_var.set(sorted_years[0] if sorted_years else cur_year)
            elif p == "By Month":
                month_vals = [months_map[m] for m in sorted_months]
                val_cb.config(values=month_vals, state="readonly")
                val_var.set(months_map.get(cur_month, month_vals[0] if month_vals else cur_month))
            elif p == "By Day / Date":
                day_vals = [days_map[d] for d in sorted_days]
                val_cb.config(values=day_vals, state="readonly")
                val_var.set(days_map.get(cur_day, day_vals[0] if day_vals else cur_day))
            else:
                val_cb.config(values=["All Time History"], state="readonly")
                val_var.set("All Time History")
            populate()

        def populate(*args):
            for item in tree.get_children():
                tree.delete(item)

            p = period_var.get()
            raw_v = val_var.get()
            selected_v = raw_v.split(" ")[0].strip() if " " in raw_v else raw_v.strip()
            stype = type_var.get()
            q = search_var.get().strip().lower()

            filtered = []
            for r in all_records:
                if stype == "Parts Sold Only" and r["type"] != "Part Sale":
                    continue
                if stype == "Phone Repairs Only" and r["type"] != "Phone Repair":
                    continue

                if p == "By Year":
                    if r["year"] != selected_v:
                        continue
                elif p == "By Month":
                    if r["month"] != selected_v:
                        continue
                elif p == "By Day / Date":
                    if r["date"] != selected_v:
                        continue

                if q:
                    haystack = f"{r['item_name']} {r['brand']} {r['models']} {r['note']} {r['day_fmt']} {r['month_fmt']} {r['year']}".lower()
                    if q not in haystack:
                        continue

                filtered.append(r)

            tot_qty = sum(r["quantity"] for r in filtered)
            tot_sale = sum(r["sale"] for r in filtered)
            tot_cost = sum(r["cost"] for r in filtered)
            tot_prof = sum(r["profit"] for r in filtered)
            tot_parts = sum(r["quantity"] for r in filtered if r["type"] == "Part Sale")
            tot_repairs = sum(1 for r in filtered if r["type"] == "Phone Repair")
            part_sale = sum(r["sale"] for r in filtered if r["type"] == "Part Sale")
            rep_sale = sum(r["sale"] for r in filtered if r["type"] == "Phone Repair")

            lbl_qty.config(text=f"{tot_qty} units")
            lbl_sales.config(text=f"₹{tot_sale:,.2f}")
            lbl_costs.config(text=f"₹{tot_cost:,.2f}" if self.is_admin() else "🔒")
            lbl_profits.config(text=f"₹{tot_prof:,.2f}" if self.is_admin() else "🔒")

            if on_stats_updated:
                on_stats_updated({
                    "period_type": p,
                    "selected_val": selected_v,
                    "display_period": raw_v,
                    "tot_qty": tot_qty,
                    "tot_sale": tot_sale,
                    "tot_cost": tot_cost,
                    "tot_profit": tot_prof,
                    "tot_parts": tot_parts,
                    "tot_repairs": tot_repairs,
                    "parts_sale": part_sale,
                    "repairs_sale": rep_sale,
                    "count": len(filtered)
                })

            for r in filtered:
                dt_show = r["datetime"][:16] if len(r["datetime"]) >= 16 else r["datetime"]
                prof_str = f"₹{r['profit']:.2f}" if self.is_admin() else "🔒"
                tree.insert("", "end", values=(
                    dt_show,
                    r["day_fmt"],
                    r["month_fmt"],
                    r["year"],
                    r["type"],
                    r["item_name"],
                    r["models"],
                    r["quantity"],
                    f"₹{r['unit_price']:.2f}",
                    f"₹{r['sale']:.2f}",
                    prof_str,
                    r["note"]
                ))

        period_cb.bind("<<ComboboxSelected>>", on_period_change)
        val_cb.bind("<<ComboboxSelected>>", populate)
        type_cb.bind("<<ComboboxSelected>>", populate)
        search_ent.bind("<KeyRelease>", populate)

        ttk.Button(filter_bar, text="Search", command=populate).pack(side="left", padx=4)
        def reset_filter():
            period_var.set("By Day / Date")
            type_var.set("All Sales")
            search_var.set("")
            on_period_change()
        ttk.Button(filter_bar, text="Show All / Reset", command=reset_filter).pack(side="left", padx=4)

        on_period_change()

    def show_sales_history(self):
        self.show_dashboard()

    def show_reports(self):
        self.clear_content(); self.title("Stock & Financial Reports", "Inventory valuation, revenue & stock movement history.")
        cur = self.conn.cursor()
        total_value = cur.execute("SELECT COALESCE(SUM(quantity*purchase_price),0) n FROM parts").fetchone()["n"]
        total_sell = cur.execute("SELECT COALESCE(SUM(quantity*selling_price),0) n FROM parts").fetchone()["n"]

        today_str = datetime.now().strftime("%Y-%m-%d")
        month_str = datetime.now().strftime("%Y-%m")

        rep_today = cur.execute("SELECT COALESCE(SUM(estimated_charge),0) s, COALESCE(SUM(estimated_charge - COALESCE(repair_cost,0)),0) p FROM phones WHERE status='Delivered' AND (delivered_date=? OR (delivered_date='' AND received_date=?))", (today_str, today_str)).fetchone()
        part_today = cur.execute("SELECT COALESCE(SUM(h.quantity * CASE WHEN h.sale_price>0 THEN h.sale_price ELSE p.selling_price END),0) s, COALESCE(SUM(h.quantity * ((CASE WHEN h.sale_price>0 THEN h.sale_price ELSE p.selling_price END) - (CASE WHEN h.purchase_price>0 THEN h.purchase_price ELSE p.purchase_price END))),0) p FROM stock_history h LEFT JOIN parts p ON p.id=h.part_id WHERE h.action='OUT' AND substr(h.created_at,1,10)=?", (today_str,)).fetchone()
        today_s = rep_today["s"] + part_today["s"]
        today_p = rep_today["p"] + part_today["p"]

        rep_month = cur.execute("SELECT COALESCE(SUM(estimated_charge),0) s, COALESCE(SUM(estimated_charge - COALESCE(repair_cost,0)),0) p FROM phones WHERE status='Delivered' AND (substr(delivered_date,1,7)=? OR (delivered_date='' AND substr(received_date,1,7)=?))", (month_str, month_str)).fetchone()
        part_month = cur.execute("SELECT COALESCE(SUM(h.quantity * CASE WHEN h.sale_price>0 THEN h.sale_price ELSE p.selling_price END),0) s, COALESCE(SUM(h.quantity * ((CASE WHEN h.sale_price>0 THEN h.sale_price ELSE p.selling_price END) - (CASE WHEN h.purchase_price>0 THEN h.purchase_price ELSE p.purchase_price END))),0) p FROM stock_history h LEFT JOIN parts p ON p.id=h.part_id WHERE h.action='OUT' AND substr(h.created_at,1,7)=?", (month_str,)).fetchone()
        month_s = rep_month["s"] + part_month["s"]
        month_p = rep_month["p"] + part_month["p"]

        summary = tk.Frame(self.content,bg=BG); summary.pack(fill="x",pady=(0,12))
        val_buy_str = f"₹{total_value:,.2f}" if self.is_admin() else "🔒 Admin Only"
        prof_today_str = f"₹{today_p:,.2f}" if self.is_admin() else "🔒 Admin Only"
        prof_month_str = f"₹{month_p:,.2f}" if self.is_admin() else "🔒 Admin Only"

        self.stat_card(summary,"Purchase Stock Value",val_buy_str,"Current stock at purchase prices",accent="#475569").pack(side="left",fill="x",expand=True,padx=(0,6))
        self.stat_card(summary,"Potential Selling Value",f"₹{total_sell:,.2f}","Current stock at selling prices",accent="#2563eb").pack(side="left",fill="x",expand=True,padx=6)
        self.stat_card(summary,"Today's Net Profit",prof_today_str,f"From ₹{today_s:,.2f} total sales today",accent="#16a34a").pack(side="left",fill="x",expand=True,padx=6)
        self.stat_card(summary,"This Month's Profit",prof_month_str,f"From ₹{month_s:,.2f} monthly sales",accent="#0d9488").pack(side="left",fill="x",expand=True,padx=(6,0))

        recent_hdr = tk.Frame(self.content, bg=BG)
        recent_hdr.pack(fill="x", pady=(8, 8))
        tk.Label(recent_hdr, text="Recent Stock Movements & Sales", bg=BG, fg=TEXT, font=("Segoe UI", 13, "bold")).pack(side="left")

        rep_filter = tk.Frame(self.content, bg=BG)
        rep_filter.pack(fill="x", pady=(0, 8))
        tk.Label(rep_filter, text="🔍 Search Part / Note:", bg=BG, fg=TEXT, font=("Segoe UI", 9, "bold")).pack(side="left")
        rep_search_var = tk.StringVar()
        rep_search_ent = ttk.Entry(rep_filter, textvariable=rep_search_var, width=28)
        rep_search_ent.pack(side="left", padx=8)

        tree = self.make_table(("date","part","action","quantity","price","note"),("Date","Part Name","Action","Quantity","Price / Unit (₹)","Note / Reason"),(150,220,90,80,120,380))

        def populate_stock_report(q=""):
            for item in tree.get_children():
                tree.delete(item)
            q_clean = q.strip()
            if q_clean:
                pattern = f"%{q_clean}%"
                rows = self.conn.execute("""SELECT h.*, p.name FROM stock_history h 
                                            LEFT JOIN parts p ON p.id=h.part_id 
                                            WHERE p.name LIKE ? OR h.note LIKE ? OR h.action LIKE ?
                                            ORDER BY h.id DESC LIMIT 300""", (pattern, pattern, pattern)).fetchall()
            else:
                rows = self.conn.execute("""SELECT h.*, p.name FROM stock_history h 
                                            LEFT JOIN parts p ON p.id=h.part_id 
                                            ORDER BY h.id DESC LIMIT 300""").fetchall()
            for r in rows:
                if r["action"] == "OUT":
                    price_str = f"₹{r['sale_price']:.2f}" if r["sale_price"] > 0 else "-"
                else:
                    price_str = f"₹{r['purchase_price']:.2f}" if (self.is_admin() and r["purchase_price"] > 0) else ("🔒" if not self.is_admin() else "-")
                tree.insert("", "end", values=(r["created_at"], r["name"] or "(deleted part)", r["action"], r["quantity"], price_str, r["note"]))

        ttk.Button(rep_filter, text="Search", command=lambda: populate_stock_report(rep_search_var.get())).pack(side="left")
        ttk.Button(rep_filter, text="Show All", command=lambda: (rep_search_var.set(""), populate_stock_report(""))).pack(side="left", padx=6)
        rep_search_ent.bind("<Return>", lambda e: populate_stock_report(rep_search_var.get()))
        rep_search_ent.bind("<KeyRelease>", lambda e: populate_stock_report(rep_search_var.get()))

        populate_stock_report()

    # =========================================================================
    # BACKUP & RESTORE (ADMIN ONLY)
    # =========================================================================
    def show_backup_restore(self):
        if not self.is_admin():
            messagebox.showerror("Permission Denied", "Backup & Restore operations are restricted to administrators.")
            return

        self.clear_content()
        self.title("Database Backup & Restore", "Create disaster recovery backups or safely restore from a previous copy.")

        box = tk.Frame(self.content, bg=CARD, highlightbackground="#cbd5e1", highlightthickness=1, padx=25, pady=22)
        box.pack(fill="x", pady=(0, 16))

        tk.Label(box, text="📦 Create Database Backup", font=("Segoe UI", 14, "bold"), bg=CARD, fg=TEXT).pack(anchor="w")
        tk.Label(box, text="Saves a verified, complete copy of all your inventory, customers, repairs, and audit logs.",
                 font=("Segoe UI", 9), bg=CARD, fg=MUTED).pack(anchor="w", pady=(2, 12))
        ttk.Button(box, text="📥 Create Backup Now", command=self.backup_db).pack(anchor="w")

        box2 = tk.Frame(self.content, bg=CARD, highlightbackground="#fca5a5", highlightthickness=1, padx=25, pady=22)
        box2.pack(fill="x")

        tk.Label(box2, text="⚠️ Restore Database from Backup", font=("Segoe UI", 14, "bold"), bg=CARD, fg=DANGER).pack(anchor="w")
        tk.Label(box2, text="Restores all shop data from a previously created .db backup file. A safety backup of current data will be created first.",
                 font=("Segoe UI", 9), bg=CARD, fg=MUTED).pack(anchor="w", pady=(2, 12))
        ttk.Button(box2, text="🔄 Select Backup File & Restore", command=self.restore_db).pack(anchor="w")

    def backup_db(self):
        self.conn.commit()
        target = filedialog.asksaveasfilename(
            title="Save Database Backup",
            defaultextension=".db",
            initialfile=f"mobile_repair_backup_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db",
            filetypes=[("SQLite database", "*.db"), ("All files", "*.*")]
        )
        if target:
            try:
                # Use SQLite VACUUM INTO for consistent, hot-safe backup
                if os.path.exists(target):
                    os.remove(target)
                self.conn.execute(f"VACUUM INTO '{target}'")
                self.log_audit("BACKUP_DB", "system", "", f"Backup successfully saved to {target}")
                messagebox.showinfo("Backup Successful", f"Database backup saved successfully to:\n{target}")
            except Exception as e:
                # Fallback to copy2 if vacuum into fails
                try:
                    shutil.copy2(DB_FILE, target)
                    self.log_audit("BACKUP_DB", "system", "", f"Backup (copy) saved to {target}")
                    messagebox.showinfo("Backup Successful", f"Database backup saved successfully to:\n{target}")
                except Exception as ex:
                    messagebox.showerror("Backup Failed", "Unable to create backup file. Please check folder permissions.")

    def restore_db(self):
        source = filedialog.askopenfilename(
            title="Select Backup Database File to Restore",
            filetypes=[("SQLite database", "*.db"), ("All files", "*.*")]
        )
        if not source:
            return

        # Security check: verify SQLite magic header (b'SQLite format 3\x00')
        try:
            with open(source, "rb") as f:
                header = f.read(16)
            if not header.startswith(b"SQLite format 3"):
                messagebox.showerror("Invalid File", "The selected file is not a valid SQLite database backup.")
                return
        except Exception:
            messagebox.showerror("Error", "Could not read the selected backup file.")
            return

        # Admin password verification dialog
        confirm_win = tk.Toplevel(self.root)
        confirm_win.title("Confirm Security Authorization")
        confirm_win.configure(bg=BG); confirm_win.resizable(False, False)
        confirm_win.transient(self.root); confirm_win.grab_set()

        tk.Label(confirm_win, text="Confirm Restore Authorization", font=("Segoe UI", 13, "bold"), bg=BG, fg=DANGER).pack(padx=20, pady=(15, 6))
        tk.Label(confirm_win, text=f"Restoring from:\n{os.path.basename(source)}\n\nPlease enter your Admin password to proceed:",
                 font=("Segoe UI", 9), bg=BG, fg=TEXT, justify="center").pack(padx=20, pady=(0, 10))

        pwd_var = tk.StringVar()
        p_frame, p_entry = make_password_entry_row(confirm_win, pwd_var, width=24, bg=BG)
        p_frame.pack(padx=20, pady=(0, 12))
        p_entry.focus()

        def do_restore():
            pwd = pwd_var.get()
            u_row = self.conn.execute("SELECT password_hash, salt FROM users WHERE id = ?", (self.current_user["id"],)).fetchone()
            if not verify_password(pwd, u_row["password_hash"], u_row["salt"]):
                messagebox.showerror("Authorization Failed", "Incorrect password. Restore operation cancelled.", parent=confirm_win)
                return

            confirm_win.destroy()
            try:
                # 1. Create emergency rollback safety backup
                safety_file = f"pre_restore_safety_{datetime.now().strftime('%Y%m%d_%H%M%S')}.db"
                shutil.copy2(DB_FILE, safety_file)

                # 2. Close active connection
                self.conn.close()

                # 3. Replace database file
                shutil.copy2(source, DB_FILE)

                # 4. Reopen database connection
                self.conn = sqlite3.connect(DB_FILE)
                self.conn.row_factory = sqlite3.Row
                self.setup_db()

                self.log_audit("RESTORE_DB", "system", "", f"Database restored from {source}. Rollback saved to {safety_file}")
                messagebox.showinfo("Restore Complete", f"Database successfully restored!\nA rollback backup was saved as '{safety_file}'.")
                self.build_layout()
                self.show_dashboard()
            except Exception as e:
                # Reopen connection
                try:
                    self.conn = sqlite3.connect(DB_FILE)
                    self.conn.row_factory = sqlite3.Row
                except Exception:
                    pass
                messagebox.showerror("Restore Failed", "Could not complete database restore. Current database remains intact.")

        ttk.Button(confirm_win, text="Authorize & Restore", command=do_restore).pack(pady=(0, 15))

    # =========================================================================
    # AUDIT LOGS VIEWER (ADMIN ONLY)
    # =========================================================================
    def show_audit_logs(self):
        if not self.is_admin():
            messagebox.showerror("Permission Denied", "Audit logs are accessible to administrators only.")
            return

        self.clear_content()
        self.title("Security & Operational Audit Logs", "Immutable trail of user logins, inventory updates, and repair deliveries.",
                   action_btn=("⟳ Refresh", self.show_audit_logs))

        top = tk.Frame(self.content, bg=BG)
        top.pack(fill="x", pady=(0, 10))

        filter_var = tk.StringVar(value="All Actions")
        search_var = tk.StringVar()

        tk.Label(top, text="Action Filter:", bg=BG, fg=TEXT, font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 5))
        actions_list = ["All Actions", "LOGIN", "LOGOUT", "AUTO_LOGOUT", "ADD_PART", "EDIT_PART", "DELETE_PART",
                        "STOCK_MOVEMENT", "ADD_PHONE", "EDIT_PHONE", "DELIVER_PHONE", "BACKUP_DB", "RESTORE_DB", "USER_MGMT"]
        action_cb = ttk.Combobox(top, textvariable=filter_var, values=actions_list, state="readonly", width=18)
        action_cb.pack(side="left", padx=(0, 10))

        tk.Label(top, text="Search Details / User:", bg=BG, fg=TEXT, font=("Segoe UI", 9, "bold")).pack(side="left", padx=(0, 5))
        ent = ttk.Entry(top, textvariable=search_var, width=22)
        ent.pack(side="left", padx=(0, 8))

        cols = ("id", "timestamp", "username", "action", "entity", "details")
        headers = ("Log ID", "Timestamp", "User", "Action Taken", "Entity / ID", "Audit Details")
        widths = (60, 140, 100, 130, 110, 480)

        tree = self.make_table(cols, headers, widths)

        def populate(*args):
            for it in tree.get_children(): tree.delete(it)
            act = filter_var.get()
            q = f"%{search_var.get().strip()}%"

            if act == "All Actions":
                rows = self.conn.execute("""
                    SELECT * FROM audit_logs 
                    WHERE (username LIKE ? OR action LIKE ? OR details LIKE ? OR entity_type LIKE ?)
                    ORDER BY id DESC LIMIT 500
                """, (q, q, q, q)).fetchall()
            else:
                rows = self.conn.execute("""
                    SELECT * FROM audit_logs 
                    WHERE action LIKE ? AND (username LIKE ? OR details LIKE ? OR entity_type LIKE ?)
                    ORDER BY id DESC LIMIT 500
                """, (f"%{act}%", q, q, q)).fetchall()

            for r in rows:
                ent_txt = f"{r['entity_type']} #{r['entity_id']}" if r["entity_id"] else r["entity_type"]
                tree.insert("", "end", values=(r["id"], r["timestamp"], r["username"], r["action"], ent_txt, r["details"]))

        action_cb.bind("<<ComboboxSelected>>", populate)
        ent.bind("<KeyRelease>", populate)
        ttk.Button(top, text="Search", command=populate).pack(side="left")
        populate()

    # =========================================================================
    # USER MANAGEMENT (ADMIN ONLY)
    # =========================================================================
    def show_user_management(self):
        if not self.is_admin():
            messagebox.showerror("Permission Denied", "User management is restricted to administrators.")
            return

        self.clear_content()
        self.title("User Accounts & Access Control", "Manage administrator and staff login accounts and permissions.",
                   action_btn=("+ Add New User", self.add_user_dialog))

        cols = ("id", "username", "full_name", "role", "created_at", "last_login", "status")
        headers = ("User ID", "Username", "Full Name", "Role", "Created At", "Last Login", "Status")
        widths = (65, 120, 180, 100, 140, 140, 90)

        tree = self.make_table(cols, headers, widths)

        def populate():
            for it in tree.get_children(): tree.delete(it)
            rows = self.conn.execute("SELECT * FROM users ORDER BY id ASC").fetchall()
            for u in rows:
                status_txt = "Active" if u["is_active"] else "Disabled"
                tree.insert("", "end", values=(u["id"], u["username"], u["full_name"], u["role"].upper(), u["created_at"], u["last_login"] or "Never", status_txt))

        def get_selected_user():
            sel = tree.selection()
            if not sel:
                messagebox.showwarning("Select User", "Please select a user account from the table first.")
                return None
            uid = int(tree.item(sel[0], "values")[0])
            return self.conn.execute("SELECT * FROM users WHERE id=?", (uid,)).fetchone()

        def toggle_status():
            u = get_selected_user()
            if not u: return
            if u["id"] == self.current_user["id"]:
                messagebox.showwarning("Restricted", "You cannot disable your own active administrator account.")
                return
            new_status = 0 if u["is_active"] else 1
            action_name = "Deactivated" if new_status == 0 else "Activated"
            self.conn.execute("UPDATE users SET is_active=? WHERE id=?", (new_status, u["id"]))
            self.conn.commit()
            self.log_audit("USER_MGMT", "user", u["id"], f"Account '{u['username']}' status changed to {action_name}.")
            populate()

        def reset_user_pass():
            u = get_selected_user()
            if not u: return
            self.admin_reset_password_dialog(u)

        actions = tk.Frame(self.content, bg=BG)
        actions.pack(fill="x", pady=10)
        ttk.Button(actions, text="🔑 Reset Password", command=reset_user_pass).pack(side="left")
        ttk.Button(actions, text="Toggle Active / Disabled", command=toggle_status).pack(side="left", padx=8)

        populate()

    def add_user_dialog(self):
        win = tk.Toplevel(self.root)
        win.title("Add New User")
        win.configure(bg=BG); win.resizable(False, False)
        win.transient(self.root); win.grab_set()

        tk.Label(win, text="Create New User Account", font=("Segoe UI", 15, "bold"), bg=BG, fg=TEXT).grid(row=0, column=0, columnspan=2, padx=20, pady=(16, 12), sticky="w")

        fields = [
            ("Username *", "username", ""),
            ("Full Name", "full_name", ""),
            ("Role", "role", "staff"),
            ("Password *", "password", ""),
            ("Confirm Password *", "confirm_pass", "")
        ]
        vars_ = {}
        for r, (lbl, key, def_val) in enumerate(fields, start=1):
            tk.Label(win, text=lbl, bg=BG, fg=TEXT, font=("Segoe UI", 10)).grid(row=r, column=0, padx=20, pady=5, sticky="w")
            v = tk.StringVar(value=def_val)
            vars_[key] = v
            if key == "role":
                w = ttk.Combobox(win, textvariable=v, values=["staff", "admin"], state="readonly", width=30)
                w.grid(row=r, column=1, padx=20, pady=5)
            elif "pass" in key:
                pf, pe = make_password_entry_row(win, v, width=24, bg=BG)
                pf.grid(row=r, column=1, padx=20, pady=5, sticky="w")
            else:
                w = ttk.Entry(win, textvariable=v, width=32)
                w.grid(row=r, column=1, padx=20, pady=5)

        def save():
            u = vars_["username"].get().strip()
            name = vars_["full_name"].get().strip()
            role = vars_["role"].get()
            p1 = vars_["password"].get()
            p2 = vars_["confirm_pass"].get()

            if not u:
                messagebox.showerror("Validation", "Username is required.", parent=win)
                return
            if not u.isalnum() and "_" not in u:
                messagebox.showerror("Validation", "Username can only contain alphanumeric characters.", parent=win)
                return
            if p1 != p2:
                messagebox.showerror("Validation", "Passwords do not match.", parent=win)
                return

            valid, msg = validate_password_strength(p1)
            if not valid:
                messagebox.showerror("Weak Password", msg, parent=win)
                return

            pwd_hash, salt = hash_password(p1)
            now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            try:
                self.conn.execute(
                    "INSERT INTO users(username, password_hash, salt, role, full_name, created_at) VALUES(?,?,?,?,?,?)",
                    (u, pwd_hash, salt, role, name, now)
                )
                new_id = self.conn.execute("SELECT last_insert_rowid()").fetchone()[0]
                self.conn.commit()
                self.log_audit("USER_CREATED", "user", new_id, f"Created {role} user '{u}'.")
                win.destroy()
                messagebox.showinfo("Success", f"User '{u}' created successfully!")
                self.show_user_management()
            except sqlite3.IntegrityError:
                messagebox.showerror("Duplicate Username", f"Username '{u}' is already taken.", parent=win)

        btn_row = tk.Frame(win, bg=BG)
        btn_row.grid(row=len(fields)+1, column=0, columnspan=2, pady=16)
        ttk.Button(btn_row, text="Create Account", command=save).pack(side="left", padx=6)
        ttk.Button(btn_row, text="Cancel", command=win.destroy).pack(side="left", padx=6)

    def change_password_dialog(self):
        """Allows logged-in user to change their own password."""
        win = tk.Toplevel(self.root)
        win.title("Change Password")
        win.configure(bg=BG); win.resizable(False, False)
        win.transient(self.root); win.grab_set()

        tk.Label(win, text="Change Your Password", font=("Segoe UI", 14, "bold"), bg=BG, fg=TEXT).pack(padx=20, pady=(16, 12))

        cur_p_var = tk.StringVar()
        new_p_var = tk.StringVar()
        cnf_p_var = tk.StringVar()

        for lbl, v in [("Current Password:", cur_p_var), ("New Password:", new_p_var), ("Confirm New Password:", cnf_p_var)]:
            tk.Label(win, text=lbl, bg=BG, fg=TEXT, font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=20)
            pf, pe = make_password_entry_row(win, v, width=26, bg=BG)
            pf.pack(fill="x", padx=20, pady=(2, 8))

        def update_pass():
            cp = cur_p_var.get()
            np = new_p_var.get()
            cnf = cnf_p_var.get()

            u = self.conn.execute("SELECT password_hash, salt FROM users WHERE id = ?", (self.current_user["id"],)).fetchone()
            if not verify_password(cp, u["password_hash"], u["salt"]):
                messagebox.showerror("Error", "Current password is incorrect.", parent=win)
                return
            if np != cnf:
                messagebox.showerror("Error", "New passwords do not match.", parent=win)
                return

            valid, msg = validate_password_strength(np)
            if not valid:
                messagebox.showerror("Weak Password", msg, parent=win)
                return

            new_hash, new_salt = hash_password(np)
            self.conn.execute("UPDATE users SET password_hash=?, salt=? WHERE id=?", (new_hash, new_salt, self.current_user["id"]))
            self.conn.commit()
            self.log_audit("PASSWORD_CHANGE", "user", self.current_user["id"], "User changed their password.")
            win.destroy()
            messagebox.showinfo("Success", "Password updated successfully!")

        ttk.Button(win, text="Update Password", command=update_pass).pack(pady=(6, 16))

    def admin_reset_password_dialog(self, target_user):
        win = tk.Toplevel(self.root)
        win.title(f"Reset Password - {target_user['username']}")
        win.configure(bg=BG); win.resizable(False, False)
        win.transient(self.root); win.grab_set()

        tk.Label(win, text=f"Reset Password for '{target_user['username']}'", font=("Segoe UI", 13, "bold"), bg=BG, fg=TEXT).pack(padx=20, pady=(16, 10))

        new_p_var = tk.StringVar()
        tk.Label(win, text="New Password:", bg=BG, fg=TEXT, font=("Segoe UI", 9, "bold")).pack(anchor="w", padx=20)
        pf, pe = make_password_entry_row(win, new_p_var, width=24, bg=BG)
        pf.pack(padx=20, pady=(2, 12))

        def reset_now():
            np = new_p_var.get()
            valid, msg = validate_password_strength(np)
            if not valid:
                messagebox.showerror("Weak Password", msg, parent=win)
                return
            new_hash, new_salt = hash_password(np)
            self.conn.execute("UPDATE users SET password_hash=?, salt=? WHERE id=?", (new_hash, new_salt, target_user["id"]))
            self.conn.commit()
            self.log_audit("USER_MGMT", "user", target_user["id"], f"Admin reset password for user '{target_user['username']}'.")
            win.destroy()
            messagebox.showinfo("Success", f"Password for '{target_user['username']}' reset successfully!")

        ttk.Button(win, text="Set New Password", command=reset_now).pack(pady=(4, 16))

    def close(self):
        if self.current_user:
            self.log_audit("LOGOUT", "user", self.current_user["id"], "Application closed by user.")
        self.conn.close()
        self.root.destroy()


if __name__ == "__main__":
    import sys
    import threading
    import subprocess
    import socket
    import webbrowser
    import time

    def is_port_open(port=5000):
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        try:
            s.settimeout(0.3)
            return s.connect_ex(('127.0.0.1', port)) == 0
        except Exception:
            return False
        finally:
            s.close()

    def run_flask_server():
        try:
            from web_app import app as flask_app
            flask_app.run(host="0.0.0.0", port=5000, debug=False, use_reloader=False)
        except Exception as e:
            print("Flask server error:", e)

    # If --classic is passed, run legacy Tkinter window
    if "--classic" in sys.argv or "-c" in sys.argv:
        root = tk.Tk()
        app = RepairManager(root)
        root.protocol("WM_DELETE_WINDOW", app.close)
        root.mainloop()
    else:
        # Start Flask background server if not already running
        if not is_port_open(5000):
            t = threading.Thread(target=run_flask_server, daemon=True)
            t.start()
            for _ in range(30):
                if is_port_open(5000):
                    break
                time.sleep(0.15)

        # Locate Microsoft Edge or Google Chrome for standalone App Window mode
        candidates = [
            r"C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Microsoft\Edge\Application\msedge.exe",
            r"C:\Program Files\Google\Chrome\Application\chrome.exe",
            r"C:\Program Files (x86)\Google\Chrome\Application\chrome.exe",
            os.path.expandvars(r"%LOCALAPPDATA%\Microsoft\Edge\Application\msedge.exe"),
            os.path.expandvars(r"%LOCALAPPDATA%\Google\Chrome\Application\chrome.exe"),
        ]
        browser_exe = None
        for cand in candidates:
            if os.path.exists(cand):
                browser_exe = cand
                break

        url = "http://127.0.0.1:5000"
        if browser_exe:
            print(f"[*] Launching Patiraj Mobile Repair Shop in Native Desktop Window: {browser_exe}")
            user_data_dir = os.path.join(os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "PatirajRepair", "AppProfile")
            try:
                os.makedirs(user_data_dir, exist_ok=True)
            except Exception:
                pass

            subprocess.Popen([
                browser_exe,
                f"--app={url}",
                f"--user-data-dir={user_data_dir}",
                "--no-first-run",
                "--no-default-browser-check",
                "--window-size=1280,820",
                "--window-position=60,40"
            ])
        else:
            print(f"[*] Opening Patiraj Mobile Repair Shop in default browser: {url}")
            webbrowser.open(url)

        print("\n=================================================================")
        print("  PATIRAJ MOBILE REPAIR SHOP - APPLICATION IS ACTIVE")
        print("  Local URL:  http://127.0.0.1:5000")
        print("  Status:     Server is running smoothly.")
        print("  NOTE: Keep this window open while using the software.")
        print("  Press Ctrl+C to close.")
        print("=================================================================\n")
        try:
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("\n[*] Exiting Patiraj Mobile Repair Shop...")
