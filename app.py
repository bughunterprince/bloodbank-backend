from flask import Flask, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import os
import sqlite3
from dotenv import load_dotenv
import random
import smtplib
from email.mime.text import MIMEText
from email.utils import formataddr
import requests
import traceback
import ssl

# Bootstrap
load_dotenv()
env_alt_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), "env")
if os.path.exists(env_alt_path):
    load_dotenv(env_alt_path, override=True)

ROOT_DIR = os.path.dirname(os.path.abspath(__file__))
DB_ENGINE = os.getenv("DB_ENGINE", "sqlite").lower()
SQLITE_PATH = os.getenv("SQLITE_PATH", os.path.join(ROOT_DIR, "bloodbank.db"))

app = Flask(__name__)
# CORS: allow all in dev, restrict in prod via env FRONTEND_ORIGIN
frontend_origin = os.getenv("FRONTEND_ORIGIN")
if frontend_origin:
    CORS(app, resources={r"/*": {"origins": frontend_origin}}, supports_credentials=True)
else:
    CORS(app, resources={r"/*": {"origins": "*"}}, supports_credentials=True)
app.secret_key = os.getenv("SECRET_KEY", "fallback_secret")

app.config["SESSION_COOKIE_SAMESITE"] = "None"
# Secure cookies on Render (when PORT is present) unless explicitly disabled
app.config["SESSION_COOKIE_SECURE"] = bool(os.getenv("PORT")) and os.getenv("COOKIE_SECURE", "1") not in ("0", "false", "no")

# (Import-time DB init will be added after the function definition)

def get_connection():
    conn = sqlite3.connect(SQLITE_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn

def adapt_query(query: str) -> str:
    return query.replace("%s", "?")

def init_sqlite_db():
    conn = get_connection()
    cur = conn.cursor()
    # Create tables if they don't exist
    cur.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT NOT NULL,
            email TEXT NOT NULL UNIQUE,
            password_hash TEXT NOT NULL,
            user_type TEXT,
            otp TEXT,
            otp_verified INTEGER DEFAULT 0,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS customer_appointments (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT NOT NULL,
            age INTEGER,
            gender TEXT,
            appointment_date TEXT NOT NULL,
            time_slot TEXT NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
            UNIQUE(email, appointment_date, time_slot)
        );
        CREATE TABLE IF NOT EXISTS blood_stock (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hospital_name TEXT NOT NULL,
            blood_group TEXT NOT NULL,
            units INTEGER NOT NULL,
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
        CREATE TABLE IF NOT EXISTS blood_requests (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            hospital_name TEXT NOT NULL,
            patient_name TEXT NOT NULL,
            blood_group TEXT NOT NULL,
            units_required INTEGER NOT NULL,
            urgency TEXT NOT NULL,
            contact_number TEXT,
            request_date TEXT NOT NULL,
            status TEXT DEFAULT 'pending',
            created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
        );
    """)
    # Lightweight migrations for existing DBs
    try:
        cur.execute("PRAGMA table_info(users)")
        cols = {row[1] for row in cur.fetchall()}
        if 'user_type' not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN user_type TEXT")
        if 'otp' not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN otp TEXT")
        if 'otp_verified' not in cols:
            cur.execute("ALTER TABLE users ADD COLUMN otp_verified INTEGER DEFAULT 0")
    except Exception as e:
        print(f"[DB MIGRATION] {e}")
    conn.commit()
    cur.close()
    conn.close()

# Ensure DB is initialized even when running under gunicorn (Flask 3 removed before_first_request)
try:
    init_sqlite_db()
except Exception as e:
    print(f"[BOOTSTRAP] DB init skipped due to error: {e}")

@app.route("/")
def root():
    return jsonify({
        "message": "Blood Bank Management API",
        "status": "running",
        "version": "1.0.0",
        "endpoints": [
            "/api/health",
            "/api/login",
            "/api/logout",
            "/api/user",
            "/api/register",
            "/api/verify-otp",
            "/api/submit-customer",
            "/api/appointments"
        ]
    })

@app.route("/api/health")
def health():
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT 1")
        cur.fetchone()
        cur.close()
        conn.close()
        return jsonify({"status": "ok", "engine": DB_ENGINE}), 200
    except Exception as e:
        return jsonify({"status": "error", "engine": DB_ENGINE, "error": str(e)}), 500

@app.route("/api/login", methods=["POST"])
def login():
    data = request.get_json()
    email = data.get("email", "").strip()
    password = data.get("password", "")
    
    if not email or not password:
        return jsonify({"error": "Email and password required"}), 400
    
    # Check for admin login
    if email == "admin@gmail.com" and password == "admin":
        session["username"] = "admin"
        session["is_admin"] = True
        return jsonify({"message": "Login successful", "user_type": "admin", "username": "admin"})
    
    # Hospital quick login rule
    if email.lower().endswith("@hospital.com") and password == "prince":
        username = email.split("@")[0]
        session["username"] = username
        session["email"] = email.lower()
        session["user_type"] = "hospital"
        return jsonify({"message": "Login successful", "user_type": "hospital", "username": username})

    # Normal user login using DB
    try:
        conn = get_connection()
        cur = conn.cursor()
        # Detect available columns for backward-compatible queries
        cur.execute("PRAGMA table_info(users)")
        cols = {row[1] for row in cur.fetchall()}
        if 'user_type' in cols and 'otp_verified' in cols:
            cur.execute("SELECT username, password_hash, COALESCE(user_type,'user'), COALESCE(otp_verified,0) FROM users WHERE email=?", (email.lower(),))
            row = cur.fetchone()
            user_type_from_db = None
        else:
            # Minimal query; treat user as verified if column missing
            cur.execute("SELECT username, password_hash FROM users WHERE email=?", (email.lower(),))
            row = cur.fetchone()
            user_type_from_db = 'user'
        cur.close(); conn.close()
        if not row:
            return jsonify({"error": "Invalid email or password"}), 401
        if 'user_type' in locals() or user_type_from_db is None:
            username, password_hash, user_type, otp_verified = row
        else:
            username, password_hash = row
            user_type = user_type_from_db
            otp_verified = 1
        if not check_password_hash(password_hash, password):
            return jsonify({"error": "Invalid email or password"}), 401
        if not otp_verified:
            return jsonify({"error": "Email not verified. Please verify OTP."}), 403
        session["username"] = username
        session["email"] = email.lower()
        session["user_type"] = user_type
        return jsonify({"message": "Login successful", "user_type": user_type, "username": username})
    except Exception as e:
        return jsonify({"error": f"Login failed: {e}"}), 500

# Helpers for registration/OTP
def generate_otp():
    return str(random.randint(100000, 999999))

def _email_subject_body(name: str, otp: str):
    subject = "Your OTP for Blood Bank Account"
    body = (
        f"Hi {name or 'there'},\n\n"
        f"Your One-Time Password is: {otp}\n\n"
        "Use this code to verify your email address.\n"
        "This code will expire in 10 minutes.\n\n"
        "If you didn't request this, please ignore this email.\n\n"
        "— Blood Bank Team"
    )
    return subject, body

def _send_via_sendgrid(to_email: str, name: str, otp: str) -> bool:
    api_key = os.getenv("SENDGRID_API_KEY")
    sender = os.getenv("SENDER_EMAIL") or os.getenv("SMTP_FROM")
    if not api_key or not sender:
        return False
    subject, body = _email_subject_body(name, otp)
    try:
        resp = requests.post(
            "https://api.sendgrid.com/v3/mail/send",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "personalizations": [{"to": [{"email": to_email}]}],
                "from": {"email": sender, "name": os.getenv("SENDER_NAME", "Blood Bank Service")},
                "subject": subject,
                "content": [{"type": "text/plain", "value": body}],
            },
            timeout=12,
        )
        if resp.status_code in (200, 202):
            print(f"[EMAIL] SendGrid accepted mail to {to_email}")
            return True
        print(f"[EMAIL] SendGrid error {resp.status_code}: {resp.text[:200]}")
        return False
    except Exception as e:
        print(f"[EMAIL] SendGrid exception: {type(e).__name__}: {e}")
        return False

def _send_via_resend(to_email: str, name: str, otp: str) -> bool:
    api_key = os.getenv("RESEND_API_KEY")
    sender = os.getenv("RESEND_FROM") or os.getenv("SENDER_EMAIL") or os.getenv("SMTP_FROM")
    if not api_key or not sender:
        return False
    subject, body = _email_subject_body(name, otp)
    try:
        resp = requests.post(
            "https://api.resend.com/emails",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
            },
            json={
                "from": sender,
                "to": [to_email],
                "subject": subject,
                "text": body,
            },
            timeout=12,
        )
        if resp.status_code in (200, 201):
            print(f"[EMAIL] Resend accepted mail to {to_email}")
            return True
        print(f"[EMAIL] Resend error {resp.status_code}: {resp.text[:200]}")
        return False
    except Exception as e:
        print(f"[EMAIL] Resend exception: {type(e).__name__}: {e}")
        return False

def send_otp_email(to_email: str, name: str, otp: str) -> bool:
    """Send OTP via HTTP API (SendGrid/Resend preferred) or SMTP fallback."""
    print(f"[DEBUG] Attempting to send OTP to: {to_email}")
    
    # TRY HTTP APIs FIRST (Render blocks SMTP ports)
    if _send_via_sendgrid(to_email, name, otp):
        return True
    if _send_via_resend(to_email, name, otp):
        return True
    
    # SMTP fallback (only works locally, not on Render)
    sender = os.getenv("SENDER_EMAIL")
    password = os.getenv("SENDER_PASSWORD")
    print(f"[DEBUG] SMTP Config - Sender: {sender}")
    print(f"[DEBUG] Password configured: {bool(password)}")
    if not sender or not password:
        print(f"[ERROR] No email provider configured. Set SENDGRID_API_KEY or SENDER_EMAIL+SENDER_PASSWORD")
        return False
    if not sender or not password:
        print(f"[ERROR] No email provider configured. Set SENDGRID_API_KEY or SENDER_EMAIL+SENDER_PASSWORD")
        return False

    try:
        # Gmail SMTP (blocked on Render, works locally only)
        clean_password = password.replace(" ", "").strip()
        print(f"[DEBUG] Password length after cleaning: {len(clean_password)}")
        display_name = os.getenv("SENDER_NAME", "Blood Bank Service")
        subject, body = _email_subject_body(name, otp)
        msg = MIMEText(body, _charset="utf-8")
        msg["From"] = formataddr((display_name, sender))
        msg["To"] = to_email
        msg["Subject"] = subject

        smtp_host = os.getenv("SMTP_HOST", "smtp.gmail.com")
        # 1) Try SMTPS (SSL) on 465
        try:
            ssl_port = int(os.getenv("SMTP_SSL_PORT", "465"))
            print(f"[DEBUG] Connecting via SMTP_SSL {smtp_host}:{ssl_port} ...")
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(smtp_host, ssl_port, context=context, timeout=12) as server:
                server.ehlo()
                print(f"[DEBUG] Logging in (SSL) with user: {sender}")
                server.login(sender, clean_password)
                print(f"[DEBUG] Sending email (SSL)...")
                server.sendmail(sender, [to_email], msg.as_string())
            print(f"[SUCCESS] OTP email sent via SSL to {to_email}")
            return True
        except Exception as e_ssl:
            print(f"[WARN] SMTP_SSL failed: {type(e_ssl).__name__}: {e_ssl}")

        # 2) Fallback to STARTTLS on 587
        try:
            tls_port = int(os.getenv("SMTP_PORT", "587"))
            print(f"[DEBUG] Connecting via SMTP {smtp_host}:{tls_port} (STARTTLS) ...")
            with smtplib.SMTP(smtp_host, tls_port, timeout=15) as server:
                server.ehlo()
                print(f"[DEBUG] Starting TLS...")
                server.starttls(context=ssl.create_default_context())
                server.ehlo()
                print(f"[DEBUG] Logging in (TLS) with user: {sender}")
                server.login(sender, clean_password)
                print(f"[DEBUG] Sending email (TLS)...")
                server.sendmail(sender, [to_email], msg.as_string())
            print(f"[SUCCESS] OTP email sent via STARTTLS to {to_email}")
            return True
        except Exception as e_tls:
            print(f"[WARN] SMTP STARTTLS failed: {type(e_tls).__name__}: {e_tls}")

        # If both SMTP attempts fail, try providers only if keys are present
        if _send_via_sendgrid(to_email, name, otp) or _send_via_resend(to_email, name, otp):
            return True
        return False
        
    except smtplib.SMTPAuthenticationError as e:
        print(f"[ERROR] SMTP Authentication failed: {e}")
        print(f"[HINT] Check if 2-Step Verification is enabled and App Password is correct")
        return False
    except smtplib.SMTPRecipientsRefused as e:
        print(f"[ERROR] Recipient refused: {e}")
        return False
    except smtplib.SMTPServerDisconnected as e:
        print(f"[ERROR] SMTP server disconnected: {e}")
        return False
    except Exception as e:
        print(f"[ERROR] Unexpected SMTP error: {type(e).__name__}: {e}")
        traceback.print_exc()
        return False
        
    except smtplib.SMTPAuthenticationError as e:
        print(f"[ERROR] SMTP Authentication failed: {e}")
        print(f"[HINT] Check if 2-Step Verification is enabled and App Password is correct")
        return False
    except smtplib.SMTPRecipientsRefused as e:
        print(f"[ERROR] Recipient refused: {e}")
        return False
    except smtplib.SMTPServerDisconnected as e:
        print(f"[ERROR] SMTP server disconnected: {e}")
        return False
    except Exception as e:
        print(f"[ERROR] Unexpected SMTP error: {type(e).__name__}: {e}")
        traceback.print_exc()
        return False

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    # Force simple user signups only; ignore incoming user_type
    user_type = "user"
    if not all([name, email, password]):
        return jsonify({"error": "All fields required"}), 400
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id FROM users WHERE email=?", (email,))
        if cur.fetchone():
            cur.close(); conn.close()
            return jsonify({"error": "Email already registered"}), 409
        password_hash = generate_password_hash(password)
        otp = generate_otp()
        # Build insert dynamically based on available columns
        cur.execute("PRAGMA table_info(users)")
        user_cols = {row[1] for row in cur.fetchall()}
        insert_cols = ["username", "email", "password_hash"]
        insert_vals = [name, email, password_hash]
        if 'user_type' in user_cols:
            insert_cols.append('user_type'); insert_vals.append(user_type)
        if 'otp' in user_cols:
            insert_cols.append('otp'); insert_vals.append(otp)
        if 'otp_verified' in user_cols:
            insert_cols.append('otp_verified'); insert_vals.append(0)
        placeholders = ", ".join(["?"] * len(insert_cols))
        sql = f"INSERT INTO users ({', '.join(insert_cols)}) VALUES ({placeholders})"
        cur.execute(sql, tuple(insert_vals))
        conn.commit()
        cur.close(); conn.close()
        # Send OTP via email - must succeed or registration fails
        print(f"[REGISTER] Attempting to send OTP to {email}")
        sent = send_otp_email(email, name, otp)
        if not sent:
            cur.close(); conn.close()
            return jsonify({"error": "Failed to send OTP email. Please check your email address or try again later."}), 500
        
        return jsonify({"message": "Registration successful! Check your email for OTP.", "email": email})
    except Exception as e:
        return jsonify({"error": f"Registration failed: {e}"}), 500

@app.route("/api/verify-otp", methods=["POST"])
def verify_otp():
    data = request.get_json()
    email = (data.get("email") or "").strip().lower()
    otp = (data.get("otp") or "").strip()
    if not email or not otp:
        return jsonify({"error": "Email and OTP required"}), 400
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, otp FROM users WHERE email=?", (email,))
        row = cur.fetchone()
        if not row:
            cur.close(); conn.close()
            return jsonify({"error": "User not found"}), 404
        uid, saved_otp = row
        if not saved_otp or saved_otp != otp:
            cur.close(); conn.close()
            return jsonify({"error": "Invalid OTP"}), 400
        cur.execute("UPDATE users SET otp_verified=1, otp=NULL WHERE id=?", (uid,))
        conn.commit()
        cur.close(); conn.close()
        return jsonify({"message": "OTP verified successfully"})
    except Exception as e:
        return jsonify({"error": f"Verification failed: {e}"}), 500

@app.route("/api/logout", methods=["POST"])
def logout():
    session.clear()
    return jsonify({"message": "Logged out successfully"})

@app.route("/api/user", methods=["GET"])
def get_user():
    if session.get("username"):
        user_type = "admin" if session.get("is_admin") else "user"
        return jsonify({
            "username": session["username"],
            "user_type": user_type,
            "is_admin": session.get("is_admin", False)
        })
    return jsonify({"error": "Not logged in"}), 401

@app.route("/api/submit-customer", methods=["POST"])
def submit_customer():
    try:
        data = request.get_json()
        name = data.get("name")
        email = data.get("email")
        age = data.get("age")
        gender = data.get("gender")
        appointment_date = data.get("appointment_date")
        time_slot = data.get("time_slot")
        
        if not all([name, email, age, gender, appointment_date, time_slot]):
            return jsonify({"message": "Missing fields"}), 400
        
        conn = get_connection()
        cur = conn.cursor()
        sql = adapt_query("INSERT INTO customer_appointments (name, email, age, gender, appointment_date, time_slot) VALUES (%s, %s, %s, %s, %s, %s)")
        cur.execute(sql, (name, email, age, gender, appointment_date, time_slot))
        conn.commit()
        cur.close()
        conn.close()
        return jsonify({"message": "✅ Appointment confirmed!"})
    except Exception as e:
        return jsonify({"message": f"❌ Failed to save appointment. Error: {e}"}), 500


# New endpoint: get all customer appointments
@app.route("/api/appointments", methods=["GET"])
def get_appointments():
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT id, name, email, age, gender, appointment_date, time_slot, created_at FROM customer_appointments ORDER BY created_at DESC")
        rows = cur.fetchall()
        appointments = [dict(row) for row in rows]
        cur.close()
        conn.close()
        return jsonify({"appointments": appointments})
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route("/api/smtp-status", methods=["GET"])
def smtp_status():
    """Check SMTP configuration status"""
    sender = os.getenv("SENDER_EMAIL")
    password = os.getenv("SENDER_PASSWORD")
    return jsonify({
        "sender_configured": bool(sender),
        "password_configured": bool(password),
        "sender_email": sender or "Not set",
        "password_length": len(password) if password else 0
    })

@app.route("/api/test-otp", methods=["POST"])
def test_otp():
    """Test OTP sending to a specific email"""
    data = request.get_json()
    test_email = data.get("email") if data else None
    
    if not test_email:
        return jsonify({"error": "Email required"}), 400
    
    test_otp = generate_otp()
    success = send_otp_email(test_email, "Test User", test_otp)
    
    return jsonify({
        "success": success,
        "message": "OTP sent successfully" if success else "Failed to send OTP",
        "test_email": test_email
    })

if __name__ == "__main__":
    # Initialize DB (no-op if exists)
    init_sqlite_db()
    # Use PORT provided by Render; default to 5000 locally
    port = int(os.getenv("PORT", "5000"))
    # Disable debug by default in production
    debug = os.getenv("FLASK_DEBUG", "0").lower() in ("1", "true", "yes")
    app.run(host="0.0.0.0", port=port, debug=debug)