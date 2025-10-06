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

# Ensure DB is initialized in environments where __main__ is not executed (e.g., gunicorn)
@app.before_first_request
def _bootstrap_db():
    try:
        init_sqlite_db()
    except Exception as e:
        print(f"[BOOTSTRAP] DB init skipped due to error: {e}")

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

def send_otp_email(to_email: str, name: str, otp: str) -> bool:
    """Send OTP to user's email using SMTP.
    Returns True if sent, False otherwise.
    Uses env SENDER_EMAIL and SENDER_PASSWORD. Falls back to console print when missing/failing.
    """
    sender = os.getenv("SENDER_EMAIL")
    password = os.getenv("SENDER_PASSWORD")
    if not sender or not password:
        # Fallback: no credentials configured
        print(f"[OTP:FALLBACK] OTP for {to_email}: {otp}")
        return False

    try:
        clean_password = password.replace(" ", "")
        display_name = os.getenv("SENDER_NAME", "Blood Bank Service")
        subject = "Your OTP for Blood Bank Account"
        body = (
            f"Hi {name or 'there'},\n\n"
            f"Use this One-Time Password to verify your email: {otp}\n\n"
            "This code will expire soon. If you didn't try to sign up, you can ignore this email.\n\n"
            "— Blood Bank Team"
        )
        msg = MIMEText(body, _charset="utf-8")
        msg["From"] = formataddr((display_name, sender))
        msg["To"] = to_email
        msg["Subject"] = subject

        with smtplib.SMTP("smtp.gmail.com", 587, timeout=20) as server:
            server.ehlo()
            server.starttls()
            server.login(sender, clean_password)
            server.sendmail(sender, [to_email], msg.as_string())
        print(f"[OTP:EMAIL] Sent OTP to {to_email}")
        return True
    except Exception as e:
        print(f"[OTP:EMAIL:ERROR] Could not send email to {to_email}: {e}")
        print(f"[OTP:FALLBACK] OTP for {to_email}: {otp}")
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
        # Attempt to send OTP via email; fallback is console log handled inside
        sent = send_otp_email(email, name, otp)
        msg = "Registered! OTP sent to your email" if sent else "Registered! OTP sent (check logs)"
        return jsonify({"message": msg, "email": email})
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

if __name__ == "__main__":
    # Initialize DB (no-op if exists)
    init_sqlite_db()
    # Use PORT provided by Render; default to 5000 locally
    port = int(os.getenv("PORT", "5000"))
    # Disable debug by default in production
    debug = os.getenv("FLASK_DEBUG", "0").lower() in ("1", "true", "yes")
    app.run(host="0.0.0.0", port=port, debug=debug)