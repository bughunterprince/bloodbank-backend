from flask import Flask, request, jsonify, session
from werkzeug.security import generate_password_hash, check_password_hash
from flask_cors import CORS
import os
import sqlite3
from dotenv import load_dotenv
import random

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
    
    # Normal user login using DB
    try:
        conn = get_connection()
        cur = conn.cursor()
        cur.execute("SELECT username, password_hash, COALESCE(user_type,'user'), COALESCE(otp_verified,0) FROM users WHERE email=?", (email.lower(),))
        row = cur.fetchone()
        cur.close(); conn.close()
        if not row:
            return jsonify({"error": "Invalid email or password"}), 401
        username, password_hash, user_type, otp_verified = row
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

@app.route("/api/register", methods=["POST"])
def register():
    data = request.get_json()
    name = (data.get("name") or "").strip()
    email = (data.get("email") or "").strip().lower()
    password = data.get("password") or ""
    user_type = (data.get("user_type") or "user").strip().lower()
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
        cur.execute(
            "INSERT INTO users (username, email, password_hash, user_type, otp, otp_verified) VALUES (?, ?, ?, ?, ?, 0)",
            (name, email, password_hash, user_type, otp)
        )
        conn.commit()
        cur.close(); conn.close()
        print(f"[OTP] Registration OTP for {email}: {otp}")
        return jsonify({"message": "Registered! OTP sent (check logs)", "email": email})
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