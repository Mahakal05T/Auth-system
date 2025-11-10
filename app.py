# app.py (JWT-integrated, sessions replaced)
import logging
import os
import re
import random
import string
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, request, jsonify, render_template, redirect, url_for, send_from_directory
)
import bcrypt
import mysql.connector as mysql
import smtplib
from email.mime.text import MIMEText
from twilio.rest import Client
from dotenv import load_dotenv
from ratelimit import limits, sleep_and_retry

# JWT imports
from flask_jwt_extended import (
    JWTManager, create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt
)

# ---------------- Config ----------------
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
load_dotenv(os.path.join(os.path.dirname(__file__), "credentials.env"))

# Use dedicated JWT secret (fallback to existing SECRET_KEY if needed)
app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", os.getenv("SECRET_KEY", "fallback_dev_key"))
# Access token lifetime and refresh token lifetime
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)       # access token lifetime
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=1)      # refresh token lifetime
app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies"]
app.config["JWT_IDENTITY_CLAIM"] = "identity"
jwt = JWTManager(app)


# In-memory blocklist for revoked tokens (jti strings).
# NOTE: ephemeral — replace with Redis/DB for production/multi-worker.
JWT_BLOCKLIST = set()

# Temporary in-memory storage for pending profile updates and OTP used previously stored in session.
# Structure: PENDING_PROFILE_UPDATES[user_id] = {"otp_hash": "...", "pending_profile": {...}, "expiry": datetime}
PENDING_PROFILE_UPDATES = {}

# Allowed roles
ALLOWED_ROLES = {"user", "admin", "hr"}  # added "hr"

# ---------------- DB Utilities ----------------
def connect_db():
    return mysql.connect(
        host=os.getenv("DB_HOST", "localhost"),
        user=os.getenv("DB_USER", "root"),
        password=os.getenv("DB_PASS", ""),
        database=os.getenv("DB_NAME", "auth_db")
    )

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(stored_hash, password):
    return bcrypt.checkpw(password.encode(), stored_hash.encode())

def count_admins(conn):
    cur = conn.cursor()
    cur.execute("SELECT COUNT(*) FROM users WHERE role='admin'")
    n = cur.fetchone()[0]
    cur.close()
    return n

# ---------------- Helpers ----------------
def generate_otp():
    return str(random.randint(100000, 999999))

def is_valid_email(email):
    return re.match(r"[^@]+@[^@]+\.[^@]+", email)

def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"[0-9]", password) and
        re.search(r"[^A-Za-z0-9]", password)
    )


def generate_employee_id():
    return "emp" + str(random.randint(1000, 9999))

def generate_random_password(length=10):
    characters = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(secrets.choice(characters) for _ in range(length))

# ---------------- Email / SMS ----------------
def send_email(to_email, subject, body):
    email_user = os.getenv("EMAIL_USER")
    email_pass = os.getenv("EMAIL_PASS")
    if not email_user or not email_pass:
        logging.error("EMAIL_USER or EMAIL_PASS not set")
        return False
    msg = MIMEText(body)
    msg["Subject"] = subject
    msg["From"] = email_user
    msg["To"] = to_email
    try:
        server = smtplib.SMTP("smtp.gmail.com", 587)
        server.starttls()
        server.login(email_user, email_pass)
        server.sendmail(email_user, to_email, msg.as_string())
        server.quit()
        logging.info(f"Email sent to {to_email}")
        return True
    except Exception as e:
        logging.error(f"Failed to send email to {to_email}: {e}")
        return False

def send_otp_email(email, otp):
    return send_email(email, "Your OTP code", f"Your OTP code is: {otp}")

def send_reset_link_email(email, link):
    return send_email(email, "Reset Your Password", f"Reset link: {link}")

def send_credentials_email(email, emp_id, password):
    return send_email(email, "Your Account Credentials", f"Welcome!\n\nYour employee ID: {emp_id}\nYour temporary password: {password}")

# ---------------- JWT blocklist handling ----------------
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload.get("jti")
    return jti in JWT_BLOCKLIST

@jwt.revoked_token_loader
def revoked_token_callback(jwt_header, jwt_payload):
    return jsonify({"error": "Token has been revoked"}), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"error": "Token has expired"}), 401

@jwt.invalid_token_loader
def invalid_token_callback(reason):
    return jsonify({"error": "Invalid token", "reason": reason}), 401

@jwt.unauthorized_loader
def missing_token_callback(reason):
    return jsonify({"error": "Missing token", "reason": reason}), 401

# ---------------- Decorators (JWT-based) ----------------
def login_required(f):
    @wraps(f)
    @jwt_required()
    def wrapper(*args, **kwargs):
        # jwt_required ensures token present & valid
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    @jwt_required()
    def wrapper(*args, **kwargs):
        identity = get_jwt_identity() or {}
        if identity.get("role") != "admin":
            return redirect(url_for('unauthorized'))
        return f(*args, **kwargs)
    return wrapper

# ---------------- Routes ----------------
@app.route("/")
def root():
    return redirect(url_for("login_user"))

# ---- Login ----
@sleep_and_retry
@limits(calls=5, period=60)
@app.route("/login", methods=["GET", "POST"])
def login_user():
    if request.method == "GET":
        return render_template("login.html")

    try:
        data = request.get_json()
        if not data:
            return jsonify({"error": "Missing JSON data"}), 400

        identifier = data.get("identifier", "").strip()
        password = data.get("password", "").strip()

        if not identifier or not password:
            return jsonify({"error": "Missing identifier or password"}), 400

        conn = connect_db()
        cursor = conn.cursor(dictionary=True)

        # Try to find user by either emp_id or email
        cursor.execute(
            "SELECT * FROM users WHERE emp_id=%s OR email=%s LIMIT 1",
            (identifier, identifier)
        )
        user = cursor.fetchone()

        if not user:
            return jsonify({"error": "User not found"}), 401

        role = user["role"].lower()

        # Verify password hash
        if not check_password(user["password_hash"], password):
            return jsonify({"error": "Invalid credentials"}), 401

        # If user was inactive, mark as active
        if user.get("status") != "active":
            cursor.execute("UPDATE users SET status='active' WHERE id=%s", (user["id"],))
            conn.commit()

        # Create JWT identity payload (keep relevant info used across app)
        identity = {
            "id": user["id"],
            "role": role,
            "name": user.get("name"),
            "department": user.get("department")
        }

        access_token = create_access_token(identity=identity)
        refresh_token = create_refresh_token(identity=identity)

        # Redirect URLs based on role (kept as before)
        redirect_url = {
            "admin": "/admin/dashboard",
            "user": "/dashboard",
            "hr": "/hr/dashboard"
        }.get(role, "/dashboard")

        return jsonify({
            "message": f"{role.capitalize()} login successful",
            "role": role,
            "redirect": redirect_url,
            "access_token": access_token,
            "refresh_token": refresh_token
        }), 200

    except Exception as e:
        logging.error(f"Login error: {e}")
        return jsonify({"error": "Server error"}), 500

    finally:
        if 'conn' in locals():
            conn.close()

# ---- Logout ----
@app.route("/logout", methods=["POST"])
@jwt_required(optional=True)
def logout():
    # Client should send tokens in Authorization header or body; we revoke the incoming token's jti.
    jwt_payload = get_jwt()  # may be None if optional and no token
    if jwt_payload:
        jti = jwt_payload.get("jti")
        JWT_BLOCKLIST.add(jti)
    # Optionally accept token JTIs in body for revoking refresh token too
    data = request.get_json(silent=True) or {}
    refresh_jti = data.get("refresh_jti")
    if refresh_jti:
        JWT_BLOCKLIST.add(refresh_jti)
    return jsonify({"message": "Token revoked (logout)"}), 200

# ---- Refresh endpoint ----
@app.route("/token/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh_access_token():
    identity = get_jwt_identity()
    jti = get_jwt()["jti"]
    JWT_BLOCKLIST.add(jti)  # revoke the old refresh token

    # issue new tokens
    new_access = create_access_token(identity=identity)
    new_refresh = create_refresh_token(identity=identity)

    return jsonify({
        "access_token": new_access,
        "refresh_token": new_refresh
    }), 200


# ---- Dashboards ---
@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    identity = get_jwt_identity() or {}
    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    try:
        # Fetch all users
        cursor.execute("SELECT id, name, email, phone, role, emp_id, department, created_at, status FROM users")
        users = cursor.fetchall()

        # Dashboard metrics
        total_users = len(users)
        active_users = len([u for u in users if u.get("is_active") == 1])
        last_registered_user = None
        if users:
            last_registered_user = max(users, key=lambda u: u.get("created_at", ""))

    finally:
        conn.close()

    return render_template(
        "admin_dashboard.html",
        name=identity.get('name'),
        users=users,
        total_users=total_users,
        active_users=active_users,
        last_registered_user=last_registered_user
    )

@app.route("/hr/dashboard")
@login_required
def hr_dashboard():
    identity = get_jwt_identity() or {}
    if identity.get('role') != 'hr':
        return redirect(url_for('unauthorized'))

    user_dept = identity.get('department')
    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute(
            "SELECT id, name, emp_id, email, phone FROM users WHERE department=%s",
            (user_dept,)
        )
        employees = cursor.fetchall()
    finally:
        conn.close()

    return render_template("hr_dashboard.html", employees=employees, department=user_dept)

@app.route("/dashboard")
@login_required
def user_dashboard():
    identity = get_jwt_identity() or {}
    user_id = identity.get('id')
    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, name, emp_id, email, phone FROM users WHERE id=%s", (user_id,))
        user = cursor.fetchone()
    finally:
        conn.close()

    return render_template("dashboard.html", user=user)

# ---- Admin: list / add users ----
@app.route('/admin/manage', methods=["GET", "POST"])
@admin_required
def manage_users():
    if request.method == "POST":
        data = request.get_json()
        name = data.get("name")
        email = data.get("email")
        phone = data.get("phone")
        department = data.get("department")
        if not name or not email or not phone or not department:
            return jsonify({"error": "Missing fields"}), 400

        emp_id = generate_employee_id()
        temp_password = generate_random_password()
        hashed_password = hash_password(temp_password)

        conn = connect_db()
        cursor = conn.cursor(dictionary=True)
        try:
            cursor.execute("SELECT id FROM users WHERE email=%s OR phone=%s OR name=%s", (email, phone, name))
            if cursor.fetchone():
                return jsonify({"error": "User already exists"}), 400

            cursor.execute(
                "INSERT INTO users (name, email, phone, password_hash, role, emp_id, department) VALUES (%s, %s, %s, %s, %s, %s, %s)",
                (name, email, phone, hashed_password, 'user', emp_id, department)
            )
            conn.commit()
            email_sent = send_credentials_email(email, emp_id, temp_password)
            return jsonify({"message": "User added", "emp_id": emp_id, "email_sent": email_sent}), 200
        finally:
            conn.close()

    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, name, email, phone, role, emp_id, department FROM users")
        users = cursor.fetchall()
    finally:
        conn.close()
    return render_template("users_list.html", users=users)

@app.route("/admin/add_user", methods=["GET", "POST"])
@admin_required
def add_user_by_admin():
    if request.method == "GET":
        return render_template("add_user.html")
    data = request.get_json()
    name = data.get("name")
    email = data.get("email")
    phone = data.get("phone")
    if not name or not email or not phone:
        return jsonify({"error": "Missing fields"}), 400

    emp_id = generate_employee_id()
    temp_password = generate_random_password()
    hashed_password = hash_password(temp_password)

    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id FROM users WHERE email=%s OR phone=%s OR name=%s", (email, phone, name))
        if cursor.fetchone():
            return jsonify({"error": "User already exists"}), 400

        role = data.get("role", "user").lower()
        department = data.get("department")

        if role not in ALLOWED_ROLES:
            return jsonify({"error": "Invalid role"}), 400

        cursor.execute(
            "INSERT INTO users (name, email, phone, password_hash, role, emp_id, department) VALUES (%s, %s, %s, %s, %s, %s, %s)",
            (name, email, phone, hashed_password, role, emp_id, department)
        )

        conn.commit()
        email_sent = send_credentials_email(email, emp_id, temp_password)
        return jsonify({"message": "User added", "email_sent": email_sent}), 200
    finally:
        conn.close()

# ---- Admin: delete user with protections ----
@app.route("/admin/delete_user/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    # Prevent deleting yourself (get current user id from token)
    current_identity = get_jwt_identity() or {}
    current_user_id = current_identity.get("id")

    if user_id == current_user_id:
        return jsonify({"error": "You cannot delete your own account"}), 400

    conn = connect_db()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT id, role FROM users WHERE id=%s", (user_id,))
        target = cur.fetchone()
        if not target:
            return jsonify({"error": "User not found"}), 404

        if target["role"] == "admin" and count_admins(conn) <= 1:
            return jsonify({"error": "Cannot delete the last admin"}), 400

        cur2 = conn.cursor()
        cur2.execute("DELETE FROM users WHERE id=%s", (user_id,))
        conn.commit()
        cur2.close()
        return jsonify({"message": "User deleted successfully."}), 200
    finally:
        cur.close()
        conn.close()

# ---- Admin: roles page & set role endpoint ----
@app.route("/admin/roles", methods=["GET"])
@admin_required
def admin_roles_page():
    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, name, email, phone, role, emp_id FROM users ORDER BY name")
        users = cursor.fetchall()
    finally:
        conn.close()
    return render_template("roles.html", users=users, allowed_roles=sorted(list(ALLOWED_ROLES)))

@app.route("/admin/set_role", methods=["PATCH", "POST"])
@admin_required
def admin_set_role():
    data = request.get_json(force=True)
    user_id = data.get("user_id")
    new_role = data.get("role")
    if not user_id or not new_role:
        return jsonify({"error": "user_id and role are required"}), 400
    if new_role not in ALLOWED_ROLES:
        return jsonify({"error": f"role must be one of {sorted(list(ALLOWED_ROLES))}"}), 400

    conn = connect_db()
    cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT id, role FROM users WHERE id=%s", (user_id,))
        target = cur.fetchone()
        if not target:
            return jsonify({"error": "User not found"}), 404

        # Prevent demoting the last admin
        if target["role"] == "admin" and new_role != "admin":
            if count_admins(conn) <= 1:
                return jsonify({"error": "Cannot remove role: this is the last admin"}), 400

        # Prevent an admin removing their own admin role
        current_identity = get_jwt_identity() or {}
        if target["id"] == current_identity.get("id") and new_role != "admin":
            return jsonify({"error": "Admins cannot remove their own admin role"}), 400

        cur2 = conn.cursor()
        cur2.execute("UPDATE users SET role=%s WHERE id=%s", (new_role, user_id))
        conn.commit()
        cur2.close()
        return jsonify({"message": "Role updated", "user_id": user_id, "role": new_role}), 200
    finally:
        cur.close()
        conn.close()

# ---------------- Forgot / Reset (OTP + reset link) ----------------
# Rate-limited forgot_password (keeps same behavior)
@sleep_and_retry
@limits(calls=3, period=60)  # Limit OTP requests to 3 per minute
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")

    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON data"}), 400

    identifier = data.get("identifier")  # emp_id for users, email for admin , hr
    otp = data.get("otp")  # optional, for verification

    if not identifier:
        return jsonify({"error": "Missing identifier"}), 400

    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    try:
        # Determine if user or admin
        cursor.execute(
            "SELECT id, email, phone, role FROM users WHERE emp_id=%s OR email=%s",
            (identifier, identifier)
        )
        user = cursor.fetchone()
        if not user:
            logging.debug(f"Forgot password: User/Admin not found for identifier={identifier}")
            return jsonify({"error": "User not found"}), 404

        # If OTP provided, verify
        if otp:
            cursor.execute(
                "SELECT * FROM otp_codes WHERE identifier=%s AND expiry_time > NOW()",
                (identifier,)
            )
            record = cursor.fetchone()
            if record and bcrypt.checkpw(otp.encode(), record["otp"].encode()):
                # Generate reset token
                token = secrets.token_urlsafe(32)
                expiry_time = datetime.now() + timedelta(minutes=15)

                cursor.execute("DELETE FROM reset_links WHERE identifier=%s", (identifier,))
                cursor.execute(
                    "INSERT INTO reset_links (identifier, token, expiry_time) VALUES (%s, %s, %s)",
                    (identifier, token, expiry_time)
                )
                conn.commit()

                reset_url = f"http://127.0.0.1:5000/reset_password?token={token}"
                send_reset_link_email(user["email"], reset_url)

                return jsonify({"message": "OTP verified. Reset link sent."}), 200

            return jsonify({"error": "Invalid or expired OTP"}), 400

        # Generate and send new OTP
        new_otp = generate_otp()
        expiry = datetime.now() + timedelta(minutes=10)
        hashed_otp = bcrypt.hashpw(new_otp.encode(), bcrypt.gensalt()).decode()

        cursor.execute("DELETE FROM otp_codes WHERE identifier=%s", (identifier,))
        cursor.execute(
            "INSERT INTO otp_codes (identifier, otp, expiry_time) VALUES (%s, %s, %s)",
            (identifier, hashed_otp, expiry)
        )
        conn.commit()

        sent = send_otp_email(user["email"], new_otp)
        if sent:
            return jsonify({"message": "OTP sent successfully"}), 200
        else:
            logging.error(f"Failed to send OTP to identifier={identifier}")
            return jsonify({"error": "Failed to send OTP. Check email/SMS config."}), 500

    finally:
        conn.close()

@app.route('/reset_password', methods=['GET', 'POST'])
def reset_password():
    if request.method == "GET":
        token = request.args.get("token")
        return render_template("reset_password.html", token=token)

    data = request.get_json()
    token = data.get('token')
    new_password = data.get('new_password')
    if not token or not new_password:
        return jsonify({'error': 'Missing fields'}), 400
    conn = connect_db()
    cursor = conn.cursor()
    try:
        # Get the identifier from reset_links
        cursor.execute("SELECT identifier FROM reset_links WHERE token=%s AND expiry_time > NOW()", (token,))
        row = cursor.fetchone()
        if not row:
            return jsonify({'error': 'Invalid or expired token'}), 400

        identifier = row[0]

        # Fetch the user properly based on role
        cursor.execute("SELECT id, password_hash, role FROM users WHERE emp_id=%s OR email=%s", (identifier, identifier))
        user = cursor.fetchone()
        if not user:
            return jsonify({'error': 'User not found'}), 404

        hashed = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt()).decode()
        cursor.execute("UPDATE users SET password_hash=%s WHERE id=%s", (hashed, user[0]))
        cursor.execute("DELETE FROM reset_links WHERE token=%s", (token,))
        conn.commit()
        return jsonify({'message': 'Password reset successful'})
    finally:
        cursor.close()
        conn.close()

# ---- Static files and template routes ----
@app.route("/static/<path:path>")
def static_files(path):
    return send_from_directory("static", path)

# ---------------- User Profile Update ----------------
@app.route("/dashboard/update_profile", methods=["POST"])
@login_required
def update_profile():
    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON data"}), 400

    name = data.get("name")
    emp_id = data.get("emp_id")
    new_email = data.get("email")
    new_phone = data.get("phone")

    if not name or not emp_id or not new_email or not new_phone:
        return jsonify({"error": "All fields are required"}), 400

    identity = get_jwt_identity() or {}
    user_id = identity.get("id")

    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT email, phone FROM users WHERE id=%s", (user_id,))
        user = cursor.fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404

        # Check if email or phone changed
        email_changed = new_email != user["email"]
        phone_changed = new_phone != user["phone"]

        # If email or phone changed, generate OTP and store in temporary store
        if email_changed or phone_changed:
            otp = generate_otp()
            otp_hash = bcrypt.hashpw(otp.encode(), bcrypt.gensalt()).decode()
            expiry_time = datetime.now() + timedelta(minutes=10)
            PENDING_PROFILE_UPDATES[user_id] = {
                "otp_hash": otp_hash,
                "pending_profile": {"name": name, "emp_id": emp_id, "email": new_email, "phone": new_phone},
                "expiry": expiry_time
            }

            # Send OTP to old email/phone
            sent_email = sent_phone = False
            if email_changed:
                sent_email = send_otp_email(user["email"], otp)

            return jsonify({
                "message": "OTP sent to your current email/phone for confirmation",
                "email_sent": sent_email,
                "sms_sent": sent_phone
            }), 200

        # Otherwise, update directly
        cursor.execute(
            "UPDATE users SET name=%s, emp_id=%s WHERE id=%s",
            (name, emp_id, user_id)
        )
        conn.commit()
        return jsonify({"message": "Profile updated successfully"}), 200
    finally:
        cursor.close()
        conn.close()

@app.route("/dashboard/verify_update_otp", methods=["POST"])
@login_required
def verify_update_otp():
    data = request.get_json()
    if not data or "otp" not in data:
        return jsonify({"error": "Missing OTP"}), 400

    otp_entered = data["otp"]
    identity = get_jwt_identity() or {}
    user_id = identity.get("id")

    record = PENDING_PROFILE_UPDATES.get(user_id)
    if not record:
        return jsonify({"error": "No pending update found"}), 400

    # check expiry
    if datetime.now() > record.get("expiry", datetime.min):
        PENDING_PROFILE_UPDATES.pop(user_id, None)
        return jsonify({"error": "OTP expired"}), 400

    if not bcrypt.checkpw(otp_entered.encode(), record["otp_hash"].encode()):
        return jsonify({"error": "Invalid OTP"}), 400

    pending_profile = record.get("pending_profile")
    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE users SET name=%s, emp_id=%s, email=%s, phone=%s WHERE id=%s",
            (pending_profile["name"], pending_profile["emp_id"],
             pending_profile["email"], pending_profile["phone"], user_id)
        )
        conn.commit()
        # Clear temp data
        PENDING_PROFILE_UPDATES.pop(user_id, None)
        return jsonify({"message": "Profile updated successfully"}), 200
    finally:
        cursor.close()
        conn.close()

# Existing route duplicates: preserve original behavior but ensure no accidental re-definition
# (Your file had two definitions for /forgot_password GET earlier — kept main function above.)

@app.route("/forgot_password", methods=["GET"])
def forgot_password_page():
    return render_template("forgot_password.html")

@app.route("/reset_password", methods=["GET"])
def reset_password_page():
    return render_template("reset_password.html", token=request.args.get("token"))

@app.after_request
def add_security_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, max-age=0'
    response.headers['Pragma'] = 'no-cache'
    response.headers['Expires'] = '0'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'no-referrer'
    response.headers['Strict-Transport-Security'] = 'max-age=31536000; includeSubDomains; preload'

    return response

# ----------------- Run -----------------
if __name__ == "__main__":
    app.run(debug=True)
