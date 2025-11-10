# app.py (Fixed Version)
import logging
import os
import re
import random
import string
import secrets
import json
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, request, jsonify, render_template, redirect, url_for, send_from_directory
)
import bcrypt
import mysql.connector as mysql
import smtplib
from email.mime.text import MIMEText
# Removed unused Twilio import
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

app.config["JWT_SECRET_KEY"] = os.getenv("JWT_SECRET_KEY", os.getenv("SECRET_KEY", "fallback_dev_key"))
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=1)
app.config["JWT_TOKEN_LOCATION"] = ["headers", "cookies"]
app.config["JWT_IDENTITY_CLAIM"] = "identity"
jwt = JWTManager(app)

ALLOWED_ROLES = {"user", "admin", "hr"}

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

# ---------------- Email ----------------
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
        # Note: smtp.gmail.com often blocks these attempts. Consider SendGrid/Mailgun for production.
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

# ---------------- JWT blocklist (DB-backed) ----------------
@jwt.token_in_blocklist_loader
def check_if_token_revoked(jwt_header, jwt_payload):
    jti = jwt_payload["jti"]
    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT jti FROM token_blocklist WHERE jti=%s", (jti,))
        return cursor.fetchone() is not None
    finally:
        cursor.close()
        conn.close()

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

# ---------------- Decorators ----------------
def login_required(f):
    @wraps(f)
    @jwt_required()
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    @jwt_required()
    def wrapper(*args, **kwargs):
        identity = get_jwt_identity() or {}
        if identity.get("role") != "admin":
            # Redirects to the now-existent unauthorized route
            return redirect(url_for('unauthorized'))
        return f(*args, **kwargs)
    return wrapper

# ---------------- Routes ----------------
@app.route("/")
def root():
    return redirect(url_for("login_user"))

@app.route("/unauthorized")
def unauthorized():
    return render_template("unauthorized.html") if os.path.exists("templates/unauthorized.html") else jsonify({"error": "Unauthorized access"}), 403

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
        try:
            cursor.execute(
                "SELECT * FROM users WHERE emp_id=%s OR email=%s LIMIT 1",
                (identifier, identifier)
            )
            user = cursor.fetchone()

            if not user:
                return jsonify({"error": "Invalid credentials"}), 401

            if not check_password(user["password_hash"], password):
                return jsonify({"error": "Invalid credentials"}), 401

            # FIX: Ensure we are using the correct status column name.
            # Assuming 'status' based on previous code usage.
            if user.get("status") != "active":
                cursor.execute("UPDATE users SET status='active' WHERE id=%s", (user["id"],))
                conn.commit()

            role = user["role"].lower()
            identity = {
                "id": user["id"],
                "role": role,
                "name": user.get("name"),
                "department": user.get("department")
            }

            access_token = create_access_token(identity=identity)
            refresh_token = create_refresh_token(identity=identity)

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
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        logging.error(f"Login error: {e}")
        return jsonify({"error": "Server error"}), 500

# ---- Logout (DB-backed) ----
@app.route("/logout", methods=["POST"])
@jwt_required(optional=True)
def logout():
    jwt_payload = get_jwt()
    jtis_to_revoke = []
    if jwt_payload:
        jtis_to_revoke.append(jwt_payload["jti"])

    data = request.get_json(silent=True) or {}
    refresh_jti = data.get("refresh_jti")
    if refresh_jti:
        jtis_to_revoke.append(refresh_jti)

    if jtis_to_revoke:
        conn = connect_db()
        cursor = conn.cursor()
        try:
            cursor.executemany(
                "INSERT IGNORE INTO token_blocklist (jti) VALUES (%s)",
                [(jti,) for jti in jtis_to_revoke]
            )
            conn.commit()
        finally:
            cursor.close()
            conn.close()

    return jsonify({"message": "Logged out successfully"}), 200

# ---- Refresh endpoint ----
@app.route("/token/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh_access_token():
    identity = get_jwt_identity()
    jti = get_jwt()["jti"]

    # Revoke old refresh token
    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT IGNORE INTO token_blocklist (jti) VALUES (%s)", (jti,))
        conn.commit()
    finally:
        cursor.close()
        conn.close()

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
        cursor.execute("SELECT id, name, email, phone, role, emp_id, department, created_at, status FROM users")
        users = cursor.fetchall()

        total_users = len(users)
        # FIX: Use 'status' column instead of 'is_active' to match login logic
        active_users = len([u for u in users if u.get("status") == "active"])
        last_registered_user = max(users, key=lambda u: u.get("created_at") or datetime.min) if users else None

    finally:
        cursor.close() # Ensure cursor is closed
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
        cursor.close()
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
        cursor.execute("SELECT id, name, emp_id, email, phone, department, role , status FROM users WHERE id=%s", (user_id,))
        user = cursor.fetchone()
    finally:
        cursor.close()
        conn.close()

    return render_template("dashboard.html", user=user)

# ---- Admin: User Management ----
# FIX: Consolidated 'manage' to just be the list view
@app.route('/admin/manage', methods=["GET"])
@admin_required
def manage_users():
    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, name, email, phone, role, emp_id, department, status FROM users")
        users = cursor.fetchall()
    finally:
        cursor.close()
        conn.close()
    return render_template("users_list.html", users=users)

# FIX: Unified user addition into one robust route
@app.route("/admin/add_user", methods=["GET", "POST"])
@admin_required
def add_user():
    if request.method == "GET":
        return render_template("add_user.html")

    data = request.get_json()
    if not data:
         return jsonify({"error": "Missing JSON data"}), 400

    name = data.get("name")
    email = data.get("email")
    phone = data.get("phone")
    role = data.get("role", "user").lower()
    department = data.get("department")

    if not name or not email or not phone:
        return jsonify({"error": "Missing required fields"}), 400
    if role not in ALLOWED_ROLES:
        return jsonify({"error": "Invalid role"}), 400

    emp_id = generate_employee_id()
    temp_password = generate_random_password()
    hashed_password = hash_password(temp_password)

    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    try:
        # Check for existing user
        cursor.execute("SELECT id FROM users WHERE email=%s OR phone=%s", (email, phone))
        if cursor.fetchone():
            return jsonify({"error": "User with this email or phone already exists"}), 409

        cursor.execute(
            "INSERT INTO users (name, email, phone, password_hash, role, emp_id, department, status) VALUES (%s, %s, %s, %s, %s, %s, %s, 'active')",
            (name, email, phone, hashed_password, role, emp_id, department)
        )
        conn.commit()

        email_sent = send_credentials_email(email, emp_id, temp_password)
        return jsonify({"message": "User added successfully", "emp_id": emp_id, "email_sent": email_sent}), 201
    except Exception as e:
        conn.rollback()
        logging.error(f"Error adding user: {e}")
        return jsonify({"error": "Database error while adding user"}), 500
    finally:
        cursor.close()
        conn.close()

@app.route("/admin/delete_user/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    current_identity = get_jwt_identity() or {}
    if user_id == current_identity.get("id"):
        return jsonify({"error": "You cannot delete your own account"}), 400

    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, role FROM users WHERE id=%s", (user_id,))
        target = cursor.fetchone()
        if not target:
            return jsonify({"error": "User not found"}), 404

        if target["role"] == "admin" and count_admins(conn) <= 1:
            return jsonify({"error": "Cannot delete the last admin"}), 400

        cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
        conn.commit()
        return jsonify({"message": "User deleted successfully."}), 200
    finally:
        cursor.close()
        conn.close()

@app.route("/admin/roles", methods=["GET"])
@admin_required
def admin_roles_page():
    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, name, email, role FROM users ORDER BY name")
        users = cursor.fetchall()
    finally:
        cursor.close()
        conn.close()
    return render_template("roles.html", users=users, allowed_roles=sorted(list(ALLOWED_ROLES)))

@app.route("/admin/set_role", methods=["PATCH", "POST"])
@admin_required
def admin_set_role():
    # Support both standard JSON and force=True if content-type is wrong
    data = request.get_json(silent=True) or request.get_json(force=True)
    user_id = data.get("user_id")
    new_role = data.get("role")

    if not user_id or not new_role:
        return jsonify({"error": "user_id and role are required"}), 400
    if new_role not in ALLOWED_ROLES:
        return jsonify({"error": f"Invalid role. Must be one of {list(ALLOWED_ROLES)}"}), 400

    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, role FROM users WHERE id=%s", (user_id,))
        target = cursor.fetchone()
        if not target:
            return jsonify({"error": "User not found"}), 404

        current_identity = get_jwt_identity() or {}
        # Prevent last admin demotion
        if target["role"] == "admin" and new_role != "admin":
            if count_admins(conn) <= 1:
                return jsonify({"error": "Cannot remove the last admin"}), 400
            # Prevent self-demotion
            if target["id"] == current_identity.get("id"):
                 return jsonify({"error": "Admins cannot remove their own admin role"}), 400

        cursor.execute("UPDATE users SET role=%s WHERE id=%s", (new_role, user_id))
        conn.commit()
        return jsonify({"message": "Role updated successfully", "user_id": user_id, "role": new_role}), 200
    finally:
        cursor.close()
        conn.close()

# ---------------- Forgot / Reset ----------------
@sleep_and_retry
@limits(calls=3, period=60)
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")

    data = request.get_json()
    if not data:
         return jsonify({"error": "Missing data"}), 400
    identifier = data.get("identifier")
    otp = data.get("otp")

    if not identifier:
        return jsonify({"error": "Missing identifier"}), 400

    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT id, email FROM users WHERE emp_id=%s OR email=%s", (identifier, identifier))
        user = cursor.fetchone()
        if not user:
            return jsonify({"error": "User not found"}), 404

        if otp:
            # Verify OTP
            cursor.execute("SELECT otp, expiry_time FROM otp_codes WHERE identifier=%s AND expiry_time > NOW()", (identifier,))
            record = cursor.fetchone()

            if record and bcrypt.checkpw(otp.encode(), record["otp"].encode()):
                token = secrets.token_urlsafe(32)
                expiry_time = datetime.now() + timedelta(minutes=15)

                cursor.execute("DELETE FROM reset_links WHERE identifier=%s", (identifier,))
                cursor.execute("INSERT INTO reset_links (identifier, token, expiry_time) VALUES (%s, %s, %s)",
                               (identifier, token, expiry_time))
                # Clean up used OTP
                cursor.execute("DELETE FROM otp_codes WHERE identifier=%s", (identifier,))
                conn.commit()

                # FIX: Use full external URL for production, here using localhost as placeholder
                reset_url = url_for('reset_password', token=token, _external=True)
                send_reset_link_email(user["email"], reset_url)
                return jsonify({"message": "OTP verified. Reset link sent to email."}), 200
            return jsonify({"error": "Invalid or expired OTP"}), 400

        # Generate OTP
        new_otp = generate_otp()
        hashed_otp = bcrypt.hashpw(new_otp.encode(), bcrypt.gensalt()).decode()
        expiry = datetime.now() + timedelta(minutes=10)

        cursor.execute("DELETE FROM otp_codes WHERE identifier=%s", (identifier,))
        cursor.execute("INSERT INTO otp_codes (identifier, otp, expiry_time) VALUES (%s, %s, %s)",
                       (identifier, hashed_otp, expiry))
        conn.commit()

        if send_otp_email(user["email"], new_otp):
            return jsonify({"message": "OTP sent successfully"}), 200
        return jsonify({"error": "Failed to send OTP email"}), 500
    finally:
        cursor.close()
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
        return jsonify({'error': 'Missing token or password'}), 400
    if not is_strong_password(new_password):
         return jsonify({'error': 'Password does not meet complexity requirements'}), 400

    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute("SELECT identifier FROM reset_links WHERE token=%s AND expiry_time > NOW()", (token,))
        row = cursor.fetchone()
        if not row:
            return jsonify({'error': 'Invalid or expired token'}), 400
        identifier = row[0]

        hashed = hash_password(new_password)
        # Update user by identifier (supports both email/emp_id based on how it was stored)
        cursor.execute("UPDATE users SET password_hash=%s WHERE emp_id=%s OR email=%s", (hashed, identifier, identifier))
        cursor.execute("DELETE FROM reset_links WHERE token=%s", (token,))
        conn.commit()
        return jsonify({'message': 'Password reset successful'}), 200
    finally:
        cursor.close()
        conn.close()

# ---------------- User Profile Update (DB-backed) ----------------
@app.route("/dashboard/update_profile", methods=["POST"])
@login_required
def update_profile():
    data = request.get_json()
    if not data:
         return jsonify({"error": "Missing data"}), 400

    # Extract and validate
    pending_profile = {
        "name": data.get("name"),
        "emp_id": data.get("emp_id"),
        "email": data.get("email"),
        "phone": data.get("phone")
    }
    if not all(pending_profile.values()):
        return jsonify({"error": "All fields are required"}), 400

    identity = get_jwt_identity()
    user_id = identity["id"]

    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT email, phone FROM users WHERE id=%s", (user_id,))
        current_user = cursor.fetchone()
        if not current_user:
             return jsonify({"error": "User not found"}), 404

        email_changed = pending_profile["email"] != current_user["email"]
        phone_changed = pending_profile["phone"] != current_user["phone"]

        if email_changed or phone_changed:
            otp = generate_otp()
            otp_hash = hash_password(otp)
            expiry = datetime.now() + timedelta(minutes=10)
            profile_json = json.dumps(pending_profile)

            # UPSERT into pending_profile_updates
            cursor.execute("""
                INSERT INTO pending_profile_updates (user_id, otp_hash, pending_data, expiry)
                VALUES (%s, %s, %s, %s)
                ON DUPLICATE KEY UPDATE otp_hash=VALUES(otp_hash), pending_data=VALUES(pending_data), expiry=VALUES(expiry)
            """, (user_id, otp_hash, profile_json, expiry))
            conn.commit()

            # Send OTP to OLD email for security
            if email_changed:
                 send_otp_email(current_user["email"], otp)

            return jsonify({"message": "Sensitive changes detected. OTP sent to current email.", "require_otp": True}), 200

        # No sensitive changes, update immediately
        cursor.execute(
            "UPDATE users SET name=%s, emp_id=%s WHERE id=%s",
            (pending_profile["name"], pending_profile["emp_id"], user_id)
        )
        conn.commit()
        return jsonify({"message": "Profile updated successfully", "require_otp": False}), 200
    finally:
        cursor.close()
        conn.close()

@app.route("/dashboard/verify_update_otp", methods=["POST"])
@login_required
def verify_update_otp():
    data = request.get_json()
    otp_entered = data.get("otp")
    if not otp_entered:
        return jsonify({"error": "Missing OTP"}), 400

    user_id = get_jwt_identity()["id"]
    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT * FROM pending_profile_updates WHERE user_id=%s", (user_id,))
        record = cursor.fetchone()

        if not record:
            return jsonify({"error": "No pending update found"}), 404
        if datetime.now() > record["expiry"]:
            cursor.execute("DELETE FROM pending_profile_updates WHERE user_id=%s", (user_id,))
            conn.commit()
            return jsonify({"error": "OTP expired"}), 400
        if not check_password(record["otp_hash"], otp_entered):
            return jsonify({"error": "Invalid OTP"}), 400

        # Apply updates
        updates = json.loads(record["pending_data"]) # Ensure your DB supports JSON or text for this
        cursor.execute(
            "UPDATE users SET name=%s, emp_id=%s, email=%s, phone=%s WHERE id=%s",
            (updates["name"], updates["emp_id"], updates["email"], updates["phone"], user_id)
        )
        cursor.execute("DELETE FROM pending_profile_updates WHERE user_id=%s", (user_id,))
        conn.commit()
        return jsonify({"message": "Profile updated successfully"}), 200
    finally:
        cursor.close()
        conn.close()

@app.route("/static/<path:path>")
def static_files(path):
    return send_from_directory("static", path)

@app.after_request
def add_security_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, max-age=0'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    return response

if __name__ == "__main__":
    app.run(debug=True)