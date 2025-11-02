# app.py
import logging
import os
import re
import random
import string
import secrets
from datetime import datetime, timedelta
from functools import wraps

from flask import (
    Flask, request, jsonify, render_template, session, redirect, url_for, send_from_directory
)
import bcrypt
import mysql.connector as mysql
import smtplib
from email.mime.text import MIMEText
from twilio.rest import Client
from dotenv import load_dotenv
from ratelimit import limits, sleep_and_retry

# ---------------- Config ----------------
logging.basicConfig(level=logging.DEBUG, format='%(asctime)s - %(levelname)s - %(message)s')

app = Flask(__name__)
load_dotenv(os.path.join(os.path.dirname(__file__), "credentials.env"))
app.secret_key = os.getenv("SECRET_KEY", "fallback_dev_key")

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
    return len(password) >= 8 and any(char.isdigit() for char in password) and any(not char.isalnum() for char in password)

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

def send_sms(to_phone, body):
    sid = os.getenv("TWILIO_SID")
    token = os.getenv("TWILIO_TOKEN")
    from_phone = os.getenv("TWILIO_PHONE")
    if not sid or not token or not from_phone:
        logging.error("Twilio config missing")
        return False
    try:
        client = Client(sid, token)
        client.messages.create(body=body, from_=from_phone, to=to_phone)
        logging.info(f"SMS sent to {to_phone}")
        return True
    except Exception as e:
        logging.error(f"Failed to send SMS to {to_phone}: {e}")
        return False

def send_otp_email(email, otp):
    return send_email(email, "Your OTP code", f"Your OTP code is: {otp}")

def send_otp_sms(phone, otp):
    return send_sms(phone, f"Your OTP code is: {otp}")

def send_reset_link_email(email, link):
    return send_email(email, "Reset Your Password", f"Reset link: {link}")

def send_reset_link_sms(phone, link):
    return send_sms(phone, f"Reset your password: {link}")

def send_credentials_email(email, emp_id, password):
    return send_email(email, "Your Account Credentials", f"Welcome!\n\nYour employee ID: {emp_id}\nYour temporary password: {password}")

def send_credentials_sms(phone, emp_id, password):
    return send_sms(phone, f"Your ID: {emp_id}, Temp Password: {password}")

# ---------------- Decorators ----------------
def login_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if not session.get('user_id'):
            return redirect(url_for('login_user'))
        return f(*args, **kwargs)
    return wrapper

def admin_required(f):
    @wraps(f)
    def wrapper(*args, **kwargs):
        if session.get('role') != 'admin':
            return redirect(url_for('unauthorized'))
        return f(*args, **kwargs)
    return wrapper

# ---------------- Routes ----------------
@app.route("/")
def root():
    return redirect(url_for("login_user"))


# ---- Login ----
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
        role = data.get("role", "").strip().lower()

        if not identifier or not password or not role:
            return jsonify({"error": "Missing identifier, password, or role"}), 400

        conn = connect_db()
        cursor = conn.cursor(dictionary=True)

        # 🔹 Correct SQL logic — restrict role for both conditions
        if role == "admin":
            cursor.execute(
                "SELECT * FROM users WHERE email=%s AND role='admin' LIMIT 1",
                (identifier,)
            )
        elif role == "user":
            cursor.execute(
                "SELECT * FROM users WHERE emp_id=%s AND role='user' LIMIT 1",
                (identifier,)
            )
        elif role == "hr":
            cursor.execute(
                "SELECT * FROM users WHERE email=%s AND role='hr' LIMIT 1",
                (identifier,)
            )
        else:
            return jsonify({"error": "Invalid role"}), 400

        user = cursor.fetchone()

        if not user:
            return jsonify({"error": f"{role.capitalize()} not found"}), 401

        # ✅ Verify password hash
        if not check_password(user["password_hash"], password):
            return jsonify({"error": "Invalid credentials"}), 401

        # ✅ Store session
        session["user_id"] = user["id"]
        session["name"] = user["name"]
        session["role"] = user["role"]
        session["department"] = user.get("department")

        # ✅ Redirect URLs based on role
        redirect_url = {
            "admin": "/admin/dashboard",
            "user": "/dashboard",
            "hr": "/hr/dashboard"
        }.get(role, "/dashboard")

        return jsonify({
            "message": f"{role.capitalize()} login successful",
            "role": role,
            "redirect": redirect_url
        }), 200

    except Exception as e:
        logging.error(f"Login error: {e}")
        return jsonify({"error": "Server error"}), 500

    finally:
        if 'conn' in locals():
            conn.close()


# ---- Logout ----
@app.route("/logout")
def logout():
    session.clear()
    return redirect(url_for("login_user"))



# ---- Dashboards ---
@app.route("/admin/dashboard")
@admin_required
def admin_dashboard():
    conn = connect_db()
    cursor = conn.cursor(dictionary=True)
    try:
        # Fetch all users
        cursor.execute("SELECT id, name, email, phone, role, emp_id, department, created_at, is_active FROM users")
        users = cursor.fetchall()

        # --- Dashboard metrics ---
        total_users = len(users)

        # Active users (assuming 'is_active' = 1 means active)
        active_users = len([u for u in users if u.get("is_active") == 1])

        # Last registered user (by created_at)
        last_registered_user = None
        if users:
            last_registered_user = max(users, key=lambda u: u.get("created_at", ""))
    finally:
        conn.close()

    return render_template(
        "admin_dashboard.html",
        name=session.get('name'),
        users=users,
        total_users=total_users,
        active_users=active_users,
        last_registered_user=last_registered_user
    )


@app.route("/hr/dashboard")
@login_required
def hr_dashboard():
    if session.get('role') != 'hr':
        return redirect(url_for('unauthorized'))

    user_dept = session.get('department')
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
    user_id = session.get('user_id')
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
            sms_sent = send_credentials_sms(phone, emp_id, temp_password)
            return jsonify({"message": "User added", "emp_id": emp_id, "email_sent": email_sent, "sms_sent": sms_sent}), 200
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

        cursor.execute(
            "INSERT INTO users (name, email, phone, password_hash, role, emp_id) VALUES (%s, %s, %s, %s, %s, %s)",
            (name, email, phone, hashed_password, 'user', emp_id)
        )
        conn.commit()
        email_sent = send_credentials_email(email, emp_id, temp_password)
        sms_sent = send_credentials_sms(phone, emp_id, temp_password)
        return jsonify({"message": "User added", "email_sent": email_sent, "sms_sent": sms_sent}), 200
    finally:
        conn.close()

# ---- Admin: delete user with protections ----
@app.route("/admin/delete_user/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    # Prevent deleting yourself
    if user_id == session.get("user_id"):
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
        if target["id"] == session.get("user_id") and new_role != "admin":
            return jsonify({"error": "Admins cannot remove their own admin role"}), 400

        cur2 = conn.cursor()
        cur2.execute("UPDATE users SET role=%s WHERE id=%s", (new_role, user_id))
        conn.commit()
        cur2.close()
        return jsonify({"message": "Role updated", "user_id": user_id, "role": new_role}), 200
    finally:
        cur.close()
        conn.close()

    return "403 Unauthorized - Admins only", 403

# ---------------- Forgot / Reset (OTP + reset link) ----------------
@sleep_and_retry
@limits(calls=3, period=60)  # Limit OTP requests to 3 per minute
@app.route("/forgot_password", methods=["GET", "POST"])
def forgot_password():
    if request.method == "GET":
        return render_template("forgot_password.html")

    data = request.get_json()
    if not data:
        return jsonify({"error": "Missing JSON data"}), 400

    identifier = data.get("identifier")  # emp_id for users, email for admin
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
                if user["role"] == "user":
                    send_reset_link_email(user["email"], reset_url)
                else:
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

        # Send OTP to registered email only
        sent = False
        if user["role"] == "user":
            sent = send_otp_email(user["email"], new_otp)
            logging.debug(f"Email sent to user {user['email']}: {sent}")
        else:  # admin
            sent = send_otp_email(user["email"], new_otp)
            logging.debug(f"Email sent to admin {user['email']}: {sent}")

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

    user_id = session.get("user_id")
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

        # If email or phone changed, generate OTP and store in session temporarily
        if email_changed or phone_changed:
            otp = generate_otp()
            session["update_profile_otp"] = bcrypt.hashpw(otp.encode(), bcrypt.gensalt()).decode()
            session["pending_profile"] = {"name": name, "emp_id": emp_id, "email": new_email, "phone": new_phone}

            # Send OTP to old email/phone
            sent_email = sent_phone = False
            if email_changed:
                sent_email = send_otp_email(user["email"], otp)
            if phone_changed:
                sent_phone = send_otp_sms(user["phone"], otp)

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
    hashed_otp = session.get("update_profile_otp")
    pending_profile = session.get("pending_profile")

    if not hashed_otp or not pending_profile:
        return jsonify({"error": "No pending update found"}), 400

    if not bcrypt.checkpw(otp_entered.encode(), hashed_otp.encode()):
        return jsonify({"error": "Invalid OTP"}), 400

    # Update user profile
    user_id = session.get("user_id")
    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "UPDATE users SET name=%s, emp_id=%s, email=%s, phone=%s WHERE id=%s",
            (pending_profile["name"], pending_profile["emp_id"],
             pending_profile["email"], pending_profile["phone"], user_id)
        )
        conn.commit()

        # Clear session temporary data
        session.pop("update_profile_otp", None)
        session.pop("pending_profile", None)

        return jsonify({"message": "Profile updated successfully"}), 200
    finally:
        cursor.close()
        conn.close()


@app.route("/forgot_password", methods=["GET"])
def forgot_password_page():
    return render_template("forgot_password.html")

@app.route("/reset_password", methods=["GET"])
def reset_password_page():
    return render_template("reset_password.html", token=request.args.get("token"))

# ----------------- Run -----------------
if __name__ == "__main__":
    app.run(debug=True)
