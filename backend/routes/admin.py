import logging
import re
import psycopg2.extras
from functools import wraps
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from database import connect_db, count_admins
from utils import is_valid_email, generate_employee_id, generate_random_password, hash_password
from email_service import send_credentials_email

ALLOWED_ROLES = {"user", "admin"}

admin_bp = Blueprint('admin', __name__, url_prefix='/admin')

def admin_required(f):
    @wraps(f)
    @jwt_required()
    def wrapper(*args, **kwargs):
        identity = get_jwt_identity() or {}
        if identity.get("role") != "admin":
            return jsonify({"success": False, "error": "Unauthorized access"}), 403
        return f(*args, **kwargs)
    return wrapper

@admin_bp.route("/dashboard", methods=["GET"])
@admin_required
def admin_dashboard():
    conn = connect_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cursor.execute("SELECT id, name, email, phone, role, emp_id, department, created_at, status FROM users")
        users_records = cursor.fetchall()

        users = [dict(u) for u in users_records]
        total_users = len(users)
        active_users = len([u for u in users if u.get("status") == "active"])
        
        return jsonify({
            "success": True,
            "data": {
                "users": users,
                "total_users": total_users,
                "active_users": active_users
            }
        }), 200
    finally:
        cursor.close()
        conn.close()

@admin_bp.route("/add_user", methods=["POST"])
@admin_required
def add_user():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "error": "Missing JSON data"}), 400

    name = data.get("name")
    email = data.get("email")
    phone = data.get("phone")
    role = data.get("role", "user").lower()
    department = data.get("department")

    if not name or not email or not phone:
        return jsonify({"success": False, "error": "Missing required fields"}), 400
    if not is_valid_email(email):
        return jsonify({"success": False, "error": "Invalid email format"}), 400
    if phone and not re.match(r'^\+?\d{7,15}$', phone):
        return jsonify({"success": False, "error": "Invalid phone number format"}), 400
    if role not in ALLOWED_ROLES:
        return jsonify({"success": False, "error": "Invalid role"}), 400

    conn = connect_db()
    emp_id = generate_employee_id(conn)
    conn.close()
    temp_password = generate_random_password()
    hashed_password = hash_password(temp_password)

    conn = connect_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cursor.execute("SELECT id FROM users WHERE email=%s OR phone=%s", (email, phone))
        if cursor.fetchone():
            return jsonify({"success": False, "error": "User with this email or phone already exists"}), 409

        cursor.execute(
            "INSERT INTO users (name, email, phone, password_hash, role, emp_id, department, status) "
            "VALUES (%s, %s, %s, %s, %s, %s, %s, 'active')",
            (name, email, phone, hashed_password, role, emp_id, department)
        )
        conn.commit()

        email_sent = send_credentials_email(email, emp_id, temp_password)
        return jsonify({"success": True, "message": "User added successfully", "emp_id": emp_id, "email_sent": email_sent}), 201
    except Exception as e:
        conn.rollback()
        logging.error(f"Error adding user: {e}")
        return jsonify({"success": False, "error": "Database error while adding user"}), 500
    finally:
        cursor.close()
        conn.close()

@admin_bp.route("/delete_user/<int:user_id>", methods=["DELETE"])
@admin_required
def delete_user(user_id):
    current_identity = get_jwt_identity() or {}
    if user_id == current_identity.get("id"):
        return jsonify({"success": False, "error": "You cannot delete your own account"}), 400

    conn = connect_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cursor.execute("SELECT id, role FROM users WHERE id=%s", (user_id,))
        target = cursor.fetchone()
        if not target:
            return jsonify({"success": False, "error": "User not found"}), 404

        if target["role"] == "admin" and count_admins(conn) <= 1:
            return jsonify({"success": False, "error": "Cannot delete the last admin"}), 400

        cursor.execute("DELETE FROM users WHERE id=%s", (user_id,))
        conn.commit()
        return jsonify({"success": True, "message": "User deleted successfully."}), 200
    finally:
        cursor.close()
        conn.close()

@admin_bp.route("/set_role", methods=["PATCH"])
@admin_required
def admin_set_role():
    data = request.get_json(force=True, silent=True) or {}
    user_id = data.get("user_id")
    new_role = data.get("role")

    if not user_id or not new_role:
        return jsonify({"success": False, "error": "user_id and role are required"}), 400
    if new_role not in ALLOWED_ROLES:
        return jsonify({"success": False, "error": f"Invalid role. Must be one of {list(ALLOWED_ROLES)}"}), 400

    conn = connect_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cursor.execute("SELECT id, role FROM users WHERE id=%s", (user_id,))
        target = cursor.fetchone()
        if not target:
            return jsonify({"success": False, "error": "User not found"}), 404

        current_identity = get_jwt_identity() or {}
        if target["role"] == "admin" and new_role != "admin":
            if count_admins(conn) <= 1:
                return jsonify({"success": False, "error": "Cannot remove the last admin"}), 400
            if target["id"] == current_identity.get("id"):
                return jsonify({"success": False, "error": "Admins cannot remove their own admin role"}), 400

        cursor.execute("UPDATE users SET role=%s WHERE id=%s", (new_role, user_id))
        conn.commit()
        return jsonify({"success": True, "message": "Role updated successfully", "user_id": user_id, "role": new_role}), 200
    finally:
        cursor.close()
        conn.close()
