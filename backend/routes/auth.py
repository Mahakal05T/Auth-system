import logging
import psycopg2.extras
from flask import Blueprint, request, jsonify
from ratelimit import limits
from flask_jwt_extended import (
    create_access_token, create_refresh_token,
    jwt_required, get_jwt_identity, get_jwt,
    set_access_cookies, set_refresh_cookies, unset_jwt_cookies,
    verify_jwt_in_request
)

from database import connect_db
from utils import is_valid_email, is_strong_password, generate_employee_id, hash_password, check_password

auth_bp = Blueprint('auth', __name__)

@auth_bp.route("/register", methods=["POST"])
@limits(calls=5, period=60)
def register_user():
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"success": False, "error": "Missing JSON data"}), 400

        name = data.get("name", "").strip()
        email = data.get("email", "").strip()
        phone = data.get("phone", "").strip()
        password = data.get("password", "").strip()

        if not name or not email or not phone or not password:
            return jsonify({"success": False, "error": "Missing required fields"}), 400
            
        if not is_valid_email(email):
            return jsonify({"success": False, "error": "Invalid email format"}), 400
            
        if not is_strong_password(password):
            return jsonify({"success": False, "error": "Password does not meet complexity requirements"}), 400

        conn = connect_db()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        try:
            cursor.execute("SELECT id FROM users WHERE email=%s OR phone=%s", (email, phone))
            if cursor.fetchone():
                return jsonify({"success": False, "error": "User with this email or phone already exists"}), 409

            emp_id = generate_employee_id(conn)
            hashed_password = hash_password(password)
            role = "user"
            department = "Unassigned"

            cursor.execute(
                "INSERT INTO users (name, email, phone, password_hash, role, emp_id, department, status) "
                "VALUES (%s, %s, %s, %s, %s, %s, %s, 'active')",
                (name, email, phone, hashed_password, role, emp_id, department)
            )
            conn.commit()

            return jsonify({"success": True, "message": "Registration successful. You can now login."}), 201
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        logging.error(f"Registration error: {e}")
        return jsonify({"success": False, "error": "Server error"}), 500

@auth_bp.route("/login", methods=["POST"])
@limits(calls=5, period=60)
def login_user():
    try:
        data = request.get_json(silent=True)
        if not data:
            return jsonify({"success": False, "error": "Missing JSON data"}), 400

        identifier = data.get("identifier", "").strip()
        password = data.get("password", "").strip()

        if not identifier or not password:
            return jsonify({"success": False, "error": "Missing identifier or password"}), 400

        conn = connect_db()
        cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
        try:
            cursor.execute(
                "SELECT * FROM users WHERE emp_id=%s OR email=%s LIMIT 1",
                (identifier, identifier)
            )
            user = cursor.fetchone()

            if not user or not check_password(user["password_hash"], password):
                return jsonify({"success": False, "error": "Invalid credentials"}), 401

            if user.get("status") != "active":
                return jsonify({"success": False, "error": "Account is deactivated. Contact administrator."}), 403

            role = user["role"].lower()
            identity = {
                "id": user["id"],
                "role": role,
                "name": user.get("name"),
                "department": user.get("department")
            }

            access_token = create_access_token(identity=identity)
            refresh_token = create_refresh_token(identity=identity)

            response = jsonify({
                "success": True,
                "message": f"{role.capitalize()} login successful",
                "role": role,
                "user": identity
            })
            set_access_cookies(response, access_token)
            set_refresh_cookies(response, refresh_token)

            return response, 200
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        logging.error(f"Login error: {e}")
        return jsonify({"success": False, "error": "Server error"}), 500

@auth_bp.route("/logout", methods=["POST"])
def logout():
    jtis_to_revoke = []

    try:
        verify_jwt_in_request(optional=True)
        jwt_payload = get_jwt()
    except Exception:
        jwt_payload = None

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
                "INSERT INTO token_blocklist (jti) VALUES (%s) ON CONFLICT (jti) DO NOTHING",
                [(jti,) for jti in jtis_to_revoke]
            )
            conn.commit()
        finally:
            cursor.close()
            conn.close()

    response = jsonify({"success": True, "message": "Logged out"})
    unset_jwt_cookies(response)
    return response, 200

@auth_bp.route("/token/refresh", methods=["POST"])
@jwt_required(refresh=True)
def refresh_access_token():
    identity = get_jwt_identity()
    jti = get_jwt()["jti"]

    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute("INSERT INTO token_blocklist (jti) VALUES (%s) ON CONFLICT (jti) DO NOTHING", (jti,))
        conn.commit()
    finally:
        cursor.close()
        conn.close()

    new_access = create_access_token(identity=identity)
    new_refresh = create_refresh_token(identity=identity)

    response = jsonify({
        "success": True,
        "access_token": new_access,
        "refresh_token": new_refresh
    })
    set_access_cookies(response, new_access)
    set_refresh_cookies(response, new_refresh)
    return response, 200
