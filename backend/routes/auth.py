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

from database import connect_db, get_dict_cursor, is_mysql
from utils import is_valid_email, is_strong_password, hash_password, check_password

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
        cursor = get_dict_cursor(conn)
        try:
            cursor.execute("SELECT id FROM users WHERE email=%s OR phone=%s", (email, phone))
            if cursor.fetchone():
                return jsonify({"success": False, "error": "User with this email or phone already exists"}), 409

            hashed_password = hash_password(password)
            role = "user"

            cursor.execute(
                "INSERT INTO users (name, email, phone, password_hash, role, status) "
                "VALUES (%s, %s, %s, %s, %s, 'active')",
                (name, email, phone, hashed_password, role)
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

        email = (data.get("email") or data.get("identifier") or "").strip().lower()
        password = data.get("password", "").strip()

        if not email or not password:
            return jsonify({"success": False, "error": "Missing email or password"}), 400

        conn = connect_db()
        cursor = get_dict_cursor(conn)
        try:
            cursor.execute(
                "SELECT * FROM users WHERE email=%s LIMIT 1",
                (email,)
            )
            user = cursor.fetchone()

            if not user or not check_password(user["password_hash"], password):
                return jsonify({"success": False, "error": "Invalid email or password"}), 401

            if user.get("status") != "active":
                return jsonify({"success": False, "error": "Account is deactivated. Contact support."}), 403

            role = (user.get("role") or "user").lower()
            if role not in ("user", "admin"):
                role = "user"

            identity = {
                "id": user["id"],
                "role": role,
                "name": user.get("name"),
                "email": user.get("email")
            }

            access_token = create_access_token(identity=identity)
            refresh_token = create_refresh_token(identity=identity)

            response = jsonify({
                "success": True,
                "message": "Login successful",
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

@auth_bp.route("/me", methods=["GET"])
@jwt_required()
def get_current_user():
    try:
        identity = get_jwt_identity() or {}
        user_id = identity.get("id")
        if not user_id:
            return jsonify({"success": False, "error": "Invalid token identity"}), 401

        conn = connect_db()
        cursor = get_dict_cursor(conn)
        try:
            cursor.execute(
                "SELECT id, name, email, phone, role, status, created_at FROM users WHERE id=%s",
                (user_id,)
            )
            user = cursor.fetchone()
            if not user:
                return jsonify({"success": False, "error": "User not found"}), 404
            if user.get("status") != "active":
                return jsonify({"success": False, "error": "Account deactivated"}), 403

            role = (user.get("role") or "user").lower()
            if role not in ("user", "admin"):
                role = "user"

            user_data = {
                "id": user["id"],
                "name": user.get("name"),
                "email": user.get("email"),
                "phone": user.get("phone"),
                "role": role,
                "status": user.get("status"),
                "created_at": str(user.get("created_at")) if user.get("created_at") else None
            }
            return jsonify({"success": True, "user": user_data, "role": role}), 200
        finally:
            cursor.close()
            conn.close()
    except Exception as e:
        logging.error(f"Error fetching current user: {e}")
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
            sql = "INSERT IGNORE INTO token_blocklist (jti) VALUES (%s)" if is_mysql(conn) else "INSERT INTO token_blocklist (jti) VALUES (%s) ON CONFLICT (jti) DO NOTHING"
            cursor.executemany(sql, [(jti,) for jti in jtis_to_revoke])
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
        sql = "INSERT IGNORE INTO token_blocklist (jti) VALUES (%s)" if is_mysql(conn) else "INSERT INTO token_blocklist (jti) VALUES (%s) ON CONFLICT (jti) DO NOTHING"
        cursor.execute(sql, (jti,))
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
