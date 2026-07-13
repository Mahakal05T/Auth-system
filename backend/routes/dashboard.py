import json
import logging
from datetime import datetime, timedelta
from functools import wraps

import psycopg2.extras
from flask import Blueprint, request, jsonify
from flask_jwt_extended import jwt_required, get_jwt_identity

from database import connect_db
from utils import generate_otp, hash_password, check_password
from email_service import send_otp_email

dashboard_bp = Blueprint('dashboard', __name__, url_prefix='/dashboard')

def login_required(f):
    @wraps(f)
    @jwt_required()
    def wrapper(*args, **kwargs):
        return f(*args, **kwargs)
    return wrapper

@dashboard_bp.route("", methods=["GET"])
@login_required
def user_dashboard():
    identity = get_jwt_identity() or {}
    user_id = identity.get('id')
    conn = connect_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cursor.execute(
            "SELECT id, name, emp_id, email, phone, department, role, status, created_at "
            "FROM users WHERE id=%s",
            (user_id,)
        )
        user = cursor.fetchone()
        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404
        return jsonify({"success": True, "data": {"user": dict(user)}}), 200
    finally:
        cursor.close()
        conn.close()

@dashboard_bp.route("/update_profile", methods=["POST"])
@login_required
def update_profile():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "error": "Missing data"}), 400

    pending_profile = {
        "name": data.get("name"),
        "email": data.get("email"),
        "phone": data.get("phone")
    }
    if not all(pending_profile.values()):
        return jsonify({"success": False, "error": "All fields are required"}), 400

    identity = get_jwt_identity()
    user_id = identity["id"]

    conn = connect_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cursor.execute("SELECT email, phone FROM users WHERE id=%s", (user_id,))
        current_user = cursor.fetchone()
        if not current_user:
            return jsonify({"success": False, "error": "User not found"}), 404

        email_changed = pending_profile["email"] != current_user["email"]
        phone_changed = pending_profile["phone"] != current_user["phone"]

        if email_changed or phone_changed:
            otp = generate_otp()
            otp_hash = hash_password(otp)
            expiry = datetime.now() + timedelta(minutes=10)
            profile_json = json.dumps(pending_profile)

            cursor.execute("""
                INSERT INTO pending_profile_updates (user_id, otp_hash, pending_data, expiry)
                VALUES (%s, %s, %s, %s)
                ON CONFLICT (user_id) DO UPDATE SET 
                    otp_hash=EXCLUDED.otp_hash,
                    pending_data=EXCLUDED.pending_data,
                    expiry=EXCLUDED.expiry
            """, (user_id, otp_hash, profile_json, expiry))
            conn.commit()

            if email_changed or phone_changed:
                send_otp_email(current_user["email"], otp)
            return jsonify({
                "success": True,
                "message": "Sensitive changes detected. OTP sent to current email.",
                "require_otp": True
            }), 200

        cursor.execute(
            "UPDATE users SET name=%s WHERE id=%s",
            (pending_profile["name"], user_id)
        )
        conn.commit()
        return jsonify({"success": True, "message": "Profile updated successfully", "require_otp": False}), 200
    finally:
        cursor.close()
        conn.close()

@dashboard_bp.route("/verify_update_otp", methods=["POST"])
@login_required
def verify_update_otp():
    data = request.get_json(silent=True)
    otp_entered = data.get("otp")
    if not otp_entered:
        return jsonify({"success": False, "error": "Missing OTP"}), 400

    user_id = get_jwt_identity()["id"]
    conn = connect_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cursor.execute("SELECT * FROM pending_profile_updates WHERE user_id=%s", (user_id,))
        record = cursor.fetchone()

        if not record:
            return jsonify({"success": False, "error": "No pending update found"}), 404
        if datetime.now() > record["expiry"]:
            cursor.execute("DELETE FROM pending_profile_updates WHERE user_id=%s", (user_id,))
            conn.commit()
            return jsonify({"success": False, "error": "OTP expired"}), 400

        if not check_password(record["otp_hash"], otp_entered):
            return jsonify({"success": False, "error": "Invalid OTP"}), 400

        updates = json.loads(record["pending_data"])
        cursor.execute(
            "UPDATE users SET name=%s, email=%s, phone=%s WHERE id=%s",
            (updates["name"], updates["email"], updates["phone"], user_id)
        )
        cursor.execute("DELETE FROM pending_profile_updates WHERE user_id=%s", (user_id,))
        conn.commit()
        return jsonify({"success": True, "message": "Profile updated successfully"}), 200
    finally:
        cursor.close()
        conn.close()

@dashboard_bp.route("/resend_update_otp", methods=["POST"])
@login_required
def resend_update_otp():
    user_id = get_jwt_identity()["id"]

    conn = connect_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)

    try:
        cursor.execute(
            "SELECT * FROM pending_profile_updates WHERE user_id=%s",
            (user_id,)
        )
        record = cursor.fetchone()

        if not record:
            return jsonify({"success": False, "error": "No pending profile update found"}), 404

        cursor.execute(
            "SELECT email FROM users WHERE id=%s",
            (user_id,)
        )
        user = cursor.fetchone()

        if not user:
            return jsonify({"success": False, "error": "User not found"}), 404

        otp = generate_otp()
        otp_hash = hash_password(otp)
        expiry = datetime.now() + timedelta(minutes=10)

        cursor.execute("""
            UPDATE pending_profile_updates
            SET otp_hash=%s,
                expiry=%s
            WHERE user_id=%s
        """, (otp_hash, expiry, user_id))

        conn.commit()

        send_otp_email(user["email"], otp)

        return jsonify({
            "success": True,
            "message": "OTP resent successfully"
        }), 200

    except Exception as e:
        conn.rollback()
        logging.error(f"Failed to resend OTP: {e}")
        return jsonify({"success": False, "error": "Failed to resend OTP"}), 500

    finally:
        cursor.close()
        conn.close()
