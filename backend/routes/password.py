import secrets
import bcrypt
from datetime import datetime, timedelta

import psycopg2.extras
from flask import Blueprint, request, jsonify
from ratelimit import limits

from database import connect_db
from utils import generate_otp, is_strong_password, hash_password
from email_service import send_otp_email, send_reset_link_email

password_bp = Blueprint('password', __name__)

@password_bp.route("/forgot_password", methods=["POST"])
@limits(calls=3, period=60)
def forgot_password():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "error": "Missing data"}), 400
    
    identifier = data.get("identifier")
    otp = data.get("otp")

    if not identifier:
        return jsonify({"success": False, "error": "Missing identifier"}), 400

    conn = connect_db()
    cursor = conn.cursor(cursor_factory=psycopg2.extras.DictCursor)
    try:
        cursor.execute("SELECT id, email FROM users WHERE emp_id=%s OR email=%s", (identifier, identifier))
        user = cursor.fetchone()
        if not user:
            # Don't reveal whether the user exists (prevents enumeration)
            return jsonify({"success": True, "message": "If an account with that identifier exists, an OTP has been sent."}), 200

        if otp:
            cursor.execute(
                "SELECT otp, expiry_time FROM otp_codes "
                "WHERE identifier=%s AND expiry_time > NOW()",
                (identifier,)
            )
            record = cursor.fetchone()

            if record and bcrypt.checkpw(otp.encode(), record["otp"].encode()):
                token = secrets.token_urlsafe(32)
                expiry_time = datetime.now() + timedelta(minutes=15)

                cursor.execute("DELETE FROM reset_links WHERE identifier=%s", (identifier,))
                cursor.execute(
                    "INSERT INTO reset_links (identifier, token, expiry_time) VALUES (%s, %s, %s)",
                    (identifier, token, expiry_time)
                )
                cursor.execute("DELETE FROM otp_codes WHERE identifier=%s", (identifier,))
                conn.commit()

                # Generate a frontend URL instead of url_for since this is API only.
                # The frontend should handle /reset_password?token=...
                # For now, we will construct a relative path assuming the frontend is at the origin.
                # A better approach is to read FRONTEND_URL from env.
                import os
                frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173")
                reset_url = f"{frontend_url}/reset-password?token={token}"
                
                send_reset_link_email(user["email"], reset_url)
                return jsonify({"success": True, "message": "OTP verified. Reset link sent to email."}), 200
            
            return jsonify({"success": False, "error": "Invalid or expired OTP"}), 400

        # Generate OTP
        new_otp = generate_otp()
        hashed_otp = bcrypt.hashpw(new_otp.encode(), bcrypt.gensalt()).decode()
        expiry = datetime.now() + timedelta(minutes=10)

        cursor.execute("DELETE FROM reset_links WHERE identifier=%s", (identifier,))
        cursor.execute("DELETE FROM otp_codes WHERE identifier=%s", (identifier,))
        cursor.execute(
            "INSERT INTO otp_codes (identifier, otp, expiry_time) VALUES (%s, %s, %s)",
            (identifier, hashed_otp, expiry)
        )
        conn.commit()

        if send_otp_email(user["email"], new_otp):
            return jsonify({"success": True, "message": "OTP sent successfully"}), 200
        return jsonify({"success": False, "error": "Failed to send OTP email"}), 500
    finally:
        cursor.close()
        conn.close()

@password_bp.route('/reset_password', methods=['POST'])
def reset_password():
    data = request.get_json(silent=True)
    if not data:
        return jsonify({"success": False, "error": "Missing data"}), 400
        
    token = data.get('token')
    new_password = data.get('new_password')

    if not token or not new_password:
        return jsonify({'success': False, 'error': 'Missing token or password'}), 400
    if not is_strong_password(new_password):
        return jsonify({'success': False, 'error': 'Password does not meet complexity requirements'}), 400

    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT identifier FROM reset_links WHERE token=%s AND expiry_time > NOW()",
            (token,)
        )
        row = cursor.fetchone()
        if not row:
            return jsonify({'success': False, 'error': 'Invalid or expired token'}), 400
        identifier = row[0]

        hashed = hash_password(new_password)
        cursor.execute(
            "UPDATE users SET password_hash=%s WHERE emp_id=%s OR email=%s",
            (hashed, identifier, identifier)
        )
        cursor.execute("DELETE FROM reset_links WHERE token=%s", (token,))
        conn.commit()
        return jsonify({'success': True, 'message': 'Password reset successful'}), 200
    finally:
        cursor.close()
        conn.close()

@password_bp.route('/verify_reset_token/<token>', methods=['GET'])
def verify_reset_token(token):
    conn = connect_db()
    cursor = conn.cursor()
    try:
        cursor.execute(
            "SELECT identifier FROM reset_links WHERE token=%s AND expiry_time > NOW()",
            (token,)
        )
        if cursor.fetchone():
            return jsonify({'success': True, 'message': 'Token is valid'}), 200
        return jsonify({'success': False, 'error': 'Invalid or expired token'}), 400
    finally:
        cursor.close()
        conn.close()
