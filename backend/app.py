import logging
import os
from datetime import timedelta

from flask import Flask, jsonify, request
from flask_cors import CORS
from dotenv import load_dotenv
from ratelimit import RateLimitException

from flask_jwt_extended import JWTManager

from database import connect_db
from routes.auth import auth_bp
from routes.admin import admin_bp
from routes.dashboard import dashboard_bp
from routes.password import password_bp

_log_level = os.getenv("LOG_LEVEL", "WARNING").upper()
logging.basicConfig(level=getattr(logging, _log_level, logging.WARNING),
                    format='%(asctime)s - %(levelname)s - %(message)s')

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
load_dotenv(os.path.join(BASE_DIR, "credentials.env"))

app = Flask(__name__)

# Configure CORS for React frontend
frontend_url = os.getenv("FRONTEND_URL", "http://localhost:5173")
# Since Render can have multiple domains, you could also use a comma-separated list
# e.g. FRONTEND_URL="http://localhost:5173,https://my-app.onrender.com"
origins = [url.strip() for url in frontend_url.split(",")]
CORS(app, supports_credentials=True, origins=origins)

_jwt_secret = os.getenv("JWT_SECRET_KEY")
if not _jwt_secret:
    raise RuntimeError("FATAL: JWT_SECRET_KEY environment variable is not set.")
app.config["JWT_SECRET_KEY"] = _jwt_secret
app.config["JWT_ACCESS_TOKEN_EXPIRES"] = timedelta(minutes=15)
app.config["JWT_REFRESH_TOKEN_EXPIRES"] = timedelta(days=1)

# Use cookies for JWT
app.config["JWT_TOKEN_LOCATION"] = ["cookies"]
app.config["JWT_IDENTITY_CLAIM"] = "identity"

app.config["JWT_ACCESS_COOKIE_NAME"] = "access_token_cookie"
app.config["JWT_REFRESH_COOKIE_NAME"] = "refresh_token_cookie"

# Cookie security: SECURE=True requires HTTPS
app.config["JWT_COOKIE_SECURE"] = os.getenv("JWT_COOKIE_SECURE", "false").lower() == "true"
app.config["JWT_COOKIE_SAMESITE"] = "Lax"

app.config["JWT_COOKIE_CSRF_PROTECT"] = True
app.config["JWT_CSRF_IN_COOKIES"] = True

jwt = JWTManager(app)

@app.errorhandler(RateLimitException)
def handle_rate_limit(e):
    return jsonify({"success": False, "error": "You have reached your request limit. Please try again later."}), 429

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
    return jsonify({"success": False, "error": "Token revoked"}), 401

@jwt.expired_token_loader
def expired_token_callback(jwt_header, jwt_payload):
    return jsonify({"success": False, "error": "Token expired"}), 401

@jwt.invalid_token_loader
def invalid_token_callback(reason):
    return jsonify({"success": False, "error": "Invalid token"}), 401

@jwt.unauthorized_loader
def missing_token_callback(reason):
    return jsonify({"success": False, "error": "Missing token"}), 401

# Register Blueprints
app.register_blueprint(auth_bp)
app.register_blueprint(admin_bp)
app.register_blueprint(dashboard_bp)
app.register_blueprint(password_bp)

# Health check route
@app.route("/health", methods=["GET"])
def health_check():
    return jsonify({"success": True, "message": "API is running"}), 200

@app.after_request
def add_security_headers(response):
    response.headers['Cache-Control'] = 'no-store, no-cache, must-revalidate, private, max-age=0'
    response.headers['X-Frame-Options'] = 'DENY'
    response.headers['X-Content-Type-Options'] = 'nosniff'
    response.headers['Referrer-Policy'] = 'strict-origin-when-cross-origin'
    response.headers['Permissions-Policy'] = 'geolocation=(), camera=(), microphone=()'
    response.headers['X-XSS-Protection'] = '1; mode=block'
    return response

if __name__ == "__main__":
    app.run(debug=True)
