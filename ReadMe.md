# Authentication System (Flask + PostgreSQL)

This project is a secure user authentication system built with **Flask** and **PostgreSQL**, supporting:
- User registration
- Login with JWT (cookie-based)
- Forgot password with **OTP verification** (Email via Resend)
- Password reset via **secure token-based links**
- Admin dashboard with user management
- Rate limiting for OTPs and login
- CSRF-protected JWT cookies
- Environment variable usage for credentials

---

## Features
- Secure password hashing using **bcrypt**
- OTP verification system via **Resend** email API
- Rate limiting for OTP requests and login
- Token-based password reset after OTP verification
- Admin user management (add, delete, role changes)
- Profile update with OTP verification for sensitive changes
- JWT token blocklist (DB-backed) for secure logout
- Responsive frontend with Tailwind CSS

---

## Tech Stack
- Python (Flask)
- PostgreSQL
- HTML / Tailwind CSS
- Resend API (email)
- dotenv for environment variables
- bcrypt for password hashing
- ratelimit for OTP/login protection
- Flask-JWT-Extended (cookie-based JWT auth)

---

## Setup Instructions

### 1. Clone the Repository
```bash
git clone https://github.com/Mahakal05T/Auth-System.git
cd Auth-System
```

### 2. Create Virtual Environment (optional but recommended)
```bash
python -m venv venv
source venv/bin/activate   # On Windows: venv\Scripts\activate
```

### 3. Install Requirements
```bash
pip install -r backend/requirements.txt
```

---

## 4. Configure Environment Variables
Copy `.env.example` to `credentials.env` and fill in your values:

```bash
cp .env.example credentials.env
```

Required variables:
- `DB_HOST`, `DB_USER`, `DB_PASS`, `DB_NAME` (or `DATABASE_URL`)
- `RESEND_API_KEY`
- `JWT_SECRET_KEY` (must be a strong random hex string)

> 🔥 **Never push your `credentials.env` file to public repositories!**

---

## 5. Run the Flask Application
```bash
cd backend
python app.py
```
Visit:
```
http://127.0.0.1:5000/
```

---

## Folder Structure
```
/User-Auth
  |-- backend/
      |-- app.py
      |-- requirements.txt
      |-- Procfile
  |-- templates/
      |-- login.html
      |-- register.html
      |-- forgot_password.html
      |-- reset_password.html
      |-- admin_dashboard.html
      |-- dashboard.html
  |-- static/
      |-- style.css
      |-- scripts.js
  |-- postgres_schema.sql
  |-- .env.example
  |-- credentials.env  (git-ignored)
  |-- README.md
```

---

## Notes
- Ensure that your PostgreSQL database and tables are correctly set up before running the application.
- The `JWT_SECRET_KEY` must be set as an environment variable — the app will refuse to start without it.
- Set `JWT_COOKIE_SECURE=true` in production (HTTPS).
- Set `LOG_LEVEL=WARNING` or `ERROR` in production.

---

## License
This project is licensed under the MIT License.