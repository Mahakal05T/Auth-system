import re
import secrets
import string
import bcrypt

def hash_password(password):
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

def check_password(stored_hash, password):
    return bcrypt.checkpw(password.encode(), stored_hash.encode())

def generate_otp():
    return str(secrets.randbelow(900000) + 100000)

def is_valid_email(email):
    return re.match(r'^[a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$', email) is not None

def is_strong_password(password):
    return (
        len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"[0-9]", password) and
        re.search(r"[^A-Za-z0-9]", password)
    )

def generate_employee_id(conn=None):
    """Generate a unique, unpredictable employee ID."""
    if conn:
        while True:
            emp_id = "emp" + secrets.token_hex(4).upper()
            cur = conn.cursor()
            cur.execute("SELECT 1 FROM users WHERE emp_id=%s", (emp_id,))
            if not cur.fetchone():
                cur.close()
                return emp_id
            cur.close()
    return "emp" + secrets.token_hex(4).upper()

def generate_random_password(length=10):
    characters = string.ascii_letters + string.digits + "!@#$%^&*()"
    return ''.join(secrets.choice(characters) for _ in range(length))
