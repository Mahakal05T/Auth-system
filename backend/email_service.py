import os
import logging
import resend

resend.api_key = os.getenv("RESEND_API_KEY")

def send_email(to_email, subject, body):
    try:
        resend.Emails.send({
            "from": "onboarding@resend.dev",
            "to": [to_email],
            "subject": subject,
            "text": body,
        })
        logging.info(f"Email sent to {to_email}")
        return True

    except Exception as e:
        logging.exception("Resend error")
        print("RESEND ERROR:", repr(e))
        raise
        return False

def send_otp_email(email, otp):
    return send_email(email, "Your OTP code", f"Your OTP code is: {otp}")

def send_reset_link_email(email, link):
    return send_email(email, "Reset Your Password", f"Reset link: {link}")

def send_credentials_email(email, emp_id, password):
    return send_email(
        email,
        "Your Account Credentials",
        f"Welcome!\n\nYour employee ID: {emp_id}\nYour temporary password: {password}"
    )
