"""Create demo user and enable 2FA for manual testing."""

import re

import pyotp

from app import app
from database import db
from models.user import User

DEMO = {
    "fullname": "Demo User",
    "username": "demouser",
    "email": "demo@example.com",
    "password": "DemoPass1!",
}


def get_csrf(html):
    match = re.search(r'name="csrf_token"[^>]*value="([^"]+)"', html.decode())
    if not match:
        raise RuntimeError("CSRF token not found")
    return match.group(1)


def main():
    with app.app_context():
        existing = User.query.filter_by(username=DEMO["username"]).first()
        if existing:
            db.session.delete(existing)
            db.session.commit()
            print("Removed existing demouser account.")

    client = app.test_client()

    response = client.get("/register")
    csrf = get_csrf(response.data)
    response = client.post(
        "/register",
        data={
            "csrf_token": csrf,
            "fullname": DEMO["fullname"],
            "username": DEMO["username"],
            "email": DEMO["email"],
            "password": DEMO["password"],
            "confirm_password": DEMO["password"],
            "submit": "Create Account",
        },
        follow_redirects=False,
    )
    if response.status_code not in (302, 303):
        raise RuntimeError(f"Registration failed: {response.status_code}")
    print("Registered demo user.")

    response = client.get("/login")
    csrf = get_csrf(response.data)
    response = client.post(
        "/login",
        data={
            "csrf_token": csrf,
            "username": DEMO["username"],
            "password": DEMO["password"],
            "submit": "Sign In",
        },
        follow_redirects=False,
    )
    if response.status_code not in (302, 303):
        raise RuntimeError(f"Login failed: {response.status_code}")
    print("Logged in as demouser.")

    response = client.get("/profile")
    if response.status_code != 200:
        raise RuntimeError(f"Profile page failed: {response.status_code}")

    with app.app_context():
        user = User.query.filter_by(username=DEMO["username"]).first()
        user_id = str(user.id)

    with client.session_transaction() as sess:
        pending = sess.get("pending_2fa_secrets", {}).get(user_id)

    if not pending:
        raise RuntimeError("Pending 2FA secret not found in session")

    otp = pyotp.TOTP(pending).now()
    csrf = get_csrf(response.data)
    response = client.post(
        "/profile",
        data={
            "csrf_token": csrf,
            "otp_token": otp,
            "enable_submit": "Enable 2FA",
        },
        follow_redirects=True,
    )

    with app.app_context():
        user = User.query.filter_by(username=DEMO["username"]).first()
        if not user.is_2fa_enabled:
            from utils.otp import verify_otp

            if verify_otp(pending, otp):
                user.secret_key = pending
                user.is_2fa_enabled = True
                db.session.commit()
                print("Enabled 2FA directly (form POST did not persist).")
            else:
                raise RuntimeError("OTP verification failed for demo setup")
        stored_secret = user.secret_key
        if not user.is_2fa_enabled or not stored_secret:
            raise RuntimeError("2FA was not enabled on the user record")

    print()
    print("=" * 52)
    print("DEMO ACCOUNT READY")
    print("=" * 52)
    print(f"URL:      http://127.0.0.1:5000/login")
    print(f"Username: {DEMO['username']}")
    print(f"Email:    {DEMO['email']}")
    print(f"Password: {DEMO['password']}")
    print()
    print("2FA ENABLED")
    print(f"Manual TOTP secret (Google Authenticator): {stored_secret}")
    print(f"Current OTP code (valid ~30s): {pyotp.TOTP(stored_secret).now()}")
    print()
    print("Login flow: password first, then 6-digit authenticator code.")
    print("=" * 52)


if __name__ == "__main__":
    main()
