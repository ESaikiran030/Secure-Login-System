"""Security helpers for password hashing and session management."""

from flask import session
from flask_bcrypt import Bcrypt

bcrypt = Bcrypt()


def hash_password(password):
    """Hash a plain-text password using bcrypt."""
    return bcrypt.generate_password_hash(password).decode("utf-8")


def verify_password(password_hash, password):
    """Verify a plain-text password against a bcrypt hash."""
    return bcrypt.check_password_hash(password_hash, password)


def init_security(app):
    """Initialize bcrypt with the Flask application."""
    bcrypt.init_app(app)


def clear_pending_2fa():
    """Remove pending 2FA session data after login completes or is cancelled."""
    session.pop("pending_2fa_user_id", None)
    session.pop("pending_2fa_remember", None)


def set_pending_2fa(user_id, remember=False):
    """Store pending 2FA verification state in the server session."""
    session["pending_2fa_user_id"] = user_id
    session["pending_2fa_remember"] = remember


def get_pending_2fa():
    """Return pending 2FA user id and remember-me flag from session."""
    user_id = session.get("pending_2fa_user_id")
    remember = session.get("pending_2fa_remember", False)
    return user_id, remember
