"""Input validation utilities for registration and profile updates."""

import re

from flask import current_app


def sanitize_input(value):
    """Strip whitespace and remove null bytes from user input."""
    if value is None:
        return ""
    cleaned = str(value).strip()
    return cleaned.replace("\x00", "")


def validate_fullname(fullname):
    """
    Validate full name: 2-100 characters, letters, spaces, hyphens, apostrophes.
    Returns (is_valid, error_message).
    """
    fullname = sanitize_input(fullname)
    if not fullname:
        return False, "Full name is required."
    if len(fullname) < 2:
        return False, "Full name must be at least 2 characters."
    if len(fullname) > 100:
        return False, "Full name must not exceed 100 characters."
    if not re.match(r"^[a-zA-Z\s\-'.]+$", fullname):
        return False, "Full name may only contain letters, spaces, hyphens, and apostrophes."
    return True, ""


def validate_username(username):
    """
    Validate username: 3-50 characters, alphanumeric and underscores only.
    Returns (is_valid, error_message).
    """
    username = sanitize_input(username)
    if not username:
        return False, "Username is required."
    if len(username) < 3:
        return False, "Username must be at least 3 characters."
    if len(username) > 50:
        return False, "Username must not exceed 50 characters."
    if not re.match(r"^[a-zA-Z0-9_]+$", username):
        return False, "Username may only contain letters, numbers, and underscores."
    return True, ""


def validate_email(email):
    """
    Validate email format using a conservative regex pattern.
    Returns (is_valid, error_message).
    """
    email = sanitize_input(email).lower()
    if not email:
        return False, "Email is required."
    if len(email) > 120:
        return False, "Email must not exceed 120 characters."
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    if not re.match(pattern, email):
        return False, "Please enter a valid email address."
    return True, ""


def validate_password(password, confirm_password=None):
    """
    Validate password against the configured security policy.
    Returns (is_valid, error_message).
    """
    if password is None:
        password = ""
    min_len = current_app.config.get("PASSWORD_MIN_LENGTH", 8)
    max_len = current_app.config.get("PASSWORD_MAX_LENGTH", 64)

    if not password:
        return False, "Password is required."
    if len(password) < min_len:
        return False, f"Password must be at least {min_len} characters."
    if len(password) > max_len:
        return False, f"Password must not exceed {max_len} characters."
    if not re.search(r"[A-Z]", password):
        return False, "Password must contain at least one uppercase letter."
    if not re.search(r"[a-z]", password):
        return False, "Password must contain at least one lowercase letter."
    if not re.search(r"\d", password):
        return False, "Password must contain at least one digit."
    if not re.search(r"[!@#$%^&*(),.?\":{}|<>_\-\[\]\\;/+=~`']", password):
        return False, "Password must contain at least one special character."
    if confirm_password is not None and password != confirm_password:
        return False, "Passwords do not match."
    return True, ""


def get_password_strength(password):
    """
    Calculate password strength score from 0 to 100.
    Used by the client-side meter and server-side feedback.
    """
    if not password:
        return 0

    score = 0
    min_len = current_app.config.get("PASSWORD_MIN_LENGTH", 8)

    if len(password) >= min_len:
        score += 20
    if len(password) >= min_len + 4:
        score += 10
    if re.search(r"[A-Z]", password):
        score += 15
    if re.search(r"[a-z]", password):
        score += 15
    if re.search(r"\d", password):
        score += 15
    if re.search(r"[!@#$%^&*(),.?\":{}|<>_\-\[\]\\;/+=~`']", password):
        score += 15
    if len(password) >= 12:
        score += 10

    return min(score, 100)
