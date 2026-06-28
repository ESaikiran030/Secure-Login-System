"""Dashboard and profile management routes."""

from flask import Blueprint, flash, redirect, render_template, request, url_for
from flask_login import current_user, login_required
from flask_wtf import FlaskForm
from wtforms import PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length

from database import db
from models.user import User
from utils.otp import generate_qr_code, generate_secret, get_provisioning_uri, verify_otp
from utils.security import hash_password, verify_password
from utils.validators import (
    sanitize_input,
    validate_email,
    validate_fullname,
    validate_password,
    validate_username,
)

dashboard_bp = Blueprint("dashboard", __name__)


class ProfileForm(FlaskForm):
    """Update profile information."""

    fullname = StringField(
        "Full Name",
        validators=[DataRequired(message="Full name is required."), Length(max=100)],
    )
    username = StringField(
        "Username",
        validators=[DataRequired(message="Username is required."), Length(max=50)],
    )
    email = StringField(
        "Email",
        validators=[DataRequired(message="Email is required."), Length(max=120)],
    )
    profile_submit = SubmitField("Save Changes")


class ChangePasswordForm(FlaskForm):
    """Change password with current password verification."""

    current_password = PasswordField(
        "Current Password",
        validators=[DataRequired(message="Current password is required."), Length(max=64)],
    )
    new_password = PasswordField(
        "New Password",
        validators=[DataRequired(message="New password is required."), Length(max=64)],
    )
    confirm_password = PasswordField(
        "Confirm New Password",
        validators=[
            DataRequired(message="Please confirm your new password."),
            Length(max=64),
        ],
    )
    password_submit = SubmitField("Change Password")


class Enable2FAForm(FlaskForm):
    """Verify OTP before enabling two-factor authentication."""

    otp_token = StringField(
        "Authentication Code",
        validators=[
            DataRequired(message="Authentication code is required."),
            Length(min=6, max=6),
        ],
    )
    enable_submit = SubmitField("Enable 2FA")


class Disable2FAForm(FlaskForm):
    """Verify OTP or password before disabling two-factor authentication."""

    otp_token = StringField(
        "Authentication Code",
        validators=[DataRequired(message="Authentication code is required."), Length(min=6, max=6)],
    )
    disable_submit = SubmitField("Disable 2FA")


class DeleteAccountForm(FlaskForm):
    """Confirm account deletion with password."""

    password = PasswordField(
        "Password",
        validators=[DataRequired(message="Password is required to delete your account.")],
    )
    delete_submit = SubmitField("Delete My Account")


@dashboard_bp.route("/")
@dashboard_bp.route("/dashboard")
@login_required
def index():
    """Display the authenticated user dashboard."""
    return render_template("dashboard.html", user=current_user)


@dashboard_bp.route("/profile", methods=["GET", "POST"])
@login_required
def profile():
    """Manage profile, password, 2FA, and account deletion."""
    profile_form = ProfileForm(
        fullname=current_user.fullname,
        username=current_user.username,
        email=current_user.email,
    )
    password_form = ChangePasswordForm()
    enable_2fa_form = Enable2FAForm()
    disable_2fa_form = Disable2FAForm()
    delete_form = DeleteAccountForm()

    qr_code = None
    provisioning_uri = None
    pending_secret = None
    totp_secret = None

    if current_user.is_2fa_enabled:
        setup_mode = False
    else:
        setup_mode = True
        pending_secret = session_get_pending_2fa_secret(current_user.id)
        if not pending_secret:
            pending_secret = generate_secret()
            session_set_pending_2fa_secret(current_user.id, pending_secret)
        provisioning_uri = get_provisioning_uri(pending_secret, current_user.username)
        qr_code = generate_qr_code(provisioning_uri)
        totp_secret = pending_secret

    if request.method == "POST":
        if profile_form.profile_submit.data and profile_form.validate():
            return _handle_profile_update(profile_form)
        if password_form.password_submit.data and password_form.validate():
            return _handle_password_change(password_form)
        if enable_2fa_form.enable_submit.data and enable_2fa_form.validate():
            return _handle_enable_2fa(enable_2fa_form, pending_secret)
        if disable_2fa_form.disable_submit.data and disable_2fa_form.validate():
            return _handle_disable_2fa(disable_2fa_form)
        if delete_form.delete_submit.data and delete_form.validate():
            return _handle_delete_account(delete_form)

    return render_template(
        "profile.html",
        user=current_user,
        profile_form=profile_form,
        password_form=password_form,
        enable_2fa_form=enable_2fa_form,
        disable_2fa_form=disable_2fa_form,
        delete_form=delete_form,
        qr_code=qr_code,
        provisioning_uri=provisioning_uri,
        totp_secret=totp_secret,
        setup_mode=setup_mode,
    )


def _handle_profile_update(form):
    """Process profile field updates."""
    fullname = sanitize_input(form.fullname.data)
    username = sanitize_input(form.username.data).lower()
    email = sanitize_input(form.email.data).lower()

    valid, message = validate_fullname(fullname)
    if not valid:
        flash(message, "danger")
        return redirect(url_for("dashboard.profile"))

    valid, message = validate_username(username)
    if not valid:
        flash(message, "danger")
        return redirect(url_for("dashboard.profile"))

    valid, message = validate_email(email)
    if not valid:
        flash(message, "danger")
        return redirect(url_for("dashboard.profile"))

    existing = User.query.filter(
        User.username == username, User.id != current_user.id
    ).first()
    if existing:
        flash("This username is already taken.", "danger")
        return redirect(url_for("dashboard.profile"))

    existing = User.query.filter(User.email == email, User.id != current_user.id).first()
    if existing:
        flash("This email is already registered.", "danger")
        return redirect(url_for("dashboard.profile"))

    current_user.fullname = fullname
    current_user.username = username
    current_user.email = email
    db.session.commit()
    flash("Your profile has been updated successfully.", "success")
    return redirect(url_for("dashboard.profile"))


def _handle_password_change(form):
    """Process password change request."""
    if not verify_password(current_user.password_hash, form.current_password.data):
        flash("Current password is incorrect.", "danger")
        return redirect(url_for("dashboard.profile"))

    valid, message = validate_password(
        form.new_password.data, form.confirm_password.data
    )
    if not valid:
        flash(message, "danger")
        return redirect(url_for("dashboard.profile"))

    current_user.password_hash = hash_password(form.new_password.data)
    db.session.commit()
    flash("Your password has been changed successfully.", "success")
    return redirect(url_for("dashboard.profile"))


def _handle_enable_2fa(form, pending_secret):
    """Enable 2FA after OTP verification."""
    if not pending_secret:
        flash("2FA setup session expired. Please refresh the page.", "warning")
        return redirect(url_for("dashboard.profile"))

    token = sanitize_input(form.otp_token.data)
    if not verify_otp(pending_secret, token):
        flash("Invalid authentication code. Please try again.", "danger")
        return redirect(url_for("dashboard.profile"))

    current_user.secret_key = pending_secret
    current_user.is_2fa_enabled = True
    db.session.commit()
    session_clear_pending_2fa_secret(current_user.id)
    flash("Two-factor authentication has been enabled.", "success")
    return redirect(url_for("dashboard.profile"))


def _handle_disable_2fa(form):
    """Disable 2FA after OTP verification."""
    token = sanitize_input(form.otp_token.data)
    if not verify_otp(current_user.secret_key, token):
        flash("Invalid authentication code.", "danger")
        return redirect(url_for("dashboard.profile"))

    current_user.secret_key = None
    current_user.is_2fa_enabled = False
    db.session.commit()
    session_clear_pending_2fa_secret(current_user.id)
    flash("Two-factor authentication has been disabled.", "info")
    return redirect(url_for("dashboard.profile"))


def _handle_delete_account(form):
    """Permanently delete the user account."""
    if not verify_password(current_user.password_hash, form.password.data):
        flash("Incorrect password. Account was not deleted.", "danger")
        return redirect(url_for("dashboard.profile"))

    user_id = current_user.id
    user = db.session.get(User, user_id)
    from flask_login import logout_user

    logout_user()
    db.session.delete(user)
    db.session.commit()
    flash("Your account has been permanently deleted.", "info")
    return redirect(url_for("auth.login"))


def session_get_pending_2fa_secret(user_id):
    """Retrieve a pending 2FA secret stored in server session during setup."""
    from flask import session

    secrets = session.get("pending_2fa_secrets", {})
    return secrets.get(str(user_id))


def session_set_pending_2fa_secret(user_id, secret):
    """Store a pending 2FA secret in server session during setup."""
    from flask import session

    secrets = session.get("pending_2fa_secrets", {})
    secrets[str(user_id)] = secret
    session["pending_2fa_secrets"] = secrets


def session_clear_pending_2fa_secret(user_id):
    """Remove pending 2FA secret from server session."""
    from flask import session

    secrets = session.get("pending_2fa_secrets", {})
    secrets.pop(str(user_id), None)
    session["pending_2fa_secrets"] = secrets
