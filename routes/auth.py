"""Authentication routes: register, login, logout, 2FA, forgot password."""

from flask import (
    Blueprint,
    current_app,
    flash,
    jsonify,
    redirect,
    render_template,
    request,
    session,
    url_for,
)
from flask_login import current_user, login_required, login_user, logout_user
from flask_wtf import FlaskForm
from wtforms import BooleanField, PasswordField, StringField, SubmitField
from wtforms.validators import DataRequired, Length

from database import db
from extensions import limiter
from models.user import User
from utils.otp import verify_otp
from utils.security import (
    clear_pending_2fa,
    get_pending_2fa,
    hash_password,
    set_pending_2fa,
    verify_password,
)
from utils.validators import (
    sanitize_input,
    validate_email,
    validate_fullname,
    validate_password,
    validate_username,
)

auth_bp = Blueprint("auth", __name__)


class LoginForm(FlaskForm):
    """Login form with CSRF protection."""

    username = StringField(
        "Username or Email",
        validators=[
            DataRequired(message="Username or email is required."),
            Length(max=120),
        ],
    )
    password = PasswordField(
        "Password",
        validators=[DataRequired(message="Password is required."), Length(max=64)],
    )
    remember = BooleanField("Remember Me")
    submit = SubmitField("Sign In")


class RegisterForm(FlaskForm):
    """Registration form with CSRF protection."""

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
    password = PasswordField(
        "Password",
        validators=[DataRequired(message="Password is required."), Length(max=64)],
    )
    confirm_password = PasswordField(
        "Confirm Password",
        validators=[
            DataRequired(message="Please confirm your password."),
            Length(max=64),
        ],
    )
    submit = SubmitField("Create Account")


class OTPForm(FlaskForm):
    """Two-factor authentication verification form."""

    otp_token = StringField(
        "Authentication Code",
        validators=[
            DataRequired(message="Authentication code is required."),
            Length(min=6, max=6),
        ],
    )
    submit = SubmitField("Verify")


class ForgotPasswordForm(FlaskForm):
    """Forgot password form (mocked email delivery)."""

    email = StringField(
        "Email",
        validators=[DataRequired(message="Email is required."), Length(max=120)],
    )
    submit = SubmitField("Send Reset Link")


def _login_rate_limit():
    return current_app.config.get("LOGIN_RATE_LIMIT", "10 per minute")


def _register_rate_limit():
    return current_app.config.get("REGISTER_RATE_LIMIT", "5 per minute")


def _complete_login(user, remember=False):
    """Finalize login after password and optional 2FA verification."""
    user.reset_failed_attempts()
    user.update_last_login()
    db.session.commit()
    clear_pending_2fa()
    login_user(user, remember=remember)
    session.permanent = True
    flash("Welcome back! You have signed in successfully.", "success")
    return redirect(url_for("dashboard.index"))


@auth_bp.route("/login", methods=["GET", "POST"])
@limiter.limit(_login_rate_limit, methods=["POST"])
def login():
    """Handle user login with lockout and optional 2FA."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = LoginForm()
    if form.validate_on_submit():
        identifier = sanitize_input(form.username.data).lower()
        password = form.password.data
        remember = form.remember.data

        user = User.query.filter(
            (User.username == identifier) | (User.email == identifier)
        ).first()

        if user is None:
            flash("Invalid username/email or password.", "danger")
            return render_template("login.html", form=form)

        if user.is_account_locked():
            flash(
                "Your account is temporarily locked due to too many failed login attempts. "
                "Please try again later.",
                "warning",
            )
            return render_template("login.html", form=form)

        if not verify_password(user.password_hash, password):
            user.record_failed_attempt(
                current_app.config["MAX_LOGIN_ATTEMPTS"],
                current_app.config["LOCKOUT_DURATION_MINUTES"],
            )
            db.session.commit()
            remaining = current_app.config["MAX_LOGIN_ATTEMPTS"] - user.failed_attempts
            if user.is_account_locked():
                flash(
                    "Too many failed attempts. Your account has been locked for "
                    f"{current_app.config['LOCKOUT_DURATION_MINUTES']} minutes.",
                    "danger",
                )
            elif remaining > 0:
                flash(
                    f"Invalid username/email or password. {remaining} attempt(s) remaining.",
                    "danger",
                )
            else:
                flash("Invalid username/email or password.", "danger")
            return render_template("login.html", form=form)

        if user.is_2fa_enabled and user.secret_key:
            set_pending_2fa(user.id, remember)
            return redirect(url_for("auth.verify_2fa"))

        return _complete_login(user, remember)

    return render_template("login.html", form=form)


@auth_bp.route("/register", methods=["GET", "POST"])
@limiter.limit(_register_rate_limit, methods=["POST"])
def register():
    """Handle new user registration with validation."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = RegisterForm()
    if form.validate_on_submit():
        fullname = sanitize_input(form.fullname.data)
        username = sanitize_input(form.username.data).lower()
        email = sanitize_input(form.email.data).lower()
        password = form.password.data
        confirm = form.confirm_password.data

        valid, message = validate_fullname(fullname)
        if not valid:
            flash(message, "danger")
            return render_template("register.html", form=form)

        valid, message = validate_username(username)
        if not valid:
            flash(message, "danger")
            return render_template("register.html", form=form)

        valid, message = validate_email(email)
        if not valid:
            flash(message, "danger")
            return render_template("register.html", form=form)

        valid, message = validate_password(password, confirm)
        if not valid:
            flash(message, "danger")
            return render_template("register.html", form=form)

        if User.query.filter_by(username=username).first():
            flash("This username is already taken. Please choose another.", "danger")
            return render_template("register.html", form=form)

        if User.query.filter_by(email=email).first():
            flash("An account with this email already exists.", "danger")
            return render_template("register.html", form=form)

        user = User(
            fullname=fullname,
            username=username,
            email=email,
            password_hash=hash_password(password),
        )
        db.session.add(user)
        db.session.commit()

        flash("Registration successful! Please sign in with your new account.", "success")
        return redirect(url_for("auth.login"))

    return render_template("register.html", form=form)


@auth_bp.route("/logout")
@login_required
def logout():
    """Log out the current user and clear session data."""
    logout_user()
    clear_pending_2fa()
    session.clear()
    flash("You have been signed out successfully.", "info")
    return redirect(url_for("auth.login"))


@auth_bp.route("/verify-2fa", methods=["GET", "POST"])
def verify_2fa():
    """Verify TOTP code after successful password authentication."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    user_id, remember = get_pending_2fa()
    if not user_id:
        flash("Please sign in first.", "warning")
        return redirect(url_for("auth.login"))

    user = db.session.get(User, user_id)
    if user is None or not user.is_2fa_enabled:
        clear_pending_2fa()
        flash("Two-factor authentication session expired. Please sign in again.", "warning")
        return redirect(url_for("auth.login"))

    form = OTPForm()
    if form.validate_on_submit():
        token = sanitize_input(form.otp_token.data)
        if verify_otp(user.secret_key, token):
            return _complete_login(user, remember)
        flash("Invalid authentication code. Please try again.", "danger")

    return render_template("verify_2fa.html", form=form, username=user.username)


@auth_bp.route("/forgot-password", methods=["GET", "POST"])
def forgot_password():
    """Mock forgot-password flow (no actual email sent)."""
    if current_user.is_authenticated:
        return redirect(url_for("dashboard.index"))

    form = ForgotPasswordForm()
    if form.validate_on_submit():
        email = sanitize_input(form.email.data).lower()
        valid, message = validate_email(email)
        if not valid:
            flash(message, "danger")
            return render_template("forgot_password.html", form=form)

        flash(
            "If an account exists for that email, a password reset link has been sent. "
            "(Mock: no email was actually sent in this demo.)",
            "info",
        )
        return redirect(url_for("auth.login"))

    return render_template("forgot_password.html", form=form)


@auth_bp.route("/api/password-strength", methods=["POST"])
def password_strength_api():
    """AJAX endpoint for real-time password strength feedback."""
    from utils.validators import get_password_strength

    data = request.get_json(silent=True) or {}
    password = data.get("password", "")
    score = get_password_strength(password)

    if score < 40:
        label, level = "Weak", "danger"
    elif score < 70:
        label, level = "Fair", "warning"
    elif score < 90:
        label, level = "Good", "info"
    else:
        label, level = "Strong", "success"

    return jsonify({"score": score, "label": label, "level": level})
