"""Secure Login System - Flask application entry point."""

import logging
import os
from logging.handlers import RotatingFileHandler

from flask import Flask, redirect, render_template, request, url_for
from flask_login import current_user
from flask_wtf.csrf import CSRFProtect

from config import get_config
from database import db, init_db
from extensions import limiter, login_manager
from routes.auth import auth_bp
from routes.dashboard import dashboard_bp
from utils.security import init_security

csrf = CSRFProtect()


def create_app(config_class=None):
    """Application factory for the Secure Login System."""
    app = Flask(__name__)

    if config_class is None:
        config_class = get_config()
    app.config.from_object(config_class)

    _configure_logging(app)
    _init_extensions(app)
    _register_blueprints(app)
    _register_error_handlers(app)
    _register_context_processors(app)
    _register_security_headers(app)

    with app.app_context():
        init_db(app)

    return app


def _configure_logging(app):
    """Configure rotating file and console logging."""
    if not app.debug and not app.testing:
        log_dir = os.path.join(app.root_path, "logs")
        os.makedirs(log_dir, exist_ok=True)
        file_handler = RotatingFileHandler(
            os.path.join(log_dir, "secure_login.log"),
            maxBytes=102400,
            backupCount=10,
        )
        file_handler.setFormatter(
            logging.Formatter(
                "%(asctime)s %(levelname)s: %(message)s [in %(pathname)s:%(lineno)d]"
            )
        )
        file_handler.setLevel(logging.INFO)
        app.logger.addHandler(file_handler)
        app.logger.setLevel(logging.INFO)
        app.logger.info("Secure Login System startup")


def _init_extensions(app):
    """Initialize Flask extensions."""
    db.init_app(app)
    csrf.init_app(app)
    init_security(app)

    login_manager.init_app(app)
    login_manager.login_view = "auth.login"
    login_manager.login_message = "Please sign in to access this page."
    login_manager.login_message_category = "warning"
    login_manager.session_protection = "strong"

    @login_manager.user_loader
    def load_user(user_id):
        from models.user import User

        return db.session.get(User, int(user_id))

    limiter.init_app(app)
    limiter.storage_uri = app.config.get("RATELIMIT_STORAGE_URI", "memory://")


def _register_blueprints(app):
    """Register application blueprints."""
    app.register_blueprint(auth_bp)
    app.register_blueprint(dashboard_bp)

    @app.route("/")
    def root():
        if current_user.is_authenticated:
            return redirect(url_for("dashboard.index"))
        return redirect(url_for("auth.login"))


def _register_error_handlers(app):
    """Register custom HTTP error pages."""

    @app.errorhandler(404)
    def not_found_error(error):
        return render_template("404.html"), 404

    @app.errorhandler(500)
    def internal_error(error):
        db.session.rollback()
        app.logger.error("Server Error: %s", error)
        return render_template("500.html"), 500

    @app.errorhandler(429)
    def ratelimit_handler(error):
        flash("Too many requests. Please wait a moment and try again.", "warning")
        if request.endpoint == "auth.register":
            from routes.auth import RegisterForm

            return render_template("register.html", form=RegisterForm()), 429
        from routes.auth import LoginForm

        return render_template("login.html", form=LoginForm()), 429


def _register_context_processors(app):
    """Inject global template variables."""

    @app.context_processor
    def inject_globals():
        return {"app_name": app.config.get("APP_NAME", "Secure Login System")}


def _register_security_headers(app):
    """Add security headers to every response."""

    @app.after_request
    def set_security_headers(response):
        response.headers["X-Content-Type-Options"] = "nosniff"
        response.headers["X-Frame-Options"] = "SAMEORIGIN"
        response.headers["X-XSS-Protection"] = "1; mode=block"
        response.headers["Referrer-Policy"] = "strict-origin-when-cross-origin"
        if not app.debug:
            response.headers["Content-Security-Policy"] = (
                "default-src 'self'; "
                "script-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net; "
                "style-src 'self' 'unsafe-inline' https://cdn.jsdelivr.net "
                "https://cdnjs.cloudflare.com; "
                "font-src 'self' https://cdnjs.cloudflare.com; "
                "img-src 'self' data:; "
                "connect-src 'self';"
            )
        return response


app = create_app()


if __name__ == "__main__":
    debug_mode = os.environ.get("FLASK_ENV", "development") == "development"
    app.run(host="0.0.0.0", port=int(os.environ.get("PORT", 5000)), debug=debug_mode)
