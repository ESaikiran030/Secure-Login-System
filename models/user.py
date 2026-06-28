"""User model with authentication, lockout, and 2FA support."""

from datetime import datetime, timezone

from flask_login import UserMixin

from database import db


class User(UserMixin, db.Model):
    """Application user with secure authentication fields."""

    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    fullname = db.Column(db.String(100), nullable=False)
    username = db.Column(db.String(50), unique=True, nullable=False, index=True)
    email = db.Column(db.String(120), unique=True, nullable=False, index=True)
    password_hash = db.Column(db.String(128), nullable=False)
    secret_key = db.Column(db.String(32), nullable=True)
    is_2fa_enabled = db.Column(db.Boolean, default=False, nullable=False)
    failed_attempts = db.Column(db.Integer, default=0, nullable=False)
    locked_until = db.Column(db.DateTime, nullable=True)
    last_login = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(
        db.DateTime,
        default=lambda: datetime.now(timezone.utc),
        nullable=False,
    )

    def __repr__(self):
        return f"<User {self.username}>"

    def get_id(self):
        """Return the user ID as a string for Flask-Login."""
        return str(self.id)

    def is_account_locked(self):
        """Return True if the account is currently locked."""
        if self.locked_until is None:
            return False
        now = datetime.now(timezone.utc)
        locked = self.locked_until
        if locked.tzinfo is None:
            locked = locked.replace(tzinfo=timezone.utc)
        return now < locked

    def reset_failed_attempts(self):
        """Clear failed login attempts and lockout."""
        self.failed_attempts = 0
        self.locked_until = None

    def record_failed_attempt(self, max_attempts, lockout_minutes):
        """Increment failed attempts and lock account if threshold reached."""
        self.failed_attempts += 1
        if self.failed_attempts >= max_attempts:
            from datetime import timedelta

            self.locked_until = datetime.now(timezone.utc) + timedelta(
                minutes=lockout_minutes
            )

    def update_last_login(self):
        """Set last login timestamp to now."""
        self.last_login = datetime.now(timezone.utc)

    def formatted_last_login(self):
        """Return a human-readable last login string."""
        if not self.last_login:
            return "Never"
        return self.last_login.strftime("%B %d, %Y at %I:%M %p UTC")

    def formatted_created_at(self):
        """Return a human-readable account creation string."""
        return self.created_at.strftime("%B %d, %Y")
