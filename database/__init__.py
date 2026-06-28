"""Database initialization and extension setup."""

from flask_sqlalchemy import SQLAlchemy

db = SQLAlchemy()


def init_db(app):
    """Create all database tables within the application context."""
    with app.app_context():
        db.create_all()
