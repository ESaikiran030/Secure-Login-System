"""Application route blueprints."""

from routes.auth import auth_bp
from routes.dashboard import dashboard_bp

__all__ = ["auth_bp", "dashboard_bp"]
