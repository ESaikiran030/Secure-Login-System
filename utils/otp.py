"""Two-factor authentication utilities using TOTP."""

import base64
import io

import pyotp
import qrcode
import qrcode.image.svg
from flask import current_app


def generate_secret():
    """Generate a new base32-encoded TOTP secret."""
    return pyotp.random_base32()


def get_totp(secret):
    """Return a TOTP instance for the given secret."""
    return pyotp.TOTP(secret)


def verify_otp(secret, token):
    """Verify a 6-digit OTP token against the user's secret."""
    if not secret or not token:
        return False
    totp = get_totp(secret)
    return totp.verify(str(token).strip(), valid_window=1)


def get_provisioning_uri(secret, username):
    """Build the otpauth:// URI for authenticator apps."""
    issuer = current_app.config.get("OTP_ISSUER", "Secure Login System")
    totp = get_totp(secret)
    return totp.provisioning_uri(name=username, issuer_name=issuer)


def generate_qr_code(provisioning_uri):
    """
    Generate a QR code image as a base64-encoded SVG data URI.
    Uses SVG output so Pillow is not required.
    """
    qr = qrcode.QRCode(
        version=1,
        error_correction=qrcode.constants.ERROR_CORRECT_L,
        box_size=10,
        border=4,
        image_factory=qrcode.image.svg.SvgPathImage,
    )
    qr.add_data(provisioning_uri)
    qr.make(fit=True)

    image = qr.make_image()
    buffer = io.BytesIO()
    image.save(buffer)
    encoded = base64.b64encode(buffer.getvalue()).decode("utf-8")
    return f"data:image/svg+xml;base64,{encoded}"
