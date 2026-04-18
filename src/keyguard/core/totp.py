"""TOTP (RFC 6238) generation, provisioning URI, QR rendering, and verification.

KeyGuard uses TOTP as the second factor on every vault unlock. The shared
secret is stored in the OS keychain (not in the vault file) via
:mod:`keyguard.core.keychain`.
"""

import io
from base64 import b32encode
from secrets import token_bytes
from typing import Final

import pyotp
import qrcode

__all__ = [
    "DEFAULT_ISSUER",
    "TOTP_SECRET_LEN",
    "generate_totp_secret",
    "provisioning_uri",
    "render_qr_ascii",
    "verify_code",
]

TOTP_SECRET_LEN: Final[int] = 20  # 160 bits — RFC 4226 standard
DEFAULT_ISSUER: Final[str] = "KeyGuard"


def generate_totp_secret() -> bytes:
    """Return a fresh 20-byte TOTP shared secret via :func:`secrets.token_bytes`."""
    return token_bytes(TOTP_SECRET_LEN)


def _base32(secret: bytes) -> str:
    return b32encode(secret).decode("ascii").rstrip("=")


def provisioning_uri(secret: bytes, account: str, issuer: str = DEFAULT_ISSUER) -> str:
    """Return the ``otpauth://`` URI an authenticator app imports.

    ``account`` typically shown alongside the issuer in the user's app (e.g.
    their email). ``issuer`` identifies KeyGuard in the app's list.
    """
    return pyotp.TOTP(_base32(secret)).provisioning_uri(name=account, issuer_name=issuer)


def render_qr_ascii(uri: str) -> str:
    """Render the provisioning URI as an ASCII QR for terminal display.

    Uses :mod:`qrcode`'s built-in ASCII renderer with ``invert=True`` so the
    QR is readable in both light and dark terminal themes when they render
    whitespace as background.
    """
    qr = qrcode.QRCode(border=1, box_size=1)
    qr.add_data(uri)
    qr.make(fit=True)
    buf = io.StringIO()
    qr.print_ascii(out=buf, tty=False, invert=True)
    return buf.getvalue()


def verify_code(secret: bytes, code: str, valid_window: int = 1) -> bool:
    """Return whether ``code`` is a valid TOTP for ``secret`` right now.

    ``valid_window`` allows this many 30-second steps of clock skew on each
    side. Default of 1 tolerates a ~±30s drift, which pyotp compares in
    constant time via :func:`hmac.compare_digest` internally.
    """
    return pyotp.TOTP(_base32(secret)).verify(code, valid_window=valid_window)
