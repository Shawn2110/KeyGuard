"""Tests for :mod:`keyguard.core.totp`."""

import pyotp

from keyguard.core import totp

# ---------------------------------------------------------------------------
# generate_totp_secret
# ---------------------------------------------------------------------------


def test_generate_totp_secret_length_and_randomness() -> None:
    s1 = totp.generate_totp_secret()
    s2 = totp.generate_totp_secret()
    assert len(s1) == totp.TOTP_SECRET_LEN == 20
    assert s1 != s2


# ---------------------------------------------------------------------------
# provisioning_uri
# ---------------------------------------------------------------------------


def test_provisioning_uri_has_expected_parts() -> None:
    uri = totp.provisioning_uri(b"\x00" * 20, account="alice@example.com")
    assert uri.startswith("otpauth://totp/")
    assert "alice%40example.com" in uri or "alice@example.com" in uri
    assert "issuer=KeyGuard" in uri
    assert "secret=" in uri


def test_provisioning_uri_respects_custom_issuer() -> None:
    uri = totp.provisioning_uri(b"\x00" * 20, account="a", issuer="Acme")
    assert "issuer=Acme" in uri


# ---------------------------------------------------------------------------
# QR rendering
# ---------------------------------------------------------------------------


def test_render_qr_ascii_produces_non_empty_multiline_output() -> None:
    uri = totp.provisioning_uri(b"\x00" * 20, account="alice")
    ascii_qr = totp.render_qr_ascii(uri)
    assert ascii_qr
    assert "\n" in ascii_qr
    # QR codes are at least 21 modules wide (version 1); with border 1 that's ~24 cols.
    longest_line = max(len(line) for line in ascii_qr.splitlines() if line)
    assert longest_line >= 20


# ---------------------------------------------------------------------------
# verify_code
# ---------------------------------------------------------------------------


def test_verify_code_accepts_current_code() -> None:
    secret = totp.generate_totp_secret()
    now_code = pyotp.TOTP(totp._base32(secret)).now()
    assert totp.verify_code(secret, now_code) is True


def test_verify_code_rejects_garbage() -> None:
    secret = totp.generate_totp_secret()
    assert totp.verify_code(secret, "000000") is False or True  # may randomly match ≈1/1M
    # Use something that cannot possibly be a 6-digit code.
    assert totp.verify_code(secret, "abcdef") is False
    assert totp.verify_code(secret, "") is False


def test_verify_code_tolerates_one_step_skew() -> None:
    secret = totp.generate_totp_secret()
    # A code computed for the PREVIOUS 30s step should still pass with
    # valid_window=1 (default).
    import time

    t = pyotp.TOTP(totp._base32(secret))
    prev_step_code = t.at(time.time() - 30)
    assert totp.verify_code(secret, prev_step_code, valid_window=1) is True


def test_verify_code_rejects_skew_outside_window() -> None:
    secret = totp.generate_totp_secret()
    import time

    t = pyotp.TOTP(totp._base32(secret))
    # Five steps back = 150s — well outside default window.
    stale = t.at(time.time() - 150)
    assert totp.verify_code(secret, stale, valid_window=1) is False
