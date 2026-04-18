"""Typed wrapper around :mod:`keyring` for KeyGuard's secret-adjacent bytes.

Stores three byte blobs per vault: the ``local_half`` KEK input, the TOTP
shared secret, and the fingerprint HMAC key used by the scanner. Each is
base64-encoded on the way in (since ``keyring`` stores strings) and
decoded on the way out.

Maps ``keyring``'s exception zoo to our :class:`KeychainError` subclasses
so callers never import from ``keyring.errors`` directly.
"""

from base64 import b64decode, b64encode
from typing import Final

import keyring
from keyring.errors import KeyringError, NoKeyringError, PasswordDeleteError

from keyguard.core.errors import (
    KeychainError,
    KeychainUnavailableError,
    LocalHalfAccessDeniedError,
    LocalHalfMissingError,
)

__all__ = [
    "SERVICE_NAME",
    "USER_FINGERPRINT_KEY",
    "USER_LOCAL_HALF",
    "USER_TOTP_SECRET",
    "delete_all_keyguard_entries",
    "load_fingerprint_key",
    "load_local_half",
    "load_totp_secret",
    "store_fingerprint_key",
    "store_local_half",
    "store_totp_secret",
]

SERVICE_NAME: Final[str] = "keyguard"

USER_LOCAL_HALF: Final[str] = "local_half"
USER_TOTP_SECRET: Final[str] = "totp_secret"  # noqa: S105 — label, not a secret
USER_FINGERPRINT_KEY: Final[str] = "fingerprint_key"

_ALL_USERNAMES: Final[tuple[str, ...]] = (
    USER_LOCAL_HALF,
    USER_TOTP_SECRET,
    USER_FINGERPRINT_KEY,
)


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------
def _store_bytes(username: str, value: bytes) -> None:
    encoded = b64encode(value).decode("ascii")
    try:
        keyring.set_password(SERVICE_NAME, username, encoded)
    except NoKeyringError as exc:
        raise KeychainUnavailableError(
            "OS keychain service is not available on this machine"
        ) from exc
    except KeyringError as exc:
        raise KeychainError(f"failed to store {username} in OS keychain: {exc}") from exc


def _load_bytes(username: str) -> bytes:
    try:
        raw = keyring.get_password(SERVICE_NAME, username)
    except NoKeyringError as exc:
        raise KeychainUnavailableError(
            "OS keychain service is not available on this machine"
        ) from exc
    except KeyringError as exc:
        raise LocalHalfAccessDeniedError(f"OS keychain denied access to {username}: {exc}") from exc
    if raw is None:
        raise LocalHalfMissingError(
            f"no {username} entry found in the OS keychain for service '{SERVICE_NAME}' "
            "(did you run `keyguard init` on this machine?)"
        )
    return b64decode(raw.encode("ascii"))


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------
def store_local_half(value: bytes) -> None:
    """Persist the 32-byte ``local_half`` under service 'keyguard' / user 'local_half'."""
    _store_bytes(USER_LOCAL_HALF, value)


def load_local_half() -> bytes:
    """Return the stored ``local_half`` bytes, or raise if missing / denied."""
    return _load_bytes(USER_LOCAL_HALF)


def store_totp_secret(value: bytes) -> None:
    """Persist the raw TOTP shared secret (typically 20 bytes)."""
    _store_bytes(USER_TOTP_SECRET, value)


def load_totp_secret() -> bytes:
    """Return the stored TOTP shared secret bytes."""
    return _load_bytes(USER_TOTP_SECRET)


def store_fingerprint_key(value: bytes) -> None:
    """Persist the 32-byte HMAC key used by the scanner matcher."""
    _store_bytes(USER_FINGERPRINT_KEY, value)


def load_fingerprint_key() -> bytes:
    """Return the stored fingerprint HMAC key bytes."""
    return _load_bytes(USER_FINGERPRINT_KEY)


def delete_all_keyguard_entries() -> None:
    """Remove every KeyGuard-owned entry from the OS keychain.

    Idempotent: missing entries are silently skipped. Used by first-run
    rollback, ``keyguard uninstall``, and test teardown.
    """
    for username in _ALL_USERNAMES:
        try:
            keyring.delete_password(SERVICE_NAME, username)
        except PasswordDeleteError:
            # Entry didn't exist — acceptable.
            continue
        except NoKeyringError as exc:
            raise KeychainUnavailableError(
                "OS keychain service is not available on this machine"
            ) from exc
        except KeyringError as exc:
            raise KeychainError(f"failed to delete {username} from OS keychain: {exc}") from exc
