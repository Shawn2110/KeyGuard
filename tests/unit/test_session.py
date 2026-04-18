"""Tests for :mod:`keyguard.core.session`.

Uses the in-memory keyring backend from ``test_keychain.py`` (reimported
here to keep each test file standalone) and a real vault file under
``tmp_path``.
"""

import time
from collections.abc import Iterator
from pathlib import Path

import keyring
import pyotp
import pytest
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError
from pydantic import SecretStr

from keyguard.core import keychain, totp, vault
from keyguard.core.errors import (
    LocalHalfMissingError,
    SessionLockedError,
    WrongPasswordError,
    WrongTOTPError,
)
from keyguard.core.models import EventType, Key, KeyVersion
from keyguard.core.session import Session

PASSWORD = "correct-horse-battery"
LOCAL_HALF = b"\xaa" * 32
RECOVERY_RAW = b"\xbb" * 20


class _InMemoryKeyring(KeyringBackend):
    priority = 1  # type: ignore[assignment]

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], str] = {}

    def set_password(self, service: str, username: str, password: str) -> None:
        self._store[(service, username)] = password

    def get_password(self, service: str, username: str) -> str | None:
        return self._store.get((service, username))

    def delete_password(self, service: str, username: str) -> None:
        key = (service, username)
        if key not in self._store:
            raise PasswordDeleteError(f"no such entry: {service}/{username}")
        del self._store[key]


@pytest.fixture
def memory_keyring() -> Iterator[None]:
    previous = keyring.get_keyring()
    keyring.set_keyring(_InMemoryKeyring())
    try:
        yield
    finally:
        keyring.set_keyring(previous)


@pytest.fixture
def prepared_vault(tmp_path: Path, memory_keyring: None) -> Path:
    """Create a vault + populate keychain with valid entries."""
    vault_path = tmp_path / "vault.enc"
    keychain.store_local_half(LOCAL_HALF)
    totp_secret = totp.generate_totp_secret()
    keychain.store_totp_secret(totp_secret)
    vault.create_vault(vault_path, PASSWORD, LOCAL_HALF, RECOVERY_RAW)
    return vault_path


def _current_totp() -> str:
    secret = keychain.load_totp_secret()
    return pyotp.TOTP(totp._base32(secret)).now()


# ---------------------------------------------------------------------------
# unlock
# ---------------------------------------------------------------------------


def test_unlock_happy_path_records_event(prepared_vault: Path) -> None:
    s = Session.unlock(prepared_vault, PASSWORD, _current_totp())
    try:
        assert not s.is_locked
        # The unlock itself appended a VAULT_UNLOCKED event and was saved.
        assert any(e.event_type == EventType.VAULT_UNLOCKED for e in s.vault.access_log)
    finally:
        s.lock()


def test_unlock_with_bad_totp_raises_wrong_totp(prepared_vault: Path) -> None:
    with pytest.raises(WrongTOTPError):
        Session.unlock(prepared_vault, PASSWORD, "000000")


def test_unlock_with_bad_password_raises_wrong_password(prepared_vault: Path) -> None:
    with pytest.raises(WrongPasswordError):
        Session.unlock(prepared_vault, "nope", _current_totp())


def test_unlock_without_keychain_entries_raises(tmp_path: Path, memory_keyring: None) -> None:
    # No store_local_half / store_totp_secret calls — keychain is empty.
    vault_path = tmp_path / "vault.enc"
    with pytest.raises(LocalHalfMissingError):
        Session.unlock(vault_path, PASSWORD, "000000")


# ---------------------------------------------------------------------------
# lock
# ---------------------------------------------------------------------------


def test_lock_records_event_and_transitions_state(prepared_vault: Path) -> None:
    s = Session.unlock(prepared_vault, PASSWORD, _current_totp())
    s.lock()
    assert s.is_locked
    # Access to .vault now raises
    with pytest.raises(SessionLockedError):
        _ = s.vault
    # Reopening shows the VAULT_LOCKED event was recorded + persisted.
    s2 = Session.unlock(prepared_vault, PASSWORD, _current_totp())
    try:
        types = [e.event_type for e in s2.vault.access_log]
        assert EventType.VAULT_LOCKED in types
    finally:
        s2.lock()


def test_lock_is_idempotent(prepared_vault: Path) -> None:
    s = Session.unlock(prepared_vault, PASSWORD, _current_totp())
    s.lock()
    s.lock()  # second call must not raise
    assert s.is_locked


# ---------------------------------------------------------------------------
# Operations
# ---------------------------------------------------------------------------


def test_add_key_appends_and_records_event(prepared_vault: Path) -> None:
    s = Session.unlock(prepared_vault, PASSWORD, _current_totp())
    try:
        kv = KeyVersion(
            version_number=1,
            value=SecretStr("sk-a"),
            created_at=s.vault.created_at,
            fingerprint=b"\x01" * 32,
        )
        k = Key(name="STRIPE", provider="stripe", versions=[kv])
        s.add_key(k)
        s.save()
        assert any(v.name == "STRIPE" for v in s.vault.keys)
        assert any(e.event_type == EventType.KEY_ADDED for e in s.vault.access_log)
    finally:
        s.lock()


def test_operations_after_lock_raise(prepared_vault: Path) -> None:
    from datetime import UTC, datetime

    s = Session.unlock(prepared_vault, PASSWORD, _current_totp())
    s.lock()
    with pytest.raises(SessionLockedError):
        s.save()
    kv = KeyVersion(
        version_number=1,
        value=SecretStr("x"),
        created_at=datetime.now(UTC),
        fingerprint=b"\x00" * 32,
    )
    with pytest.raises(SessionLockedError):
        s.add_key(Key(name="X", provider="stripe", versions=[kv]))


# ---------------------------------------------------------------------------
# Auto-lock timer
# ---------------------------------------------------------------------------


def test_auto_lock_fires_after_timeout(prepared_vault: Path) -> None:
    # Set the vault settings so the auto-lock fires quickly.
    s = Session.unlock(prepared_vault, PASSWORD, _current_totp())
    s.vault.settings.auto_lock_seconds = 1
    s.save()  # re-arms the timer with the new value

    # Wait long enough for the timer to fire.
    deadline = time.monotonic() + 5.0
    while time.monotonic() < deadline:
        if s.is_locked:
            break
        time.sleep(0.1)
    assert s.is_locked, "auto-lock timer did not fire within 5s"


def test_auto_lock_resets_on_save(prepared_vault: Path) -> None:
    s = Session.unlock(prepared_vault, PASSWORD, _current_totp())
    try:
        s.vault.settings.auto_lock_seconds = 2
        s.save()
        # Wait just under the timeout, then save again — timer should reset.
        time.sleep(1.0)
        s.save()
        time.sleep(1.0)  # total 2s since first save, but only 1s since last
        assert not s.is_locked
    finally:
        s.lock()
