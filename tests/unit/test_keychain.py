"""Tests for :mod:`keyguard.core.keychain` using an in-memory keyring backend.

The real OS keychain is NEVER touched from a test (per AGENT.md §2.7). We
swap in a custom ``KeyringBackend`` subclass in a fixture.
"""

from collections.abc import Iterator

import keyring
import pytest
from keyring.backend import KeyringBackend
from keyring.errors import (
    NoKeyringError,
    PasswordDeleteError,
    PasswordSetError,
)

from keyguard.core import keychain
from keyguard.core.errors import (
    KeychainError,
    KeychainUnavailableError,
    LocalHalfMissingError,
)


class _InMemoryKeyring(KeyringBackend):
    """Minimal keyring backend that stores entries in a dict."""

    priority = 1  # type: ignore[assignment]  # must be positive to be selectable

    def __init__(self) -> None:
        self._store: dict[tuple[str, str], str] = {}
        self._fail_set: bool = False

    def set_password(self, service: str, username: str, password: str) -> None:
        if self._fail_set:
            raise PasswordSetError("simulated failure")
        self._store[(service, username)] = password

    def get_password(self, service: str, username: str) -> str | None:
        return self._store.get((service, username))

    def delete_password(self, service: str, username: str) -> None:
        key = (service, username)
        if key not in self._store:
            raise PasswordDeleteError(f"no such entry: {service}/{username}")
        del self._store[key]


class _NoBackend(KeyringBackend):
    """Simulates the "no backend available" state on headless machines."""

    priority = 1  # type: ignore[assignment]

    def set_password(self, service: str, username: str, password: str) -> None:
        raise NoKeyringError("no backend available")

    def get_password(self, service: str, username: str) -> str | None:
        raise NoKeyringError("no backend available")

    def delete_password(self, service: str, username: str) -> None:
        raise NoKeyringError("no backend available")


@pytest.fixture
def memory_keyring() -> Iterator[_InMemoryKeyring]:
    previous = keyring.get_keyring()
    backend = _InMemoryKeyring()
    keyring.set_keyring(backend)
    try:
        yield backend
    finally:
        keyring.set_keyring(previous)


@pytest.fixture
def broken_keyring() -> Iterator[None]:
    previous = keyring.get_keyring()
    keyring.set_keyring(_NoBackend())
    try:
        yield
    finally:
        keyring.set_keyring(previous)


# ---------------------------------------------------------------------------
# Round-trip
# ---------------------------------------------------------------------------


def test_local_half_store_load_roundtrip(memory_keyring: _InMemoryKeyring) -> None:
    payload = b"\x01" * 32
    keychain.store_local_half(payload)
    assert keychain.load_local_half() == payload


def test_totp_secret_store_load_roundtrip(memory_keyring: _InMemoryKeyring) -> None:
    payload = b"\x02" * 20
    keychain.store_totp_secret(payload)
    assert keychain.load_totp_secret() == payload


def test_fingerprint_key_store_load_roundtrip(memory_keyring: _InMemoryKeyring) -> None:
    payload = b"\x03" * 32
    keychain.store_fingerprint_key(payload)
    assert keychain.load_fingerprint_key() == payload


def test_entries_are_namespaced_by_username(memory_keyring: _InMemoryKeyring) -> None:
    keychain.store_local_half(b"\x01" * 32)
    keychain.store_totp_secret(b"\x02" * 20)
    keychain.store_fingerprint_key(b"\x03" * 32)
    assert keychain.load_local_half() == b"\x01" * 32
    assert keychain.load_totp_secret() == b"\x02" * 20
    assert keychain.load_fingerprint_key() == b"\x03" * 32


# ---------------------------------------------------------------------------
# Missing / unavailable cases
# ---------------------------------------------------------------------------


def test_load_missing_raises_local_half_missing(memory_keyring: _InMemoryKeyring) -> None:
    with pytest.raises(LocalHalfMissingError):
        keychain.load_local_half()


def test_load_when_keychain_unavailable_raises_unavailable(broken_keyring: None) -> None:
    with pytest.raises(KeychainUnavailableError):
        keychain.load_local_half()


def test_store_when_keychain_unavailable_raises_unavailable(broken_keyring: None) -> None:
    with pytest.raises(KeychainUnavailableError):
        keychain.store_local_half(b"\x00" * 32)


def test_store_on_backend_failure_raises_keychain_error(
    memory_keyring: _InMemoryKeyring,
) -> None:
    memory_keyring._fail_set = True
    with pytest.raises(KeychainError):
        keychain.store_local_half(b"\x00" * 32)


# ---------------------------------------------------------------------------
# delete_all_keyguard_entries
# ---------------------------------------------------------------------------


def test_delete_all_removes_every_keyguard_entry(memory_keyring: _InMemoryKeyring) -> None:
    keychain.store_local_half(b"\x01" * 32)
    keychain.store_totp_secret(b"\x02" * 20)
    keychain.store_fingerprint_key(b"\x03" * 32)
    keychain.delete_all_keyguard_entries()
    with pytest.raises(LocalHalfMissingError):
        keychain.load_local_half()
    with pytest.raises(LocalHalfMissingError):
        keychain.load_totp_secret()
    with pytest.raises(LocalHalfMissingError):
        keychain.load_fingerprint_key()


def test_delete_all_is_idempotent_when_some_entries_missing(
    memory_keyring: _InMemoryKeyring,
) -> None:
    keychain.store_local_half(b"\x01" * 32)
    # Delete twice — second run should not raise.
    keychain.delete_all_keyguard_entries()
    keychain.delete_all_keyguard_entries()


def test_delete_all_raises_when_keychain_unavailable(broken_keyring: None) -> None:
    with pytest.raises(KeychainUnavailableError):
        keychain.delete_all_keyguard_entries()
