"""KeyGuard cryptographic primitives.

Pure functions wrapping the locked AES-256-GCM / Argon2id / HKDF-SHA256 scheme
from ``docs/ARCHITECTURE.md`` §4. No file I/O, no global state, no logging.

Design decisions baked in:

* **Option B for KEK composition.** Each input into a KEK preimage is run
  through HKDF-SHA256 with a distinct ``info`` label before concatenation,
  so an attacker cannot splice bytes between ``password``, ``local_half``,
  ``server_half``, or ``recovery_code``. See :func:`compose_primary_kek_input`.
* **AAD is caller-supplied.** ``encrypt_body``/``decrypt_body`` take the
  associated-authenticated-data as an argument; its composition is a
  vault-level decision finalized in :mod:`keyguard.core.vault` (Task 2.2).
* **No in-module fingerprinting.** SHA-256 fingerprints for scanner match are
  computed in :mod:`keyguard.core.models` at ``KeyVersion`` creation time.

Signature deviations from ARCHITECTURE §6.1:

* ``wrap_dek`` takes an extra ``salt`` parameter so the returned
  :class:`WrappedDEK` carries the KDF salt that produced the wrapping KEK.
* ``unwrap_dek`` accepts a keyword-only ``recovery`` flag so the caller
  chooses whether an auth-tag failure surfaces as
  :class:`WrongPasswordError` or :class:`WrongRecoveryCodeError`.
"""

from __future__ import annotations

from base64 import b32encode
from secrets import token_bytes
from typing import Final

from argon2.low_level import Type as Argon2Type
from argon2.low_level import hash_secret_raw
from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from pydantic import BaseModel, ConfigDict, field_validator

from keyguard.core.errors import (
    CorruptedVaultError,
    CryptoError,
    WrongPasswordError,
    WrongRecoveryCodeError,
)

__all__ = [
    "ARGON2_MEMORY_COST",
    "ARGON2_PARALLELISM",
    "ARGON2_TIME_COST",
    "DEK_LEN",
    "GCM_TAG_LEN",
    "HKDF_OUTPUT_LEN",
    "KEY_LEN",
    "NONCE_LEN",
    "RECOVERY_CODE_RAW_LEN",
    "SALT_LEN",
    "EncryptedBody",
    "WrappedDEK",
    "compose_primary_kek_input",
    "compose_recovery_kek_input",
    "decrypt_body",
    "derive_kek",
    "encrypt_body",
    "generate_dek",
    "generate_recovery_code",
    "generate_salt",
    "unwrap_dek",
    "wrap_dek",
]

# ---------------------------------------------------------------------------
# Locked constants — do not change without updating ARCHITECTURE §4.3
# ---------------------------------------------------------------------------
SALT_LEN: Final[int] = 16
NONCE_LEN: Final[int] = 12
KEY_LEN: Final[int] = 32
DEK_LEN: Final[int] = 32
GCM_TAG_LEN: Final[int] = 16
HKDF_OUTPUT_LEN: Final[int] = 32
RECOVERY_CODE_RAW_LEN: Final[int] = 20

ARGON2_TIME_COST: Final[int] = 3
ARGON2_MEMORY_COST: Final[int] = 65536  # KiB (= 64 MiB)
ARGON2_PARALLELISM: Final[int] = 4

_HKDF_INFO_PASSWORD: Final[bytes] = b"keyguard-kek-password-v1"
_HKDF_INFO_LOCAL_HALF: Final[bytes] = b"keyguard-kek-local-half-v1"
_HKDF_INFO_SERVER_HALF: Final[bytes] = b"keyguard-kek-server-half-v1"
_HKDF_INFO_RECOVERY_CODE: Final[bytes] = b"keyguard-kek-recovery-code-v1"


# ---------------------------------------------------------------------------
# Structured ciphertexts
# ---------------------------------------------------------------------------
class WrappedDEK(BaseModel):
    """AES-GCM-wrapped Data Encryption Key with the salt that produced the KEK.

    Keeping ``salt`` alongside the wrapped DEK means each unlock-path entry
    in the vault file is self-contained — swapping between primary and
    recovery (or, in v2, adding a device) never requires coordinating
    salt placement elsewhere.
    """

    model_config = ConfigDict(strict=True, frozen=True)

    salt: bytes
    nonce: bytes
    ciphertext: bytes

    @field_validator("salt")
    @classmethod
    def _check_salt(cls, v: bytes) -> bytes:
        if len(v) != SALT_LEN:
            raise CryptoError(f"WrappedDEK.salt must be {SALT_LEN} bytes, got {len(v)}")
        return v

    @field_validator("nonce")
    @classmethod
    def _check_nonce(cls, v: bytes) -> bytes:
        if len(v) != NONCE_LEN:
            raise CryptoError(f"WrappedDEK.nonce must be {NONCE_LEN} bytes, got {len(v)}")
        return v


class EncryptedBody(BaseModel):
    """AES-GCM ciphertext for the serialized vault body."""

    model_config = ConfigDict(strict=True, frozen=True)

    nonce: bytes
    ciphertext: bytes

    @field_validator("nonce")
    @classmethod
    def _check_nonce(cls, v: bytes) -> bytes:
        if len(v) != NONCE_LEN:
            raise CryptoError(f"EncryptedBody.nonce must be {NONCE_LEN} bytes, got {len(v)}")
        return v


# ---------------------------------------------------------------------------
# Randomness
# ---------------------------------------------------------------------------
def generate_salt() -> bytes:
    """Return a fresh 16-byte KDF salt."""
    return token_bytes(SALT_LEN)


def generate_dek() -> bytes:
    """Return a fresh 32-byte Data Encryption Key."""
    return token_bytes(DEK_LEN)


def _generate_nonce() -> bytes:
    return token_bytes(NONCE_LEN)


def generate_recovery_code() -> tuple[str, bytes]:
    """Return ``(display_form, raw_bytes)`` for a fresh recovery code.

    Raw form is 20 bytes (160 bits). Display form is 32 base32 characters
    grouped as ``XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`` — eight 4-char
    blocks joined by ``-``. The user sees the display form exactly once
    at ``keyguard init``; the raw form is what enters
    :func:`compose_recovery_kek_input`.
    """
    raw = token_bytes(RECOVERY_CODE_RAW_LEN)
    chars = b32encode(raw).decode("ascii")  # 20 B → 32 chars exact, no padding
    display = "-".join(chars[i : i + 4] for i in range(0, len(chars), 4))
    return display, raw


# ---------------------------------------------------------------------------
# KEK preimage composition (Option B)
# ---------------------------------------------------------------------------
def _hkdf(ikm: bytes, info: bytes) -> bytes:
    return HKDF(
        algorithm=hashes.SHA256(),
        length=HKDF_OUTPUT_LEN,
        salt=None,
        info=info,
    ).derive(ikm)


def compose_primary_kek_input(password: str, local_half: bytes, server_half: bytes) -> bytes:
    """Build the 96-byte Argon2id preimage for ``KEK_primary``.

    Each input is run through HKDF-SHA256 with a distinct ``info`` label
    before concatenation, so a change to any one input cannot be faked by
    shifting bytes between inputs.
    """
    if not password:
        raise CryptoError("password must be non-empty")
    if len(local_half) != KEY_LEN:
        raise CryptoError(f"local_half must be {KEY_LEN} bytes, got {len(local_half)}")
    if len(server_half) != KEY_LEN:
        raise CryptoError(f"server_half must be {KEY_LEN} bytes, got {len(server_half)}")
    return (
        _hkdf(password.encode("utf-8"), _HKDF_INFO_PASSWORD)
        + _hkdf(local_half, _HKDF_INFO_LOCAL_HALF)
        + _hkdf(server_half, _HKDF_INFO_SERVER_HALF)
    )


def compose_recovery_kek_input(password: str, recovery_code: bytes) -> bytes:
    """Build the 64-byte Argon2id preimage for ``KEK_recovery``.

    ``recovery_code`` is the raw 20-byte form (the display form's dashes
    and base32 alphabet are stripped by the caller before getting here).
    """
    if not password:
        raise CryptoError("password must be non-empty")
    if len(recovery_code) != RECOVERY_CODE_RAW_LEN:
        raise CryptoError(
            f"recovery_code must be {RECOVERY_CODE_RAW_LEN} bytes, got {len(recovery_code)}"
        )
    return _hkdf(password.encode("utf-8"), _HKDF_INFO_PASSWORD) + _hkdf(
        recovery_code, _HKDF_INFO_RECOVERY_CODE
    )


# ---------------------------------------------------------------------------
# KEK derivation
# ---------------------------------------------------------------------------
def derive_kek(preimage: bytes, salt: bytes) -> bytes:
    """Derive a 32-byte KEK from ``preimage`` via Argon2id with the locked params.

    ``preimage`` is produced by :func:`compose_primary_kek_input` or
    :func:`compose_recovery_kek_input`. ``salt`` is a 16-byte random value
    stored in cleartext alongside the wrapped DEK in the vault file.
    """
    if not preimage:
        raise CryptoError("preimage must be non-empty")
    if len(salt) != SALT_LEN:
        raise CryptoError(f"salt must be {SALT_LEN} bytes, got {len(salt)}")
    return hash_secret_raw(
        secret=preimage,
        salt=salt,
        time_cost=ARGON2_TIME_COST,
        memory_cost=ARGON2_MEMORY_COST,
        parallelism=ARGON2_PARALLELISM,
        hash_len=KEY_LEN,
        type=Argon2Type.ID,
    )


# ---------------------------------------------------------------------------
# DEK wrap / unwrap (AES-256-GCM; KEK is already salted, no AAD needed)
# ---------------------------------------------------------------------------
def wrap_dek(kek: bytes, dek: bytes, salt: bytes) -> WrappedDEK:
    """Encrypt ``dek`` under ``kek`` and package with the Argon2id ``salt``.

    A fresh 12-byte nonce is generated per call; never reuse a (key, nonce)
    pair. The returned :class:`WrappedDEK` carries the salt that produced
    ``kek`` so the vault file groups per-unlock-path metadata together.
    """
    if len(kek) != KEY_LEN:
        raise CryptoError(f"kek must be {KEY_LEN} bytes, got {len(kek)}")
    if len(dek) != DEK_LEN:
        raise CryptoError(f"dek must be {DEK_LEN} bytes, got {len(dek)}")
    nonce = _generate_nonce()
    ciphertext = AESGCM(kek).encrypt(nonce, dek, None)
    return WrappedDEK(salt=salt, nonce=nonce, ciphertext=ciphertext)


def unwrap_dek(kek: bytes, wrapped: WrappedDEK, *, recovery: bool = False) -> bytes:
    """Decrypt a :class:`WrappedDEK` with ``kek``.

    An auth-tag failure surfaces as :class:`WrongPasswordError` by default,
    or :class:`WrongRecoveryCodeError` if ``recovery=True`` — so the CLI
    can render a credential-specific message without :mod:`crypto` knowing
    which unlock path the caller is on.
    """
    if len(kek) != KEY_LEN:
        raise CryptoError(f"kek must be {KEY_LEN} bytes, got {len(kek)}")
    try:
        plaintext = AESGCM(kek).decrypt(wrapped.nonce, wrapped.ciphertext, None)
    except InvalidTag as exc:
        if recovery:
            raise WrongRecoveryCodeError from exc
        raise WrongPasswordError from exc
    if len(plaintext) != DEK_LEN:
        raise CorruptedVaultError(
            f"unwrapped DEK has wrong length: expected {DEK_LEN}, got {len(plaintext)}"
        )
    return plaintext


# ---------------------------------------------------------------------------
# Body encrypt / decrypt
# ---------------------------------------------------------------------------
def encrypt_body(dek: bytes, plaintext: bytes, aad: bytes) -> EncryptedBody:
    """Encrypt the vault body under the DEK with AES-256-GCM.

    ``aad`` is bound to the ciphertext by the 128-bit GCM tag — the caller
    (``core.vault``) supplies the authoritative AAD composition.
    """
    if len(dek) != DEK_LEN:
        raise CryptoError(f"dek must be {DEK_LEN} bytes, got {len(dek)}")
    nonce = _generate_nonce()
    ciphertext = AESGCM(dek).encrypt(nonce, plaintext, aad)
    return EncryptedBody(nonce=nonce, ciphertext=ciphertext)


def decrypt_body(dek: bytes, body: EncryptedBody, aad: bytes) -> bytes:
    """Decrypt ``body`` with the DEK.

    Any auth-tag failure surfaces as :class:`CorruptedVaultError`: either
    the ciphertext, the nonce, or the AAD has been tampered with,
    truncated, or written under a different key.
    """
    if len(dek) != DEK_LEN:
        raise CryptoError(f"dek must be {DEK_LEN} bytes, got {len(dek)}")
    try:
        return AESGCM(dek).decrypt(body.nonce, body.ciphertext, aad)
    except InvalidTag as exc:
        raise CorruptedVaultError from exc
