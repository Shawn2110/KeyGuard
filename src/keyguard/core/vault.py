"""Vault file I/O — JSON envelope around the encrypted body.

Owns the on-disk format from ``docs/ARCHITECTURE.md`` §5:

- Atomic writes via ``.tmp`` + ``os.replace``.
- Rolling backups: ``vault.enc.bak.1`` (newest), ``.bak.2``, ``.bak.3``.
- Body AAD binds ``format_version``, ``kdf`` params, and the full
  ``wrapped_deks`` list to the GCM tag via SHA-256 of canonical JSON —
  tamper with any metadata and decryption fails.

Does **not** own cryptography (that's ``core.crypto``) or session lifecycle
(``core.session``). The only state on :class:`UnlockedVault` is the
in-memory DEK plus the decrypted :class:`Vault` model.
"""

import json
import os
import shutil
from base64 import b64decode, b64encode
from dataclasses import dataclass, field
from datetime import UTC, datetime
from hashlib import sha256
from pathlib import Path
from typing import Annotated, Any, Final, Literal

import platformdirs
from pydantic import BaseModel, BeforeValidator, ConfigDict, PlainSerializer, ValidationError

from keyguard.core import crypto
from keyguard.core.errors import CorruptedVaultError, CryptoError, UnsupportedVersionError
from keyguard.core.models import Vault, VaultSettings, encrypted_context

__all__ = [
    "SERVER_HALF_V1_PLACEHOLDER",
    "SUPPORTED_FORMAT_VERSION",
    "KdfParams",
    "UnlockedVault",
    "VaultFileFormat",
    "WrappedDEKEntry",
    "create_vault",
    "default_vault_path",
    "open_vault",
    "open_vault_with_recovery",
]

SUPPORTED_FORMAT_VERSION: Final[int] = 1

# v1 sentinel for server_half — ARCHITECTURE §4.2 "hardcoded placeholder (all zeros)".
# In v2 this becomes a real value fetched from a split-key server.
SERVER_HALF_V1_PLACEHOLDER: Final[bytes] = b"\x00" * crypto.KEY_LEN


def _decode_b64_on_load(value: Any) -> bytes:
    if isinstance(value, str):
        return b64decode(value)
    if isinstance(value, bytes):
        return value  # Python-side raw construction, already bytes
    raise TypeError(f"expected str or bytes, got {type(value).__name__}")


# Bytes field that accepts raw bytes in Python and base64 strings in JSON,
# and emits base64 strings when serialized to JSON.
_B64Bytes = Annotated[
    bytes,
    BeforeValidator(_decode_b64_on_load),
    PlainSerializer(lambda b: b64encode(b).decode("ascii"), return_type=str, when_used="json"),
]


# ---------------------------------------------------------------------------
# On-disk envelope models
# ---------------------------------------------------------------------------
class KdfParams(BaseModel):
    """Argon2id parameter snapshot persisted in the vault file."""

    model_config = ConfigDict(strict=True, extra="ignore")

    algorithm: Literal["argon2id"] = "argon2id"
    time_cost: int = crypto.ARGON2_TIME_COST
    memory_cost: int = crypto.ARGON2_MEMORY_COST
    parallelism: int = crypto.ARGON2_PARALLELISM


class WrappedDEKEntry(BaseModel):
    """One wrapped-DEK entry in the vault envelope (primary or recovery)."""

    model_config = ConfigDict(strict=True, extra="ignore")

    id: Literal["primary", "recovery"]
    salt: _B64Bytes
    nonce: _B64Bytes
    ciphertext: _B64Bytes

    def to_crypto(self) -> crypto.WrappedDEK:
        return crypto.WrappedDEK(salt=self.salt, nonce=self.nonce, ciphertext=self.ciphertext)

    @classmethod
    def from_crypto(
        cls, entry_id: Literal["primary", "recovery"], w: crypto.WrappedDEK
    ) -> "WrappedDEKEntry":
        return cls(id=entry_id, salt=w.salt, nonce=w.nonce, ciphertext=w.ciphertext)


class _EncryptedBodyOnDisk(BaseModel):
    model_config = ConfigDict(strict=True, extra="ignore")

    nonce: _B64Bytes
    ciphertext: _B64Bytes


class VaultFileFormat(BaseModel):
    """The full JSON envelope as it lives on disk."""

    model_config = ConfigDict(strict=True, extra="ignore")

    format_version: int
    created_at: datetime
    kdf: KdfParams
    wrapped_deks: list[WrappedDEKEntry]
    body: _EncryptedBodyOnDisk


# ---------------------------------------------------------------------------
# Path helpers
# ---------------------------------------------------------------------------
def default_vault_path() -> Path:
    """Return the platform-default vault path (via ``platformdirs``)."""
    return Path(platformdirs.user_data_dir("keyguard", appauthor=False)) / "vault.enc"


def _backup_path(path: Path, n: int) -> Path:
    return path.parent / f"{path.name}.bak.{n}"


# ---------------------------------------------------------------------------
# AAD composition — binds envelope metadata to the body tag
# ---------------------------------------------------------------------------
def _compute_body_aad(
    format_version: int,
    kdf: KdfParams,
    wrapped_deks: list[WrappedDEKEntry],
) -> bytes:
    payload = {
        "format_version": format_version,
        "kdf": kdf.model_dump(mode="json"),
        "wrapped_deks": [w.model_dump(mode="json") for w in wrapped_deks],
    }
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return sha256(canonical.encode("utf-8")).digest()


# ---------------------------------------------------------------------------
# Atomic write + backup rotation
# ---------------------------------------------------------------------------
def _rotate_backups_preserving_current(path: Path, count: int) -> None:
    """Shift ``.bak.1..bak.count``, copy current ``path`` into ``.bak.1``.

    Does NOT delete ``path`` — that happens in the atomic replace step.
    """
    oldest = _backup_path(path, count)
    if oldest.exists():
        oldest.unlink()
    for i in range(count - 1, 0, -1):
        src = _backup_path(path, i)
        dst = _backup_path(path, i + 1)
        if src.exists():
            src.replace(dst)
    shutil.copy2(path, _backup_path(path, 1))


def _atomic_write(path: Path, envelope: VaultFileFormat, backup_count: int) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_name(path.name + ".tmp")
    tmp.write_bytes(envelope.model_dump_json(indent=2).encode("utf-8"))
    if path.exists():
        _rotate_backups_preserving_current(path, count=backup_count)
    os.replace(tmp, path)  # noqa: PTH105 — kept as os.replace so tests can monkeypatch it


# ---------------------------------------------------------------------------
# Load/parse
# ---------------------------------------------------------------------------
def _load_envelope(path: Path) -> VaultFileFormat:
    raw = path.read_bytes()
    try:
        envelope = VaultFileFormat.model_validate_json(raw)
    except ValidationError as exc:
        raise CorruptedVaultError(f"vault file at {path} is not a valid envelope") from exc
    if envelope.format_version > SUPPORTED_FORMAT_VERSION:
        raise UnsupportedVersionError(
            f"vault format_version {envelope.format_version} is newer than "
            f"this build supports (v{SUPPORTED_FORMAT_VERSION})"
        )
    return envelope


def _find_entry(
    wrapped_deks: list[WrappedDEKEntry], entry_id: Literal["primary", "recovery"]
) -> WrappedDEKEntry:
    for w in wrapped_deks:
        if w.id == entry_id:
            return w
    raise CorruptedVaultError(f"vault is missing '{entry_id}' wrapped DEK entry")


# ---------------------------------------------------------------------------
# UnlockedVault — the in-memory handle for an open vault
# ---------------------------------------------------------------------------
@dataclass
class UnlockedVault:
    """Mutable handle to an open vault. Callers mutate ``self.vault`` and
    call :meth:`save` to persist.

    ``_dek`` is held in memory only while this object lives; drop the
    reference (or call :meth:`zeroize`) to "lock" — though Python's GC
    makes true zeroization best-effort.
    """

    path: Path
    vault: Vault
    _dek: bytes
    _wrapped_primary: crypto.WrappedDEK
    _wrapped_recovery: crypto.WrappedDEK
    _access_log_length_at_open: int = field(default=0)

    def save(self) -> None:
        """Serialize and persist the vault atomically.

        Refuses to save if the access log has shrunk since open — an
        invariant of the append-only audit log (ARCHITECTURE §8).
        """
        if len(self.vault.access_log) < self._access_log_length_at_open:
            raise CryptoError(
                "refusing to save: access log shrank from "
                f"{self._access_log_length_at_open} to {len(self.vault.access_log)} "
                "entries since unlock"
            )
        with encrypted_context():
            body_plaintext = self.vault.model_dump_json().encode("utf-8")
        kdf_params = KdfParams()
        wrapped_entries = [
            WrappedDEKEntry.from_crypto("primary", self._wrapped_primary),
            WrappedDEKEntry.from_crypto("recovery", self._wrapped_recovery),
        ]
        aad = _compute_body_aad(SUPPORTED_FORMAT_VERSION, kdf_params, wrapped_entries)
        body = crypto.encrypt_body(self._dek, body_plaintext, aad)
        envelope = VaultFileFormat(
            format_version=SUPPORTED_FORMAT_VERSION,
            created_at=self.vault.created_at,
            kdf=kdf_params,
            wrapped_deks=wrapped_entries,
            body=_EncryptedBodyOnDisk(nonce=body.nonce, ciphertext=body.ciphertext),
        )
        _atomic_write(self.path, envelope, backup_count=self.vault.settings.backup_count)
        self._access_log_length_at_open = len(self.vault.access_log)

    def rotate_password(self, new_password: str, local_half: bytes) -> None:
        """Re-derive ``KEK_primary`` under a new password and re-wrap the DEK.

        The vault body is untouched — that's the point of envelope
        encryption. Save must be called to persist the re-wrap.
        """
        salt_primary = crypto.generate_salt()
        preimage = crypto.compose_primary_kek_input(
            new_password, local_half, SERVER_HALF_V1_PLACEHOLDER
        )
        kek_primary = crypto.derive_kek(preimage, salt_primary)
        self._wrapped_primary = crypto.wrap_dek(kek_primary, self._dek, salt_primary)
        self.save()


# ---------------------------------------------------------------------------
# Factory flows
# ---------------------------------------------------------------------------
def create_vault(
    path: Path,
    password: str,
    local_half: bytes,
    recovery_code_raw: bytes,
    *,
    settings: VaultSettings | None = None,
) -> UnlockedVault:
    """Generate a fresh DEK, wrap it under both KEKs, and persist the vault.

    ``recovery_code_raw`` is the 20-byte raw form of the code the user just
    wrote down (not the dashed display form). ``local_half`` must already
    exist in the keychain — this function does not touch ``keyring``.
    """
    dek = crypto.generate_dek()

    salt_primary = crypto.generate_salt()
    kek_primary = crypto.derive_kek(
        crypto.compose_primary_kek_input(password, local_half, SERVER_HALF_V1_PLACEHOLDER),
        salt_primary,
    )
    wrapped_primary = crypto.wrap_dek(kek_primary, dek, salt_primary)

    salt_recovery = crypto.generate_salt()
    kek_recovery = crypto.derive_kek(
        crypto.compose_recovery_kek_input(password, recovery_code_raw),
        salt_recovery,
    )
    wrapped_recovery = crypto.wrap_dek(kek_recovery, dek, salt_recovery)

    vault = Vault(created_at=datetime.now(UTC), settings=settings or VaultSettings())

    uv = UnlockedVault(
        path=path,
        vault=vault,
        _dek=dek,
        _wrapped_primary=wrapped_primary,
        _wrapped_recovery=wrapped_recovery,
    )
    uv.save()
    return uv


def open_vault(path: Path, password: str, local_half: bytes) -> UnlockedVault:
    """Unlock via the primary path (password + local_half)."""
    envelope = _load_envelope(path)
    primary_entry = _find_entry(envelope.wrapped_deks, "primary")
    kek_primary = crypto.derive_kek(
        crypto.compose_primary_kek_input(password, local_half, SERVER_HALF_V1_PLACEHOLDER),
        primary_entry.salt,
    )
    dek = crypto.unwrap_dek(kek_primary, primary_entry.to_crypto())
    aad = _compute_body_aad(envelope.format_version, envelope.kdf, envelope.wrapped_deks)
    body_plaintext = crypto.decrypt_body(
        dek,
        crypto.EncryptedBody(nonce=envelope.body.nonce, ciphertext=envelope.body.ciphertext),
        aad,
    )
    vault = Vault.model_validate_json(body_plaintext)
    recovery_entry = _find_entry(envelope.wrapped_deks, "recovery")
    return UnlockedVault(
        path=path,
        vault=vault,
        _dek=dek,
        _wrapped_primary=primary_entry.to_crypto(),
        _wrapped_recovery=recovery_entry.to_crypto(),
        _access_log_length_at_open=len(vault.access_log),
    )


def open_vault_with_recovery(path: Path, password: str, recovery_code_raw: bytes) -> UnlockedVault:
    """Unlock via the recovery path (password + recovery code).

    The caller typically follows this with :meth:`UnlockedVault.rotate_password`
    to re-establish a primary KEK on the current device.
    """
    envelope = _load_envelope(path)
    recovery_entry = _find_entry(envelope.wrapped_deks, "recovery")
    kek_recovery = crypto.derive_kek(
        crypto.compose_recovery_kek_input(password, recovery_code_raw),
        recovery_entry.salt,
    )
    dek = crypto.unwrap_dek(kek_recovery, recovery_entry.to_crypto(), recovery=True)
    aad = _compute_body_aad(envelope.format_version, envelope.kdf, envelope.wrapped_deks)
    body_plaintext = crypto.decrypt_body(
        dek,
        crypto.EncryptedBody(nonce=envelope.body.nonce, ciphertext=envelope.body.ciphertext),
        aad,
    )
    vault = Vault.model_validate_json(body_plaintext)
    primary_entry = _find_entry(envelope.wrapped_deks, "primary")
    return UnlockedVault(
        path=path,
        vault=vault,
        _dek=dek,
        _wrapped_primary=primary_entry.to_crypto(),
        _wrapped_recovery=recovery_entry.to_crypto(),
        _access_log_length_at_open=len(vault.access_log),
    )
