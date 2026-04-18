"""Pydantic v2 data models for the KeyGuard vault body and supporting types.

All models forbid JSON serialization of ``SecretStr`` fields outside an
explicit :func:`encrypted_context` scope. ``vault.save()`` is the only
code path that enters this context; everywhere else gets ``CryptoError``
on attempt. This is the Task 2.1 guardrail from ``docs/PLAN.md``.
"""

from collections.abc import Iterator
from contextlib import contextmanager
from contextvars import ContextVar
from datetime import datetime
from enum import StrEnum
from hashlib import sha256
from hmac import new as hmac_new
from typing import Any
from uuid import UUID, uuid4

from pydantic import Base64Bytes, BaseModel, ConfigDict, Field, SecretStr, field_serializer

from keyguard.core.errors import CryptoError

__all__ = [
    "FINGERPRINT_KEY_LEN",
    "FINGERPRINT_LEN",
    "AccessEvent",
    "Deployment",
    "EventType",
    "Exposure",
    "ExposureLifecycle",
    "ExposureSeverity",
    "ExposureSourceType",
    "ExposureStatus",
    "Key",
    "KeyVersion",
    "Vault",
    "VaultSettings",
    "compute_fingerprint",
    "encrypted_context",
    "is_in_encrypted_context",
]

FINGERPRINT_LEN = 32  # HMAC-SHA256 output
FINGERPRINT_KEY_LEN = 32  # per-vault HMAC key


# ---------------------------------------------------------------------------
# Encrypted-context guardrail
# ---------------------------------------------------------------------------
_encrypted_context: ContextVar[bool] = ContextVar("keyguard_encrypted_context", default=False)


@contextmanager
def encrypted_context() -> Iterator[None]:
    """Enter a scope where SecretStr JSON serialization is permitted.

    Only ``vault.save()`` should enter this context. Any other code path
    that tries to JSON-dump a model containing a ``SecretStr`` will raise
    :class:`CryptoError` — a deliberate tripwire against accidental leaks
    through logging or debug prints.
    """
    token = _encrypted_context.set(True)
    try:
        yield
    finally:
        _encrypted_context.reset(token)


def is_in_encrypted_context() -> bool:
    """Return whether the current task is inside :func:`encrypted_context`."""
    return _encrypted_context.get()


# ---------------------------------------------------------------------------
# Fingerprint
# ---------------------------------------------------------------------------
def compute_fingerprint(value: str, fingerprint_key: bytes) -> bytes:
    """HMAC-SHA256 fingerprint of ``value`` under ``fingerprint_key``.

    Used by the scanner/matcher to check whether a finding is a known
    vault key without unlocking the vault. The per-vault HMAC key (stored
    in the OS keychain alongside ``local_half``) prevents offline
    fingerprint-guessing against low-entropy secrets.
    """
    if len(fingerprint_key) != FINGERPRINT_KEY_LEN:
        raise CryptoError(
            f"fingerprint_key must be {FINGERPRINT_KEY_LEN} bytes, got {len(fingerprint_key)}"
        )
    return hmac_new(fingerprint_key, value.encode("utf-8"), sha256).digest()


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------
class EventType(StrEnum):
    """Types of entries recorded in :attr:`Vault.access_log`."""

    VAULT_UNLOCKED = "vault_unlocked"
    VAULT_LOCKED = "vault_locked"
    VAULT_UNLOCK_FAILED = "vault_unlock_failed"
    KEY_ADDED = "key_added"
    KEY_REVEALED = "key_revealed"
    KEY_COPIED = "key_copied"
    KEY_EDITED = "key_edited"
    KEY_DELETED = "key_deleted"
    KEY_ROTATED = "key_rotated"
    SCAN_RUN = "scan_run"
    EXPOSURE_DETECTED = "exposure_detected"
    EXPOSURE_ACKNOWLEDGED = "exposure_acknowledged"
    EXPOSURE_RESOLVED = "exposure_resolved"
    DEPLOYMENT_ADDED = "deployment_added"
    DEPLOYMENT_REMOVED = "deployment_removed"


class ExposureStatus(StrEnum):
    """Classification of a :class:`Key`'s overall exposure state."""

    UNKNOWN = "unknown"
    SUSPECTED_LEAKED = "suspected_leaked"
    CONFIRMED_LEAKED = "confirmed_leaked"
    RESOLVED = "resolved"


class ExposureLifecycle(StrEnum):
    """Lifecycle of a single :class:`Exposure` incident."""

    DETECTED = "detected"
    ACKNOWLEDGED = "acknowledged"
    RESOLVED = "resolved"


class ExposureSeverity(StrEnum):
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class ExposureSourceType(StrEnum):
    GIT_HISTORY = "git_history"
    FILESYSTEM = "filesystem"
    PUBLIC_GITHUB = "public_github"
    USER_REPORTED = "user_reported"


# ---------------------------------------------------------------------------
# Shared base
# ---------------------------------------------------------------------------
class _StrictBase(BaseModel):
    """Shared configuration: strict type coercion, tolerate extra fields.

    ``extra='ignore'`` preserves forward compat within a single
    ``format_version`` — newer writers may add fields, and older readers
    silently drop them rather than refusing to open the vault.
    """

    model_config = ConfigDict(strict=True, extra="ignore")


# ---------------------------------------------------------------------------
# Leaf models
# ---------------------------------------------------------------------------
class KeyVersion(_StrictBase):
    """One generation of a stored secret under a :class:`Key`.

    ``value`` is a :class:`SecretStr` — opaque in :meth:`model_dump` and
    only JSON-serializable inside :func:`encrypted_context`. ``fingerprint``
    is pre-computed via :func:`compute_fingerprint` at version creation.
    """

    version_number: int = Field(ge=1)
    value: SecretStr
    created_at: datetime
    revoked_at: datetime | None = None
    rotation_reason: str | None = None
    fingerprint: Base64Bytes

    @field_serializer("value", when_used="json")
    def _serialize_value(self, v: SecretStr) -> str:
        if not is_in_encrypted_context():
            raise CryptoError(
                "refusing to serialize SecretStr outside encrypted_context() — "
                "only core.vault.UnlockedVault.save() should ever enter that context"
            )
        return v.get_secret_value()


class Deployment(_StrictBase):
    """Where a :class:`Key` is installed (free-form per-key record)."""

    id: UUID = Field(default_factory=uuid4)
    platform: str  # e.g. "vercel", "github-actions", "local-env"
    identifier: str  # e.g. "project-xyz", "repo/workflow.yml"
    variable_name: str  # e.g. "STRIPE_SECRET_KEY"
    added_at: datetime
    last_verified_at: datetime | None = None
    notes: str | None = None


class Exposure(_StrictBase):
    """A recorded leak incident for a specific :class:`KeyVersion`."""

    id: UUID = Field(default_factory=uuid4)
    discovered_at: datetime
    source_type: ExposureSourceType
    location: str  # human-readable: file path, commit SHA, URL, etc.
    key_fingerprint: Base64Bytes
    severity: ExposureSeverity
    status: ExposureLifecycle = ExposureLifecycle.DETECTED
    resolved_at: datetime | None = None
    resolved_by_new_version_number: int | None = None


class Key(_StrictBase):
    """A single stored secret identity, possibly with multiple versions."""

    id: UUID = Field(default_factory=uuid4)
    name: str  # unique within the vault; enforced at Vault level
    provider: str  # Provider.name, e.g. "openai"
    tags: list[str] = Field(default_factory=list)
    notes: str | None = None
    versions: list[KeyVersion]  # ordered oldest-first; last is current
    deployments: list[Deployment] = Field(default_factory=list)
    exposure_status: ExposureStatus = ExposureStatus.UNKNOWN
    exposures: list[Exposure] = Field(default_factory=list)


class AccessEvent(_StrictBase):
    """One immutable entry in :attr:`Vault.access_log`.

    ``frozen=True`` means attribute assignment on an existing event raises
    ``ValidationError`` — the audit log is append-only, and individual
    entries are also write-once. (The ``details`` dict can still be
    mutated by reference; audit callers should not rely on that.)
    """

    model_config = ConfigDict(strict=True, extra="ignore", frozen=True)

    timestamp: datetime
    event_type: EventType
    key_id: UUID | None = None
    details: dict[str, Any] = Field(default_factory=dict)
    device_fingerprint: str


class VaultSettings(_StrictBase):
    """User-adjustable vault behavior defaults."""

    clipboard_timeout_seconds: int = 20
    auto_lock_seconds: int = 300
    password_min_length: int = 12
    backup_count: int = 3
    old_version_retention_days: int = 30
    scanner_ignore_globs: list[str] = Field(
        default_factory=lambda: [
            "node_modules/*",
            ".git/*",
            ".venv/*",
            "__pycache__/*",
            "dist/*",
            "build/*",
        ]
    )
    scanner_env_filename_globs: list[str] = Field(
        default_factory=lambda: [
            ".env*",
            "*credentials*",
            "secrets.y*ml",
            ".npmrc",
            ".pypirc",
        ]
    )


class Vault(_StrictBase):
    """Top-level container — everything the vault body decrypts to."""

    format_version: int = 1
    created_at: datetime
    keys: list[Key] = Field(default_factory=list)
    access_log: list[AccessEvent] = Field(default_factory=list)
    settings: VaultSettings = Field(default_factory=VaultSettings)
