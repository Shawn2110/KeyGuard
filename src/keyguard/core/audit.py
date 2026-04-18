"""Append-only audit log helpers for :class:`Vault.access_log`.

The log lives inside the encrypted body so only the vault owner can read
or modify it. Two invariants hold at the API level:

* Appends go through :func:`append_event` — direct ``vault.access_log.append(...)``
  still works (Python can't prevent it) but is not the supported path, and
  ``AccessEvent`` itself is frozen so existing entries cannot be mutated.
* :func:`verify_log_not_shrunk` is what ``UnlockedVault.save`` uses to
  refuse writes that would erase history. Callers who want to assert the
  invariant mid-session without saving can call it directly.
"""

import hashlib
import platform
from datetime import UTC, datetime
from typing import Any
from uuid import UUID

from keyguard.core.errors import CryptoError
from keyguard.core.models import AccessEvent, EventType, Vault

__all__ = [
    "append_event",
    "current_device_fingerprint",
    "verify_log_not_shrunk",
]


def current_device_fingerprint() -> str:
    """Return a short stable fingerprint of the current machine.

    SHA-256 hex of ``platform.node()``, truncated to 16 chars. Not secret —
    only used for display in audit entries.
    """
    node = platform.node() or "unknown"
    return hashlib.sha256(node.encode("utf-8")).hexdigest()[:16]


def append_event(
    vault: Vault,
    event_type: EventType,
    *,
    key_id: UUID | None = None,
    details: dict[str, Any] | None = None,
) -> AccessEvent:
    """Append a new :class:`AccessEvent` to ``vault.access_log`` and return it.

    Timestamps are always UTC; device fingerprint is the current machine's.
    Callers should prefer this over building an ``AccessEvent`` by hand.
    """
    event = AccessEvent(
        timestamp=datetime.now(UTC),
        event_type=event_type,
        key_id=key_id,
        details=details or {},
        device_fingerprint=current_device_fingerprint(),
    )
    vault.access_log.append(event)
    return event


def verify_log_not_shrunk(length_at_open: int, vault: Vault) -> None:
    """Raise :class:`CryptoError` if the log has fewer entries than at open.

    Enforces the append-only invariant. ``UnlockedVault.save`` calls this
    before serializing the body; anywhere else that mutates the log should
    also call this before relying on the monotonic property.
    """
    if len(vault.access_log) < length_at_open:
        raise CryptoError(
            f"access log shrank from {length_at_open} to "
            f"{len(vault.access_log)} entries — log is append-only"
        )
