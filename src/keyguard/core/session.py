"""Session — the lifecycle around an :class:`UnlockedVault`.

The CLI obtains a :class:`Session` via :meth:`Session.unlock` and calls
methods on it rather than touching the vault directly. This gives us:

* One spot for TOTP verification.
* One spot to append :class:`AccessEvent` entries to the audit log.
* An auto-lock timer that zeroizes the DEK after inactivity.
* A single guarded :meth:`save` that both persists and resets the timer.

``Session`` is not thread-safe; the CLI is single-threaded. The auto-lock
timer runs on a background thread but only ever calls :meth:`lock`.
"""

from __future__ import annotations

import threading
from pathlib import Path
from uuid import UUID

from keyguard.core import audit, keychain, totp
from keyguard.core import vault as vault_io
from keyguard.core.errors import SessionLockedError, WrongTOTPError
from keyguard.core.models import EventType, Key, Vault

__all__ = ["Session"]


class Session:
    """Handle to an unlocked vault with auto-lock + audit logging baked in.

    Do not instantiate directly — use :meth:`Session.unlock`.
    """

    def __init__(self, unlocked: vault_io.UnlockedVault) -> None:
        self._vault: vault_io.UnlockedVault | None = unlocked
        self._timer: threading.Timer | None = None
        self._reset_auto_lock()

    # --------------------------------------------------------------------- #
    # Factories
    # --------------------------------------------------------------------- #
    @classmethod
    def unlock(cls, vault_path: Path, password: str, totp_code: str) -> Session:
        """Load keychain material, verify TOTP, open vault, record unlock event.

        Order matters:

        1. Load TOTP secret from keychain.
        2. Verify TOTP code (fail-closed if wrong — no disk touch).
        3. Load ``local_half`` from keychain.
        4. Open the vault (raises ``WrongPasswordError`` if password wrong).
        5. Record ``VAULT_UNLOCKED`` in the audit log.
        6. Save so the event persists immediately.
        """
        totp_secret = keychain.load_totp_secret()
        if not totp.verify_code(totp_secret, totp_code):
            raise WrongTOTPError("TOTP code did not verify against the stored secret")
        local_half = keychain.load_local_half()
        unlocked = vault_io.open_vault(vault_path, password, local_half)
        audit.append_event(unlocked.vault, EventType.VAULT_UNLOCKED)
        unlocked.save()
        return cls(unlocked)

    # --------------------------------------------------------------------- #
    # State
    # --------------------------------------------------------------------- #
    @property
    def is_locked(self) -> bool:
        return self._vault is None

    @property
    def vault(self) -> Vault:
        """The decrypted :class:`Vault` model. Callers mutate this directly
        for reads and light edits; state-changing operations should go
        through :class:`Session` methods that record audit events.
        """
        return self._require_unlocked().vault

    def _require_unlocked(self) -> vault_io.UnlockedVault:
        if self._vault is None:
            raise SessionLockedError("session is locked — unlock again to continue")
        return self._vault

    # --------------------------------------------------------------------- #
    # Lifecycle
    # --------------------------------------------------------------------- #
    def lock(self) -> None:
        """Zeroize the DEK, cancel the auto-lock timer, and record the event.

        Idempotent — calling ``lock`` on an already-locked session is a no-op.
        The ``VAULT_LOCKED`` event is recorded on a best-effort basis; if
        the vault save fails during lock (e.g. disk went away), we still
        drop the in-memory state.
        """
        if self._vault is None:
            return
        self._cancel_timer()
        try:
            audit.append_event(self._vault.vault, EventType.VAULT_LOCKED)
            self._vault.save()
        except Exception:  # noqa: S110 — locking must succeed regardless
            # If save fails during lock we still drop in-memory state.
            # Underlying error will surface on next open.
            pass
        self._vault.zeroize()
        self._vault = None

    def save(self) -> None:
        """Persist current state and reset the auto-lock timer."""
        unlocked = self._require_unlocked()
        unlocked.save()
        self._reset_auto_lock()

    # --------------------------------------------------------------------- #
    # Mutations (each records audit + resets auto-lock)
    # --------------------------------------------------------------------- #
    def add_key(self, key: Key) -> None:
        """Append a new :class:`Key` to the vault."""
        unlocked = self._require_unlocked()
        unlocked.vault.keys.append(key)
        audit.append_event(
            unlocked.vault,
            EventType.KEY_ADDED,
            key_id=key.id,
            details={"name": key.name, "provider": key.provider},
        )
        self._reset_auto_lock()

    def record_key_revealed(self, key_id: UUID) -> None:
        """Record a ``KEY_REVEALED`` audit event (e.g. ``show --reveal``)."""
        unlocked = self._require_unlocked()
        audit.append_event(unlocked.vault, EventType.KEY_REVEALED, key_id=key_id)
        self._reset_auto_lock()

    def record_key_copied(self, key_id: UUID) -> None:
        """Record a ``KEY_COPIED`` audit event (e.g. clipboard copy)."""
        unlocked = self._require_unlocked()
        audit.append_event(unlocked.vault, EventType.KEY_COPIED, key_id=key_id)
        self._reset_auto_lock()

    # --------------------------------------------------------------------- #
    # Auto-lock
    # --------------------------------------------------------------------- #
    def _reset_auto_lock(self) -> None:
        self._cancel_timer()
        if self._vault is None:
            return
        timeout = self._vault.vault.settings.auto_lock_seconds
        if timeout <= 0:
            return
        self._timer = threading.Timer(timeout, self.lock)
        self._timer.daemon = True
        self._timer.start()

    def _cancel_timer(self) -> None:
        if self._timer is not None:
            self._timer.cancel()
            self._timer = None
