"""Tests for :mod:`keyguard.core.audit`."""

from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import ValidationError

from keyguard.core import audit
from keyguard.core.errors import CryptoError
from keyguard.core.models import AccessEvent, EventType, Vault


def _empty_vault() -> Vault:
    return Vault(created_at=datetime.now(UTC))


# ---------------------------------------------------------------------------
# append_event
# ---------------------------------------------------------------------------


def test_append_event_adds_to_log() -> None:
    v = _empty_vault()
    ev = audit.append_event(v, EventType.VAULT_UNLOCKED)
    assert len(v.access_log) == 1
    assert v.access_log[0] is ev
    assert ev.event_type == EventType.VAULT_UNLOCKED


def test_append_event_fills_timestamp_and_device_fingerprint() -> None:
    v = _empty_vault()
    ev = audit.append_event(v, EventType.VAULT_UNLOCKED)
    assert ev.timestamp.tzinfo is not None
    assert ev.device_fingerprint
    assert len(ev.device_fingerprint) == 16


def test_append_event_accepts_key_id_and_details() -> None:
    v = _empty_vault()
    kid = uuid4()
    ev = audit.append_event(v, EventType.KEY_ADDED, key_id=kid, details={"name": "STRIPE"})
    assert ev.key_id == kid
    assert ev.details == {"name": "STRIPE"}


def test_append_event_multiple_events_ordered() -> None:
    v = _empty_vault()
    audit.append_event(v, EventType.VAULT_UNLOCKED)
    audit.append_event(v, EventType.KEY_ADDED)
    audit.append_event(v, EventType.KEY_COPIED)
    assert [e.event_type for e in v.access_log] == [
        EventType.VAULT_UNLOCKED,
        EventType.KEY_ADDED,
        EventType.KEY_COPIED,
    ]


# ---------------------------------------------------------------------------
# AccessEvent is frozen — cannot mutate a prior entry
# ---------------------------------------------------------------------------


def test_access_event_is_frozen() -> None:
    ev = AccessEvent(
        timestamp=datetime.now(UTC),
        event_type=EventType.VAULT_UNLOCKED,
        device_fingerprint="abc",
    )
    with pytest.raises(ValidationError):
        ev.event_type = EventType.KEY_DELETED  # type: ignore[misc]  # testing frozen guard


# ---------------------------------------------------------------------------
# verify_log_not_shrunk
# ---------------------------------------------------------------------------


def test_verify_log_not_shrunk_passes_when_equal_or_grown() -> None:
    v = _empty_vault()
    audit.verify_log_not_shrunk(0, v)
    audit.append_event(v, EventType.VAULT_UNLOCKED)
    audit.verify_log_not_shrunk(0, v)
    audit.verify_log_not_shrunk(1, v)


def test_verify_log_not_shrunk_raises_when_cleared() -> None:
    v = _empty_vault()
    audit.append_event(v, EventType.VAULT_UNLOCKED)
    audit.append_event(v, EventType.KEY_ADDED)
    v.access_log.clear()
    with pytest.raises(CryptoError):
        audit.verify_log_not_shrunk(2, v)


def test_verify_log_not_shrunk_raises_when_popped() -> None:
    v = _empty_vault()
    audit.append_event(v, EventType.VAULT_UNLOCKED)
    v.access_log.pop()
    with pytest.raises(CryptoError):
        audit.verify_log_not_shrunk(1, v)


# ---------------------------------------------------------------------------
# Device fingerprint
# ---------------------------------------------------------------------------


def test_current_device_fingerprint_is_deterministic_and_short() -> None:
    a = audit.current_device_fingerprint()
    b = audit.current_device_fingerprint()
    assert a == b
    assert len(a) == 16
    assert all(c in "0123456789abcdef" for c in a)
