"""Tests for :mod:`keyguard.core.models`.

Covers the SecretStr guardrail, fingerprint helper, enum serialization,
and full Vault JSON round-trip inside :func:`encrypted_context`.
"""

import json
from datetime import UTC, datetime
from uuid import uuid4

import pytest
from pydantic import SecretStr, ValidationError
from pydantic_core import PydanticSerializationError

from keyguard.core import models
from keyguard.core.errors import CryptoError

# ---------------------------------------------------------------------------
# encrypted_context
# ---------------------------------------------------------------------------


def test_encrypted_context_default_is_false() -> None:
    assert not models.is_in_encrypted_context()


def test_encrypted_context_sets_and_resets() -> None:
    with models.encrypted_context():
        assert models.is_in_encrypted_context()
    assert not models.is_in_encrypted_context()


def test_encrypted_context_nests_cleanly() -> None:
    with models.encrypted_context():
        with models.encrypted_context():
            assert models.is_in_encrypted_context()
        assert models.is_in_encrypted_context()
    assert not models.is_in_encrypted_context()


# ---------------------------------------------------------------------------
# compute_fingerprint
# ---------------------------------------------------------------------------


def test_compute_fingerprint_length_and_determinism() -> None:
    key = b"\x00" * models.FINGERPRINT_KEY_LEN
    f1 = models.compute_fingerprint("sk-test", key)
    f2 = models.compute_fingerprint("sk-test", key)
    assert f1 == f2
    assert len(f1) == models.FINGERPRINT_LEN == 32


def test_compute_fingerprint_differs_by_value() -> None:
    key = b"\x00" * 32
    assert models.compute_fingerprint("a", key) != models.compute_fingerprint("b", key)


def test_compute_fingerprint_differs_by_key() -> None:
    assert models.compute_fingerprint("x", b"\x00" * 32) != models.compute_fingerprint(
        "x", b"\x01" * 32
    )


def test_compute_fingerprint_rejects_bad_key_length() -> None:
    with pytest.raises(CryptoError):
        models.compute_fingerprint("x", b"\x00" * 31)


# ---------------------------------------------------------------------------
# KeyVersion / SecretStr guardrail
# ---------------------------------------------------------------------------


def _sample_key_version() -> models.KeyVersion:
    return models.KeyVersion(
        version_number=1,
        value=SecretStr("sk-test-123"),
        created_at=datetime.now(UTC),
        fingerprint=b"\x00" * 32,
    )


def test_key_version_dict_dump_leaves_secret_opaque() -> None:
    kv = _sample_key_version()
    d = kv.model_dump()
    assert isinstance(d["value"], SecretStr)
    # repr() of SecretStr never exposes the value
    assert "sk-test-123" not in repr(d["value"])


def test_key_version_json_dump_outside_context_raises() -> None:
    kv = _sample_key_version()
    # Pydantic wraps serializer exceptions in PydanticSerializationError; our
    # CryptoError lives in the __cause__ chain and the message still mentions
    # encrypted_context — both properties are what the guardrail promises.
    with pytest.raises(PydanticSerializationError, match="encrypted_context"):
        kv.model_dump_json()


def test_key_version_json_dump_inside_context_roundtrips() -> None:
    kv = _sample_key_version()
    with models.encrypted_context():
        raw = kv.model_dump_json()
    parsed = json.loads(raw)
    assert parsed["value"] == "sk-test-123"
    kv2 = models.KeyVersion.model_validate_json(raw)
    assert kv2.value.get_secret_value() == "sk-test-123"
    assert kv2.fingerprint == kv.fingerprint


def test_key_version_rejects_zero_version_number() -> None:
    with pytest.raises(ValidationError):
        models.KeyVersion(
            version_number=0,
            value=SecretStr("x"),
            created_at=datetime.now(UTC),
            fingerprint=b"\x00" * 32,
        )


# ---------------------------------------------------------------------------
# Vault
# ---------------------------------------------------------------------------


def test_vault_defaults_are_safe() -> None:
    v = models.Vault(created_at=datetime.now(UTC))
    assert v.format_version == 1
    assert v.keys == []
    assert v.access_log == []
    assert v.settings.auto_lock_seconds == 300
    assert v.settings.backup_count == 3


def test_vault_json_outside_context_raises_when_secret_present() -> None:
    kv = _sample_key_version()
    k = models.Key(name="STRIPE_KEY", provider="stripe", versions=[kv])
    v = models.Vault(created_at=datetime.now(UTC), keys=[k])
    with pytest.raises(PydanticSerializationError, match="encrypted_context"):
        v.model_dump_json()


def test_vault_json_roundtrip_inside_context() -> None:
    kv = _sample_key_version()
    k = models.Key(name="STRIPE_KEY", provider="stripe", versions=[kv])
    v = models.Vault(created_at=datetime.now(UTC), keys=[k])
    with models.encrypted_context():
        raw = v.model_dump_json()
    v2 = models.Vault.model_validate_json(raw)
    assert v2.keys[0].name == "STRIPE_KEY"
    assert v2.keys[0].versions[0].value.get_secret_value() == "sk-test-123"
    assert v2.keys[0].provider == "stripe"


def test_vault_empty_dumps_without_context() -> None:
    # No SecretStr → no guardrail trips.
    v = models.Vault(created_at=datetime.now(UTC))
    raw = v.model_dump_json()
    assert json.loads(raw)["format_version"] == 1


def test_vault_ignores_unknown_fields_on_load() -> None:
    # Strict mode rejects ISO-string datetimes via model_validate(dict);
    # use model_validate_json which parses the datetime during decoding.
    payload = json.dumps(
        {
            "format_version": 1,
            "created_at": datetime.now(UTC).isoformat(),
            "keys": [],
            "access_log": [],
            "settings": models.VaultSettings().model_dump(mode="json"),
            "future_field": "ignore me",
        }
    )
    v = models.Vault.model_validate_json(payload)
    assert v.format_version == 1


# ---------------------------------------------------------------------------
# Enum serialization
# ---------------------------------------------------------------------------


def test_access_event_enum_serializes_as_string() -> None:
    e = models.AccessEvent(
        timestamp=datetime.now(UTC),
        event_type=models.EventType.VAULT_UNLOCKED,
        device_fingerprint="device-abc",
    )
    d = json.loads(e.model_dump_json())
    assert d["event_type"] == "vault_unlocked"


def test_exposure_enums_serialize_as_strings() -> None:
    exp = models.Exposure(
        discovered_at=datetime.now(UTC),
        source_type=models.ExposureSourceType.GIT_HISTORY,
        location="deadbeef:.env:3",
        key_fingerprint=b"\x00" * 32,
        severity=models.ExposureSeverity.HIGH,
    )
    d = json.loads(exp.model_dump_json())
    assert d["source_type"] == "git_history"
    assert d["severity"] == "high"
    assert d["status"] == "detected"


# ---------------------------------------------------------------------------
# Key + Deployment integration
# ---------------------------------------------------------------------------


def test_key_accepts_multiple_versions_and_deployments() -> None:
    kv1 = _sample_key_version()
    kv2 = models.KeyVersion(
        version_number=2,
        value=SecretStr("sk-test-456"),
        created_at=datetime.now(UTC),
        fingerprint=b"\x01" * 32,
    )
    dep = models.Deployment(
        platform="vercel",
        identifier="acme-staging",
        variable_name="STRIPE_KEY",
        added_at=datetime.now(UTC),
    )
    k = models.Key(
        name="STRIPE",
        provider="stripe",
        tags=["prod", "billing"],
        versions=[kv1, kv2],
        deployments=[dep],
    )
    assert len(k.versions) == 2
    assert k.versions[-1].version_number == 2
    assert k.deployments[0].platform == "vercel"
    assert k.exposure_status == models.ExposureStatus.UNKNOWN


def test_vault_settings_scanner_globs_have_sensible_defaults() -> None:
    s = models.VaultSettings()
    assert any("node_modules" in g for g in s.scanner_ignore_globs)
    assert ".env*" in s.scanner_env_filename_globs


# ---------------------------------------------------------------------------
# UUID handling
# ---------------------------------------------------------------------------


def test_key_assigns_unique_ids_by_default() -> None:
    k1 = models.Key(name="a", provider="x", versions=[_sample_key_version()])
    k2 = models.Key(name="b", provider="x", versions=[_sample_key_version()])
    assert k1.id != k2.id


def test_explicit_uuid_is_preserved() -> None:
    u = uuid4()
    k = models.Key(id=u, name="a", provider="x", versions=[_sample_key_version()])
    assert k.id == u
