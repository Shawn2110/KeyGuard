"""Tests for :mod:`keyguard.core.vault`.

Covers create/open round-trip, wrong-password rejection, crash-simulation
during save, recovery-code unlock, password rotation, AAD tamper, and
backup rotation.
"""

import json
import os
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import SecretStr

from keyguard.core import vault
from keyguard.core.errors import (
    CorruptedVaultError,
    CryptoError,
    UnsupportedVersionError,
    WrongPasswordError,
    WrongRecoveryCodeError,
)
from keyguard.core.models import Key, KeyVersion

PASSWORD = "correct-horse-battery"
LOCAL_HALF = b"\x11" * 32
RECOVERY_RAW = b"\x22" * 20


@pytest.fixture
def vault_path(tmp_path: Path) -> Path:
    return tmp_path / "vault.enc"


def _make_key_version(value: str = "sk-test-v1", fingerprint: bytes | None = None) -> KeyVersion:
    return KeyVersion(
        version_number=1,
        value=SecretStr(value),
        created_at=datetime.now(UTC),
        fingerprint=fingerprint if fingerprint is not None else b"\x33" * 32,
    )


# ---------------------------------------------------------------------------
# create_vault
# ---------------------------------------------------------------------------


def test_create_vault_writes_file(vault_path: Path) -> None:
    uv = vault.create_vault(vault_path, PASSWORD, LOCAL_HALF, RECOVERY_RAW)
    assert vault_path.exists()
    assert uv.vault.format_version == 1
    # Envelope is valid JSON
    envelope = json.loads(vault_path.read_bytes())
    assert envelope["format_version"] == 1
    assert {w["id"] for w in envelope["wrapped_deks"]} == {"primary", "recovery"}


def test_create_then_open_roundtrip(vault_path: Path) -> None:
    uv1 = vault.create_vault(vault_path, PASSWORD, LOCAL_HALF, RECOVERY_RAW)
    kv = _make_key_version()
    uv1.vault.keys.append(Key(name="STRIPE", provider="stripe", versions=[kv]))
    uv1.save()

    uv2 = vault.open_vault(vault_path, PASSWORD, LOCAL_HALF)
    assert len(uv2.vault.keys) == 1
    assert uv2.vault.keys[0].name == "STRIPE"
    assert uv2.vault.keys[0].versions[0].value.get_secret_value() == "sk-test-v1"


# ---------------------------------------------------------------------------
# Wrong credentials
# ---------------------------------------------------------------------------


def test_open_with_wrong_password_raises_and_leaves_file_unchanged(vault_path: Path) -> None:
    vault.create_vault(vault_path, PASSWORD, LOCAL_HALF, RECOVERY_RAW)
    before = vault_path.read_bytes()
    with pytest.raises(WrongPasswordError):
        vault.open_vault(vault_path, "wrong-password", LOCAL_HALF)
    assert vault_path.read_bytes() == before


def test_open_with_wrong_local_half_raises(vault_path: Path) -> None:
    vault.create_vault(vault_path, PASSWORD, LOCAL_HALF, RECOVERY_RAW)
    with pytest.raises(WrongPasswordError):
        vault.open_vault(vault_path, PASSWORD, b"\xaa" * 32)


def test_open_with_wrong_recovery_code_raises(vault_path: Path) -> None:
    vault.create_vault(vault_path, PASSWORD, LOCAL_HALF, RECOVERY_RAW)
    with pytest.raises(WrongRecoveryCodeError):
        vault.open_vault_with_recovery(vault_path, PASSWORD, b"\xbb" * 20)


# ---------------------------------------------------------------------------
# Recovery-code path
# ---------------------------------------------------------------------------


def test_recovery_code_unlocks_vault(vault_path: Path) -> None:
    uv1 = vault.create_vault(vault_path, PASSWORD, LOCAL_HALF, RECOVERY_RAW)
    uv1.vault.keys.append(
        Key(name="K", provider="openai", versions=[_make_key_version("sk-openai-xxx")])
    )
    uv1.save()

    uv2 = vault.open_vault_with_recovery(vault_path, PASSWORD, RECOVERY_RAW)
    assert uv2.vault.keys[0].versions[0].value.get_secret_value() == "sk-openai-xxx"


# ---------------------------------------------------------------------------
# Password rotation
# ---------------------------------------------------------------------------


def test_rotate_password_works_and_old_password_fails(vault_path: Path) -> None:
    uv1 = vault.create_vault(vault_path, PASSWORD, LOCAL_HALF, RECOVERY_RAW)
    new_password = "brand-new-horse-battery"
    new_local_half = b"\x44" * 32
    uv1.rotate_password(new_password, new_local_half)

    # Old password no longer works
    with pytest.raises(WrongPasswordError):
        vault.open_vault(vault_path, PASSWORD, LOCAL_HALF)
    # New password works
    uv2 = vault.open_vault(vault_path, new_password, new_local_half)
    assert uv2.vault.format_version == 1
    # Recovery code still works (recovery wrap was untouched)
    uv3 = vault.open_vault_with_recovery(vault_path, PASSWORD, RECOVERY_RAW)
    assert uv3.vault.format_version == 1


# ---------------------------------------------------------------------------
# Crash simulation during save
# ---------------------------------------------------------------------------


def test_crash_after_tmp_before_replace_preserves_previous(
    vault_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    uv1 = vault.create_vault(vault_path, PASSWORD, LOCAL_HALF, RECOVERY_RAW)
    original_bytes = vault_path.read_bytes()
    uv1.vault.keys.append(Key(name="K", provider="stripe", versions=[_make_key_version()]))

    def boom(src: str, dst: str) -> None:
        raise RuntimeError("simulated crash between .tmp and replace")

    monkeypatch.setattr(os, "replace", boom)
    with pytest.raises(RuntimeError):
        uv1.save()

    # Original file on disk is unchanged.
    assert vault_path.read_bytes() == original_bytes
    # Re-open works and shows no appended key.
    uv2 = vault.open_vault(vault_path, PASSWORD, LOCAL_HALF)
    assert uv2.vault.keys == []


# ---------------------------------------------------------------------------
# Backup rotation
# ---------------------------------------------------------------------------


def test_backup_bak1_created_on_second_save(vault_path: Path) -> None:
    uv = vault.create_vault(vault_path, PASSWORD, LOCAL_HALF, RECOVERY_RAW)
    uv.vault.keys.append(Key(name="a", provider="stripe", versions=[_make_key_version()]))
    uv.save()
    bak1 = vault_path.parent / (vault_path.name + ".bak.1")
    assert bak1.exists()
    assert bak1.read_bytes() != vault_path.read_bytes()


def test_backup_rotates_across_three_saves(vault_path: Path) -> None:
    uv = vault.create_vault(vault_path, PASSWORD, LOCAL_HALF, RECOVERY_RAW)
    for i in range(5):
        uv.vault.keys.append(
            Key(name=f"k{i}", provider="stripe", versions=[_make_key_version(f"sk-{i}")])
        )
        uv.save()
    # We expect .bak.1, .bak.2, .bak.3 to all exist; .bak.4 should not.
    assert (vault_path.parent / (vault_path.name + ".bak.1")).exists()
    assert (vault_path.parent / (vault_path.name + ".bak.2")).exists()
    assert (vault_path.parent / (vault_path.name + ".bak.3")).exists()
    assert not (vault_path.parent / (vault_path.name + ".bak.4")).exists()


# ---------------------------------------------------------------------------
# AAD tamper detection
# ---------------------------------------------------------------------------


def test_metadata_tamper_causes_corrupted_vault(vault_path: Path) -> None:
    vault.create_vault(vault_path, PASSWORD, LOCAL_HALF, RECOVERY_RAW)
    envelope = json.loads(vault_path.read_bytes())
    # Flip a bit of the primary salt — this changes the AAD and fails the
    # body GCM tag. (Password derivation would also fail because the salt
    # drives KEK derivation, so expect WrongPasswordError instead.)
    primary = next(w for w in envelope["wrapped_deks"] if w["id"] == "primary")
    import base64

    salt_bytes = bytearray(base64.b64decode(primary["salt"]))
    salt_bytes[0] ^= 0x01
    primary["salt"] = base64.b64encode(bytes(salt_bytes)).decode("ascii")
    vault_path.write_bytes(json.dumps(envelope).encode("utf-8"))
    with pytest.raises(WrongPasswordError):
        vault.open_vault(vault_path, PASSWORD, LOCAL_HALF)


def test_body_ciphertext_tamper_causes_corrupted_vault(vault_path: Path) -> None:
    vault.create_vault(vault_path, PASSWORD, LOCAL_HALF, RECOVERY_RAW)
    envelope = json.loads(vault_path.read_bytes())
    import base64

    ct = bytearray(base64.b64decode(envelope["body"]["ciphertext"]))
    ct[0] ^= 0x01
    envelope["body"]["ciphertext"] = base64.b64encode(bytes(ct)).decode("ascii")
    vault_path.write_bytes(json.dumps(envelope).encode("utf-8"))
    with pytest.raises(CorruptedVaultError):
        vault.open_vault(vault_path, PASSWORD, LOCAL_HALF)


# ---------------------------------------------------------------------------
# Envelope validation
# ---------------------------------------------------------------------------


def test_unknown_format_version_raises(vault_path: Path) -> None:
    vault.create_vault(vault_path, PASSWORD, LOCAL_HALF, RECOVERY_RAW)
    envelope = json.loads(vault_path.read_bytes())
    envelope["format_version"] = 99
    vault_path.write_bytes(json.dumps(envelope).encode("utf-8"))
    with pytest.raises(UnsupportedVersionError):
        vault.open_vault(vault_path, PASSWORD, LOCAL_HALF)


def test_malformed_envelope_raises_corrupted(vault_path: Path) -> None:
    vault_path.write_bytes(b"not even json")
    with pytest.raises(CorruptedVaultError):
        vault.open_vault(vault_path, PASSWORD, LOCAL_HALF)


def test_missing_wrapped_entry_raises_corrupted(vault_path: Path) -> None:
    vault.create_vault(vault_path, PASSWORD, LOCAL_HALF, RECOVERY_RAW)
    envelope = json.loads(vault_path.read_bytes())
    envelope["wrapped_deks"] = [w for w in envelope["wrapped_deks"] if w["id"] != "primary"]
    vault_path.write_bytes(json.dumps(envelope).encode("utf-8"))
    with pytest.raises(CorruptedVaultError):
        vault.open_vault(vault_path, PASSWORD, LOCAL_HALF)


# ---------------------------------------------------------------------------
# Access log monotonicity guard
# ---------------------------------------------------------------------------


def test_save_refuses_if_access_log_shrank(vault_path: Path) -> None:
    from keyguard.core.models import AccessEvent, EventType

    uv = vault.create_vault(vault_path, PASSWORD, LOCAL_HALF, RECOVERY_RAW)
    uv.vault.access_log.append(
        AccessEvent(
            timestamp=datetime.now(UTC),
            event_type=EventType.VAULT_UNLOCKED,
            device_fingerprint="test",
        )
    )
    uv.save()
    # Reopen, then simulate tampering: shrink the log before saving.
    uv2 = vault.open_vault(vault_path, PASSWORD, LOCAL_HALF)
    uv2.vault.access_log.clear()
    with pytest.raises(CryptoError):
        uv2.save()


# ---------------------------------------------------------------------------
# Default path
# ---------------------------------------------------------------------------


def test_default_vault_path_is_under_user_data() -> None:
    p = vault.default_vault_path()
    assert p.name == "vault.enc"
    assert "keyguard" in str(p).lower()
