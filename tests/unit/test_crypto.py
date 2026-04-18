"""Tests for :mod:`keyguard.core.crypto`.

Includes Hypothesis property tests covering the three acceptance properties
in ``docs/PLAN.md`` Task 1.1: encrypt/decrypt round-trip, tamper detection,
and wrong-KEK rejection on ``unwrap_dek``.
"""

from __future__ import annotations

import pytest
from hypothesis import given, settings
from hypothesis import strategies as st
from pydantic import ValidationError

from keyguard.core import crypto
from keyguard.core.errors import (
    CorruptedVaultError,
    CryptoError,
    WrongPasswordError,
    WrongRecoveryCodeError,
)

# ---------------------------------------------------------------------------
# generate_salt / generate_dek
# ---------------------------------------------------------------------------


def test_generate_salt_length_and_randomness() -> None:
    s1 = crypto.generate_salt()
    s2 = crypto.generate_salt()
    assert len(s1) == crypto.SALT_LEN == 16
    assert len(s2) == crypto.SALT_LEN
    assert s1 != s2  # vanishingly unlikely to collide


def test_generate_dek_length_and_randomness() -> None:
    k1 = crypto.generate_dek()
    k2 = crypto.generate_dek()
    assert len(k1) == crypto.DEK_LEN == 32
    assert k1 != k2


# ---------------------------------------------------------------------------
# generate_recovery_code
# ---------------------------------------------------------------------------


def test_generate_recovery_code_shape() -> None:
    display, raw = crypto.generate_recovery_code()
    assert len(raw) == crypto.RECOVERY_CODE_RAW_LEN == 20
    assert len(display) == 32 + 7  # 32 base32 chars + 7 dashes
    groups = display.split("-")
    assert len(groups) == 8
    assert all(len(g) == 4 for g in groups)


def test_generate_recovery_code_uses_base32_alphabet_only() -> None:
    display, _ = crypto.generate_recovery_code()
    allowed = set("ABCDEFGHIJKLMNOPQRSTUVWXYZ234567-")
    assert set(display) <= allowed


def test_generate_recovery_code_is_random_across_calls() -> None:
    codes = {crypto.generate_recovery_code()[0] for _ in range(20)}
    assert len(codes) == 20


# ---------------------------------------------------------------------------
# compose_primary_kek_input / compose_recovery_kek_input
# ---------------------------------------------------------------------------


def test_compose_primary_kek_input_length_and_determinism() -> None:
    out1 = crypto.compose_primary_kek_input("pw", b"\x00" * 32, b"\x00" * 32)
    out2 = crypto.compose_primary_kek_input("pw", b"\x00" * 32, b"\x00" * 32)
    assert out1 == out2
    assert len(out1) == 3 * crypto.HKDF_OUTPUT_LEN == 96


def test_compose_primary_kek_input_is_splicing_resistant() -> None:
    # Swapping local_half and server_half bytes must produce a different
    # preimage — that is the point of HKDF-per-input domain separation.
    a = crypto.compose_primary_kek_input("pw", b"\x01" * 32, b"\x02" * 32)
    b = crypto.compose_primary_kek_input("pw", b"\x02" * 32, b"\x01" * 32)
    assert a != b


def test_compose_primary_kek_input_password_matters() -> None:
    a = crypto.compose_primary_kek_input("pw-a", b"\x00" * 32, b"\x00" * 32)
    b = crypto.compose_primary_kek_input("pw-b", b"\x00" * 32, b"\x00" * 32)
    assert a != b


def test_compose_recovery_kek_input_length_and_determinism() -> None:
    out1 = crypto.compose_recovery_kek_input("pw", b"\x00" * 20)
    out2 = crypto.compose_recovery_kek_input("pw", b"\x00" * 20)
    assert out1 == out2
    assert len(out1) == 2 * crypto.HKDF_OUTPUT_LEN == 64


def test_compose_primary_rejects_empty_password() -> None:
    with pytest.raises(CryptoError):
        crypto.compose_primary_kek_input("", b"\x00" * 32, b"\x00" * 32)


def test_compose_primary_rejects_wrong_length_local_half() -> None:
    with pytest.raises(CryptoError):
        crypto.compose_primary_kek_input("pw", b"\x00" * 31, b"\x00" * 32)


def test_compose_primary_rejects_wrong_length_server_half() -> None:
    with pytest.raises(CryptoError):
        crypto.compose_primary_kek_input("pw", b"\x00" * 32, b"\x00" * 33)


def test_compose_recovery_rejects_empty_password() -> None:
    with pytest.raises(CryptoError):
        crypto.compose_recovery_kek_input("", b"\x00" * 20)


def test_compose_recovery_rejects_wrong_length_code() -> None:
    with pytest.raises(CryptoError):
        crypto.compose_recovery_kek_input("pw", b"\x00" * 19)


# ---------------------------------------------------------------------------
# derive_kek
# ---------------------------------------------------------------------------


def test_derive_kek_is_deterministic_and_correct_length() -> None:
    preimage = b"x" * 96
    salt = b"\x11" * 16
    k1 = crypto.derive_kek(preimage, salt)
    k2 = crypto.derive_kek(preimage, salt)
    assert k1 == k2
    assert len(k1) == crypto.KEY_LEN == 32


def test_derive_kek_different_salt_yields_different_key() -> None:
    preimage = b"x" * 96
    k1 = crypto.derive_kek(preimage, b"\x01" * 16)
    k2 = crypto.derive_kek(preimage, b"\x02" * 16)
    assert k1 != k2


def test_derive_kek_rejects_empty_preimage() -> None:
    with pytest.raises(CryptoError):
        crypto.derive_kek(b"", b"\x00" * 16)


def test_derive_kek_rejects_wrong_salt_length() -> None:
    with pytest.raises(CryptoError):
        crypto.derive_kek(b"x" * 96, b"\x00" * 15)


# ---------------------------------------------------------------------------
# wrap_dek / unwrap_dek
# ---------------------------------------------------------------------------


def test_wrap_unwrap_roundtrip() -> None:
    kek = crypto.generate_dek()
    dek = crypto.generate_dek()
    salt = crypto.generate_salt()
    wrapped = crypto.wrap_dek(kek, dek, salt)
    assert crypto.unwrap_dek(kek, wrapped) == dek
    assert wrapped.salt == salt
    assert len(wrapped.nonce) == crypto.NONCE_LEN
    assert len(wrapped.ciphertext) == crypto.DEK_LEN + crypto.GCM_TAG_LEN


def test_wrap_uses_fresh_nonce_each_time() -> None:
    kek = crypto.generate_dek()
    dek = crypto.generate_dek()
    salt = crypto.generate_salt()
    w1 = crypto.wrap_dek(kek, dek, salt)
    w2 = crypto.wrap_dek(kek, dek, salt)
    assert w1.nonce != w2.nonce
    assert w1.ciphertext != w2.ciphertext


def test_unwrap_with_wrong_kek_raises_wrong_password() -> None:
    kek = crypto.generate_dek()
    other = crypto.generate_dek()
    wrapped = crypto.wrap_dek(kek, crypto.generate_dek(), crypto.generate_salt())
    with pytest.raises(WrongPasswordError):
        crypto.unwrap_dek(other, wrapped)


def test_unwrap_with_wrong_kek_in_recovery_mode_raises_wrong_recovery() -> None:
    kek = crypto.generate_dek()
    other = crypto.generate_dek()
    wrapped = crypto.wrap_dek(kek, crypto.generate_dek(), crypto.generate_salt())
    with pytest.raises(WrongRecoveryCodeError):
        crypto.unwrap_dek(other, wrapped, recovery=True)


def test_wrap_rejects_wrong_length_kek() -> None:
    with pytest.raises(CryptoError):
        crypto.wrap_dek(b"\x00" * 31, b"\x00" * 32, b"\x00" * 16)


def test_wrap_rejects_wrong_length_dek() -> None:
    with pytest.raises(CryptoError):
        crypto.wrap_dek(b"\x00" * 32, b"\x00" * 31, b"\x00" * 16)


def test_unwrap_rejects_wrong_length_kek() -> None:
    wrapped = crypto.wrap_dek(crypto.generate_dek(), crypto.generate_dek(), crypto.generate_salt())
    with pytest.raises(CryptoError):
        crypto.unwrap_dek(b"\x00" * 31, wrapped)


# ---------------------------------------------------------------------------
# encrypt_body / decrypt_body
# ---------------------------------------------------------------------------


def test_encrypt_decrypt_body_roundtrip() -> None:
    dek = crypto.generate_dek()
    plaintext = b"the quick brown fox" * 1000
    aad = b"metadata"
    body = crypto.encrypt_body(dek, plaintext, aad)
    assert crypto.decrypt_body(dek, body, aad) == plaintext


def test_encrypt_body_empty_plaintext_and_aad_allowed() -> None:
    dek = crypto.generate_dek()
    body = crypto.encrypt_body(dek, b"", b"")
    assert crypto.decrypt_body(dek, body, b"") == b""


def test_decrypt_with_wrong_dek_raises_corrupted_vault() -> None:
    dek = crypto.generate_dek()
    other = crypto.generate_dek()
    body = crypto.encrypt_body(dek, b"secret", b"aad")
    with pytest.raises(CorruptedVaultError):
        crypto.decrypt_body(other, body, b"aad")


def test_decrypt_with_wrong_aad_raises_corrupted_vault() -> None:
    dek = crypto.generate_dek()
    body = crypto.encrypt_body(dek, b"secret", b"aad-A")
    with pytest.raises(CorruptedVaultError):
        crypto.decrypt_body(dek, body, b"aad-B")


def test_encrypt_body_rejects_wrong_length_dek() -> None:
    with pytest.raises(CryptoError):
        crypto.encrypt_body(b"\x00" * 31, b"data", b"aad")


def test_decrypt_body_rejects_wrong_length_dek() -> None:
    dek = crypto.generate_dek()
    body = crypto.encrypt_body(dek, b"x", b"")
    with pytest.raises(CryptoError):
        crypto.decrypt_body(b"\x00" * 31, body, b"")


def test_encrypt_decrypt_10mb_roundtrip() -> None:
    # PLAN 1.1 acceptance: plaintext up to 10 MB must round-trip.
    dek = crypto.generate_dek()
    plaintext = b"A" * (10 * 1024 * 1024)
    body = crypto.encrypt_body(dek, plaintext, b"aad")
    assert crypto.decrypt_body(dek, body, b"aad") == plaintext


# ---------------------------------------------------------------------------
# WrappedDEK / EncryptedBody model validation
# ---------------------------------------------------------------------------


def test_wrapped_dek_rejects_wrong_salt_length() -> None:
    with pytest.raises(CryptoError):
        crypto.WrappedDEK(salt=b"\x00" * 15, nonce=b"\x00" * 12, ciphertext=b"\x00" * 48)


def test_wrapped_dek_rejects_wrong_nonce_length() -> None:
    with pytest.raises(CryptoError):
        crypto.WrappedDEK(salt=b"\x00" * 16, nonce=b"\x00" * 11, ciphertext=b"\x00" * 48)


def test_encrypted_body_rejects_wrong_nonce_length() -> None:
    with pytest.raises(CryptoError):
        crypto.EncryptedBody(nonce=b"\x00" * 11, ciphertext=b"\x00" * 16)


def test_wrapped_dek_is_frozen() -> None:
    w = crypto.WrappedDEK(salt=b"\x00" * 16, nonce=b"\x00" * 12, ciphertext=b"\x00" * 48)
    with pytest.raises(ValidationError):
        w.salt = b"\x11" * 16  # type: ignore[misc]  # exercising frozen guard


def test_encrypted_body_is_frozen() -> None:
    b_ = crypto.EncryptedBody(nonce=b"\x00" * 12, ciphertext=b"\x00" * 16)
    with pytest.raises(ValidationError):
        b_.nonce = b"\x11" * 12  # type: ignore[misc]  # exercising frozen guard


# ---------------------------------------------------------------------------
# Hypothesis property tests (PLAN 1.1 acceptance)
# ---------------------------------------------------------------------------


@given(plaintext=st.binary(min_size=0, max_size=4096), aad=st.binary(max_size=256))
@settings(max_examples=100, deadline=None)
def test_property_encrypt_decrypt_roundtrip(plaintext: bytes, aad: bytes) -> None:
    dek = crypto.generate_dek()
    body = crypto.encrypt_body(dek, plaintext, aad)
    assert crypto.decrypt_body(dek, body, aad) == plaintext


@given(
    plaintext=st.binary(min_size=1, max_size=256),
    aad=st.binary(max_size=64),
    flip=st.integers(min_value=0),
)
@settings(max_examples=100, deadline=None)
def test_property_tamper_ciphertext_bit_raises(plaintext: bytes, aad: bytes, flip: int) -> None:
    dek = crypto.generate_dek()
    body = crypto.encrypt_body(dek, plaintext, aad)
    bit = flip % (len(body.ciphertext) * 8)
    byte_i, bit_i = divmod(bit, 8)
    ct = bytearray(body.ciphertext)
    ct[byte_i] ^= 1 << bit_i
    tampered = crypto.EncryptedBody(nonce=body.nonce, ciphertext=bytes(ct))
    with pytest.raises(CorruptedVaultError):
        crypto.decrypt_body(dek, tampered, aad)


@given(
    plaintext=st.binary(min_size=1, max_size=256),
    aad=st.binary(min_size=1, max_size=64),
    flip=st.integers(min_value=0),
)
@settings(max_examples=50, deadline=None)
def test_property_tamper_aad_bit_raises(plaintext: bytes, aad: bytes, flip: int) -> None:
    dek = crypto.generate_dek()
    body = crypto.encrypt_body(dek, plaintext, aad)
    bit = flip % (len(aad) * 8)
    byte_i, bit_i = divmod(bit, 8)
    tampered_aad = bytearray(aad)
    tampered_aad[byte_i] ^= 1 << bit_i
    with pytest.raises(CorruptedVaultError):
        crypto.decrypt_body(dek, body, bytes(tampered_aad))


@given(
    plaintext=st.binary(min_size=1, max_size=256),
    aad=st.binary(max_size=64),
    flip=st.integers(min_value=0, max_value=crypto.NONCE_LEN * 8 - 1),
)
@settings(max_examples=50, deadline=None)
def test_property_tamper_nonce_bit_raises(plaintext: bytes, aad: bytes, flip: int) -> None:
    dek = crypto.generate_dek()
    body = crypto.encrypt_body(dek, plaintext, aad)
    byte_i, bit_i = divmod(flip, 8)
    nonce = bytearray(body.nonce)
    nonce[byte_i] ^= 1 << bit_i
    tampered = crypto.EncryptedBody(nonce=bytes(nonce), ciphertext=body.ciphertext)
    with pytest.raises(CorruptedVaultError):
        crypto.decrypt_body(dek, tampered, aad)


@given(dek_payload=st.binary(min_size=32, max_size=32))
@settings(max_examples=30, deadline=None)
def test_property_wrap_unwrap_roundtrip(dek_payload: bytes) -> None:
    kek = crypto.generate_dek()
    wrapped = crypto.wrap_dek(kek, dek_payload, crypto.generate_salt())
    assert crypto.unwrap_dek(kek, wrapped) == dek_payload


@given(dek_payload=st.binary(min_size=32, max_size=32))
@settings(max_examples=30, deadline=None)
def test_property_unwrap_with_wrong_kek_raises(dek_payload: bytes) -> None:
    kek = crypto.generate_dek()
    other = crypto.generate_dek()
    wrapped = crypto.wrap_dek(kek, dek_payload, crypto.generate_salt())
    with pytest.raises(WrongPasswordError):
        crypto.unwrap_dek(other, wrapped)
