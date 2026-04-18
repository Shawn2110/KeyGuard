"""Topology tests for the KeyGuard exception hierarchy (ARCHITECTURE §9)."""

from keyguard.core import errors


def test_every_public_error_descends_from_keyguard_error() -> None:
    for name in errors.__all__:
        cls = getattr(errors, name)
        assert issubclass(cls, errors.KeyGuardError), name


def test_crypto_subtree() -> None:
    assert issubclass(errors.CryptoError, errors.KeyGuardError)
    assert issubclass(errors.WrongPasswordError, errors.CryptoError)
    assert issubclass(errors.WrongRecoveryCodeError, errors.CryptoError)
    assert issubclass(errors.CorruptedVaultError, errors.CryptoError)
    assert issubclass(errors.UnsupportedVersionError, errors.CryptoError)


def test_keychain_subtree() -> None:
    assert issubclass(errors.KeychainError, errors.KeyGuardError)
    assert issubclass(errors.KeychainUnavailableError, errors.KeychainError)
    assert issubclass(errors.LocalHalfMissingError, errors.KeychainError)
    assert issubclass(errors.LocalHalfAccessDeniedError, errors.KeychainError)


def test_provider_subtree() -> None:
    assert issubclass(errors.ProviderError, errors.KeyGuardError)
    assert issubclass(errors.ProviderAuthError, errors.ProviderError)
    assert issubclass(errors.ProviderRateLimitError, errors.ProviderError)
    assert issubclass(errors.ProviderUnavailableError, errors.ProviderError)


def test_scanner_subtree() -> None:
    assert issubclass(errors.ScannerError, errors.KeyGuardError)
    assert issubclass(errors.GitleaksNotFoundError, errors.ScannerError)
    assert issubclass(errors.ScanTimeoutError, errors.ScannerError)


def test_subtrees_do_not_cross_contaminate() -> None:
    assert not issubclass(errors.CryptoError, errors.KeychainError)
    assert not issubclass(errors.KeychainError, errors.CryptoError)
    assert not issubclass(errors.ProviderError, errors.ScannerError)
    assert not issubclass(errors.ScannerError, errors.ProviderError)


def test_every_class_is_raisable_and_caught_at_root() -> None:
    for name in errors.__all__:
        cls = getattr(errors, name)
        try:
            raise cls("probe message")
        except errors.KeyGuardError as exc:
            assert type(exc) is cls
            assert "probe message" in str(exc)
