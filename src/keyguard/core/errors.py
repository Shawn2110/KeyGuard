"""Exception hierarchy for KeyGuard.

Per ``docs/ARCHITECTURE.md`` §9. Every exception KeyGuard raises itself derives
from :class:`KeyGuardError` so callers at the CLI boundary can catch the whole
library surface with one ``except``. The four subtrees (crypto / keychain /
provider / scanner) stay flat and independent.
"""

from __future__ import annotations

__all__ = [
    "CorruptedVaultError",
    "CryptoError",
    "GitleaksNotFoundError",
    "KeyGuardError",
    "KeychainError",
    "KeychainUnavailableError",
    "LocalHalfAccessDeniedError",
    "LocalHalfMissingError",
    "ProviderAuthError",
    "ProviderError",
    "ProviderRateLimitError",
    "ProviderUnavailableError",
    "ScanTimeoutError",
    "ScannerError",
    "UnsupportedVersionError",
    "WrongPasswordError",
    "WrongRecoveryCodeError",
]


class KeyGuardError(Exception):
    """Root of every exception KeyGuard raises itself.

    The CLI catches this at the command boundary and renders a friendly
    message. Library internals raise a specific subclass — never this class.
    """


# ---------------------------------------------------------------------------
# Crypto subtree
# ---------------------------------------------------------------------------


class CryptoError(KeyGuardError):
    """Base for failures in crypto primitives or envelope handling."""


class WrongPasswordError(CryptoError):
    """Password did not derive a KEK that unwraps the stored DEK."""


class WrongRecoveryCodeError(CryptoError):
    """Recovery code did not derive a KEK that unwraps the stored DEK."""


class CorruptedVaultError(CryptoError):
    """AES-GCM authentication failed on the body or a wrapped DEK.

    Indicates the ciphertext, nonce, or associated data has been tampered
    with, truncated, or written with a mismatched key.
    """


class UnsupportedVersionError(CryptoError):
    """Vault ``format_version`` is newer than this build understands, or is
    a legacy version with no automatic migration path.
    """


# ---------------------------------------------------------------------------
# Keychain subtree
# ---------------------------------------------------------------------------


class KeychainError(KeyGuardError):
    """Base for OS keychain access failures."""


class KeychainUnavailableError(KeychainError):
    """OS keychain service is not reachable at all.

    Typical on a headless Linux session with no Secret Service backend.
    """


class LocalHalfMissingError(KeychainError):
    """Keychain is available but does not contain a ``local_half`` entry.

    Typical on a fresh machine when the user has copied a vault over
    without running ``keyguard init`` on that machine first.
    """


class LocalHalfAccessDeniedError(KeychainError):
    """OS denied access to the stored ``local_half``.

    e.g. the user dismissed the keychain-unlock prompt on macOS.
    """


# ---------------------------------------------------------------------------
# Provider subtree
# ---------------------------------------------------------------------------


class ProviderError(KeyGuardError):
    """Base for failures calling an external key-issuing provider API."""


class ProviderAuthError(ProviderError):
    """Provider rejected the existing (user-supplied) API key.

    Typical during ``create_key`` / ``revoke_key`` / ``list_keys``.
    """


class ProviderRateLimitError(ProviderError):
    """Provider returned HTTP 429 or equivalent rate-limit signal."""


class ProviderUnavailableError(ProviderError):
    """Provider endpoint is unreachable — network error, 5xx, or timeout."""


# ---------------------------------------------------------------------------
# Scanner subtree
# ---------------------------------------------------------------------------


class ScannerError(KeyGuardError):
    """Base for scanner subsystem failures."""


class GitleaksNotFoundError(ScannerError):
    """Bundled gitleaks binary cannot be located for the current platform.

    Indicates a packaging problem, not user error.
    """


class ScanTimeoutError(ScannerError):
    """Scanner subprocess exceeded the configured timeout."""
