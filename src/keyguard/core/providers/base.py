"""Abstract base class for external key-issuing providers.

A :class:`Provider` is a plugin: subclasses implement the four lifecycle
methods (``create_key``, ``revoke_key``, ``test_key``, ``list_keys``) and
declare class-level metadata (name, display name, key regex). The
:mod:`registry` module auto-discovers subclasses by ``name``.
"""

from __future__ import annotations

import re
from abc import ABC, abstractmethod
from datetime import datetime
from typing import ClassVar

from pydantic import BaseModel, ConfigDict, SecretStr, field_serializer

from keyguard.core.errors import CryptoError
from keyguard.core.models import is_in_encrypted_context

__all__ = [
    "Provider",
    "ProviderKey",
    "ProviderKeyInfo",
]


class ProviderKey(BaseModel):
    """A freshly created key returned by :meth:`Provider.create_key`.

    The secret ``value`` is the only field that ever carries plaintext.
    Same JSON guardrail as :class:`KeyVersion` — serializing this outside
    :func:`encrypted_context` raises.
    """

    model_config = ConfigDict(strict=True, extra="ignore")

    key_id: str
    value: SecretStr
    created_at: datetime | None = None
    label: str | None = None

    @field_serializer("value", when_used="json")
    def _serialize_value(self, v: SecretStr) -> str:
        if not is_in_encrypted_context():
            raise CryptoError("refusing to serialize ProviderKey.value outside encrypted_context()")
        return v.get_secret_value()


class ProviderKeyInfo(BaseModel):
    """Metadata about an existing key as returned by :meth:`Provider.list_keys`.

    No secret material. Safe to serialize anywhere.
    """

    model_config = ConfigDict(strict=True, extra="ignore")

    key_id: str
    label: str | None = None
    created_at: datetime | None = None
    last_used_at: datetime | None = None
    is_active: bool = True


class Provider(ABC):
    """Plugin interface for one external API-key-issuing service.

    Subclasses set three class-level attributes:

    - ``name`` — registry key (lowercase, matches ``Key.provider``).
    - ``display_name`` — human-readable.
    - ``key_pattern`` — regex the scanner can use to recognize this
      provider's keys even before vault lookup.
    """

    name: ClassVar[str]
    display_name: ClassVar[str]
    key_pattern: ClassVar[re.Pattern[str]]

    @abstractmethod
    def create_key(self, existing_key: str, label: str) -> ProviderKey:
        """Create a new API key using ``existing_key`` for auth. Return the new key."""

    @abstractmethod
    def revoke_key(self, existing_key: str, key_id_to_revoke: str) -> None:
        """Revoke a specific key by id. ``existing_key`` authenticates the call."""

    @abstractmethod
    def test_key(self, key: str) -> bool:
        """Return True iff the key successfully authenticates against the provider."""

    @abstractmethod
    def list_keys(self, existing_key: str) -> list[ProviderKeyInfo]:
        """Return metadata for every key visible to ``existing_key``."""
