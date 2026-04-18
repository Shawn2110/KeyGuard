"""Tests for :mod:`keyguard.core.providers.registry` and the base ABC."""

from __future__ import annotations

import re
from typing import ClassVar

import pytest

from keyguard.core.providers.base import Provider, ProviderKey, ProviderKeyInfo
from keyguard.core.providers.registry import all_providers, get, register


class _FakeProvider(Provider):
    name: ClassVar[str] = "fake-test-provider"
    display_name: ClassVar[str] = "Fake"
    key_pattern: ClassVar[re.Pattern[str]] = re.compile(r"^fake-")

    def test_key(self, key: str) -> bool:
        return key.startswith("fake-")

    def create_key(self, existing_key: str, label: str) -> ProviderKey:
        raise NotImplementedError

    def revoke_key(self, existing_key: str, key_id_to_revoke: str) -> None:
        raise NotImplementedError

    def list_keys(self, existing_key: str) -> list[ProviderKeyInfo]:
        return []


def test_register_and_get_roundtrip() -> None:
    register(_FakeProvider)
    assert get("fake-test-provider") is _FakeProvider


def test_get_unknown_raises_keyerror() -> None:
    with pytest.raises(KeyError):
        get("does-not-exist")


def test_all_providers_includes_builtins() -> None:
    # Importing keyguard.core.providers.{openai,anthropic,stripe} registers them.
    import keyguard.core.providers.anthropic
    import keyguard.core.providers.openai
    import keyguard.core.providers.stripe  # noqa: F401

    names = all_providers().keys()
    assert {"openai", "anthropic", "stripe"} <= set(names)
