"""Tests for OpenAI provider via respx-mocked httpx."""

from __future__ import annotations

import httpx
import pytest
import respx

from keyguard.core.errors import (
    ProviderAuthError,
    ProviderRateLimitError,
    ProviderUnavailableError,
)
from keyguard.core.providers.openai import OpenAIProvider


def test_test_key_returns_true_on_200() -> None:
    with respx.mock:
        respx.get("https://api.openai.com/v1/models").mock(
            return_value=httpx.Response(200, json={"data": []})
        )
        assert OpenAIProvider().test_key("sk-ok") is True


def test_test_key_returns_false_on_401() -> None:
    with respx.mock:
        respx.get("https://api.openai.com/v1/models").mock(return_value=httpx.Response(401))
        assert OpenAIProvider().test_key("sk-bad") is False


def test_create_key_parses_response() -> None:
    with respx.mock:
        respx.post("https://api.openai.com/organization/admin/api_keys").mock(
            return_value=httpx.Response(
                200,
                json={"id": "key_123", "value": "sk-newkey-xyz", "created_at": 1720000000},
            )
        )
        pk = OpenAIProvider().create_key("sk-admin", label="prod-laptop")
        assert pk.key_id == "key_123"
        assert pk.value.get_secret_value() == "sk-newkey-xyz"
        assert pk.label == "prod-laptop"
        assert pk.created_at is not None


def test_revoke_key_sends_delete() -> None:
    with respx.mock:
        route = respx.delete("https://api.openai.com/organization/admin/api_keys/key_123").mock(
            return_value=httpx.Response(200)
        )
        OpenAIProvider().revoke_key("sk-admin", "key_123")
        assert route.called


def test_list_keys_parses_data_array() -> None:
    with respx.mock:
        respx.get("https://api.openai.com/organization/admin/api_keys").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": [
                        {"id": "k1", "name": "laptop", "created_at": 1720000000},
                        {"id": "k2", "name": "ci", "created_at": 1720000100, "revoked": True},
                    ]
                },
            )
        )
        result = OpenAIProvider().list_keys("sk-admin")
        assert [k.key_id for k in result] == ["k1", "k2"]
        assert result[0].is_active is True
        assert result[1].is_active is False


def test_create_key_with_invalid_existing_raises_auth() -> None:
    with respx.mock:
        respx.post("https://api.openai.com/organization/admin/api_keys").mock(
            return_value=httpx.Response(401)
        )
        with pytest.raises(ProviderAuthError):
            OpenAIProvider().create_key("sk-bad", label="x")


def test_create_key_with_429_raises_rate_limit() -> None:
    with respx.mock:
        respx.post("https://api.openai.com/organization/admin/api_keys").mock(
            return_value=httpx.Response(429)
        )
        with pytest.raises(ProviderRateLimitError):
            OpenAIProvider().create_key("sk-admin", label="x")


def test_network_failure_raises_unavailable() -> None:
    with respx.mock:
        respx.get("https://api.openai.com/organization/admin/api_keys").mock(
            side_effect=httpx.ConnectError("boom")
        )
        with pytest.raises(ProviderUnavailableError):
            OpenAIProvider().list_keys("sk-admin")
