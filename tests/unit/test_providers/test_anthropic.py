"""Tests for Anthropic provider via respx-mocked httpx."""

from __future__ import annotations

import httpx
import pytest
import respx

from keyguard.core.errors import ProviderAuthError, ProviderUnavailableError
from keyguard.core.providers.anthropic import AnthropicProvider

_ADMIN = "https://api.anthropic.com/v1/organizations/default/api_keys"


def test_test_key_returns_true_on_200() -> None:
    with respx.mock:
        respx.get("https://api.anthropic.com/v1/models").mock(
            return_value=httpx.Response(200, json={"data": []})
        )
        assert AnthropicProvider().test_key("sk-ant-ok") is True


def test_test_key_returns_false_on_403() -> None:
    with respx.mock:
        respx.get("https://api.anthropic.com/v1/models").mock(return_value=httpx.Response(403))
        assert AnthropicProvider().test_key("sk-ant-bad") is False


def test_create_key_parses_response() -> None:
    with respx.mock:
        respx.post(_ADMIN).mock(
            return_value=httpx.Response(
                200,
                json={"id": "ak_1", "key": "sk-ant-new", "created_at": "2026-04-18T10:00:00Z"},
            )
        )
        pk = AnthropicProvider().create_key("sk-ant-admin", label="laptop")
        assert pk.key_id == "ak_1"
        assert pk.value.get_secret_value() == "sk-ant-new"


def test_revoke_key_sends_delete() -> None:
    with respx.mock:
        route = respx.delete(f"{_ADMIN}/ak_1").mock(return_value=httpx.Response(200))
        AnthropicProvider().revoke_key("sk-ant-admin", "ak_1")
        assert route.called


def test_list_keys_parses_status_active() -> None:
    with respx.mock:
        respx.get(_ADMIN).mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": [
                        {"id": "a1", "name": "laptop", "status": "active"},
                        {"id": "a2", "name": "old", "status": "revoked"},
                    ]
                },
            )
        )
        result = AnthropicProvider().list_keys("sk-ant-admin")
        assert result[0].is_active is True
        assert result[1].is_active is False


def test_create_key_wrong_auth_raises() -> None:
    with respx.mock:
        respx.post(_ADMIN).mock(return_value=httpx.Response(401))
        with pytest.raises(ProviderAuthError):
            AnthropicProvider().create_key("sk-bad", label="x")


def test_network_failure_raises_unavailable() -> None:
    with respx.mock:
        respx.get(_ADMIN).mock(side_effect=httpx.ConnectError("boom"))
        with pytest.raises(ProviderUnavailableError):
            AnthropicProvider().list_keys("sk-ant-admin")
