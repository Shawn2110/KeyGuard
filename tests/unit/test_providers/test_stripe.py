"""Tests for Stripe provider via respx-mocked httpx."""

from __future__ import annotations

import httpx
import pytest
import respx

from keyguard.core.errors import (
    ProviderAuthError,
    ProviderRateLimitError,
    ProviderUnavailableError,
)
from keyguard.core.providers.stripe import StripeProvider

_API = "https://api.stripe.com/v1"


def test_test_key_returns_true_on_200() -> None:
    with respx.mock:
        respx.get(f"{_API}/account").mock(return_value=httpx.Response(200, json={"id": "acct_1"}))
        assert StripeProvider().test_key("sk_test_abc") is True


def test_test_key_returns_false_on_401() -> None:
    with respx.mock:
        respx.get(f"{_API}/account").mock(return_value=httpx.Response(401))
        assert StripeProvider().test_key("sk_test_bad") is False


def test_create_key_parses_response() -> None:
    with respx.mock:
        respx.post(f"{_API}/api_keys").mock(
            return_value=httpx.Response(
                200,
                json={"id": "rk_123", "key": "rk_test_abc", "created": 1720000000},
            )
        )
        pk = StripeProvider().create_key("sk_test_root", label="laptop")
        assert pk.key_id == "rk_123"
        assert pk.value.get_secret_value() == "rk_test_abc"
        assert pk.created_at is not None


def test_revoke_key_posts_to_expire_endpoint() -> None:
    with respx.mock:
        route = respx.post(f"{_API}/api_keys/rk_123/expire").mock(return_value=httpx.Response(200))
        StripeProvider().revoke_key("sk_test_root", "rk_123")
        assert route.called


def test_list_keys_parses_expired_flag() -> None:
    with respx.mock:
        respx.get(f"{_API}/api_keys").mock(
            return_value=httpx.Response(
                200,
                json={
                    "data": [
                        {"id": "rk_a", "name": "live", "expired": False},
                        {"id": "rk_b", "name": "dead", "expired": True},
                    ]
                },
            )
        )
        result = StripeProvider().list_keys("sk_test_root")
        assert result[0].is_active is True
        assert result[1].is_active is False


def test_create_key_with_bad_auth_raises() -> None:
    with respx.mock:
        respx.post(f"{_API}/api_keys").mock(return_value=httpx.Response(401))
        with pytest.raises(ProviderAuthError):
            StripeProvider().create_key("sk_test_bad", label="x")


def test_rate_limit_raises() -> None:
    with respx.mock:
        respx.get(f"{_API}/api_keys").mock(return_value=httpx.Response(429))
        with pytest.raises(ProviderRateLimitError):
            StripeProvider().list_keys("sk_test_root")


def test_network_failure_raises_unavailable() -> None:
    with respx.mock:
        respx.get(f"{_API}/api_keys").mock(side_effect=httpx.ConnectError("boom"))
        with pytest.raises(ProviderUnavailableError):
            StripeProvider().list_keys("sk_test_root")
