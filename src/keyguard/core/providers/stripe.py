"""Stripe provider — creates, tests, revokes, and lists Stripe restricted keys.

Stripe restricted keys have scoped permissions — we prefer them to full
secret keys when KeyGuard creates new keys on the user's behalf, to limit
blast radius if something goes wrong.
"""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import ClassVar

import httpx
from pydantic import SecretStr

from keyguard.core.errors import (
    ProviderAuthError,
    ProviderError,
    ProviderRateLimitError,
    ProviderUnavailableError,
)
from keyguard.core.providers.base import Provider, ProviderKey, ProviderKeyInfo
from keyguard.core.providers.registry import register

__all__ = ["StripeProvider"]


_API_BASE = "https://api.stripe.com/v1"


def _stripe_request(
    method: str,
    url: str,
    *,
    api_key: str,
    data: dict[str, str] | None = None,
    timeout: float = 15.0,
) -> httpx.Response:
    """Stripe uses Basic auth (key as username) and form-encoded bodies.

    Mirrors :func:`_http.request` but with Stripe's specific conventions.
    """
    try:
        with httpx.Client(timeout=timeout, auth=(api_key, "")) as client:
            resp = client.request(method, url, data=data)
    except httpx.TimeoutException as exc:
        raise ProviderUnavailableError(f"timeout calling {url}") from exc
    except httpx.TransportError as exc:
        raise ProviderUnavailableError(f"network error calling {url}: {exc}") from exc

    if resp.status_code in (401, 403):
        raise ProviderAuthError(f"Stripe rejected credentials at {url} ({resp.status_code})")
    if resp.status_code == 429:
        raise ProviderRateLimitError(f"Stripe rate limited request to {url}")
    if resp.status_code >= 500:
        raise ProviderUnavailableError(f"Stripe returned {resp.status_code} for {url}")
    if resp.status_code >= 400:
        raise ProviderError(f"Stripe returned {resp.status_code} for {url}: {resp.text[:200]}")
    return resp


@register
class StripeProvider(Provider):
    """Stripe. Creates restricted keys with the default read-write scope."""

    name: ClassVar[str] = "stripe"
    display_name: ClassVar[str] = "Stripe"
    key_pattern: ClassVar[re.Pattern[str]] = re.compile(r"sk_(test|live)_[A-Za-z0-9]{24,}")

    def test_key(self, key: str) -> bool:
        try:
            resp = _stripe_request("GET", f"{_API_BASE}/account", api_key=key, timeout=10.0)
        except ProviderError:
            return False
        return resp.status_code == 200

    def create_key(self, existing_key: str, label: str) -> ProviderKey:
        # Stripe's "Create API key" endpoint returns a restricted key.
        resp = _stripe_request(
            "POST",
            f"{_API_BASE}/api_keys",
            api_key=existing_key,
            data={"name": label},
        )
        data = resp.json()
        return ProviderKey(
            key_id=str(data.get("id", "")),
            value=SecretStr(str(data.get("key", data.get("secret", "")))),
            created_at=_parse_created(data.get("created")),
            label=label,
        )

    def revoke_key(self, existing_key: str, key_id_to_revoke: str) -> None:
        _stripe_request(
            "POST",  # Stripe uses POST /{id}/expire to revoke
            f"{_API_BASE}/api_keys/{key_id_to_revoke}/expire",
            api_key=existing_key,
        )

    def list_keys(self, existing_key: str) -> list[ProviderKeyInfo]:
        resp = _stripe_request("GET", f"{_API_BASE}/api_keys", api_key=existing_key)
        data = resp.json()
        items = data.get("data", []) if isinstance(data, dict) else []
        return [
            ProviderKeyInfo(
                key_id=str(item.get("id", "")),
                label=item.get("name"),
                created_at=_parse_created(item.get("created")),
                is_active=not bool(item.get("expired", False)),
            )
            for item in items
            if isinstance(item, dict)
        ]


def _parse_created(value: object) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, int | float):
        return datetime.fromtimestamp(float(value), UTC)
    return None
