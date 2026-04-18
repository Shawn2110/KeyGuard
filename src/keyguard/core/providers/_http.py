"""Shared httpx helpers for providers — maps HTTP errors to ProviderError subclasses."""

from __future__ import annotations

import httpx

from keyguard.core.errors import (
    ProviderAuthError,
    ProviderError,
    ProviderRateLimitError,
    ProviderUnavailableError,
)

__all__ = ["request"]


def request(
    method: str,
    url: str,
    *,
    api_key: str,
    timeout: float = 15.0,
    json: dict | None = None,  # type: ignore[type-arg]
    headers: dict[str, str] | None = None,
) -> httpx.Response:
    """Issue an HTTP request with the provider's Bearer auth.

    Raises the appropriate :class:`ProviderError` subclass on 4xx/5xx and
    on network failures. Successful (2xx) responses are returned as-is.
    """
    hdrs = {"Authorization": f"Bearer {api_key}", "Content-Type": "application/json"}
    if headers:
        hdrs.update(headers)
    try:
        with httpx.Client(timeout=timeout) as client:
            resp = client.request(method, url, headers=hdrs, json=json)
    except httpx.TimeoutException as exc:
        raise ProviderUnavailableError(f"timeout calling {url}") from exc
    except httpx.TransportError as exc:
        raise ProviderUnavailableError(f"network error calling {url}: {exc}") from exc

    if resp.status_code == 401 or resp.status_code == 403:
        raise ProviderAuthError(f"provider rejected credentials at {url} ({resp.status_code})")
    if resp.status_code == 429:
        raise ProviderRateLimitError(f"provider rate limited request to {url}")
    if resp.status_code >= 500:
        raise ProviderUnavailableError(f"provider returned {resp.status_code} for {url}")
    if resp.status_code >= 400:
        raise ProviderError(f"provider returned {resp.status_code} for {url}: {resp.text[:200]}")
    return resp
