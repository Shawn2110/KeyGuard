"""OpenAI provider — creates, tests, revokes, and lists OpenAI API keys."""

from __future__ import annotations

import re
from datetime import UTC, datetime
from typing import ClassVar

from pydantic import SecretStr

from keyguard.core.errors import ProviderError
from keyguard.core.providers._http import request
from keyguard.core.providers.base import Provider, ProviderKey, ProviderKeyInfo
from keyguard.core.providers.registry import register

__all__ = ["OpenAIProvider"]


_API_BASE = "https://api.openai.com/v1"
_ADMIN_BASE = "https://api.openai.com/organization/admin/api_keys"


@register
class OpenAIProvider(Provider):
    """OpenAI. Use with an admin-scoped key for create/revoke/list."""

    name: ClassVar[str] = "openai"
    display_name: ClassVar[str] = "OpenAI"
    key_pattern: ClassVar[re.Pattern[str]] = re.compile(r"^sk-[A-Za-z0-9_\-]{20,}$")

    def test_key(self, key: str) -> bool:
        """Cheap GET /v1/models to verify auth."""
        try:
            resp = request("GET", f"{_API_BASE}/models", api_key=key, timeout=10.0)
        except ProviderError:
            return False
        return resp.status_code == 200

    def create_key(self, existing_key: str, label: str) -> ProviderKey:
        resp = request(
            "POST",
            _ADMIN_BASE,
            api_key=existing_key,
            json={"name": label},
        )
        data = resp.json()
        return ProviderKey(
            key_id=str(data.get("id", "")),
            value=SecretStr(str(data.get("value", ""))),
            created_at=_parse_created(data.get("created_at")),
            label=label,
        )

    def revoke_key(self, existing_key: str, key_id_to_revoke: str) -> None:
        request(
            "DELETE",
            f"{_ADMIN_BASE}/{key_id_to_revoke}",
            api_key=existing_key,
        )

    def list_keys(self, existing_key: str) -> list[ProviderKeyInfo]:
        resp = request("GET", _ADMIN_BASE, api_key=existing_key)
        data = resp.json()
        items = data.get("data", []) if isinstance(data, dict) else []
        return [
            ProviderKeyInfo(
                key_id=str(item.get("id", "")),
                label=item.get("name"),
                created_at=_parse_created(item.get("created_at")),
                last_used_at=_parse_created(item.get("last_used_at")),
                is_active=not bool(item.get("revoked", False)),
            )
            for item in items
            if isinstance(item, dict)
        ]


def _parse_created(value: object) -> datetime | None:
    if value is None:
        return None
    if isinstance(value, int | float):
        return datetime.fromtimestamp(float(value), UTC)
    if isinstance(value, str):
        try:
            return datetime.fromisoformat(value.replace("Z", "+00:00"))
        except ValueError:
            return None
    return None
