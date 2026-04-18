"""Dynamic discovery of :class:`Provider` subclasses.

A provider registers itself via the ``@register`` decorator at module
load time. Once registered, the CLI can look up by ``Key.provider`` name.
"""

from __future__ import annotations

from keyguard.core.providers.base import Provider

__all__ = ["all_providers", "get", "register"]


_REGISTRY: dict[str, type[Provider]] = {}


def register(provider_cls: type[Provider]) -> type[Provider]:
    """Decorator — register ``provider_cls`` under ``provider_cls.name``.

    Re-registering the same name replaces the existing class (useful for
    tests that substitute stubs). Use sparingly — production providers
    should not collide.
    """
    _REGISTRY[provider_cls.name] = provider_cls
    return provider_cls


def get(name: str) -> type[Provider]:
    """Return the provider class registered under ``name``.

    Raises :class:`KeyError` if no such provider is registered.
    """
    try:
        return _REGISTRY[name]
    except KeyError as exc:
        raise KeyError(f"no provider registered with name: {name!r}") from exc


def all_providers() -> dict[str, type[Provider]]:
    """Return a snapshot of the name → class map."""
    return dict(_REGISTRY)
