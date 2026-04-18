"""Shared unlock helper — prompts for password + TOTP, returns a :class:`Session`.

Lives under ``cli/`` so core stays untouched by prompt concerns.
"""

from __future__ import annotations

from pathlib import Path

import click

from keyguard.cli import ui
from keyguard.core import vault
from keyguard.core.errors import KeyGuardError
from keyguard.core.session import Session

__all__ = ["unlock_or_abort"]


def unlock_or_abort(vault_path: Path | None = None) -> Session:
    """Prompt, unlock, and return a :class:`Session`, or raise ``click.Abort``.

    Catches the whole :class:`KeyGuardError` tree and renders a single
    intentionally-ambiguous message — we do not leak whether the
    password, the TOTP, or the keychain failed, to avoid giving an
    attacker oracle-style feedback.
    """
    path = vault_path or vault.default_vault_path()
    if not path.exists():
        ui.print_error(f"no vault at {path} — run `keyguard init` first, or pass --vault-path")
        raise click.Abort()
    password = click.prompt("Master password", hide_input=True)
    code = click.prompt("TOTP code (6 digits)").strip()
    try:
        return Session.unlock(path, password, code)
    except KeyGuardError as exc:
        ui.print_error(
            "could not unlock vault — wrong password, wrong TOTP, or the "
            "vault file has been tampered with"
        )
        raise click.Abort() from exc
