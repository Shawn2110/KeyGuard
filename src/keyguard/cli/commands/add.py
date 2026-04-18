"""``keyguard add`` — store a new secret in the vault."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import click
from pydantic import SecretStr

from keyguard.cli import ui
from keyguard.cli._unlock import unlock_or_abort
from keyguard.core import keychain
from keyguard.core.models import Deployment, Key, KeyVersion, compute_fingerprint
from keyguard.core.session import Session

__all__ = ["add_command"]


@click.command("add")
@click.argument("name")
@click.option("--provider", required=True, help="Registry name, e.g. openai, anthropic, stripe.")
@click.option("--tag", "tags", multiple=True, help="Repeatable. Tags attached to this key.")
@click.option(
    "--deployed-at",
    "deployments",
    multiple=True,
    help="Repeatable. platform/identifier/VAR_NAME — e.g. vercel/acme/STRIPE_KEY.",
)
@click.option("--notes", default=None, help="Optional free-form notes.")
@click.option(
    "--vault-path",
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    default=None,
)
def add_command(
    name: str,
    provider: str,
    tags: tuple[str, ...],
    deployments: tuple[str, ...],
    notes: str | None,
    vault_path: Path | None,
) -> None:
    """Store a new secret under NAME in the vault."""
    session = unlock_or_abort(vault_path)
    try:
        value = click.prompt(f"Value for {name!r}", hide_input=True)
        fingerprint_key = keychain.load_fingerprint_key()
        now = datetime.now(UTC)
        kv = KeyVersion(
            version_number=1,
            value=SecretStr(value),
            created_at=now,
            fingerprint=compute_fingerprint(value, fingerprint_key),
        )
        deploys = [_parse_deployment(spec, now) for spec in deployments]
        key = Key(
            name=name,
            provider=provider,
            tags=list(tags),
            notes=notes,
            versions=[kv],
            deployments=deploys,
        )
        _ensure_unique(session, name)
        session.add_key(key)
        session.save()
        ui.print_success(
            f"added {name!r} (provider={provider}, versions=1, deployments={len(deploys)})"
        )
    finally:
        session.lock()


def _parse_deployment(spec: str, now: datetime) -> Deployment:
    parts = spec.split("/")
    if len(parts) != 3 or not all(parts):
        raise click.BadParameter(
            f"--deployed-at value {spec!r} must be in the form platform/identifier/VAR_NAME"
        )
    platform, identifier, var = parts
    return Deployment(
        platform=platform,
        identifier=identifier,
        variable_name=var,
        added_at=now,
    )


def _ensure_unique(session: Session, name: str) -> None:
    if any(k.name == name for k in session.vault.keys):
        ui.print_error(f"a key named {name!r} already exists in this vault")
        raise click.Abort()
