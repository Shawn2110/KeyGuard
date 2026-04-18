"""``keyguard list`` — table view of every key in the vault."""

from __future__ import annotations

from pathlib import Path

import click

from keyguard.cli import ui
from keyguard.cli._unlock import unlock_or_abort

__all__ = ["list_command"]


@click.command("list")
@click.option("--provider", default=None, help="Filter by provider name.")
@click.option("--tag", default=None, help="Filter by tag.")
@click.option("--exposed/--all", default=False, help="Only show confirmed-leaked keys.")
@click.option(
    "--vault-path",
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    default=None,
)
def list_command(
    provider: str | None,
    tag: str | None,
    exposed: bool,
    vault_path: Path | None,
) -> None:
    """List every key in the vault, optionally filtered."""
    session = unlock_or_abort(vault_path)
    try:
        table = ui.render_key_table(
            list(session.vault.keys),
            provider_filter=provider,
            tag_filter=tag,
            exposed_only=exposed,
        )
        ui.console.print(table)
    finally:
        session.lock()
