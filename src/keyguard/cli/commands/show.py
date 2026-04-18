"""``keyguard show NAME`` — print metadata. ``--reveal`` prints the value."""

from __future__ import annotations

from pathlib import Path

import click

from keyguard.cli import ui
from keyguard.cli._unlock import unlock_or_abort

__all__ = ["show_command"]


@click.command("show")
@click.argument("name")
@click.option("--reveal/--no-reveal", default=False, help="Print the secret value.")
@click.option(
    "--vault-path",
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    default=None,
)
def show_command(name: str, reveal: bool, vault_path: Path | None) -> None:
    """Show metadata for the key NAME; optionally reveal its value."""
    session = unlock_or_abort(vault_path)
    try:
        key = next((k for k in session.vault.keys if k.name == name), None)
        if key is None:
            ui.print_error(f"no key named {name!r} in this vault")
            raise click.Abort()

        ui.console.print(f"[bold cyan]{key.name}[/bold cyan]")
        ui.console.print(f"  provider        : {key.provider}")
        ui.console.print(f"  tags            : {', '.join(key.tags) or '—'}")
        ui.console.print(f"  versions        : {len(key.versions)}")
        ui.console.print(f"  deployments     : {len(key.deployments)}")
        ui.console.print(f"  exposure_status : {key.exposure_status.value}")
        ui.console.print(f"  exposures       : {len(key.exposures)}")
        if key.notes:
            ui.console.print(f"  notes           : {key.notes}")
        for d in key.deployments:
            ui.console.print(f"    - {d.platform}/{d.identifier} ([dim]{d.variable_name}[/dim])")

        if reveal:
            current = key.versions[-1]
            ui.console.print(
                f"\n[bold red]value (v{current.version_number})[/bold red]: "
                f"{current.value.get_secret_value()}"
            )
            session.record_key_revealed(key.id)
            session.save()
    finally:
        session.lock()
