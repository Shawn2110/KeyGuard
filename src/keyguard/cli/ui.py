"""Shared ``rich`` formatting helpers for the CLI.

No business logic here — just rendering.
"""

from __future__ import annotations

from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from keyguard.core.models import ExposureStatus, Key

__all__ = [
    "console",
    "err_console",
    "print_error",
    "print_info",
    "print_recovery_code_panel",
    "print_success",
    "print_warning",
    "render_key_table",
]

console = Console()
err_console = Console(stderr=True)


def print_error(message: str) -> None:
    """Print an error to stderr in red."""
    err_console.print(f"[bold red]error:[/bold red] {message}")


def print_warning(message: str) -> None:
    """Print a warning to stderr in yellow."""
    err_console.print(f"[yellow]warning:[/yellow] {message}")


def print_success(message: str) -> None:
    """Print a success message to stdout in green."""
    console.print(f"[green]ok:[/green] {message}")


def print_info(message: str) -> None:
    """Print an informational message to stdout."""
    console.print(message)


def print_recovery_code_panel(display_form: str) -> None:
    """Render the recovery code prominently so the user actually notices it."""
    panel = Panel.fit(
        f"\n[bold yellow]{display_form}[/bold yellow]\n\n"
        "[dim]Write this down NOW. It is the only way to recover the vault "
        "if you lose your password.\nKeyGuard never stores this code — it "
        "will not be shown again.[/dim]\n",
        title="[bold]Recovery code[/bold]",
        border_style="yellow",
    )
    console.print(panel)


def render_key_table(
    keys: list[Key],
    *,
    provider_filter: str | None = None,
    tag_filter: str | None = None,
    exposed_only: bool = False,
) -> Table:
    """Build a ``rich`` table for the vault's keys with optional filters."""
    rows = [
        k
        for k in keys
        if (provider_filter is None or k.provider == provider_filter)
        and (tag_filter is None or tag_filter in k.tags)
        and (not exposed_only or k.exposure_status == ExposureStatus.CONFIRMED_LEAKED)
    ]
    table = Table(title=f"{len(rows)} key(s)", show_lines=False, header_style="bold")
    table.add_column("Name", style="cyan", no_wrap=True)
    table.add_column("Provider", style="magenta")
    table.add_column("Tags")
    table.add_column("Versions", justify="right")
    table.add_column("Deployments", justify="right")
    table.add_column("Exposure")
    for k in rows:
        status = k.exposure_status.value
        status_style = "red" if k.exposure_status == ExposureStatus.CONFIRMED_LEAKED else "dim"
        table.add_row(
            k.name,
            k.provider,
            ", ".join(k.tags) if k.tags else "[dim]—[/dim]",
            str(len(k.versions)),
            str(len(k.deployments)),
            f"[{status_style}]{status}[/{status_style}]",
        )
    return table
