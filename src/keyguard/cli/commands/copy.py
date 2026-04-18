"""``keyguard copy NAME`` — put the secret on the clipboard with auto-clear."""

from __future__ import annotations

import threading
from pathlib import Path

import click
import pyperclip

from keyguard.cli import ui
from keyguard.cli._unlock import unlock_or_abort

__all__ = ["copy_command"]


@click.command("copy")
@click.argument("name")
@click.option(
    "--timeout",
    default=20,
    show_default=True,
    help="Seconds before the clipboard is auto-cleared.",
)
@click.option(
    "--vault-path",
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    default=None,
)
def copy_command(name: str, timeout: int, vault_path: Path | None) -> None:
    """Copy NAME's current secret value to the clipboard."""
    session = unlock_or_abort(vault_path)
    try:
        key = next((k for k in session.vault.keys if k.name == name), None)
        if key is None:
            ui.print_error(f"no key named {name!r}")
            raise click.Abort()

        value = key.versions[-1].value.get_secret_value()
        try:
            pyperclip.copy(value)
        except pyperclip.PyperclipException as exc:
            ui.print_error(
                f"clipboard unavailable on this system: {exc}. "
                "Install xclip or xsel (Linux) or run under a desktop session."
            )
            raise click.Abort() from exc

        session.record_key_copied(key.id)
        session.save()
        ui.print_success(f"copied {name!r} to clipboard; clearing in {timeout}s")
        # Schedule a best-effort clear. Separate thread because
        # pyperclip.copy is blocking and the main thread should exit.
        _schedule_clear(value, timeout)
    finally:
        session.lock()


def _schedule_clear(previous_value: str, timeout: int) -> None:
    def clear() -> None:
        try:
            # Only clear if the clipboard still holds what we put there;
            # do not stomp on the user's subsequent copy.
            if pyperclip.paste() == previous_value:
                pyperclip.copy("")
        except pyperclip.PyperclipException:
            pass

    t = threading.Timer(timeout, clear)
    t.daemon = False
    t.start()
