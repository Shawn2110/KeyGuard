"""KeyGuard CLI entry point — the ``keyguard`` command installed by pipx."""

from __future__ import annotations

import click

from keyguard import __version__
from keyguard.cli.commands.add import add_command
from keyguard.cli.commands.copy import copy_command
from keyguard.cli.commands.hooks import install_hooks_command
from keyguard.cli.commands.init import init_command
from keyguard.cli.commands.list_cmd import list_command
from keyguard.cli.commands.rotate import rotate_command
from keyguard.cli.commands.scan import scan_command
from keyguard.cli.commands.show import show_command

# Import concrete providers so their @register decorators fire at CLI startup.
from keyguard.core.providers import anthropic as _anth_provider  # noqa: F401
from keyguard.core.providers import openai as _oa_provider  # noqa: F401
from keyguard.core.providers import stripe as _stripe_provider  # noqa: F401

__all__ = ["cli"]


@click.group(context_settings={"help_option_names": ["-h", "--help"]})
@click.version_option(version=__version__, prog_name="keyguard")
def cli() -> None:
    """KeyGuard — local-first encrypted vault for API keys.

    See https://github.com/Shawn2110/KeyGuard or ``docs/`` in the repo
    for full documentation.
    """


cli.add_command(init_command)
cli.add_command(add_command)
cli.add_command(list_command)
cli.add_command(show_command)
cli.add_command(copy_command)
cli.add_command(scan_command)
cli.add_command(rotate_command)
cli.add_command(install_hooks_command)


if __name__ == "__main__":
    cli()
