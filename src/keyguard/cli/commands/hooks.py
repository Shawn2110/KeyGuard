"""``keyguard install-hooks`` — global git pre-commit scanner."""

from __future__ import annotations

import contextlib
import platform
import shutil
import subprocess
from pathlib import Path

import click

from keyguard.cli import ui
from keyguard.core.errors import KeyGuardError

__all__ = ["install_hooks_command"]


_HOOKS_DIR_NAME = ".keyguard/hooks"
_HOOK_SCRIPT_SH = """#!/bin/sh
# Installed by `keyguard install-hooks`.
# Delegates to the KeyGuard pre-commit shim; any failure blocks the commit.
python -m keyguard.cli.hook "$@"
"""


def hooks_dir() -> Path:
    """Return ``~/.keyguard/hooks``, creating the parent dir if needed."""
    d = Path.home() / _HOOKS_DIR_NAME
    d.mkdir(parents=True, exist_ok=True)
    return d


def _install_hooks_impl() -> None:
    """Actual install logic — factored out so ``init`` can call it without click."""
    d = hooks_dir()
    hook = d / "pre-commit"
    hook.write_text(_HOOK_SCRIPT_SH, encoding="utf-8")
    # Windows: no real chmod; script runs via git-bash sh anyway.
    with contextlib.suppress(OSError):
        hook.chmod(0o755)
    _set_hooks_path(d)


def _uninstall_hooks_impl() -> None:
    d = hooks_dir()
    hook = d / "pre-commit"
    if hook.exists():
        hook.unlink()
    _unset_hooks_path()


def _set_hooks_path(d: Path) -> None:
    git = shutil.which("git")
    if git is None:
        raise KeyGuardError("git is not installed or not on PATH")
    # Use posix-style path; git accepts it on all platforms.
    subprocess.run(  # noqa: S603
        [git, "config", "--global", "core.hooksPath", str(d).replace("\\", "/")],
        check=True,
    )


def _unset_hooks_path() -> None:
    git = shutil.which("git")
    if git is None:
        raise KeyGuardError("git is not installed or not on PATH")
    subprocess.run(  # noqa: S603
        [git, "config", "--global", "--unset", "core.hooksPath"],
        check=False,  # ok if not set
    )


@click.command("install-hooks")
@click.option("--uninstall/--install", default=False, help="Remove the hook instead.")
def install_hooks_command(uninstall: bool) -> None:
    """Install (or uninstall with --uninstall) the global pre-commit hook."""
    try:
        if uninstall:
            _uninstall_hooks_impl()
            ui.print_success("pre-commit hook removed; core.hooksPath unset")
        else:
            _install_hooks_impl()
            ui.print_success(
                f"pre-commit hook installed at {hooks_dir() / 'pre-commit'} "
                f"(platform: {platform.system()})"
            )
    except KeyGuardError as exc:
        ui.print_error(str(exc))
        raise click.Abort() from exc
