"""``keyguard init`` — scaffold a new vault + keychain state on this machine."""

from __future__ import annotations

from pathlib import Path
from secrets import token_bytes

import click
from pydantic import (
    SecretStr,  # noqa: F401  # re-exported to keep model available if hook adds keys
)

from keyguard.cli import ui
from keyguard.cli.commands.hooks import _install_hooks_impl
from keyguard.core import crypto, keychain, totp, vault
from keyguard.core.errors import KeyGuardError

__all__ = ["init_command"]


@click.command("init")
@click.option(
    "--vault-path",
    type=click.Path(path_type=Path, dir_okay=False),
    default=None,
    help="Where to create the vault (default: platform user data dir).",
)
@click.option(
    "--account",
    default="keyguard-user",
    show_default=True,
    help="Account name shown in your authenticator app.",
)
@click.option(
    "--force/--no-force",
    default=False,
    help="Overwrite an existing vault file at the path.",
)
def init_command(vault_path: Path | None, account: str, force: bool) -> None:
    """Create an encrypted vault and register keychain + TOTP on this machine."""
    vault_path = vault_path or vault.default_vault_path()
    if vault_path.exists() and not force:
        ui.print_error(f"vault already exists at {vault_path} — re-run with --force to overwrite")
        raise click.Abort()

    password = click.prompt(
        "Master password (≥12 chars)",
        hide_input=True,
        confirmation_prompt=True,
    )
    if len(password) < 12:
        ui.print_error("password must be at least 12 characters")
        raise click.Abort()

    # Generate keychain-resident secrets.
    local_half = token_bytes(crypto.KEY_LEN)
    totp_secret = totp.generate_totp_secret()
    fingerprint_key = token_bytes(32)

    try:
        keychain.store_local_half(local_half)
        keychain.store_totp_secret(totp_secret)
        keychain.store_fingerprint_key(fingerprint_key)
    except KeyGuardError as exc:
        ui.print_error(f"could not write to OS keychain: {exc}")
        raise click.Abort() from exc

    # Show the TOTP QR + base32 fallback so the user can register the secret.
    provisioning = totp.provisioning_uri(totp_secret, account=account)
    ui.print_info("\nScan this QR in your authenticator app:")
    ui.print_info(totp.render_qr_ascii(provisioning))
    from base64 import b32encode

    ui.print_info(
        f"Base32 fallback: [bold]{b32encode(totp_secret).decode('ascii').rstrip('=')}[/bold]\n"
    )
    code = click.prompt("Current TOTP code (6 digits)", type=str).strip()
    if not totp.verify_code(totp_secret, code):
        ui.print_error("TOTP code did not validate — aborting init")
        keychain.delete_all_keyguard_entries()
        raise click.Abort()

    # Show the recovery code and require retype.
    display_form, recovery_raw = crypto.generate_recovery_code()
    ui.print_recovery_code_panel(display_form)
    retyped = click.prompt("Type the recovery code back to confirm").strip().upper()
    if retyped != display_form:
        ui.print_error("recovery code mismatch — aborting init to keep your data safe")
        keychain.delete_all_keyguard_entries()
        raise click.Abort()

    # Create the vault.
    try:
        vault.create_vault(vault_path, password, local_half, recovery_raw)
    except KeyGuardError as exc:
        ui.print_error(f"vault creation failed: {exc}")
        keychain.delete_all_keyguard_entries()
        raise click.Abort() from exc

    ui.print_success(f"vault created at {vault_path}")
    if click.confirm("Install global git pre-commit hook now?", default=False):
        try:
            _install_hooks_impl()
            ui.print_success("pre-commit hook installed")
        except KeyGuardError as exc:
            ui.print_warning(f"hook install skipped: {exc}")
