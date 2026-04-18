"""``keyguard rotate`` — orchestrate provider key rotation end-to-end."""

from __future__ import annotations

from datetime import UTC, datetime
from pathlib import Path

import click
from pydantic import SecretStr

from keyguard.cli import ui
from keyguard.cli._unlock import unlock_or_abort
from keyguard.core import keychain
from keyguard.core.errors import KeyGuardError
from keyguard.core.models import AccessEvent, EventType, KeyVersion, compute_fingerprint
from keyguard.core.providers import registry

__all__ = ["rotate_command"]


@click.command("rotate")
@click.argument("name")
@click.option(
    "--dry-run/--no-dry-run", default=False, help="Walk the flow without calling the provider."
)
@click.option(
    "--vault-path",
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    default=None,
)
def rotate_command(name: str, dry_run: bool, vault_path: Path | None) -> None:
    """Rotate the key named NAME with its provider, and revoke the old one."""
    session = unlock_or_abort(vault_path)
    try:
        key = next((k for k in session.vault.keys if k.name == name), None)
        if key is None:
            ui.print_error(f"no key named {name!r}")
            raise click.Abort()

        try:
            provider_cls = registry.get(key.provider)
        except KeyError as exc:
            ui.print_error(f"no provider plugin registered for {key.provider!r}")
            raise click.Abort() from exc
        provider = provider_cls()

        old_kv = key.versions[-1]
        if dry_run:
            ui.print_info(
                f"DRY-RUN: would create new {key.provider} key, "
                f"update {len(key.deployments)} deployment(s), and revoke "
                f"old key {old_kv.version_number}"
            )
            return

        ui.print_info(f"creating new {key.provider} key for {name!r}…")
        try:
            new_key = provider.create_key(
                existing_key=old_kv.value.get_secret_value(),
                label=name,
            )
        except KeyGuardError as exc:
            ui.print_error(f"provider create_key failed: {exc}")
            raise click.Abort() from exc

        # Add the new version alongside the old one.
        fingerprint_key = keychain.load_fingerprint_key()
        new_value = new_key.value.get_secret_value()
        new_kv = KeyVersion(
            version_number=old_kv.version_number + 1,
            value=SecretStr(new_value),
            created_at=datetime.now(UTC),
            fingerprint=compute_fingerprint(new_value, fingerprint_key),
        )
        key.versions.append(new_kv)
        session.vault.access_log.append(
            AccessEvent(
                timestamp=datetime.now(UTC),
                event_type=EventType.KEY_ROTATED,
                key_id=key.id,
                device_fingerprint="",
                details={
                    "from_version": old_kv.version_number,
                    "to_version": new_kv.version_number,
                },
            )
        )
        session.save()

        ui.print_info("[bold]confirm you have updated these deployments:[/bold]")
        for d in key.deployments:
            ui.print_info(f"  - {d.platform}/{d.identifier} ({d.variable_name})")
        if not click.confirm("All deployments updated?", default=False):
            ui.print_warning("old key NOT revoked; new version is stored but kept alongside")
            return

        # Verify new key works before revoking old.
        if not provider.test_key(new_value):
            ui.print_error("new key failed verification — rolling back, old key stays active")
            key.versions.pop()  # undo
            session.save()
            raise click.Abort()

        try:
            provider.revoke_key(new_value, key_id_to_revoke=new_key.key_id)
        except KeyGuardError as exc:
            ui.print_error(f"provider revoke_key failed: {exc} — old key still active")
            raise click.Abort() from exc

        old_kv_new = old_kv.model_copy(
            update={"revoked_at": datetime.now(UTC), "rotation_reason": "rotate"}
        )
        key.versions[-2] = old_kv_new
        session.save()
        ui.print_success(
            f"rotated {name!r} from v{old_kv.version_number} to v{new_kv.version_number}; "
            "old key revoked"
        )
    finally:
        session.lock()
