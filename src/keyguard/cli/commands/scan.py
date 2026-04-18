"""``keyguard scan`` — gitleaks + fileshunt, cross-referenced with the vault."""

from __future__ import annotations

import json as _json
from pathlib import Path

import click

from keyguard.cli import ui
from keyguard.cli._unlock import unlock_or_abort
from keyguard.core import keychain
from keyguard.core.errors import GitleaksNotFoundError, ScannerError
from keyguard.core.models import AccessEvent, EventType
from keyguard.core.scanner import fileshunt, gitleaks, matcher

__all__ = ["scan_command"]


@click.command("scan")
@click.argument("path", type=click.Path(path_type=Path, exists=True, file_okay=False), default=".")
@click.option(
    "--format",
    "output_format",
    type=click.Choice(["text", "json"]),
    default="text",
    show_default=True,
)
@click.option("--no-git/--git", default=False, help="Skip gitleaks; only walk the filesystem.")
@click.option(
    "--vault-path",
    type=click.Path(path_type=Path, dir_okay=False, exists=True),
    default=None,
)
def scan_command(path: Path, output_format: str, no_git: bool, vault_path: Path | None) -> None:
    """Scan PATH for leaked secrets that match the vault."""
    session = unlock_or_abort(vault_path)
    try:
        findings: list[gitleaks.RawFinding] = []
        if not no_git:
            try:
                findings.extend(gitleaks.run_gitleaks(path))
            except GitleaksNotFoundError as exc:
                ui.print_warning(f"gitleaks scan skipped: {exc}")
            except ScannerError as exc:
                ui.print_warning(f"gitleaks scan failed: {exc}")
        findings.extend(fileshunt.hunt(path))

        fingerprint_key = keychain.load_fingerprint_key()
        new_exposures = matcher.match_findings(findings, session.vault, fingerprint_key)

        # Record SCAN_RUN and persist any newly-found exposures.
        from datetime import UTC as _UTC
        from datetime import datetime as _datetime

        session.vault.access_log.append(
            AccessEvent(
                timestamp=_datetime.now(_UTC),
                event_type=EventType.SCAN_RUN,
                device_fingerprint="",
                details={"findings": len(findings), "new_exposures": len(new_exposures)},
            )
        )
        session.save()

        if output_format == "json":
            payload = {
                "findings": len(findings),
                "new_exposures": [
                    {
                        "location": e.location,
                        "severity": e.severity.value,
                        "source_type": e.source_type.value,
                    }
                    for e in new_exposures
                ],
            }
            ui.console.print_json(_json.dumps(payload))
        else:
            ui.print_info(
                f"scanned {path}: {len(findings)} raw findings, "
                f"{len(new_exposures)} new exposure(s) of known keys"
            )
            for e in new_exposures:
                ui.console.print(f"  - [red]{e.location}[/red] ({e.source_type.value})")

        if new_exposures:
            raise click.exceptions.Exit(code=1)
    finally:
        session.lock()
