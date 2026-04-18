"""Subprocess wrapper around the bundled ``gitleaks`` binary.

Locates the platform-specific binary under ``vendor/gitleaks/<platform>/``
and invokes it with a JSON report format. Gitleaks uses a non-zero exit
code (1) to signal "found secrets" — that is **not** an error, and we
treat it as success.
"""

from __future__ import annotations

import json
import platform as _sys_platform
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import Literal

from keyguard.core.errors import GitleaksNotFoundError, ScannerError, ScanTimeoutError

__all__ = [
    "RawFinding",
    "locate_gitleaks_binary",
    "run_gitleaks",
]


@dataclass(frozen=True)
class RawFinding:
    """One secret-like hit from the scanner, before vault matching."""

    secret: str
    file: str
    line: int
    commit: str | None = None
    rule_id: str | None = None
    source: Literal["gitleaks", "fileshunt"] = "gitleaks"


_PLATFORM_DIRS: dict[tuple[str, str], str] = {
    ("linux", "x86_64"): "linux-x64",
    ("linux", "amd64"): "linux-x64",
    ("linux", "aarch64"): "linux-arm64",
    ("linux", "arm64"): "linux-arm64",
    ("darwin", "x86_64"): "macos-x64",
    ("darwin", "arm64"): "macos-arm64",
    ("windows", "amd64"): "windows-x64",
    ("windows", "x86_64"): "windows-x64",
}


def locate_gitleaks_binary(vendor_root: Path | None = None) -> Path:
    """Return the path to the bundled gitleaks binary for this platform.

    Raises :class:`GitleaksNotFoundError` if the platform isn't supported
    or the binary hasn't been fetched yet (run ``scripts/package_binaries.py``).
    """
    if vendor_root is None:
        vendor_root = Path(__file__).resolve().parents[4] / "vendor" / "gitleaks"
    system = _sys_platform.system().lower()
    machine = _sys_platform.machine().lower()
    plat_dir = _PLATFORM_DIRS.get((system, machine))
    if plat_dir is None:
        raise GitleaksNotFoundError(f"no bundled gitleaks for platform {system}/{machine}")
    binary_name = "gitleaks.exe" if system == "windows" else "gitleaks"
    binary = vendor_root / plat_dir / binary_name
    if not binary.exists():
        raise GitleaksNotFoundError(
            f"bundled gitleaks binary not found at {binary} — "
            "run `python scripts/package_binaries.py`"
        )
    return binary


def run_gitleaks(
    repo_path: Path,
    *,
    timeout_seconds: float = 300.0,
    binary: Path | None = None,
) -> list[RawFinding]:
    """Invoke gitleaks against ``repo_path`` and parse its JSON output.

    ``binary`` lets tests inject a mock path; production code should let
    :func:`locate_gitleaks_binary` do its job.
    """
    if binary is None:
        binary = locate_gitleaks_binary()
    cmd = [
        str(binary),
        "detect",
        "--source",
        str(repo_path),
        "--report-format",
        "json",
        "--report-path",
        "-",
        "--no-banner",
    ]
    try:
        proc = subprocess.run(  # noqa: S603 — args built from trusted inputs
            cmd,
            capture_output=True,
            timeout=timeout_seconds,
            check=False,
        )
    except subprocess.TimeoutExpired as exc:
        raise ScanTimeoutError(f"gitleaks scan exceeded {timeout_seconds}s") from exc

    # Gitleaks: 0 = clean, 1 = found secrets, >1 = error.
    if proc.returncode not in (0, 1):
        raise ScannerError(
            f"gitleaks failed with exit code {proc.returncode}: "
            f"{proc.stderr.decode(errors='replace')[:200]}"
        )

    if not proc.stdout.strip():
        return []
    try:
        raw = json.loads(proc.stdout.decode("utf-8"))
    except json.JSONDecodeError as exc:
        raise ScannerError(f"gitleaks output was not valid JSON: {exc}") from exc
    if not isinstance(raw, list):
        return []
    return [
        RawFinding(
            secret=str(item.get("Secret", "")),
            file=str(item.get("File", "")),
            line=int(item.get("StartLine", 0) or 0),
            commit=item.get("Commit") or None,
            rule_id=item.get("RuleID") or None,
            source="gitleaks",
        )
        for item in raw
        if isinstance(item, dict)
    ]
