"""Walk the filesystem for .env-like files and extract KEY=value pairs.

Complements :mod:`gitleaks` — which focuses on git history — by surfacing
plain files on disk that the repo's git doesn't track.
"""

from __future__ import annotations

import fnmatch
import re
from collections.abc import Iterable, Iterator
from pathlib import Path

from keyguard.core.scanner.gitleaks import RawFinding

__all__ = [
    "DEFAULT_EXCLUDE_DIRS",
    "DEFAULT_INCLUDE_GLOBS",
    "hunt",
]

DEFAULT_INCLUDE_GLOBS: list[str] = [
    ".env*",
    "*credentials*",
    "secrets.yml",
    "secrets.yaml",
    ".npmrc",
    ".pypirc",
]

DEFAULT_EXCLUDE_DIRS: set[str] = {
    "node_modules",
    ".git",
    ".venv",
    "venv",
    "__pycache__",
    "dist",
    "build",
    ".mypy_cache",
    ".pytest_cache",
    ".ruff_cache",
}

# KEY=VALUE lines where KEY is UPPER_SNAKE_CASE — the common .env style.
# Quoted values strip their surrounding quotes.
_KV_PATTERN = re.compile(r"^\s*([A-Z_][A-Z0-9_]*)\s*=\s*['\"]?([^'\"\n]+?)['\"]?\s*$")


def hunt(
    root: Path,
    *,
    include_globs: Iterable[str] | None = None,
    exclude_dirs: Iterable[str] | None = None,
) -> list[RawFinding]:
    """Return every KEY=value pair in files matching ``include_globs``
    under ``root``, skipping directories whose names appear in
    ``exclude_dirs``.
    """
    include = list(include_globs) if include_globs is not None else DEFAULT_INCLUDE_GLOBS
    exclude = set(exclude_dirs) if exclude_dirs is not None else DEFAULT_EXCLUDE_DIRS
    findings: list[RawFinding] = []
    for path in _walk(root, exclude):
        if not any(fnmatch.fnmatch(path.name, g) for g in include):
            continue
        findings.extend(_parse_env_file(path))
    return findings


def _walk(root: Path, exclude_dirs: set[str]) -> Iterator[Path]:
    if not root.exists():
        return
    for item in root.rglob("*"):
        if any(part in exclude_dirs for part in item.parts):
            continue
        if item.is_file():
            yield item


def _parse_env_file(path: Path) -> list[RawFinding]:
    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []
    findings: list[RawFinding] = []
    for lineno, line in enumerate(content.splitlines(), start=1):
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _KV_PATTERN.match(stripped)
        if match is None:
            continue
        value = match.group(2)
        if not value or value.startswith("$"):
            # Skip variable references like VAR=$OTHER or empty strings.
            continue
        findings.append(
            RawFinding(
                secret=value,
                file=str(path),
                line=lineno,
                source="fileshunt",
            )
        )
    return findings
