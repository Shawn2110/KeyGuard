"""Pre-commit hook entry point.

Invoked by ``~/.keyguard/hooks/pre-commit``. Scans staged files for
likely secrets and blocks the commit on any match.
"""

from __future__ import annotations

import re
import shutil
import subprocess
import sys

__all__ = ["check_diff", "main"]


# Per-provider patterns copied from the concrete :class:`Provider` impls.
# Kept in sync by importing the registry lazily — but since a commit hook
# must be fast, we also hard-code the common ones as a fallback.
_FALLBACK_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_\-]{20,}"),  # openai
    re.compile(r"sk-ant-[A-Za-z0-9_\-]{20,}"),  # anthropic
    re.compile(r"sk_(test|live)_[A-Za-z0-9]{24,}"),  # stripe
]


def _load_patterns() -> list[re.Pattern[str]]:
    try:
        from keyguard.core.providers import anthropic as _anth  # noqa: F401
        from keyguard.core.providers import openai as _oa  # noqa: F401
        from keyguard.core.providers import stripe as _st  # noqa: F401
        from keyguard.core.providers.registry import all_providers

        return [cls.key_pattern for cls in all_providers().values()]
    except Exception:
        return _FALLBACK_PATTERNS


def _staged_diff() -> str:
    git = shutil.which("git")
    if git is None:
        return ""
    try:
        result = subprocess.run(  # noqa: S603 — arg vector is hard-coded
            [git, "diff", "--cached", "--no-color", "-U0"],
            capture_output=True,
            text=True,
            check=False,
        )
    except OSError:
        return ""
    return result.stdout


def check_diff(diff: str, patterns: list[re.Pattern[str]] | None = None) -> int:
    """Scan ``diff`` text for known key patterns. Returns 0 clean, 1 blocked.

    Factored out from :func:`main` so tests can exercise the matching
    logic directly without mocking ``subprocess``.
    """
    if not diff:
        return 0
    pats = patterns if patterns is not None else _load_patterns()
    hits: list[tuple[str, str]] = []
    for line in diff.splitlines():
        if not line.startswith("+") or line.startswith("+++"):
            continue
        for pat in pats:
            m = pat.search(line)
            if m:
                hits.append((pat.pattern, m.group(0)))
                break
    if not hits:
        return 0
    sys.stderr.write("[KeyGuard] commit blocked — possible secret in staged diff:\n")
    for pattern_src, matched in hits:
        redacted = matched[:6] + "…" if len(matched) > 8 else "…"
        sys.stderr.write(f"  - pattern {pattern_src} matched {redacted}\n")
    sys.stderr.write(
        "\nIf this is a false positive, bypass this commit with `git commit --no-verify` "
        "(use sparingly — the hook exists because this is usually a bug).\n"
    )
    return 1


def main() -> int:
    return check_diff(_staged_diff())


if __name__ == "__main__":
    sys.exit(main())
