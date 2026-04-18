"""Download and verify the pinned gitleaks binary for every supported platform.

Run manually or from the release pipeline::

    python scripts/package_binaries.py                # all platforms
    python scripts/package_binaries.py --only linux-x64

The script:

1. Fetches each platform's archive from GitHub Releases over HTTPS.
2. Computes SHA-256 of the downloaded archive.
3. Compares against the pinned digest in ``_PINNED``. Unknown digests
   (placeholder ``"TODO-…"``) are tolerated once — the script prints the
   observed digest so a maintainer can commit it back into ``_PINNED``.
4. Extracts the ``gitleaks`` binary into
   ``vendor/gitleaks/<platform>/``.

The script never runs at install time. It populates
``vendor/gitleaks/`` in the working tree so the wheel built by hatchling
includes the right binary for each platform wheel.
"""

from __future__ import annotations

import argparse
import hashlib
import io
import shutil
import sys
import tarfile
import urllib.request
import zipfile
from pathlib import Path

# Bumping this is a deliberate act — diff the new upstream release, verify
# its binary is signed by Zach Rice, commit the new digests.
GITLEAKS_VERSION = "8.21.0"


_BASE_URL = f"https://github.com/gitleaks/gitleaks/releases/download/v{GITLEAKS_VERSION}"


# Platform → (archive filename, SHA-256 of the archive, binary path inside archive).
# Digests marked TODO-<platform> are placeholders; running the script with
# --accept-new will print the observed digest so it can be pinned properly.
_PINNED: dict[str, tuple[str, str, str]] = {
    "linux-x64": (
        f"gitleaks_{GITLEAKS_VERSION}_linux_x64.tar.gz",
        "TODO-linux-x64",
        "gitleaks",
    ),
    "linux-arm64": (
        f"gitleaks_{GITLEAKS_VERSION}_linux_arm64.tar.gz",
        "TODO-linux-arm64",
        "gitleaks",
    ),
    "macos-x64": (
        f"gitleaks_{GITLEAKS_VERSION}_darwin_x64.tar.gz",
        "TODO-macos-x64",
        "gitleaks",
    ),
    "macos-arm64": (
        f"gitleaks_{GITLEAKS_VERSION}_darwin_arm64.tar.gz",
        "TODO-macos-arm64",
        "gitleaks",
    ),
    "windows-x64": (
        f"gitleaks_{GITLEAKS_VERSION}_windows_x64.zip",
        "TODO-windows-x64",
        "gitleaks.exe",
    ),
}


def _vendor_root() -> Path:
    return Path(__file__).resolve().parents[1] / "vendor" / "gitleaks"


def _download(url: str) -> bytes:
    with urllib.request.urlopen(url, timeout=60) as resp:  # noqa: S310 — HTTPS upstream
        return bytes(resp.read())


def _extract(data: bytes, archive_name: str, binary_inside: str, dest: Path) -> None:
    dest.mkdir(parents=True, exist_ok=True)
    target = dest / binary_inside
    if archive_name.endswith(".zip"):
        with (
            zipfile.ZipFile(io.BytesIO(data)) as zf,
            zf.open(binary_inside) as src,
            target.open("wb") as out,
        ):
            shutil.copyfileobj(src, out)
    else:
        with tarfile.open(fileobj=io.BytesIO(data), mode="r:gz") as tf:
            member = tf.getmember(binary_inside)
            extracted = tf.extractfile(member)
            if extracted is None:
                raise RuntimeError(f"archive member {binary_inside!r} not extractable")
            with target.open("wb") as out:
                shutil.copyfileobj(extracted, out)
    target.chmod(0o755)


def _fetch_one(platform: str, *, accept_new: bool) -> None:
    if platform not in _PINNED:
        raise KeyError(f"unknown platform {platform!r}; known: {sorted(_PINNED)}")
    archive_name, pinned_sha, binary_name = _PINNED[platform]
    url = f"{_BASE_URL}/{archive_name}"
    print(f"→ {platform}: downloading {archive_name}")
    data = _download(url)
    observed_sha = hashlib.sha256(data).hexdigest()

    if pinned_sha.startswith("TODO"):
        if not accept_new:
            print(
                f"  ! pinned digest is placeholder. Observed SHA-256:\n"
                f"    {observed_sha}\n"
                f"    Commit this into scripts/package_binaries.py, then re-run.",
                file=sys.stderr,
            )
            return
        print(f"  ! accepted new digest {observed_sha}")
    else:
        if observed_sha != pinned_sha:
            raise RuntimeError(
                f"SHA-256 mismatch for {platform}:\n"
                f"  expected: {pinned_sha}\n"
                f"  observed: {observed_sha}\n"
                "Refusing to extract. Investigate before proceeding."
            )
        print("  ✓ SHA-256 matches pin")

    dest = _vendor_root() / platform
    _extract(data, archive_name, binary_name, dest)
    print(f"  ✓ extracted to {dest}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--only",
        choices=sorted(_PINNED.keys()),
        action="append",
        default=None,
        help="Restrict to one or more platforms (repeatable).",
    )
    parser.add_argument(
        "--accept-new",
        action="store_true",
        help="When a pinned digest is still a TODO placeholder, accept and extract.",
    )
    args = parser.parse_args(argv)
    platforms = args.only if args.only else sorted(_PINNED.keys())
    for platform in platforms:
        _fetch_one(platform, accept_new=args.accept_new)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
