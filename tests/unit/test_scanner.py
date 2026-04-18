"""Tests for :mod:`keyguard.core.scanner` — gitleaks wrapper, fileshunt, matcher."""

from __future__ import annotations

import json
import subprocess
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import SecretStr

from keyguard.core.errors import GitleaksNotFoundError, ScannerError, ScanTimeoutError
from keyguard.core.models import (
    ExposureStatus,
    Key,
    KeyVersion,
    Vault,
    compute_fingerprint,
)
from keyguard.core.scanner import fileshunt, gitleaks, matcher
from keyguard.core.scanner.gitleaks import RawFinding

# ===========================================================================
# gitleaks wrapper
# ===========================================================================


class _FakeCompleted:
    def __init__(self, stdout: bytes = b"", returncode: int = 0, stderr: bytes = b""):
        self.stdout = stdout
        self.returncode = returncode
        self.stderr = stderr


def test_run_gitleaks_parses_findings(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    fake_binary = tmp_path / "gitleaks"
    fake_binary.touch()
    report = [
        {
            "Secret": "sk-test-123",
            "File": ".env",
            "StartLine": 7,
            "Commit": "deadbeef",
            "RuleID": "openai-api-key",
        }
    ]

    def fake_run(*args: object, **kwargs: object) -> _FakeCompleted:
        return _FakeCompleted(
            stdout=json.dumps(report).encode("utf-8"),
            returncode=1,  # gitleaks exits 1 when it finds things
        )

    monkeypatch.setattr(subprocess, "run", fake_run)
    findings = gitleaks.run_gitleaks(tmp_path, binary=fake_binary)
    assert len(findings) == 1
    assert findings[0].secret == "sk-test-123"
    assert findings[0].file == ".env"
    assert findings[0].line == 7
    assert findings[0].commit == "deadbeef"
    assert findings[0].rule_id == "openai-api-key"
    assert findings[0].source == "gitleaks"


def test_run_gitleaks_zero_findings_returns_empty(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_binary = tmp_path / "gitleaks"
    fake_binary.touch()

    def fake_run(*args: object, **kwargs: object) -> _FakeCompleted:
        return _FakeCompleted(stdout=b"", returncode=0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    assert gitleaks.run_gitleaks(tmp_path, binary=fake_binary) == []


def test_run_gitleaks_nonzero_error_raises_scanner_error(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_binary = tmp_path / "gitleaks"
    fake_binary.touch()

    def fake_run(*args: object, **kwargs: object) -> _FakeCompleted:
        return _FakeCompleted(stdout=b"", returncode=2, stderr=b"something broke")

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(ScannerError):
        gitleaks.run_gitleaks(tmp_path, binary=fake_binary)


def test_run_gitleaks_timeout_raises_scan_timeout(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    fake_binary = tmp_path / "gitleaks"
    fake_binary.touch()

    def fake_run(*args: object, **kwargs: object) -> _FakeCompleted:
        raise subprocess.TimeoutExpired(cmd=["gitleaks"], timeout=1.0)

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(ScanTimeoutError):
        gitleaks.run_gitleaks(tmp_path, binary=fake_binary)


def test_locate_gitleaks_binary_raises_if_missing(tmp_path: Path) -> None:
    empty_vendor = tmp_path / "vendor" / "gitleaks"
    empty_vendor.mkdir(parents=True)
    with pytest.raises(GitleaksNotFoundError):
        gitleaks.locate_gitleaks_binary(vendor_root=empty_vendor)


# ===========================================================================
# fileshunt
# ===========================================================================


def test_fileshunt_finds_env_key_value_pairs(tmp_path: Path) -> None:
    env_file = tmp_path / ".env"
    env_file.write_text(
        "# leading comment\nAPI_KEY=sk-openai-xxx\nDB_URL='postgres://...'\nVAR_REF=$OTHER\n\n"
    )
    findings = fileshunt.hunt(tmp_path)
    values = {f.secret for f in findings}
    assert "sk-openai-xxx" in values
    assert "postgres://..." in values
    assert all(not f.secret.startswith("$") for f in findings)


def test_fileshunt_skips_excluded_dirs(tmp_path: Path) -> None:
    leaky = tmp_path / "node_modules" / "subdir"
    leaky.mkdir(parents=True)
    (leaky / ".env").write_text("KEY=value\n")
    assert fileshunt.hunt(tmp_path) == []


def test_fileshunt_respects_custom_globs(tmp_path: Path) -> None:
    (tmp_path / "secrets.yml").write_text("TOKEN=abc\n")
    (tmp_path / "noise.txt").write_text("TOKEN=abc\n")
    findings = fileshunt.hunt(tmp_path, include_globs=["secrets.y*ml"])
    assert len(findings) == 1
    assert findings[0].file.endswith("secrets.yml")


def test_fileshunt_on_missing_root_returns_empty(tmp_path: Path) -> None:
    assert fileshunt.hunt(tmp_path / "does-not-exist") == []


# ===========================================================================
# matcher
# ===========================================================================


FP_KEY = b"\xab" * 32


def _vault_with_key(value: str) -> Vault:
    fp = compute_fingerprint(value, FP_KEY)
    kv = KeyVersion(
        version_number=1,
        value=SecretStr(value),
        created_at=datetime.now(UTC),
        fingerprint=fp,
    )
    return Vault(
        created_at=datetime.now(UTC),
        keys=[Key(name="STRIPE", provider="stripe", versions=[kv])],
    )


def test_matcher_flags_known_key_as_confirmed_leaked() -> None:
    v = _vault_with_key("sk-test-leaked")
    findings = [RawFinding(secret="sk-test-leaked", file=".env", line=1, source="fileshunt")]
    exposures = matcher.match_findings(findings, v, FP_KEY)
    assert len(exposures) == 1
    assert v.keys[0].exposure_status == ExposureStatus.CONFIRMED_LEAKED
    assert v.keys[0].exposures[0].location == ".env:1"


def test_matcher_ignores_unknown_findings() -> None:
    v = _vault_with_key("sk-vault-only")
    findings = [RawFinding(secret="totally-unrelated", file="x", line=1)]
    assert matcher.match_findings(findings, v, FP_KEY) == []
    assert v.keys[0].exposure_status == ExposureStatus.UNKNOWN


def test_matcher_dedups_identical_exposure() -> None:
    v = _vault_with_key("sk-dup")
    finding = RawFinding(secret="sk-dup", file=".env", line=1, source="fileshunt")
    matcher.match_findings([finding], v, FP_KEY)
    matcher.match_findings([finding], v, FP_KEY)  # same finding again
    assert len(v.keys[0].exposures) == 1


def test_matcher_records_different_locations_separately() -> None:
    v = _vault_with_key("sk-two-spots")
    findings = [
        RawFinding(secret="sk-two-spots", file=".env", line=1, source="fileshunt"),
        RawFinding(secret="sk-two-spots", file="other.env", line=1, source="fileshunt"),
    ]
    matcher.match_findings(findings, v, FP_KEY)
    assert len(v.keys[0].exposures) == 2
