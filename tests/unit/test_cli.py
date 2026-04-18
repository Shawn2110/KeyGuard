"""CLI command tests via :class:`click.testing.CliRunner`.

Every test uses an in-memory keyring backend (no real OS keychain) and a
vault under :func:`tmp_path`. Provider HTTP is mocked with ``respx``.
Clipboard is monkeypatched. Network is never touched.
"""

from __future__ import annotations

from collections.abc import Iterator
from pathlib import Path

import httpx
import keyring
import pyotp
import pytest
import respx
from click.testing import CliRunner
from keyring.backend import KeyringBackend
from keyring.errors import PasswordDeleteError

from keyguard.cli.main import cli
from keyguard.core import keychain, totp

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


class _MemKeyring(KeyringBackend):
    priority = 1  # type: ignore[assignment]

    def __init__(self) -> None:
        self._s: dict[tuple[str, str], str] = {}

    def set_password(self, service: str, username: str, password: str) -> None:
        self._s[(service, username)] = password

    def get_password(self, service: str, username: str) -> str | None:
        return self._s.get((service, username))

    def delete_password(self, service: str, username: str) -> None:
        k = (service, username)
        if k not in self._s:
            raise PasswordDeleteError(f"no such entry: {service}/{username}")
        del self._s[k]


@pytest.fixture
def memory_keyring() -> Iterator[None]:
    previous = keyring.get_keyring()
    keyring.set_keyring(_MemKeyring())
    try:
        yield
    finally:
        keyring.set_keyring(previous)


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


@pytest.fixture
def prepared(runner: CliRunner, tmp_path: Path, memory_keyring: None) -> tuple[Path, str, str]:
    """Run `keyguard init` and return (vault_path, password, totp_secret_b32)."""
    vault_path = tmp_path / "vault.enc"
    password = "correct-horse-battery"
    # Patch generate_totp_secret to a deterministic value so we can compute
    # the "current code" inside test flow without reading keychain beforehand.
    from keyguard.core import totp as totp_mod

    fixed_secret = b"\x11" * 20
    original = totp_mod.generate_totp_secret
    totp_mod.generate_totp_secret = lambda: fixed_secret  # type: ignore[assignment]
    try:
        now_code = pyotp.TOTP(totp._base32(fixed_secret)).now()
        # Patch generate_recovery_code to a deterministic pair.
        from keyguard.core import crypto as crypto_mod

        orig_rec = crypto_mod.generate_recovery_code
        fixed_display = "AAAA-BBBB-CCCC-DDDD-EEEE-FFFF-GGGG-HHHH"
        crypto_mod.generate_recovery_code = lambda: (fixed_display, b"\x22" * 20)  # type: ignore[assignment]
        try:
            inputs = "\n".join(
                [
                    password,  # password
                    password,  # confirm
                    now_code,  # TOTP
                    fixed_display,  # recovery retype
                    "n",  # skip hook install
                ]
            )
            result = runner.invoke(
                cli,
                ["init", "--vault-path", str(vault_path)],
                input=inputs + "\n",
            )
            assert result.exit_code == 0, result.output + str(result.exception)
        finally:
            crypto_mod.generate_recovery_code = orig_rec  # type: ignore[assignment]
    finally:
        totp_mod.generate_totp_secret = original  # type: ignore[assignment]

    return vault_path, password, totp._base32(fixed_secret)


def _current_code(totp_b32: str) -> str:
    return pyotp.TOTP(totp_b32).now()


def _unlock_inputs(password: str, totp_b32: str) -> str:
    return f"{password}\n{_current_code(totp_b32)}\n"


# ---------------------------------------------------------------------------
# init
# ---------------------------------------------------------------------------


def test_init_creates_vault_and_keychain(prepared: tuple[Path, str, str]) -> None:
    vault_path, _, _ = prepared
    assert vault_path.exists()
    assert keychain.load_local_half()
    assert keychain.load_totp_secret()
    assert keychain.load_fingerprint_key()


def test_init_refuses_to_overwrite_without_force(
    runner: CliRunner, prepared: tuple[Path, str, str], memory_keyring: None
) -> None:
    vault_path, _, _ = prepared
    result = runner.invoke(
        cli,
        ["init", "--vault-path", str(vault_path)],
        input="pw\npw\n",
    )
    assert result.exit_code != 0
    assert "already exists" in result.output


# ---------------------------------------------------------------------------
# add + list + show
# ---------------------------------------------------------------------------


def test_add_list_show_roundtrip(runner: CliRunner, prepared: tuple[Path, str, str]) -> None:
    vault_path, password, totp_b32 = prepared

    # add
    add_inputs = _unlock_inputs(password, totp_b32) + "sk-test-value\n"
    r1 = runner.invoke(
        cli,
        ["add", "STRIPE", "--provider", "stripe", "--tag", "prod", "--vault-path", str(vault_path)],
        input=add_inputs,
    )
    assert r1.exit_code == 0, r1.output + str(r1.exception)
    assert "added 'STRIPE'" in r1.output

    # list
    r2 = runner.invoke(
        cli, ["list", "--vault-path", str(vault_path)], input=_unlock_inputs(password, totp_b32)
    )
    assert r2.exit_code == 0, r2.output
    assert "STRIPE" in r2.output
    assert "stripe" in r2.output

    # show (no reveal)
    r3 = runner.invoke(
        cli,
        ["show", "STRIPE", "--vault-path", str(vault_path)],
        input=_unlock_inputs(password, totp_b32),
    )
    assert r3.exit_code == 0, r3.output
    assert "provider        : stripe" in r3.output
    assert "sk-test-value" not in r3.output

    # show --reveal
    r4 = runner.invoke(
        cli,
        ["show", "STRIPE", "--reveal", "--vault-path", str(vault_path)],
        input=_unlock_inputs(password, totp_b32),
    )
    assert r4.exit_code == 0
    assert "sk-test-value" in r4.output


def test_add_rejects_duplicate_name(runner: CliRunner, prepared: tuple[Path, str, str]) -> None:
    vault_path, password, totp_b32 = prepared
    inp = _unlock_inputs(password, totp_b32) + "sk-1\n"
    runner.invoke(
        cli,
        ["add", "K", "--provider", "openai", "--vault-path", str(vault_path)],
        input=inp,
    )
    inp2 = _unlock_inputs(password, totp_b32) + "sk-2\n"
    r = runner.invoke(
        cli,
        ["add", "K", "--provider", "openai", "--vault-path", str(vault_path)],
        input=inp2,
    )
    assert r.exit_code != 0
    assert "already exists" in r.output


def test_show_missing_key_errors(runner: CliRunner, prepared: tuple[Path, str, str]) -> None:
    vault_path, password, totp_b32 = prepared
    r = runner.invoke(
        cli,
        ["show", "NOPE", "--vault-path", str(vault_path)],
        input=_unlock_inputs(password, totp_b32),
    )
    assert r.exit_code != 0
    assert "no key named" in r.output


# ---------------------------------------------------------------------------
# copy (mock pyperclip)
# ---------------------------------------------------------------------------


def test_copy_puts_value_on_clipboard(
    runner: CliRunner,
    prepared: tuple[Path, str, str],
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    vault_path, password, totp_b32 = prepared
    runner.invoke(
        cli,
        ["add", "K", "--provider", "openai", "--vault-path", str(vault_path)],
        input=_unlock_inputs(password, totp_b32) + "sk-abc\n",
    )

    import pyperclip

    captured: list[str] = []

    def fake_copy(v: str) -> None:
        captured.append(v)

    def fake_paste() -> str:
        return captured[-1] if captured else ""

    monkeypatch.setattr(pyperclip, "copy", fake_copy)
    monkeypatch.setattr(pyperclip, "paste", fake_paste)

    r = runner.invoke(
        cli,
        ["copy", "K", "--timeout", "0", "--vault-path", str(vault_path)],
        input=_unlock_inputs(password, totp_b32),
    )
    assert r.exit_code == 0, r.output
    assert captured[0] == "sk-abc"


# ---------------------------------------------------------------------------
# scan
# ---------------------------------------------------------------------------


def test_scan_detects_planted_matching_file(
    runner: CliRunner, prepared: tuple[Path, str, str], tmp_path: Path
) -> None:
    vault_path, password, totp_b32 = prepared
    # Add a key so we have something to match against.
    runner.invoke(
        cli,
        ["add", "K", "--provider", "openai", "--vault-path", str(vault_path)],
        input=_unlock_inputs(password, totp_b32) + "sk-leak-target\n",
    )
    # Plant it in a .env file.
    scan_root = tmp_path / "project"
    scan_root.mkdir()
    (scan_root / ".env").write_text("API_KEY=sk-leak-target\n")
    r = runner.invoke(
        cli,
        ["scan", str(scan_root), "--no-git", "--vault-path", str(vault_path)],
        input=_unlock_inputs(password, totp_b32),
    )
    assert r.exit_code == 1, r.output  # findings → exit 1
    assert "new exposure" in r.output or "1 new exposure" in r.output


# ---------------------------------------------------------------------------
# rotate (mocked provider via respx)
# ---------------------------------------------------------------------------


def test_rotate_happy_path(runner: CliRunner, prepared: tuple[Path, str, str]) -> None:
    vault_path, password, totp_b32 = prepared
    # Add an OpenAI key first.
    runner.invoke(
        cli,
        ["add", "OAI", "--provider", "openai", "--vault-path", str(vault_path)],
        input=_unlock_inputs(password, totp_b32) + "sk-old\n",
    )

    with respx.mock:
        respx.post("https://api.openai.com/organization/admin/api_keys").mock(
            return_value=httpx.Response(
                200,
                json={"id": "key_new", "value": "sk-new", "created_at": 1720000000},
            )
        )
        respx.get("https://api.openai.com/v1/models").mock(
            return_value=httpx.Response(200, json={"data": []})
        )
        respx.delete("https://api.openai.com/organization/admin/api_keys/key_new").mock(
            return_value=httpx.Response(200)
        )
        r = runner.invoke(
            cli,
            ["rotate", "OAI", "--vault-path", str(vault_path)],
            input=_unlock_inputs(password, totp_b32) + "y\n",  # confirm deployments
        )
    assert r.exit_code == 0, r.output + str(r.exception)
    assert "rotated 'OAI' from v1 to v2" in r.output


def test_rotate_dry_run_does_not_call_provider(
    runner: CliRunner, prepared: tuple[Path, str, str]
) -> None:
    vault_path, password, totp_b32 = prepared
    runner.invoke(
        cli,
        ["add", "OAI", "--provider", "openai", "--vault-path", str(vault_path)],
        input=_unlock_inputs(password, totp_b32) + "sk-x\n",
    )
    # If the provider were called, there's no respx mock and it would fail.
    r = runner.invoke(
        cli,
        ["rotate", "OAI", "--dry-run", "--vault-path", str(vault_path)],
        input=_unlock_inputs(password, totp_b32),
    )
    assert r.exit_code == 0, r.output
    assert "DRY-RUN" in r.output


# ---------------------------------------------------------------------------
# hooks (mock git config)
# ---------------------------------------------------------------------------


def test_install_hooks_writes_script_and_sets_config(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    # Redirect Path.home() to tmp_path so we don't touch real ~/.keyguard.
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    import subprocess

    called: list[list[str]] = []

    def fake_run(args, **kwargs):  # type: ignore[no-untyped-def]
        called.append(list(args))

        class _R:
            returncode = 0

        return _R()

    monkeypatch.setattr(subprocess, "run", fake_run)

    r = runner.invoke(cli, ["install-hooks"])
    assert r.exit_code == 0, r.output
    hook_file = tmp_path / ".keyguard" / "hooks" / "pre-commit"
    assert hook_file.exists()
    assert "python -m keyguard.cli.hook" in hook_file.read_text()
    assert any("core.hooksPath" in " ".join(c) for c in called)


def test_uninstall_hooks_removes_and_unsets(
    runner: CliRunner, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    monkeypatch.setattr(Path, "home", lambda: tmp_path)

    import subprocess

    def fake_run(args, **kwargs):  # type: ignore[no-untyped-def]
        class _R:
            returncode = 0

        return _R()

    monkeypatch.setattr(subprocess, "run", fake_run)

    # Install first.
    runner.invoke(cli, ["install-hooks"])
    hook_file = tmp_path / ".keyguard" / "hooks" / "pre-commit"
    assert hook_file.exists()

    r = runner.invoke(cli, ["install-hooks", "--uninstall"])
    assert r.exit_code == 0, r.output
    assert not hook_file.exists()


# ---------------------------------------------------------------------------
# hook.py (pre-commit pattern matching)
# ---------------------------------------------------------------------------


def test_hook_blocks_commit_with_openai_key_in_diff() -> None:
    from keyguard.cli import hook as hook_module

    diff = "+++ b/.env\n+OPENAI_API_KEY=sk-abcdefghijABCDEFGHIJ1234567890\n"
    assert hook_module.check_diff(diff) == 1


def test_hook_allows_clean_diff() -> None:
    from keyguard.cli import hook as hook_module

    assert hook_module.check_diff("+++ b/README.md\n+Some unrelated text\n") == 0


def test_hook_ignores_non_added_lines() -> None:
    from keyguard.cli import hook as hook_module

    # Removed lines and context lines must not trigger.
    diff = "-OLD_KEY=sk-longenoughkeyABCDEFGHIJ1234567890\n unchanged content\n"
    assert hook_module.check_diff(diff) == 0
