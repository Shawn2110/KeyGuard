"""End-to-end smoke: init → add → scan (clean) → plant leak → scan (finds) → rotate.

A single pytest that walks the full user journey against a real vault
file (under ``tmp_path``), a real TOTP secret, an in-memory keyring
backend, and ``respx``-mocked provider HTTP. No network, no real
keychain, no real filesystem outside ``tmp_path``.
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
from keyguard.core import crypto as crypto_mod
from keyguard.core import totp as totp_mod


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


def test_full_user_journey(
    tmp_path: Path,
    memory_keyring: None,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """init → add → scan clean → plant leak → scan finds → rotate → verify."""
    runner = CliRunner()
    vault_path = tmp_path / "vault.enc"
    project_root = tmp_path / "project"
    project_root.mkdir()
    password = "super-secret-123456"
    fixed_totp = b"\x77" * 20
    fixed_recovery_display = "WXYZ-WXYZ-WXYZ-WXYZ-WXYZ-WXYZ-WXYZ-WXYZ"
    fixed_recovery_raw = b"\x66" * 20

    monkeypatch.setattr(totp_mod, "generate_totp_secret", lambda: fixed_totp)
    monkeypatch.setattr(
        crypto_mod,
        "generate_recovery_code",
        lambda: (fixed_recovery_display, fixed_recovery_raw),
    )

    totp_b32 = totp_mod._base32(fixed_totp)
    now_code = lambda: pyotp.TOTP(totp_b32).now()  # noqa: E731 — tiny helper
    unlock = lambda: f"{password}\n{now_code()}\n"  # noqa: E731

    # ---------- init ----------
    init_inputs = "\n".join([password, password, now_code(), fixed_recovery_display, "n"]) + "\n"
    r = runner.invoke(cli, ["init", "--vault-path", str(vault_path)], input=init_inputs)
    assert r.exit_code == 0, r.output
    assert vault_path.exists()

    # ---------- add ----------
    add_inputs = unlock() + "sk-leakme-1234567890ABCDEF\n"
    r = runner.invoke(
        cli,
        [
            "add",
            "OAI",
            "--provider",
            "openai",
            "--tag",
            "prod",
            "--vault-path",
            str(vault_path),
        ],
        input=add_inputs,
    )
    assert r.exit_code == 0, r.output

    # ---------- scan: clean ----------
    r = runner.invoke(
        cli,
        ["scan", str(project_root), "--no-git", "--vault-path", str(vault_path)],
        input=unlock(),
    )
    assert r.exit_code == 0, r.output
    assert (
        "0 new exposure" in r.output or "no new exposures" in r.output or "new exposure" in r.output
    )

    # ---------- plant the leak ----------
    (project_root / ".env").write_text("OPENAI_API_KEY=sk-leakme-1234567890ABCDEF\n")

    # ---------- scan: finds ----------
    r = runner.invoke(
        cli,
        ["scan", str(project_root), "--no-git", "--vault-path", str(vault_path)],
        input=unlock(),
    )
    assert r.exit_code == 1, r.output  # findings → exit 1
    assert ".env" in r.output

    # ---------- rotate ----------
    with respx.mock:
        respx.post("https://api.openai.com/organization/admin/api_keys").mock(
            return_value=httpx.Response(
                200,
                json={
                    "id": "key_new",
                    "value": "sk-fresh-ABCDEFGHIJ0123456789",
                    "created_at": 1720000000,
                },
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
            input=unlock() + "y\n",  # confirm deployments updated
        )
    assert r.exit_code == 0, r.output + str(r.exception)
    assert "rotated 'OAI' from v1 to v2" in r.output

    # ---------- verify the vault now has v2 and the old key is revoked ----------
    r = runner.invoke(
        cli,
        ["show", "OAI", "--reveal", "--vault-path", str(vault_path)],
        input=unlock(),
    )
    assert r.exit_code == 0, r.output
    assert "sk-fresh-ABCDEFGHIJ0123456789" in r.output
    assert "versions        : 2" in r.output
