# KeyGuard — Implementation Plan

> Sequenced tasks to build KeyGuard v1. Each task is scoped to a single PR with clear acceptance criteria. Do not skip ahead. Do not combine tasks. When a task is complete, mark it `[x]` and move on.
>
> Claude Code: read `AGENT.md` before starting any task. Read the section of `ARCHITECTURE.md` relevant to the current task before writing code.

## Milestone 0 — Project foundations

### Task 0.1 — Repo scaffold

- [x] Initialize repository with `uv init`.
- [x] Create `pyproject.toml` with dependencies per `AGENT.md` §5.
- [x] Create the `src/keyguard/` directory structure per `ARCHITECTURE.md` §3.
- [x] Configure `ruff`, `mypy --strict`, `pytest`, `bandit` in `pyproject.toml`.
- [x] Add `.pre-commit-config.yaml` running ruff, mypy, and the test suite.
- [x] Add GitHub Actions workflow: lint → type-check → test → security scan.
- [x] Add `.gitignore` for Python, IDE files, and test artifacts.

**Acceptance:** `uv sync && uv run pytest` runs cleanly on an empty test suite; `uv run ruff check` passes; `uv run mypy --strict src/` passes.

### Task 0.2 — Threat model document

- [x] Write `docs/THREAT_MODEL.md` covering:
  - Assets: vault file, TOTP secret, `local_half`, master password, recovery code, decrypted DEK in memory.
  - Adversaries: opportunistic thief (stolen laptop powered off), same-user malware, network attacker, cloud-backup leak, phishing.
  - For each adversary, what they can and cannot achieve against the current design.
  - Explicitly out-of-scope: fully-owned unlocked machine, sophisticated state-level adversary, side-channel attacks.

**Acceptance:** Document reviewed against the design; any gaps found cause an `ARCHITECTURE.md` update before proceeding.

## Milestone 1 — Crypto core

### Task 1.1 — Crypto primitives (`core/crypto.py`)

- [x] Implement `derive_kek`, `generate_dek`, `wrap_dek`, `unwrap_dek`, `encrypt_body`, `decrypt_body`, `generate_salt`, `generate_recovery_code`.
- [x] All functions pure; no file I/O; no global state.
- [x] Enforce parameter validation (salt length, key length) at function boundaries; raise `CryptoError` subclasses on misuse.
- [x] Define `WrappedDEK` and `EncryptedBody` Pydantic models.

**Acceptance:**

- All functions have type hints and docstrings.
- `tests/unit/test_crypto.py` has ≥95% coverage of `crypto.py`.
- Hypothesis property tests:
  - Round-trip: `decrypt_body(dek, encrypt_body(dek, p, aad), aad) == p` for any plaintext `p` up to 10 MB.
  - Tamper detection: flipping any bit in `ciphertext`, `nonce`, or `aad` causes `decrypt_body` to raise `CorruptedVaultError`.
  - Wrong-key rejection: `unwrap_dek` with a KEK other than the one used to wrap raises `WrongPasswordError`.

### Task 1.2 — Error hierarchy (`core/errors.py`)

- [x] Implement the exception tree from `ARCHITECTURE.md` §9.
- [x] Each exception class has a docstring describing when it's raised.

**Acceptance:** Import from `keyguard.core.errors`; used consistently by `crypto.py`.

## Milestone 2 — Data model and vault I/O

### Task 2.1 — Pydantic models (`core/models.py`)

- [ ] Implement `Vault`, `Key`, `KeyVersion`, `Deployment`, `Exposure`, `AccessEvent`, `VaultSettings`, plus all required enums.
- [ ] `KeyVersion.value` is `SecretStr`.
- [ ] Custom JSON serializer that raises if a `SecretStr` is serialized outside an "encrypted context" flag.
- [ ] Fingerprints are computed once at `KeyVersion` creation and stored.

**Acceptance:** Full round-trip serialization test; attempt to JSON-dump a `SecretStr` in non-encrypted context raises.

### Task 2.2 — Vault file I/O (`core/vault.py`)

- [ ] Implement `create_vault`, `open_vault`, `open_vault_with_recovery`, `UnlockedVault.save`, `UnlockedVault.rotate_password`.
- [ ] Atomic writes: `.tmp` + `os.replace`.
- [ ] Backup rotation: keep last 3 backups as `vault.enc.bak.1`, `.bak.2`, `.bak.3`.
- [ ] Use `platformdirs` to determine the default vault path.

**Acceptance:**

- Integration test: create vault → close → open with correct inputs → read back keys.
- Integration test: create vault → attempt open with wrong password → raises `WrongPasswordError`; file unchanged.
- Integration test: simulate crash during save (kill after `.tmp` write but before rename) → next open uses the previous intact file.
- Integration test: recovery code unlocks after the user "forgets" their password.

## Milestone 3 — TOTP and keychain

### Task 3.1 — Keychain wrapper (`core/keychain.py`)

- [ ] Thin typed wrapper over `keyring` with methods: `store_local_half`, `load_local_half`, `store_totp_secret`, `load_totp_secret`, `delete_all_keyguard_entries`.
- [ ] Map `keyring` exceptions to our `KeychainError` subclasses.
- [ ] Handle the "first run on a new machine" case gracefully.

**Acceptance:** Unit tests use a mock keyring backend (`keyring.backends.null` or a custom one). No real keychain touched in tests.

### Task 3.2 — TOTP module (`core/totp.py`)

- [ ] `generate_totp_secret() -> bytes`
- [ ] `provisioning_uri(secret: bytes, account: str) -> str`
- [ ] `render_qr_ascii(uri: str) -> str` — for terminal display.
- [ ] `verify_code(secret: bytes, code: str, valid_window: int = 1) -> bool`

**Acceptance:** Unit tests cover correct code acceptance, clock-skew tolerance, incorrect code rejection, and malformed input.

## Milestone 4 — Session and audit

### Task 4.1 — Session manager (`core/session.py`)

- [ ] `Session.unlock(vault_path, password, totp_code)` — orchestrates keychain read, TOTP verification, vault open.
- [ ] `Session.lock()` — zeroize the DEK reference, drop the in-memory vault.
- [ ] Auto-lock timer: configurable, default 5 minutes.
- [ ] All vault-mutating operations go through `Session` methods; each appends an `AccessEvent`.

**Acceptance:**

- Integration test: unlock → add key → lock → assert DEK and decrypted vault are no longer accessible.
- Test: auto-lock fires after timeout.

### Task 4.2 — Audit log (`core/audit.py`)

- [ ] Append-only API; no methods to delete or edit events.
- [ ] `Session.save` refuses to persist if the access log has shrunk since unlock.

**Acceptance:** Attempt to mutate a prior event raises; shrinking the log and saving raises.

## Milestone 5 — Scanner

### Task 5.1 — Gitleaks wrapper (`core/scanner/gitleaks.py`)

- [ ] Locate the bundled gitleaks binary (in `vendor/gitleaks/<platform>/`).
- [ ] Invoke via `subprocess` with a known-good ruleset.
- [ ] Parse JSON output into a list of `RawFinding` dataclasses.
- [ ] Handle missing binary, timeout, non-zero exit codes (gitleaks returns non-zero when findings exist — that's not an error).

**Acceptance:** Fixture repository with planted secrets; scanner finds exactly the planted ones.

### Task 5.2 — Filesystem hunt (`core/scanner/fileshunt.py`)

- [ ] Walk a root path; find files matching `.env*`, `*credentials*`, `secrets.y*ml`, `.npmrc`, `.pypirc`, etc.
- [ ] Skip `node_modules`, `.git`, `.venv`, `__pycache__` by default.
- [ ] Configurable allow/deny lists for paths.
- [ ] For each matched file, extract lines that look like `KEY=value` pairs; return `RawFinding` records.

**Acceptance:** Tests against fixture directory tree assert expected findings and ignored paths.

### Task 5.3 — Matcher (`core/scanner/matcher.py`)

- [ ] Given `RawFinding`s and the vault, compute SHA-256 fingerprints and match against stored `KeyVersion.fingerprint` values.
- [ ] Produce `Exposure` records, each linked to the matching `KeyVersion`.
- [ ] Update the `Key.exposure_status` and `Key.exposures` list.

**Acceptance:** End-to-end test: plant a key that matches a vault entry in a fake git repo; run the scanner; assert the corresponding `Key` is flagged as `CONFIRMED_LEAKED` with a new `Exposure` record.

## Milestone 6 — Providers

### Task 6.1 — Provider base and registry (`core/providers/base.py`, `registry.py`)

- [ ] Define `Provider` ABC per `ARCHITECTURE.md` §6.4.
- [ ] `ProviderKey`, `ProviderKeyInfo` Pydantic models.
- [ ] Registry discovers all `Provider` subclasses and exposes them by `name`.

**Acceptance:** Tests: a mock `FakeProvider` subclass is automatically discovered by the registry.

### Task 6.2 — OpenAI provider (`core/providers/openai.py`)

- [ ] Implement `create_key`, `revoke_key`, `test_key`, `list_keys` against OpenAI's admin API.
- [ ] Use the official `openai` SDK where possible; fall back to `httpx` for admin endpoints not yet in the SDK.
- [ ] `test_key` makes a cheap models-list call.

**Acceptance:** Mock-based unit tests cover happy path and three error cases (invalid existing key, rate limit, network failure). Opt-in integration test exists but is not run by default CI.

### Task 6.3 — Anthropic provider (`core/providers/anthropic.py`)

- [ ] Same API as OpenAI provider.

**Acceptance:** Same as 6.2.

### Task 6.4 — Stripe provider (`core/providers/stripe.py`)

- [ ] Same API. Use Stripe's restricted-key creation endpoint where possible to limit blast radius of vault-issued keys.

**Acceptance:** Same as 6.2.

## Milestone 7 — CLI

### Task 7.1 — `keyguard init` (`cli/commands/init.py`)

- [ ] Prompt for master password (≥12 chars, confirmed).
- [ ] Generate `local_half`, store in keychain.
- [ ] Generate TOTP secret, display QR in terminal, show base32 fallback.
- [ ] Generate recovery code, display it once, require user to type it back to confirm they saved it.
- [ ] Create the encrypted vault at the default path (or `--vault-path`).
- [ ] Offer to install git hooks (y/N).

**Acceptance:** Integration test drives the prompts via `click.testing.CliRunner`; verify vault file exists, keychain entry exists, recovery code was required for confirmation.

### Task 7.2 — `keyguard add`

- [ ] Accept `NAME`, `--provider`, `--tags`, `--deployed-at` (repeatable), `--notes`.
- [ ] Prompt for the key value with echo off.
- [ ] Require unlock (password + TOTP) before writing.
- [ ] Append to vault; save.

**Acceptance:** Integration test adds a key and reads it back via `list` and `show`.

### Task 7.3 — `keyguard list` / `show` / `copy`

- [ ] `list` prints a table of entries via `rich` (name, provider, tags, exposure status). Filters: `--provider`, `--tag`, `--exposed`.
- [ ] `show NAME` prints metadata. `--reveal` prints the key value (requires fresh TOTP, no caching).
- [ ] `copy NAME` puts the key on the clipboard (requires fresh TOTP). Auto-clears after `--timeout` seconds (default 20).

**Acceptance:** Tests cover all flags; `copy` with no clipboard available fails gracefully.

### Task 7.4 — `keyguard scan`

- [ ] Run gitleaks + fileshunt + matcher.
- [ ] Report in three formats: `text` (default, pretty), `json`, `html`.
- [ ] Update vault with any new exposures found.
- [ ] Exit non-zero if exposures are found (useful for CI).

**Acceptance:** End-to-end test on fixture repo; verifies correct exposures surface.

### Task 7.5 — `keyguard rotate`

- [ ] Look up key, find its provider.
- [ ] Call provider to create new key.
- [ ] Add as a new `KeyVersion`; old version stays, marked `revoked_at=null` for now.
- [ ] Display deployment locations; require user to confirm they've updated each.
- [ ] On confirmation, call provider to revoke the old key; mark `revoked_at`.
- [ ] Verify new key works via `test_key`; if it fails, rollback and keep old key active.
- [ ] Preserve old key for 30 days (configurable) before auto-purge.
- [ ] `--dry-run` flag.

**Acceptance:** Mock-based integration test drives a full rotation for the OpenAI provider; verifies all state transitions and that a failed `test_key` does not revoke the old key.

### Task 7.6 — `keyguard install-hooks`

- [ ] Write a `pre-commit` script to `~/.keyguard/hooks/pre-commit`.
- [ ] Set `git config --global core.hooksPath ~/.keyguard/hooks`.
- [ ] The hook script invokes the bundled gitleaks binary on `--staged` diffs.
- [ ] `--uninstall` flag reverses the config.

**Acceptance:** After install, a test repo that stages a file containing an OpenAI key has its commit blocked; after uninstall, the same commit succeeds.

## Milestone 8 — Packaging and distribution

### Task 8.1 — Bundled gitleaks binary

- [ ] `scripts/package_binaries.py` downloads pinned gitleaks release, verifies SHA-256, places binaries in `vendor/gitleaks/<platform>/`.
- [ ] Build process invokes this script.
- [ ] `core/scanner/gitleaks.py` locates the right binary at runtime.

**Acceptance:** Fresh clone + `uv sync` + `python scripts/package_binaries.py` produces usable binaries for macOS-arm64, macOS-x64, linux-x64, linux-arm64, windows-x64.

### Task 8.2 — `pipx install` support

- [ ] `pyproject.toml` configured with `[project.scripts] keyguard = "keyguard.cli.main:cli"`.
- [ ] Test `pipx install .` works from a fresh clone.

**Acceptance:** `pipx install .` succeeds; `keyguard --version` prints the version.

### Task 8.3 — Documentation site

- [ ] `mkdocs.yml` with Material theme.
- [ ] Pages: Quickstart, How It Works (threat model), CLI Reference, Provider Matrix, FAQ, Security Disclosure.
- [ ] CI deploys to GitHub Pages on tag.

**Acceptance:** `mkdocs serve` renders locally; deployed site is accessible.

## Milestone 9 — Hardening and polish

### Task 9.1 — Error messages audit

- [ ] Every exception surfaced to the CLI has a human-readable message that tells the user what's wrong and what to try.
- [ ] Common error paths (wrong password, missing keychain entry, expired TOTP) have specific wording tested.

**Acceptance:** Review pass over every `raise` in `cli/` and matching error rendering.

### Task 9.2 — End-to-end smoke test

- [ ] A single pytest that runs the full user journey: init → add → scan (finds nothing) → plant a key in a fixture repo → scan (finds it) → rotate → verify old key revoked and new key works.

**Acceptance:** Green in CI.

### Task 9.3 — Release v0.1.0

- [ ] Tag `v0.1.0`.
- [ ] Write release notes in `CHANGELOG.md`.
- [ ] GitHub release includes the source tarball and a note on how to install via `pipx`.

**Acceptance:** Release published; a fresh environment can `pipx install keyguard==0.1.0` from the release.

## Post-v1 backlog (v2 starts here — do not work on these during v1)

- Device enrollment and multi-device sync with split-key server.
- Deployment auto-updaters: Vercel, GitHub Actions, AWS Secrets Manager, Netlify, Heroku.
- Browser extension (Chromium + Firefox) with native messaging bridge.
- GUI (Tauri or PyQt6, TBD).
- GitHub secret scanning partner integration.
- SQLCipher storage migration.
- Additional providers: GitHub, AWS IAM, Google Cloud, Azure.
- `keyguard watch` background daemon.
- Public paste-site monitoring.
- Team features (shared vaults, role-based access).
