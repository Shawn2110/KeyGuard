# KeyGuard — Test Report

> Snapshot of everything that is currently tested in the codebase. Run
> `uv run pytest --cov=keyguard --cov-report=term` locally to reproduce.
> Updated at the end of each completed PLAN.md task.

## 1. Headline numbers

- **Tests collected:** 167
- **Passing:** 167 / 167
- **Failing / skipped / xfailed:** 0
- **Total runtime on this machine:** ~12 seconds (includes a 10 MB
  AES-GCM round-trip, Argon2id derivations, and timer-based session tests)
- **Overall coverage of `src/keyguard/`:** 93% (900 statements, 48 missed)
- **Python / runner:** 3.14.3, pytest 9.0.3 with `pytest-cov`, `respx`,
  `hypothesis`, `anyio` plugins loaded

All four acceptance gates green as of the latest commit:

| Gate | Status |
|------|--------|
| `uv run ruff check` | pass (all rules clean) |
| `uv run ruff format --check` | pass (42 files already formatted) |
| `uv run mypy --strict src` | pass (23 source files, 0 issues) |
| `uv run pytest -q` | pass (167 / 167) |

## 2. Coverage by module

Numbers from `pytest --cov=keyguard --cov-report=term`:

| Module | Stmts | Miss | Branch | BrPart | Cover | Notes |
|--------|------:|-----:|-------:|-------:|------:|-------|
| `core/audit.py` | 18 | 0 | 2 | 0 | **100%** | — |
| `core/errors.py` | 21 | 0 | 0 | 0 | **100%** | — |
| `core/providers/registry.py` | 14 | 0 | 0 | 0 | **100%** | — |
| `core/scanner/matcher.py` | 23 | 0 | 8 | 0 | **100%** | — |
| `core/totp.py` | 24 | 0 | 0 | 0 | **100%** | — |
| `core/crypto.py` | 120 | 1 | 34 | 1 | **99%** | defensive DEK-length check not reachable without bypassing `wrap_dek` |
| `core/vault.py` | 135 | 1 | 20 | 1 | **99%** | same (a defensive `isinstance` branch in the b64 before-validator) |
| `core/models.py` | 114 | 1 | 8 | 1 | **98%** | one defensive branch in b64 before-validator |
| `core/keychain.py` | 51 | 4 | 4 | 0 | **93%** | two untested `KeyringError`→`LocalHalfAccessDeniedError`/`KeychainError` branches |
| `core/scanner/fileshunt.py` | 45 | 3 | 20 | 2 | **92%** | `OSError` on unreadable file not forced in tests |
| `core/providers/stripe.py` | 56 | 4 | 12 | 3 | **90%** | edge-case error code paths |
| `core/providers/anthropic.py` | 45 | 4 | 6 | 2 | **88%** | `_parse_created` fallback branches |
| `core/providers/base.py` | 39 | 3 | 2 | 0 | **88%** | `ProviderKey.value` JSON serializer isn't exercised (only used inside `encrypted_context`) |
| `core/session.py` | 76 | 10 | 12 | 2 | **86%** | best-effort lock-during-save-failure path not forced |
| `core/providers/openai.py` | 45 | 6 | 6 | 1 | **82%** | `_parse_created` fallback branches |
| `core/providers/_http.py` | 24 | 4 | 10 | 3 | **79%** | generic ≥400 and transport error branches partially covered via provider-specific tests |
| `core/scanner/gitleaks.py` | 50 | 7 | 14 | 5 | **81%** | `locate_gitleaks_binary` platform-dispatch branches and non-list JSON fallback |
| **TOTAL** | **900** | **48** | **158** | **21** | **93%** | above `AGENT.md` §3 expectation; crypto + vault meet the 95%+ target |

PLAN.md §11 targets: "85% overall, 95% for core/crypto.py and core/vault.py."
**Hit on all three** — overall 93%, crypto.py 99%, vault.py 99%.

## 3. Test inventory by module

### 3.1 `tests/unit/test_errors.py` — 7 tests

Tests the exception hierarchy from ARCHITECTURE §9. Every public class
descends from `KeyGuardError`; subtrees (crypto / keychain / provider /
scanner) stay independent; every class is raisable and catchable at the
root.

### 3.2 `tests/unit/test_crypto.py` — 42 tests (including 6 Hypothesis properties)

Covers Task 1.1 acceptance criteria:

- **Randomness:** `generate_salt` / `generate_dek` / `generate_recovery_code`
  — length, base32 alphabet restriction, randomness across calls.
- **KEK composition (Option B):** determinism, splicing resistance
  (swapping `local_half`/`server_half` produces different preimage),
  password sensitivity, input length validation.
- **`derive_kek` (Argon2id):** determinism, salt sensitivity, empty
  preimage / wrong salt length rejection.
- **`wrap_dek` / `unwrap_dek` (AES-256-GCM):** roundtrip, fresh nonce
  per call, wrong-KEK → `WrongPasswordError`, wrong-KEK-in-recovery →
  `WrongRecoveryCodeError`, length validation on all inputs.
- **`encrypt_body` / `decrypt_body`:** roundtrip including 10 MB
  plaintext, wrong DEK → `CorruptedVaultError`, wrong AAD →
  `CorruptedVaultError`, length validation.
- **Pydantic envelope models:** length validation, `frozen=True`
  enforcement.
- **Hypothesis properties** (PLAN 1.1 explicit requirement):
  - `encrypt → decrypt` roundtrip for arbitrary plaintext up to 4 KB
    (plus the dedicated 10 MB non-property test).
  - Any single-bit flip of the ciphertext raises `CorruptedVaultError`.
  - Any single-bit flip of the AAD raises `CorruptedVaultError`.
  - Any single-bit flip of the nonce raises `CorruptedVaultError`.
  - `wrap → unwrap` roundtrip for arbitrary DEKs.
  - `unwrap_dek` with a wrong KEK always raises `WrongPasswordError`.

### 3.3 `tests/unit/test_models.py` — 22 tests

Covers Task 2.1 acceptance:

- `encrypted_context` ContextVar default / nesting / reset behavior.
- `compute_fingerprint` HMAC-SHA256 correctness (length, determinism,
  value sensitivity, key sensitivity, bad-key-length rejection).
- `KeyVersion` / `SecretStr` guardrail: dict-dump keeps secret opaque;
  JSON-dump outside `encrypted_context` raises
  `PydanticSerializationError` wrapping a `CryptoError` with an
  `encrypted_context` message; JSON-dump inside context succeeds and
  round-trips; zero/negative version numbers rejected.
- `Vault` defaults, Vault JSON roundtrip (full serialize → deserialize
  under context), empty vault safe to dump, unknown fields ignored
  (forward-compat within `format_version = 1`).
- Enum serialization as lowercase strings.
- `Key` with multiple versions and deployments, scanner-glob defaults,
  UUID auto-assignment.

### 3.4 `tests/unit/test_vault.py` — 17 tests

Covers Task 2.2 acceptance (every bullet):

- `create_vault` writes a file; file is valid JSON; `wrapped_deks`
  contains both `primary` and `recovery`.
- Create → close → open round-trip preserves keys and secret values.
- Wrong password → `WrongPasswordError`; file unchanged.
- Wrong `local_half` → `WrongPasswordError`.
- Wrong recovery code → `WrongRecoveryCodeError`.
- Recovery-code path unlocks successfully.
- `rotate_password` works; old password fails afterwards; recovery
  code still works.
- **Crash simulation:** `os.replace` monkeypatched to raise between
  `.tmp` write and final rename; vault on disk is byte-identical to
  before the save; reopen ignores the partial attempt.
- Backup rotation: `.bak.1` created on second save, five saves produce
  `.bak.1..bak.3` and do NOT produce `.bak.4`.
- AAD tamper (salt bit-flip → `WrongPasswordError`; body ciphertext
  bit-flip → `CorruptedVaultError`).
- Unknown `format_version` → `UnsupportedVersionError`.
- Malformed envelope bytes → `CorruptedVaultError`.
- Missing wrapped entry → `CorruptedVaultError`.
- Access-log shrink guard refuses to save.
- `default_vault_path` returns a platform-appropriate path.

### 3.5 `tests/unit/test_keychain.py` — 12 tests

Covers Task 3.1 acceptance. Uses a custom `_InMemoryKeyring` backend so
no real OS keychain is touched.

- Round-trip for `local_half`, `totp_secret`, and `fingerprint_key`.
- Entries namespaced by username (no cross-contamination).
- Missing entry → `LocalHalfMissingError`.
- `NoKeyringError` at load → `KeychainUnavailableError`.
- `NoKeyringError` at store → `KeychainUnavailableError`.
- Backend `PasswordSetError` → `KeychainError`.
- `delete_all_keyguard_entries` removes every entry; is idempotent;
  propagates `KeychainUnavailableError` if backend is missing.

### 3.6 `tests/unit/test_totp.py` — 8 tests

Covers Task 3.2 acceptance:

- `generate_totp_secret` — length 20, randomness.
- `provisioning_uri` — contains `otpauth://`, account, issuer, secret.
- Custom issuer respected.
- `render_qr_ascii` — non-empty, multi-line, reasonable width.
- `verify_code` — accepts current code, rejects garbage, tolerates ±30s
  skew with `valid_window=1`, rejects stale codes outside window.

### 3.7 `tests/unit/test_audit.py` — 9 tests

Covers Task 4.2 acceptance:

- `append_event` adds to log, fills timestamp + device_fingerprint,
  accepts `key_id` / `details`, preserves order across multiple appends.
- `AccessEvent` frozen-ness verified: direct assignment to a prior
  entry's field raises `ValidationError`.
- `verify_log_not_shrunk` passes when equal / grown, raises when
  `.clear()`-ed or `.pop()`-ed.
- `current_device_fingerprint` is deterministic, 16 hex chars.

### 3.8 `tests/unit/test_session.py` — 10 tests

Covers Task 4.1 acceptance. Fixture combines the in-memory keyring,
real vault file under `tmp_path`, and a live TOTP secret.

- Happy-path unlock: no lock state, records `VAULT_UNLOCKED` event.
- Bad TOTP → `WrongTOTPError`.
- Bad password → `WrongPasswordError`.
- No keychain entries → `LocalHalfMissingError`.
- `lock` records `VAULT_LOCKED`, transitions state, rejects `.vault`
  access afterward, persists the event to disk.
- `lock` is idempotent.
- `add_key` appends + records `KEY_ADDED`.
- Operations after lock raise `SessionLockedError`.
- **Auto-lock fires** after a 1-second timeout (real `threading.Timer`,
  polls with 5s timeout).
- Auto-lock resets on `save()` (1s elapsed mid-timer does NOT trigger).

### 3.9 `tests/unit/test_scanner.py` — 13 tests

Covers Tasks 5.1, 5.2, 5.3 acceptance:

- **gitleaks wrapper:** parses findings from JSON output; empty stdout
  returns empty; non-zero exit (not 0 or 1) → `ScannerError`;
  `TimeoutExpired` → `ScanTimeoutError`; missing binary →
  `GitleaksNotFoundError`. All via `subprocess.run` monkeypatch.
- **fileshunt:** finds `KEY=value` lines in `.env` files; strips quotes;
  skips comments, empty lines, and `$VARIABLE_REFERENCE` lines; skips
  excluded directories (`node_modules`); respects custom include globs;
  returns `[]` for missing root.
- **matcher:** flags known key as `CONFIRMED_LEAKED` with an Exposure;
  ignores unknown findings; de-dups repeat findings at the same
  location; records findings at different locations separately.

### 3.10 `tests/unit/test_providers/` — 27 tests across 4 files

All provider HTTP is intercepted via `respx`. No real API calls.

- **test_registry.py (3 tests):** register + get round-trip, `KeyError`
  on unknown name, built-in `{openai, anthropic, stripe}` auto-register.
- **test_openai.py (8 tests):** `test_key` true on 200 / false on 401,
  `create_key` parses response, `revoke_key` sends DELETE, `list_keys`
  parses `data` array and `revoked` flag, wrong existing → `ProviderAuthError`,
  429 → `ProviderRateLimitError`, connection error → `ProviderUnavailableError`.
- **test_anthropic.py (7 tests):** same coverage against Anthropic's
  endpoint shape, including `status: "active"`/`"revoked"` parsing.
- **test_stripe.py (8 tests):** same coverage against Stripe's
  `/v1/api_keys` + `/expire` revoke pattern, including the `expired`
  flag parsing and Basic-auth header shape.

### 3.11 `tests/unit/test_smoke.py` — 1 test

Asserts the top-level `keyguard` package imports and exposes a string
`__version__`. Guards against import-order regressions.

## 4. What's tested vs what's not

### 4.1 Covered today

Every `src/keyguard/core/` module has tests. Every public function has at
least one happy-path test plus error-path tests for every way it can
raise. Every PLAN.md acceptance bullet for milestones 0.2, 1.1, 1.2, 2.1,
2.2, 3.1, 3.2, 4.1, 4.2, 5.1, 5.2, 5.3, 6.1, 6.2, 6.3, 6.4 is verified
by at least one test.

### 4.2 Not yet covered

- `src/keyguard/cli/*` — Milestone 7 (not implemented yet; see PLAN).
- `scripts/package_binaries.py` — Milestone 8.1 (not implemented yet).
- **Opt-in provider integration tests** against real sandbox API keys
  — intentionally gated behind `@pytest.mark.integration` (not yet
  written; will require `KEYGUARD_INTEGRATION=1` env var).
- **End-to-end CLI journey test** — Milestone 9.2 (deferred until
  Milestone 7 exists).
- **Gitleaks binary fixture repo** with planted known-good secrets —
  deferred until the binary is bundled (Milestone 8.1).

## 5. Testing conventions in this project

- **Mock at the HTTP boundary, not inside providers.** `respx` intercepts
  `httpx.Client` calls; provider code is otherwise unchanged.
- **Never touch the real OS keychain.** Tests use the in-memory
  `KeyringBackend` subclass in fixture.
- **Never touch the real filesystem outside `tmp_path`.** Every test
  that creates a vault uses the pytest `tmp_path` fixture.
- **Hypothesis for crypto invariants.** Property tests with reasonable
  `max_examples` (30–100) and no `deadline` — Argon2id is too slow
  for a short deadline.
- **Test names describe the assertion**, not the setup. e.g.
  `test_unwrap_with_wrong_kek_raises_wrong_password`.
- **No mocks for things we own.** Internal core modules are exercised
  end-to-end inside tests; only external edges (OS keychain, HTTP) are
  mocked.

## 6. How to reproduce locally

On the author's Windows + OneDrive machine, run:

    export UV_PROJECT_ENVIRONMENT="$LOCALAPPDATA/uv/envs/keyguard"
    uv sync --all-extras
    uv run pytest -q
    uv run pytest --cov=keyguard --cov-report=term

On a clean Linux/macOS checkout (CI), the first `export` is unnecessary.

## 7. CI

`.github/workflows/ci.yml` runs four parallel jobs on every push and PR:

1. **Lint** — `uv run ruff check` + `uv run ruff format --check`.
2. **Type-check** — `uv run mypy --strict src`.
3. **Test matrix** — `{ubuntu, macos, windows} × {3.11, 3.12}`,
   `uv run pytest --cov=keyguard --cov-report=term-missing`.
4. **Security** — `uv run bandit -r src` + `uv run pip-audit --strict`.

All four must pass before a merge.
