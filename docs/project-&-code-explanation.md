# KeyGuard — Project & Code Explanation

> A complete walkthrough of what KeyGuard is, how it's designed, what every
> part of the codebase does, and where we are in the build. This document is
> updated at the end of each completed task in `PLAN.md`. If something here
> conflicts with the code, the code is right and this doc is stale —
> please open an issue.

## Table of contents

1. [One-paragraph summary](#1-one-paragraph-summary)
2. [The problem KeyGuard solves](#2-the-problem-keyguard-solves)
3. [Who it's for (and who it isn't for)](#3-who-its-for-and-who-it-isnt-for)
4. [Design principles](#4-design-principles)
5. [High-level architecture](#5-high-level-architecture)
6. [How the crypto works, in plain English](#6-how-the-crypto-works-in-plain-english)
7. [The vault file on disk](#7-the-vault-file-on-disk)
8. [Directory tour](#8-directory-tour)
9. [Module-by-module walkthrough](#9-module-by-module-walkthrough)
10. [Key user flows](#10-key-user-flows)
11. [Tech stack — why each tool](#11-tech-stack--why-each-tool)
12. [Testing strategy](#12-testing-strategy)
13. [Development workflow](#13-development-workflow)
14. [Current implementation status](#14-current-implementation-status)
15. [v1 → v2 roadmap](#15-v1--v2-roadmap)
16. [Glossary](#16-glossary)

---

## 1. One-paragraph summary

KeyGuard is a local-first, command-line tool for developers that does three
things in one: stores API keys (OpenAI, Stripe, Anthropic, ...) in an
encrypted vault on your own machine; scans your codebase and filesystem for
keys that have accidentally leaked; and, when a leak is found, rotates the
leaked key with the provider automatically and walks you through updating
every place the old key was deployed. Unlike a password manager, the vault is
a means to an end — the product's real value is the **detect → rotate → update
deployments** loop, which existing tools leave to the user.

## 2. The problem KeyGuard solves

Developers leak API keys constantly. The most common paths are:

1. Committing a `.env` file or hardcoded secret to a git repo (sometimes
   public, sometimes to a private repo that later becomes public).
2. Pasting keys into Slack, issue trackers, or StackOverflow when asking for
   help.
3. Leaving keys in log files that get shipped to log aggregators.
4. Embedding keys in screenshots or during screen-shares.
5. Storing keys in plaintext in CI/CD configs and emailing them around.

The current market has two half-solutions. **Password managers** (1Password,
Bitwarden, KeePassXC) store secrets securely but do nothing about the
leakage workflow. **Secret scanners** (gitleaks, trufflehog) detect leaks but
don't help you fix them. No existing tool closes the full loop: detect the
leak, identify *which* of your keys it is, rotate it, and update every place
it was deployed. KeyGuard is that tool.

## 3. Who it's for (and who it isn't for)

**Primary users.** Individual developers and small teams (1–10 people) who
have 5–30 third-party API keys and use 2–10 deployment targets (local dev,
Vercel, Netlify, AWS, GitHub Actions, ...). They've been burned once or know
someone who has.

**Not target users.** Large enterprises with dedicated security teams —
they already use HashiCorp Vault, AWS Secrets Manager, or similar.
KeyGuard doesn't try to compete there.

## 4. Design principles

From [`ARCHITECTURE.md` §1](ARCHITECTURE.md#1-guiding-principles):

1. **Core as library, CLI as a thin wrapper.** The CLI is one frontend among
   several — a future GUI, browser extension, or server will reuse the same
   core. The core library never imports from `cli/`.
2. **Plugins for anything with N implementations.** Providers (OpenAI,
   Stripe, ...) and deployment updaters (Vercel, GitHub Actions, ...) are
   plugins behind ABCs. Adding a new one must not touch any other code.
3. **Explicit trust boundaries.** Every component declares what it trusts
   and what it emits. Secrets never cross a boundary in plaintext except
   when strictly necessary (e.g., calling a provider API).
4. **Fail closed.** If decryption fails, if rotation partial-fails, if the
   keychain is unavailable — the tool stops and reports. It never proceeds
   "best effort" with secrets.

## 5. High-level architecture

```
                +---------------------------------------------+
                |                   CLI (click)                |
                |  init, add, list, show, copy, scan,          |
                |  rotate, install-hooks                       |
                +----------------------+----------------------+
                                       | (function calls only)
                +----------------------v----------------------+
                |                Core library                 |
                |                                             |
                |  +-----------+   +-------------+            |
                |  |  Vault    |   |  Session    |            |
                |  |  service  |   |  manager    |            |
                |  +-----+-----+   +------+------+            |
                |        |                |                   |
                |  +-----v-----+   +------v------+            |
                |  |  Crypto   |   |  Providers  |            |
                |  | primitives|   |  (plugins)  |            |
                |  +-----------+   +-------------+            |
                |                                             |
                |  +-----------+   +-------------+            |
                |  |  Scanner  |   |  Audit log  |            |
                |  |  adapter  |   |             |            |
                |  +-----------+   +-------------+            |
                +-------------------+-------------------------+
                                    |
        +--------------+------------+------------+-------------+
        v              v            v            v             v
  +----------+   +----------+   +---------+  +---------+  +----------+
  | OS       |   | Encrypted|   | Gitleaks|  |Provider |  | GitHub   |
  | keychain |   | vault    |   | binary  |  |  APIs   |  | Actions  |
  |          |   | file     |   |         |  |         |  | (v2)     |
  +----------+   +----------+   +---------+  +---------+  +----------+
```

Read the diagram top to bottom: CLI commands call into core services,
services use primitives, and primitives (plus the Scanner adapter) touch
the outside world — OS keychain, vault file, bundled gitleaks, and provider
HTTPS endpoints. The **core never calls the CLI**, and **only the Scanner
and the Providers do network I/O** in v1.

## 6. How the crypto works, in plain English

This is the part most people trip on. The TL;DR: **there's one key that
actually encrypts your secrets (the DEK) and one or more keys that
encrypt the DEK (the KEKs). The KEKs are derived from what you know
(password) and what you have (local keychain entry, recovery code).**
Changing your password means re-deriving a KEK and re-wrapping the DEK —
the big blob of ciphertext with all your secrets in it never has to change.

### 6.1 Envelope encryption (two layers)

**Layer 1 — the Data Encryption Key (DEK).** A 32-byte random key generated
once when you first run `keyguard init`. The whole vault body (all your
stored API keys, deployments, metadata) is encrypted under this DEK using
AES-256-GCM. The DEK never changes during the life of the vault unless the
user explicitly rotates the master key.

**Layer 2 — the Key Encryption Keys (KEKs).** Each KEK is a key that wraps
(encrypts) a copy of the DEK. Different KEKs exist for different unlock
paths:

- `KEK_primary` — derived from your password + a machine-local random value
  (`local_half` stored in the OS keychain) + a per-installation value
  (`server_half`, which is all-zeros in v1 and becomes real in v2).
- `KEK_recovery` — derived from your password + a one-time recovery code
  shown at signup.

Both KEKs wrap the **same** DEK, each producing a different wrapped blob
stored side-by-side in the vault file.

**Why two layers?** Because changing any unlock input (the password, adding
a device, using the recovery code) only needs to re-derive a KEK and
re-wrap the DEK — the big vault body is untouched. Fast, even with a huge
vault. Without this pattern, a password change would re-encrypt every
stored key.

### 6.2 Key derivation — the preimage

Before Argon2id compresses the KEK inputs into a 32-byte KEK, we
**domain-separate** each input with HKDF-SHA256 so that a change in one
input can't pretend to be a change in another:

```
hkdf_password      = HKDF-SHA256(password.encode("utf-8"),
                                 salt=b"", info=b"keyguard-kek-password-v1",
                                 length=32)
hkdf_local_half    = HKDF-SHA256(local_half,
                                 salt=b"", info=b"keyguard-kek-local-half-v1",
                                 length=32)
hkdf_server_half   = HKDF-SHA256(server_half,
                                 salt=b"", info=b"keyguard-kek-server-half-v1",
                                 length=32)
primary_preimage = hkdf_password || hkdf_local_half || hkdf_server_half
                   # 96 bytes

KEK_primary = Argon2id(primary_preimage, salt=salt_primary,
                       time_cost=3, memory_cost=65536 KiB, parallelism=4,
                       hash_len=32)
```

For the recovery KEK, analogous with `hkdf_recovery_code` instead of
`local_half + server_half`. This is "Option B" in the initial design
discussion — approved because it prevents splicing attacks (you can't
prepend bytes to the password and pretend they came from `local_half`).

### 6.3 Argon2id parameters (fixed, do not change)

```
time_cost   = 3
memory_cost = 65536   (64 MiB)
parallelism = 4
hash_len    = 32
```

These are above OWASP 2024 minimums. On 2020+ hardware this derivation
takes ~1 second — which is fine for an interactive unlock and painful for
an offline attacker trying billions of passwords.

### 6.4 AES-256-GCM usage

- Key size: 256 bits.
- Nonce: 12 random bytes per encrypt. Never reused. Since we generate a
  fresh nonce every time, and the DEK is stable, we're within the
  AES-GCM birthday bound for 2^32 messages before rotation is recommended.
- Associated data (AAD): binds vault metadata (format version, salts) to
  the ciphertext so an attacker can't swap metadata without invalidating
  the GCM auth tag. Exact composition is finalized in Task 2.2
  (`core/vault.py`).
- Tag size: 128 bits — the AES-GCM default.

### 6.5 The inputs, concretely

- **`password`** — what you type. UTF-8 encoded. Never stored anywhere.
- **`local_half`** — 32 random bytes, generated at `keyguard init`, stored
  in the OS keychain (macOS Keychain, Windows Credential Manager, Linux
  libsecret). Never leaves this machine.
- **`server_half`** — 32 bytes. In v1 it's all zeros (placeholder for v2).
  In v2 it'll be fetched from a split-key server post-authentication —
  making the vault useless if you only have the file or only have the
  server, but unlockable with both plus the password.
- **`recovery_code`** — 20 random bytes (160 bits), shown once at
  `init` as 32 base32 characters grouped like
  `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`. If you lose your password,
  this gets you back in. KeyGuard never stores it anywhere — you have to
  write it down.
- **`salt_primary`**, **`salt_recovery`** — 16 random bytes each, stored
  in cleartext in the vault file. Different for each KEK entry.

### 6.6 TOTP — the second factor on unlock

In addition to the password, the CLI asks for a TOTP code (6-digit number
from Google Authenticator / Authy / 1Password) before it even tries to
decrypt. The TOTP secret is stored in the OS keychain (separately from
`local_half`). This means someone who steals your laptop and knows your
disk password still can't unlock the vault without also having your phone.

## 7. The vault file on disk

Single JSON file, pretty-printed:

```json
{
  "format_version": 1,
  "created_at": "2026-04-18T12:00:00Z",
  "kdf": {
    "algorithm":   "argon2id",
    "time_cost":   3,
    "memory_cost": 65536,
    "parallelism": 4
  },
  "wrapped_deks": [
    {"id": "primary",  "salt": "<b64>", "nonce": "<b64>", "ciphertext": "<b64>"},
    {"id": "recovery", "salt": "<b64>", "nonce": "<b64>", "ciphertext": "<b64>"}
  ],
  "body": {
    "nonce":           "<b64>",
    "ciphertext":      "<b64>",
    "associated_data": "<b64>"
  }
}
```

**Atomic writes.** Every save writes to `<path>.tmp` first, then calls
`os.replace()` to swap it into place. This is atomic on all supported OSes
and means a crash mid-write never leaves a half-written vault.

**Backups.** Before every save, the previous file is copied to
`vault.enc.bak.1`, rotating older backups to `.bak.2` and `.bak.3`. The
oldest is dropped. More vaults have been saved by backups than by
cryptography.

The *decrypted* body is a Pydantic model tree — see §9's walkthrough of
`core/models.py`.

## 8. Directory tour

```
keyguard/
├── .github/workflows/ci.yml       CI: lint, type-check, test matrix, security
├── .gitignore                     Python, IDE, venv, vault files, Claude local
├── .pre-commit-config.yaml        Local pre-commit hooks (ruff + mypy + pytest)
├── AGENT.md                       (none — docs live under docs/)
├── README.md                      One-page pointer into docs/
├── docs/
│   ├── AGENT.md                   Rules for Claude Code contributors
│   ├── ARCHITECTURE.md            System design, crypto scheme, vault format
│   ├── PLAN.md                    Milestone-sequenced task list
│   ├── PRD.md                     Product requirements
│   └── project-&-code-explanation.md   (this file)
├── pyproject.toml                 Deps + ruff/mypy/pytest/bandit config
├── scripts/                       Packaging helpers (populated in Task 8.1)
├── src/keyguard/                  All runtime code
│   ├── __init__.py                `__version__`
│   ├── core/                      Pure logic — no CLI, no network (mostly)
│   │   ├── errors.py              Exception hierarchy (done in Task 1.2)
│   │   ├── crypto.py              Crypto primitives (Task 1.1, pending)
│   │   ├── vault.py               Vault file I/O (Task 2.2, pending)
│   │   ├── session.py             Unlock/lock lifecycle (Task 4.1, pending)
│   │   ├── models.py              Pydantic data model (Task 2.1, pending)
│   │   ├── keychain.py            OS keychain wrapper (Task 3.1, pending)
│   │   ├── totp.py                TOTP + QR (Task 3.2, pending)
│   │   ├── audit.py               Append-only access log (Task 4.2, pending)
│   │   ├── scanner/
│   │   │   ├── gitleaks.py        Bundled gitleaks subprocess (Task 5.1)
│   │   │   ├── fileshunt.py       Filesystem .env hunt (Task 5.2)
│   │   │   └── matcher.py         Cross-ref findings with vault (Task 5.3)
│   │   └── providers/
│   │       ├── base.py            Provider ABC (Task 6.1)
│   │       ├── registry.py        Dynamic provider discovery (Task 6.1)
│   │       ├── openai.py          OpenAI rotation (Task 6.2)
│   │       ├── anthropic.py       Anthropic rotation (Task 6.3)
│   │       └── stripe.py          Stripe rotation (Task 6.4)
│   └── cli/                       Thin CLI over core
│       ├── main.py                click entry point (Task 7.*)
│       ├── ui.py                  rich formatters
│       └── commands/              one file per CLI command
├── tests/
│   ├── unit/                      Per-module fast tests + Hypothesis
│   ├── integration/               End-to-end CLI ↔ filesystem tests
│   └── fixtures/                  Planted-secret repos, etc.
├── vendor/gitleaks/               Bundled gitleaks binary per platform
│                                  (populated in Task 8.1)
├── uv.lock                        Pinned dependency resolution
└── init.py                        (stray 2-byte file, pre-existing —
                                    flagged for removal)
```

## 9. Module-by-module walkthrough

The source tree exists today as scaffolding — most modules are empty
package-marker `__init__.py` files. This section describes what each one
**will** contain, plus marks what's **currently implemented**.

### 9.1 `src/keyguard/__init__.py`  [scaffold, done]

Top-level package. Exposes `__version__ = "0.0.0"`. No other public API.

### 9.2 `src/keyguard/core/errors.py`  [implemented — Task 1.2]

The exception hierarchy. Every exception KeyGuard raises itself derives
from `KeyGuardError`, which lets CLI boundary code catch the whole library
surface with one `except`. Four independent subtrees:

- **Crypto** — `CryptoError`, and children:
  - `WrongPasswordError` — password failed to derive a KEK that unwraps the DEK.
  - `WrongRecoveryCodeError` — recovery code failed similarly.
  - `CorruptedVaultError` — AES-GCM auth-tag check failed (tamper,
    truncation, or wrong key).
  - `UnsupportedVersionError` — vault's `format_version` is newer than
    this build understands.
- **Keychain** — `KeychainError`, and children:
  - `KeychainUnavailableError` — service not reachable (headless Linux).
  - `LocalHalfMissingError` — no `local_half` on this machine yet.
  - `LocalHalfAccessDeniedError` — OS denied access (macOS prompt dismissed).
- **Provider** — `ProviderError`, and children:
  - `ProviderAuthError` — provider rejected the user-supplied existing key.
  - `ProviderRateLimitError` — 429 from the provider.
  - `ProviderUnavailableError` — network error, 5xx, or timeout.
- **Scanner** — `ScannerError`, and children:
  - `GitleaksNotFoundError` — bundled binary missing for this platform.
  - `ScanTimeoutError` — subprocess exceeded timeout.

Each class's docstring names the exact trigger condition. The CLI catches
`KeyGuardError` at the command boundary and renders a friendly message;
the core library never prints.

**Tested by** [`tests/unit/test_errors.py`](../tests/unit/test_errors.py) —
six topology tests confirming every public name is a `KeyGuardError`
subclass, subtrees don't cross-contaminate, and every class is raisable
and catchable at the root.

### 9.3 `src/keyguard/core/crypto.py`  [implemented — Task 1.1]

Pure functions. No file I/O, no global state. Wraps `cryptography` and
`argon2-cffi`. Public API:

- `derive_kek(preimage, salt) -> bytes` — Argon2id with the locked params
  (`t=3, m=64 MiB, p=4, hash_len=32`).
- `compose_primary_kek_input(password, local_half, server_half) -> bytes` —
  HKDF-per-input composition (Option B), produces the 96-byte Argon2id
  preimage for `KEK_primary`.
- `compose_recovery_kek_input(password, recovery_code) -> bytes` — same
  pattern for the recovery path, producing a 64-byte preimage.
- `generate_dek() -> bytes` — 32 random bytes via `secrets.token_bytes`.
- `wrap_dek(kek, dek, salt) -> WrappedDEK` — AES-256-GCM encrypt the DEK;
  the KDF salt that produced `kek` is packaged into the returned
  `WrappedDEK` so every unlock-path entry is self-contained.
- `unwrap_dek(kek, wrapped, *, recovery=False) -> bytes` — inverse; raises
  `WrongPasswordError` by default or `WrongRecoveryCodeError` when the
  caller sets `recovery=True`.
- `encrypt_body(dek, plaintext, aad) -> EncryptedBody` — vault body cipher.
- `decrypt_body(dek, body, aad) -> bytes` — inverse; raises
  `CorruptedVaultError` on any auth-tag failure.
- `generate_salt() -> bytes` — 16 random bytes.
- `generate_recovery_code() -> tuple[str, bytes]` — 20 raw bytes plus the
  dashed base32 display form `XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX-XXXX`.

Signature deviations from ARCHITECTURE §6.1 (minor, on the record):
`wrap_dek` takes a third `salt` argument so `WrappedDEK` carries KDF
metadata inline, and `unwrap_dek` accepts a keyword-only `recovery` flag
so the caller picks the error type. AAD composition remains deferred to
Task 2.2 (`core/vault.py`).

**Tested by** [`tests/unit/test_crypto.py`](../tests/unit/test_crypto.py) —
43 unit tests plus 6 Hypothesis property tests covering round-trip,
ciphertext/nonce/AAD bit-flip tamper detection, and wrong-KEK rejection.
Coverage: **99%** on `crypto.py` (target: 95%).

### 9.4 `src/keyguard/core/vault.py`  [pending — Task 2.2]

Owns the vault file format. Reads and writes the JSON envelope in §7. Uses
`core/crypto.py` for every cryptographic operation; it contains **no**
crypto itself. Public API:

- `create_vault(path, password, local_half, recovery_code) -> Vault`
- `open_vault(path, password, local_half) -> UnlockedVault`
- `open_vault_with_recovery(path, password, recovery_code) -> UnlockedVault`
- `UnlockedVault.save() -> None` — atomic, preserves backups.
- `UnlockedVault.rotate_password(new_password) -> None` — re-derives
  `KEK_primary` and re-wraps the DEK; vault body untouched.

Atomic writes via `.tmp` + `os.replace()`; backup rotation keeps three.

### 9.5 `src/keyguard/core/session.py`  [pending — Task 4.1]

The lifecycle of an unlocked vault. Holds the in-memory DEK and decrypted
state. Handles the auto-lock timer (5-minute default). Zeroizes secrets on
lock. Every vault-mutating operation goes through a `Session` method so
auto-lock and audit logging are consistent — callers never hold a DEK
directly.

### 9.6 `src/keyguard/core/models.py`  [pending — Task 2.1]

Pydantic v2 data classes. Everything persisted inside the encrypted body:

- `Vault` — top-level: `format_version`, `created_at`, `keys`, `access_log`,
  `settings`.
- `Key` — `id`, `name`, `provider`, `tags`, `notes`, `versions`,
  `deployments`, `exposure_status`, `exposures`.
- `KeyVersion` — `version_number`, `value: SecretStr`, `created_at`,
  `revoked_at`, `rotation_reason`, `fingerprint`.
- `Deployment` — where the key is installed (Vercel project X, GH Actions
  repo Y, local .env at path Z, ...).
- `Exposure` — a recorded leak with `discovered_at`, `source_type`,
  `location`, `severity`, `status`, and a link back to the exact
  `KeyVersion` that leaked.
- `AccessEvent` — one audit-log entry.
- `VaultSettings` — clipboard timeout, auto-lock seconds, scanner
  defaults, etc.

A custom JSON serializer enforces that `SecretStr` fields can only be
serialized inside an explicit "encrypted context" — any accidental
`model_dump_json()` outside `vault.save()` raises.

### 9.7 `src/keyguard/core/keychain.py`  [pending — Task 3.1]

Thin, typed wrapper over `keyring`. Exposes `store_local_half` /
`load_local_half` / `store_totp_secret` / `load_totp_secret` /
`delete_all_keyguard_entries`. Maps the many `keyring` exceptions down to
our `KeychainError` subclasses (so callers only deal with our types).
Handles the "first run on a new machine" case gracefully.

### 9.8 `src/keyguard/core/totp.py`  [pending — Task 3.2]

TOTP secret generation, QR code rendering for the setup flow, and code
verification with a one-step clock-skew tolerance. Built on `pyotp`.

### 9.9 `src/keyguard/core/audit.py`  [pending — Task 4.2]

Append-only access log. No API to delete or edit events. The vault writer
refuses to save if the log has shrunk between open and save — a defence
against accidental or malicious history erasure within an unlocked session.

### 9.10 `src/keyguard/core/scanner/gitleaks.py`  [pending — Task 5.1]

Subprocess wrapper around the bundled `gitleaks` binary. Locates the right
binary for the current platform, invokes it with our ruleset, and parses
JSON output into a list of `RawFinding` records. Handles the quirk that
gitleaks exits non-zero when it finds secrets — that's success, not error.

### 9.11 `src/keyguard/core/scanner/fileshunt.py`  [pending — Task 5.2]

Walks a root path looking for likely-secret-bearing files (`.env*`,
`*credentials*`, `secrets.y*ml`, `.npmrc`, `.pypirc`, ...). Skips
`node_modules`, `.git`, `.venv`, `__pycache__`. Extracts `KEY=value`
pairs and emits them as `RawFinding` records.

### 9.12 `src/keyguard/core/scanner/matcher.py`  [pending — Task 5.3]

Takes `RawFinding`s, computes SHA-256 fingerprints, and compares against
the `fingerprint` field of every `KeyVersion` in the vault. When matches
are found, produces `Exposure` records linked to the exact leaked
version. The critical design choice: **fingerprints are stored outside
the encrypted body**, so the scanner can match without unlocking the
vault. The vault only needs to be unlocked when the user wants to *see*
which key leaked (not just know that one did).

### 9.13 `src/keyguard/core/providers/`  [pending — Tasks 6.1–6.4]

- `base.py` — the `Provider` ABC: `create_key`, `revoke_key`, `test_key`,
  `list_keys`, class attributes for `name`, `display_name`, `key_pattern`.
- `registry.py` — enumerates all `Provider` subclasses and maps `name` →
  class. Dynamic so new providers are automatic.
- `openai.py` / `anthropic.py` / `stripe.py` — the three v1 providers.
  Each uses the provider's official SDK where available, falls back to
  `httpx` for admin endpoints not covered by the SDK.

### 9.14 `src/keyguard/cli/`  [pending — Tasks 7.1–7.6]

`main.py` is the `click` entry point. Every user-facing command lives in
`commands/`, one file per command, matching PLAN.md Milestone 7. The CLI
layer contains zero business logic: argparse → call core → format with
`rich`. If a conditional changes behavior, it belongs in core.

## 10. Key user flows

### 10.1 First run: `keyguard init`

1. User runs `keyguard init`.
2. CLI prompts for a master password (≥ 12 chars, confirmed).
3. Core generates `local_half` (32 random bytes), stores it in the OS
   keychain under a fixed service name.
4. Core generates a TOTP secret, prints a terminal QR code + base32
   fallback, and stores the secret in the keychain.
5. Core generates a recovery code (20 bytes → 32 base32 chars with
   dashes), prints it **once** in a visually conspicuous way, and asks
   the user to type it back to confirm it was recorded. KeyGuard never
   stores it.
6. Core derives `KEK_primary` and `KEK_recovery`, generates the DEK,
   wraps the DEK under both KEKs, writes the vault file.
7. CLI offers to run `install-hooks` to set up the global pre-commit
   scanner. User confirms or declines.

### 10.2 Daily use: add, list, show, copy

- `keyguard add NAME` — prompts for the secret value with echo off,
  requires fresh password + TOTP, writes to the vault.
- `keyguard list` — prints a filterable table: name, provider, tags,
  exposure status.
- `keyguard show NAME` — prints metadata; `--reveal` prints the value
  (fresh TOTP required, no caching).
- `keyguard copy NAME` — puts value on clipboard (fresh TOTP required),
  auto-clears after `--timeout` seconds (default 20).

### 10.3 Rotation: `keyguard rotate NAME`

The product's signature flow. Steps:

1. Look up `Key` by name, find its `Provider`.
2. Call `Provider.create_key()` with the user's existing key — returns a
   new key.
3. Record the new key as a new `KeyVersion`. Old version stays usable for
   now.
4. Display every tracked deployment for this key. For each one, the CLI
   walks the user through updating it (or, in v2, auto-updates via
   `DeploymentUpdater`).
5. When the user confirms all deployments updated, call
   `Provider.revoke_key()` on the old key. Mark `revoked_at` on the old
   `KeyVersion`.
6. Call `Provider.test_key()` on the new key. If it fails, **rollback**:
   don't revoke, keep the old one active, bail with a clear error.
7. Preserve the old version for 30 days (configurable) for forensic
   purposes before auto-purge.

`--dry-run` walks the flow without actually calling the provider.

### 10.4 Scanner: `keyguard scan [PATH]`

1. Run `gitleaks.py` against git history in the given path.
2. Run `fileshunt.py` over the filesystem below the path.
3. Feed all `RawFinding`s into `matcher.py` along with the vault's
   fingerprints.
4. Any matches become new `Exposure` records on the relevant `Key`. The
   key's `exposure_status` goes to `CONFIRMED_LEAKED`.
5. Emit report in `text` (default, via `rich`), `json`, or `html`.
6. Exit non-zero if any exposures were found (useful for CI).

### 10.5 Git pre-commit hook: `keyguard install-hooks`

1. Write a shell script to `~/.keyguard/hooks/pre-commit`.
2. `git config --global core.hooksPath ~/.keyguard/hooks`.
3. The script invokes the bundled gitleaks on staged diffs.
4. Any finding aborts the commit with a clear message pointing to
   `keyguard add` or `keyguard rotate` as follow-up.
5. `--uninstall` reverses the config cleanly.

## 11. Tech stack — why each tool

Locked by `AGENT.md` §5. Swapping any of these requires user approval.

| Concern | Tool | Why this choice |
|---|---|---|
| Package manager | `uv` | Fast, deterministic, one tool replaces pip+pip-tools+venv+pyenv. |
| Python | 3.11+ | 3.11 stable, typed-exceptions improvements, pattern matching. |
| CLI framework | `click` | Mature, composable, plays well with `rich`. |
| Terminal UI | `rich` | Tables, colors, QR code rendering, zero-config. |
| Interactive prompts | `questionary` | Nicer UX than click prompts for multi-step flows. |
| Crypto | `cryptography` + `argon2-cffi` + `pyotp` | Industry-standard, audited, not DIY. |
| Data models | `pydantic` v2 | Type-driven validation, `SecretStr` built-in, good JSON support. |
| OS keychain | `keyring` | Cross-platform (macOS, Windows, libsecret). |
| Paths | `platformdirs` | Cross-platform default config/data dirs. |
| HTTP | `httpx` | Sync + async, better defaults than `requests`. |
| Logging | `structlog` | Structured output, built-in `SecretStr` redaction. |
| Tests | `pytest` + `hypothesis` + `respx` + `pytest-cov` | Hypothesis is non-negotiable for crypto; respx mocks httpx cleanly. |
| Lint/format | `ruff` | Fast, replaces flake8+isort+pyupgrade+black. |
| Type checking | `mypy --strict` | Strict mode catches untyped function definitions — non-negotiable for a security tool. |
| Security scan | `bandit` + `pip-audit` | Bandit for code, pip-audit for CVE'd deps. |
| Git hook scanner | bundled `gitleaks` | Compiled Go binary, fast on large repos. |
| Docs | `mkdocs-material` | Same tool docs users already recognize. |

## 12. Testing strategy

- **Unit tests** live in `tests/unit/`, mirror the source tree 1:1
  (`src/keyguard/core/crypto.py` → `tests/unit/test_crypto.py`).
- **Property tests** with `hypothesis` for every crypto primitive:
  round-trip, tamper detection, wrong-key rejection. Non-crypto code
  can use hypothesis too, but it's mandatory only for crypto.
- **Integration tests** in `tests/integration/` drive the CLI →
  core → filesystem flow against a temporary vault (always via
  `tmp_path`, never the real `~/.keyguard`).
- **Provider tests** mock `httpx` via `respx`. The only place real
  HTTP is allowed is an opt-in CI workflow that uses sandbox
  credentials and only runs on `[integration]`-tagged tests.
- **Scanner tests** use a fixture repo with known-planted secrets
  and assert the scanner finds exactly those.
- **Coverage target:** 85% overall, 95% for `core/crypto.py` and
  `core/vault.py` specifically.
- **Tests that touch the real keychain or the real filesystem
  outside `tmp_path` are a bug.** Enforced by code review and
  eventually by test fixtures.

## 13. Development workflow

### 13.1 Setup

On the author's Windows + OneDrive box, two workarounds apply (live in
memory as reference; see also `pyproject.toml` for #1):

1. **mypy mypyc wheel is blocked by Windows Application Control.** The
   pre-compiled `mypy` wheel ships a generated-named `.pyd` that triggers
   Smart App Control. Workaround: `[tool.uv] no-binary-package = ["mypy"]`
   in `pyproject.toml` so `uv sync` builds mypy from source. No action
   needed on other machines.
2. **OneDrive locks files inside `.venv/`.** Running `uv sync` on a path
   OneDrive is actively syncing produces partial installs (files missing
   mid-write). Workaround: set
   `UV_PROJECT_ENVIRONMENT=$LOCALAPPDATA/uv/envs/keyguard` so the venv
   lives outside OneDrive's scope. Every shell working on this repo
   should export this before running `uv` commands.

### 13.2 Day-to-day commands

```
uv sync --all-extras           # Set up / refresh the venv
uv run pytest -q               # Run tests
uv run ruff check              # Lint
uv run ruff format --check     # Format check (no changes)
uv run ruff format             # Apply formatting
uv run mypy --strict src       # Type-check
uv run bandit -r src           # Security scan
uv run pip-audit               # CVE scan of deps
pre-commit install             # One-time, installs local git hooks
```

### 13.3 Commit cadence

- **Micro-commits:** every commit touches exactly one file.
- **Conventional Commits:** `feat`, `fix`, `test`, `docs`, `refactor`,
  `perf`, `chore`, `build`, `ci`. Body optional but encouraged.
- **No `Co-Authored-By` trailer.**
- **Push after a task is complete.** Mid-task work stays local until
  the acceptance gate is green and PLAN.md is updated.

### 13.4 CI pipeline

GitHub Actions at `.github/workflows/ci.yml`. Four parallel jobs:

1. **Lint** — `ruff check` + `ruff format --check`.
2. **Type-check** — `mypy --strict src`.
3. **Test** — matrix: {ubuntu, macos, windows} × {py3.11, py3.12},
   `pytest --cov`.
4. **Security** — `bandit -r src` + `pip-audit --strict`.

All four must pass before merge.

## 14. Current implementation status

As of 2026-04-18:

| Milestone | Task | Status | Files |
|---|---|---|---|
| 0 | 0.1 Repo scaffold | ✅ Done | `pyproject.toml`, `.github/workflows/ci.yml`, `.pre-commit-config.yaml`, `.gitignore`, `README.md`, full `src/` + `tests/` package tree |
| 0 | 0.2 Threat model doc | Not started | `docs/THREAT_MODEL.md` |
| 1 | 1.1 Crypto primitives | ✅ Done (99% cov) | `src/keyguard/core/crypto.py`, `tests/unit/test_crypto.py` |
| 1 | 1.2 Error hierarchy | ✅ Done | `src/keyguard/core/errors.py`, `tests/unit/test_errors.py` |
| 2 | 2.1 Pydantic models | Not started | `src/keyguard/core/models.py` |
| 2 | 2.2 Vault I/O | Not started | `src/keyguard/core/vault.py` |
| 3 | 3.1 Keychain wrapper | Not started | `src/keyguard/core/keychain.py` |
| 3 | 3.2 TOTP module | Not started | `src/keyguard/core/totp.py` |
| 4 | 4.1 Session manager | Not started | `src/keyguard/core/session.py` |
| 4 | 4.2 Audit log | Not started | `src/keyguard/core/audit.py` |
| 5 | 5.1–5.3 Scanner | Not started | `src/keyguard/core/scanner/*.py` |
| 6 | 6.1–6.4 Providers | Not started | `src/keyguard/core/providers/*.py` |
| 7 | 7.1–7.6 CLI | Not started | `src/keyguard/cli/*.py` |
| 8 | 8.1–8.3 Packaging | Not started | `scripts/`, `mkdocs.yml` |
| 9 | 9.1–9.3 Hardening + release | Not started | |

Acceptance gate snapshot: `ruff check` clean, `ruff format` clean,
`mypy --strict src` clean (8 source files), `pytest` 51 passed, crypto
module at 99% coverage.

## 15. v1 → v2 roadmap

Kept intentionally forward-compatible — the vault file format stays at
`format_version: 1` through v2 where possible, so v1 vaults migrate by
adding fields, not rewriting:

- **Device enrollment & sync.** Each device gets its own `local_half` and
  its own wrapped DEK entry in the vault. Revoking a device just removes
  its wrapped DEK — vault stays encrypted under the same DEK for
  everyone else.
- **Split-key server.** `server_half` transitions from "all zeros
  placeholder" to a real value fetched post-authentication. Vault file
  format identical; only the source of one input changes.
- **Deployment auto-updaters.** Vercel, GitHub Actions, AWS Secrets
  Manager, Netlify, Heroku. New `DeploymentUpdater` ABC parallel to
  `Provider`.
- **Browser extension.** Chromium + Firefox, native messaging bridge
  into the core library.
- **GUI.** Tauri or PyQt6, TBD.
- **More providers.** GitHub, AWS IAM, Google Cloud, Azure.
- **Storage migration.** JSON → SQLCipher via a one-shot
  `keyguard migrate-to-sqlite` command. JSON remains readable as an
  import source indefinitely.

## 16. Glossary

- **AAD** — Associated Authenticated Data. Part of AES-GCM: bytes that
  aren't encrypted but are bound to the ciphertext by the auth tag. Used
  here to bind vault metadata (version, salts) so an attacker can't swap
  them without breaking the tag.
- **AES-256-GCM** — AES in Galois/Counter Mode with a 256-bit key.
  Provides confidentiality + integrity (auth tag) in one pass.
- **Argon2id** — Memory-hard password hashing function, winner of the
  Password Hashing Competition. The `id` variant combines Argon2i (side-
  channel-resistant) and Argon2d (GPU-resistant).
- **DEK** — Data Encryption Key. The 32-byte key that actually encrypts
  the vault body. Stable for the life of the vault.
- **Envelope encryption** — The two-layer pattern: DEK encrypts data,
  KEK(s) encrypt the DEK. Makes password changes / device add+remove
  fast because the data layer doesn't re-encrypt.
- **Fingerprint** — SHA-256 hash of a key value, stored alongside the
  vault **outside** the encrypted body so the scanner can check for
  matches without unlocking.
- **HKDF-SHA256** — HMAC-based Key Derivation Function. Used here for
  domain-separating KEK input components so they can't be spliced.
- **KEK** — Key Encryption Key. Wraps (encrypts) the DEK. Derived from
  what you know (password) + what you have (keychain, recovery code,
  server half). Multiple KEKs per DEK = multiple unlock paths.
- **local_half** — A 32-byte random value stored in the OS keychain on
  each device. Contributes to `KEK_primary` so copying the vault file
  alone is useless — you also need the keychain entry.
- **recovery_code** — 160 bits shown once at `init`. Derives a second KEK
  that can unlock the vault if you lose your password.
- **server_half** — A 32-byte value that will (in v2) be fetched from a
  split-key server post-authentication. In v1 it's all zeros.
- **SecretStr** — Pydantic type that wraps a string/bytes, redacts it in
  `repr`/`str`, and prevents accidental serialization. Used for every
  credential-bearing field in the vault models.
- **TOTP** — Time-based One-Time Password (RFC 6238). The 6-digit rolling
  codes from Google Authenticator / Authy / 1Password. Required on every
  vault unlock.
- **wrapped_dek** — The DEK after being encrypted under a KEK. Stored in
  the vault file in cleartext — useless without the KEK that wrapped it.
