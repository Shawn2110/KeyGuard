# KeyGuard — Architecture

## 1. Guiding principles

1. **Core as a library, CLI as a thin wrapper.** The CLI is one frontend among several (future GUI, browser extension, server). The core library must never import from `cli/`.
2. **Plugins for anything that has N implementations.** Providers (OpenAI, Stripe, ...) and deployment platforms (Vercel, GitHub Actions, ...) are plugins behind abstract base classes. Adding a new one should not touch any other code.
3. **Explicit trust boundaries.** Every component declares what it trusts as input and what it produces as output. Secrets never cross a boundary in plaintext except when strictly necessary (e.g., calling a provider API).
4. **Fail closed.** If decryption fails, if a rotation partial-fails, if the keychain is unavailable — the tool stops and reports. It never proceeds "best effort" with secrets.

## 2. High-level component map

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

## 3. Directory structure

```
keyguard/
├── pyproject.toml
├── README.md
├── docs/
│   ├── PRD.md
│   ├── ARCHITECTURE.md       (this file)
│   ├── PLAN.md
│   ├── AGENT.md
│   └── THREAT_MODEL.md       (to be written by Claude Code in task 1)
├── src/
│   └── keyguard/
│       ├── __init__.py
│       ├── core/
│       │   ├── __init__.py
│       │   ├── crypto.py           # Argon2id, AES-GCM, HKDF wrappers
│       │   ├── vault.py            # Vault file I/O, encryption envelope
│       │   ├── session.py          # Unlock lifecycle, auto-lock timer
│       │   ├── models.py           # Pydantic models: Key, KeyVersion, etc.
│       │   ├── keychain.py         # keyring wrapper with typed API
│       │   ├── totp.py             # TOTP generation, QR, verification
│       │   ├── audit.py            # Access log, append-only
│       │   ├── scanner/
│       │   │   ├── __init__.py
│       │   │   ├── gitleaks.py     # Subprocess wrapper around gitleaks
│       │   │   ├── fileshunt.py    # Find .env-like files on filesystem
│       │   │   └── matcher.py      # Cross-reference findings with vault
│       │   ├── providers/
│       │   │   ├── __init__.py
│       │   │   ├── base.py         # Provider ABC
│       │   │   ├── openai.py
│       │   │   ├── anthropic.py
│       │   │   ├── stripe.py
│       │   │   └── registry.py     # Dynamic provider discovery
│       │   ├── deployments.py      # Deployment model + placeholder for v2 updaters
│       │   └── errors.py           # Custom exception hierarchy
│       └── cli/
│           ├── __init__.py
│           ├── main.py             # click entry point
│           ├── commands/
│           │   ├── __init__.py
│           │   ├── init.py
│           │   ├── add.py
│           │   ├── list_cmd.py     # Avoid shadowing builtin `list`
│           │   ├── show.py
│           │   ├── copy.py
│           │   ├── scan.py
│           │   ├── rotate.py
│           │   └── hooks.py        # install-hooks
│           └── ui.py               # rich formatting helpers
├── tests/
│   ├── unit/
│   │   ├── test_crypto.py
│   │   ├── test_vault.py
│   │   ├── test_totp.py
│   │   ├── test_scanner.py
│   │   └── test_providers/
│   ├── integration/
│   │   ├── test_end_to_end.py
│   │   └── test_rotation_flow.py
│   └── fixtures/
├── vendor/
│   └── gitleaks/                   # Bundled gitleaks binary per platform
└── scripts/
    └── package_binaries.py         # Downloads/verifies gitleaks for packaging
```

## 4. Cryptographic architecture

### 4.1 Envelope encryption (two-layer)

The vault uses a standard envelope-encryption pattern. This matters because it makes password changes, device additions, and recovery-code flows tractable without re-encrypting the vault body.

```
Layer 1 — Data Encryption Key (DEK):
    DEK = 32 random bytes, generated once at vault creation, never changes
          (unless user explicitly rotates the vault master key).
    Vault body ciphertext = AES-256-GCM(DEK, serialized vault plaintext)

Layer 2 — Key Encryption Keys (KEKs):
    Each KEK wraps a copy of the DEK. Different KEKs for different unlock paths.

    KEK_primary  = Argon2id(password || local_half || server_half, salt_primary)
    KEK_recovery = Argon2id(password || recovery_code,             salt_recovery)

    Wrapped DEKs stored in the vault file:
        wrapped_dek_primary  = AES-256-GCM(KEK_primary,  DEK)
        wrapped_dek_recovery = AES-256-GCM(KEK_recovery, DEK)
```

**Why two layers?**

- Changing the password only re-derives KEK_primary and re-wraps the DEK. The vault body is untouched. Fast.
- Adding a device (v2) just creates a new KEK from that device's inputs and adds another wrapped DEK entry.
- Losing a device (v2) revokes its wrapped DEK entry. The vault stays encrypted under the same DEK for all other devices.
- The recovery code is structurally equivalent to another device — its own KEK, its own wrapped DEK.

### 4.2 Key derivation inputs

For v1:

- `password` — user's master password, UTF-8 encoded. Typed fresh on every unlock.
- `local_half` — 32 random bytes generated at `init`, stored in OS keychain via `keyring`. Never transmitted.
- `server_half` — in v1, a hardcoded placeholder (all zeros). In v2, fetched from the split-key server post-authentication. This is a deliberate stub so v2 activation doesn't break v1 vaults: the vault format is identical; only the source of `server_half` changes.
- `recovery_code` — 20 random bytes, base32-encoded as 32 chars with dashes for display. Generated at `init`, shown once, never stored anywhere by KeyGuard.
- `salt_primary`, `salt_recovery` — 16 random bytes each, stored in the vault file in cleartext.

### 4.3 Argon2id parameters

Fixed at:

- `time_cost = 3`
- `memory_cost = 65536` (64 MiB)
- `parallelism = 4`
- `hash_len = 32`

These are above OWASP 2024 minimums and produce roughly 1-second derivation times on typical 2020+ hardware. Unlocking is interactive, so this is acceptable.

### 4.4 AES-GCM usage

- Key size: 256 bits.
- Nonce: 12 random bytes per encryption operation. Never reuse a (key, nonce) pair. Since we generate a fresh nonce per encrypt and the DEK is stable, birthday bounds are fine (2^32 messages per key before rotation is recommended).
- Associated data: the vault file's version field and salt. This binds metadata to the ciphertext so an attacker can't swap metadata without invalidating the tag.
- Tag size: 128 bits (AES-GCM default, non-negotiable).

### 4.5 HKDF for domain separation (v2)

When the server is introduced, the **password sent for authentication** and the **password used to derive KEK_primary** must not be the same bytes. Use HKDF-SHA256 with different `info` strings:

```
auth_hash_input = HKDF(password, salt=email, info=b"keyguard-auth-v1",    length=32)
kek_input       = HKDF(password, salt=email, info=b"keyguard-encrypt-v1", length=32)
```

The server stores `Argon2id(auth_hash_input)`. The server never sees anything that would let it derive KEK_primary.

## 5. Vault file format

On-disk structure (JSON, pretty-printed):

```json
{
  "format_version": 1,
  "created_at": "2026-04-18T12:00:00Z",
  "kdf": {
    "algorithm": "argon2id",
    "time_cost": 3,
    "memory_cost": 65536,
    "parallelism": 4
  },
  "wrapped_deks": [
    {
      "id": "primary",
      "salt":       "<base64>",
      "nonce":      "<base64>",
      "ciphertext": "<base64>"
    },
    {
      "id": "recovery",
      "salt":       "<base64>",
      "nonce":      "<base64>",
      "ciphertext": "<base64>"
    }
  ],
  "body": {
    "nonce":      "<base64>",
    "ciphertext": "<base64>",
    "associated_data": "<base64>"
  }
}
```

The decrypted `body` contains the serialized Pydantic model hierarchy described in section 7.

**Atomic writes:** always write to `<path>.tmp` first, then `os.replace()` to the final path. This prevents a half-written vault on crash.

**Backups:** on every save, copy the previous vault file to `<path>.bak` before overwriting. Keep the last 3 backups. This has saved more vaults than any cryptographic feature.

## 6. Component responsibilities

### 6.1 `core/crypto.py`

Pure functions. No file I/O, no state. Wraps `cryptography` and `argon2-cffi`.

Exposed API:

- `derive_kek(password: str, extra_inputs: bytes, salt: bytes) -> bytes`
- `generate_dek() -> bytes`
- `wrap_dek(kek: bytes, dek: bytes) -> WrappedDEK`
- `unwrap_dek(kek: bytes, wrapped: WrappedDEK) -> bytes`
- `encrypt_body(dek: bytes, plaintext: bytes, aad: bytes) -> EncryptedBody`
- `decrypt_body(dek: bytes, body: EncryptedBody, aad: bytes) -> bytes`
- `generate_salt() -> bytes`
- `generate_recovery_code() -> tuple[str, bytes]`  # (display_form, raw_bytes)

### 6.2 `core/vault.py`

Owns the vault file format. Reads and writes the JSON envelope. Calls into `crypto.py`.

Exposed API:

- `create_vault(path: Path, password: str, local_half: bytes, recovery_code: bytes) -> Vault`
- `open_vault(path: Path, password: str, local_half: bytes) -> UnlockedVault`
- `open_vault_with_recovery(path: Path, password: str, recovery_code: bytes) -> UnlockedVault`
- `UnlockedVault.save() -> None`  # atomic, preserves backups
- `UnlockedVault.rotate_password(new_password: str) -> None`

### 6.3 `core/session.py`

Manages the lifecycle of an unlocked vault: holds the in-memory DEK and decrypted state, handles auto-lock timer, clears secrets on lock.

Exposed API:

- `Session.unlock(vault_path, password, totp_code) -> Session`
- `Session.lock() -> None`
- `Session.add_key(...)`, `Session.rotate_key(...)`, etc. — all operations go through the session so auto-lock and audit logging are consistent.

### 6.4 `core/providers/base.py`

Abstract base class for any external key-issuing provider.

```python
class Provider(ABC):
    name: ClassVar[str]                     # "openai"
    display_name: ClassVar[str]             # "OpenAI"
    key_pattern: ClassVar[re.Pattern]       # For scanner matching

    @abstractmethod
    def create_key(self, existing_key: str, label: str) -> ProviderKey: ...

    @abstractmethod
    def revoke_key(self, existing_key: str, key_id_to_revoke: str) -> None: ...

    @abstractmethod
    def test_key(self, key: str) -> bool: ...

    @abstractmethod
    def list_keys(self, existing_key: str) -> list[ProviderKeyInfo]: ...
```

Each concrete provider (`openai.py`, etc.) implements this. A registry in `providers/registry.py` enumerates all subclasses.

### 6.5 `core/scanner/`

- `gitleaks.py` — subprocess wrapper. Locates the bundled binary, invokes it with a configured ruleset, parses JSON output.
- `fileshunt.py` — walks the filesystem for filenames matching `.env*`, `*credentials*`, `secrets.yml`, etc. Configurable allow/deny lists.
- `matcher.py` — given a list of findings (strings) and the current vault, computes SHA-256 fingerprints of findings and checks them against stored `KeyVersion.fingerprint` values. Produces a list of `Exposure` records linked to specific vault entries.

Crucially, the matcher operates on **fingerprints** (SHA-256 hashes of key values) that are stored alongside the vault outside the encrypted body — so the scanner can run fingerprint comparison without unlocking the vault. Only when the user wants to *see* which key is exposed does the vault need to be unlocked.

### 6.6 `cli/`

Thin. Each command:

1. Parses arguments via `click`.
2. Calls into core library.
3. Formats results via `rich`.

No business logic in the CLI layer. If you're tempted to write an `if` that changes behavior based on a flag, that logic belongs in core.

## 7. Data model (Pydantic v2)

See `src/keyguard/core/models.py`. Summarized:

- `Vault` — top-level container: `format_version`, `created_at`, `keys: list[Key]`, `access_log: list[AccessEvent]`, `settings: VaultSettings`.
- `Key` — one stored secret: `id`, `name`, `provider`, `tags`, `notes`, `versions: list[KeyVersion]`, `deployments: list[Deployment]`, `exposure_status`, `exposures: list[Exposure]`.
- `KeyVersion` — `version_number`, `value: SecretStr`, `created_at`, `revoked_at`, `rotation_reason`, `fingerprint`.
- `Deployment` — `id`, `platform`, `identifier`, `variable_name`, `added_at`, `last_verified_at`, `notes`.
- `Exposure` — `id`, `discovered_at`, `source_type`, `location`, `key_fingerprint`, `severity`, `status`, `resolved_at`, `resolved_by_rotation_of`.
- `AccessEvent` — `timestamp`, `event_type`, `key_id`, `details`, `device_fingerprint`.
- `VaultSettings` — clipboard timeout, auto-lock seconds, scanner defaults, etc.

All secret-bearing fields use `SecretStr`. Never log these. Custom JSON serializer raises if a `SecretStr` would be serialized outside an encrypted context.

## 8. Audit logging

Every sensitive operation appends an `AccessEvent` to `vault.access_log`. Events are:

- `VAULT_UNLOCKED`, `VAULT_LOCKED`, `VAULT_UNLOCK_FAILED`
- `KEY_ADDED`, `KEY_REVEALED`, `KEY_COPIED`, `KEY_EDITED`, `KEY_DELETED`
- `KEY_ROTATED` (with `from_version`, `to_version`, `reason`)
- `SCAN_RUN` (with `duration_ms`, `findings_count`)
- `EXPOSURE_DETECTED`, `EXPOSURE_ACKNOWLEDGED`, `EXPOSURE_RESOLVED`
- `DEPLOYMENT_ADDED`, `DEPLOYMENT_REMOVED`

Log entries are append-only. The vault writer refuses to save if `access_log` has shrunk between open and save.

## 9. Error handling

Custom exception hierarchy in `core/errors.py`:

```
KeyGuardError                           (base)
├── CryptoError                         (base for crypto failures)
│   ├── WrongPasswordError
│   ├── WrongRecoveryCodeError
│   ├── CorruptedVaultError             (GCM tag check failed)
│   └── UnsupportedVersionError
├── KeychainError
│   ├── KeychainUnavailableError
│   ├── LocalHalfMissingError           (first run on new machine, etc.)
│   └── LocalHalfAccessDeniedError
├── ProviderError                       (base for external API failures)
│   ├── ProviderAuthError               (existing key rejected)
│   ├── ProviderRateLimitError
│   └── ProviderUnavailableError
└── ScannerError
    ├── GitleaksNotFoundError
    └── ScanTimeoutError
```

CLI commands catch at the boundary and render friendly messages via `rich`. Core library never prints; it only raises.

## 10. v1 → v2 migration plan

- Vault file `format_version` stays 1 through v2 if possible. New fields are additive and optional.
- Storage migration to SQLCipher happens in v2 via a one-shot migration command: `keyguard migrate-to-sqlite`. The JSON format remains readable as an import source indefinitely.
- The `server_half` becomes a real value fetched from the server; the code path in `crypto.py` is unchanged.
- A new `Device` concept is introduced in v2; each device has its own `local_half` and its own wrapped DEK entry in the vault. v1 vaults are treated as "device 1" implicitly on first v2 launch.
- Provider integrations are purely additive.
- Deployment updaters (Vercel, GitHub Actions, etc.) slot in behind a new `DeploymentUpdater` ABC, parallel to `Provider`.

## 11. Testing strategy

- **Unit tests** (`pytest`) for every module in `core/`. Crypto module has property-based tests via `hypothesis`: "for any password and plaintext, encrypt-then-decrypt round-trips" and "any bit flip in ciphertext causes decryption to fail."
- **Integration tests** that exercise the full CLI → core → filesystem flow against a temporary vault.
- **Provider tests** mock HTTP via `respx`. No real API calls in CI except in a separate opt-in workflow that uses sandbox credentials.
- **Scanner tests** include a fixture repo with known-planted secrets and assert the scanner finds exactly those.
- **Coverage target**: 85% overall, 95% for `core/crypto.py` and `core/vault.py`.
