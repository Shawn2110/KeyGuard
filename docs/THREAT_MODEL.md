# KeyGuard — Threat Model

> Written against ARCHITECTURE.md §4–§5 and the crypto implementation in
> `src/keyguard/core/crypto.py`. Updated as the design evolves. If this
> document and the code disagree, the code is authoritative and this
> document is stale — file an issue.

## 1. Assets

| Asset | Where it lives | Criticality | Persists? |
|---|---|---|---|
| **Vault file** (encrypted) | `platformdirs` default data dir, single JSON file | High (holds all keys ciphertext) | Yes, on disk |
| **Master password** | User's head | Critical | No — typed fresh every unlock |
| **`local_half`** (32 B random) | OS keychain | Critical (one of three KEK_primary inputs) | Yes, in keychain |
| **TOTP shared secret** | OS keychain | High | Yes, in keychain |
| **`fingerprint_key`** (32 B random) | OS keychain | Medium (scanner-matching integrity) | Yes, in keychain |
| **Recovery code** (160 bits) | User's offline backup | Critical | No — shown once, user writes it down |
| **`server_half`** (v1: all zeros) | Hardcoded placeholder | Low in v1 | n/a |
| **DEK** (32 B random) | In-memory only while unlocked | Critical | No — zeroized on lock |
| **KEK_primary / KEK_recovery** | In-memory only during derivation | Critical | No — GC'd after wrap/unwrap |
| **Decrypted vault body** (plaintext Pydantic tree) | In-memory only while unlocked | Critical | No — dropped on lock |

## 2. Adversaries considered

### 2.1 Opportunistic thief — laptop stolen, disk at rest

**Capabilities:** Physical access to powered-off device. Full-disk
encryption may or may not be enabled. No knowledge of the master
password, no access to the user's phone (TOTP), no access to the
recovery code.

**What they can achieve:**
- Read the vault file bytes (format_version, salts, wrapped DEK
  ciphertext, body ciphertext).
- **Cannot** derive `KEK_primary` without the password *and* the
  `local_half` from the OS keychain. On modern OSes with FileVault /
  BitLocker / encrypted home, they also can't read the keychain at all
  without the disk password.
- **Cannot** derive `KEK_recovery` without the password *and* the
  recovery code.
- Offline password guessing is throttled by Argon2id's 64 MiB / ~1s
  per attempt — billions of guesses take centuries on commodity GPUs.

**Mitigations in design:**
- Argon2id with locked high-memory parameters (ARCHITECTURE §4.3).
- Per-KEK salts stored in cleartext are fine — they're not secret.
- The `local_half` in the OS keychain means a "just the file" leak is
  useless.
- AES-GCM's 128-bit tag rules out undetected ciphertext manipulation.

**Residual risk:** If the user picks a weak password AND an attacker
somehow also gets the keychain entry (e.g., no full-disk encryption),
offline guessing becomes tractable. Mitigation: password complexity
minimum at `init`, and strongly recommend FDE.

### 2.2 Same-user malware — running as the user on an unlocked machine

**Capabilities:** Arbitrary code execution as the user while KeyGuard
may or may not be unlocked. Can read the vault file. Can call
`keyring` APIs (they look identical to KeyGuard's own calls). Can
observe the screen and keyboard.

**What they can achieve:**
- If KeyGuard is currently unlocked: dump the process memory and
  extract the DEK and decrypted body. **Game over.**
- If KeyGuard is locked but the user unlocks later: keylog the
  password, observe the TOTP code, wait for the session, dump memory.
- Read `local_half` from the keychain at any time (on macOS / Linux
  the keychain prompts; on Windows Credential Manager it typically
  doesn't).

**What they cannot achieve:**
- Decrypt a vault file on a *different* machine — they'd still need
  `local_half` from that other machine's keychain.
- Forge vault writes without the DEK (GCM tag catches tampering).

**Mitigations in design:**
- Auto-lock timer (5 min default) shrinks the window.
- No persistent plaintext copies of secrets anywhere else.
- `SecretStr` redaction prevents logs and tracebacks from leaking
  values, *even under the legitimate user's own logging*.

**Residual risk: severe.** No pure-software scheme defeats a fully
compromised client. Documented honestly; YubiKey-hardware-token
integration is a v2+ mitigation to explore.

### 2.3 Network attacker

**Capabilities:** Can intercept and modify any network traffic.

**In v1:** KeyGuard makes no network calls for the vault itself.
Only `keyguard rotate` and `keyguard scan --github` (v2) reach
external endpoints. Rotation calls go over TLS to the provider's
published endpoint using `httpx` defaults.

**What they can achieve:**
- Nothing against the vault itself in v1 — it never crosses the wire.
- Against rotation: a MITM that can break TLS could trick the user
  into revealing the existing API key. Standard TLS defeats casual
  MITM; attacks that break TLS (stolen CA keys, pinning bypass) are
  out of scope.

**Residual risk (v1):** Minimal for the vault. Rotation calls are
only as safe as the provider's TLS setup.

**v2 consideration:** Split-key server introduces network dependence.
Design will use HKDF to separate "auth hash" from "encrypt-KEK input"
(ARCHITECTURE §4.5) so the server can't derive `KEK_primary` even if
fully compromised.

### 2.4 Cloud-backup leak — vault file ends up in a Dropbox/iCloud/etc. breach

**Capabilities:** Attacker obtains the vault file through a backup
provider compromise. No keychain access, no password, no recovery
code.

**What they can achieve:**
- Same as §2.1 minus the keychain: even less power. They don't have
  `local_half`, so `KEK_primary` is unreachable. Recovery path
  requires the password plus the recovery code, neither of which are
  in a cloud backup (assuming the user didn't put the recovery code
  into iCloud Notes — see §2.5).
- Offline guess the password: bounded by Argon2id as in §2.1, and
  additionally useless without `local_half`.

**Mitigations:** `local_half` is NOT backed up to cloud. It's in the
OS keychain, which respectable backup providers exclude. The
`.gitignore` excludes `vault.enc` and its backups from accidental
commit.

**Residual risk:** Low. The split-key design (even with `server_half`
as zeros in v1) means the vault file alone is not sufficient.

### 2.5 Phishing / social engineering

**Capabilities:** Attacker convinces the user to type their password
into a fake prompt, or to paste their recovery code into a support-
desk-looking page.

**What they can achieve:**
- Capture the password. To unlock the real vault, still needs
  `local_half` + TOTP — so phishing alone doesn't win.
- Capture the recovery code. To unlock, still needs the password.
- Capture both. **Game over.**

**Mitigations:**
- `init` insists the recovery code is shown only once and makes the
  user retype it (friction discourages casual screenshots).
- Docs explicitly tell the user: KeyGuard will never ask for the
  recovery code outside an explicit "forgot password" flow they
  initiated.
- CLI is the only supported UI in v1 — no web surface to spoof.

**Residual risk:** Human factors. No software mitigation fully
addresses a determined social-engineering attack.

### 2.6 Vault-file tamper

**Capabilities:** An attacker with write access to the vault file
modifies its bytes.

**What they can achieve:**
- Break decryption: flipping any bit in body ciphertext, nonce, or
  associated-authenticated-data causes GCM tag check to fail and
  surfaces `CorruptedVaultError`. Same for wrapped-DEK entries.
- Denial of service (destroying the vault). Backups (3 generations)
  mitigate this.
- **Cannot** read or selectively modify plaintext.

**Mitigations:** AES-GCM auth tag + AAD binding (§4.4), atomic writes
with `.tmp`+`os.replace`, rolling backups.

### 2.7 Supply-chain — bundled gitleaks binary is malicious

**Capabilities:** Hypothetical attacker compromises our release
pipeline and ships a tampered gitleaks binary.

**Mitigations:**
- `scripts/package_binaries.py` downloads gitleaks from its upstream
  release URL and verifies a pinned SHA-256 before bundling.
- Binaries are committed to `vendor/gitleaks/` per platform, letting
  the user diff against upstream themselves.
- CI runs `pip-audit` on every PR for dependency CVEs.

**Residual risk:** Upstream gitleaks compromise. Not in our threat
model to defend against; documented in README.

## 3. Explicitly out of scope

These are **not** mitigated. If you face them, KeyGuard won't save you.

- **Fully-owned unlocked machine.** Any software-only scheme falls here.
- **Sophisticated state-level adversary.** Hardware side channels, TLS
  break-in with stolen CA keys, targeted zero-days — outside scope.
- **Side-channel attacks** (power, timing, acoustic, EM) against
  Argon2id / AES-GCM on the user's own CPU. We use constant-time
  comparisons where applicable (`hmac.compare_digest`) but do not
  claim side-channel resistance.
- **Provider-side breach.** If OpenAI / Anthropic / Stripe leaks keys
  from their side, KeyGuard can detect via scanner + rotation but
  cannot prevent.
- **User writes their password on a sticky note.** Out of scope.
- **User disables TOTP or uses `keyguard init --no-totp`** (not
  implemented, and won't be, because this is the precise mitigation
  against §2.1).

## 4. Defense-in-depth summary by asset

| Asset | Layer 1 | Layer 2 | Layer 3 |
|---|---|---|---|
| Vault file | AES-256-GCM | GCM auth tag + AAD | Atomic writes + 3 backups |
| DEK | Wrapped under KEK (AES-GCM) | In-memory only while unlocked | Zeroized on lock |
| KEK | Derived from 3 inputs (HKDF-each + Argon2id) | Salt per KEK, stored cleartext is fine | Never persisted |
| Password | User's head | ≥12-char minimum enforced | Never compared with `==`; never logged |
| TOTP secret | Keychain | Second factor required on unlock | Never logged |
| local_half | Keychain | 32 B entropy | Never transmitted |
| Recovery code | User's offline backup | 160 bits entropy | Shown once, never stored |
| Fingerprints | HMAC-SHA256 with keychain key | Not reversible | Stored outside encrypted body but useless without keychain access |

## 5. Invariants the code must preserve

Violation of any of these is a bug and a security issue:

1. `SecretStr.get_secret_value()` is only called inside the encrypted-
   context contextvar or in the CLI reveal/copy paths. Never from
   logging / error formatting / serialization.
2. No `random.random()` / `uuid1` / weak entropy sources anywhere in
   `core/`. Only `secrets.token_bytes()` / `os.urandom()`.
3. All byte comparisons of secret-adjacent values use
   `hmac.compare_digest()`. Never `==`.
4. `UnlockedVault.save()` always writes to `.tmp` first, then
   `os.replace`. Backups rotate before the replace.
5. `Session.save()` refuses to persist if the access-log length has
   shrunk since unlock.
6. Argon2id / AES-GCM / HKDF-SHA256 parameters match
   `src/keyguard/core/crypto.py` constants — do not special-case.
7. Body AAD is always the canonical-JSON SHA-256 of
   `{format_version, kdf, wrapped_deks}`. Changing this is a
   format-breaking change.

## 6. Open questions (reviewed each milestone)

- **Concurrent writers.** Two unlocked sessions on the same host.
  Current design catches this via monotonic access-log check at save;
  the later write fails. No OS-level file lock yet. Likely OK for a
  single-user v1 but a source of sharp-edge bugs — revisit if a daemon
  mode is introduced.
- **Recovery-code usability.** 32 base32 characters is long. Is it
  memorable enough to write down accurately? First-run UX testing
  needed.
- **Hardware tokens.** YubiKey / OpenPGP smartcard integration would
  strip a huge chunk of §2.2's residual risk. Slated for v2.
