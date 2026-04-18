# Error-message audit — Task 9.1

> Review every `raise` in `src/keyguard/cli/` and confirm each surfaced
> error tells the user exactly what went wrong and what to try next.
> Ran at 2026-04-18 against commit `a1097a1`.

## Methodology

1. `grep -rn "raise " src/keyguard/cli/` to enumerate every `raise`.
2. For each, trace back to the nearest `ui.print_error(...)` that
   renders the issue to the user, and read what the user will actually
   see.
3. For every CLI-user-observable error path, verify the message:
   - Names the specific thing that failed.
   - Tells the user what action to take (re-run with a flag, unset
     an option, run `keyguard init`, etc.).
   - Does not leak secret material or oracle-style auth feedback.

## Results

### `cli/_unlock.py`

- Missing vault: `"no vault at {path} — run `keyguard init` first, or pass --vault-path"` — names the file, tells the user what command to run. **Good.**
- Unlock failure: `"could not unlock vault — wrong password, wrong TOTP, or the vault file has been tampered with"` — intentionally ambiguous so we don't leak which factor failed. Audit-log entry still differentiates. **Good.**

### `cli/commands/init.py`

- Vault already exists: `"vault already exists at {path} — re-run with --force to overwrite"` — names the path, tells user the flag to add. **Good.**
- Password too short: `"password must be at least 12 characters"` — clear, enforces PLAN requirement. **Good.**
- Keychain write failure: `"could not write to OS keychain: {exc}"` — surfaces the underlying keyring error. **Good.**
- TOTP mismatch: `"TOTP code did not validate — aborting init"` + keychain cleanup rollback. **Good.**
- Recovery code mismatch: `"recovery code mismatch — aborting init to keep your data safe"` + keychain cleanup. **Good.**
- Vault creation failure: `"vault creation failed: {exc}"` + keychain rollback. **Good.**

### `cli/commands/add.py`

- Duplicate name: `"a key named {name!r} already exists in this vault"`. **Good.**
- Bad `--deployed-at` format: `raise click.BadParameter(...)` — click renders with built-in formatting. **Good.**

### `cli/commands/show.py`

- Missing key: `"no key named {name!r} in this vault"`. **Good.**

### `cli/commands/copy.py`

- Missing key: same as `show`.
- Clipboard unavailable: `"clipboard unavailable on this system: {exc}. Install xclip or xsel (Linux) or run under a desktop session."` — tells the user both what broke and what to install. **Good.**

### `cli/commands/scan.py`

- Gitleaks binary absent: prints a `ui.print_warning` and continues with fileshunt — not an abort. **Good.**
- Gitleaks subprocess error: same — warning + continue. **Good.**

### `cli/commands/rotate.py`

- Missing key: `"no key named {name!r}"`. **Good.**
- Missing provider plugin: `"no provider plugin registered for {key.provider!r}"`. **Good.**
- Provider `create_key` failure: `"provider create_key failed: {exc}"` — passes through the typed `ProviderError` subclass message. **Good.**
- New key fails `test_key`: `"new key failed verification — rolling back, old key stays active"`. **Good.**
- Provider `revoke_key` failure after create succeeded:
  `"provider revoke_key failed: {exc} — old key still active"` — explicitly tells the user the old key is untouched. **Good.**
- User declined deployments-updated confirmation: `ui.print_warning("old key NOT revoked; new version is stored but kept alongside")` — describes the in-between state. **Good.**

### `cli/commands/hooks.py`

- `git` not on PATH: `"git is not installed or not on PATH"`. **Good.**
- Any other wrapped error: `ui.print_error(str(exc))` + abort. **Good.**

### `cli/hook.py` (pre-commit shim)

- Match found: `"[KeyGuard] commit blocked — possible secret in staged diff:"` followed by redacted match and an escape hatch: `"bypass this commit with `git commit --no-verify` (use sparingly — the hook exists because this is usually a bug)."`. **Good.**

## Findings

Every user-facing error path is covered. Nothing in the CLI raises a
generic `Exception` or `RuntimeError` to the user; core-library
exceptions all descend from `KeyGuardError` and are formatted at the
CLI boundary.

No follow-up fixes required.

## Standing invariants (will trip CI via `bandit` or `ruff` if violated)

- CLI commands catch `KeyGuardError` at the boundary, never import
  internal library exceptions just to silently swallow them.
- No f-string contains `.get_secret_value()` except in `show --reveal`
  and `copy`, which explicitly record `KEY_REVEALED` / `KEY_COPIED`
  audit events.
- No `print()` calls in `core/` — verified by grep.
