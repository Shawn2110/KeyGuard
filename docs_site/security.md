# Security disclosure

If you believe you've found a security issue in KeyGuard, please DO
NOT open a public GitHub issue. Instead, contact the maintainer
privately through a method of your choosing (email in the repo's
`CODEOWNERS` or repository profile).

We will acknowledge within 72 hours.

## What we consider a security issue

- Any path that causes a `SecretStr` to appear in logs, tracebacks,
  or a non-encrypted on-disk file.
- Any sequence of commands that causes the vault's GCM tag to verify
  against maliciously-swapped metadata (e.g. swapped `wrapped_deks`).
- Any flow that accepts a wrong password + wrong TOTP combination as
  a valid unlock.
- Any observed deviation from the crypto parameters pinned in
  [`docs/ARCHITECTURE.md`](https://github.com/Shawn2110/KeyGuard/blob/main/docs/ARCHITECTURE.md) §4.3.

## What we do not consider a security issue

- A fully-owned unlocked machine dumping KeyGuard's process memory.
  That is explicitly out of scope in
  [`docs/THREAT_MODEL.md`](https://github.com/Shawn2110/KeyGuard/blob/main/docs/THREAT_MODEL.md)
  §3.
- A user writing their password on a sticky note.
- False positives from gitleaks' ruleset — please file those upstream
  against `gitleaks/gitleaks`.
