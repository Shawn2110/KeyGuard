# Quickstart

## Install

```console
pipx install keyguard
```

## Initialize

```console
keyguard init
```

Prompts for:

1. A master password (≥12 characters).
2. Scans a TOTP QR code with your authenticator app.
3. Shows a recovery code — write this down now, it is not shown again.
4. Offers to install the global git pre-commit hook.

## Daily use

```console
keyguard add STRIPE --provider stripe --tag prod --deployed-at vercel/acme/STRIPE_KEY
keyguard list
keyguard show STRIPE --reveal
keyguard copy STRIPE            # clipboard, auto-clears in 20 s
keyguard scan .                 # git history + filesystem
keyguard rotate STRIPE          # create → test → confirm deployments → revoke
```

Every mutating operation requires a fresh password + TOTP unlock.
