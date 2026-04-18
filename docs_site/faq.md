# FAQ

## What if I lose my password?

Use `keyguard unlock --recovery` (or answer the recovery prompt) with
the 32-character recovery code shown at `init`. You did write it down,
right?

## What if I lose my password AND the recovery code?

The vault is unrecoverable by design. KeyGuard has no copies of either
credential. This is not a bug, it's the feature — a provider or thief
can't coerce your vault open either.

## Can I use this with a YubiKey / hardware token?

Not in v1. Planned for v2. For now, pairing KeyGuard with full-disk
encryption + TOTP on a separate device is the strongest setup.

## What's the `server_half` field in the vault file?

A placeholder for v2 split-key sync. In v1 it's all zeros and adds no
security — but keeping the field reserved means v1 vaults can migrate
to v2 without a format break.

## Why is scan finding things I know are already in the vault?

A finding is only "confirmed leaked" when its fingerprint matches a
known `KeyVersion.fingerprint`. If scan flags something that's in
your vault, that value has ended up somewhere it shouldn't — e.g. a
committed `.env` file. Rotate it.

## Is the pre-commit hook a replacement for secret scanning in CI?

No. It's a fast first line. Run `keyguard scan` in CI too.
