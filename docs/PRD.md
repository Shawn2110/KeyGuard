# KeyGuard — Product Requirements (PRD)

## 1. Problem

Developers regularly leak API keys by accident. The most common paths are:

1. Committing `.env` files or hardcoded keys to public (or later-made-public) git repositories.
2. Pasting keys into chat tools, issue trackers, or Stack Overflow when asking for help.
3. Leaving keys in log files that get shipped to third-party log aggregators.
4. Embedding keys in screenshots or screen-shares.
5. Storing keys in plaintext in CI/CD configs and sharing them over email or Slack.

Existing password managers (1Password, Bitwarden, KeePassXC) store keys securely but do nothing about the *workflow* that causes leaks. Existing scanners (gitleaks, trufflehog) detect leaks but don't help you fix them. Nobody connects the dots: **detect the leak, identify which of your keys it is, rotate it, and update every place it was deployed** — all in one tool.

KeyGuard is that tool.

## 2. Target user

Primary: **individual developers and small teams (1–10 people)** who use 5–30 third-party API keys across 2–10 deployment targets (local dev, Vercel / Netlify / AWS / GitHub Actions). They have been burned once by a leak or know someone who has.

Non-target: large enterprises with dedicated security teams. They use HashiCorp Vault, AWS Secrets Manager, or similar. KeyGuard isn't trying to compete there.

## 3. Goals

- **Prevent** accidental commits of keys via a zero-config git pre-commit hook.
- **Detect** keys already exposed in git history, local files, and public GitHub.
- **Recover** from leaks with one-command rotation across supported providers.
- **Track** where each key is deployed so rotation isn't a scavenger hunt.
- **Protect** the vault with a split-key design so copying the file alone is useless.

## 4. Non-goals (v1 and v2)

- Not a general password manager. No web logins, no credit cards, no secure notes beyond brief metadata.
- Not a runtime secret-injection proxy. Keys are retrieved manually (or via CLI env injection in v2), not served via a live proxy. Doppler / Infisical own that niche.
- Not a team collaboration tool in v1. Single-user focus. Shared vaults are a v2 concern at earliest.
- Not a mobile app. Desktop CLI first, optional GUI and browser extension in v2.
- Not a cloud service in v1. Vault is fully local. v2 introduces optional sync with a split-key server.

## 5. User stories

Written as the user's actual mental model.

### v1 — core loop

- **As a developer**, I want to store my OpenAI, Stripe, and GitHub keys in one encrypted place so I stop having them in scattered `.env` files.
- **As a developer**, I want a git hook installed globally so I physically cannot commit a key to any repo, even ones I forget to configure.
- **As a developer**, I want to scan my laptop and find keys I've forgotten about in old projects, old commits, and stray config files.
- **As a developer**, when a key leaks, I want one command to rotate it with the provider and get a new working key — without needing to remember Stripe's dashboard URL.
- **As a developer**, I want to record where each key is deployed (Vercel project X, GitHub Actions for repo Y, local `.env` at path Z) so when I rotate, I have a checklist of places to update.
- **As a developer**, I want TOTP as a second factor on vault unlock so a stolen laptop with my disk password isn't a total disaster.

### v2 — automation and recovery

- **As a developer**, when I rotate a key, I want KeyGuard to automatically update Vercel / GitHub Actions / AWS Secrets Manager with the new value so I don't have to do it by hand.
- **As a developer**, I want a browser extension that warns me when I'm about to paste a real API key into Slack, a GitHub issue, or a public form.
- **As a small team**, we want to share a vault across 2–3 devices with end-to-end encryption (split-key server).
- **As a developer**, if I lose my laptop, I want to recover my vault on a new machine using a recovery code I stored at signup.

## 6. Key product principles

1. **The vault is a prerequisite, not the point.** Users pay attention because of the scanner and the rotation assistant, not because of yet another encrypted file format.
2. **Act on the user's behalf, don't just warn.** Every competitor stops at "we detected a leak." KeyGuard rotates it.
3. **Zero-config where possible.** `keyguard init` should set up hooks, vault, and TOTP without a config file. Users who want power come later.
4. **Fail closed, never silently.** If the scanner can't reach GitHub's API, say so. If rotation partially succeeds, show exactly which deployments were updated.
5. **Never trust the network for key material.** The vault's master key is never transmitted. Even in v2, the split-key design means the server alone cannot decrypt.

## 7. Success metrics (directional, not targets)

- **Activation:** % of users who complete `init` and add at least one key. Target: >80%.
- **Retention:** % of users still running `keyguard scan` at least weekly after 30 days.
- **Core value event:** first successful rotation. If users never rotate anything, the product isn't delivering its unique value.
- **Leakage caught:** number of commits blocked by the pre-commit hook per user per month. High numbers = product is working.

## 8. Scope boundaries

### v1 scope (in)

- Encrypted local vault with password + TOTP unlock.
- CRUD for keys: `add`, `list`, `show`, `copy`, `edit`, `delete`.
- Deployment tracking (free-form per-key).
- Scanner: git history + local filesystem, cross-referenced with vault fingerprints.
- Rotation for three providers end-to-end: **OpenAI, Anthropic, Stripe**.
- Pre-commit hook installer (bundled gitleaks binary).
- Recovery code at signup, usable for vault recovery on a new device.
- Access log (append-only, inside encrypted vault).

### v1 scope (out, deferred to v2)

- Server-side split-key sync / multi-device.
- Automated deployment updates to Vercel / GitHub Actions / AWS.
- Browser extension.
- GUI (CLI only in v1).
- Additional providers beyond the initial three.
- GitHub secret-scanning API integration.
- Public paste-site monitoring.

## 9. Constraints

- **Language:** Python 3.11+ throughout v1 and v2. No polyglot rewrites without a measured bottleneck.
- **Offline-first:** v1 must work with zero network access except for rotation calls.
- **Single-file vault:** the encrypted vault must be a single file the user can back up with `cp`.
- **No plaintext storage of secrets anywhere outside the vault**, including logs, temp files, or the recovery flow.
- **Crypto choices are fixed:** Argon2id, AES-256-GCM, HKDF. Do not negotiate these.

## 10. Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| User loses both password and recovery code | Medium | Total data loss | Make recovery code prominent at signup, force explicit confirmation, offer to email a reminder to export |
| Provider API changes break rotation | Medium | Feature breaks silently | Integration tests against sandbox APIs in CI; clear error surfacing in the CLI |
| Gitleaks false positives train users to ignore warnings | High | Hook gets disabled | Tune the ruleset; allow `keyguard` to maintain an allowlist the user builds over time |
| Performance on large repos/monorepos | Medium | Scanner becomes unusable | Scanner uses the compiled gitleaks binary; Python only does post-processing |
| Crypto misuse (nonce reuse, weak KDF params) | Low but severe | Catastrophic | Property-based tests; fixed KDF params; code review any crypto change |
| Malware on unlocked machine reads vault | High for targeted attacks | Vault compromised | Document honestly: no software-only scheme defeats this. Suggest YubiKey for users who need it. |
