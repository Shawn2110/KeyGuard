# KeyGuard

> Local-first encrypted vault for API keys. Built-in leak scanner.
> One-command provider rotation. Everything happens on your machine.

KeyGuard closes the loop that existing tools leave open. Password
managers store secrets but don't help you recover when one leaks.
Secret scanners detect leaks but don't help you fix them. KeyGuard
does both — **detect the leak, identify which of your keys it is,
rotate it with the provider, and walk you through updating every
place it was deployed** — in one tool.

---

## The 30-second pitch

```console
$ pipx install keyguard
$ keyguard init                           # password + TOTP + recovery code
$ keyguard add STRIPE --provider stripe   # store a secret
$ keyguard scan .                         # find leaks across git + filesystem
$ keyguard rotate STRIPE                  # create new key, revoke old, update deployments
```

Every mutating operation requires a fresh password + TOTP unlock. The
vault is a single file you can back up with `cp`. There is no server,
no telemetry, no cloud dependency — until you explicitly opt into v2
split-key sync.

## Features (v1)

| | |
|---|---|
| **Encrypted vault** | AES-256-GCM body, Argon2id-derived KEKs, envelope encryption |
| **Two unlock paths** | Password + keychain `local_half` (primary) **or** password + 20-byte recovery code |
| **TOTP second factor** | Required on every unlock; provisioned at `init` via QR |
| **Scanner** | Bundled `gitleaks` for git history + filesystem hunt for `.env`-like files, cross-referenced against vault fingerprints (HMAC-SHA256) |
| **Provider rotation** | OpenAI, Anthropic, Stripe — create new, verify, walk through deployments, revoke old, rollback on failure |
| **Pre-commit hook** | Global git hook blocks commits containing known provider key patterns |
| **Audit log** | Append-only, inside the encrypted body; every reveal/copy/rotation recorded |
| **Atomic writes + backups** | `.tmp` + `os.replace` + three rolling backups |

## Install

```console
pipx install keyguard
```

Python 3.11+ required. Works on macOS, Linux, Windows.

## How it protects your keys

KeyGuard uses **envelope encryption**. A stable 32-byte Data Encryption
Key (DEK) encrypts the vault body. The DEK is wrapped twice:

- **Primary KEK** ← Argon2id(HKDF(password) ‖ HKDF(local_half) ‖ HKDF(server_half), salt)
- **Recovery KEK** ← Argon2id(HKDF(password) ‖ HKDF(recovery_code), salt)

The HKDF-per-input step (Option B) prevents splicing — an attacker
can't shift bytes between the password, the keychain entry, and the
server half to forge a valid preimage.

Argon2id parameters are fixed at `t=3, m=64 MiB, p=4, hash_len=32`
(above OWASP 2024 minimums). AES-GCM uses a 128-bit auth tag and
binds vault metadata (format version, KDF params, wrapped DEKs) to
the body via a SHA-256-of-canonical-JSON AAD.

Full threat model: [`docs/THREAT_MODEL.md`](docs/THREAT_MODEL.md).
Full crypto architecture: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

## CLI

| Command | What it does |
|---------|-------------|
| `keyguard init` | Create vault + keychain state on this machine |
| `keyguard add NAME --provider P` | Store a new secret (repeatable `--tag`, `--deployed-at`) |
| `keyguard list` | Filterable rich table of vault keys |
| `keyguard show NAME [--reveal]` | Metadata; optional value reveal |
| `keyguard copy NAME [--timeout N]` | Clipboard with auto-clear |
| `keyguard scan PATH [--format text\|json] [--no-git]` | Detect leaked secrets |
| `keyguard rotate NAME [--dry-run]` | Provider-backed rotation |
| `keyguard install-hooks [--uninstall]` | Global git pre-commit scanner |

Every command accepts `--vault-path` to override the default
(platform user-data dir + `vault.enc`).

## Project layout

```
docs/                          Design docs: PRD, ARCHITECTURE, PLAN, THREAT_MODEL, test + error audit reports
docs_site/                     Published user docs (mkdocs-material)
src/keyguard/
    core/                      Pure library — never imports from cli/
        crypto.py              Argon2id + AES-GCM + HKDF primitives
        vault.py               Atomic JSON envelope I/O + backups
        models.py              Pydantic data model + SecretStr guardrail
        session.py             Unlock/lock lifecycle + auto-lock timer
        keychain.py            OS keychain wrapper
        totp.py                TOTP + QR + verify
        audit.py               Append-only log helpers
        errors.py              Exception hierarchy
        scanner/               gitleaks wrapper, fileshunt, matcher
        providers/             Provider ABC + registry + openai/anthropic/stripe
    cli/                       Thin click layer over core
        main.py                Entry point
        ui.py                  Rich formatting
        hook.py                Pre-commit shim
        _unlock.py             Shared unlock helper
        commands/              One file per CLI command
scripts/                       Packaging helpers (gitleaks binary fetcher)
tests/
    unit/                      Per-module tests + Hypothesis properties
    integration/               End-to-end CLI journey
vendor/gitleaks/               Bundled binaries per platform (populated by scripts/package_binaries.py)
```

## Tech stack

Python 3.11+ · `uv` · `click` · `rich` · `questionary` ·
`cryptography` · `argon2-cffi` · `pyotp` · `qrcode` · `pydantic` v2 ·
`keyring` · `platformdirs` · `httpx` · `structlog` · `pyperclip` ·
`pytest` · `hypothesis` · `respx` · `ruff` · `mypy --strict` ·
`bandit` · `pip-audit` · `mkdocs-material` · bundled `gitleaks`.

## Status

Pre-alpha. All Milestones 0–9 tasks from [`docs/PLAN.md`](docs/PLAN.md)
are complete except 9.3 (release tag). **182 tests passing · 93%
coverage** (99% on `core/crypto.py` and `core/vault.py`).

Full test report: [`docs/TEST_REPORT.md`](docs/TEST_REPORT.md).
Error-message audit: [`docs/ERROR_MESSAGES_AUDIT.md`](docs/ERROR_MESSAGES_AUDIT.md).

## Development

```console
uv sync --all-extras
uv run pytest -q
uv run ruff check
uv run ruff format --check
uv run mypy --strict src
uv run bandit -r src
uv run pip-audit
```

`uv run pre-commit install` registers the local hooks.

### Windows + OneDrive

Two workarounds are baked into the repo / documented in memory for
developers on Windows under an OneDrive-synced path:

1. `pyproject.toml` pins `mypy` to a source build (`[tool.uv]
   no-binary-package = ["mypy"]`) because the mypyc-compiled wheel
   trips Windows Application Control on some machines.
2. Export `UV_PROJECT_ENVIRONMENT=$LOCALAPPDATA/uv/envs/keyguard`
   before `uv` commands so the virtualenv lives outside OneDrive's
   sync scope. OneDrive mid-sync locks on `.venv/` cause
   reproducible partial installs otherwise.

## Roadmap

**v1 (shipped):** local vault, TOTP, scanner, three providers,
pre-commit hook, CLI.

**v2 (planned):** split-key server for multi-device sync, automated
deployment updaters (Vercel / GitHub Actions / AWS Secrets Manager),
browser extension, GUI, YubiKey support, more providers.

See [`docs/PRD.md`](docs/PRD.md) §5 for the user-story-driven roadmap
and [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md) §10 for the v1→v2
migration plan.

## Security disclosure

See [`docs_site/security.md`](docs_site/security.md) — please do not
file public issues for security bugs.

## License

MIT
