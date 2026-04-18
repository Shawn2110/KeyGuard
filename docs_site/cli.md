# CLI reference

All commands accept `--vault-path PATH` to override the default
(platform user-data dir + `vault.enc`).

| Command | What it does |
|---------|--------------|
| `keyguard init` | Create vault + keychain state on this machine |
| `keyguard add NAME --provider P [--tag T] [--deployed-at p/i/V]` | Store a new secret |
| `keyguard list [--provider P] [--tag T] [--exposed]` | Table of vault keys |
| `keyguard show NAME [--reveal]` | Metadata; optionally print the value |
| `keyguard copy NAME [--timeout N]` | Clipboard with auto-clear |
| `keyguard scan [PATH] [--format text\|json] [--no-git]` | Look for leaked secrets |
| `keyguard rotate NAME [--dry-run]` | Create new provider key, revoke old |
| `keyguard install-hooks [--uninstall]` | Global git pre-commit scanner |

Every mutating command prompts for the master password and a fresh
TOTP code. The wrong-credentials message is intentionally ambiguous so
the CLI doesn't tell an attacker which factor failed.
