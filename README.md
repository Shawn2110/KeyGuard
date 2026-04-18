# KeyGuard

Local-first encrypted vault for API keys with built-in leak scanner and one-command provider rotation.

See [`docs/`](docs/) for the PRD, architecture, threat model, and implementation plan.

## Status

Pre-alpha. Track milestone progress in [`docs/PLAN.md`](docs/PLAN.md).

## Development quickstart

    uv sync --all-extras
    uv run pytest
    uv run ruff check
    uv run mypy --strict src

## License

MIT
