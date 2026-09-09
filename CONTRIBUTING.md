# Contributing to Agent-Vault

Thank you for contributing. Agent-Vault prioritizes predictable local behavior, script-friendly JSON output, a stable interoperability contract, and conservative security boundaries.

## Development setup

Use Python 3.10 or newer in an isolated environment:

```bash
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

## Required checks

Run the same checks expected by CI before opening a pull request:

```bash
ruff format --check src tests
ruff check src tests
mypy src
pytest --cov=agent_vault --cov-report=term-missing
python -m build --outdir dist
pip-audit
```

The coverage gate is configured at **98% line coverage**. Tests should demonstrate behavior, not merely execute lines. Add unit tests for validation, models, and cryptography; integration tests for SQLite, migrations, filtering, corruption, backups, restore, and key rotation; and subprocess tests for CLI entry points and safe error behavior.

## Design expectations

Keep domain behavior independent from the CLI and SQLite implementation. Use small cohesive functions, explicit types, parameterized SQLite queries, context-managed connections, and stable domain exceptions. New commands should emit structured JSON on success, return `1` for operational failures, return `2` for malformed usage, and document their arguments in the README.

Treat the public JSON schema as compatibility-sensitive. Additive optional fields are preferred to breaking changes. Any change to [`docs/memory-schema.md`](docs/memory-schema.md) must include a compatibility explanation and regression tests.

Security-sensitive changes must explain key handling, failure behavior, and whether plaintext can appear in logs, process arguments, database files, backups, or temporary files. Do not weaken authenticated encryption, store plaintext search metadata, deserialize untrusted objects, or add network access to the core runtime without an architectural proposal.

Never commit `.agentvault/`, private keys, SQLite databases, backup archives, local virtual environments, build outputs, caches, or generated package metadata. The repository `.gitignore` contains defensive patterns, but contributors remain responsible for checking `git status` and inspecting the diff.

## Pull requests

A pull request should describe the problem, the chosen solution, compatibility impact, security implications, test evidence, and any remaining limitation. Keep changes focused and update documentation in the same change. If a feature changes operational recovery, include backup/restore or migration tests as appropriate.

## Release workflow

The release owner updates `__version__`, `pyproject.toml`, `CHANGELOG.md`, and any user-facing compatibility notes together. From a clean checkout, run all required checks, build both wheel and source distributions, inspect the artifacts, and verify `agent-vault --version`, `python -m agent_vault`, and lifecycle smoke tests. Releases are published from the `main` branch after the CI matrix and dependency audit pass.
