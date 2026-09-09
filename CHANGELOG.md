# Changelog

All notable changes to Agent-Vault are documented here.

## [1.0.0] - 2026-09-09

Agent-Vault is promoted from alpha to a production-ready local component. The public JSON envelope remains compatible at version `1.0`; the internal SQLite schema is version `1.1`.

### Added

- `status`, `verify`, `migrate`, `backup`, `restore`, and `rotate-key` lifecycle commands.
- Transactional initialization with temporary-directory cleanup and duplicate-initialization protection.
- Authenticated Fernet encryption for complete memory payloads, with restrictive key and storage permissions.
- Keyed HMAC metadata tokens for private kind and tag filtering without plaintext metadata indexes.
- Secure `--stdin` and `--file` recording modes for avoiding shell-history and process-argument exposure.
- Path, symlink, archive-member, timestamp, metadata, content, tag, source, sensitivity, and schema validation.
- SQLite WAL mode, busy timeouts, foreign keys, explicit transaction boundaries, schema upgrades, and corruption checks.
- Atomic backup/restore workflows and transactional key rotation with rollback of updated payloads on key replacement failure.
- Strict mypy configuration, 95% coverage enforcement, Python 3.10–3.13 CI matrix, wheel/sdist build validation, and dependency auditing.
- Expanded unit, integration, subprocess, security, corruption, migration, recovery, and packaging-entrypoint tests.

### Changed

- Operational errors now return safe concise messages without tracebacks; malformed usage is separated with exit code `2`.
- Documentation now reflects the actual CLI, public schema, internal migration behavior, threat model, backup requirements, limitations, and release process.
- CI workflow is located at `.github/workflows/ci.yml` with least-privilege read-only repository permissions.

### Security notes

Backup archives include `context.key` because the database cannot be recovered without it. Treat backups as secrets and verify restored repositories before deleting the source. Agent-Vault remains a single-user local component and does not provide remote synchronization, multi-user access control, or cloud key escrow.

## [0.1.0] - 2026-08-16

### Added

- Initial local project initialization under `.agentvault/`.
- Encrypted SQLite-backed memory recording for decisions, facts, constraints, todos, and notes.
- Versioned JSON project-state retrieval with kind, tag, and limit filters.
- Initial interoperability schema and architecture documentation.
