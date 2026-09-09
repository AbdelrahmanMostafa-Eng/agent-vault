# Agent-Vault

**Agent-Vault is a local-first, encrypted memory layer for AI agents.** It gives Manus, Cursor, local LLM workflows, and developer scripts a shared project context so a new session can begin from the current state instead of starting from scratch.

## Problem / Solution

AI-agent sessions are productive but ephemeral. Architecture decisions, constraints, facts, and follow-up work are often trapped in one chat transcript. The next agent or new session then repeats discovery, makes inconsistent assumptions, or loses the rationale behind existing code.

Agent-Vault solves this with a deterministic Python CLI and a project-local SQLite repository. Agents record durable memories once, and any compatible tool can fetch a versioned JSON project state. Memory payloads are authenticated and encrypted at rest with a private key kept outside the database, without requiring a hosted service or network connection.

## Technical Architecture

The implementation is intentionally modular:

| Component | Responsibility |
| --- | --- |
| `cli` | Parses commands, validates arguments, emits safe machine-readable JSON, and maps operational failures to exit code `1`. Malformed usage returns exit code `2`. |
| `models` | Defines the `Memory` and `ProjectState` domain objects and their JSON serialization contract. |
| `validation` | Centralizes input, timestamp, path, archive, and schema validation. Symlinks and unsafe restore parents are rejected. |
| `crypto` | Creates private Fernet keys, validates key permissions, encrypts payloads, decrypts authenticated ciphertext, and derives keyed metadata tokens. |
| `storage` | Owns SQLite schema creation, migrations, transactions, metadata indexing, secure filesystem permissions, and persistence. |
| `lifecycle` | Implements repository status, verification, migration, backup, restore, and key rotation. |

A repository is created under the project root:

```text
.agentvault/
├── context.db       # SQLite metadata, encrypted memory payloads, and keyed indexes
├── context.db-wal   # SQLite WAL file while active; ignored by Git
├── context.db-shm   # SQLite shared-memory file while active; ignored by Git
└── context.key      # Fernet key, mode 0600; required for decryption
```

Memory content, tags, kinds, sources, and sensitivity values are not stored in plaintext. Equality filtering uses keyed HMAC-SHA-256 tokens for kind and tags; the encrypted payload remains the source of truth. See [`ARCHITECTURE.md`](ARCHITECTURE.md) and [`docs/memory-schema.md`](docs/memory-schema.md).

## Installation

Agent-Vault requires **Python 3.10 or newer**. Install it in an isolated environment from a checkout:

```bash
git clone https://github.com/AbdelrahmanMostafa-Eng/agent-vault.git
cd agent-vault
python3 -m venv .venv
. .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -e '.[dev]'
```

For runtime-only installation, use `python -m pip install .`. The development extra adds pytest, coverage, Ruff, mypy, build, and pip-audit.

## Quick Start

Initialize the current project with a stable human-readable name:

```bash
agent-vault init . --name "Checkout Service"
```

Record decisions, facts, constraints, todos, and notes. Direct arguments are convenient for non-sensitive content:

```bash
agent-vault record "Use SQLite for the local memory store" --kind decision --tag storage
agent-vault record "The service must remain offline-capable" --kind constraint --tag architecture
agent-vault record "Add a migration command before the production release" --kind todo --source planning.md
```

For sensitive content, avoid shell history and process arguments by using standard input or a file:

```bash
printf '%s\n' 'The recovery key is held by the operations owner.' | agent-vault record --stdin --kind fact --sensitivity private
agent-vault record --file private-note.txt --kind note --sensitivity secret
```

Fetch the shared state as JSON for another agent or integration:

```bash
agent-vault fetch . --pretty
agent-vault fetch . --kind decision --limit 20
agent-vault fetch . --tag architecture --offset 20 --limit 20
```

The output is a stable JSON envelope, suitable for piping to a local LLM, plugin, or script. `--limit` and `--offset` provide deterministic offset pagination over the created-at/id ordering; `--offset` must be non-negative. The interoperability contract is documented in [`docs/memory-schema.md`](docs/memory-schema.md).

## CLI Reference

### Core commands

| Command | Purpose | Important options |
| --- | --- | --- |
| `agent-vault init [PATH]` | Create a new encrypted repository transactionally. | `--name NAME` |
| `agent-vault record [CONTENT]` | Validate, encrypt, and store one memory. | `--stdin`, `--file FILE`, `--kind`, `--tag`, `--source`, `--sensitivity`, `--path` |
| `agent-vault fetch [PATH]` | Return project metadata and decrypted memories as JSON. | `--kind`, `--tag`, `--limit`, `--pretty` |

Exactly one content source is required for `record`: positional content, `--stdin`, or `--file`. The supported kinds are `decision`, `fact`, `constraint`, `todo`, and `note`. Supported sensitivity levels are `normal`, `private`, and `secret`.

### Lifecycle commands

| Command | Purpose | Safety behavior |
| --- | --- | --- |
| `agent-vault status [PATH]` | Show initialization, schema, and count metadata without decrypting memories. | Does not print memory content or keys. |
| `agent-vault verify [PATH]` | Validate key permissions, schema, SQLite integrity, metadata, timestamps, symlink safety, and every encrypted payload. | Fails closed on corruption or unsupported schema. |
| `agent-vault migrate [PATH]` | Upgrade a supported older database schema transactionally. | Preserves encrypted payloads and commits only after successful decoding and indexing. |
| `agent-vault backup ARCHIVE --path PATH` | Create a consistent ZIP backup containing the database and key. | Takes a snapshot-consistent read while using a shared advisory lock, checkpoints and removes SQLite sidecars, and writes fixed, size-limited archive members with mode `0600`. |
| `agent-vault restore ARCHIVE --path PATH` | Validate and atomically install a backup. | Performs staged validation of archive names, sizes, permissions, key, schema, integrity, and every payload before installation; rejects path traversal, symlinks, malformed archives, invalid keys, bad integrity, and non-current schemas. Use `--force` to replace an existing repository. |
| `agent-vault rotate-key [PATH]` | Re-encrypt all payloads with a newly generated key. | Uses an exclusive advisory lock and a durable prepared/committed journal; interrupted rotations are recovered before repository access, and original payloads remain recoverable on failure. |

All successful commands emit JSON. Normal operational failures print a concise `agent-vault: error: ...` message to standard error and return `1`; malformed command usage returns `2`. No normal error path prints a traceback, key, decrypted memory, or ciphertext.

## Privacy and Security Model

Agent-vault is designed for a **single trusted local user**. The threat model protects memory content and key material from accidental plaintext storage, ordinary repository inspection, Git commits, unsafe archive extraction, and common symlink/path attacks. It does not provide protection from a user or process that already has equivalent privileges on the host, from a compromised Python runtime, or from an attacker who can read the process memory of a running agent.

The database stores encrypted memory payloads. The separate key file is mode `0600`, the `.agentvault` directory is mode `0700`, and the SQLite database is mode `0600`. Repository files are rejected when they are symlinks. SQLite uses parameterized statements, a busy timeout, WAL mode, foreign keys, and explicit transaction boundaries. Lifecycle mutations use an exclusive advisory lock; backup readers use a shared lock, while SQLite WAL checkpointing is completed before database files are moved or archived.

The key is the recovery boundary. If `context.key` is deleted or lost, encrypted memories cannot be recovered from the database alone. Back up the archive and key through an approved private channel. A backup contains the key by design and must be protected accordingly. Agent-Vault does not send data over the network or manage remote key escrow.

Direct `record CONTENT` arguments may still be visible in shell history or process inspection. Use `--stdin` or `--file` for sensitive material; the file is read, validated, encrypted, and not copied into an Agent-Vault temporary file.

## Backup and Recovery

Create a verified backup before migrations, key rotation, or moving a repository:

```bash
agent-vault verify .
agent-vault backup agent-vault-backup.zip --path .
```

Restore into a new project directory:

```bash
mkdir recovered-project
agent-vault restore agent-vault-backup.zip --path recovered-project
agent-vault verify recovered-project
```

Restoring over an existing repository requires `--force`. Never delete the original repository until the restored copy has been verified and the key has been recovered through an independent channel.

## Repository Structure

```text
agent-vault/
├── .github/workflows/ci.yml
├── docs/memory-schema.md
├── src/agent_vault/
│   ├── cli.py
│   ├── crypto.py
│   ├── lifecycle.py
│   ├── models.py
│   ├── storage.py
│   └── validation.py
├── tests/test_agent_vault.py
├── ARCHITECTURE.md
├── CHANGELOG.md
├── CONTRIBUTING.md
├── LICENSE
├── pyproject.toml
└── README.md
```

Runtime repositories, keys, SQLite WAL files, caches, distributions, and temporary archives are ignored by Git. Do not commit `.agentvault/` or a backup archive containing `context.key`.

## Development and Verification

From an activated development environment, run the same gates used by CI:

```bash
ruff format --check src tests
ruff check src tests
mypy src
pytest --cov=agent_vault --cov-report=term-missing
python -m build --outdir dist
pip-audit
```

The test suite covers unit behavior, encrypted SQLite persistence, migrations, filtering and ordering, corruption, backup/restore, key rotation, secure input modes, path attacks, subprocess CLI behavior, and packaging entry points. CI tests Python 3.10 through 3.13, enforces at least 98% line coverage, builds wheel and source distributions, and audits dependencies.

## Troubleshooting

**`Agent-Vault is already initialized`** means the target already contains `.agentvault/`. Use `status` or `verify`; do not delete the directory unless you have a verified backup.

**`repository is incomplete`** means the database or key is missing. Restore both from a trusted backup, or reinitialize only if the old encrypted memories are intentionally disposable.

**`key permissions are too broad`** means the key is readable by group or other users. Restrict it to mode `0600` and rerun `verify`.

**`Unable to decrypt memory payload`** or a corruption error means the key, database, or ciphertext is inconsistent. Stop writes, preserve the original files, and recover from a verified backup. Do not attempt to repair ciphertext manually.

**`Backup must be migrated before restore`** means the archive was created from an older supported schema. Run `agent-vault migrate` on the source repository, create a new backup, and restore that new archive.

## Project Status and Limitations

Agent-Vault 1.0.0 is a production-ready local component, not a hosted synchronization service. It deliberately does not implement remote synchronization, conflict resolution, multi-user key management, access-control lists, cloud key escrow, or cross-machine replication. Plugins and agents must exchange the documented JSON state through their own local integration boundary.

See [`CONTRIBUTING.md`](CONTRIBUTING.md) for development and release expectations, and [`CHANGELOG.md`](CHANGELOG.md) for release history.
