# Agent-Vault Memory Schema

Agent-Vault emits a versioned JSON envelope from `agent-vault fetch`. The public schema is language-neutral and intentionally independent from the private SQLite implementation. Plugins should invoke the CLI and parse standard output rather than reading `.agentvault/context.db` directly.

## Current envelope

The current public envelope version is **`1.0`**:

```json
{
  "schema_version": "1.0",
  "project": {
    "project_id": "8c0c0b34-39e7-4f4f-9fb2-2e6e65d5a4d4",
    "name": "Checkout Service",
    "root_path": "/workspace/checkout-service",
    "created_at": "2026-08-16T10:15:00Z"
  },
  "memories": [
    {
      "id": "c4d937a9-1462-4d88-a4b1-699dd0ce2a4a",
      "kind": "decision",
      "content": "Use SQLite for local persistence.",
      "tags": ["storage", "architecture"],
      "source": "architecture.md",
      "sensitivity": "normal",
      "created_at": "2026-08-16T10:16:00Z"
    }
  ]
}
```

## Envelope fields

| Field | Type | Required | Contract |
| --- | --- | --- | --- |
| `schema_version` | string | yes | Current value is `1.0`. This is the public JSON contract version. |
| `project` | object | yes | Project metadata object described below. |
| `memories` | array | yes | Matching memories, ordered newest first by `created_at`, then by `id` for deterministic ties. |

### Project fields

| Field | Type | Required | Contract |
| --- | --- | --- | --- |
| `project.project_id` | UUID-like string | yes | Stable identifier generated during initialization. |
| `project.name` | string | yes | Non-empty validated human-readable project name. |
| `project.root_path` | string | yes | Absolute normalized project path. |
| `project.created_at` | ISO-8601 string | yes | Timestamp with an explicit timezone, normally rendered in UTC with `Z`. |

### Memory fields

| Field | Type | Required | Contract |
| --- | --- | --- | --- |
| `memories[].id` | string | yes | Stable unique memory identifier. New CLI records use UUIDs. |
| `memories[].kind` | enum | yes | `decision`, `fact`, `constraint`, `todo`, or `note`. |
| `memories[].content` | string | yes | Decrypted memory content for an authorized local consumer. Multiline UTF-8 content is supported. |
| `memories[].tags` | string array | yes | Deduplicated labels, normalized for equality filtering. |
| `memories[].source` | string or null | yes | Optional file, agent, or workflow origin. |
| `memories[].sensitivity` | enum | yes | `normal`, `private`, or `secret`. All values are encrypted regardless of this label. |
| `memories[].created_at` | ISO-8601 string | yes | Timestamp with an explicit timezone. |

Unknown fields should be preserved when a plugin can do so and ignored when they are not required for its operation. Required fields, enum values, and timestamps should be validated before a plugin acts on a memory.

## Compatibility and versioning

The public `schema_version` changes only when the JSON shape or semantics require a consumer-visible compatibility decision. Additive optional fields are preferred over breaking changes. Consumers should accept known versions, ignore unknown optional fields, and fail safely when they cannot interpret a required field or version.

The internal SQLite schema is separate from this public version. Agent-Vault 1.0.0 uses internal schema `1.1`, while the public envelope remains `1.0`. Internal migrations add keyed metadata indexes without changing the JSON contract or exposing plaintext content.

## Filters and ordering

The CLI supports `--kind`, `--tag`, and `--limit` filters. Filters are applied before the result envelope is emitted. The current implementation preserves the deterministic ordering contract even when timestamps tie. `--limit` must be a positive integer; omitted limits return all matching memories.

```bash
agent-vault fetch /path/to/project --kind decision --tag architecture --limit 20 --pretty
```

A plugin must treat the result as a complete document, not as a stream of independent rows. The command returns exit code `0` for success, `1` for operational errors such as a missing or corrupted repository, and `2` for malformed CLI usage.

## Writing memories through the CLI

The CLI is also the write interoperability boundary:

```bash
agent-vault record "Use SQLite for local persistence" \
  --kind decision --tag storage --source architecture.md

cat private-note.txt | agent-vault record --stdin \
  --kind note --sensitivity private
```

Exactly one content source is required: positional content, `--stdin`, or `--file`. Plugins should use `--stdin` or `--file` for sensitive content so it does not appear in shell history or process arguments.

## Migration behavior

Plugins do not need to migrate SQLite files. If an existing repository uses supported internal schema `1.0`, normal read/write operations invoke the same transactional upgrader used by `agent-vault migrate`. The upgrader decrypts and validates existing payloads, creates keyed kind/tag indexes, and commits only after all rows are processed. A failed migration returns a nonzero error and does not publish partial index state.

The explicit command is useful for operational workflows:

```bash
agent-vault migrate /path/to/project
agent-vault verify /path/to/project
```

Backups must be created from the current internal schema. If restore reports `Backup must be migrated before restore`, migrate the source repository and create a new backup.

## Security contract

The JSON envelope is decrypted output for a trusted local consumer. Do not transmit or persist `memories[].content` unless the consuming agent is authorized to see it. In the SQLite repository, memory content, tags, kinds, sources, and sensitivity are encrypted inside the payload. Equality-filter indexes use keyed HMAC tokens rather than plaintext values.

The key file is required to decrypt the payloads. Loss of `.agentvault/context.key` is equivalent to loss of the encrypted memory data. Backup archives include the key by design and must be treated as secrets.
