"""Transactional SQLite persistence for encrypted Agent-Vault project context."""

from __future__ import annotations

import fcntl
import json
import os
import sqlite3
import stat
import uuid
from collections.abc import Iterator
from contextlib import contextmanager
from pathlib import Path

from .crypto import decrypt, encrypt, load_key, search_token
from .models import MEMORY_KINDS, Memory, ProjectState, utc_now
from .validation import (
    ValidationError,
    normalize_root,
    reject_symlink,
    validate_memory,
    validate_memory_dict,
    validate_project_name,
    validate_tags,
    validate_timestamp,
)

PUBLIC_SCHEMA_VERSION = "1.0"
DATABASE_SCHEMA_VERSION = "1.1"
DATABASE_FILENAME = "context.db"
KEY_FILENAME = "context.key"


class RepositoryError(RuntimeError):
    """Raised for invalid repository state or persistence failures."""


def repository_dir(root: Path) -> Path:
    return root / ".agentvault"


def _fsync_directory(path: Path) -> None:
    try:
        fd = os.open(path, os.O_RDONLY | getattr(os, "O_DIRECTORY", 0))
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as exc:
        raise RepositoryError("Unable to durably update Agent-Vault storage") from exc


def _recover_pending_rotations(root: Path) -> None:
    """Recover or finalize interrupted key rotations before opening the repository."""
    storage = repository_dir(root)
    if not storage.exists():
        return
    if storage.is_symlink() or not storage.is_dir():
        raise RepositoryError("Agent-Vault storage path is not a safe directory")
    changed = False
    for journal_dir in sorted(storage.glob(".rotation-*")):
        if journal_dir.is_symlink() or not journal_dir.is_dir():
            raise RepositoryError("Interrupted key rotation contains an unsafe path")
        journal_file = journal_dir / "journal.json"
        try:
            journal = json.loads(journal_file.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            raise RepositoryError("Interrupted key rotation journal is invalid") from exc
        if journal.get("state") not in {"prepared", "committed"}:
            raise RepositoryError("Interrupted key rotation journal is invalid")
        old_db = journal_dir / "old.db"
        old_key = journal_dir / "old.key"
        live_db = storage / DATABASE_FILENAME
        live_key = storage / KEY_FILENAME
        for candidate in (old_db, old_key, live_db, live_key):
            reject_symlink(candidate, "key rotation file")
        if journal["state"] == "prepared":
            if old_db.exists():
                os.replace(old_db, live_db)
            if old_key.exists():
                os.replace(old_key, live_key)
            _fsync_directory(storage)
        import shutil

        shutil.rmtree(journal_dir, ignore_errors=False)
        changed = True
    if changed:
        _fsync_directory(storage)


@contextmanager
def repository_lock(root: Path, *, exclusive: bool = True) -> Iterator[None]:
    """Serialize lifecycle mutations while allowing SQLite readers to coexist."""
    storage = repository_dir(root)
    if storage.is_symlink() or not storage.is_dir():
        raise RepositoryError("Agent-Vault repository is not initialized")
    os.chmod(storage, 0o700)
    lock_path = storage / ".operation.lock"
    reject_symlink(lock_path, "Agent-Vault operation lock")
    try:
        fd = os.open(lock_path, os.O_RDWR | os.O_CREAT, 0o600)
        os.fchmod(fd, 0o600)
        fcntl.flock(fd, fcntl.LOCK_EX if exclusive else fcntl.LOCK_SH)
    except OSError as exc:
        raise RepositoryError("Unable to acquire the Agent-Vault operation lock") from exc
    try:
        yield
    finally:
        try:
            fcntl.flock(fd, fcntl.LOCK_UN)
            os.close(fd)
        except OSError as exc:
            raise RepositoryError("Unable to release the Agent-Vault operation lock") from exc


def database_path(root: Path) -> Path:
    return repository_dir(root) / DATABASE_FILENAME


def key_path(root: Path) -> Path:
    return repository_dir(root) / KEY_FILENAME


def _ensure_secure_dir(path: Path) -> None:
    reject_symlink(path, "Agent-Vault storage directory")
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise RepositoryError("Agent-Vault storage path is not a directory") from exc
    if not path.is_dir() or path.is_symlink():
        raise RepositoryError("Agent-Vault storage path is not a directory")
    os.chmod(path, 0o700)


def _harden_file(path: Path) -> None:
    reject_symlink(path, "Agent-Vault storage file")
    try:
        file_stat = path.stat()
    except OSError as exc:
        raise RepositoryError("Unable to inspect Agent-Vault storage file") from exc
    if not stat.S_ISREG(file_stat.st_mode):
        raise RepositoryError("Agent-Vault storage file must be a regular file")
    os.chmod(path, 0o600)


def _connect(db_path: Path) -> sqlite3.Connection:
    reject_symlink(db_path, "Agent-Vault database")
    try:
        connection = sqlite3.connect(db_path, timeout=5.0)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA busy_timeout = 5000")
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("PRAGMA journal_mode = WAL")
        return connection
    except sqlite3.DatabaseError as exc:
        raise RepositoryError("Agent-Vault database is unavailable or corrupted") from exc


def _schema_version(connection: sqlite3.Connection) -> str:
    try:
        row = connection.execute(
            "SELECT value FROM metadata WHERE key = 'schema_version'"
        ).fetchone()
    except sqlite3.OperationalError:
        return "1.0"
    return str(row["value"]) if row else "1.0"


def _check_supported_schema(connection: sqlite3.Connection) -> str:
    version = _schema_version(connection)
    if version > DATABASE_SCHEMA_VERSION:
        raise RepositoryError(f"Database schema version {version} is newer than this release")
    if version not in {"1.0", DATABASE_SCHEMA_VERSION}:
        raise RepositoryError(f"Unsupported database schema version: {version}")
    return version


def _table_columns(connection: sqlite3.Connection, table: str) -> set[str]:
    return {str(row["name"]) for row in connection.execute(f"PRAGMA table_info({table})")}


def _table_exists(connection: sqlite3.Connection, table: str) -> bool:
    row = connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = ?", (table,)
    ).fetchone()
    return row is not None


def upgrade_schema(root: Path) -> dict[str, str]:
    """Upgrade a legacy repository transactionally without replacing ciphertext."""
    root = normalize_root(root)
    ensure_initialized(root)
    key = load_key(key_path(root))
    db_path = database_path(root)
    current = DATABASE_SCHEMA_VERSION
    try:
        with _connect(db_path) as connection:
            current = _check_supported_schema(connection)
            connection.execute("BEGIN IMMEDIATE")
            columns = _table_columns(connection, "memories")
            has_journal = _table_exists(connection, "schema_migrations")
            complete = {"kind_token", "payload"}.issubset(columns) and has_journal
            if current == DATABASE_SCHEMA_VERSION and complete:
                connection.commit()
                return {"status": "already-current", "schema_version": current}

            rows = connection.execute("SELECT id, payload FROM memories").fetchall()
            decoded = [(_decode_memory(key, row), row["payload"]) for row in rows]
            connection.execute(
                "CREATE TABLE IF NOT EXISTS schema_migrations ("
                "version TEXT PRIMARY KEY, applied_at TEXT NOT NULL)"
            )
            connection.execute(
                "CREATE TABLE IF NOT EXISTS metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
            )
            if "kind_token" not in columns:
                connection.execute("ALTER TABLE memories ADD COLUMN kind_token TEXT")
            connection.execute(
                "CREATE TABLE IF NOT EXISTS memory_tags ("
                "memory_id TEXT NOT NULL REFERENCES memories(id) ON DELETE CASCADE, "
                "tag_token TEXT NOT NULL, PRIMARY KEY (memory_id, tag_token))"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS memories_created_at_idx "
                "ON memories(created_at DESC, id DESC)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS memories_kind_token_idx ON memories(kind_token)"
            )
            connection.execute(
                "CREATE INDEX IF NOT EXISTS memory_tags_tag_token_idx ON memory_tags(tag_token)"
            )
            for memory, _ in decoded:
                connection.execute(
                    "UPDATE memories SET kind_token = ? WHERE id = ?",
                    (search_token(key, memory.kind), memory.id),
                )
                connection.execute("DELETE FROM memory_tags WHERE memory_id = ?", (memory.id,))
                connection.executemany(
                    "INSERT INTO memory_tags (memory_id, tag_token) VALUES (?, ?)",
                    [(memory.id, search_token(key, tag)) for tag in validate_tags(memory.tags)],
                )
            connection.execute(
                "INSERT OR REPLACE INTO metadata (key, value) VALUES ('schema_version', ?)",
                (DATABASE_SCHEMA_VERSION,),
            )
            connection.execute(
                "INSERT OR IGNORE INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                (DATABASE_SCHEMA_VERSION, utc_now()),
            )
            connection.commit()
    except (sqlite3.DatabaseError, ValidationError, ValueError) as exc:
        raise RepositoryError("Schema migration failed; no changes were committed") from exc
    _harden_file(db_path)
    return {"status": "migrated", "from": current, "schema_version": DATABASE_SCHEMA_VERSION}


def _validate_project_row(row: sqlite3.Row | None) -> dict[str, str]:
    if row is None:
        raise RepositoryError("Project metadata is missing from the Agent-Vault database")
    try:
        project = {
            "project_id": row["project_id"],
            "name": row["name"],
            "root_path": row["root_path"],
            "created_at": row["created_at"],
        }
    except (KeyError, TypeError) as exc:
        raise RepositoryError("Project metadata is missing required fields") from exc
    try:
        validate_project_name(project["name"])
        validate_timestamp(project["created_at"], "project created_at")
    except ValidationError as exc:
        raise RepositoryError("Project metadata is invalid") from exc
    if not isinstance(project["project_id"], str) or not project["project_id"].strip():
        raise RepositoryError("Project metadata is invalid")
    return project


def initialize(root: Path, name: str | None = None) -> dict[str, str]:
    """Create a new repository atomically, refusing partial or duplicate state."""
    root = normalize_root(root)
    name = validate_project_name(name)
    storage = repository_dir(root)
    reject_symlink(storage, "Agent-Vault storage directory")
    if storage.exists():
        raise RepositoryError(f"Agent-Vault is already initialized at {storage}")

    temporary = root / f".agentvault.tmp-{uuid.uuid4().hex}"
    project = {
        "project_id": str(uuid.uuid4()),
        "name": name or root.name or "untitled-project",
        "root_path": str(root),
        "created_at": utc_now(),
    }
    try:
        _ensure_secure_dir(temporary)
        from .crypto import create_key

        create_key(temporary / KEY_FILENAME)
        db_path = temporary / DATABASE_FILENAME
        with _connect(db_path) as connection:
            connection.executescript(
                """
                CREATE TABLE metadata (
                    key TEXT PRIMARY KEY,
                    value TEXT NOT NULL
                );
                CREATE TABLE schema_migrations (
                    version TEXT PRIMARY KEY,
                    applied_at TEXT NOT NULL
                );
                CREATE TABLE project (
                    id INTEGER PRIMARY KEY CHECK (id = 1),
                    project_id TEXT NOT NULL UNIQUE,
                    name TEXT NOT NULL,
                    root_path TEXT NOT NULL,
                    created_at TEXT NOT NULL
                );
                CREATE TABLE memories (
                    id TEXT PRIMARY KEY,
                    created_at TEXT NOT NULL,
                    kind_token TEXT NOT NULL,
                    payload BLOB NOT NULL
                );
                CREATE TABLE memory_tags (
                    memory_id TEXT NOT NULL REFERENCES memories(id) ON DELETE CASCADE,
                    tag_token TEXT NOT NULL,
                    PRIMARY KEY (memory_id, tag_token)
                );
                CREATE INDEX memories_created_at_idx ON memories(created_at DESC, id DESC);
                CREATE INDEX memories_kind_token_idx ON memories(kind_token);
                CREATE INDEX memory_tags_tag_token_idx ON memory_tags(tag_token);
                """
            )
            connection.execute(
                "INSERT INTO metadata (key, value) VALUES ('schema_version', ?)",
                (DATABASE_SCHEMA_VERSION,),
            )
            connection.execute(
                "INSERT INTO schema_migrations (version, applied_at) VALUES (?, ?)",
                (DATABASE_SCHEMA_VERSION, utc_now()),
            )
            connection.execute(
                "INSERT INTO project (id, project_id, name, root_path, created_at) "
                "VALUES (1, ?, ?, ?, ?)",
                (
                    project["project_id"],
                    project["name"],
                    project["root_path"],
                    project["created_at"],
                ),
            )
        _harden_file(db_path)
        os.replace(temporary, storage)
        _harden_file(key_path(root))
        _harden_file(database_path(root))
    except (OSError, sqlite3.DatabaseError, ValidationError) as exc:
        try:
            if temporary.exists() and not temporary.is_symlink():
                import shutil

                shutil.rmtree(temporary)
        except OSError:
            pass
        if isinstance(exc, ValidationError):
            raise RepositoryError(str(exc)) from exc
        raise RepositoryError("Unable to initialize Agent-Vault repository") from exc
    return project


def ensure_initialized(root: Path) -> None:
    """Ensure a complete repository exists and its database schema is supported."""
    root = normalize_root(root)
    _recover_pending_rotations(root)
    storage = repository_dir(root)
    if not storage.is_dir() or storage.is_symlink():
        raise RepositoryError(
            f"Agent-Vault is not initialized at {root}. Run 'agent-vault init' first."
        )
    db_path = database_path(root)
    secret_path = key_path(root)
    if not db_path.is_file() or not secret_path.is_file():
        raise RepositoryError("Agent-Vault repository is incomplete; restore or reinitialize it")
    _harden_file(storage / DATABASE_FILENAME)
    load_key(secret_path)
    try:
        with _connect(db_path) as connection:
            _check_supported_schema(connection)
            _validate_project_row(
                connection.execute(
                    "SELECT project_id, name, root_path, created_at FROM project WHERE id = 1"
                ).fetchone()
            )
    except (sqlite3.DatabaseError, ValidationError) as exc:
        if isinstance(exc, ValidationError):
            raise RepositoryError("Project metadata is invalid") from exc
        raise RepositoryError("Agent-Vault database is unavailable or corrupted") from exc


def add_memory(root: Path, memory: Memory) -> Memory:
    """Validate, encrypt, and persist one memory atomically."""
    ensure_initialized(root)
    try:
        memory = validate_memory(memory)
    except ValidationError as exc:
        raise RepositoryError(str(exc)) from exc
    with repository_lock(root):
        upgrade_schema(root)
        key = load_key(key_path(root))
        payload = json.dumps(memory.to_dict(), separators=(",", ":"), sort_keys=True)
        encrypted = encrypt(key, payload)
        try:
            with _connect(database_path(root)) as connection:
                connection.execute("BEGIN IMMEDIATE")
                connection.execute(
                    "INSERT INTO memories (id, created_at, kind_token, payload) "
                    "VALUES (?, ?, ?, ?)",
                    (memory.id, memory.created_at, search_token(key, memory.kind), encrypted),
                )
                connection.executemany(
                    "INSERT INTO memory_tags (memory_id, tag_token) VALUES (?, ?)",
                    [(memory.id, search_token(key, tag)) for tag in memory.tags],
                )
                connection.commit()
        except sqlite3.IntegrityError as exc:
            raise RepositoryError("A memory with this identifier already exists") from exc
        except sqlite3.DatabaseError as exc:
            raise RepositoryError("Unable to write memory to the Agent-Vault database") from exc
        _harden_file(database_path(root))
    return memory


def _decode_memory(key: bytes, row: sqlite3.Row) -> Memory:
    try:
        data = json.loads(decrypt(key, row["payload"]))
        return validate_memory_dict(data)
    except (ValueError, TypeError, json.JSONDecodeError, ValidationError) as exc:
        raise RepositoryError(f"Memory {row['id']} is corrupted or invalid") from exc


def _filter_values(key: bytes, kind: str | None, tag: str | None) -> tuple[str | None, str | None]:
    if kind is not None and kind not in MEMORY_KINDS:
        raise RepositoryError(f"kind must be one of: {', '.join(MEMORY_KINDS)}")
    try:
        normalized_tag = validate_tags((tag,))[0] if tag is not None else None
    except ValidationError as exc:
        raise RepositoryError(str(exc)) from exc
    kind_token = search_token(key, kind) if kind is not None else None
    tag_token = search_token(key, normalized_tag) if normalized_tag is not None else None
    return kind_token, tag_token


def list_memories(
    root: Path,
    *,
    kind: str | None = None,
    tag: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> tuple[Memory, ...]:
    """Query indexed candidates first, decrypting only rows that can match."""
    ensure_initialized(root)
    if limit is not None and limit < 1:
        raise RepositoryError("limit must be greater than zero")
    if offset < 0:
        raise RepositoryError("offset must not be negative")
    upgrade_schema(root)
    key = load_key(key_path(root))
    kind_token, tag_token = _filter_values(key, kind, tag)
    conditions: list[str] = []
    params: list[object] = []
    if kind_token is not None:
        conditions.append("m.kind_token = ?")
        params.append(kind_token)
    if tag_token is not None:
        conditions.append(
            "EXISTS (SELECT 1 FROM memory_tags mt WHERE mt.memory_id = m.id AND mt.tag_token = ?)"
        )
        params.append(tag_token)
    query = "SELECT m.id, m.created_at, m.payload FROM memories m"
    if conditions:
        query += " WHERE " + " AND ".join(conditions)
    query += " ORDER BY m.created_at DESC, m.id DESC LIMIT ? OFFSET ?"
    params.extend([limit if limit is not None else -1, offset])
    try:
        with _connect(database_path(root)) as connection:
            rows = connection.execute(query, params).fetchall()
    except sqlite3.DatabaseError as exc:
        raise RepositoryError("Unable to read the Agent-Vault database") from exc
    return tuple(_decode_memory(key, row) for row in rows)


def fetch_state(
    root: Path,
    *,
    kind: str | None = None,
    tag: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> ProjectState:
    """Return project metadata and matching memories as a stable JSON envelope."""
    ensure_initialized(root)
    try:
        with _connect(database_path(root)) as connection:
            _check_supported_schema(connection)
            project = _validate_project_row(
                connection.execute(
                    "SELECT project_id, name, root_path, created_at FROM project WHERE id = 1"
                ).fetchone()
            )
    except sqlite3.DatabaseError as exc:
        raise RepositoryError("Unable to read project metadata") from exc
    return ProjectState(
        schema_version=PUBLIC_SCHEMA_VERSION,
        project=project,
        memories=list_memories(root, kind=kind, tag=tag, limit=limit, offset=offset),
    )


def database_schema_version(root: Path) -> str:
    ensure_initialized(root)
    with _connect(database_path(root)) as connection:
        return _schema_version(connection)


def memory_count(root: Path) -> int:
    ensure_initialized(root)
    try:
        with _connect(database_path(root)) as connection:
            row = connection.execute("SELECT COUNT(*) AS count FROM memories").fetchone()
            return int(row["count"])
    except sqlite3.DatabaseError as exc:
        raise RepositoryError("Unable to count Agent-Vault memories") from exc
