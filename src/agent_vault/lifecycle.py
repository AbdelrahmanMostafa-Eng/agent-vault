"""Operational lifecycle workflows for Agent-Vault repositories."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import sqlite3
import stat
import tempfile
import uuid
import zipfile
from pathlib import Path
from typing import Any

from .crypto import create_key, decrypt, encrypt, load_key
from .models import utc_now
from .storage import (
    DATABASE_FILENAME,
    DATABASE_SCHEMA_VERSION,
    KEY_FILENAME,
    RepositoryError,
    _connect,
    _decode_memory,
    _fsync_directory,
    _harden_file,
    _schema_version,
    _validate_project_row,
    database_path,
    ensure_initialized,
    key_path,
    memory_count,
    repository_dir,
    repository_lock,
    upgrade_schema,
)
from .validation import (
    MAX_ARCHIVE_MEMBER_SIZE,
    normalize_root,
    reject_symlink,
    validate_archive_path,
    validate_timestamp,
)

ARCHIVE_FORMAT = "agent-vault-backup"
ARCHIVE_VERSION = "1"
MAX_ARCHIVE_TOTAL_SIZE = 250 * 1024 * 1024


class LifecycleError(RuntimeError):
    """Raised when an operational lifecycle command cannot complete safely."""


def _secure_directory(path: Path) -> None:
    reject_symlink(path, "storage directory")
    try:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    except OSError as exc:
        raise LifecycleError("storage directory is not safe") from exc
    if path.is_symlink() or not path.is_dir():
        raise LifecycleError("storage directory is not safe")
    os.chmod(path, 0o700)


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    try:
        with path.open("rb") as handle:
            for block in iter(lambda: handle.read(1024 * 1024), b""):
                digest.update(block)
    except OSError as exc:
        raise LifecycleError("Unable to inspect lifecycle file") from exc
    return digest.hexdigest()


def _checkpoint_database(path: Path) -> None:
    """Checkpoint and remove SQLite WAL sidecars before moving a database file."""
    try:
        with _connect(path) as connection:
            connection.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    except sqlite3.DatabaseError as exc:
        raise LifecycleError("Unable to checkpoint Agent-Vault database") from exc
    for suffix in ("-wal", "-shm"):
        sidecar = Path(f"{path}{suffix}")
        reject_symlink(sidecar, "SQLite sidecar")
        try:
            sidecar.unlink(missing_ok=True)
        except OSError as exc:
            raise LifecycleError("Unable to remove SQLite sidecar") from exc


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{uuid.uuid4().hex}.tmp")
    try:
        fd = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as handle:
            json.dump(value, handle, sort_keys=True, separators=(",", ":"))
            handle.write("\n")
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        _fsync_directory(path.parent)
    except OSError as exc:
        temporary.unlink(missing_ok=True)
        raise LifecycleError("Unable to write lifecycle journal") from exc


def _check_integrity(root: Path) -> dict[str, Any]:
    root = normalize_root(root)
    storage = repository_dir(root)
    if not storage.is_dir() or not database_path(root).is_file() or not key_path(root).is_file():
        raise LifecycleError("Agent-Vault repository is incomplete")
    for path in (storage, database_path(root), key_path(root)):
        if path.is_symlink():
            raise LifecycleError(f"Repository path must not be a symlink: {path.name}")
    key = load_key(key_path(root))
    try:
        with _connect(database_path(root)) as connection:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            schema_version = _schema_version(connection)
            if schema_version not in {"1.0", DATABASE_SCHEMA_VERSION}:
                raise LifecycleError(f"Unsupported database schema version: {schema_version}")
            project = _validate_project_row(
                connection.execute(
                    "SELECT project_id, name, root_path, created_at FROM project WHERE id = 1"
                ).fetchone()
            )
            rows = connection.execute(
                "SELECT id, created_at, payload FROM memories ORDER BY created_at DESC, id DESC"
            ).fetchall()
    except (sqlite3.DatabaseError, RepositoryError) as exc:
        if isinstance(exc.__cause__, ValueError):
            raise exc.__cause__ from exc
        raise LifecycleError("Agent-Vault database integrity or metadata check failed") from exc
    if integrity != "ok":
        raise LifecycleError("Agent-Vault database integrity check failed")
    checked = 0
    for row in rows:
        try:
            memory = _decode_memory(key, row)
        except RepositoryError as exc:
            raise LifecycleError(f"Memory {row['id']} failed integrity verification") from exc
        if memory.created_at != row["created_at"]:
            raise LifecycleError(f"Memory {row['id']} timestamp is inconsistent")
        validate_timestamp(row["created_at"], "memory row created_at")
        checked += 1
    validate_timestamp(project["created_at"], "project created_at")
    for path in (repository_dir(root), database_path(root), key_path(root)):
        if path.is_symlink():
            raise LifecycleError(f"Repository path must not be a symlink: {path.name}")
    return {
        "status": "ok",
        "schema_version": schema_version,
        "project_id": project["project_id"],
        "memory_count": checked,
        "database_integrity": integrity,
        "key_permissions": oct(stat.S_IMODE(key_path(root).stat().st_mode)),
        "database_permissions": oct(stat.S_IMODE(database_path(root).stat().st_mode)),
    }


def status(root: Path) -> dict[str, Any]:
    """Return non-sensitive repository state without decrypting memory content."""
    root = normalize_root(root)
    storage = repository_dir(root)
    db = database_path(root)
    secret = key_path(root)
    result: dict[str, Any] = {
        "initialized": False,
        "root_path": str(root),
        "storage_path": str(storage),
        "database_exists": db.is_file(),
        "key_exists": secret.is_file(),
    }
    if not storage.exists():
        return result
    if storage.is_symlink() or not storage.is_dir():
        raise LifecycleError("Agent-Vault storage path is not a safe directory")
    if db.is_file() and secret.is_file():
        ensure_initialized(root)
        with _connect(db) as connection:
            schema_version = _schema_version(connection)
        result.update(
            {
                "initialized": True,
                "schema_version": schema_version,
                "memory_count": memory_count(root),
            }
        )
    return result


def verify(root: Path) -> dict[str, Any]:
    """Validate key, schema, SQLite integrity, metadata, and every ciphertext row."""
    return _check_integrity(normalize_root(root))


def migrate(root: Path) -> dict[str, Any]:
    """Migrate an older repository schema without exposing or replacing payloads."""
    try:
        return upgrade_schema(normalize_root(root))
    except (OSError, sqlite3.DatabaseError, ValueError) as exc:
        raise LifecycleError("Migration failed; no changes were committed") from exc


def _sqlite_snapshot(root: Path, destination: Path, *, locked: bool = False) -> bytes:
    """Snapshot the database with a consistent read transaction."""
    if locked:
        return _sqlite_snapshot_unlocked(root, destination)
    with repository_lock(root, exclusive=False):
        return _sqlite_snapshot_unlocked(root, destination)


def _sqlite_snapshot_unlocked(root: Path, destination: Path) -> bytes:
    with _connect(database_path(root)) as source:
        source.execute("BEGIN")
        try:
            key = load_key(key_path(root))
            target = sqlite3.connect(destination, timeout=5.0)
            try:
                source.backup(target)
            finally:
                target.close()
            source.commit()
        except BaseException:
            source.rollback()
            raise
    _harden_file(destination)
    return key


def _validate_repository_files(
    database: Path,
    key_file: Path,
    manifest: dict[str, Any] | None = None,
) -> dict[str, Any]:
    """Validate a database/key pair, decrypting and validating every payload."""
    reject_symlink(database, "database file")
    reject_symlink(key_file, "key file")
    _harden_file(database)
    _harden_file(key_file)
    try:
        key = load_key(key_file)
    except (OSError, ValueError, RepositoryError) as exc:
        raise LifecycleError("Repository key is invalid or unreadable") from exc
    try:
        with _connect(database) as connection:
            integrity = connection.execute("PRAGMA integrity_check").fetchone()[0]
            if integrity != "ok":
                raise LifecycleError("Database failed integrity verification")
            schema_version = _schema_version(connection)
            if schema_version != DATABASE_SCHEMA_VERSION:
                raise LifecycleError(
                    "Database must be migrated before it can be archived or restored"
                )
            project = _validate_project_row(
                connection.execute(
                    "SELECT project_id, name, root_path, created_at FROM project WHERE id = 1"
                ).fetchone()
            )
            rows = connection.execute(
                "SELECT id, created_at, payload FROM memories ORDER BY created_at DESC, id DESC"
            ).fetchall()
            for row in rows:
                memory = _decode_memory(key, row)
                if memory.created_at != row["created_at"]:
                    raise LifecycleError(f"Memory {row['id']} timestamp is inconsistent")
    except (sqlite3.DatabaseError, RepositoryError) as exc:
        raise LifecycleError("Database or encrypted payload failed integrity verification") from exc
    result = {
        "project_id": project["project_id"],
        "schema_version": schema_version,
        "memory_count": len(rows),
        "database_sha256": _sha256(database),
        "key_sha256": _sha256(key_file),
    }
    if manifest is not None:
        expected = {
            "project_id": manifest.get("project_id"),
            "schema_version": manifest.get("schema_version"),
            "memory_count": manifest.get("memory_count"),
            "database_sha256": manifest.get("database_sha256"),
            "key_sha256": manifest.get("key_sha256"),
        }
        if expected != result:
            raise LifecycleError("Backup manifest does not match staged repository content")
    return result


def backup(root: Path, archive: Path, *, overwrite: bool = False) -> dict[str, Any]:
    """Create a consistent, integrity-bound ZIP backup containing the database and key."""
    root = normalize_root(root)
    upgrade_schema(root)
    verify(root)
    archive = validate_archive_path(archive)
    if archive.exists() and not overwrite:
        raise LifecycleError(f"Backup archive already exists: {archive}")
    archive.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    if archive.parent.is_symlink():
        raise LifecycleError("Backup destination directory must not be a symlink")
    temporary_dir = Path(tempfile.mkdtemp(prefix="agent-vault-backup-", dir=archive.parent))
    temporary_archive = archive.parent / f".{archive.name}.{uuid.uuid4().hex}.tmp"
    manifest: dict[str, Any]
    try:
        snapshot = temporary_dir / DATABASE_FILENAME
        key = _sqlite_snapshot(root, snapshot)
        key_file = temporary_dir / KEY_FILENAME
        key_file.write_bytes(key)
        os.chmod(key_file, 0o600)
        staged = _validate_repository_files(snapshot, key_file)
        manifest = {
            "format": ARCHIVE_FORMAT,
            "version": ARCHIVE_VERSION,
            "created_at": utc_now(),
            **staged,
        }
        with zipfile.ZipFile(temporary_archive, "x", compression=zipfile.ZIP_DEFLATED) as bundle:
            bundle.writestr("manifest.json", json.dumps(manifest, sort_keys=True).encode("utf-8"))
            bundle.write(snapshot, DATABASE_FILENAME)
            bundle.write(key_file, KEY_FILENAME)
        os.chmod(temporary_archive, 0o600)
        _fsync_directory(archive.parent)
        os.replace(temporary_archive, archive)
        _harden_file(archive)
        _fsync_directory(archive.parent)
    except (
        OSError,
        sqlite3.DatabaseError,
        ValueError,
        RepositoryError,
        zipfile.BadZipFile,
        LifecycleError,
    ) as exc:
        raise (
            exc
            if isinstance(exc, LifecycleError)
            else LifecycleError("Unable to create backup archive")
        ) from exc
    finally:
        shutil.rmtree(temporary_dir, ignore_errors=True)
        if temporary_archive.exists():
            temporary_archive.unlink(missing_ok=True)
    return {
        "status": "backed-up",
        "archive": str(archive),
        "memory_count": manifest["memory_count"],
        "project_id": manifest["project_id"],
    }


def _read_archive(archive: Path, staging: Path) -> dict[str, Any]:
    """Extract an allowlisted archive with duplicate, size, and regular-file checks."""
    try:
        with zipfile.ZipFile(archive) as bundle:
            infos = bundle.infolist()
            names = [info.filename for info in infos]
            required = {"manifest.json", DATABASE_FILENAME, KEY_FILENAME}
            if len(names) != len(set(names)) or set(names) != required:
                raise LifecycleError(
                    "Backup archive contains unexpected, duplicate, or missing files"
                )
            total_size = 0
            for info in infos:
                name = info.filename
                mode = (info.external_attr >> 16) & 0o170000
                if (
                    not name
                    or Path(name).name != name
                    or name.endswith("/")
                    or (mode and mode != stat.S_IFREG)
                    or info.file_size > MAX_ARCHIVE_MEMBER_SIZE
                    or info.compress_size == 0
                    or info.file_size > info.compress_size * 1000
                ):
                    raise LifecycleError("Backup archive contains an unsafe member")
                total_size += info.file_size
                if total_size > MAX_ARCHIVE_TOTAL_SIZE:
                    raise LifecycleError("Backup archive is too large")
                target = staging / name
                data = bundle.read(info)
                if len(data) != info.file_size:
                    raise LifecycleError("Backup archive member size is inconsistent")
                with target.open("xb") as handle:
                    handle.write(data)
                    handle.flush()
                    os.fsync(handle.fileno())
                os.chmod(target, 0o600)
            manifest_path = staging / "manifest.json"
            manifest = json.loads(manifest_path.read_text(encoding="utf-8"))
            if not isinstance(manifest, dict):
                raise LifecycleError("Backup manifest must be a JSON object")
            if (
                manifest.get("format") != ARCHIVE_FORMAT
                or manifest.get("version") != ARCHIVE_VERSION
            ):
                raise LifecycleError("Unsupported Agent-Vault backup format")
            for field in (
                "project_id",
                "schema_version",
                "database_sha256",
                "key_sha256",
            ):
                if not isinstance(manifest.get(field), str) or not manifest[field]:
                    raise LifecycleError("Backup manifest is missing required integrity metadata")
            if not isinstance(manifest.get("memory_count"), int) or manifest["memory_count"] < 0:
                raise LifecycleError("Backup manifest memory count is invalid")
            created_at = manifest.get("created_at")
            if not isinstance(created_at, str):
                raise LifecycleError("Backup manifest timestamp is invalid")
            try:
                validate_timestamp(created_at, "backup created_at")
            except ValueError as exc:
                raise LifecycleError("Backup manifest timestamp is invalid") from exc
            for digest_name in ("database_sha256", "key_sha256"):
                digest = manifest[digest_name]
                if len(digest) != 64 or any(char not in "0123456789abcdef" for char in digest):
                    raise LifecycleError("Backup manifest integrity metadata is invalid")
            return manifest
    except (OSError, KeyError, json.JSONDecodeError, zipfile.BadZipFile) as exc:
        raise LifecycleError("Backup archive is invalid") from exc


def restore(root: Path, archive: Path, *, overwrite: bool = False) -> dict[str, Any]:
    """Validate every staged byte and atomically install a backup repository."""
    root = normalize_root(root, must_exist=False)
    archive = validate_archive_path(archive)
    if not archive.is_file():
        raise LifecycleError(f"Backup archive does not exist: {archive}")
    storage = repository_dir(root)
    if storage.is_symlink():
        raise LifecycleError("Restore destination storage path must not be a symlink")
    if storage.exists() and not overwrite:
        raise LifecycleError("Repository already exists; use --force to replace it")
    staging = root / f".agentvault.restore-{uuid.uuid4().hex}"
    previous = root / f".agentvault.previous-{uuid.uuid4().hex}"
    installed = False
    previous_moved = False
    manifest: dict[str, Any] = {}
    try:
        _secure_directory(staging)
        manifest = _read_archive(archive, staging)
        _validate_repository_files(staging / DATABASE_FILENAME, staging / KEY_FILENAME, manifest)
        if storage.exists():
            os.replace(storage, previous)
            previous_moved = True
            _fsync_directory(root)
        os.replace(staging, storage)
        installed = True
        _fsync_directory(root)
        verified = _check_integrity(root)
        if verified["memory_count"] != manifest["memory_count"]:
            raise LifecycleError("Restored memory count does not match backup manifest")
        if previous_moved:
            shutil.rmtree(previous, ignore_errors=False)
        _fsync_directory(root)
    except (OSError, sqlite3.DatabaseError, ValueError, RepositoryError, LifecycleError) as exc:
        try:
            if installed and storage.exists() and not storage.is_symlink():
                shutil.rmtree(storage, ignore_errors=False)
            if previous_moved and previous.exists():
                os.replace(previous, storage)
                _fsync_directory(root)
            elif staging.exists() and not staging.is_symlink():
                shutil.rmtree(staging, ignore_errors=True)
        except OSError as rollback_exc:
            raise LifecycleError(
                "Restore failed and automatic rollback also failed"
            ) from rollback_exc
        raise (
            exc
            if isinstance(exc, LifecycleError)
            else LifecycleError("Unable to restore backup archive")
        ) from exc
    return {
        "status": "restored",
        "archive": str(archive),
        "memory_count": manifest["memory_count"],
        "project_id": manifest["project_id"],
    }


def rotate_key(root: Path) -> dict[str, Any]:
    root = normalize_root(root)
    with repository_lock(root):
        return _rotate_key_locked(root)


def _rotate_key_locked(root: Path) -> dict[str, Any]:
    """Re-encrypt every memory using a journaled database/key replacement protocol."""
    root = normalize_root(root)
    ensure_initialized(root)
    upgrade_schema(root)
    try:
        verify(root)
    except (LifecycleError, ValueError, RepositoryError) as exc:
        raise LifecycleError(
            "Key rotation failed; the original key and payloads were preserved"
        ) from exc
    storage = repository_dir(root)
    journal = storage / f".rotation-{uuid.uuid4().hex}"
    new_key_path = journal / "new.key"
    new_db_path = journal / "new.db"
    old_db_path = journal / "old.db"
    old_key_path = journal / "old.key"
    journal_path = journal / "journal.json"
    prepared = False
    try:
        _secure_directory(journal)
        _write_json_atomic(
            journal_path,
            {"state": "prepared", "created_at": utc_now(), "memory_count": 0},
        )
        prepared = True
        create_key(new_key_path)
        new_key = load_key(new_key_path)
        _checkpoint_database(database_path(root))
        old_key = load_key(key_path(root))
        shutil.copy2(database_path(root), old_db_path)
        shutil.copy2(key_path(root), old_key_path)
        _harden_file(old_db_path)
        _harden_file(old_key_path)
        _sqlite_snapshot(root, new_db_path, locked=True)
        _checkpoint_database(new_db_path)
        _harden_file(new_db_path)
        with _connect(new_db_path) as connection:
            connection.execute("BEGIN IMMEDIATE")
            rows = connection.execute("SELECT id, payload FROM memories").fetchall()
            for row in rows:
                plaintext = decrypt(old_key, row["payload"])
                updated = encrypt(new_key, plaintext)
                connection.execute(
                    "UPDATE memories SET payload = ? WHERE id = ?", (updated, row["id"])
                )
            connection.commit()
        _checkpoint_database(new_db_path)
        _validate_repository_files(new_db_path, new_key_path)
        _write_json_atomic(
            journal_path,
            {"state": "prepared", "created_at": utc_now(), "memory_count": len(rows)},
        )
        os.replace(database_path(root), old_db_path.with_name("live.db"))
        os.replace(new_db_path, database_path(root))
        _fsync_directory(storage)
        os.replace(key_path(root), old_key_path.with_name("live.key"))
        os.replace(new_key_path, key_path(root))
        _fsync_directory(storage)
        _validate_repository_files(database_path(root), key_path(root))
        _write_json_atomic(
            journal_path,
            {"state": "committed", "created_at": utc_now(), "memory_count": len(rows)},
        )
        shutil.rmtree(journal, ignore_errors=False)
        _fsync_directory(storage)
    except (OSError, sqlite3.DatabaseError, ValueError, LifecycleError) as exc:
        if prepared:
            try:
                from .storage import _recover_pending_rotations

                _recover_pending_rotations(root)
            except Exception as recovery_exc:
                raise LifecycleError(
                    "Key rotation failed and recovery requires manual intervention"
                ) from recovery_exc
        else:
            shutil.rmtree(journal, ignore_errors=True)
        raise (
            exc
            if isinstance(exc, LifecycleError)
            else LifecycleError("Key rotation failed; the original key and payloads were preserved")
        ) from exc
    return {"status": "rotated", "memory_count": len(rows)}
