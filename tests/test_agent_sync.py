from __future__ import annotations

import json
import os
import sqlite3
import stat
import subprocess
import sys
import zipfile
from pathlib import Path

import pytest

from agent_vault.cli import main
from agent_vault.crypto import EncryptionError, create_key, decrypt, encrypt, load_key
from agent_vault.lifecycle import (
    LifecycleError,
    backup,
    migrate,
    restore,
    rotate_key,
    status,
    verify,
)
from agent_vault.models import Memory, ProjectState, utc_now
from agent_vault.storage import (
    RepositoryError,
    add_memory,
    database_path,
    fetch_state,
    initialize,
    key_path,
    list_memories,
    memory_count,
    upgrade_schema,
)
from agent_vault.validation import (
    ValidationError,
    normalize_root,
    validate_memory,
    validate_memory_dict,
)


@pytest.fixture
def project(tmp_path: Path) -> Path:
    initialize(tmp_path, "Test Project")
    return tmp_path


def make_memory(
    memory_id: str = "memory-1",
    *,
    kind: str = "decision",
    content: str = "Use SQLite",
    tags: tuple[str, ...] = ("storage", "architecture"),
    created_at: str = "2026-01-01T00:00:00Z",
) -> Memory:
    return Memory(memory_id, kind, content, tags, "design.md", "private", created_at)


def test_crypto_round_trip_and_invalid_ciphertext(tmp_path: Path) -> None:
    key_file = tmp_path / "context.key"
    create_key(key_file)
    key = load_key(key_file)
    assert decrypt(key, encrypt(key, "hello")) == "hello"
    with pytest.raises(EncryptionError):
        decrypt(key, b"not-fernet")
    assert stat.S_IMODE(key_file.stat().st_mode) == 0o600


def test_crypto_rejects_unsafe_key_and_symlink(tmp_path: Path) -> None:
    key_file = tmp_path / "context.key"
    create_key(key_file)
    key_file.chmod(0o644)
    with pytest.raises(EncryptionError, match="permissions"):
        load_key(key_file)
    key_file.chmod(0o600)
    link = tmp_path / "link.key"
    link.symlink_to(key_file)
    with pytest.raises(EncryptionError, match="symlink"):
        load_key(link)


def test_crypto_rejects_malformed_key(tmp_path: Path) -> None:
    key_file = tmp_path / "context.key"
    key_file.write_text("not a key")
    key_file.chmod(0o600)
    with pytest.raises(EncryptionError, match="Invalid"):
        load_key(key_file)


def test_models_and_validation_contract() -> None:
    memory = validate_memory(make_memory(tags=("Storage", "storage", "unicode-✓")))
    assert memory.tags == ("storage", "unicode-✓")
    assert (
        ProjectState("1.0", {"name": "x"}, (memory,)).to_dict()["memories"][0]["id"] == "memory-1"
    )
    assert utc_now().endswith("Z")
    with pytest.raises(ValidationError, match="timestamp"):
        validate_memory(make_memory(created_at="not-a-time"))
    with pytest.raises(ValidationError, match="kind"):
        validate_memory(make_memory(kind="invalid"))
    with pytest.raises(ValidationError, match="required fields"):
        validate_memory_dict({"id": "only-id"})
    with pytest.raises(ValidationError, match="content"):
        validate_memory(make_memory(content="\x00secret"))


def test_initialize_is_transactional_and_idempotency_safe(tmp_path: Path) -> None:
    metadata = initialize(tmp_path, "Test Project")
    assert metadata["name"] == "Test Project"
    storage = tmp_path / ".agentvault"
    assert database_path(tmp_path).exists()
    assert stat.S_IMODE(storage.stat().st_mode) == 0o700
    assert stat.S_IMODE(database_path(tmp_path).stat().st_mode) == 0o600
    with pytest.raises(RepositoryError, match="already initialized"):
        initialize(tmp_path)


def test_initialize_rejects_partial_and_symlink_repositories(tmp_path: Path) -> None:
    storage = tmp_path / ".agentvault"
    storage.mkdir()
    with pytest.raises(RepositoryError, match="already initialized"):
        initialize(tmp_path)
    storage.rmdir()
    target = tmp_path / "target"
    target.mkdir()
    (tmp_path / "link").symlink_to(target, target_is_directory=True)
    with pytest.raises(ValidationError, match="symlink"):
        initialize(tmp_path / "link")


def test_record_and_fetch_decrypts_payload(project: Path) -> None:
    memory = make_memory()
    add_memory(project, memory)
    state = fetch_state(project)
    assert state.schema_version == "1.0"
    assert state.project["name"] == "Test Project"
    assert state.memories == (memory,)
    raw = (
        sqlite3.connect(database_path(project))
        .execute("SELECT payload FROM memories")
        .fetchone()[0]
    )
    assert b"Use SQLite" not in raw
    tag_token = (
        sqlite3.connect(database_path(project))
        .execute("SELECT tag_token FROM memory_tags")
        .fetchone()[0]
    )
    assert "architecture" not in tag_token


def test_memory_filters_ordering_limits_and_duplicates(project: Path) -> None:
    add_memory(
        project,
        make_memory(
            "1", kind="decision", content="one", tags=("a",), created_at="2026-01-01T00:00:00Z"
        ),
    )
    add_memory(
        project,
        make_memory(
            "2", kind="fact", content="two", tags=("b",), created_at="2026-01-02T00:00:00Z"
        ),
    )
    add_memory(
        project,
        make_memory(
            "3", kind="decision", content="three", tags=("a",), created_at="2026-01-03T00:00:00Z"
        ),
    )
    assert [item.id for item in list_memories(project, kind="decision")] == ["3", "1"]
    assert [item.id for item in list_memories(project, tag="a", limit=1)] == ["3"]
    assert [item.id for item in list_memories(project, limit=2)] == ["3", "2"]
    with pytest.raises(RepositoryError, match="greater than zero"):
        list_memories(project, limit=0)
    with pytest.raises(RepositoryError, match="identifier"):
        add_memory(project, make_memory("1"))


def test_large_unicode_and_multiline_content(project: Path) -> None:
    content = "第一行\nsecond line\n" + "✓" * 5000
    memory = make_memory("unicode", content=content, tags=("unicode",))
    add_memory(project, memory)
    assert fetch_state(project).memories[0].content == content


def test_corrupted_payload_and_key_are_safe_errors(project: Path) -> None:
    add_memory(project, make_memory("valid"))
    connection = sqlite3.connect(database_path(project))
    connection.execute("UPDATE memories SET payload = ? WHERE id = ?", (b"corrupted", "valid"))
    connection.commit()
    connection.close()
    with pytest.raises(RepositoryError, match="corrupted"):
        fetch_state(project)
    key_path(project).write_bytes(b"invalid")
    key_path(project).chmod(0o600)
    with pytest.raises(EncryptionError, match="Invalid"):
        load_key(key_path(project))


def test_upgrade_schema_from_legacy_layout(tmp_path: Path) -> None:
    initialize(tmp_path, "Legacy")
    key = load_key(key_path(tmp_path))
    memory = make_memory("legacy", tags=("legacy",))
    payload = encrypt(key, json.dumps(memory.to_dict(), separators=(",", ":")))
    connection = sqlite3.connect(database_path(tmp_path))
    connection.execute("DROP TABLE metadata")
    connection.execute("DROP INDEX memories_kind_token_idx")
    connection.execute("DROP TABLE memory_tags")
    connection.execute("ALTER TABLE memories DROP COLUMN kind_token")
    connection.execute(
        "INSERT INTO memories (id, created_at, payload) VALUES (?, ?, ?)",
        (memory.id, memory.created_at, payload),
    )
    connection.commit()
    connection.close()
    assert upgrade_schema(tmp_path)["status"] == "migrated"
    assert fetch_state(tmp_path).memories[0].id == "legacy"
    assert migrate(tmp_path)["status"] == "already-current"


def test_unsupported_schema_is_rejected(project: Path) -> None:
    connection = sqlite3.connect(database_path(project))
    connection.execute("UPDATE metadata SET value = '99.0' WHERE key = 'schema_version'")
    connection.commit()
    connection.close()
    with pytest.raises(RepositoryError, match="newer"):
        fetch_state(project)


def test_cli_end_to_end_and_secure_inputs(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["init", str(tmp_path), "--name", "CLI Project"]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "initialized"
    assert (
        main(
            [
                "record",
                "Keep the CLI JSON-only",
                "--kind",
                "constraint",
                "--tag",
                "interop",
                "--path",
                str(tmp_path),
            ]
        )
        == 0
    )
    assert json.loads(capsys.readouterr().out)["status"] == "recorded"
    content_file = tmp_path / "memory.txt"
    content_file.write_text("from file\nmultiline")
    assert main(["record", "--file", str(content_file), "--path", str(tmp_path)]) == 0
    capsys.readouterr()
    assert main(["fetch", str(tmp_path), "--kind", "constraint"]) == 0
    state = json.loads(capsys.readouterr().out)
    assert state["project"]["name"] == "CLI Project"
    assert state["memories"][0]["content"] == "Keep the CLI JSON-only"


def test_cli_usage_and_operational_errors(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["record", "--path", str(tmp_path)]) == 2
    assert "exactly one" in capsys.readouterr().err
    assert main(["fetch", str(tmp_path)]) == 1
    assert "not initialized" in capsys.readouterr().err
    assert main(["fetch", str(tmp_path), "--limit", "0"]) == 1
    assert "not initialized" in capsys.readouterr().err


def test_lifecycle_status_verify_backup_restore_and_rotation(tmp_path: Path) -> None:
    initialize(tmp_path, "Lifecycle")
    add_memory(tmp_path, make_memory("lifecycle", content="keep me"))
    assert status(tmp_path)["memory_count"] == 1
    assert verify(tmp_path)["status"] == "ok"
    archive = tmp_path.parent / "agent-vault-test-backup.zip"
    result = backup(tmp_path, archive)
    assert result["memory_count"] == 1
    before = key_path(tmp_path).read_bytes()
    assert rotate_key(tmp_path)["status"] == "rotated"
    assert key_path(tmp_path).read_bytes() != before
    assert fetch_state(tmp_path).memories[0].content == "keep me"
    restored = tmp_path.parent / "restored-project"
    restored.mkdir()
    assert restore(restored, archive)["status"] == "restored"
    assert fetch_state(restored).memories[0].content == "keep me"
    archive.unlink()


def test_backup_refuses_overwrite_and_restore_requires_force(tmp_path: Path) -> None:
    initialize(tmp_path)
    archive = tmp_path.parent / "backup.zip"
    backup(tmp_path, archive)
    with pytest.raises(LifecycleError, match="already exists"):
        backup(tmp_path, archive)
    with pytest.raises(LifecycleError, match="already exists"):
        restore(tmp_path, archive)
    backup(tmp_path, archive, overwrite=True)
    archive.unlink()


def test_malformed_backup_is_rejected(tmp_path: Path) -> None:
    initialize(tmp_path)
    archive = tmp_path / "bad.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        bundle.writestr("../escape", "bad")
    with pytest.raises(LifecycleError):
        restore(tmp_path / "restore", archive)
    archive.unlink()


def test_cli_subprocess_entry_points(tmp_path: Path) -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
    init = subprocess.run(
        [sys.executable, "-m", "agent_vault", "init", str(tmp_path)],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert init.returncode == 0
    fetch = subprocess.run(
        [sys.executable, "-m", "agent_vault", "fetch", str(tmp_path)],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert fetch.returncode == 0
    assert json.loads(fetch.stdout)["memories"] == []


def test_verify_detects_database_corruption(project: Path) -> None:
    connection = sqlite3.connect(database_path(project))
    connection.execute("PRAGMA writable_schema = ON")
    connection.execute(
        "UPDATE sqlite_master SET sql = 'corrupt' WHERE type = 'table' AND name = 'project'"
    )
    connection.commit()
    connection.close()
    with pytest.raises((RepositoryError, LifecycleError)):
        verify(project)


def test_memory_count(project: Path) -> None:
    assert memory_count(project) == 0
    add_memory(project, make_memory())
    assert memory_count(project) == 1


def test_cli_stdin_and_file_validation(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    initialize(tmp_path)
    monkeypatch.setattr(sys, "stdin", __import__("io").StringIO("stdin memory\nline two"))
    assert main(["record", "--stdin", "--path", str(tmp_path)]) == 0
    capsys.readouterr()
    missing = tmp_path / "missing.txt"
    assert main(["record", "--file", str(missing), "--path", str(tmp_path)]) == 1
    assert "regular file" in capsys.readouterr().err
    bad = tmp_path / "bad.txt"
    bad.write_bytes(bytes([0xFF]))
    assert main(["record", "--file", str(bad), "--path", str(tmp_path)]) == 1
    assert "UTF-8" in capsys.readouterr().err
    link = tmp_path / "link.txt"
    link.symlink_to(bad)
    assert main(["record", "--file", str(link), "--path", str(tmp_path)]) == 1
    assert "symlink" in capsys.readouterr().err


def test_cli_dispatches_lifecycle_commands(
    tmp_path: Path, capsys: pytest.CaptureFixture[str]
) -> None:
    assert main(["init", str(tmp_path)]) == 0
    capsys.readouterr()
    assert main(["status", str(tmp_path)]) == 0
    assert json.loads(capsys.readouterr().out)["initialized"] is True
    assert main(["verify", str(tmp_path)]) == 0
    capsys.readouterr()
    assert main(["migrate", str(tmp_path)]) == 0
    capsys.readouterr()
    assert main(["rotate-key", str(tmp_path)]) == 0
    capsys.readouterr()
    archive = tmp_path.parent / "cli-backup.zip"
    assert main(["backup", str(archive), "--path", str(tmp_path)]) == 0
    capsys.readouterr()
    restored = tmp_path.parent / "cli-restored"
    restored.mkdir()
    assert main(["restore", str(archive), "--path", str(restored)]) == 0
    assert json.loads(capsys.readouterr().out)["status"] == "restored"
    archive.unlink()


def test_validation_rejects_bad_metadata_and_limits() -> None:
    with pytest.raises(ValidationError, match="project name"):
        from agent_vault.validation import validate_project_name

        validate_project_name(" ")
    with pytest.raises(ValidationError, match="source"):
        from agent_vault.validation import validate_source

        validate_source("\x00source")
    with pytest.raises(ValidationError, match="tags"):
        from agent_vault.validation import validate_tags

        validate_tags(tuple(str(i) for i in range(33)))
    with pytest.raises(ValidationError, match="tag"):
        from agent_vault.validation import validate_tags

        validate_tags(("",))
    with pytest.raises(ValidationError, match="memory id"):
        validate_memory(make_memory("bad id"))
    with pytest.raises(ValidationError, match="sensitivity"):
        validate_memory(Memory("valid", "note", "x", sensitivity="sensitive"))


def test_storage_detects_incomplete_and_missing_metadata(project: Path) -> None:
    key_path(project).unlink()
    with pytest.raises(RepositoryError, match="incomplete"):
        fetch_state(project)
    other = project.parent / "other"
    other.mkdir()
    initialize(other)
    connection = sqlite3.connect(database_path(other))
    connection.execute("DELETE FROM project")
    connection.commit()
    connection.close()
    with pytest.raises(RepositoryError, match="metadata"):
        fetch_state(other)


def test_storage_rejects_corrupt_json_payload(project: Path) -> None:
    key = load_key(key_path(project))
    payload = encrypt(key, json.dumps({"id": "broken"}))
    connection = sqlite3.connect(database_path(project))
    connection.execute(
        "INSERT INTO memories (id, created_at, kind_token, payload) VALUES (?, ?, ?, ?)",
        ("broken", "2026-01-01T00:00:00Z", "bad", payload),
    )
    connection.commit()
    connection.close()
    with pytest.raises(RepositoryError, match="corrupted"):
        fetch_state(project)


def test_lifecycle_status_partial_and_unsafe_paths(tmp_path: Path) -> None:
    partial = tmp_path / "partial"
    (partial / ".agentvault").mkdir(parents=True)
    assert status(partial)["initialized"] is False
    bad = tmp_path / "bad"
    bad.write_text("not a directory")
    with pytest.raises(ValidationError, match="existing directory"):
        status(bad)


def test_verify_detects_invalid_timestamp(project: Path) -> None:
    connection = sqlite3.connect(database_path(project))
    connection.execute("UPDATE project SET created_at = 'invalid' WHERE id = 1")
    connection.commit()
    connection.close()
    with pytest.raises(ValidationError, match="timestamp"):
        verify(project)


def test_backup_missing_and_unsafe_archive_paths(project: Path) -> None:
    with pytest.raises(LifecycleError, match="Backup archive"):
        from agent_vault.lifecycle import restore

        restore(project.parent / "new", project / "missing.zip")
    target = project / "target-dir"
    target.mkdir()
    with pytest.raises(ValidationError, match="regular file"):
        backup(project, target)


def test_crypto_rejects_non_file_and_bad_key_input(tmp_path: Path) -> None:
    directory = tmp_path / "key-dir"
    directory.mkdir()
    with pytest.raises(EncryptionError, match="regular file"):
        load_key(directory)
    with pytest.raises(EncryptionError, match="encrypt"):
        encrypt(b"not-a-fernet-key", "secret")


def test_database_and_key_paths_are_not_symlinks(project: Path) -> None:
    db = database_path(project)
    original = db.read_bytes()
    db.unlink()
    db.symlink_to(project / "elsewhere.db")
    with pytest.raises(RepositoryError):
        fetch_state(project)
    db.unlink()
    db.write_bytes(original)
    db.chmod(0o600)
    key = key_path(project)
    key.chmod(0o644)
    with pytest.raises(EncryptionError):
        fetch_state(project)
    key.chmod(0o600)


def test_duplicate_tag_tokens_are_deduplicated(project: Path) -> None:
    add_memory(project, make_memory("dedupe", tags=("same", "same", "SAME")))
    rows = (
        sqlite3.connect(database_path(project))
        .execute("SELECT COUNT(*) FROM memory_tags WHERE memory_id = 'dedupe'")
        .fetchone()[0]
    )
    assert rows == 1


def test_defensive_storage_branches(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import agent_vault.storage as storage_module

    def fail_connect(*args: object, **kwargs: object) -> None:
        raise sqlite3.DatabaseError("simulated")

    monkeypatch.setattr(storage_module.sqlite3, "connect", fail_connect)
    with pytest.raises(RepositoryError, match="unavailable"):
        storage_module._connect(tmp_path / "context.db")
    with pytest.raises(RepositoryError, match="not a directory"):
        storage_module._ensure_secure_dir(tmp_path / "file") if (tmp_path / "file").write_text(
            "x"
        ) else None
    with pytest.raises(RepositoryError, match="inspect"):
        storage_module._harden_file(tmp_path / "missing")
    with pytest.raises(RepositoryError, match="regular file"):
        storage_module._harden_file(tmp_path)
    with pytest.raises(RepositoryError, match="invalid"):
        storage_module._validate_project_row(
            {"project_id": "x", "name": "\x00", "root_path": "x", "created_at": "x"}
        )


def test_storage_query_error_branches(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import agent_vault.storage as storage_module

    class FakeConnection:
        def __enter__(self) -> FakeConnection:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, query: str, *args: object) -> None:
            raise sqlite3.DatabaseError("simulated")

    monkeypatch.setattr(storage_module, "ensure_initialized", lambda root: None)
    monkeypatch.setattr(storage_module, "load_key", lambda path: b"key")
    monkeypatch.setattr(storage_module, "upgrade_schema", lambda root: None)
    monkeypatch.setattr(storage_module, "_connect", lambda path: FakeConnection())
    with pytest.raises(RepositoryError, match="read"):
        storage_module.list_memories(tmp_path)
    with pytest.raises(RepositoryError, match="project metadata"):
        storage_module.fetch_state(tmp_path)
    with pytest.raises(RepositoryError, match="count"):
        storage_module.memory_count(tmp_path)


def test_storage_schema_version_fallback() -> None:
    import agent_vault.storage as storage_module

    class OperationalConnection:
        def execute(self, query: str) -> None:
            raise sqlite3.OperationalError("no metadata")

    assert storage_module._schema_version(OperationalConnection()) == "1.0"


def test_initialize_cleans_temporary_repository_on_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_vault.crypto as crypto_module

    def fail_key(path: Path) -> None:
        raise OSError("simulated key failure")

    monkeypatch.setattr(crypto_module, "create_key", fail_key)
    with pytest.raises(RepositoryError, match="initialize"):
        initialize(tmp_path)
    assert not list(tmp_path.glob(".agentvault.tmp-*"))


def test_lifecycle_defensive_branches(
    tmp_path: Path, project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_vault.lifecycle as lifecycle_module

    empty = project / "empty"
    empty.mkdir()
    assert status(empty)["initialized"] is False
    monkeypatch.setattr(
        lifecycle_module,
        "upgrade_schema",
        lambda root: (_ for _ in ()).throw(sqlite3.DatabaseError("simulated")),
    )
    with pytest.raises(LifecycleError, match="Migration failed"):
        migrate(project)
    monkeypatch.undo()
    monkeypatch.setattr(
        lifecycle_module,
        "_sqlite_snapshot",
        lambda root, destination: (_ for _ in ()).throw(OSError("simulated")),
    )
    with pytest.raises(LifecycleError, match="backup"):
        backup(project, tmp_path / "backup.zip")
    monkeypatch.undo()
    invalid_zip = tmp_path / "invalid.zip"
    invalid_zip.write_bytes(b"not a zip")
    with pytest.raises(LifecycleError, match="invalid"):
        lifecycle_module.restore(tmp_path / "new-target", invalid_zip)


def test_lifecycle_integrity_result_branches(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_vault.lifecycle as lifecycle_module

    class Result:
        def __init__(self, value: object) -> None:
            self.value = value

        def fetchone(self) -> object:
            return self.value

        def fetchall(self) -> list[object]:
            return []

    class RowConnection:
        def __init__(self, integrity: str, project_row: object, schema: str = "1.1") -> None:
            self.integrity = integrity
            self.project_row = project_row
            self.schema = schema

        def __enter__(self) -> RowConnection:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, query: str, *args: object) -> object:
            if "PRAGMA integrity_check" in query:
                return Result((self.integrity,))
            if "SELECT project_id" in query:
                return Result(self.project_row)
            return Result(None)

    monkeypatch.setattr(lifecycle_module, "ensure_initialized", lambda root: None)
    monkeypatch.setattr(lifecycle_module, "load_key", lambda path: b"key")
    monkeypatch.setattr(
        lifecycle_module, "_connect", lambda path: RowConnection("failed", object())
    )
    with pytest.raises(LifecycleError, match="integrity"):
        lifecycle_module._check_integrity(project)
    monkeypatch.setattr(lifecycle_module, "_connect", lambda path: RowConnection("ok", None))
    with pytest.raises(LifecycleError, match="metadata"):
        lifecycle_module._check_integrity(project)


def test_rotate_key_reports_corrupt_ciphertext(project: Path) -> None:
    connection = sqlite3.connect(database_path(project))
    connection.execute(
        "INSERT INTO memories (id, created_at, kind_token, payload) VALUES (?, ?, ?, ?)",
        ("broken", "2026-01-01T00:00:00Z", "bad", b"broken"),
    )
    connection.commit()
    connection.close()
    with pytest.raises(LifecycleError, match="rotation failed"):
        rotate_key(project)


def test_validation_edge_cases(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_vault.validation import (
        normalize_root,
        reject_symlink,
        validate_archive_path,
        validate_content,
        validate_project_name,
        validate_tags,
        validate_timestamp,
    )

    with pytest.raises(ValidationError, match="must be text"):
        validate_project_name(123)  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="exceeds"):
        validate_content("x" * 1_048_577)
    with pytest.raises(ValidationError, match="list"):
        validate_tags("not-a-list")  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="timestamp"):
        validate_timestamp("")
    with pytest.raises(ValidationError, match="timezone"):
        validate_timestamp("2026-01-01T00:00:00")
    with pytest.raises(ValidationError, match="Memory"):
        validate_memory("not-a-memory")  # type: ignore[arg-type]
    with pytest.raises(ValidationError, match="JSON object"):
        validate_memory_dict([])
    with pytest.raises(ValidationError, match="cannot be resolved"):
        normalize_root(tmp_path / "missing")
    parent = tmp_path / "real-parent"
    parent.mkdir()
    target = tmp_path / "target-parent"
    target.symlink_to(parent, target_is_directory=True)
    with pytest.raises(ValidationError, match="restore parent"):
        normalize_root(target / "new", must_exist=False)
    archive_dir = tmp_path / "archive-dir"
    archive_dir.mkdir()
    with pytest.raises(ValidationError, match="regular file"):
        validate_archive_path(archive_dir)
    monkeypatch.setattr(Path, "is_symlink", lambda self: (_ for _ in ()).throw(OSError("denied")))
    with pytest.raises(ValidationError, match="inspect"):
        reject_symlink(tmp_path / "any", "test path")


def test_database_schema_version_and_project_validation(project: Path) -> None:
    from agent_vault.storage import database_schema_version

    assert database_schema_version(project) == "1.1"
    connection = sqlite3.connect(database_path(project))
    connection.execute("UPDATE project SET name = ? WHERE id = 1", ("\x00bad",))
    connection.commit()
    connection.close()
    with pytest.raises(RepositoryError, match="invalid"):
        fetch_state(project)


def test_restore_force_replaces_existing_repository(tmp_path: Path) -> None:
    source = tmp_path / "source"
    destination = tmp_path / "destination"
    source.mkdir()
    destination.mkdir()
    initialize(source, "Source")
    initialize(destination, "Destination")
    archive = tmp_path / "force.zip"
    backup(source, archive)
    assert restore(destination, archive, overwrite=True)["status"] == "restored"
    assert fetch_state(destination).project["name"] == "Source"
    archive.unlink()


def test_restore_rejects_unsupported_manifest(tmp_path: Path, project: Path) -> None:
    archive = tmp_path / "manifest.zip"
    backup(project, archive)
    rewritten = tmp_path / "rewritten.zip"
    with zipfile.ZipFile(archive) as source, zipfile.ZipFile(rewritten, "w") as target:
        for info in source.infolist():
            data = source.read(info.filename)
            if info.filename == "manifest.json":
                manifest = json.loads(data)
                manifest["version"] = "999"
                data = json.dumps(manifest).encode()
            target.writestr(info.filename, data)
    with pytest.raises(LifecycleError, match="Unsupported"):
        restore(tmp_path / "manifest-target", rewritten)
    archive.unlink()
    rewritten.unlink()


def test_cli_parser_and_input_size_errors(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]
) -> None:
    from agent_vault.cli import UsageError, _memory_content, build_parser

    assert main(["record", "--unknown"]) == 2
    assert "unrecognized arguments" in capsys.readouterr().err
    initialize(tmp_path)
    oversized = tmp_path / "oversized.txt"
    oversized.write_text("x" * 1_048_577)
    assert main(["record", "--file", str(oversized), "--path", str(tmp_path)]) == 1
    assert "exceeds" in capsys.readouterr().err
    monkeypatch.setattr(
        Path, "read_text", lambda *args, **kwargs: (_ for _ in ()).throw(OSError("denied"))
    )
    readable = tmp_path / "readable.txt"
    readable.write_text("content")
    assert main(["record", "--file", str(readable), "--path", str(tmp_path)]) == 1
    assert "could not be read" in capsys.readouterr().err
    parser = build_parser()
    args = parser.parse_args(["record", "--stdin"])
    monkeypatch.setattr(sys, "stdin", __import__("io").StringIO("x" * 1_048_577))
    with pytest.raises(ValidationError, match="stdin"):
        _memory_content(args)
    with pytest.raises(UsageError, match="unknown"):
        from agent_vault.cli import run

        run(__import__("argparse").Namespace(command="unknown"))


def test_crypto_filesystem_failure_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_vault.crypto as crypto_module

    key = tmp_path / "key"
    key.write_bytes(b"key")
    key.chmod(0o600)
    with monkeypatch.context() as context:
        context.setattr(
            Path,
            "stat",
            lambda self, *args, **kwargs: (_ for _ in ()).throw(OSError("denied")),
        )
        with pytest.raises(EncryptionError, match="Unable to inspect"):
            crypto_module.load_key(key)

    existing = tmp_path / "existing"
    existing.write_bytes(b"x")
    with pytest.raises(FileExistsError, match="already exists"):
        crypto_module.create_key(existing)


def test_cli_module_entrypoint_version() -> None:
    env = os.environ.copy()
    env["PYTHONPATH"] = str(Path(__file__).parents[1] / "src")
    result = subprocess.run(
        [sys.executable, "-m", "agent_vault.cli", "--version"],
        env=env,
        text=True,
        capture_output=True,
        check=False,
    )
    assert result.returncode == 0
    assert "agent-vault" in result.stdout


def test_storage_write_and_migration_error_branches(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_vault.storage as storage_module

    class FailingConnection:
        def __enter__(self) -> FailingConnection:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, *args: object, **kwargs: object) -> None:
            raise sqlite3.DatabaseError("simulated")

    real_key = load_key(key_path(project))
    original_upgrade = storage_module.upgrade_schema
    monkeypatch.setattr(storage_module, "ensure_initialized", lambda root: None)
    monkeypatch.setattr(storage_module, "validate_memory", lambda memory: memory)
    monkeypatch.setattr(storage_module, "load_key", lambda path: real_key)
    monkeypatch.setattr(storage_module, "upgrade_schema", lambda root: None)
    monkeypatch.setattr(storage_module, "_connect", lambda path: FailingConnection())
    with pytest.raises(RepositoryError, match="write"):
        add_memory(project, make_memory("write-error"))
    monkeypatch.setattr(storage_module, "upgrade_schema", original_upgrade)
    with pytest.raises(RepositoryError, match="migration"):
        storage_module.upgrade_schema(project)


def test_storage_newer_schema_is_rejected(project: Path) -> None:
    import agent_vault.storage as storage_module

    class VersionConnection:
        def execute(self, query: str) -> object:
            class Row:
                def fetchone(self) -> dict[str, str]:
                    return {"value": "9.0"}

            return Row()

    with pytest.raises(RepositoryError, match="newer"):
        storage_module._check_supported_schema(VersionConnection())


def test_lifecycle_integrity_database_and_symlink_errors(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_vault.lifecycle as lifecycle_module

    monkeypatch.setattr(lifecycle_module, "ensure_initialized", lambda root: None)
    monkeypatch.setattr(lifecycle_module, "load_key", lambda path: b"key")
    monkeypatch.setattr(
        lifecycle_module,
        "_connect",
        lambda path: (_ for _ in ()).throw(sqlite3.DatabaseError("simulated")),
    )
    with pytest.raises(LifecycleError, match="integrity"):
        lifecycle_module._check_integrity(project)

    class Result:
        def __init__(self, value: object) -> None:
            self.value = value

        def fetchone(self) -> object:
            return self.value

        def fetchall(self) -> list[object]:
            return []

    class Connection:
        def __enter__(self) -> Connection:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, query: str, *args: object) -> Result:
            if "PRAGMA integrity_check" in query:
                return Result(("ok",))
            if "SELECT project_id" in query:
                return Result({"created_at": "2026-01-01T00:00:00Z"})
            return Result(None)

    monkeypatch.setattr(lifecycle_module, "_connect", lambda path: Connection())
    monkeypatch.setattr(lifecycle_module, "_schema_version", lambda connection: "9.0")
    with pytest.raises(LifecycleError, match="Unsupported"):
        lifecycle_module._check_integrity(project)

    monkeypatch.setattr(lifecycle_module, "repository_dir", lambda root: project / "missing-link")
    (project / "missing-link").symlink_to(project, target_is_directory=True)
    monkeypatch.setattr(lifecycle_module, "_schema_version", lambda connection: "1.1")
    with pytest.raises(LifecycleError, match="symlink"):
        lifecycle_module._check_integrity(project)


def test_lifecycle_status_rejects_unsafe_storage_path(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_vault.lifecycle as lifecycle_module

    storage_file = project / "storage-file"
    storage_file.write_text("bad")
    monkeypatch.setattr(lifecycle_module, "repository_dir", lambda root: storage_file)
    with pytest.raises(LifecycleError, match="safe directory"):
        lifecycle_module.status(project)


def test_indexed_filters_and_offset_pagination(project: Path) -> None:
    import agent_vault.storage as storage_module
    from agent_vault.crypto import load_key, search_token

    add_memory(project, make_memory("a", kind="decision", tags=("shared",)))
    add_memory(project, make_memory("b", kind="fact", tags=("shared",)))
    add_memory(project, make_memory("c", kind="decision", tags=("other",)))
    page = list_memories(project, kind="decision", limit=1, offset=1)
    assert [memory.id for memory in page] == ["a"]
    with pytest.raises(RepositoryError, match="offset"):
        list_memories(project, offset=-1)
    key = load_key(key_path(project))
    kind_token = search_token(key, "decision")
    tag_token = search_token(key, "shared")
    with storage_module._connect(database_path(project)) as connection:
        kind_plan = " ".join(
            str(row[3])
            for row in connection.execute(
                "EXPLAIN QUERY PLAN SELECT id FROM memories WHERE kind_token = ?",
                (kind_token,),
            ).fetchall()
        )
        tag_plan = " ".join(
            str(row[3])
            for row in connection.execute(
                "EXPLAIN QUERY PLAN SELECT memory_id FROM memory_tags WHERE tag_token = ?",
                (tag_token,),
            ).fetchall()
        )
    assert "memories_kind_token_idx" in kind_plan
    assert "memory_tags_tag_token_idx" in tag_plan


def test_interrupted_rotation_prepared_state_is_recovered(project: Path) -> None:
    import shutil

    from agent_vault.storage import ensure_initialized

    add_memory(project, make_memory("recover"))
    storage = project / ".agentvault"
    journal = storage / ".rotation-interrupted"
    journal.mkdir(mode=0o700)
    shutil.copy2(database_path(project), journal / "old.db")
    shutil.copy2(key_path(project), journal / "old.key")
    (journal / "journal.json").write_text(
        json.dumps({"state": "prepared", "created_at": utc_now(), "memory_count": 1}),
        encoding="utf-8",
    )
    database_path(project).unlink()
    key_path(project).unlink()
    ensure_initialized(project)
    assert fetch_state(project).memories[0].id == "recover"
    assert not journal.exists()


def test_invalid_rotation_journal_fails_closed(project: Path) -> None:
    from agent_vault.storage import ensure_initialized

    journal = project / ".agentvault" / ".rotation-invalid"
    journal.mkdir(mode=0o700)
    (journal / "journal.json").write_text("{}", encoding="utf-8")
    with pytest.raises(RepositoryError, match="journal is invalid"):
        ensure_initialized(project)


def test_archive_rejects_traversal_and_duplicate_members(project: Path, tmp_path: Path) -> None:
    archive = tmp_path / "valid.zip"
    backup(project, archive)
    traversal = tmp_path / "traversal.zip"
    with zipfile.ZipFile(traversal, "w") as bundle:
        bundle.writestr("../escape", b"bad")
        bundle.writestr("manifest.json", b"{}")
        bundle.writestr("context.db", b"bad")
        bundle.writestr("context.key", b"bad")
    with pytest.raises(LifecycleError, match="unexpected"):
        restore(tmp_path / "traversal-target", traversal)
    duplicate = tmp_path / "duplicate.zip"
    with zipfile.ZipFile(archive) as source, zipfile.ZipFile(duplicate, "w") as target:
        for info in source.infolist():
            target.writestr(info, source.read(info.filename))
        target.writestr("manifest.json", source.read("manifest.json"))
    with pytest.raises(LifecycleError, match="duplicate"):
        restore(tmp_path / "duplicate-target", duplicate)


def test_key_validation_regular_file_and_stat_failure(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_vault.crypto as crypto_module

    directory = tmp_path / "key-directory"
    directory.mkdir()
    with pytest.raises(EncryptionError, match="regular file"):
        load_key(directory)
    key = tmp_path / "key"
    create_key(key)
    original_stat = crypto_module.Path.stat
    monkeypatch.setattr(
        crypto_module.Path,
        "stat",
        lambda self, *args, **kwargs: (_ for _ in ()).throw(OSError("denied")),
    )
    with pytest.raises(EncryptionError, match="Unable to inspect"):
        crypto_module._validate_key_permissions(key)
    monkeypatch.setattr(crypto_module.Path, "stat", original_stat)


def test_lifecycle_helper_failure_boundaries(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_vault.lifecycle as lifecycle_module

    missing = tmp_path / "missing"
    with pytest.raises(LifecycleError, match="inspect"):
        lifecycle_module._sha256(missing)
    with pytest.raises(ValidationError, match="storage directory"):
        lifecycle_module._secure_directory(tmp_path / "link") if (tmp_path / "link").symlink_to(
            tmp_path, target_is_directory=True
        ) is None else None
    target = tmp_path / "journal.json"
    monkeypatch.setattr(
        lifecycle_module.os, "replace", lambda *args: (_ for _ in ()).throw(OSError("denied"))
    )
    with pytest.raises(LifecycleError, match="journal"):
        lifecycle_module._write_json_atomic(target, {"state": "prepared"})


def test_restore_rejects_archive_parent_symlink(project: Path, tmp_path: Path) -> None:
    archive = tmp_path / "backup.zip"
    backup(project, archive)
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    alias = tmp_path / "alias"
    alias.symlink_to(real_parent, target_is_directory=True)
    with pytest.raises(ValidationError, match="archive parent"):
        restore(tmp_path / "restore-target", alias / "backup.zip")


def test_repository_lock_rejects_uninitialized_path(tmp_path: Path) -> None:
    from agent_vault.storage import repository_lock

    with pytest.raises(RepositoryError, match="not initialized"):
        with repository_lock(tmp_path):
            pass


def test_storage_durability_and_schema_failure_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_vault.storage as storage_module

    with monkeypatch.context() as context:
        with pytest.raises(RepositoryError, match="durably"):
            context.setattr(
                storage_module.os,
                "open",
                lambda *args, **kwargs: (_ for _ in ()).throw(OSError("denied")),
            )
            storage_module._fsync_directory(tmp_path)
    with pytest.raises(RepositoryError, match="not a directory"):
        file_path = tmp_path / "file"
        file_path.write_text("x")
        storage_module._ensure_secure_dir(file_path)
    with pytest.raises(RepositoryError, match="Unsupported"):
        storage_module._check_supported_schema(
            type(
                "Connection",
                (),
                {
                    "execute": lambda self, query: type(
                        "Row", (), {"fetchone": lambda self: {"value": "0.9"}}
                    )()
                },
            )()
        )
    repo_root = tmp_path / "repo"
    repo_root.mkdir()
    initialize(repo_root)
    with pytest.raises(RepositoryError, match="kind"):
        storage_module._filter_values(load_key(key_path(repo_root)), "bad", None)


def test_storage_metadata_and_read_failure_branches(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_vault.storage as storage_module

    with pytest.raises(RepositoryError, match="invalid"):
        storage_module._validate_project_row(
            {
                "project_id": "",
                "name": "Project",
                "root_path": str(project),
                "created_at": utc_now(),
            }
        )
    with pytest.raises(RepositoryError, match="tag"):
        storage_module._filter_values(load_key(key_path(project)), None, "\x00bad")

    class BrokenConnection:
        def __enter__(self) -> BrokenConnection:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, *args: object, **kwargs: object) -> object:
            raise sqlite3.DatabaseError("read failure")

    monkeypatch.setattr(storage_module, "ensure_initialized", lambda root: None)
    monkeypatch.setattr(storage_module, "upgrade_schema", lambda root: None)
    monkeypatch.setattr(storage_module, "load_key", lambda path: b"key")
    monkeypatch.setattr(storage_module, "_filter_values", lambda *args: (None, None))
    monkeypatch.setattr(storage_module, "_connect", lambda path: BrokenConnection())
    with pytest.raises(RepositoryError, match="read"):
        storage_module.list_memories(project)


def test_rotation_recovery_rejects_unsafe_and_committed_journals(project: Path) -> None:
    from agent_vault.storage import ensure_initialized

    unsafe = project / ".agentvault" / ".rotation-unsafe"
    unsafe.mkdir(mode=0o700)
    (unsafe / "journal.json").write_text(json.dumps({"state": "committed"}), encoding="utf-8")
    (unsafe / "old.db").symlink_to(database_path(project))
    with pytest.raises(ValidationError, match="key rotation file"):
        ensure_initialized(project)
    (unsafe / "old.db").unlink()
    (unsafe / "journal.json").write_text(json.dumps({"state": "committed"}), encoding="utf-8")
    ensure_initialized(project)
    assert not unsafe.exists()


def test_lifecycle_integrity_detects_row_mismatch_and_bad_ciphertext(project: Path) -> None:
    add_memory(project, make_memory("mismatch"))
    connection = sqlite3.connect(database_path(project))
    connection.execute(
        "UPDATE memories SET created_at = '2020-01-01T00:00:00Z' WHERE id = 'mismatch'"
    )
    connection.commit()
    connection.close()
    with pytest.raises(LifecycleError, match="timestamp"):
        verify(project)
    connection = sqlite3.connect(database_path(project))
    connection.execute(
        "UPDATE memories SET created_at = '2026-01-01T00:00:00Z', "
        "payload = ? WHERE id = 'mismatch'",
        (b"broken",),
    )
    connection.commit()
    connection.close()
    with pytest.raises(LifecycleError, match="failed integrity"):
        verify(project)


def test_lifecycle_snapshot_and_checkpoint_failures(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_vault.lifecycle as lifecycle_module

    class BrokenConnection:
        def __enter__(self) -> BrokenConnection:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, *args: object, **kwargs: object) -> object:
            raise sqlite3.DatabaseError("checkpoint failure")

    monkeypatch.setattr(lifecycle_module, "_connect", lambda path: BrokenConnection())
    with pytest.raises(LifecycleError, match="checkpoint"):
        lifecycle_module._checkpoint_database(tmp_path / "db")

    class SourceConnection:
        def __enter__(self) -> SourceConnection:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, *args: object, **kwargs: object) -> SourceConnection:
            return self

        def backup(self, target: object) -> None:
            raise sqlite3.DatabaseError("backup failure")

        def rollback(self) -> None:
            return None

        def commit(self) -> None:
            return None

    class TargetConnection:
        def close(self) -> None:
            return None

    monkeypatch.setattr(lifecycle_module, "_connect", lambda path: SourceConnection())
    monkeypatch.setattr(
        lifecycle_module.sqlite3,
        "connect",
        lambda path, timeout=5.0: TargetConnection(),
    )
    with pytest.raises(sqlite3.DatabaseError, match="backup"):
        lifecycle_module._sqlite_snapshot_unlocked(project, tmp_path / "snapshot.db")


def test_restore_rolls_back_existing_repository_on_post_install_failure(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_vault.lifecycle as lifecycle_module

    original_name = fetch_state(project).project["name"]
    archive = tmp_path / "rollback.zip"
    backup(project, archive)
    monkeypatch.setattr(
        lifecycle_module,
        "_check_integrity",
        lambda root: (_ for _ in ()).throw(LifecycleError("post-install verification failure")),
    )
    with pytest.raises(LifecycleError, match="post-install"):
        restore(project, archive, overwrite=True)
    assert fetch_state(project).project["name"] == original_name


def test_restore_rejects_unsafe_archive_member_mode(project: Path, tmp_path: Path) -> None:
    archive = tmp_path / "unsafe-mode.zip"
    with zipfile.ZipFile(archive, "w") as bundle:
        info = zipfile.ZipInfo("manifest.json")
        info.external_attr = stat.S_IFLNK << 16
        bundle.writestr(info, b"{}")
    with pytest.raises(LifecycleError, match="unexpected|unsafe|missing"):
        restore(tmp_path / "unsafe-target", archive)


def test_lifecycle_directory_sidecar_and_integrity_failures(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_vault.lifecycle as lifecycle_module

    bad_dir = tmp_path / "bad-dir"
    original_mkdir = Path.mkdir
    monkeypatch.setattr(
        Path,
        "mkdir",
        lambda self, *args, **kwargs: (
            (_ for _ in ()).throw(OSError("denied"))
            if self == bad_dir
            else original_mkdir(self, *args, **kwargs)
        ),
    )
    with pytest.raises(LifecycleError, match="storage directory"):
        lifecycle_module._secure_directory(bad_dir)
    monkeypatch.setattr(Path, "mkdir", original_mkdir)

    copied_db = tmp_path / "checkpoint.db"
    copied_db.write_bytes(database_path(project).read_bytes())
    sidecar = Path(f"{copied_db}-wal")
    sidecar.write_bytes(b"sidecar")
    original_unlink = Path.unlink
    monkeypatch.setattr(
        Path,
        "unlink",
        lambda self, *args, **kwargs: (
            (_ for _ in ()).throw(OSError("locked"))
            if self == sidecar
            else original_unlink(self, *args, **kwargs)
        ),
    )
    with pytest.raises(LifecycleError, match="sidecar"):
        lifecycle_module._checkpoint_database(copied_db)

    key = key_path(project)
    key.unlink()
    with pytest.raises(LifecycleError, match="incomplete"):
        verify(project)


def test_lifecycle_integrity_and_repository_validation_branches(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import shutil

    import agent_vault.lifecycle as lifecycle_module

    add_memory(project, make_memory("validation"))
    with pytest.raises(LifecycleError, match="invalid or unreadable"):
        invalid_key = tmp_path / "invalid.key"
        invalid_key.write_bytes(b"bad")
        invalid_key.chmod(0o600)
        lifecycle_module._validate_repository_files(database_path(project), invalid_key)

    class FakeRow:
        def __init__(self, value: str) -> None:
            self.value = value

        def __getitem__(self, key: object) -> str:
            return self.value

    class FakeConnection:
        def __init__(self, value: str) -> None:
            self.value = value

        def __enter__(self) -> FakeConnection:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, query: str, params: object = ()) -> FakeConnection:
            return self

        def fetchone(self) -> FakeRow:
            return FakeRow(self.value)

    monkeypatch.setattr(lifecycle_module, "_connect", lambda path: FakeConnection("bad"))
    with pytest.raises(LifecycleError, match="integrity"):
        lifecycle_module._validate_repository_files(database_path(project), key_path(project))
    monkeypatch.setattr(lifecycle_module, "_connect", lambda path: FakeConnection("ok"))
    monkeypatch.setattr(lifecycle_module, "_schema_version", lambda connection: "1.0")
    with pytest.raises(LifecycleError, match="migrated"):
        lifecycle_module._validate_repository_files(database_path(project), key_path(project))
    monkeypatch.undo()

    lifecycle_module._checkpoint_database(database_path(project))
    copied = tmp_path / "copy.db"
    copied_key = tmp_path / "copy.key"
    shutil.copy2(database_path(project), copied)
    shutil.copy2(key_path(project), copied_key)
    connection = sqlite3.connect(copied)
    connection.execute("UPDATE memories SET created_at = '2020-01-01T00:00:00Z'")
    connection.commit()
    connection.close()
    with pytest.raises(LifecycleError, match="timestamp"):
        lifecycle_module._validate_repository_files(copied, copied_key)
    shutil.copy2(database_path(project), copied)
    with pytest.raises(LifecycleError, match="manifest"):
        lifecycle_module._validate_repository_files(copied, copied_key, {"project_id": "wrong"})


def test_archive_manifest_validation_errors(project: Path, tmp_path: Path) -> None:
    source = tmp_path / "source.zip"
    backup(project, source)
    cases = (
        ({"format": "wrong"}, "Unsupported"),
        ({"memory_count": -1}, "memory count"),
        ({"created_at": "invalid"}, "timestamp"),
        ({"database_sha256": "not-a-digest"}, "integrity metadata"),
    )
    for index, (changes, message) in enumerate(cases):
        target = tmp_path / f"invalid-{index}.zip"
        with zipfile.ZipFile(source) as bundle, zipfile.ZipFile(target, "w") as output:
            manifest = json.loads(bundle.read("manifest.json"))
            manifest.update(changes)
            output.writestr("manifest.json", json.dumps(manifest))
            output.writestr("context.db", bundle.read("context.db"))
            output.writestr("context.key", bundle.read("context.key"))
        with pytest.raises(LifecycleError, match=message):
            restore(tmp_path / f"target-{index}", target)


def test_restore_missing_archive_and_memory_count_mismatch(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_vault.lifecycle as lifecycle_module

    with pytest.raises(LifecycleError, match="does not exist"):
        restore(tmp_path / "missing-target", tmp_path / "missing.zip")
    archive = tmp_path / "count.zip"
    backup(project, archive)
    monkeypatch.setattr(lifecycle_module, "_check_integrity", lambda root: {"memory_count": 1})
    with pytest.raises(LifecycleError, match="memory count"):
        restore(tmp_path / "count-target", archive)


def test_key_rotation_failure_before_and_after_journal(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_vault.lifecycle as lifecycle_module

    monkeypatch.setattr(
        lifecycle_module,
        "_secure_directory",
        lambda path: (_ for _ in ()).throw(OSError("cannot stage")),
    )
    with pytest.raises(LifecycleError, match="Key rotation failed"):
        rotate_key(project)
    monkeypatch.undo()
    original_write = lifecycle_module._write_json_atomic
    calls = 0

    def fail_second(path: Path, value: dict[str, object]) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("journal write failed")
        original_write(path, value)

    monkeypatch.setattr(lifecycle_module, "_write_json_atomic", fail_second)
    with pytest.raises(LifecycleError, match="Key rotation failed"):
        rotate_key(project)


def test_remaining_key_and_storage_validation_branches(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_vault.crypto as crypto_module
    import agent_vault.storage as storage_module

    directory = tmp_path / "directory-key"
    directory.mkdir()
    with pytest.raises(EncryptionError, match="regular file"):
        crypto_module._validate_key_permissions(directory)
    file_path = tmp_path / "not-directory"
    file_path.write_text("x")
    with pytest.raises(RepositoryError, match="not a directory"):
        storage_module._ensure_secure_dir(file_path)
    storage = tmp_path / ".agentvault"
    storage.mkdir()
    journal = storage / ".rotation-invalid"
    journal.mkdir()
    (journal / "journal.json").write_text("not-json", encoding="utf-8")
    with pytest.raises(RepositoryError, match="journal is invalid"):
        storage_module._recover_pending_rotations(tmp_path)


def test_ensure_initialized_reports_invalid_persisted_metadata(project: Path) -> None:
    connection = sqlite3.connect(database_path(project))
    connection.execute("UPDATE project SET name = '' WHERE id = 1")
    connection.commit()
    connection.close()
    with pytest.raises(RepositoryError, match="Project metadata is invalid"):
        from agent_vault.storage import ensure_initialized

        ensure_initialized(project)


def test_integrity_and_repository_database_error_boundaries(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_vault.lifecycle as lifecycle_module

    class IntegrityResult:
        def __init__(self, row: object | None = None, rows: list[object] | None = None) -> None:
            self.row = row
            self.rows = rows or []

        def fetchone(self) -> object | None:
            return self.row

        def fetchall(self) -> list[object]:
            return self.rows

    class IntegrityConnection:
        def __enter__(self) -> IntegrityConnection:
            return self

        def __exit__(self, *args: object) -> None:
            return None

        def execute(self, query: str, *args: object, **kwargs: object) -> IntegrityResult:
            if "integrity_check" in query:
                return IntegrityResult(("not-ok",))
            if "FROM project" in query:
                return IntegrityResult(
                    {
                        "project_id": "project",
                        "name": "Project",
                        "root_path": str(project),
                        "created_at": utc_now(),
                    }
                )
            return IntegrityResult(rows=[])

    monkeypatch.setattr(lifecycle_module, "_schema_version", lambda connection: "1.1")
    monkeypatch.setattr(lifecycle_module, "_connect", lambda path: IntegrityConnection())
    with pytest.raises(LifecycleError, match="integrity check failed"):
        verify(project)
    monkeypatch.setattr(
        lifecycle_module,
        "_connect",
        lambda path: (_ for _ in ()).throw(sqlite3.DatabaseError("database failure")),
    )
    with pytest.raises(LifecycleError, match="integrity"):
        lifecycle_module._validate_repository_files(database_path(project), key_path(project))


def test_backup_and_restore_path_boundaries(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_vault.lifecycle as lifecycle_module

    alias = tmp_path / "alias"
    alias.mkdir()
    archive = tmp_path / "archive.zip"
    real_parent = tmp_path / "real-parent"
    real_parent.mkdir()
    alias.rmdir()
    alias.symlink_to(real_parent, target_is_directory=True)
    monkeypatch.setattr(
        lifecycle_module, "validate_archive_path", lambda path: alias / "backup.zip"
    )
    monkeypatch.setattr(lifecycle_module, "upgrade_schema", lambda root: {"status": "migrated"})
    monkeypatch.setattr(lifecycle_module, "verify", lambda root: {"status": "ok"})
    with pytest.raises(LifecycleError, match="destination directory"):
        lifecycle_module.backup(project, archive)
    monkeypatch.undo()
    valid = tmp_path / "valid.zip"
    backup(project, valid)
    destination = tmp_path / "destination"
    destination.mkdir()
    (destination / ".agentvault").symlink_to(project / ".agentvault", target_is_directory=True)
    with pytest.raises(LifecycleError, match="must not be a symlink"):
        restore(destination, valid, overwrite=True)


def test_archive_unsafe_member_and_manifest_field_validation(project: Path, tmp_path: Path) -> None:
    source = tmp_path / "source.zip"
    backup(project, source)
    with zipfile.ZipFile(source) as bundle:
        payloads = {name: bundle.read(name) for name in bundle.namelist()}
    unsafe = tmp_path / "unsafe.zip"
    with zipfile.ZipFile(unsafe, "w") as bundle:
        for name, payload in payloads.items():
            info = zipfile.ZipInfo(name)
            if name == "context.db":
                info.external_attr = stat.S_IFLNK << 16
            bundle.writestr(info, payload)
    with pytest.raises(LifecycleError, match="unsafe member"):
        restore(tmp_path / "unsafe-target", unsafe)
    invalid_field = tmp_path / "missing-field.zip"
    manifest = json.loads(payloads["manifest.json"])
    del manifest["database_sha256"]
    with zipfile.ZipFile(invalid_field, "w") as bundle:
        bundle.writestr("manifest.json", json.dumps(manifest))
        bundle.writestr("context.db", payloads["context.db"])
        bundle.writestr("context.key", payloads["context.key"])
    with pytest.raises(LifecycleError, match="required integrity"):
        restore(tmp_path / "missing-field-target", invalid_field)


def test_rotation_recovery_manual_intervention_error(
    project: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_vault.lifecycle as lifecycle_module
    import agent_vault.storage as storage_module

    original_write = lifecycle_module._write_json_atomic
    calls = 0

    def fail_after_prepare(path: Path, value: dict[str, object]) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("journal failure")
        original_write(path, value)

    monkeypatch.setattr(lifecycle_module, "_write_json_atomic", fail_after_prepare)
    monkeypatch.setattr(lifecycle_module, "ensure_initialized", lambda root: None)
    monkeypatch.setattr(lifecycle_module, "upgrade_schema", lambda root: {"status": "migrated"})
    monkeypatch.setattr(
        storage_module,
        "_recover_pending_rotations",
        lambda root: (_ for _ in ()).throw(OSError("recovery failure")),
    )
    with pytest.raises(LifecycleError, match="manual intervention"):
        rotate_key(project)


def test_final_crypto_path_and_lock_failure_branches(
    project: Path, tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    import agent_vault.crypto as crypto_module
    import agent_vault.storage as storage_module

    key = tmp_path / "key"
    key.write_bytes(b"key")
    key.chmod(0o600)
    with monkeypatch.context() as context:
        context.setattr(Path, "is_symlink", lambda self: False)
        context.setattr(
            Path,
            "stat",
            lambda self, *args, **kwargs: (
                (_ for _ in ()).throw(OSError("stat denied"))
                if self == key
                else Path.stat(self, *args, **kwargs)
            ),
        )
        with pytest.raises(EncryptionError, match="Unable to inspect encryption key"):
            crypto_module._validate_key_permissions(key)

    with pytest.raises(ValidationError, match="restore parent"):
        normalize_root(tmp_path / "missing" / "repository", must_exist=False)

    with monkeypatch.context() as context:
        context.setattr(
            storage_module.os,
            "open",
            lambda *args, **kwargs: (_ for _ in ()).throw(OSError("locked")),
        )
        with pytest.raises(RepositoryError, match="acquire"):
            with storage_module.repository_lock(project):
                pass

    original_flock = storage_module.fcntl.flock
    calls = 0

    def fail_release(fd: int, operation: int) -> None:
        nonlocal calls
        calls += 1
        if calls == 2:
            raise OSError("unlock denied")
        original_flock(fd, operation)

    monkeypatch.setattr(storage_module.fcntl, "flock", fail_release)
    with pytest.raises(RepositoryError, match="release"):
        with storage_module.repository_lock(project):
            pass
