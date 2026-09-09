"""Command-line interface for Agent-Vault."""

from __future__ import annotations

import argparse
import json
import sys
import uuid
from pathlib import Path
from typing import NoReturn

from . import __version__
from .crypto import EncryptionError
from .lifecycle import LifecycleError, backup, migrate, restore, rotate_key, status, verify
from .models import MEMORY_KINDS, SENSITIVITY_LEVELS, Memory, utc_now
from .storage import RepositoryError, add_memory, fetch_state, initialize
from .validation import (
    MAX_CONTENT_LENGTH,
    ValidationError,
    normalize_root,
    reject_symlink,
    validate_content,
    validate_project_name,
    validate_source,
    validate_tags,
)


class UsageError(ValueError):
    """Raised for malformed command-line arguments."""


class AgentVaultArgumentParser(argparse.ArgumentParser):
    """Argument parser that lets the CLI keep operational errors machine-safe."""

    def error(self, message: str) -> NoReturn:
        raise UsageError(message)


def _read_file_content(path_value: str) -> str:
    path = Path(path_value).expanduser()
    reject_symlink(path, "content file")
    if not path.is_file():
        raise ValidationError("content file must be an existing regular file")
    if path.stat().st_size > MAX_CONTENT_LENGTH:
        raise ValidationError(f"content file exceeds {MAX_CONTENT_LENGTH} bytes")
    try:
        return validate_content(path.read_text(encoding="utf-8"))
    except UnicodeDecodeError as exc:
        raise ValidationError("content file must be valid UTF-8") from exc
    except OSError as exc:
        raise ValidationError("content file could not be read") from exc


def build_parser() -> argparse.ArgumentParser:
    parser = AgentVaultArgumentParser(
        prog="agent-vault",
        description="A local-first encrypted memory layer for AI agent project context.",
    )
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    subparsers = parser.add_subparsers(
        dest="command", required=True, parser_class=AgentVaultArgumentParser
    )

    init_parser = subparsers.add_parser(
        "init", help="Initialize Agent-Vault in a project directory"
    )
    init_parser.add_argument("path", nargs="?", default=".", help="Project directory")
    init_parser.add_argument("--name", help="Human-readable project name")

    record_parser = subparsers.add_parser("record", help="Store an encrypted project memory")
    record_parser.add_argument("content", nargs="?", help="Memory content")
    content_input = record_parser.add_mutually_exclusive_group()
    content_input.add_argument(
        "--stdin", action="store_true", help="Read memory content from stdin"
    )
    content_input.add_argument("--file", help="Read memory content from a UTF-8 file")
    record_parser.add_argument("--kind", choices=MEMORY_KINDS, default="note")
    record_parser.add_argument(
        "--tag", action="append", default=[], help="Tag; repeat for multiple tags"
    )
    record_parser.add_argument("--source", help="Origin of the memory")
    record_parser.add_argument("--sensitivity", choices=SENSITIVITY_LEVELS, default="normal")
    record_parser.add_argument("--path", default=".", help="Project directory")

    fetch_parser = subparsers.add_parser("fetch", help="Retrieve project state as JSON")
    fetch_parser.add_argument("path", nargs="?", default=".", help="Project directory")
    fetch_parser.add_argument("--kind", choices=MEMORY_KINDS)
    fetch_parser.add_argument("--tag")
    fetch_parser.add_argument("--limit", type=int)
    fetch_parser.add_argument("--offset", type=int, default=0)
    fetch_parser.add_argument("--pretty", action="store_true", help="Indent JSON")

    for command, help_text in (
        ("status", "Show repository health without decrypting memories"),
        ("verify", "Verify the key, schema, database, and encrypted payloads"),
        ("migrate", "Migrate an older Agent-Vault database schema"),
        ("rotate-key", "Re-encrypt all memories with a newly generated key"),
    ):
        lifecycle_parser = subparsers.add_parser(command, help=help_text)
        lifecycle_parser.add_argument("path", nargs="?", default=".", help="Project directory")

    backup_parser = subparsers.add_parser(
        "backup", help="Create a consistent encrypted repository backup"
    )
    backup_parser.add_argument("archive", help="Destination ZIP archive")
    backup_parser.add_argument("--path", default=".", help="Project directory")
    backup_parser.add_argument("--force", action="store_true", help="Overwrite an existing archive")

    restore_parser = subparsers.add_parser("restore", help="Restore a repository from a backup")
    restore_parser.add_argument("archive", help="Source ZIP archive")
    restore_parser.add_argument("--path", default=".", help="Project directory")
    restore_parser.add_argument(
        "--force", action="store_true", help="Replace an existing repository"
    )
    return parser


def _memory_content(args: argparse.Namespace) -> str:
    inputs = int(args.content is not None) + int(args.stdin) + int(args.file is not None)
    if inputs != 1:
        raise UsageError("record requires exactly one of CONTENT, --stdin, or --file")
    if args.stdin:
        content = sys.stdin.read(MAX_CONTENT_LENGTH + 1)
        if len(content) > MAX_CONTENT_LENGTH:
            raise ValidationError(f"stdin content exceeds {MAX_CONTENT_LENGTH} characters")
        return validate_content(content)
    if args.file:
        return _read_file_content(args.file)
    return validate_content(args.content)


def _emit(value: object, *, pretty: bool = False) -> None:
    print(json.dumps(value, indent=2 if pretty else None, ensure_ascii=False))


def run(args: argparse.Namespace) -> int:
    if args.command == "init":
        project = initialize(normalize_root(Path(args.path)), validate_project_name(args.name))
        _emit({"status": "initialized", "project": project}, pretty=True)
        return 0

    if args.command == "record":
        content = _memory_content(args)
        memory = Memory(
            id=str(uuid.uuid4()),
            kind=args.kind,
            content=content,
            tags=validate_tags(args.tag),
            source=validate_source(args.source),
            sensitivity=args.sensitivity,
            created_at=utc_now(),
        )
        add_memory(normalize_root(Path(args.path)), memory)
        _emit({"status": "recorded", "memory": memory.to_dict()}, pretty=True)
        return 0

    if args.command == "fetch":
        state = fetch_state(
            normalize_root(Path(args.path)),
            kind=args.kind,
            tag=args.tag,
            limit=args.limit,
            offset=args.offset,
        )
        _emit(state.to_dict(), pretty=args.pretty)
        return 0

    if args.command == "status":
        _emit(status(normalize_root(Path(args.path))), pretty=True)
        return 0
    if args.command == "verify":
        _emit(verify(normalize_root(Path(args.path))), pretty=True)
        return 0
    if args.command == "migrate":
        _emit(migrate(normalize_root(Path(args.path))), pretty=True)
        return 0
    if args.command == "rotate-key":
        _emit(rotate_key(normalize_root(Path(args.path))), pretty=True)
        return 0
    if args.command == "backup":
        _emit(
            backup(
                normalize_root(Path(args.path)),
                Path(args.archive).expanduser(),
                overwrite=args.force,
            ),
            pretty=True,
        )
        return 0
    if args.command == "restore":
        _emit(
            restore(
                normalize_root(Path(args.path), must_exist=False),
                Path(args.archive).expanduser(),
                overwrite=args.force,
            ),
            pretty=True,
        )
        return 0
    raise UsageError(f"unknown command: {args.command}")


def main(argv: list[str] | None = None) -> int:
    try:
        args = build_parser().parse_args(argv)
        return run(args)
    except UsageError as exc:
        print(f"agent-vault: error: {exc}", file=sys.stderr)
        return 2
    except (
        RepositoryError,
        LifecycleError,
        EncryptionError,
        ValidationError,
        OSError,
    ) as exc:
        print(f"agent-vault: error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
