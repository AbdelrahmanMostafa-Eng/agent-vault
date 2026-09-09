"""Validation and path-safety primitives shared by the CLI and storage layer."""

from __future__ import annotations

import re
from datetime import datetime
from pathlib import Path

from .models import MEMORY_KINDS, SENSITIVITY_LEVELS, Memory

MAX_PROJECT_NAME = 200
MAX_CONTENT_LENGTH = 1_048_576
MAX_TAGS = 32
MAX_TAG_LENGTH = 64
MAX_SOURCE_LENGTH = 512
MAX_MEMORY_ID_LENGTH = 128
MAX_ARCHIVE_MEMBER_SIZE = 100 * 1024 * 1024

_CONTROL_CHARS = re.compile(r"[\x00-\x1f\x7f]")
_CONTENT_CONTROL_CHARS = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SAFE_ID = re.compile(r"^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$")


class ValidationError(ValueError):
    """Raised when a user or persisted value violates the public contract."""


def _text(
    value: object,
    field: str,
    *,
    max_length: int,
    required: bool = True,
    multiline: bool = False,
) -> str:
    if not isinstance(value, str):
        raise ValidationError(f"{field} must be text")
    control_chars = _CONTENT_CONTROL_CHARS if multiline else _CONTROL_CHARS
    if control_chars.search(value):
        raise ValidationError(f"{field} contains unsupported control characters")
    if required and not value.strip():
        raise ValidationError(f"{field} must not be empty")
    if len(value) > max_length:
        raise ValidationError(f"{field} exceeds the maximum length of {max_length} characters")
    return value


def validate_project_name(name: str | None) -> str | None:
    if name is None:
        return None
    return _text(name, "project name", max_length=MAX_PROJECT_NAME).strip()


def validate_content(content: str) -> str:
    return _text(content, "content", max_length=MAX_CONTENT_LENGTH, multiline=True)


def validate_source(source: str | None) -> str | None:
    if source is None:
        return None
    return _text(source, "source", max_length=MAX_SOURCE_LENGTH).strip()


def validate_tags(tags: tuple[str, ...] | list[str]) -> tuple[str, ...]:
    if not isinstance(tags, (tuple, list)):
        raise ValidationError("tags must be a list of text values")
    if len(tags) > MAX_TAGS:
        raise ValidationError(f"tags cannot contain more than {MAX_TAGS} values")
    result: list[str] = []
    seen: set[str] = set()
    for tag in tags:
        normalized = _text(tag, "tag", max_length=MAX_TAG_LENGTH).strip().lower()
        if normalized not in seen:
            result.append(normalized)
            seen.add(normalized)
    return tuple(result)


def validate_timestamp(value: str, field: str = "timestamp") -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError(f"{field} must be an ISO-8601 timestamp")
    normalized = value.strip()
    try:
        parsed = datetime.fromisoformat(normalized.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValidationError(f"{field} must be an ISO-8601 timestamp") from exc
    if parsed.tzinfo is None:
        raise ValidationError(f"{field} must include a timezone")
    return normalized


def validate_memory(memory: Memory) -> Memory:
    if not isinstance(memory, Memory):
        raise ValidationError("memory must be a Memory object")
    if not isinstance(memory.id, str) or not _SAFE_ID.fullmatch(memory.id):
        raise ValidationError("memory id contains unsupported characters")
    if memory.kind not in MEMORY_KINDS:
        raise ValidationError(f"kind must be one of: {', '.join(MEMORY_KINDS)}")
    if memory.sensitivity not in SENSITIVITY_LEVELS:
        raise ValidationError(f"sensitivity must be one of: {', '.join(SENSITIVITY_LEVELS)}")
    validate_content(memory.content)
    validate_tags(memory.tags)
    validate_source(memory.source)
    validate_timestamp(memory.created_at, "memory created_at")
    return Memory(
        id=memory.id,
        kind=memory.kind,
        content=memory.content,
        tags=validate_tags(memory.tags),
        source=validate_source(memory.source),
        sensitivity=memory.sensitivity,
        created_at=memory.created_at,
    )


def validate_memory_dict(data: object) -> Memory:
    if not isinstance(data, dict):
        raise ValidationError("memory payload must be a JSON object")
    try:
        memory = Memory(
            id=data["id"],
            kind=data["kind"],
            content=data["content"],
            tags=tuple(data.get("tags", [])),
            source=data.get("source"),
            sensitivity=data.get("sensitivity", "normal"),
            created_at=data["created_at"],
        )
    except (KeyError, TypeError) as exc:
        raise ValidationError("memory payload is missing required fields") from exc
    return validate_memory(memory)


def normalize_root(value: Path, *, must_exist: bool = True) -> Path:
    """Resolve a project path while rejecting symlinks and unsafe restore targets."""
    candidate = Path(value).expanduser()
    if candidate.is_symlink():
        raise ValidationError("project path must not be a symlink")
    try:
        root = candidate.resolve(strict=must_exist)
    except OSError as exc:
        raise ValidationError("project path cannot be resolved") from exc
    if must_exist and not root.is_dir():
        raise ValidationError("project path must be an existing directory")
    if not must_exist:
        for ancestor in (candidate.parent, *candidate.parent.parents):
            if ancestor.is_symlink():
                raise ValidationError("restore parent directory must be safe and existing")
        parent = root.parent
        if not parent.is_dir() or parent.is_symlink():
            raise ValidationError("restore parent directory must be safe and existing")
    return root


def reject_symlink(path: Path, label: str) -> None:
    try:
        if path.is_symlink():
            raise ValidationError(f"{label} must not be a symlink")
    except OSError as exc:
        raise ValidationError(f"unable to inspect {label}") from exc


def validate_archive_path(path: Path) -> Path:
    candidate = Path(path).expanduser()
    reject_symlink(candidate, "archive path")
    for ancestor in (candidate.parent, *candidate.parent.parents):
        if ancestor.exists() and ancestor.is_symlink():
            raise ValidationError("archive parent directory must not be a symlink")
    if candidate.exists() and not candidate.is_file():
        raise ValidationError("archive path must be a regular file")
    return candidate.resolve()
