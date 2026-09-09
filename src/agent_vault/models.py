"""Domain models for Agent-Vault memories and project state."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime, timezone
from typing import Any

MEMORY_KINDS = ("decision", "fact", "constraint", "todo", "note")
SENSITIVITY_LEVELS = ("normal", "private", "secret")


def utc_now() -> str:
    """Return an ISO-8601 UTC timestamp with second precision."""
    return datetime.now(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


@dataclass(frozen=True, slots=True)
class Memory:
    """A durable, agent-readable project memory."""

    id: str
    kind: str
    content: str
    tags: tuple[str, ...] = field(default_factory=tuple)
    source: str | None = None
    sensitivity: str = "normal"
    created_at: str = field(default_factory=utc_now)

    def to_dict(self) -> dict[str, Any]:
        """Serialize the memory according to the public JSON schema."""
        data = asdict(self)
        data["tags"] = list(self.tags)
        return data


@dataclass(frozen=True, slots=True)
class ProjectState:
    """The stable JSON envelope returned by ``agent-vault fetch``."""

    schema_version: str
    project: dict[str, Any]
    memories: tuple[Memory, ...]

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "project": self.project,
            "memories": [memory.to_dict() for memory in self.memories],
        }
