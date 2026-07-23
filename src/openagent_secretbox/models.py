"""Small immutable data models shared by the SecretBox core.

The models deliberately contain only request metadata.  Secret values are
never stored on these objects, which makes it harder to accidentally include
them in status responses or logs.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass(frozen=True)
class SecretNeed:
    """A single secret requested by an agent."""

    type: str
    name: str
    required: bool = True
    description: str | None = None
    target: str | None = None
    max_bytes: int | None = None
    # Optional non-secret convenience default.  It is metadata only; callers
    # should still require explicit approval before persisting it.
    default_value: str | None = field(default=None, repr=False)

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "type": self.type,
            "name": self.name,
            "required": self.required,
        }
        if self.description is not None:
            value["description"] = self.description
        if self.target is not None:
            value["target"] = self.target
        if self.max_bytes is not None:
            value["max_bytes"] = self.max_bytes
        if self.default_value is not None:
            value["default_value"] = self.default_value
        return value


@dataclass(frozen=True)
class WritePolicy:
    """Conservative write policy attached to a request.

    ``backup`` is intentionally false by default.  A persistent backup is an
    additional copy of a secret and must be explicitly requested by the
    trusted user-side policy.
    """

    env_file: str = ".env"
    mode: str = "merge_only"
    no_overwrite: bool = True
    backup: bool = False
    backup_ttl_seconds: int = 3600
    max_file_size: int = 10 * 1024 * 1024

    def to_dict(self) -> dict[str, Any]:
        return {
            "env_file": self.env_file,
            "mode": self.mode,
            "no_overwrite": self.no_overwrite,
            "backup": self.backup,
            "backup_ttl_seconds": self.backup_ttl_seconds,
            "max_file_size": self.max_file_size,
        }


@dataclass(frozen=True)
class SecretRequest:
    """Validated request metadata (schema version 1)."""

    request_id: str
    title: str
    needs: tuple[SecretNeed, ...]
    write_policy: WritePolicy = field(default_factory=WritePolicy)
    schema_version: int = 1
    workspace_root: str | None = None
    allowed_targets: tuple[str, ...] = ()
    forbidden_targets: tuple[str, ...] = ()

    def to_dict(self) -> dict[str, Any]:
        value: dict[str, Any] = {
            "schema_version": self.schema_version,
            "request_id": self.request_id,
            "title": self.title,
            "needs": [item.to_dict() for item in self.needs],
            "write_policy": self.write_policy.to_dict(),
        }
        if self.workspace_root is not None:
            value["workspace_root"] = self.workspace_root
        if self.allowed_targets:
            value["allowed_targets"] = list(self.allowed_targets)
        if self.forbidden_targets:
            value["forbidden_targets"] = list(self.forbidden_targets)
        return value
