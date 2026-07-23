"""Validation and parsing for request schema v1.

The validator is intentionally strict.  Requests are untrusted input and are
only metadata: a request can describe a target, but it cannot grant itself
filesystem authority.  Callers that have a trusted workspace registry should
pass ``workspace_root`` to :func:`validate_request`; a request containing a
different root is then rejected before any path is resolved.
"""

from __future__ import annotations

import json
import os
import re
from collections.abc import Mapping
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any, NoReturn

from .models import SecretNeed, SecretRequest, WritePolicy


class RequestValidationError(ValueError):
    """Raised when an untrusted request does not satisfy schema v1."""

    def __init__(self, message: str, *, field: str | None = None) -> None:
        self.field = field
        super().__init__(message)


# These limits are deliberately small enough for an intake request and large
# enough for ordinary configuration workflows.
MAX_REQUEST_BYTES = 256 * 1024
MAX_NEEDS = 128
MAX_TARGETS = 256
MAX_ID_LENGTH = 128
MAX_TITLE_LENGTH = 200
MAX_DESCRIPTION_LENGTH = 1000
MAX_PATH_LENGTH = 4096
MAX_FILE_SIZE = 10 * 1024 * 1024

REQUEST_FIELDS = {
    "schema_version",
    "request_id",
    "title",
    "workspace_root",
    "needs",
    "write_policy",
    "allowed_targets",
    "forbidden_targets",
}
NEED_FIELDS = {"type", "name", "required", "description", "target", "max_bytes", "default_value"}
POLICY_FIELDS = {
    "env_file",
    "mode",
    "no_overwrite",
    "backup",
    "backup_ttl_seconds",
    "max_file_size",
}
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_NAME_RE = re.compile(r"^[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


def _fail(message: str, field: str | None = None) -> NoReturn:
    raise RequestValidationError(message, field=field)


def _string(value: Any, field: str, *, max_length: int, allow_empty: bool = False) -> str:
    if not isinstance(value, str):
        _fail(f"{field} must be a string", field)
    if not allow_empty and not value:
        _fail(f"{field} must not be empty", field)
    if len(value) > max_length:
        _fail(f"{field} is too long", field)
    if _CONTROL_RE.search(value):
        _fail(f"{field} contains control characters", field)
    return value


def _strict_mapping(value: Any, field: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{field} must be an object", field)
    unknown = set(value) - (
        REQUEST_FIELDS
        if field == "request"
        else NEED_FIELDS
        if field == "needs[]"
        else POLICY_FIELDS
    )
    if unknown:
        _fail(f"{field} contains unknown field(s): {', '.join(sorted(map(str, unknown)))}", field)
    return value


def _validate_relative_pattern(value: Any, field: str) -> str:
    text = _string(value, field, max_length=MAX_PATH_LENGTH)
    # A request target is interpreted as a POSIX-style relative path on every
    # platform.  Rejecting backslashes avoids Windows/POSIX separator ambiguity.
    if "\\" in text:
        _fail(f"{field} must use '/' separators", field)
    if "\x00" in text:
        _fail(f"{field} contains NUL", field)
    windows = PureWindowsPath(text)
    posix = PurePosixPath(text)
    if posix.is_absolute() or windows.is_absolute() or windows.drive or windows.root:
        _fail(f"{field} must be relative", field)
    if not text or text == ".":
        _fail(f"{field} must identify a target", field)
    if any(part == ".." for part in posix.parts):
        _fail(f"{field} may not contain '..'", field)
    for part in posix.parts:
        basename = part.split(".", 1)[0].upper()
        if ":" in part or part.endswith((".", " ")) or basename in _WINDOWS_RESERVED_NAMES:
            _fail(f"{field} contains a Windows-unsafe path component", field)
    return "/".join(part for part in posix.parts if part not in ("", "."))


def _validate_targets(value: Any, field: str) -> tuple[str, ...]:
    if value is None:
        return ()
    if not isinstance(value, list):
        _fail(f"{field} must be an array", field)
    if len(value) > MAX_TARGETS:
        _fail(f"{field} has too many entries", field)
    output: list[str] = []
    for index, item in enumerate(value):
        output.append(_validate_relative_pattern(item, f"{field}[{index}]"))
    if len(set(output)) != len(output):
        _fail(f"{field} contains duplicates", field)
    return tuple(output)


def _validate_need(value: Any, index: int) -> SecretNeed:
    item = _strict_mapping(value, "needs[]")
    prefix = f"needs[{index}]"
    kind = _string(item.get("type"), f"{prefix}.type", max_length=32)
    if kind not in {"env", "file", "env_file"}:
        _fail(f"{prefix}.type must be one of env, file, env_file", f"{prefix}.type")
    name = _string(item.get("name"), f"{prefix}.name", max_length=MAX_ID_LENGTH)
    if not _NAME_RE.fullmatch(name):
        _fail(f"{prefix}.name has invalid characters", f"{prefix}.name")
    if kind == "env" and not _ENV_NAME_RE.fullmatch(name):
        _fail(f"{prefix}.name must be a valid environment variable name", f"{prefix}.name")
    required = item.get("required", True)
    if not isinstance(required, bool):
        _fail(f"{prefix}.required must be boolean", f"{prefix}.required")
    description = item.get("description")
    if description is not None:
        description = _string(
            description,
            f"{prefix}.description",
            max_length=MAX_DESCRIPTION_LENGTH,
            allow_empty=True,
        )
    target = item.get("target")
    if target is not None:
        target = _validate_relative_pattern(target, f"{prefix}.target")
    if kind == "file" and target is None:
        _fail(f"{prefix}.target is required for file needs", f"{prefix}.target")
    if kind == "env" and target is not None:
        _fail(f"{prefix}.target is not valid for env needs", f"{prefix}.target")
    max_bytes = item.get("max_bytes")
    if max_bytes is not None:
        if (
            isinstance(max_bytes, bool)
            or not isinstance(max_bytes, int)
            or not 0 < max_bytes <= MAX_FILE_SIZE
        ):
            _fail(
                f"{prefix}.max_bytes must be between 1 and {MAX_FILE_SIZE}", f"{prefix}.max_bytes"
            )
    default_value = item.get("default_value")
    if default_value is not None:
        if kind != "env":
            _fail(f"{prefix}.default_value is only valid for env needs", f"{prefix}.default_value")
        default_value = _string(
            default_value, f"{prefix}.default_value", max_length=MAX_PATH_LENGTH, allow_empty=True
        )
        if "\n" in default_value or "\r" in default_value or "\x00" in default_value:
            _fail(f"{prefix}.default_value contains an unsafe character", f"{prefix}.default_value")
    return SecretNeed(kind, name, required, description, target, max_bytes, default_value)


def _validate_policy(value: Any) -> WritePolicy:
    if value is None:
        return WritePolicy()
    item = _strict_mapping(value, "write_policy")
    env_file = _validate_relative_pattern(item.get("env_file", ".env"), "write_policy.env_file")
    mode = item.get("mode", "merge_only")
    if mode != "merge_only":
        _fail("write_policy.mode must be 'merge_only'", "write_policy.mode")
    no_overwrite = item.get("no_overwrite", True)
    if not isinstance(no_overwrite, bool):
        _fail("write_policy.no_overwrite must be boolean", "write_policy.no_overwrite")
    backup = item.get("backup", False)
    if not isinstance(backup, bool):
        _fail("write_policy.backup must be boolean", "write_policy.backup")
    ttl = item.get("backup_ttl_seconds", 3600)
    if isinstance(ttl, bool) or not isinstance(ttl, int) or not 60 <= ttl <= 7 * 24 * 60 * 60:
        _fail(
            "write_policy.backup_ttl_seconds must be between 60 and 604800",
            "write_policy.backup_ttl_seconds",
        )
    max_file_size = item.get("max_file_size", 10 * 1024 * 1024)
    if (
        isinstance(max_file_size, bool)
        or not isinstance(max_file_size, int)
        or not 0 < max_file_size <= MAX_FILE_SIZE
    ):
        _fail(
            f"write_policy.max_file_size must be between 1 and {MAX_FILE_SIZE}",
            "write_policy.max_file_size",
        )
    return WritePolicy(env_file, mode, no_overwrite, backup, ttl, max_file_size)


def validate_request(
    data: Mapping[str, Any] | str | bytes | bytearray,
    *,
    workspace_root: str | os.PathLike[str] | None = None,
    max_bytes: int = MAX_REQUEST_BYTES,
) -> SecretRequest:
    """Parse and validate a request mapping according to schema v1.

    ``workspace_root`` is a trusted value supplied by the host application.
    When present, the request's optional ``workspace_root`` is merely an
    assertion and must resolve to the same directory; it cannot select a new
    trust boundary.
    """

    if isinstance(data, (str, bytes, bytearray)):
        raw = bytes(data, "utf-8") if isinstance(data, str) else bytes(data)
        if len(raw) > max_bytes:
            _fail("request exceeds size limit")
        try:
            data = json.loads(raw.decode("utf-8"))
        except (UnicodeDecodeError, json.JSONDecodeError) as exc:
            raise RequestValidationError("request must be valid UTF-8 JSON") from exc
    if not isinstance(data, Mapping):
        _fail("request must be an object")
    item = _strict_mapping(data, "request")
    version = item.get("schema_version", 1)
    if version == "1":
        version = 1
    if isinstance(version, bool) or not isinstance(version, int) or version != 1:
        _fail("schema_version must be integer 1", "schema_version")
    request_id = _string(item.get("request_id"), "request_id", max_length=MAX_ID_LENGTH)
    if not _ID_RE.fullmatch(request_id):
        _fail("request_id has invalid characters", "request_id")
    title = _string(item.get("title"), "title", max_length=MAX_TITLE_LENGTH)
    needs_value = item.get("needs")
    if not isinstance(needs_value, list) or not needs_value:
        _fail("needs must be a non-empty array", "needs")
    if len(needs_value) > MAX_NEEDS:
        _fail("needs has too many entries", "needs")
    needs = tuple(_validate_need(value, index) for index, value in enumerate(needs_value))
    names = [need.name for need in needs]
    if len(set(names)) != len(names):
        _fail("needs names must be unique", "needs")
    write_policy = _validate_policy(item.get("write_policy"))
    request_workspace = item.get("workspace_root")
    if request_workspace is not None:
        request_workspace = _string(request_workspace, "workspace_root", max_length=MAX_PATH_LENGTH)
        if "\x00" in request_workspace:
            _fail("workspace_root contains NUL", "workspace_root")
    if workspace_root is not None and request_workspace is not None:
        try:
            expected = Path(workspace_root).expanduser().resolve(strict=False)
            declared = Path(request_workspace).expanduser().resolve(strict=False)
            if expected != declared:
                _fail("workspace_root does not match trusted workspace", "workspace_root")
        except (OSError, RuntimeError, ValueError) as exc:
            raise RequestValidationError(
                "workspace_root is invalid", field="workspace_root"
            ) from exc
    allowed = _validate_targets(item.get("allowed_targets"), "allowed_targets")
    forbidden = _validate_targets(item.get("forbidden_targets"), "forbidden_targets")
    return SecretRequest(
        request_id=request_id,
        title=title,
        needs=needs,
        write_policy=write_policy,
        schema_version=version,
        workspace_root=request_workspace,
        allowed_targets=allowed,
        forbidden_targets=forbidden,
    )


def parse_request(
    data: Mapping[str, Any] | str | bytes | bytearray, **kwargs: Any
) -> SecretRequest:
    """Compatibility alias for :func:`validate_request`."""

    return validate_request(data, **kwargs)


def load_request(path: str | Path, **kwargs: Any) -> SecretRequest:
    """Read a UTF-8 JSON request from ``path`` and validate it."""

    source = Path(path)
    try:
        raw = source.read_bytes()
    except OSError as exc:
        raise RequestValidationError("unable to read request file") from exc
    return validate_request(raw, **kwargs)


__all__ = [
    "MAX_REQUEST_BYTES",
    "RequestValidationError",
    "load_request",
    "parse_request",
    "validate_request",
]
