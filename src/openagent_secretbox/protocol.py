"""Strict, metadata-only result protocol for agent integrations.

The validator intentionally uses only the standard library so production
callers do not need a JSON Schema package.  The published JSON Schema remains
the language-neutral contract; these helpers enforce the same closed shapes at
Python integration boundaries.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping
from datetime import datetime
from pathlib import PurePosixPath, PureWindowsPath
from typing import Any, NoReturn

WRITER_STATUSES = frozenset({"applied", "noop", "partial", "blocked"})
INTAKE_STATUSES = frozenset(
    {"awaiting_input", "applied", "failed", "cancelled", "expired"}
)
MCP_STATUSES = INTAKE_STATUSES

_WRITER_FIELDS = frozenset(
    {"request_id", "status", "written", "conflicts", "missing", "blocked"}
)
_INTAKE_FIELDS = frozenset(
    {
        "schema_version",
        "status",
        "request_id",
        "browser_opened",
        "result",
        "error_code",
    }
)
_MCP_FIELDS = frozenset(
    {
        "schema_version",
        "intake_id",
        "request_id",
        "status",
        "expires_at",
        "browser_opened",
        "result",
        "error_code",
    }
)
_MCP_ERROR_FIELDS = frozenset({"schema_version", "status", "error"})
_ERROR_FIELDS = frozenset({"code", "message"})
_ACTION_FIELDS = frozenset({"type", "name", "action", "target", "mode"})
_CONFLICT_FIELDS = frozenset({"type", "name", "action", "target"})
_BLOCKED_FIELDS = frozenset({"code", "name", "target"})
_BLOCK_CODES = frozenset(
    {"invalid_request_or_workspace", "invalid_values", "apply_failed"}
)
_MCP_ERROR_CODES = frozenset({"apply_blocked", "apply_failed", "expired"})
_MCP_PUBLIC_ERRORS = frozenset(
    {
        "invalid_ttl",
        "invalid_request",
        "policy_rejected",
        "server_closed",
        "too_many_active_intakes",
        "browser_open_failed",
        "server_unavailable",
        "intake_not_found",
        "status_unavailable",
        "apply_in_progress",
    }
)
_ID_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,127}$")
_INTAKE_ID_RE = re.compile(r"^int_[A-Za-z0-9_-]{16,64}$")
_ERROR_CODE_RE = re.compile(r"^[a-z][a-z0-9_]{0,63}$")
_TIMESTAMP_RE = re.compile(r"^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9]{2}:[0-9]{2}:[0-9]{2}Z$")
_CONTROL_RE = re.compile(r"[\x00-\x1f\x7f]")
_SENSITIVE_FIELD_RE = re.compile(
    r"secret|value|body|token|content|raw|password|passphrase|authorization|"
    r"credential|api[_-]?key|private[_-]?key",
    re.IGNORECASE,
)
_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


class ResultValidationError(ValueError):
    """Raised when an agent-facing result violates protocol version 1."""


def _fail(message: str) -> NoReturn:
    raise ResultValidationError(message)


def _object(value: Any, path: str) -> Mapping[str, Any]:
    if not isinstance(value, Mapping):
        _fail(f"{path} must be an object")
    if not all(isinstance(key, str) for key in value):
        _fail(f"{path} field names must be strings")
    return value


def _check_sensitive_fields(value: Any, path: str = "result") -> None:
    if isinstance(value, Mapping):
        for key, item in value.items():
            if not isinstance(key, str):
                _fail(f"{path} field names must be strings")
            if _SENSITIVE_FIELD_RE.search(key):
                _fail(f"{path}.{key} is a forbidden sensitive field")
            _check_sensitive_fields(item, f"{path}.{key}")
    elif isinstance(value, list):
        for index, item in enumerate(value):
            _check_sensitive_fields(item, f"{path}[{index}]")


def _keys(
    value: Mapping[str, Any],
    *,
    allowed: frozenset[str],
    required: frozenset[str],
    path: str,
) -> None:
    unknown = set(value) - allowed
    missing = required - set(value)
    if unknown:
        _fail(f"{path} contains unknown field(s): {', '.join(sorted(unknown))}")
    if missing:
        _fail(f"{path} is missing field(s): {', '.join(sorted(missing))}")


def _string(value: Any, path: str, *, max_length: int) -> str:
    if not isinstance(value, str) or not value:
        _fail(f"{path} must be a non-empty string")
    if len(value) > max_length or _CONTROL_RE.search(value):
        _fail(f"{path} is not safe metadata")
    return value


def _identifier(value: Any, path: str) -> str:
    text = _string(value, path, max_length=128)
    if not _ID_RE.fullmatch(text):
        _fail(f"{path} is not a valid identifier")
    return text


def _intake_id(value: Any, path: str) -> str:
    text = _string(value, path, max_length=68)
    if not _INTAKE_ID_RE.fullmatch(text):
        _fail(f"{path} is not a valid MCP intake handle")
    return text


def _timestamp(value: Any, path: str) -> str:
    text = _string(value, path, max_length=20)
    if not _TIMESTAMP_RE.fullmatch(text):
        _fail(f"{path} must be a UTC timestamp without fractional seconds")
    try:
        datetime.strptime(text, "%Y-%m-%dT%H:%M:%SZ")
    except ValueError:
        _fail(f"{path} is not a real calendar timestamp")
    return text


def _metadata_name(value: Any, path: str) -> str:
    text = _string(value, path, max_length=255)
    if "/" in text or "\\" in text:
        _fail(f"{path} must be a metadata name, not a path")
    return text


def _target(value: Any, path: str) -> str:
    text = _string(value, path, max_length=4096)
    if "\\" in text:
        _fail(f"{path} must use '/' separators")
    posix = PurePosixPath(text)
    windows = PureWindowsPath(text)
    if posix.is_absolute() or windows.is_absolute() or windows.drive or windows.root:
        _fail(f"{path} must be relative")
    if text == "." or any(part == ".." for part in posix.parts):
        _fail(f"{path} may not escape the workspace")
    for part in posix.parts:
        basename = part.split(".", 1)[0].upper()
        if ":" in part or part.endswith((".", " ")) or basename in _WINDOWS_RESERVED_NAMES:
            _fail(f"{path} contains an unsafe path component")
    return "/".join(part for part in posix.parts if part not in ("", "."))


def _array(value: Any, path: str) -> list[Any]:
    if not isinstance(value, list):
        _fail(f"{path} must be an array")
    if len(value) > 128:
        _fail(f"{path} has too many entries")
    return value


def _unique(items: list[Any], path: str) -> None:
    encoded = [json.dumps(item, ensure_ascii=True, sort_keys=True) for item in items]
    if len(set(encoded)) != len(encoded):
        _fail(f"{path} contains duplicate entries")


def _normalize_action(value: Any, index: int) -> dict[str, Any]:
    path = f"result.written[{index}]"
    item = _object(value, path)
    _keys(
        item,
        allowed=_ACTION_FIELDS,
        required=frozenset({"type", "name", "action", "target"}),
        path=path,
    )
    kind = _string(item["type"], f"{path}.type", max_length=16)
    action = _string(item["action"], f"{path}.action", max_length=32)
    if kind == "env":
        allowed_actions = {"added", "updated", "skipped"}
        mode_required = False
        mode_forbidden = True
    elif kind == "env_file":
        allowed_actions = {"permissions_repaired"}
        mode_required = True
        mode_forbidden = False
    elif kind == "file":
        allowed_actions = {"created", "updated", "skipped", "permissions_repaired"}
        mode_required = action != "skipped"
        mode_forbidden = action == "skipped"
    else:
        _fail(f"{path}.type is not supported")
    if action not in allowed_actions:
        _fail(f"{path}.action is not valid for {kind}")
    if mode_required and "mode" not in item:
        _fail(f"{path}.mode is required")
    if mode_forbidden and "mode" in item:
        _fail(f"{path}.mode is not valid for {kind}/{action}")
    normalized: dict[str, Any] = {
        "type": kind,
        "name": _metadata_name(item["name"], f"{path}.name"),
        "action": action,
        "target": _target(item["target"], f"{path}.target"),
    }
    if "mode" in item:
        mode = item["mode"]
        if mode not in {"0600", "owner-only"}:
            _fail(f"{path}.mode is not supported")
        normalized["mode"] = mode
    return normalized


def _normalize_conflict(value: Any, index: int) -> dict[str, str]:
    path = f"result.conflicts[{index}]"
    item = _object(value, path)
    _keys(item, allowed=_CONFLICT_FIELDS, required=_CONFLICT_FIELDS, path=path)
    kind = item["type"]
    if kind not in {"env", "file"}:
        _fail(f"{path}.type is not supported")
    if item["action"] != "conflict":
        _fail(f"{path}.action must be conflict")
    return {
        "type": kind,
        "name": _metadata_name(item["name"], f"{path}.name"),
        "action": "conflict",
        "target": _target(item["target"], f"{path}.target"),
    }


def _normalize_blocked(value: Any, index: int) -> dict[str, str]:
    path = f"result.blocked[{index}]"
    item = _object(value, path)
    _keys(
        item,
        allowed=_BLOCKED_FIELDS,
        required=frozenset({"code"}),
        path=path,
    )
    code = item["code"]
    if code not in _BLOCK_CODES:
        _fail(f"{path}.code is not supported")
    normalized = {"code": code}
    if "name" in item:
        normalized["name"] = _metadata_name(item["name"], f"{path}.name")
    if "target" in item:
        normalized["target"] = _target(item["target"], f"{path}.target")
    return normalized


def normalize_writer_result(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and return a detached protocol-v1 writer result."""

    item = _object(value, "result")
    _check_sensitive_fields(item)
    _keys(item, allowed=_WRITER_FIELDS, required=_WRITER_FIELDS, path="result")
    status = item["status"]
    if status not in WRITER_STATUSES:
        _fail("result.status is not a writer status")
    written = [
        _normalize_action(entry, index)
        for index, entry in enumerate(_array(item["written"], "result.written"))
    ]
    conflicts = [
        _normalize_conflict(entry, index)
        for index, entry in enumerate(_array(item["conflicts"], "result.conflicts"))
    ]
    missing = [
        _metadata_name(entry, f"result.missing[{index}]")
        for index, entry in enumerate(_array(item["missing"], "result.missing"))
    ]
    blocked = [
        _normalize_blocked(entry, index)
        for index, entry in enumerate(_array(item["blocked"], "result.blocked"))
    ]
    for entries, path in (
        (written, "result.written"),
        (conflicts, "result.conflicts"),
        (missing, "result.missing"),
        (blocked, "result.blocked"),
    ):
        _unique(entries, path)
    if status == "applied" and (not written or conflicts or missing or blocked):
        _fail("applied requires writes and no unresolved entries")
    if status == "noop" and (conflicts or missing or blocked):
        _fail("noop may not contain unresolved entries")
    if status == "partial" and (not written or missing or not (conflicts or blocked)):
        _fail("partial requires writes plus a conflict or blocked reason")
    if status == "blocked" and (written or not (conflicts or missing or blocked)):
        _fail("blocked requires no writes and at least one unresolved entry")
    return {
        "request_id": _identifier(item["request_id"], "result.request_id"),
        "status": status,
        "written": written,
        "conflicts": conflicts,
        "missing": missing,
        "blocked": blocked,
    }


def normalize_intake_event(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate and return a detached CLI intake event."""

    item = _object(value, "event")
    _check_sensitive_fields(item, "event")
    _keys(
        item,
        allowed=_INTAKE_FIELDS,
        required=frozenset({"schema_version", "status", "request_id", "browser_opened"}),
        path="event",
    )
    version = item["schema_version"]
    if isinstance(version, bool) or version != 1:
        _fail("event.schema_version must be integer 1")
    status = item["status"]
    if status not in INTAKE_STATUSES:
        _fail("event.status is not an intake status")
    browser_opened = item["browser_opened"]
    if not isinstance(browser_opened, bool):
        _fail("event.browser_opened must be boolean")
    normalized: dict[str, Any] = {
        "schema_version": 1,
        "status": status,
        "request_id": _identifier(item["request_id"], "event.request_id"),
        "browser_opened": browser_opened,
    }
    terminal_only = {"result", "error_code"}
    if status == "awaiting_input":
        if terminal_only & set(item):
            _fail("awaiting_input may not contain terminal fields")
        if not browser_opened:
            _fail("agent-safe awaiting_input requires browser_opened=true")
        return normalized
    if status == "applied":
        if "result" not in item or "error_code" in item:
            _fail("applied requires a result and no error_code")
        result = normalize_writer_result(_object(item["result"], "event.result"))
        if result["status"] not in {"applied", "noop"}:
            _fail("applied intake event requires an applied or noop writer result")
        if result["request_id"] != normalized["request_id"]:
            _fail("event and writer result request_id values must match")
        normalized["result"] = result
    elif status == "failed":
        if "error_code" not in item:
            _fail("failed requires error_code")
        if "result" in item:
            result = normalize_writer_result(_object(item["result"], "event.result"))
            if result["status"] not in {"partial", "blocked"}:
                _fail("failed intake result must be partial or blocked")
            if result["request_id"] != normalized["request_id"]:
                _fail("event and writer result request_id values must match")
            normalized["result"] = result
    elif status == "cancelled":
        if terminal_only & set(item):
            _fail("cancelled may not contain result or error_code")
    elif status == "expired":
        if item.get("error_code") != "expired" or "result" in item:
            _fail("expired requires only error_code=expired")
    if "error_code" in item:
        error_code = item["error_code"]
        if not isinstance(error_code, str) or not _ERROR_CODE_RE.fullmatch(error_code):
            _fail("event.error_code is not valid")
        normalized["error_code"] = error_code
    return normalized


def normalize_mcp_result(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate an MCP open/status/cancel response without browser credentials."""

    item = _object(value, "mcp_result")
    _check_sensitive_fields(item, "mcp_result")
    _keys(
        item,
        allowed=_MCP_FIELDS,
        required=frozenset({"schema_version", "intake_id", "request_id", "status"}),
        path="mcp_result",
    )
    version = item["schema_version"]
    if isinstance(version, bool) or version != 1:
        _fail("mcp_result.schema_version must be integer 1")
    status = item["status"]
    if status not in MCP_STATUSES:
        _fail("mcp_result.status is not supported")
    normalized: dict[str, Any] = {
        "schema_version": 1,
        "intake_id": _intake_id(item["intake_id"], "mcp_result.intake_id"),
        "request_id": _identifier(item["request_id"], "mcp_result.request_id"),
        "status": status,
    }
    if "expires_at" in item:
        normalized["expires_at"] = _timestamp(item["expires_at"], "mcp_result.expires_at")
    if "browser_opened" in item:
        browser_opened = item["browser_opened"]
        if browser_opened is not True:
            _fail("mcp_result.browser_opened must be true when present")
        normalized["browser_opened"] = True
    terminal_only = {"result", "error_code"}
    if status == "awaiting_input":
        if "expires_at" not in item:
            _fail("awaiting_input MCP result requires expires_at")
        if terminal_only & set(item):
            _fail("awaiting_input MCP result may not contain terminal fields")
        return normalized
    if "browser_opened" in item:
        _fail("terminal MCP results may not contain browser_opened")
    if status == "applied":
        if "result" not in item or "error_code" in item:
            _fail("applied MCP result requires writer result and no error_code")
        result = normalize_writer_result(_object(item["result"], "mcp_result.result"))
        if result["status"] not in {"applied", "noop"}:
            _fail("applied MCP result requires applied or noop writer status")
        if result["request_id"] != normalized["request_id"]:
            _fail("MCP and writer result request_id values must match")
        normalized["result"] = result
    elif status == "failed":
        if "error_code" not in item:
            _fail("failed MCP result requires error_code")
        if "result" in item:
            result = normalize_writer_result(_object(item["result"], "mcp_result.result"))
            if result["status"] not in {"partial", "blocked"}:
                _fail("failed MCP writer result must be partial or blocked")
            if result["request_id"] != normalized["request_id"]:
                _fail("MCP and writer result request_id values must match")
            normalized["result"] = result
    elif status == "cancelled":
        if terminal_only & set(item):
            _fail("cancelled MCP result may not contain result or error_code")
    elif status == "expired":
        if item.get("error_code") != "expired" or "result" in item:
            _fail("expired MCP result requires only error_code=expired")
    if "error_code" in item:
        error_code = item["error_code"]
        if error_code not in _MCP_ERROR_CODES:
            _fail("mcp_result.error_code is not supported")
        normalized["error_code"] = error_code
    return normalized


def normalize_mcp_error(value: Mapping[str, Any]) -> dict[str, Any]:
    """Validate a closed MCP tool error response."""

    item = _object(value, "mcp_error")
    _check_sensitive_fields(item, "mcp_error")
    _keys(
        item,
        allowed=_MCP_ERROR_FIELDS,
        required=_MCP_ERROR_FIELDS,
        path="mcp_error",
    )
    version = item["schema_version"]
    if isinstance(version, bool) or version != 1:
        _fail("mcp_error.schema_version must be integer 1")
    if item["status"] != "error":
        _fail("mcp_error.status must be error")
    error = _object(item["error"], "mcp_error.error")
    _keys(error, allowed=_ERROR_FIELDS, required=_ERROR_FIELDS, path="mcp_error.error")
    code = error["code"]
    if code not in _MCP_PUBLIC_ERRORS:
        _fail("mcp_error.error.code is not supported")
    message = _string(error["message"], "mcp_error.error.message", max_length=300)
    folded_message = message.casefold()
    forbidden_markers = ("http://", "https://", "/intake/", "#token=", "ses_")
    if any(marker in folded_message for marker in forbidden_markers):
        _fail("mcp_error.error.message may not contain a URL or browser session reference")
    return {
        "schema_version": 1,
        "status": "error",
        "error": {"code": code, "message": message},
    }


def normalize_agent_result(value: Mapping[str, Any]) -> dict[str, Any]:
    """Normalize a writer result, CLI event, or MCP tool response."""

    item = _object(value, "result")
    if "schema_version" in item:
        if item.get("status") == "error":
            return normalize_mcp_error(item)
        if "intake_id" in item:
            return normalize_mcp_result(item)
        return normalize_intake_event(item)
    return normalize_writer_result(item)


validate_agent_result = normalize_agent_result


__all__ = [
    "INTAKE_STATUSES",
    "MCP_STATUSES",
    "ResultValidationError",
    "WRITER_STATUSES",
    "normalize_agent_result",
    "normalize_intake_event",
    "normalize_mcp_error",
    "normalize_mcp_result",
    "normalize_writer_result",
    "validate_agent_result",
]
