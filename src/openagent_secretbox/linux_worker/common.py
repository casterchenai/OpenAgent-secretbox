"""Closed request/result protocol shared by the Linux worker and client."""

from __future__ import annotations

import json
import math
import re
import ssl
from pathlib import Path
from typing import Any

ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9_-]{0,79}\Z")
TASK_ID = re.compile(r"task_[a-f0-9]{32}\Z")
OPERATIONS = {
    "rds.connectivity_check": set(),
    "rds.restore_public_business": {"backup_id", "scope", "allow_existing_data"},
    "rds.verify_restore": {"expected_manifest"},
}
TERMINAL = {"succeeded", "failed", "cancelled", "timed_out"}


def public_result(value: dict[str, Any]) -> dict[str, Any]:
    try:
        return _public_result(value)
    except (TypeError, ValueError, OverflowError):
        raise Rejected("SBX-011") from None


def _public_result(value: dict[str, Any]) -> dict[str, Any]:
    """Reject unexpected fields instead of treating worker output as a log channel."""
    codes = {f"SBX-{n:03d}" for n in range(1, 15)} | {f"RDS-{n:03d}" for n in range(1, 11)}
    if set(value) == {"error_code"} and value["error_code"] in codes:
        return value
    required = {
        "task_id",
        "operation",
        "target_id",
        "status",
        "error_code",
        "exit_code",
        "summary",
        "events",
        "preflight_id",
        "created_at",
        "finished_at",
    }
    if set(value) not in (required, required | {"cancel_requested"}):
        raise Rejected("SBX-011")
    states = TERMINAL | {
        "created",
        "validated",
        "queued",
        "preflight",
        "awaiting_confirmation",
        "approved",
        "running",
    }
    if (
        not isinstance(value["task_id"], str)
        or not TASK_ID.fullmatch(value["task_id"])
        or value["operation"] not in OPERATIONS
        or value["target_id"] != "isolated-local"
        or value["status"] not in states
        or value["error_code"] not in codes | {None}
        or (
            value["exit_code"] is not None
            and (type(value["exit_code"]) is not int or value["exit_code"] != 0)
        )
        or ("cancel_requested" in value and value["cancel_requested"] is not True)
    ):
        raise Rejected("SBX-011")
    for name in ("created_at", "finished_at"):
        number = value[name]
        if number is None and name == "finished_at":
            continue
        if type(number) not in (int, float) or not math.isfinite(number) or number <= 0:
            raise Rejected("SBX-011")
    preflight = value["preflight_id"]
    if preflight is not None and (
        not isinstance(preflight, str) or not re.fullmatch("[a-f0-9]{64}", preflight)
    ):
        raise Rejected("SBX-011")
    summary = value["summary"]
    if type(summary) is not dict or set(summary) - {
        "connected",
        "server_major",
        "restored",
        "verified",
        "tables",
        "rows",
        "constraints",
    }:
        raise Rejected("SBX-011")
    for key, item in summary.items():
        if key in {"connected", "restored", "verified"}:
            if type(item) is not bool:
                raise Rejected("SBX-011")
        elif type(item) is not int or not 0 <= item <= 1_000_000_000:
            raise Rejected("SBX-011")
    events = value["events"]
    if (
        type(events) is not list
        or len(events) > 20
        or any(not isinstance(event, str) or event not in states for event in events)
    ):
        raise Rejected("SBX-011")
    return value


class Rejected(Exception):
    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


def decode(raw: bytes) -> dict[str, Any]:
    def unique(pairs: list[tuple[str, Any]]) -> dict[str, Any]:
        result: dict[str, Any] = {}
        for key, value in pairs:
            if key in result:
                raise Rejected("SBX-001")
            result[key] = value
        return result

    try:
        value = json.loads(raw, object_pairs_hook=unique)
    except (ValueError, UnicodeError, RecursionError):
        raise Rejected("SBX-001") from None
    if type(value) is not dict:
        raise Rejected("SBX-001")
    return value


def validate(request: dict[str, Any], config: dict[str, Any]) -> dict[str, Any]:
    if set(request) != {"request_id", "operation", "target_id", "parameters", "ttl_seconds"}:
        raise Rejected("SBX-001")
    if not isinstance(request["request_id"], str) or not ID.fullmatch(request["request_id"]):
        raise Rejected("SBX-001")
    if request["target_id"] != config["target_id"] or config["environment"] != "isolated":
        raise Rejected("SBX-002")
    op = request["operation"]
    if not isinstance(op, str) or op not in OPERATIONS:
        raise Rejected("SBX-003")
    if op not in config["operations"]:
        raise Rejected("SBX-003")
    params = request["parameters"]
    if type(params) is not dict or set(params) != OPERATIONS[op]:
        raise Rejected("SBX-001")
    ttl = request["ttl_seconds"]
    if type(ttl) is not int or not 1 <= ttl <= 600:
        raise Rejected("SBX-001")
    if op == "rds.restore_public_business" and (
        params["backup_id"] != config["backup_id"]
        or params["scope"] != "public_business_only"
        or params["allow_existing_data"] is not False
    ):
        raise Rejected("SBX-001")
    if op == "rds.verify_restore" and params["expected_manifest"] != config["backup_id"]:
        raise Rejected("SBX-001")
    return request


def tls(directory: Path, *, server: bool = False) -> ssl.SSLContext:
    # Do not honor SSLKEYLOGFILE or arbitrary system CAs for this private channel.
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER if server else ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = ssl.TLSVersion.TLSv1_2
    ctx.verify_mode = ssl.CERT_REQUIRED
    ctx.load_verify_locations(str(directory / "ca.crt"))
    ctx.load_cert_chain(str(directory / "identity.crt"), str(directory / "identity.key"))
    return ctx
