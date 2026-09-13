"""Metadata-only CLI client. TLS private material stays inside its configured host."""

from __future__ import annotations

import argparse
import http.client
import json
import sys
from pathlib import Path
from typing import Any

from .common import Rejected, decode, public_result, tls


def call(method: str, path: str, body: dict[str, Any] | None = None) -> dict[str, Any]:
    connection = http.client.HTTPSConnection("worker", 8443, context=tls(Path("/tls")), timeout=10)
    try:
        connection.request(
            method,
            path,
            json.dumps(body) if body is not None else None,
            {"Content-Type": "application/json"},
        )
        response = connection.getresponse()
        raw = response.read(16385)
        if len(raw) > 16384:
            raise Rejected("SBX-011")
        return public_result(decode(raw))
    finally:
        connection.close()


def main() -> None:
    parser = argparse.ArgumentParser(description="SecretBox Linux task client (metadata only)")
    parser.add_argument("action", choices=("create", "status", "cancel", "confirm"))
    parser.add_argument("task_id", nargs="?")
    args = parser.parse_args()
    try:
        if args.action == "create":
            result = call("POST", "/v1/tasks", decode(sys.stdin.buffer.read(4097)))
        elif args.action == "status":
            result = call("GET", f"/v1/tasks/{args.task_id}")
        else:
            payload = decode(sys.stdin.buffer.read(4097)) if args.action == "confirm" else {}
            result = call("POST", f"/v1/tasks/{args.task_id}/{args.action}", payload)
    except Rejected as exc:
        result = {"error_code": exc.code}
    except Exception:
        result = {"error_code": "SBX-008"}
    print(json.dumps(result, ensure_ascii=True))
    if "error_code" in result and "task_id" not in result:
        raise SystemExit(1)


if __name__ == "__main__":
    main()
