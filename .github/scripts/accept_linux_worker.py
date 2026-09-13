"""Run real Linux acceptance against ONLY the named disposable Compose lab."""

from __future__ import annotations

import json
import socket
import ssl
import subprocess
import sys
import time
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parents[2]
COMPOSE = ["docker", "compose", "-f", str(ROOT / "deploy/linux-worker/compose.yaml")]


def command(args: list[str], data: bytes | None = None, timeout: int = 60) -> bytes:
    result = subprocess.run(
        COMPOSE + args,
        input=data,
        capture_output=True,
        timeout=timeout,
        cwd=ROOT,
    )
    if result.returncode:
        raise RuntimeError("Acceptance command failed (raw output withheld): " + args[0])
    return result.stdout


def api(action: str, task: str | None = None, payload: dict | None = None) -> dict:
    args = [
        "exec",
        "-T",
        "agent",
        "python3",
        "-m",
        "openagent_secretbox.linux_worker.client",
        action,
    ]
    if task:
        args.append(task)
    return json.loads(command(args, json.dumps(payload).encode() if payload else None))


def create(ttl: int = 60, request_id: str | None = None) -> dict:
    return api(
        "create",
        payload={
            "request_id": request_id or "fault-" + uuid.uuid4().hex,
            "target_id": "isolated-local",
            "operation": "rds.connectivity_check",
            "parameters": {},
            "ttl_seconds": ttl,
        },
    )


def wait(task: str, expected: set[str], seconds: int = 30) -> dict:
    deadline = time.monotonic() + seconds
    while time.monotonic() < deadline:
        result = api("status", task)
        if result["status"] in expected:
            return result
        if result["status"] in {"succeeded", "failed", "cancelled", "timed_out"}:
            raise RuntimeError("Unexpected terminal result: " + json.dumps(result))
        time.sleep(0.1)
    raise RuntimeError("Acceptance deadline exceeded")


def probe(name: str, service: str = "worker") -> None:
    command(["exec", "-T", service, "python3", "/app/faults.py", name])
    print("PASS " + name, flush=True)


def main() -> int:
    ca = command(
        [
            "exec",
            "-T",
            "agent",
            "python3",
            "-c",
            "from pathlib import Path; print(Path('/tls/ca.crt').read_text())",
        ]
    )
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations(cadata=ca.decode())
    try:
        with socket.create_connection(("127.0.0.1", 17443), timeout=3) as raw:
            with ctx.wrap_socket(raw, server_hostname="worker") as secure:
                secure.sendall(b"GET / HTTP/1.1\r\nHost: worker\r\n\r\n")
                data = secure.recv(4096)
                assert not data, "Unauthenticated host client received an HTTP response"
    except ssl.SSLError as exc:
        assert "CERTIFICATE_VERIFY_FAILED" not in str(exc)
    print(
        "PASS host port reachable with valid server identity and mandatory client certificate",
        flush=True,
    )
    command(["exec", "-T", "agent", "python3", "/app/acceptance.py", "ingress"])
    print("PASS authenticated end-to-end TLS through fixed ingress", flush=True)
    command(
        [
            "exec",
            "-T",
            "--user",
            "postgres",
            "database",
            "psql",
            "-X",
            "-w",
            "-d",
            "sbx_lab",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            "DROP TABLE IF EXISTS public.sbx_fixture;",
        ]
    )
    for service, test in (("agent", "policy"), ("agent", "boundary"), ("agent", "unprivileged")):
        command(["exec", "-T", service, "python3", "/app/acceptance.py", test])
        print("PASS " + test, flush=True)
    # Only the synthetic table in the dedicated lab database is touched.
    command(
        [
            "exec",
            "-T",
            "--user",
            "postgres",
            "database",
            "psql",
            "-X",
            "-w",
            "-d",
            "sbx_lab",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            "DROP TABLE IF EXISTS public.sbx_fixture;",
        ]
    )
    command(["exec", "-T", "owner", "python3", "/app/acceptance.py", "restore"])
    print("PASS real restore, verify, nonempty guard and duplicate-approval guard", flush=True)
    for name in ("lease", "timeout", "bounded", "errors", "cleanup"):
        probe(name)
    command(["exec", "-T", "--user", "10005:10001", "worker", "python3", "/app/faults.py", "peer"])
    print("PASS credential provider peer-UID restriction", flush=True)
    command(["exec", "-T", "bootstrap", "chmod", "644", "/provider-secrets/database-password"])
    try:
        bad_permissions = create()["task_id"]
        assert wait(bad_permissions, {"failed"})["error_code"] == "SBX-009"
    finally:
        command(["exec", "-T", "bootstrap", "chmod", "400", "/provider-secrets/database-password"])
    print("PASS unsafe credential-file permissions fail closed", flush=True)

    # Pause the isolated DB only, creating a genuine blocked PostgreSQL process.
    command(["pause", "database"])
    try:
        running = create()["task_id"]
        wait(running, {"running"})
        probe("anonymous")
        result = api("cancel", running)
        assert result.get("cancel_requested") or result["status"] == "cancelled"
        assert wait(running, {"cancelled"})["error_code"] == "SBX-013"
        probe("cleanup")
        print("PASS running-task cancellation acknowledged only after process cleanup", flush=True)

        blocking = create()["task_id"]
        wait(blocking, {"running"})
        expired = create(ttl=1)["task_id"]
        assert wait(blocking, {"failed"})["error_code"] == "RDS-001"
        assert wait(expired, {"timed_out"})["error_code"] == "SBX-005"
        probe("cleanup")
        print("PASS database outage, queue expiry and bounded failure", flush=True)

        crash = create()["task_id"]
        wait(crash, {"running"})
        command(["kill", "-s", "SIGKILL", "worker"])
        command(["up", "-d", "--no-deps", "--no-recreate", "--no-build", "worker"])
        # TLS listener startup is asynchronous; readiness is checked with a public status read.
        for attempt in range(30):
            try:
                result = api("status", crash)
                break
            except RuntimeError:
                if attempt == 29:
                    raise
                time.sleep(0.2)
        assert result["status"] == "failed" and result["error_code"] == "SBX-008"
        probe("cleanup")
        print(
            "PASS SIGKILL restart reconciles uncertain task, without retry or orphan process",
            flush=True,
        )
    finally:
        command(["unpause", "database"])
        command(["up", "-d", "--no-deps", "--no-recreate", "--no-build", "worker"])

    replay_id = "restart-" + uuid.uuid4().hex
    task = create(request_id=replay_id)["task_id"]
    wait(task, {"succeeded"})
    command(["restart", "--no-deps", "worker"])
    for attempt in range(30):
        try:
            assert api("status", task)["status"] == "succeeded"
            break
        except RuntimeError:
            if attempt == 29:
                raise
            time.sleep(0.2)
    payload = {
        "request_id": replay_id,
        "target_id": "isolated-local",
        "operation": "rds.connectivity_check",
        "parameters": {},
        "ttl_seconds": 60,
    }
    result = subprocess.run(
        COMPOSE
        + [
            "exec",
            "-T",
            "agent",
            "python3",
            "-m",
            "openagent_secretbox.linux_worker.client",
            "create",
        ],
        input=json.dumps(payload).encode(),
        capture_output=True,
        timeout=10,
    )
    assert json.loads(result.stdout)["error_code"] == "SBX-006"
    print("PASS completed task and replay protection survive restart", flush=True)

    command(["stop", "provider"])
    try:
        unavailable = create()["task_id"]
        assert wait(unavailable, {"failed"})["error_code"] == "SBX-009"
    finally:
        command(["up", "-d", "--no-deps", "--no-recreate", "--no-build", "provider"])
    print("PASS unavailable credential provider fails closed", flush=True)
    logs = command(["logs", "--no-color"])
    command(["exec", "-T", "bootstrap", "python3", "/app/lab.py", "scan"], logs)
    print("PASS generated passwords and private keys absent from captured service logs", flush=True)

    # Leave a usable empty target for the user's own restore acceptance.
    command(
        [
            "exec",
            "-T",
            "--user",
            "postgres",
            "database",
            "psql",
            "-X",
            "-w",
            "-d",
            "sbx_lab",
            "-v",
            "ON_ERROR_STOP=1",
            "-c",
            "DROP TABLE IF EXISTS public.sbx_fixture;",
        ]
    )
    wait(create()["task_id"], {"succeeded"})
    print("PASS synthetic table cleaned; live mTLS task service remains available", flush=True)
    return 0


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    except Exception as exc:
        print(f"FAIL Linux acceptance ({type(exc).__name__}); raw logs withheld", file=sys.stderr)
        raise SystemExit(1) from None
