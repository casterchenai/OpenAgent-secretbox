"""Container-side assertions. Only fixed pass messages and public metadata are printed."""

import json
import socket
import ssl
import sys
import time
import uuid
from pathlib import Path

from openagent_secretbox.linux_worker.client import call
from openagent_secretbox.linux_worker.common import tls


def request(operation, request_id=None):
    params = {
        "rds.connectivity_check": {},
        "rds.restore_public_business": {
            "backup_id": "lab-public-v1",
            "scope": "public_business_only",
            "allow_existing_data": False,
        },
        "rds.verify_restore": {"expected_manifest": "lab-public-v1"},
    }[operation]
    return {
        "request_id": request_id or "qa-" + uuid.uuid4().hex,
        "operation": operation,
        "target_id": "isolated-local",
        "parameters": params,
        "ttl_seconds": 60,
    }


def wait(task, expected):
    for _ in range(240):
        result = call("GET", "/v1/tasks/" + task)
        if result["status"] in expected:
            return result
        if result["status"] in ("failed", "cancelled", "timed_out", "succeeded"):
            raise RuntimeError("Unexpected terminal state: " + json.dumps(result))
        time.sleep(0.1)
    raise RuntimeError("Task wait deadline exceeded")


def policy():
    r = request("rds.connectivity_check")
    result = call("POST", "/v1/tasks", r)
    assert wait(result["task_id"], {"succeeded"})["summary"]["connected"] is True
    assert call("POST", "/v1/tasks", r)["error_code"] == "SBX-006"
    for key, value, error in [
        ("target_id", "production", "SBX-002"),
        ("operation", "shell", "SBX-003"),
        ("parameters", {"host": "elsewhere"}, "SBX-001"),
        ("ttl_seconds", 0, "SBX-001"),
    ]:
        bad = {**request("rds.connectivity_check"), key: value}
        assert call("POST", "/v1/tasks", bad)["error_code"] == error
    import http.client

    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.load_verify_locations("/tls/ca.crt")
    conn = http.client.HTTPSConnection("worker", 8443, context=ctx, timeout=5)
    try:
        conn.request("GET", "/v1/tasks/task_" + "0" * 32)
        conn.getresponse()
    except (ssl.SSLError, ConnectionError):
        pass
    else:
        raise AssertionError("Unauthenticated client was accepted")
    finally:
        conn.close()
    print("PASS real TLS database connection, replay, policy, mTLS client-certificate enforcement")


def restore():
    result = call("POST", "/v1/tasks", request("rds.restore_public_business"))
    task = result["task_id"]
    ready = wait(task, {"awaiting_confirmation"})
    if sys.argv[1] == "unprivileged":
        denied = call("POST", f"/v1/tasks/{task}/confirm", {"preflight_id": ready["preflight_id"]})
        assert denied["error_code"] == "SBX-007"
        assert call("POST", f"/v1/tasks/{task}/cancel", {})["status"] == "cancelled"
        print("PASS agent cannot approve restore; awaiting task cancellation")
        return
    result = call("POST", f"/v1/tasks/{task}/confirm", {"preflight_id": ready["preflight_id"]})
    assert result["status"] == "approved"
    result = wait(task, {"succeeded"})
    assert result["summary"] == {
        "restored": True,
        "verified": True,
        "tables": 1,
        "rows": 2,
        "constraints": 1,
    }
    assert (
        call("POST", f"/v1/tasks/{task}/confirm", {"preflight_id": ready["preflight_id"]})[
            "error_code"
        ]
        == "SBX-004"
    )
    verified = call("POST", "/v1/tasks", request("rds.verify_restore"))
    assert wait(verified["task_id"], {"succeeded"})["summary"]["verified"]
    again = call("POST", "/v1/tasks", request("rds.restore_public_business"))
    assert wait(again["task_id"], {"failed"})["error_code"] == "RDS-003"
    print("PASS actual pg_restore, typed count verification, no overwrite, no duplicate approval")


def provider_boundary():
    # This runs as the agent: no credential/provider/worker-state volumes are mounted.
    for path in (
        "/secrets/database-password",
        "/run/provider/credentials.sock",
        "/db-secrets/admin-password",
        "/state/tasks.sqlite",
        "/config/worker.json",
    ):
        assert not Path(path).exists()
    print(
        "PASS agent container cannot access database credentials, provider socket or worker state"
    )


def ingress():
    with socket.create_connection(("ingress", 8443), timeout=3) as raw:
        with tls(Path("/tls")).wrap_socket(raw, server_hostname="worker") as secure:
            secure.sendall(
                b"GET /v1/tasks/task_00000000000000000000000000000000 HTTP/1.1\r\n"
                b"Host: worker\r\nConnection: close\r\n\r\n"
            )
            data = bytearray()
            while True:
                chunk = secure.recv(4096)
                if not chunk:
                    break
                data.extend(chunk)
            assert b'"error_code": "SBX-001"' in data
    print("PASS ingress relays authenticated TLS without terminating it")


if __name__ == "__main__":
    {
        "policy": policy,
        "unprivileged": restore,
        "restore": restore,
        "boundary": provider_boundary,
        "ingress": ingress,
    }[sys.argv[1]]()
