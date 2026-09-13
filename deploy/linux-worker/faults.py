"""Trusted Linux-only fault probes. Never exposed as worker task operations."""

import json
import os
import socket
import sys
import threading
import time
from pathlib import Path

from openagent_secretbox.linux_worker.common import Rejected
from openagent_secretbox.linux_worker.executor import credential, query, run


def cleanup():
    children = []
    memory_fds = []
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            command = (proc / "cmdline").read_bytes()
            if b"/usr/bin/psql\0" in command or b"/usr/bin/pg_restore\0" in command:
                children.append(proc.name)
            for fd in (proc / "fd").iterdir():
                if "memfd:sbx-pgpass" in os.readlink(fd):
                    memory_fds.append(proc.name)
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    assert not children and not memory_fds, "Worker child or pgpass fd survived cleanup"
    print("PASS no surviving PostgreSQL child or anonymous credential fd")


def anonymous():
    found = False
    for proc in Path("/proc").iterdir():
        if not proc.name.isdigit() or int(proc.name) == os.getpid():
            continue
        try:
            cmd = (proc / "cmdline").read_bytes()
            env = (proc / "environ").read_bytes()
            assert b"PGPASSWORD=" not in env
            for fd in (proc / "fd").iterdir():
                link = os.readlink(fd)
                if "memfd:sbx-pgpass" in link:
                    assert (fd.stat().st_mode & 0o777) == 0o600
                    password = fd.read_bytes().rstrip(b"\n").rsplit(b":", 1)[1]
                    assert password not in env and password not in cmd
                    assert b"PGPASSFILE=/proc/self/fd/" in env or proc.name == "1"
                    found = True
            assert b"password=" not in cmd.lower()
        except (FileNotFoundError, PermissionError, ProcessLookupError):
            continue
    assert found, "Expected active anonymous pgpass fd"
    print("PASS active anonymous 0600 pgpass; no PGPASSWORD or password argument")


def timeout():
    config = json.loads(Path("/config/worker.json").read_text())
    with credential(config) as env:
        try:
            run(
                ["/usr/bin/psql", "-X", "-w", "-At"],
                b"SELECT pg_sleep(20);",
                env,
                time.monotonic() + 0.5,
                threading.Event(),
            )
        except Rejected as exc:
            assert exc.code == "SBX-012"
        else:
            raise AssertionError("Real process timeout did not fire")
    cleanup()
    print("PASS real sleeping SQL timeout and child cleanup")


def bounded():
    config = json.loads(Path("/config/worker.json").read_text())
    with credential(config) as env:
        try:
            run(
                ["/usr/bin/psql", "-X", "-w", "-At"],
                b"SELECT repeat('x',20000);",
                env,
                time.monotonic() + 5,
                threading.Event(),
            )
        except Rejected as exc:
            assert exc.code == "SBX-011"
        else:
            raise AssertionError("Raw output limit not enforced")
    cleanup()
    print("PASS excessive subprocess output rejected without returning raw output")


def lease_replay():
    def get(data):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(3)
            channel.connect("/run/provider/credentials.sock")
            channel.sendall(json.dumps(data).encode() + b"\n")
            return channel.recv(1024)

    req = {
        "lease_id": os.urandom(32).hex(),
        "target_id": "isolated-local",
        "expires_at": time.time() + 20,
    }
    assert len(get(req)) > 0
    assert get(req) == b""
    assert get({**req, "lease_id": os.urandom(32).hex(), "expires_at": time.time() - 1}) == b""
    assert get({**req, "lease_id": os.urandom(32).hex(), "target_id": "other"}) == b""
    print("PASS credential provider replay, TTL and target restrictions")


def peer():
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
        channel.settimeout(3)
        channel.connect("/run/provider/credentials.sock")
        try:
            channel.sendall(
                json.dumps(
                    {
                        "lease_id": os.urandom(32).hex(),
                        "target_id": "isolated-local",
                        "expires_at": time.time() + 20,
                    }
                ).encode()
                + b"\n"
            )
            assert channel.recv(1024) == b""
        except ConnectionResetError:
            pass
    print("PASS provider rejects unauthorized peer UID even with socket filesystem access")


def errors():
    config = json.loads(Path("/config/worker.json").read_text())
    for sql, code in [
        ("SELECT 'synthetic-sensitive-output';", "SBX-011"),
        ("DO $$ BEGIN RAISE EXCEPTION 'synthetic-sensitive-error'; END $$;", "RDS-001"),
    ]:
        with credential(config) as env:
            try:
                query(sql, env, time.monotonic() + 5, threading.Event())
            except Rejected as exc:
                assert str(exc) == code
            else:
                raise AssertionError("Unexpected output was accepted")
    print("PASS real stdout/stderr failures return stable codes only")


if __name__ == "__main__":
    {
        "cleanup": cleanup,
        "anonymous": anonymous,
        "timeout": timeout,
        "bounded": bounded,
        "lease": lease_replay,
        "peer": peer,
        "errors": errors,
    }[sys.argv[1]]()
