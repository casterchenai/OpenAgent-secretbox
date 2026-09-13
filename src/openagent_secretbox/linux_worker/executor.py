"""Fixed PostgreSQL operations; bounded output and anonymous pgpass descriptor."""

from __future__ import annotations

import contextlib
import ctypes
import hashlib
import json
import os
import selectors
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Iterator
from pathlib import Path
from typing import Any

from .common import Rejected, decode

if sys.platform != "linux":
    raise RuntimeError("Execution worker requires Linux")


@contextlib.contextmanager
def credential(config: dict[str, Any]) -> Iterator[dict[str, str]]:
    fd = -1
    password = bytearray()
    try:
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as channel:
            channel.settimeout(3)
            channel.connect("/run/provider/credentials.sock")
            channel.sendall(
                json.dumps(
                    {
                        "lease_id": os.urandom(32).hex(),
                        "target_id": config["target_id"],
                        "expires_at": time.time() + 20,
                    }
                ).encode()
                + b"\n"
            )
            while len(password) <= 512:
                chunk = channel.recv(513)
                if not chunk:
                    break
                password.extend(chunk)
        if not password or len(password) > 512 or b"\n" in password or b"\r" in password:
            raise Rejected("SBX-009")
        fd = os.memfd_create("sbx-pgpass", os.MFD_CLOEXEC)
        os.fchmod(fd, 0o600)
        fields = [
            config["host"].encode(),
            b"5432",
            config["database"].encode(),
            config["username"].encode(),
            bytes(password),
        ]
        os.write(
            fd, b":".join(v.replace(b"\\", b"\\\\").replace(b":", b"\\:") for v in fields) + b"\n"
        )
        os.lseek(fd, 0, os.SEEK_SET)
        yield {
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "PGHOST": config["host"],
            "PGPORT": "5432",
            "PGDATABASE": config["database"],
            "PGUSER": config["username"],
            "PGPASSFILE": f"/proc/self/fd/{fd}",
            "PGSSLMODE": "verify-full",
            "PGSSLROOTCERT": "/config/db-ca.crt",
            "PGCONNECT_TIMEOUT": "5",
            "PGOPTIONS": "-c statement_timeout=30000 -c lock_timeout=3000",
            "PYTHONPATH": "/app/src",
            "PYTHONDONTWRITEBYTECODE": "1",
        }
    except Rejected:
        raise
    except Exception:
        raise Rejected("SBX-009") from None
    finally:
        try:
            if fd >= 0:
                os.close(fd)
        except OSError:
            raise Rejected("SBX-014") from None
        finally:
            password[:] = b"\0" * len(password)


def run(
    argv: list[str],
    sql: bytes,
    env: dict[str, str],
    deadline: float,
    cancel: threading.Event,
) -> bytes:
    fd = int(env["PGPASSFILE"].rsplit("/", 1)[1])
    process = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "openagent_secretbox.linux_worker.executor",
            str(os.getpid()),
            *argv,
        ],
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.DEVNULL,
        env=env,
        pass_fds=(fd,),
        start_new_session=True,
    )
    output = bytearray()
    try:
        assert process.stdin is not None and process.stdout is not None
        process.stdin.write(sql)
        process.stdin.close()
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            while True:
                if cancel.is_set():
                    raise Rejected("SBX-013")
                if time.monotonic() >= deadline:
                    raise Rejected("SBX-012")
                for key, _ in selector.select(0.05):
                    chunk = os.read(key.fd, 4096)
                    if chunk:
                        output.extend(chunk)
                        if len(output) > 16384:
                            raise Rejected("SBX-011")
                    else:
                        selector.unregister(key.fileobj)
                if process.poll() is not None and not selector.get_map():
                    break
        if process.returncode != 0:
            raise Rejected("RDS-007" if "pg_restore" in argv[0] else "RDS-001")
        return bytes(output)
    finally:
        try:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            process.wait(timeout=5)
        except (OSError, subprocess.TimeoutExpired):
            raise Rejected("SBX-014") from None
        if process.stdout:
            process.stdout.close()
        if process.stdin and not process.stdin.closed:
            process.stdin.close()


def query(
    sql: str, env: dict[str, str], deadline: float, cancel: threading.Event
) -> dict[str, Any]:
    raw = run(
        ["/usr/bin/psql", "-X", "-w", "-A", "-t", "-v", "ON_ERROR_STOP=1"],
        sql.encode(),
        env,
        deadline,
        cancel,
    )
    try:
        return decode(raw)
    except Rejected:
        raise Rejected("SBX-011") from None


def preflight(
    config: dict[str, Any],
    env: dict[str, str],
    deadline: float,
    cancel: threading.Event,
) -> dict[str, Any]:
    result = query(
        "SELECT json_build_object('fingerprint',(SELECT system_identifier::text "
        "FROM pg_control_system()),'database',current_database(),'username',current_user,"
        "'version',current_setting('server_version_num')::int / 10000,"
        "'tables',(SELECT count(*) FROM pg_class c JOIN pg_namespace n ON n.oid=c.relnamespace "
        "WHERE n.nspname='public' AND c.relkind IN ('r','p','v','m','S','f')),"
        "'functions',(SELECT count(*) FROM pg_proc p JOIN pg_namespace n ON n.oid=p.pronamespace "
        "WHERE n.nspname='public'));",
        env,
        deadline,
        cancel,
    )
    for key in ("fingerprint", "database", "username", "version"):
        if result.get(key) != config[key]:
            raise Rejected("RDS-010")
    return result


def verify(
    config: dict[str, Any],
    env: dict[str, str],
    deadline: float,
    cancel: threading.Event,
) -> dict[str, Any]:
    # This release deliberately supports one reviewed lab fixture, not arbitrary business SQL.
    result = query(
        "SELECT json_build_object('tables',(SELECT count(*) FROM pg_class c JOIN pg_namespace n "
        "ON n.oid=c.relnamespace WHERE n.nspname='public' AND c.relkind IN ('r','p')),"
        "'rows',(SELECT count(*) FROM public.sbx_fixture),"
        "'constraints',(SELECT count(*) FROM pg_constraint WHERE conrelid='public.sbx_fixture'"
        "::regclass));",
        env,
        deadline,
        cancel,
    )
    if result != config["expected_counts"] or any(type(v) is not int for v in result.values()):
        raise Rejected("RDS-008")
    return {"verified": True, **result}


def check_backup(config: dict[str, Any]) -> None:
    for name in ("archive.dump", "restore.list"):
        data = (Path("/backup") / name).read_bytes()
        if hashlib.sha256(data).hexdigest() != config["hashes"][name]:
            raise Rejected("RDS-004")


def execute(
    config: dict[str, Any],
    operation: str,
    cancel: threading.Event,
    *,
    inspect_only: bool = False,
) -> dict[str, Any]:
    deadline = time.monotonic() + config["max_runtime_seconds"]
    with credential(config) as env:
        state = preflight(config, env, deadline, cancel)
        if operation == "rds.connectivity_check":
            return {"connected": True, "server_major": config["version"]}
        if operation == "rds.verify_restore":
            return verify(config, env, deadline, cancel)
        check_backup(config)
        if state["tables"] != 0 or state["functions"] != 0:
            raise Rejected("RDS-003")
        if inspect_only:
            return {"preflight_passed": True}
        run(
            [
                "/usr/bin/pg_restore",
                "--no-password",
                "--no-owner",
                "--no-privileges",
                "--single-transaction",
                "--exit-on-error",
                "--use-list=/backup/restore.list",
                f"--dbname={config['database']}",
                "/backup/archive.dump",
            ],
            b"",
            env,
            deadline,
            cancel,
        )
        return {"restored": True, **verify(config, env, deadline, cancel)}


def child() -> None:
    # Separate single-threaded launcher avoids preexec_fn in the multithreaded server.
    parent = int(sys.argv[1])
    libc = ctypes.CDLL(None, use_errno=True)
    if os.getppid() != parent or libc.prctl(1, signal.SIGKILL, 0, 0, 0) != 0:
        os._exit(125)
    if os.getppid() != parent:
        os._exit(125)
    if sys.argv[2] not in ("/usr/bin/psql", "/usr/bin/pg_restore"):
        os._exit(126)
    os.execv(sys.argv[2], sys.argv[2:])


if __name__ == "__main__":
    child()
