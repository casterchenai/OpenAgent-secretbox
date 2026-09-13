"""mTLS task service with durable replay records and serialized execution."""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
import secrets
import signal
import sqlite3
import ssl
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path
from typing import Any

from .common import TASK_ID, TERMINAL, Rejected, decode, tls, validate
from .executor import execute

if sys.platform != "linux":
    raise RuntimeError("Task service requires Linux")


class Tasks:
    def __init__(self, config: dict[str, Any], path: str = "/state/tasks.sqlite") -> None:
        self.config = config
        self.lock = threading.RLock()
        self.stopping = threading.Event()
        self.cancels: dict[str, threading.Event] = {}
        self.db = sqlite3.connect(path, check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        self.db.execute("PRAGMA journal_mode=WAL")
        self.db.execute("PRAGMA synchronous=FULL")
        self.db.execute(
            "CREATE TABLE IF NOT EXISTS tasks (id TEXT PRIMARY KEY, request_id TEXT UNIQUE,"
            " operation TEXT, status TEXT, expires REAL, created REAL, finished REAL,"
            " confirmation TEXT, approval_deadline REAL, error TEXT, summary TEXT, history TEXT)",
        )
        # No auto-retry after process death: restore may already have committed.
        for row in self.db.execute(
            "SELECT id FROM tasks WHERE status NOT IN "
            "('succeeded','failed','cancelled','timed_out')",
        ).fetchall():
            self.change(row["id"], "failed", "SBX-008")
        self.db.commit()
        self.thread = threading.Thread(target=self.work, daemon=False)
        self.thread.start()

    def row(self, task_id: str) -> sqlite3.Row:
        if not TASK_ID.fullmatch(task_id):
            raise Rejected("SBX-001")
        row = self.db.execute("SELECT * FROM tasks WHERE id=?", (task_id,)).fetchone()
        if row is None:
            raise Rejected("SBX-001")
        assert isinstance(row, sqlite3.Row)
        return row

    def change(self, task_id: str, status: str, error: str | None = None) -> None:
        row = self.row(task_id)
        history = json.loads(row["history"])
        history.append(status)
        self.db.execute(
            "UPDATE tasks SET status=?,error=?,history=?,finished=? WHERE id=?",
            (
                status,
                error,
                json.dumps(history),
                time.time() if status in TERMINAL else None,
                task_id,
            ),
        )
        self.db.commit()

    def create(self, request: dict[str, Any]) -> dict[str, Any]:
        validate(request, self.config)
        with self.lock:
            if self.db.execute("SELECT count(*) FROM tasks").fetchone()[0] >= 10000:
                raise Rejected("SBX-008")
            active = self.db.execute(
                "SELECT count(*) FROM tasks WHERE status NOT IN "
                "('succeeded','failed','cancelled','timed_out')",
            ).fetchone()[0]
            if active >= 8:
                raise Rejected("SBX-008")
            task_id = "task_" + secrets.token_hex(16)
            try:
                self.db.execute(
                    "INSERT INTO tasks VALUES (?,?,?,?,?,?,NULL,NULL,NULL,NULL,?,?)",
                    (
                        task_id,
                        request["request_id"],
                        request["operation"],
                        "queued",
                        time.time() + request["ttl_seconds"],
                        time.time(),
                        "{}",
                        json.dumps(["created", "validated", "queued"]),
                    ),
                )
                self.db.commit()
            except sqlite3.IntegrityError:
                self.db.rollback()
                raise Rejected("SBX-006") from None
            return self.status(task_id)

    def status(self, task_id: str) -> dict[str, Any]:
        with self.lock:
            row = self.row(task_id)
            return {
                "task_id": row["id"],
                "operation": row["operation"],
                "target_id": self.config["target_id"],
                "status": row["status"],
                "error_code": row["error"],
                "exit_code": 0 if row["status"] == "succeeded" else None,
                "summary": json.loads(row["summary"]),
                "events": json.loads(row["history"]),
                "preflight_id": row["confirmation"],
                "created_at": row["created"],
                "finished_at": row["finished"],
            }

    def cancel(self, task_id: str) -> dict[str, Any]:
        with self.lock:
            row = self.row(task_id)
            if row["status"] in ("running", "preflight"):
                self.cancels[task_id].set()
                # This is only a request; do not promise rollback or completed cleanup.
                return {**self.status(task_id), "cancel_requested": True}
            if row["status"] not in TERMINAL:
                self.change(task_id, "cancelled", "SBX-013")
            return self.status(task_id)

    def confirm(self, task_id: str, request: dict[str, Any]) -> dict[str, Any]:
        with self.lock:
            row = self.row(task_id)
            if set(request) != {"preflight_id"} or (
                row["status"] != "awaiting_confirmation"
                or request["preflight_id"] != row["confirmation"]
                or time.time() >= row["approval_deadline"]
                or time.time() >= row["expires"]
            ):
                raise Rejected("SBX-004")
            self.change(task_id, "approved")
            return self.status(task_id)

    def work(self) -> None:
        while not self.stopping.wait(0.05):
            with self.lock:
                for row in self.db.execute(
                    "SELECT * FROM tasks WHERE status IN "
                    "('queued','approved','awaiting_confirmation')",
                ).fetchall():
                    if time.time() >= row["expires"] or (
                        row["status"] == "awaiting_confirmation"
                        and time.time() >= row["approval_deadline"]
                    ):
                        self.change(row["id"], "timed_out", "SBX-005")
                row = self.db.execute(
                    "SELECT * FROM tasks WHERE status IN ('queued','approved') "
                    "ORDER BY created LIMIT 1",
                ).fetchone()
                if row is None:
                    continue
                task_id = row["id"]
                inspecting = row["operation"] == "rds.restore_public_business" and (
                    row["status"] == "queued"
                )
                cancel = threading.Event()
                self.cancels[task_id] = cancel
                self.change(task_id, "preflight" if inspecting else "running")
            error = None
            summary: dict[str, Any] = {}
            try:
                summary = execute(self.config, row["operation"], cancel, inspect_only=inspecting)
            except Rejected as exc:
                error = exc.code
            except Exception:
                error = "SBX-008"
            with self.lock:
                if cancel.is_set() and error is None:
                    error = "SBX-013"
                self.cancels.pop(task_id, None)
                if error:
                    status = {"SBX-013": "cancelled", "SBX-012": "timed_out"}.get(error, "failed")
                    self.change(task_id, status, error)
                elif inspecting:
                    # Bind approval to immutable task + immutable backup hashes.
                    preflight = hashlib.sha256(
                        (task_id + json.dumps(self.config["hashes"], sort_keys=True)).encode(),
                    ).hexdigest()
                    self.db.execute(
                        "UPDATE tasks SET confirmation=?,approval_deadline=? WHERE id=?",
                        (preflight, min(row["expires"], time.time() + 300), task_id),
                    )
                    self.change(task_id, "awaiting_confirmation")
                else:
                    self.db.execute(
                        "UPDATE tasks SET summary=? WHERE id=?",
                        (json.dumps(summary), task_id),
                    )
                    self.change(task_id, "succeeded")

    def close(self) -> None:
        self.stopping.set()
        with self.lock:
            for event in self.cancels.values():
                event.set()
        self.thread.join(timeout=40)
        if self.thread.is_alive():
            raise RuntimeError("worker shutdown failed")
        self.db.close()


def main() -> None:
    os.umask(0o077)
    if os.getuid() == 0:
        raise SystemExit("Worker must run as a non-root user")
    lock_fd = os.open("/state/worker.lock", os.O_CREAT | os.O_RDWR, 0o600)
    fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
    config = decode(Path("/config/worker.json").read_bytes())
    if config["environment"] != "isolated" or config["max_runtime_seconds"] > 1800:
        raise SystemExit("Invalid trusted worker configuration")
    tasks = Tasks(config)
    shutdown = threading.Event()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, format: str, *args: Any) -> None:
            pass

        def handle_one_request(self) -> None:
            self.connection.settimeout(3)
            try:
                super().handle_one_request()
            except (OSError, ValueError):
                self.close_connection = True

        def respond(self, status: int, result: dict[str, Any]) -> None:
            data = json.dumps(result).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Cache-Control", "no-store")
            self.send_header("X-Content-Type-Options", "nosniff")
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Connection", "close")
            self.end_headers()
            self.wfile.write(data)

        def route(self) -> None:
            try:
                if not isinstance(self.connection, ssl.SSLSocket):
                    raise Rejected("SBX-007")
                cert: Any = self.connection.getpeercert()
                names = [
                    value
                    for group in (cert or {}).get("subject", ())
                    for key, value in group
                    if key == "commonName"
                ]
                if names not in (["sbx-agent"], ["sbx-owner"]):
                    raise Rejected("SBX-007")
                if self.headers.get("Origin") or self.headers.get("Transfer-Encoding"):
                    raise Rejected("SBX-001")
                parts = self.path.split("/")
                body: dict[str, Any] = {}
                if self.command == "POST":
                    if (
                        len(self.headers.get_all("Content-Length", [])) != 1
                        or self.headers.get("Content-Type") != "application/json"
                    ):
                        raise Rejected("SBX-001")
                    length = int(self.headers.get("Content-Length", "0"))
                    if not 1 <= length <= 4096:
                        raise Rejected("SBX-001")
                    body = decode(self.rfile.read(length))
                if self.command == "POST" and self.path == "/v1/tasks":
                    self.respond(201, tasks.create(body))
                elif len(parts) == 4 and parts[1:3] == ["v1", "tasks"] and self.command == "GET":
                    self.respond(200, tasks.status(parts[3]))
                elif len(parts) == 5 and parts[1:3] == ["v1", "tasks"] and self.command == "POST":
                    if parts[4] == "cancel" and body == {}:
                        self.respond(200, tasks.cancel(parts[3]))
                    elif parts[4] == "confirm" and names == ["sbx-owner"]:
                        self.respond(200, tasks.confirm(parts[3], body))
                    else:
                        raise Rejected("SBX-007")
                else:
                    raise Rejected("SBX-001")
            except Rejected as exc:
                self.respond(400, {"error_code": exc.code})
            except Exception:
                try:
                    self.respond(500, {"error_code": "SBX-008"})
                except OSError:
                    pass

        do_GET = route
        do_POST = route

    class Server(HTTPServer):
        def get_request(self) -> tuple[ssl.SSLSocket, Any]:
            sock, address = self.socket.accept()
            sock.settimeout(3)
            try:
                return context.wrap_socket(sock, server_side=True), address
            except Exception:
                sock.close()
                raise

        def handle_error(self, request: Any, client_address: Any) -> None:
            pass

    context = tls(Path("/tls"), server=True)
    server = Server(("0.0.0.0", 8443), Handler)
    server.timeout = 0.2
    signal.signal(signal.SIGTERM, lambda *_: shutdown.set())
    signal.signal(signal.SIGINT, lambda *_: shutdown.set())
    try:
        while not shutdown.is_set():
            if not tasks.thread.is_alive():
                raise SystemExit("Worker executor stopped")
            server.handle_request()
    finally:
        server.server_close()
        tasks.close()
        os.close(lock_fd)


if __name__ == "__main__":
    main()
