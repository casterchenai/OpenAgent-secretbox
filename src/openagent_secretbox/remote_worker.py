"""Phase 1 simulation only: no sockets, subprocesses, credentials, or MCP exposure."""

from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import threading
import time
from collections.abc import Callable, Mapping
from dataclasses import dataclass, field
from typing import Any

OPERATIONS = frozenset({
    "rds.connectivity_check", "rds.restore_public_business", "rds.verify_restore",
})
TERMINAL = frozenset({"succeeded", "failed", "timed_out", "cancelled"})
IDENTIFIER = re.compile(r"[a-zA-Z0-9][a-zA-Z0-9_-]{0,79}\Z")


class WorkerError(Exception):
    """Only stable codes cross the public boundary."""

    def __init__(self, code: str) -> None:
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class MockTarget:
    target_id: str
    operations: frozenset[str] = OPERATIONS
    environment: str = "isolated"


@dataclass(frozen=True)
class MockScenario:
    """Trusted test harness inputs; never accepted from task metadata."""

    duration: float = 0
    stdout: str = field(default="", repr=False)
    stderr: str = field(default="", repr=False)
    crash: bool = False
    cleanup_fails: bool = False
    verification_fails: bool = False
    preflight_fails: bool = False


@dataclass
class _Task:
    request: dict[str, Any]
    task_id: str
    expires: float
    nonce: str
    status: str = "created"
    history: list[str] = field(default_factory=lambda: ["created"])
    error: str | None = None
    started: float | None = None
    finished: float | None = None
    cleanup: bool = False
    cancel: threading.Event = field(default_factory=threading.Event)
    confirmation_expires: float | None = None
    preflight_id: str | None = None
    scenario: MockScenario = field(default_factory=MockScenario, repr=False)

    def transition(self, status: str) -> None:
        self.status = status
        self.history.append(status)


class MockWorker:
    """In-process broker/worker simulator. Tokens are internal, not agent results.

    A fresh random signing key on every instance invalidates pre-restart tokens.
    All mutations are serialized. Only fixed events, never free-form output, leave
    the simulator. This is not a remote authentication or execution service.
    """

    def __init__(
        self, targets: tuple[MockTarget, ...], *, worker_id: str = "mock-worker",
        clock: Callable[[], float] = time.monotonic, capacity: int = 1000,
    ) -> None:
        self._targets = {t.target_id: t for t in targets}
        self._worker_id = worker_id
        self._key = secrets.token_bytes(32)
        self._clock = clock
        self._capacity = capacity
        self._tasks: dict[str, _Task] = {}
        self._requests: set[str] = set()
        self._used: set[str] = set()
        self._lock = threading.RLock()

    def create(self, request: Mapping[str, Any], *, ttl: int = 600) -> dict[str, Any]:
        with self._lock:
            if (set(request) != {"request_id", "operation", "target_id", "parameters"}
                    or type(ttl) is not int or not 1 <= ttl <= 600):
                raise WorkerError("SBX-001")
            for key in ("request_id", "target_id"):
                if not isinstance(request[key], str) or not IDENTIFIER.fullmatch(request[key]):
                    raise WorkerError("SBX-001")
            operation = request["operation"]
            if not isinstance(operation, str) or operation not in OPERATIONS:
                raise WorkerError("SBX-003")
            target = self._targets.get(request["target_id"])
            if target is None or target.environment != "isolated":
                raise WorkerError("SBX-002")
            if operation not in target.operations:
                raise WorkerError("SBX-003")
            params = request["parameters"]
            expected = {
                "rds.connectivity_check": set(),
                "rds.restore_public_business": {"backup_id", "scope", "allow_existing_data"},
                "rds.verify_restore": {"expected_manifest"},
            }[operation]
            if type(params) is not dict or set(params) != expected:
                raise WorkerError("SBX-001")
            if operation == "rds.restore_public_business" and (
                params["scope"] != "public_business_only"
                or params["allow_existing_data"] is not False
            ):
                raise WorkerError("SBX-001")
            for key in ("backup_id", "expected_manifest"):
                if key in params and (
                    not isinstance(params[key], str) or not IDENTIFIER.fullmatch(params[key])
                ):
                    raise WorkerError("SBX-001")
            if request["request_id"] in self._requests:
                raise WorkerError("SBX-006")
            if len(self._tasks) >= self._capacity:
                raise WorkerError("SBX-008")
            task_id = "task_" + secrets.token_hex(16)
            task = _Task(
                json.loads(json.dumps(dict(request))), task_id, self._clock() + ttl,
                secrets.token_hex(16),
            )
            task.transition("validated")
            task.transition("queued")
            self._tasks[task_id] = task
            self._requests.add(request["request_id"])
            return self.status(task_id)

    def _get(self, task_id: str) -> _Task:
        task = self._tasks.get(task_id)
        if task is None:
            raise WorkerError("SBX-001")
        return task

    def _payload(self, task: _Task) -> bytes:
        return json.dumps({
            "task_id": task.task_id, "worker_id": self._worker_id,
            "request": task.request, "expires": task.expires, "nonce": task.nonce,
        }, sort_keys=True, separators=(",", ":")).encode()

    def issue_internal_token(self, task_id: str) -> str:
        """Trusted broker-to-worker harness only. Never expose through MCP."""
        with self._lock:
            payload = self._payload(self._get(task_id))
            return hmac.new(self._key, payload, hashlib.sha256).hexdigest()

    def _finish(self, task: _Task, status: str, code: str | None = None) -> None:
        task.cleanup = not task.scenario.cleanup_fails
        task.error = code if task.cleanup else "SBX-014"
        task.finished = self._clock()
        task.transition(status if task.cleanup else "failed")

    def _tick(self, task: _Task) -> None:
        now = self._clock()
        if task.status == "queued" and now >= task.expires:
            self._finish(task, "timed_out", "SBX-005")
        elif task.status == "awaiting_confirmation" and (
            now >= task.expires or now >= (task.confirmation_expires or 0)
        ):
            self._finish(task, "timed_out", "SBX-005")
        elif task.status == "running":
            if task.cancel.is_set():
                self._finish(task, "cancelled", "SBX-013")
            elif now >= task.expires:
                self._finish(task, "timed_out", "SBX-012")
            elif now - (task.started or 0) >= task.scenario.duration:
                if task.scenario.crash:
                    self._finish(task, "failed", "SBX-008")
                elif task.scenario.verification_fails:
                    self._finish(task, "failed", "RDS-008")
                else:
                    self._finish(task, "succeeded")

    def dispatch(
        self, task_id: str, token: str, *, scenario: MockScenario | None = None,
    ) -> dict[str, Any]:
        with self._lock:
            task = self._get(task_id)
            self._tick(task)
            if task.status == "timed_out":
                raise WorkerError("SBX-005")
            if task.nonce in self._used or task.status != "queued":
                raise WorkerError("SBX-006")
            if (not isinstance(token, str) or not re.fullmatch(r"[0-9a-f]{64}", token)
                    or not hmac.compare_digest(
                token, self.issue_internal_token(task_id),
            )):
                raise WorkerError("SBX-007")
            self._used.add(task.nonce)
            scenario = scenario or MockScenario()
            task.scenario = scenario
            if task.request["operation"] == "rds.restore_public_business":
                if scenario.preflight_fails:
                    self._finish(task, "failed", "RDS-010")
                else:
                    task.preflight_id = "preflight_" + secrets.token_hex(16)
                    task.confirmation_expires = min(task.expires, self._clock() + 300)
                    task.transition("awaiting_confirmation")
            else:
                task.started = self._clock()
                task.expires = task.started + 1800
                task.transition("running")
            return self.status(task_id)

    def confirm_from_trusted_ui(self, task_id: str, preflight_id: str) -> dict[str, Any]:
        """Harness stand-in for authenticated owner UI, NOT an agent tool."""
        with self._lock:
            task = self._get(task_id)
            self._tick(task)
            if task.status != "awaiting_confirmation" or preflight_id != task.preflight_id:
                raise WorkerError("SBX-004")
            task.started = self._clock()
            task.expires = task.started + 1800
            task.transition("running")
            return self.status(task_id)

    def cancel(self, task_id: str) -> dict[str, Any]:
        with self._lock:
            task = self._get(task_id)
            self._tick(task)
            if task.status not in TERMINAL:
                task.cancel.set()
                self._finish(task, "cancelled", "SBX-013")
            return self.status(task_id)

    def status(self, task_id: str) -> dict[str, Any]:
        with self._lock:
            task = self._get(task_id)
            self._tick(task)
            return {
                "task_id": task.task_id, "status": task.status, "error_code": task.error,
                "exit_code": 0 if task.status == "succeeded" else None,
                "summary": {"simulation": True, "cleanup_completed": task.cleanup},
                "redacted_logs": list(task.history),
                "preflight_id": task.preflight_id,
            }
