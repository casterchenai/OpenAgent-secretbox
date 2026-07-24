"""MCP stdio adapter for local, browser-mediated secret intake.

The MCP boundary accepts request metadata only.  Secret values travel from the
browser directly to the loopback intake server and are never returned through
MCP.  The trusted workspace and host target allowlist are process-startup
configuration, not tool arguments an agent can expand.
"""

from __future__ import annotations

import argparse
import atexit
import copy
import re
import secrets
import stat
import sys
import threading
import time
import webbrowser
from collections.abc import Callable, Mapping, Sequence
from contextlib import asynccontextmanager
from dataclasses import dataclass, replace
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .cli import DEFAULT_ALLOWED_TARGETS, _flatten_submission
from .policy import PolicyError, build_policy
from .protocol import (
    ResultValidationError,
    normalize_mcp_error,
    normalize_mcp_result,
    normalize_writer_result,
)
from .redaction import REDACTED, redact_result
from .schema import RequestValidationError, validate_request
from .server import Serving, UnknownSession, serve_once
from .ui_handoff import publish_intake_url
from .writers import apply_request

SCHEMA_VERSION = 1
DEFAULT_TTL_SECONDS = 600
MAX_TTL_SECONDS = 3_600
DEFAULT_MAX_ACTIVE_INTAKES = 8
MAX_CONFIGURED_ACTIVE_INTAKES = 32
MAX_RETAINED_TERMINAL_INTAKES = 256
TERMINAL_DRAIN_TIMEOUT_SECONDS = 2.0

_PUBLIC_STATUS = {
    "pending": "awaiting_input",
    "exchanged": "awaiting_input",
    "submitted": "awaiting_input",
    "applied": "applied",
    "failed": "failed",
    "cancelled": "cancelled",
    "expired": "expired",
}
_PUBLIC_ERROR_CODES = frozenset({"apply_blocked", "apply_failed", "expired"})
_INTAKE_ID_PATTERN = re.compile(r"^int_[A-Za-z0-9_-]{16,64}$")
_WINDOWS_REPARSE_POINT = 0x0400


class McpConfigurationError(ValueError):
    """Raised for invalid trusted process configuration."""


@dataclass
class _ManagedIntake:
    intake_id: str
    request_id: str
    serving: Serving | None
    created_at: float
    snapshot: dict[str, Any] | None = None


def _iso_timestamp(value: float) -> str:
    return (
        datetime.fromtimestamp(value, tz=timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z")
    )


def _error(code: str, message: str) -> dict[str, Any]:
    return normalize_mcp_error(
        {
            "schema_version": SCHEMA_VERSION,
            "status": "error",
            "error": {"code": code, "message": message},
        }
    )


def _json_safe(value: Any, *, depth: int = 0) -> Any:
    """Copy protocol metadata without invoking arbitrary object formatters."""

    if depth >= 16:
        return REDACTED
    if isinstance(value, Mapping):
        output: dict[str, Any] = {}
        for key, item in value.items():
            safe_key = key if isinstance(key, str) else "[REDACTED-KEY]"
            output[safe_key] = _json_safe(item, depth=depth + 1)
        return output
    if isinstance(value, (list, tuple)):
        return [_json_safe(item, depth=depth + 1) for item in value]
    if isinstance(value, (str, int, float, bool)) or value is None:
        return value
    return REDACTED


def _release_terminal_serving(serving: Serving) -> None:
    """Drop plaintext bootstrap data, then let the HTTP response drain."""

    serving.url = None
    serving.handle = None
    serving.thread.join(timeout=TERMINAL_DRAIN_TIMEOUT_SECONDS)
    if serving.thread.is_alive():
        # A terminal response is tiny and should have drained by now.  Fall back
        # to bounded forced cleanup rather than retaining a stuck listener.
        serving.close()


class IntakeManager:
    """Own loopback intake servers for one MCP stdio process."""

    def __init__(
        self,
        workspace: str | Path,
        *,
        allowed_targets: Sequence[str] = DEFAULT_ALLOWED_TARGETS,
        max_active: int = DEFAULT_MAX_ACTIVE_INTAKES,
        browser_open: Callable[[str], bool] | None = None,
        server_factory: Callable[..., Serving] = serve_once,
        clock: Callable[[], float] = time.time,
        ui_handoff_url: str | None = None,
        ui_handoff_token: str | None = None,
        ui_handoff_publish: Callable[..., bool] | None = None,
    ) -> None:
        supplied = Path(workspace).expanduser()
        try:
            root_stat = supplied.lstat()
            if (
                stat.S_ISLNK(root_stat.st_mode)
                or getattr(root_stat, "st_file_attributes", 0) & _WINDOWS_REPARSE_POINT
                or not supplied.is_dir()
            ):
                raise McpConfigurationError("workspace must be an existing directory")
            resolved = supplied.resolve(strict=True)
        except (OSError, RuntimeError, ValueError) as exc:
            raise McpConfigurationError("workspace must be an existing directory") from exc
        if isinstance(max_active, bool) or not 1 <= max_active <= MAX_CONFIGURED_ACTIVE_INTAKES:
            raise McpConfigurationError(
                f"max_active must be between 1 and {MAX_CONFIGURED_ACTIVE_INTAKES}"
            )
        self.workspace = resolved
        self.allowed_targets = tuple(allowed_targets)
        self.max_active = max_active
        self._browser_open = browser_open or (lambda url: bool(webbrowser.open(url, new=2)))
        self._server_factory = server_factory
        self._clock = clock
        handoff_url = (ui_handoff_url or "").strip() or None
        handoff_token = (ui_handoff_token or "").strip() or None
        if (handoff_url is None) ^ (handoff_token is None):
            raise McpConfigurationError(
                "ui handoff requires both --ui-handoff-url and --ui-handoff-token"
            )
        if handoff_url is not None and not (
            handoff_url.startswith("http://127.0.0.1:")
            or handoff_url.startswith("http://localhost:")
        ):
            raise McpConfigurationError("ui handoff URL must target loopback HTTP")
        if handoff_token is not None and len(handoff_token) < 16:
            raise McpConfigurationError("ui handoff token must be at least 16 characters")
        self._ui_handoff_url = handoff_url
        self._ui_handoff_token = handoff_token
        self._ui_handoff_publish = ui_handoff_publish or publish_intake_url
        self._lock = threading.RLock()
        self._intakes: dict[str, _ManagedIntake] = {}
        self._closed = False

    def _active_count_locked(self) -> int:
        count = 0
        for record in tuple(self._intakes.values()):
            status = self._status_locked(record).get("status")
            if status == "awaiting_input":
                count += 1
        return count

    def _trim_terminal_locked(self, *, protect: str | None = None) -> None:
        terminal_ids = [
            intake_id for intake_id, record in self._intakes.items() if record.snapshot is not None
        ]
        excess = len(terminal_ids) - MAX_RETAINED_TERMINAL_INTAKES
        for intake_id in terminal_ids:
            if excess <= 0:
                break
            if intake_id == protect:
                continue
            self._intakes.pop(intake_id, None)
            excess -= 1

    def _finalize_locked(
        self,
        record: _ManagedIntake,
        serving: Serving,
        output: dict[str, Any],
    ) -> dict[str, Any]:
        record.snapshot = copy.deepcopy(output)
        record.serving = None
        _release_terminal_serving(serving)
        self._trim_terminal_locked(protect=record.intake_id)
        return copy.deepcopy(output)

    def _status_locked(self, record: _ManagedIntake) -> dict[str, Any]:
        if record.snapshot is not None:
            return copy.deepcopy(record.snapshot)
        serving = record.serving
        if serving is None:
            return _error("status_unavailable", "Intake status is unavailable.")
        try:
            handle = serving.handle
            if handle is None:
                raise UnknownSession()
            raw = serving.store.get(handle.session_id)
        except (AttributeError, UnknownSession):
            return self._finalize_locked(
                record,
                serving,
                _error("status_unavailable", "Intake status is unavailable."),
            )

        raw_status = raw.get("status")
        if not isinstance(raw_status, str) or raw_status not in _PUBLIC_STATUS:
            return self._finalize_locked(
                record,
                serving,
                _error("status_unavailable", "Intake status is unavailable."),
            )
        public_status = _PUBLIC_STATUS[raw_status]
        normalized_result: dict[str, Any] | None = None
        result_invalid = False
        if public_status in {"applied", "failed"} and "result" in raw:
            try:
                candidate = redact_result(_json_safe(raw["result"]))
                normalized_result = normalize_writer_result(candidate)
            except (ResultValidationError, TypeError, ValueError):
                result_invalid = True
            else:
                allowed_nested = (
                    {"applied", "noop"} if public_status == "applied" else {"partial", "blocked"}
                )
                if normalized_result["status"] not in allowed_nested:
                    result_invalid = True
                    normalized_result = None
                elif normalized_result["request_id"] != record.request_id:
                    result_invalid = True
                    normalized_result = None
        elif public_status == "applied":
            result_invalid = True

        if result_invalid:
            public_status = "failed"
            normalized_result = None

        output: dict[str, Any] = {
            "schema_version": SCHEMA_VERSION,
            "intake_id": record.intake_id,
            "request_id": record.request_id,
            "status": public_status,
        }
        expires_at = raw.get("expires_at")
        if isinstance(expires_at, (int, float)) and not isinstance(expires_at, bool):
            output["expires_at"] = _iso_timestamp(float(expires_at))
        if normalized_result is not None:
            output["result"] = normalized_result
        error_code = raw.get("error_code")
        if result_invalid:
            output["error_code"] = "apply_failed"
        elif public_status == "failed":
            output["error_code"] = (
                error_code
                if error_code in _PUBLIC_ERROR_CODES
                else "apply_blocked"
                if normalized_result is not None
                else "apply_failed"
            )
        elif public_status == "expired":
            output["error_code"] = "expired"
        elif error_code in _PUBLIC_ERROR_CODES:
            output["error_code"] = error_code
        output = normalize_mcp_result(output)
        if public_status in {"applied", "failed", "cancelled", "expired"}:
            return self._finalize_locked(record, serving, output)
        return copy.deepcopy(output)

    def open_intake(
        self, request: Mapping[str, Any], ttl_seconds: int = DEFAULT_TTL_SECONDS
    ) -> dict[str, Any]:
        """Open a one-time local intake page without returning its bearer URL."""

        if (
            isinstance(ttl_seconds, bool)
            or not isinstance(ttl_seconds, int)
            or not 1 <= ttl_seconds <= MAX_TTL_SECONDS
        ):
            return _error(
                "invalid_ttl",
                f"ttl_seconds must be between 1 and {MAX_TTL_SECONDS}",
            )
        try:
            model = validate_request(request, workspace_root=self.workspace)
            policy = build_policy(
                model,
                self.workspace,
                allowed_targets=self.allowed_targets,
            )
        except RequestValidationError:
            return _error(
                "invalid_request",
                "Request metadata does not match the SecretBox schema.",
            )
        except PolicyError:
            return _error(
                "policy_rejected",
                "Requested targets are not authorized by the configured workspace policy.",
            )

        # Agent-supplied metadata can only narrow these controls.
        policy = replace(policy, no_overwrite=True, backup=False)

        def apply_values(_spec: Mapping[str, Any], values: Mapping[str, Any]) -> dict[str, Any]:
            flattened = _flatten_submission(model, values)
            return apply_request(model, flattened, policy=policy)

        server_request = model.to_dict()
        server_request["workspace_root"] = str(policy.workspace_root)
        server_request["write_policy"]["no_overwrite"] = True
        server_request["write_policy"]["backup"] = False

        serving: Serving | None = None
        with self._lock:
            if self._closed:
                return _error("server_closed", "The SecretBox MCP server is shutting down.")
            if self._active_count_locked() >= self.max_active:
                return _error(
                    "too_many_active_intakes",
                    "Complete or cancel an existing intake before opening another one.",
                )
            self._trim_terminal_locked()
            try:
                serving = self._server_factory(
                    request=server_request,
                    apply_fn=apply_values,
                    host="127.0.0.1",
                    port=0,
                    ttl=ttl_seconds,
                )
                if serving.url is None or serving.handle is None:
                    raise RuntimeError("missing intake handle")
            except Exception:
                if serving is not None:
                    serving.close()
                return _error(
                    "server_unavailable",
                    "The local intake server could not be started.",
                )

            intake_id = "int_" + secrets.token_urlsafe(18)
            while intake_id in self._intakes:
                intake_id = "int_" + secrets.token_urlsafe(18)

            delivery = "none"
            try:
                if self._browser_open(serving.url):
                    delivery = "desktop"
                elif self._ui_handoff_url and self._ui_handoff_token:
                    published = self._ui_handoff_publish(
                        self._ui_handoff_url,
                        token=self._ui_handoff_token,
                        intake_id=intake_id,
                        request_id=model.request_id,
                        title=str(getattr(model, "title", None) or model.request_id),
                        expires_at=_iso_timestamp(serving.handle.expires_at),
                        intake_url=serving.url,
                    )
                    if published:
                        delivery = "handoff"
            except Exception:
                delivery = "none"

            if delivery == "none":
                serving.close()
                return _error(
                    "browser_open_failed",
                    (
                        "The local intake page could not be opened. Configure a UI handoff "
                        "bridge for headless/remote hosts, or open intake on a desktop."
                    ),
                )

            record = _ManagedIntake(
                intake_id=intake_id,
                request_id=model.request_id,
                serving=serving,
                created_at=self._clock(),
            )
            self._intakes[intake_id] = record
            # Delivery path is intentionally not exposed beyond browser_opened=true.
            # Desktop open and UI handoff both mean the user can fill the form outside
            # agent context; never return URLs, tokens, or path hints that embed them.
            return normalize_mcp_result(
                {
                    "schema_version": SCHEMA_VERSION,
                    "intake_id": intake_id,
                    "request_id": model.request_id,
                    "status": "awaiting_input",
                    "expires_at": _iso_timestamp(serving.handle.expires_at),
                    "browser_opened": True,
                }
            )

    def get_status(self, intake_id: str) -> dict[str, Any]:
        """Return redacted status metadata for an intake owned by this process."""

        if not isinstance(intake_id, str) or not _INTAKE_ID_PATTERN.fullmatch(intake_id):
            return _error("intake_not_found", "The intake id is unknown or no longer retained.")
        with self._lock:
            record = self._intakes.get(intake_id)
            if record is None:
                return _error("intake_not_found", "The intake id is unknown or no longer retained.")
            return self._status_locked(record)

    def cancel_intake(self, intake_id: str) -> dict[str, Any]:
        """Stop an intake only if secret application has not started."""

        if not isinstance(intake_id, str) or not _INTAKE_ID_PATTERN.fullmatch(intake_id):
            return _error("intake_not_found", "The intake id is unknown or no longer retained.")
        with self._lock:
            record = self._intakes.get(intake_id)
            if record is None:
                return _error("intake_not_found", "The intake id is unknown or no longer retained.")
            if record.snapshot is not None:
                return copy.deepcopy(record.snapshot)
            serving = record.serving
            if serving is None:
                return _error("status_unavailable", "Intake status is unavailable.")
            try:
                handle = serving.handle
                if handle is None:
                    raise UnknownSession()
                raw = serving.store.cancel_pending(handle.session_id)
            except (AttributeError, UnknownSession):
                return self._status_locked(record)

            raw_status = raw.get("status")
            if raw_status == "submitted":
                return _error(
                    "apply_in_progress",
                    "Secret application is in progress and can no longer be cancelled. "
                    "Poll status for the final result.",
                )
            if raw_status != "cancelled":
                return self._status_locked(record)

            snapshot = {
                "schema_version": SCHEMA_VERSION,
                "intake_id": record.intake_id,
                "request_id": record.request_id,
                "status": "cancelled",
            }
            snapshot = normalize_mcp_result(snapshot)
            record.snapshot = snapshot
            record.serving = None
            if serving is not None:
                serving.close()
            self._trim_terminal_locked(protect=record.intake_id)
            return copy.deepcopy(snapshot)

    def close(self) -> None:
        """Close every listener and release bearer URLs retained in memory."""

        with self._lock:
            if self._closed:
                return
            self._closed = True
            records = tuple(self._intakes.values())
            self._intakes.clear()
        for record in records:
            if record.serving is not None:
                record.serving.close()


def create_mcp_server(manager: IntakeManager) -> Any:
    """Create the official FastMCP v1 stdio server around an intake manager."""

    try:
        from mcp.server.fastmcp import FastMCP
        from mcp.types import ToolAnnotations
    except ModuleNotFoundError as exc:
        if exc.name == "mcp" or (exc.name and exc.name.startswith("mcp.")):
            raise McpConfigurationError(
                "MCP support is not installed; install openagent-secretbox[mcp]"
            ) from exc
        raise

    @asynccontextmanager
    async def lifespan(_server: Any) -> Any:
        try:
            yield None
        finally:
            manager.close()

    app = FastMCP(
        "OpenAgent SecretBox",
        instructions=(
            "Open one-time local secret intake pages. Never include secret values in tool "
            "arguments. The server returns status metadata only and never returns bearer URLs."
        ),
        lifespan=lifespan,
    )

    @app.tool(
        annotations=ToolAnnotations(
            title="Open secret intake",
            readOnlyHint=False,
            destructiveHint=False,
            idempotentHint=False,
            openWorldHint=False,
        )
    )
    def open_secret_intake(
        request: dict[str, Any], ttl_seconds: int = DEFAULT_TTL_SECONDS
    ) -> dict[str, Any]:
        """Open the local one-time form for request metadata.

        Never place API keys, passwords, tokens, private-key content, bearer
        URLs, or other secret values in ``request``.  The workspace is fixed by
        trusted server startup configuration and cannot be selected here.
        """

        return manager.open_intake(request, ttl_seconds)

    @app.tool(
        annotations=ToolAnnotations(
            title="Get secret intake status",
            readOnlyHint=True,
            destructiveHint=False,
            idempotentHint=True,
            openWorldHint=False,
        )
    )
    def get_secret_intake_status(intake_id: str) -> dict[str, Any]:
        """Get the redacted status and nested write result for an intake."""

        return manager.get_status(intake_id)

    @app.tool(
        annotations=ToolAnnotations(
            title="Cancel secret intake",
            readOnlyHint=False,
            destructiveHint=True,
            idempotentHint=True,
            openWorldHint=False,
        )
    )
    def cancel_secret_intake(intake_id: str) -> dict[str, Any]:
        """Stop a pending intake and invalidate its local page."""

        return manager.cancel_intake(intake_id)

    return app


def _positive_max_active(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if not 1 <= parsed <= MAX_CONFIGURED_ACTIVE_INTAKES:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_CONFIGURED_ACTIVE_INTAKES}")
    return parsed


def _build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="secretbox-mcp",
        description="OpenAgent SecretBox MCP stdio server",
    )
    parser.add_argument(
        "--workspace",
        required=True,
        help="trusted workspace root fixed for the lifetime of this MCP process",
    )
    parser.add_argument(
        "--allow-target",
        action="append",
        default=[],
        metavar="PATTERN",
        help="trusted target pattern; repeat to extend the default local policy",
    )
    parser.add_argument(
        "--max-active",
        type=_positive_max_active,
        default=DEFAULT_MAX_ACTIVE_INTAKES,
        help=f"maximum simultaneous intake pages (default: {DEFAULT_MAX_ACTIVE_INTAKES})",
    )
    parser.add_argument(
        "--ui-handoff-url",
        default="",
        help=(
            "loopback publish URL for headless UI handoff "
            "(e.g. http://127.0.0.1:8787/internal/publish)"
        ),
    )
    parser.add_argument(
        "--ui-handoff-token",
        default="",
        help="shared secret for the UI handoff bridge (min 16 chars)",
    )
    parser.add_argument(
        "--ui-handoff-token-file",
        default="",
        help="read UI handoff token from a file (mode 600 recommended)",
    )
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Run the MCP server over stdio; stdout is reserved for protocol frames."""

    args = _build_parser().parse_args(sys.argv[1:] if argv is None else list(argv))
    handoff_token = (args.ui_handoff_token or "").strip()
    if not handoff_token and args.ui_handoff_token_file:
        try:
            handoff_token = Path(args.ui_handoff_token_file).expanduser().read_text(
                encoding="utf-8"
            ).strip()
        except OSError as exc:
            print(f"secretbox-mcp: cannot read ui handoff token file: {exc}", file=sys.stderr)
            return 2
    try:
        manager = IntakeManager(
            args.workspace,
            allowed_targets=DEFAULT_ALLOWED_TARGETS + tuple(args.allow_target),
            max_active=args.max_active,
            ui_handoff_url=(args.ui_handoff_url or "").strip() or None,
            ui_handoff_token=handoff_token or None,
        )
        app = create_mcp_server(manager)
    except McpConfigurationError as exc:
        print(f"secretbox-mcp: {exc}", file=sys.stderr)
        return 2
    atexit.register(manager.close)
    try:
        app.run(transport="stdio")
    finally:
        manager.close()
        atexit.unregister(manager.close)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())


__all__ = [
    "DEFAULT_MAX_ACTIVE_INTAKES",
    "DEFAULT_TTL_SECONDS",
    "IntakeManager",
    "MAX_TTL_SECONDS",
    "MAX_RETAINED_TERMINAL_INTAKES",
    "McpConfigurationError",
    "TERMINAL_DRAIN_TIMEOUT_SECONDS",
    "create_mcp_server",
    "main",
]
