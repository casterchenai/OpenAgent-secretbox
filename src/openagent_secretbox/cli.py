"""Command-line entry point for the local SecretBox MVP.

The registry stores metadata only. Intake values stay in the loopback server
process and are passed directly to the policy-bound writers.
"""

from __future__ import annotations

import argparse
import base64
import binascii
import json
import os
import re
import secrets
import sys
import webbrowser
from collections.abc import Callable, Mapping, Sequence
from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
from importlib import resources
from pathlib import Path
from typing import Any, NoReturn, cast

from . import __version__
from .models import SecretRequest
from .policy import PolicyError, build_policy
from .schema import RequestValidationError, load_request
from .writers import apply_request

EXIT_USAGE = 2
EXIT_NOT_FOUND = 3
EXIT_DOCTOR = 5
SCHEMA_VERSION = 1
DEFAULT_TTL_SECONDS = 600
MAX_TTL_SECONDS = 86_400
DEFAULT_ALLOWED_TARGETS = (".env", ".env.*", "secrets/*")
STATE_ENV = "SECRETBOX_STATE_DIR"


class CliError(Exception):
    """An expected CLI failure that is safe to show to the caller."""

    def __init__(
        self,
        code: str,
        message: str,
        exit_code: int = EXIT_USAGE,
        details: dict[str, Any] | None = None,
    ) -> None:
        super().__init__(message)
        self.code = code
        self.message = message
        self.exit_code = exit_code
        self.details = details or {}


class SecretboxArgumentParser(argparse.ArgumentParser):
    """Argparse variant that lets machine mode serialize usage errors."""

    def error(self, message: str) -> NoReturn:
        raise CliError("usage_error", message, EXIT_USAGE)


@dataclass(frozen=True)
class CommandResult:
    payload: dict[str, Any]
    exit_code: int = 0
    human: str | None = None
    emitted: bool = False


Handler = Callable[[argparse.Namespace], CommandResult]


def _positive_int(value: str) -> int:
    try:
        parsed = int(value)
    except ValueError as exc:
        raise argparse.ArgumentTypeError("must be an integer") from exc
    if parsed < 1 or parsed > MAX_TTL_SECONDS:
        raise argparse.ArgumentTypeError(f"must be between 1 and {MAX_TTL_SECONDS} seconds")
    return parsed


def _state_directory(explicit: str | None = None) -> Path:
    configured = explicit or os.environ.get(STATE_ENV)
    if configured:
        return Path(configured).expanduser()
    if os.name == "nt":
        root = os.environ.get("LOCALAPPDATA")
        if root:
            return Path(root) / "OpenAgent" / "SecretBox"
    if sys.platform == "darwin":
        return Path.home() / "Library" / "Application Support" / "OpenAgent" / "SecretBox"
    root = os.environ.get("XDG_STATE_HOME")
    return (Path(root) if root else Path.home() / ".local" / "state") / "openagent-secretbox"


def _ensure_state_directory(path: Path) -> Path:
    try:
        path.mkdir(parents=True, exist_ok=True)
        if os.name != "nt":
            path.chmod(0o700)
    except OSError as exc:
        raise CliError("state_unavailable", "cannot create the local state directory") from exc
    return path


def _atomic_write_json(path: Path, document: dict[str, Any]) -> None:
    temporary = path.with_name(f".{path.name}.{secrets.token_hex(8)}.tmp")
    try:
        temporary.write_text(
            json.dumps(document, ensure_ascii=True, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        if os.name != "nt":
            temporary.chmod(0o600)
        os.replace(temporary, path)
    except OSError as exc:
        try:
            temporary.unlink(missing_ok=True)
        except OSError:
            pass
        raise CliError("state_write_failed", "cannot write request metadata") from exc


def _schema_available() -> bool:
    try:
        packaged = resources.files("openagent_secretbox").joinpath("schemas/request-v1.json")
        if packaged.is_file():
            return True
    except (FileNotFoundError, ModuleNotFoundError):
        pass
    try:
        return (Path(__file__).resolve().parents[2] / "schemas" / "request-v1.json").is_file()
    except OSError:
        return False


def _load_request_model(path: Path, workspace_root: Path | None = None) -> SecretRequest:
    if not path.is_file():
        raise CliError("input_not_found", "request file does not exist", EXIT_NOT_FOUND)
    try:
        return load_request(path, workspace_root=workspace_root)
    except RequestValidationError as exc:
        details: dict[str, Any] = {}
        if exc.field:
            details["field"] = exc.field
        raise CliError(
            "invalid_request",
            "request does not match the SecretBox request schema",
            details=details,
        ) from exc


def _flatten_submission(
    request: SecretRequest,
    values: Mapping[str, Any],
) -> dict[str, Any]:
    if not isinstance(values, Mapping) or set(values) - {"env", "files"}:
        raise ValueError("invalid submission shape")
    env_values = values.get("env", {})
    file_values = values.get("files", {})
    if not isinstance(env_values, Mapping) or not isinstance(file_values, Mapping):
        raise ValueError("invalid submission groups")
    needs = {need.name: need for need in request.needs}
    flat: dict[str, Any] = {}
    for name, value in env_values.items():
        need = needs.get(name)
        if (
            not isinstance(name, str)
            or need is None
            or need.type not in {"env", "env_file"}
            or not isinstance(value, str)
            or name in flat
        ):
            raise ValueError("invalid environment submission")
        flat[name] = value
    for name, value in file_values.items():
        need = needs.get(name)
        if (
            not isinstance(name, str)
            or need is None
            or need.type != "file"
            or not isinstance(value, Mapping)
            or name in flat
            or set(value) - {"filename", "content_base64"}
        ):
            raise ValueError("invalid file submission")
        filename = value.get("filename")
        encoded = value.get("content_base64")
        if (
            not isinstance(filename, str)
            or not filename
            or len(filename) > 255
            or "\x00" in filename
            or not isinstance(encoded, str)
        ):
            raise ValueError("invalid file submission")
        maximum = need.max_bytes or request.write_policy.max_file_size
        if len(encoded) > ((maximum + 2) // 3) * 4 + 4:
            raise ValueError("file submission exceeds size limit")
        try:
            content = base64.b64decode(encoded, validate=True)
        except (binascii.Error, ValueError) as exc:
            raise ValueError("invalid file encoding") from exc
        if len(content) > maximum:
            raise ValueError("file submission exceeds size limit")
        flat[name] = content
    return flat


def _new_request_id() -> str:
    return "req_" + secrets.token_urlsafe(18).replace("-", "_").replace("/", "_")


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _iso(value: datetime) -> str:
    return value.astimezone(timezone.utc).replace(microsecond=0).isoformat().replace("+00:00", "Z")


def _state_path(state_dir: Path, request_id: str) -> Path:
    if not re.fullmatch(r"req_[A-Za-z0-9_]{8,64}", request_id):
        raise CliError("invalid_request_id", "request id has an invalid format")
    return state_dir / "requests" / f"{request_id}.json"


def _safe_status(state: dict[str, Any]) -> dict[str, Any]:
    return {
        "schema_version": SCHEMA_VERSION,
        "request_id": state["request_id"],
        "status": state["status"],
        "created_at": state["created_at"],
        "expires_at": state["expires_at"],
        "next_action": state.get("next_action"),
    }


def _load_state(state_dir: Path, request_id: str) -> tuple[Path, dict[str, Any]]:
    path = _state_path(state_dir, request_id)
    if not path.is_file():
        raise CliError("request_not_found", "request id was not found", EXIT_NOT_FOUND)
    try:
        state = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise CliError("state_corrupt", "request metadata cannot be read") from exc
    if not isinstance(state, dict) or state.get("request_id") != request_id:
        raise CliError("state_corrupt", "request metadata is invalid")
    return path, state


def _cmd_validate(args: argparse.Namespace) -> CommandResult:
    request = _load_request_model(Path(args.request_path))
    payload = {
        "schema_version": SCHEMA_VERSION,
        "status": "valid",
        "request_id": request.request_id,
        "need_count": len(request.needs),
    }
    return CommandResult(payload, human=f"valid request: {request.request_id}")


def _cmd_create(args: argparse.Namespace) -> CommandResult:
    request = _load_request_model(Path(args.request_path))
    request_id = _new_request_id()
    created = _now()
    expires = created + timedelta(seconds=args.ttl)
    state_dir = _ensure_state_directory(_state_directory(getattr(args, "state_dir", None)))
    requests_dir = _ensure_state_directory(state_dir / "requests")
    path = _state_path(requests_dir.parent, request_id)
    registry_spec = request.to_dict()
    for need in registry_spec["needs"]:
        need.pop("default_value", None)
    state = {
        "schema_version": SCHEMA_VERSION,
        "request_id": request_id,
        "status": "proposed",
        "next_action": "serve",
        "created_at": _iso(created),
        "expires_at": _iso(expires),
        "spec": registry_spec,
    }
    if path.exists():
        raise CliError("request_collision", "generated request id already exists")
    _atomic_write_json(path, state)
    payload = _safe_status(state)
    payload["client_request_id"] = request.request_id
    return CommandResult(
        payload,
        human=(
            f"created metadata record {request_id}; "
            "secretbox serve starts a separate intake session"
        ),
    )


def _cmd_status(args: argparse.Namespace) -> CommandResult:
    state_dir = _state_directory(getattr(args, "state_dir", None))
    path, state = _load_state(state_dir, args.request_id)
    if state.get("status") in {"proposed", "awaiting_input"}:
        try:
            expired = _now() >= datetime.fromisoformat(state["expires_at"].replace("Z", "+00:00"))
        except (KeyError, TypeError, ValueError) as exc:
            raise CliError("state_corrupt", "request expiry metadata is invalid") from exc
        if expired:
            state["status"] = "expired"
            state["next_action"] = None
            _atomic_write_json(path, state)
    payload = _safe_status(state)
    return CommandResult(payload, human=f"{payload['request_id']}: {payload['status']}")


def _cmd_doctor(args: argparse.Namespace) -> CommandResult:
    checks: dict[str, dict[str, str]] = {}
    schema_ok = _schema_available()
    checks["schema"] = {"status": "ok" if schema_ok else "error"}
    state_dir = _state_directory(getattr(args, "state_dir", None))
    try:
        _ensure_state_directory(state_dir)
        checks["state_dir"] = {"status": "ok"}
    except CliError:
        checks["state_dir"] = {"status": "error"}
    if args.workspace:
        workspace = Path(args.workspace).expanduser()
        checks["workspace"] = {"status": "ok" if workspace.is_dir() else "error"}
    if args.request_path:
        try:
            _load_request_model(Path(args.request_path))
            checks["request"] = {"status": "ok"}
        except CliError:
            checks["request"] = {"status": "error"}
    overall = "ok" if all(value["status"] == "ok" for value in checks.values()) else "error"
    payload = {"schema_version": SCHEMA_VERSION, "status": overall, "checks": checks}
    return CommandResult(
        payload,
        EXIT_DOCTOR if overall != "ok" else 0,
        human=f"doctor: {overall}",
    )


def _cmd_serve(args: argparse.Namespace) -> CommandResult:
    workspace = Path(args.workspace).expanduser()
    if not workspace.is_dir():
        raise CliError("workspace_not_found", "workspace directory does not exist", EXIT_NOT_FOUND)
    request = _load_request_model(Path(args.request_path), workspace.resolve())
    allowed_targets = DEFAULT_ALLOWED_TARGETS + tuple(args.allow_target)
    try:
        policy = build_policy(request, workspace, allowed_targets=allowed_targets)
    except PolicyError as exc:
        raise CliError(
            "policy_rejected",
            "request targets are not authorized by the local workspace policy",
        ) from exc
    # The agent request may narrow these controls but cannot disable them.
    policy = replace(policy, no_overwrite=True, backup=False)

    def apply_values(
        _spec: Mapping[str, Any],
        values: Mapping[str, Any],
    ) -> dict[str, Any]:
        flattened = _flatten_submission(request, values)
        return apply_request(request, flattened, policy=policy)

    try:
        from .server import serve_once

        server_request = request.to_dict()
        server_request["workspace_root"] = str(policy.workspace_root)
        server_request["write_policy"]["no_overwrite"] = policy.no_overwrite
        server_request["write_policy"]["backup"] = policy.backup
        serving = serve_once(
            request=server_request,
            apply_fn=apply_values,
            host=args.host,
            port=args.port,
            ttl=args.ttl,
        )
    except (OSError, ValueError) as exc:
        raise CliError("server_unavailable", "cannot start the local intake server") from exc
    if not serving.url:
        serving.close()
        raise CliError("server_unavailable", "intake session was not created")
    opened = False
    if not args.no_open:
        opened = webbrowser.open(serving.url, new=2)
        if not opened:
            serving.close()
            raise CliError(
                "browser_open_failed",
                "cannot open a browser; retry with --no-open and protect the printed URL",
                EXIT_DOCTOR,
            )
    initial_payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "awaiting_input",
        "request_id": request.request_id,
        "browser_opened": opened,
    }
    initial_human = "intake server started; complete the request in the browser"
    if args.no_open:
        initial_payload["sensitive_intake_url"] = serving.url
        initial_payload["warning"] = (
            "The intake URL is a bearer secret; do not paste it into chat or logs."
        )
        initial_human = f"SENSITIVE intake URL (do not share): {serving.url}"
        if bool(getattr(args, "json_output", False)):
            _emit_json(initial_payload)
        else:
            print(initial_human, flush=True)
    elif not bool(getattr(args, "json_output", False)):
        print(initial_human)
    try:
        serving.thread.join()
    except KeyboardInterrupt:
        serving.close()
        raise CliError("cancelled", "intake server stopped by user", 130) from None
    finally:
        if not serving.thread.is_alive():
            serving.close()
    final = (
        serving.store.get(serving.handle.session_id)
        if serving.handle is not None
        else {"status": "failed", "error_code": "missing_session"}
    )
    final_status = str(final.get("status", "failed"))
    payload = {
        "schema_version": SCHEMA_VERSION,
        "status": final_status,
        "request_id": request.request_id,
        "browser_opened": opened,
    }
    if "result" in final:
        payload["result"] = final["result"]
    if "error_code" in final:
        payload["error_code"] = final["error_code"]
    exit_code = 0 if final_status == "applied" else EXIT_DOCTOR
    return CommandResult(
        payload,
        exit_code=exit_code,
        human=f"{request.request_id}: {final_status}",
    )


def _add_json_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--json",
        dest="json_output",
        action="store_true",
        default=argparse.SUPPRESS,
        help="emit machine-readable JSON (serve --no-open emits two JSONL events)",
    )


def _add_state_dir_flag(parser: argparse.ArgumentParser) -> None:
    parser.add_argument(
        "--state-dir",
        default=argparse.SUPPRESS,
        help=argparse.SUPPRESS,
    )


def _build_parser() -> SecretboxArgumentParser:
    parser = SecretboxArgumentParser(prog="secretbox", description="OpenAgent SecretBox")
    parser.set_defaults(json_output=False)
    parser.add_argument("--version", action="version", version=__version__)
    _add_json_flag(parser)
    _add_state_dir_flag(parser)
    commands = parser.add_subparsers(
        dest="command",
        parser_class=SecretboxArgumentParser,
    )

    validate = commands.add_parser("validate")
    _add_json_flag(validate)
    _add_state_dir_flag(validate)
    validate.add_argument("request_path")
    validate.set_defaults(handler=_cmd_validate)

    create = commands.add_parser("create")
    _add_json_flag(create)
    _add_state_dir_flag(create)
    create.add_argument("request_path")
    create.add_argument("--ttl", type=_positive_int, default=DEFAULT_TTL_SECONDS)
    create.set_defaults(handler=_cmd_create)

    serve = commands.add_parser("serve")
    _add_json_flag(serve)
    _add_state_dir_flag(serve)
    serve.add_argument("--workspace", required=True)
    serve.add_argument("--request", dest="request_path", required=True)
    serve.add_argument("--ttl", type=_positive_int, default=DEFAULT_TTL_SECONDS)
    serve.add_argument("--host", default="127.0.0.1")
    serve.add_argument("--port", type=int, default=0)
    serve.add_argument(
        "--allow-target",
        action="append",
        default=[],
        metavar="PATTERN",
        help="trusted target pattern; repeat to extend the default local policy",
    )
    serve.add_argument(
        "--no-open",
        action="store_true",
        help="do not open a browser; print the sensitive one-time URL",
    )
    serve.set_defaults(handler=_cmd_serve)

    status = commands.add_parser("status")
    _add_json_flag(status)
    _add_state_dir_flag(status)
    status.add_argument("request_id")
    status.set_defaults(handler=_cmd_status)

    doctor = commands.add_parser("doctor")
    _add_json_flag(doctor)
    _add_state_dir_flag(doctor)
    doctor.add_argument("--workspace")
    doctor.add_argument("--request", dest="request_path")
    doctor.set_defaults(handler=_cmd_doctor)

    request = commands.add_parser("request")
    _add_json_flag(request)
    _add_state_dir_flag(request)
    request_commands = request.add_subparsers(
        dest="request_command",
        parser_class=SecretboxArgumentParser,
    )
    request_create = request_commands.add_parser("create")
    _add_json_flag(request_create)
    _add_state_dir_flag(request_create)
    request_create.add_argument("request_path")
    request_create.add_argument("--ttl", type=_positive_int, default=DEFAULT_TTL_SECONDS)
    request_create.set_defaults(handler=_cmd_create)
    request_status = request_commands.add_parser("status")
    _add_json_flag(request_status)
    _add_state_dir_flag(request_status)
    request_status.add_argument("request_id")
    request_status.set_defaults(handler=_cmd_status)
    return parser


def _json_requested(arguments: Sequence[str]) -> bool:
    return "--json" in arguments


def _error_payload(error: CliError) -> dict[str, Any]:
    payload: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "status": "error",
        "error": {"code": error.code, "message": error.message},
    }
    if error.details:
        payload["error"]["details"] = error.details
    return payload


def _emit_json(payload: dict[str, Any]) -> None:
    print(json.dumps(payload, ensure_ascii=True, sort_keys=True), flush=True)


def main(argv: Sequence[str] | None = None) -> int:
    arguments = list(sys.argv[1:] if argv is None else argv)
    machine = _json_requested(arguments)
    parser = _build_parser()
    try:
        args = parser.parse_args(arguments)
        machine = machine or bool(getattr(args, "json_output", False))
        handler = cast(Handler | None, getattr(args, "handler", None))
        if handler is None:
            raise CliError("usage_error", "a command is required", EXIT_USAGE)
        result = handler(args)
    except CliError as error:
        if machine:
            _emit_json(_error_payload(error))
        else:
            print(f"secretbox: {error.code}: {error.message}", file=sys.stderr)
        return error.exit_code
    if result.emitted:
        return result.exit_code
    if machine:
        _emit_json(result.payload)
    elif result.human:
        print(result.human)
    return result.exit_code


if __name__ == "__main__":
    raise SystemExit(main())
