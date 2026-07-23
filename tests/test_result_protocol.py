from __future__ import annotations

import copy
import json
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest
from jsonschema import Draft202012Validator

from openagent_secretbox import cli
from openagent_secretbox import server as server_module
from openagent_secretbox.mcp_server import IntakeManager
from openagent_secretbox.protocol import ResultValidationError, normalize_agent_result
from openagent_secretbox.redaction import safe_status
from openagent_secretbox.schema import validate_request
from openagent_secretbox.writers import apply_request

ROOT = Path(__file__).resolve().parents[1]
REQUEST_SCHEMA = json.loads((ROOT / "schemas" / "request-v1.json").read_text(encoding="utf-8"))
RESULT_SCHEMA = json.loads((ROOT / "schemas" / "result-v1.json").read_text(encoding="utf-8"))
REQUEST_VALIDATOR = Draft202012Validator(REQUEST_SCHEMA)
RESULT_VALIDATOR = Draft202012Validator(RESULT_SCHEMA)
REQUEST_EXAMPLES = [
    ROOT / "examples" / "anthropic.request.json",
    ROOT / "examples" / "stripe.request.json",
]
RESULT_EXAMPLES = sorted((ROOT / "examples").glob("*.result.json"))


def writer_result(status: str) -> dict[str, Any]:
    written: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    missing: list[str] = []
    blocked: list[dict[str, Any]] = []
    if status in {"applied", "partial"}:
        written.append(
            {
                "type": "env",
                "name": "ANTHROPIC_API_KEY",
                "action": "added",
                "target": ".env.local",
            }
        )
    if status == "noop":
        written.append(
            {
                "type": "env",
                "name": "ANTHROPIC_API_KEY",
                "action": "skipped",
                "target": ".env.local",
            }
        )
    if status == "partial":
        conflicts.append(
            {
                "type": "file",
                "name": "private.pem",
                "action": "conflict",
                "target": "secrets/private.pem",
            }
        )
    if status == "blocked":
        missing.append("ANTHROPIC_API_KEY")
    return safe_status(
        request_id="anthropic-local-setup",
        status=status,
        written=written,
        conflicts=conflicts,
        missing=missing,
        blocked=blocked,
    )


def test_published_result_schema_is_valid_draft_2020_12() -> None:
    Draft202012Validator.check_schema(RESULT_SCHEMA)


@pytest.mark.parametrize("example", REQUEST_EXAMPLES, ids=lambda path: path.name)
def test_anthropic_and_stripe_requests_match_schema_and_runtime(example: Path) -> None:
    document = json.loads(example.read_text(encoding="utf-8"))
    REQUEST_VALIDATOR.validate(document)
    normalized = validate_request(document).to_dict()
    assert normalized["request_id"] == document["request_id"]
    assert normalized["needs"] == document["needs"]
    assert normalized["write_policy"] | document["write_policy"] == normalized["write_policy"]


@pytest.mark.parametrize("example", RESULT_EXAMPLES, ids=lambda path: path.name)
def test_agent_facing_result_examples_match_schema_and_runtime(example: Path) -> None:
    document = json.loads(example.read_text(encoding="utf-8"))
    RESULT_VALIDATOR.validate(document)
    assert normalize_agent_result(document) == document


@pytest.mark.parametrize("status", ["applied", "noop", "partial", "blocked"])
def test_existing_safe_status_writer_shapes_match_protocol(status: str) -> None:
    result = writer_result(status)
    RESULT_VALIDATOR.validate(result)
    assert normalize_agent_result(result) == result


def test_real_apply_request_applied_noop_and_blocked_match_protocol(tmp_path: Path) -> None:
    request_document = json.loads(REQUEST_EXAMPLES[0].read_text(encoding="utf-8"))
    request_document["workspace_root"] = str(tmp_path)
    request = validate_request(request_document, workspace_root=tmp_path)

    applied = apply_request(request, {"ANTHROPIC_API_KEY": "test-only-secret"}, tmp_path)
    noop = apply_request(request, {"ANTHROPIC_API_KEY": "test-only-secret"}, tmp_path)
    blocked = apply_request(request, {}, tmp_path)

    assert [applied["status"], noop["status"], blocked["status"]] == [
        "applied",
        "noop",
        "blocked",
    ]
    for result in (applied, noop, blocked):
        RESULT_VALIDATOR.validate(result)
        assert normalize_agent_result(result) == result
        assert "test-only-secret" not in json.dumps(result)


@pytest.mark.parametrize(
    "event",
    [
        {
            "schema_version": 1,
            "status": "awaiting_input",
            "request_id": "anthropic-local-setup",
            "browser_opened": True,
        },
        {
            "schema_version": 1,
            "status": "applied",
            "request_id": "anthropic-local-setup",
            "browser_opened": True,
            "result": writer_result("applied"),
        },
        {
            "schema_version": 1,
            "status": "failed",
            "request_id": "anthropic-local-setup",
            "browser_opened": True,
            "result": writer_result("partial"),
            "error_code": "apply_blocked",
        },
        {
            "schema_version": 1,
            "status": "failed",
            "request_id": "anthropic-local-setup",
            "browser_opened": True,
            "error_code": "apply_failed",
        },
        {
            "schema_version": 1,
            "status": "cancelled",
            "request_id": "anthropic-local-setup",
            "browser_opened": True,
        },
        {
            "schema_version": 1,
            "status": "expired",
            "request_id": "anthropic-local-setup",
            "browser_opened": True,
            "error_code": "expired",
        },
    ],
    ids=[
        "awaiting-browser",
        "applied",
        "failed-with-result",
        "failed-without-result",
        "cancelled",
        "expired",
    ],
)
def test_intake_lifecycle_events_match_protocol(event: dict[str, Any]) -> None:
    RESULT_VALIDATOR.validate(event)
    assert normalize_agent_result(event) == event


@pytest.mark.parametrize(
    "result",
    [
        {
            "schema_version": 1,
            "intake_id": "int_0123456789abcdef",
            "request_id": "anthropic-local-setup",
            "status": "awaiting_input",
            "expires_at": "2026-07-23T12:00:00Z",
            "browser_opened": True,
        },
        {
            "schema_version": 1,
            "intake_id": "int_0123456789abcdef",
            "request_id": "anthropic-local-setup",
            "status": "awaiting_input",
            "expires_at": "2026-07-23T12:00:00Z",
        },
        {
            "schema_version": 1,
            "intake_id": "int_0123456789abcdef",
            "request_id": "anthropic-local-setup",
            "status": "applied",
            "expires_at": "2026-07-23T12:00:00Z",
            "result": writer_result("applied"),
        },
        {
            "schema_version": 1,
            "intake_id": "int_0123456789abcdef",
            "request_id": "anthropic-local-setup",
            "status": "failed",
            "result": writer_result("blocked"),
            "error_code": "apply_blocked",
        },
        {
            "schema_version": 1,
            "intake_id": "int_0123456789abcdef",
            "request_id": "anthropic-local-setup",
            "status": "cancelled",
        },
        {
            "schema_version": 1,
            "intake_id": "int_0123456789abcdef",
            "request_id": "anthropic-local-setup",
            "status": "expired",
            "error_code": "expired",
        },
        {
            "schema_version": 1,
            "status": "error",
            "error": {
                "code": "intake_not_found",
                "message": "The intake id is unknown or no longer retained.",
            },
        },
        {
            "schema_version": 1,
            "status": "error",
            "error": {
                "code": "apply_in_progress",
                "message": "Secret application is in progress; poll for the final result.",
            },
        },
    ],
    ids=[
        "open",
        "status-awaiting",
        "status-applied",
        "status-failed",
        "cancel",
        "expired",
        "error",
        "apply-in-progress",
    ],
)
def test_mcp_agent_result_shapes_match_protocol(result: dict[str, Any]) -> None:
    RESULT_VALIDATOR.validate(result)
    assert normalize_agent_result(result) == result


def test_actual_mcp_open_status_cancel_and_error_match_protocol(tmp_path: Path) -> None:
    request = json.loads(REQUEST_EXAMPLES[0].read_text(encoding="utf-8"))
    request["workspace_root"] = str(tmp_path)
    manager = IntakeManager(tmp_path, browser_open=lambda _url: True)
    try:
        opened = manager.open_intake(request, ttl_seconds=60)
        awaiting = manager.get_status(opened["intake_id"])
        cancelled = manager.cancel_intake(opened["intake_id"])
        error = manager.get_status("not-a-valid-intake-id")

        assert [opened["status"], awaiting["status"], cancelled["status"]] == [
            "awaiting_input",
            "awaiting_input",
            "cancelled",
        ]
        for result in (opened, awaiting, cancelled, error):
            RESULT_VALIDATOR.validate(result)
            assert normalize_agent_result(result) == result
    finally:
        manager.close()


@pytest.mark.parametrize(
    "field",
    ["url", "path", "session_id", "token", "sensitive_intake_url"],
)
def test_mcp_result_rejects_browser_credentials_and_paths(field: str) -> None:
    result = {
        "schema_version": 1,
        "intake_id": "int_0123456789abcdef",
        "request_id": "anthropic-local-setup",
        "status": "awaiting_input",
        "expires_at": "2026-07-23T12:00:00Z",
        field: "must-not-cross-the-mcp-boundary",
    }
    assert not RESULT_VALIDATOR.is_valid(result)
    with pytest.raises(ResultValidationError):
        normalize_agent_result(result)


def test_mcp_error_rejects_urls_and_browser_session_references() -> None:
    for unsafe_message in (
        "Retry at HTTP://127.0.0.1:17321/intake/ses_example.",
        "Browser reference ses_private must not be returned.",
    ):
        result = {
            "schema_version": 1,
            "status": "error",
            "error": {"code": "status_unavailable", "message": unsafe_message},
        }
        assert not RESULT_VALIDATOR.is_valid(result)
        with pytest.raises(ResultValidationError, match="URL or browser session"):
            normalize_agent_result(result)


@pytest.mark.parametrize(
    "field",
    [
        "secret",
        "values",
        "request_body",
        "access_token",
        "file_content",
        "raw",
        "password",
        "authorization",
        "credential",
        "apiKey",
        "private_key",
        "token_count",
    ],
)
def test_sensitive_field_names_are_recursively_rejected(field: str) -> None:
    payload = writer_result("applied")
    payload["written"][0][field] = "must-not-cross-the-result-boundary"

    assert not RESULT_VALIDATOR.is_valid(payload)
    with pytest.raises(ResultValidationError, match="forbidden sensitive field"):
        normalize_agent_result(payload)


@pytest.mark.parametrize(
    "mutate",
    [
        lambda result: result.update(status="applied", written=[]),
        lambda result: result.update(status="partial", conflicts=[], blocked=[]),
        lambda result: result.update(status="blocked"),
    ],
    ids=["applied-without-write", "partial-without-failure", "blocked-with-write"],
)
def test_writer_status_invariants_fail_closed(
    mutate: Callable[[dict[str, Any]], None],
) -> None:
    payload = writer_result("applied")
    mutate(payload)

    assert not RESULT_VALIDATOR.is_valid(payload)
    with pytest.raises(ResultValidationError):
        normalize_agent_result(payload)


def test_agent_protocol_rejects_cli_headless_bearer_bootstrap() -> None:
    event = {
        "schema_version": 1,
        "status": "awaiting_input",
        "request_id": "anthropic-local-setup",
        "browser_opened": False,
        "sensitive_intake_url": (
            "http://127.0.0.1:17321/intake/ses_test#token=test-bearer"
        ),
        "warning": "This bearer URL is not an agent-safe result.",
    }
    assert not RESULT_VALIDATOR.is_valid(event)
    with pytest.raises(ResultValidationError):
        normalize_agent_result(event)


class _FakeThread:
    def join(self) -> None:
        return

    def is_alive(self) -> bool:
        return False


class _FakeHandle:
    session_id = "ses_test"


class _FakeStore:
    def get(self, _session_id: str) -> dict[str, Any]:
        return {"status": "applied", "result": writer_result("applied")}


class _FakeServing:
    url = "http://127.0.0.1:17321/intake/ses_test#token=test-bearer"
    thread = _FakeThread()
    handle = _FakeHandle()
    store = _FakeStore()

    def close(self) -> None:
        return


def test_cli_headless_bootstrap_is_excluded_but_terminal_result_is_valid(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    capsys: pytest.CaptureFixture[str],
) -> None:
    request_document = json.loads(REQUEST_EXAMPLES[0].read_text(encoding="utf-8"))
    request_document["workspace_root"] = str(tmp_path)
    request_path = tmp_path / "request.json"
    request_path.write_text(json.dumps(request_document), encoding="utf-8")

    def fake_serve_once(**_: Any) -> _FakeServing:
        return _FakeServing()

    monkeypatch.setattr(server_module, "serve_once", fake_serve_once)
    assert (
        cli.main(
            [
                "--json",
                "serve",
                "--workspace",
                str(tmp_path),
                "--request",
                str(request_path),
                "--no-open",
            ]
        )
        == 0
    )
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [event["status"] for event in events] == ["awaiting_input", "applied"]
    bootstrap, terminal = events
    assert not RESULT_VALIDATOR.is_valid(bootstrap)
    with pytest.raises(ResultValidationError):
        normalize_agent_result(bootstrap)
    RESULT_VALIDATOR.validate(terminal)
    assert normalize_agent_result(terminal) == terminal


def test_normalization_returns_detached_metadata() -> None:
    source = json.loads(RESULT_EXAMPLES[0].read_text(encoding="utf-8"))
    normalized = normalize_agent_result(source)
    assert normalized == source
    assert normalized is not source
    assert normalized["result"] is not source["result"]
    copied = copy.deepcopy(normalized)
    assert copied == normalized
