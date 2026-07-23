from __future__ import annotations

import asyncio
import json
import sys
import threading
import time
from pathlib import Path
from types import SimpleNamespace
from typing import Any
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen

import pytest

from openagent_secretbox.mcp_server import (
    MAX_RETAINED_TERMINAL_INTAKES,
    IntakeManager,
    create_mcp_server,
)
from openagent_secretbox.server import serve_once


def _request(workspace: Path, request_id: str = "mcp-test") -> dict[str, Any]:
    return {
        "schema_version": 1,
        "request_id": request_id,
        "title": "MCP test",
        "workspace_root": str(workspace),
        "needs": [
            {
                "type": "env",
                "name": "OPENAI_API_KEY",
                "required": True,
                "description": "Test API key",
            }
        ],
        "write_policy": {
            "env_file": ".env.local",
            "mode": "merge_only",
            "no_overwrite": True,
            "backup": False,
        },
    }


def _post_json(
    url: str,
    payload: dict[str, Any],
    *,
    csrf: str | None = None,
    cookie: str | None = None,
) -> tuple[dict[str, Any], str | None]:
    headers = {"Content-Type": "application/json"}
    if csrf:
        headers["X-CSRF-Token"] = csrf
    if cookie:
        headers["Cookie"] = cookie
    request = Request(url, data=json.dumps(payload).encode(), headers=headers, method="POST")
    with urlopen(request, timeout=2) as response:
        set_cookie = response.headers.get("Set-Cookie")
        return json.loads(response.read()), set_cookie


def test_end_to_end_status_is_nested_and_never_returns_bearer_or_secret(tmp_path: Path) -> None:
    opened: list[str] = []
    manager = IntakeManager(tmp_path, browser_open=lambda url: not opened.append(url))
    secret = "sk-test-mcp-must-not-appear"
    try:
        created = manager.open_intake(_request(tmp_path), ttl_seconds=60)

        assert created["status"] == "awaiting_input"
        assert created["browser_opened"] is True
        assert set(created) == {
            "schema_version",
            "intake_id",
            "request_id",
            "status",
            "expires_at",
            "browser_opened",
        }
        created_json = json.dumps(created)
        assert "token" not in created_json.lower()
        assert "/intake/" not in created_json
        assert "ses_" not in created_json

        sensitive_url = opened[0]
        parsed = urlsplit(sensitive_url)
        token = parse_qs(parsed.fragment)["token"][0]
        session_id = parsed.path.rsplit("/", 1)[1]
        with urlopen(f"{parsed.scheme}://{parsed.netloc}{parsed.path}", timeout=2) as response:
            assert response.status == 200
        exchange, set_cookie = _post_json(
            f"{parsed.scheme}://{parsed.netloc}/api/exchange",
            {"session_id": session_id, "token": token},
        )
        assert set_cookie is not None
        cookie = set_cookie.split(";", 1)[0]
        submitted, _ = _post_json(
            f"{parsed.scheme}://{parsed.netloc}/api/sessions/{session_id}/submit",
            {"values": {"env": {"OPENAI_API_KEY": secret}, "files": {}}},
            csrf=exchange["csrf_token"],
            cookie=cookie,
        )
        assert submitted["status"] == "applied"

        status = manager.get_status(created["intake_id"])
        encoded = json.dumps(status)
        assert status["status"] == "applied"
        assert status["result"]["status"] == "applied"
        assert status["result"]["written"][0]["name"] == "OPENAI_API_KEY"
        assert secret not in encoded
        assert token not in encoded
        assert sensitive_url not in encoded
        assert manager.get_status(created["intake_id"]) == status
        assert (tmp_path / ".env.local").read_text(encoding="utf-8") == f"OPENAI_API_KEY={secret}\n"
    finally:
        manager.close()


def test_cancel_during_apply_reports_in_progress_and_preserves_real_terminal_state(
    tmp_path: Path,
) -> None:
    opened_urls: list[str] = []
    servings: list[Any] = []
    apply_started = threading.Event()
    release_apply = threading.Event()
    submission: dict[str, Any] = {}

    def blocking_apply(request: dict[str, Any], _values: dict[str, Any]) -> dict[str, Any]:
        apply_started.set()
        if not release_apply.wait(timeout=3):
            raise AssertionError("test did not release apply callback")
        return {
            "request_id": request["request_id"],
            "status": "applied",
            "written": [
                {
                    "type": "env",
                    "name": "OPENAI_API_KEY",
                    "action": "added",
                    "target": ".env.local",
                }
            ],
            "conflicts": [],
            "missing": [],
            "blocked": [],
        }

    def factory(**kwargs: Any) -> Any:
        serving = serve_once(
            request=kwargs["request"],
            apply_fn=blocking_apply,
            host=kwargs["host"],
            port=kwargs["port"],
            ttl=kwargs["ttl"],
        )
        servings.append(serving)
        return serving

    manager = IntakeManager(
        tmp_path,
        browser_open=lambda url: not opened_urls.append(url),
        server_factory=factory,
    )
    worker: threading.Thread | None = None
    try:
        created = manager.open_intake(_request(tmp_path), ttl_seconds=60)
        parsed = urlsplit(opened_urls[0])
        token = parse_qs(parsed.fragment)["token"][0]
        session_id = parsed.path.rsplit("/", 1)[1]
        origin = f"{parsed.scheme}://{parsed.netloc}"
        exchange, set_cookie = _post_json(
            f"{origin}/api/exchange",
            {"session_id": session_id, "token": token},
        )
        assert set_cookie is not None

        def submit() -> None:
            try:
                result, _ = _post_json(
                    f"{origin}/api/sessions/{session_id}/submit",
                    {"values": {"env": {"OPENAI_API_KEY": "test-only-value"}}},
                    csrf=exchange["csrf_token"],
                    cookie=set_cookie.split(";", 1)[0],
                )
                submission["result"] = result
            except Exception as exc:  # pragma: no cover - asserted below
                submission["error"] = exc

        worker = threading.Thread(target=submit)
        worker.start()
        assert apply_started.wait(timeout=2)

        in_progress = manager.cancel_intake(created["intake_id"])
        assert in_progress == {
            "schema_version": 1,
            "status": "error",
            "error": {
                "code": "apply_in_progress",
                "message": (
                    "Secret application is in progress and can no longer be cancelled. "
                    "Poll status for the final result."
                ),
            },
        }
        assert manager.get_status(created["intake_id"])["status"] == "awaiting_input"
        assert servings[0].thread.is_alive()

        release_apply.set()
        worker.join(timeout=3)
        assert not worker.is_alive()
        assert "error" not in submission
        assert submission["result"]["status"] == "applied"

        final = manager.get_status(created["intake_id"])
        assert final["status"] == "applied"
        assert final["result"]["status"] == "applied"
        assert manager.cancel_intake(created["intake_id"]) == final
        assert manager.get_status(created["intake_id"]) == final
    finally:
        release_apply.set()
        if worker is not None:
            worker.join(timeout=3)
        manager.close()


class _FakeThread:
    def __init__(self) -> None:
        self.alive = True
        self.join_called = False

    def is_alive(self) -> bool:
        return self.alive

    def join(self, timeout: float | None = None) -> None:
        del timeout
        self.join_called = True
        self.alive = False


class _FakeStore:
    def __init__(self, expires_at: float, request_id: str) -> None:
        self.expires_at = expires_at
        self.status = "pending"
        self.result: dict[str, Any] = {
            "request_id": request_id,
            "status": "applied",
            "written": [
                {
                    "type": "env",
                    "name": "OPENAI_API_KEY",
                    "action": "added",
                    "target": ".env.local",
                }
            ],
            "conflicts": [],
            "missing": [],
            "blocked": [],
        }

    def get(self, _session_id: str) -> dict[str, Any]:
        return {
            "status": self.status,
            "expires_at": self.expires_at,
            "result": self.result,
        }

    def cancel_pending(self, session_id: str) -> dict[str, Any]:
        if self.status in {"pending", "exchanged"}:
            self.status = "cancelled"
        return self.get(session_id)


class _FakeServing:
    def __init__(self, index: int, request_id: str = "mcp-test") -> None:
        self.url = f"http://127.0.0.1:1234/intake/ses_{index}#token=secret-{index}"
        self.handle = SimpleNamespace(session_id=f"ses_{index}", expires_at=time.time() + 60)
        self.store = _FakeStore(self.handle.expires_at, request_id)
        self.thread = _FakeThread()
        self.closed = False

    def close(self) -> None:
        self.closed = True
        self.thread.alive = False


def test_concurrency_limit_cancel_and_unknown_id_are_safe(tmp_path: Path) -> None:
    servings: list[_FakeServing] = []

    def factory(**_kwargs: Any) -> Any:
        serving = _FakeServing(len(servings), _kwargs["request"]["request_id"])
        servings.append(serving)
        return serving

    manager = IntakeManager(
        tmp_path,
        max_active=1,
        browser_open=lambda _url: True,
        server_factory=factory,
    )
    try:
        first = manager.open_intake(_request(tmp_path, "first"))
        blocked = manager.open_intake(_request(tmp_path, "second"))
        unknown_secret = "sk-test-unknown-id"
        unknown = manager.get_status(unknown_secret)

        assert blocked["error"]["code"] == "too_many_active_intakes"
        assert unknown["error"]["code"] == "intake_not_found"
        assert unknown_secret not in json.dumps(unknown)
        assert manager.cancel_intake(first["intake_id"])["status"] == "cancelled"
        assert servings[0].closed is True

        second = manager.open_intake(_request(tmp_path, "second"))
        assert second["status"] == "awaiting_input"
        servings[1].store.status = "applied"
        safe_status = manager.get_status(second["intake_id"])
        assert safe_status["result"]["status"] == "applied"
        assert servings[1].closed is False
        assert servings[1].thread.join_called is True
        assert servings[1].url is None
        assert servings[1].handle is None
        servings[1].store.status = "failed"
        assert manager.get_status(second["intake_id"]) == safe_status
    finally:
        manager.close()
    assert all(not serving.thread.is_alive() for serving in servings)


def test_invalid_nested_result_fails_closed_instead_of_returning_redacted_fields(
    tmp_path: Path,
) -> None:
    serving = _FakeServing(9)
    serving.store.status = "applied"
    serving.store.result = {
        "status": "applied",
        "api_key": "sk-test-result-secret",
        "nested": {"password": "test-password"},
    }
    manager = IntakeManager(
        tmp_path,
        browser_open=lambda _url: True,
        server_factory=lambda **_kwargs: serving,
    )
    created = manager.open_intake(_request(tmp_path))

    status = manager.get_status(created["intake_id"])

    assert status["status"] == "failed"
    assert status["error_code"] == "apply_failed"
    assert "result" not in status
    assert "sk-test-result-secret" not in json.dumps(status)
    assert serving.closed is False
    assert serving.thread.join_called is True
    assert serving.url is None
    assert serving.handle is None
    manager.close()


def test_cancel_preserves_a_finalized_status_error(tmp_path: Path) -> None:
    class UnknownStore:
        def get(self, _session_id: str) -> dict[str, Any]:
            from openagent_secretbox.server import UnknownSession

            raise UnknownSession()

    serving = _FakeServing(10)
    serving.store = UnknownStore()  # type: ignore[assignment]
    manager = IntakeManager(
        tmp_path,
        browser_open=lambda _url: True,
        server_factory=lambda **_kwargs: serving,
    )
    created = manager.open_intake(_request(tmp_path))

    cancelled = manager.cancel_intake(created["intake_id"])

    assert cancelled["status"] == "error"
    assert cancelled["error"]["code"] == "status_unavailable"
    assert manager.get_status(created["intake_id"]) == cancelled
    assert serving.thread.join_called is True
    assert serving.closed is False
    manager.close()


def test_next_open_releases_unpolled_terminal_serving(tmp_path: Path) -> None:
    servings: list[_FakeServing] = []

    def factory(**_kwargs: Any) -> Any:
        serving = _FakeServing(len(servings), _kwargs["request"]["request_id"])
        servings.append(serving)
        return serving

    manager = IntakeManager(
        tmp_path,
        browser_open=lambda _url: True,
        server_factory=factory,
    )
    try:
        first = manager.open_intake(_request(tmp_path, "first"))
        servings[0].store.status = "applied"

        second = manager.open_intake(_request(tmp_path, "second"))

        assert second["status"] == "awaiting_input"
        assert servings[0].closed is False
        assert servings[0].thread.join_called is True
        assert servings[0].url is None
        assert servings[0].handle is None
        assert manager.get_status(first["intake_id"])["status"] == "applied"
    finally:
        manager.close()


def test_terminal_snapshot_retention_is_bounded(tmp_path: Path) -> None:
    manager = IntakeManager(
        tmp_path,
        max_active=1,
        browser_open=lambda _url: True,
        server_factory=lambda **kwargs: _FakeServing(1, kwargs["request"]["request_id"]),
    )
    first_id = ""
    last_id = ""
    try:
        for index in range(MAX_RETAINED_TERMINAL_INTAKES + 1):
            opened = manager.open_intake(_request(tmp_path, f"retained-{index}"))
            if index == 0:
                first_id = opened["intake_id"]
            last_id = opened["intake_id"]
            assert manager.cancel_intake(last_id)["status"] == "cancelled"

        assert manager.get_status(first_id)["error"]["code"] == "intake_not_found"
        assert manager.get_status(last_id)["status"] == "cancelled"
    finally:
        manager.close()


def test_browser_failure_closes_listener_and_does_not_echo_url(tmp_path: Path) -> None:
    serving = _FakeServing(7)
    manager = IntakeManager(
        tmp_path,
        browser_open=lambda _url: False,
        server_factory=lambda **_kwargs: serving,
    )

    result = manager.open_intake(_request(tmp_path))

    assert result["error"]["code"] == "browser_open_failed"
    assert serving.closed is True
    encoded = json.dumps(result)
    assert serving.url not in encoded
    assert "secret-7" not in encoded
    manager.close()


def test_invalid_request_and_workspace_cannot_expand_trusted_policy(tmp_path: Path) -> None:
    manager = IntakeManager(tmp_path, browser_open=lambda _url: True)
    try:
        wrong_workspace = tmp_path / "other"
        wrong_workspace.mkdir()
        request = _request(tmp_path)
        request["workspace_root"] = str(wrong_workspace)
        assert manager.open_intake(request)["error"]["code"] == "invalid_request"

        request = _request(tmp_path)
        request["needs"] = [
            {"type": "file", "name": "SOURCE", "target": "src/app.py", "required": True}
        ]
        assert manager.open_intake(request)["error"]["code"] == "policy_rejected"
    finally:
        manager.close()


def test_fastmcp_tools_do_not_offer_workspace_or_secret_parameters(tmp_path: Path) -> None:
    pytest.importorskip("mcp")
    manager = IntakeManager(tmp_path, browser_open=lambda _url: True)
    app = create_mcp_server(manager)
    try:
        tools = asyncio.run(app.list_tools())
        by_name = {tool.name: tool for tool in tools}

        assert set(by_name) == {
            "open_secret_intake",
            "get_secret_intake_status",
            "cancel_secret_intake",
        }
        open_schema = by_name["open_secret_intake"].inputSchema
        assert set(open_schema["properties"]) == {"request", "ttl_seconds"}
        assert "workspace" not in json.dumps(open_schema).lower()
        assert by_name["get_secret_intake_status"].annotations.readOnlyHint is True
        assert by_name["cancel_secret_intake"].annotations.destructiveHint is True
    finally:
        manager.close()


def test_stdio_entrypoint_negotiates_without_non_protocol_stdout(tmp_path: Path) -> None:
    pytest.importorskip("mcp")
    from mcp import ClientSession, StdioServerParameters
    from mcp.client.stdio import stdio_client

    async def exercise() -> set[str]:
        parameters = StdioServerParameters(
            command=sys.executable,
            args=[
                "-m",
                "openagent_secretbox.mcp_server",
                "--workspace",
                str(tmp_path),
            ],
        )
        async with stdio_client(parameters) as (read_stream, write_stream):
            async with ClientSession(read_stream, write_stream) as session:
                await session.initialize()
                response = await session.list_tools()
                return {tool.name for tool in response.tools}

    assert asyncio.run(exercise()) == {
        "open_secret_intake",
        "get_secret_intake_status",
        "cancel_secret_intake",
    }
