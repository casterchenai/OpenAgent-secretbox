from __future__ import annotations

import io
import json
import socket
import threading
import time
from collections.abc import Mapping
from typing import Any
from urllib.parse import parse_qs, urlsplit
from urllib.request import Request, urlopen
from wsgiref.util import setup_testing_defaults

import pytest

from openagent_secretbox.server import (
    InvalidState,
    InvalidToken,
    SessionStore,
    create_app,
    serve_once,
)

REQUEST = {
    "request_id": "openai-local-setup",
    "title": "OpenAI API setup",
    "needs": [
        {
            "type": "env",
            "name": "OPENAI_API_KEY",
            "required": True,
            "description": "Key used only by the local app",
        }
    ],
    "write_policy": {
        "env_file": ".env.local",
        "mode": "merge_only",
        "no_overwrite": True,
        "backup": False,
    },
}


def call_app(
    app: Any,
    method: str,
    path: str,
    payload: Mapping[str, Any] | None = None,
    *,
    host: str = "127.0.0.1:17321",
    origin: str | None = None,
    csrf: str | None = None,
    cookie: str | None = None,
) -> tuple[int, dict[str, str], bytes]:
    body = b"" if payload is None else json.dumps(payload).encode("utf-8")
    environ: dict[str, Any] = {}
    setup_testing_defaults(environ)
    environ.update(
        {
            "REQUEST_METHOD": method,
            "PATH_INFO": path,
            "QUERY_STRING": "",
            "HTTP_HOST": host,
            "CONTENT_LENGTH": str(len(body)),
            "wsgi.input": io.BytesIO(body),
        }
    )
    if payload is not None:
        environ["CONTENT_TYPE"] = "application/json"
    if origin is not None:
        environ["HTTP_ORIGIN"] = origin
    if csrf is not None:
        environ["HTTP_X_CSRF_TOKEN"] = csrf
    if cookie is not None:
        environ["HTTP_COOKIE"] = cookie
    captured: dict[str, Any] = {}

    def start_response(status: str, headers: list[tuple[str, str]], _exc_info: Any = None) -> None:
        captured["status"] = status
        captured["headers"] = headers

    response = b"".join(app(environ, start_response))
    headers = {key.lower(): value for key, value in captured["headers"]}
    return int(captured["status"].split()[0]), headers, response


def test_store_keeps_only_token_digest_and_exchange_is_single_use() -> None:
    store = SessionStore(ttl=60)
    handle = store.create(REQUEST)

    session = store._sessions[handle.session_id]
    assert isinstance(session.token_digest, bytes)
    assert handle.token.encode() not in session.token_digest
    assert handle.token not in repr(handle)
    assert handle.token not in repr(store.__dict__)

    exchange = store.exchange(handle.session_id, handle.token)
    assert exchange.session_id == handle.session_id
    assert exchange.csrf_token not in repr(exchange)
    assert exchange.session_cookie not in repr(exchange)
    assert store.get(handle.session_id)["status"] == "exchanged"
    with pytest.raises(InvalidToken):
        store.exchange(handle.session_id, handle.token)


def test_session_expires_and_cannot_be_exchanged() -> None:
    now = [100.0]
    store = SessionStore(ttl=5, clock=lambda: now[0])
    handle = store.create(REQUEST)
    now[0] = 106.0

    with pytest.raises(InvalidToken):
        store.exchange(handle.session_id, handle.token)
    assert store.get(handle.session_id)["status"] == "expired"


def test_submitted_session_ignores_ttl_and_reaches_one_terminal_state() -> None:
    now = [100.0]
    apply_started = threading.Event()
    release_apply = threading.Event()
    outcome: dict[str, Any] = {}

    def blocking_apply(_request: Any, _values: Any) -> dict[str, str]:
        apply_started.set()
        if not release_apply.wait(timeout=2):
            raise AssertionError("test did not release apply callback")
        return {"status": "applied"}

    store = SessionStore(ttl=1, clock=lambda: now[0])
    handle = store.create(REQUEST, blocking_apply)
    exchange = store.exchange(handle.session_id, handle.token)

    def submit() -> None:
        try:
            outcome["result"] = store.submit(
                handle.session_id,
                {"env": {"OPENAI_API_KEY": "test-only-value"}},
                exchange.csrf_token,
                session_cookie=exchange.session_cookie,
            )
        except Exception as exc:  # pragma: no cover - asserted below
            outcome["error"] = exc

    worker = threading.Thread(target=submit)
    worker.start()
    try:
        assert apply_started.wait(timeout=1)
        assert store.get(handle.session_id)["status"] == "submitted"

        now[0] = 102.0
        during_apply = store.get(handle.session_id)
        owner_cancel = store.cancel_pending(handle.session_id)
        assert during_apply["status"] == "submitted"
        assert owner_cancel["status"] == "submitted"
        assert "error_code" not in during_apply
        assert store.all_terminal(handle.session_id) is False
        with pytest.raises(InvalidState):
            store.cancel(
                handle.session_id,
                exchange.csrf_token,
                session_cookie=exchange.session_cookie,
            )
        assert store.get(handle.session_id)["status"] == "submitted"
    finally:
        release_apply.set()
        worker.join(timeout=2)

    assert not worker.is_alive()
    assert "error" not in outcome
    assert outcome["result"]["status"] == "applied"
    assert store.get(handle.session_id)["status"] == "applied"

    now[0] = 10_000.0
    with pytest.raises(InvalidState):
        store.authorize(
            handle.session_id,
            exchange.csrf_token,
            exchange.session_cookie,
        )
    final = store.get(handle.session_id)
    assert final["status"] == "applied"
    assert "error_code" not in final


def test_owner_cancel_wins_atomically_before_submit_transition(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    now = [100.0]
    authorized = threading.Event()
    continue_submit = threading.Event()
    apply_called = threading.Event()
    errors: list[Exception] = []

    def apply(_request: Any, _values: Any) -> dict[str, str]:
        apply_called.set()
        return {"status": "applied"}

    store = SessionStore(ttl=1, clock=lambda: now[0])
    handle = store.create(REQUEST, apply)
    exchange = store.exchange(handle.session_id, handle.token)
    original_authorize = store.authorize

    def paused_authorize(*args: Any, **kwargs: Any) -> Any:
        session = original_authorize(*args, **kwargs)
        authorized.set()
        if not continue_submit.wait(timeout=2):
            raise AssertionError("test did not release submit transition")
        return session

    monkeypatch.setattr(store, "authorize", paused_authorize)

    def submit() -> None:
        try:
            store.submit(
                handle.session_id,
                {"env": {"OPENAI_API_KEY": "test-only-value"}},
                exchange.csrf_token,
                session_cookie=exchange.session_cookie,
            )
        except Exception as exc:
            errors.append(exc)

    worker = threading.Thread(target=submit)
    worker.start()
    try:
        assert authorized.wait(timeout=1)
        cancelled = store.cancel_pending(handle.session_id)
        assert cancelled["status"] == "cancelled"
    finally:
        continue_submit.set()
        worker.join(timeout=2)

    assert not worker.is_alive()
    assert len(errors) == 1
    assert isinstance(errors[0], InvalidState)
    assert not apply_called.is_set()

    now[0] = 10_000.0
    assert store.get(handle.session_id)["status"] == "cancelled"


def test_intake_escapes_request_text_and_sets_security_headers() -> None:
    request = dict(REQUEST)
    request["title"] = '<script>alert("x")</script>'
    request["workspace_root"] = "/trusted/workspace"
    app = create_app(request=request)
    handle = app.handle

    request_path = handle.path.split("#", 1)[0]
    status, headers, body = call_app(app, "GET", request_path)

    assert status == 200
    assert b'<script>alert("x")</script>' not in body
    assert b"&lt;script&gt;alert" in body
    assert b"Target: <code>.env.local</code>" in body
    assert b"<code>/trusted/workspace</code>" in body
    assert b"overwrite blocked" in body
    assert headers["cache-control"].startswith("no-store")
    assert headers["referrer-policy"] == "no-referrer"
    assert headers["x-content-type-options"] == "nosniff"
    assert "frame-ancestors 'none'" in headers["content-security-policy"]
    assert "unsafe-inline" not in headers["content-security-policy"]
    assert "script-src 'nonce-" in headers["content-security-policy"]
    assert handle.token.encode() not in body
    assert handle.path.endswith(f"#token={handle.token}")


def test_env_file_uses_a_multiline_secret_control() -> None:
    request = dict(REQUEST)
    request["needs"] = [
        {
            "type": "env_file",
            "name": "ENV_BLOCK",
            "required": True,
            "description": "Environment block",
        }
    ]
    app = create_app(request=request)

    status, _, body = call_app(app, "GET", app.handle.path.split("#", 1)[0])

    assert status == 200
    assert b'<textarea rows="8" name="ENV_BLOCK"' in body
    assert b'data-secret-type="env"' in body
    assert b"disabled></textarea>" in body
    assert b'<button id="cancel"' in body
    assert b"sessionStorage.setItem(storageKey" in body
    assert b'type="password" name="ENV_BLOCK"' not in body


def test_intake_page_explains_one_time_flow_and_has_distinct_states() -> None:
    app = create_app(request=REQUEST)

    status, _, body = call_app(app, "GET", app.handle.path.split("#", 1)[0])

    assert status == 200
    assert "此页面只能使用一次".encode() in body
    assert "安全会话已就绪，可以填写并上传文件".encode() in body
    assert "凭据已安全保存".encode() in body
    assert "请生成新的 SecretBox 链接".encode() in body
    assert b"showUnavailable" in body
    assert b"json(fetch(" not in body
    assert body.count(b".then(json)") == 3


def test_password_inputs_have_local_visibility_controls_that_remask() -> None:
    app = create_app(request=REQUEST)

    status, _, body = call_app(app, "GET", app.handle.path.split("#", 1)[0])

    assert status == 200
    assert b'<div class="password-control">' in body
    assert b'type="password" name="OPENAI_API_KEY"' in body
    assert b'class="visibility-toggle"' in body
    assert "aria-label=\"显示 OPENAI_API_KEY\"".encode() in body
    assert b"input.type = visible ? 'text' : 'password'" in body
    assert b"visibilitychange" in body
    assert b"window.addEventListener('pagehide', maskAllSecrets)" in body
    assert body.count(b"maskAllSecrets();") >= 3


def test_reused_intake_link_returns_styled_friendly_html() -> None:
    app = create_app(request=REQUEST)
    handle = app.handle
    path = handle.path.split("#", 1)[0]

    exchanged, _, _ = call_app(
        app,
        "POST",
        "/api/exchange",
        {"session_id": handle.session_id, "token": handle.token},
    )
    assert exchanged == 200

    status, headers, body = call_app(app, "GET", path)

    assert status == 404
    assert headers["content-type"].startswith("text/html")
    assert "此一次性链接已失效，无法继续".encode() in body
    assert "要求生成新的 SecretBox 链接".encode() in body
    assert b"Session not found" not in body
    assert "style-src 'nonce-" in headers["content-security-policy"]
    assert b'<style nonce="' in body


def test_host_and_origin_are_validated() -> None:
    app = create_app(request=REQUEST)
    handle = app.handle

    status, _, _ = call_app(app, "GET", handle.path, host="attacker.example")
    assert status == 400

    status, _, _ = call_app(
        app,
        "POST",
        "/api/exchange",
        {"session_id": handle.session_id, "token": handle.token},
        origin="https://attacker.example",
    )
    assert status == 403
    assert app.store.get(handle.session_id)["status"] == "pending"


def test_exchange_csrf_submit_and_result_redaction() -> None:
    received: dict[str, Any] = {}

    def apply(request: Mapping[str, Any], values: Mapping[str, Any]) -> Mapping[str, Any]:
        received["request_id"] = request["request_id"]
        received["value"] = values["env"]["OPENAI_API_KEY"]
        return {
            "status": "applied",
            "written": [{"type": "env", "name": "OPENAI_API_KEY", "action": "added"}],
            "echo": values["env"]["OPENAI_API_KEY"],
        }

    app = create_app(request=REQUEST, apply_fn=apply)
    handle = app.handle
    origin = "http://127.0.0.1:17321"
    status, headers, body = call_app(
        app,
        "POST",
        "/api/exchange",
        {"session_id": handle.session_id, "token": handle.token},
        origin=origin,
    )
    assert status == 200
    exchange = json.loads(body)
    assert handle.token.encode() not in body
    cookie = headers["set-cookie"].split(";", 1)[0]

    repeated, _, _ = call_app(
        app,
        "POST",
        "/api/exchange",
        {"session_id": handle.session_id, "token": handle.token},
        origin=origin,
    )
    assert repeated == 404

    secret = "sk-test-should-never-return"
    denied, _, denied_body = call_app(
        app,
        "POST",
        f"/api/sessions/{exchange['session_id']}/submit",
        {"values": {"env": {"OPENAI_API_KEY": secret}}},
        origin=origin,
        csrf="wrong",
        cookie=cookie,
    )
    assert denied == 409
    assert secret.encode() not in denied_body

    applied, _, applied_body = call_app(
        app,
        "POST",
        f"/api/sessions/{exchange['session_id']}/submit",
        {"values": {"env": {"OPENAI_API_KEY": secret}}},
        origin=origin,
        csrf=exchange["csrf_token"],
        cookie=cookie,
    )
    assert applied == 200
    assert json.loads(applied_body)["status"] == "applied"
    assert secret.encode() not in applied_body
    assert b"[redacted]" in applied_body
    assert received == {"request_id": REQUEST["request_id"], "value": secret}


def test_submit_without_core_apply_has_clear_non_secret_error() -> None:
    app = create_app(request=REQUEST)
    handle = app.handle
    status, headers, body = call_app(
        app,
        "POST",
        "/api/exchange",
        {"session_id": handle.session_id, "token": handle.token},
    )
    exchange = json.loads(body)
    cookie = headers["set-cookie"].split(";", 1)[0]
    assert status == 200

    status, _, body = call_app(
        app,
        "POST",
        f"/api/sessions/{exchange['session_id']}/submit",
        {"values": {"env": {"OPENAI_API_KEY": "not-in-response"}}},
        csrf=exchange["csrf_token"],
        cookie=cookie,
    )
    assert status == 501
    assert json.loads(body)["error"]["code"] == "apply_unavailable"
    assert b"not-in-response" not in body
    assert app.store.get(handle.session_id)["status"] == "exchanged"


def test_serve_once_rejects_non_loopback_bind_and_keeps_token_in_fragment() -> None:
    with pytest.raises(ValueError):
        serve_once(REQUEST, host="0.0.0.0")

    serving = serve_once(REQUEST)
    try:
        assert serving.server.server_address[0] == "127.0.0.1"
        assert serving.url is not None
        assert "?" not in serving.url
        assert serving.handle is not None
        assert f"#token={serving.handle.token}" in serving.url
        assert serving.handle.token not in repr(serving)
    finally:
        serving.close()


def test_live_server_reads_exact_content_length_without_blocking() -> None:
    serving = serve_once(REQUEST, apply_fn=lambda _request, _values: {"ok": True})
    try:
        assert serving.url is not None
        assert serving.handle is not None
        split = urlsplit(serving.url)
        token = parse_qs(split.fragment)["token"][0]
        origin = f"http://127.0.0.1:{serving.server.server_port}"
        request = Request(
            origin + "/api/exchange",
            data=json.dumps({"session_id": serving.handle.session_id, "token": token}).encode(
                "utf-8"
            ),
            headers={"Content-Type": "application/json", "Origin": origin},
            method="POST",
        )
        with urlopen(request, timeout=2) as response:
            payload = json.loads(response.read())
        assert payload["session_id"] == serving.handle.session_id
    finally:
        serving.close()


def test_blocked_apply_is_not_reported_as_applied() -> None:
    app = create_app(request=REQUEST, apply_fn=lambda _request, _values: {"status": "blocked"})
    handle = app.handle
    status, headers, body = call_app(
        app,
        "POST",
        "/api/exchange",
        {"session_id": handle.session_id, "token": handle.token},
    )
    assert status == 200
    exchange = json.loads(body)
    cookie = headers["set-cookie"].split(";", 1)[0]

    status, _, body = call_app(
        app,
        "POST",
        f"/api/sessions/{exchange['session_id']}/submit",
        {"values": {"env": {"OPENAI_API_KEY": "not-returned"}}},
        csrf=exchange["csrf_token"],
        cookie=cookie,
    )
    payload = json.loads(body)
    assert status == 200
    assert payload["status"] == "failed"
    assert payload["error_code"] == "apply_blocked"
    assert b"not-returned" not in body


def test_apply_result_without_explicit_status_fails_closed() -> None:
    app = create_app(request=REQUEST, apply_fn=lambda _request, _values: {"ok": True})
    handle = app.handle
    status, headers, body = call_app(
        app,
        "POST",
        "/api/exchange",
        {"session_id": handle.session_id, "token": handle.token},
    )
    assert status == 200
    exchange = json.loads(body)
    cookie = headers["set-cookie"].split(";", 1)[0]

    status, _, body = call_app(
        app,
        "POST",
        f"/api/sessions/{exchange['session_id']}/submit",
        {"values": {"env": {"OPENAI_API_KEY": "not-returned"}}},
        csrf=exchange["csrf_token"],
        cookie=cookie,
    )

    assert status == 200
    assert json.loads(body)["status"] == "failed"
    assert b"not-returned" not in body


@pytest.mark.parametrize("secret", ["app", "status", "applied"])
def test_short_secret_does_not_corrupt_server_status(secret: str) -> None:
    def apply(_request: Any, _values: Any) -> dict[str, Any]:
        return {"status": "applied", "message": f"wrote {secret}"}

    app = create_app(request=REQUEST, apply_fn=apply)
    handle = app.handle
    status, headers, body = call_app(
        app,
        "POST",
        "/api/exchange",
        {"session_id": handle.session_id, "token": handle.token},
    )
    assert status == 200
    exchange = json.loads(body)
    cookie = headers["set-cookie"].split(";", 1)[0]

    status, _, body = call_app(
        app,
        "POST",
        f"/api/sessions/{exchange['session_id']}/submit",
        {"values": {"env": {"OPENAI_API_KEY": secret}}},
        csrf=exchange["csrf_token"],
        cookie=cookie,
    )

    payload = json.loads(body)
    assert status == 200
    assert payload["status"] == "applied"
    assert payload["result"]["status"] == "applied"
    assert payload["result"]["message"] == "wrote [redacted]"


def test_apply_result_never_formats_bytes_or_arbitrary_objects() -> None:
    secret = "callback-secret-must-not-appear"

    class UnsafeResult:
        def __str__(self) -> str:
            return secret

    def apply(_request: Any, _values: Any) -> dict[str, Any]:
        return {
            "status": "applied",
            "binary_detail": secret.encode(),
            "object_detail": UnsafeResult(),
            secret: "unsafe-key",
            UnsafeResult(): "unsafe-object-key",
        }

    app = create_app(request=REQUEST, apply_fn=apply)
    handle = app.handle
    status, headers, body = call_app(
        app,
        "POST",
        "/api/exchange",
        {"session_id": handle.session_id, "token": handle.token},
    )
    assert status == 200
    exchange = json.loads(body)
    cookie = headers["set-cookie"].split(";", 1)[0]

    status, _, body = call_app(
        app,
        "POST",
        f"/api/sessions/{exchange['session_id']}/submit",
        {"values": {"env": {"OPENAI_API_KEY": secret}}},
        csrf=exchange["csrf_token"],
        cookie=cookie,
    )

    payload = json.loads(body)
    assert status == 200
    assert payload["status"] == "applied"
    assert payload["result"]["binary_detail"] == "[redacted]"
    assert payload["result"]["object_detail"] == "[redacted]"
    assert payload["result"]["[redacted]"] == "unsafe-key"
    assert payload["result"]["[redacted-key]"] == "unsafe-object-key"
    assert secret.encode() not in body


def test_exchange_rejects_token_from_a_different_displayed_session() -> None:
    store = SessionStore()
    first = store.create(REQUEST)
    second_request = dict(REQUEST)
    second_request["request_id"] = "second-request"
    second = store.create(second_request)
    app = create_app(store=store)

    status, _, page = call_app(app, "GET", first.path.split("#", 1)[0])
    assert status == 200
    assert REQUEST["title"].encode() in page

    status, _, _ = call_app(
        app,
        "POST",
        "/api/exchange",
        {"session_id": first.session_id, "token": second.token},
    )
    assert status == 404
    assert store.get(first.session_id)["status"] == "pending"
    assert store.get(second.session_id)["status"] == "pending"

    status, _, body = call_app(
        app,
        "POST",
        "/api/exchange",
        {"session_id": second.session_id, "token": second.token},
    )
    assert status == 200
    assert json.loads(body)["session_id"] == second.session_id


def test_session_cookie_is_required_and_scoped_per_session() -> None:
    store = SessionStore()
    first = store.create(REQUEST, lambda _request, _values: {"status": "applied"})
    second_request = dict(REQUEST)
    second_request["request_id"] = "parallel-request"
    second = store.create(second_request, lambda _request, _values: {"status": "applied"})
    app = create_app(store=store)

    def exchange(handle: Any) -> tuple[dict[str, Any], str, str]:
        status, headers, body = call_app(
            app,
            "POST",
            "/api/exchange",
            {"session_id": handle.session_id, "token": handle.token},
        )
        assert status == 200
        set_cookie = headers["set-cookie"]
        return json.loads(body), set_cookie.split(";", 1)[0], set_cookie

    first_exchange, first_cookie, first_set_cookie = exchange(first)
    second_exchange, second_cookie, second_set_cookie = exchange(second)
    assert first_cookie.split("=", 1)[0] != second_cookie.split("=", 1)[0]
    assert f"Path=/api/sessions/{first.session_id}/" in first_set_cookie
    assert f"Path=/api/sessions/{second.session_id}/" in second_set_cookie

    missing_cookie, _, _ = call_app(
        app,
        "POST",
        f"/api/sessions/{first.session_id}/submit",
        {"values": {"env": {"OPENAI_API_KEY": "secret"}}},
        csrf=first_exchange["csrf_token"],
    )
    assert missing_cookie == 409

    combined_cookies = f"{first_cookie}; {second_cookie}"
    applied, _, _ = call_app(
        app,
        "POST",
        f"/api/sessions/{first.session_id}/submit",
        {"values": {"env": {"OPENAI_API_KEY": "secret"}}},
        csrf=first_exchange["csrf_token"],
        cookie=combined_cookies,
    )
    assert applied == 200

    # The second session remains independently usable with the same browser jar.
    cancelled, _, _ = call_app(
        app,
        "POST",
        f"/api/sessions/{second.session_id}/cancel",
        {},
        csrf=second_exchange["csrf_token"],
        cookie=combined_cookies,
    )
    assert cancelled == 200


def test_partial_body_does_not_block_server_and_close_stops_workers() -> None:
    serving = serve_once(REQUEST, apply_fn=lambda _request, _values: {"status": "applied"})
    client: socket.socket | None = None
    try:
        assert serving.url is not None
        port = serving.server.server_port
        client = socket.create_connection(("127.0.0.1", port), timeout=2)
        client.sendall(
            (
                "POST /api/exchange HTTP/1.1\r\n"
                f"Host: 127.0.0.1:{port}\r\n"
                f"Origin: http://127.0.0.1:{port}\r\n"
                "Content-Type: application/json\r\n"
                "Content-Length: 1000\r\n"
                "Connection: close\r\n\r\n"
                "{"
            ).encode("ascii")
        )
        time.sleep(0.05)

        with urlopen(f"http://127.0.0.1:{port}/healthz", timeout=1) as response:
            assert json.loads(response.read()) == {"ok": True}

        started = time.monotonic()
        serving.close()
        assert time.monotonic() - started < 1.5
        assert not serving.thread.is_alive()
        assert serving.server.wait_for_active_requests(timeout=0.5)
    finally:
        if client is not None:
            client.close()
        serving.close()
