from __future__ import annotations

import base64
import hashlib
import io
import json
import re
import threading
from collections.abc import Mapping
from http.client import HTTPConnection
from typing import Any
from urllib.parse import urlencode
from wsgiref.util import setup_testing_defaults

import pytest

from openagent_secretbox.gateway import (
    AUTH_COOKIE_NAME,
    GatewayApplication,
    GatewayBroker,
    GatewayError,
    GatewayRuntime,
    UnknownIntake,
)
from openagent_secretbox.server import ApplyFailed, UnknownSession

ACCESS_KEY = "test-owner-access-key-32-bytes"
ORIGIN = "https://secretbox.example.com"
HOST = "secretbox.example.com"
REQUEST = {
    "request_id": "wechat-pay-setup",
    "title": "WeChat Pay API v3 setup",
    "workspace_root": "/srv/payment",
    "needs": [
        {
            "type": "env",
            "name": "WECHAT_PAY_MCH_ID",
            "required": True,
            "description": "WeChat Pay merchant ID",
        },
        {
            "type": "file",
            "name": "apiclient_key.pem",
            "target": "secrets/apiclient_key.pem",
            "required": True,
        },
    ],
    "write_policy": {
        "env_file": ".env.local",
        "mode": "merge_only",
        "no_overwrite": True,
        "backup": False,
    },
    "allowed_targets": [".env.local", "secrets/apiclient_key.pem"],
}


def _apply(_request: Mapping[str, Any], _values: Mapping[str, Any]) -> Mapping[str, Any]:
    return {"status": "applied", "message": "saved"}


def call_app(
    app: Any,
    method: str,
    path: str,
    *,
    payload: Mapping[str, Any] | None = None,
    form: Mapping[str, str] | None = None,
    host: str = HOST,
    origin: str | None = None,
    cookie: str | None = None,
    csrf: str | None = None,
) -> tuple[int, list[tuple[str, str]], bytes]:
    if payload is not None and form is not None:
        raise AssertionError("payload and form are mutually exclusive")
    if payload is not None:
        body = json.dumps(payload).encode("utf-8")
        content_type = "application/json"
    elif form is not None:
        body = urlencode(form).encode("utf-8")
        content_type = "application/x-www-form-urlencoded"
    else:
        body = b""
        content_type = ""
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
    if content_type:
        environ["CONTENT_TYPE"] = content_type
    if origin is not None:
        environ["HTTP_ORIGIN"] = origin
    if cookie is not None:
        environ["HTTP_COOKIE"] = cookie
    if csrf is not None:
        environ["HTTP_X_CSRF_TOKEN"] = csrf
    captured: dict[str, Any] = {}

    def start_response(status: str, headers: list[tuple[str, str]], _exc: Any = None) -> None:
        captured["status"] = status
        captured["headers"] = headers

    response = b"".join(app(environ, start_response))
    return int(captured["status"].split()[0]), captured["headers"], response


def header_values(headers: list[tuple[str, str]], name: str) -> list[str]:
    return [value for key, value in headers if key.lower() == name.lower()]


def login(app: GatewayApplication) -> str:
    status, headers, _ = call_app(
        app,
        "POST",
        "/login",
        form={"access_key": ACCESS_KEY},
        origin=ORIGIN,
    )
    assert status == 303
    cookie = header_values(headers, "set-cookie")[0]
    return cookie.split(";", 1)[0]


def test_public_origin_requires_https_except_explicit_loopback_http() -> None:
    with pytest.raises(ValueError, match="loopback"):
        GatewayBroker("http://secretbox.example.com", ACCESS_KEY)
    for invalid_origin in (
        "https://secretbox.example.com/portal",
        r"https://secretbox.example.com\ses_example",
        "https://:443",
        "https://secretbox.example.com.",
        "https://secretbox.example.com:65536",
        "https://secretbox.example.com:",
        "HTTPS://secretbox.example.com",
        "https://[::::]",
        "https://[abc]",
        "https://[1:2:3:4:5:6:7:8:9]",
        "https://[::ffff:192.0.2.128]",
        "https://" + ".".join(["a" * 63] * 4),
        "https://exa\tmple.com",
        "https://exam\nple.com",
        "https://exam\rple.com",
        "https://secretbox.example.com\n",
    ):
        with pytest.raises(ValueError):
            GatewayBroker(invalid_origin, ACCESS_KEY)
    with pytest.raises(ValueError, match="at least 16"):
        GatewayBroker(ORIGIN, "too-short")

    broker = GatewayBroker("http://127.0.0.1:17321/", ACCESS_KEY)
    assert broker.public_origin == "http://127.0.0.1:17321"
    assert broker.portal_url == "http://127.0.0.1:17321/"
    assert broker.secure_cookies is False

    default_https = GatewayBroker("https://SecretBox.Example.com:443", ACCESS_KEY)
    assert default_https.public_origin == ORIGIN
    assert default_https.expected_host == HOST

    ipv4 = GatewayBroker("https://192.0.2.10:8443/", ACCESS_KEY)
    assert ipv4.public_origin == "https://192.0.2.10:8443"
    assert ipv4.expected_host == "192.0.2.10:8443"


def test_broker_create_returns_only_agent_safe_fixed_portal_metadata() -> None:
    broker = GatewayBroker(ORIGIN, ACCESS_KEY)

    first = broker.create(REQUEST, _apply, ttl=120)
    second_request = dict(REQUEST, request_id="stripe-setup", title="Stripe setup")
    second = broker.create(second_request, _apply, ttl=120)

    assert set(first) == {"intake_id", "request_id", "status", "expires_at", "portal_url"}
    assert first["status"] == "pending"
    assert first["request_id"] == REQUEST["request_id"]
    assert first["portal_url"] == ORIGIN + "/"
    assert second["portal_url"] == first["portal_url"]
    assert second["intake_id"] != first["intake_id"]
    serialized = json.dumps([first, second])
    assert "session_id" not in serialized
    assert "token" not in serialized
    assert "/requests/" not in serialized


def test_broker_status_and_cancel_never_expose_internal_session_fields() -> None:
    broker = GatewayBroker(ORIGIN, ACCESS_KEY)
    created = broker.create(REQUEST, _apply)

    pending = broker.status(created["intake_id"])
    cancelled = broker.cancel(created["intake_id"])

    assert pending == {
        "intake_id": created["intake_id"],
        "request_id": REQUEST["request_id"],
        "status": "pending",
        "expires_at": created["expires_at"],
    }
    assert cancelled["status"] == "cancelled"
    assert "session_id" not in cancelled
    assert "token" not in json.dumps(cancelled)
    with pytest.raises(UnknownIntake):
        broker.status("int_missing")


def test_terminal_intake_retention_discards_store_and_broker_state() -> None:
    broker = GatewayBroker(ORIGIN, ACCESS_KEY, max_retained_terminal=1)
    first = broker.create(dict(REQUEST, request_id="first"), _apply)
    first_session = broker._record(first["intake_id"]).session_id
    assert broker.discard_terminal(first["intake_id"]) is False

    assert broker.cancel(first["intake_id"])["status"] == "cancelled"
    second = broker.create(dict(REQUEST, request_id="second"), _apply)
    assert broker.cancel(second["intake_id"])["status"] == "cancelled"

    with pytest.raises(UnknownIntake):
        broker.status(first["intake_id"])
    with pytest.raises(UnknownSession):
        broker.store.get(first_session)
    assert broker.status(second["intake_id"])["status"] == "cancelled"
    assert broker.discard_terminal(second["intake_id"]) is True
    with pytest.raises(UnknownIntake):
        broker.status(second["intake_id"])


def test_unauthenticated_scanners_cannot_list_or_consume_an_intake() -> None:
    broker = GatewayBroker(ORIGIN, ACCESS_KEY)
    created = broker.create(REQUEST, _apply)
    app = GatewayApplication(broker)

    root_status, root_headers, _ = call_app(app, "GET", "/")
    request_status, request_headers, _ = call_app(
        app, "GET", f"/requests/{created['intake_id']}"
    )

    assert root_status == request_status == 303
    assert header_values(root_headers, "location") == ["/login"]
    assert header_values(request_headers, "location") == ["/login"]
    assert broker.status(created["intake_id"])["status"] == "pending"

    owner_cookie = login(app)
    authenticated_get, _, _ = call_app(
        app, "GET", f"/requests/{created['intake_id']}/open", cookie=owner_cookie
    )
    assert authenticated_get == 404
    assert broker.status(created["intake_id"])["status"] == "pending"


def test_login_uses_memory_cookie_with_strict_security_attributes() -> None:
    broker = GatewayBroker(ORIGIN, ACCESS_KEY)
    app = GatewayApplication(broker)

    invalid_status, invalid_headers, invalid_body = call_app(
        app,
        "POST",
        "/login",
        form={"access_key": "wrong-owner-key-value"},
        origin=ORIGIN,
    )
    assert invalid_status == 401
    assert not header_values(invalid_headers, "set-cookie")
    assert b"wrong-owner-key-value" not in invalid_body

    owner_cookie = login(app)
    raw_cookie = next(iter(broker._auth_sessions))
    assert ACCESS_KEY.encode() not in raw_cookie
    assert owner_cookie.startswith(AUTH_COOKIE_NAME + "=")
    _, valid_headers, _ = call_app(
        app,
        "POST",
        "/login",
        form={"access_key": ACCESS_KEY},
        origin=ORIGIN,
    )
    set_cookie = header_values(valid_headers, "set-cookie")[0]
    assert "HttpOnly" in set_cookie
    assert "SameSite=Strict" in set_cookie
    assert "Path=/" in set_cookie
    assert "Secure" in set_cookie

    local = GatewayApplication(GatewayBroker("http://localhost:17321", ACCESS_KEY))
    _, local_headers, _ = call_app(
        local,
        "POST",
        "/login",
        form={"access_key": ACCESS_KEY},
        host="localhost:17321",
        origin="http://localhost:17321",
    )
    assert "Secure" not in header_values(local_headers, "set-cookie")[0]


def test_exact_host_and_origin_are_enforced_before_login() -> None:
    broker = GatewayBroker(ORIGIN, ACCESS_KEY)
    app = GatewayApplication(broker)

    wrong_host, _, _ = call_app(app, "GET", "/login", host="attacker.example")
    missing_origin, _, _ = call_app(
        app, "POST", "/login", form={"access_key": ACCESS_KEY}
    )
    wrong_origin, _, _ = call_app(
        app,
        "POST",
        "/login",
        form={"access_key": ACCESS_KEY},
        origin="https://attacker.example",
    )

    assert wrong_host == 400
    assert missing_origin == wrong_origin == 403
    assert not broker._auth_sessions


def test_authenticated_portal_lists_multiple_pending_requests_without_secrets() -> None:
    broker = GatewayBroker(ORIGIN, ACCESS_KEY)
    first = broker.create(REQUEST, _apply)
    second = broker.create(dict(REQUEST, request_id="second", title="Second request"), _apply)
    app = GatewayApplication(broker)
    owner_cookie = login(app)

    status, headers, body = call_app(app, "GET", "/", cookie=owner_cookie)

    assert status == 200
    assert first["intake_id"].encode() in body
    assert second["intake_id"].encode() in body
    assert b"WeChat Pay API v3 setup" in body
    assert b"Second request" in body
    assert b'method="post"' in body
    assert f"/requests/{first['intake_id']}/open".encode() in body
    assert b"session_id" not in body
    assert b"bootstrap_token" not in body
    assert header_values(headers, "cache-control")[0].startswith("no-store")
    content_security_policy = header_values(headers, "content-security-policy")[0]
    assert "frame-ancestors 'none'" in content_security_policy
    assert "connect-src 'self'" in content_security_policy


def test_opening_request_exchanges_server_side_and_bootstraps_existing_form() -> None:
    broker = GatewayBroker(ORIGIN, ACCESS_KEY)
    created = broker.create(REQUEST, _apply)
    app = GatewayApplication(broker)
    owner_cookie = login(app)
    internal = broker._record(created["intake_id"])
    one_time_token = internal.bootstrap_token
    assert one_time_token is not None

    status, headers, body = call_app(
        app,
        "POST",
        f"/requests/{created['intake_id']}/open",
        origin=ORIGIN,
        cookie=owner_cookie,
    )

    assert status == 200
    assert broker.status(created["intake_id"])["status"] == "exchanged"
    assert internal.bootstrap_token is None
    assert one_time_token.encode() not in body
    assert b"sessionStorage.setItem" in body
    assert b"WECHAT_PAY_MCH_ID" in body
    intake_cookie = header_values(headers, "set-cookie")[0]
    assert "HttpOnly" in intake_cookie
    assert "SameSite=Strict" in intake_cookie
    assert "Secure" in intake_cookie
    assert f"Path=/api/sessions/{internal.session_id}/" in intake_cookie

    again, again_headers, again_body = call_app(
        app,
        "POST",
        f"/requests/{created['intake_id']}/open",
        origin=ORIGIN,
        cookie=owner_cookie,
    )
    assert again == 410
    assert not header_values(again_headers, "set-cookie")
    assert b"can no longer be opened" in again_body

    portal_status, _, portal_body = call_app(app, "GET", "/", cookie=owner_cookie)
    assert portal_status == 200
    assert created["intake_id"].encode() not in portal_body


def test_authenticated_browser_can_submit_while_agent_status_stays_redacted() -> None:
    received: dict[str, Any] = {}

    def apply(request: Mapping[str, Any], values: Mapping[str, Any]) -> Mapping[str, Any]:
        secret_value = values["env"]["WECHAT_PAY_MCH_ID"]
        received["request_id"] = request["request_id"]
        received["secret"] = secret_value
        return {
            "status": "applied",
            "echo": secret_value,
            "encoded": base64.b64encode(secret_value.encode()).decode(),
            "hashed": hashlib.sha256(secret_value.encode()).hexdigest(),
            "session_id": "ses_callback-metadata",
            "token": "callback-token",
            "url": "https://secretbox.example.com/intake/ses_callback-metadata",
        }

    broker = GatewayBroker(ORIGIN, ACCESS_KEY)
    created = broker.create(REQUEST, apply)
    app = GatewayApplication(broker)
    owner_cookie = login(app)
    _, form_headers, form_body = call_app(
        app,
        "POST",
        f"/requests/{created['intake_id']}/open",
        origin=ORIGIN,
        cookie=owner_cookie,
    )
    internal = broker._record(created["intake_id"])
    match = re.search(rb'"csrf_token":"([^"]+)"', form_body)
    assert match is not None
    csrf = match.group(1).decode("ascii")
    intake_cookie = header_values(form_headers, "set-cookie")[0].split(";", 1)[0]
    secret = "1900000109-test-secret"

    submitted, _, response = call_app(
        app,
        "POST",
        f"/api/sessions/{internal.session_id}/submit",
        payload={"values": {"env": {"WECHAT_PAY_MCH_ID": secret}}},
        origin=ORIGIN,
        cookie=f"{owner_cookie}; {intake_cookie}",
        csrf=csrf,
    )

    assert submitted == 200
    assert secret.encode() not in response
    assert received == {"request_id": REQUEST["request_id"], "secret": secret}
    agent_status = broker.status(created["intake_id"])
    assert agent_status["status"] == "failed"
    assert agent_status["error_code"] == "apply_failed"
    assert "result" not in agent_status
    assert "session_id" not in agent_status
    assert secret not in json.dumps(agent_status)
    serialized_status = json.dumps(agent_status)
    assert base64.b64encode(secret.encode()).decode() not in serialized_status
    assert hashlib.sha256(secret.encode()).hexdigest() not in serialized_status
    assert "ses_callback-metadata" not in serialized_status
    assert "callback-token" not in serialized_status
    assert "https://" not in serialized_status
    assert internal.csrf_token is None


def test_broker_close_revokes_authentication_and_discards_pending_state() -> None:
    broker = GatewayBroker(ORIGIN, ACCESS_KEY)
    created = broker.create(REQUEST, _apply)
    session_id = broker._record(created["intake_id"]).session_id
    owner_cookie = login(GatewayApplication(broker))
    owner_token = owner_cookie.split("=", 1)[1]

    broker.close()

    assert broker._intakes == {}
    assert broker._sessions == {}
    assert broker._auth_sessions == {}
    assert broker._authenticate(owner_token) is False
    with pytest.raises(UnknownIntake):
        broker.status(created["intake_id"])
    with pytest.raises(UnknownSession):
        broker.store.get(session_id)
    with pytest.raises(GatewayError):
        broker.create(REQUEST, _apply)


@pytest.mark.parametrize("apply_fails", [False, True])
def test_broker_close_discards_submitted_session_after_apply_finishes(
    apply_fails: bool,
) -> None:
    entered = threading.Event()
    release = threading.Event()

    def blocking_apply(
        request: Mapping[str, Any], _values: Mapping[str, Any]
    ) -> Mapping[str, Any]:
        entered.set()
        assert release.wait(timeout=2)
        if apply_fails:
            raise RuntimeError("disposable callback failure")
        return {
            "request_id": request["request_id"],
            "status": "applied",
            "written": [
                {
                    "type": "env",
                    "name": "WECHAT_PAY_MCH_ID",
                    "action": "added",
                    "target": ".env.local",
                }
            ],
            "conflicts": [],
            "missing": [],
            "blocked": [],
        }

    broker = GatewayBroker(ORIGIN, ACCESS_KEY)
    created = broker.create(REQUEST, blocking_apply)
    record = broker._record(created["intake_id"])
    bootstrap = broker.store.exchange(record.session_id, record.bootstrap_token or "")
    errors: list[type[BaseException]] = []

    def submit() -> None:
        try:
            broker.store.submit(
                record.session_id,
                {"env": {"WECHAT_PAY_MCH_ID": "disposable"}},
                bootstrap.csrf_token,
                session_cookie=bootstrap.session_cookie,
            )
        except ApplyFailed:
            errors.append(ApplyFailed)

    worker = threading.Thread(target=submit)
    worker.start()
    assert entered.wait(timeout=2)
    assert broker.store.get(record.session_id)["status"] == "submitted"

    broker.close()
    assert broker.store.get(record.session_id)["status"] == "submitted"
    release.set()
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert errors == ([ApplyFailed] if apply_fails else [])
    with pytest.raises(UnknownSession):
        broker.store.get(record.session_id)


def test_login_racing_gateway_close_returns_stable_unavailable(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    broker = GatewayBroker(ORIGIN, ACCESS_KEY)
    app = GatewayApplication(broker)
    verified = threading.Event()
    release = threading.Event()
    original_verify = broker._verify_owner_key

    def blocking_verify(candidate: str) -> bool:
        result = original_verify(candidate)
        verified.set()
        assert release.wait(timeout=2)
        return result

    monkeypatch.setattr(broker, "_verify_owner_key", blocking_verify)
    responses: list[tuple[int, bytes]] = []

    def sign_in() -> None:
        status, _, body = call_app(
            app,
            "POST",
            "/login",
            form={"access_key": ACCESS_KEY},
            origin=ORIGIN,
        )
        responses.append((status, body))

    worker = threading.Thread(target=sign_in)
    worker.start()
    assert verified.wait(timeout=2)
    broker.close()
    release.set()
    worker.join(timeout=2)

    assert not worker.is_alive()
    assert responses[0][0] == 503
    assert ACCESS_KEY.encode() not in responses[0][1]


def test_two_concurrent_portal_opens_consume_one_bootstrap_only() -> None:
    broker = GatewayBroker(ORIGIN, ACCESS_KEY)
    created = broker.create(REQUEST, _apply)
    app = GatewayApplication(broker)
    owner_cookie = login(app)
    barrier = threading.Barrier(3)
    statuses: list[int] = []

    def open_request() -> None:
        barrier.wait()
        status, _, _ = call_app(
            app,
            "POST",
            f"/requests/{created['intake_id']}/open",
            origin=ORIGIN,
            cookie=owner_cookie,
        )
        statuses.append(status)

    first = threading.Thread(target=open_request)
    second = threading.Thread(target=open_request)
    first.start()
    second.start()
    barrier.wait()
    first.join(timeout=2)
    second.join(timeout=2)

    assert not first.is_alive()
    assert not second.is_alive()
    assert sorted(statuses) == [200, 410]


def test_logout_revokes_memory_session() -> None:
    broker = GatewayBroker(ORIGIN, ACCESS_KEY)
    app = GatewayApplication(broker)
    owner_cookie = login(app)

    status, headers, _ = call_app(
        app, "POST", "/logout", origin=ORIGIN, cookie=owner_cookie
    )
    after, after_headers, _ = call_app(app, "GET", "/", cookie=owner_cookie)

    assert status == 303
    assert "Max-Age=0" in header_values(headers, "set-cookie")[0]
    assert after == 303
    assert header_values(after_headers, "location") == ["/login"]


def test_gateway_runtime_is_long_lived_and_reuses_one_application() -> None:
    broker = GatewayBroker("http://127.0.0.1:17321", ACCESS_KEY)
    with pytest.raises(ValueError, match="only binds"):
        GatewayRuntime(broker, host="0.0.0.0", port=17321)
    with GatewayRuntime(broker, port=0) as runtime:
        first = broker.create(REQUEST, _apply)
        second = broker.create(dict(REQUEST, request_id="later"), _apply)
        assert runtime.app.broker is broker
        assert runtime.port > 0
        assert first["portal_url"] == second["portal_url"]
        assert broker.status(first["intake_id"])["status"] == "pending"
        assert broker.status(second["intake_id"])["status"] == "pending"

        connection = HTTPConnection(runtime.host, runtime.port, timeout=2)
        connection.request("GET", "/healthz", headers={"Host": "127.0.0.1:17321"})
        response = connection.getresponse()
        assert response.status == 200
        assert json.loads(response.read()) == {"ok": True}
        connection.close()
