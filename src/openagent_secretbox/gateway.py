"""Authenticated, fixed-origin gateway for remote SecretBox intake.

The local intake server issues a separate browser URL for every request.  This
module adds the remote deployment control plane: agents receive an opaque intake
identifier and one stable portal URL, while the one-time SecretBox bootstrap
credentials stay inside the authenticated portal process.

The gateway is intentionally stateful and single-owner.  Intake mappings and
owner browser sessions live in memory, so restarting the process signs browsers
out and invalidates undispatched portal links without persisting credentials.
"""

from __future__ import annotations

import hashlib
import html
import http.cookies
import json
import secrets
import threading
import time
from collections.abc import Callable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass, field
from http import HTTPStatus
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any
from urllib.parse import parse_qs, quote, unquote
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from .origin import normalize_portal_origin
from .protocol import ResultValidationError, normalize_writer_result
from .server import (
    MAX_BODY_BYTES,
    InvalidToken,
    SecretBoxApplication,
    SessionExpired,
    SessionStore,
    TokenUsed,
    UnknownSession,
)
from .templates import render_intake, render_intake_error

DEFAULT_AUTH_TTL_SECONDS = 12 * 60 * 60
DEFAULT_MAX_RETAINED_TERMINAL_INTAKES = 256
AUTH_COOKIE_NAME = "secretbox_owner"
_AUTH_TOKEN_BYTES = 32
_INTAKE_ID_BYTES = 18
_TERMINAL_STATES = frozenset({"applied", "failed", "cancelled", "expired"})
_PUBLIC_ERROR_CODES = frozenset({"apply_blocked", "apply_failed", "expired"})


class GatewayError(Exception):
    """Base error for gateway control-plane operations."""

    code = "gateway_error"


class UnknownIntake(GatewayError):
    """The opaque intake identifier is not registered by this gateway."""

    code = "unknown_intake"


class IntakeUnavailable(GatewayError):
    """The intake can no longer be opened in the portal."""

    code = "intake_unavailable"


@dataclass
class _GatewayIntake:
    intake_id: str
    session_id: str = field(repr=False)
    request_id: str
    request: Mapping[str, Any] = field(repr=False)
    created_at: float
    expires_at: float
    bootstrap_token: str | None = field(repr=False)
    csrf_token: str | None = field(default=None, repr=False)


@dataclass(frozen=True)
class _PortalBootstrap:
    intake_id: str
    session_id: str = field(repr=False)
    request: Mapping[str, Any] = field(repr=False)
    expires_at: float
    csrf_token: str = field(repr=False)
    session_cookie: str | None = field(default=None, repr=False)


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("utf-8", "strict")).digest()


def _normalize_public_origin(value: str) -> tuple[str, str, str]:
    try:
        return normalize_portal_origin(value, allow_loopback_http=True)
    except ValueError as exc:
        raise ValueError(str(exc).replace("origin", "public_origin")) from exc


class GatewayBroker:
    """Thread-safe agent control plane for a multi-session gateway.

    The public methods deliberately never return the internal session id, the
    one-time bootstrap token, or a request-specific URL.  ``portal_url`` is the
    same stable URL for every intake.
    """

    def __init__(
        self,
        public_origin: str,
        owner_access_key: str,
        *,
        store: SessionStore | None = None,
        auth_ttl: float = DEFAULT_AUTH_TTL_SECONDS,
        max_retained_terminal: int = DEFAULT_MAX_RETAINED_TERMINAL_INTAKES,
        clock: Callable[[], float] | None = None,
    ) -> None:
        origin, expected_host, scheme = _normalize_public_origin(public_origin)
        if not isinstance(owner_access_key, str) or len(owner_access_key.encode("utf-8")) < 16:
            raise ValueError("owner_access_key must contain at least 16 UTF-8 bytes")
        if auth_ttl <= 0:
            raise ValueError("auth_ttl must be positive")
        if (
            isinstance(max_retained_terminal, bool)
            or not isinstance(max_retained_terminal, int)
            or not 1 <= max_retained_terminal <= 4096
        ):
            raise ValueError("max_retained_terminal must be between 1 and 4096")
        self.public_origin = origin
        self.portal_url = origin + "/"
        self.expected_host = expected_host
        self.secure_cookies = scheme == "https"
        self.store = store or SessionStore()
        self.auth_ttl = float(auth_ttl)
        self.max_retained_terminal = max_retained_terminal
        self._clock = clock or time.time
        self._owner_access_digest = _digest(owner_access_key)
        self._lock = threading.RLock()
        self._intakes: dict[str, _GatewayIntake] = {}
        self._sessions: dict[str, str] = {}
        self._auth_sessions: dict[bytes, float] = {}
        self._closed = False

    def create(
        self,
        request: Mapping[str, Any] | str | Path,
        apply_fn: Callable[..., Any],
        ttl: float | None = None,
    ) -> dict[str, Any]:
        """Create one intake and return only Agent-safe discovery metadata."""

        if not callable(apply_fn):
            raise ValueError("apply_fn must be callable")
        with self._lock:
            if self._closed:
                raise GatewayError("gateway broker is closed")
            handle = self.store.create_session(request, apply_fn, ttl=ttl)
            request_id = str(handle.request.get("request_id", ""))
            intake_id = "int_" + secrets.token_urlsafe(_INTAKE_ID_BYTES)
            while intake_id in self._intakes:
                intake_id = "int_" + secrets.token_urlsafe(_INTAKE_ID_BYTES)
            record = _GatewayIntake(
                intake_id=intake_id,
                session_id=handle.session_id,
                request_id=request_id,
                request=dict(handle.request),
                created_at=self._clock(),
                expires_at=handle.expires_at,
                bootstrap_token=handle.token,
            )
            self._intakes[intake_id] = record
            self._sessions[handle.session_id] = intake_id
        self._trim_terminal()
        return {
            "intake_id": intake_id,
            "request_id": request_id,
            "status": "pending",
            "expires_at": handle.expires_at,
            "portal_url": self.portal_url,
        }

    def status(self, intake_id: str) -> dict[str, Any]:
        """Return redacted status metadata for an Agent-facing poll."""

        record = self._record(intake_id)
        raw = self.store.get(record.session_id)
        raw_status = str(raw.get("status", "failed"))
        self._clear_bootstrap_if_terminal(record, raw_status)
        public_status = raw_status
        normalized_result: dict[str, Any] | None = None
        invalid_result = False
        if raw_status in {"applied", "failed"} and "result" in raw:
            try:
                candidate = normalize_writer_result(raw["result"])
            except (ResultValidationError, TypeError, ValueError):
                invalid_result = True
            else:
                allowed = {"applied", "noop"} if raw_status == "applied" else {"partial", "blocked"}
                if (
                    candidate["status"] not in allowed
                    or candidate["request_id"] != record.request_id
                ):
                    invalid_result = True
                else:
                    normalized_result = candidate
        elif raw_status == "applied":
            invalid_result = True
        if invalid_result:
            public_status = "failed"

        result: dict[str, Any] = {
            "intake_id": record.intake_id,
            "request_id": record.request_id,
            "status": public_status,
            "expires_at": record.expires_at,
        }
        if normalized_result is not None:
            result["result"] = normalized_result
        error_code = raw.get("error_code")
        if invalid_result:
            result["error_code"] = "apply_failed"
        elif isinstance(error_code, str) and error_code in _PUBLIC_ERROR_CODES:
            result["error_code"] = error_code
        return result

    def close(self) -> None:
        """Invalidate portal authentication and remove every retained intake."""

        with self._lock:
            if self._closed:
                return
            self._closed = True
            records = tuple(self._intakes.values())
            self._intakes.clear()
            self._sessions.clear()
            self._auth_sessions.clear()
            for record in records:
                record.bootstrap_token = None
                record.csrf_token = None
        for record in records:
            try:
                state = str(self.store.cancel_pending(record.session_id).get("status", ""))
            except UnknownSession:
                continue
            if state in _TERMINAL_STATES:
                self.store.discard_terminal(record.session_id)
            else:
                self.store.discard_when_terminal(record.session_id)

    def cancel(self, intake_id: str) -> dict[str, Any]:
        """Cancel an intake if applying submitted values has not begun."""

        record = self._record(intake_id)
        self.store.cancel_pending(record.session_id)
        with self._lock:
            record.bootstrap_token = None
            record.csrf_token = None
        result = self.status(intake_id)
        self._trim_terminal(protect=intake_id)
        return result

    def discard_terminal(self, intake_id: str) -> bool:
        """Drop one terminal intake after its owner keeps a redacted snapshot."""

        record = self._record(intake_id)
        try:
            discarded = self.store.discard_terminal(record.session_id)
        except UnknownSession:
            discarded = False
        if not discarded:
            try:
                state = str(self.store.get(record.session_id).get("status", ""))
            except UnknownSession:
                state = "missing"
            if state in _TERMINAL_STATES:
                discarded = self.store.discard_terminal(record.session_id)
                if not discarded:
                    return False
            elif state != "missing":
                return False
        with self._lock:
            if self._intakes.get(intake_id) is record:
                self._intakes.pop(intake_id, None)
                self._sessions.pop(record.session_id, None)
                record.bootstrap_token = None
                record.csrf_token = None
        return True

    def _trim_terminal(self, *, protect: str | None = None) -> None:
        with self._lock:
            records = list(self._intakes.values())
        terminal: list[_GatewayIntake] = []
        for record in records:
            try:
                state = str(self.store.get(record.session_id).get("status", ""))
            except UnknownSession:
                state = "missing"
            if state in _TERMINAL_STATES or state == "missing":
                terminal.append(record)
        terminal.sort(key=lambda item: (item.created_at, item.intake_id))
        excess = len(terminal) - self.max_retained_terminal
        for record in terminal:
            if excess <= 0:
                break
            if record.intake_id == protect:
                continue
            try:
                if self.discard_terminal(record.intake_id):
                    excess -= 1
            except UnknownIntake:
                excess -= 1

    def _record(self, intake_id: str) -> _GatewayIntake:
        if not isinstance(intake_id, str) or len(intake_id) > 100:
            raise UnknownIntake()
        with self._lock:
            record = self._intakes.get(intake_id)
            if record is None:
                raise UnknownIntake()
            return record

    def _record_for_session(self, session_id: str) -> _GatewayIntake:
        with self._lock:
            intake_id = self._sessions.get(session_id)
            record = self._intakes.get(intake_id) if intake_id is not None else None
            if record is None:
                raise UnknownIntake()
            return record

    def _active_intakes(self) -> list[_GatewayIntake]:
        self._trim_terminal()
        active: list[_GatewayIntake] = []
        with self._lock:
            records = list(self._intakes.values())
        for record in records:
            try:
                status = self.status(record.intake_id)["status"]
            except (UnknownIntake, UnknownSession):
                continue
            if status == "pending":
                active.append(record)
        active.sort(key=lambda item: (item.expires_at, item.request_id, item.intake_id))
        return active

    def _begin_portal_intake(self, intake_id: str) -> _PortalBootstrap:
        """Consume a bootstrap token only after portal authentication."""

        record = self._record(intake_id)
        with self._lock:
            try:
                raw = self.store.get(record.session_id)
            except UnknownSession:
                raise IntakeUnavailable() from None
            state = str(raw.get("status", ""))
            session_cookie: str | None = None
            if state == "pending":
                token = record.bootstrap_token
                if token is None:
                    raise IntakeUnavailable()
                try:
                    exchanged = self.store.exchange(record.session_id, token)
                except (InvalidToken, SessionExpired, TokenUsed, UnknownSession):
                    record.bootstrap_token = None
                    record.csrf_token = None
                    raise IntakeUnavailable() from None
                record.bootstrap_token = None
                record.csrf_token = exchanged.csrf_token
                session_cookie = exchanged.session_cookie
            else:
                self._clear_bootstrap_if_terminal(record, state)
                raise IntakeUnavailable()
            return _PortalBootstrap(
                intake_id=record.intake_id,
                session_id=record.session_id,
                request=dict(record.request),
                expires_at=record.expires_at,
                csrf_token=record.csrf_token,
                session_cookie=session_cookie,
            )

    def _clear_bootstrap_if_terminal(self, record: _GatewayIntake, state: str) -> None:
        if state in _TERMINAL_STATES:
            with self._lock:
                record.bootstrap_token = None
                record.csrf_token = None

    def _verify_owner_key(self, candidate: str) -> bool:
        with self._lock:
            if self._closed:
                return False
        try:
            candidate_digest = _digest(candidate)
        except (UnicodeEncodeError, ValueError):
            return False
        return secrets.compare_digest(self._owner_access_digest, candidate_digest)

    def _new_auth_session(self) -> tuple[str, float]:
        now = self._clock()
        token = secrets.token_urlsafe(_AUTH_TOKEN_BYTES)
        digest = _digest(token)
        expires_at = now + self.auth_ttl
        with self._lock:
            if self._closed:
                raise GatewayError("gateway broker is closed")
            self._purge_auth_locked(now)
            while digest in self._auth_sessions:
                token = secrets.token_urlsafe(_AUTH_TOKEN_BYTES)
                digest = _digest(token)
            self._auth_sessions[digest] = expires_at
        return token, expires_at

    def _authenticate(self, token: str | None) -> bool:
        if not token or len(token) > 256:
            return False
        try:
            digest = _digest(token)
        except (UnicodeEncodeError, ValueError):
            return False
        with self._lock:
            if self._closed:
                return False
            now = self._clock()
            self._purge_auth_locked(now)
            expires_at = self._auth_sessions.get(digest)
            return expires_at is not None and expires_at > now

    def _logout(self, token: str | None) -> None:
        if not token or len(token) > 256:
            return
        try:
            digest = _digest(token)
        except (UnicodeEncodeError, ValueError):
            return
        with self._lock:
            self._auth_sessions.pop(digest, None)

    def _purge_auth_locked(self, now: float) -> None:
        for digest, expires_at in list(self._auth_sessions.items()):
            if expires_at <= now:
                self._auth_sessions.pop(digest, None)


class GatewayApplication:
    """WSGI portal that authenticates an owner before exposing intake forms."""

    def __init__(self, broker: GatewayBroker) -> None:
        self.broker = broker
        self._secretbox = SecretBoxApplication(broker.store)

    def __call__(
        self, environ: MutableMapping[str, Any], start_response: Callable[..., Any]
    ) -> list[bytes]:
        method = str(environ.get("REQUEST_METHOD", "GET")).upper()
        path = unquote(str(environ.get("PATH_INFO", "/")))
        host = str(environ.get("HTTP_HOST", "")).strip().lower()
        if host != self.broker.expected_host:
            return self._error(
                start_response, HTTPStatus.BAD_REQUEST, "invalid_host", "Host is not allowed"
            )
        if method in {"POST", "PUT", "PATCH", "DELETE"}:
            origin = str(environ.get("HTTP_ORIGIN", ""))
            if origin != self.broker.public_origin:
                return self._error(
                    start_response,
                    HTTPStatus.FORBIDDEN,
                    "invalid_origin",
                    "Origin is not allowed",
                )

        owner_token = self._cookie_value(environ, AUTH_COOKIE_NAME)
        authenticated = self.broker._authenticate(owner_token)
        try:
            if method == "GET" and path == "/healthz":
                return self._json(start_response, HTTPStatus.OK, {"ok": True})
            if method == "GET" and path == "/login":
                if authenticated:
                    return self._redirect(start_response, "/")
                return self._login_page(start_response)
            if method == "POST" and path == "/login":
                access_key = self._parse_access_key(environ)
                if not self.broker._verify_owner_key(access_key):
                    return self._login_page(start_response, invalid=True)
                try:
                    token, expires_at = self.broker._new_auth_session()
                except GatewayError:
                    return self._error(
                        start_response,
                        HTTPStatus.SERVICE_UNAVAILABLE,
                        "gateway_closed",
                        "SecretBox is shutting down",
                    )
                return self._redirect(
                    start_response,
                    "/",
                    (("Set-Cookie", self._auth_cookie(token, expires_at)),),
                )
            if not authenticated:
                if path.startswith("/api/"):
                    return self._error(
                        start_response,
                        HTTPStatus.UNAUTHORIZED,
                        "authentication_required",
                        "Owner authentication is required",
                    )
                return self._redirect(start_response, "/login")
            if method == "POST" and path == "/logout":
                self.broker._logout(owner_token)
                return self._redirect(
                    start_response,
                    "/login",
                    (("Set-Cookie", self._expired_auth_cookie()),),
                )
            if method == "GET" and path == "/":
                return self._portal_page(start_response)
            if method == "POST" and path.startswith("/requests/") and path.endswith("/open"):
                intake_id = path[len("/requests/") : -len("/open")]
                if not intake_id or "/" in intake_id:
                    raise UnknownIntake()
                return self._intake_page(start_response, intake_id)
            if path.startswith("/api/sessions/"):
                session_id = self._api_session_id(path)
                self.broker._record_for_session(session_id)
                response = self._delegate_secretbox(environ, start_response)
                try:
                    record = self.broker._record_for_session(session_id)
                    state = str(self.broker.store.get(session_id).get("status", ""))
                    self.broker._clear_bootstrap_if_terminal(record, state)
                except (UnknownIntake, UnknownSession):
                    pass
                return response
            return self._error(start_response, HTTPStatus.NOT_FOUND, "not_found", "Not found")
        except UnknownIntake:
            return self._error(
                start_response, HTTPStatus.NOT_FOUND, "not_found", "Intake not found"
            )
        except IntakeUnavailable:
            return self._unavailable_page(start_response)
        except TimeoutError:
            return self._error(
                start_response,
                HTTPStatus.REQUEST_TIMEOUT,
                "request_timeout",
                "Request body timed out",
            )
        except OverflowError:
            return self._error(
                start_response,
                HTTPStatus.REQUEST_ENTITY_TOO_LARGE,
                "body_too_large",
                "Request body is too large",
            )
        except ValueError:
            return self._error(
                start_response, HTTPStatus.BAD_REQUEST, "bad_request", "Invalid request"
            )

    def _portal_page(self, start_response: Callable[..., Any]) -> list[bytes]:
        nonce = secrets.token_urlsafe(18)
        rows: list[str] = []
        for record in self.broker._active_intakes():
            title = html.escape(str(record.request.get("title", "Secret request")), quote=True)
            request_id = html.escape(record.request_id, quote=True)
            intake_path = "/requests/" + quote(record.intake_id, safe="") + "/open"
            state = html.escape(self.broker.status(record.intake_id)["status"], quote=True)
            rows.append(
                f'<li><form method="post" action="{intake_path}">'
                f'<button class="request" type="submit">{title}</button></form>'
                f'<span>Request <code>{request_id}</code> - {state}</span></li>'
            )
        items = "".join(rows) or "<li class=\"empty\">No pending secret requests.</li>"
        body = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>SecretBox requests</title><style nonce="{nonce}">{self._styles()}</style></head>
<body><main><div class="heading"><div><h1>SecretBox requests</h1>
<p>Choose a pending request to enter credentials or upload files.</p></div>
<form method="post" action="/logout"><button class="secondary" type="submit">Sign out</button>
</form></div><ul>{items}</ul></main></body></html>"""
        return self._html(start_response, HTTPStatus.OK, body, nonce)

    def _login_page(
        self, start_response: Callable[..., Any], *, invalid: bool = False
    ) -> list[bytes]:
        nonce = secrets.token_urlsafe(18)
        error = (
            '<p class="error" role="alert">The access key is not valid.</p>' if invalid else ""
        )
        body = f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Sign in to SecretBox</title><style nonce="{nonce}">{self._styles()}</style></head>
<body><main class="login"><h1>SecretBox</h1>
<p>Sign in to review pending requests. Opening this page does not consume a request.</p>
{error}<form method="post" action="/login"><label>Owner access key
<input type="password" name="access_key" autocomplete="current-password" required autofocus>
</label><button type="submit">Sign in</button></form></main></body></html>"""
        status = HTTPStatus.UNAUTHORIZED if invalid else HTTPStatus.OK
        return self._html(start_response, status, body, nonce)

    def _intake_page(
        self, start_response: Callable[..., Any], intake_id: str
    ) -> list[bytes]:
        bootstrap = self.broker._begin_portal_intake(intake_id)
        nonce = secrets.token_urlsafe(18)
        body = render_intake(bootstrap.request, nonce, bootstrap.session_id)
        session_data = json.dumps(
            {
                "session_id": bootstrap.session_id,
                "csrf_token": bootstrap.csrf_token,
                "expires_at": bootstrap.expires_at,
            },
            ensure_ascii=True,
            separators=(",", ":"),
        )
        storage_key = json.dumps(
            "secretbox-session:" + bootstrap.session_id,
            ensure_ascii=True,
        )
        injected = (
            f'  <script nonce="{nonce}">try {{ sessionStorage.setItem({storage_key}, '
            f"JSON.stringify({session_data})); }} catch (_) {{}}</script>\n"
        )
        marker = f'  <script nonce="{nonce}">'
        if marker not in body:
            raise RuntimeError("intake template bootstrap marker is missing")
        body = body.replace(marker, injected + marker, 1)
        extra: list[tuple[str, str]] = []
        if bootstrap.session_cookie is not None:
            extra.append(
                (
                    "Set-Cookie",
                    self._intake_cookie(
                        bootstrap.session_id,
                        bootstrap.session_cookie,
                        bootstrap.expires_at,
                    ),
                )
            )
        return self._html(start_response, HTTPStatus.OK, body, nonce, extra)

    def _unavailable_page(self, start_response: Callable[..., Any]) -> list[bytes]:
        nonce = secrets.token_urlsafe(18)
        body = render_intake_error(
            title="SecretBox request unavailable",
            heading="This request can no longer be opened",
            message=(
                "It may have been submitted, cancelled, or expired. Return to the portal "
                "to choose another pending request."
            ),
            status_code=HTTPStatus.GONE,
            nonce=nonce,
        )
        return self._html(start_response, HTTPStatus.GONE, body, nonce)

    def _delegate_secretbox(
        self, environ: MutableMapping[str, Any], start_response: Callable[..., Any]
    ) -> list[bytes]:
        delegated = dict(environ)
        delegated["HTTP_HOST"] = "127.0.0.1"
        delegated["SERVER_NAME"] = "127.0.0.1"
        delegated["SERVER_PORT"] = "80"
        delegated["wsgi.url_scheme"] = "http"
        if str(delegated.get("REQUEST_METHOD", "GET")).upper() in {
            "POST",
            "PUT",
            "PATCH",
            "DELETE",
        }:
            delegated["HTTP_ORIGIN"] = "http://127.0.0.1"

        def delegated_start(
            status: str,
            headers: list[tuple[str, str]],
            exc_info: Any = None,
        ) -> None:
            rewritten: list[tuple[str, str]] = []
            for key, value in headers:
                if (
                    key.lower() == "set-cookie"
                    and self.broker.secure_cookies
                    and "secure" not in value.lower()
                ):
                    value += "; Secure"
                rewritten.append((key, value))
            start_response(status, rewritten, exc_info)

        return self._secretbox(delegated, delegated_start)

    @staticmethod
    def _api_session_id(path: str) -> str:
        remainder = path[len("/api/sessions/") :]
        session_id = remainder.split("/", 1)[0]
        if not session_id or len(session_id) > 100:
            raise UnknownIntake()
        return session_id

    @staticmethod
    def _cookie_value(environ: Mapping[str, Any], name: str) -> str | None:
        cookies = http.cookies.SimpleCookie()
        try:
            cookies.load(str(environ.get("HTTP_COOKIE", "")))
        except http.cookies.CookieError:
            return None
        morsel = cookies.get(name)
        return morsel.value if morsel is not None else None

    @staticmethod
    def _parse_access_key(environ: Mapping[str, Any]) -> str:
        raw_length = environ.get("CONTENT_LENGTH", "")
        try:
            length = int(raw_length)
        except (TypeError, ValueError):
            raise ValueError("content_length") from None
        if length < 0 or length > min(MAX_BODY_BYTES, 64 * 1024):
            raise OverflowError("body_too_large")
        stream = environ.get("wsgi.input")
        if stream is None:
            raise ValueError("body")
        body = stream.read(length)
        if not isinstance(body, bytes) or len(body) != length:
            raise ValueError("body")
        content_type = str(environ.get("CONTENT_TYPE", "")).split(";", 1)[0].lower()
        try:
            if content_type == "application/json":
                parsed = json.loads(body.decode("utf-8"))
                value = parsed.get("access_key") if isinstance(parsed, Mapping) else None
            elif content_type == "application/x-www-form-urlencoded":
                parsed_form = parse_qs(
                    body.decode("utf-8"), keep_blank_values=True, max_num_fields=4
                )
                values = parsed_form.get("access_key", [])
                value = values[0] if len(values) == 1 else None
            else:
                raise ValueError("content_type")
        except (UnicodeDecodeError, json.JSONDecodeError, ValueError):
            raise ValueError("body") from None
        if not isinstance(value, str) or len(value.encode("utf-8")) > 4096:
            raise ValueError("access_key")
        return value

    def _auth_cookie(self, value: str, expires_at: float) -> str:
        max_age = max(1, int(expires_at - self.broker._clock()))
        cookie = (
            f"{AUTH_COOKIE_NAME}={value}; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}"
        )
        if self.broker.secure_cookies:
            cookie += "; Secure"
        return cookie

    def _expired_auth_cookie(self) -> str:
        cookie = (
            f"{AUTH_COOKIE_NAME}=; Path=/; HttpOnly; SameSite=Strict; Max-Age=0"
        )
        if self.broker.secure_cookies:
            cookie += "; Secure"
        return cookie

    def _intake_cookie(
        self, session_id: str, value: str, expires_at: float
    ) -> str:
        max_age = max(1, int(expires_at - self.broker._clock()))
        cookie = (
            f"secretbox_session_{session_id}={value}; "
            f"Path=/api/sessions/{session_id}/; HttpOnly; SameSite=Strict; Max-Age={max_age}"
        )
        if self.broker.secure_cookies:
            cookie += "; Secure"
        return cookie

    @staticmethod
    def _styles() -> str:
        return """
:root { color-scheme: light; font-family: Inter, Segoe UI, system-ui, sans-serif;
  --ink:#18201c; --muted:#5d665f; --line:#d8ded9; --canvas:#f2f5f2;
  --surface:#fff; --primary:#197447; --danger:#a12622; }
* { box-sizing:border-box; } body { margin:0; min-height:100vh; padding:2rem 1rem;
  background:var(--canvas); color:var(--ink); }
main { max-width:48rem; margin:0 auto; padding:1.75rem; background:var(--surface);
  border:1px solid var(--line); border-radius:8px; }
main.login { max-width:30rem; } h1 { margin:0; font-size:1.55rem; } p { color:var(--muted); }
.heading { display:flex; justify-content:space-between; gap:1rem; align-items:start; }
ul { list-style:none; padding:0; margin:1.5rem 0 0; border-top:1px solid var(--line); }
li { padding:1rem 0; border-bottom:1px solid var(--line); display:grid; gap:.25rem; }
li span { color:var(--muted); font-size:.9rem; }
label { display:block; margin:1.25rem 0; font-weight:650; }
input { display:block; width:100%; margin-top:.4rem; padding:.75rem; border:1px solid #aeb6af;
  border-radius:6px; font:inherit; }
button { min-height:2.5rem; padding:.7rem 1rem; border:0; border-radius:6px;
  background:var(--primary); color:#fff; font:inherit; font-weight:700; cursor:pointer; }
button.secondary { background:#fff; color:var(--ink); border:1px solid #aeb6af; }
button.request { min-height:0; padding:0; background:transparent; color:var(--primary);
  text-align:left; }
.error { color:var(--danger); font-weight:650; } .empty { color:var(--muted); }
@media (max-width:36rem) { body { padding:0; } main { min-height:100vh; border:0;
  border-radius:0; padding:1.25rem; } .heading { align-items:stretch; flex-direction:column; } }
"""

    def _security_headers(
        self, content_type: str, *, nonce: str | None = None
    ) -> list[tuple[str, str]]:
        csp = (
            "default-src 'none'; connect-src 'self'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'"
        )
        if nonce is not None:
            csp += f"; style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'"
        headers = [
            ("Content-Type", content_type),
            ("Cache-Control", "no-store, max-age=0"),
            ("Pragma", "no-cache"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
            ("Content-Security-Policy", csp),
            ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
        ]
        if self.broker.secure_cookies:
            headers.append(("Strict-Transport-Security", "max-age=31536000"))
        return headers

    def _json(
        self,
        start_response: Callable[..., Any],
        status: HTTPStatus,
        payload: Mapping[str, Any],
    ) -> list[bytes]:
        body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        headers = self._security_headers("application/json; charset=utf-8")
        headers.append(("Content-Length", str(len(body))))
        start_response(f"{status.value} {status.phrase}", headers)
        return [body]

    def _html(
        self,
        start_response: Callable[..., Any],
        status: HTTPStatus,
        body_text: str,
        nonce: str,
        extra: Sequence[tuple[str, str]] = (),
    ) -> list[bytes]:
        body = body_text.encode("utf-8")
        headers = self._security_headers("text/html; charset=utf-8", nonce=nonce)
        headers.extend(extra)
        headers.append(("Content-Length", str(len(body))))
        start_response(f"{status.value} {status.phrase}", headers)
        return [body]

    def _redirect(
        self,
        start_response: Callable[..., Any],
        location: str,
        extra: Sequence[tuple[str, str]] = (),
    ) -> list[bytes]:
        headers = self._security_headers("text/plain; charset=utf-8")
        headers.extend(extra)
        headers.extend((("Location", location), ("Content-Length", "0")))
        start_response(f"{HTTPStatus.SEE_OTHER.value} {HTTPStatus.SEE_OTHER.phrase}", headers)
        return [b""]

    def _error(
        self,
        start_response: Callable[..., Any],
        status: HTTPStatus,
        code: str,
        message: str,
    ) -> list[bytes]:
        return self._json(start_response, status, {"error": {"code": code, "message": message}})


class _QuietRequestHandler(WSGIRequestHandler):
    def log_message(self, _format: str, *args: Any) -> None:
        return


class _ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    daemon_threads = True
    allow_reuse_address = True


class GatewayRuntime:
    """A fixed-port, long-running WSGI runtime that serves every intake."""

    def __init__(
        self,
        broker: GatewayBroker,
        *,
        host: str = "127.0.0.1",
        port: int = 17321,
    ) -> None:
        if host != "127.0.0.1":
            raise ValueError("Gateway runtime only binds to 127.0.0.1")
        if not isinstance(port, int) or isinstance(port, bool) or not 0 <= port <= 65535:
            raise ValueError("port must be between 0 and 65535")
        self.broker = broker
        self.app = GatewayApplication(broker)
        self.server = make_server(
            host,
            port,
            self.app,
            server_class=_ThreadingWSGIServer,
            handler_class=_QuietRequestHandler,
        )
        self.host = str(self.server.server_address[0])
        self.port = int(self.server.server_port)
        self._thread: threading.Thread | None = None

    def serve_forever(self) -> None:
        self.server.serve_forever()

    def start(self) -> GatewayRuntime:
        if self._thread is not None and self._thread.is_alive():
            return self
        self._thread = threading.Thread(
            target=self.serve_forever,
            name="secretbox-gateway",
            daemon=True,
        )
        self._thread.start()
        return self

    def close(self) -> None:
        thread = self._thread
        if thread is not None and thread.is_alive():
            self.server.shutdown()
            thread.join(timeout=5)
        self.server.server_close()

    def __enter__(self) -> GatewayRuntime:
        return self.start()

    def __exit__(self, _exc_type: Any, _exc: Any, _traceback: Any) -> None:
        self.close()


def create_gateway_app(broker: GatewayBroker) -> GatewayApplication:
    """Return the WSGI application for framework and reverse-proxy adapters."""

    return GatewayApplication(broker)
