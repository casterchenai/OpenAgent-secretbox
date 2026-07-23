"""Local-only intake server and one-time session registry.

This module intentionally uses only the Python standard library.  It is a small
control plane, not a general purpose HTTP server: it binds to 127.0.0.1, accepts
short JSON requests, and keeps secret values in memory only long enough to invoke
the configured apply callback.
"""

from __future__ import annotations

import copy
import hashlib
import http.cookies
import inspect
import json
import secrets
import socket
import threading
import time
from collections.abc import Callable, Mapping, MutableMapping, Sequence
from dataclasses import dataclass, field
from http import HTTPStatus
from pathlib import Path
from socketserver import ThreadingMixIn
from typing import Any
from urllib.parse import unquote
from wsgiref.simple_server import WSGIRequestHandler, WSGIServer, make_server

from .schema import (
    load_request as _schema_load_request,
)
from .schema import (
    validate_request as _schema_validate_request,
)
from .templates import render_intake, render_intake_error

MAX_BODY_BYTES = 16 * 1024 * 1024
DEFAULT_TTL_SECONDS = 600
TOKEN_BYTES = 32
CSRF_BYTES = 32
COOKIE_BYTES = 24
REQUEST_READ_TIMEOUT_SECONDS = 1.0
_RESULT_STATUSES = frozenset({"applied", "noop", "blocked", "partial", "failed"})


class SessionError(Exception):
    """Base error for a rejected or expired intake session."""

    code = "session_error"


class InvalidToken(SessionError):
    code = "invalid_token"


class TokenUsed(SessionError):
    code = "token_used"


class SessionExpired(SessionError):
    code = "expired"


class UnknownSession(SessionError):
    code = "unknown_session"


class InvalidState(SessionError):
    code = "invalid_state"


class ApplyFailed(SessionError):
    code = "apply_failed"


@dataclass(frozen=True)
class SessionHandle:
    """Values returned to the caller that creates a request.

    ``token`` is intentionally returned only to the creator.  ``SessionStore``
    retains its SHA-256 digest, never this plaintext token.
    """

    session_id: str
    token: str = field(repr=False)
    path: str = field(repr=False)
    expires_at: float
    request: Mapping[str, Any] = field(repr=False)

    @property
    def url_path(self) -> str:
        return self.path

    def __getitem__(self, key: str) -> Any:
        return getattr(self, key)


@dataclass
class _Session:
    session_id: str
    request: Mapping[str, Any]
    token_digest: bytes
    created_at: float
    expires_at: float
    apply_fn: Callable[..., Any] | None
    state: str = "pending"
    csrf_digest: bytes | None = None
    cookie_digest: bytes | None = None
    result: Mapping[str, Any] | None = None
    error_code: str | None = None
    exchanged_at: float | None = None
    completed_at: float | None = None


@dataclass(frozen=True)
class ExchangeResult:
    session_id: str
    csrf_token: str = field(repr=False)
    session_cookie: str = field(repr=False)
    request: Mapping[str, Any]
    expires_at: float

    def as_dict(self) -> dict[str, Any]:
        return {
            "session_id": self.session_id,
            "csrf_token": self.csrf_token,
            "expires_at": self.expires_at,
            "request": _safe_request(self.request),
        }


def _digest(value: str) -> bytes:
    return hashlib.sha256(value.encode("ascii", "strict")).digest()


def _new_token(size: int) -> str:
    return secrets.token_urlsafe(size)


def _safe_request(request: Mapping[str, Any]) -> dict[str, Any]:
    """Return request metadata; never expose defaults or value-like fields."""

    needs = request.get("needs", [])
    safe_needs: list[dict[str, Any]] = []
    if isinstance(needs, Sequence) and not isinstance(needs, (str, bytes, bytearray)):
        for item in needs:
            if not isinstance(item, Mapping):
                continue
            safe_need: dict[str, Any] = {}
            for key in ("type", "name", "required", "description", "target"):
                if key in item:
                    value = item[key]
                    if isinstance(value, (str, bool, int, float)) or value is None:
                        safe_need[key] = value
            safe_needs.append(safe_need)
    safe: dict[str, Any] = {
        "request_id": str(request.get("request_id", "")),
        "title": str(request.get("title", "Secret request")),
        "needs": safe_needs,
    }
    if isinstance(request.get("workspace_root"), str):
        safe["workspace_root"] = request["workspace_root"]
    # A relative target policy is useful to the user; absolute workspace paths are
    # intentionally omitted from the browser response.
    if isinstance(request.get("write_policy"), Mapping):
        policy: dict[str, Any] = {}
        for key in ("env_file", "mode", "no_overwrite", "backup"):
            value = request["write_policy"].get(key)
            if isinstance(value, (str, bool, int, float)) or value is None:
                policy[key] = value
        safe["write_policy"] = policy
    return safe


def _redact_result(value: Any, *, key: str = "", secret_literals: tuple[str, ...] = ()) -> Any:
    """Keep operation metadata while dropping fields likely to contain secrets."""

    secret_words = (
        "secret",
        "value",
        "token",
        "password",
        "passwd",
        "content",
        "private_key",
        "credential",
        "api_key",
        "apikey",
        "authorization",
        "cookie",
    )
    lowered = key.lower()
    if any(word in lowered for word in secret_words):
        return "[redacted]"
    if isinstance(value, Mapping):
        safe_mapping: dict[str, Any] = {}
        for raw_key, item in value.items():
            if isinstance(raw_key, str):
                safe_key = raw_key
                for literal in secret_literals:
                    if literal:
                        safe_key = safe_key.replace(literal, "[redacted]")
            else:
                safe_key = "[redacted-key]"
            safe_mapping[safe_key] = _redact_result(
                item, key=safe_key, secret_literals=secret_literals
            )
        return safe_mapping
    if isinstance(value, list):
        return [_redact_result(item, key=key, secret_literals=secret_literals) for item in value]
    if isinstance(value, tuple):
        return [_redact_result(item, key=key, secret_literals=secret_literals) for item in value]
    if isinstance(value, str):
        scrubbed = value
        for literal in secret_literals:
            if literal:
                scrubbed = scrubbed.replace(literal, "[redacted]")
        return scrubbed
    if isinstance(value, (int, float, bool)) or value is None:
        return value
    # Callback results are an untrusted extension point.  Never invoke an
    # arbitrary object formatter or expose byte content in the status channel.
    return "[redacted]"


def _collect_secret_literals(value: Any) -> tuple[str, ...]:
    found: set[str] = set()

    def visit(item: Any) -> None:
        if isinstance(item, str):
            if item:
                found.add(item)
            return
        if isinstance(item, bytes):
            try:
                text = item.decode("utf-8")
            except UnicodeDecodeError:
                return
            if text:
                found.add(text)
            return
        if isinstance(item, Mapping):
            for child in item.values():
                visit(child)
            return
        if isinstance(item, Sequence) and not isinstance(item, (str, bytes, bytearray)):
            for child in item:
                visit(child)

    visit(value)
    # Replacing longer values first prevents a short value from hiding part of a
    # longer credential and leaving the rest visible.
    return tuple(sorted(found, key=len, reverse=True))


class SessionStore:
    """Thread-safe in-memory registry for one-time intake sessions."""

    def __init__(
        self,
        ttl: float = DEFAULT_TTL_SECONDS,
        *,
        clock: Callable[[], float] | None = None,
        token_bytes: int = TOKEN_BYTES,
    ) -> None:
        if ttl <= 0:
            raise ValueError("ttl must be positive")
        if token_bytes < 16:
            raise ValueError("token_bytes must be at least 16")
        self.ttl = float(ttl)
        self._clock = clock or time.time
        self._token_bytes = token_bytes
        self._lock = threading.RLock()
        self._sessions: dict[str, _Session] = {}
        self._token_index: dict[bytes, str] = {}

    def create_session(
        self,
        request: Mapping[str, Any] | str | Path,
        apply_fn: Callable[..., Any] | None = None,
        *,
        ttl: float | None = None,
    ) -> SessionHandle:
        loaded = _load_request(request)
        if not isinstance(loaded, Mapping):
            raise ValueError("request must be a mapping")
        lifetime = self.ttl if ttl is None else float(ttl)
        if lifetime <= 0:
            raise ValueError("ttl must be positive")
        now = self._clock()
        token = _new_token(self._token_bytes)
        sid = "ses_" + _new_token(18)
        token_digest = _digest(token)
        session = _Session(
            session_id=sid,
            request=copy.deepcopy(dict(loaded)),
            token_digest=token_digest,
            created_at=now,
            expires_at=now + lifetime,
            apply_fn=apply_fn,
        )
        with self._lock:
            self._purge_locked(now)
            # The probability of a duplicate is negligible, but checking the index
            # makes the invariant explicit and keeps tests deterministic if secrets
            # is monkeypatched.
            while token_digest in self._token_index or sid in self._sessions:
                token = _new_token(self._token_bytes)
                sid = "ses_" + _new_token(18)
                token_digest = _digest(token)
                session.token_digest = token_digest
                session.session_id = sid
            self._sessions[sid] = session
            self._token_index[token_digest] = sid
        return SessionHandle(
            session_id=sid,
            token=token,
            # Fragments are not included in the HTTP request line. The page
            # clears this fragment before exchanging the one-time token.
            path=f"/intake/{sid}#token={token}",
            expires_at=session.expires_at,
            request=copy.deepcopy(session.request),
        )

    # Friendly aliases used by early integrations.
    create = create_session
    issue = create_session

    def _purge_locked(self, now: float) -> None:
        for session in self._sessions.values():
            # TTL bounds how long the user may start an intake. Once apply has
            # started, its synchronous result owns the only legal next state.
            if session.expires_at <= now and session.state in {"pending", "exchanged"}:
                session.state = "expired"
                session.error_code = "expired"
                session.completed_at = now
        # Keep terminal metadata briefly available for status polling.  The token
        # index is always removed as soon as a session expires or is consumed.
        for digest, sid in list(self._token_index.items()):
            indexed_session = self._sessions.get(sid)
            if indexed_session is None or indexed_session.state != "pending":
                self._token_index.pop(digest, None)

    def exchange(self, session_id: str, token: str) -> ExchangeResult:
        if not isinstance(session_id, str) or not session_id or len(session_id) > 100:
            raise InvalidToken()
        if not isinstance(token, str) or not token or len(token) > 256:
            raise InvalidToken()
        try:
            digest = _digest(token)
        except (UnicodeEncodeError, ValueError):
            raise InvalidToken() from None
        with self._lock:
            now = self._clock()
            self._purge_locked(now)
            sid = self._token_index.get(digest)
            if sid is None or not secrets.compare_digest(sid, session_id):
                # Do not distinguish an invalid token from a previously consumed one
                # at the HTTP boundary.
                raise InvalidToken()
            session = self._sessions.get(sid)
            if session is None:
                raise InvalidToken()
            if session.expires_at <= now:
                session.state = "expired"
                session.error_code = "expired"
                self._token_index.pop(digest, None)
                raise SessionExpired()
            if session.state != "pending":
                self._token_index.pop(digest, None)
                raise TokenUsed()
            csrf = _new_token(CSRF_BYTES)
            cookie = _new_token(COOKIE_BYTES)
            session.state = "exchanged"
            session.exchanged_at = now
            session.csrf_digest = _digest(csrf)
            session.cookie_digest = _digest(cookie)
            self._token_index.pop(digest, None)
            return ExchangeResult(
                sid, csrf, cookie, copy.deepcopy(session.request), session.expires_at
            )

    def preview(self, token: str) -> Mapping[str, Any]:
        """Validate a bootstrap token without consuming it and return UI metadata."""

        if not isinstance(token, str) or not token or len(token) > 256:
            raise InvalidToken()
        try:
            digest = _digest(token)
        except (UnicodeEncodeError, ValueError):
            raise InvalidToken() from None
        with self._lock:
            now = self._clock()
            self._purge_locked(now)
            sid = self._token_index.get(digest)
            session = self._sessions.get(sid) if sid is not None else None
            if session is None or session.state != "pending":
                raise InvalidToken()
            if session.expires_at <= now:
                raise SessionExpired()
            return copy.deepcopy(session.request)

    def preview_session(self, session_id: str) -> Mapping[str, Any]:
        """Return display-only metadata without putting a bearer token in the path."""

        if not isinstance(session_id, str) or not session_id or len(session_id) > 100:
            raise UnknownSession()
        with self._lock:
            now = self._clock()
            self._purge_locked(now)
            session = self._sessions.get(session_id)
            if session is None or session.state != "pending":
                raise UnknownSession()
            if session.expires_at <= now:
                raise SessionExpired()
            return copy.deepcopy(session.request)

    def get(self, session_id: str) -> dict[str, Any]:
        with self._lock:
            now = self._clock()
            self._purge_locked(now)
            session = self._sessions.get(session_id)
            if session is None:
                raise UnknownSession()
            return self._status_locked(session)

    status = get

    def authorize(
        self, session_id: str, csrf_token: str | None, session_cookie: str | None = None
    ) -> _Session:
        if not isinstance(csrf_token, str) or not csrf_token or len(csrf_token) > 256:
            raise InvalidState()
        with self._lock:
            now = self._clock()
            self._purge_locked(now)
            session = self._sessions.get(session_id)
            if session is None:
                raise UnknownSession()
            if session.state == "expired":
                raise SessionExpired()
            if session.state not in {"exchanged", "submitted"}:
                raise InvalidState()
            if session.state == "exchanged" and session.expires_at <= now:
                session.state = "expired"
                session.error_code = "expired"
                session.completed_at = now
                raise SessionExpired()
            try:
                csrf_digest = _digest(csrf_token)
                cookie_digest = _digest(session_cookie) if session_cookie else None
            except (UnicodeEncodeError, ValueError):
                raise InvalidState() from None
            if session.csrf_digest is None or not secrets.compare_digest(
                session.csrf_digest, csrf_digest
            ):
                raise InvalidState()
            if (
                cookie_digest is None
                or session.cookie_digest is None
                or not secrets.compare_digest(session.cookie_digest, cookie_digest)
            ):
                raise InvalidState()
            return session

    def submit(
        self,
        session_id: str,
        values: Mapping[str, Any],
        csrf_token: str,
        *,
        session_cookie: str | None = None,
    ) -> dict[str, Any]:
        if not isinstance(values, Mapping):
            raise ValueError("values must be an object")
        session = self.authorize(session_id, csrf_token, session_cookie)
        with self._lock:
            if session.state != "exchanged":
                raise InvalidState()
            apply_fn = session.apply_fn
            request = copy.deepcopy(session.request)
            if apply_fn is not None:
                session.state = "submitted"
        if apply_fn is None:
            raise RuntimeError(
                "no apply callback configured; configure core apply before submitting secrets"
            )
        # Do not retain the values after this call.  The callback must perform the
        # transactional write synchronously and return only redacted metadata.
        try:
            result = _invoke_apply(apply_fn, request, values)
            raw_status = result.get("status") if isinstance(result, Mapping) else None
            reported_status = (
                raw_status
                if isinstance(raw_status, str) and raw_status in _RESULT_STATUSES
                else "failed"
            )
            redaction_source = (
                {key: item for key, item in result.items() if key != "status"}
                if isinstance(result, Mapping)
                else result
            )
            redacted_details = _redact_result(
                redaction_source,
                secret_literals=_collect_secret_literals(values),
            )
            redacted = (
                {"status": reported_status, **redacted_details}
                if isinstance(redacted_details, Mapping)
                else {"status": reported_status, "details": redacted_details}
            )
        except Exception as exc:
            with self._lock:
                session.state = "failed"
                session.error_code = "apply_failed"
                session.completed_at = self._clock()
            raise ApplyFailed() from exc
        finally:
            # Best effort release of this local reference; callers should also drop
            # their request body as soon as possible.
            values = {}
        with self._lock:
            session.result = redacted
            if reported_status in {"applied", "noop"}:
                session.state = "applied"
            else:
                session.state = "failed"
                session.error_code = "apply_blocked"
            session.completed_at = self._clock()
            return self._status_locked(session)

    def cancel_pending(self, session_id: str) -> dict[str, Any]:
        """Atomically cancel an intake only if secret application has not started.

        This owner-level operation is used by trusted local control planes that
        do not possess the browser's CSRF credentials. It deliberately leaves a
        ``submitted`` session untouched so its write result remains authoritative.
        """

        with self._lock:
            now = self._clock()
            self._purge_locked(now)
            session = self._sessions.get(session_id)
            if session is None:
                raise UnknownSession()
            if session.state in {"pending", "exchanged"}:
                session.state = "cancelled"
                session.completed_at = now
                self._token_index.pop(session.token_digest, None)
            return self._status_locked(session)

    def cancel(
        self, session_id: str, csrf_token: str, *, session_cookie: str | None = None
    ) -> dict[str, Any]:
        session = self.authorize(session_id, csrf_token, session_cookie)
        with self._lock:
            if session.state != "exchanged":
                raise InvalidState()
            session.state = "cancelled"
            session.completed_at = self._clock()
            return self._status_locked(session)

    def all_terminal(self, session_id: str | None = None) -> bool:
        with self._lock:
            self._purge_locked(self._clock())
            if session_id is not None:
                session = self._sessions.get(session_id)
                return session is None or session.state in {
                    "applied",
                    "failed",
                    "cancelled",
                    "expired",
                }
            return all(
                s.state in {"applied", "failed", "cancelled", "expired"}
                for s in self._sessions.values()
            )

    def _status_locked(self, session: _Session) -> dict[str, Any]:
        result: dict[str, Any] = {
            "session_id": session.session_id,
            "request_id": str(session.request.get("request_id", "")),
            "status": session.state,
            "expires_at": session.expires_at,
        }
        if session.result is not None:
            result["result"] = _redact_result(session.result)
        if session.error_code:
            result["error_code"] = session.error_code
        return result


def _load_request(value: Mapping[str, Any] | str | Path) -> Mapping[str, Any]:
    # The validated schema model intentionally is not a ``Mapping``.  Accept its
    # stable serialization so the server can sit between schema and core layers.
    if hasattr(value, "to_dict") and callable(value.to_dict):
        converted = value.to_dict()
        if isinstance(converted, Mapping):
            return converted
    if isinstance(value, Mapping):
        return _schema_validate_request(value).to_dict()
    return _schema_load_request(Path(value)).to_dict()


def _invoke_apply(
    apply_fn: Callable[..., Any], request: Mapping[str, Any], values: Mapping[str, Any]
) -> Any:
    """Call the core writer with the documented two-argument shape.

    A one-argument callback is accepted for small integrations that close over the
    request.  Signature inspection avoids catching a TypeError raised *inside* the
    callback, which would otherwise be mistaken for a compatibility mismatch.
    """

    try:
        signature = inspect.signature(apply_fn)
        positional_count = sum(
            parameter.kind in (parameter.POSITIONAL_ONLY, parameter.POSITIONAL_OR_KEYWORD)
            for parameter in signature.parameters.values()
        )
    except (TypeError, ValueError):
        positional_count = 2
    if positional_count == 1:
        return apply_fn(values)
    return apply_fn(request, values)


def _parse_json(environ: Mapping[str, Any]) -> dict[str, Any]:
    content_type = str(environ.get("CONTENT_TYPE", "")).split(";", 1)[0].strip().lower()
    if content_type != "application/json":
        raise ValueError("content_type")
    raw_length = environ.get("CONTENT_LENGTH", "")
    try:
        length = int(raw_length)
    except (TypeError, ValueError):
        raise ValueError("content_length") from None
    if length < 0 or length > MAX_BODY_BYTES:
        raise OverflowError("body_too_large")
    stream = environ.get("wsgi.input")
    if stream is None:
        raise ValueError("body")
    remaining = length
    chunks: list[bytes] = []
    while remaining:
        chunk = stream.read(min(remaining, 64 * 1024))
        if not chunk:
            raise ValueError("body")
        chunks.append(chunk)
        remaining -= len(chunk)
    body = b"".join(chunks)
    try:
        parsed = json.loads(body.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        raise ValueError("json") from None
    if not isinstance(parsed, dict):
        raise ValueError("json_object")
    return parsed


def _cookies(environ: Mapping[str, Any]) -> http.cookies.SimpleCookie:
    cookie = http.cookies.SimpleCookie()
    try:
        cookie.load(str(environ.get("HTTP_COOKIE", "")))
    except http.cookies.CookieError:
        return http.cookies.SimpleCookie()
    return cookie


def _host_value(environ: Mapping[str, Any]) -> str:
    return str(environ.get("HTTP_HOST") or environ.get("SERVER_NAME") or "").strip().lower()


def _host_is_loopback(host: str) -> bool:
    if not host:
        return False
    if host.startswith("["):
        return False  # this server deliberately binds IPv4 loopback only
    hostname, separator, port = host.partition(":")
    if separator and (not port.isdigit() or int(port) > 65535):
        return False
    return hostname in {"127.0.0.1", "localhost"}


def _origin_is_loopback(origin: str, host: str) -> bool:
    if not origin:
        return True  # non-browser local API clients have no Origin header
    if origin == "null" or "://" not in origin:
        return False
    scheme, rest = origin.split("://", 1)
    if scheme.lower() != "http":
        return False
    origin_host = rest.split("/", 1)[0].lower()
    if not _host_is_loopback(origin_host):
        return False
    # Host and Origin must identify this exact listener.  Treating localhost and
    # 127.0.0.1 as interchangeable would weaken the browser's same-origin boundary.
    return origin_host == host


class SecretBoxApplication:
    def __init__(self, store: SessionStore) -> None:
        self.store = store

    def __call__(
        self, environ: MutableMapping[str, Any], start_response: Callable[..., Any]
    ) -> list[bytes]:
        method = str(environ.get("REQUEST_METHOD", "GET")).upper()
        path = unquote(str(environ.get("PATH_INFO", "/")))
        host = _host_value(environ)
        if not _host_is_loopback(host):
            return self._error(
                start_response, HTTPStatus.BAD_REQUEST, "invalid_host", "Host must be loopback"
            )
        if method in {"POST", "PUT", "PATCH", "DELETE"} and not _origin_is_loopback(
            str(environ.get("HTTP_ORIGIN", "")), host
        ):
            return self._error(
                start_response, HTTPStatus.FORBIDDEN, "invalid_origin", "Origin is not allowed"
            )
        try:
            if method == "GET" and path == "/healthz":
                return self._json(start_response, HTTPStatus.OK, {"ok": True})
            if method == "GET" and path.startswith("/intake/"):
                session_id = path[len("/intake/") :]
                if not session_id or "/" in session_id:
                    raise UnknownSession()
                try:
                    request = self.store.preview_session(session_id)
                except SessionExpired:
                    nonce = _new_token(18)
                    html = render_intake_error(
                        title="SecretBox 链接已过期",
                        heading="此一次性链接已过期",
                        message=(
                            "该安全会话未在有效期内完成。为保护凭据，"
                            "已过期的链接不能再次使用。"
                        ),
                        status_code=HTTPStatus.GONE,
                        nonce=nonce,
                    )
                    return self._html(start_response, HTTPStatus.GONE, html, nonce=nonce)
                except UnknownSession:
                    nonce = _new_token(18)
                    html = render_intake_error(
                        title="SecretBox 链接已失效",
                        heading="此一次性链接已失效，无法继续",
                        message=(
                            "该链接可能已被打开、刷新、提交或已取消。"
                            "SecretBox 不允许重新打开已使用的表单。"
                        ),
                        status_code=HTTPStatus.NOT_FOUND,
                        nonce=nonce,
                    )
                    return self._html(start_response, HTTPStatus.NOT_FOUND, html, nonce=nonce)
                nonce = _new_token(18)
                html = render_intake(request, nonce, session_id)
                return self._html(start_response, HTTPStatus.OK, html, nonce=nonce)
            if method == "POST" and path == "/api/exchange":
                payload = _parse_json(environ)
                exchange_session_id = payload.get("session_id")
                token = payload.get("token")
                if not isinstance(exchange_session_id, str) or not isinstance(token, str):
                    raise InvalidToken()
                exchanged = self.store.exchange(exchange_session_id, token)
                body = exchanged.as_dict()
                headers = [
                    (
                        "Set-Cookie",
                        self._session_cookie(
                            exchanged.session_id,
                            exchanged.session_cookie,
                            exchanged.expires_at,
                        ),
                    )
                ]
                return self._json(start_response, HTTPStatus.OK, body, headers)
            if path.startswith("/api/sessions/"):
                remainder = path[len("/api/sessions/") :]
                parts = remainder.split("/")
                session_id = parts[0]
                if (
                    not session_id
                    or len(session_id) > 100
                    or any(
                        c not in "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789_-"
                        for c in session_id
                    )
                ):
                    raise UnknownSession()
                if method == "GET" and len(parts) == 1:
                    return self._json(start_response, HTTPStatus.OK, self.store.get(session_id))
                if method == "POST" and len(parts) == 2 and parts[1] in {"submit", "cancel"}:
                    payload = _parse_json(environ)
                    csrf = str(environ.get("HTTP_X_CSRF_TOKEN", ""))
                    if not csrf:
                        csrf = str(payload.pop("csrf_token", ""))
                    cookies = _cookies(environ)
                    cookie = cookies.get(self._session_cookie_name(session_id))
                    cookie_value = cookie.value if cookie else None
                    if parts[1] == "cancel":
                        result = self.store.cancel(session_id, csrf, session_cookie=cookie_value)
                    else:
                        values = payload.get("values", payload)
                        if not isinstance(values, Mapping):
                            raise ValueError("values")
                        result = self.store.submit(
                            session_id, values, csrf, session_cookie=cookie_value
                        )
                    return self._json(start_response, HTTPStatus.OK, result)
            return self._error(start_response, HTTPStatus.NOT_FOUND, "not_found", "Not found")
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
        except ValueError as exc:
            code = (
                str(exc)
                if str(exc)
                in {"content_type", "content_length", "body", "json", "json_object", "values"}
                else "bad_request"
            )
            return self._error(start_response, HTTPStatus.BAD_REQUEST, code, "Invalid JSON request")
        except (InvalidToken, UnknownSession):
            return self._error(
                start_response, HTTPStatus.NOT_FOUND, "not_found", "Session not found"
            )
        except TokenUsed:
            return self._error(
                start_response, HTTPStatus.GONE, "token_used", "Intake link is no longer valid"
            )
        except SessionExpired:
            return self._error(
                start_response, HTTPStatus.GONE, "expired", "Intake link has expired"
            )
        except InvalidState:
            return self._error(
                start_response,
                HTTPStatus.CONFLICT,
                "invalid_state",
                "Session is not accepting this operation",
            )
        except RuntimeError as exc:
            # Apply callbacks are an integration boundary; never send their message,
            # which may accidentally contain a path or value.
            if str(exc).startswith("no apply callback"):
                return self._error(
                    start_response,
                    HTTPStatus.NOT_IMPLEMENTED,
                    "apply_unavailable",
                    "Secret application is not configured",
                )
            return self._error(
                start_response,
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "apply_failed",
                "Secret application failed",
            )
        except ApplyFailed:
            return self._error(
                start_response,
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "apply_failed",
                "Secret application failed",
            )
        except Exception:
            return self._error(
                start_response,
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "internal_error",
                "Internal server error",
            )

    @staticmethod
    def _session_cookie_name(session_id: str) -> str:
        return f"secretbox_session_{session_id}"

    @classmethod
    def _session_cookie(cls, session_id: str, value: str, expires_at: float) -> str:
        max_age = max(1, int(expires_at - time.time()))
        name = cls._session_cookie_name(session_id)
        path = f"/api/sessions/{session_id}/"
        return f"{name}={value}; Path={path}; HttpOnly; SameSite=Strict; Max-Age={max_age}"

    @staticmethod
    def _headers(
        content_type: str,
        extra: Sequence[tuple[str, str]] = (),
        *,
        nonce: str | None = None,
    ) -> list[tuple[str, str]]:
        content_security_policy = (
            "default-src 'none'; connect-src 'self'; base-uri 'none'; "
            "form-action 'self'; frame-ancestors 'none'"
        )
        if nonce is not None:
            content_security_policy += f"; style-src 'nonce-{nonce}'; script-src 'nonce-{nonce}'"
        headers = [
            ("Content-Type", content_type),
            ("Cache-Control", "no-store, max-age=0"),
            ("Pragma", "no-cache"),
            ("X-Content-Type-Options", "nosniff"),
            ("X-Frame-Options", "DENY"),
            ("Referrer-Policy", "no-referrer"),
            ("Content-Security-Policy", content_security_policy),
            ("Permissions-Policy", "camera=(), microphone=(), geolocation=()"),
        ]
        headers.extend(extra)
        return headers

    def _json(
        self,
        start_response: Callable[..., Any],
        status: HTTPStatus,
        payload: Mapping[str, Any],
        extra: Sequence[tuple[str, str]] = (),
    ) -> list[bytes]:
        body = json.dumps(payload, ensure_ascii=True, separators=(",", ":")).encode("utf-8")
        headers = self._headers("application/json; charset=utf-8", extra)
        headers.append(("Content-Length", str(len(body))))
        start_response(f"{status.value} {status.phrase}", headers)
        return [body]

    def _html(
        self,
        start_response: Callable[..., Any],
        status: HTTPStatus,
        body_text: str,
        *,
        nonce: str | None = None,
    ) -> list[bytes]:
        body = body_text.encode("utf-8")
        headers = self._headers("text/html; charset=utf-8", nonce=nonce)
        headers.append(("Content-Length", str(len(body))))
        start_response(f"{status.value} {status.phrase}", headers)
        return [body]

    def _error(
        self, start_response: Callable[..., Any], status: HTTPStatus, code: str, message: str
    ) -> list[bytes]:
        return self._json(start_response, status, {"error": {"code": code, "message": message}})


def create_app(
    store: SessionStore | None = None,
    request: Mapping[str, Any] | str | Path | None = None,
    apply_fn: Callable[..., Any] | None = None,
    *,
    ttl: float = DEFAULT_TTL_SECONDS,
) -> SecretBoxApplication:
    """Create the WSGI app and optionally issue one intake session.

    The issued handle is available as ``app.handle`` for convenience.  Keeping
    request creation separate from HTTP routing lets an agent create a request and
    hand only ``handle.path`` to the user.
    """

    actual_store = store or SessionStore(ttl=ttl)
    app = SecretBoxApplication(actual_store)
    app.store = actual_store  # public integration hook
    app.handle = actual_store.create_session(request, apply_fn) if request is not None else None  # type: ignore[attr-defined]
    return app


class _QuietRequestHandler(WSGIRequestHandler):
    """Suppress access logs for the sensitive local intake service."""

    # Buffered socket ``makefile`` reads cannot be interrupted reliably by a
    # concurrent close on Windows.  The JSON reader handles partial raw reads and
    # the socket timeout bounds inactivity, so an unbuffered stream is both safe
    # for TCP segmentation and promptly closeable.
    rbufsize = 0

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A002
        # Request paths contain high-entropy session identifiers. Tokens stay in
        # fragments, but suppressing all access logs keeps future routes fail-safe.
        return


class _ThreadingWSGIServer(ThreadingMixIn, WSGIServer):
    """Thread-per-request WSGI server with bounded, closeable client sockets."""

    daemon_threads = True
    block_on_close = False
    allow_reuse_address = True

    def __init__(self, *args: Any, **kwargs: Any) -> None:
        self._active_condition = threading.Condition()
        self._active_requests: set[socket.socket] = set()
        super().__init__(*args, **kwargs)

    def get_request(self) -> tuple[socket.socket, Any]:
        request, client_address = super().get_request()
        request.settimeout(REQUEST_READ_TIMEOUT_SECONDS)
        with self._active_condition:
            self._active_requests.add(request)
        return request, client_address

    def shutdown_request(self, request: socket.socket | tuple[bytes, socket.socket]) -> None:
        try:
            super().shutdown_request(request)
        finally:
            if isinstance(request, socket.socket):
                with self._active_condition:
                    self._active_requests.discard(request)
                    self._active_condition.notify_all()

    def wait_for_active_requests(self, timeout: float) -> bool:
        with self._active_condition:
            return self._active_condition.wait_for(lambda: not self._active_requests, timeout)

    def close_active_requests(self) -> None:
        with self._active_condition:
            requests = tuple(self._active_requests)
        for request in requests:
            try:
                request.shutdown(socket.SHUT_RDWR)
            except OSError:
                pass
            try:
                request.close()
            except OSError:
                pass


@dataclass
class Serving:
    server: _ThreadingWSGIServer
    store: SessionStore
    handle: SessionHandle | None
    thread: threading.Thread
    url: str | None = field(repr=False)
    _stop: threading.Event = field(default_factory=threading.Event, repr=False)

    def close(self) -> None:
        self._stop.set()
        self.server.close_active_requests()
        try:
            self.server.server_close()
        except OSError:
            pass
        if self.thread.is_alive():
            self.thread.join(timeout=2)

    def __enter__(self) -> Serving:
        return self

    def __exit__(self, *_: Any) -> None:
        self.close()


def serve_once(
    request: Mapping[str, Any] | str | Path | None = None,
    apply_fn: Callable[..., Any] | None = None,
    *,
    store: SessionStore | None = None,
    host: str = "127.0.0.1",
    port: int = 0,
    ttl: float = DEFAULT_TTL_SECONDS,
) -> Serving:
    """Start a temporary loopback server and return its URL/handle.

    The background loop services requests until the issued session is applied,
    cancelled, failed, or expires.  Call ``Serving.close`` to stop it explicitly.
    ``host`` is intentionally not configurable away from IPv4 loopback.
    """

    if host != "127.0.0.1":
        raise ValueError("SecretBox intake server only binds to 127.0.0.1")
    actual_store = store or SessionStore(ttl=ttl)
    handle = actual_store.create_session(request, apply_fn) if request is not None else None
    app = SecretBoxApplication(actual_store)
    server = make_server(
        host, port, app, server_class=_ThreadingWSGIServer, handler_class=_QuietRequestHandler
    )
    server.timeout = 0.25
    actual_port = int(server.server_port)
    url = f"http://127.0.0.1:{actual_port}{handle.path}" if handle else None
    stop = threading.Event()

    def runner() -> None:
        try:
            while not stop.is_set():
                try:
                    server.handle_request()
                except OSError:
                    # ``Serving.close`` closes the listening socket to wake a
                    # blocked Windows ``select`` call.  WinError 10038 is expected
                    # only during that shutdown race; preserve unexpected socket
                    # failures while the server is meant to be running.
                    if not stop.is_set():
                        raise
                    break
                if handle is not None and actual_store.all_terminal(handle.session_id):
                    break
        finally:
            stop.set()
            try:
                server.server_close()
            except OSError:
                pass
            if not server.wait_for_active_requests(timeout=REQUEST_READ_TIMEOUT_SECONDS + 0.25):
                server.close_active_requests()
                server.wait_for_active_requests(timeout=0.25)

    thread = threading.Thread(target=runner, name="secretbox-intake", daemon=True)
    thread.start()
    serving = Serving(server, actual_store, handle, thread, url, stop)
    return serving


__all__ = [
    "ApplyFailed",
    "ExchangeResult",
    "InvalidState",
    "InvalidToken",
    "SessionError",
    "SessionExpired",
    "SessionHandle",
    "SessionStore",
    "Serving",
    "TokenUsed",
    "UnknownSession",
    "create_app",
    "serve_once",
]
