"""Trusted UI handoff bridge for headless / remote browser sessions.

SecretBox MCP never returns bearer URLs to agents.  When the OS desktop browser
cannot open the loopback intake page, the MCP process may POST the full URL to a
loopback-only handoff service with a shared secret.

Remote users open this bridge in their own browser.  The bridge renders a form
and **proxies** exchange/submit to the loopback SecretBox intake server so users
never need to reach 127.0.0.1 from their laptop.

Security properties:
- publish endpoint is loopback-only and requires a shared secret header;
- MCP tool results still omit URLs, tokens, and session ids (only intake_id);
- public form pages expire with the intake TTL;
- secret values travel browser → bridge → loopback intake → disk, never chat/LLM.
"""

from __future__ import annotations

import argparse
import json
import secrets
import threading
import time
from collections.abc import Mapping
from dataclasses import dataclass, field
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.parse import urlsplit
from urllib.request import Request, urlopen


HANDOFF_HEADER = "X-SecretBox-Handoff-Token"
DEFAULT_BRIDGE_HOST = "0.0.0.0"
DEFAULT_BRIDGE_PORT = 8787


def publish_intake_url(
    handoff_url: str,
    *,
    token: str,
    intake_id: str,
    request_id: str,
    title: str,
    expires_at: str,
    intake_url: str,
    timeout: float = 3.0,
) -> bool:
    """Publish a loopback intake URL to a trusted handoff bridge.

    Returns True only when the bridge acknowledges the publish.  Never logs the
    intake URL.  Callers must not put the URL into MCP results.
    """

    if not handoff_url or not token or not intake_url or not intake_id:
        return False
    payload = {
        "schema_version": 1,
        "intake_id": intake_id,
        "request_id": request_id,
        "title": title,
        "expires_at": expires_at,
        "intake_url": intake_url,
    }
    body = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")
    request = Request(
        handoff_url,
        data=body,
        method="POST",
        headers={
            "Content-Type": "application/json; charset=utf-8",
            "Content-Length": str(len(body)),
            HANDOFF_HEADER: token,
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310 — loopback bridge only
            if getattr(response, "status", 200) >= 300:
                return False
            raw = response.read(4096)
    except (HTTPError, URLError, TimeoutError, OSError, ValueError):
        return False
    try:
        data = json.loads(raw.decode("utf-8") or "{}")
    except (UnicodeDecodeError, json.JSONDecodeError):
        return False
    return isinstance(data, Mapping) and data.get("ok") is True


@dataclass
class _HandoffRecord:
    intake_id: str
    request_id: str
    title: str
    expires_at: str
    intake_url: str = field(repr=False)
    created_at: float
    page_token: str = field(repr=False)
    session_id: str = field(default="", repr=False)
    bearer_token: str = field(default="", repr=False)
    base_url: str = field(default="", repr=False)
    csrf_token: str | None = field(default=None, repr=False)
    session_cookie: str | None = field(default=None, repr=False)
    needs: list[dict[str, Any]] = field(default_factory=list)
    env_file: str = ".env.local"
    state: str = "pending"  # pending | ready | applied | failed | error


class HandoffStore:
    def __init__(self, *, token: str, clock: Any = time.time) -> None:
        if not token or len(token) < 16:
            raise ValueError("handoff token must be at least 16 characters")
        self._token = token
        self._clock = clock
        self._lock = threading.RLock()
        self._by_intake: dict[str, _HandoffRecord] = {}
        self._by_page: dict[str, str] = {}

    def authorize(self, header_value: str | None) -> bool:
        if not isinstance(header_value, str) or not header_value:
            return False
        return secrets.compare_digest(header_value, self._token)

    def publish(self, payload: Mapping[str, Any]) -> dict[str, Any]:
        intake_id = payload.get("intake_id")
        request_id = payload.get("request_id")
        title = payload.get("title")
        expires_at = payload.get("expires_at")
        intake_url = payload.get("intake_url")
        if not all(
            isinstance(v, str) and v
            for v in (intake_id, request_id, title, expires_at, intake_url)
        ):
            raise ValueError("invalid_payload")
        if not str(intake_url).startswith("http://127.0.0.1:") and not str(intake_url).startswith(
            "http://localhost:"
        ):
            raise ValueError("intake_url must be loopback")
        parts = urlsplit(str(intake_url))
        path = parts.path or ""
        if not path.startswith("/intake/"):
            raise ValueError("invalid intake path")
        session_id = path.rsplit("/", 1)[-1]
        fragment = parts.fragment or ""
        bearer = ""
        if fragment.startswith("token="):
            bearer = fragment[len("token=") :]
        elif "token=" in fragment:
            for piece in fragment.split("&"):
                if piece.startswith("token="):
                    bearer = piece[len("token=") :]
                    break
        if not session_id or not bearer:
            raise ValueError("invalid intake url")
        page_token = secrets.token_urlsafe(24)
        record = _HandoffRecord(
            intake_id=str(intake_id),
            request_id=str(request_id),
            title=str(title),
            expires_at=str(expires_at),
            intake_url=str(intake_url),
            created_at=float(self._clock()),
            page_token=page_token,
            session_id=session_id,
            bearer_token=bearer,
            base_url=f"{parts.scheme}://{parts.netloc}",
        )
        with self._lock:
            old = self._by_intake.get(record.intake_id)
            if old is not None:
                self._by_page.pop(old.page_token, None)
            self._by_intake[record.intake_id] = record
            self._by_page[page_token] = record.intake_id
        return {
            "ok": True,
            "intake_id": record.intake_id,
            "page_path": f"/f/{page_token}",
        }

    def get_by_page_token(self, page_token: str) -> _HandoffRecord | None:
        with self._lock:
            intake_id = self._by_page.get(page_token)
            if not intake_id:
                return None
            return self._by_intake.get(intake_id)

    def clear(self, intake_id: str) -> None:
        with self._lock:
            record = self._by_intake.pop(intake_id, None)
            if record is not None:
                self._by_page.pop(record.page_token, None)

    def list_public(self) -> list[dict[str, str]]:
        with self._lock:
            items = []
            for record in self._by_intake.values():
                if record.state in {"applied", "failed"}:
                    continue
                items.append(
                    {
                        "intake_id": record.intake_id,
                        "request_id": record.request_id,
                        "title": record.title,
                        "expires_at": record.expires_at,
                        "page_path": f"/f/{record.page_token}",
                    }
                )
            return items


def _html_escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#39;")
    )


def _post_loopback_json(
    url: str,
    payload: Mapping[str, Any],
    *,
    headers: Mapping[str, str] | None = None,
    timeout: float = 10.0,
) -> tuple[int, dict[str, Any], str | None]:
    body = json.dumps(payload, ensure_ascii=False).encode("utf-8")
    parts = urlsplit(url)
    origin = f"{parts.scheme}://{parts.netloc}"
    hdrs = {
        "Content-Type": "application/json; charset=utf-8",
        "Content-Length": str(len(body)),
        "Origin": origin,
        "Host": parts.netloc,
    }
    if headers:
        hdrs.update(headers)
        # Force Origin to match the loopback listener even if caller passes one.
        hdrs["Origin"] = origin
    request = Request(url, data=body, headers=hdrs, method="POST")
    try:
        with urlopen(request, timeout=timeout) as response:  # noqa: S310
            raw = response.read(1_048_576)
            set_cookie = response.headers.get("Set-Cookie")
            status = int(getattr(response, "status", 200))
            data = json.loads(raw.decode("utf-8") or "{}")
            if not isinstance(data, dict):
                data = {}
            return status, data, set_cookie
    except HTTPError as exc:
        try:
            raw = exc.read(1_048_576)
            data = json.loads(raw.decode("utf-8") or "{}")
            if not isinstance(data, dict):
                data = {}
        except Exception:
            data = {"error": "http_error"}
        return int(exc.code), data, None
    except (URLError, TimeoutError, OSError, ValueError, json.JSONDecodeError):
        return 0, {"error": "upstream_unavailable"}, None


def _cookie_value(set_cookie: str | None) -> str | None:
    if not set_cookie:
        return None
    jar = SimpleCookie()
    try:
        jar.load(set_cookie)
    except Exception:
        # Fallback parse: name=value; ...
        first = set_cookie.split(";", 1)[0]
        if "=" in first:
            return first.split("=", 1)[1].strip()
        return None
    for morsel in jar.values():
        if morsel.value:
            return morsel.value
    return None


def ensure_exchanged(record: _HandoffRecord) -> str | None:
    """Exchange bearer on loopback; return error message or None on success."""

    if record.csrf_token and record.session_cookie and record.needs:
        record.state = "ready"
        return None
    status, data, set_cookie = _post_loopback_json(
        f"{record.base_url}/api/exchange",
        {"session_id": record.session_id, "token": record.bearer_token},
    )
    if status != 200:
        record.state = "error"
        return str(data.get("message") or data.get("error") or "exchange_failed")
    csrf = data.get("csrf_token")
    request_meta = data.get("request")
    if not isinstance(csrf, str) or not isinstance(request_meta, Mapping):
        record.state = "error"
        return "invalid_exchange"
    cookie = _cookie_value(set_cookie)
    if not cookie:
        record.state = "error"
        return "missing_session_cookie"
    needs = request_meta.get("needs")
    if not isinstance(needs, list):
        needs = []
    write_policy = request_meta.get("write_policy") or {}
    env_file = ".env.local"
    if isinstance(write_policy, Mapping) and isinstance(write_policy.get("env_file"), str):
        env_file = write_policy["env_file"]
    record.csrf_token = csrf
    record.session_cookie = cookie
    record.needs = [n for n in needs if isinstance(n, dict)]
    record.env_file = env_file
    record.bearer_token = ""
    record.state = "ready"
    return None


def submit_values(record: _HandoffRecord, values: Mapping[str, str]) -> tuple[bool, str]:
    err = ensure_exchanged(record)
    if err:
        return False, err
    assert record.csrf_token and record.session_cookie
    env_values: dict[str, str] = {}
    file_values: dict[str, str] = {}
    for need in record.needs:
        name = str(need.get("name") or "")
        if not name or name not in values:
            continue
        ntype = str(need.get("type") or "env")
        if ntype == "file":
            file_values[name] = values[name]
        else:
            # env and env_file map into env bag for SecretBox apply protocol
            env_values[name] = values[name]
    cookie_name = f"secretbox_session_{record.session_id}"
    status, data, _ = _post_loopback_json(
        f"{record.base_url}/api/sessions/{record.session_id}/submit",
        {"values": {"env": env_values, "files": file_values}},
        headers={
            "X-CSRF-Token": record.csrf_token,
            "Cookie": f"{cookie_name}={record.session_cookie}",
        },
    )
    if status != 200:
        msg = str(data.get("message") or data.get("error") or f"submit_failed_{status}")
        record.state = "failed"
        return False, msg
    record.csrf_token = None
    record.session_cookie = None
    record.needs = []
    record.state = "applied"
    return True, "applied"


def _render_index(items: list[dict[str, str]]) -> bytes:
    rows = []
    for item in items:
        rows.append(
            "<li>"
            f"<a href=\"{_html_escape(item['page_path'])}\">{_html_escape(item['title'])}</a>"
            f" <code>{_html_escape(item['request_id'])}</code>"
            f" <span>expires {_html_escape(item['expires_at'])}</span>"
            "</li>"
        )
    body = "\n".join(rows) or "<li>当前没有待填写的密钥表单。</li>"
    html = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>OpenAgent SecretBox 表单</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; max-width: 720px; color: #111; }}
    code {{ background: #f4f4f5; padding: 0.1rem 0.3rem; border-radius: 4px; }}
    li {{ margin: 0.75rem 0; }}
    a {{ font-weight: 600; }}
  </style>
</head>
<body>
  <h1>OpenAgent SecretBox</h1>
  <p>以下表单由 Agent 发起；密钥只在本页填写，不要粘贴到聊天。</p>
  <ul>
    {body}
  </ul>
  <p><button onclick="location.reload()">刷新列表</button></p>
</body>
</html>
"""
    return html.encode("utf-8")


def _render_form(record: _HandoffRecord, *, error: str | None = None) -> bytes:
    fields = []
    for need in record.needs:
        name = str(need.get("name") or "")
        if not name:
            continue
        ntype = str(need.get("type") or "env")
        required = bool(need.get("required", True))
        desc = str(need.get("description") or "")
        req_attr = "required" if required else ""
        input_type = "password" if ntype in {"env", "env_file"} else "text"
        if ntype == "file":
            # File needs still accept paste of PEM/text content for MVP proxy form.
            input_type = "text"
        fields.append(
            f"""
            <label>
              <span>{_html_escape(name)}{' *' if required else ''}</span>
              <small>{_html_escape(desc)}</small>
              <input name="{_html_escape(name)}" type="{input_type}" autocomplete="off" {req_attr} />
            </label>
            """
        )
    err_html = f'<p class="err">{_html_escape(error)}</p>' if error else ""
    html = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{_html_escape(record.title)}</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; max-width: 640px; color: #111; }}
    label {{ display: block; margin: 1rem 0; }}
    span {{ display:block; font-weight: 600; }}
    small {{ display:block; color: #555; margin: 0.2rem 0 0.4rem; }}
    input {{ width: 100%; padding: 0.6rem; font-size: 1rem; box-sizing: border-box; }}
    button {{ margin-top: 1rem; padding: 0.7rem 1.2rem; font-size: 1rem; }}
    .err {{ color: #b91c1c; }}
    .meta {{ color: #444; font-size: 0.95rem; }}
  </style>
</head>
<body>
  <h1>{_html_escape(record.title)}</h1>
  <p class="meta">request: <code>{_html_escape(record.request_id)}</code> · 写入 <code>{_html_escape(record.env_file)}</code> · 过期 <code>{_html_escape(record.expires_at)}</code></p>
  <p>密钥仅提交到本机 SecretBox，不会进入聊天。提交后请回到对话回复 <code>applied</code>。</p>
  {err_html}
  <form method="post" action="/f/{_html_escape(record.page_token)}">
    {''.join(fields)}
    <button type="submit">安全提交</button>
  </form>
</body>
</html>
"""
    return html.encode("utf-8")


def _render_done(title: str, message: str) -> bytes:
    html = f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1" />
  <title>{_html_escape(title)}</title>
  <style>body{{font-family:system-ui,sans-serif;margin:2rem;max-width:640px}}</style>
</head>
<body>
  <h1>{_html_escape(title)}</h1>
  <p>{_html_escape(message)}</p>
  <p>请回到 Hermes 对话，只回复状态词（如 <code>applied</code>），不要粘贴密钥。</p>
  <p><a href="/">返回表单列表</a></p>
</body>
</html>
"""
    return html.encode("utf-8")


def _render_gone(message: str) -> bytes:
    return _render_done("表单不可用", message)


class HandoffHandler(BaseHTTPRequestHandler):
    store: HandoffStore

    def log_message(self, format: str, *args: Any) -> None:  # noqa: A003
        sys_stderr = __import__("sys").stderr
        print(f"secretbox-ui-handoff: {self.command} {self.path.split('?', 1)[0]}", file=sys_stderr)

    def _read_json(self) -> Mapping[str, Any]:
        length = int(self.headers.get("Content-Length") or "0")
        if length <= 0 or length > 65536:
            raise ValueError("body")
        raw = self.rfile.read(length)
        data = json.loads(raw.decode("utf-8"))
        if not isinstance(data, Mapping):
            raise ValueError("json_object")
        return data

    def _read_form(self) -> dict[str, str]:
        length = int(self.headers.get("Content-Length") or "0")
        if length <= 0 or length > 1_048_576:
            raise ValueError("body")
        raw = self.rfile.read(length)
        from urllib.parse import parse_qs

        parsed = parse_qs(raw.decode("utf-8"), keep_blank_values=True)
        return {k: (v[0] if v else "") for k, v in parsed.items()}

    def _send(self, status: int, body: bytes, content_type: str) -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path in {"/", "/index.html"}:
            body = _render_index(self.store.list_public())
            self._send(200, body, "text/html; charset=utf-8")
            return
        if path == "/api/active":
            payload = json.dumps({"items": self.store.list_public()}, ensure_ascii=False).encode(
                "utf-8"
            )
            self._send(200, payload, "application/json; charset=utf-8")
            return
        if path.startswith("/f/"):
            page_token = path[len("/f/") :]
            record = self.store.get_by_page_token(page_token)
            if record is None:
                self._send(404, _render_gone("链接已失效或已被使用。"), "text/html; charset=utf-8")
                return
            if record.state == "applied":
                self._send(
                    200,
                    _render_done(record.title, "已提交成功。"),
                    "text/html; charset=utf-8",
                )
                return
            err = ensure_exchanged(record)
            if err:
                self._send(
                    410,
                    _render_gone(f"无法打开表单：{err}"),
                    "text/html; charset=utf-8",
                )
                return
            self._send(200, _render_form(record), "text/html; charset=utf-8")
            return
        self._send(404, b'{"error":"not_found"}', "application/json; charset=utf-8")

    def do_POST(self) -> None:  # noqa: N802
        path = self.path.split("?", 1)[0]
        if path == "/internal/publish":
            client_ip = self.client_address[0]
            if client_ip not in {"127.0.0.1", "::1", "localhost"}:
                self._send(403, b'{"error":"forbidden"}', "application/json; charset=utf-8")
                return
            if not self.store.authorize(self.headers.get(HANDOFF_HEADER)):
                self._send(401, b'{"error":"unauthorized"}', "application/json; charset=utf-8")
                return
            try:
                payload = self._read_json()
                result = self.store.publish(payload)
            except ValueError:
                self._send(400, b'{"error":"bad_request"}', "application/json; charset=utf-8")
                return
            body = json.dumps(result, ensure_ascii=False).encode("utf-8")
            self._send(200, body, "application/json; charset=utf-8")
            return
        if path.startswith("/f/"):
            page_token = path[len("/f/") :]
            record = self.store.get_by_page_token(page_token)
            if record is None:
                self._send(404, _render_gone("链接已失效。"), "text/html; charset=utf-8")
                return
            try:
                values = self._read_form()
            except ValueError:
                self._send(400, _render_gone("表单无效。"), "text/html; charset=utf-8")
                return
            # Only forward declared need names.
            allowed = {str(n.get("name")) for n in record.needs if isinstance(n.get("name"), str)}
            filtered = {k: v for k, v in values.items() if k in allowed}
            ok, message = submit_values(record, filtered)
            if ok:
                self._send(
                    200,
                    _render_done(record.title, "提交成功，密钥已按策略写入 workspace。"),
                    "text/html; charset=utf-8",
                )
            else:
                # Re-exchange may be needed if still pending.
                ensure_exchanged(record)
                self._send(
                    400,
                    _render_form(record, error=message),
                    "text/html; charset=utf-8",
                )
            return
        self._send(404, b'{"error":"not_found"}', "application/json; charset=utf-8")


def serve_handoff(
    *,
    host: str = DEFAULT_BRIDGE_HOST,
    port: int = DEFAULT_BRIDGE_PORT,
    token: str,
) -> ThreadingHTTPServer:
    store = HandoffStore(token=token)

    class BoundHandler(HandoffHandler):
        pass

    BoundHandler.store = store
    server = ThreadingHTTPServer((host, port), BoundHandler)
    return server


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="secretbox-ui-handoff")
    parser.add_argument("--host", default=DEFAULT_BRIDGE_HOST)
    parser.add_argument("--port", type=int, default=DEFAULT_BRIDGE_PORT)
    parser.add_argument(
        "--token",
        default="",
        help="shared secret; if empty, generate and print once to stderr",
    )
    parser.add_argument(
        "--token-file",
        default="",
        help="write generated/used token to this path (mode 600)",
    )
    parser.add_argument(
        "--public-base",
        default="",
        help="optional public base URL printed for users (e.g. http://HOST:8787)",
    )
    args = parser.parse_args(argv)
    token = args.token.strip()
    if args.token_file and not token:
        path = Path(args.token_file).expanduser()
        if path.is_file():
            token = path.read_text(encoding="utf-8").strip()
    if not token:
        token = secrets.token_urlsafe(32)
        print(
            f"secretbox-ui-handoff: generated token (save this): {token}",
            file=__import__("sys").stderr,
        )
    if args.token_file:
        path = Path(args.token_file).expanduser()
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(token + "\n", encoding="utf-8")
        try:
            path.chmod(0o600)
        except OSError:
            pass
    server = serve_handoff(host=args.host, port=args.port, token=token)
    public = args.public_base.rstrip("/") or f"http://127.0.0.1:{args.port}"
    print(
        f"secretbox-ui-handoff listening on {args.host}:{args.port}",
        file=__import__("sys").stderr,
    )
    print(f"open form index: {public}/", file=__import__("sys").stderr)
    print(
        f"publish URL for MCP: http://127.0.0.1:{args.port}/internal/publish",
        file=__import__("sys").stderr,
    )
    try:
        server.serve_forever(poll_interval=0.5)
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
