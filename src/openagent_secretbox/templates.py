"""Small, dependency-free HTML templates for the local intake page.

The page is deliberately self contained.  It does not load a font, script, image,
or stylesheet from the network, and all request supplied strings are escaped before
they are inserted into the document.
"""

from __future__ import annotations

from collections.abc import Mapping
from html import escape
from json import dumps
from typing import Any


def _safe_need(need: Mapping[str, Any]) -> dict[str, Any]:
    """Return only fields that are useful in the UI and safe to display."""

    allowed = ("type", "name", "required", "description", "target")
    return {key: need[key] for key in allowed if key in need}


def _safe_request(request: Mapping[str, Any]) -> dict[str, Any]:
    needs = request.get("needs", [])
    if not isinstance(needs, list):
        needs = []
    write_policy = request.get("write_policy", {})
    env_file = ".env"
    if isinstance(write_policy, Mapping):
        candidate = write_policy.get("env_file")
        if isinstance(candidate, str):
            env_file = candidate
    safe_policy = {
        key: write_policy[key]
        for key in ("env_file", "mode", "no_overwrite", "backup")
        if isinstance(write_policy, Mapping) and key in write_policy
    }
    safe_needs: list[dict[str, Any]] = []
    for item in needs:
        if not isinstance(item, Mapping):
            continue
        safe_need = _safe_need(item)
        if safe_need.get("type") in {"env", "env_file"} and "target" not in safe_need:
            safe_need["target"] = env_file
        safe_needs.append(safe_need)
    safe: dict[str, Any] = {
        "request_id": str(request.get("request_id", "")),
        "title": str(request.get("title", "Secret request")),
        "needs": safe_needs,
        "write_policy": safe_policy,
    }
    if isinstance(request.get("workspace_root"), str):
        safe["workspace_root"] = request["workspace_root"]
    return safe


def render_intake(request: Mapping[str, Any], nonce: str, session_id: str) -> str:
    """Render the browser bootstrap page for a pending session.

    The one-time token stays in the URL fragment, which the browser does not send
    in the HTTP request. JavaScript clears it from history before exchange.
    """

    safe = _safe_request(request)
    title = escape(safe["title"], quote=True)
    request_id = escape(safe["request_id"], quote=True)
    workspace = escape(str(safe.get("workspace_root", "Not declared")), quote=True)
    escaped_nonce = escape(nonce, quote=True)
    escaped_session_id = escape(session_id, quote=True)

    fields: list[str] = []
    for index, need in enumerate(safe["needs"]):
        kind = str(need.get("type", "env"))
        name = str(need.get("name", f"secret_{index + 1}"))
        description = escape(str(need.get("description", "")), quote=True)
        target = escape(str(need.get("target", "")), quote=True)
        name_attr = escape(name, quote=True)
        required = " required" if bool(need.get("required", False)) else ""
        label = f"{name_attr}"
        hints = []
        if description:
            hints.append(f"<small>{description}</small>")
        if target:
            hints.append(f"<small>Target: <code>{target}</code></small>")
        hint = "".join(hints)
        if kind == "file":
            fields.append(
                f'<label>{label}{hint}<input type="file" '
                f'name="{name_attr}" data-secret-name="{name_attr}" '
                f'data-secret-type="file"{required} disabled></label>'
            )
        elif kind == "env_file":
            fields.append(
                f'<label>{label}{hint}<textarea rows="8" '
                f'name="{name_attr}" data-secret-name="{name_attr}" '
                f'data-secret-type="env" autocomplete="off" spellcheck="false"'
                f"{required} disabled></textarea></label>"
            )
        else:
            field_id = f"secret-field-{index}"
            escaped_field_id = escape(field_id, quote=True)
            fields.append(
                f'<label class="password-label" for="{escaped_field_id}">{label}{hint}</label>'
                f'<div class="password-control"><input id="{escaped_field_id}" '
                f'type="password" name="{name_attr}" data-secret-name="{name_attr}" '
                f'data-secret-type="env" autocomplete="off"{required} disabled>'
                f'<button class="visibility-toggle" type="button" '
                f'data-target="{escaped_field_id}" data-secret-label="{name_attr}" '
                f'aria-label="显示 {name_attr}" aria-pressed="false" '
                f'title="显示此值" disabled><span class="eye-icon" '
                f'aria-hidden="true"></span></button></div>'
            )

    fields_html = "\n".join(fields) or '<p class="muted">No inputs were requested.</p>'
    # The JSON is generated from the already-filtered request.  It is escaped for
    # an HTML attribute so user-controlled strings cannot terminate the attribute.
    metadata = escape(dumps(safe, separators=(",", ":")), quote=True)
    policy = safe["write_policy"]
    overwrite = "blocked" if policy.get("no_overwrite", True) else "policy controlled"
    backup = "disabled" if not policy.get("backup", False) else "enabled"
    policy_summary = escape(
        f"merge-only; overwrite {overwrite}; persistent backup {backup}", quote=True
    )

    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta name="referrer" content="no-referrer">
  <title>{title} - SecretBox</title>
  <style nonce="{escaped_nonce}">
    :root {{ color-scheme: light; font-family: Inter, "Segoe UI", system-ui, sans-serif;
      --ink: #18201c; --muted: #5d665f; --line: #d8ded9; --surface: #fff;
      --canvas: #f2f5f2; --primary: #197447; --primary-hover: #125f3a;
      --warning-bg: #fff7d6; --warning-line: #e5bd35; --warning-ink: #5c4300;
      --danger-bg: #fff1f0; --danger: #a12622; --success-bg: #eaf7ee; --success: #126b39; }}
    * {{ box-sizing: border-box; }}
    body {{ margin: 0; min-height: 100vh; padding: 2rem 1rem; background: var(--canvas);
      color: var(--ink); }}
    main {{ max-width: 44rem; margin: 0 auto; background: var(--surface); padding: 1.75rem;
      border: 1px solid var(--line); border-radius: 8px; box-shadow: 0 12px 36px #17201912; }}
    h1 {{ margin: 0; font-size: 1.55rem; line-height: 1.25; }}
    h2 {{ margin: 0 0 .5rem; font-size: 1.15rem; }}
    .lede {{ margin: .5rem 0 1.25rem; color: var(--muted); }}
    .notice {{ margin: 1.25rem 0; padding: 1rem; border: 1px solid var(--warning-line);
      border-left-width: 5px; border-radius: 6px; background: var(--warning-bg);
      color: var(--warning-ink); }}
    .notice strong {{ display: block; margin-bottom: .25rem; font-size: 1rem; }}
    .notice p {{ margin: 0; }}
    .context-grid {{ display: grid; gap: .75rem; margin: 1.25rem 0;
      padding: 1rem; background: #f8faf8; border: 1px solid var(--line); border-radius: 6px; }}
    .context {{ margin: 0; }} .context code {{ overflow-wrap: anywhere; }}
    .context strong {{ display: block; margin-bottom: .15rem; font-size: .8rem;
      color: var(--muted); text-transform: uppercase; }}
    label {{ display: block; margin: 1.1rem 0; font-weight: 650; }}
    label.password-label {{ margin-bottom: 0; }}
    input, textarea {{ display: block; width: 100%; box-sizing: border-box; margin-top: .4rem;
      padding: .75rem; border: 1px solid #aeb6af; border-radius: 6px; background: #fff;
      color: var(--ink); font: inherit; }}
    input[type="file"] {{ padding: .55rem; }}
    .password-control {{ position: relative; margin-top: .4rem; }}
    .password-control input {{ margin-top: 0; padding-right: 3.25rem; }}
    textarea {{ min-height: 9rem; resize: vertical; font-family: ui-monospace, SFMono-Regular,
      Consolas, "Liberation Mono", monospace; line-height: 1.45; }}
    input:focus-visible, textarea:focus-visible, button:focus-visible {{ outline: 3px solid #75c79c;
      outline-offset: 2px; }}
    small {{ display: block; margin-top: .25rem; color: var(--muted); font-weight: 400; }}
    .actions {{ display: flex; flex-wrap: wrap; gap: .75rem; margin-top: 1.5rem; }}
    button {{ min-height: 2.5rem; padding: .7rem 1rem; border: 0; border-radius: 6px;
      background: var(--primary); color: #fff; font: inherit; font-weight: 700; cursor: pointer; }}
    button:hover {{ background: var(--primary-hover); }}
    button.secondary {{ background: #fff; color: var(--ink); border: 1px solid #aeb6af; }}
    button.secondary:hover {{ background: #f2f5f2; }}
    button.visibility-toggle {{ position: absolute; top: 4px; right: 4px; width: 40px;
      height: 40px; min-height: 40px; display: grid; place-items: center; padding: 0;
      border-radius: 6px; background: transparent; color: var(--muted); }}
    button.visibility-toggle:hover {{ background: #edf2ee; color: var(--ink); }}
    button.visibility-toggle[aria-pressed="true"] {{ color: var(--primary); }}
    .eye-icon {{ position: relative; display: block; width: 18px; height: 12px;
      border: 2px solid currentColor; border-radius: 75% 20%; transform: rotate(45deg); }}
    .eye-icon::before {{ content: ""; position: absolute; width: 4px; height: 4px;
      top: 2px; left: 5px; border-radius: 50%; background: currentColor; }}
    .visibility-toggle[aria-pressed="true"] .eye-icon::after {{ content: "";
      position: absolute; width: 22px; height: 2px; top: 3px; left: -4px;
      background: currentColor; box-shadow: 0 0 0 2px var(--surface); transform: rotate(90deg); }}
    button:disabled {{ opacity: .55; cursor: not-allowed; }}
    .muted {{ color: var(--muted); }}
    #status {{ min-height: 1.4rem; margin: 1rem 0 0; font-weight: 650; }}
    .error {{ color: var(--danger); }} .ok {{ color: var(--success); }}
    .state-panel {{ padding: 1.25rem; border-radius: 8px; }}
    .state-panel.error-panel {{ background: var(--danger-bg); border: 1px solid #e5b7b3; }}
    .state-panel.success-panel {{ background: var(--success-bg); border: 1px solid #a9d8b8; }}
    .state-panel p {{ margin: .4rem 0 0; color: var(--muted); }}
    [hidden] {{ display: none !important; }}
    @media (max-width: 36rem) {{ body {{ padding: 0; }} main {{ min-height: 100vh;
      padding: 1.25rem; border: 0; border-radius: 0; box-shadow: none; }}
      .actions button {{ width: 100%; }} }}
  </style>
</head>
<body>
  <main>
    <h1>{title}</h1>
    <p class="lede">请求 <code>{request_id}</code>。内容只会发送到本机 SecretBox，
      不会展示给发起请求的 AI。</p>
    <aside id="one-time-notice" class="notice" aria-label="一次性链接提示">
      <strong>此页面只能使用一次</strong>
      <p>请在当前页面一次完成填写和提交。刷新、关闭或再次打开后链接将失效；
        如需重试，请向 AI 发送要求以获取新链接。</p>
    </aside>
    <div id="request-context" class="context-grid">
      <p class="context"><strong>工作目录</strong><code>{workspace}</code></p>
      <p class="context"><strong>写入策略</strong>{policy_summary}</p>
    </div>
    <form id="secret-form" data-request="{metadata}" data-session-id="{escaped_session_id}">
      {fields_html}
      <div class="actions">
        <button id="submit" type="submit" disabled>正在建立安全会话...</button>
        <button id="cancel" class="secondary" type="button" disabled>取消</button>
      </div>
    </form>
    <p id="status" class="muted" role="status" aria-live="polite">正在验证一次性链接...</p>
    <section id="unavailable" class="state-panel error-panel" tabindex="-1" hidden>
      <h2>此链接已失效，无法继续</h2>
      <p>该链接可能已被打开、刷新、提交或已过期。为保护凭据，SecretBox 不允许再次使用。</p>
      <p><strong>请返回 AI 对话，发送“请生成新的 SecretBox 链接”。</strong></p>
    </section>
    <section id="success" class="state-panel success-panel" tabindex="-1" hidden>
      <h2>凭据已安全保存</h2>
      <p>请求已经完成，可以关闭此页面并返回 AI 对话继续操作。</p>
      <p>此链接已经失效；刷新或再次打开不会重新显示表单。</p>
    </section>
    <section id="apply-failed" class="state-panel error-panel" tabindex="-1" hidden>
      <h2>保存未完成，此页面无法重试</h2>
      <p>SecretBox 未能确认所有凭据均已保存；部分目标可能已经写入。为保护凭据，
        此次一次性会话已经结束，表单将保持锁定。</p>
      <p><strong>请返回 AI 对话，说明保存失败并要求生成新的 SecretBox 链接。</strong></p>
    </section>
    <section id="cancelled" class="state-panel" tabindex="-1" hidden>
      <h2>已取消</h2>
      <p>没有提交任何内容。若需要重新填写，请返回 AI 对话索取新链接。</p>
    </section>
    <section id="cancel-uncertain" class="state-panel error-panel" tabindex="-1" hidden>
      <h2>无法确认取消结果</h2>
      <p>取消请求已经发出，但 SecretBox 未收到可确认的响应。为避免重复操作，
        此页面不会再次启用。</p>
      <p><strong>请返回 AI 对话查询当前状态；如需继续，请要求生成新的 SecretBox 链接。</strong></p>
    </section>
  </main>
  <script nonce="{escaped_nonce}">
  (() => {{
    const form = document.getElementById('secret-form');
    const status = document.getElementById('status');
    const button = document.getElementById('submit');
    const cancelButton = document.getElementById('cancel');
    const notice = document.getElementById('one-time-notice');
    const context = document.getElementById('request-context');
    const unavailable = document.getElementById('unavailable');
    const success = document.getElementById('success');
    const applyFailed = document.getElementById('apply-failed');
    const cancelled = document.getElementById('cancelled');
    const cancelUncertain = document.getElementById('cancel-uncertain');
    const visibilityButtons = Array.from(form.querySelectorAll('.visibility-toggle'));
    const controls = Array.from(form.querySelectorAll('input, textarea, button'));
    const setReady = (ready) => {{
      controls.forEach((control) => {{ control.disabled = !ready; }});
      button.textContent = ready ? '安全保存' : '处理中...';
    }};
    const sessionId = form.dataset.sessionId;
    const storageKey = 'secretbox-session:' + sessionId;
    let token = new URLSearchParams(window.location.hash.slice(1)).get('token');
    window.history.replaceState(null, '', window.location.pathname);
    let session = null;
    const say = (message, ok) => {{ status.textContent = message;
      status.className = ok ? 'ok' : 'error'; }};
    const showFinalState = (panel) => {{
      form.hidden = true; notice.hidden = true; context.hidden = true; status.hidden = true;
      panel.hidden = false; panel.focus();
    }};
    const clearLocalSession = () => {{
      try {{ sessionStorage.removeItem(storageKey); }} catch (_) {{ /* best effort */ }}
      session = null;
      token = null;
    }};
    const clearSecretInputs = () => form.querySelectorAll('[data-secret-name]')
      .forEach((input) => {{ input.value = ''; }});
    const showTerminalState = (panel) => {{
      setReady(false);
      clearSecretInputs();
      clearLocalSession();
      showFinalState(panel);
    }};
    const showUnavailable = () => showTerminalState(unavailable);
    const showTerminalFailure = () => showTerminalState(applyFailed);
    const showCancelUncertain = () => showTerminalState(cancelUncertain);
    const setSecretVisible = (toggle, input, visible) => {{
      input.type = visible ? 'text' : 'password';
      toggle.setAttribute('aria-pressed', String(visible));
      toggle.setAttribute('aria-label', (visible ? '隐藏 ' : '显示 ') + toggle.dataset.secretLabel);
      toggle.title = visible ? '隐藏此值' : '显示此值';
    }};
    const maskAllSecrets = () => visibilityButtons.forEach((toggle) => {{
      const input = document.getElementById(toggle.dataset.target);
      if (input) setSecretVisible(toggle, input, false);
    }});
    visibilityButtons.forEach((toggle) => {{
      const input = document.getElementById(toggle.dataset.target);
      if (!input) return;
      toggle.addEventListener('click', () => {{
        setSecretVisible(toggle, input, input.type === 'password');
      }});
      input.addEventListener('blur', (event) => {{
        if (event.relatedTarget !== toggle) setSecretVisible(toggle, input, false);
      }});
      toggle.addEventListener('blur', (event) => {{
        if (event.relatedTarget !== input) setSecretVisible(toggle, input, false);
      }});
    }});
    document.addEventListener('visibilitychange', () => {{
      if (document.hidden) maskAllSecrets();
    }});
    window.addEventListener('pagehide', maskAllSecrets);
    const json = async (response) => {{
      const body = await response.json().catch(() => ({{}}));
      if (!response.ok) throw new Error(body.error?.message || 'Request failed');
      return body;
    }};
    try {{
      const restored = JSON.parse(sessionStorage.getItem(storageKey) || 'null');
      if (restored?.session_id === sessionId && restored?.csrf_token &&
          restored?.expires_at > Date.now() / 1000) {{
        session = restored; token = null; setReady(true);
        say('安全会话已就绪，可以填写并上传文件。请勿刷新页面。', true);
      }} else {{
        sessionStorage.removeItem(storageKey);
      }}
    }} catch (_) {{ sessionStorage.removeItem(storageKey); }}
    if (!session && !token) {{
      showUnavailable();
    }} else if (!session) {{
      fetch('/api/exchange', {{ method: 'POST', headers: {{
        'Content-Type': 'application/json', 'Accept': 'application/json'
      }}, body: JSON.stringify({{ session_id: sessionId, token }}) }})
        .then(json)
        .then((body) => {{
          session = {{ session_id: body.session_id, csrf_token: body.csrf_token,
            expires_at: body.expires_at }};
          token = null;
          sessionStorage.setItem(storageKey, JSON.stringify(session));
          setReady(true);
          say('安全会话已就绪，可以填写并上传文件。请勿刷新页面。', true);
        }})
        .catch(showUnavailable);
    }}
    form.addEventListener('submit', async (event) => {{
      event.preventDefault();
      if (!session) {{ showUnavailable(); return; }}
      maskAllSecrets();
      setReady(false); say('正在安全写入，请勿关闭页面...', true);
      const values = {{ env: {{}}, files: {{}} }};
      let submissionDispatched = false;
      try {{
        for (const input of form.querySelectorAll('[data-secret-name]')) {{
          const name = input.dataset.secretName;
          if (input.dataset.secretType === 'file') {{
            const file = input.files[0];
            if (!file) continue;
            const bytes = new Uint8Array(await file.arrayBuffer());
            let binary = ''; for (const byte of bytes) binary += String.fromCharCode(byte);
            values.files[name] = {{ filename: file.name, content_base64: btoa(binary) }};
          }} else if (input.value) values.env[name] = input.value;
        }}
        submissionDispatched = true;
        const applied = await fetch(
          '/api/sessions/' + encodeURIComponent(session.session_id) + '/submit', {{
          method: 'POST', headers: {{ 'Content-Type': 'application/json',
            'Accept': 'application/json', 'X-CSRF-Token': session.csrf_token }},
          body: JSON.stringify({{ values }})
        }}).then(json);
        if (applied.status !== 'applied') {{
          showTerminalFailure();
          return;
        }}
        showTerminalState(success);
      }} catch (error) {{
        if (submissionDispatched) {{ showTerminalFailure(); return; }}
        button.textContent = '安全保存';
        say(error.message || '保存失败，请检查输入后重试。', false);
        setReady(true);
      }}
    }});
    cancelButton.addEventListener('click', async () => {{
      if (!session) {{ showUnavailable(); return; }}
      maskAllSecrets();
      setReady(false); say('正在取消...', true);
      try {{
        await fetch(
          '/api/sessions/' + encodeURIComponent(session.session_id) + '/cancel', {{
          method: 'POST', headers: {{ 'Content-Type': 'application/json',
            'Accept': 'application/json', 'X-CSRF-Token': session.csrf_token }},
          body: '{{}}'
        }}).then(json);
        showTerminalState(cancelled);
      }} catch (error) {{
        showCancelUncertain();
      }}
    }});
  }})();
  </script>
</body>
</html>
"""


def render_intake_error(
    *,
    title: str,
    heading: str,
    message: str,
    status_code: int,
    nonce: str,
) -> str:
    """Render a clear explanation page for an unavailable intake link."""

    escaped_title = escape(title, quote=True)
    escaped_heading = escape(heading, quote=True)
    escaped_message = escape(message, quote=True)
    escaped_status_code = escape(str(status_code), quote=True)
    escaped_nonce = escape(nonce, quote=True)
    return f"""<!doctype html>
<html lang="zh-CN">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <meta http-equiv="Cache-Control" content="no-store">
  <title>{escaped_title}</title>
  <style nonce="{escaped_nonce}">
    :root {{
      color-scheme: light;
       --bg: #f2f5f2;
      --card: #ffffff;
       --text: #18201c;
       --muted: #5d665f;
      --error: #b42318;
      --border: #d7deea;
    }}
    * {{ box-sizing: border-box; }}
    body {{
      margin: 0;
      min-height: 100vh;
      display: grid;
      place-items: center;
      padding: 32px;
       background: var(--bg);
      color: var(--text);
      font: 16px/1.5 Inter, Segoe UI, system-ui, -apple-system, sans-serif;
    }}
    main {{
      width: min(720px, 100%);
      background: var(--card);
      border: 1px solid var(--border);
       border-radius: 8px;
      padding: 32px;
       box-shadow: 0 12px 36px rgba(24, 32, 28, 0.08);
    }}
    .eyebrow {{
      display: inline-flex;
      align-items: center;
      gap: 8px;
      color: var(--error);
      font-size: 13px;
      font-weight: 700;
       letter-spacing: 0;
    }}
    h1 {{
      margin: 14px 0 12px;
       font-size: 28px;
      line-height: 1.1;
    }}
    p {{
      margin: 0 0 14px;
      color: var(--muted);
      font-size: 16px;
    }}
    .status {{
      display: inline-block;
      margin-top: 14px;
      padding: 8px 12px;
       border-radius: 6px;
      background: #f8fafc;
      color: var(--muted);
      font-size: 13px;
      border: 1px solid var(--border);
    }}
  </style>
</head>
<body>
  <main>
    <div class="eyebrow">SecretBox 一次性凭据页面</div>
    <h1>{escaped_heading}</h1>
    <p>{escaped_message}</p>
    <p><strong>若需要再次填写，请返回 AI 对话并要求生成新的 SecretBox 链接。</strong></p>
    <div class="status">HTTP {escaped_status_code}</div>
  </main>
</body>
</html>"""


__all__ = ["render_intake", "render_intake_error"]
