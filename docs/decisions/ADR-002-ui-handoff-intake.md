# ADR-002: UI handoff intake for headless / remote Web UI hosts

Status: Accepted  
Date: 2026-07-24

## Context

MVP SecretBox opens a loopback intake URL with the OS desktop browser
(`webbrowser.open`) and never returns that URL through MCP. That is correct for
a desktop agent session.

It fails when Hermes runs on a remote/headless host (no `DISPLAY`, no local
browser) while the user interacts through Hermes Web UI in their own browser.
Users then cannot fill the form “in conversation” and fall back to terminal
commands, which is not the product goal.

Remote raw intake URLs must still not enter chat/LLM context (token fragments
are secrets).

## Decision

Add a **trusted UI handoff** path alongside desktop browser open:

1. MCP process still starts loopback intake (`127.0.0.1` only).
2. If desktop browser open fails **and** a trusted handoff is configured, SecretBox
   posts the full loopback intake URL (including fragment token) to a local
   handoff service over loopback HTTP with a shared secret.
3. The handoff service exposes a **separate public page** on a configured host/port
   (for example host LAN IP or reverse-proxy URL). That page does **not** embed the
   bearer in agent-visible MCP results.
4. MCP returns only:
   - `intake_id`
   - redacted status
   - `browser_opened: true` when either desktop browser or handoff publish succeeds
   - optional non-secret `ui_hint` string such as `open the SecretBox form tab / handoff page`
5. Agents still must not open, poll, or paste intake URLs. Users open the handoff
   page themselves (bookmark or Web UI link).

## Non-goals (this ADR)

- Putting intake URLs into chat messages or MCP tool results
- Binding SecretBox intake itself to a non-loopback interface
- Replacing Hermes Web UI’s built-in components (third-party package)

## Security controls

| Control | Requirement |
|---|---|
| Handoff channel | Loopback only (`127.0.0.1`) between SecretBox MCP and bridge |
| Auth | Shared secret header `X-SecretBox-Handoff-Token` required on publish |
| Public page | HTTPS preferred when exposed beyond localhost; no secret values in query logs |
| TTL | Handoff pages expire with intake TTL; cancel clears public form |
| Agent surface | No URL/token/session id in MCP results beyond opaque `intake_id` |
| Write policy | Unchanged: fixed workspace + allowlist + merge_only + no_overwrite |

## Alternatives considered

1. **Return URL to agent** — rejected (chat leakage).
2. **Only manual `secretbox serve --no-open`** — rejected for UX on remote hosts.
3. **Patch hermes-web-ui dist in place** — deferred; third-party binary package.
   Bridge can sit beside Web UI until upstream embeds a native form widget.

## Consequences

- Default desktop behavior stays unchanged when `webbrowser.open` works.
- Headless hosts enable `--ui-handoff-url` + token on `secretbox-mcp`.
- Skill docs teach agents: on success, tell the user to open the handoff page,
  never ask for values in chat, poll status by `intake_id` only.
