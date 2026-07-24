---
name: openagent-secretbox
description: "Open local secret intake without exposing secret values. Use when credentials, API keys, tokens, env vars, or secret files must be written locally without pasting values into chat. Default MCP workspace is the host-registered path (often ~/.hermes/workspaces/default); agents never choose or override it unless the user explicitly directs a trusted re-registration outside chat."
version: 1.2.0
author: casterchenai
license: MIT
platforms: [linux, macos, windows]
metadata:
  hermes:
    tags: [security, secrets, credentials, local-first, mcp]
    category: security
---

# OpenAgent SecretBox Skill

Open a policy-bound local browser intake while keeping bearer URLs, secret
values, and target-file contents outside Hermes. Prefer the preconfigured
SecretBox MCP tools; use the user-launched CLI flow only as a fallback.

## When to Use

- Use when a local project needs API keys, tokens, passwords, certificates,
  private keys, or other credentials written to `.env`, `.env.*`, or
  `secrets/*`.
- Use when the user wants a browser intake instead of pasting a value into chat.
- Do not use this skill to read, rotate, transform, test, or display an existing
  secret.
- Do not use it for remote intake. The supported flow is loopback-only on the
  trusted user's machine.

## Default workspace rule (agent-critical)

Unless the user **explicitly** names a different trusted workspace and directs
a trusted-terminal reconfiguration, treat the pre-registered MCP workspace as
the only write root.

| Situation | Agent behavior |
|---|---|
| User says "set up API key / secret / .env" with no path | Use MCP as-is. Do **not** ask for a workspace path. |
| User says "for this project" but MCP is already registered | Still use the registered default. Report that secrets land under the MCP workspace (for example `~/.hermes/workspaces/default`). Do not invent a project path. |
| User explicitly wants project-local secrets under `/path/to/project` | Stop. Tell the user that workspace is fixed at MCP startup. Offer the trusted-terminal re-register command for that absolute path. Do not edit Hermes config yourself. |
| MCP tools missing | Manual fallback only. Prefer default workspace `~/.hermes/workspaces/default` (expand to absolute) unless the user already named another absolute path. |

Canonical host default used by this integration when the trusted user wants
all sessions to share one secret root:

```text
~/.hermes/workspaces/default
```

On a typical Linux Hermes host that expands to:

```text
/root/.hermes/workspaces/default
```

or `$HOME/.hermes/workspaces/default` for a non-root install. Agents never pass
this path in MCP request objects; they only report it when explaining where
files will land.

Default host allowlist (startup policy, not agent input):

- `.env`
- `.env.*`
- `secrets/*`

Relative targets in requests (for example `.env.local`, `secrets/key.pem`) are
always resolved under that fixed workspace.

## Prerequisites

Prefer these exact tools from the user-configured `openagent-secretbox` MCP
server:

- `mcp__openagent_secretbox__open_secret_intake`
- `mcp__openagent_secretbox__get_secret_intake_status`
- `mcp__openagent_secretbox__cancel_secret_intake`

The trusted user, not the agent, must register that server with a fixed
workspace and host allowlist. Recommended default for host-wide use:

```yaml
mcp_servers:
  openagent-secretbox:
    command: /absolute/path/to/secretbox-mcp
    args:
      - --workspace
      - /absolute/path/to/.hermes/workspaces/default
    enabled: true
```

If the tools are absent, do not run `hermes mcp add` or edit Hermes config. Use
the manual fallback below and point the user to the integration install
instructions.

Read [the trusted user boundary](references/trusted-user-boundary.md) before
using an unfamiliar service or a target beyond the default allowlist.

## How to Run

Invoke this skill with credential names and the intended task, never credential
values:

```text
/openagent-secretbox prepare OPENAI_API_KEY for local setup
```

Do not require the user to supply a workspace path. Use the pre-registered MCP
workspace automatically.

Use [the request template](templates/request-v1.json) as a structural starting
point. Replace or remove every example need before opening intake.

## Quick Reference

| Actor | Allowed | Forbidden |
|---|---|---|
| Hermes | Define metadata; call MCP open/status/cancel; report redacted status and default relative targets | Receive values; choose/pass workspace or host allowlist; receive or open intake URLs; inspect targets; edit MCP config |
| Trusted user | Register fixed MCP policy (prefer `~/.hermes/workspaces/default`); review targets; use local browser | Paste URL tokens or values into chat |
| SecretBox MCP | Apply startup policy; open browser server-side; return ids/status only | Return URL, token, session id, or submitted values |

Hard stops:

- Never ask for or accept a secret value through chat or a tool argument.
- Never ask "which workspace?" when MCP is already registered. Use the default.
- Never call `secretbox serve`, `secretbox-mcp`, or `hermes mcp add` through
  `terminal`, a subagent, a script, a scheduled job, or another agent tool.
- Never navigate to, poll, inspect, or screenshot an `/intake/` URL with Hermes.
- Never pass `workspace_root` or `allowed_targets` in the MCP request object.

## Procedure

### 1. Select the path

Use MCP when all three exact tools listed under Prerequisites are available.
Otherwise use Manual Fallback. Do not silently substitute a similarly named MCP
server because its startup workspace and policy may differ.

Completion criterion: the chosen path is either the exact trusted MCP server or
the explicit user-launched fallback.

### 2. Define metadata only

Identify:

- a short request id and title;
- each input's non-secret name, type, description, and relative target;
- whether each input is required.

Ask only for missing metadata. Never ask the user to paste, upload, describe,
partially reveal, hash, encode, or confirm a secret value in chat. Never ask
for a workspace path unless the user is deliberately changing trusted policy.

Use `env` for one environment variable, `file` for a private file, and
`env_file` only when the user explicitly wants to paste an environment block in
the SecretBox browser. Use `default_value` only for a clearly non-secret path
such as `./secrets/client.pem`; omit it when uncertain.

The request object must omit `workspace_root` and `allowed_targets`. They are
trusted MCP startup controls, not agent inputs. Keep these policy values:

```json
{
  "schema_version": 1,
  "write_policy": {
    "env_file": ".env.local",
    "mode": "merge_only",
    "no_overwrite": true,
    "backup": false
  }
}
```

Never propose `.git`, source files, executables, shell startup files, Hermes
configuration, or absolute/traversing paths as targets.

If a value or intake URL has already entered chat or tool output, do not quote
it. Follow Exposure Response in the trusted-boundary reference.

Completion criterion: every need is expressible without a value, workspace, or
host-policy argument.

### 3. Preview the request

Show only the title, variable/input names, relative targets, required flags,
TTL, enforced write policy, and a one-line reminder that writes go under the
pre-registered MCP workspace (default host root: `~/.hermes/workspaces/default`).
Obtain confirmation unless the user already approved those exact fields in the
current turn. Do not display placeholders that could be mistaken for real
credentials.

Completion criterion: the user can see every proposed write target before the
browser accepts values.

### 4. Open with MCP

Call `mcp__openagent_secretbox__open_secret_intake` with exactly:

```json
{
  "request": {
    "schema_version": 1,
    "request_id": "service-local-setup",
    "title": "Service local credential setup",
    "needs": [],
    "write_policy": {
      "env_file": ".env.local",
      "mode": "merge_only",
      "no_overwrite": true,
      "backup": false
    }
  },
  "ttl_seconds": 600
}
```

Populate `needs`; do not add `workspace_root`, `allowed_targets`, values, or URL
fields. The expected result contains `schema_version`, `intake_id`,
`request_id`, `status`, `expires_at`, and `browser_opened` only. `intake_id` is
a non-secret status handle and may remain in context.

Tell the user that SecretBox opened a one-time form. On **desktop** hosts the
OS browser opens automatically. On **headless / Hermes Web UI** hosts with UI
handoff configured, tell the user to open the bookmarked SecretBox form index
(for example `http://HOST:8787/`) and click the pending title — never invent or
paste intake URLs yourself.

Do not ask them to send anything from the page back to chat except a status-only
word such as `applied`.

If MCP returns `invalid_request` or `policy_rejected`, fix metadata or ask the
user to review trusted policy. Never weaken write policy or configure a broader
workspace/allowlist yourself. If it returns `browser_open_failed` or
`server_unavailable`, do **not** pretend a chat form exists. Report that handoff
is not configured / browser open failed, and ask the user whether to enable UI
handoff (trusted terminal) or cancel. Do not fall back to printing
`secretbox serve` as if it were a conversation form.

Completion criterion: the result is `awaiting_input`, contains no URL/token,
and the user's local browser is open.

### 5. Check or cancel safely

After the user submits, or when they ask for progress, call
`mcp__openagent_secretbox__get_secret_intake_status` with only `intake_id`.
Accept only redacted statuses: `awaiting_input`, `applied`, `failed`,
`cancelled`, or `expired`.

Call `mcp__openagent_secretbox__cancel_secret_intake` with only `intake_id` when
the user cancels, a preview was wrong, or a replacement intake is required.
Never cancel an unrelated id.

If cancel returns `apply_in_progress`, secret application has already started.
Do not retry cancellation and do not open a replacement intake. Poll that same
`intake_id` until it reaches `applied` or `failed`, then report the real result.

On success, report only declared names, relative target paths, write actions,
and redacted status. Optionally remind that absolute paths are under the
registered workspace root. Never verify by reading `.env`, file contents,
process environments, logs, hashes, or encoded derivatives.

Completion criterion: a terminal redacted status is reported and no submitted
value entered Hermes.

## Manual Fallback

Use this only when the trusted MCP tools are absent or unavailable.

1. Choose workspace:
   - user-named absolute path if they explicitly provided one in this turn;
   - otherwise default to `~/.hermes/workspaces/default` expanded to an absolute
     path (create nothing with elevated privileges; tell the user if missing).
2. Write the metadata-only request JSON under
   `<workspace>/.secretbox/requests/<request-id>.json` or another untracked
   path. Omit `workspace_root`, `allowed_targets`, and all values.
3. Run only `secretbox validate "<absolute-request-path>"`. Do not start intake.
4. Print one reviewed command:

```bash
secretbox serve --workspace "<absolute-workspace-path>" --request "<absolute-request-path>"
```

Precede it with: "Run this yourself in a separate trusted local terminal, not
through Hermes." Do not execute it or add `--no-open`, `--json`,
`--allow-target`, `--host`, or a fixed port.

If browser auto-open fails, the user may privately add `--no-open` in their
trusted terminal. They must not paste the printed URL into chat, logs, issues,
or a remote messaging gateway. Wait for status-only user confirmation; the MCP
status tools do not own or track this fallback intake.

Completion criterion: the user runs the fallback, no intake URL appears in
agent-visible output, and the user reports only a redacted outcome.

## Pitfalls

- Running `hermes mcp add` from an agent tool lets the agent choose the trusted
  workspace. Registration belongs to a separate user-controlled terminal.
- Do not ask the user for a workspace on every secret request. Default to the
  registered MCP root / `~/.hermes/workspaces/default`.
- On some Hermes CLI builds, `hermes mcp add ... --args --workspace PATH` may
  misparse `--workspace` as a Hermes flag. Prefer writing the absolute command
  and args into `~/.hermes/config.yaml` from a trusted terminal, then
  `hermes mcp test openagent-secretbox`.
- MCP request `workspace_root` and `allowed_targets` are unnecessary authority
  assertions. Omit them even though request schema v1 accepts them.
- Manual `secretbox serve --no-open --json` emits the bearer URL. It is
  forbidden in agent-visible execution.
- Hermes skill `metadata.hermes.config` values are injected into skill context.
  Never declare credentials there or add `setup.collect_secrets` entries.
- Existing conflicting values are blocked by design. Do not read the old value
  or weaken no-overwrite; tell the user to resolve ownership outside Hermes.
- Output redaction and stdio environment filtering are not containment. An
  unrestricted local Hermes process can still read files available to its OS
  identity.
- Writing project app secrets into the host default workspace is intentional for
  agent convenience. If the app must read secrets from a project directory, the
  trusted user must re-register MCP for that project path or copy/symlink
  outside chat after apply.

## Verification

- [ ] The trusted user configured MCP workspace/allowlist outside Hermes.
- [ ] Unless the user explicitly overrode policy, the agent used the default
      registered workspace and did not solicit a path.
- [ ] The request contains metadata only and omits workspace/allowed targets.
- [ ] No secret, encoded secret, bearer token, or intake URL entered Hermes.
- [ ] MCP open returned only an intake id, redacted status, and expiry metadata.
- [ ] Hermes never opened or inspected the intake page or destination files.
- [ ] Final reporting contains only redacted status, names, and relative paths.
- [ ] Strict-separation deployments use an OS or whole-process boundary.
