---
name: openagent-secretbox
description: Securely collect API keys, passwords, certificates, private keys, environment variables, and other sensitive files for an approved project without placing their values or contents in Hermes chat. Use when Hermes needs user-provided secrets written to a preconfigured local workspace through a loopback browser or to a preconfigured remote server through a fixed HTTPS SecretBox portal.
---

# OpenAgent SecretBox

Use only the SecretBox MCP server already configured by the trusted user. Keep
secret values, uploaded file contents, browser credentials, and destination
file contents outside Hermes.

## Required tools

Use exactly these tools from the configured `openagent-secretbox` server:

- `mcp__openagent_secretbox__open_secret_intake`
- `mcp__openagent_secretbox__get_secret_intake_status`
- `mcp__openagent_secretbox__cancel_secret_intake`

If any tool is unavailable, stop and ask the user to complete the trusted
SecretBox setup. Do not install the package, register MCP, generate an owner
key, configure a workspace, extend an allowlist, set a public origin, start a
gateway, or edit Hermes configuration.

Read [the trusted user boundary](references/trusted-user-boundary.md) before
handling an unfamiliar deployment, a policy rejection, or a suspected
exposure. Use [the request template](templates/request-v1.json) only as a
metadata structure; replace every example need.

## Procedure

### 1. Define metadata

Describe only:

- a short request id and title;
- each input's public name, type, description, and required flag;
- an exact relative `target` for each `file` or `env_file` input;
- a conservative TTL, write policy, size limits, and forbidden targets.

Use `env` for one environment variable, `file` for an uploaded file, and
`env_file` only when the user explicitly wants to paste an environment block
inside SecretBox. Do not put `target` on an `env` need; its effective target is
`write_policy.env_file`. Use `default_value` only for clearly non-secret path
text.

Never ask the user to paste, upload, encode, hash, summarize, or partially
reveal a secret in chat. Never include values, absolute paths,
`workspace_root`, `allowed_targets`, bearer data, or URL fields in the request.
Never target `.git`, source files, executables, shell startup files, or Hermes
configuration.

Keep this write policy unless the trusted service enforces a narrower one:

```json
{
  "env_file": ".env.local",
  "mode": "merge_only",
  "no_overwrite": true,
  "backup": false,
  "max_file_size": 1048576
}
```

Use per-file `max_bytes` and top-level `forbidden_targets` only to narrow the
trusted service policy. Never imply that request metadata can expand the
server's allowlist or size limits.

### 2. Preview and open

Show the title, public input names, effective destination for every input,
required flags, TTL, write policy, size limits, and forbidden targets. For an
`env` need, label `write_policy.env_file` as its effective destination. Obtain
confirmation unless the user already approved those exact fields in the
current turn.

Call `mcp__openagent_secretbox__open_secret_intake` with only `request` and
`ttl_seconds`. A valid request follows this shape:

```json
{
  "request": {
    "schema_version": 1,
    "request_id": "service-setup",
    "title": "Service credential setup",
    "needs": [],
    "forbidden_targets": [".git", "node_modules"],
    "write_policy": {
      "env_file": ".env.local",
      "mode": "merge_only",
      "no_overwrite": true,
      "backup": false,
      "max_file_size": 1048576
    }
  },
  "ttl_seconds": 600
}
```

Populate `needs`. Treat `intake_id` as a non-secret status handle.

### 3. Guide the user by the returned mode

- When `browser_opened` is `true`, tell the user that SecretBox opened a
  single-use page in their local browser. Do not send or request a URL.
- When `browser_opened` is `false` and `portal_url` is present, tell the user to
  open that fixed portal. Relay it only when it is an HTTPS origin root with no
  user info, non-root path, query, or fragment. Do not append `intake_id`, a
  request id, or any other data to it.

The fixed `portal_url` may appear in remote chat because it is a public service
entry point, not an intake credential. Never navigate to, inspect, screenshot,
or authenticate to the portal with an agent browser. Never expose an owner key
or ask the user to return information from the page.

Reject any open result that contains an intake path, session id, token, query,
fragment, or non-HTTPS remote URL. Report a service configuration error without
repeating the suspicious value.

### 4. Poll or cancel

After the user submits, or when they ask for progress, call
`mcp__openagent_secretbox__get_secret_intake_status` with only `intake_id`.
Accept lifecycle statuses only when they are `awaiting_input`, `applied`,
`failed`, `cancelled`, or `expired`. A response with `status: error` is a tool
error, not an intake lifecycle state.

If the user reports that the page was refreshed, closed, or says it can no
longer be opened, poll the same `intake_id`. The fixed portal home page is
reusable, but a selected intake form can be opened only once. Refresh never
authorizes creating a replacement automatically.

Call `mcp__openagent_secretbox__cancel_secret_intake` with only `intake_id` when
the user cancels or a replacement is required after an intake was opened.
Never cancel an unrelated intake.

If cancellation returns `apply_in_progress`, keep polling the same intake until
it reaches `applied` or `failed`. Do not open a replacement while application
is in progress. Open a replacement only after cancellation authoritatively
returns `cancelled`, or after another terminal state is known and the user
confirms a new request. If cancellation returns `awaiting_input`, an error, or
an uncertain result, retain the same `intake_id` and do not create a second
active intake.

Handle every public tool error without inventing status:

- Correct `invalid_ttl` or `invalid_request` metadata and preview it again.
- For `policy_rejected`, ask the trusted operator to review configuration
  outside Hermes; never weaken policy.
- For `too_many_active_intakes`, let the user finish or explicitly cancel a
  known intake before retrying.
- For `server_closed`, `server_unavailable`, `browser_open_failed`, or
  `status_unavailable`, report that SecretBox is unavailable and retry only the
  same safe operation when the user asks.
- For `intake_not_found`, report that the handle is no longer retained and ask
  before preparing a new request.
- For `apply_in_progress`, poll the same intake to a terminal state.

### 5. Report only public results

Report the terminal status and top-level `error_code` when present, plus
declared names, relative targets, write actions, conflict entries, missing
names, and stable codes from `blocked` entries. Do not invent a code for a
conflict entry. Do not verify success by reading destination files, process
environments, logs, hashes, or encoded derivatives.

If the service returns `policy_rejected`, ask the user to review the trusted
workspace and allowlist outside Hermes. Never weaken the policy or reconfigure
the service yourself.

## Hard stops

- Never receive a secret value or sensitive file through chat or a tool
  argument.
- Never run SecretBox bootstrap, server, key-generation, MCP-registration, or
  reverse-proxy commands through Hermes, a subagent, or a scheduled task.
- Never pass `workspace_root` or `allowed_targets` to an intake tool.
- Never open or inspect a SecretBox page or a destination file.
- Never treat output redaction as OS-level isolation.

## Completion check

- Confirm that only the three expected tools were used.
- Confirm that the request contained metadata and relative targets only.
- Confirm that local mode exposed no URL, or remote mode exposed only the fixed
  HTTPS portal root.
- Confirm that no secret, file content, owner key, bearer token, or intake URL
  entered Hermes.
- Confirm that the final report contains only redacted public metadata.
