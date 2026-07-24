# OpenAgent SecretBox

**Secure secret intake for AI agents — let users provide API keys, environment variables, and private files without exposing secrets in chat.**

OpenAgent SecretBox is a local-first credential intake gateway for AI-agent workflows.

It solves a practical contradiction in agent-assisted development:

> Users should not paste secrets into chat, but agents often need secrets to configure projects, deploy services, or connect integrations.

OpenAgent SecretBox gives the agent a safe protocol:

1. The agent declares what secrets it needs.
2. The user enters or uploads those secrets in a separate loopback intake window.
3. SecretBox writes them to approved local targets using safe merge rules.
4. The agent receives only a redacted result: what was written, where it was written, and whether anything is missing or blocked.

The AI agent does **not** need to see the secret values.

---

## Project status

This repository now contains a local-only `0.1.0a1` pre-release MVP. It
includes strict request validation, merge-only writers, path policy checks,
redacted status data, a loopback intake server, and an installable CLI.

It has not received an independent security assessment. Remote intake is not
enabled by the CLI; the supported server binds to `127.0.0.1` only.

Install a development checkout and validate an example:

```bash
uv sync --extra dev
uv run secretbox --json validate examples/openai.request.json
```

Start local intake directly:

```bash
uv run secretbox serve \
  --workspace /path/to/project \
  --request examples/openai.request.json
```

If the request declares `workspace_root`, it must match `--workspace`. By default, SecretBox
opens the one-time intake URL in the user's browser and does not print the bearer
token. The token is carried in a URL fragment, cleared before exchange, and never
sent in an HTTP request path. `--no-open` prints that sensitive URL for headless use; never paste it
into chat, logs, issues, or shell history.

---

## Why this exists

Today, many agent workflows still rely on unsafe patterns:

```text
User: Here is my OPENAI_API_KEY=sk-...
Agent: I will add it to your .env file.
```

That creates several problems:

- secrets enter the chat transcript
- secrets enter the LLM context window
- secrets may be stored by the chat provider
- secrets may be replayed in future agent context
- agents may accidentally print them in logs or summaries
- users are taught the wrong habit

But the opposite instruction is also incomplete:

```text
Do not paste secrets into chat.
```

That is safe advice, but not enough. Many users do not know how to SSH into a server, edit `.env` files, set permissions, merge without overwriting, or upload PEM files correctly.

OpenAgent SecretBox provides the missing middle layer.

---

## Core idea

OpenAgent SecretBox is not just a password manager and not just a file uploader.

It is a **secret intake broker for AI agents**.

The agent can say:

> I need these secret names and private files to complete the setup.

The user provides values through a dedicated intake UI.

SecretBox applies those values according to a strict policy:

- no secret values returned to the agent
- no overwrite by default
- merge-only `.env` updates
- conflict detection
- target path allowlists
- atomic replacement without persistent backup by default
- redacted status output; persistent audit logging remains future work
- restrictive file permissions

---

## The boundary

OpenAgent SecretBox mainly protects against accidental exposure through the AI conversation layer.

It helps keep secrets out of:

- chat messages
- LLM context
- agent summaries
- generated docs
- logs
- git commits

It does **not** magically solve every secret-management problem.

If an agent has unrestricted shell access to the same machine and the same user account, it may still be able to read files after they are written. Stronger protection requires additional isolation, such as:

- separate OS users
- filesystem ACLs
- container boundaries
- process-level secret injection
- cloud KMS / HashiCorp Vault / AWS Secrets Manager / GCP Secret Manager

OpenAgent SecretBox starts with a realistic and valuable goal:

> Keep secrets out of AI chat while still letting agents finish configuration work.

---

## Architecture overview

```text
+---------------------+
|      AI Agent       |
|---------------------|
| Declares required   |
| env vars and files  |
|                     |
| Receives only       |
| redacted status     |
+----------+----------+
           |
           | secret request schema
           v
+----------+----------+
|  OpenAgent SecretBox|
|---------------------|
| one-time sessions   |
| policy engine       |
| env merge writer    |
| file writer         |
+----------+----------+
           ^
           |
           | user submits values
+----------+----------+
|  Loopback Intake UI |
|---------------------|
| paste env vars      |
| paste API keys      |
| upload PEM/JSON     |
| show write policy   |
+----------+----------+
           |
           | controlled writes
           v
+----------+----------+
|   Target Workspace  |
|---------------------|
| .env.local          |
| secrets/*.pem       |
| config/*.json       |
+---------------------+
```

---

## Agent workflow

### 1. Agent creates a secret request

The agent prepares a schema describing the secrets it needs.

Example:

```json
{
  "request_id": "wechat-pay-setup",
  "title": "WeChat Pay setup",
  "workspace_root": "/opt/my-app",
  "needs": [
    {
      "type": "env",
      "name": "WECHAT_PAY_MCH_ID",
      "required": true,
      "description": "WeChat Pay merchant ID"
    },
    {
      "type": "env",
      "name": "WECHAT_PAY_API_V3_KEY",
      "required": true,
      "description": "WeChat Pay API v3 key"
    },
    {
      "type": "file",
      "name": "apiclient_key.pem",
      "required": true,
      "target": "secrets/apiclient_key.pem",
      "description": "Merchant private key PEM file"
    }
  ],
  "write_policy": {
    "env_file": ".env.local",
    "mode": "merge_only",
    "no_overwrite": true,
    "backup": false
  }
}
```

### 2. SecretBox opens an intake session

A local-only intake URL is generated. The session id is sent in the path while
the bearer token remains in the browser fragment:

```text
http://127.0.0.1:17321/intake/ses_random#token=one-time-token
```

The token should be:

- high entropy
- bound to one request
- short-lived
- consumed atomically during the initial session exchange

### 3. User enters values outside the chat

The user can:

- paste individual API keys
- paste `.env`-style variables
- upload private files such as `.pem`, `.json`, `.p12`
- review declared targets and the enforced write policy
- cancel the session without submitting values

Values go directly to SecretBox, not to the chat.

### 4. SecretBox writes safely

For environment files:

- parse existing `.env` file if present
- preserve existing comments and unrelated values where possible
- append missing values
- skip identical values
- block changed values; the alpha CLI has no overwrite approval path
- avoid persistent backups, which would create another secret copy

For uploaded files:

- normalize and validate paths
- reject path traversal
- restrict writes to allowed targets
- write with restrictive permissions
- avoid echoing content in logs or responses

### 5. Agent receives redacted result

Example:

```json
{
  "request_id": "wechat-pay-setup",
  "status": "applied",
  "written": [
    {
      "type": "env",
      "name": "WECHAT_PAY_MCH_ID",
      "target": ".env.local",
      "action": "added"
    },
    {
      "type": "env",
      "name": "WECHAT_PAY_API_V3_KEY",
      "target": ".env.local",
      "action": "added"
    },
    {
      "type": "file",
      "name": "apiclient_key.pem",
      "target": "secrets/apiclient_key.pem",
      "action": "created",
      "mode": "0600"
    }
  ],
  "conflicts": [],
  "missing": []
}
```

No secret value appears in this response.

---

## Command-line interface

Validate request metadata without accepting secret values:

```bash
secretbox --json validate ./secret-request.json
```

Create a local metadata-only registry entry. `request create` is an alias:

```bash
secretbox create ./secret-request.json
secretbox request create ./secret-request.json
```

This registry is optional in `0.1.0a1`. It is not connected to a running
`serve` process: `status` reports only the metadata record created by `create`,
while `serve` waits and returns its own final redacted result.

Start a one-time loopback intake session:

```bash
secretbox serve \
  --workspace /path/to/project \
  --request ./secret-request.json \
  --ttl 600
```

The trusted CLI policy authorizes `.env`, `.env.*`, and `secrets/*` by default.
Use a repeated `--allow-target PATTERN` option to authorize an additional target;
request-provided allowlists can narrow access but cannot expand this host policy.
Uploads are limited to 10 MiB per declared file and 16 MiB for the complete HTTP request.

The person running `secretbox serve` is the policy authority. Do not let an
untrusted agent choose `--workspace` or `--allow-target`. This local MVP reduces
chat leakage and accidental writes; it does not isolate an agent that already has
unrestricted shell access as the same OS user.

```bash
secretbox status <request-id>
```

```bash
secretbox doctor --workspace /path/to/project
```

Add `--json` before or after a command for machine-readable output. Unsupported
or invalid operations return a non-zero exit code. Secret values are never accepted
as command-line arguments.

With `--json --no-open`, stdout is a two-line JSON event stream: the first event
is `awaiting_input` and contains the explicitly marked sensitive bearer URL; the
second is the final redacted `applied`, `failed`, or `expired` result. Do not send
the first event to shared logs.

### MCP agent integration

Install the optional MCP support:

```bash
python -m pip install -e ".[mcp]"
```

Configure an MCP client to start SecretBox over stdio with a workspace chosen by
the trusted user:

```json
{
  "mcpServers": {
    "openagent-secretbox": {
      "command": "secretbox-mcp",
      "args": ["--workspace", "/absolute/path/to/project"]
    }
  }
}
```

The server exposes three tools:

| Tool | Purpose |
|---|---|
| `open_secret_intake` | Validate metadata and open the one-time form directly in the local browser |
| `get_secret_intake_status` | Return lifecycle state and a structured, redacted write result |
| `cancel_secret_intake` | Atomically cancel before secret application starts |

The MCP process fixes `--workspace`, the host target allowlist, and the maximum
active intake count at startup. Tool arguments cannot change those controls.
The open tool returns an opaque MCP intake handle for status and cancellation,
but never returns the browser session id, bearer URL, URL fragment, or token.
Browser launch failure closes the listener and returns a stable error code.

TTL limits how long a user may begin submission. Once secret application has
started, it runs to an authoritative `applied` or `failed` result and cannot be
safely interrupted. A concurrent cancel returns `apply_in_progress`; poll status
for the real terminal result. SecretBox never reports `cancelled` while writes
may still complete.

`--allow-target` expands write authority and therefore belongs only in
user-reviewed MCP startup configuration. Do not let an agent construct the MCP
server command or pass secret values in request metadata. The stdio process
reserves stdout for MCP protocol frames and closes all active listeners on exit.

See [the result protocol](./docs/result-protocol.md), its
[JSON Schema](./schemas/result-v1.json), and the
[Hermes integration](./integrations/hermes/README.md). When installing the Hermes
skill from a direct URL, verify that the installed directory contains
`SKILL.md`, `references/trusted-user-boundary.md`, and
`templates/request-v1.json`; an exit code of 0 can still leave a partial install.
The sensitive bootstrap event emitted by CLI `--no-open --json` is deliberately
outside the agent-safe result protocol.

Later versions may support controlled command execution:

```bash
secretbox run --env .env.local -- npm run deploy
```

In that mode, secrets are injected into a child process but are still not printed back to the agent.

---

## Write policy

OpenAgent SecretBox should default to conservative behavior.

`0.1.0a1` guarantees atomic replacement per target file, not a distributed
transaction across several targets. If a later target is blocked after an earlier
write succeeds, the result is explicitly `partial` and the intake UI does not
report success.

### Environment files

| Situation | Default behavior |
|---|---|
| variable does not exist | add it |
| variable exists with same value | skip |
| variable exists with different value | block and report conflict |
| variable exists but is empty | block and report conflict |
| multi-line secret | prefer file write plus `*_PATH` env var |

### Files

| Situation | Default behavior |
|---|---|
| target file does not exist | create with restrictive permissions |
| target file exists with identical content | verify/repair owner-only permissions, then skip |
| target file exists with different content | block in the alpha CLI |
| target path escapes workspace | reject |
| target path is not allowlisted | reject |
| upload exceeds size limit | reject |

---

## Path policy

A request describes desired targets but does not authorize them. The trusted CLI
policy defines where SecretBox may write.

Example host authorization:

```bash
secretbox serve --workspace /opt/my-app --request request.json \
  --allow-target "config/*.json"
```

Rules:

- all relative paths are resolved under `workspace_root`
- absolute targets are always rejected
- `..` path traversal is rejected after normalization
- symlinks, Windows reparse points/junctions, and hard-linked files are rejected

---

## Audit logs

Persistent audit logging is not implemented in `0.1.0a1`. A future audit backend
must use an allowlisted metadata schema and never log intake bodies or values.

Example:

```json
{
  "time": "2026-07-23T15:30:12+08:00",
  "request_id": "wechat-pay-setup",
  "workspace_root": "/opt/my-app",
  "actions": [
    {
      "type": "env",
      "name": "WECHAT_PAY_MCH_ID",
      "target": ".env.local",
      "action": "added"
    },
    {
      "type": "file",
      "name": "apiclient_key.pem",
      "target": "secrets/apiclient_key.pem",
      "action": "created",
      "mode": "0600"
    }
  ]
}
```

Audit logs must never include:

- API key values
- private key bodies
- full bearer tokens
- secret file contents
- raw uploaded request bodies

---

## Modes

### Local mode

Best for local development.

```text
Agent starts SecretBox on localhost.
User opens a browser window.
SecretBox writes into the local project workspace.
```

### Remote server mode

Remote intake is not implemented or supported by the current CLI. The following
describes a future deployment mode and must not be treated as an operating guide.

```text
Agent starts a temporary SecretBox intake service on the server.
User receives a one-time URL.
User uploads or pastes secrets.
SecretBox writes directly on the server.
The intake service shuts down after completion or TTL expiry.
```

Remote mode needs stricter protection:

- one-time token
- short TTL
- HTTPS required
- no request-body logging
- upload size limits
- bind to expected host/interface
- optional reverse tunnel or gateway integration

### Agent platform integration mode

Best for AI platforms and agent UIs.

```text
The agent platform hosts the intake UI.
SecretBox exposes a controlled backend API.
The agent can create requests and poll status.
The user provides values outside the chat message stream.
```

This can later integrate with platforms such as Hermes Agent, MCP-compatible agents, CLI agents, IDE agents, or hosted agent dashboards.

---

## Threat model

### Protected against

- users accidentally pasting secrets into AI chat
- agents accidentally repeating secrets in summaries
- secrets appearing in generated README files
- simple `.env` overwrite mistakes
- path traversal in upload targets
- accidental commits of common secret files through `.gitignore`

### Not fully protected against

- compromised host machine
- malicious agent with unrestricted shell access
- malicious project code that prints env vars
- secret exfiltration by dependencies during runtime
- terminal history or process list leaks outside SecretBox control
- cloud provider or operating system compromise

### Future hardening options

- separate `secretbox` OS user
- separate `agent` OS user
- write secrets readable only by app runtime user
- use Unix sockets with access control
- encrypted-at-rest local vault
- pass secrets only via subprocess environment
- KMS backend support
- hardware-backed secure storage where available

---

## MVP roadmap

### Phase 0 — Documentation and design

- [x] Define project purpose
- [x] Define core architecture
- [x] Define safety boundary
- [x] Define MVP behavior
- [x] Add ADRs for key security decisions

### Phase 1 — Python single-file prototype

- [x] Parse request schema JSON
- [x] Start loopback-only HTTP intake server
- [x] Generate one-time token
- [x] Render intake form
- [x] Accept declared env values and file content
- [x] Write `.env.local` with merge-only behavior
- [x] Write declared private files under allowlisted targets
- [x] Apply POSIX `0600` or an explicit current-user Windows DACL
- [x] Generate redacted status JSON
- [x] Auto-shutdown after success or TTL

### Phase 2 — CLI package

- [x] `secretbox request create`
- [x] `secretbox serve`
- [x] `secretbox status`
- [x] `secretbox doctor`
- [x] installable Python package
- [x] tests for request schema, env merge, path policy, server, and CLI

### Phase 3 — Agent integration

- [x] agent-facing request schema examples
- [x] Hermes skill integration
- [x] MCP server or tool wrapper
- [x] structured redacted result protocol
- [x] examples for common services: OpenAI, Anthropic, Supabase, Stripe, WeChat Pay

### Phase 4 — Hardening

- [ ] encrypted local request store
- [x] restrictive browser security headers
- [x] CSRF and loopback Host/Origin protection
- [ ] upload MIME and extension policies
- [x] symlink and Windows reparse-point rejection
- [x] Windows owner-only DACL behavior
- [ ] remote HTTPS deployment guide
- [ ] optional OS-user isolation guide

---

## Example use cases

### API key setup

The agent needs:

```text
OPENAI_API_KEY
ANTHROPIC_API_KEY
SUPABASE_SERVICE_ROLE_KEY
```

SecretBox writes them to `.env.local` without ever returning the values to the agent.

### Private key upload

The user uploads:

```text
apiclient_key.pem
```

SecretBox writes:

```text
secrets/apiclient_key.pem
```

and adds:

```env
WECHAT_PAY_PRIVATE_KEY_PATH=./secrets/apiclient_key.pem
```

### Service account JSON

The user uploads:

```text
google-service-account.json
```

SecretBox writes:

```text
secrets/google-service-account.json
```

and adds:

```env
GOOGLE_APPLICATION_CREDENTIALS=./secrets/google-service-account.json
```

---

## Design principles

1. **Secrets should not enter chat.**
2. **Agents declare needs; users provide values.**
3. **The agent receives status, not secrets.**
4. **Merge beats replace.**
5. **Conflict beats silent overwrite.**
6. **Every write should be auditable.**
7. **Every secret target should be policy-bound.**
8. **A small safe tool is better than a large magical one.**
9. **Be honest about the boundary.**
10. **Security behavior must be the default, not an advanced option.**

---

## Repository structure

```text
OpenAgent-secretbox/
|-- .github/workflows/ci.yml
|-- README.md
|-- SECURITY.md
|-- pyproject.toml
|-- uv.lock
|-- schemas/request-v1.json
|-- schemas/result-v1.json
|-- src/openagent_secretbox/
|   |-- cli.py
|   |-- mcp_server.py
|   |-- models.py
|   |-- policy.py
|   |-- protocol.py
|   |-- redaction.py
|   |-- schema.py
|   |-- server.py
|   |-- templates.py
|   `-- writers.py
|-- examples/
|-- integrations/hermes/
|-- docs/
`-- tests/
```

---

## Contributing

This project welcomes contributions, especially around:

- secure `.env` merging
- path allowlist policy
- local web intake UX
- CLI design
- agent integration protocols
- threat modeling
- tests for unsafe edge cases

Please read [SECURITY.md](./SECURITY.md) before contributing.

Do not include real credentials in issues, pull requests, logs, screenshots, tests, or examples.

---

## License

MIT License. See [LICENSE](./LICENSE).
