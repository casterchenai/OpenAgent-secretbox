# OpenAgent SecretBox

**Secure secret intake for AI agents — let users provide API keys, environment variables, and private files without exposing secrets in chat.**

OpenAgent SecretBox is a local-first credential intake gateway for AI-agent workflows.

It solves a practical contradiction in agent-assisted development:

> Users should not paste secrets into chat, but agents often need secrets to configure projects, deploy services, or connect integrations.

OpenAgent SecretBox gives the agent a safe protocol:

1. The agent declares what secrets it needs.
2. The user enters or uploads those secrets in an isolated intake window.
3. SecretBox writes them to approved local targets using safe merge rules.
4. The agent receives only a redacted result: what was written, where it was written, and whether anything is missing or blocked.

The AI agent does **not** need to see the secret values.

---

## Project status

This repository is at the initial design and MVP planning stage.

The first milestone is a small Python-based prototype:

- local web intake page
- one-time request token
- `.env` merge-only writer
- private file upload into `secrets/`
- automatic backups
- `0600` file permissions where supported
- redacted JSON status output for agents

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
- automatic backup before write
- redacted audit logs
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
| Request registry    |
| policy engine       |
| env merge writer    |
| file writer         |
| audit logger        |
+----------+----------+
           ^
           |
           | user submits values
+----------+----------+
|  Isolated Intake UI |
|---------------------|
| paste env vars      |
| paste API keys      |
| upload PEM/JSON     |
| approve conflicts   |
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
    "backup": true
  }
}
```

### 2. SecretBox opens an intake session

A local or remote intake URL is generated:

```text
http://127.0.0.1:17321/intake?token=one-time-token
```

The token should be:

- high entropy
- bound to one request
- short-lived
- single-use after successful apply

### 3. User enters values outside the chat

The user can:

- paste individual API keys
- paste `.env`-style variables
- upload private files such as `.pem`, `.json`, `.p12`
- review conflicts
- approve or reject overwrites if policy allows it

Values go directly to SecretBox, not to the chat.

### 4. SecretBox writes safely

For environment files:

- parse existing `.env` file if present
- preserve existing comments and unrelated values where possible
- append missing values
- skip identical values
- block changed values unless explicitly approved
- back up before modification

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

## Proposed command-line interface

The exact CLI may change. The MVP can start with commands like these:

```bash
secretbox request create ./secret-request.json
```

```bash
secretbox serve \
  --workspace /path/to/project \
  --request ./secret-request.json \
  --ttl 600
```

```bash
secretbox status <request-id>
```

```bash
secretbox doctor --workspace /path/to/project
```

Later versions may support controlled command execution:

```bash
secretbox run --env .env.local -- npm run deploy
```

In that mode, secrets are injected into a child process but are still not printed back to the agent.

---

## Write policy

OpenAgent SecretBox should default to conservative behavior.

### Environment files

| Situation | Default behavior |
|---|---|
| variable does not exist | add it |
| variable exists with same value | skip |
| variable exists with different value | block and report conflict |
| variable exists but is empty | add only with approval or policy rule |
| multi-line secret | prefer file write plus `*_PATH` env var |

### Files

| Situation | Default behavior |
|---|---|
| target file does not exist | create with restrictive permissions |
| target file exists | block unless overwrite is explicitly allowed |
| target path escapes workspace | reject |
| target path is not allowlisted | reject |
| upload exceeds size limit | reject |

---

## Path policy

A request should define where SecretBox is allowed to write.

Example:

```json
{
  "workspace_root": "/opt/my-app",
  "allowed_targets": [
    ".env",
    ".env.local",
    "secrets/*",
    "config/*.json"
  ],
  "forbidden_targets": [
    ".git/*",
    "node_modules/*",
    "/etc/*",
    "/root/.ssh/*"
  ]
}
```

Rules:

- all relative paths are resolved under `workspace_root`
- absolute targets are rejected unless explicitly allowed by policy
- `..` path traversal is rejected after normalization
- symlinks require special handling and should be rejected in the MVP

---

## Audit logs

OpenAgent SecretBox should produce useful audit logs without leaking secrets.

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
  ],
  "backup": ".env.local.backup.20260723-153012"
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

Best for cloud instances or remote deployments.

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
- HTTPS preferred
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
- [ ] Add ADRs for key security decisions

### Phase 1 — Python single-file prototype

- [ ] Parse request schema JSON
- [ ] Start local HTTP intake server
- [ ] Generate one-time token
- [ ] Render intake form
- [ ] Accept env values and file uploads
- [ ] Write `.env.local` with merge-only behavior
- [ ] Write uploaded files under `secrets/`
- [ ] Apply `0600` permissions
- [ ] Generate redacted status JSON
- [ ] Auto-shutdown after success or TTL

### Phase 2 — CLI package

- [ ] `secretbox request create`
- [ ] `secretbox serve`
- [ ] `secretbox status`
- [ ] `secretbox doctor`
- [ ] installable Python package
- [ ] tests for env merge and path policy

### Phase 3 — Agent integration

- [ ] agent-facing request schema examples
- [ ] Hermes skill integration
- [ ] MCP server or tool wrapper
- [ ] structured redacted result protocol
- [ ] examples for common services: OpenAI, Anthropic, Supabase, Stripe, WeChat Pay

### Phase 4 — Hardening

- [ ] encrypted local request store
- [ ] stronger browser security headers
- [ ] CSRF protection
- [ ] upload MIME and extension policies
- [ ] symlink safety
- [ ] Windows permission behavior
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

## Possible repository structure

```text
OpenAgent-secretbox/
├── README.md
├── SECURITY.md
├── LICENSE
├── pyproject.toml
├── src/
│   └── openagent_secretbox/
│       ├── __init__.py
│       ├── cli.py
│       ├── server.py
│       ├── schema.py
│       ├── policy.py
│       ├── env_writer.py
│       ├── file_writer.py
│       └── audit.py
├── examples/
│   ├── openai.request.json
│   ├── supabase.request.json
│   └── wechat-pay.request.json
├── docs/
│   ├── threat-model.md
│   ├── request-schema.md
│   └── decisions/
│       └── ADR-001-local-first-secret-intake.md
└── tests/
    ├── test_env_writer.py
    ├── test_policy.py
    └── test_redaction.py
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
