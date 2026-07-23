# Threat Model

OpenAgent SecretBox is designed to reduce secret exposure in AI-agent workflows.

## Primary security goal

Keep sensitive values out of AI chat messages, LLM context windows, generated documentation, and routine agent logs while still allowing agents to complete configuration tasks.

## In scope

- API keys
- environment variables
- private key files
- service account JSON files
- payment provider certificates
- local project configuration workflows through a loopback-only intake service

## Out of scope for MVP

- protecting secrets from a fully compromised host
- preventing a same-user unrestricted shell agent from reading files after write
- enterprise-grade KMS replacement
- secret rotation
- long-term encrypted secret storage
- cloud IAM governance
- remote or non-loopback intake

## Main risks

### Chat leakage

Users paste secrets into chat. The model, platform, transcript, and future context may retain them.

Mitigation: provide a separate intake UI and teach agents to request secrets by schema rather than asking for raw values.

### Accidental overwrite

Agents replace existing `.env` files or break runtime settings.

Mitigation: merge-only atomic writes and conflict blocking. The alpha CLI has no
overwrite approval path.
Persistent backups are disabled by the CLI because they create another secret copy.

### Path traversal

A malicious or buggy request tries to write outside the project workspace.

Mitigation: normalize targets, reject `..`, use allowlists, reject symlinks in MVP.

Residual risk: path checks are best-effort and path-based. A malicious process
running concurrently as the same OS user may race filesystem changes; that actor
is outside the MVP boundary.

### Log leakage

Secret values appear in status responses, logs, exceptions, or test output.

Mitigation: centralized redaction rules and tests that assert secret values never appear in agent-facing results.

### Agent tool boundary

An agent attempts to expand the trusted workspace or target allowlist through a
tool call, or a tool response exposes the one-time browser bearer URL.

Mitigation: the MCP server accepts workspace and host allowlist only as trusted
process-startup arguments. Tools accept metadata, TTL, and an opaque MCP status
handle only. The server opens the browser itself and validates every response
against a closed, agent-safe protocol that rejects URL, token, browser session,
raw-value, and unknown fields.

An agent may also create many abandoned sessions or poll immediately after a
browser submit.

Mitigation: active sessions are bounded, terminal snapshots have bounded
retention, terminal HTTP responses drain before their listener is force-closed,
and process shutdown closes every remaining listener. TTL applies only before
secret application begins. Cancel and submit use one atomic state transition;
after submit wins, cancel reports `apply_in_progress` and cannot replace the
eventual write result with a false `cancelled` state.

Residual risk: an unrestricted same-user agent may alter its MCP configuration,
start a different process, or read written targets directly. Strict containment
requires a separate OS identity or whole-process sandbox.

### Remote intake exposure

A future temporary remote intake page could be reachable by unintended parties.

MVP decision: remote intake is not implemented. Any future remote mode must add
authenticated transport, HTTPS, origin and proxy hardening, body-log suppression,
rate limits, and a separate security review before it is supported.
