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
- local and remote project configuration workflows

## Out of scope for MVP

- protecting secrets from a fully compromised host
- preventing a same-user unrestricted shell agent from reading files after write
- enterprise-grade KMS replacement
- secret rotation
- long-term encrypted secret storage
- cloud IAM governance

## Main risks

### Chat leakage

Users paste secrets into chat. The model, platform, transcript, and future context may retain them.

Mitigation: provide a separate intake UI and teach agents to request secrets by schema rather than asking for raw values.

### Accidental overwrite

Agents replace existing `.env` files or break runtime settings.

Mitigation: merge-only writes, backups, conflict detection, and user approval for overwrites.

### Path traversal

A malicious or buggy request tries to write outside the project workspace.

Mitigation: normalize targets, reject `..`, use allowlists, reject symlinks in MVP.

### Log leakage

Secret values appear in status responses, logs, exceptions, or test output.

Mitigation: centralized redaction rules and tests that assert secret values never appear in agent-facing results.

### Remote intake exposure

A temporary remote intake page is reachable by unintended parties.

Mitigation: high-entropy one-time token, short TTL, HTTPS, no body logs, upload limits, and auto-shutdown.
