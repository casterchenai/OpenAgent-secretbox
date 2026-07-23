# ADR-001: Local-first secret intake broker

## Status

Accepted

## Date

2026-07-23

## Context

AI agents often need API keys, environment variables, private keys, and service-account files to configure software. Asking users to paste secrets into chat is unsafe because values may enter transcripts, LLM context windows, logs, generated documentation, or future memory.

At the same time, telling non-expert users to manually edit `.env` files, upload PEM files, and set permissions creates a high-friction workflow that often fails in local and cloud environments.

## Decision

OpenAgent SecretBox will be a local-first secret intake broker.

Agents declare required secrets through a schema. Users provide values through a
separate loopback intake UI. SecretBox applies values to allowed workspace targets
and returns only redacted status to the agent.

Default behavior:

- no secret values returned to the agent
- merge-only env writes
- no overwrite without explicit approval
- no persistent backup by default; any future retained recovery copy needs a
  trusted retention policy and owner-only storage
- path allowlists
- restrictive file permissions
- redacted audit logs

## Alternatives considered

### Ask users to paste secrets into chat

- Pros: simple and fast
- Cons: leaks secrets into the least appropriate layer
- Rejected because it trains unsafe user behavior.

### Tell users to configure everything manually

- Pros: avoids chat leakage
- Cons: high user burden; error-prone for remote/cloud environments
- Rejected because it blocks agent usefulness for ordinary users.

### Use enterprise KMS only

- Pros: strong production-grade model
- Cons: too heavy for local development and ordinary open-source users
- Rejected for MVP, but future KMS backends may be supported.

## Consequences

OpenAgent SecretBox must be honest about its boundary. It reduces chat-context leakage but does not, by itself, protect secrets from a compromised host or an agent with unrestricted same-user shell access.

Future hardening can add OS-user isolation, subprocess-only secret injection, encrypted local storage, and KMS backends.
