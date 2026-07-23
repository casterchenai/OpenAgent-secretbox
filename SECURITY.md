# Security Policy

OpenAgent SecretBox is designed for a sensitive problem: helping AI agents configure software without exposing secrets in chat context.

## Security boundaries

This project aims to keep secrets out of:

- AI chat messages
- LLM context windows
- agent logs
- generated documentation
- git history

It does **not** claim to protect secrets from a compromised host or from an agent that has unrestricted shell access to files after secrets are written. Stronger isolation requires OS-level users, filesystem permissions, containers, or an external KMS.

The current pre-release CLI supports loopback intake only and binds to
`127.0.0.1`. Remote or non-loopback intake is unsupported. The package has not
received an independent security assessment and should not yet be used as the
sole control for production credentials.

The optional MCP server uses stdio and opens the one-time loopback URL directly
in the local browser. Its tools never return that URL, its fragment token, or
the browser session id. The trusted user must fix `--workspace` and any
additional `--allow-target` values when the MCP process is registered; those
startup controls cannot be expanded by tool arguments. Request metadata may
only assert the same workspace or narrow the configured targets.

The CLI `--no-open --json` bootstrap event contains a bearer URL for private
manual use. It is not an agent-safe result and is rejected by result protocol
version 1. Never forward that event to an agent, log collector, or chat.

## Supported versions

| Version | Supported |
|---|---|
| `main` / `0.1.0a1` pre-release | Security fixes accepted |
| Earlier snapshots | No |

## Reporting vulnerabilities

Please do not open a public issue for vulnerabilities that could expose credentials.

Use the repository's [private security advisory form](https://github.com/casterchenai/OpenAgent-secretbox/security/advisories/new).
If private reporting is unavailable, open a non-sensitive issue asking the
maintainer for a private contact channel. Do not include exploit details,
credentials, bearer URLs, logs, or screenshots in that issue.

## Rules for contributors

- Never commit real API keys, private keys, tokens, certificates, or `.env` files.
- Never print secret values in logs, test output, errors, screenshots, or README examples.
- Test fixtures must use fake values such as `sk-test-redacted`.
- All secret-writing code must default to merge-only / no-overwrite behavior.
- Any overwrite flow must require explicit user approval.
- Uploaded files must be size-limited, path-normalized, and written only inside allowed targets.
- MCP integrations must keep workspace and host allowlist selection in trusted
  startup configuration, never in agent tool arguments.
- Agent-facing result changes must update both the closed JSON Schema and the
  runtime normalizer, with tests proving that URLs, tokens, session ids, raw
  values, and unknown fields fail closed.
