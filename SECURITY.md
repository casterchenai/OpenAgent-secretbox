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

## Reporting vulnerabilities

Please do not open a public issue for vulnerabilities that could expose credentials.

Instead, use GitHub private vulnerability reporting if enabled, or contact the maintainers privately.

## Rules for contributors

- Never commit real API keys, private keys, tokens, certificates, or `.env` files.
- Never print secret values in logs, test output, errors, screenshots, or README examples.
- Test fixtures must use fake values such as `sk-test-redacted`.
- All secret-writing code must default to merge-only / no-overwrite behavior.
- Any overwrite flow must require explicit user approval.
- Uploaded files must be size-limited, path-normalized, and written only inside allowed targets.
