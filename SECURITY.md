# Security Policy

OpenAgent SecretBox helps an AI Agent configure software without requiring the
user to expose secrets in chat. It is a pre-release security tool and has not
received an independent security assessment. Do not use it as the sole control
for production credentials.

## Supported source

| Version | Supported |
|---|---|
| `main` / `0.1.0a1` pre-release | Security fixes accepted |
| Earlier snapshots | No |

There is currently no supported PyPI release or GitHub Release. Review and pin
the exact source commit used for a deployment.

## Security boundary

SecretBox aims to keep these materials out of AI chat, model context, Agent
tool results, generated documentation, routine logs, and git history:

- submitted environment-variable and API-key values;
- uploaded private files;
- Gateway Owner Keys;
- browser session IDs, cookies, CSRF tokens, and one-time bearer URLs.

Agent-visible results are closed and redacted. In remote mode the only allowed
URL is the fixed HTTPS `portal_url` origin, such as
`https://secretbox.example.com`. It contains no request path, query, fragment,
intake ID, or authorization data. An MCP `intake_id` is an internal status and
cancellation handle; never append it to the portal origin or send it as a user
link.

SecretBox does not protect against a compromised host, browser, reverse proxy,
or runtime. It also cannot stop an Agent with unrestricted shell access as the
same OS user from reading a destination after write. Use a separate OS identity,
container boundary, constrained runtime, or external KMS/Vault when that threat
is in scope.

## Supported deployment modes

### Local desktop mode

The local intake server binds to `127.0.0.1`. The MCP process opens the
single-use page directly in the user's browser and never returns the URL,
fragment token, or browser session identifier to the Agent.

The CLI `--no-open --json` bootstrap event is a deliberate exception for direct
operator use: it contains a bearer URL and is outside result protocol version
1. Never forward it to an Agent, chat, shared log, issue, or shell-history
collector.

### Remote fixed Gateway mode

Remote mode uses one long-running multi-session listener on `127.0.0.1` behind
a trusted HTTPS reverse proxy. The public surface is one stable origin on the
existing port 443. Direct public bind, random public ports per request, and
bearer intake URLs in chat are unsupported.

Run trusted setup in an operator terminal outside Agent chat:

```bash
secretbox gateway keygen --output /path/to/owner.key
```

```bash
secretbox-mcp \
  --workspace /srv/project \
  --gateway-public-origin https://secretbox.example.com \
  --gateway-bind 127.0.0.1 \
  --gateway-port 17321 \
  --gateway-owner-key-file /path/to/owner.key
```

The key generator refuses overwrite, does not print the key, and verifies an
owner-only POSIX mode or Windows ACL. Gateway startup rejects an existing key
whose permissions are too broad and never repairs it in place, because a later
permission change cannot revoke prior disclosure. Keep the key outside the
project and out of Agent-readable configuration wherever the OS boundary
permits.

Only Caddy, Nginx, or an equivalent trusted proxy should listen publicly on
443. Do not expose `17321` through the host firewall or cloud security group.
The proxy must:

- terminate valid TLS for the exact configured origin;
- preserve the configured Host and Origin;
- forward only to `127.0.0.1:17321`;
- avoid logging request bodies, cookies, authorization data, and Owner Keys;
- enforce compatible body limits and rate-limit login attempts.

SecretBox does not automatically configure DNS, certificates, firewall rules,
or the proxy, and it does not trust arbitrary `Forwarded` or
`X-Forwarded-*` headers. Gateway owner sessions and request mappings are
memory-only; process restart signs browsers out and invalidates pending
requests.

## Trusted startup controls

The person registering `secretbox-mcp` is the policy authority. The following
must be fixed in reviewed startup configuration, never selected or changed by
an Agent tool call:

- `--workspace`;
- every additional `--allow-target` pattern;
- Gateway public origin, loopback bind, and fixed internal port;
- Gateway Owner Key file;
- TLS, DNS, firewall, and reverse-proxy policy.

Requests can assert the configured workspace or narrow targets, but cannot
expand this authority. Installing the Agent Skill teaches tool behavior; it
does not install the package or grant filesystem or network authority.

## Operational requirements

- Use merge-only, no-overwrite behavior for env values and files.
- Keep persistent backups disabled unless a separately reviewed retention policy exists.
- Use only relative, allowlisted targets under the trusted workspace.
- Rotate the Owner Key by replacing it through a trusted operator workflow and restarting Gateway.
- Use disposable fake values for acceptance tests and remove them afterward.
- Inspect chat, MCP output, Agent logs, proxy logs, screenshots, and shell history after testing.
- Treat unexpected bearer, session, Owner Key, submitted value, or file-content exposure as an incident.

If exposure is suspected, cancel pending requests where possible, stop the
Gateway, rotate the affected credential and Owner Key through a non-Agent
channel, clear authenticated browser state, remove leaked logs or artifacts
where retention policy permits, and investigate the host and reverse proxy
before restarting.

## Reporting vulnerabilities

Do not open a public issue for a vulnerability that could expose credentials.
Use the repository's
[private security advisory form](https://github.com/casterchenai/OpenAgent-secretbox/security/advisories/new).
If private reporting is unavailable, open a non-sensitive issue asking the
maintainer for a private contact channel. Do not include exploit details,
credentials, bearer URLs, logs, or screenshots in that issue.

## Rules for contributors

- Never commit real keys, private files, tokens, certificates, or `.env` files.
- Never print secret values in logs, tests, errors, screenshots, examples, or documentation.
- Test fixtures must use clearly fake, disposable values.
- Secret-writing code must remain merge-only and no-overwrite by default.
- Any future overwrite flow requires explicit user approval and a separate threat review.
- Uploads must be size-limited, path-normalized, and restricted to approved targets.
- MCP tool arguments must not select trusted startup controls.
- Remote listeners must remain loopback-only behind an explicit HTTPS proxy boundary.
- Agent-facing changes must update the closed JSON Schema, runtime normalizer, documentation, and negative tests together.
- Tests must prove that submitted data, Owner Keys, browser sessions, bearer URLs, request-specific URLs, and unknown fields fail closed.

See [the threat model](./docs/threat-model.md) for assumptions, controls, and
residual risks, and [the result protocol](./docs/result-protocol.md) for the
Agent-visible data contract.
