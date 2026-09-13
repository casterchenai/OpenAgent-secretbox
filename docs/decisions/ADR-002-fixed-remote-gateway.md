# ADR-002: Fixed remote gateway for self-hosted agents

## Status

Accepted for the remote gateway alpha.

## Date

2026-07-24

## Business context

The primary user does not operate SecretBox as a command-line product. They
interact with an agent through a desktop app, web UI, Feishu, WeChat, or a
similar channel. The agent knows the project workspace and destination paths;
the user should only need to review those destinations and provide the missing
values or files.

Local desktop agents can open a loopback form. A self-hosted remote agent cannot:
`127.0.0.1` in a chat link points to the user's device, while opening a new public
port for every request creates firewall and cloud security-group work.

## Decision

SecretBox will support two delivery modes behind the same agent protocol:

1. **Local mode** opens a one-time loopback page on the user's machine.
2. **Gateway mode** keeps one multi-session HTTP listener on the agent host. A
   trusted reverse proxy exposes a fixed HTTPS origin, normally on port 443.

Gateway mode creates a new request record, not a new listener or public port,
for each intake. The agent receives a non-secret intake handle, redacted status,
and the fixed portal origin. It never receives a browser session identifier,
one-time bearer, submitted value, or uploaded file content.

The portal URL is a locator, not an authorization credential. The owner signs
in with an access key configured outside the agent conversation. Link scanners,
preview bots, and unauthenticated visitors cannot inspect or consume requests.

The trusted startup configuration fixes:

- workspace root;
- host target allowlist;
- public HTTPS origin;
- internal bind address and fixed port;
- owner access-key file;
- maximum concurrent intake count.

Agent tool arguments may narrow a request to concrete relative targets but may
not change any of these controls.

## Deployment boundary

The alpha gateway binds to IPv4 loopback and expects a user-managed HTTPS
reverse proxy such as Caddy or Nginx. SecretBox does not automatically modify
DNS, TLS certificates, cloud firewalls, or reverse-proxy configuration.

The proxy must preserve the configured Host and Origin, disable request-body
logging, enforce upload limits, and forward only to the configured loopback
listener. SecretBox validates the exact public origin and does not trust
arbitrary `Forwarded` or `X-Forwarded-*` headers.

## Consequences

- A self-hosted agent needs only one externally reachable HTTPS origin.
- Feishu, WeChat, and web UI messages can contain the stable portal URL without
  carrying a session bearer.
- The gateway process must remain alive while requests are pending.
- Pending requests and owner browser sessions are memory-only in the alpha and
  are invalidated by process restart.
- The owner access key is an operational secret and must not be installed,
  printed, or read through an agent tool.
- Gateway transport keeps values out of model context but does not stop an
  unrestricted same-user agent from reading destination files after write.

## Rejected alternatives

### Public random port per request

Rejected because it requires repeated security-group changes and enlarges the
network attack surface.

### Bearer intake URL in chat

Rejected because the model, channel provider, link preview service, transcript,
and logs can receive the complete URL and race the user to the one-time session.

### Bind the alpha WSGI server directly to `0.0.0.0`

Rejected. TLS termination, origin enforcement, authentication, rate limiting,
and proxy logging need an explicit gateway boundary and separate review.
