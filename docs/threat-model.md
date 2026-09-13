# Threat Model

OpenAgent SecretBox reduces secret exposure in AI-assisted configuration. Its
primary goal is to keep values and private files out of AI chat, model context,
Agent-visible tool results, generated documents, and routine logs while still
letting an Agent complete an approved project setup.

This document describes the `0.1.0a1` source tree. The project has not received
an independent security assessment.

## Deployment scenarios

### Local desktop Agent

Codex App, Claude Code App, or another desktop Agent runs on the same machine as
the target workspace. SecretBox creates one loopback listener per request,
opens the browser directly, and never returns the bearer URL through the MCP
Agent channel.

### Remote self-hosted Agent

Hermes or another MCP Agent runs on a remote server while the owner uses a web
UI, Feishu, WeChat, or another channel. One long-running, multi-session Gateway
binds to `127.0.0.1`. A trusted Caddy or Nginx instance exposes one fixed HTTPS
origin on the existing public port 443. New requests reuse that listener and
origin; they do not create public ports or require repeated cloud security-group
changes.

### Managed Agent platform

A generic integration with platform-native environment-variable and precise
file-upload controls is not implemented. Where those controls exist, they
remain preferable until a platform adapter defines equivalent isolation and
Agent-safe result guarantees.

## Assets

- API keys, passwords, environment-variable values, and pasted env blocks;
- private keys, certificates, service-account files, and other uploads;
- the Gateway Owner Key and authenticated browser cookies;
- one-time browser bootstrap credentials and browser session identifiers;
- integrity of existing destination files and their permissions;
- trusted workspace, target allowlist, Gateway origin, bind address, and port.

Public request names, request titles, relative destination paths, lifecycle
states, and the fixed remote portal origin are not treated as secret values.
They still should contain no customer data or credentials.

## Roles and trust boundaries

### Trusted operator

The computer or server owner selects the workspace and host allowlist. In remote
mode the operator also selects DNS/TLS, the public origin, loopback listener,
fixed port, reverse-proxy policy, and owner-only key file. These are startup
authorization controls and must be configured outside Agent chat.

### Owner browser

The user reviews declared targets and supplies secrets directly to SecretBox.
In remote mode the owner authenticates to the fixed portal with the Owner Key.
The key is an operational secret and never belongs in an Agent tool call.

### Agent

The Agent is trusted to propose non-secret request metadata and use the three
MCP lifecycle tools. It is not trusted with submitted values, browser
credentials, Owner Keys, or the ability to expand startup policy. An Agent with
unrestricted shell access as the same OS user remains able to read destination
files after SecretBox writes them; preventing that requires a stronger process
or OS identity boundary.

### SecretBox and target host

SecretBox validates metadata, hosts the intake page, writes approved targets,
and emits closed redacted results. The host OS, Python runtime, and SecretBox
process are trusted. Host compromise is outside this boundary.

### Reverse proxy

The remote reverse proxy terminates TLS and can observe traffic. It is therefore
trusted not to record or export request bodies, cookies, authorization data, or
Owner Keys. SecretBox does not configure or attest the proxy.

### Chat and model provider

The chat channel, transcript store, model context, Agent summaries, and link
preview services are treated as unsuitable for secrets. The remote fixed
`portal_url` may traverse these systems because it is a public locator with no
request or authorization component.

## Security goals

1. Submitted values and files never cross the Agent result boundary.
2. Browser authorization material never appears in Agent-visible output.
3. Agent request metadata cannot expand the operator-selected workspace or target allowlist.
4. Existing different values are blocked instead of overwritten by default.
5. A remote unauthenticated visitor cannot enumerate or consume pending requests.
6. Every remote request uses one fixed HTTPS origin and loopback listener, not a new public port.
7. Terminal status is authoritative even when cancel and submit race.

## Main risks and controls

### Chat or model-context leakage

**Risk:** A user pastes a key or file into chat, or a tool result returns it.

**Controls:** The Agent declares only names, descriptions, relative targets, and
policy. Intake happens in a separate browser page. The closed result schema and
runtime normalizer reject submitted-value fields, file content, browser
credentials, URL-shaped metadata, and unknown fields. Gateway mode permits only
the stable HTTPS `portal_url` exception.

**Residual risk:** A user or third-party Agent integration can still ignore the
workflow and paste a value into chat. Training and Skill instructions are part
of the control.

### Agent policy expansion

**Risk:** An Agent attempts to choose another workspace, extend the allowlist,
publish the internal listener, or replace the Owner Key.

**Controls:** `--workspace`, `--allow-target`, Gateway public origin, bind,
port, and Owner Key file are process-startup controls. Tool arguments can only
describe concrete targets already authorized by that policy. Gateway bind is
hard-limited to `127.0.0.1`.

**Residual risk:** An unrestricted same-user Agent may edit its own MCP
configuration, start another process, or access files directly. Use a separate
OS identity or whole-process sandbox when this threat matters.

### Accidental overwrite and partial application

**Risk:** Configuration automation replaces an existing `.env` value or private
file, or several targets leave the workspace in an ambiguous state.

**Controls:** The alpha policy is merge-only, no-overwrite, and no persistent
backup. Existing different values become conflicts. Each target replacement is
atomic and the result distinguishes `applied`, `noop`, `partial`, and `blocked`.

**Residual risk:** A request that writes several targets is not a distributed
transaction. A later conflict can leave earlier approved writes applied; the
result reports `partial` and the UI does not claim success.

### Filesystem escape

**Risk:** Malicious metadata writes outside the workspace or follows an alias to
another file.

**Controls:** Targets must be relative and allowlisted. SecretBox rejects
absolute paths, `..`, unsafe Windows components, symlinks, Windows reparse
points/junctions, and unsafe hard-linked targets. New secret files receive
POSIX `0600` or an explicit current-user Windows DACL.

**Residual risk:** Checks are path-based. A malicious concurrent process under
the same OS user may race filesystem changes; that actor is outside this alpha
boundary.

### Local bearer exposure

**Risk:** A one-time loopback URL enters chat, logs, history, or a different
browser process.

**Controls:** MCP local mode opens the browser itself and reports only
`browser_opened: true`. The token is placed in a URL fragment, cleared before
exchange, high entropy, short-lived, and consumed atomically.

**Residual risk:** CLI `--no-open --json` intentionally emits a sensitive
bootstrap URL for direct operator use. It is outside the Agent-safe protocol and
must not be forwarded or logged.

### Remote portal discovery and link previews

**Risk:** A scanner, chat preview bot, or unauthenticated visitor learns about or
consumes a pending request.

**Controls:** Chat receives only the fixed origin root, never a request route,
intake ID, query, fragment, or bearer. Unauthenticated access redirects to
login. The pending list and request-open action require an authenticated owner
session. A request's one-time browser bootstrap is consumed only after owner
authentication and explicit selection.

**Residual risk:** Public availability reveals that a SecretBox portal exists.
Request titles and relative targets become visible to anyone with an active
owner browser session, so the Owner Key and device must remain controlled.

### Remote authentication and web attacks

**Risk:** Owner Key guessing, cookie theft, CSRF, framing, cross-origin requests,
or host-header confusion exposes the portal.

**Controls:** The key is generated with high entropy into a no-overwrite,
owner-only file and compared by digest. Authenticated sessions are random,
bounded, stored only in memory, revocable by logout, and carried in `HttpOnly`,
`SameSite=Strict`, `Secure` cookies under HTTPS. SecretBox validates the exact
configured Host and mutation Origin. Responses use no-store caching, a nonce
CSP, frame denial, no-referrer, nosniff, HSTS under HTTPS, and restricted browser
permissions.

**Residual risk:** The alpha Gateway has no built-in persistent identity store,
multi-factor authentication, account lockout, or comprehensive rate limiter.
The trusted reverse proxy should rate-limit login attempts and enforce request
size limits. A stolen Owner Key remains valid until the file and process are
rotated.

### Reverse-proxy or transport misconfiguration

**Risk:** The internal port is exposed directly, TLS is absent, forwarded
headers change security decisions, or request bodies are logged.

**Controls:** Gateway mode requires a configured HTTPS public origin and
hard-limits its own bind to IPv4 loopback. SecretBox validates the exact public
Host/Origin and does not derive trust from arbitrary `Forwarded` or
`X-Forwarded-*` headers. The deployment contract exposes only reverse-proxy
port 443.

**Residual risk:** DNS, certificate lifecycle, firewall rules, proxy logging,
rate limiting, and proxy compromise are operator responsibilities. The built-in
threaded WSGI listener is an internal application server, not a direct public
TLS endpoint.

### Log and diagnostic leakage

**Risk:** Values appear in access logs, exception text, screenshots, test output,
or future audit records.

**Controls:** SecretBox's built-in HTTP request handler suppresses access logs,
errors are mapped to stable public messages, and tests assert redacted result
shapes. Persistent audit logging is not implemented. The proxy must suppress
body, Cookie, and authorization logging.

**Residual risk:** Host-level tracing, crash dumps, browser extensions, endpoint
monitoring, and operator screenshots are outside SecretBox control.

### Lifecycle races and process restart

**Risk:** Cancel reports success while writes complete, a used form writes
twice, or a restarted service revives stale authorization.

**Controls:** Submit and cancel compete for one atomic state transition. After
apply begins, cancel returns `apply_in_progress` and polling yields the terminal
truth. Browser bootstrap is single use. Gateway request mappings and owner
sessions are memory-only, so restart invalidates them rather than restoring
stale browser authority.

**Residual risk:** Restart loses pending requests and signs out users. The Agent
must create a new request; the alpha does not provide durable recovery.

## Out of scope

- protecting secrets from a compromised host, kernel, browser, reverse proxy, or SecretBox process;
- hiding written files from an unrestricted same-user Agent;
- enterprise KMS, IAM governance, rotation, or revocation workflows;
- long-term encrypted secret storage or durable request recovery;
- preventing project code or dependencies from exfiltrating secrets at runtime;
- automatic DNS, TLS, cloud firewall, or reverse-proxy configuration;
- a general managed-sandbox integration.

## Hardening path

Production-oriented deployments should add a dedicated SecretBox OS identity,
a separate runtime identity from the Agent, proxy-level login throttling,
central secret storage or short-lived injection, upload type policy, carefully
allowlisted metadata audit events, and an independent security assessment.
