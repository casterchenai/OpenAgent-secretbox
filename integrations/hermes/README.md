# Hermes Agent integration

OpenAgent SecretBox gives Hermes a user-facing form for sensitive text and
files. Hermes describes what is needed and where it belongs; the user enters or
uploads it outside chat; Hermes receives only a redacted completion result.

The Skill install is one command. A trusted user must first configure the
workspace, target allowlist, and, for remote use, the public gateway. Those
settings are the authorization boundary and are deliberately not delegated to
the Agent.

## Choose the deployment

### Local desktop Agent

Use loopback mode for a local Hermes, Codex App, or similar desktop Agent. The
Agent can name a deeply nested destination without making the user find it. On
each request SecretBox opens the form directly in the user's local browser. No
URL or credential enters chat.

### Remote Hermes server

Use fixed-gateway mode when Hermes runs on a cloud server and the user talks to
it through Hermes Web UI, Feishu, WeChat, or another remote channel. Configure
one HTTPS origin such as `https://secretbox.example.com` behind the server's
existing port 443. Every request reuses that origin and a fixed internal port;
there is no new cloud firewall or security-group change per request.

Remote chat may show the fixed portal URL. It never shows a one-time path,
session id, query, fragment, or bearer token. The user opens the portal and
submits values or files directly to SecretBox on the server.

## Install the package

There is no supported PyPI release yet. In a trusted operator terminal, review
and pin a full Git commit, then install that checkout into the Python
environment used by Hermes:

```bash
git clone https://github.com/casterchenai/OpenAgent-secretbox.git
cd OpenAgent-secretbox
git checkout <reviewed-full-commit-sha>
python -m pip install ".[mcp]"
secretbox-mcp --help
```

Use editable installation only while developing this checkout:

```bash
python -m pip install -e ".[mcp]"
```

## Trusted bootstrap: local mode

Run this once in a trusted terminal outside Hermes chat:

```bash
hermes mcp add openagent-secretbox --command secretbox-mcp --args --workspace "/absolute/path/to/project"
```

On Windows, absolute executable and workspace paths are supported:

```powershell
hermes mcp add openagent-secretbox --command "C:\path\to\secretbox-mcp.exe" --args --workspace "E:\path\to\project"
```

The server authorizes `.env`, `.env.*`, and `secrets/*` by default. Add only a
narrow, reviewed target when the application requires it:

```bash
hermes mcp add openagent-secretbox --command secretbox-mcp --args --workspace "/absolute/project" --allow-target "config/private.json"
```

`--args` must be the final Hermes option. Everything after it is passed to
`secretbox-mcp`.

## Trusted bootstrap: remote fixed gateway

Run every command in this section as the trusted server operator, never through
Hermes or another Agent.

Generate a gateway owner key outside the project workspace and restrict its
filesystem permissions:

```bash
secretbox gateway keygen --output /etc/openagent-secretbox/owner.key
```

Gateway startup accepts only a key file that is already owner-only. It refuses
an insecure existing file without repairing and trusting it in place.

Register the MCP process with a fixed public origin, loopback bind, internal
port, workspace, allowlist, and owner key:

```bash
hermes mcp add openagent-secretbox \
  --command secretbox-mcp \
  --args \
  --workspace "/srv/apps/payment-service" \
  --gateway-public-origin "https://secretbox.example.com" \
  --gateway-bind "127.0.0.1" \
  --gateway-port "17321" \
  --gateway-owner-key-file "/etc/openagent-secretbox/owner.key"
```

Terminate TLS on the existing reverse proxy and forward only this hostname to
`127.0.0.1:17321`. For example, a minimal Caddy site is:

```caddyfile
secretbox.example.com {
    reverse_proxy 127.0.0.1:17321
}
```

Keep the gateway bind address on loopback. Open port 443 once at the cloud
firewall or security group; do not expose the internal gateway port publicly.
Use a dedicated hostname, valid TLS certificate, and a reverse proxy configured
not to log request bodies, cookies, or authorization headers.

The owner key, `--workspace`, `--allow-target`, public origin, bind address,
port, TLS, and reverse proxy are trusted controls. Do not ask Hermes to create,
change, or troubleshoot them with Agent tools.

## Verify MCP

The add flow should discover exactly:

- `open_secret_intake`
- `get_secret_intake_status`
- `cancel_secret_intake`

Enable those tools and test the connection:

```bash
hermes mcp test openagent-secretbox
```

Start a new Hermes session or run `/reload-mcp`. Hermes exposes:

- `mcp__openagent_secretbox__open_secret_intake`
- `mcp__openagent_secretbox__get_secret_intake_status`
- `mcp__openagent_secretbox__cancel_secret_intake`

## One-command Skill install

After reviewing the source revision, install the complete Hermes Skill with one
command:

```bash
hermes skills install "https://raw.githubusercontent.com/casterchenai/OpenAgent-secretbox/main/integrations/hermes/skills/openagent-secretbox/SKILL.md" --category security
```

For a reproducible deployment, replace `main` with a reviewed full Git commit
SHA. The Skill links its required `references/` and `templates/` files, so
Hermes fetches them with `SKILL.md` and rejects an incomplete bundle.

Reload skills:

```text
/reload-skills
```

Then ask Hermes naturally, without including any value:

```text
Use OpenAgent SecretBox to collect the payment API key and certificate for this project.
```

Installing the Skill teaches Hermes how to use an already trusted SecretBox
connection. It does not install the Python package or grant filesystem/network
authority.

For a local source checkout, point Hermes at the collection:

```yaml
skills:
  external_dirs:
    - /absolute/path/to/OpenAgent-secretbox/integrations/hermes/skills
```

Use a YAML-safe path on Windows:

```yaml
skills:
  external_dirs:
    - E:/path/to/OpenAgent-secretbox/integrations/hermes/skills
```

## Agent-visible behavior

In both modes Hermes sends metadata only and may create, poll, or cancel an
intake. It never configures the service or reads a destination.

In local mode, `open_secret_intake` returns an intake id, redacted status,
expiry, and `browser_opened: true`. The browser opens locally and no URL crosses
MCP.

In remote mode, it returns the same public metadata with
`browser_opened: false` and `portal_url`. The portal URL is always the configured
HTTPS origin root, for example `https://secretbox.example.com/`. It contains no
request-specific or authentication data and is safe to send through the user's
remote chat channel.

Cancellation is effective only before secret application starts. If cancel
returns `apply_in_progress`, poll the same `intake_id` until it reaches the
authoritative `applied` or `failed` state.

## User acceptance checks

### Local loopback

- [ ] Ask Hermes for a test environment variable without giving its value.
- [ ] Confirm the browser opens automatically on `127.0.0.1` or `localhost`.
- [ ] Confirm chat and tool output contain no URL, token, or submitted value.
- [ ] Submit a disposable value and confirm Hermes reports only its name,
  relative target, action, and redacted status.
- [ ] Remove the disposable target outside Hermes after the test.

### Remote fixed gateway

- [ ] Confirm the cloud security group exposes only the existing HTTPS port,
  not `17321`.
- [ ] Create two requests and confirm both chats show the same portal root with
  no path, query, fragment, intake id, or token.
- [ ] Open the portal from the user's device and confirm it identifies the
  intended server workspace and exact relative targets before submission.
- [ ] Upload a disposable file to a nested allowlisted target without manually
  locating that server path.
- [ ] Confirm refresh, reuse, expiry, and cancellation show clear portal states.
- [ ] Confirm Hermes reports only redacted status and never reads the written
  value or file.
- [ ] Remove the disposable intake and target through the trusted operator path.

## Security limit

SecretBox prevents secrets from crossing chat and MCP transport. It cannot stop
Hermes from reading a destination that its OS account can access. Use a
separate OS identity or whole-process sandbox when the Agent must not read the
secret after it is written.

See the [trusted user boundary](skills/openagent-secretbox/references/trusted-user-boundary.md)
for the full role split and exposure response.

## Compatibility basis

This integration follows Hermes Agent upstream `main` commit
`08298dabbd202eac2ce0b66deee0452863c738e0`, reviewed on 2026-07-23:

- https://github.com/NousResearch/hermes-agent/blob/main/website/docs/guides/work-with-skills.md
- https://github.com/NousResearch/hermes-agent/blob/main/website/docs/guides/use-mcp-with-hermes.md
- https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/mcp.md
- https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/skills.md
- https://github.com/NousResearch/hermes-agent/blob/main/SECURITY.md
