# Trusted User Boundary

Use this reference to distinguish the two supported deployments and respond to
policy or exposure failures. In both modes, Hermes is an untrusted request
author. The trusted user configures write authority once; Hermes may only
create, poll, and cancel intakes within that authority.

## Local loopback mode

Use this mode when Hermes and the user's browser run on the same desktop.

```text
Hermes -> metadata-only MCP open/status/cancel
  -> SecretBox opens a one-time loopback page in the local browser
  -> user enters values or uploads files
  -> SecretBox writes approved relative targets
  -> Hermes receives redacted status only
```

The MCP process fixes `--workspace` and any `--allow-target` values at startup.
It opens the browser itself and never returns the bearer URL through MCP.

## Remote fixed-gateway mode

Use this mode when Hermes runs on a server and the user reaches it through a Web
UI, Feishu, WeChat, or another remote channel.

```text
Hermes -> metadata-only MCP open/status/cancel
  -> SecretBox creates a pending intake behind the fixed gateway
  -> Hermes receives only an intake id, redacted status, and fixed portal root
  -> chat may show https://secretbox.example.com/
  -> user opens the portal and authenticates outside Hermes
  -> SecretBox writes approved targets on the server
```

The trusted operator configures the gateway once behind HTTPS on port 443. The
internal SecretBox port remains fixed and loopback-bound, so new intakes do not
require new ports or cloud security-group rules.

The portal URL is intentionally the same origin root for every request. It must
not contain a session path, request id, query, fragment, token, or user info.
The portal URL is public routing metadata and may be sent through chat. Portal
authentication material, owner keys, intake URLs, and submitted values may not.

## Authority split

Hermes may:

- define non-secret request metadata and relative targets;
- call the configured open, status, and cancel tools;
- relay a validated fixed HTTPS portal root in remote mode;
- report redacted terminal results.

The trusted user or operator must:

- install and verify SecretBox;
- choose the absolute workspace and target allowlist;
- choose the gateway public origin, bind address, and fixed port;
- generate and protect the gateway owner key;
- configure TLS and the reverse proxy;
- register MCP outside an active agent session.

SecretBox must:

- enforce the startup workspace and allowlist;
- enforce merge-only and no-overwrite behavior;
- keep browser credentials and submitted data out of MCP results;
- return no URL in local mode and only the fixed portal root in remote mode;
- preserve one authoritative terminal result when submit and cancel race.

## Invariants

1. Keep secret values and file contents out of requests, prompts, chat, tool
   arguments, logs, command lines, and skill configuration.
2. Keep `workspace_root`, `allowed_targets`, public origin, bind settings, owner
   key, and reverse-proxy configuration under trusted user control.
3. Never let Hermes run `secretbox gateway keygen`, `secretbox-mcp`, `hermes
   mcp add`, a gateway service command, or reverse-proxy setup.
4. Never let Hermes receive or open a one-time intake URL. In remote mode, allow
   only the fixed HTTPS origin root returned as `portal_url`.
5. Never append an intake id or request id to the portal URL.
6. Never inspect destination contents after apply. Use redacted status.
7. Keep no-overwrite enabled when a conflict occurs. Resolve ownership outside
   Hermes, then create a new intake.

## Trusted setup checklist

Before enabling the tools, verify:

- the executable is the expected OpenAgent SecretBox installation;
- the workspace is the intended existing directory, not a link or junction;
- every additional allow-target pattern is necessary and narrow;
- remote mode uses an HTTPS public origin with no path, query, or fragment;
- the gateway binds to loopback behind a trusted TLS reverse proxy;
- the owner key file is outside the workspace and unreadable by the Agent OS
  identity where practical;
- Hermes discovers exactly open, status, and cancel tools;
- an end-to-end test writes only a disposable target and leaves no value in
  chat, tool output, or service logs.

The default startup allowlist is `.env`, `.env.*`, and `secrets/*`. Request
metadata may select a concrete target within that policy but may not expand it.

## What this boundary does not provide

SecretBox keeps values out of model and tool transport. It does not contain a
malicious or compromised agent that can read the destination with the same OS
permissions.

For strict separation, run Hermes under a separate OS identity or whole-process
sandbox, deny it read access to secret targets, and let only SecretBox and the
credential-consuming application access those targets.

## Exposure response

If a one-time intake URL or owner key appears in chat, do not repeat it. Revoke
or rotate it outside Hermes, cancel the affected intake when possible, and
create a fresh intake. Deleting the chat message is not revocation.

If a credential value or sensitive file content appears in chat, treat it as
exposed. Revoke or rotate the credential at its issuer, then collect the
replacement through a fresh intake.

If `portal_url` contains a path other than `/`, a query, a fragment, user info,
or a non-HTTPS remote scheme, do not relay it. Report a gateway configuration
error without repeating the URL.

## Upstream security basis

- https://github.com/NousResearch/hermes-agent/blob/main/SECURITY.md
- https://github.com/NousResearch/hermes-agent/blob/main/website/docs/guides/use-mcp-with-hermes.md
- https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/mcp.md
- https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/skills.md
