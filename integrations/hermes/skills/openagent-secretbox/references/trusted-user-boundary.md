# Trusted User Boundary

Read this reference before using SecretBox through Hermes Agent.

## Preferred MCP data flow

```text
Trusted user terminal (outside Hermes)
  | registers secretbox-mcp with fixed --workspace/--allow-target policy
  v
Hermes Agent -> metadata-only open/status/cancel tool calls
  v
SecretBox MCP subprocess
  | validates against startup policy; URL stays inside subprocess
  | opens the default local browser directly
  v
Trusted browser: user enters values -> loopback SecretBox writer
  v
Approved workspace targets

SecretBox MCP -> Hermes: intake id and redacted status only
```

The MCP server never returns its intake URL, fragment token, session id, or
submitted values through MCP. The agent request omits `workspace_root` and
`allowed_targets`; startup configuration supplies those trusted controls.

## Manual fallback data flow

```text
Hermes -> metadata-only request JSON and an unexecuted serve command
  v
Trusted user terminal -> secretbox serve -> trusted local browser
  v
Approved workspace targets

User -> Hermes: status-only confirmation
```

Fallback is less convenient because Hermes cannot use MCP status/cancel. It
still keeps the bearer and values outside model/tool context when the user runs
the command separately.

## Roles

Hermes is an untrusted request author. It may propose credential names and
relative targets, call the three SecretBox MCP tools, and receive redacted
status. It may not register or reconfigure the MCP server.

The local user is the policy authority. In a separate trusted terminal, the
user installs SecretBox, verifies the executable, and registers MCP with an
absolute `--workspace`. Only the user may add startup `--allow-target` values.

SecretBox MCP is the value handler. It binds intake to loopback, opens the URL
directly in the local browser, consumes the one-time session, applies
merge-only/no-overwrite policy, and returns redacted protocol data.

Cancel is effective only before application starts. After the atomic submit
transition wins, MCP returns `apply_in_progress`; the write continues to a real
`applied` or `failed` terminal state and is never mislabeled `cancelled`.

## Invariants

1. Do not place secret values in request JSON, skill frontmatter, Hermes config,
   prompts, messages, tool arguments, logs, or command lines.
2. Do not let the agent run `hermes mcp add`, `secretbox-mcp`, or
   `secretbox serve`; those commands establish or bypass trusted process policy.
3. Do not pass `workspace_root` or `allowed_targets` in an MCP request. The
   request may declare only concrete relative write targets.
4. Do not let Hermes receive, open, exchange, poll, or screenshot an intake URL.
   MCP status polling uses only the non-secret `intake_id`.
5. Do not send loopback intake URLs through gateway platforms or between hosts.
6. Do not inspect target contents after apply. Use redacted MCP status or a
   status-only user confirmation.
7. Do not let an agent select startup `--allow-target`. Request metadata may
   select concrete targets only within the user-fixed host policy.

## Trusted registration checklist

Before running `hermes mcp add` outside chat, verify:

- `secretbox-mcp` is the expected installed OpenAgent SecretBox executable;
- `--workspace` is the intended existing directory, not a link or junction;
- `--args` is the final Hermes option and only reviewed server arguments follow;
- any repeated `--allow-target` extension is necessary and narrowly scoped;
- the probe discovers only open, status, and cancel tools;
- `hermes mcp test openagent-secretbox` succeeds;
- a new Hermes session or `/reload-mcp` exposes the expected namespaced tools.

The default startup allowlist is `.env`, `.env.*`, and `secrets/*`. Request
metadata can choose concrete targets inside it but cannot expand it. The MCP
server also forces no-overwrite and disables persistent backup.

## What this boundary does not provide

This flow prevents bearer and submitted-value transport through MCP. It does
not contain a malicious or compromised agent running as the same OS user.
Hermes Agent's official security policy states that skills/plugins run in
process and that subprocess environment filtering, approval gates, redaction,
and skill scanning are heuristics rather than full security boundaries.

If Hermes can read the destination with its OS permissions, it can access the
secret after SecretBox writes it. For strict separation:

- run Hermes under a separate OS identity or whole-process sandbox;
- deny that identity read access to `.env*` and `secrets/*` targets;
- run SecretBox and the credential-consuming application under a trusted
  identity that can access those targets;
- keep untrusted web, email, and gateway input out of the trusted process.

## Exposure response

If an intake URL appears in chat or agent-visible output, do not repeat it.
Cancel the intake by its non-secret intake id when available, or stop/expire the
fallback server, then create a fresh session. Deleting a message is not
revocation.

If a credential value appears in chat, treat it as exposed. Revoke or rotate it
at the issuing provider, then use a fresh SecretBox session for the replacement.
Deleting local logs or chat history is not a substitute for rotation.

If a target conflict occurs, keep no-overwrite enabled. Resolve the existing
credential and file ownership manually outside Hermes, then create a new
one-time intake.

## Upstream security basis

- https://github.com/NousResearch/hermes-agent/blob/main/SECURITY.md
- https://github.com/NousResearch/hermes-agent/blob/main/website/docs/guides/use-mcp-with-hermes.md
- https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/mcp.md
- https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/skills.md
