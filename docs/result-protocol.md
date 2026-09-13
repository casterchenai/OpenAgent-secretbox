# Result Protocol

`schemas/result-v1.json` is the language-neutral contract for metadata that may
cross the Agent boundary. `openagent_secretbox.protocol` implements the same
closed validation and normalization rules without requiring JSON Schema at
runtime.

Version 1 covers:

- the core writer result;
- a local CLI intake event;
- an MCP open, status, or cancel result;
- an MCP tool error.

The sensitive bootstrap event emitted by local CLI `--no-open --json` is
deliberately outside this protocol.

## Security invariant

An Agent-safe result may identify the request, name declared inputs, show
relative targets and actions, and report lifecycle state. It must never contain:

- a submitted value or uploaded file content;
- an encoded, encrypted, hashed, previewed, or otherwise derived secret value;
- an Owner Key, authorization value, password, credential, or API key;
- a browser session identifier, cookie, CSRF token, or one-time bearer;
- a request-specific browser URL, intake path, query, or fragment;
- an absolute workspace path or an unknown extension field.

Every protocol object uses `additionalProperties: false`. The runtime also
recursively rejects field names associated with values, tokens, request bodies,
file content, passwords, authorization, credentials, API keys, and private
keys. The field-name ban is intentionally lexical: a name such as `token_count`
also fails. A new safe field requires a new reviewed protocol version, not a
looser version 1 validator.

## Writer result

Writer statuses match `apply_request`:

- `applied`: at least one write or permission repair completed and no item is unresolved;
- `noop`: nothing changed and no item is unresolved;
- `partial`: at least one write completed before a conflict or blocked operation;
- `blocked`: no write completed and a conflict, missing input, or blocked reason is present.

The only allowed item metadata is a declared type, public name, action, relative
target, permission mode, or stable reason code. Values and file contents never
appear, including when the outcome is a conflict.

Example:

```json
{
  "request_id": "payment-setup",
  "status": "applied",
  "written": [
    {
      "type": "env",
      "name": "PAYMENT_API_KEY",
      "action": "added",
      "target": ".env.local"
    }
  ],
  "conflicts": [],
  "missing": [],
  "blocked": []
}
```

## Local CLI intake event

CLI events use `schema_version: 1` and one lifecycle status:

- `awaiting_input`
- `applied`
- `failed`
- `cancelled`
- `expired`

An Agent-safe local `awaiting_input` event requires `browser_opened: true` and
contains no URL. A terminal `applied` event contains an `applied` or `noop`
writer result. A terminal `failed` event may contain a `partial` or `blocked`
writer result and always contains a stable `error_code`.

Local CLI `--no-open --json` emits a bootstrap line carrying a loopback bearer
URL for direct, private operator use. That line is rejected by both the schema
and runtime normalizer. It must not be sent to an Agent, chat, shared log,
ticket, or shell transcript collector.

## MCP result

MCP tools use `intake_id` as an opaque control handle for status and
cancellation. It is scoped to one MCP process and is not the browser session ID
or an authorization credential. An Agent may retain it internally, but must
never append it to `portal_url`, turn it into a browser URL, or ask the user to
open it.

### Local discovery

Local mode opens the browser directly and returns no URL:

```json
{
  "schema_version": 1,
  "intake_id": "int_exampleLocalHandle123",
  "request_id": "payment-setup",
  "status": "awaiting_input",
  "expires_at": "2026-07-24T10:10:00Z",
  "browser_opened": true
}
```

### Remote Gateway discovery

Gateway mode does not open a browser on the remote host. It returns the same
fixed public origin for every request:

```json
{
  "schema_version": 1,
  "intake_id": "int_exampleRemoteHandle12",
  "request_id": "payment-setup",
  "status": "awaiting_input",
  "expires_at": "2026-07-24T10:10:00Z",
  "browser_opened": false,
  "portal_url": "https://secretbox.example.com"
}
```

`portal_url` is the one delivery exception in the Agent-safe MCP result. It is
a public locator, not a bearer. The validator accepts only a fixed HTTPS origin
with an ASCII DNS name or IPv4 address and an optional canonical port. Protocol
version 1 deliberately excludes IPv6 literals so the runtime and published
Schema share one exact grammar. Credentials, backslashes, a non-root path,
query, fragment, trailing-dot hostname, malformed port, and HTTP are rejected.
The normalized value has no request-specific component.

Only an `awaiting_input` result with `browser_opened: false` may contain
`portal_url`. Terminal results must not retain `browser_opened` or
`portal_url`; this prevents delivery metadata from spreading into later Agent
summaries.

The authenticated portal, not the Agent, maps a selected request to its
one-time internal browser session. Browser session IDs and bearer material never
cross MCP. Unauthenticated page previews can reach the login page but cannot
enumerate, open, or consume a request.

### Terminal state and cancellation

MCP status and cancel results use the same lifecycle states as intake events.
Their nested terminal `result`, when present, must satisfy the writer contract
and have the same `request_id`.

`cancel_secret_intake` may return the `apply_in_progress` MCP error after a
submission has entered the write phase. This is a non-terminal control response:
the intake remains active and status polling must return the authoritative
`applied` or `failed` result. It must never be rewritten as `cancelled` while
writes may still complete.

## MCP tool error

Tool failures use the closed shape:

```json
{
  "schema_version": 1,
  "status": "error",
  "error": {
    "code": "invalid_request",
    "message": "The secret request is not valid."
  }
}
```

The code is allowlisted and the message is bounded and single-line. Internal
paths, exception details, submitted data, browser identifiers, and URLs are not
allowed.

## Conformance

Any producer changing an Agent-visible response must update all of:

1. `schemas/result-v1.json`;
2. `openagent_secretbox.protocol`;
3. positive and negative protocol tests;
4. this document and affected integrations.

`examples/anthropic.result.json` demonstrates a successful terminal result.
`examples/stripe.result.json` demonstrates a conflict without disclosing either
the existing or submitted value.
