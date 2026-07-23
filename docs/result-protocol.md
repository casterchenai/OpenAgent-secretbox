# Result Protocol

`schemas/result-v1.json` is the language-neutral contract for metadata returned
to an agent. It accepts closed shapes for a core writer result, a versioned CLI
intake event, an MCP intake result, and an MCP tool error.
`openagent_secretbox.protocol` provides the same validation and normalization
rules without a production JSON Schema dependency.

## Writer result

Writer statuses match `apply_request`:

- `applied`: at least one write or permission repair completed, with no unresolved item
- `noop`: nothing changed and no item is unresolved
- `partial`: at least one write completed before a conflict or blocked operation
- `blocked`: no write completed; a conflict, missing input, or blocked reason is present

The only allowed item metadata is a declared type, name, action, relative target,
permission mode, or stable reason code. The schema recursively rejects field
names associated with values, tokens, request bodies, file content, passwords,
authorization, credentials, API keys, and private keys. Every object also uses
`additionalProperties: false` so extensions fail closed.

The field-name ban is deliberately lexical. For example, `token_count` is also
rejected even if a caller intends it as non-sensitive telemetry. A future safe
extension requires a new protocol version rather than weakening version 1.

## Intake event

CLI events use `schema_version: 1` and one of these lifecycle statuses:

- `awaiting_input`
- `applied`
- `failed`
- `cancelled`
- `expired`

A terminal `applied` event contains an `applied` or `noop` writer result. A
terminal `failed` event may contain a `partial` or `blocked` writer result and
always contains a stable `error_code`.

The `--no-open` CLI bootstrap line is deliberately outside this agent-safe
protocol because it carries a loopback bearer URL. The schema and runtime
validator reject that object. It must not be sent to an agent, persisted, or
logged.

## MCP result

MCP `open`, `status`, and `cancel` responses use an `intake_id` control handle.
It is scoped to the MCP process and is not the browser session id or bearer
credential. MCP responses never contain a browser URL, intake path, browser
session id, or token. Their terminal nested `result`, when present, must satisfy
the writer result contract above. MCP tool failures use the closed
`{schema_version, status, error}` shape with an allowlisted code and bounded,
single-line message.

`cancel_secret_intake` may return the `apply_in_progress` error after submission
has crossed into the write phase. This is a non-terminal control response: the
intake remains active and status polling will return the authoritative
`applied` or `failed` result. It must never be rewritten as `cancelled`.

## Examples

`examples/anthropic.result.json` shows a successful terminal event.
`examples/stripe.result.json` shows a conflict without either the existing or
submitted value. Request examples use matching request identifiers so an agent
can correlate the documents without receiving secret material.
