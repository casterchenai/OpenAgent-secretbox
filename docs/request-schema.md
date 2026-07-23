# Request Schema

This document describes request schema version 1 used by OpenAgent SecretBox.

The schema is intentionally explicit: agents declare what they need, where values may be written, and which write policy applies. Users provide the actual secret values outside the chat context.

## Minimal example

```json
{
  "request_id": "openai-local-setup",
  "title": "OpenAI API setup",
  "workspace_root": "/path/to/project",
  "needs": [
    {
      "type": "env",
      "name": "OPENAI_API_KEY",
      "required": true,
      "description": "OpenAI API key"
    }
  ],
  "write_policy": {
    "env_file": ".env.local",
    "mode": "merge_only",
    "no_overwrite": true,
    "backup": false
  }
}
```

## Fields

### `request_id`

Client label for local tracking. The server creates a separate high-entropy session id;
this value is never used as an authentication credential.

### `title`

Human-readable title displayed in the intake UI.

### `workspace_root`

An optional assertion about the intended root, not an authorization grant. When
present, it must resolve to the same directory as trusted `--workspace` or the CLI
rejects the request.

### `needs`

Array of required or optional secret inputs.

The runtime requires every `need.name` to be unique across the request. JSON
Schema's `uniqueItems` catches identical duplicate objects; name-level uniqueness
is an additional semantic validation performed by `secretbox validate`.

Supported draft types:

- `env`: an environment variable value
- `file`: an uploaded private file
- `env_file`: a pasted `.env` block to parse and merge

For `env`, `name` must be a conventional environment-variable identifier:
letters or `_` first, followed by letters, digits, or `_`. File and `env_file`
labels may additionally contain `.`, and `-` after the first character.

All targets use `/` separators and are relative to the trusted workspace.
Absolute paths, `..`, backslashes, alternate data stream syntax, trailing dots
or spaces, and Windows device names are rejected on every platform.

### `write_policy`

Requests may ask for these constraints, but they cannot weaken the trusted host
policy. The CLI always enforces no-overwrite, disables persistent backup, and
authorizes only `.env`, `.env.*`, and `secrets/*` unless the user supplies an
additional `--allow-target` pattern.

The user running the CLI owns this host policy. Passing control of `--workspace`
or `--allow-target` to an untrusted same-user agent is outside the MVP security
boundary.

The MCP adapter applies the same rule: its trusted user fixes `--workspace` and
any extra `--allow-target` patterns when registering the stdio process. MCP
request objects normally omit `workspace_root` and `allowed_targets`. If
present, those fields can only assert the configured workspace or narrow its
target policy; they cannot expand startup authority. Concrete targets declared
by `needs` must already fit the startup policy.

- `mode: merge_only`
- `no_overwrite: true`
- `backup: false` for the CLI; persistent backups duplicate secrets and require a
  separate trusted retention policy

## Redaction rule

Status responses may include names and target paths, but must never include secret values.
