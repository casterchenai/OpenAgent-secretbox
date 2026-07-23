# Request Schema

This document describes the draft request schema used by OpenAgent SecretBox.

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
    "backup": true
  }
}
```

## Fields

### `request_id`

Stable request identifier. Should be unique enough for local tracking.

### `title`

Human-readable title displayed in the intake UI.

### `workspace_root`

Root directory for all relative target paths.

### `needs`

Array of required or optional secret inputs.

Supported draft types:

- `env`: an environment variable value
- `file`: an uploaded private file
- `env_file`: a pasted `.env` block to parse and merge

### `write_policy`

Controls how values are applied. The default project policy should be conservative:

- `mode: merge_only`
- `no_overwrite: true`
- `backup: true`

## Redaction rule

Status responses may include names and target paths, but must never include secret values.
