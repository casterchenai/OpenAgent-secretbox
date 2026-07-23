# Hermes Agent integration

This directory provides a native Hermes Agent skill for OpenAgent SecretBox.
The preferred path uses SecretBox's local stdio MCP server: the trusted user
fixes the workspace and host target policy once, then Hermes can open, check,
and cancel browser-mediated intake without receiving a bearer URL or value.

## 1. Install SecretBox with MCP support

Install the package in an environment visible to Hermes:

```bash
python -m pip install "openagent-secretbox[mcp]"
secretbox-mcp --help
```

For a development checkout, install the checkout rather than a registry build:

```bash
python -m pip install -e ".[mcp]"
```

## 2. Register the trusted MCP boundary

Run this yourself in a trusted local terminal, outside an active Hermes chat:

```bash
hermes mcp add openagent-secretbox --command secretbox-mcp --args --workspace "/absolute/path/to/project"
```

`--args` must be the final Hermes option. Everything after it is passed to
`secretbox-mcp`. On Windows, an absolute executable and workspace are valid:

```powershell
hermes mcp add openagent-secretbox --command "C:\path\to\secretbox-mcp.exe" --args --workspace "E:\path\to\project"
```

The server always authorizes `.env`, `.env.*`, and `secrets/*`. A trusted user
may explicitly extend that startup policy with a repeated argument:

```bash
hermes mcp add openagent-secretbox --command secretbox-mcp --args --workspace "/absolute/project" --allow-target "config/private.json"
```

Do not ask Hermes to run or modify these commands. The user-selected
`--workspace` and any `--allow-target` values are the authorization boundary.

The add flow probes the stdio server and should discover exactly:

- `open_secret_intake`
- `get_secret_intake_status`
- `cancel_secret_intake`

Enable those three tools, then verify the connection:

```bash
hermes mcp test openagent-secretbox
```

Start a new Hermes session or run `/reload-mcp`. With the registered server
name above, Hermes exposes these tool names:

- `mcp__openagent_secretbox__open_secret_intake`
- `mcp__openagent_secretbox__get_secret_intake_status`
- `mcp__openagent_secretbox__cancel_secret_intake`

## 3. Install the skill

After these files are published to the repository's default `main` branch,
use Hermes's documented direct-URL form. This makes the fetched `SKILL.md`
revision explicit instead of relying on source-router interpretation of a
repository/subdirectory identifier.

Inspect the community skill before installing it:

```bash
hermes skills inspect "https://raw.githubusercontent.com/casterchenai/OpenAgent-secretbox/main/integrations/hermes/skills/openagent-secretbox/SKILL.md"
```

Install the same URL into the `security` category:

```bash
hermes skills install "https://raw.githubusercontent.com/casterchenai/OpenAgent-secretbox/main/integrations/hermes/skills/openagent-secretbox/SKILL.md" --category security
```

For a reproducible review, replace `main` in both commands with the same full
Git commit SHA. A raw URL returns 404 until that revision and the integration
files have been pushed to GitHub.

Hermes does not enumerate the surrounding GitHub directory for a direct URL.
It downloads `SKILL.md` plus only the paths that `SKILL.md` explicitly
references under its allowlisted support directories. This skill explicitly
links both bundled support files, so installation also fetches:

- `references/trusted-user-boundary.md`
- `templates/request-v1.json`

The install summary should list those paths with `SKILL.md`. If either fetch
fails, Hermes rejects the bundle instead of silently installing an incomplete
skill.

For a local checkout, add the skill collection to `~/.hermes/config.yaml`:

```yaml
skills:
  external_dirs:
    - /absolute/path/to/OpenAgent-secretbox/integrations/hermes/skills
```

On Windows, use a YAML-safe path such as:

```yaml
skills:
  external_dirs:
    - E:/path/to/OpenAgent-secretbox/integrations/hermes/skills
```

Start a new session or run `/reload-skills`, then invoke:

```text
/openagent-secretbox prepare the credential intake for this project
```

`external_dirs` reads the complete skill directory in place, so the adjacent
`references/` and `templates/` directories remain available without a separate
download or copy step. Treat the checkout as agent-writable unless filesystem
permissions make it read-only.

## MCP flow

1. Hermes prepares a request object containing names, descriptions, relative
   targets, and conservative write policy only. It omits `workspace_root` and
   `allowed_targets`.
2. Hermes calls `open_secret_intake`. The trusted MCP process applies its fixed
   workspace/allowlist and opens the one-time URL directly in the local browser.
3. MCP returns only a non-secret intake id, redacted status, and expiry. It
   never returns the intake URL, token, session id, or submitted values.
4. The user enters values in the browser. Hermes may call the status tool, or
   cancel the intake at the user's request.

Cancellation is atomic only before secret application starts. If cancel returns
`apply_in_progress`, do not retry or open a replacement intake; poll the existing
`intake_id` until it reports the authoritative `applied` or `failed` result.

Do not paste the intake URL, its fragment token, submitted values, or target
file contents into Hermes.

## Manual fallback

When the MCP tools are not configured, the skill may create and validate a
metadata-only request file. It prints this command but never executes it:

```bash
secretbox serve --workspace "/absolute/project" --request "/absolute/request.json"
```

The trusted user runs it in a separate local terminal. If browser auto-open
fails, the user may privately add `--no-open`; the printed URL must never be
pasted into chat or logs.

## Security boundary

The MCP design prevents bearer URLs and submitted values from crossing the tool
protocol, but the skill remains a procedural guardrail rather than a sandbox.
Hermes Agent's official security model states that skills, plugins, MCP
subprocess filtering, output redaction, and approval heuristics are not complete
isolation boundaries. A Hermes process with unrestricted local filesystem
access can still read files available to its OS account.

For strict separation, run Hermes under a different OS identity or a
whole-process sandbox that cannot read secret targets. See the
[trusted user boundary](skills/openagent-secretbox/references/trusted-user-boundary.md).

## Compatibility basis

This integration follows Hermes Agent upstream `main` commit
`08298dabbd202eac2ce0b66deee0452863c738e0`, reviewed on 2026-07-23:

- https://github.com/NousResearch/hermes-agent/blob/main/website/docs/guides/work-with-skills.md
- https://github.com/NousResearch/hermes-agent/blob/main/website/docs/guides/use-mcp-with-hermes.md
- https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/mcp.md
- https://github.com/NousResearch/hermes-agent/blob/main/website/docs/user-guide/features/skills.md
- https://github.com/NousResearch/hermes-agent/blob/main/SECURITY.md
