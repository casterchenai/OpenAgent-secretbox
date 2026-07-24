# Hermes Agent integration

This directory provides a native Hermes Agent skill for OpenAgent SecretBox.
The preferred path uses SecretBox's local stdio MCP server: the trusted user
fixes the workspace and host target policy once, then Hermes can open, check,
and cancel browser-mediated intake without receiving a bearer URL or value.

## Default workspace (host-wide)

Unless a project explicitly needs its own secret root, register SecretBox once
against the Hermes host default:

```text
~/.hermes/workspaces/default
```

Examples after expansion:

| Host | Absolute workspace |
|---|---|
| root Hermes install | `/root/.hermes/workspaces/default` |
| user install | `$HOME/.hermes/workspaces/default` |

Create it once in a trusted terminal:

```bash
mkdir -p ~/.hermes/workspaces/default/secrets
chmod 700 ~/.hermes/workspaces/default ~/.hermes/workspaces/default/secrets
```

Agent rule encoded in the skill:

- if the user does **not** name another absolute workspace, always use the
  pre-registered MCP workspace (the default above);
- never ask for a workspace path on routine secret intake;
- never pass `workspace_root` / `allowed_targets` in MCP requests;
- if the user wants project-local secrets under `/path/to/project`, stop and
  give a trusted-terminal re-registration command; do not reconfigure MCP from
  chat.

Default allowlist remains `.env`, `.env.*`, and `secrets/*` under that root.

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

Run this yourself in a trusted local terminal, outside an active Hermes chat.

### Host-wide default (recommended)

```bash
# resolve secretbox-mcp with `command -v secretbox-mcp` or the Hermes venv path
hermes mcp add openagent-secretbox \
  --command "$(command -v secretbox-mcp)" \
  --args --workspace "$HOME/.hermes/workspaces/default"
```

Root Hermes installs commonly use:

```bash
hermes mcp add openagent-secretbox \
  --command /usr/local/lib/hermes-agent/venv/bin/secretbox-mcp \
  --args --workspace /root/.hermes/workspaces/default
```

### Project-local override (only when user insists)

```bash
hermes mcp add openagent-secretbox \
  --command "$(command -v secretbox-mcp)" \
  --args --workspace "/absolute/path/to/project"
```

`--args` must be the final Hermes option. Everything after it is passed to
`secretbox-mcp`. On Windows, an absolute executable and workspace are valid:

```powershell
hermes mcp add openagent-secretbox --command "C:\path\to\secretbox-mcp.exe" --args --workspace "$env:USERPROFILE\.hermes\workspaces\default"
```

### If `hermes mcp add` misparses `--workspace`

Some Hermes CLI builds treat `--workspace` after `--args` as a Hermes flag and
fail with `unrecognized arguments: --workspace`. In that case, write the entry
directly into `~/.hermes/config.yaml` from a trusted terminal:

```yaml
mcp_servers:
  openagent-secretbox:
    command: /absolute/path/to/secretbox-mcp
    args:
      - --workspace
      - /absolute/path/to/.hermes/workspaces/default
    enabled: true
    timeout: 120
    connect_timeout: 60
```

Then:

```bash
hermes mcp test openagent-secretbox
```

The server always authorizes `.env`, `.env.*`, and `secrets/*`. A trusted user
may explicitly extend that startup policy with a repeated argument:

```bash
hermes mcp add openagent-secretbox \
  --command "$(command -v secretbox-mcp)" \
  --args --workspace "$HOME/.hermes/workspaces/default" \
  --allow-target "config/private.json"
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

The skill needs the full directory, not just `SKILL.md`:

```text
openagent-secretbox/
├── SKILL.md
├── references/trusted-user-boundary.md
└── templates/request-v1.json
```

`SKILL.md` links the two support files. If they are missing, Hermes cannot load
the trusted-user boundary notes or the request template.

### Preferred: local checkout or `external_dirs`

If you already have this repository checked out, point Hermes at the complete
skill collection:

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

`external_dirs` reads the complete skill directory in place, so the adjacent
`references/` and `templates/` directories remain available without a separate
download or copy step.

You can also copy the complete skill directory into the Hermes skills tree:

```bash
SRC=/absolute/path/to/OpenAgent-secretbox/integrations/hermes/skills/openagent-secretbox
DST=~/.hermes/skills/security/openagent-secretbox
mkdir -p "$DST/references" "$DST/templates"
cp -a "$SRC/SKILL.md" "$DST/"
cp -a "$SRC/references/." "$DST/references/"
cp -a "$SRC/templates/." "$DST/templates/"
```

Verify the installed bundle before using the skill:

```bash
find ~/.hermes/skills/security/openagent-secretbox -type f | sort
```

A complete install must include all three paths:

```text
~/.hermes/skills/security/openagent-secretbox/SKILL.md
~/.hermes/skills/security/openagent-secretbox/references/trusted-user-boundary.md
~/.hermes/skills/security/openagent-secretbox/templates/request-v1.json
```

### Optional: direct URL install

After these files are published to the repository's default `main` branch, you
can use Hermes's documented direct-URL form. This makes the fetched `SKILL.md`
revision explicit instead of relying on source-router interpretation of a
repository/subdirectory identifier.

Inspect the community skill before installing it:

```bash
hermes skills inspect "https://raw.githubusercontent.com/casterchenai/OpenAgent-secretbox/main/integrations/hermes/skills/openagent-secretbox/SKILL.md"
```

Install the same URL into the `security` category:

```bash
hermes skills install "https://raw.githubusercontent.com/casterchenai/OpenAgent-secretbox/main/integrations/hermes/skills/openagent-secretbox/SKILL.md" --category security --yes
```

For a reproducible review, replace `main` in both commands with the same full
Git commit SHA. A raw URL returns 404 until that revision and the integration
files have been pushed to GitHub.

#### Important: verify the URL install is complete

Hermes does not enumerate the surrounding GitHub directory for a direct URL.
It downloads `SKILL.md`, and may also try to fetch only the relative paths that
`SKILL.md` explicitly references under allowlisted support directories such as
`references/` and `templates/`.

Do **not** assume the install is complete just because the command exits 0.
Inspect the install summary and the installed files:

```bash
# The install summary should list more than SKILL.md.
# Then verify on disk:
find ~/.hermes/skills/security/openagent-secretbox -type f | sort
```

If the directory contains only `SKILL.md`, the install is incomplete. Hermes
may report success while leaving the skill unable to open:

- `references/trusted-user-boundary.md`
- `templates/request-v1.json`

Repair an incomplete URL install from a local checkout:

```bash
SRC=/absolute/path/to/OpenAgent-secretbox/integrations/hermes/skills/openagent-secretbox
DST=~/.hermes/skills/security/openagent-secretbox
mkdir -p "$DST/references" "$DST/templates"
cp -a "$SRC/SKILL.md" "$DST/"
cp -a "$SRC/references/." "$DST/references/"
cp -a "$SRC/templates/." "$DST/templates/"
find "$DST" -type f | sort
```

Or reinstall from a complete local skill directory via `external_dirs` as shown
above.

### After install

Start a new session or run `/reload-skills`, then invoke:

```text
/openagent-secretbox prepare the credential intake for this project
```

Treat the checkout as agent-writable unless filesystem
permissions make it read-only.

## MCP flow

1. Hermes prepares a request object containing names, descriptions, relative
   targets, and conservative write policy only. It omits `workspace_root` and
   `allowed_targets`. It does not ask for a workspace path when MCP is already
   registered; writes land under the fixed host default unless the trusted user
   re-registered a project path.
2. Hermes calls `open_secret_intake`. The trusted MCP process applies its fixed
   workspace/allowlist and opens the one-time URL directly in the local browser.
3. MCP returns only a non-secret intake id, redacted status, and expiry. It
   never returns the intake URL, token, session id, or submitted values.
4. The user enters values in the browser. Hermes may call the status tool, or
   cancel the intake at the user's request.
5. On success Hermes reports only names, relative targets, and redacted status.
   Absolute location is implied by the registered workspace
   (`~/.hermes/workspaces/default` by default).

Cancellation is atomic only before secret application starts. If cancel returns
`apply_in_progress`, do not retry or open a replacement intake; poll the existing
`intake_id` until it reports the authoritative `applied` or `failed` result.

Do not paste the intake URL, its fragment token, submitted values, or target
file contents into Hermes.

## Manual fallback

When the MCP tools are not configured, the skill may create and validate a
metadata-only request file. Unless the user already named another absolute path,
use the host default workspace. The skill prints this command but never executes
it:

```bash
secretbox serve \
  --workspace "$HOME/.hermes/workspaces/default" \
  --request "/absolute/request.json"
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
