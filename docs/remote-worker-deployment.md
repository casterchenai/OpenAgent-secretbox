# Real Linux Worker: local isolated deployment

This is the Phase 2 Linux implementation, not the Phase 1 `MockWorker`.
Windows hosts run the Linux containers through Docker Desktop. Tasks cross an
mTLS connection between separate client and worker containers; actual PostgreSQL
17 clients connect to a separate PostgreSQL server over verified TLS.

The shipped restore adapter is intentionally limited to the **reviewed synthetic
`lab-public-v1` backup and `isolated-local` target**. It restores one table, two
synthetic rows and one primary-key constraint. It does not claim arbitrary
business-backup compatibility, production readiness or an ECS/RDS acceptance run.
No existing local Supabase container, volume, password or certificate is used.

## Start

Requirements: Docker with Linux containers, Compose v2, available localhost port
17443. For host-side automated tests/MCP, install this repository's `.[dev]`
dependencies in a Python 3.10+ venv.

```powershell
docker compose -f deploy/linux-worker/compose.yaml up -d --build
.\.venv\Scripts\python.exe .github/scripts/accept_linux_worker.py
.\.venv\Scripts\python.exe .github/scripts/smoke_worker_mcp.py
```

The first command creates only the `secretbox-worker-lab` Compose project.
Images are built without workspace secrets; the Docker build context is
allowlisted. The PostgreSQL base image digest is pinned. Debian packages are
resolved at build time, so a Git SHA alone is not a reproducible image digest;
retain the built image digest for deployment provenance.

## Components and privilege boundary

| Component | Runtime authority |
|---|---|
| bootstrap | Offline trusted provisioning; holds RAM-backed credential volumes mounted |
| database | Disposable PostgreSQL, no host-published DB port, separate internal network |
| provision | One-time trusted fixture/role/fingerprint/backup manifest setup |
| provider | UID 10002, no network, exact target and UID 10001 peer allowlist |
| worker | UID 10001, read-only root, no capabilities, no-new-privileges, bounded memory/PIDs |
| ingress | Fixed-destination, bounded TCP relay; publishes only 127.0.0.1:17443; no keys or TLS termination |
| agent | UID 10003, only agent mTLS certificate; no provider, database or task-state mounts |
| owner | UID 10004, separate owner certificate; may approve a preflight |

The provider grants a short-lived nonce once, persists replay records, and reads
only its owner-only password file on tmpfs. The worker's `PGPASSFILE` is an
anonymous `memfd` with mode 0600, passed as an FD to fixed PostgreSQL commands.
The password is absent from worker argv and environment. Raw stderr is discarded,
stdout is bounded, and only allowlisted typed results cross the API/MCP boundary.

Passwords and TLS private keys never enter the build image, Git or host task
arguments. PostgreSQL retains its normal password verifier in the isolated DB.
The official PostgreSQL entrypoint uses its standard password-file bootstrap;
the no-secret-environment assertion specifically covers the Worker subprocess
path, not every internal step of the trusted database initialization.
Python does not guarantee elimination of all memory copies, and tmpfs may be
swapped by the host. Strict deployments must disable/protect swap and dumps.

**Docker administrator access is effectively privileged.** A hostile agent with
unrestricted Docker/shell access could enter the owner/provider containers.
This design prevents normal MCP credential transit; it does not make Docker
admin access safe for an untrusted agent. Deploy an independently administered
worker host or constrained identity for stronger isolation.

## Actual task API

The worker is reachable through the encrypted relay at `https://127.0.0.1:17443` on the host and
`https://worker:8443` on the internal network. Every endpoint requires a valid
client certificate from the lab CA. The server certificate names `worker`;
host-native clients must map that name to loopback and validate it, not disable
TLS verification. The bundled container client handles this automatically.

| Method | Path | Role and behavior |
|---|---|---|
| POST | `/v1/tasks` | agent/owner; exact metadata schema |
| GET | `/v1/tasks/{task_id}` | agent/owner; public status and typed counts |
| POST | `/v1/tasks/{task_id}/cancel` | agent/owner; `{}`; running cancellation is only a request until terminal |
| POST | `/v1/tasks/{task_id}/confirm` | owner only; exact `preflight_id` from preflight |

PowerShell example, containing metadata only:

```powershell
$request = @{
  request_id = "check-" + [guid]::NewGuid().ToString("N")
  operation = "rds.connectivity_check"
  target_id = "isolated-local"
  parameters = @{}
  ttl_seconds = 60
} | ConvertTo-Json -Compress
$created = $request | docker compose -f deploy/linux-worker/compose.yaml exec -T agent `
  python3 -m openagent_secretbox.linux_worker.client create | ConvertFrom-Json
docker compose -f deploy/linux-worker/compose.yaml exec -T agent `
  python3 -m openagent_secretbox.linux_worker.client status $created.task_id
```

For restore, use `operation: rds.restore_public_business` and:

```json
{"backup_id":"lab-public-v1","scope":"public_business_only","allow_existing_data":false}
```

Wait for `awaiting_confirmation`. A trusted user invokes the **owner** client:

```powershell
@{preflight_id = "<preflight_id from status>"} | ConvertTo-Json -Compress |
  docker compose -f deploy/linux-worker/compose.yaml exec -T owner `
  python3 -m openagent_secretbox.linux_worker.client confirm <task_id>
```

The Agent MCP interface deliberately has no confirm tool. Approval is bound to
the task and configured backup hashes and expires in at most 300 seconds.
Target fingerprint, empty-database policy and hashes are rechecked immediately
before execution. Archive and restore list are mounted read-only.
Restore uses `--single-transaction --exit-on-error --no-owner --no-privileges`.
Cancelling a running or already-committed restore is **not** a rollback guarantee.
An uncertain restart never automatically retries the restore.

Verification uses `rds.verify_restore` with
`{"expected_manifest":"lab-public-v1"}` and returns counts, not business rows.

## Separate MCP adapter

The actual stdio entrypoint is:

```powershell
.\.venv\Scripts\python.exe -m openagent_secretbox.linux_worker.mcp_bridge `
  --compose "E:\Users\HUAWEI\Documents\OpenAgent-secretbox\deploy\linux-worker\compose.yaml"
```

Register that command and arguments with the desired MCP client outside the
intake skill. It exposes exactly:

- `create_remote_task(request)`
- `get_remote_task_status(task_id)`
- `cancel_remote_task(task_id)`

The service is named `secretbox-linux-worker`; the original intake MCP service
is unchanged. The bridge only calls the agent container. It does not read the
database password or TLS key, and rejects unknown result fields. Installing
this code does not automatically reload an already-running app's tool catalog.

## Restart, shutdown and reset

To restart the worker without running provisioning dependencies:

```powershell
docker compose -f deploy/linux-worker/compose.yaml restart --no-deps worker
```

Task metadata and provider replay state are persisted in dedicated SQLite
volumes. Startup marks any uncertain nonterminal task failed (`SBX-008`) and
does not retry. A child launcher uses parent-death SIGKILL, process groups are
killed on cancellation/timeout, and Docker destroys the process namespace on
container death. This was tested with a real blocked database client.

Keys/passwords are intentionally volatile. Certificates expire after seven
days. Stopping all holders of a tmpfs volume or restarting Docker may lose keys.
Loss fails closed; it is not a production credential recovery mechanism.
For this disposable lab only, reset explicitly:

```powershell
docker compose -f deploy/linux-worker/compose.yaml down --volumes
docker compose -f deploy/linux-worker/compose.yaml up -d --build
```

**Reset irreversibly deletes only this lab's test DB, task history, credentials
and volumes.** Never apply it to another Compose project. The automated
acceptance script drops only `public.sbx_fixture` in `sbx_lab`, pauses only this
lab's database, restarts only this lab's worker/provider, and leaves an empty
synthetic target with a working API.

## Before connecting an actual ECS/RDS

Replace lab provisioning with an operator-controlled credential provider and
certificate lifecycle, configure independently verified instance fingerprints,
use a least-privileged database role, and review the real archive/object manifest
and verification schema. Restrict network access and service identities on that
host. Do not simply point the lab at production or expand accepted request
parameters. Full restore rollback, production approval policy, audit retention,
credential rotation and independent security review remain release gates.
