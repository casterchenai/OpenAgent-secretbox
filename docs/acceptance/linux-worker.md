# Linux Worker acceptance record

## Scope

Real Linux containers on Docker Desktop, dedicated `secretbox-worker-lab`
networks/volumes and PostgreSQL 17.11. No existing Supabase data, cloud ECS/RDS,
production credentials or production database were used.

The tested implementation is the Git revision containing this record, not the
old `6dc9c68` baseline. The pre-revision-label acceptance image was
`sha256:60cb52b6c569448fcb832c645bd3030558b212ac819d005092857907dd07adf9`.
Deployment may attach the final Git revision as an OCI label; that changes image
metadata/digest without changing tested source. The source base image digest is
pinned in the Dockerfile.

## Automated results

| Check | Result |
|---|---|
| Full Windows pytest | 274 passed, 4 skipped |
| Ruff | Passed |
| Mypy, Windows target | Passed, 22 source files |
| Mypy, Linux target | Passed, 22 source files |
| Isolated sdist/wheel build | Passed |
| Fresh-venv wheel installation outside repository | Passed, including Worker MCP entrypoint |
| Real Linux execution/fault script | Passed |
| Real stdio MCP to mTLS to PostgreSQL | Passed |
| Host-published port and authenticated relay | Passed |

The four pytest skips cover unavailable Windows symlinks and POSIX permission
tests. Linux execution/failure behavior was tested through containers, not
inferred from those Windows skips.

## Real execution assertions

- Verified TLS connection to PostgreSQL returns only connection success and major version.
- Unauthenticated clients cannot call the API; the host endpoint validates as `worker`.
- The ingress relays encrypted TLS unchanged and has no private key.
- Unknown targets, operations, arbitrary parameters and invalid TTL are rejected.
- Duplicate requests are rejected, including after worker restart.
- Agent container lacks provider, DB secret and task-state mounts.
- The agent certificate cannot approve restore; owner approval is separately authenticated.
- Actual `pg_restore` restores one reviewed synthetic table, two rows and one PK constraint.
- Actual count verification succeeds; a second restore fails the nonempty-target check.
- Duplicate approval cannot execute again.
- Provider rejects replayed/expired grants, wrong targets and unauthorized peer UID.
- Unsafe credential-file permissions cause credential acquisition to fail closed.
- An active pgpass is an anonymous 0600 descriptor; the actual password is absent
  from the observed worker command line and environment.
- Real sleeping SQL is terminated at the runtime deadline.
- Oversized stdout is rejected; invalid stdout and PostgreSQL stderr errors
  produce stable codes, not raw output.
- Running cancellation completes only after process-group cleanup.
- Paused DB produces bounded failure; expired queued work never runs.
- SIGKILL/restart marks uncertain tasks failed without automatic retry.
- No PostgreSQL child process or anonymous credential fd survives tested cleanup.
- Provider outage fails closed and recovery restores service.
- Captured service logs do not contain this run's generated passwords/private keys.
- The MCP adapter discovers exactly create/status/cancel, completes a real task,
  and does not change an already-successful task to cancelled.

## Reproduce and manually confirm

```powershell
docker compose -f deploy/linux-worker/compose.yaml up -d --build
.\.venv\Scripts\python.exe .github/scripts/accept_linux_worker.py
.\.venv\Scripts\python.exe .github/scripts/smoke_worker_mcp.py
```

- [ ] Submit `rds.connectivity_check` and observe `succeeded / connected: true`.
- [ ] Submit the reviewed restore and observe `awaiting_confirmation`.
- [ ] Confirm through the owner client and observe restored/verified counts.
- [ ] Attempt the same restore again and observe `RDS-003`, not overwrite.
- [ ] Confirm chat/tool results contain only metadata/counts, never passwords or raw logs.

See [deployment and actual interfaces](../remote-worker-deployment.md) for exact
metadata, approval, reset and MCP commands.

## Retained state and limitations

Acceptance removes the synthetic table and leaves the API/provider/empty test
target running for user validation. Test credentials remain only in the lab's
RAM-backed secret volumes; metadata and the disposable PostgreSQL data directory
remain in this lab's own volumes. The explicit lab reset command destroys them.

This is not independent security certification, production migration acceptance,
an arbitrary-backup restore engine or a cloud instance-fingerprint verification.
The adapter intentionally restricts restore to `lab-public-v1`. No automatic
production rollback, audit-retention service or cloud KMS integration is claimed.
Unrestricted Docker administrator access remains outside the credential isolation
boundary. Review the full limitations in the deployment document before reuse.
