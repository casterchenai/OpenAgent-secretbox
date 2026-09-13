# Remote Worker protocol: Phase 1

This document describes the retained Mock protocol. The implemented Phase 2
mTLS HTTP and separate MCP interfaces are documented in
[remote-worker-deployment.md](remote-worker-deployment.md). Phase 2 binds requests
through authenticated TLS and durable unique request IDs, not the Mock's
in-process HMAC token. Do not expose Mock token APIs remotely.

Status: local simulation only. No remote daemon, network transport, MCP tools,
real secret provider, subprocess, or database connection is enabled.
The existing intake/status/cancel MCP contract is unchanged.

## Request

`MockWorker.create` accepts exactly `request_id`, `operation`, `target_id`,
and `parameters`. Unknown fields are rejected. Identifiers are bounded ASCII.
Targets are supplied by the trusted harness, never created by requests.
Only isolated targets and per-target operations are accepted.

```json
{
  "request_id": "restore-test-01",
  "operation": "rds.restore_public_business",
  "target_id": "isolated-test",
  "parameters": {
    "backup_id": "reviewed-backup",
    "scope": "public_business_only",
    "allow_existing_data": false
  }
}
```

## Authorization and lifecycle

The local harness signs canonical JSON using HMAC-SHA256 with a random
per-instance key. The signature binds task ID, worker ID, complete request,
expiry and nonce. Tokens stay on the trusted harness interface. They must not
be returned to an agent. Replay consumption and state updates share a lock.
Duplicate request IDs are rejected; capacity exhaustion fails closed.
Restart destroys the key and invalidates old tokens. This is NOT cross-process
registration, durable replay protection, mTLS, or a production token service.

`created -> validated -> queued -> running -> terminal`.
Restore inserts `awaiting_confirmation` after simulated preflight and before
running. Confirmation is a trusted harness method, not an agent capability.
Invalid requests raise a stable error without creating a task.

Queue TTL: 1-600 seconds. Confirmation: at most 300 seconds and never past
queue expiry. Simulated runtime: at most 1800 seconds. Polling advances the
simulation using a monotonic clock; no real process runs between polls.
Terminal results are immutable. Cleanup failure overrides success/cancellation
with `failed / SBX-014`. Cancellation cannot retroactively undo a completed task.

## Public result

Only task ID, status, fixed error code, exit code, `simulation` and
`cleanup_completed` booleans, fixed lifecycle events and preflight ID leave
the simulator. No raw stdout/stderr, free-form exceptions, business rows,
connection strings, tokens or credentials are serialized.
Zero exit code means simulation succeeded, NOT that a database was restored.

Implemented errors: SBX-001 invalid request, SBX-002 forbidden target,
SBX-003 forbidden operation, SBX-004 confirmation invalid, SBX-005 expiry,
SBX-006 replay, SBX-007 signature mismatch, SBX-008 capacity/crash,
SBX-012 runtime timeout, SBX-013 cancellation, SBX-014 cleanup failure,
RDS-008 simulated verification failure, RDS-010 simulated fingerprint failure.
Other design error codes remain reserved for real adapters.
