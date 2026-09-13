# Remote Worker threat model

Phase 2 implementation details and remaining release gates are in
[deployment](remote-worker-deployment.md). The table below is the Phase 1 design
baseline. The local Linux lab now verifies mTLS, durable replay records,
restricted credential delivery and actual process cleanup, but not independent
host isolation, production rollback or cloud instance identity verification.

## Boundary and data flow

Current: test metadata -> in-process broker -> signed simulated dispatch ->
fixed operation simulation -> closed public result.

Future: agent metadata -> SecretBox policy/owner approval -> authenticated
worker channel -> isolated worker -> fixed database target -> typed counts.
Secrets must flow from a trusted provider directly to the worker, never
through agent requests or results.

## Threats and controls

| Threat | Current control | Required before real execution |
|---|---|---|
| Arbitrary shell or destination | No shell/network adapter; exact parameter sets | Fixed executable/argv, environment and egress allowlists |
| Task tampering/replay | Full-request MAC, nonce, lock, bounded TTL | Independent worker keys, mTLS, durable replay ledger |
| Production overwrite | Reject non-isolated target configuration | Verify provider instance ID and DB fingerprint independently of request |
| Secret in error/output | Discard all raw output; fixed events only | Typed parser, no raw exception logging, bounded output capture |
| Confirmation bypass | Separate harness-only confirmation method | Authenticated owner UI, CSRF defense, expiring approval bound to manifest hash |
| Worker crash/partition | Simulated terminal failure and cleanup | Process groups, watchdog, lease expiry, restart reconciliation |
| Malicious backup | No backup is executed | Reviewed object manifest, hash, schema/object exclusions, no platform triggers/roles |
| Worker compromise | Simulator has no credentials | Separate OS user, least-privilege DB role, no production network or app-file access |

The mock's Python methods are not an authorization boundary against an attacker
in the same interpreter. Signing and confirmation must be split across trusted
components before exposure. A compromised real worker can use credentials it
holds; redaction does not protect against that compromise.

## Rollback

This module is not connected to the intake MCP service. Stop using the mock to
disable it; existing intake behavior is unaffected. Real restore is not
transactionally reversible by cancellation. Before enabling it, rehearse
discarding/recreating only the isolated database and restoring a reviewed
backup. Production migration requires a separate target, approval policy,
maintenance window and rollback drill; restore must never enable production.
