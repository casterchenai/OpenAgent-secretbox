# Remote Worker operations

Historical Mock scope follows. The real Phase 2 adapter implements these three
operations for a reviewed synthetic PostgreSQL fixture only; see
[deployment and API](remote-worker-deployment.md). General business-backup
support and real cloud target onboarding remain outside this adapter.

All three operations currently SIMULATE behavior. None runs SQL or pg_restore.

| Operation | Exact parameters | Real-adapter release gate |
|---|---|---|
| `rds.connectivity_check` | empty object | Fixed endpoint, TLS, role and major-version checks; no business data |
| `rds.restore_public_business` | backup_id, scope=`public_business_only`, allow_existing_data=false | Isolated fingerprint, empty DB, reviewed backup hash/object manifest, owner approval |
| `rds.verify_restore` | expected_manifest | Reviewed counts for tables, indexes, sequences, constraints, RLS, functions and account access |

The simulator's preflight success is a fixture, not evidence about any server.
Real preflight must reject unknown instance, wrong version, nonempty DB,
unverified backup and unexpected platform objects. Reject auth/storage/neon/
vault/_realtime schemas, platform event triggers, role passwords and external
network jobs. Filtering by schema name alone is insufficient for untrusted SQL.
Restore success must include post-restore verification; a zero pg_restore exit
code alone is not sufficient.

Backup IDs must eventually resolve through a trusted immutable registry;
never accept a path, URL, arbitrary SQL or flags from agent metadata.
Recheck target and manifest immediately before execution to prevent stale
approval and preflight-to-execution changes.
