# Remote Worker secret boundary

The sections below record Phase 1 constraints. Phase 2 now implements a
UID-restricted Unix socket provider with replay grants and tmpfs credentials,
and an actual 0600 memfd pgpass execution path. Its limitations, lifecycle and
trust boundaries are specified in [deployment](remote-worker-deployment.md).

Phase 1 does not read `.env`, request real secrets, inject credentials or write
temporary credential files. Its random internal signing key is ephemeral and
not returned in public results. Test scenarios contain disposable fake text.

Raw logs are dropped entirely rather than sanitized by regex and then released.
Regex-only filtering cannot guarantee arbitrary secrets or business rows are
removed. Future results must be built from allowlisted typed observations and
fixed event codes, never free-form database errors.

Before Phase 2, select an operator-controlled provider. Worker credentials must
not share the portal application's OS identity or read its environment files.
Use an isolated Linux worker and restricted credential-consuming subprocess.
Never place passwords in argv, SSH shell strings, PGPASSWORD, Git, audit logs,
or persistent environment files.

The proposed pgpass memory-fd mechanism is not implemented or certified here.
Validate actual libpq behavior, fd inheritance, permissions and escaping on the
target Linux/PostgreSQL versions before choosing it. A fallback is allowed only
in restricted tmpfs with 0600 permissions, finally cleanup and crash cleanup.
Python object deletion does not guarantee secure memory erasure; do not claim
credentials are destroyed merely because a variable is deleted.

Audit only fixed metadata and stable error codes. Production audit storage and
retention (180 days metadata, one year security events) remain unimplemented.
Do not retain raw stdout/stderr even on failure.
