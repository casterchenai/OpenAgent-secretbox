"""Disposable Linux lab provisioning. Never prints generated credentials."""

import datetime
import hashlib
import json
import os
import secrets
import subprocess
import sys
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID


def write(path, value, uid=0, gid=0, mode=0o400):
    path = Path(path)
    path.write_bytes(value if isinstance(value, bytes) else value.encode())
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def directory(path, uid, gid, mode=0o700):
    os.chown(path, uid, gid)
    os.chmod(path, mode)


def bootstrap():
    # Fresh lab only. Never rotate passwords underneath an existing database.
    if Path("/worker-config/worker.json").exists():
        if not Path("/tls-worker/identity.key").exists():
            raise SystemExit("Ephemeral keys were lost: explicitly reset the disposable lab")
        while True:
            time.sleep(60)
    os.umask(0o077)
    admin = secrets.token_urlsafe(48)
    password = secrets.token_urlsafe(48)
    directory("/db-secrets", 0, 0, 0o755)
    write("/db-secrets/admin-password", admin, 999, 999)
    write("/db-secrets/worker-password", password)
    directory("/provider-secrets", 10002, 10001)
    write("/provider-secrets/database-password", password, 10002, 10001)
    directory("/provider-socket", 10002, 10001, 0o770)
    directory("/provider-state", 10002, 10001)
    directory("/worker-state", 10001, 10001)
    directory("/worker-config", 0, 0, 0o755)
    directory("/backup", 0, 0, 0o755)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    now = datetime.datetime.now(datetime.timezone.utc)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "SecretBox disposable lab CA")])
    ca = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - datetime.timedelta(minutes=5))
        .not_valid_after(now + datetime.timedelta(days=7))
        .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
        .sign(key, hashes.SHA256())
    )
    for name, cn, uid, server in (
        ("db", "database", 999, True),
        ("worker", "worker", 10001, True),
        ("agent", "sbx-agent", 10003, False),
        ("owner", "sbx-owner", 10004, False),
    ):
        identity = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        builder = (
            x509.CertificateBuilder()
            .subject_name(x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)]))
            .issuer_name(subject)
            .public_key(identity.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(now - datetime.timedelta(minutes=5))
            .not_valid_after(now + datetime.timedelta(days=7))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(
                x509.ExtendedKeyUsage(
                    [
                        ExtendedKeyUsageOID.SERVER_AUTH
                        if server
                        else ExtendedKeyUsageOID.CLIENT_AUTH,
                    ]
                ),
                critical=True,
            )
        )
        if server:
            builder = builder.add_extension(
                x509.SubjectAlternativeName([x509.DNSName(cn)]),
                critical=False,
            )
        cert = builder.sign(key, hashes.SHA256())
        root = f"/tls-{name}"
        directory(root, uid, uid, 0o700)
        write(
            root + "/identity.key",
            identity.private_bytes(
                serialization.Encoding.PEM,
                serialization.PrivateFormat.PKCS8,
                serialization.NoEncryption(),
            ),
            uid,
            uid,
        )
        write(root + "/identity.crt", cert.public_bytes(serialization.Encoding.PEM), uid, uid)
        write(root + "/ca.crt", ca.public_bytes(serialization.Encoding.PEM), uid, uid)
    write("/worker-config/db-ca.crt", ca.public_bytes(serialization.Encoding.PEM), mode=0o444)
    print("PASS bootstrap: generated temporary credentials; values suppressed")
    Path("/worker-config/bootstrap.ready").touch()
    # Hold the tmpfs mounts for the lifetime of the disposable lab.
    while True:
        time.sleep(60)


def provision():
    if Path("/worker-config/worker.json").exists():
        print("PASS existing lab configuration retained; no re-provisioning")
        return
    env = {
        "PATH": "/usr/lib/postgresql/17/bin:/usr/bin:/bin",
        "PGHOST": "database",
        "PGPORT": "5432",
        "PGDATABASE": "sbx_lab",
        "PGUSER": "postgres",
        "PGSSLMODE": "verify-full",
        "PGSSLROOTCERT": "/db-tls/ca.crt",
    }
    fd = os.memfd_create("sbx-admin-pgpass", os.MFD_CLOEXEC)
    os.fchmod(fd, 0o600)
    os.write(
        fd,
        b"database:5432:sbx_lab:postgres:"
        + Path("/db-secrets/admin-password").read_bytes()
        + b"\n",
    )
    env["PGPASSFILE"] = f"/proc/self/fd/{fd}"

    def pg(args, sql=b""):
        result = subprocess.run(
            args, input=sql, env=env, pass_fds=(fd,), capture_output=True, timeout=60
        )
        if result.returncode:
            raise RuntimeError("Provisioning command failed; raw output suppressed")
        return result.stdout

    try:
        password = Path("/db-secrets/worker-password").read_text()
        assert all(c.isalnum() or c in "-_" for c in password)
        pg(
            ["psql", "-X", "-w", "-v", "ON_ERROR_STOP=1"],
            (
                f"CREATE ROLE sbx_worker LOGIN PASSWORD '{password}';"
                "REVOKE CREATE ON SCHEMA public FROM PUBLIC;"
                "GRANT USAGE, CREATE ON SCHEMA public TO sbx_worker;"
                "GRANT EXECUTE ON FUNCTION pg_control_system() TO sbx_worker;"
                "SET ROLE sbx_worker;"
                "CREATE TABLE public.sbx_fixture (id integer PRIMARY KEY, marker text NOT NULL);"
                "INSERT INTO public.sbx_fixture VALUES (1,'synthetic'),(2,'synthetic');"
            ).encode(),
        )
        archive = pg(
            ["pg_dump", "-w", "-Fc", "--no-owner", "--no-privileges", "--table=public.sbx_fixture"]
        )
        write("/backup/archive.dump", archive, mode=0o444)
        toc = pg(["pg_restore", "-l", "/backup/archive.dump"])
        lines = [line for line in toc.decode().splitlines() if line and not line.startswith(";")]
        if len(lines) != 3 or not all(
            any(
                kind in line
                for kind in (
                    " TABLE public sbx_fixture ",
                    " TABLE DATA public sbx_fixture ",
                    " CONSTRAINT public sbx_fixture sbx_fixture_pkey ",
                )
            )
            for line in lines
        ):
            raise RuntimeError("Unexpected archive object list")
        write("/backup/restore.list", "\n".join(lines) + "\n", mode=0o444)
        fingerprint = (
            pg(
                ["psql", "-X", "-w", "-At"],
                b"SELECT system_identifier::text FROM pg_control_system();",
            )
            .decode()
            .strip()
        )
        pg(["psql", "-X", "-w", "-v", "ON_ERROR_STOP=1"], b"DROP TABLE public.sbx_fixture;")
        config = {
            "target_id": "isolated-local",
            "environment": "isolated",
            "host": "database",
            "database": "sbx_lab",
            "username": "sbx_worker",
            "fingerprint": fingerprint,
            "version": 17,
            "max_runtime_seconds": 10,
            "backup_id": "lab-public-v1",
            "operations": [
                "rds.connectivity_check",
                "rds.restore_public_business",
                "rds.verify_restore",
            ],
            "expected_counts": {"tables": 1, "rows": 2, "constraints": 1},
            "hashes": {
                name: hashlib.sha256((Path("/backup") / name).read_bytes()).hexdigest()
                for name in ("archive.dump", "restore.list")
            },
        }
        write("/worker-config/worker.json", json.dumps(config), mode=0o444)
        print("PASS provision: isolated database and reviewed three-object backup ready")
    finally:
        os.close(fd)


def scan():
    raw = sys.stdin.buffer.read(8 * 1024 * 1024 + 1)
    assert len(raw) <= 8 * 1024 * 1024
    for path in (
        "/db-secrets/admin-password",
        "/db-secrets/worker-password",
        "/tls-db/identity.key",
        "/tls-worker/identity.key",
        "/tls-agent/identity.key",
        "/tls-owner/identity.key",
    ):
        value = Path(path).read_bytes()
        assert value not in raw
        if b"PRIVATE KEY" in value:
            for line in value.splitlines()[1:-1]:
                assert line not in raw
    assert b"PGPASSWORD=" not in raw
    print("PASS secret scan; values suppressed")


if __name__ == "__main__":
    {"bootstrap": bootstrap, "provision": provision, "scan": scan}[sys.argv[1]]()
