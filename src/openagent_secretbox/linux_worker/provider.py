"""Local Unix credential provider: peer UID, bounded messages, durable lease replay."""

from __future__ import annotations

import os
import re
import socket
import sqlite3
import stat
import struct
import sys
import time
from pathlib import Path

from .common import Rejected, decode

if sys.platform != "linux":
    raise RuntimeError("Credential provider requires Linux")


def protected_read(path: Path) -> bytes:
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW)
    try:
        info = os.fstat(fd)
        if (
            not stat.S_ISREG(info.st_mode)
            or info.st_mode & 0o077
            or info.st_uid != os.getuid()
            or not 1 <= info.st_size <= 512
        ):
            raise Rejected("SBX-009")
        return os.read(fd, 513)
    finally:
        os.close(fd)


def serve() -> None:
    os.umask(0o077)
    path = Path("/run/provider/credentials.sock")
    if path.exists():
        path.unlink()
    db = sqlite3.connect("/state/provider.sqlite")
    db.execute("CREATE TABLE IF NOT EXISTS leases (id TEXT PRIMARY KEY, expires REAL NOT NULL)")
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as listener:
        listener.bind(str(path))
        os.chmod(path, 0o660)
        listener.listen(8)
        while True:
            conn, _ = listener.accept()
            with conn:
                conn.settimeout(3)
                try:
                    _, uid, _ = struct.unpack(
                        "3i",
                        conn.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12),
                    )
                    if uid != 10001:
                        raise Rejected("SBX-007")
                    raw = bytearray()
                    while b"\n" not in raw and len(raw) <= 1024:
                        chunk = conn.recv(1024)
                        if not chunk:
                            break
                        raw.extend(chunk)
                    req = decode(bytes(raw))
                    if set(req) != {"lease_id", "target_id", "expires_at"}:
                        raise Rejected("SBX-001")
                    if req["target_id"] != "isolated-local":
                        raise Rejected("SBX-002")
                    lease = req["lease_id"]
                    if not isinstance(lease, str) or not re.fullmatch(r"[a-f0-9]{64}", lease):
                        raise Rejected("SBX-001")
                    expires = req["expires_at"]
                    if (
                        type(expires) not in (int, float)
                        or not time.time() < expires <= time.time() + 30
                    ):
                        raise Rejected("SBX-005")
                    # Expired grants cannot be replayed after ledger compaction.
                    db.execute("DELETE FROM leases WHERE expires < ?", (time.time() - 60,))
                    db.execute("INSERT INTO leases VALUES (?, ?)", (lease, expires))
                    db.commit()
                    password = protected_read(Path("/secrets/database-password"))
                    conn.sendall(password)
                except Exception:
                    db.rollback()
                    # No exception, request or credential contents are logged.
                    try:
                        conn.sendall(b"")
                    except OSError:
                        pass


if __name__ == "__main__":
    serve()
