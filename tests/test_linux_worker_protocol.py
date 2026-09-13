"""Cross-platform request checks for the real Linux worker protocol."""

import json

import pytest

from openagent_secretbox.linux_worker.common import Rejected, decode, validate


def config():
    return {
        "target_id": "isolated-local",
        "environment": "isolated",
        "backup_id": "lab-public-v1",
        "operations": [
            "rds.connectivity_check",
            "rds.restore_public_business",
            "rds.verify_restore",
        ],
    }


def request():
    return {
        "request_id": "unit-test",
        "operation": "rds.connectivity_check",
        "target_id": "isolated-local",
        "parameters": {},
        "ttl_seconds": 60,
    }


def test_valid():
    assert validate(request(), config()) == request()


@pytest.mark.parametrize(
    "key,value,code",
    [
        ("target_id", "production", "SBX-002"),
        ("operation", "shell", "SBX-003"),
        ("operation", [], "SBX-003"),
        ("parameters", {"host": "example"}, "SBX-001"),
        ("parameters", {"password": "synthetic-only"}, "SBX-001"),
        ("parameters", [], "SBX-001"),
        ("request_id", "../x", "SBX-001"),
        ("request_id", "x" * 81, "SBX-001"),
        ("request_id", None, "SBX-001"),
        ("ttl_seconds", True, "SBX-001"),
        ("ttl_seconds", 0, "SBX-001"),
        ("ttl_seconds", 601, "SBX-001"),
        ("ttl_seconds", 1.0, "SBX-001"),
    ],
)
def test_bad_metadata(key, value, code):
    with pytest.raises(Rejected, match=code):
        validate({**request(), key: value}, config())


def test_trusted_policy():
    with pytest.raises(Rejected, match="SBX-002"):
        validate(request(), {**config(), "environment": "production"})
    with pytest.raises(Rejected, match="SBX-003"):
        validate(request(), {**config(), "operations": []})
    with pytest.raises(Rejected, match="SBX-001"):
        validate({**request(), "command": "anything"}, config())


@pytest.mark.parametrize(
    "params",
    [
        {
            "backup_id": "lab-public-v1",
            "scope": "public_business_only",
            "allow_existing_data": True,
        },
        {"backup_id": "lab-public-v1", "scope": "all", "allow_existing_data": False},
        {"backup_id": "../dump", "scope": "public_business_only", "allow_existing_data": False},
        {"backup_id": "lab-public-v1", "scope": "public_business_only", "allow_existing_data": 0},
    ],
)
def test_restore_params(params):
    with pytest.raises(Rejected, match="SBX-001"):
        validate(
            {**request(), "operation": "rds.restore_public_business", "parameters": params},
            config(),
        )


@pytest.mark.parametrize(
    "raw", [b"[]", b"null", b"{", b"\xff", b'{"a":1,"a":2}', b'{"parameters":{"a":1,"a":2}}']
)
def test_closed_json(raw):
    with pytest.raises(Rejected, match="SBX-001"):
        decode(raw)


def test_roundtrip():
    assert decode(json.dumps(request()).encode()) == request()
