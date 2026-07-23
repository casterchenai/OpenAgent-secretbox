from __future__ import annotations

import json
import os
import subprocess
from pathlib import Path, PureWindowsPath
from types import SimpleNamespace

import pytest

import openagent_secretbox.writers as writers
from openagent_secretbox.policy import PolicyError, build_policy, resolve_safe_target
from openagent_secretbox.redaction import REDACTED, redact
from openagent_secretbox.schema import RequestValidationError, validate_request
from openagent_secretbox.writers import (
    WriteError,
    apply_request,
    merge_env_file,
    merge_env_text,
    write_private_file,
)


def _trusted_windows_test_executable(*parts: str) -> str:
    return str(PureWindowsPath("C:/Windows/System32", *parts))


class _FakeSid:
    def __init__(self, value: str, *, valid: bool = True) -> None:
        self.value = value
        self.valid = valid

    def IsValid(self) -> bool:
        return self.valid


class _FakeAcl:
    def __init__(self, aces: list[object], *, valid: bool = True) -> None:
        self.aces = aces
        self.valid = valid

    def IsValid(self) -> bool:
        return self.valid

    def GetAceCount(self) -> int:
        return len(self.aces)

    def GetAce(self, index: int) -> object:
        return self.aces[index]


class _FakeSecurityDescriptor:
    def __init__(
        self,
        *,
        owner: _FakeSid | None,
        dacl: _FakeAcl | None,
        control: int = 0x1000,
    ) -> None:
        self.owner = owner
        self.dacl = dacl
        self.control = control

    def GetSecurityDescriptorOwner(self) -> _FakeSid | None:
        return self.owner

    def GetSecurityDescriptorDacl(self) -> _FakeAcl | None:
        return self.dacl

    def GetSecurityDescriptorControl(self) -> tuple[int, int]:
        return self.control, 1


class _FakeWin32Security:
    SE_FILE_OBJECT = 1
    OWNER_SECURITY_INFORMATION = 1
    DACL_SECURITY_INFORMATION = 4
    SE_DACL_PROTECTED = 0x1000
    ACCESS_ALLOWED_ACE_TYPE = 0
    ACCESS_DENIED_ACE_TYPE = 1
    INHERIT_ONLY_ACE = 8

    def __init__(self, descriptor: _FakeSecurityDescriptor) -> None:
        self.descriptor = descriptor
        self.calls: list[tuple[str, int, int]] = []

    def GetNamedSecurityInfo(self, path: str, object_type: int, information: int) -> object:
        self.calls.append((path, object_type, information))
        return self.descriptor

    @staticmethod
    def ConvertSidToStringSid(sid: _FakeSid) -> str:
        return sid.value

    @staticmethod
    def MapGenericMask(mask: int, mapping: tuple[int, int, int, int]) -> int:
        return mapping[3] if mask & 0x10000000 else mask


_FAKE_NT_SECURITY = SimpleNamespace(
    FILE_GENERIC_READ=0x00120089,
    FILE_GENERIC_WRITE=0x00120116,
    FILE_GENERIC_EXECUTE=0x001200A0,
    FILE_ALL_ACCESS=0x001F01FF,
)


def request_for(workspace: Path) -> dict:
    return {
        "schema_version": "1",
        "request_id": "test-request",
        "title": "Test request",
        "workspace_root": str(workspace),
        "needs": [
            {"type": "env", "name": "API_KEY", "required": True},
            {
                "type": "file",
                "name": "private.pem",
                "target": "secrets/private.pem",
                "required": False,
            },
        ],
        "write_policy": {"env_file": ".env.local", "mode": "merge_only", "no_overwrite": True},
    }


def test_schema_is_strict_and_workspace_is_authoritative(tmp_path: Path) -> None:
    spec = request_for(tmp_path)
    request = validate_request(spec, workspace_root=tmp_path)
    assert request.schema_version == 1
    with pytest.raises(RequestValidationError):
        validate_request({**spec, "unexpected": True})
    with pytest.raises(RequestValidationError):
        validate_request(spec, workspace_root=tmp_path / "different")


def test_default_metadata_is_hidden_from_model_repr(tmp_path: Path) -> None:
    spec = request_for(tmp_path)
    spec["needs"][0]["default_value"] = "default-must-not-appear"

    request = validate_request(spec, workspace_root=tmp_path)

    assert "default-must-not-appear" not in repr(request)


def test_request_target_rules_only_narrow_the_host_policy(tmp_path: Path) -> None:
    spec = request_for(tmp_path)
    spec["allowed_targets"] = [".env.local", "secrets/*", "src/*"]
    request = validate_request(spec, workspace_root=tmp_path)

    policy = build_policy(
        request,
        tmp_path,
        allowed_targets=(".env.*", "secrets/*"),
    )

    assert policy.allowed_targets == (".env.local", "secrets/private.pem")
    with pytest.raises(PolicyError):
        policy.resolve("src/app.py")

    spec["allowed_targets"] = ["secrets/*"]
    with pytest.raises(PolicyError, match="request allowlist omits"):
        build_policy(
            validate_request(spec, workspace_root=tmp_path),
            tmp_path,
            allowed_targets=(".env.*", "secrets/*"),
        )
    with pytest.raises(PolicyError, match="allowlisted"):
        build_policy(request, tmp_path, allowed_targets=())

    spec = request_for(tmp_path)
    spec["forbidden_targets"] = ["secrets/*"]
    with pytest.raises(PolicyError, match="forbidden"):
        build_policy(
            validate_request(spec, workspace_root=tmp_path),
            tmp_path,
            allowed_targets=(".env.*", "secrets/*"),
        )


def test_repository_examples_validate() -> None:
    root = Path(__file__).resolve().parents[1]
    for source in (root / "examples").glob("*.request.json"):
        validate_request(json.loads(source.read_text(encoding="utf-8")))


def test_path_policy_rejects_traversal_and_symlink(tmp_path: Path) -> None:
    with pytest.raises(PolicyError):
        resolve_safe_target(tmp_path, "../outside", allowed_targets=("*",))
    with pytest.raises(PolicyError):
        resolve_safe_target(tmp_path, str(tmp_path / "absolute"), allowed_targets=("*",))
    for unsafe in ("secrets/key.pem:stream", "secrets/NUL.txt", "secrets/trailing."):
        with pytest.raises(PolicyError):
            resolve_safe_target(tmp_path, unsafe, allowed_targets=("secrets/*",))
    link = tmp_path / "link"
    outside = tmp_path.parent / f"{tmp_path.name}-outside"
    outside.mkdir(exist_ok=True)
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlinks are not available for this test user")
    with pytest.raises(PolicyError):
        resolve_safe_target(tmp_path, "link/secret", allowed_targets=("link/*",))


def test_merge_only_blocks_entire_conflicting_write(tmp_path: Path) -> None:
    target = tmp_path / ".env"
    target.write_text("# existing\nAPI_KEY=old\n", encoding="utf-8")
    result = merge_env_file(target, {"API_KEY": "new-secret", "OTHER": "another-secret"})
    assert result.changed is False
    assert target.read_text(encoding="utf-8") == "# existing\nAPI_KEY=old\n"
    assert "new-secret" not in repr(result.as_dict())
    assert "another-secret" not in repr(result.as_dict())


def test_env_merge_preserves_comments_and_requires_explicit_overwrite() -> None:
    plan = merge_env_text("# keep\nA=old\n", {"A": "new", "B": "value"})
    assert plan.conflicts
    assert plan.changed is False
    approved = merge_env_text(
        "# keep\nA=old\n",
        {"A": "new", "B": "value"},
        no_overwrite=False,
        allow_overwrite=True,
    )
    assert approved.content == "# keep\nA=new\nB=value\n"
    assert "old" not in repr(approved)
    assert "value" not in repr(approved)


def test_private_file_is_owner_only_and_result_is_metadata(tmp_path: Path) -> None:
    spec = validate_request(request_for(tmp_path), workspace_root=tmp_path)
    policy = build_policy(spec, tmp_path)
    result = write_private_file("secrets/private.pem", "private-test-body", policy=policy)
    target = tmp_path / "secrets" / "private.pem"
    assert target.read_text(encoding="utf-8") == "private-test-body"
    assert "private-test-body" not in repr(result.as_dict())
    if os.name != "nt":
        assert target.stat().st_mode & 0o777 == 0o600


@pytest.mark.skipif(os.name == "nt", reason="POSIX permission test")
def test_identical_targets_repair_posix_permissions_and_then_noop(tmp_path: Path) -> None:
    env_target = tmp_path / ".env"
    env_target.write_text("API_KEY=same\n", encoding="utf-8")
    env_target.chmod(0o644)

    env_result = merge_env_file(env_target, {"API_KEY": "same"})

    assert env_result.changed is True
    assert env_target.stat().st_mode & 0o777 == 0o600
    assert env_result.actions[-1] == {
        "type": "env_file",
        "name": ".env",
        "action": "permissions_repaired",
        "target": ".env",
        "mode": "0600",
    }
    assert merge_env_file(env_target, {"API_KEY": "same"}).changed is False

    file_target = tmp_path / "private.pem"
    file_target.write_bytes(b"same")
    file_target.chmod(0o640)

    file_result = write_private_file(file_target, b"same")

    assert file_result.changed is True
    assert file_target.stat().st_mode & 0o777 == 0o600
    assert file_result.action == {
        "type": "file",
        "name": "private.pem",
        "action": "permissions_repaired",
        "target": "private.pem",
        "mode": "0600",
    }
    assert write_private_file(file_target, b"same").changed is False


@pytest.mark.skipif(os.name != "nt", reason="Windows ACL integration test")
def test_identical_windows_target_repairs_acl_and_then_noops(tmp_path: Path) -> None:
    target = tmp_path / "private.pem"
    target.write_bytes(b"same")
    subprocess.run(
        [writers._windows_system_executable("icacls.exe"), str(target), "/grant", "*S-1-1-0:(R)"],
        check=True,
        capture_output=True,
        text=True,
    )

    repaired = write_private_file(target, b"same")
    unchanged = write_private_file(target, b"same")

    assert repaired.changed is True
    assert repaired.action is not None
    assert repaired.action["action"] == "permissions_repaired"
    assert repaired.action["mode"] == "owner-only"
    assert unchanged.changed is False
    assert unchanged.action is not None
    assert unchanged.action["action"] == "skipped"


def test_permission_repair_is_reported_as_applied(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    secret = "same-secret"
    (tmp_path / ".env.local").write_text(f"API_KEY={secret}\n", encoding="utf-8")
    monkeypatch.setattr(writers, "_ensure_existing_owner_only", lambda *_args: True)

    result = apply_request(request_for(tmp_path), {"API_KEY": secret}, tmp_path)

    assert result["status"] == "applied"
    assert result["written"][-1]["action"] == "permissions_repaired"
    assert secret not in json.dumps(result)


def test_identical_targets_fail_closed_when_permissions_cannot_be_secured(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    env_target = tmp_path / ".env"
    env_target.write_text("A=same\n", encoding="utf-8")
    file_target = tmp_path / "private.pem"
    file_target.write_bytes(b"same")

    def fail_permissions(*_args: object) -> bool:
        raise WriteError("permission repair failed")

    monkeypatch.setattr(writers, "_ensure_existing_owner_only", fail_permissions)

    with pytest.raises(WriteError):
        merge_env_file(env_target, {"A": "same"})
    with pytest.raises(WriteError):
        write_private_file(file_target, b"same")


def test_temp_file_identity_change_is_rejected_before_secret_write(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    monkeypatch.setattr(writers, "_set_owner_only", lambda *_args: None)
    monkeypatch.setattr(writers, "_same_file_identity", lambda *_args: False)

    with pytest.raises(WriteError, match="temporary target changed"):
        writers._write_temp_file(tmp_path, ".secretbox-test-", b"must-not-be-written")

    assert list(tmp_path.iterdir()) == []


def test_windows_acl_check_reports_secure_target_without_mutation(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "private.pem"
    sid = "S-1-5-21-test"
    mutations: list[tuple[Path, tuple[str, ...]]] = []

    monkeypatch.setattr(writers, "_windows_current_sid", lambda: sid)
    monkeypatch.setattr(
        writers,
        "_inspect_windows_acl",
        lambda _path: (sid, True, ((sid, True, True),)),
    )
    monkeypatch.setattr(
        writers,
        "_run_icacls",
        lambda path, *arguments: mutations.append((path, arguments)),
    )

    assert writers._set_windows_owner_only(target) is False
    assert mutations == []


def test_windows_acl_inspection_uses_native_sid_rules(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    owner = _FakeSid("S-1-5-21-owner")
    other = _FakeSid("S-1-1-0")
    descriptor = _FakeSecurityDescriptor(
        owner=owner,
        dacl=_FakeAcl(
            [
                ((0, 0), 0x10000000, owner),
                ((1, 0), 0x00120089, other),
            ]
        ),
    )
    security = _FakeWin32Security(descriptor)
    monkeypatch.setattr(
        writers,
        "_windows_acl_libraries",
        lambda: (security, _FAKE_NT_SECURITY),
    )
    target = tmp_path / "private.pem"

    assert writers._inspect_windows_acl(target) == (
        "S-1-5-21-owner",
        True,
        (
            ("S-1-5-21-owner", True, True),
            ("S-1-1-0", False, False),
        ),
    )
    assert security.calls == [(str(target), 1, 5)]


def test_windows_acl_repair_uses_icacls_and_verifies_result(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "private.pem"
    sid = "S-1-5-21-test"
    other_sid = "S-1-1-0"
    snapshots = iter(
        [
            (sid, False, ((other_sid, True, False),)),
            (sid, True, ((sid, True, True),)),
        ]
    )
    commands: list[tuple[Path, tuple[str, ...]]] = []

    monkeypatch.setattr(writers, "_windows_current_sid", lambda: sid)
    monkeypatch.setattr(
        writers, "_inspect_windows_acl", lambda _path: next(snapshots)
    )
    monkeypatch.setattr(
        writers,
        "_run_icacls",
        lambda path, *arguments: commands.append((path, arguments)),
    )

    assert writers._set_windows_owner_only(target) is True
    assert commands == [
        (target, ("/grant:r", f"*{sid}:(F)")),
        (target, ("/remove:d", f"*{sid}")),
        (target, ("/grant:r", f"*{sid}:(F)")),
        (target, ("/setowner", f"*{sid}")),
        (target, ("/inheritance:r",)),
        (target, ("/remove", f"*{other_sid}")),
    ]


@pytest.mark.parametrize(
    "descriptor",
    [
        _FakeSecurityDescriptor(owner=_FakeSid("S-1-5-21-owner"), dacl=None),
        _FakeSecurityDescriptor(
            owner=_FakeSid("S-1-5-21-owner"),
            dacl=_FakeAcl([((5, 0), 0x001F01FF, _FakeSid("S-1-5-21-owner"))]),
        ),
        _FakeSecurityDescriptor(
            owner=_FakeSid("S-1-5-21-owner"),
            dacl=_FakeAcl([((0, 8), 0x001F01FF, _FakeSid("S-1-5-21-owner"))]),
        ),
        _FakeSecurityDescriptor(
            owner=_FakeSid("S-1-5-21-owner"),
            dacl=_FakeAcl([((0, "invalid"), 0x001F01FF, _FakeSid("S-1-5-21-owner"))]),
        ),
        _FakeSecurityDescriptor(
            owner=_FakeSid("S-1-5-21-owner", valid=False),
            dacl=_FakeAcl([]),
        ),
        _FakeSecurityDescriptor(
            owner=_FakeSid("S-1-5-21-owner"),
            dacl=_FakeAcl([], valid=False),
        ),
    ],
)
def test_windows_acl_inspection_rejects_unsafe_native_snapshots(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
    descriptor: _FakeSecurityDescriptor,
) -> None:
    security = _FakeWin32Security(descriptor)
    monkeypatch.setattr(
        writers,
        "_windows_acl_libraries",
        lambda: (security, _FAKE_NT_SECURITY),
    )

    with pytest.raises(WriteError, match="unable to inspect Windows permissions"):
        writers._inspect_windows_acl(tmp_path / "private.pem")


def test_windows_acl_native_failure_is_fail_closed_and_redacted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    target = tmp_path / "private.pem"
    security = _FakeWin32Security(
        _FakeSecurityDescriptor(owner=_FakeSid("S-1-5-21-owner"), dacl=_FakeAcl([]))
    )

    def fail(*_args: object) -> object:
        raise RuntimeError(f"sensitive-native-error:{target}")

    security.GetNamedSecurityInfo = fail  # type: ignore[method-assign]
    monkeypatch.setattr(
        writers,
        "_windows_acl_libraries",
        lambda: (security, _FAKE_NT_SECURITY),
    )

    with pytest.raises(WriteError, match="unable to inspect Windows permissions") as raised:
        writers._inspect_windows_acl(target)

    assert "sensitive-native-error" not in str(raised.value)
    assert str(target) not in str(raised.value)


def test_windows_acl_command_failure_is_fail_closed_and_redacted(
    tmp_path: Path,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    sid = "S-1-5-21-test"
    def fake_run(command: list[str], **_kwargs: object) -> subprocess.CompletedProcess[str]:
        return subprocess.CompletedProcess(
            command,
            5,
            stdout="",
            stderr="sensitive-diagnostic-must-not-escape",
        )

    monkeypatch.setattr(writers, "_windows_current_sid", lambda: sid)
    monkeypatch.setattr(
        writers, "_windows_system_executable", _trusted_windows_test_executable
    )
    monkeypatch.setattr(
        writers,
        "_inspect_windows_acl",
        lambda _path: (sid, False, (("S-1-1-0", True, False),)),
    )
    monkeypatch.setattr(writers.subprocess, "run", fake_run)

    with pytest.raises(WriteError, match="unable to set owner-only") as raised:
        writers._set_windows_owner_only(tmp_path / "private.pem")
    assert "sensitive-diagnostic" not in str(raised.value)


@pytest.mark.skipif(os.name != "nt", reason="Windows executable resolution test")
def test_windows_system_executables_ignore_workspace_shadows(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    for name in ("whoami.exe", "icacls.exe"):
        (tmp_path / name).write_bytes(b"workspace-shadow")
    fake_root = tmp_path / "fake-windows"
    fake_system = fake_root / "System32"
    fake_system.mkdir(parents=True)
    for path in (
        fake_system / "whoami.exe",
        fake_system / "icacls.exe",
    ):
        path.write_bytes(b"environment-shadow")
    monkeypatch.setenv("SystemRoot", str(fake_root))
    monkeypatch.setenv("WINDIR", str(fake_root))
    monkeypatch.chdir(tmp_path)
    writers._windows_system_directory.cache_clear()
    writers._windows_system_executable.cache_clear()

    resolved = [
        Path(writers._windows_system_executable("whoami.exe")),
        Path(writers._windows_system_executable("icacls.exe")),
    ]

    assert all(path.is_absolute() and path.is_file() for path in resolved)
    assert all(path.parent != tmp_path for path in resolved)
    assert all(not path.is_relative_to(fake_root) for path in resolved)


def test_apply_request_never_returns_secret(tmp_path: Path) -> None:
    secret = "test-secret-value"
    result = apply_request(request_for(tmp_path), {"API_KEY": secret}, tmp_path)
    assert result["status"] == "applied"
    assert secret not in json.dumps(result)
    assert (tmp_path / ".env.local").read_text(encoding="utf-8") == f"API_KEY={secret}\n"


@pytest.mark.parametrize("secret", ["app", "status", "applied"])
def test_short_secret_does_not_corrupt_protocol_status(tmp_path: Path, secret: str) -> None:
    result = apply_request(request_for(tmp_path), {"API_KEY": secret}, tmp_path)

    assert result["status"] == "applied"
    assert (tmp_path / ".env.local").read_text(encoding="utf-8") == f"API_KEY={secret}\n"


def test_env_block_results_use_only_the_declared_request_name(tmp_path: Path) -> None:
    request = request_for(tmp_path)
    request["needs"] = [
        {"type": "env_file", "name": "ENV_BLOCK", "required": True}
    ]

    result = apply_request(
        request,
        {"ENV_BLOCK": "SECRET_FIRST=one\nSECRET_SECOND=two"},
        tmp_path,
    )

    assert result["status"] == "applied"
    assert result["written"] == [
        {
            "type": "env",
            "name": "ENV_BLOCK",
            "action": "added",
            "target": ".env.local",
        }
    ]
    encoded = json.dumps(result)
    assert "SECRET_FIRST" not in encoded
    assert "SECRET_SECOND" not in encoded


def test_multi_target_failure_is_reported_as_partial(tmp_path: Path) -> None:
    secret_dir = tmp_path / "secrets"
    secret_dir.mkdir()
    private_key = secret_dir / "private.pem"
    private_key.write_text("existing", encoding="utf-8")

    result = apply_request(
        request_for(tmp_path),
        {"API_KEY": "new-env-value", "private.pem": "replacement"},
        tmp_path,
    )

    assert result["status"] == "partial"
    assert private_key.read_text(encoding="utf-8") == "existing"
    assert (tmp_path / ".env.local").exists()
    assert "new-env-value" not in json.dumps(result)
    assert "replacement" not in json.dumps(result)


def test_redaction_handles_keys_and_embedded_values() -> None:
    result = redact(
        {"message": "failed for test-secret", "api_key": "test-secret"}, ["test-secret"]
    )
    assert result == {"message": f"failed for {REDACTED}", "api_key": REDACTED}
