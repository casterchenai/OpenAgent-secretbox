"""Secure, merge-only writers used by the SecretBox intake service."""

from __future__ import annotations

import csv
import ctypes
import json
import os
import re
import stat
import subprocess
import tempfile
import time
from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field, replace
from functools import lru_cache
from pathlib import Path
from typing import Any

from .models import SecretRequest
from .policy import PathPolicy, PolicyError, build_policy, ensure_safe_parent
from .protocol import normalize_writer_result
from .redaction import safe_status
from .schema import RequestValidationError, validate_request


class WriteError(RuntimeError):
    """Base class for a write that cannot be completed safely."""


class EnvParseError(WriteError):
    """Raised for ambiguous or unsupported existing .env syntax."""


class SecretConflictError(WriteError):
    """Raised by strict callers when a destination already differs."""


_ENV_NAME_RE = re.compile(r"^[A-Za-z_][A-Za-z0-9_]{0,127}$")
_ENV_LINE_RE = re.compile(r"^(?:export[ \t]+)?([A-Za-z_][A-Za-z0-9_]{0,127})[ \t]*=(.*)$")
_REPARSE_POINT = 0x0400
DEFAULT_MAX_FILE_SIZE = 10 * 1024 * 1024

_WINDOWS_ACL_INSPECT_SCRIPT = r"""
$ErrorActionPreference = 'Stop'
$Path = [Environment]::GetEnvironmentVariable(
  'OPENAGENT_SECRETBOX_ACL_PATH', 'Process'
)
$acl = Get-Acl -LiteralPath $Path
$ownerSid = $acl.GetOwner(
  [System.Security.Principal.SecurityIdentifier]
).Value
$rules = @(
  foreach ($rule in @($acl.Access)) {
    $ruleSid = $rule.IdentityReference.Translate(
      [System.Security.Principal.SecurityIdentifier]
    ).Value
    [PSCustomObject]@{
      'sid' = $ruleSid
      'allow' = [bool](
        $rule.AccessControlType -eq
          [System.Security.AccessControl.AccessControlType]::Allow
      )
      'full_control' = [bool](
        ($rule.FileSystemRights -band
          [System.Security.AccessControl.FileSystemRights]::FullControl) -eq
          [System.Security.AccessControl.FileSystemRights]::FullControl
      )
    }
  }
)
[PSCustomObject]@{
  'owner' = $ownerSid
  'protected' = [bool]$acl.AreAccessRulesProtected
  'rules' = $rules
} | ConvertTo-Json -Compress -Depth 3
"""


@lru_cache(maxsize=1)
def _windows_system_directory() -> Path:
    """Return the real System32 directory without trusting process environment state."""

    if os.name != "nt":
        raise WriteError("unable to locate a trusted Windows system executable")
    try:
        win_dll = ctypes.__dict__.get("WinDLL")
        if not callable(win_dll):
            raise OSError("WinDLL is unavailable")
        kernel32 = win_dll("kernel32", use_last_error=True)
        get_system_directory = kernel32.GetSystemDirectoryW
        get_system_directory.argtypes = [ctypes.c_wchar_p, ctypes.c_uint]
        get_system_directory.restype = ctypes.c_uint
        buffer = ctypes.create_unicode_buffer(32_768)
        length = int(get_system_directory(buffer, len(buffer)))
    except (AttributeError, OSError, TypeError, ValueError) as exc:
        raise WriteError("unable to locate a trusted Windows system executable") from exc
    if length <= 0 or length >= len(buffer):
        raise WriteError("unable to locate a trusted Windows system executable")
    try:
        directory = Path(buffer.value).resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise WriteError("unable to locate a trusted Windows system executable") from exc
    if not directory.is_absolute() or not directory.is_dir():
        raise WriteError("unable to locate a trusted Windows system executable")
    return directory


@lru_cache(maxsize=8)
def _windows_system_executable(*relative_parts: str) -> str:
    """Resolve a trusted Windows binary without searching the workspace or PATH."""

    root = _windows_system_directory()
    try:
        candidate = root.joinpath(*relative_parts).resolve(strict=True)
        candidate.relative_to(root)
    except (OSError, RuntimeError, ValueError) as exc:
        raise WriteError("unable to locate a trusted Windows system executable") from exc
    if not candidate.is_file():
        raise WriteError("unable to locate a trusted Windows system executable")
    return str(candidate)


def _windows_powershell_environment(extra: Mapping[str, str]) -> dict[str, str]:
    system_directory = _windows_system_directory()
    windows_directory = system_directory.parent
    environment = {
        "SystemRoot": str(windows_directory),
        "WINDIR": str(windows_directory),
        "ComSpec": str(system_directory / "cmd.exe"),
        "PATH": str(system_directory),
        "PATHEXT": ".COM;.EXE;.BAT;.CMD",
        "PSModulePath": str(system_directory / "WindowsPowerShell" / "v1.0" / "Modules"),
    }
    environment.update(extra)
    return environment


def _parse_windows_acl_snapshot(value: str) -> tuple[str, bool, tuple[tuple[str, bool, bool], ...]]:
    try:
        payload = json.loads(value)
    except (json.JSONDecodeError, TypeError) as exc:
        raise WriteError("unable to inspect Windows permissions") from exc
    if not isinstance(payload, dict):
        raise WriteError("unable to inspect Windows permissions")
    owner = payload.get("owner")
    protected = payload.get("protected")
    raw_rules = payload.get("rules")
    if not isinstance(owner, str) or not owner.startswith("S-"):
        raise WriteError("unable to inspect Windows permissions")
    if not isinstance(protected, bool) or not isinstance(raw_rules, list):
        raise WriteError("unable to inspect Windows permissions")
    rules: list[tuple[str, bool, bool]] = []
    for raw_rule in raw_rules:
        if not isinstance(raw_rule, dict):
            raise WriteError("unable to inspect Windows permissions")
        sid = raw_rule.get("sid")
        allow = raw_rule.get("allow")
        full_control = raw_rule.get("full_control")
        if (
            not isinstance(sid, str)
            or not sid.startswith("S-")
            or not isinstance(allow, bool)
            or not isinstance(full_control, bool)
        ):
            raise WriteError("unable to inspect Windows permissions")
        rules.append((sid, allow, full_control))
    return owner, protected, tuple(rules)


def _inspect_windows_acl(
    path: Path,
    *,
    environment: Mapping[str, str],
) -> tuple[str, bool, tuple[tuple[str, bool, bool], ...]]:
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    powershell = _windows_system_executable(
        "WindowsPowerShell", "v1.0", "powershell.exe"
    )
    try:
        result = subprocess.run(
            [
                powershell,
                "-NoProfile",
                "-NonInteractive",
                "-Command",
                _WINDOWS_ACL_INSPECT_SCRIPT,
            ],
            check=False,
            capture_output=True,
            text=True,
            timeout=30,
            creationflags=creation_flags,
            env=environment,
            cwd=str(Path(powershell).parent),
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise WriteError("unable to inspect Windows permissions") from exc
    if result.returncode != 0:
        raise WriteError("unable to inspect Windows permissions")
    return _parse_windows_acl_snapshot(result.stdout.strip())


def _run_icacls(path: Path, *arguments: str) -> None:
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        result = subprocess.run(
            [_windows_system_executable("icacls.exe"), str(path), *arguments],
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=creation_flags,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise WriteError("unable to set owner-only Windows permissions") from exc
    if result.returncode != 0:
        raise WriteError("unable to set owner-only Windows permissions")


def _windows_acl_is_owner_only(
    snapshot: tuple[str, bool, tuple[tuple[str, bool, bool], ...]],
    sid: str,
) -> bool:
    owner, protected, rules = snapshot
    return owner == sid and protected and rules == ((sid, True, True),)


def _set_windows_owner_only(path: Path) -> bool:
    sid = _windows_current_sid()
    environment = _windows_powershell_environment(
        {"OPENAGENT_SECRETBOX_ACL_PATH": str(path)}
    )
    before = _inspect_windows_acl(path, environment=environment)
    if _windows_acl_is_owner_only(before, sid):
        return False

    sid_argument = f"*{sid}"
    # Every mutation is monotonic: first guarantee the current user retains
    # control, then remove inheritance and all other observed principals.
    _run_icacls(path, "/grant:r", f"{sid_argument}:(F)")
    _run_icacls(path, "/remove:d", sid_argument)
    _run_icacls(path, "/grant:r", f"{sid_argument}:(F)")
    _run_icacls(path, "/setowner", sid_argument)
    _run_icacls(path, "/inheritance:r")
    for rule_sid in sorted({rule[0] for rule in before[2]} - {sid}):
        _run_icacls(path, "/remove", f"*{rule_sid}")

    verified = _inspect_windows_acl(path, environment=environment)
    if not _windows_acl_is_owner_only(verified, sid):
        raise WriteError("unable to verify owner-only Windows permissions")
    return True


@dataclass(frozen=True)
class EnvMergeResult:
    """Metadata-only result of an environment merge.

    ``content`` is intentionally private and excluded from ``as_dict``.  It is
    used only between the pure merge planner and the atomic file writer.
    """

    changed: bool
    actions: tuple[dict[str, Any], ...] = ()
    conflicts: tuple[dict[str, Any], ...] = ()
    backup: str | None = None
    _content: str | None = field(default=None, repr=False)

    @property
    def content(self) -> str | None:
        """Proposed content for trusted writer internals; never serialize it."""

        return self._content

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "changed": self.changed,
            "actions": [dict(item) for item in self.actions],
            "conflicts": [dict(item) for item in self.conflicts],
        }
        if self.backup is not None:
            result["backup"] = self.backup
        return result

    to_dict = as_dict


@dataclass(frozen=True)
class FileWriteResult:
    changed: bool
    action: dict[str, Any] | None = None
    conflict: dict[str, Any] | None = None
    backup: str | None = None

    def as_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {"changed": self.changed}
        if self.action is not None:
            result["action"] = dict(self.action)
        if self.conflict is not None:
            result["conflict"] = dict(self.conflict)
        if self.backup is not None:
            result["backup"] = self.backup
        return result

    to_dict = as_dict


def _decode_env_value(raw: str, *, line_number: int) -> str:
    value = raw.strip()
    if not value:
        return ""
    if value[0] not in {"'", '"'}:
        return value
    quote = value[0]
    if len(value) < 2 or value[-1] != quote:
        raise EnvParseError(f"invalid quoted value on line {line_number}")
    inner = value[1:-1]
    if quote == "'":
        return inner
    output: list[str] = []
    escaped = False
    translations = {"n": "\n", "r": "\r", "t": "\t", '"': '"', "\\": "\\"}
    for character in inner:
        if escaped:
            output.append(translations.get(character, character))
            escaped = False
        elif character == "\\":
            escaped = True
        else:
            output.append(character)
    if escaped:
        raise EnvParseError(f"invalid escape on line {line_number}")
    return "".join(output)


def _parse_env_entries(text: str) -> tuple[dict[str, str], dict[str, int], list[str]]:
    if not isinstance(text, str):
        raise EnvParseError("environment content must be text")
    if "\x00" in text:
        raise EnvParseError("environment content contains NUL")
    entries: dict[str, str] = {}
    line_indices: dict[str, int] = {}
    lines = text.splitlines(keepends=True)
    # splitlines() omits an empty logical final line, which is fine because the
    # original newline remains attached to the preceding line.
    for index, original in enumerate(lines):
        line = original.rstrip("\r\n")
        stripped = line.strip()
        if not stripped or stripped.startswith("#"):
            continue
        match = _ENV_LINE_RE.fullmatch(line)
        if match is None:
            raise EnvParseError(f"unsupported environment syntax on line {index + 1}")
        key, raw_value = match.groups()
        if key in entries:
            raise EnvParseError(f"duplicate environment key on line {index + 1}")
        entries[key] = _decode_env_value(raw_value, line_number=index + 1)
        line_indices[key] = index
    return entries, line_indices, lines


def parse_env(text: str) -> dict[str, str]:
    """Parse a deliberately small, non-evaluating .env syntax subset."""

    entries, _, _ = _parse_env_entries(text)
    return entries


parse_env_text = parse_env


def _validate_env_values(values: Mapping[str, str]) -> dict[str, str]:
    if not isinstance(values, Mapping):
        raise WriteError("environment values must be an object")
    output: dict[str, str] = {}
    for key, value in values.items():
        if not isinstance(key, str) or not _ENV_NAME_RE.fullmatch(key):
            raise WriteError("invalid environment variable name")
        if not isinstance(value, str):
            raise WriteError("environment values must be strings")
        if "\x00" in value:
            raise WriteError("environment value contains NUL")
        if "\n" in value or "\r" in value:
            raise WriteError("multi-line environment values are not supported")
        output[key] = value
    return output


def _format_env_value(value: str) -> str:
    if value == "":
        return ""
    # Quote values that a typical dotenv parser could otherwise trim or treat
    # as a comment.  Dollar signs remain literal; SecretBox never interpolates.
    if value != value.strip() or any(
        character in value for character in ("#", "'", '"', "\\", " ", "\t")
    ):
        escaped = value.replace("\\", "\\\\").replace('"', '\\"')
        return f'"{escaped}"'
    return value


def _action(kind: str, name: str, action: str, target: str | None = None) -> dict[str, Any]:
    result: dict[str, Any] = {"type": kind, "name": name, "action": action}
    if target is not None:
        result["target"] = target
    return result


def _permission_action(kind: str, name: str, target: str) -> dict[str, Any]:
    result = _action(kind, name, "permissions_repaired", target)
    result["mode"] = "owner-only" if os.name == "nt" else "0600"
    return result


def merge_env_text(
    existing_text: str,
    values: Mapping[str, str],
    *,
    target: str | None = None,
    no_overwrite: bool = True,
    allow_overwrite: bool = False,
) -> EnvMergeResult:
    """Plan a merge without touching the filesystem.

    Any conflict blocks the entire merge, including otherwise-missing keys.
    Overwrites require both a policy which permits them and explicit approval.
    """

    incoming = _validate_env_values(values)
    existing, line_indices, lines = _parse_env_entries(existing_text)
    conflicts: list[dict[str, Any]] = []
    actions: list[dict[str, Any]] = []
    replacements: dict[int, str] = {}
    additions: list[str] = []
    for key, value in incoming.items():
        if key not in existing:
            additions.append(f"{key}={_format_env_value(value)}")
            actions.append(_action("env", key, "added", target))
        elif existing[key] == value:
            actions.append(_action("env", key, "skipped", target))
        elif no_overwrite or not allow_overwrite:
            conflicts.append(_action("env", key, "conflict", target))
        else:
            index = line_indices[key]
            old_line = lines[index]
            ending = (
                "\r\n" if old_line.endswith("\r\n") else "\n" if old_line.endswith("\n") else ""
            )
            replacements[index] = f"{key}={_format_env_value(value)}{ending}"
            actions.append(_action("env", key, "updated", target))
    if conflicts:
        return EnvMergeResult(False, (), tuple(conflicts), _content=existing_text)
    for index, value in replacements.items():
        lines[index] = value
    result_text = "".join(lines)
    if additions:
        newline = "\r\n" if "\r\n" in existing_text else "\n"
        if result_text and not result_text.endswith(("\n", "\r")):
            result_text += newline
        result_text += newline.join(additions) + newline
    changed = bool(replacements or additions)
    return EnvMergeResult(changed, tuple(actions), (), _content=result_text)


def _is_link_or_reparse(path: Path, st: os.stat_result) -> bool:
    return stat.S_ISLNK(st.st_mode) or bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT)


def _inspect_destination(path: Path) -> os.stat_result | None:
    try:
        st = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise WriteError("unable to inspect target") from exc
    if _is_link_or_reparse(path, st):
        raise WriteError("target may not be a symlink or reparse point")
    if not stat.S_ISREG(st.st_mode):
        raise WriteError("target must be a regular file")
    if getattr(st, "st_nlink", 1) > 1:
        raise WriteError("hard-linked targets are not supported")
    return st


@lru_cache(maxsize=1)
def _windows_current_sid() -> str:
    creation_flags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    try:
        result = subprocess.run(
            [_windows_system_executable("whoami.exe"), "/user", "/fo", "csv", "/nh"],
            check=True,
            capture_output=True,
            text=True,
            timeout=5,
            creationflags=creation_flags,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        raise WriteError("unable to identify the current Windows user") from exc
    try:
        fields = next(csv.reader([result.stdout.strip()]))
    except (csv.Error, StopIteration) as exc:
        raise WriteError("unable to identify the current Windows user") from exc
    if len(fields) < 2 or not fields[1].startswith("S-"):
        raise WriteError("unable to identify the current Windows user")
    return fields[1]


def _set_owner_only(fd: int, path: Path | None = None) -> None:
    if os.name == "nt":
        if path is None:
            raise WriteError("a path is required to set Windows permissions")
        _set_windows_owner_only(path)
        return
    try:
        fchmod = getattr(os, "fchmod", None)
        if fchmod is None:
            raise AttributeError("fchmod is unavailable")
        fchmod(fd, 0o600)
    except AttributeError as exc:
        raise WriteError("owner-only permissions are unavailable") from exc
    except OSError as exc:
        raise WriteError("unable to set owner-only permissions") from exc
    if path is not None:
        try:
            os.chmod(path, 0o600, follow_symlinks=False)
        except OSError as exc:
            raise WriteError("unable to set owner-only permissions") from exc


def _same_file_identity(first: os.stat_result, second: os.stat_result) -> bool:
    return first.st_dev == second.st_dev and first.st_ino == second.st_ino


def _ensure_existing_owner_only(path: Path, expected: os.stat_result) -> bool:
    """Secure the inspected file in place and report whether permissions changed."""

    flags = os.O_RDONLY
    flags |= getattr(os, "O_CLOEXEC", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    flags |= getattr(os, "O_NONBLOCK", 0)
    flags |= getattr(os, "O_BINARY", 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        raise WriteError("unable to open existing target securely") from exc
    try:
        try:
            opened = os.fstat(fd)
        except OSError as exc:
            raise WriteError("unable to inspect opened target") from exc
        if (
            not stat.S_ISREG(opened.st_mode)
            or getattr(opened, "st_nlink", 1) > 1
            or not _same_file_identity(expected, opened)
        ):
            raise WriteError("target changed during permission validation")

        if os.name == "nt":
            current = _inspect_destination(path)
            if current is None or not _same_file_identity(opened, current):
                raise WriteError("target changed during permission validation")
            changed = _set_windows_owner_only(path)
        else:
            changed = stat.S_IMODE(opened.st_mode) != 0o600
            if changed:
                _set_owner_only(fd)

        try:
            verified = os.fstat(fd)
        except OSError as exc:
            raise WriteError("unable to verify owner-only permissions") from exc
        if (
            not stat.S_ISREG(verified.st_mode)
            or getattr(verified, "st_nlink", 1) > 1
            or not _same_file_identity(opened, verified)
            or (os.name != "nt" and stat.S_IMODE(verified.st_mode) != 0o600)
        ):
            raise WriteError("unable to verify owner-only permissions")
        current = _inspect_destination(path)
        if current is None or not _same_file_identity(verified, current):
            raise WriteError("target changed during permission validation")
        return changed
    finally:
        os.close(fd)


def _fsync_directory(directory: Path) -> None:
    flags = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0)
    try:
        fd = os.open(directory, flags)
    except OSError:
        return
    try:
        os.fsync(fd)
    except OSError:
        pass
    finally:
        os.close(fd)


def _write_temp_file(directory: Path, prefix: str, data: bytes) -> Path:
    try:
        fd, raw_path = tempfile.mkstemp(prefix=prefix, suffix=".tmp", dir=directory)
    except OSError as exc:
        raise WriteError("unable to create secure temporary file") from exc
    path = Path(raw_path)
    try:
        _set_owner_only(fd, path)
        opened = os.fstat(fd)
        current = _inspect_destination(path)
        if current is None or not _same_file_identity(opened, current):
            raise WriteError("temporary target changed during permission validation")
        with os.fdopen(fd, "wb", closefd=True) as handle:
            fd = -1
            handle.write(data)
            handle.flush()
            os.fsync(handle.fileno())
    except Exception:
        if fd >= 0:
            os.close(fd)
        try:
            path.unlink()
        except OSError:
            pass
        raise
    return path


def _cleanup_backups(path: Path, ttl_seconds: int, now: float) -> None:
    prefix = f".{path.name}.secretbox-backup-"
    try:
        candidates = tuple(path.parent.iterdir())
    except OSError:
        return
    for candidate in candidates:
        if not candidate.name.startswith(prefix):
            continue
        try:
            st = candidate.lstat()
            if _is_link_or_reparse(candidate, st) or not stat.S_ISREG(st.st_mode):
                continue
            if now - st.st_mtime > ttl_seconds:
                candidate.unlink()
        except OSError:
            continue


def _make_backup(path: Path, data: bytes, *, ttl_seconds: int) -> Path:
    now = time.time()
    _cleanup_backups(path, ttl_seconds, now)
    prefix = f".{path.name}.secretbox-backup-{int(now)}-"
    backup = _write_temp_file(path.parent, prefix, data)
    # Keep an identifiable suffix while avoiding predictable complete names.
    final = backup.with_suffix(".bak")
    try:
        os.replace(backup, final)
    except OSError as exc:
        try:
            backup.unlink()
        except OSError:
            pass
        raise WriteError("unable to create backup") from exc
    if os.name != "nt":
        try:
            os.chmod(final, 0o600, follow_symlinks=False)
        except OSError as exc:
            raise WriteError("unable to secure backup") from exc
    _fsync_directory(path.parent)
    return final


def _atomic_replace(
    path: Path,
    data: bytes,
    *,
    backup: bool,
    backup_ttl_seconds: int,
) -> Path | None:
    existing_stat = _inspect_destination(path)
    old_data: bytes | None = None
    if existing_stat is not None:
        try:
            old_data = path.read_bytes()
        except OSError as exc:
            raise WriteError("unable to read existing target") from exc
    backup_path = (
        _make_backup(path, old_data, ttl_seconds=backup_ttl_seconds)
        if backup and old_data is not None
        else None
    )
    temporary = _write_temp_file(path.parent, f".{path.name}.secretbox-", data)
    try:
        # Re-check after staging.  os.replace replaces a final symlink rather
        # than following it; the second check primarily catches parent swaps.
        _inspect_destination(path)
        os.replace(temporary, path)
        if os.name != "nt":
            os.chmod(path, 0o600, follow_symlinks=False)
        _fsync_directory(path.parent)
    except Exception:
        try:
            temporary.unlink()
        except OSError:
            pass
        raise
    return backup_path


def _resolve_writer_target(
    path: str | os.PathLike[str], policy: PathPolicy | None
) -> tuple[Path, str]:
    if policy is not None:
        target_text = os.fspath(path)
        target = policy.resolve(target_text)
        policy.ensure_parent(target)
        # Re-resolve after creating parents to catch a component swap.
        target = policy.resolve(target_text)
        return target, target_text.replace("\\", "/")
    target = Path(path).expanduser().resolve(strict=False)
    ensure_safe_parent(target)
    return target, target.name


def merge_env_file(
    path: str | os.PathLike[str],
    values: Mapping[str, str],
    *,
    policy: PathPolicy | None = None,
    no_overwrite: bool | None = None,
    allow_overwrite: bool = False,
    backup: bool | None = None,
    backup_ttl_seconds: int | None = None,
) -> EnvMergeResult:
    """Merge values into a UTF-8 .env file using an atomic replacement."""

    target_path, target_label = _resolve_writer_target(path, policy)
    st = _inspect_destination(target_path)
    if st is None:
        existing = ""
    else:
        try:
            raw = target_path.read_bytes()
            existing = raw.decode("utf-8-sig")
        except UnicodeDecodeError as exc:
            raise EnvParseError("existing environment file is not UTF-8") from exc
        except OSError as exc:
            raise WriteError("unable to read environment file") from exc
    effective_no_overwrite = (
        policy.no_overwrite
        if no_overwrite is None and policy
        else True
        if no_overwrite is None
        else no_overwrite
    )
    plan = merge_env_text(
        existing,
        values,
        target=target_label,
        no_overwrite=effective_no_overwrite,
        allow_overwrite=allow_overwrite,
    )
    if plan.conflicts:
        return replace(plan, _content=None)
    if not plan.changed:
        if st is None:
            return replace(plan, _content=None)
        permissions_changed = _ensure_existing_owner_only(target_path, st)
        actions = plan.actions
        if permissions_changed:
            actions += (_permission_action("env_file", Path(target_label).name, target_label),)
        return replace(
            plan,
            changed=permissions_changed,
            actions=actions,
            _content=None,
        )
    should_backup = (
        policy.backup if backup is None and policy else False if backup is None else backup
    )
    ttl = (
        policy.backup_ttl_seconds
        if backup_ttl_seconds is None and policy
        else 3600
        if backup_ttl_seconds is None
        else backup_ttl_seconds
    )
    if ttl < 60:
        raise WriteError("backup TTL must be at least 60 seconds")
    backup_path = _atomic_replace(
        target_path,
        (plan.content or "").encode("utf-8"),
        backup=should_backup,
        backup_ttl_seconds=ttl,
    )
    backup_label = None
    if backup_path is not None:
        try:
            backup_label = (
                backup_path.relative_to(policy.workspace_root).as_posix()
                if policy
                else backup_path.name
            )
        except ValueError:
            backup_label = backup_path.name
    return replace(plan, backup=backup_label, _content=None)


write_env_file = merge_env_file


def write_private_file(
    path: str | os.PathLike[str],
    content: str | bytes | bytearray | memoryview,
    *,
    policy: PathPolicy | None = None,
    name: str | None = None,
    allow_overwrite: bool = False,
    no_overwrite: bool | None = None,
    backup: bool | None = None,
    backup_ttl_seconds: int | None = None,
    max_size: int | None = None,
) -> FileWriteResult:
    """Create or explicitly overwrite a private file using an atomic replace."""

    if isinstance(content, str):
        data = content.encode("utf-8")
    elif isinstance(content, (bytes, bytearray, memoryview)):
        data = bytes(content)
    else:
        raise WriteError("file content must be text or bytes")
    limit = (
        max_size
        if max_size is not None
        else policy.max_file_size
        if policy
        else DEFAULT_MAX_FILE_SIZE
    )
    if isinstance(limit, bool) or not isinstance(limit, int) or limit <= 0:
        raise WriteError("invalid file size limit")
    if len(data) > limit:
        raise WriteError("file exceeds size limit")
    target_path, target_label = _resolve_writer_target(path, policy)
    existing_stat = _inspect_destination(target_path)
    existing_data: bytes | None = None
    if existing_stat is not None:
        try:
            existing_data = target_path.read_bytes()
        except OSError as exc:
            raise WriteError("unable to read existing target") from exc
    display_name = name or Path(target_label).name
    if existing_data == data:
        if existing_stat is None:
            raise WriteError("existing target disappeared during validation")
        permissions_changed = _ensure_existing_owner_only(target_path, existing_stat)
        action = (
            _permission_action("file", display_name, target_label)
            if permissions_changed
            else _action("file", display_name, "skipped", target_label)
        )
        return FileWriteResult(permissions_changed, action)
    effective_no_overwrite = (
        policy.no_overwrite
        if no_overwrite is None and policy
        else True
        if no_overwrite is None
        else no_overwrite
    )
    if existing_data is not None and (effective_no_overwrite or not allow_overwrite):
        return FileWriteResult(
            False, conflict=_action("file", display_name, "conflict", target_label)
        )
    should_backup = (
        policy.backup if backup is None and policy else False if backup is None else backup
    )
    ttl = (
        policy.backup_ttl_seconds
        if backup_ttl_seconds is None and policy
        else 3600
        if backup_ttl_seconds is None
        else backup_ttl_seconds
    )
    backup_path = _atomic_replace(target_path, data, backup=should_backup, backup_ttl_seconds=ttl)
    action_name = "updated" if existing_data is not None else "created"
    action = _action("file", display_name, action_name, target_label)
    action["mode"] = "0600" if os.name != "nt" else "owner-only"
    backup_label = None
    if backup_path is not None:
        try:
            backup_label = (
                backup_path.relative_to(policy.workspace_root).as_posix()
                if policy
                else backup_path.name
            )
        except ValueError:
            backup_label = backup_path.name
    return FileWriteResult(True, action=action, backup=backup_label)


write_file = write_private_file


def _block(code: str, *, name: str | None = None, target: str | None = None) -> dict[str, str]:
    result = {"code": code}
    if name is not None:
        result["name"] = name
    if target is not None:
        result["target"] = target
    return result


def apply_request(
    spec: SecretRequest | Mapping[str, Any] | str | bytes,
    values: Mapping[str, Any],
    workspace_root: str | os.PathLike[str] | None = None,
    *,
    policy: PathPolicy | None = None,
    allowed_targets: Iterable[str] | None = None,
    forbidden_targets: Iterable[str] | None = None,
    allow_overwrite: bool = False,
) -> dict[str, Any]:
    """Apply a request and return a metadata-only, redacted status.

    This is the small orchestration API intended for the local server/CLI.  It
    accepts secret values only in memory and never includes them in its return
    value or exception messages.
    """

    try:
        request = (
            spec
            if isinstance(spec, SecretRequest)
            else validate_request(spec, workspace_root=workspace_root)
        )
        effective_policy = policy or build_policy(
            request,
            workspace_root,
            allowed_targets=allowed_targets,
            forbidden_targets=forbidden_targets,
        )
    except (RequestValidationError, PolicyError):
        request_id = spec.request_id if isinstance(spec, SecretRequest) else "invalid-request"
        return safe_status(
            request_id=request_id,
            status="blocked",
            blocked=[_block("invalid_request_or_workspace")],
        )
    if not isinstance(values, Mapping):
        return safe_status(
            request_id=request.request_id, status="blocked", blocked=[_block("invalid_values")]
        )
    missing = [need.name for need in request.needs if need.required and need.name not in values]
    if missing:
        return safe_status(request_id=request.request_id, status="blocked", missing=missing)

    written: list[dict[str, Any]] = []
    conflicts: list[dict[str, Any]] = []
    blocked: list[dict[str, Any]] = []
    env_by_target: dict[str, dict[str, str]] = {}
    env_public_names: dict[str, dict[str, str]] = {}
    file_needs: list[tuple[Any, Any]] = []
    try:
        for need in request.needs:
            if need.name not in values:
                continue
            raw_value = values[need.name]
            if need.type == "env":
                if not isinstance(raw_value, str):
                    raise WriteError("invalid environment value")
                target = request.write_policy.env_file
                env_by_target.setdefault(target, {})[need.name] = raw_value
                env_public_names.setdefault(target, {})[need.name] = need.name
            elif need.type == "env_file":
                target = need.target or request.write_policy.env_file
                if isinstance(raw_value, str):
                    parsed = parse_env(raw_value)
                elif isinstance(raw_value, Mapping):
                    parsed = _validate_env_values(raw_value)
                else:
                    raise WriteError("invalid environment block")
                overlap = set(parsed) & set(env_by_target.setdefault(target, {}))
                if overlap:
                    raise WriteError("duplicate environment input")
                env_by_target[target].update(parsed)
                public_names = env_public_names.setdefault(target, {})
                public_names.update({key: need.name for key in parsed})
            elif need.type == "file":
                file_needs.append((need, raw_value))

        for target, env_values in env_by_target.items():
            env_result = merge_env_file(
                target,
                env_values,
                policy=effective_policy,
                allow_overwrite=allow_overwrite,
            )
            aliases = env_public_names.get(target, {})
            public_conflicts: list[dict[str, Any]] = []
            for item in env_result.conflicts:
                public_item = dict(item)
                if public_item.get("type") == "env":
                    public_name = aliases.get(str(public_item.get("name", "")))
                    if public_name is None:
                        raise WriteError("environment result contains an undeclared name")
                    public_item["name"] = public_name
                if public_item not in public_conflicts:
                    public_conflicts.append(public_item)
            conflicts.extend(public_conflicts)
            if env_result.conflicts:
                break
            public_actions: list[dict[str, Any]] = []
            for item in env_result.actions:
                public_item = dict(item)
                if public_item.get("type") == "env":
                    public_name = aliases.get(str(public_item.get("name", "")))
                    if public_name is None:
                        raise WriteError("environment result contains an undeclared name")
                    public_item["name"] = public_name
                if public_item not in public_actions:
                    public_actions.append(public_item)
            written.extend(public_actions)
        if not conflicts:
            for need, raw_value in file_needs:
                file_result = write_private_file(
                    need.target or "",
                    raw_value,
                    policy=effective_policy,
                    name=need.name,
                    allow_overwrite=allow_overwrite,
                    max_size=need.max_bytes,
                )
                if file_result.conflict:
                    conflicts.append(file_result.conflict)
                    continue
                if file_result.action:
                    written.append(file_result.action)
    except (EnvParseError, WriteError, PolicyError, OSError, ValueError):
        # Exception text is deliberately omitted: filesystem and parser errors
        # can contain attacker-controlled input or portions of a secret.
        blocked.append(_block("apply_failed"))

    if (conflicts or blocked) and written:
        status = "partial"
    elif conflicts or blocked:
        status = "blocked"
    elif any(
        item.get("action") in {"added", "updated", "created", "permissions_repaired"}
        for item in written
    ):
        status = "applied"
    else:
        status = "noop"
    status_result = safe_status(
        request_id=request.request_id,
        status=status,
        written=written,
        conflicts=conflicts,
        missing=(),
        blocked=blocked,
    )
    # The writer result is a closed, metadata-only protocol.  Scrubbing submitted
    # literals across it would corrupt public metadata when a secret happens to
    # equal an enum, name, or target.  Normalization returns a detached allowlisted
    # copy and rejects any future value-bearing extension before it can escape.
    return normalize_writer_result(status_result)


__all__ = [
    "DEFAULT_MAX_FILE_SIZE",
    "EnvMergeResult",
    "EnvParseError",
    "FileWriteResult",
    "SecretConflictError",
    "WriteError",
    "apply_request",
    "merge_env_file",
    "merge_env_text",
    "parse_env",
    "parse_env_text",
    "write_env_file",
    "write_file",
    "write_private_file",
]
