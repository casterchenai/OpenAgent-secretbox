"""Filesystem policy and path confinement for SecretBox writes."""

from __future__ import annotations

import fnmatch
import os
import stat
from collections.abc import Iterable, Mapping
from dataclasses import dataclass
from pathlib import Path, PurePosixPath, PureWindowsPath
from typing import Any

from .models import SecretRequest
from .schema import RequestValidationError, validate_request


class PolicyError(ValueError):
    """Raised when a requested target cannot be authorised safely."""


_REPARSE_POINT = 0x0400
_DEFAULT_FORBIDDEN = (".git", ".git/*", "node_modules", "node_modules/*")
_WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}


def _is_reparse(path: Path, st: os.stat_result | None = None) -> bool:
    """Return true for Windows links/junctions/reparse points."""

    try:
        st = st or path.lstat()
    except OSError:
        return False
    return bool(getattr(st, "st_file_attributes", 0) & _REPARSE_POINT)


def _check_no_link(path: Path, *, label: str) -> os.stat_result | None:
    try:
        st = path.lstat()
    except FileNotFoundError:
        return None
    except OSError as exc:
        raise PolicyError(f"unable to inspect {label}") from exc
    if stat.S_ISLNK(st.st_mode) or _is_reparse(path, st):
        raise PolicyError(f"{label} may not be a symlink or reparse point")
    return st


def _validate_relative_target(target: str | os.PathLike[str]) -> tuple[str, ...]:
    if not isinstance(target, (str, os.PathLike)):
        raise PolicyError("target must be a path string")
    try:
        text = os.fspath(target)
    except TypeError as exc:
        raise PolicyError("target must be a path string") from exc
    if isinstance(text, bytes):
        try:
            text = text.decode("utf-8")
        except UnicodeDecodeError as exc:
            raise PolicyError("target must be valid text") from exc
    if not text or "\x00" in text:
        raise PolicyError("target must be non-empty and contain no NUL")
    # Keep one unambiguous path grammar across POSIX and Windows.  In
    # particular, a Windows drive/UNC path must never be interpreted as a
    # relative POSIX path when running on Linux.
    if "\\" in text:
        raise PolicyError("target must use '/' separators")
    posix = PurePosixPath(text)
    windows = PureWindowsPath(text)
    if posix.is_absolute() or windows.is_absolute() or windows.drive or windows.root:
        raise PolicyError("absolute targets are not permitted")
    parts = tuple(part for part in posix.parts if part not in ("", "."))
    if not parts or any(part == ".." for part in parts):
        raise PolicyError("target traversal is not permitted")
    for part in parts:
        basename = part.split(".", 1)[0].upper()
        if ":" in part or part.endswith((".", " ")) or basename in _WINDOWS_RESERVED_NAMES:
            raise PolicyError("target contains a Windows-unsafe path component")
    return parts


def _relative_string(parts: Iterable[str]) -> str:
    return "/".join(parts)


def _normalise_root(workspace_root: str | os.PathLike[str]) -> Path:
    try:
        supplied = Path(workspace_root).expanduser()
    except (TypeError, ValueError) as exc:
        raise PolicyError("workspace_root is invalid") from exc
    if "\x00" in str(supplied):
        raise PolicyError("workspace_root contains NUL")
    try:
        # A symlink as the registered root is rejected.  This prevents a
        # caller from silently changing the trust boundary after registration.
        root_stat = supplied.lstat()
    except OSError as exc:
        raise PolicyError("workspace_root cannot be inspected") from exc
    if stat.S_ISLNK(root_stat.st_mode) or _is_reparse(supplied, root_stat):
        raise PolicyError("workspace_root may not be a symlink or reparse point")
    try:
        root = supplied.resolve(strict=True)
    except (OSError, RuntimeError) as exc:
        raise PolicyError("workspace_root does not exist") from exc
    try:
        if not root.is_dir():
            raise PolicyError("workspace_root must be a directory")
    except OSError as exc:
        raise PolicyError("workspace_root cannot be inspected") from exc
    return root


def _check_components(
    root: Path, parts: tuple[str, ...], *, allow_missing_final: bool = True
) -> Path:
    current = root
    for index, part in enumerate(parts):
        current = current / part
        st = _check_no_link(current, label="target component")
        if st is None:
            # Once a component is missing, no later existing component can be
            # reached without creating it, so the path is safe to stage.
            if not allow_missing_final:
                raise PolicyError("target does not exist")
            break
        if index < len(parts) - 1 and not stat.S_ISDIR(st.st_mode):
            raise PolicyError("target parent is not a directory")
    return root.joinpath(*parts)


def _match_pattern(relative: str, pattern: str) -> bool:
    # fnmatch's '*' also crosses separators.  That is acceptable only for an
    # explicit pattern supplied by the trusted host; request validation still
    # rejects absolute and traversal patterns.
    return fnmatch.fnmatchcase(relative, pattern) or PurePosixPath(relative).match(pattern)


def resolve_safe_target(
    workspace_root: str | os.PathLike[str],
    target: str | os.PathLike[str],
    *,
    allowed_targets: Iterable[str] | None = None,
    forbidden_targets: Iterable[str] | None = None,
    allow_missing: bool = True,
) -> Path:
    """Resolve a relative target while rejecting traversal and links.

    All existing components, including the final file, are inspected with
    ``lstat``.  This is a fail-closed best-effort defence against symlinks,
    Windows junctions/reparse points, and common path races.  Writers perform
    a second check immediately before their atomic replace.
    """

    root = _normalise_root(workspace_root)
    parts = _validate_relative_target(target)
    relative = _relative_string(parts)
    forbidden = tuple(forbidden_targets or _DEFAULT_FORBIDDEN)
    for pattern in forbidden:
        try:
            fparts = _validate_relative_target(pattern.replace("*", "placeholder"))
        except PolicyError as exc:
            # A malformed trusted forbidden pattern is itself unsafe.
            raise PolicyError("invalid forbidden target pattern") from exc
        del fparts
        if _match_pattern(relative, pattern):
            raise PolicyError("target is forbidden")
    if allowed_targets is not None:
        allowed = tuple(allowed_targets)
        if not any(_match_pattern(relative, pattern) for pattern in allowed):
            raise PolicyError("target is not allowlisted")
    candidate = _check_components(root, parts, allow_missing_final=allow_missing)
    # A lexical containment check remains useful if an unusual filesystem
    # implementation returns a surprising Path object.
    try:
        candidate.parent.resolve(strict=False).relative_to(root)
    except (ValueError, OSError, RuntimeError) as exc:
        raise PolicyError("target escapes workspace") from exc
    return candidate


def ensure_safe_parent(path: Path, workspace_root: Path | None = None) -> None:
    """Create missing parent directories without traversing links."""

    if workspace_root is None:
        parent = path.parent
        if parent.exists():
            _check_no_link(parent, label="target parent")
            return
        parent.mkdir(parents=True, mode=0o700, exist_ok=True)
        return
    root = _normalise_root(workspace_root)
    try:
        relative = path.parent.relative_to(root)
    except ValueError as exc:
        raise PolicyError("target parent escapes workspace") from exc
    current = root
    for part in relative.parts:
        current = current / part
        st = _check_no_link(current, label="target parent")
        if st is None:
            try:
                current.mkdir(mode=0o700)
            except FileExistsError:
                pass
            st = _check_no_link(current, label="target parent")
            if st is None or not stat.S_ISDIR(st.st_mode):
                raise PolicyError("target parent is not a directory")


@dataclass(frozen=True)
class PathPolicy:
    """Authoritative policy used by writers.

    ``allowed_targets`` should normally come from a user-registered workspace,
    not from the untrusted request.  When omitted, the request's declared
    concrete targets are used as a conservative MVP fallback.
    """

    workspace_root: Path
    allowed_targets: tuple[str, ...]
    forbidden_targets: tuple[str, ...] = _DEFAULT_FORBIDDEN
    env_file: str = ".env"
    mode: str = "merge_only"
    no_overwrite: bool = True
    backup: bool = False
    backup_ttl_seconds: int = 3600
    max_file_size: int = 10 * 1024 * 1024

    def resolve(self, target: str | os.PathLike[str], *, allow_missing: bool = True) -> Path:
        return resolve_safe_target(
            self.workspace_root,
            target,
            allowed_targets=self.allowed_targets,
            forbidden_targets=self.forbidden_targets,
            allow_missing=allow_missing,
        )

    def ensure_parent(self, path: Path) -> None:
        ensure_safe_parent(path, self.workspace_root)


Policy = PathPolicy


def build_policy(
    request: SecretRequest | Mapping[str, Any],
    workspace_root: str | os.PathLike[str] | None = None,
    *,
    allowed_targets: Iterable[str] | None = None,
    forbidden_targets: Iterable[str] | None = None,
) -> PathPolicy:
    """Build an authoritative path policy from validated request metadata."""

    try:
        req = (
            request
            if isinstance(request, SecretRequest)
            else validate_request(request, workspace_root=workspace_root)
        )
    except RequestValidationError as exc:
        raise PolicyError(str(exc)) from exc
    root_value = workspace_root if workspace_root is not None else req.workspace_root
    if root_value is None:
        raise PolicyError("a trusted workspace_root is required")
    root = _normalise_root(root_value)
    if req.workspace_root is not None:
        declared = _normalise_root(req.workspace_root)
        if declared != root:
            raise PolicyError("request workspace_root does not match trusted workspace")
    declared_targets = {req.write_policy.env_file}
    declared_targets.update(need.target for need in req.needs if need.target)
    effective_forbidden = (
        tuple(forbidden_targets or ()) + tuple(req.forbidden_targets) + tuple(_DEFAULT_FORBIDDEN)
    )
    # A host allowlist is authoritative.  The request can only select a target
    # which the host already authorised; each concrete request target is checked
    # against it here, before any secret value is accepted.
    host_allowed = tuple(allowed_targets) if allowed_targets is not None else None
    validation_allowed = (
        host_allowed if host_allowed is not None else tuple(sorted(declared_targets))
    )
    for target in declared_targets:
        resolve_safe_target(
            root,
            target,
            allowed_targets=validation_allowed,
            forbidden_targets=effective_forbidden,
        )
    if req.allowed_targets:
        uncovered = [
            target
            for target in declared_targets
            if not any(_match_pattern(target, pattern) for pattern in req.allowed_targets)
        ]
        if uncovered:
            raise PolicyError("request allowlist omits a declared target")
        # Arbitrary glob intersections are not representable as another glob.
        # The declared concrete targets are the strict intersection of this
        # request and the trusted host policy.
        effective_allowed = tuple(sorted(declared_targets))
    elif host_allowed is None:
        effective_allowed = tuple(sorted(declared_targets))
    else:
        effective_allowed = host_allowed
    return PathPolicy(
        workspace_root=root,
        allowed_targets=effective_allowed,
        forbidden_targets=effective_forbidden,
        env_file=req.write_policy.env_file,
        mode=req.write_policy.mode,
        no_overwrite=req.write_policy.no_overwrite,
        backup=req.write_policy.backup,
        backup_ttl_seconds=req.write_policy.backup_ttl_seconds,
        max_file_size=req.write_policy.max_file_size,
    )


def validate_target(*args: Any, **kwargs: Any) -> Path:
    """Compatibility alias for :func:`resolve_safe_target`."""

    return resolve_safe_target(*args, **kwargs)


__all__ = [
    "PathPolicy",
    "Policy",
    "PolicyError",
    "build_policy",
    "ensure_safe_parent",
    "resolve_safe_target",
    "validate_target",
]
