"""Central redaction helpers for agent-facing results and diagnostics."""

from __future__ import annotations

import json
from collections.abc import Iterable, Mapping, Sequence
from typing import Any, cast

REDACTED = "[REDACTED]"
SENSITIVE_KEY_NAMES = frozenset(
    {
        "secret",
        "secrets",
        "value",
        "values",
        "content",
        "body",
        "raw",
        "token",
        "access_token",
        "refresh_token",
        "authorization",
        "password",
        "passphrase",
        "api_key",
        "apikey",
        "private_key",
        "client_secret",
        "credential",
        "credentials",
        "data",
    }
)


def _key_is_sensitive(key: Any) -> bool:
    if not isinstance(key, str):
        return False
    normal = key.casefold().replace("-", "_")
    return normal in SENSITIVE_KEY_NAMES or any(
        marker in normal
        for marker in ("password", "token", "secret", "private_key", "api_key", "credential")
    )


def _replace_strings(value: str, secrets: tuple[str, ...], replacement: str) -> str:
    result = value
    for secret in secrets:
        if secret:
            result = result.replace(secret, replacement)
    return result


def redact(value: Any, secrets: Iterable[str | bytes] = (), *, replacement: str = REDACTED) -> Any:
    """Return a JSON-compatible copy with secret values removed.

    Exact secret strings are scrubbed even when they occur inside an error
    message.  Mapping fields whose names clearly denote sensitive data are
    replaced wholesale; this protects callers that forgot to pass the raw
    value list.
    """

    secret_values: list[str] = []
    for item in secrets:
        if isinstance(item, bytes):
            try:
                item = item.decode("utf-8")
            except UnicodeDecodeError:
                continue
        if isinstance(item, str) and item:
            secret_values.append(item)
    # Replace longer values first so a short prefix cannot leave a suffix.
    secret_tuple = tuple(sorted(set(secret_values), key=len, reverse=True))

    def visit(item: Any) -> Any:
        if isinstance(item, Mapping):
            return {
                key: replacement if _key_is_sensitive(key) else visit(val)
                for key, val in item.items()
            }
        if isinstance(item, (list, tuple, set, frozenset)):
            return [visit(entry) for entry in item]
        if isinstance(item, bytes):
            return replacement
        if isinstance(item, str):
            return _replace_strings(item, secret_tuple, replacement)
        # Dataclasses and result objects commonly expose as_dict().  Do not
        # introspect arbitrary objects (which can invoke user code); only use
        # the narrow, explicit protocol.
        as_dict = getattr(item, "as_dict", None)
        if callable(as_dict):
            return visit(as_dict())
        to_dict = getattr(item, "to_dict", None)
        if callable(to_dict):
            return visit(to_dict())
        return item

    return visit(value)


def redact_result(result: Any, secrets: Iterable[str | bytes] = ()) -> Any:
    """Alias used by writers and HTTP handlers."""

    return redact(result, secrets)


def safe_status(
    *,
    request_id: str,
    status: str,
    written: Sequence[Mapping[str, Any]] = (),
    conflicts: Sequence[Mapping[str, Any]] = (),
    missing: Sequence[str] = (),
    blocked: Sequence[Mapping[str, Any]] = (),
) -> dict[str, Any]:
    """Construct a deliberately narrow agent-facing status object."""

    result = {
        "request_id": request_id,
        "status": status,
        "written": list(written),
        "conflicts": list(conflicts),
        "missing": list(missing),
        "blocked": list(blocked),
    }
    return cast(dict[str, Any], redact(result))


def redacted_json(value: Any, secrets: Iterable[str | bytes] = ()) -> str:
    """Serialize a redacted value for logs or an agent response."""

    return json.dumps(
        redact(value, secrets), ensure_ascii=True, sort_keys=True, separators=(",", ":")
    )


__all__ = [
    "REDACTED",
    "redact",
    "redact_result",
    "redacted_json",
    "safe_status",
]
