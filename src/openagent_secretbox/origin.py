"""Canonical validation for the fixed SecretBox portal origin."""

from __future__ import annotations

import ipaddress
import re
from urllib.parse import urlsplit

_DNS_LABEL_RE = re.compile(r"^[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$")
_UNSAFE_ORIGIN_RE = re.compile(r"[\x00-\x20\x7f]")


def _normalized_host(hostname: str) -> tuple[str, bool]:
    """Return a browser-safe ASCII host and whether it is loopback."""

    if not hostname or hostname.endswith(".") or "%" in hostname:
        raise ValueError("origin must contain a valid host")
    try:
        hostname.encode("ascii", "strict")
    except UnicodeEncodeError as exc:
        raise ValueError("origin host must use ASCII or punycode") from exc

    lowered = hostname.lower()
    try:
        address = ipaddress.ip_address(lowered)
    except ValueError:
        if lowered.isdigit() or (
            "." in lowered and all(character in "0123456789." for character in lowered)
        ):
            raise ValueError("origin must contain a valid host") from None
        labels = lowered.split(".")
        if (
            len(lowered) > 253
            or not any(character in "abcdefghijklmnopqrstuvwxyz" for character in lowered)
            or any(not _DNS_LABEL_RE.fullmatch(label) for label in labels)
        ):
            raise ValueError("origin must contain a valid host") from None
        return lowered, lowered == "localhost"
    if address.version != 4:
        raise ValueError("origin IP addresses must use IPv4 in protocol version 1")
    normalized = address.compressed.lower()
    return normalized, address.is_loopback


def normalize_portal_origin(
    value: str,
    *,
    allow_loopback_http: bool = False,
) -> tuple[str, str, str]:
    """Validate and canonicalize a route-free public origin.

    HTTPS is mandatory except for explicit loopback-only test deployments.
    The returned tuple is ``(origin, expected_host_header, scheme)``.
    """

    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or "\\" in value
        or _UNSAFE_ORIGIN_RE.search(value)
        or not (value.startswith("https://") or value.startswith("http://"))
    ):
        raise ValueError("origin must be an absolute HTTPS origin")
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError as exc:
        raise ValueError("origin contains an invalid host or port") from exc
    if parsed.scheme not in {"http", "https"}:
        raise ValueError("origin must use HTTPS")
    if (
        not parsed.netloc
        or parsed.netloc.endswith(":")
        or parsed.username is not None
        or parsed.password is not None
        or parsed.path not in {"", "/"}
        or parsed.query
        or parsed.fragment
        or parsed.hostname is None
    ):
        raise ValueError("origin must contain only scheme, host, and optional port")

    hostname, is_loopback = _normalized_host(parsed.hostname)
    if parsed.scheme == "http" and (not allow_loopback_http or not is_loopback):
        raise ValueError("HTTP origin is allowed only for explicit loopback testing")
    if port == 0:
        raise ValueError("origin port must be between 1 and 65535")

    if port is not None:
        authority = parsed.netloc
        separator = "]:" if authority.startswith("[") else ":"
        raw_port = authority.rsplit(separator, 1)[1]
        if raw_port != str(port):
            raise ValueError("origin port must use canonical decimal notation")

    host = f"[{hostname}]" if ":" in hostname else hostname
    if (parsed.scheme == "https" and port == 443) or (parsed.scheme == "http" and port == 80):
        port = None
    if port is not None:
        host = f"{host}:{port}"
    return f"{parsed.scheme}://{host}", host, parsed.scheme
