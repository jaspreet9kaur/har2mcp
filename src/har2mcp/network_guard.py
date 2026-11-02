"""Experimental policy inspection helpers. No live HTTP transport is shipped."""

from __future__ import annotations

from dataclasses import dataclass, field
import ipaddress
import socket
from typing import Any
from urllib.parse import urlencode, urlsplit


from har2mcp.limits import DEFAULT_LIMITS

METADATA_HOSTS = frozenset(
    {
        "metadata.google.internal",
        "metadata",
        "169.254.169.254",
        "100.100.100.200",
        "fd00:ec2::254",
    }
)

CARRIER_GRADE_NAT = ipaddress.ip_network("100.64.0.0/10")
BENCHMARK_NET = ipaddress.ip_network("198.18.0.0/15")


@dataclass(frozen=True)
class LiveRequestPolicy:
    """Explicit operator policy required before any live outbound HTTP call."""

    allow_live_mode: bool = False
    allowed_origins: frozenset[str] = field(default_factory=frozenset)
    allowed_methods: frozenset[str] = field(
        default_factory=lambda: frozenset({"GET", "HEAD"})
    )
    allow_private_network: bool = False
    timeout_seconds: float = DEFAULT_LIMITS.default_live_timeout_seconds
    max_response_bytes: int = DEFAULT_LIMITS.max_live_response_bytes


def normalize_origin(url: str) -> str:
    split = urlsplit(url)
    scheme = split.scheme.lower()
    if scheme not in ("http", "https") or not split.hostname:
        raise ValueError(f"Unsupported URL scheme or missing hostname: {url}")
    if split.username is not None or split.password is not None:
        raise ValueError("URLs containing embedded userinfo credentials are refused")
    host = split.hostname.lower()
    port = split.port
    default_port = 80 if scheme == "http" else 443
    return (
        f"{scheme}://{host}"
        if (port is None or port == default_port)
        else f"{scheme}://{host}:{port}"
    )


def is_blocked_ip(
    ip_str: str,
    allow_private_network: bool = False,
) -> tuple[bool, str]:
    """Check an IPv4 or IPv6 address (including IPv4-mapped IPv6) against SSRF ranges."""
    addr = ipaddress.ip_address(ip_str)
    if isinstance(addr, ipaddress.IPv6Address) and addr.ipv4_mapped is not None:
        addr = addr.ipv4_mapped

    if str(addr) in ("169.254.169.254", "100.100.100.200", "fd00:ec2::254"):
        return (True, f"Cloud metadata address blocked: {addr}")
    if addr.is_link_local:
        return (True, f"Link-local address blocked: {addr}")
    if addr.is_unspecified or addr.is_multicast:
        return (True, f"Unspecified or multicast address blocked: {addr}")

    if not allow_private_network:
        if addr.is_loopback:
            return (True, f"Loopback address blocked by default SSRF policy: {addr}")
        if addr.is_private:
            return (True, f"Private network address blocked by default SSRF policy: {addr}")
        if addr.is_reserved:
            return (True, f"Reserved address blocked: {addr}")
        if isinstance(addr, ipaddress.IPv4Address) and (
            addr in CARRIER_GRADE_NAT or addr in BENCHMARK_NET
        ):
            return (True, f"Special-use IPv4 range blocked: {addr}")

    return (False, "")


def verify_target_url_safety(
    url: str,
    method: str,
    policy: LiveRequestPolicy,
    resolver: Any = None,
) -> str:
    """Validate live mode opt-in, origin allowlist, method allowlist, and resolved DNS IPs."""
    if not policy.allow_live_mode:
        raise PermissionError(
            "Live network calls are disabled by default. Enable allow_live_mode explicitly."
        )

    norm_method = method.strip().upper()
    if norm_method not in policy.allowed_methods:
        raise PermissionError(
            f"HTTP method '{norm_method}' is not in allowed_methods {sorted(policy.allowed_methods)}"
        )

    origin = normalize_origin(url)
    if origin not in policy.allowed_origins:
        raise PermissionError(
            f"Target origin '{origin}' is not in allowed_origins {sorted(policy.allowed_origins)}"
        )

    split = urlsplit(url)
    host = (split.hostname or "").lower()
    if host in METADATA_HOSTS or host.endswith(".internal"):
        raise PermissionError(f"Blocked metadata or internal hostname: {host}")

    try:
        ipaddress.ip_address(host)
        blocked, reason = is_blocked_ip(host, allow_private_network=policy.allow_private_network)
        if blocked:
            raise PermissionError(reason)
        return origin
    except ValueError:
        pass

    if host == "localhost" or host.endswith(".localhost"):
        if not policy.allow_private_network:
            raise PermissionError("Loopback hostname 'localhost' blocked by default SSRF policy")
        return origin

    lookup_fn = resolver or socket.getaddrinfo
    try:
        addr_infos = lookup_fn(
            host,
            split.port or (443 if split.scheme == "https" else 80),
            type=socket.SOCK_STREAM,
        )
    except OSError as exc:
        raise PermissionError(f"DNS resolution failed for '{host}': {exc}") from exc

    if not addr_infos:
        raise PermissionError(f"DNS resolution returned no addresses for '{host}'")

    for info in addr_infos:
        sockaddr = info[4]
        resolved_ip = str(sockaddr[0]).split("%", 1)[0]
        blocked, reason = is_blocked_ip(
            resolved_ip, allow_private_network=policy.allow_private_network
        )
        if blocked:
            raise PermissionError(f"Host '{host}' resolved to blocked IP ({reason})")

    return origin


def execute_guarded_live_request(
    method: str, origin: str, path: str,
    query_params: dict[str, Any] | None, json_body: Any,
    policy: LiveRequestPolicy, resolver: Any = None,
) -> dict[str, Any]:
    """No live transport is shipped until connection-bound policy is implemented."""
    raise PermissionError(
        "Live HTTP is unavailable in this release. Use cassette or simulated-state mode."
    )
