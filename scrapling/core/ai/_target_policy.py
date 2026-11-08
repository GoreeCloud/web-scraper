"""Fail-closed destination preflight for GoreeCloud's served MCP HTTP tools.

A DNS preflight is defense in depth, not network confinement or DNS pinning.
Always combine with a sandbox/firewall for untrusted callers.
"""

from __future__ import annotations

from asyncio import to_thread
from ipaddress import ip_address
from socket import getaddrinfo, SOCK_STREAM
from urllib.parse import urlsplit


def _origin(url: str, *, configured: bool = False) -> tuple[str, str, int]:
    if not isinstance(url, str) or not url or any(ord(c) <= 32 or ord(c) == 127 for c in url):
        raise ValueError("Target URL must be an absolute, whitespace-free HTTP(S) URL")
    if "\\" in url:
        raise ValueError("Backslashes are prohibited in target URLs")
    try:
        parsed = urlsplit(url)
        hostname = parsed.hostname
        port = parsed.port
    except ValueError as exc:
        raise ValueError("Invalid target URL authority or port") from exc
    if (
        parsed.scheme not in ("http", "https")
        or not hostname or parsed.username is not None or parsed.password is not None
        or parsed.fragment or "%" in parsed.netloc or not parsed.netloc
        or hostname.endswith(".")
    ):
        raise ValueError("Target URL must be HTTP(S), without credentials, fragments, or ambiguous host syntax")
    try:
        hostname.encode("ascii")
    except UnicodeEncodeError as exc:
        raise ValueError("Use ASCII/IDNA hostnames for explicit target authorization") from exc
    if any(label == "" or not label.replace("-", "").isalnum() or
           label.startswith("-") or label.endswith("-") for label in hostname.split(".")) and ":" not in hostname:
        raise ValueError("Invalid target hostname")
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("Target URL port must be between 1 and 65535")
    if configured and (parsed.path not in ("", "/") or parsed.query):
        raise ValueError("Allowed target entries must be exact origins, not paths or query strings")
    return parsed.scheme, hostname.lower(), port or (443 if parsed.scheme == "https" else 80)


class MCPDestinationPolicy:
    def __init__(self, allowed_origins: tuple[str, ...] = (), allow_loopback: bool = False):
        self.origins = frozenset(_origin(origin, configured=True) for origin in allowed_origins)
        self.allow_loopback = bool(allow_loopback)

    async def require(self, target_url: str) -> None:
        scheme, hostname, port = _origin(target_url)
        if (scheme, hostname, port) not in self.origins:
            raise ValueError("Target destination is not in the configured MCP origin allowlist")
        # DNS checks are *not* a guarantee that the HTTP client uses the same address.
        # A production server also needs connection-level IP pinning/egress filtering.
        try:
            address = ip_address(hostname)
        except ValueError:
            try:
                resolved = await to_thread(getaddrinfo, hostname, port, 0, SOCK_STREAM)
            except OSError as exc:
                raise ValueError("Target destination DNS lookup failed; request refused") from exc
            addresses = []
            for result in resolved:
                try:
                    addresses.append(ip_address(result[4][0]))
                except (ValueError, IndexError) as exc:
                    raise ValueError("Invalid DNS address for target") from exc
        else:
            addresses = [address]
        # Opting into loopback must not let a malicious public-looking hostname
        # redirect through DNS to a local service.
        is_explicit_loopback = hostname in ("localhost", "127.0.0.1", "::1")
        if not addresses or any(
            not (ip.is_global or (self.allow_loopback and is_explicit_loopback and ip.is_loopback))
            for ip in addresses
        ):
            raise ValueError("Target DNS addresses include private, local, reserved, or unapproved IP space")
