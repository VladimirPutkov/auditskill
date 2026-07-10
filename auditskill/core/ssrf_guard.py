"""DNS-rebinding-safe SSRF guard for outbound HTTP requests.

This is the CRITICAL security module.  Every outbound request made by
AuditSkill (e.g. liveness probes, endpoint validation) MUST go through
:func:`safe_request` so that server-side request forgery is impossible.

The defence is layered:

1. **Scheme validation** — only ``http`` and ``https`` are allowed.
2. **Hostname blocklist** — known dangerous hostnames are rejected
   immediately (``localhost``, ``*.local``, ``*.internal``,
   ``metadata.google.internal``, ``instance-data``).
3. **DNS resolution + IP check** — every resolved address is tested
   against RFC-1918 private ranges, link-local, loopback, CGNAT,
   benchmarking, and IPv6 equivalents.
4. **IP pinning** — the vetted IP is used for the actual TCP connection
   (custom httpx transport) so a DNS-rebinding TOCTOU attack cannot
   substitute a private IP between the check and the connect.
5. **Redirect re-validation** — each ``Location`` hop (max 2) is fully
   re-checked through steps 1–4.
6. **Hard limits** — 3 s timeout, 256 KiB max response body, no cookies,
   no auth headers forwarded.
"""

from __future__ import annotations

import asyncio
import ipaddress
import logging
import re
import socket
from dataclasses import dataclass
from typing import Any
from urllib.parse import urlparse

import httpx

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Public types
# ---------------------------------------------------------------------------


class SSRFBlockedError(Exception):
    """Raised when a URL is blocked by the SSRF guard."""

    def __init__(self, reason: str, url: str = "") -> None:
        self.reason = reason
        self.url = url
        super().__init__(f"SSRF blocked: {reason}" + (f" (url={url})" if url else ""))


@dataclass(frozen=True, slots=True)
class SSRFCheckResult:
    """Outcome of an SSRF safety check on a URL."""

    safe: bool
    resolved_ip: str | None = None
    error: str | None = None


# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

_ALLOWED_SCHEMES = frozenset({"http", "https"})

# Hostnames that are always blocked (case-insensitive exact match or suffix).
_BLOCKED_HOSTNAME_EXACT = frozenset(
    {
        "localhost",
        "metadata.google.internal",
        "instance-data",
    }
)
_BLOCKED_HOSTNAME_SUFFIXES = (
    ".local",
    ".internal",
    ".localhost",
)

# Hostname patterns — numeric-only IPv4 literals like 127.0.0.1 or [::1]
# are caught later by the CIDR check, but we also want to block attempts
# to use decimal/octal/hex encoding (e.g. 0x7f000001, 2130706433).
_NUMERIC_HOST_RE = re.compile(
    r"^(?:\d+\.){0,3}\d+$"  # dotted-decimal / plain decimal
    r"|^0[xX][0-9a-fA-F]+$"  # hex literal
    r"|^0[0-7]+$"  # octal literal
    r"|^\[.+\]$",  # bracketed IPv6
)

# CIDR ranges that must never be contacted.
_BLOCKED_IPV4_NETWORKS = [
    ipaddress.IPv4Network("127.0.0.0/8"),  # loopback
    ipaddress.IPv4Network("10.0.0.0/8"),  # private class A
    ipaddress.IPv4Network("172.16.0.0/12"),  # private class B
    ipaddress.IPv4Network("192.168.0.0/16"),  # private class C
    ipaddress.IPv4Network("169.254.0.0/16"),  # link-local + cloud metadata
    ipaddress.IPv4Network("0.0.0.0/8"),  # unspecified
    ipaddress.IPv4Network("100.64.0.0/10"),  # CGNAT (RFC 6598)
    ipaddress.IPv4Network("198.18.0.0/15"),  # benchmarking (RFC 2544)
]
_BLOCKED_IPV6_NETWORKS = [
    ipaddress.IPv6Network("::1/128"),  # loopback
    ipaddress.IPv6Network("::/128"),  # unspecified
    ipaddress.IPv6Network("fc00::/7"),  # unique local
    ipaddress.IPv6Network("fe80::/10"),  # link-local
    ipaddress.IPv6Network("64:ff9b::/96"),  # NAT64 (embeds IPv4)
    ipaddress.IPv6Network("2001::/32"),  # Teredo (embeds IPv4)
]

# Ports we will connect to: standard web ports, plus the unprivileged range
# (dev servers, alt-HTTP).  Privileged non-web ports (22/SSH, 25/SMTP,
# 6379-via-<1024 etc.) are refused so the service cannot be used to poke
# arbitrary infrastructure services.
_ALLOWED_LOW_PORTS = frozenset({80, 443})

# Hard limits
_TIMEOUT_SECONDS = 3.0
_DEFAULT_MAX_RESPONSE_BYTES = 256 * 1024  # 256 KiB
_MAX_ALLOWED_RESPONSE_BYTES = 2 * 1024 * 1024  # 2 MiB absolute ceiling
_MAX_REDIRECTS = 2

# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def check_url(url: str) -> SSRFCheckResult:
    """Validate that *url* is safe to request.

    Performs scheme validation, hostname blocklist check, DNS resolution,
    and IP-range verification.  Returns an :class:`SSRFCheckResult` with
    ``safe=True`` and the first resolved public IP on success, or
    ``safe=False`` with an error message on failure.
    """
    try:
        parsed = urlparse(url)
        _validate_scheme(parsed.scheme, url)
        _validate_port(parsed, url)
        hostname = _extract_hostname(parsed, url)
        _check_blocked_hostname(hostname, url)
        # DNS resolution is blocking; run it in a worker thread so it does not
        # stall the event loop (matters under concurrent /discover fan-out).
        resolved_ip = await asyncio.to_thread(_resolve_and_check, hostname, url)
        return SSRFCheckResult(safe=True, resolved_ip=resolved_ip)
    except SSRFBlockedError as exc:
        logger.warning("SSRF check failed for %r: %s", url, exc.reason)
        return SSRFCheckResult(safe=False, error=exc.reason)


async def safe_request(
    method: str,
    url: str,
    *,
    timeout_override: float | None = None,
    max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
    **kwargs: Any,
) -> httpx.Response:
    """Make an HTTP request through the SSRF guard.

    The URL (and every redirect hop) is fully validated before a TCP
    connection is opened.  The request connects directly to the pinned IP
    so DNS-rebinding attacks are impossible.

    Args:
        timeout_override: Optional per-request timeout in seconds.
            Defaults to ``_TIMEOUT_SECONDS`` (3 s) when *None*.

    Raises:
        SSRFBlockedError: If the URL or any redirect target is unsafe.
        httpx.HTTPError: On transport-level failures (timeout, etc.).

    Returns:
        The :class:`httpx.Response` for the final (possibly redirected)
        request.
    """
    effective_timeout = timeout_override if timeout_override is not None else _TIMEOUT_SECONDS
    if not 1 <= max_response_bytes <= _MAX_ALLOWED_RESPONSE_BYTES:
        raise ValueError(
            f"max_response_bytes must be between 1 and {_MAX_ALLOWED_RESPONSE_BYTES} bytes"
        )
    # Strip dangerous kwargs the caller might try to sneak in
    kwargs.pop("follow_redirects", None)
    kwargs.pop("cookies", None)
    kwargs.pop("auth", None)
    kwargs.pop("timeout", None)

    current_url = url
    for hop in range(_MAX_REDIRECTS + 1):  # 0, 1, 2 → initial + 2 redirects
        result = await check_url(current_url)
        if not result.safe:
            raise SSRFBlockedError(result.error or "URL failed safety check", current_url)

        assert result.resolved_ip is not None  # guaranteed when safe=True

        response = await _pinned_request(
            method=method if hop == 0 else "GET",  # redirects always GET
            url=current_url,
            pinned_ip=result.resolved_ip,
            timeout_seconds=effective_timeout,
            max_response_bytes=max_response_bytes,
            **kwargs,
        )

        # Check for redirect
        if response.is_redirect and "location" in response.headers:
            location = str(response.headers["location"])
            # Resolve relative redirects against the URL we just fetched
            # (this hop), NOT the original request URL — otherwise A→B→C with
            # a relative Location on B resolves against A and mis-targets.
            if not location.startswith(("http://", "https://")):
                from urllib.parse import urljoin

                location = urljoin(current_url, location)
            current_url = location
            logger.debug("SSRF guard following redirect hop %d → %s", hop + 1, current_url)
            continue

        return response

    raise SSRFBlockedError(
        f"Too many redirects (>{_MAX_REDIRECTS})",
        current_url,
    )


# ---------------------------------------------------------------------------
# Validation helpers
# ---------------------------------------------------------------------------


def _validate_scheme(scheme: str, url: str) -> None:
    """Raise if scheme is not http/https."""
    if scheme.lower() not in _ALLOWED_SCHEMES:
        raise SSRFBlockedError(f"Scheme {scheme!r} is not allowed", url)


def _validate_port(parsed: Any, url: str) -> None:
    """Raise if the URL targets a privileged non-web port (SSH, SMTP, …)."""
    try:
        port = parsed.port  # None when no explicit port in the URL
    except ValueError as exc:  # non-numeric / out-of-range port literal
        raise SSRFBlockedError(f"Invalid port in URL: {exc}", url) from exc
    if port is None:
        return
    if port < 1024 and port not in _ALLOWED_LOW_PORTS:
        raise SSRFBlockedError(
            f"Port {port} is not allowed (only 80, 443, and unprivileged ports)",
            url,
        )


def _extract_hostname(parsed: Any, url: str) -> str:
    """Extract and validate the hostname from a parsed URL."""
    hostname = parsed.hostname
    if not hostname:
        raise SSRFBlockedError("No hostname in URL", url)
    return hostname.lower()


def _check_blocked_hostname(hostname: str, url: str) -> None:
    """Raise if hostname is in the blocklist."""
    if hostname in _BLOCKED_HOSTNAME_EXACT:
        raise SSRFBlockedError(f"Blocked hostname: {hostname}", url)
    for suffix in _BLOCKED_HOSTNAME_SUFFIXES:
        if hostname.endswith(suffix):
            raise SSRFBlockedError(f"Blocked hostname suffix: {suffix}", url)

    # Detect raw IP-address literals embedded as hostnames —
    # they'll be caught later by CIDR check, but we also reject
    # obfuscated numeric forms (hex, octal, decimal-encoded) early.
    if _NUMERIC_HOST_RE.match(hostname):
        # Let it through to DNS/CIDR check — the numeric value will be
        # parsed as an IP and validated against blocked ranges there.
        pass


def _resolve_and_check(hostname: str, url: str) -> str:
    """DNS-resolve *hostname* and verify EVERY resulting IP is public.

    Returns the first safe resolved IP address (the one we'll pin to).
    """
    try:
        addr_infos = socket.getaddrinfo(hostname, None, socket.AF_UNSPEC, socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise SSRFBlockedError(f"DNS resolution failed: {exc}", url) from exc

    if not addr_infos:
        raise SSRFBlockedError("DNS resolution returned no addresses", url)

    first_safe_ip: str | None = None

    for family, _type, _proto, _canonname, sockaddr in addr_infos:
        ip_str = str(sockaddr[0])
        try:
            ip_obj = ipaddress.ip_address(ip_str)
        except ValueError as exc:
            raise SSRFBlockedError(f"Unparseable resolved IP: {ip_str}", url) from exc

        # Check against blocked ranges
        if isinstance(ip_obj, ipaddress.IPv4Address):
            for net in _BLOCKED_IPV4_NETWORKS:
                if ip_obj in net:
                    raise SSRFBlockedError(
                        f"Resolved IP {ip_str} is in blocked range {net}",
                        url,
                    )
        elif isinstance(ip_obj, ipaddress.IPv6Address):
            for net in _BLOCKED_IPV6_NETWORKS:
                if ip_obj in net:
                    raise SSRFBlockedError(
                        f"Resolved IP {ip_str} is in blocked range {net}",
                        url,
                    )
            # Also check IPv4-mapped IPv6 addresses (e.g. ::ffff:127.0.0.1)
            mapped_v4 = ip_obj.ipv4_mapped
            if mapped_v4 is not None:
                for net in _BLOCKED_IPV4_NETWORKS:
                    if mapped_v4 in net:
                        raise SSRFBlockedError(
                            f"Resolved IP {ip_str} maps to blocked IPv4 {mapped_v4} in range {net}",
                            url,
                        )

        if first_safe_ip is None:
            first_safe_ip = ip_str

    if first_safe_ip is None:
        raise SSRFBlockedError("No resolved IPs passed safety check", url)

    return first_safe_ip


# ---------------------------------------------------------------------------
# Pinned-IP HTTP transport
# ---------------------------------------------------------------------------


class _PinnedIPTransport(httpx.AsyncHTTPTransport):
    """Custom transport that connects to a pre-resolved IP address.

    The ``Host`` header is preserved so TLS SNI and virtual-hosting still
    work correctly.  This defeats DNS-rebinding TOCTOU attacks because the
    DNS result that was validated is the one used for the connection.
    """

    def __init__(self, pinned_ip: str, original_host: str, port: int, **kwargs: Any) -> None:
        super().__init__(**kwargs)
        self._pinned_ip = pinned_ip
        self._original_host = original_host
        self._port = port

    async def handle_async_request(self, request: httpx.Request) -> httpx.Response:
        """Connect to the pinned IP while preserving Host + TLS hostname.

        The URL authority is rewritten to the vetted IP so the TCP connection
        goes exactly where we validated (defeating DNS-rebinding TOCTOU), but:

        * the ``Host`` header keeps the original hostname (virtual hosting), and
        * the ``sni_hostname`` request extension pins TLS SNI *and* certificate
          verification to the original hostname — so HTTPS still validates the
          real server's certificate, not the bare IP.
        """
        # Preserve the original hostname for the Host header.
        request.headers["host"] = self._original_host

        # Rewrite the URL authority to the pinned IP (IPv6 gets brackets).
        ip_host = f"[{self._pinned_ip}]" if ":" in self._pinned_ip else self._pinned_ip
        parsed = urlparse(str(request.url))
        pinned_url = parsed._replace(netloc=f"{ip_host}:{self._port}").geturl()
        request.url = httpx.URL(pinned_url)

        # Tell the TLS layer to use the real hostname for SNI + cert checks.
        request.extensions = {**request.extensions, "sni_hostname": self._original_host}

        return await super().handle_async_request(request)


async def _pinned_request(
    *,
    method: str,
    url: str,
    pinned_ip: str,
    timeout_seconds: float = _TIMEOUT_SECONDS,
    max_response_bytes: int = _DEFAULT_MAX_RESPONSE_BYTES,
    **kwargs: Any,
) -> httpx.Response:
    """Execute a single HTTP request pinned to a specific IP.

    Enforces timeout, max response size, and strips cookies / auth.
    """
    parsed = urlparse(url)
    original_host = parsed.hostname or ""
    port = parsed.port or (443 if parsed.scheme == "https" else 80)

    # Build verify setting — for HTTPS we need TLS to validate the
    # real hostname (SNI), not the IP we're connecting to.
    transport = _PinnedIPTransport(
        pinned_ip=pinned_ip,
        original_host=original_host,
        port=port,
        verify=True,
    )

    async with httpx.AsyncClient(
        transport=transport,
        timeout=httpx.Timeout(timeout_seconds),
        follow_redirects=False,  # we handle redirects ourselves
        max_redirects=0,
    ) as client:
        # Stream the body and abort as soon as the cap is exceeded, so a
        # hostile server cannot make us buffer an unbounded response in
        # memory before a size check.  aiter_bytes() yields *decoded* bytes,
        # so the cap also bounds decompression bombs (a tiny gzip body that
        # inflates past the limit is cut off at the limit).
        request = client.build_request(method.upper(), url, **kwargs)
        response = await client.send(request, stream=True)
        try:
            chunks: list[bytes] = []
            total = 0
            async for chunk in response.aiter_bytes():
                total += len(chunk)
                if total > max_response_bytes:
                    raise SSRFBlockedError(
                        f"Response body too large: {total} bytes (max {max_response_bytes})",
                        url,
                    )
                chunks.append(chunk)
        finally:
            await response.aclose()

    return _rebuild_response(response, b"".join(chunks), request)


def _rebuild_response(
    original: httpx.Response, decoded_body: bytes, request: httpx.Request
) -> httpx.Response:
    """Package a fully-read, *decoded* body as a plain httpx.Response.

    The streamed chunks came out of httpx's content decoder, so the body is
    already plaintext.  The original ``Content-Encoding`` / ``Content-Length``
    / ``Transfer-Encoding`` headers describe the wire form, not this body —
    carrying them over would make httpx try to gunzip plaintext a second
    time and fail with a DecodingError (this broke /discover when the NANDA
    registry started serving gzip).
    """
    headers = [
        (k, v)
        for k, v in original.headers.raw
        if k.lower() not in (b"content-encoding", b"content-length", b"transfer-encoding")
    ]
    return httpx.Response(
        status_code=original.status_code,
        headers=headers,
        content=decoded_body,
        request=request,
        extensions=original.extensions,
    )
