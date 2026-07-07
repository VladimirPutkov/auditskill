"""Rate-limiting configuration for the AuditSkill API.

Uses SlowAPI (a Starlette/FastAPI wrapper around ``limits``) with the
default in-memory backend.  Key function: client IP address.

Behind a reverse proxy (Railway, Fly, etc.) ``request.client.host`` is the
proxy's address, so every caller would share a single rate-limit bucket and
one busy client could 429 everyone else.  We therefore prefer the first hop
of ``X-Forwarded-For`` (the original client, as appended by the platform's
edge) and fall back to the socket address when the header is absent
(e.g. local development and tests).
"""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address
from starlette.requests import Request


def client_ip(request: Request) -> str:
    """Return the originating client IP for rate-limit bucketing."""
    forwarded = request.headers.get("x-forwarded-for", "")
    if forwarded:
        first_hop = forwarded.split(",")[0].strip()
        if first_hop:
            return first_hop
    return get_remote_address(request)


limiter = Limiter(key_func=client_ip)
