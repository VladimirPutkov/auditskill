"""Rate-limiting configuration for the AuditSkill API.

Uses SlowAPI (a Starlette/FastAPI wrapper around ``limits``) with the
default in-memory backend.  Key function: remote IP address.
"""

from __future__ import annotations

from slowapi import Limiter
from slowapi.util import get_remote_address

limiter = Limiter(key_func=get_remote_address)
