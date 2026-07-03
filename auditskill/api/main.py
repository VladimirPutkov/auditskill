"""FastAPI application entry point for AuditSkill.

Initialises the AuditStore via the async lifespan context, wires up
CORS middleware, SlowAPI rate-limit handling, and the main API router.
"""

from __future__ import annotations

import asyncio
import contextlib
import os
import uvicorn
from contextlib import asynccontextmanager
from typing import AsyncIterator

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from slowapi import _rate_limit_exceeded_handler
from slowapi.errors import RateLimitExceeded

from auditskill.api.rate_limiter import limiter
from auditskill.api.routes import router
from auditskill.core.pricing import price_cache
from auditskill.db.store import AuditStore

store = AuditStore()


@asynccontextmanager
async def lifespan(app: FastAPI) -> AsyncIterator[None]:
    """Manage the application lifecycle — database + background price refresh."""
    await store.initialize()
    app.state.store = store
    # Refresh model prices in the background (startup, then daily).  Audits
    # never wait on this — they read the in-memory snapshot only.
    price_task = asyncio.create_task(price_cache.refresh_loop())
    yield
    price_task.cancel()
    with contextlib.suppress(asyncio.CancelledError):
        await price_task
    await store.close()


app = FastAPI(
    title="AuditSkill",
    description=(
        "Third-party attestation layer for NANDA agent skills. "
        "Audits SKILL.md files and issues signed Ed25519 certificates."
    ),
    version="1.0.0",
    lifespan=lifespan,
)

# --- Rate-limit support via SlowAPI ---
app.state.limiter = limiter
app.add_exception_handler(RateLimitExceeded, _rate_limit_exceeded_handler)

# --- CORS ---
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["GET", "POST"],
    allow_headers=["*"],
)

# --- Routes ---
app.include_router(router)


def run() -> None:
    """CLI entry-point (registered as ``auditskill`` console-script)."""
    port = int(os.environ.get("PORT", 8000))
    uvicorn.run("auditskill.api.main:app", host="0.0.0.0", port=port, reload=False)


if __name__ == "__main__":
    run()
