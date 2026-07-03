"""Safe endpoint liveness checker for AuditSkill.

Tests endpoints extracted from a parsed SKILL.md using only safe HTTP
methods (GET / HEAD).  All outbound requests are routed through
:func:`auditskill.core.ssrf_guard.safe_request` so that private /
internal network targets are never contacted.

Produces a :class:`LivenessReport` with per-endpoint results, a list
of skipped endpoints, and an aggregate health score (0-100).

Abuse controls:
- Only GET/HEAD are ever sent — PUT/PATCH/POST/DELETE are never executed.
- At most ``MAX_ENDPOINTS`` endpoints are probed per audit; the rest are
  reported as skipped.  Because every endpoint of a skill shares one
  ``base_url`` host, this doubles as a per-target-domain probe cap.
- Concurrency is bounded and each request has a hard timeout.
"""

from __future__ import annotations

import asyncio
import time
from typing import Sequence

import httpx

from auditskill.api.models import (
    EndpointResult,
    LivenessReport,
    ParsedEndpoint,
    SkippedEndpoint,
)
from auditskill.core.ssrf_guard import SSRFBlockedError, safe_request

# Methods considered safe for automated liveness probes.
_SAFE_METHODS: frozenset[str] = frozenset({"GET", "HEAD"})

# Hard cap on how many endpoints we probe in a single audit (also a
# per-target-domain cap, since all endpoints share one base_url host).
MAX_ENDPOINTS: int = 15


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _build_url(base_url: str, path: str) -> str:
    """Combine *base_url* and *path*, normalising duplicate slashes."""
    base = base_url.rstrip("/")
    path = path if path.startswith("/") else f"/{path}"
    return f"{base}{path}"


async def _probe_single(
    method: str,
    url: str,
    timeout: float,
) -> EndpointResult:
    """Issue one safe HTTP request and return an :class:`EndpointResult`."""
    start = time.monotonic()
    tls = url.lower().startswith("https://")
    try:
        response = await safe_request(method, url, timeout_override=timeout)
        latency_ms = round((time.monotonic() - start) * 1000, 1)

        content_type = response.headers.get("content-type", "")
        valid_json = False
        if "json" in content_type.lower():
            try:
                response.json()
                valid_json = True
            except Exception:  # noqa: BLE001
                pass

        return EndpointResult(
            url=url,
            method=method,
            status=response.status_code,
            latency_ms=latency_ms,
            tls=tls,
            content_type=content_type or None,
            valid_json=valid_json,
            error=None,
        )
    except SSRFBlockedError as exc:
        latency_ms = round((time.monotonic() - start) * 1000, 1)
        return EndpointResult(
            url=url, method=method, status=None, latency_ms=latency_ms,
            tls=tls, content_type=None, valid_json=False,
            error=f"SSRF blocked: {exc}",
        )
    except httpx.TimeoutException:
        latency_ms = round((time.monotonic() - start) * 1000, 1)
        return EndpointResult(
            url=url, method=method, status=None, latency_ms=latency_ms,
            tls=tls, content_type=None, valid_json=False,
            error=f"Timeout after {timeout}s",
        )
    except Exception as exc:  # noqa: BLE001
        latency_ms = round((time.monotonic() - start) * 1000, 1)
        return EndpointResult(
            url=url, method=method, status=None, latency_ms=latency_ms,
            tls=tls, content_type=None, valid_json=False,
            error=str(exc),
        )


def _is_dead(r: EndpointResult) -> bool:
    """A probe is 'dead' if it errored or returned a >=400 status."""
    return r.error is not None or (r.status is not None and r.status >= 400)


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

async def test_endpoints(
    endpoints: list[ParsedEndpoint],
    base_url: str | None,
    mode: str = "liveness",
    max_concurrent: int = 3,
    timeout_per_request: float = 3.0,
) -> LivenessReport:
    """Test a set of parsed endpoints for liveness.

    Only GET/HEAD are probed. State-changing methods are skipped. At most
    ``MAX_ENDPOINTS`` endpoints are probed; the remainder are reported as
    skipped. Returns a not-tested report (``score=None``) when there is
    nothing safe to probe, so the overall score renormalises cleanly.
    """
    skipped: list[SkippedEndpoint] = []

    # ---- Early-exit paths (nothing to probe) ----
    if mode != "liveness" or not endpoints or not base_url:
        if mode != "liveness":
            reason = "safe_static mode — no network I/O"
        elif not base_url:
            reason = "No base URL provided"
        else:
            reason = "No endpoints to test"
        for ep in endpoints:
            skipped.append(SkippedEndpoint(path=ep.path, method=ep.method, reason=reason))
        return LivenessReport(
            score=None, tested=0, alive=0, dead=0,
            avg_latency_ms=None, results=[], skipped=skipped, findings=[],
        )

    # ---- Classify endpoints into testable vs skipped ----
    to_test: list[tuple[str, str]] = []  # (method, full_url)
    for ep in endpoints:
        method_upper = ep.method.upper()
        if method_upper not in _SAFE_METHODS:
            skipped.append(SkippedEndpoint(
                path=ep.path, method=ep.method,
                reason="State-changing method not executed in liveness mode",
            ))
            continue
        if len(to_test) >= MAX_ENDPOINTS:
            skipped.append(SkippedEndpoint(
                path=ep.path, method=ep.method,
                reason=f"Endpoint cap reached (max {MAX_ENDPOINTS} probed per audit)",
            ))
            continue
        to_test.append((method_upper, _build_url(base_url, ep.path)))

    # If everything was skipped (no safe methods / cap):
    if not to_test:
        return LivenessReport(
            score=None, tested=0, alive=0, dead=0,
            avg_latency_ms=None, results=[], skipped=skipped, findings=[],
        )

    # ---- Concurrent probing ----
    semaphore = asyncio.Semaphore(max_concurrent)

    async def _bounded_probe(method: str, url: str) -> EndpointResult:
        async with semaphore:
            return await _probe_single(method, url, timeout_per_request)

    results: Sequence[EndpointResult] = await asyncio.gather(
        *(_bounded_probe(m, u) for m, u in to_test)
    )

    # ---- Aggregate metrics ----
    total_tested = len(results)
    alive = sum(1 for r in results if r.status is not None and 200 <= r.status <= 399)
    dead = total_tested - alive

    latencies = [r.latency_ms for r in results if r.error is None and r.latency_ms is not None]
    avg_latency_ms = round(sum(latencies) / len(latencies), 1) if latencies else None

    # ---- Score calculation ----
    score = 100.0
    findings: list[str] = []
    for r in results:
        if _is_dead(r):
            # Each dead endpoint costs its proportional share of the score,
            # floored at 15 so a single failure still stings.  Capped at
            # 100/total so N dead endpoints can zero the score but never
            # overflow it (previously max(15, 150) tanked any 1-endpoint skill).
            penalty = max(15.0, 100.0 / total_tested)
            score -= penalty
            reason = r.error or f"HTTP {r.status}"
            findings.append(f"Endpoint {r.method} {r.url} not reachable ({reason})")
        if r.error is None and r.latency_ms is not None and r.latency_ms > 2000:
            score -= 5.0
        if not r.tls:
            score -= 10.0
            findings.append(f"Endpoint {r.method} {r.url} does not use HTTPS/TLS")

    score_int = int(round(max(0.0, min(100.0, score))))

    return LivenessReport(
        score=score_int,
        tested=total_tested,
        alive=alive,
        dead=dead,
        avg_latency_ms=avg_latency_ms,
        results=list(results),
        skipped=skipped,
        findings=findings,
    )
