"""Safe-discovery layer: audit the live NANDA Town registry.

This is the "antivirus built into discovery" surface.  Instead of an agent
searching the registry and blindly loading whatever it finds, it searches
*through* AuditSkill: every registry entry comes back with a verdict already
attached, so an unsafe skill is flagged before the agent ever loads it.

The registry itself is fetched through the SSRF-safe client, each entry's
SKILL.md is audited (inline ``content`` when present, otherwise the declared
``source_url`` is fetched), and results are cached by content hash so the
same file is never re-audited within the cache window.
"""

from __future__ import annotations

import asyncio
import logging
from typing import Any

from auditskill.api.models import DiscoverResponse, DiscoverResult
from auditskill.core import security_scanner
from auditskill.core.auditor import fetch_skill_from_url, run_audit
from auditskill.core.ssrf_guard import safe_request
from auditskill.db.store import AuditStore

logger = logging.getLogger(__name__)

# Default machine-readable registry.  Overridable via the endpoint so the
# same logic can audit any NANDA-style registry that returns this shape.
DEFAULT_REGISTRY_URL = "https://nandatown.projectnanda.org/api/skills"

# Bound the work so one /discover call can never fan out unboundedly.
_MAX_ENTRIES = 30
_MAX_CONCURRENCY = 4
_PER_AUDIT_TIMEOUT = 20.0
# The public registry currently averages roughly 2.3 KiB per listing. A
# 2 MiB decoded-body cap accommodates the expected maximum of 500 submissions
# with substantial headroom while remaining a strict, memory-safe bound. This
# larger allowance applies only to the registry feed; arbitrary skill URLs and
# endpoint probes retain safe_request's 256 KiB default.
_MAX_REGISTRY_RESPONSE_BYTES = 2 * 1024 * 1024

# Deterministic ranking: composite = overall_score + density bonus.  The
# formula is published verbatim in /benchmarks — no hidden magic.
DENSITY_BONUS: dict[str, int] = {"high": 5, "medium": 0, "low": -5}
_FAILS = "FAILS_BASIC_AUDIT"

# Frontier flagship whose cost is surfaced in the compact /discover summary —
# the model class that actually loads skills at runtime, so an agent sees the
# cost on "its own" tier alongside the cheapest/most-expensive extremes.
_FLAGSHIP_MODEL = "claude-opus-4-8"


_VERDICT_SEVERITY_RANK: dict[str, int] = {
    "PASS_BASIC_AUDIT": 0,
    "PASS_WITH_WARNINGS": 1,
    "REQUIRES_HUMAN_REVIEW": 2,
    "FAILS_BASIC_AUDIT": 3,
}


def _verdict_rank(verdict: str | None) -> int:
    """Higher = more severe.  Used to downgrade-only when metadata is poisoned."""
    return _VERDICT_SEVERITY_RANK.get(verdict or "", 0)


def _matches_query(entry: dict[str, Any], q: str) -> bool:
    """Case-insensitive substring match over name/description/tags/author."""
    if not q:
        return True
    hay = " ".join(
        str(entry.get(k) or "") for k in ("name", "description", "tags", "author")
    ).lower()
    return q.lower() in hay


async def _resolve_skill_text(entry: dict[str, Any]) -> tuple[str | None, str | None]:
    """Return ``(skill_md, reason_if_unavailable)`` for a registry entry.

    Prefers inline ``content`` (no network).  Falls back to fetching the
    declared ``source_url`` through the SSRF-safe client.
    """
    content = entry.get("content")
    if content and isinstance(content, str) and content.strip():
        return content, None

    source_url = entry.get("source_url")
    if source_url and isinstance(source_url, str) and source_url.startswith("https://"):
        try:
            text = await fetch_skill_from_url(source_url)
            return text, None
        except Exception as exc:  # noqa: BLE001
            return None, f"Could not fetch source_url ({type(exc).__name__}): {exc}"

    return None, "No inline content and no https source_url to fetch"


async def _audit_entry(
    entry: dict[str, Any], mode: str, store: AuditStore | None
) -> DiscoverResult:
    """Audit one registry entry and fold the verdict into a DiscoverResult."""
    # Registry metadata is untrusted too. Scan it before constructing the
    # response so poisoned names and descriptions are never echoed to agents.
    meta_text = "\n".join(
        str(entry.get(k) or "") for k in ("name", "author", "description", "tags")
    )
    meta_report = security_scanner.scan(meta_text)
    meta_findings = [
        finding for finding in meta_report.findings if finding.severity in ("critical", "high")
    ]
    unsafe_metadata = bool(meta_findings)
    base = DiscoverResult(
        name="[unsafe registry metadata withheld]" if unsafe_metadata else entry.get("name"),
        author=None if unsafe_metadata else entry.get("author"),
        description=None if unsafe_metadata else entry.get("description"),
        source_url=entry.get("source_url"),
        tags=None if unsafe_metadata else entry.get("tags"),
        metadata_withheld=unsafe_metadata,
        critical_findings=sum(1 for f in meta_findings if f.severity == "critical"),
        high_findings=sum(1 for f in meta_findings if f.severity == "high"),
        security_findings=len(meta_findings),
        security_rule_ids=sorted({f.rule_id for f in meta_findings}),
    )

    skill_md, reason = await _resolve_skill_text(entry)
    if skill_md is None:
        base.audited = False
        suffix = " Unsafe registry metadata was withheld." if unsafe_metadata else ""
        base.reason = f"{reason or 'Skill unavailable'}.{suffix}".strip()
        return base

    try:
        result = await asyncio.wait_for(
            run_audit(skill_md, mode=mode, store=store), timeout=_PER_AUDIT_TIMEOUT
        )
    except asyncio.TimeoutError:
        base.audited = False
        base.reason = f"Audit timed out after {_PER_AUDIT_TIMEOUT}s"
        return base
    except Exception as exc:  # noqa: BLE001
        base.audited = False
        base.reason = f"Audit error ({type(exc).__name__}): {exc}"
        return base

    all_findings = list(result.security.findings) + meta_findings
    critical = sum(1 for f in all_findings if f.severity == "critical")
    high = sum(1 for f in all_findings if f.severity == "high")
    base.audited = True
    base.verdict = result.verdict
    base.score = result.overall_score
    base.risk_level = result.security.risk_level
    base.critical_findings = critical
    base.high_findings = high
    base.security_findings = len(all_findings)
    base.security_rule_ids = sorted({finding.rule_id for finding in all_findings})
    base.skill_hash = result.skill_hash
    base.cached = result.cached

    if meta_findings:
        # Downgrade only (never upgrade): poisoned metadata forces at least
        # human-review, and a critical hit fails outright — regardless of the
        # document score.
        forced = "FAILS_BASIC_AUDIT" if critical else "REQUIRES_HUMAN_REVIEW"
        if _verdict_rank(forced) > _verdict_rank(base.verdict):
            base.verdict = forced
        base.score = min(base.score or 100, 39 if critical else 69)
        base.risk_level = "critical" if critical else "high"
        # This certificate signs the document-only audit, not the combined
        # metadata downgrade, so exposing it would misrepresent the result.
        base.certificate_id = None
        base.reason = (
            f"Registry metadata contains a {'critical' if critical else 'high'}-"
            f"severity pattern ({meta_findings[0].rule_id}: "
            f"{meta_findings[0].category}); metadata was withheld and the "
            "combined result was downgraded."
        )
    else:
        base.certificate_id = result.certificate_id

    # Compact context-cost summary so the agent can weigh safety AND price
    # in one /discover call (core mission: pick the right skill to load).
    # Carry both ends of the price range with model names so an agent can
    # answer "is it worth the tokens?" from the /discover response alone,
    # without a second /audit for the per-model breakdown.
    cc = result.context_cost
    cheapest_entry = min(cc.per_model, key=lambda c: c.input_cost_usd, default=None)
    priciest_entry = max(cc.per_model, key=lambda c: c.input_cost_usd, default=None)
    # Also surface the cost on a frontier flagship (Claude Opus) — the class of
    # model that actually loads skills at runtime — so the "what will this cost
    # ME" number is present, not just the extremes of the tracked range.
    flagship_entry = next((c for c in cc.per_model if c.model == _FLAGSHIP_MODEL), None)
    base.context_cost = {
        "tokens_estimate": cc.tokens_estimate,
        "density": cc.density,
        "cheapest_input_usd": cheapest_entry.input_cost_usd if cheapest_entry else None,
        "cheapest_model": cheapest_entry.model if cheapest_entry else None,
        "flagship_input_usd": flagship_entry.input_cost_usd if flagship_entry else None,
        "flagship_model": flagship_entry.model if flagship_entry else None,
        "most_expensive_input_usd": priciest_entry.input_cost_usd if priciest_entry else None,
        "most_expensive_model": priciest_entry.model if priciest_entry else None,
    }
    return base


# ---------------------------------------------------------------------------
# Ranking (pure, deterministic — unit-testable without network)
# ---------------------------------------------------------------------------


# Safety tiers — a stronger verdict ALWAYS ranks above a weaker one, whatever
# the density bonus.  Density only breaks ties *within* a verdict tier, so a
# PASS_WITH_WARNINGS can never outrank a PASS_BASIC_AUDIT on density alone.
_VERDICT_TIER: dict[str, int] = {
    "PASS_BASIC_AUDIT": 0,
    "PASS_WITH_WARNINGS": 1,
    "REQUIRES_HUMAN_REVIEW": 2,
}


def _composite(r: DiscoverResult) -> int:
    density = (r.context_cost or {}).get("density")
    return (r.score or 0) + DENSITY_BONUS.get(str(density or ""), 0)


def rank_results(results: list[DiscoverResult]) -> list[DiscoverResult]:
    """Order results best-first and attach ``rank`` / ``rank_reason``.

    Buckets (never mixed): passing audits → failing audits → unaudited.
    Within the passing bucket the primary key is the **verdict tier**
    (PASS_BASIC_AUDIT before PASS_WITH_WARNINGS before REQUIRES_HUMAN_REVIEW);
    only *within* one tier does density-adjusted composite, then score, then
    fewer critical findings, then name, break the tie — fully deterministic.
    """
    passing = [r for r in results if r.audited and r.verdict != _FAILS]
    failing = [r for r in results if r.audited and r.verdict == _FAILS]
    unaudited = [r for r in results if not r.audited]

    passing.sort(
        key=lambda r: (
            _VERDICT_TIER.get(r.verdict or "", 9),
            -_composite(r),
            -(r.score or 0),
            r.critical_findings,
            (r.name or "").lower(),
        )
    )
    failing.sort(key=lambda r: (-(r.score or 0), (r.name or "").lower()))

    for r in passing:
        density = (r.context_cost or {}).get("density")
        bonus = DENSITY_BONUS.get(str(density or ""), 0)
        r.rank_reason = (
            f"{r.verdict} tier; composite {_composite(r)} = score {r.score} "
            f"+ density bonus {bonus:+d} ({density or 'unknown'})"
        )
    for r in failing:
        r.rank_reason = "excluded from top ranking: FAILS_BASIC_AUDIT"
    for r in unaudited:
        r.rank_reason = f"not ranked: {r.reason or 'could not be audited'}"

    ordered = passing + failing + unaudited
    for position, r in enumerate(ordered, start=1):
        r.rank = position
    return ordered


async def discover(
    q: str = "",
    mode: str = "safe_static",
    limit: int = _MAX_ENTRIES,
    registry_url: str = DEFAULT_REGISTRY_URL,
    store: AuditStore | None = None,
) -> DiscoverResponse:
    """Fetch a NANDA-style registry and audit every (matching) entry.

    Args:
        q: Optional case-insensitive filter over name/description/tags/author.
        mode: ``safe_static`` (fast, no network) or ``liveness`` (also probes
            each skill's declared endpoints).
        limit: Max entries to audit (hard-capped at 30).
        registry_url: The registry to read (must be https).
        store: Optional cache/persistence.

    Returns:
        A :class:`DiscoverResponse` — the registry listing with a verdict,
        score, and risk level attached to each entry.
    """
    if mode not in ("safe_static", "liveness"):
        raise ValueError(
            "mode must be 'safe_static' or 'liveness'. "
            "Fix: omit mode for the fast offline scan, or pass 'liveness' to "
            "also probe each skill's endpoints."
        )

    if not registry_url.startswith("https://"):
        raise ValueError(
            "registry_url must use HTTPS (start with 'https://'). "
            "Fix: omit registry_url to scan the default NANDA Town registry."
        )

    limit = max(1, min(limit, _MAX_ENTRIES))

    resp = await safe_request(
        "GET",
        registry_url,
        max_response_bytes=_MAX_REGISTRY_RESPONSE_BYTES,
    )
    try:
        payload = resp.json()
    except Exception as exc:  # noqa: BLE001 — registry served non-JSON
        raise ValueError(
            f"Registry at {registry_url} did not return JSON "
            f"({type(exc).__name__}). Fix: point registry_url at a "
            "NANDA-style JSON registry endpoint."
        ) from exc
    skills: list[dict[str, Any]] = payload.get("skills", []) if isinstance(payload, dict) else []
    total = len(skills)

    # De-duplicate by (name, source_url) so the registry's repeat submissions
    # don't get audited (and listed) multiple times.
    seen: set[tuple[str, str]] = set()
    unique: list[dict[str, Any]] = []
    for s in skills:
        key = (
            str(s.get("name") or ""),
            str(s.get("source_url") or s.get("content") or "")[:120],
        )
        if key in seen:
            continue
        seen.add(key)
        unique.append(s)

    selected = [s for s in unique if _matches_query(s, q)][:limit]

    semaphore = asyncio.Semaphore(_MAX_CONCURRENCY)

    async def _bounded(entry: dict[str, Any]) -> DiscoverResult:
        async with semaphore:
            return await _audit_entry(entry, mode, store)

    results = await asyncio.gather(*(_bounded(s) for s in selected))
    audited_count = sum(1 for r in results if r.audited)

    # Best-first: the agent's decision engine, not a bare listing.
    ranked = rank_results(list(results))

    return DiscoverResponse(
        registry=registry_url,
        mode=mode,
        total_in_registry=total,
        returned=len(ranked),
        audited=audited_count,
        results=ranked,
    )
