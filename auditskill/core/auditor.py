"""Main audit orchestrator for AuditSkill.

Coordinates the full audit pipeline: parsing, security scanning, scope
analysis, structure scoring, metadata checking, optional liveness testing,
score aggregation, verdict determination, certificate issuance, and
persistent storage.

Also provides :func:`fetch_skill_from_url` for retrieving SKILL.md files
from remote URLs via the SSRF-safe HTTP client.
"""

from __future__ import annotations

import asyncio
import logging
import secrets
from datetime import datetime, timezone
from typing import Any

from auditskill.api.models import (
    AuditResponse,
    Certificate,
    ContextCost,
    Issue,
    LivenessReport,
    MetadataReport,
    ParsedSkill,
    ScopeReport,
    SecurityReport,
    StructureReport,
)
from auditskill.core import (
    certifier,
    metadata_checker,
    parser,
    pricing,
    security_scanner,
    scope_analyzer,
    endpoint_tester,
)
from auditskill.core.crypto import hash_text
from auditskill.core.ssrf_guard import SSRFBlockedError, safe_request
from auditskill.db.store import AuditStore
from auditskill.rules.quality_benchmarks import (
    calculate_overall_score,
    calculate_structure_score,
    determine_verdict,
)

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Constants
# ---------------------------------------------------------------------------

_MAX_SKILL_BYTES = 200 * 1024  # 200 KiB — matches AuditRequest input limit
_GLOBAL_LIVENESS_TIMEOUT = 25.0  # seconds — keep the whole audit under ~30s

_VALID_MODES = ("safe_static", "liveness")

# Context-cost density thresholds.
# A "useful token" is estimated from endpoint count, examples, and structure.
_TOKEN_HIGH_DENSITY_THRESHOLD = 0.08   # ≥8% of tokens map to useful info
_TOKEN_LOW_DENSITY_THRESHOLD = 0.03    # <3% → bloated
_TOKENS_LARGE_SKILL = 3000             # above this, flag as large
_FETCH_TIMEOUT = 10.0                  # generous timeout for SKILL.md downloads
                                       # (free-tier hosts need cold-start time)

_SEVERITY_ORDER: dict[str, int] = {
    "critical": 0,
    "high": 1,
    "medium": 2,
    "low": 3,
    "info": 4,
}

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _build_structure_report(parsed: ParsedSkill) -> StructureReport:
    """Build a :class:`StructureReport` (with score) from parsed fields."""
    findings: list[str] = []
    if not parsed.name:
        findings.append("Skill name/title is missing")
    if not parsed.description:
        findings.append("Skill description is missing")
    if not parsed.endpoints:
        findings.append("No endpoints declared")
    if not parsed.base_url:
        findings.append("No base URL specified")
    if not parsed.has_examples:
        findings.append("No usage examples provided")
    if not parsed.has_error_docs:
        findings.append("No error-handling documentation")
    if not parsed.has_workflow:
        findings.append("No workflow / usage guide")

    report = StructureReport(
        score=0,
        has_name=bool(parsed.name),
        has_description=bool(parsed.description),
        has_base_url=bool(parsed.base_url),
        has_endpoints=bool(parsed.endpoints),
        has_examples=bool(parsed.has_examples),
        has_error_docs=parsed.has_error_docs,
        has_auth_docs=parsed.has_auth_docs,
        has_rate_limits=parsed.has_rate_limits,
        has_workflow=parsed.has_workflow,
        has_side_effects_warning=parsed.has_side_effects_warning,
        endpoint_count=len(parsed.endpoints),
        example_count=parsed.example_count,
        section_count=parsed.section_count,
        findings=findings,
    )
    # Score via the richer required/recommended-section rubric.
    report.score = calculate_structure_score(report)
    return report


def _severity_from_score(score: int | None) -> str:
    """Infer an issue severity from a 0-100 module score."""
    if score is None:
        return "info"
    if score < 50:
        return "high"
    if score < 80:
        return "medium"
    return "low"


def _collect_issues(
    structure: StructureReport,
    security: SecurityReport,
    scope: ScopeReport,
    metadata: MetadataReport,
    liveness: LivenessReport,
) -> list[Issue]:
    """Flatten every module's findings into a sorted list of :class:`Issue`.

    Security findings carry their own explicit severity; findings from the
    other modules inherit severity from that module's score.
    """
    issues: list[Issue] = []

    # Security findings already carry an explicit severity.
    for f in security.findings:
        issues.append(Issue(severity=f.severity, msg=f.detail, module="security"))

    # String findings from the remaining modules.
    for report, module in (
        (structure, "structure"),
        (scope, "scope"),
        (metadata, "metadata"),
        (liveness, "liveness"),
    ):
        severity = _severity_from_score(getattr(report, "score", None))
        for finding in getattr(report, "findings", []) or []:
            issues.append(Issue(severity=severity, msg=finding, module=module))

    issues.sort(key=lambda i: _SEVERITY_ORDER.get(i.severity, 99))
    return issues


def _empty_liveness() -> LivenessReport:
    """Return a not-tested liveness report (safe_static mode)."""
    return LivenessReport(
        score=None,
        tested=0,
        alive=0,
        dead=0,
        avg_latency_ms=None,
        results=[],
        skipped=[],
        findings=[],
    )


# ---------------------------------------------------------------------------
# Public API — audit orchestration
# ---------------------------------------------------------------------------


async def run_audit(
    skill_md: str,
    mode: str = "liveness",
    store: AuditStore | None = None,
) -> AuditResponse:
    """Execute the full audit pipeline on a SKILL.md document.

    Args:
        skill_md: Raw SKILL.md text content.
        mode: One of ``'safe_static'`` or ``'liveness'``.
        store: Optional persistent store for caching and history.

    Returns:
        A complete :class:`AuditResponse` with per-module reports,
        aggregated score, verdict, issues list, and a signed certificate.
    """
    if mode not in _VALID_MODES:
        raise ValueError(f"Unknown audit mode {mode!r}; expected one of {_VALID_MODES}")

    # 1. Content hash -------------------------------------------------------
    skill_hash = hash_text(skill_md)

    # 2. Cache check --------------------------------------------------------
    if store:
        cached = await store.get_cached_audit(skill_hash, mode)
        if cached is not None:
            try:
                resp = AuditResponse(**cached["result_json"])
                resp.cached = True
                logger.info("Returning cached audit for %s (mode=%s)", skill_hash, mode)
                return resp
            except Exception:  # noqa: BLE001 — fall through to recompute
                logger.exception("Failed to reconstruct cached audit; recomputing")

    # 3. Parse --------------------------------------------------------------
    parsed: ParsedSkill = parser.parse_skill_md(skill_md)

    # 4. Security scan ------------------------------------------------------
    security_report: SecurityReport = security_scanner.scan(
        skill_md,
        endpoints=parsed.endpoints,
        description=parsed.description,
        base_url=parsed.base_url,
    )

    # 5. Scope analysis -----------------------------------------------------
    scope_report: ScopeReport = scope_analyzer.analyze_scope(parsed)

    # 6. Structure ----------------------------------------------------------
    structure_report: StructureReport = _build_structure_report(parsed)

    # 7. Metadata -----------------------------------------------------------
    metadata_report: MetadataReport = await metadata_checker.check_metadata(
        parsed, check_reachability=(mode == "liveness")
    )

    # 8. Liveness -----------------------------------------------------------
    if mode == "liveness":
        try:
            liveness_report = await asyncio.wait_for(
                endpoint_tester.test_endpoints(
                    endpoints=parsed.endpoints,
                    base_url=parsed.base_url,
                    mode=mode,
                ),
                timeout=_GLOBAL_LIVENESS_TIMEOUT,
            )
        except asyncio.TimeoutError:
            logger.warning("Liveness testing timed out after %ss", _GLOBAL_LIVENESS_TIMEOUT)
            liveness_report = _empty_liveness()
            liveness_report.findings = ["Liveness testing timed out"]
    else:
        liveness_report = _empty_liveness()

    # 9. Overall score (renormalised over present modules) ------------------
    module_scores: dict[str, float | None] = {
        "structure": structure_report.score,
        "security": security_report.score,
        "liveness": liveness_report.score,
        "metadata": metadata_report.score,
        "scope": scope_report.score,
    }
    overall_score = calculate_overall_score(module_scores)

    # 10. Verdict (severity gating comes from security findings) ------------
    verdict_findings: list[dict[str, Any]] = [
        {"severity": f.severity} for f in security_report.findings
    ]
    verdict = determine_verdict(overall_score, verdict_findings)

    # 10b. Non-skill / empty-document guard ---------------------------------
    # A GitHub 404 HTML page, whitespace, or a bare heading is not a SKILL.md.
    # Without this, such inputs score ~50 (REQUIRES_HUMAN_REVIEW) because the
    # security module finds nothing to flag.  If the document carries none of
    # the load-bearing signals (name, endpoints, base URL), fail it explicitly.
    if not (parsed.name or parsed.endpoints or parsed.base_url):
        finding = "Input does not look like a SKILL.md (no title, endpoints, or base URL found)"
        if finding not in structure_report.findings:
            structure_report.findings.insert(0, finding)
        overall_score = min(overall_score, 30)
        verdict = determine_verdict(overall_score, verdict_findings)

    # 11. Issues ------------------------------------------------------------
    issues = _collect_issues(
        structure_report,
        security_report,
        scope_report,
        metadata_report,
        liveness_report,
    )

    # 12. Certificate -------------------------------------------------------
    certificate: Certificate = certifier.create_certificate(
        skill_name=parsed.name,
        skill_hash=skill_hash,
        mode=mode,
        overall_score=overall_score,
        verdict=verdict,
        structure_score=structure_report.score,
        liveness_score=liveness_report.score,
        security_score=security_report.score,
        scope_score=scope_report.score,
        metadata_score=metadata_report.score,
    )

    # 13. Context cost ------------------------------------------------------
    context_cost = _estimate_context_cost(skill_md, parsed, structure_report)

    # 14. Build response ----------------------------------------------------
    audit_id = f"audit_{secrets.token_hex(6)}"
    tested_at = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")

    response = AuditResponse(
        audit_id=audit_id,
        mode=mode,
        skill_name=parsed.name,
        skill_hash=skill_hash,
        overall_score=overall_score,
        verdict=verdict,
        cached=False,
        structure=structure_report,
        liveness=liveness_report,
        security=security_report,
        scope=scope_report,
        metadata=metadata_report,
        context_cost=context_cost,
        issues=issues,
        limitations=certificate.limitations,
        certificate_id=certificate.certificate_id,
        certificate=certificate,
        tested_at=tested_at,
    )

    # 15. Persist -----------------------------------------------------------
    if store:
        try:
            await store.save_audit(
                audit_id=audit_id,
                skill_hash=skill_hash,
                mode=mode,
                verdict=verdict,
                score=overall_score,
                result_json=response.model_dump(mode="json"),
                created_at=tested_at,
            )
            await store.save_certificate(
                cert_id=certificate.certificate_id,
                skill_hash=skill_hash,
                skill_name=certificate.skill_name,
                verdict=certificate.verdict,
                score=certificate.score,
                cert_json=certificate.model_dump(mode="json"),
                signature=certificate.signature,
                created_at=certificate.tested_at,
                valid_until=certificate.valid_until,
            )
        except Exception:  # noqa: BLE001 — persistence is best-effort
            logger.exception("Failed to persist audit results")

    # 16. Return ------------------------------------------------------------
    return response


# ---------------------------------------------------------------------------
# Context cost estimation
# ---------------------------------------------------------------------------


def _estimate_context_cost(
    raw_text: str,
    parsed: ParsedSkill,
    structure: StructureReport,
) -> ContextCost:
    """Estimate how many tokens this SKILL.md will consume and whether it's worth reading."""
    size_bytes = len(raw_text.encode("utf-8"))
    # Token heuristic: ASCII runs ~4 chars/token, but CJK/Cyrillic/emoji are
    # typically ~1 token per character (often more). A flat len//4 badly
    # undercounts non-Latin scripts, so weight non-ASCII characters at ~1 token.
    ascii_chars = sum(1 for ch in raw_text if ord(ch) < 128)
    non_ascii_chars = len(raw_text) - ascii_chars
    tokens = max(1, ascii_chars // 4 + non_ascii_chars)

    # "Useful content" signals: endpoints, examples, documented sections
    useful_signals = (
        len(parsed.endpoints) * 2
        + parsed.example_count * 3
        + (1 if structure.has_name else 0)
        + (1 if structure.has_description else 0)
        + (1 if structure.has_endpoints else 0)
        + (1 if structure.has_error_docs else 0)
        + (1 if structure.has_auth_docs else 0)
        + (1 if structure.has_workflow else 0)
    )
    density_ratio = useful_signals / max(1, tokens / 100)

    if density_ratio >= _TOKEN_HIGH_DENSITY_THRESHOLD:
        density = "high"
    elif density_ratio >= _TOKEN_LOW_DENSITY_THRESHOLD:
        density = "medium"
    else:
        density = "low"

    # Build recommendation
    parts: list[str] = []
    if tokens > _TOKENS_LARGE_SKILL:
        parts.append(
            f"This skill file is {tokens:,} tokens — larger than the ~1,500 token median. "
            "Loading it will consume a meaningful portion of your context window."
        )
    if density == "low":
        parts.append(
            "Information density is low: the file is large relative to its useful content "
            "(endpoints, examples, documentation sections). Consider whether you need it."
        )
    if density == "high" and tokens <= _TOKENS_LARGE_SKILL:
        parts.append(
            "Compact and well-structured. Low context-window cost."
        )
    if not parts:
        parts.append("Moderate size and density. Reasonable context-window cost.")

    # Per-model tokens + input cost (USD) + window share.  Reads the in-memory
    # price snapshot only — never touches the network (safe_static invariant).
    try:
        per_model, price_source = pricing.estimate_for_models(
            ascii_chars, non_ascii_chars
        )
    except Exception:  # noqa: BLE001 — pricing must never break an audit
        logger.exception("Per-model cost estimation failed; returning base estimate")
        per_model, price_source = [], None

    if per_model:
        max_cost = max(c.input_cost_usd for c in per_model)
        parts.append(
            f"Loading costs at most ${max_cost:.4f} (input) on tracked models."
        )

    return ContextCost(
        tokens_estimate=tokens,
        size_bytes=size_bytes,
        density=density,
        recommendation=" ".join(parts),
        per_model=per_model,
        error_margin_pct=pricing.ERROR_MARGIN_PCT,
        price_source=price_source,
    )


# ---------------------------------------------------------------------------
# Public API — remote SKILL.md fetching
# ---------------------------------------------------------------------------


async def fetch_skill_from_url(url: str) -> str:
    """Fetch a SKILL.md file from a remote URL via the SSRF-safe client.

    Args:
        url: The URL to retrieve (must survive SSRF validation).

    Returns:
        The raw text content of the SKILL.md file.

    Raises:
        ValueError: If the response is not text content, exceeds the
            size limit, or the request fails.
        SSRFBlockedError: If the URL targets a disallowed host/IP.
    """
    try:
        response = await safe_request("GET", url, timeout_override=_FETCH_TIMEOUT)
    except SSRFBlockedError:
        raise
    except Exception as exc:  # noqa: BLE001
        raise ValueError(f"Failed to fetch SKILL.md from {url}: {exc}") from exc

    content_type = response.headers.get("content-type", "")
    if not any(
        ct in content_type
        for ct in ("text/", "application/yaml", "application/json", "application/octet-stream")
    ) and content_type:
        raise ValueError(
            f"Unexpected content type from {url}: {content_type!r} "
            "(expected text, YAML, or JSON)"
        )

    if len(response.content) > _MAX_SKILL_BYTES:
        raise ValueError(
            f"SKILL.md from {url} is too large: {len(response.content)} bytes "
            f"(limit {_MAX_SKILL_BYTES})"
        )

    # octet-stream is allowed (many hosts serve .md as binary), but reject
    # actual binary payloads: a NUL byte means this is not a text SKILL.md.
    if b"\x00" in response.content:
        raise ValueError(
            f"Content from {url} appears to be binary, not a text SKILL.md"
        )

    return response.text
