"""API route handlers for AuditSkill.

Endpoints
---------
POST /audit          – Run a SKILL.md audit (accepts raw text or a URL).
POST /verify         – Verify a certificate's Ed25519 signature.
GET  /certificate/{cert_id} – Retrieve a stored certificate by ID.
GET  /certificates   – List certificates for a given skill hash.
GET  /.well-known/auditskill-keys – Public key discovery (JWKS-style).
GET  /health         – Liveness probe.
GET  /benchmarks     – Expose scoring weights, thresholds, and limits.
"""

from __future__ import annotations

import logging
import os
from typing import Any

from pathlib import Path

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse, PlainTextResponse

from auditskill.api.rate_limiter import limiter
from auditskill.api.models import (
    AuditRequest,
    AuditResponse,
    ErrorResponse,
    HealthResponse,
    KeyInfo,
    KeysResponse,
    VerifyRequest,
    VerifyResponse,
)
from auditskill.core import pricing
from auditskill.core.auditor import fetch_skill_from_url, run_audit
from auditskill.core.demo import render_demo_report, run_demo
from auditskill.core.certifier import (
    CERT_VALIDITY_DAYS,
    RULESET_HASH,
    RULESET_VERSION,
    get_public_key,
    verify_certificate_status,
)
from auditskill.core.discover import DENSITY_BONUS, discover
from auditskill.core.ssrf_guard import SSRFBlockedError
from auditskill.rules.quality_benchmarks import SCORING_WEIGHTS
from auditskill.rules.security_rules import get_all_rules

# Constants (match the plan limits)
MAX_SKILL_INPUT_BYTES = 200 * 1024  # 200 KB
MAX_ENDPOINTS = 15

logger = logging.getLogger(__name__)

router = APIRouter()


# ---------------------------------------------------------------------------
# POST /audit
# ---------------------------------------------------------------------------


@router.post(
    "/audit",
    response_model=AuditResponse,
    responses={422: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    summary="Audit a SKILL.md",
    description="Submit a SKILL.md for auditing. Provide either raw `skill_md` text or a `skill_url` to fetch.",
)
@limiter.limit("10/minute")
async def audit_skill(request: Request, body: AuditRequest) -> AuditResponse:
    """Run structural, security, and liveness checks on a SKILL.md file."""
    return await _execute_audit(request, body)


@router.get(
    "/audit",
    response_model=AuditResponse,
    responses={422: {"model": ErrorResponse}, 500: {"model": ErrorResponse}},
    summary="Audit a SKILL.md by URL (GET fallback)",
    description=(
        "URL-based audit for agents that can only issue GET requests. "
        "Same pipeline and response shape as POST /audit; raw `skill_md` "
        "text still requires POST (too large for a query string)."
    ),
)
@limiter.limit("10/minute")
async def audit_skill_get(
    request: Request,
    skill_url: str = Query(..., description="HTTPS URL of the SKILL.md to audit."),
    mode: str = Query(default="safe_static", description="'safe_static' or 'liveness'."),
    model: str | None = Query(default=None, description="Optional model ID to narrow costs."),
) -> AuditResponse:
    """GET fallback for URL-based audits (egress-restricted agents)."""
    try:
        body = AuditRequest(skill_url=skill_url, mode=mode, model=model)  # type: ignore[arg-type]
    except Exception as exc:  # pydantic ValidationError → self-healing 422
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    return await _execute_audit(request, body)


async def _execute_audit(request: Request, body: AuditRequest) -> AuditResponse:
    """Shared audit implementation behind both /audit routes.

    Kept outside the rate-limited handlers so the GET fallback does not
    burn two rate-limit slots per call by invoking the decorated POST
    handler.
    """
    store = request.app.state.store

    try:
        # Validate the optional model narrowing up front (cheap, self-healing).
        if body.model is not None and body.model not in pricing.known_models():
            raise HTTPException(
                status_code=422,
                detail=(
                    f"Unknown model '{body.model}'. Tracked models: "
                    f"{', '.join(pricing.known_models())}. "
                    "Fix: omit 'model' to get every tracked model, or pick one "
                    "from the list."
                ),
            )

        # Resolve the SKILL.md content ----------------------------------
        skill_md = body.skill_md
        if body.skill_url and not skill_md:
            skill_md = await fetch_skill_from_url(str(body.skill_url))

        if not skill_md:
            raise HTTPException(
                status_code=422,
                detail="Either 'skill_md' or 'skill_url' must be provided.",
            )

        # Execute the audit pipeline -----------------------------------
        result = await run_audit(skill_md, body.mode, store)

        # Narrow per-model costs AFTER the (cached) audit so the cache key
        # stays model-independent and every cache hit serves every model.
        if body.model is not None and result.context_cost.per_model:
            result.context_cost.per_model = [
                c for c in result.context_cost.per_model if c.model == body.model
            ]
        return result

    except HTTPException:
        raise
    except SSRFBlockedError as exc:
        # A blocked target URL is a bad *request*, not a server fault.
        logger.warning("Audit blocked by SSRF guard: %s", exc)
        raise HTTPException(
            status_code=422,
            detail=f"skill_url was blocked by the SSRF guard: {exc.reason}",
        ) from exc
    except ValueError as exc:
        logger.warning("Audit validation error: %s", exc)
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Unexpected error during audit")
        raise HTTPException(
            status_code=500,
            detail=f"Internal audit error: {exc}",
        ) from exc


# ---------------------------------------------------------------------------
# POST /verify
# ---------------------------------------------------------------------------


@router.post(
    "/verify",
    response_model=VerifyResponse,
    summary="Verify a certificate signature",
    description="Submit a full certificate JSON to verify its Ed25519 signature.",
)
@limiter.limit("60/minute")
async def verify_cert(request: Request, body: VerifyRequest) -> VerifyResponse:
    """Verify the Ed25519 signature embedded in a certificate."""
    try:
        public_key_b64 = get_public_key()
        if not public_key_b64:
            raise HTTPException(
                status_code=500,
                detail=(
                    "Server signing key is not configured "
                    "(AUDITSKILL_PRIVATE_KEY or AUDITSKILL_PUBLIC_KEY)."
                ),
            )

        certificate: dict[str, Any] = body.certificate

        raw_signature = certificate.get("signature", "")
        if not raw_signature:
            return VerifyResponse(
                valid=False,
                signature_valid=False,
                certificate_id=str(certificate.get("certificate_id", "") or ""),
                verdict=None,
                score=None,
                error="Certificate has no 'signature' field — nothing to verify.",
            )
        return VerifyResponse(**verify_certificate_status(certificate, public_key_b64))

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Error during certificate verification")
        raise HTTPException(
            status_code=500,
            detail=f"Verification error: {exc}",
        ) from exc


# ---------------------------------------------------------------------------
# GET /certificate/{cert_id}
# ---------------------------------------------------------------------------


@router.get(
    "/certificate/{cert_id}",
    summary="Retrieve a certificate by ID",
    description="Fetch a previously issued audit certificate by its unique identifier.",
)
@limiter.limit("60/minute")
async def get_certificate(request: Request, cert_id: str) -> JSONResponse:
    """Look up and return a stored certificate."""
    store = request.app.state.store

    try:
        record = await store.get_certificate(cert_id)
        if record is None:
            raise HTTPException(status_code=404, detail=f"Certificate '{cert_id}' not found.")
        # Return the signed certificate object — not the store wrapper —
        # so the response can be fed directly into POST /verify.
        cert_payload = record.get("certificate_json", record)
        return JSONResponse(content=cert_payload)

    except HTTPException:
        raise
    except Exception as exc:
        logger.exception("Error retrieving certificate %s", cert_id)
        raise HTTPException(
            status_code=500,
            detail=f"Error retrieving certificate: {exc}",
        ) from exc


# ---------------------------------------------------------------------------
# GET /certificates
# ---------------------------------------------------------------------------


@router.get(
    "/certificates",
    summary="List certificates by skill hash",
    description="Return all certificates associated with the given SKILL.md content hash.",
)
@limiter.limit("30/minute")
async def list_certificates(
    request: Request,
    skill_hash: str = Query(..., description="SHA-256 hash of the SKILL.md content (sha256:hex)."),
) -> JSONResponse:
    """Return every certificate for a particular skill content hash."""
    store = request.app.state.store

    try:
        records = await store.get_certificates_by_hash(skill_hash)
        # Unwrap store rows → signed certificate objects (verify-compatible).
        certs = [r.get("certificate_json", r) for r in records]
        return JSONResponse(content=certs)

    except Exception as exc:
        logger.exception("Error listing certificates for hash %s", skill_hash)
        raise HTTPException(
            status_code=500,
            detail=f"Error listing certificates: {exc}",
        ) from exc


# ---------------------------------------------------------------------------
# GET /.well-known/auditskill-keys
# ---------------------------------------------------------------------------


@router.get(
    "/.well-known/auditskill-keys",
    response_model=KeysResponse,
    summary="Public key discovery",
    description="Returns the server's Ed25519 public key for certificate verification.",
)
async def well_known_keys() -> KeysResponse:
    """Publish the auditor's public key so agents can verify certificates offline."""
    public_key_b64 = get_public_key()
    if not public_key_b64:
        raise HTTPException(
            status_code=500,
            detail=(
                "Server signing key is not configured "
                "(AUDITSKILL_PRIVATE_KEY or AUDITSKILL_PUBLIC_KEY)."
            ),
        )

    key_id = os.environ.get("AUDITSKILL_KEY_ID", "auditskill-2026-07")
    created_at = os.environ.get("AUDITSKILL_KEY_CREATED", "2026-07-01")

    return KeysResponse(
        keys=[
            KeyInfo(
                key_id=key_id,
                algorithm="ed25519",
                public_key=public_key_b64,
                created_at=created_at,
            )
        ],
    )


# ---------------------------------------------------------------------------
# GET /  and  GET /skill.md
# ---------------------------------------------------------------------------

# Repo root (two levels above auditskill/api/); SKILL.md ships in the image.
_SKILL_MD_PATH = Path(__file__).resolve().parents[2] / "SKILL.md"


@router.get(
    "/",
    summary="Service index",
    description="Minimal JSON pointer so the root URL is never a dead end.",
)
async def index() -> dict[str, Any]:
    """Point agents and humans at the machine manifest and the skill file."""
    return {
        "service": "AuditSkill",
        "skill_md": "/skill.md",
        "about": "/about",
        "benchmarks": "/benchmarks",
        "health": "/health",
        "docs": "/docs",
    }


@router.get(
    "/skill.md",
    summary="Serve this service's own SKILL.md",
    description=(
        "The canonical SKILL.md for AuditSkill, served from the deployed "
        "code itself — so the registry entry and the running service can "
        "never drift apart."
    ),
)
async def skill_md() -> PlainTextResponse:
    """Serve the SKILL.md file that ships with the deployed service."""
    try:
        text = _SKILL_MD_PATH.read_text(encoding="utf-8")
    except OSError as exc:
        logger.exception("SKILL.md not found at %s", _SKILL_MD_PATH)
        raise HTTPException(
            status_code=500, detail="SKILL.md is not available on this deployment."
        ) from exc
    return PlainTextResponse(text, media_type="text/markdown; charset=utf-8")


# ---------------------------------------------------------------------------
# GET /demo
# ---------------------------------------------------------------------------


@router.get(
    "/demo",
    response_model=None,
    summary="Run the end-to-end demonstration server-side",
    description=(
        "One request runs three service operations: a sampled /discover pipeline "
        "over the live registry, an /audit pipeline over a server-side synthetic "
        "fixture, and a /verify pipeline over the resulting certificate. The "
        "response is structured for direct reporting and never returns the fixture text."
    ),
)
@limiter.limit("5/minute")
async def demo(
    request: Request,
    format: str = Query(
        default="json",
        pattern="^(json|report)$",
        description="json for structured data; report for final plain text",
    ),
) -> dict[str, Any] | PlainTextResponse:
    """One-call demonstration for a vanilla agent."""
    store = request.app.state.store
    try:
        result = await run_demo(store)
        if format == "report":
            return PlainTextResponse(render_demo_report(result))
        return result
    except Exception as exc:  # noqa: BLE001
        logger.exception("Error running demo")
        raise HTTPException(status_code=500, detail=f"Demo error: {exc}") from exc


@router.get(
    "/health",
    response_model=HealthResponse,
    summary="Health check",
    description="Liveness probe — returns 200 if the service is running.",
)
async def health() -> HealthResponse:
    """Return a simple health status."""
    return HealthResponse(status="ok", version="1.0.0")


# ---------------------------------------------------------------------------
# GET /about
# ---------------------------------------------------------------------------


@router.get(
    "/about",
    summary="Machine-readable self-description",
    description=(
        "A compact manifest an agent can read to understand what AuditSkill "
        "does, who it is for, the two problems it solves, and when to use it "
        "— without loading the full SKILL.md."
    ),
)
async def about() -> dict[str, Any]:
    """Return an agent-facing description of the service and its purpose."""
    return {
        "service": "AuditSkill",
        "version": "1.0.0",
        "purpose": (
            "Audit a third-party SKILL.md before it enters an agent's context "
            "window: is it safe to load, and is it worth the tokens?"
        ),
        "for_whom": (
            "Autonomous AI agents that discover and load skills at runtime and "
            "cannot pause to ask a human to vet each one. A human can inspect a "
            "skill by hand; an autonomous agent needs a machine it can call."
        ),
        "problems_solved": [
            "Safety — a SKILL.md is instructions by design, so a malicious one "
            "can inject, exfiltrate, or hijack the moment it is read. AuditSkill "
            "checks it first, deterministically, without executing anything.",
            "Context cost — every loaded SKILL.md spends tokens from the window. "
            "AuditSkill estimates the token, dollar, and context-window cost so "
            "the agent can decide whether loading it is worth the budget.",
        ],
        "how": (
            "POST /audit checks one file; GET /discover returns a bounded, "
            "ranked registry sample; GET /demo?format=report demonstrates the "
            "workflow. Deterministic, rule-based, no LLM, zero auth."
        ),
        "when_to_use": "Before loading any skill you did not write.",
        "when_not_to_use": (
            "It audits the SKILL.md document, not a running service or an "
            "agent's runtime actions. It is not an identity, payment, or "
            "reputation layer."
        ),
        "primary_endpoints": {
            "demonstrate": "GET /demo?format=report",
            "audit": "POST /audit",
            "discover": "GET /discover",
            "verify": "POST /verify",
            "rules": "GET /rules",
            "benchmarks": "GET /benchmarks",
        },
        "question_routing": {
            "exact_rule_ids_and_descriptions": "GET /rules",
            "raw_detection_patterns": "GET /rules?include_patterns=true",
            "scoring_thresholds_modes_pricing_and_certificates": "GET /benchmarks",
            "purpose_limits_data_handling_and_rate_limits": "GET /about",
            "complete_request_and_response_schemas": "GET /openapi.json",
            "current_service_status": "GET /health",
            "public_verification_key": "GET /.well-known/auditskill-keys",
        },
        "data_handling": {
            "raw_skill_document_persisted": False,
            "stored": (
                "Audit result, content hash, parsed findings, and signed certificate "
                "metadata are stored for cache and certificate retrieval."
            ),
            "automatic_retention_deletion": False,
            "user_accounts": False,
        },
        "rate_limits_per_ip": {
            "POST /audit": "10/minute",
            "GET /audit": "10/minute",
            "GET /demo": "5/minute",
            "GET /discover": "5/minute",
            "POST /verify": "60/minute",
            "GET /certificate/{id}": "60/minute",
            "GET /certificates": "30/minute",
            "public_metadata_endpoints": "unlimited",
        },
        "limitations": [
            "A pass means no catalogued pattern was found, not proof of safety.",
            "The document is audited; the running service behind it is not.",
            "Static mode does not establish endpoint availability.",
            "Token and cost values are heuristic estimates from a dated snapshot.",
        ],
        "self_contained": (
            "All scoring, security rules, and price data ship inside the "
            "service — no dependency on any third-party skill or external feed."
        ),
        "source": "https://github.com/VladimirPutkov/auditskill",
    }


# ---------------------------------------------------------------------------
# GET /discover
# ---------------------------------------------------------------------------


@router.get(
    "/discover",
    summary="Safe discovery — audit the live registry",
    description=(
        "Fetches the NANDA Town skill registry (or any NANDA-style registry) "
        "and audits a bounded matching sample inline. Audited entries carry a "
        "verdict, score, and risk level; unavailable entries are marked, and "
        "suspicious registry metadata is withheld."
    ),
)
@limiter.limit("5/minute")
async def discover_skills(
    request: Request,
    q: str = Query(
        default="",
        description="Filter skills by name/description/tags (case-insensitive substring).",
    ),
    mode: str = Query(
        default="safe_static",
        description="'safe_static' (fast) or 'liveness' (also probes endpoints).",
    ),
    limit: int = Query(default=20, ge=1, le=30, description="Max entries to audit (capped at 30)."),
    registry_url: str = Query(
        default="https://nandatown.projectnanda.org/api/skills",
        description="Registry URL to scan (must be https).",
    ),
) -> dict[str, Any]:
    """Proxy the live NANDA Town registry with inline audit verdicts."""
    store = request.app.state.store
    try:
        result = await discover(q=q, mode=mode, limit=limit, registry_url=registry_url, store=store)
        return result.model_dump(mode="json")
    except SSRFBlockedError as exc:
        # A blocked registry URL is a bad *request*, not a server fault.
        logger.warning("Discovery blocked by SSRF guard: %s", exc)
        raise HTTPException(
            status_code=422,
            detail=f"registry_url was blocked by the SSRF guard: {exc.reason}",
        ) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except Exception as exc:
        logger.exception("Error during discovery")
        raise HTTPException(
            status_code=500,
            detail=f"Discovery error: {exc}",
        ) from exc


# ---------------------------------------------------------------------------
# GET /rules
# ---------------------------------------------------------------------------


@router.get(
    "/rules",
    summary="Security rule catalog",
    description=(
        "Return every security rule with its stable SEC identifier, category, "
        "severity, and human-readable detection purpose. Filter by rule, category, "
        "or severity; request raw regex patterns only when needed."
    ),
)
async def rules_catalog(
    rule_id: str | None = Query(
        default=None,
        description="Exact stable identifier, for example SEC-001.",
    ),
    category: str | None = Query(
        default=None,
        description="Exact category, for example prompt_injection.",
    ),
    severity: str | None = Query(
        default=None,
        pattern="^(critical|high|medium|low)$",
    ),
    include_patterns: bool = Query(
        default=False,
        description="Include the raw case-insensitive regex for each returned rule.",
    ),
) -> dict[str, Any]:
    """Expose the complete versioned detection policy to autonomous agents."""
    all_rules = sorted(get_all_rules(), key=lambda rule: rule.rule_id)
    normalized_id = rule_id.upper() if rule_id else None
    normalized_category = category.lower() if category else None
    selected = [
        rule
        for rule in all_rules
        if (normalized_id is None or rule.rule_id == normalized_id)
        and (normalized_category is None or rule.category == normalized_category)
        and (severity is None or rule.severity == severity)
    ]
    if rule_id and not selected:
        raise HTTPException(
            status_code=404,
            detail=f"Unknown rule_id '{rule_id}'. Use GET /rules to list all rule IDs.",
        )

    rules: list[dict[str, Any]] = []
    for rule in selected:
        item: dict[str, Any] = {
            "rule_id": rule.rule_id,
            "category": rule.category,
            "severity": rule.severity,
            "description": rule.description,
            "code_context_sensitive": rule.is_code_block_safe,
        }
        if include_patterns:
            item["pattern"] = rule.pattern
            item["pattern_flags"] = ["IGNORECASE"]
        rules.append(item)

    categories = sorted({rule.category for rule in all_rules})
    return {
        "ruleset_version": RULESET_VERSION,
        "ruleset_hash": RULESET_HASH,
        "total_rules_in_ruleset": len(all_rules),
        "returned": len(rules),
        "available_categories": categories,
        "filters": {
            "rule_id": normalized_id,
            "category": normalized_category,
            "severity": severity,
            "include_patterns": include_patterns,
        },
        "context_policy": (
            "Operational matches use the declared severity. Documentation or code "
            "context may lower confidence from critical/high to medium, but a heading "
            "or code fence never suppresses a raw match."
        ),
        "rules": rules,
    }


# ---------------------------------------------------------------------------
# GET /benchmarks
# ---------------------------------------------------------------------------


@router.get(
    "/benchmarks",
    summary="Scoring benchmarks",
    description=(
        "Return the scoring weights, verdict thresholds, security rule "
        "categories, and operational limits used by the auditor."
    ),
)
async def benchmarks() -> dict[str, Any]:
    """Expose auditing parameters so clients can anticipate scoring behaviour."""
    # Build a summary of security categories with rule counts
    all_rules = get_all_rules()
    categories: dict[str, int] = {}
    for rule in all_rules:
        categories[rule.category] = categories.get(rule.category, 0) + 1

    verdict_thresholds = {
        "PASS_BASIC_AUDIT": "score >= 85 and no medium/high/critical findings",
        "PASS_WITH_WARNINGS": "score >= 70 and no high/critical findings",
        "REQUIRES_HUMAN_REVIEW": "score >= 40 and no critical findings (or any high finding)",
        "FAILS_BASIC_AUDIT": "score < 40 or any critical finding",
    }

    return {
        "scoring_weights": SCORING_WEIGHTS,
        "verdict_thresholds": verdict_thresholds,
        "security_categories": categories,
        "total_rules": len(all_rules),
        "rule_catalog": {
            "all_rules": "GET /rules",
            "filter_examples": [
                "GET /rules?rule_id=SEC-001",
                "GET /rules?category=prompt_injection",
                "GET /rules?severity=critical",
                "GET /rules?include_patterns=true",
            ],
            "ruleset_version": RULESET_VERSION,
            "ruleset_hash": RULESET_HASH,
        },
        "audit_modes": {
            "safe_static": ("Parse and scan the document without probing its declared endpoints."),
            "liveness": (
                "Run the same static audit, then bounded GET/HEAD availability probes; "
                "never send POST, PUT, PATCH, or DELETE."
            ),
        },
        "discover_ranking": {
            "primary": (
                "verdict tier: PASS_BASIC_AUDIT, PASS_WITH_WARNINGS, "
                "REQUIRES_HUMAN_REVIEW, FAILS_BASIC_AUDIT, unaudited"
            ),
            "within_tier_composite": "overall_score + density_bonus",
            "density_bonus": DENSITY_BONUS,
            "tie_break": [
                "within-tier composite desc",
                "overall_score desc",
                "critical_findings asc",
                "name asc",
            ],
            "automatic_recommendation": "PASS_BASIC_AUDIT only",
        },
        "context_density": {
            "signal_caps": {"endpoints": 10, "examples": 3},
            "high": ">= 8 signals/1k tokens and <= 3000 tokens",
            "medium": ">= 4 signals/1k tokens and <= 6000 tokens",
            "low": "everything else",
        },
        "context_cost_models": pricing.known_models(),
        "model_pricing": [
            {
                "model": price.model,
                "family": price.family,
                "input_usd_per_million_tokens": round(price.input_per_1k_usd * 1000, 6),
                "context_window_tokens": price.context_window_k * 1000,
            }
            for price in sorted(pricing.price_cache.prices.values(), key=lambda item: item.model)
        ],
        "price_snapshot": {
            "source": pricing.price_cache.source,
            "error_margin_pct": pricing.ERROR_MARGIN_PCT,
        },
        "certificate_policy": {
            "signature_algorithm": "Ed25519",
            "validity_days": CERT_VALIDITY_DAYS,
            "trust_condition": (
                "Trust verdict and score only when signature_valid=true, "
                "expired=false, and valid=true."
            ),
            "public_key_endpoint": "GET /.well-known/auditskill-keys",
            "online_verification_endpoint": "POST /verify",
            "schema_fields": [
                "schema_version",
                "service_version",
                "ruleset_version",
                "ruleset_hash",
            ],
        },
        "limits": {
            "max_skill_input_bytes": MAX_SKILL_INPUT_BYTES,
            "max_endpoints": MAX_ENDPOINTS,
        },
    }
