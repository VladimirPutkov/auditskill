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
from auditskill.core.demo import run_demo
from auditskill.core.certifier import get_public_key, verify_certificate
from auditskill.core.discover import DENSITY_BONUS, discover
from auditskill.core.ssrf_guard import SSRFBlockedError
from auditskill.rules.quality_benchmarks import SCORING_WEIGHTS
from auditskill.rules.security_rules import get_all_rules

# Constants (match the plan limits)
MAX_SKILL_INPUT_BYTES = 200 * 1024  # 200 KB
MAX_ENDPOINTS = 15

logger = logging.getLogger(__name__)

router = APIRouter()


def _is_expired(valid_until: Any) -> bool:
    """Return True if *valid_until* (ISO-8601) is in the past. Unparseable → not expired."""
    if not isinstance(valid_until, str) or not valid_until:
        return False
    from datetime import datetime, timezone

    raw = valid_until[:-1] + "+00:00" if valid_until.endswith("Z") else valid_until
    try:
        dt = datetime.fromisoformat(raw)
    except ValueError:
        return False
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt < datetime.now(timezone.utc)


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

        # certificate_id is a harmless opaque label — safe to echo so the
        # caller can correlate the answer.  verdict/score are the trust-
        # bearing claims and are echoed ONLY when the signature is valid;
        # on any failure they are withheld (returning null) so a naive agent
        # can never read a tampered "PASS_BASIC_AUDIT / 99" back out of a
        # certificate that did not verify.
        cert_id = str(certificate.get("certificate_id", "") or "")

        raw_signature = certificate.get("signature", "")
        if not raw_signature:
            return VerifyResponse(
                valid=False,
                signature_valid=False,
                certificate_id=cert_id,
                verdict=None,
                score=None,
                error="Certificate has no 'signature' field — nothing to verify.",
            )

        # Pass the FULL certificate (signature included): verify_certificate
        # reads the signature out and canonicalises the rest itself.  Stripping
        # the signature here would make verification always fail.
        signature_valid = verify_certificate(certificate, public_key_b64)

        if not signature_valid:
            return VerifyResponse(
                valid=False,
                signature_valid=False,
                certificate_id=cert_id,
                verdict=None,
                score=None,
                error=(
                    "Signature verification failed — the certificate is not "
                    "authentic or has been modified since it was issued. Do not "
                    "trust its verdict or score."
                ),
            )

        # Signature authentic — now check expiry.  `valid` means "trust it":
        # authentic AND not past valid_until.  An expired-but-authentic cert is
        # signature_valid=True, expired=True, valid=False.
        valid_until = certificate.get("valid_until")
        expired = _is_expired(valid_until)
        raw_score = certificate.get("score")
        return VerifyResponse(
            valid=not expired,
            signature_valid=True,
            expired=expired,
            certificate_id=cert_id,
            verdict=str(certificate.get("verdict", "") or ""),
            score=raw_score if isinstance(raw_score, int) else None,
            valid_until=str(valid_until) if valid_until else None,
            error=(
                None
                if not expired
                else f"Certificate signature is authentic but expired at {valid_until}."
            ),
        )

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
# GET /health
# ---------------------------------------------------------------------------


@router.get(
    "/demo",
    summary="Run the end-to-end demonstration server-side",
    description=(
        "Runs the whole AuditSkill story in one call: scans the live registry "
        "(ranked), audits a built-in mock attack to show detection, and verifies "
        "the resulting certificate. Returns an interpreted, render-ready result. "
        "The mock attack lives on the server, so no malicious text is placed in "
        "the caller's context window."
    ),
)
@limiter.limit("5/minute")
async def demo(request: Request) -> dict[str, Any]:
    """Server-side Scenario-0 orchestration (one call for a vanilla agent)."""
    store = request.app.state.store
    try:
        return await run_demo(store)
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
            "POST /audit one file, or GET /discover to scan the whole registry "
            "ranked best-first. Deterministic, rule-based, no LLM, zero auth."
        ),
        "when_to_use": "Before loading any skill you did not write.",
        "when_not_to_use": (
            "It audits the SKILL.md document, not a running service or an "
            "agent's runtime actions. It is not an identity, payment, or "
            "reputation layer."
        ),
        "primary_endpoints": {
            "audit": "POST /audit",
            "discover": "GET /discover",
            "verify": "POST /verify",
            "benchmarks": "GET /benchmarks",
        },
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
        "and audits every matching entry inline. Returns the listing with a "
        "verdict, score, and risk level attached to each skill — so an agent "
        "only ever sees pre-vetted results."
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
        "discover_ranking": {
            "composite": "overall_score + density_bonus",
            "density_bonus": DENSITY_BONUS,
            "tie_break": ["overall_score desc", "critical_findings asc", "name asc"],
            "excluded": (
                "FAILS_BASIC_AUDIT entries are never ranked above passing "
                "entries; unaudited entries always rank last (with a reason)"
            ),
        },
        "context_cost_models": pricing.known_models(),
        "limits": {
            "max_skill_input_bytes": MAX_SKILL_INPUT_BYTES,
            "max_endpoints": MAX_ENDPOINTS,
        },
    }
