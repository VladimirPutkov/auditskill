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

from fastapi import APIRouter, HTTPException, Query, Request
from fastapi.responses import JSONResponse

from auditskill.api.rate_limiter import limiter
from auditskill.api.models import (
    AuditRequest,
    AuditResponse,
    ErrorResponse,
    HealthResponse,
    KeysResponse,
    VerifyRequest,
    VerifyResponse,
)
from auditskill.core.auditor import fetch_skill_from_url, run_audit
from auditskill.core.certifier import verify_certificate
from auditskill.core.discover import discover
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
    store = request.app.state.store

    try:
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
        public_key_b64 = os.environ.get("AUDITSKILL_PUBLIC_KEY", "")
        if not public_key_b64:
            raise HTTPException(
                status_code=500,
                detail="Server public key is not configured (AUDITSKILL_PUBLIC_KEY).",
            )

        certificate: dict[str, Any] = body.certificate

        # Extract and clean the signature value -------------------------
        raw_signature = certificate.get("signature", "")
        if not raw_signature:
            return VerifyResponse(
                valid=False,
                certificate_id=certificate.get("certificate_id", ""),
                verdict=certificate.get("verdict", ""),
                score=certificate.get("score"),
            )

        # Pass the FULL certificate (signature included): verify_certificate
        # reads the signature out and canonicalises the rest itself.  Stripping
        # the signature here would make verification always fail.
        valid = verify_certificate(certificate, public_key_b64)

        return VerifyResponse(
            valid=valid,
            certificate_id=certificate.get("certificate_id", ""),
            verdict=certificate.get("verdict", ""),
            score=certificate.get("score"),
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
        certificate = await store.get_certificate(cert_id)
        if certificate is None:
            raise HTTPException(status_code=404, detail=f"Certificate '{cert_id}' not found.")
        return JSONResponse(content=certificate)

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
        certificates = await store.get_certificates_by_hash(skill_hash)
        return JSONResponse(content=certificates)

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
    public_key_b64 = os.environ.get("AUDITSKILL_PUBLIC_KEY", "")
    if not public_key_b64:
        raise HTTPException(
            status_code=500,
            detail="Server public key is not configured (AUDITSKILL_PUBLIC_KEY).",
        )

    key_id = os.environ.get("AUDITSKILL_KEY_ID", "auditskill-2026-07")
    created_at = os.environ.get("AUDITSKILL_KEY_CREATED", "2026-07-01")

    return KeysResponse(
        keys=[
            {
                "key_id": key_id,
                "algorithm": "ed25519",
                "public_key": public_key_b64,
                "created_at": created_at,
            }
        ],
    )


# ---------------------------------------------------------------------------
# GET /health
# ---------------------------------------------------------------------------

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
    q: str = Query(default="", description="Filter skills by name/description/tags (case-insensitive substring)."),
    mode: str = Query(default="safe_static", description="'safe_static' (fast) or 'liveness' (also probes endpoints)."),
    limit: int = Query(default=20, ge=1, le=30, description="Max entries to audit (capped at 30)."),
    registry_url: str = Query(
        default="https://nandatown.projectnanda.org/api/skills",
        description="Registry URL to scan (must be https).",
    ),
) -> dict[str, Any]:
    """Proxy the live NANDA Town registry with inline audit verdicts."""
    store = request.app.state.store
    try:
        result = await discover(
            q=q, mode=mode, limit=limit, registry_url=registry_url, store=store
        )
        return result.model_dump(mode="json")
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
        "limits": {
            "max_skill_input_bytes": MAX_SKILL_INPUT_BYTES,
            "max_endpoints": MAX_ENDPOINTS,
        },
    }
