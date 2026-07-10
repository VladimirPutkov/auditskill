"""Score aggregation, verdict determination, and Ed25519 certificate issuance.

Collects per-module audit scores, delegates overall-score calculation and
verdict logic to :mod:`auditskill.rules.quality_benchmarks`, then builds an
Ed25519-signed ``Certificate`` that attests to the audit results.

Certificates are short-lived (``CERT_VALIDITY_DAYS``, default 7) and carry
explicit ``limitations`` so consumers understand what the audit does *not*
guarantee.

Cherry-picked and adapted from AgentGate (MIT).
"""

from __future__ import annotations

import logging
import os
import secrets
from datetime import datetime, timedelta, timezone
from typing import Any

from auditskill.api.models import Certificate
from auditskill.core.crypto import derive_public_key, sign_document, verify_signature

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level configuration (from environment)
# ---------------------------------------------------------------------------

PRIVATE_KEY: str = os.environ.get("AUDITSKILL_PRIVATE_KEY", "")
PUBLIC_KEY_ID: str = os.environ.get("AUDITSKILL_KEY_ID", "auditskill-2026-07")
CERT_VALIDITY_DAYS: int = 7


def get_public_key() -> str:
    """Return the active verification (public) key, base64-encoded.

    When a signing key is configured, the public key is **derived from it**
    — a single source of truth, so the published key can never mismatch the
    key certificates are actually signed with (two independently-pasted env
    vars drifted apart in production once; this removes that failure class).
    Falls back to ``AUDITSKILL_PUBLIC_KEY`` for verify-only deployments.
    """
    if PRIVATE_KEY:
        try:
            return derive_public_key(PRIVATE_KEY)
        except Exception:
            logger.exception(
                "Could not derive public key from AUDITSKILL_PRIVATE_KEY; "
                "falling back to AUDITSKILL_PUBLIC_KEY"
            )
    return os.environ.get("AUDITSKILL_PUBLIC_KEY", "")


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

_CHECK_PASS_THRESHOLD = 80
_CHECK_WARN_THRESHOLD = 50


def _score_to_status(score: int | None) -> str:
    """Map a module score to a human-readable check status.

    Returns:
        ``'pass'`` for scores ≥ 80, ``'warning'`` for ≥ 50,
        ``'fail'`` for < 50, or ``'not_tested'`` for ``None``.
    """
    if score is None:
        return "not_tested"
    if score >= _CHECK_PASS_THRESHOLD:
        return "pass"
    if score >= _CHECK_WARN_THRESHOLD:
        return "warning"
    return "fail"


def _build_limitations(mode: str) -> list[str]:
    """Assemble the list of attestation limitations for the given audit mode."""
    limitations: list[str] = [
        "Rule-based audit only - does not guarantee semantic correctness",
        "Does not guarantee future availability of endpoints",
    ]
    if mode == "safe_static":
        limitations.append("Endpoints were not tested - liveness unknown")
    if mode == "liveness":
        limitations.append("State-changing endpoints (POST/PUT/DELETE) were not executed")
    return limitations


# ---------------------------------------------------------------------------
# Public API — certificate creation
# ---------------------------------------------------------------------------


def create_certificate(
    skill_name: str | None,
    skill_hash: str,
    mode: str,
    overall_score: int,
    verdict: str,
    structure_score: int,
    liveness_score: int | None,
    security_score: int,
    scope_score: int,
    metadata_score: int,
) -> Certificate:
    """Create a signed audit certificate for a SKILL.md file.

    Args:
        skill_name: Human-readable skill name (may be ``None``).
        skill_hash: ``sha256:<hex>`` content hash of the raw SKILL.md text.
        mode: Audit mode (``'safe_static'`` or ``'liveness'``).
        overall_score: Aggregated score in [0, 100].
        verdict: One of the four audit verdicts (``PASS_BASIC_AUDIT``,
            ``PASS_WITH_WARNINGS``, ``REQUIRES_HUMAN_REVIEW``,
            ``FAILS_BASIC_AUDIT``).
        structure_score: Score from the structure analysis module.
        liveness_score: Score from endpoint testing (``None`` if not tested).
        security_score: Score from the security scanner module.
        scope_score: Score from the scope analysis module.
        metadata_score: Score from the metadata checker module.

    Returns:
        A :class:`Certificate` Pydantic model containing all attestation
        fields and an Ed25519 signature (or an ``unsigned:…`` marker when
        no private key is configured).
    """
    now = datetime.now(timezone.utc)
    certificate_id = f"seal_{secrets.token_hex(6)}"
    tested_at = now.isoformat().replace("+00:00", "Z")
    valid_until = (now + timedelta(days=CERT_VALIDITY_DAYS)).isoformat().replace("+00:00", "Z")

    checks: dict[str, str] = {
        "structure": _score_to_status(structure_score),
        "liveness": _score_to_status(liveness_score),
        "security": _score_to_status(security_score),
        "scope": _score_to_status(scope_score),
        "metadata": _score_to_status(metadata_score),
    }

    limitations = _build_limitations(mode)

    # Build the certificate payload *without* the signature so we can
    # sign the canonical JSON representation.
    cert_dict: dict[str, Any] = {
        "certificate_id": certificate_id,
        "skill_name": skill_name,
        "skill_hash": skill_hash,
        "mode": mode,
        "score": overall_score,
        "verdict": verdict,
        "tested_at": tested_at,
        "valid_until": valid_until,
        "public_key_id": PUBLIC_KEY_ID,
        "checks": checks,
        "limitations": limitations,
    }

    # Sign with Ed25519 — or mark as unsigned.
    if PRIVATE_KEY:
        try:
            sig = sign_document(cert_dict, PRIVATE_KEY)
            signature = f"ed25519:{sig}"
        except Exception:
            logger.exception("Ed25519 signing failed; issuing unsigned certificate")
            signature = "unsigned:signing_error"
    else:
        signature = "unsigned:no_key_configured"

    cert_dict["signature"] = signature

    return Certificate(**cert_dict)


# ---------------------------------------------------------------------------
# Public API — certificate verification
# ---------------------------------------------------------------------------


def verify_certificate(certificate: dict[str, Any], public_key_b64: str) -> bool:
    """Verify the Ed25519 signature on a certificate dict.

    The ``signature`` field is expected to have the form ``ed25519:<b64sig>``.
    The field is stripped before canonical-JSON verification.

    Args:
        certificate: Certificate payload as a plain dict.
        public_key_b64: Base64-encoded Ed25519 public (verify) key.

    Returns:
        ``True`` if the signature is valid, ``False`` otherwise.
    """
    sig_raw = certificate.get("signature", "")
    if not isinstance(sig_raw, str) or not sig_raw.startswith("ed25519:"):
        logger.warning("Certificate signature is not ed25519-prefixed: %s", sig_raw)
        return False

    signature_b64 = sig_raw.removeprefix("ed25519:")
    return verify_signature(certificate, signature_b64, public_key_b64)
