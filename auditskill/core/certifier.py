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
import hashlib
import json
from datetime import datetime, timedelta, timezone
from typing import Any

from auditskill import __version__
from auditskill.api.models import Certificate
from auditskill.core.crypto import derive_public_key, sign_document, verify_signature
from auditskill.rules.security_rules import get_all_rules

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Module-level configuration (from environment)
# ---------------------------------------------------------------------------

PRIVATE_KEY: str = os.environ.get("AUDITSKILL_PRIVATE_KEY", "")
PUBLIC_KEY_ID: str = os.environ.get("AUDITSKILL_KEY_ID", "auditskill-2026-07")
CERT_VALIDITY_DAYS: int = 7
CERTIFICATE_SCHEMA_VERSION: str = "1"
RULESET_VERSION: str = "2026-07-10"


def _calculate_ruleset_hash() -> str:
    """Return a stable digest of the security policy carried by a certificate."""
    policy = [
        {
            "rule_id": rule.rule_id,
            "category": rule.category,
            "severity": rule.severity,
            "pattern": rule.pattern,
            "is_code_block_safe": rule.is_code_block_safe,
        }
        for rule in get_all_rules()
    ]
    encoded = json.dumps(policy, sort_keys=True, separators=(",", ":")).encode("utf-8")
    return f"sha256:{hashlib.sha256(encoded).hexdigest()}"


RULESET_HASH: str = _calculate_ruleset_hash()


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
        "schema_version": CERTIFICATE_SCHEMA_VERSION,
        "service_version": __version__,
        "ruleset_version": RULESET_VERSION,
        "ruleset_hash": RULESET_HASH,
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


def verify_certificate_status(certificate: dict[str, Any], public_key_b64: str) -> dict[str, Any]:
    """Verify signature, expiry, and the minimum certificate schema.

    Trust-bearing verdict and score fields are returned only while the
    certificate is both authentic and current.
    """
    cert_id = str(certificate.get("certificate_id", "") or "")
    signature_valid = verify_certificate(certificate, public_key_b64)
    if not signature_valid:
        return {
            "valid": False,
            "signature_valid": False,
            "expired": None,
            "certificate_id": cert_id,
            "verdict": None,
            "score": None,
            "valid_until": None,
            "ruleset_version": None,
            "ruleset_hash": None,
            "error": (
                "Signature verification failed - the certificate is not authentic "
                "or has been modified. Do not trust its verdict or score."
            ),
        }

    required_version_fields = (
        "schema_version",
        "service_version",
        "ruleset_version",
        "ruleset_hash",
    )
    missing_versions = [
        field
        for field in required_version_fields
        if not isinstance(certificate.get(field), str) or not certificate.get(field)
    ]
    if missing_versions:
        return {
            "valid": False,
            "signature_valid": True,
            "expired": None,
            "certificate_id": cert_id,
            "verdict": None,
            "score": None,
            "valid_until": None,
            "ruleset_version": None,
            "ruleset_hash": None,
            "error": (
                "Certificate signature is authentic but required version fields "
                f"are missing: {', '.join(missing_versions)}."
            ),
        }

    valid_until = certificate.get("valid_until")
    if not isinstance(valid_until, str) or not valid_until:
        return {
            "valid": False,
            "signature_valid": True,
            "expired": None,
            "certificate_id": cert_id,
            "verdict": None,
            "score": None,
            "valid_until": None,
            "ruleset_version": str(certificate.get("ruleset_version") or "") or None,
            "ruleset_hash": str(certificate.get("ruleset_hash") or "") or None,
            "error": "Certificate signature is authentic but valid_until is missing.",
        }

    raw_expiry = valid_until[:-1] + "+00:00" if valid_until.endswith("Z") else valid_until
    try:
        expiry = datetime.fromisoformat(raw_expiry)
    except ValueError:
        return {
            "valid": False,
            "signature_valid": True,
            "expired": None,
            "certificate_id": cert_id,
            "verdict": None,
            "score": None,
            "valid_until": valid_until,
            "ruleset_version": str(certificate.get("ruleset_version") or "") or None,
            "ruleset_hash": str(certificate.get("ruleset_hash") or "") or None,
            "error": "Certificate signature is authentic but valid_until is not valid ISO-8601.",
        }
    if expiry.tzinfo is None:
        expiry = expiry.replace(tzinfo=timezone.utc)
    expired = expiry <= datetime.now(timezone.utc)
    raw_score = certificate.get("score")
    return {
        "valid": not expired,
        "signature_valid": True,
        "expired": expired,
        "certificate_id": cert_id,
        "verdict": None if expired else str(certificate.get("verdict", "") or ""),
        "score": None if expired or not isinstance(raw_score, int) else raw_score,
        "valid_until": valid_until,
        "ruleset_version": str(certificate.get("ruleset_version") or "") or None,
        "ruleset_hash": str(certificate.get("ruleset_hash") or "") or None,
        "error": (
            f"Certificate signature is authentic but expired at {valid_until}." if expired else None
        ),
    }
