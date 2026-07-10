"""Quality benchmarks — scoring weights, penalties, and verdict logic.

Provides deterministic helpers for computing per-module and overall
audit scores and mapping those scores to one of four verdict levels.
"""

from __future__ import annotations

from typing import Any

# ---------------------------------------------------------------------------
# Scoring weights (must sum to 1.0)
# ---------------------------------------------------------------------------

SCORING_WEIGHTS: dict[str, float] = {
    "structure": 0.30,
    "security": 0.30,
    "liveness": 0.25,
    "metadata": 0.10,
    "scope": 0.05,
}

# ---------------------------------------------------------------------------
# Structure scoring — required & recommended sections
# ---------------------------------------------------------------------------

#: Each tuple is ``(field_name, penalty_if_missing)``.
REQUIRED_SECTIONS: list[tuple[str, int]] = [
    ("has_name", 15),
    ("has_description", 15),
    ("has_base_url", 15),
    ("has_endpoints", 15),
]

RECOMMENDED_SECTIONS: list[tuple[str, int]] = [
    ("has_examples", 8),
    ("has_error_docs", 8),
    ("has_auth_docs", 8),
    ("has_rate_limits", 8),
    ("has_workflow", 8),
    ("has_side_effects_warning", 8),
]

# ---------------------------------------------------------------------------
# Liveness penalties
# ---------------------------------------------------------------------------

LIVENESS_PENALTIES: dict[str, int] = {
    "dead_endpoint_base": 15,
    "high_latency": 5,  # >2 s response time
    "no_tls": 10,
}

# ---------------------------------------------------------------------------
# Security penalties (applied to the security sub-score per finding)
# ---------------------------------------------------------------------------

SECURITY_PENALTIES: dict[str, int] = {
    "medium": -5,
    "high": -15,
    "critical": -30,
}

# ---------------------------------------------------------------------------
# Verdict levels (highest precedence first)
# ---------------------------------------------------------------------------

VERDICT_FAILS: str = "FAILS_BASIC_AUDIT"
VERDICT_HUMAN_REVIEW: str = "REQUIRES_HUMAN_REVIEW"
VERDICT_WARNINGS: str = "PASS_WITH_WARNINGS"
VERDICT_PASS: str = "PASS_BASIC_AUDIT"

# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def calculate_structure_score(parsed: Any) -> int:
    """Compute a structure sub-score (0–100) for a parsed SKILL.md.

    The score starts at 100 and is decremented by the penalty for each
    required or recommended section that is missing (the corresponding
    boolean flag in *parsed* is falsy).

    Args:
        parsed: A dict or Pydantic model with boolean keys/attributes
            matching the ``field_name`` values in
            :data:`REQUIRED_SECTIONS` and :data:`RECOMMENDED_SECTIONS`.

    Returns:
        An integer score clamped to ``[0, 100]``.
    """

    def _get(obj: object, key: str) -> bool:
        """Get a boolean field from a dict or Pydantic model."""
        try:
            return bool(getattr(obj, key))
        except AttributeError:
            if isinstance(obj, dict):
                return bool(obj.get(key))
            return False

    score = 100

    for field_name, penalty in REQUIRED_SECTIONS:
        if not _get(parsed, field_name):
            score -= penalty

    for field_name, penalty in RECOMMENDED_SECTIONS:
        if not _get(parsed, field_name):
            score -= penalty

    return max(0, min(100, score))


def calculate_overall_score(
    module_scores: dict[str, float | None],
) -> int:
    """Compute a weighted overall audit score from per-module sub-scores.

    Modules whose score is ``None`` (e.g. liveness was skipped) are
    excluded and the weights of the remaining modules are **renormalised**
    to sum to 1.0 so the final score is still on a 0–100 scale.

    Args:
        module_scores: Mapping of module name (``structure``,
            ``security``, ``liveness``, ``metadata``, ``scope``) to the
            module's 0–100 score, or ``None`` if that module was not run.

    Returns:
        An integer score clamped to ``[0, 100]``.

    Raises:
        ValueError: If no modules have a non-``None`` score.
    """
    weighted_sum = 0.0
    weight_sum = 0.0

    for module, weight in SCORING_WEIGHTS.items():
        score = module_scores.get(module)
        if score is not None:
            weighted_sum += score * weight
            weight_sum += weight

    if weight_sum == 0.0:
        raise ValueError("Cannot compute overall score — all module scores are None")

    normalised = weighted_sum / weight_sum
    return max(0, min(100, round(normalised)))


def determine_verdict(score: int, findings: list[dict[str, Any]]) -> str:
    """Map a final score and finding list to a human-readable verdict.

    Verdict precedence (highest first):

    1. **FAILS_BASIC_AUDIT** — any *critical* finding, or score < 40.
    2. **REQUIRES_HUMAN_REVIEW** — any *high* finding, or score < 70.
    3. **PASS_WITH_WARNINGS** — score < 85, or any *medium* finding.
    4. **PASS_BASIC_AUDIT** — everything else.

    Args:
        score: The overall 0–100 audit score.
        findings: A list of finding dicts, each expected to have a
            ``"severity"`` key (``"critical"``, ``"high"``, ``"medium"``,
            or ``"low"``).

    Returns:
        One of the four ``VERDICT_*`` constants defined in this module.
    """
    severities = {f.get("severity", "").lower() for f in findings}

    # --- Level 1: automatic failure ---
    if "critical" in severities or score < 40:
        return VERDICT_FAILS

    # --- Level 2: needs human review ---
    if "high" in severities or score < 70:
        return VERDICT_HUMAN_REVIEW

    # --- Level 3: pass with warnings ---
    if score < 85 or "medium" in severities:
        return VERDICT_WARNINGS

    # --- Level 4: clean pass ---
    return VERDICT_PASS
