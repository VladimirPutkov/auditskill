"""Scope analyser for AuditSkill.

Examines a :class:`ParsedSkill` — the structured representation of a
SKILL.md file — and produces a :class:`ScopeReport` that scores the
skill on breadth, documentation completeness, and overall quality.

The analyser is pure (no network I/O, fully synchronous) and
deterministic for any given input.
"""

from __future__ import annotations

import re
from typing import Sequence

from auditskill.api.models import ParsedSkill, ScopeReport

# ------------------------------------------------------------------
# Keyword → domain mapping
# ------------------------------------------------------------------

DOMAIN_KEYWORDS: dict[str, list[str]] = {
    "weather": ["weather", "forecast", "temperature", "climate"],
    "finance": [
        "stock", "price", "trade", "payment", "invoice",
        "currency", "exchange",
    ],
    "health": ["health", "medical", "patient", "clinical", "diagnosis"],
    "social": [
        "social", "post", "tweet", "message", "chat", "notification",
    ],
    "search": ["search", "query", "find", "lookup", "discover"],
    "data": ["data", "database", "store", "crud", "record"],
    "auth": ["auth", "login", "register", "token", "session", "verify"],
    "media": ["image", "video", "audio", "file", "upload", "download"],
    "ai": [
        "ai", "model", "predict", "classify", "generate", "llm",
        "embedding",
    ],
    "infra": ["deploy", "monitor", "log", "metric", "health", "status"],
}

# Human-readable labels for documentation sections.
_SECTION_LABELS: dict[str, str] = {
    "has_error_docs": "error handling",
    "has_auth_docs": "authentication",
    "has_rate_limits": "rate limiting",
    "has_workflow": "workflow / usage guide",
    "has_side_effects_warning": "side-effects warning",
}

# Sections always checked regardless of endpoint types.
_ALWAYS_CHECKED_SECTIONS: Sequence[str] = (
    "has_error_docs",
    "has_auth_docs",
    "has_rate_limits",
    "has_workflow",
)

# Methods that trigger the side-effects warning requirement.
_STATE_CHANGING_METHODS: frozenset[str] = frozenset({"DELETE", "PUT", "POST", "PATCH"})

# Penalties per missing section type.
_REQUIRED_SECTION_PENALTY = 12
_RECOMMENDED_SECTION_PENALTY = 6

# Word-boundary pattern cache (lazy-initialised).
_WORD_PATTERNS: dict[str, re.Pattern[str]] = {}


def _word_pattern(keyword: str) -> re.Pattern[str]:
    """Return a compiled word-boundary regex for *keyword*, cached."""
    if keyword not in _WORD_PATTERNS:
        _WORD_PATTERNS[keyword] = re.compile(
            rf"\b{re.escape(keyword)}\b", re.IGNORECASE
        )
    return _WORD_PATTERNS[keyword]


# ------------------------------------------------------------------
# Internal helpers
# ------------------------------------------------------------------

def _detect_domains(parsed: ParsedSkill) -> list[str]:
    """Return a sorted, deduplicated list of detected domain names."""
    # Build a single text corpus from endpoint paths + description.
    parts: list[str] = []
    for ep in parsed.endpoints:
        parts.append(ep.path)
    if parsed.description:
        parts.append(parsed.description)
    corpus = " ".join(parts).lower()

    detected: set[str] = set()
    for domain, keywords in DOMAIN_KEYWORDS.items():
        for kw in keywords:
            if _word_pattern(kw).search(corpus):
                detected.add(domain)
                break  # one match per domain is enough
    return sorted(detected)


def _classify_breadth(domain_count: int) -> str:
    """Classify breadth as narrow / moderate / broad."""
    if domain_count <= 1:
        return "narrow"
    if domain_count <= 3:
        return "moderate"
    return "broad"


def _has_state_changing_endpoints(parsed: ParsedSkill) -> bool:
    """Return ``True`` if the skill declares any state-changing endpoints."""
    return any(
        ep.method.upper() in _STATE_CHANGING_METHODS for ep in parsed.endpoints
    )


def _find_missing_sections(parsed: ParsedSkill) -> list[str]:
    """Return human-readable names of missing documentation sections."""
    missing: list[str] = []
    for field in _ALWAYS_CHECKED_SECTIONS:
        if not getattr(parsed, field, False):
            missing.append(_SECTION_LABELS[field])

    # Side-effects warning only required when state-changing endpoints exist.
    if _has_state_changing_endpoints(parsed):
        if not getattr(parsed, "has_side_effects_warning", False):
            missing.append(_SECTION_LABELS["has_side_effects_warning"])

    return missing


def _generate_recommendations(
    parsed: ParsedSkill,
    domains: list[str],
    breadth: str,
    missing_sections: list[str],
) -> list[str]:
    """Generate actionable recommendations for the skill author."""
    recs: list[str] = []

    if breadth == "broad":
        domain_list = ", ".join(domains)
        recs.append(
            f"Skill covers {len(domains)} domains ({domain_list}) "
            "— consider splitting into focused skills"
        )

    for section in missing_sections:
        recs.append(f"Add {section} documentation")

    endpoint_count = len(parsed.endpoints)
    if endpoint_count > 10:
        recs.append(
            f"Consider splitting — {endpoint_count} endpoints may be "
            "hard for agents to navigate"
        )

    example_count = getattr(parsed, "example_count", 0) or 0
    if example_count == 0:
        recs.append(
            "Add usage examples — agents rely on examples to understand "
            "calling patterns"
        )

    return recs


def _calculate_score(
    missing_sections: list[str],
    breadth: str,
    parsed: ParsedSkill,
) -> int:
    """Compute a 0-100 quality score.

    Penalties
    ---------
    * Each missing *required* section (error handling, auth, rate
      limiting, workflow): ``-12``
    * Each missing *recommended* section (side-effects warning):
      ``-6``
    * Breadth == ``"broad"``: ``-10``
    """
    required_labels = {_SECTION_LABELS[f] for f in _ALWAYS_CHECKED_SECTIONS}

    score = 100.0
    for section in missing_sections:
        if section in required_labels:
            score -= _REQUIRED_SECTION_PENALTY
        else:
            score -= _RECOMMENDED_SECTION_PENALTY

    if breadth == "broad":
        score -= 10.0

    return int(round(max(0.0, min(100.0, score))))


# ------------------------------------------------------------------
# Public API
# ------------------------------------------------------------------

def analyze_scope(parsed: ParsedSkill) -> ScopeReport:
    """Analyse a parsed SKILL.md for breadth, specificity, and completeness.

    Parameters
    ----------
    parsed:
        The structured representation of a SKILL.md produced by the
        parser module.

    Returns
    -------
    ScopeReport
        Detailed breakdown including detected domains, breadth
        classification, missing sections, recommendations, and an
        aggregate score (0-100).
    """
    domains = _detect_domains(parsed)
    breadth = _classify_breadth(len(domains))
    missing = _find_missing_sections(parsed)
    recommendations = _generate_recommendations(parsed, domains, breadth, missing)
    score = _calculate_score(missing, breadth, parsed)

    findings: list[str] = []
    if breadth == "broad":
        findings.append(
            f"Skill spans {len(domains)} domains ({', '.join(domains)}) — very broad scope"
        )
    for section in missing:
        findings.append(f"Missing recommended section: {section}")

    return ScopeReport(
        score=score,
        domains_detected=domains,
        breadth=breadth,
        endpoint_count=len(parsed.endpoints),
        example_count=getattr(parsed, "example_count", 0) or 0,
        missing_sections=missing,
        recommendations=recommendations,
        findings=findings,
    )
