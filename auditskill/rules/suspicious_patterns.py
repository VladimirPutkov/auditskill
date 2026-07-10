"""Suspicious-pattern detectors for SKILL.md URLs and endpoint metadata.

Complements the regex-based :mod:`security_rules` with higher-level
heuristics that inspect URL hygiene and endpoint/description consistency.
"""

from __future__ import annotations

import re
from urllib.parse import urlparse

# ---------------------------------------------------------------------------
# Known-bad or abuse-prone TLDs
# ---------------------------------------------------------------------------

SUSPICIOUS_TLDS: set[str] = {
    ".tk",
    ".ml",
    ".ga",
    ".cf",
    ".gq",
    ".buzz",
    ".top",
    ".xyz",
    ".icu",
    ".club",
    ".work",
    ".click",
    ".link",
    ".surf",
}

# ---------------------------------------------------------------------------
# URL-level patterns
# ---------------------------------------------------------------------------

#: Matches URLs whose authority section is a bare IPv4 or IPv6 address.
IP_URL_PATTERN: re.Pattern[str] = re.compile(
    r"https?://"
    r"("
    r"\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}"  # IPv4
    r"|"
    r"\[[\da-fA-F:]+\]"  # IPv6 in brackets
    r")"
    r"(:\d+)?(/|$)",
    re.IGNORECASE,
)

#: Matches non-TLS ``http://`` URLs (plain-text transport).
NON_HTTPS_PATTERN: re.Pattern[str] = re.compile(
    r"\bhttp://[^\s\"'<>]+",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Method-mismatch patterns
# ---------------------------------------------------------------------------

#: Maps a description keyword to the set of HTTP methods that would
#: contradict that claim.  For example, a skill that describes itself as
#: "read-only" should not expose DELETE, PUT, or PATCH endpoints.
MISMATCH_PATTERNS: dict[str, dict[str, set[str] | str]] = {
    "read-only": {
        "methods": {"DELETE", "PUT", "PATCH", "POST"},
        "reason": ("Description claims read-only access but exposes write/mutating HTTP methods"),
    },
    "no auth": {
        "methods": set(),  # checked via header inspection instead
        "headers": "authorization",
        "reason": (
            "Description claims no authentication is required but "
            "examples include Authorization headers"
        ),
    },
    "safe": {
        "methods": {"DELETE", "PUT", "PATCH"},
        "reason": ("Description claims safe operations but exposes mutating HTTP methods"),
    },
    "idempotent": {
        "methods": {"POST"},
        "reason": (
            "Description claims idempotent behaviour but exposes non-idempotent POST endpoints"
        ),
    },
}

# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def check_url_suspicion(url: str) -> list[str]:
    """Analyse a single URL and return a list of reasons it is suspicious.

    Checks performed:
    1. Suspicious / abuse-prone TLD.
    2. URL uses a bare IP address instead of a hostname.
    3. URL uses plain ``http://`` (no TLS).

    Args:
        url: A URL string to inspect.

    Returns:
        A (possibly empty) list of human-readable reason strings.
    """
    reasons: list[str] = []

    # --- TLD check ---
    try:
        parsed = urlparse(url)
        hostname = parsed.hostname or ""
    except Exception:
        reasons.append("URL could not be parsed")
        return reasons

    # Extract TLD (last dot-separated segment, with the dot prefix).
    if "." in hostname:
        tld = "." + hostname.rsplit(".", maxsplit=1)[-1]
        if tld.lower() in SUSPICIOUS_TLDS:
            reasons.append(f"Uses suspicious/abuse-prone TLD '{tld}'")

    # --- Bare IP check ---
    if IP_URL_PATTERN.search(url):
        reasons.append("URL uses a bare IP address instead of a hostname")

    # --- Non-HTTPS check ---
    if NON_HTTPS_PATTERN.match(url):
        reasons.append("URL uses plain http:// (no TLS encryption)")

    return reasons


def check_method_mismatch(
    description: str,
    endpoints: list[dict[str, str]],
) -> list[str]:
    """Check for contradictions between a skill's description and its endpoints.

    Each endpoint dict is expected to have at least:
    - ``"method"``: HTTP method (GET, POST, PUT, PATCH, DELETE, …).

    Endpoint dicts *may* also contain:
    - ``"headers"``: A string of example headers (used for the ``no auth``
      check).

    Args:
        description: The skill's natural-language description, lowercased
            internally for matching.
        endpoints: A list of endpoint dicts.

    Returns:
        A (possibly empty) list of mismatch descriptions.
    """
    mismatches: list[str] = []
    desc_lower = description.lower()

    for keyword, spec in MISMATCH_PATTERNS.items():
        if keyword not in desc_lower:
            continue

        contradictory_methods: set[str] = spec.get("methods", set())  # type: ignore[assignment]
        header_keyword: str | None = spec.get("headers")  # type: ignore[assignment]
        reason: str = spec["reason"]  # type: ignore[assignment]

        # Method-level mismatch
        if contradictory_methods:
            for ep in endpoints:
                method = ep.get("method", "").upper()
                if method in contradictory_methods:
                    mismatches.append(
                        f"{reason} (found {method} on {ep.get('path', 'unknown endpoint')})"
                    )

        # Header-level mismatch (e.g. "no auth" + Authorization header)
        if header_keyword:
            for ep in endpoints:
                headers_str = ep.get("headers", "").lower()
                if header_keyword in headers_str:
                    mismatches.append(f"{reason} (found in {ep.get('path', 'unknown endpoint')})")

    return mismatches
