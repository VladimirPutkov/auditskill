"""Lightweight metadata and provenance checker for SKILL.md files.

Inspects raw skill text for author attribution, contact information,
repository URLs (with optional reachability check via SSRF-safe HTTP),
license declarations, and HTTPS base URL usage.

Scoring is deliberately lenient: a skill with zero discoverable metadata
still receives a baseline score of 50 so that closed-source or minimal
skills are not unfairly penalised.  Metadata is weighted low overall
(0.10) and can never single-handedly fail a skill.
"""

from __future__ import annotations

import logging
import re

from auditskill.api.models import MetadataReport, ParsedSkill
from auditskill.core.ssrf_guard import SSRFBlockedError, safe_request

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Regex patterns
# ---------------------------------------------------------------------------

# Author attribution: "author: Jane Doe", "built by Acme Corp", etc.
_AUTHOR_RE = re.compile(
    r"(?:author|created\s+by|maintained\s+by|built\s+by|team|developed\s+by)"
    r"\s*[:=\-]?\s*\S+",
    re.IGNORECASE,
)

# Contact info: email address or URL after a contact-related keyword.
_EMAIL_RE = re.compile(r"[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z]{2,}")
_CONTACT_KEYWORD_RE = re.compile(
    r"(?:contact|support|email|help)\s*[:=\-]?\s*(\S+)",
    re.IGNORECASE,
)
_URL_RE = re.compile(r"https?://[^\s)>\]\"']+")

# Repository URLs on major hosting platforms.
_REPO_RE = re.compile(
    r"https?://(?:github\.com|gitlab\.com|bitbucket\.org)/[^\s)>\]\"']+",
    re.IGNORECASE,
)

# Common open-source license identifiers.
_LICENSE_RE = re.compile(
    r"\b(?:MIT|Apache|GPL|BSD|ISC|MPL|LGPL)\b",
    re.IGNORECASE,
)

# ---------------------------------------------------------------------------
# Scoring weights
# ---------------------------------------------------------------------------

_WEIGHT_AUTHOR = 20
_WEIGHT_CONTACT = 10
_WEIGHT_REPO_PRESENT = 15  # repo URL is declared
_WEIGHT_REPO_REACHABLE = 15  # repo URL responded (liveness mode only)
_WEIGHT_LICENSE = 20
_WEIGHT_HTTPS = 20
_BASELINE_SCORE = 50  # awarded when *nothing* is found


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _detect_author(text: str) -> bool:
    """Return ``True`` if the text contains an author attribution pattern."""
    return bool(_AUTHOR_RE.search(text))


def _detect_contact(text: str) -> bool:
    """Return ``True`` if an email or URL appears near a contact keyword."""
    if _EMAIL_RE.search(text):
        return True
    match = _CONTACT_KEYWORD_RE.search(text)
    if match and _URL_RE.match(match.group(1)):
        return True
    return False


def _find_repo_url(text: str) -> str | None:
    """Return the first GitHub/GitLab/Bitbucket URL found, or ``None``."""
    match = _REPO_RE.search(text)
    return match.group(0) if match else None


def _detect_license(text: str) -> str | None:
    """Return the matched open-source license identifier, or ``None``."""
    match = _LICENSE_RE.search(text)
    return match.group(0).upper() if match else None


async def _check_repo_reachable(url: str) -> bool:
    """HEAD-request the repo URL via the SSRF guard; return reachability."""
    try:
        response = await safe_request("HEAD", url)
        return 200 <= response.status_code < 400
    except (SSRFBlockedError, Exception) as exc:  # noqa: BLE001
        logger.debug("Repo reachability check failed for %s: %s", url, exc)
        return False


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


async def check_metadata(
    parsed: ParsedSkill,
    check_reachability: bool = False,
) -> MetadataReport:
    """Run all metadata/provenance checks and return a scored report.

    Args:
        parsed: A previously-parsed SKILL.md representation.
        check_reachability: When ``True`` (liveness mode), HEAD-probe the
            repo URL via the SSRF guard.  In ``safe_static`` mode this is
            skipped and ``repo_reachable`` is left ``None`` (no network I/O).

    Returns:
        A :class:`MetadataReport` with boolean flags, the discovered
        repo URL (if any), and an integer score in [0, 100].
    """
    text = parsed.raw_text

    has_author = _detect_author(text)
    has_contact = _detect_contact(text)
    repo_url = _find_repo_url(text)
    has_repo_url = repo_url is not None
    license_detected = _detect_license(text)
    base_url_https = (
        parsed.base_url.startswith("https://") if parsed.base_url else False
    )

    # Reachability is only probed in liveness mode.
    repo_reachable: bool | None = None
    if repo_url and check_reachability:
        repo_reachable = await _check_repo_reachable(repo_url)

    # --- Scoring ---
    any_signal_found = any(
        [has_author, has_contact, has_repo_url, license_detected, base_url_https]
    )

    if not any_signal_found:
        # Give a neutral baseline so closed-source skills aren't punished.
        score = _BASELINE_SCORE
    else:
        score = 0
        if has_author:
            score += _WEIGHT_AUTHOR
        if has_contact:
            score += _WEIGHT_CONTACT
        if has_repo_url:
            score += _WEIGHT_REPO_PRESENT
            if repo_reachable:
                score += _WEIGHT_REPO_REACHABLE
        if license_detected:
            score += _WEIGHT_LICENSE
        if base_url_https:
            score += _WEIGHT_HTTPS
        score = min(100, score)

    findings: list[str] = []
    if not has_author:
        findings.append("No author attribution found")
    if not has_contact:
        findings.append("No contact information found")
    if not has_repo_url:
        findings.append("No repository URL found")
    elif repo_reachable is False:
        findings.append(f"Repository URL not reachable: {repo_url}")
    if not license_detected:
        findings.append("No open-source license identifier detected")
    if not base_url_https:
        findings.append("Base URL does not use HTTPS")

    return MetadataReport(
        has_author=has_author,
        has_contact=has_contact,
        has_repo_url=has_repo_url,
        repo_url=repo_url,
        repo_reachable=repo_reachable,
        license_detected=license_detected,
        base_url_https=base_url_https,
        score=score,
        findings=findings,
    )
