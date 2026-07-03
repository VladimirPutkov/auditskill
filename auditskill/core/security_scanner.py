"""Rule-based security scanner for SKILL.md content.

Scans raw SKILL.md text for security risks using pattern matching with
context awareness.  Patterns found inside fenced code blocks in
documentation sections are optionally excluded to prevent false positives
on security-related skills that *describe* attack patterns.

Each finding includes a precise line number, the triggering rule metadata,
and a human-readable detail message.  The scanner also analyses embedded
URLs for suspicious characteristics and cross-references declared
endpoints against the skill description to detect method mismatches.

The final output is a :class:`SecurityReport` containing all findings,
a 0–100 risk score, and a categorical risk level.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from auditskill.api.models import SecurityFinding, SecurityReport
from auditskill.rules.security_rules import get_all_rules
from auditskill.rules.suspicious_patterns import (
    check_method_mismatch,
    check_url_suspicion,
)

if TYPE_CHECKING:
    from auditskill.rules.security_rules import SecurityRule

# ---------------------------------------------------------------------------
# URL extraction pattern – intentionally broad to catch http, https, and
# bare IPs that could appear in SKILL.md content.
# ---------------------------------------------------------------------------
_URL_RE = re.compile(
    r"https?://[^\s\)\]\}\>\"\'\`\,]+",
    re.IGNORECASE,
)

# Severity → score-penalty mapping.
_SEVERITY_PENALTIES: dict[str, int] = {
    "critical": 30,
    "high": 15,
    "medium": 5,
    "low": 2,
}

# Inline `code` span matcher (single-backtick spans on one line).
_INLINE_CODE_RE = re.compile(r"`[^`]*`")

# Headings that mark *descriptive* prose — a section where a skill (often a
# legitimate security tool) merely lists or discusses attack patterns rather
# than instructing them.  Matches are keyed off heading text substrings.
_DESCRIPTIVE_HEADING_KEYWORDS: tuple[str, ...] = (
    "limitation",
    "pattern",
    "detection",
    "transparency",
    "disclaimer",
    "caveat",
    "false positive",
    "example",
    "known",
    "what this does not",
    "what it does not",
)

# Only these categories are suppressed inside descriptive sections.  Prompt
# injection, data exfiltration, and hidden-instruction rules are NEVER
# suppressed by section context — hiding those in a "Limitations" section is
# itself suspicious.  agent_capture is included only for its prose-level
# rule (SEC-030, mandatory-gating language): a doc that *discusses* gating
# patterns under "Limitations"/"Examples" is not itself capturing the agent.
# The supply-chain and proxy/daemon rules are code-block-unsafe and are
# never suppressed.
_DESCRIPTIVE_SKIP_CATEGORIES: frozenset[str] = frozenset(
    {"unsafe_operations", "scope_creep", "agent_capture"}
)

_HEADING_RE = re.compile(r"^\s{0,3}#{1,6}\s+(.*)")


def _strip_inline_code(line: str) -> str:
    """Blank out inline `code` spans so documented patterns don't false-fire."""
    return _INLINE_CODE_RE.sub(" ", line)


def _identify_descriptive_sections(lines: list[str]) -> set[int]:
    """Return 0-based indices of lines under a descriptive heading.

    A descriptive section runs from a heading whose text contains one of
    :data:`_DESCRIPTIVE_HEADING_KEYWORDS` until the next heading of the same
    or higher level (any subsequent ``#`` heading, conservatively).
    """
    descriptive: set[int] = set()
    active = False
    for idx, line in enumerate(lines):
        m = _HEADING_RE.match(line)
        if m:
            heading = m.group(1).strip().lower()
            active = any(kw in heading for kw in _DESCRIPTIVE_HEADING_KEYWORDS)
            continue
        if active:
            descriptive.add(idx)
    return descriptive

# Suspicion-reason → finding severity mapping (matched by keyword).
def _url_severity(reason: str) -> str:
    """Map a human-readable URL suspicion reason to a severity level."""
    r = reason.lower()
    if "bare ip" in r or "ip address" in r:
        return "medium"
    if "tls" in r or "http://" in r or "non-https" in r or "no tls" in r:
        return "low"
    if "tld" in r or "abuse" in r:
        return "medium"
    if "private" in r or "internal" in r or "metadata" in r:
        return "critical"
    return "medium"


# ---- public API -----------------------------------------------------------


def scan(
    raw_text: str,
    endpoints: list[dict[str, str]] | None = None,
    description: str | None = None,
) -> SecurityReport:
    """Scan *raw_text* for security issues and return a :class:`SecurityReport`.

    Args:
        raw_text: Full text of a ``SKILL.md`` file.
        endpoints: Optional list of endpoint dicts (used for mismatch
            detection).  Each dict is expected to carry at least ``method``
            and ``path`` keys.
        description: Optional human-readable description of the skill,
            used together with *endpoints* for mismatch detection.

    Returns:
        A fully populated :class:`SecurityReport`.
    """
    lines = raw_text.splitlines()
    code_block_lines = _identify_code_blocks(lines)
    descriptive_lines = _identify_descriptive_sections(lines)
    rules = get_all_rules()

    findings: list[SecurityFinding] = []
    rules_triggered: set[str] = set()

    # --- 1. Rule-based pattern scan ----------------------------------------
    for rule in rules:
        compiled = re.compile(rule.pattern, re.IGNORECASE)
        for idx, line in enumerate(lines):
            if rule.is_code_block_safe:
                # Code-block-safe rules describe patterns that legitimately
                # appear in *documentation*.  We therefore ignore matches that:
                #   (a) sit inside a fenced ``` code block, or
                #   (b) sit inside an inline `code` span, or
                #   (c) (for pattern-describing categories) sit under a
                #       descriptive heading like "Limitations" / "Detection
                #       Patterns" / "Examples" / "Transparency".
                if idx in code_block_lines:
                    continue
                if (
                    rule.category in _DESCRIPTIVE_SKIP_CATEGORIES
                    and idx in descriptive_lines
                ):
                    continue
                scan_line = _strip_inline_code(line)
            else:
                # Hidden-instruction rules (zero-width, bidi, homoglyph, HTML
                # comments) are dangerous regardless of context — scan raw.
                scan_line = line

            if compiled.search(scan_line):
                rules_triggered.add(rule.rule_id)
                findings.append(
                    SecurityFinding(
                        rule_id=rule.rule_id,
                        severity=rule.severity,
                        category=rule.category,
                        detail=f"{rule.description} (matched on line {idx + 1})",
                        line=idx + 1,
                    )
                )

    # --- 2. URL suspicion analysis -----------------------------------------
    for idx, line in enumerate(lines):
        for url_match in _URL_RE.finditer(line):
            url = url_match.group(0)
            reasons = check_url_suspicion(url)
            for reason in reasons:
                severity = _url_severity(reason)
                findings.append(
                    SecurityFinding(
                        rule_id=f"URL_{reason.upper().replace(' ', '_')}",
                        severity=severity,
                        category="suspicious_url",
                        detail=f"Suspicious URL ({reason}): {url} (line {idx + 1})",
                        line=idx + 1,
                    )
                )

    # --- 3. Method-mismatch detection --------------------------------------
    if endpoints is not None and description is not None:
        # check_method_mismatch expects list[dict] with "method" and "path" keys
        ep_dicts = [
            {"method": ep.method, "path": ep.path}
            if hasattr(ep, "method") else ep
            for ep in endpoints
        ]
        mismatches = check_method_mismatch(description, ep_dicts)
        for mismatch in mismatches:
            findings.append(
                SecurityFinding(
                    rule_id="METHOD_MISMATCH",
                    severity="medium",
                    category="method_mismatch",
                    detail=mismatch.get(
                        "detail",
                        "Endpoint method does not match description claims",
                    ),
                    line=0,
                )
            )

    # --- 4. Scoring --------------------------------------------------------
    score = _calculate_score(findings)
    risk_level = _score_to_risk_level(score)

    return SecurityReport(
        findings=findings,
        score=score,
        risk_level=risk_level,
        rules_checked=len(rules),
        rules_triggered=len(rules_triggered),
    )


# ---- helpers --------------------------------------------------------------


def _identify_code_blocks(lines: list[str]) -> set[int]:
    """Return set of 0-based line indices that are inside fenced code blocks.

    A fenced code block starts with a line whose *stripped* content begins
    with three or more back-ticks (````` ``` `````) and ends with another
    such line.  The opening and closing fence lines themselves are **not**
    included in the returned set — only the content lines between them.
    """
    inside: bool = False
    fence_pattern = re.compile(r"^`{3,}")
    code_lines: set[int] = set()

    for idx, line in enumerate(lines):
        stripped = line.strip()
        if fence_pattern.match(stripped):
            if inside:
                # Closing fence — stop tracking.
                inside = False
            else:
                # Opening fence — start tracking from next line.
                inside = True
            continue

        if inside:
            code_lines.add(idx)

    return code_lines


def _calculate_score(findings: list[SecurityFinding]) -> int:
    """Compute a 0–100 security score from a list of findings.

    Starts at 100 and deducts points per finding based on its severity.
    The result is clamped to the [0, 100] range.
    """
    score = 100
    for finding in findings:
        penalty = _SEVERITY_PENALTIES.get(finding.severity, 0)
        score -= penalty
    return max(0, min(100, score))


def _score_to_risk_level(score: int) -> str:
    """Map a numeric score to a categorical risk level string.

    Returns:
        One of ``'none'``, ``'low'``, ``'medium'``, ``'high'``, or
        ``'critical'``.
    """
    if score >= 90:
        return "none"
    if score >= 75:
        return "low"
    if score >= 60:
        return "medium"
    if score >= 40:
        return "high"
    return "critical"
