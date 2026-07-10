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

import base64
import binascii
import re
from typing import Any, Literal
from urllib.parse import urlparse

from auditskill.api.models import SecurityFinding, SecurityReport
from auditskill.rules.security_rules import get_all_rules
from auditskill.rules.suspicious_patterns import (
    check_method_mismatch,
    check_url_suspicion,
)

# ---------------------------------------------------------------------------
# URL extraction pattern – intentionally broad to catch http, https, and
# bare IPs that could appear in SKILL.md content.
# ---------------------------------------------------------------------------
_URL_RE = re.compile(
    r"https?://[^\s\)\]\}\>\"\'\`\,]+",
    re.IGNORECASE,
)

# "METHOD https://host/path" — an *executable* endpoint declaration with an
# absolute URL.  Used for the domain-consistency check: declared endpoints
# must live on the declared Base URL host.  Prose links (Author, repo, docs)
# never match because they carry no HTTP-method prefix.
_ENDPOINT_ABS_URL_RE = re.compile(
    r"\b(?:GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS)\s+(https?://[^\s\"'`>\)\]]+)",
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

# ---------------------------------------------------------------------------
# Evasion-normalisation (zero-width stripping + homoglyph folding)
# ---------------------------------------------------------------------------
# Attackers hide injections by (a) splicing zero-width characters into words
# ("ig<ZWSP>nore all previous instructions") or (b) swapping Latin letters for
# visually identical Cyrillic/Greek ones ("ignоre" with a Cyrillic 'о').  The
# raw-text detectors SEC-016/017/020 still flag the *presence* of these tricks,
# but the injection itself would slip past the prose rules.  We therefore run
# the prose rules against a normalised copy of each line as well.

_ZERO_WIDTH_RE = re.compile(r"[​‌‍﻿⁠⁢⁣⁤]")

# Common Cyrillic/Greek homoglyphs → their Latin lookalike.
_CONFUSABLES: dict[str, str] = {
    # Cyrillic lowercase
    "а": "a",
    "е": "e",
    "о": "o",
    "р": "p",
    "с": "c",
    "х": "x",
    "у": "y",
    "і": "i",
    "ј": "j",
    "ѕ": "s",
    "к": "k",
    "м": "m",
    "т": "t",
    "н": "h",
    "в": "b",
    "г": "r",
    "п": "n",
    # Cyrillic uppercase
    "А": "A",
    "Е": "E",
    "О": "O",
    "Р": "P",
    "С": "C",
    "Х": "X",
    "У": "Y",
    "К": "K",
    "М": "M",
    "Т": "T",
    "Н": "H",
    "В": "B",
    # Greek
    "ο": "o",
    "α": "a",
    "ε": "e",
    "ρ": "p",
    "υ": "u",
    "Ο": "O",
    "Α": "A",
    "Ε": "E",
}
_CONFUSABLE_TABLE = {ord(k): v for k, v in _CONFUSABLES.items()}


def _normalize_for_matching(text: str) -> str:
    """Strip zero-width chars and fold homoglyphs for evasion-resistant matching.

    Used only for *matching* — findings still report the original line number
    and the raw detectors continue to flag the obfuscation itself.
    """
    return _ZERO_WIDTH_RE.sub("", text).translate(_CONFUSABLE_TABLE)


# ---------------------------------------------------------------------------
# Base64-smuggled-instruction detection
# ---------------------------------------------------------------------------
# SEC-018 flags *long* Base64 blobs (>100 chars).  Short encoded injections
# (e.g. a 44-char blob decoding to "ignore all previous instructions") slip
# under that bar, so we additionally decode candidate tokens and re-scan the
# plaintext.  This fires only when the decoded content is itself malicious —
# so legitimate short Base64 (hashes, IDs) never false-fires.

_BASE64_TOKEN_RE = re.compile(r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{16,}={0,2}(?![A-Za-z0-9+/=])")
_DECODED_INJECTION_RE = re.compile(
    r"(ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts)"
    r"|system\s+prompt"
    r"|exfiltrate"
    r"|send\s+[^\n]{0,30}(token|secret|credential|env)"
    r"|forget\s+(everything|all))",
    re.IGNORECASE,
)


def _decode_base64_injection(line: str) -> str | None:
    """Return the decoded text if *line* hides an injection in Base64, else None."""
    for match in _BASE64_TOKEN_RE.finditer(line):
        token = match.group(0)
        # Base64 length must be a multiple of 4 (with padding) to decode cleanly.
        padded = token + "=" * ((4 - len(token) % 4) % 4)
        try:
            decoded_bytes = base64.b64decode(padded, validate=True)
            decoded = decoded_bytes.decode("utf-8", errors="strict")
        except (binascii.Error, ValueError, UnicodeDecodeError):
            continue
        if _DECODED_INJECTION_RE.search(decoded):
            return decoded.strip()
    return None


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
    "known",
    "what this does not",
    "what it does not",
)
# NOTE: broad, natural-sounding headings like "How to use", "Overview",
# "Problem", and "Examples"/"Usage examples" were deliberately removed — they
# let an attacker suppress a real payload simply by titling the section that
# way.  Suppression now requires an overtly *security-documentation* heading
# (Detection Patterns, Limitations, Transparency, Disclaimer, Known, False
# positives, …) — incongruous for a skill posing as an ordinary service, and
# the same heading a legitimate security tool uses to catalogue what it detects.

# Only these categories may be suppressed under a descriptive heading — a
# legitimate security tool genuinely catalogues destructive commands, broad
# scopes, capture tricks, and payment patterns under "Detection Patterns" etc.
# prompt_injection and data_exfiltration are NEVER suppressed by heading: an
# actual "ignore all previous instructions" / "send tokens to <url>" line is
# an attack wherever it sits, and AuditSkill's own docs no longer embed one
# (the demo fixture lives server-side, see core/demo.py).
_DESCRIPTIVE_SKIP_CATEGORIES: frozenset[str] = frozenset(
    {
        "unsafe_operations",
        "scope_creep",
        "agent_capture",
        "payment_safety",
    }
)

_HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.*)")

# Whole-word/phrase matcher for descriptive headings.  Substring matching used
# to misfire ("Unknown behavior" contains "known"), letting an attacker pick a
# heading that silently suppressed findings; word boundaries close that.
_DESCRIPTIVE_HEADING_RE = re.compile(
    r"\b(?:" + "|".join(re.escape(kw) for kw in _DESCRIPTIVE_HEADING_KEYWORDS) + r")s?\b",
    re.IGNORECASE,
)


def _heading_is_descriptive(heading: str) -> bool:
    """True if *heading* contains a descriptive keyword as a whole word."""
    return _DESCRIPTIVE_HEADING_RE.search(heading) is not None


def _strip_inline_code(line: str) -> str:
    """Blank out inline `code` spans so documented patterns don't false-fire."""
    return _INLINE_CODE_RE.sub(" ", line)


def _identify_descriptive_sections(lines: list[str]) -> set[int]:
    """Return 0-based indices of lines under a descriptive heading.

    A descriptive section runs from a heading whose text contains one of
    :data:`_DESCRIPTIVE_HEADING_KEYWORDS` until the next heading of the **same
    or higher level** (i.e. an equal or smaller ``#`` count).  Deeper
    sub-headings (e.g. ``### Attack examples`` under ``## Limitations``) stay
    part of the descriptive section instead of prematurely closing it.
    """
    descriptive: set[int] = set()
    active = False
    active_level = 0
    for idx, line in enumerate(lines):
        m = _HEADING_RE.match(line)
        if m:
            level = len(m.group(1))
            heading = m.group(2).strip().lower()
            is_descriptive = _heading_is_descriptive(heading)
            if is_descriptive:
                # Open (or re-anchor) a descriptive section at this level.
                active = True
                active_level = level
                continue
            if active and level <= active_level:
                # A sibling/parent heading closes the descriptive section.
                active = False
                active_level = 0
            # A deeper sub-heading (level > active_level) leaves it open.
            continue
        if active:
            descriptive.add(idx)
    return descriptive


def _url_rule_id(reason: str) -> str:
    """Map a URL-suspicion reason to a clean, machine-readable rule ID.

    Avoids stuffing slashes/quotes/dots (e.g. from a TLD like ``.tk``) into the
    ``rule_id`` field, which would break machine-readable consumers.
    """
    r = reason.lower()
    if "tld" in r:
        return "URL_SUSPICIOUS_TLD"
    if "bare ip" in r or "ip address" in r:
        return "URL_BARE_IP"
    if "tls" in r or "http://" in r or "non-https" in r or "no tls" in r:
        return "URL_NO_TLS"
    if "private" in r or "internal" in r or "metadata" in r:
        return "URL_INTERNAL_TARGET"
    if "could not be parsed" in r or "parse" in r:
        return "URL_UNPARSEABLE"
    return "URL_SUSPICIOUS"


# Suspicion-reason → finding severity mapping (matched by keyword).
def _url_severity(reason: str) -> Literal["critical", "high", "medium", "low"]:
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
    endpoints: list[Any] | None = None,
    description: str | None = None,
    base_url: str | None = None,
) -> SecurityReport:
    """Scan *raw_text* for security issues and return a :class:`SecurityReport`.

    Args:
        raw_text: Full text of a ``SKILL.md`` file.
        endpoints: Optional list of endpoints (used for mismatch
            detection).  Each entry is a dict or model carrying at least
            ``method`` and ``path``.
        description: Optional human-readable description of the skill,
            used together with *endpoints* for mismatch detection.
        base_url: Optional declared Base URL.  When given, endpoint
            declarations of the form ``METHOD https://…`` pointing at a
            *different* host are flagged (domain-consistency check).

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
        compiled = rule.compiled  # process-cached compile (see security_rules)
        for idx, line in enumerate(lines):
            raw_candidates = {line, _normalize_for_matching(line)}
            if not any(compiled.search(candidate) for candidate in raw_candidates):
                continue

            context: Literal["operational", "descriptive_documentation", "code_example"] = (
                "operational"
            )
            finding_severity = rule.severity

            # Context lowers confidence; it never erases a dangerous match.
            # An author controls headings and fences, so treating either as an
            # allow-list lets an attack document pass cleanly.
            if rule.category in _DESCRIPTIVE_SKIP_CATEGORIES and idx in descriptive_lines:
                context = "descriptive_documentation"
            elif rule.is_code_block_safe and idx in code_block_lines:
                context = "code_example"
            elif rule.is_code_block_safe:
                stripped = _strip_inline_code(line)
                stripped_candidates = {stripped, _normalize_for_matching(stripped)}
                if not any(compiled.search(candidate) for candidate in stripped_candidates):
                    context = "code_example"

            original_severity = None
            if context != "operational" and finding_severity in {"critical", "high"}:
                original_severity = finding_severity
                finding_severity = "medium"

            rules_triggered.add(rule.rule_id)
            findings.append(
                SecurityFinding(
                    rule_id=rule.rule_id,
                    severity=finding_severity,
                    original_severity=original_severity,
                    category=rule.category,
                    context=context,
                    detail=f"{rule.description} (matched on line {idx + 1})",
                    line=idx + 1,
                )
            )

    # --- 1b. Base64-smuggled instruction decoding --------------------------
    # Short Base64 blobs slip under SEC-018's length bar; decode candidate
    # tokens and flag any that decode to an injection.  Context can reduce
    # confidence, but fences and headings cannot suppress the finding.
    for idx, line in enumerate(lines):
        decoded = _decode_base64_injection(line)
        if decoded is not None:
            context: Literal["operational", "descriptive_documentation", "code_example"] = (
                "operational"
            )
            decoded_severity: Literal["high", "medium"] = "high"
            if idx in descriptive_lines:
                context = "descriptive_documentation"
                decoded_severity = "medium"
            elif idx in code_block_lines:
                context = "code_example"
                decoded_severity = "medium"
            rules_triggered.add("SEC-018B")
            findings.append(
                SecurityFinding(
                    rule_id="SEC-018B",
                    severity=decoded_severity,
                    original_severity=("high" if decoded_severity == "medium" else None),
                    category="hidden_instructions",
                    context=context,
                    detail=(
                        "Base64-encoded string decodes to an injection-like "
                        f"instruction ({decoded[:60]!r}) (matched on line {idx + 1})"
                    ),
                    line=idx + 1,
                )
            )

    # --- 2. URL suspicion analysis -----------------------------------------
    # De-duplicate by (url, reason) so a URL repeated N times in the document
    # produces one finding and one score penalty — not N (a score-gaming /
    # DoS vector otherwise).
    seen_url_findings: set[tuple[str, str]] = set()
    for idx, line in enumerate(lines):
        for url_match in _URL_RE.finditer(line):
            url = url_match.group(0)
            reasons = check_url_suspicion(url)
            for reason in reasons:
                dedup_key = (url, reason)
                if dedup_key in seen_url_findings:
                    continue
                seen_url_findings.add(dedup_key)
                url_severity = _url_severity(reason)
                findings.append(
                    SecurityFinding(
                        rule_id=_url_rule_id(reason),
                        severity=url_severity,
                        category="suspicious_url",
                        detail=f"Suspicious URL ({reason}): {url} (line {idx + 1})",
                        line=idx + 1,
                    )
                )

    # --- 2b. Domain consistency (declared endpoints vs Base URL host) ------
    # Only endpoint declarations with an absolute URL are compared; prose
    # links (Author, repository, docs) are metadata, not attack surface.
    if base_url:
        try:
            base_host = (urlparse(base_url).hostname or "").lower()
        except Exception:  # noqa: BLE001
            base_host = ""
        if base_host:
            seen_foreign: set[str] = set()
            for idx, line in enumerate(lines):
                for m in _ENDPOINT_ABS_URL_RE.finditer(line):
                    url = m.group(1)
                    try:
                        host = (urlparse(url).hostname or "").lower()
                    except Exception:  # noqa: BLE001
                        continue
                    if host and host != base_host and url not in seen_foreign:
                        seen_foreign.add(url)
                        findings.append(
                            SecurityFinding(
                                rule_id="ENDPOINT_FOREIGN_HOST",
                                severity="medium",
                                category="suspicious_url",
                                detail=(
                                    "Declared endpoint targets a different host "
                                    f"than the declared Base URL ({base_host}): "
                                    f"{url} (line {idx + 1})"
                                ),
                                line=idx + 1,
                            )
                        )

    # --- 3. Method-mismatch detection --------------------------------------
    if endpoints is not None and description is not None:
        # check_method_mismatch expects list[dict] with "method" and "path" keys
        ep_dicts = [
            {"method": ep.method, "path": ep.path} if hasattr(ep, "method") else ep
            for ep in endpoints
        ]
        mismatches = check_method_mismatch(description, ep_dicts)
        for mismatch in mismatches:
            # check_method_mismatch returns plain strings; tolerate a dict too
            # in case the contract ever changes.
            if isinstance(mismatch, str):
                detail = mismatch
            elif isinstance(mismatch, dict):
                detail = mismatch.get("detail", "Endpoint method does not match description claims")
            else:
                detail = "Endpoint method does not match description claims"
            findings.append(
                SecurityFinding(
                    rule_id="METHOD_MISMATCH",
                    severity="medium",
                    category="method_mismatch",
                    detail=detail,
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


def _score_to_risk_level(score: int) -> Literal["none", "low", "medium", "high", "critical"]:
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
