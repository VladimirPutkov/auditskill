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
    "а": "a", "е": "e", "о": "o", "р": "p", "с": "c",
    "х": "x", "у": "y", "і": "i", "ј": "j", "ѕ": "s",
    "к": "k", "м": "m", "т": "t", "н": "h", "в": "b",
    "г": "r", "п": "n",
    # Cyrillic uppercase
    "А": "A", "Е": "E", "О": "O", "Р": "P", "С": "C",
    "Х": "X", "У": "Y", "К": "K", "М": "M", "Т": "T",
    "Н": "H", "В": "B",
    # Greek
    "ο": "o", "α": "a", "ε": "e", "ρ": "p", "υ": "u",
    "Ο": "O", "Α": "A", "Ε": "E",
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

# Only these categories are suppressed inside descriptive sections.  Prompt
# injection, data exfiltration, and hidden-instruction rules are NEVER
# suppressed by section context — hiding those in a "Limitations" section is
# itself suspicious.  agent_capture is included only for its prose-level
# rule (SEC-030, mandatory-gating language): a doc that *discusses* gating
# patterns under "Limitations"/"Examples" is not itself capturing the agent.
# The supply-chain and proxy/daemon rules are code-block-unsafe and are
# never suppressed.
_DESCRIPTIVE_SKIP_CATEGORIES: frozenset[str] = frozenset(
    {
        "unsafe_operations",
        "scope_creep",
        "agent_capture",
        "payment_safety",
        "prompt_injection",
        "data_exfiltration",
    }
)

_HEADING_RE = re.compile(r"^\s{0,3}(#{1,6})\s+(.*)")


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
            is_descriptive = any(kw in heading for kw in _DESCRIPTIVE_HEADING_KEYWORDS)
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
            # (1) Descriptive-section suppression is independent of code-block
            #     safety: a skill that *lists* attack patterns under a heading
            #     like "Detection Patterns" / "Examples" / "Limitations" is
            #     documenting them, not instructing them.  Only the categories
            #     in _DESCRIPTIVE_SKIP_CATEGORIES are eligible.
            if rule.category in _DESCRIPTIVE_SKIP_CATEGORIES and idx in descriptive_lines:
                continue

            if rule.is_code_block_safe:
                # Code-block-safe rules describe patterns that also appear
                # legitimately in fenced/inline code (e.g. a long Base64 blob,
                # an HTML-comment example).  Ignore matches inside code.
                if idx in code_block_lines:
                    continue
                stripped = _strip_inline_code(line)
                candidates = {stripped, _normalize_for_matching(stripped)}
            else:
                # Code-block-UNSAFE rules are dangerous regardless of fences —
                # real malicious commands (rm -rf, DROP TABLE, pip install from
                # a URL, "ignore all previous instructions", curl -d token=…)
                # LIVE inside code blocks.  Scan the raw line (plus an
                # evasion-normalised copy) so a fenced or inline-code payload is
                # still caught.  Legitimate documentation of these patterns is
                # covered by the descriptive-section check above.
                candidates = {line, _normalize_for_matching(line)}

            if any(compiled.search(c) for c in candidates):
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

    # --- 1b. Base64-smuggled instruction decoding --------------------------
    # Short Base64 blobs slip under SEC-018's length bar; decode candidate
    # tokens (outside code blocks) and flag any that decode to an injection.
    for idx, line in enumerate(lines):
        if idx in code_block_lines:
            continue
        decoded = _decode_base64_injection(line)
        if decoded is not None:
            rules_triggered.add("SEC-018B")
            findings.append(
                SecurityFinding(
                    rule_id="SEC-018B",
                    severity="high",
                    category="hidden_instructions",
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
                severity = _url_severity(reason)
                findings.append(
                    SecurityFinding(
                        rule_id=_url_rule_id(reason),
                        severity=severity,
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
            {"method": ep.method, "path": ep.path}
            if hasattr(ep, "method") else ep
            for ep in endpoints
        ]
        mismatches = check_method_mismatch(description, ep_dicts)
        for mismatch in mismatches:
            # check_method_mismatch returns plain strings; tolerate a dict too
            # in case the contract ever changes.
            if isinstance(mismatch, str):
                detail = mismatch
            elif isinstance(mismatch, dict):
                detail = mismatch.get(
                    "detail", "Endpoint method does not match description claims"
                )
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
