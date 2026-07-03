"""Security scanning rules organised by category for SKILL.md auditing.

Each rule defines a regex pattern that flags potentially dangerous content
in a SKILL.md file.  Rules are grouped into five categories:

- **PROMPT_INJECTION** — attempts to hijack agent behaviour.
- **DATA_EXFILTRATION** — attempts to leak sensitive data externally.
- **UNSAFE_OPERATIONS** — destructive system/shell/SQL commands.
- **HIDDEN_INSTRUCTIONS** — steganographic or obfuscated instructions.
- **SCOPE_CREEP** — over-broad permission or capability claims.

All patterns are designed for ``re.IGNORECASE`` and use raw strings.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Literal

# ---------------------------------------------------------------------------
# Rule dataclass
# ---------------------------------------------------------------------------

Severity = Literal["critical", "high", "medium", "low"]


@dataclass(frozen=True, slots=True)
class SecurityRule:
    """A single security-scanning rule.

    Attributes:
        rule_id: Short identifier such as ``SEC-001``.
        category: One of the five scanning categories.
        severity: Impact level — ``critical``, ``high``, ``medium``, or ``low``.
        pattern: Regex pattern string (use with ``re.IGNORECASE``).
        description: Human-readable explanation of what the rule detects.
        is_code_block_safe: When ``True``, matches that occur inside fenced
            code blocks (` ``` `) are **not** flagged.  This prevents
            false positives on documentation that merely *describes*
            dangerous patterns without *instructing* them.
    """

    rule_id: str
    category: str
    severity: Severity
    pattern: str
    description: str
    is_code_block_safe: bool = field(default=True)

    @property
    def compiled(self) -> re.Pattern[str]:
        """Return a compiled regex with ``IGNORECASE``."""
        return re.compile(self.pattern, re.IGNORECASE)


# ---------------------------------------------------------------------------
# Category 1 — PROMPT INJECTION  (critical)
# ---------------------------------------------------------------------------

_PROMPT_INJECTION_RULES: list[SecurityRule] = [
    SecurityRule(
        rule_id="SEC-001",
        category="prompt_injection",
        severity="critical",
        pattern=r"ignore\s+(all\s+)?(previous|prior|above)\s+(instructions|prompts|directives)",
        description=(
            "Detects attempts to override prior instructions — a classic "
            "prompt-injection vector."
        ),
    ),
    SecurityRule(
        rule_id="SEC-002",
        category="prompt_injection",
        severity="critical",
        pattern=r"(you\s+are\s+now|from\s+now\s+on\s+you\s+are|pretend\s+you\s+are)",
        description=(
            "Detects persona-reassignment attacks that try to redefine "
            "the agent's identity."
        ),
        is_code_block_safe=True,
    ),
    SecurityRule(
        rule_id="SEC-003",
        category="prompt_injection",
        severity="critical",
        pattern=r"(system\s*prompt\s*override|override\s+.*system|new\s+system\s+prompt)",
        description=(
            "Detects direct attempts to replace or override the system "
            "prompt governing agent behaviour."
        ),
    ),
    SecurityRule(
        rule_id="SEC-004",
        category="prompt_injection",
        severity="critical",
        pattern=r"(forget\s+everything|forget\s+all|clear\s+.*context)",
        description=(
            "Detects context-reset attacks that instruct the agent to "
            "discard its conversation or safety context."
        ),
    ),
    SecurityRule(
        rule_id="SEC-005",
        category="prompt_injection",
        severity="critical",
        pattern=r"(do\s+not\s+follow\s+.*rules|bypass\s+.*restrictions|override\s+.*safety)",
        description=(
            "Detects explicit instructions to bypass safety guardrails "
            "or restriction rules."
        ),
    ),
]

# ---------------------------------------------------------------------------
# Category 2 — DATA EXFILTRATION  (critical)
# ---------------------------------------------------------------------------

_DATA_EXFILTRATION_RULES: list[SecurityRule] = [
    SecurityRule(
        rule_id="SEC-006",
        category="data_exfiltration",
        severity="critical",
        pattern=(
            r"send\s+.{0,40}"
            r"(data|info|content|env|token|key|secret|credentials)"
            r"\s+to\s+.{0,20}(external|https?://|url)"
        ),
        description=(
            "Detects instructions to send sensitive data (tokens, keys, "
            "credentials) to an external destination."
        ),
    ),
    SecurityRule(
        rule_id="SEC-007",
        category="data_exfiltration",
        severity="critical",
        pattern=(
            r"(upload\s+.*environment|transmit\s+.*logs|forward\s+.*credentials)"
        ),
        description=(
            "Detects instructions to upload environment variables, "
            "transmit logs, or forward credentials externally."
        ),
    ),
    SecurityRule(
        rule_id="SEC-008",
        category="data_exfiltration",
        severity="critical",
        pattern=(
            r"POST\s+.{0,60}"
            r"(api_key|token|password|secret|env|credentials)"
        ),
        description=(
            "Detects HTTP POST operations that include sensitive values "
            "such as API keys, passwords, or secrets."
        ),
        is_code_block_safe=True,
    ),
    SecurityRule(
        rule_id="SEC-009",
        category="data_exfiltration",
        severity="critical",
        pattern=r"(exfiltrate|phone\s*home|callback\s+.*external)",
        description=(
            "Detects explicit exfiltration language or phone-home / "
            "external-callback patterns."
        ),
    ),
    SecurityRule(
        rule_id="SEC-010",
        category="data_exfiltration",
        severity="critical",
        pattern=(
            r"curl\s+.*-d\s+.{0,40}"
            r"(env|token|key|secret|password)"
        ),
        description=(
            "Detects curl commands that POST sensitive values (secrets, "
            "tokens, passwords) to a remote endpoint."
        ),
    ),
]

# ---------------------------------------------------------------------------
# Category 3 — UNSAFE OPERATIONS  (high)
# ---------------------------------------------------------------------------

_UNSAFE_OPERATIONS_RULES: list[SecurityRule] = [
    SecurityRule(
        rule_id="SEC-011",
        category="unsafe_operations",
        severity="high",
        pattern=r"(rm\s+-rf|rmdir\s+.*force|del\s+/s)",
        description=(
            "Detects destructive file-system operations (recursive delete, "
            "forced rmdir, Windows del /s)."
        ),
    ),
    SecurityRule(
        rule_id="SEC-012",
        category="unsafe_operations",
        severity="high",
        pattern=r"(DROP\s+TABLE|TRUNCATE\s+TABLE|DELETE\s+FROM\s+.*WHERE\s+1)",
        description=(
            "Detects destructive SQL statements (DROP TABLE, TRUNCATE, "
            "unconditional DELETE)."
        ),
    ),
    SecurityRule(
        rule_id="SEC-013",
        category="unsafe_operations",
        severity="high",
        pattern=r"(sudo\s|chmod\s+777|chown\s+.*root)",
        description=(
            "Detects privilege-escalation commands: sudo, world-writable "
            "permissions, ownership changes to root."
        ),
    ),
    SecurityRule(
        rule_id="SEC-014",
        category="unsafe_operations",
        severity="high",
        pattern=r"(eval\s*\(|exec\s*\(|os\.system\s*\(|subprocess\.call\s*\(|__import__\s*\()",
        description=(
            "Detects dynamic code-execution calls in Python (eval, exec, "
            "os.system, subprocess.call, __import__)."
        ),
    ),
    SecurityRule(
        rule_id="SEC-015",
        category="unsafe_operations",
        severity="high",
        pattern=r"(format\s+.*disk|fdisk\s|mkfs\s|dd\s+.*if=)",
        description=(
            "Detects disk-level destructive operations (format, fdisk, "
            "mkfs, dd) that could destroy data."
        ),
    ),
]

# ---------------------------------------------------------------------------
# Category 4 — HIDDEN INSTRUCTIONS  (high)
# ---------------------------------------------------------------------------

_HIDDEN_INSTRUCTIONS_RULES: list[SecurityRule] = [
    SecurityRule(
        rule_id="SEC-016",
        category="hidden_instructions",
        severity="high",
        pattern=r"[\u200b\u200c\u200d\ufeff\u2060\u2062\u2063\u2064]",
        description=(
            "Detects Unicode zero-width characters (ZWSP, ZWNJ, ZWJ, "
            "BOM, Word Joiner, invisible separators) that can hide "
            "instructions from human reviewers."
        ),
        is_code_block_safe=False,
    ),
    SecurityRule(
        rule_id="SEC-017",
        category="hidden_instructions",
        severity="high",
        pattern=r"[\u202a\u202b\u202c\u202d\u202e\u2066\u2067\u2068\u2069]",
        description=(
            "Detects Unicode bidirectional override characters (LRE, RLE, "
            "PDF, LRO, RLO, LRI, RLI, FSI, PDI) that can reorder "
            "displayed text to conceal true intent."
        ),
        is_code_block_safe=False,
    ),
    SecurityRule(
        rule_id="SEC-018",
        category="hidden_instructions",
        severity="high",
        pattern=r"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{100,}={0,2}(?![A-Za-z0-9+/=])",
        description=(
            "Detects long Base64-encoded strings (>100 chars) in "
            "instruction context.  Legitimate documentation rarely "
            "contains raw Base64 blobs outside code fences."
        ),
        is_code_block_safe=True,
    ),
    SecurityRule(
        rule_id="SEC-019",
        category="hidden_instructions",
        severity="high",
        pattern=(
            r"<!--\s*.*?"
            r"(must|should|always|never|do\s+not|ignore|override|execute|send|forward|transmit)"
            r".*?-->"
        ),
        description=(
            "Detects HTML comments containing imperative verbs — a "
            "common technique for hiding instructions that are invisible "
            "in rendered Markdown but parsed by agents."
        ),
        is_code_block_safe=True,
    ),
    SecurityRule(
        rule_id="SEC-020",
        category="hidden_instructions",
        severity="high",
        pattern=(
            r"https?://[^\s]*"
            r"[\u0400-\u04ff]"  # Cyrillic code points mixed with Latin
            r"[^\s]*"
        ),
        description=(
            "Detects homoglyph/mixed-script attacks in URLs — Cyrillic "
            "characters mixed with Latin in a URL, used to impersonate "
            "legitimate domains (IDN homograph attack)."
        ),
        is_code_block_safe=False,
    ),
]

# ---------------------------------------------------------------------------
# Category 5 — SCOPE CREEP  (medium)
# ---------------------------------------------------------------------------

_SCOPE_CREEP_RULES: list[SecurityRule] = [
    SecurityRule(
        rule_id="SEC-021",
        category="scope_creep",
        severity="medium",
        pattern=r"(access\s+all|unlimited\s+.*permission|no\s+.*restrictions|unrestricted)",
        description=(
            "Detects over-broad access claims such as 'access all', "
            "'unlimited permission', or 'unrestricted'."
        ),
    ),
    SecurityRule(
        rule_id="SEC-022",
        category="scope_creep",
        severity="medium",
        pattern=r"(full\s+.*control|admin\s+.*mode|root\s+.*access|superuser)",
        description=(
            "Detects claims to elevated privilege modes (full control, "
            "admin mode, root access, superuser)."
        ),
    ),
    SecurityRule(
        rule_id="SEC-023",
        category="scope_creep",
        severity="medium",
        pattern=r"(skip\s+.*verification|bypass\s+.*auth|no\s+.*confirmation)",
        description=(
            "Detects instructions to skip verification, bypass "
            "authentication, or suppress user confirmation."
        ),
    ),
    SecurityRule(
        rule_id="SEC-024",
        category="scope_creep",
        severity="medium",
        pattern=r"(any\s+.*action|everything|all\s+operations|do\s+anything)",
        description=(
            "Detects overly permissive scope declarations — 'any action', "
            "'everything', 'all operations', 'do anything'."
        ),
    ),
    SecurityRule(
        rule_id="SEC-025",
        category="scope_creep",
        severity="medium",
        pattern=r"(modify\s+.*system|change\s+.*config|alter\s+.*settings)",
        description=(
            "Detects instructions to modify system configuration or "
            "settings outside of a documented API surface."
        ),
    ),
]

# ---------------------------------------------------------------------------
# Aggregate registry
# ---------------------------------------------------------------------------

_ALL_RULES: list[SecurityRule] = (
    _PROMPT_INJECTION_RULES
    + _DATA_EXFILTRATION_RULES
    + _UNSAFE_OPERATIONS_RULES
    + _HIDDEN_INSTRUCTIONS_RULES
    + _SCOPE_CREEP_RULES
)

# Build a quick lookup index by category (computed once at import time).
_RULES_BY_CATEGORY: dict[str, list[SecurityRule]] = {}
for _rule in _ALL_RULES:
    _RULES_BY_CATEGORY.setdefault(_rule.category, []).append(_rule)


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def get_all_rules() -> list[SecurityRule]:
    """Return all 25 security rules across every category.

    The returned list is a shallow copy so callers can filter or sort
    without mutating the module-level registry.
    """
    return list(_ALL_RULES)


def get_rules_by_category(category: str) -> list[SecurityRule]:
    """Return rules that belong to *category* (case-insensitive).

    Args:
        category: One of ``prompt_injection``, ``data_exfiltration``,
            ``unsafe_operations``, ``hidden_instructions``, or
            ``scope_creep``.

    Returns:
        A list of matching :class:`SecurityRule` instances.  If the
        category is unknown an empty list is returned.
    """
    return list(_RULES_BY_CATEGORY.get(category.lower(), []))
