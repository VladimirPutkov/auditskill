"""SKILL.md parser — extracts structured metadata from raw markdown text.

Extracts the title (``# H1``) and description (first prose paragraph) per the
NANDA plain-Markdown standard, with YAML frontmatter supported as a fallback.
Discovers base URLs, enumerates HTTP endpoints, counts runnable examples, and
detects documentation-quality sections.

Uses only stdlib + PyYAML.  Makes no network calls.
"""

from __future__ import annotations

import logging
import re
from urllib.parse import parse_qs, urlparse

import yaml

from auditskill.api.models import ParsedEndpoint, ParsedSkill

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Compiled patterns (module-level for performance)
# ---------------------------------------------------------------------------

# YAML frontmatter delimited by --- on its own lines
_FRONTMATTER_RE = re.compile(r"\A---\s*\n(.*?)\n---", re.DOTALL)

# Base-URL keywords followed by a URL (inline or next-line code block)
_BASE_URL_KEYWORD_RE = re.compile(
    r"(?:Base\s*URL|Endpoint|Host|Server)\s*[:\s]*"
    r"(?:`(https?://[^\s`]+)`|(https?://[^\s)>\"]+))",
    re.IGNORECASE,
)
# Also catch a URL sitting alone in a fenced code block right after a keyword header
_BASE_URL_CODEBLOCK_RE = re.compile(
    r"(?:Base\s*URL|Endpoint|Host|Server)[^\n]*\n"
    r"```[^\n]*\n\s*(https?://[^\s`]+)\s*\n```",
    re.IGNORECASE,
)

# HTTP method + path (absolute or relative)
_HTTP_METHODS = r"GET|POST|PUT|PATCH|DELETE|HEAD|OPTIONS"
_ENDPOINT_PATH_RE = re.compile(
    rf"({_HTTP_METHODS})\s+(/[^\s\"'`>)]+)",
    re.IGNORECASE,
)
_ENDPOINT_URL_RE = re.compile(
    rf"({_HTTP_METHODS})\s+(https?://[^\s\"'`>)]+)",
    re.IGNORECASE,
)

# Path parameters like {id}, {city}
_PATH_PARAM_RE = re.compile(r"\{(\w+)\}")

# Query parameters: ?key=value or &key=value
_QUERY_PARAM_RE = re.compile(r"[?&](\w+)=")

# Fenced code blocks (we need their content for example counting)
_CODE_BLOCK_RE = re.compile(r"```[^\n]*\n(.*?)```", re.DOTALL)

# Markdown ## headers
_SECTION_HEADER_RE = re.compile(r"^##\s+(.+)", re.MULTILINE)

# HTML tag stripper + control-char stripper for sanitising extracted text.
_HTML_TAG_RE = re.compile(r"<[^>]*>")
_CONTROL_CHAR_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def _sanitize_text(value: str | None, *, max_len: int = 300) -> str | None:
    """Strip HTML tags and control chars from extracted skill text.

    The name/description are echoed back in JSON responses (and may be rendered
    by downstream consumers), so a title like ``Evil<script>alert(1)</script>``
    must not carry an executable payload through the audit.
    """
    if value is None:
        return None
    cleaned = _HTML_TAG_RE.sub("", value)
    cleaned = _CONTROL_CHAR_RE.sub("", cleaned)
    cleaned = cleaned.strip()
    if len(cleaned) > max_len:
        cleaned = cleaned[:max_len].rstrip() + "…"
    return cleaned or None

# Auth type patterns (for auth_type field)
_AUTH_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("bearer", re.compile(r"bearer\s+token|authorization:\s*bearer", re.IGNORECASE)),
    ("api_key", re.compile(r"api[_\s-]?key|x-api-key", re.IGNORECASE)),
    ("oauth2", re.compile(r"oauth\s*2?\.?0?|authorization\s+code\s+flow", re.IGNORECASE)),
    ("basic", re.compile(r"basic\s+auth|authorization:\s*basic", re.IGNORECASE)),
]

# Section keyword sets for documentation quality flags
_AUTH_KEYWORDS = {"auth", "authentication", "authorization"}
_ERROR_KEYWORDS = {"error", "errors", "error response", "error handling"}
_RATE_KEYWORDS = {"rate limit", "rate limits", "throttle", "quota"}
_WORKFLOW_KEYWORDS = {
    "workflow",
    "typical workflow",
    "how to use",
    "how the agent should use this",
    "how the agent should use",
    "how the agent",
    "usage",
    "getting started",
    "quick start",
    "quickstart",
}
_SIDE_EFFECT_KEYWORDS = {
    "side effect",
    "side effects",
    "warning",
    "caution",
    "destructive",
    "state-changing",
}


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------


def parse_skill_md(raw_text: str) -> ParsedSkill:
    """Parse a raw SKILL.md string and return structured metadata."""
    name, description = _extract_name_description(raw_text)
    name = _sanitize_text(name, max_len=200)
    description = _sanitize_text(description, max_len=500)
    base_url = _find_base_url(raw_text)
    endpoints = _extract_endpoints(raw_text)
    example_count = _count_examples(raw_text)
    section_headers = _SECTION_HEADER_RE.findall(raw_text)
    section_count = len(section_headers)
    flags = _detect_section_flags(section_headers)
    auth_type = _detect_auth_type(raw_text)

    return ParsedSkill(
        name=name,
        description=description,
        base_url=base_url,
        endpoints=endpoints,
        auth_type=auth_type,
        example_count=example_count,
        has_examples=example_count > 0,
        section_count=section_count,
        raw_text=raw_text,
        **flags,
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

_H1_RE = re.compile(r"^\s{0,3}#\s+(.+?)\s*$", re.MULTILINE)


def _extract_name_description(raw_text: str) -> tuple[str | None, str | None]:
    """Extract ``(name, description)`` from a SKILL.md.

    The NANDA platform standard is *plain Markdown* (no YAML frontmatter):
    the title is the first ``# H1`` and the description is the first prose
    paragraph beneath it.  YAML frontmatter, when present, takes precedence
    as a fallback for older/other formats.
    """
    fm_name, fm_desc = _extract_frontmatter(raw_text)
    name: str | None = fm_name
    description: str | None = fm_desc

    # Scan the body (with any frontmatter block removed).
    body = _FRONTMATTER_RE.sub("", raw_text, count=1)
    lines = body.splitlines()

    # First H1 → name.
    h1_idx: int | None = None
    for i, line in enumerate(lines):
        m = re.match(r"^\s{0,3}#\s+(.+)", line)
        if m:
            h1_idx = i
            if name is None:
                name = m.group(1).strip()
            break

    # First prose paragraph after the H1 → description.
    if description is None and h1_idx is not None:
        for line in lines[h1_idx + 1:]:
            s = line.strip()
            if not s:
                continue
            if s.startswith(("#", "```", "-", "*", ">", "|")):
                break
            description = s
            break

    return name or None, description or None


def _extract_frontmatter(raw_text: str) -> tuple[str | None, str | None]:
    """Return ``(name, description)`` from YAML frontmatter, or ``(None, None)``."""
    match = _FRONTMATTER_RE.search(raw_text)
    if not match:
        return None, None

    yaml_text = match.group(1)
    try:
        data = yaml.safe_load(yaml_text)
    except yaml.YAMLError as exc:
        logger.warning("Malformed YAML frontmatter — skipping: %s", exc)
        return None, None

    if not isinstance(data, dict):
        logger.warning("YAML frontmatter is not a mapping — skipping.")
        return None, None

    name = data.get("name")
    description = data.get("description")

    # Normalise multi-line YAML scalars: collapse whitespace runs
    if isinstance(description, str):
        description = " ".join(description.split())
    if isinstance(name, str):
        name = name.strip()

    return name or None, description or None


def _find_base_url(raw_text: str) -> str | None:
    """Discover the primary base URL in the document."""
    # Try code-block form first (more precise)
    match = _BASE_URL_CODEBLOCK_RE.search(raw_text)
    if match:
        return _clean_url(match.group(1))

    # Fall back to inline form
    match = _BASE_URL_KEYWORD_RE.search(raw_text)
    if match:
        url = match.group(1) or match.group(2)
        return _clean_url(url)

    return None


def _clean_url(url: str) -> str:
    """Strip trailing punctuation and normalise a URL."""
    url = url.rstrip(".,;:)>\"'`")
    return url.rstrip("/")


def _detect_auth_type(raw_text: str) -> str | None:
    """Detect the authentication type mentioned in the document."""
    for auth_type, pattern in _AUTH_PATTERNS:
        if pattern.search(raw_text):
            return auth_type
    return None


def _extract_endpoints(raw_text: str) -> list[ParsedEndpoint]:
    """Extract all HTTP endpoints from the document body.

    De-duplicates by ``(method_upper, normalised_path)`` so an endpoint
    defined in a heading and repeated in an example is counted once.
    """
    seen: set[tuple[str, str]] = set()
    endpoints: list[ParsedEndpoint] = []

    # Collect all code block contents for has_example matching
    code_blocks = _CODE_BLOCK_RE.findall(raw_text)
    code_block_text = "\n".join(code_blocks)

    # Match "METHOD /path" patterns
    for method, path in _ENDPOINT_PATH_RE.findall(raw_text):
        _add_endpoint(method, path, seen, endpoints, code_block_text)

    # Match "METHOD https://..." patterns — extract path from full URL
    for method, full_url in _ENDPOINT_URL_RE.findall(raw_text):
        parsed = urlparse(full_url)
        path = parsed.path or "/"
        if parsed.query:
            path = f"{path}?{parsed.query}"
        _add_endpoint(method, path, seen, endpoints, code_block_text)

    return endpoints


def _add_endpoint(
    method: str,
    path: str,
    seen: set[tuple[str, str]],
    endpoints: list[ParsedEndpoint],
    code_block_text: str,
) -> None:
    """Build a ParsedEndpoint and append it if not already seen."""
    method_upper = method.upper()

    # Separate path from query string for dedup key
    if "?" in path:
        path_part, query_part = path.split("?", 1)
    else:
        path_part, query_part = path, ""

    # Normalise the path for dedup (strip trailing slash)
    norm_path = path_part.rstrip("/") or "/"
    key = (method_upper, norm_path)
    if key in seen:
        return
    seen.add(key)

    # Gather all parameters (both path and query)
    path_params = _PATH_PARAM_RE.findall(path_part)
    query_params: list[str] = []
    if query_part:
        try:
            query_params = list(parse_qs(query_part, keep_blank_values=True).keys())
        except Exception:  # noqa: BLE001 — best-effort
            query_params = _QUERY_PARAM_RE.findall(query_part)

    all_params = sorted(set(path_params + query_params))

    # Determine if this endpoint has an example in code blocks
    has_example = bool(
        re.search(
            rf"{re.escape(norm_path)}",
            code_block_text,
        )
    )

    endpoints.append(
        ParsedEndpoint(
            method=method_upper,
            path=norm_path,
            params=all_params,
            has_example=has_example,
        )
    )


def _count_examples(raw_text: str) -> int:
    """Count code blocks that look like runnable HTTP examples."""
    count = 0
    for block_content in _CODE_BLOCK_RE.findall(raw_text):
        content = block_content.strip().lower()
        # curl commands
        if content.startswith("curl") or "curl " in content:
            count += 1
            continue
        # HTTP/1.1 style request blocks
        if re.search(r"^(get|post|put|patch|delete|head|options)\s+", content, re.IGNORECASE):
            count += 1
            continue
        # wget or httpie
        if content.startswith("http ") or content.startswith("wget "):
            count += 1
            continue
    return count


def _detect_section_flags(section_headers: list[str]) -> dict[str, bool]:
    """Map section header text to documentation quality flags."""
    flags = {
        "has_auth_docs": False,
        "has_error_docs": False,
        "has_rate_limits": False,
        "has_workflow": False,
        "has_side_effects_warning": False,
    }

    for header in section_headers:
        lower = header.strip().lower()
        # Remove leading ### markers that might be captured in sub-sections
        lower = re.sub(r"^#+\s*", "", lower).strip()

        if lower in _AUTH_KEYWORDS or any(kw in lower for kw in _AUTH_KEYWORDS):
            flags["has_auth_docs"] = True
        if lower in _ERROR_KEYWORDS or any(kw in lower for kw in _ERROR_KEYWORDS):
            flags["has_error_docs"] = True
        if lower in _RATE_KEYWORDS or any(kw in lower for kw in _RATE_KEYWORDS):
            flags["has_rate_limits"] = True
        if lower in _WORKFLOW_KEYWORDS or any(kw in lower for kw in _WORKFLOW_KEYWORDS):
            flags["has_workflow"] = True
        if lower in _SIDE_EFFECT_KEYWORDS or any(kw in lower for kw in _SIDE_EFFECT_KEYWORDS):
            flags["has_side_effects_warning"] = True

    return flags
