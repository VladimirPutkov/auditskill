"""Pydantic v2 models for the AuditSkill auditing and certification service.

Defines every request, response, internal-data, and report model used across
the API surface and internal processing pipeline.
"""

from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, Field, model_validator


# ---------------------------------------------------------------------------
# Size constants
# ---------------------------------------------------------------------------

_MAX_SKILL_MD_BYTES = 200 * 1024  # 200 KiB, measured as UTF-8 bytes


# ---------------------------------------------------------------------------
# Request models
# ---------------------------------------------------------------------------


class AuditRequest(BaseModel):
    """Incoming audit request.

    Callers must supply **exactly one** of ``skill_md`` (raw text) or
    ``skill_url`` (an HTTPS URL the service will fetch).
    """

    skill_md: str | None = Field(
        default=None,
        description="Raw SKILL.md text to audit.",
    )
    skill_url: str | None = Field(
        default=None,
        description="HTTPS URL to fetch the SKILL.md from.",
    )
    mode: Literal["safe_static", "liveness"] = Field(
        default="safe_static",
        description=(
            "Audit mode. 'safe_static' (default) does document analysis only. "
            "'liveness' additionally sends GET/HEAD probes to declared endpoints."
        ),
    )
    model: str | None = Field(
        default=None,
        description=(
            "Optional model ID — narrows context_cost.per_model to this model "
            "only. Omit to get every tracked model (see /benchmarks)."
        ),
    )

    @model_validator(mode="after")
    def _validate_source(self) -> AuditRequest:
        """Ensure exactly one source is provided and apply constraints."""
        has_md = self.skill_md is not None
        has_url = self.skill_url is not None

        if has_md == has_url:
            # Both set or neither set
            raise ValueError("Exactly one of 'skill_md' or 'skill_url' must be provided.")

        if has_url:
            assert self.skill_url is not None  # for type narrowing
            if not self.skill_url.startswith("https://"):
                raise ValueError("skill_url must use HTTPS (start with 'https://').")

        if has_md:
            assert self.skill_md is not None  # for type narrowing
            if not self.skill_md.strip():
                raise ValueError(
                    "skill_md was provided but is empty. Send the SKILL.md text "
                    "in 'skill_md', or use 'skill_url' to fetch it by URL."
                )
            n_bytes = len(self.skill_md.encode("utf-8"))
            if n_bytes > _MAX_SKILL_MD_BYTES:
                raise ValueError(
                    f"skill_md exceeds maximum size of "
                    f"{_MAX_SKILL_MD_BYTES:,} bytes "
                    f"(got {n_bytes:,} UTF-8 bytes)."
                )

        return self


class VerifyRequest(BaseModel):
    """Request to verify a previously issued certificate."""

    certificate: dict[str, Any] = Field(
        ...,
        description="Full certificate JSON to verify statelessly.",
    )


# ---------------------------------------------------------------------------
# Internal data models
# ---------------------------------------------------------------------------


class ParsedEndpoint(BaseModel):
    """A single API endpoint parsed from the SKILL.md."""

    method: str = Field(
        ...,
        description="HTTP method (GET, POST, PUT, DELETE, etc.).",
    )
    path: str = Field(
        ...,
        description="Endpoint path (e.g. '/api/v1/users').",
    )
    params: list[str] = Field(
        default_factory=list,
        description="Named parameters referenced in the endpoint.",
    )
    has_example: bool = Field(
        default=False,
        description="Whether the endpoint has an accompanying usage example.",
    )


class ParsedSkill(BaseModel):
    """Structured representation of a parsed SKILL.md document."""

    name: str | None = None
    description: str | None = None
    base_url: str | None = None
    endpoints: list[ParsedEndpoint] = Field(default_factory=list)
    auth_type: str | None = None
    has_error_docs: bool = False
    has_auth_docs: bool = False
    has_rate_limits: bool = False
    has_workflow: bool = False
    has_side_effects_warning: bool = False
    has_examples: bool = False
    example_count: int = 0
    section_count: int = 0
    raw_text: str = ""


# ---------------------------------------------------------------------------
# Security finding
# ---------------------------------------------------------------------------


class SecurityFinding(BaseModel):
    """A single security issue discovered during audit."""

    rule_id: str = Field(
        ...,
        description="Unique identifier for the security rule (e.g. 'SEC-001').",
    )
    severity: Literal["critical", "high", "medium", "low"]
    category: str = Field(
        ...,
        description="Category of the finding (e.g. 'credential_leak').",
    )
    detail: str = Field(
        ...,
        description="Human-readable description of the issue.",
    )
    line: int | None = Field(
        default=None,
        description="1-based line number where the issue was found, if applicable.",
    )


# ---------------------------------------------------------------------------
# Endpoint test results
# ---------------------------------------------------------------------------


class EndpointResult(BaseModel):
    """Result of probing a single endpoint during liveness checks."""

    url: str
    method: str
    status: int | None = None
    latency_ms: float | None = None
    tls: bool | None = None
    content_type: str | None = None
    valid_json: bool | None = None
    error: str | None = None
    executed: bool = True


class SkippedEndpoint(BaseModel):
    """An endpoint that was intentionally not tested."""

    method: str
    path: str
    reason: str


# ---------------------------------------------------------------------------
# Module reports
# ---------------------------------------------------------------------------


class StructureReport(BaseModel):
    """Report from the structure / documentation-quality analyser."""

    score: int
    has_name: bool = False
    has_description: bool = False
    has_base_url: bool = False
    has_endpoints: bool = False
    has_examples: bool = False
    has_error_docs: bool = False
    has_auth_docs: bool = False
    has_rate_limits: bool = False
    has_workflow: bool = False
    has_side_effects_warning: bool = False
    endpoint_count: int = 0
    example_count: int = 0
    section_count: int = 0
    findings: list[str] = Field(default_factory=list)


class LivenessReport(BaseModel):
    """Report from the liveness / endpoint-probing module."""

    score: int | None = Field(
        default=None,
        description="None when not tested (safe_static mode).",
    )
    tested: int = 0
    alive: int = 0
    dead: int = 0
    skipped: list[SkippedEndpoint] = Field(default_factory=list)
    avg_latency_ms: float | None = None
    results: list[EndpointResult] = Field(default_factory=list)
    findings: list[str] = Field(default_factory=list)


class SecurityReport(BaseModel):
    """Report from the security rule engine."""

    score: int
    risk_level: Literal["none", "low", "medium", "high", "critical"]
    rules_checked: int
    rules_triggered: int
    findings: list[SecurityFinding] = Field(default_factory=list)


class ScopeReport(BaseModel):
    """Report from the scope / breadth analyser."""

    score: int
    breadth: str = Field(
        ...,
        description="Assessed breadth: 'narrow', 'moderate', or 'broad'.",
    )
    domains_detected: list[str] = Field(default_factory=list)
    missing_sections: list[str] = Field(default_factory=list)
    recommendations: list[str] = Field(default_factory=list)
    endpoint_count: int = 0
    example_count: int = 0
    findings: list[str] = Field(default_factory=list)


class MetadataReport(BaseModel):
    """Report from the metadata / provenance checker."""

    score: int
    has_author: bool = False
    has_contact: bool = False
    has_repo_url: bool = False
    repo_url: str | None = None
    repo_reachable: bool | None = None
    license_detected: str | None = None
    base_url_https: bool = False
    findings: list[str] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Issues & certificates
# ---------------------------------------------------------------------------


class Issue(BaseModel):
    """A single audit issue surfaced to the caller."""

    severity: Literal["critical", "high", "medium", "low", "info"]
    msg: str
    module: str | None = None


class Certificate(BaseModel):
    """Ed25519-signed audit certificate."""

    certificate_id: str
    skill_name: str | None = None
    skill_hash: str = Field(
        ...,
        description="SHA-256 hex digest of the audited SKILL.md text.",
    )
    verdict: str
    score: int
    mode: str
    checks: dict[str, str] = Field(
        ...,
        description="Module name -> 'pass' | 'warning' | 'fail'.",
    )
    limitations: list[str] = Field(default_factory=list)
    tested_at: str
    valid_until: str
    public_key_id: str
    signature: str = Field(
        ...,
        description="Ed25519 signature in 'ed25519:<base64>' format.",
    )


# ---------------------------------------------------------------------------
# Response models
# ---------------------------------------------------------------------------


class PerModelCost(BaseModel):
    """Token count, input cost, and window share for one tracked model."""

    model: str = Field(..., description="Model ID (see /benchmarks for the tracked list).")
    tokens: int = Field(..., description="Calibrated token estimate for this model family.")
    input_cost_usd: float = Field(
        ...,
        description="Estimated one-time input cost (USD) to load this file.",
    )
    window_pct: float = Field(
        ...,
        description="Share of the model's context window this file consumes, in percent.",
    )


class ContextCost(BaseModel):
    """Token-budget impact estimate for loading this SKILL.md."""

    tokens_estimate: int = Field(
        ...,
        description="Estimated token count (~4 chars/token heuristic).",
    )
    size_bytes: int
    density: Literal["high", "medium", "low"] = Field(
        ...,
        description=(
            "Information density. 'high' = concise and well-structured, "
            "'low' = bloated relative to useful content."
        ),
    )
    recommendation: str = Field(
        ...,
        description="Actionable advice for the agent about context cost.",
    )
    # All fields below default so pre-existing cached audits still deserialize.
    per_model: list[PerModelCost] = Field(
        default_factory=list,
        description="Per-model token count, input cost (USD), and context-window share.",
    )
    error_margin_pct: int = Field(
        default=10,
        description="Honest error bar of the token heuristic, in percent.",
    )
    price_source: str | None = Field(
        default=None,
        description=(
            "Provenance of the price figures: AuditSkill's built-in, "
            "self-contained price table, with its as_of date."
        ),
    )


class AuditResponse(BaseModel):
    """Full audit response returned to the caller."""

    audit_id: str
    mode: str
    skill_name: str | None = None
    skill_hash: str
    overall_score: int
    verdict: str
    cached: bool = False

    structure: StructureReport
    liveness: LivenessReport
    security: SecurityReport
    scope: ScopeReport
    metadata: MetadataReport
    context_cost: ContextCost

    issues: list[Issue] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    certificate_id: str | None = None
    certificate: Certificate | None = None
    tested_at: str


class VerifyResponse(BaseModel):
    """Response from certificate verification."""

    valid: bool = Field(
        ...,
        description="True only if the Ed25519 signature is authentic AND the certificate has not expired.",
    )
    signature_valid: bool = Field(
        default=False,
        description="True if the signature alone is authentic (regardless of expiry).",
    )
    expired: bool | None = Field(
        default=None,
        description="True if valid_until is in the past; null if no signature to check.",
    )
    certificate_id: str | None = None
    verdict: str | None = None
    score: int | None = None
    valid_until: str | None = None
    error: str | None = None


class HealthResponse(BaseModel):
    """Health-check response."""

    status: str = "ok"
    version: str
    service: str = "auditskill"


class KeyInfo(BaseModel):
    """Public-key metadata."""

    key_id: str
    algorithm: str = "Ed25519"
    public_key: str
    status: str = "active"
    created_at: str


class KeysResponse(BaseModel):
    """Response listing available public keys."""

    keys: list[KeyInfo] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Discover models (safe-discovery layer)
# ---------------------------------------------------------------------------


class DiscoverResult(BaseModel):
    """A single registry entry enriched with an AuditSkill verdict."""

    name: str | None = None
    author: str | None = None
    description: str | None = None
    source_url: str | None = None
    tags: Any = None

    audited: bool = False
    verdict: str | None = None
    score: int | None = None
    risk_level: str | None = None
    critical_findings: int = 0
    skill_hash: str | None = None
    certificate_id: str | None = None
    cached: bool = False
    reason: str | None = Field(
        default=None,
        description="Why the entry could not be audited (fetch error, no content, etc.).",
    )
    # Ranking fields (all default — pre-ranking cached rows still deserialize).
    rank: int | None = Field(
        default=None,
        description="1-based rank: passing audits first, then failing, then unaudited.",
    )
    rank_reason: str | None = Field(
        default=None,
        description="Deterministic explanation of the rank (formula in /benchmarks).",
    )
    context_cost: dict[str, Any] | None = Field(
        default=None,
        description="Compact cost summary: tokens_estimate, density, cheapest_input_usd.",
    )


class DiscoverResponse(BaseModel):
    """Response from the /discover safe-discovery endpoint."""

    registry: str = Field(
        ...,
        description="URL of the registry that was scanned.",
    )
    mode: str
    total_in_registry: int
    returned: int
    audited: int
    results: list[DiscoverResult] = Field(default_factory=list)


# ---------------------------------------------------------------------------
# Error response
# ---------------------------------------------------------------------------


class ErrorResponse(BaseModel):
    """Standard error envelope."""

    error: str
    detail: str | None = None
