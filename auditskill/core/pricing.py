"""Model-aware context-cost pricing for AuditSkill.

Answers the question at the heart of skill selection: *what does loading
this SKILL.md actually cost on my model — in tokens, in dollars, and as a
share of my context window?*

Prices are maintained as a versioned local snapshot. Audit requests never
depend on a pricing network call, but the estimates can become stale and are
reported with their snapshot date and error margin.

Design invariants:

- **No audit request ever waits on the network for prices.**  Estimates read
  the in-memory table only — there is no background fetch and no outside
  call, so every mode (including ``safe_static``) is strictly offline and
  fully deterministic.
- **Deterministic.**  Given the same text and the same price snapshot,
  the output is byte-identical.  Token counts are calibrated heuristics
  (chars-per-token per model family), not tokenizer calls — the agent is
  making a load/skip decision, not doing accounting.  The estimate error
  is surfaced honestly via ``error_margin_pct``.
"""

from __future__ import annotations

from dataclasses import dataclass

from auditskill.api.models import PerModelCost

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

#: Calibrated chars-per-token ratios for the ASCII portion of a document.
#: Non-ASCII characters are counted ~1 token each (see auditor heuristic).
_FAMILY_RATIOS: dict[str, float] = {
    "claude": 3.8,
    "gemini": 4.2,
    "llama": 4.0,
    "openai": 3.7,
}
_DEFAULT_RATIO = 4.0

#: Honest error bar for the heuristic (documented, surfaced in responses).
ERROR_MARGIN_PCT = 10


@dataclass(frozen=True)
class ModelPrice:
    """Input price and context-window size for one tracked model."""

    model: str
    family: str
    input_per_1k_usd: float
    context_window_k: int


# AuditSkill's own maintained price table: input $/1k tokens and context
# window (in thousands of tokens).  Self-contained — no external feed.
# Hand-verified as_of the date below; update this table when prices change.
_FALLBACK_AS_OF = "2026-07-10"
_FALLBACK_PRICES: dict[str, ModelPrice] = {
    "claude-fable-5": ModelPrice("claude-fable-5", "claude", 0.01, 1000),
    "claude-opus-4-8": ModelPrice("claude-opus-4-8", "claude", 0.005, 1000),
    "claude-sonnet-5": ModelPrice("claude-sonnet-5", "claude", 0.003, 1000),
    "claude-haiku-4-5": ModelPrice("claude-haiku-4-5", "claude", 0.001, 200),
    "gemini-3.1-pro-preview": ModelPrice("gemini-3.1-pro-preview", "gemini", 0.002, 1000),
    "gpt-4o": ModelPrice("gpt-4o", "openai", 0.0025, 128),
    "gpt-4o-mini": ModelPrice("gpt-4o-mini", "openai", 0.00015, 128),
    "o3": ModelPrice("o3", "openai", 0.002, 200),
    "meta-llama/Llama-3.3-70B-Instruct-Turbo": ModelPrice(
        "meta-llama/Llama-3.3-70B-Instruct-Turbo", "llama", 0.00088, 128
    ),
}

#: Models we report on.  A curated, self-contained set — the response shape
#: stays stable and never depends on an outside service.
TRACKED_MODELS: tuple[str, ...] = tuple(sorted(_FALLBACK_PRICES))


# ---------------------------------------------------------------------------
# Price table (in-memory, self-contained — no background refresh)
# ---------------------------------------------------------------------------


class PriceCache:
    """In-memory price table.  Reads are synchronous and never block.

    The table is self-contained (see :data:`_FALLBACK_PRICES`). There is no
    background refresh or request-time outside call, so an audit is
    deterministic for a fixed service version and price snapshot.
    """

    def __init__(self) -> None:
        self._prices: dict[str, ModelPrice] = dict(_FALLBACK_PRICES)
        self._source: str = f"AuditSkill built-in price table (as_of {_FALLBACK_AS_OF})"

    @property
    def prices(self) -> dict[str, ModelPrice]:
        """Return the current table (shallow copy — entries are frozen)."""
        return dict(self._prices)

    @property
    def source(self) -> str:
        """Human-readable provenance string for the price table."""
        return self._source


#: Process-wide singleton.
price_cache = PriceCache()


# ---------------------------------------------------------------------------
# Public helpers
# ---------------------------------------------------------------------------


def known_models() -> list[str]:
    """Return the sorted list of tracked model IDs."""
    return sorted(price_cache.prices)


def estimate_for_models(
    ascii_chars: int,
    non_ascii_chars: int,
    model: str | None = None,
) -> tuple[list[PerModelCost], str]:
    """Estimate token count, input cost, and window share per tracked model.

    Args:
        ascii_chars: Number of ASCII characters in the document.
        non_ascii_chars: Number of non-ASCII characters (≈1 token each).
        model: Optional model ID to narrow the result to a single entry.

    Returns:
        ``(per_model, price_source)`` where *per_model* is sorted by model ID
        for determinism.

    Raises:
        ValueError: If *model* is not a tracked model (message lists the
            tracked IDs — self-healing error style).
    """
    prices = price_cache.prices

    if model is not None and model not in prices:
        raise ValueError(
            f"Unknown model {model!r}. Tracked models: {', '.join(sorted(prices))}. "
            "Fix: omit 'model' to get every tracked model, or pick one from the list."
        )

    selected = [model] if model else sorted(prices)
    out: list[PerModelCost] = []
    for mid in selected:
        p = prices[mid]
        ratio = _FAMILY_RATIOS.get(p.family, _DEFAULT_RATIO)
        tokens = max(1, round(ascii_chars / ratio) + non_ascii_chars)
        cost = round(tokens / 1000.0 * p.input_per_1k_usd, 6)
        window_pct = round(tokens / (p.context_window_k * 1000.0) * 100, 2)
        out.append(
            PerModelCost(
                model=mid,
                tokens=tokens,
                input_cost_usd=cost,
                window_pct=window_pct,
            )
        )
    return out, price_cache.source
