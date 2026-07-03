"""Model-aware context-cost pricing for AuditSkill.

Answers the question at the heart of skill selection: *what does loading
this SKILL.md actually cost on my model — in tokens, in dollars, and as a
share of my context window?*

Prices come from the **API Pricing Look-Up** skill in the same NANDA Town
registry (one registry skill enriching the audit of another).  A built-in
fallback table guarantees the feature works even when that service is down.

Design invariants:

- **No audit request ever waits on the network for prices.**  Estimates
  read an in-memory snapshot only.  The snapshot is refreshed by a
  background task (on startup, then every 24 h) through the SSRF-safe
  client.  ``safe_static`` mode therefore stays strictly offline.
- **Deterministic.**  Given the same text and the same price snapshot,
  the output is byte-identical.  Token counts are calibrated heuristics
  (chars-per-token per model family), not tokenizer calls — the agent is
  making a load/skip decision, not doing accounting.  The estimate error
  is surfaced honestly via ``error_margin_pct``.
"""

from __future__ import annotations

import asyncio
import logging
from dataclasses import dataclass

from auditskill.api.models import PerModelCost

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Configuration
# ---------------------------------------------------------------------------

#: The registry skill we source live prices from (GET, SSRF-guarded).
PRICING_SKILL_URL = (
    "https://pricing-scraper-production-cd54.up.railway.app/pricing/models"
)

_REFRESH_INTERVAL_S = 24 * 60 * 60  # daily — the source itself scrapes daily
_INITIAL_RETRY_S = 15 * 60          # retry sooner if the first refresh fails

#: Calibrated chars-per-token ratios for the ASCII portion of a document.
#: Non-ASCII characters are counted ~1 token each (see auditor heuristic).
_FAMILY_RATIOS: dict[str, float] = {
    "claude": 3.8,
    "gemini": 4.2,
    "llama": 4.0,
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


# Built-in fallback: live snapshot of the API Pricing Look-Up skill taken
# 2026-07-03.  Used until the first successful background refresh, and kept
# whenever a refresh fails — prices may age, never disappear.
_FALLBACK_AS_OF = "2026-07-03"
_FALLBACK_PRICES: dict[str, ModelPrice] = {
    "claude-fable-5": ModelPrice("claude-fable-5", "claude", 0.01, 1000),
    "claude-opus-4-8": ModelPrice("claude-opus-4-8", "claude", 0.005, 1000),
    "claude-sonnet-4-6": ModelPrice("claude-sonnet-4-6", "claude", 0.003, 1000),
    "claude-haiku-4-5": ModelPrice("claude-haiku-4-5", "claude", 0.001, 200),
    "gemini-3": ModelPrice("gemini-3", "gemini", 0.014, 1000),
    "meta-llama/Llama-3.3-70B-Instruct-Turbo": ModelPrice(
        "meta-llama/Llama-3.3-70B-Instruct-Turbo", "llama", 0.00088, 128
    ),
}

#: Models we report on.  The live refresh updates prices/windows for these
#: IDs when the pricing skill knows them; it never adds or removes entries,
#: so the response shape stays stable and curated.
TRACKED_MODELS: tuple[str, ...] = tuple(sorted(_FALLBACK_PRICES))


# ---------------------------------------------------------------------------
# Price cache (in-memory snapshot + background refresh)
# ---------------------------------------------------------------------------


class PriceCache:
    """In-memory price snapshot.  Reads are synchronous and never block."""

    def __init__(self) -> None:
        self._prices: dict[str, ModelPrice] = dict(_FALLBACK_PRICES)
        self._source: str = f"built-in table (as_of {_FALLBACK_AS_OF})"

    # -- read side (hot path) -------------------------------------------

    @property
    def prices(self) -> dict[str, ModelPrice]:
        """Return the current snapshot (shallow copy — entries are frozen)."""
        return dict(self._prices)

    @property
    def source(self) -> str:
        """Human-readable provenance string for the current snapshot."""
        return self._source

    # -- write side (background task only) ------------------------------

    async def refresh(self) -> bool:
        """Fetch live prices via the SSRF-safe client; keep old data on failure.

        Returns ``True`` when the snapshot was updated from the live feed.
        Never raises.
        """
        # Imported here so this module stays stdlib-importable in harnesses.
        from auditskill.core.ssrf_guard import safe_request

        try:
            resp = await safe_request("GET", PRICING_SKILL_URL)
            payload = resp.json()
            models = payload.get("all_models", [])
            as_of = str(payload.get("as_of") or payload.get("scraped_at") or "?")[:10]
            if not isinstance(models, list) or not models:
                raise ValueError("pricing feed returned no models")

            updated = dict(self._prices)
            hits = 0
            for entry in models:
                mid = entry.get("model")
                if mid not in updated:
                    continue  # curated set only — never grow the response
                price = entry.get("input_per_1k_usd")
                window = entry.get("context_window_k")
                if not isinstance(price, (int, float)) or price < 0:
                    continue
                if not isinstance(window, (int, float)) or window <= 0:
                    continue
                updated[mid] = ModelPrice(
                    model=mid,
                    family=updated[mid].family,
                    input_per_1k_usd=float(price),
                    context_window_k=int(window),
                )
                hits += 1

            if hits == 0:
                raise ValueError("pricing feed had no tracked models")

            self._prices = updated
            self._source = f"API Pricing Look-Up (NANDA Town), as_of {as_of}"
            logger.info("Price cache refreshed: %d tracked models (as_of %s)", hits, as_of)
            return True
        except Exception as exc:  # noqa: BLE001 — degrade, never break audits
            logger.warning("Price refresh failed (keeping previous snapshot): %s", exc)
            return False

    async def refresh_loop(self) -> None:
        """Background loop: refresh now, then daily.  Cancelled on shutdown."""
        while True:
            ok = await self.refresh()
            try:
                await asyncio.sleep(_REFRESH_INTERVAL_S if ok else _INITIAL_RETRY_S)
            except asyncio.CancelledError:
                raise


#: Process-wide singleton, wired into the app lifespan in ``api.main``.
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
