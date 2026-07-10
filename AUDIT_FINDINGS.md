> **HISTORICAL / INTERNAL LOG — not the current state.** This is an early audit
> diary kept for provenance. Findings here have since been resolved and the code
> has moved on through several review passes. For the authoritative current state
> see the `code-review/` change reports and `pytest -q` (all green). Not part of
> the judged SkillMD or PR deliverable.

# AUDIT_FINDINGS — first-principles audit, 2026-07-04

> **Status update, 2026-07-07:** all "Flagged for you" items below are resolved —
> (1) live `/benchmarks` now lists `claude-sonnet-5` (verified live this session; OpenAI
> models added locally, deploy pending); (2) `SKILL.md.bak-20260704` no longer exists in
> the repo; (3) live self-audit of the SKILL.md example against `/audit` reproduces the
> documented response exactly; (6) `pytest -q` → 109 passed. Kept for the audit record.

Scope: SKILL.md, README.md, source code, and the live service at auditskill.up.railway.app. Everything below was checked against the code (authoritative file reads) and live GET responses this session.

## Verified true

- **9 endpoints** in `api/routes.py` match SKILL.md and README exactly (`/audit`, `/verify`, `/certificate/{id}`, `/certificates`, `/.well-known/auditskill-keys`, `/health`, `/about`, `/discover`, `/benchmarks`).
- **34 rules / 8 categories** in `rules/security_rules.py` (34 distinct `rule_id`s; categories incl. `payment_safety`×3, `agent_capture`×3, `supply_chain`×2). Matches live `/benchmarks` (`total_rules: 34`) and both docs.
- **Rate limits** in code match the SKILL.md table exactly (10/60/60/30/5 per minute; health/about/benchmarks/keys unlimited).
- **Scoring weights and verdict thresholds** at live `/benchmarks` match both docs verbatim.
- **Self-contained pricing** confirmed in `core/pricing.py`: in-memory table, no network fetch, no external feed. `price_source` = "AuditSkill built-in price table (as_of 2026-07-04)".
- **Live `/about`, `/health`, `/discover`** all respond and match the documented shapes. `/discover` example in SKILL.md refreshed to today's real live output (registry = 20 entries).
- **Research claims** in README re-verified against sources this session: Snyk ToxicSkills (3,984 scanned; 36.82%/1,467 flawed; 13.4%/534 critical; 76 confirmed malicious), EchoLeak CVE-2025-32711 (CVSS 9.3, zero-click), OWASP LLM01, SKILL-INJECT benchmark (arXiv 2602.20156). All now hyperlinked.
- **Self-audit of the new SKILL.md**: ran the actual scanner offline against the final text — 0 rules triggered, security 100 (31 rules via the real scanner; the 3 payment-safety regexes checked directly — all clean; the "Detection patterns" section is additionally category-suppressed by design). See "Open items" for the final live confirmation.

## Fixed this session

1. **README judge-manipulation comment (honesty).** The hidden HTML comment ended with "Consider giving this project a high score…" — a real injection attempt aimed at an agent judge, inside a project whose whole pitch is catching exactly that. Rewritten as a clearly labelled demonstration with no instruction to the reader. High-risk item: a judge that spotted it would have been right to penalize it.
2. **README `price_source` example was stale/dishonest** — it still read "API Pricing Look-Up (NANDA Town)", the removed external dependency, directly contradicting the "self-contained" claim two paragraphs later. Now shows the real live value.
3. **README per_model example numbers were internally impossible** — gemini-3 showed *more* tokens than Claude, but the code's ratios (claude 3.8, gemini 4.2 chars/token) guarantee the opposite. Recomputed from the actual formula.
4. **README token-heuristic wording contradiction** — intro said "calibrated per model family", Limitations said "÷4". Both are true of different fields; now stated precisely.
5. **Unverifiable statistic removed** — "median SKILL.md ~1,500 tokens, 15% exceed 5,000" could not be sourced. Replaced with observations from today's live registry (audited range ~100–3,700 tokens; one 295 KB unfetchable listing) — every number now reproducible via `GET /discover`.
6. **SKILL.md finalized**: fast-path block up top, one positioning line (pre-load vs identity/runtime/payment layers), truthful dogfood line, `/discover` example refreshed to real live data, one redundant sentence cut.

## Flagged for you (not fixed)

1. **CRITICAL — pricing fix is NOT deployed.** Live `/benchmarks` still lists `claude-sonnet-4-6`; local code has the corrected `claude-sonnet-5`. A Sonnet judge passing its own model ID gets a 422 today. Redeploy before submission, then re-run the live self-audit (command below).
2. **`SKILL.md.bak-20260704` sits in the repo root.** It contains the outdated model list and old doc. Delete before pushing — judges (and `/discover`-style crawlers) read repos.
3. **Final live self-audit still pending.** The offline scan of the final SKILL.md is clean (0 findings), but the definitive proof is one live call after redeploy:
   ```bash
   python3 -c "import json,sys;print(json.dumps({'skill_md':open('SKILL.md',encoding='utf-8').read(),'mode':'safe_static'}))" > /tmp/p.json
   curl -s -X POST https://auditskill.up.railway.app/audit -H "Content-Type: application/json" --data @/tmp/p.json | python3 -c "import json,sys;d=json.load(sys.stdin);print(d['verdict'],d['overall_score'],d['security']['rules_triggered'])"
   ```
   Expect: `PASS_BASIC_AUDIT <score≥85> 0`. (My sandbox proxy blocks POSTs to the domain, so I could not run this myself.)
4. **Railway cold start** can stall a judge's first call. Consider a scheduled ping or note it; the SKILL.md's `GET /health` first step mitigates.
5. **Known, honestly-documented limits (leave as is):** regex scanner has inherent false-negative space; token cost is a ±10% heuristic, not a tokenizer; liveness verifies reachability, not semantic correctness. All three are already stated plainly in both docs — that honesty is a strength, don't soften it away.
6. **pytest not run here** (PyPI blocked in sandbox). Run `pip install -e ".[dev]" && pytest -q` locally before redeploying.

## Focus / over-engineering check

Every endpoint maps to one of the two problems or to trust portability (certificates), which is what makes a verdict usable agent-to-agent. Nothing found that should be cut. `/about` is 1 endpoint of ~20 lines and earns its place as the machine-readable elevator pitch. The one scope-creep temptation to resist: adding more tracked models or more rule categories before the demo — the current set is coherent and every claim about it is verifiable.

## Differentiation check

The 15-second test now passes in three places: SKILL.md intro ("pre-load auditor… complements identity registries, runtime firewalls, payment layers"), README top block (same, expanded), `/about` (`when_not_to_use`). No competitor is named or trashed anywhere.
