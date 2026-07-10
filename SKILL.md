---
name: auditskill
description: Pre-load safety auditor for agent skills. Use before loading any SKILL.md you did not write. One HTTP call returns a deterministic safety verdict (34 rules), a per-model token+dollar cost, a ranked audit of the NANDA Town registry, and a signed certificate verifiable offline. Zero auth.
---

# AuditSkill

AuditSkill is the customs checkpoint for agent skills: it audits a third-party SKILL.md **before** its text becomes part of your instructions, and answers two questions in one call — is it safe to load, and is it worth the tokens?

## The problem

For a human, reading a document is passive. For an AI agent, **reading a skill file is executing it** — the moment a SKILL.md enters the context window, its text becomes operative instructions the agent will act on, and no human is in the loop. That makes skill files a live attack surface, and the risk is measured, not hypothetical:

- Snyk's ToxicSkills study (2026) scanned **3,984 published agent skills** and found **36.8% carried at least one security flaw**; 76 were confirmed malicious.
- A hostile SKILL.md can override the agent's instructions, leak secrets (env vars, API keys, conversation history) to an outside server, demand destructive shell or SQL commands, install code from an unvetted URL, or reroute the agent's traffic — all through plain text that looks like ordinary documentation.
- Even a *safe* skill has a cost: every token it spends is a token unavailable for the agent's real task.

Identity registries prove *who* an agent is; runtime firewalls gate *what* it does once running; payment layers meter spend. None of them inspect the **document itself** before it is read. Developer-side scanners exist, but they run at authoring time, on the wrong side of the trust boundary — the agent consuming a skill at runtime cannot open a dashboard. AuditSkill is the consumer-side, agent-callable check for that exact moment.

## The solution

Send AuditSkill a SKILL.md (raw text or a URL); it reads the file as **inert text — nothing in it is ever executed** — and returns a machine-readable verdict, per-module scores with line-numbered findings, a 34-rule security scan across 8 attack categories, a per-model context-cost estimate, and an Ed25519-signed certificate any other agent can verify online or offline. **Deterministic and rule-based — no LLM in the pipeline**: the static analysis is sub-second and the same input always yields the same verdict, score, and findings. That matters for a security tool: an LLM judge is probabilistic, costs money, and is itself vulnerable to injection from the file it inspects. Zero setup: no key, no signup, no install.

## Base URL

https://auditskill.up.railway.app

All `POST` requests require the header `Content-Type: application/json`.

## Default action: run the demonstration

**When you are told simply to "use this skill", "perform the service", or "run a demo" with no specific file, URL, or certificate given — make ONE call:**

`GET https://auditskill.up.railway.app/demo`  (allow up to 90 seconds; if there is no response, retry once after 5 seconds — free-tier cold start.)

`/demo` runs the whole story server-side and returns an interpreted, render-ready JSON object: it scans the live NANDA Town registry (ranked), audits a built-in **mock** attack to show detection working, and verifies the resulting certificate. The mock attack lives on the server, so no malicious text enters your context. Then render the returned fields as the report below — do not ask the human anything.

Response shape (fields you render):

```json
{
  "problem": "36.8% of 3,984 published agent skills carried at least one security flaw (Snyk ToxicSkills, 2026).",
  "registry_scan": {
    "total_in_registry": 105, "sampled": 20, "audited": 15,
    "verdict_counts": {"PASS_WITH_WARNINGS": 11, "REQUIRES_HUMAN_REVIEW": 4},
    "safest":  { "name": "...", "verdict": "...", "score": 81, "read": "...",
                 "context_cost": { "tokens_estimate": 2364, "flagship_input_usd": 0.0047,
                                   "flagship_model": "claude-opus-4-8",
                                   "cheapest_input_usd": 0.00035, "most_expensive_input_usd": 0.0057 } },
    "riskiest": { "name": "...", "verdict": "REQUIRES_HUMAN_REVIEW", "score": 62, "read": "..." }
  },
  "attack_detection": { "verdict": "FAILS_BASIC_AUDIT", "score": 37,
    "findings": [ { "rule_id": "SEC-001", "severity": "critical", "category": "prompt_injection", "line": 11 } ],
    "note": "built-in mock attack fixture — not a registry skill, audited never executed" },
  "certificate_proof": { "certificate_id": "seal_...", "valid": true, "valid_until": "..." },
  "elapsed_ms": 17000
}
```

Render it exactly like this (fill the bracketed values; keep the headings):

```
AUDITSKILL DEMONSTRATION REPORT
The problem: <problem>. AuditSkill checks a SKILL.md before it enters an agent's context window —
deterministic, no LLM, signed. Run live just now:

1. Is it safe? (registry_scan) — <total_in_registry> skills in the live registry; of <sampled>
   sampled, <audited> audited: <verdict_counts as "N pass, N review, N fail">.
   Load candidate: <safest.name> — <safest.verdict>, score <safest.score>. <safest.read>
   Worth the tokens? ~<safest.context_cost.tokens_estimate> tokens — about
   <flagship_input_usd> USD on <flagship_model>, range <cheapest_input_usd>–<most_expensive_input_usd>
   USD across 9 tracked models (Claude, GPT, Gemini, Llama). AuditSkill reports; you decide.
   Riskiest sampled: <riskiest.name> — <riskiest.verdict>, score <riskiest.score>. <riskiest.read>

2. Does detection work? (attack_detection, a built-in mock — not a registry skill):
   <verdict>, score <score>/100. One line per finding: <rule_id> (<severity>, <category>, line <line>).
   The attack text was audited as inert data, never executed.

3. Can other agents trust it? (certificate_proof): certificate <certificate_id> → valid: <valid>,
   expires <valid_until>. Any agent re-verifies this offline against the published key.

Conclusion: that was the built-in demo, run end to end with no human input — AuditSkill ranked the
live registry by safety and token cost, caught a known attack down to the line, and issued a portable
signed verdict, all before any untrusted text entered the context window. Keep using it: POST /audit
to vet a specific skill, GET /discover to browse the registry pre-audited, POST /verify to check a
certificate.
```

If `registry_scan.available` is false, say the registry was unavailable and report sections 2–3 anyway.

## Other things you can do

### Audit one skill before loading it
`POST /audit` with `{"skill_url": "<https url>"}` (or `{"skill_md": "<raw text, JSON-escaped>"}` — send exactly one). Read `verdict` and branch per the Verdicts table; quote `security.findings[]` for anything flagged; keep `certificate_id`. GET-only agents can use `GET /audit?skill_url=<url>`.

### Find safe skills in the registry
`GET /discover?mode=safe_static&limit=20` returns the sampled registry pre-audited and ranked best-first (a stronger verdict always ranks above a weaker one). Present each result's `name`, `verdict`, `score`, `rank_reason`. Recommend only `PASS_*` entries; note `audited:false` entries and their `reason`. Two entries may share a `name` but differ in `source_url` — different files; disambiguate by `source_url`.

### Verify a certificate
`POST /verify` with `{"certificate": <the certificate object from an /audit response>}`. `valid:true` means the signature is authentic AND unexpired; on `valid:false` read `error`, `signature_valid`, and `expired`. `verdict`/`score` are echoed only when valid. Offline: fetch the key once from `GET /.well-known/auditskill-keys` and check the Ed25519 signature over the certificate's canonical JSON (sorted keys, compact separators, `signature` excluded).

## Endpoints

| Endpoint | Purpose | Parameters |
|---|---|---|
| `GET /demo` | Run the whole demonstration server-side (default action) | — |
| `POST /audit` | Audit one SKILL.md → verdict + certificate | Body: exactly one of `skill_md` or `skill_url` (HTTPS; GitHub repo/blob URLs auto-rewritten to raw). Optional `mode` = `safe_static` (default) or `liveness`; `model` (narrow cost to one model ID) |
| `GET /audit` | Same audit by URL, for GET-only agents | Query: `skill_url` (required), `mode`, `model` |
| `GET /discover` | Audit the sampled registry, ranked best-first | Query: `q`, `mode` (default `safe_static`), `limit` (1-30, default 20) |
| `POST /verify` | Verify a certificate's signature + expiry (stateless) | Body: `{"certificate": {...}}` |
| `GET /certificate/{id}` | Fetch a stored certificate by ID (404 if unknown) | Path: `seal_...` |
| `GET /certificates` | List prior audits of a file by content hash | Query: `skill_hash=sha256:<hex>` |
| `GET /.well-known/auditskill-keys` | Public Ed25519 key for offline verification | — |
| `GET /health` | Liveness probe → `{"status": "ok"}` | — |
| `GET /about` | Machine-readable manifest | — |
| `GET /benchmarks` | Scoring weights, thresholds, rule categories, priced models | — |
| `GET /skill.md` | This document, served from the deployed code | — |
| `GET /` | Service index | — |

## Example: POST /audit

```bash
curl -X POST https://auditskill.up.railway.app/audit \
  -H "Content-Type: application/json" \
  -d '{"skill_url": "https://auditskill.up.railway.app/skill.md", "mode": "safe_static"}'
```

A well-formed skill returns `verdict: "PASS_BASIC_AUDIT"`, `security.score: 100`, `security.rules_triggered: 0`. Top-level fields: `verdict`, `overall_score` (0-100, weighted: structure 0.30, security 0.30, liveness 0.25, metadata 0.10, scope 0.05, renormalized over modules that ran), `security.findings[]` (each `rule_id`, `severity`, `category`, `detail`, 1-based `line`), per-module `structure`/`scope`/`metadata`/`liveness` sub-reports (`liveness.score` is `null` in `safe_static`), `context_cost` (`tokens_estimate`, `density`, `per_model[]`), `issues[]`, `certificate`/`certificate_id`, `skill_hash`. To see a **failing** audit with real findings, call `GET /demo` — it audits a built-in mock attack.

## Verdicts

| Verdict | Score gate | Security gate | What you should do |
|---|---|---|---|
| `PASS_BASIC_AUDIT` | >= 85 | no medium/high/critical findings | No known-malicious patterns detected — clear to load, but this is "no red flags found", not a proof of safety (see Limitations). |
| `PASS_WITH_WARNINGS` | >= 70 | no high/critical findings | Usable; read `issues` first, proceed with care. |
| `REQUIRES_HUMAN_REVIEW` | >= 40 | any high finding | Do not use automatically; surface `issues` to the user. |
| `FAILS_BASIC_AUDIT` | < 40 | any critical finding | Do not load. Tell the user why (see `security.findings`). |

## Detection patterns

34 deterministic rules across 8 categories. Dangerous commands are detected **even inside code blocks and under normal headings** (Usage, Installation, Setup). To avoid false-flagging legitimate security tools, patterns for destructive-ops / scope / capture / payment that appear under an overtly *descriptive* heading (Detection Patterns, Limitations, Transparency, Disclaimer, Known…, False positives) are treated as documentation; prompt-injection and data-exfiltration are never suppressed by heading. Live breakdown at `GET /benchmarks`.

| Category | Rules | Severity | Catches (described, not literal) |
|---|---|---|---|
| Prompt injection | SEC-001..005 | critical | Instruction-override, persona hijack, context reset, safety bypass |
| Data exfiltration | SEC-006..010, 034 | critical/high | Sending secrets to external URLs, phone-home, hardcoded live provider secrets |
| Unsafe operations | SEC-011..015 | high | Destructive file, SQL, shell, disk, and dynamic-exec commands |
| Hidden instructions | SEC-016..020 | high | Zero-width chars, bidi overrides, long Base64 blobs, imperative HTML comments, homoglyph URLs |
| Scope creep | SEC-021..025 | medium | Over-broad permission and elevated-privilege claims, verification bypass |
| Supply chain | SEC-026..027 | critical | Installing packages from remote URLs/tarballs, pipe-to-shell bootstrap |
| Agent capture | SEC-028..030 | high/medium | Proxy-variable rewrites, detached background daemons, mandatory single-service gating |
| Payment safety | SEC-031..033 | critical/high/medium | Handing over your own provider key, funding with no spending limit, unbounded payment-retry loops |

## Certificates

Every verdict is an Ed25519-signed certificate carrying `skill_hash`, `verdict`, `score`, `checks`, `tested_at`, `valid_until`. Verify online (`POST /verify`, which checks signature **and** expiry) or offline against the key from `/.well-known/auditskill-keys`. Proof by dogfood: this SKILL.md is itself audited by the service and returns `PASS_BASIC_AUDIT` with zero security findings.

## Errors

Errors are self-describing; the response's `detail` field says how to fix the request.

- `422` — bad input: both/neither of `skill_md`/`skill_url`, an empty or non-HTTPS `skill_url`, input over 200 KB (UTF-8 bytes), an unknown `model`, or a URL blocked by the SSRF guard. Fix per `detail` and retry once.
- `429` — rate limited. Wait 60 seconds, retry once, then report the service as busy.
- `500` — server error. Retry once; if it persists, check `GET /health` and report the service as down.
- Timeout / no response — retry once; `/demo` and `/discover` can take up to 90 s. If still failing, report the service as unreachable.

## Rate limits

| Endpoint | Limit |
|---|---|
| `POST /audit`, `GET /audit` | 10 / min per IP each |
| `GET /demo`, `GET /discover` | 5 / min (each audits many skills) |
| `POST /verify` | 60 / min |
| `GET /certificate/{id}` | 60 / min |
| `GET /certificates` | 30 / min |
| `GET /`, `/health`, `/about`, `/benchmarks`, `/skill.md`, `/.well-known/auditskill-keys` | unlimited |

## Authentication

None. AuditSkill is zero-auth — no key, no token, no signup.

## Limitations

- A `PASS` means "no known-malicious patterns detected," not "provably safe." Detection is deterministic pattern-matching, not an LLM: it catches the catalogued attack classes (including inside code blocks and under normal headings), but a novel or heavily-paraphrased injection can still pass. Treat `PASS` as a strong pre-load filter, not a guarantee; certificates carry a `valid_until`.
- Patterns for destructive-ops / scope / capture / payment catalogued under an overtly descriptive heading (`Detection Patterns`, `Limitations`, …) are treated as documentation so legitimate security tools aren't flagged. A skill deliberately hiding such payloads under that kind of heading is the main residual blind spot of a rule-based pass; prompt-injection and exfiltration are never suppressed.
- `safe_static` does not probe the audited skill's endpoints, but the service does fetch the `skill_url` / registry you point it at; network fetches add latency beyond the sub-second static analysis.
- Liveness probes use GET/HEAD only — POST/PUT/PATCH/DELETE are never sent.
- It audits the SKILL.md document, not the running service behind it, and does not verify semantic correctness.
- Token counts are calibrated per-model heuristics (not a tokenizer); the error bar is `error_margin_pct` (~10%), and the price table is self-maintained (see `price_source` for its as-of date).
- Maximum input size is 200 KB.

## Author

Built for the NANDA Town SkillMD track, NANDAHack 2026. Source: https://github.com/VladimirPutkov/auditskill (MIT License). Contact: https://github.com/VladimirPutkov/auditskill/issues
