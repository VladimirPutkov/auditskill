# AUDIT_REPORT.md — AuditSkill (historical, all findings resolved)

> **Status: ALL FINDINGS RESOLVED.** Original audit: 2 July 2026.
> Fixes confirmed by `pytest -q` → 33/33 passed (2 July 2026 22:59 ET).
>
> This file is retained as documentation of the audit process.
> For current status, see GAP_ANALYSIS.md.

---

## Summary

The original audit identified **11 critical (C1–C11)**, 6 high (H1–H6), 5 medium (M1–M5), and 5 low (L1–L5) findings across the codebase. The root cause was a single systemic issue: `models.py` was updated to a clean Pydantic v2 schema but the calling modules (`auditor`, `endpoint_tester`, `metadata_checker`, `certifier`, `store`) still used the old field names.

**All critical and high findings have been resolved:**

| Finding | Issue | Status |
|---|---|---|
| C1–C11 | Contract mismatch `run_audit` ↔ `models.py` ↔ `quality_benchmarks` ↔ `certifier` ↔ `store` | ✅ Fixed, 33 tests pass |
| H1 | `/verify` always returned `valid=false` (double signature strip) | ✅ Fixed (test: `test_certificate_verify_round_trip`) |
| H2 | IP-pinning broke TLS/SNI for HTTPS targets | ✅ Fixed (`sni_hostname` extension in `_PinnedIPTransport`) |
| H3 | Missing SKILL.md and README.md | ✅ Written, with /discover endpoint documented |
| H4 | False-positive on legitimate security skills | ✅ Fixed (descriptive-section guard + inline-code stripping; test: `test_benign_security_skill_no_false_positive`) |
| H5 | `MAX_ENDPOINTS` not enforced | ✅ Enforced in endpoint_tester |
| H6 | No global audit timeout | ✅ Added `_GLOBAL_LIVENESS_TIMEOUT = 25s` in auditor |

### Tests covering critical paths

```
test_verdict_boundaries[100-PASS_BASIC_AUDIT]
test_verdict_boundaries[85-PASS_BASIC_AUDIT]
test_verdict_boundaries[84-PASS_WITH_WARNINGS]
test_verdict_boundaries[70-PASS_WITH_WARNINGS]
test_verdict_boundaries[69-REQUIRES_HUMAN_REVIEW]
test_verdict_boundaries[40-REQUIRES_HUMAN_REVIEW]
test_verdict_boundaries[39-FAILS_BASIC_AUDIT]
test_verdict_severity_gating[critical-FAILS_BASIC_AUDIT]
test_verdict_severity_gating[high-REQUIRES_HUMAN_REVIEW]
test_verdict_severity_gating[medium-PASS_WITH_WARNINGS]
test_renormalisation_no_phantom_penalty
test_metadata_alone_cannot_fail
test_ssrf_blocks_dangerous_targets[12 targets incl. decimal-encoded loopback]
test_signature_round_trip
test_certificate_verify_round_trip
test_benign_security_skill_no_false_positive
test_parser_plain_markdown
test_good_skill_passes
test_evil_skill_fails
test_benign_security_skill_passes_end_to_end
test_state_changing_methods_never_executed
```

---

*For the original detailed findings table, see git history.*
