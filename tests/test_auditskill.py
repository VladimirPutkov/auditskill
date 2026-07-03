"""End-to-end and unit tests for AuditSkill.

Run with:  pytest -q   (needs the runtime deps: pydantic, httpx, pynacl,
aiosqlite — installed via `pip install -e .`).

These tests assert the security-critical behaviours the audit called out:
SSRF blocking, score renormalisation, verdict boundaries, Ed25519 signature
round-trip, and the false-positive guard on legitimate security skills.
"""
from __future__ import annotations

import pathlib

import pytest

from auditskill.core import parser, security_scanner
from auditskill.core.auditor import run_audit
from auditskill.core.crypto import (
    generate_keypair,
    hash_text,
    sign_document,
    verify_signature,
)
from auditskill.core.ssrf_guard import check_url
from auditskill.core.certifier import create_certificate, verify_certificate
from auditskill.rules.quality_benchmarks import (
    calculate_overall_score,
    determine_verdict,
)

FIX = pathlib.Path(__file__).parent / "fixtures"


def _read(name: str) -> str:
    return (FIX / name).read_text(encoding="utf-8")


# --------------------------------------------------------------------------
# Verdict boundaries & renormalisation
# --------------------------------------------------------------------------

@pytest.mark.parametrize("score,expected", [
    (100, "PASS_BASIC_AUDIT"),
    (85, "PASS_BASIC_AUDIT"),
    (84, "PASS_WITH_WARNINGS"),
    (70, "PASS_WITH_WARNINGS"),
    (69, "REQUIRES_HUMAN_REVIEW"),
    (40, "REQUIRES_HUMAN_REVIEW"),
    (39, "FAILS_BASIC_AUDIT"),
])
def test_verdict_boundaries(score, expected):
    assert determine_verdict(score, []) == expected


@pytest.mark.parametrize("sev,expected", [
    ("critical", "FAILS_BASIC_AUDIT"),
    ("high", "REQUIRES_HUMAN_REVIEW"),
    ("medium", "PASS_WITH_WARNINGS"),
])
def test_verdict_severity_gating(sev, expected):
    assert determine_verdict(90, [{"severity": sev}]) == expected


def test_renormalisation_no_phantom_penalty():
    # Absent liveness module must not cost points.
    full = calculate_overall_score(
        {"structure": 90, "security": 90, "liveness": 90, "metadata": 90, "scope": 90}
    )
    without_liveness = calculate_overall_score(
        {"structure": 90, "security": 90, "liveness": None, "metadata": 90, "scope": 90}
    )
    assert full == without_liveness == 90


def test_metadata_alone_cannot_fail():
    score = calculate_overall_score(
        {"structure": 100, "security": 100, "liveness": 100, "metadata": 0, "scope": 100}
    )
    assert score >= 85


# --------------------------------------------------------------------------
# SSRF guard
# --------------------------------------------------------------------------

@pytest.mark.parametrize("url", [
    "http://127.0.0.1/",
    "http://169.254.169.254/latest/meta-data/",  # cloud metadata
    "http://10.0.0.5/", "http://192.168.1.1/", "http://172.16.0.1/",
    "http://[::1]/", "http://0.0.0.0/", "http://100.64.0.1/",
    "http://metadata.google.internal/", "http://localhost/", "http://x.internal/",
    "ftp://127.0.0.1/",
    "http://2130706433/",  # decimal-encoded 127.0.0.1
])
async def test_ssrf_blocks_dangerous_targets(url):
    result = await check_url(url)
    assert result.safe is False, f"SSRF guard let through {url}"


# --------------------------------------------------------------------------
# Ed25519 signature round-trip (the /verify contract)
# --------------------------------------------------------------------------

def test_signature_round_trip():
    priv, pub = generate_keypair()
    doc = {"a": 1, "b": "hello", "nested": {"x": [1, 2, 3]}}
    sig = sign_document(doc, priv)
    assert verify_signature(doc, sig, pub) is True
    # Tamper → invalid
    doc["a"] = 2
    assert verify_signature(doc, sig, pub) is False


def test_certificate_verify_round_trip(monkeypatch):
    priv, pub = generate_keypair()
    # certifier reads the key from module state at import; patch it.
    import auditskill.core.certifier as cert_mod
    monkeypatch.setattr(cert_mod, "PRIVATE_KEY", priv)
    cert = create_certificate(
        skill_name="x", skill_hash=hash_text("x"), mode="safe_static",
        overall_score=90, verdict="PASS_BASIC_AUDIT",
        structure_score=90, liveness_score=None, security_score=90,
        scope_score=90, metadata_score=80,
    )
    d = cert.model_dump()
    assert d["signature"].startswith("ed25519:")
    assert verify_certificate(d, pub) is True
    d["score"] = 1  # tamper
    assert verify_certificate(d, pub) is False


# --------------------------------------------------------------------------
# False-positive guard on a legitimate security skill
# --------------------------------------------------------------------------

def test_benign_security_skill_no_false_positive():
    report = security_scanner.scan(_read("benign_security_skill.md"))
    sev = {f.severity for f in report.findings}
    assert "critical" not in sev and "high" not in sev, [
        (f.rule_id, f.severity, f.detail) for f in report.findings
    ]


# --------------------------------------------------------------------------
# Parser — plain-markdown (platform standard, no frontmatter)
# --------------------------------------------------------------------------

def test_parser_plain_markdown():
    p = parser.parse_skill_md(_read("good_plain_skill.md"))
    assert p.name == "Weather Lookup"
    assert p.description and p.description.startswith("Get the current weather")
    assert p.base_url == "https://weather.example.com"
    assert any(e.method == "GET" for e in p.endpoints)


# --------------------------------------------------------------------------
# End-to-end audits on fixtures (safe_static — no network)
# --------------------------------------------------------------------------

async def test_good_skill_passes():
    r = await run_audit(_read("good_skill.md"), mode="safe_static")
    assert r.verdict in ("PASS_BASIC_AUDIT", "PASS_WITH_WARNINGS")
    assert r.security.score == 100


async def test_evil_skill_fails():
    r = await run_audit(_read("evil_skill.md"), mode="safe_static")
    assert r.verdict == "FAILS_BASIC_AUDIT"
    assert any(f.severity == "critical" for f in r.security.findings)


async def test_benign_security_skill_passes_end_to_end():
    r = await run_audit(_read("benign_security_skill.md"), mode="safe_static")
    assert r.verdict in ("PASS_BASIC_AUDIT", "PASS_WITH_WARNINGS")


async def test_state_changing_methods_never_executed():
    # evil_skill declares POST/DELETE; liveness must skip them, never call them.
    r = await run_audit(_read("evil_skill.md"), mode="liveness")
    for res in r.liveness.results:
        assert res.method in ("GET", "HEAD")
