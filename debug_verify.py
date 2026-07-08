"""Reproduce the /verify bug locally."""
import asyncio
import json
from auditskill.core.certifier import create_certificate, verify_certificate, get_public_key

cert = create_certificate(
    skill_name="test",
    skill_hash="sha256:abc123",
    mode="safe_static",
    overall_score=92,
    verdict="PASS_BASIC_AUDIT",
    structure_score=92,
    liveness_score=None,
    security_score=100,
    scope_score=84,
    metadata_score=75,
)

# The certificate as a Pydantic model
print("=== Certificate model ===")
cert_dict = cert.model_dump()
print(json.dumps(cert_dict, indent=2))

# Verify directly from model dict
pub_key = get_public_key()
print(f"\nPublic key: {pub_key!r}")

print("\n=== Test 1: verify from model_dump() ===")
result = verify_certificate(cert_dict, pub_key)
print(f"valid: {result}")

# Now simulate what happens through JSON round-trip (like HTTP)
print("\n=== Test 2: verify from JSON round-trip (what the agent sees) ===")
# Pydantic response_model serialization uses model_dump(mode="json")
cert_json_dict = cert.model_dump(mode="json")
print(f"JSON mode dict: {json.dumps(cert_json_dict, indent=2)[:200]}...")
result2 = verify_certificate(cert_json_dict, pub_key)
print(f"valid: {result2}")

# Test 3: what if the score becomes a float during JSON parse?
print("\n=== Test 3: score as float (JSON parse could do this) ===")
cert_dict3 = json.loads(json.dumps(cert_dict))
print(f"score type after JSON round-trip: {type(cert_dict3.get('score'))}")
result3 = verify_certificate(cert_dict3, pub_key)
print(f"valid: {result3}")

# Debug: compare canonical forms
from auditskill.core.crypto import canonicalize
print("\n=== Canonical form comparison ===")
c1 = canonicalize(cert_dict)
c2 = canonicalize(cert_json_dict)
c3 = canonicalize(cert_dict3)
print(f"model_dump:       {c1[:200]}")
print(f"model_dump(json): {c2[:200]}")
print(f"json roundtrip:   {c3[:200]}")
print(f"c1 == c2: {c1 == c2}")
print(f"c1 == c3: {c1 == c3}")
