"""Ed25519 cryptographic operations for AuditSkill certificates.

Provides keypair generation, canonical-JSON document signing, signature
verification, and SHA-256 hashing.  All operations use Ed25519 via
PyNaCl (libsodium) — no custom crypto.

The canonical JSON form is: sorted keys, compact separators (",", ":"),
no trailing newline, UTF-8 encoded.  The ``signature`` field is always
excluded from the canonical form so that the signature never covers itself.

Cherry-picked and adapted from AgentGate (MIT).
"""

from __future__ import annotations

import base64
import hashlib
import json
from typing import Any

from nacl.exceptions import BadSignatureError
from nacl.signing import SigningKey, VerifyKey


def generate_keypair() -> tuple[str, str]:
    """Generate a new Ed25519 keypair.

    Returns:
        A tuple of ``(private_key_b64, public_key_b64)`` where both
        values are standard base64-encoded strings (32 bytes each).
    """
    signing_key = SigningKey.generate()
    private_b64 = base64.b64encode(bytes(signing_key)).decode("ascii")
    public_b64 = base64.b64encode(bytes(signing_key.verify_key)).decode("ascii")
    return private_b64, public_b64


def derive_public_key(private_key_b64: str) -> str:
    """Derive the base64 Ed25519 public key from a base64 private key.

    Lets the service publish/verify with a key that is *guaranteed* to match
    the signing key — no separately-configured public key that can drift.
    """
    signing_key = SigningKey(base64.b64decode(private_key_b64))
    return base64.b64encode(bytes(signing_key.verify_key)).decode("ascii")


def canonicalize(document: dict[str, Any]) -> bytes:
    """Produce a canonical JSON byte string for signing.

    Canonical form: sorted keys, compact separators, no trailing newline,
    UTF-8 encoded.  The top-level ``signature`` field is excluded so that
    the signature doesn't cover itself.
    """
    doc_copy = _strip_signature(document)
    return json.dumps(doc_copy, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode(
        "utf-8"
    )


def _strip_signature(document: dict[str, Any]) -> dict[str, Any]:
    """Return a shallow copy of *document* without the ``signature`` key."""
    return {k: v for k, v in document.items() if k != "signature"}


def sign_document(document: dict[str, Any], private_key_b64: str) -> str:
    """Sign a document's canonical JSON form with an Ed25519 private key.

    Args:
        document: The dictionary to sign (``signature`` key excluded automatically).
        private_key_b64: Base64-encoded 32-byte Ed25519 private (signing) key.

    Returns:
        Base64-encoded Ed25519 signature string.
    """
    key_bytes = base64.b64decode(private_key_b64)
    signing_key = SigningKey(key_bytes)
    canonical = canonicalize(document)
    signed = signing_key.sign(canonical)
    return base64.b64encode(signed.signature).decode("ascii")


def verify_signature(
    document: dict[str, Any],
    signature_b64: str,
    public_key_b64: str,
) -> bool:
    """Verify an Ed25519 signature over a document's canonical JSON form.

    Returns ``True`` if valid, ``False`` on any failure (bad sig, bad key, etc.).
    """
    try:
        sig_bytes = base64.b64decode(signature_b64)
        key_bytes = base64.b64decode(public_key_b64)
        verify_key = VerifyKey(key_bytes)
        canonical = canonicalize(document)
        verify_key.verify(canonical, sig_bytes)
        return True
    except (BadSignatureError, ValueError, TypeError):
        return False


def hash_bytes(data: bytes) -> str:
    """Return ``sha256:<hex>`` hash of raw bytes."""
    return f"sha256:{hashlib.sha256(data).hexdigest()}"


def hash_text(text: str) -> str:
    """Return ``sha256:<hex>`` hash of a UTF-8 string."""
    return hash_bytes(text.encode("utf-8"))
