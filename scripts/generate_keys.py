#!/usr/bin/env python3
"""Generate an Ed25519 keypair for AuditSkill certificate signing.

Prints environment-variable lines you can paste into your host's secret
manager.  The PRIVATE key is printed to stdout only — never commit it, and
never store it in the repo.  Only the PUBLIC key is safe to publish (it is
served at /.well-known/auditskill-keys for offline verification).

Usage:
    python scripts/generate_keys.py
"""
from __future__ import annotations

import datetime

from auditskill.core.crypto import generate_keypair


def main() -> None:
    private_b64, public_b64 = generate_keypair()
    key_id = "auditskill-" + datetime.date.today().strftime("%Y-%m")
    print("# --- AuditSkill signing keys (set these as environment variables) ---")
    print("# Keep AUDITSKILL_PRIVATE_KEY secret. Publish only the public key.")
    print(f"AUDITSKILL_PRIVATE_KEY={private_b64}")
    print(f"AUDITSKILL_PUBLIC_KEY={public_b64}")
    print(f"AUDITSKILL_KEY_ID={key_id}")


if __name__ == "__main__":
    main()
