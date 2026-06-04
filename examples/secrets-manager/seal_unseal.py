"""
examples/secrets-manager/seal_unseal.py
───────────────────────────────────────
Demonstrates HSED vault role (hsed:3 / --ED) for secrets management.

The vault role can only Encrypt and Decrypt — it cannot hash artifacts
or create signatures. This is the right boundary for a secrets manager:
it holds the keys to the safe but cannot vouch for code authenticity.

Run: python examples/secrets-manager/seal_unseal.py
"""

import base64
import os
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from hsed import Bit, HSEDPermissionError, Policy, Role, enforce

# ── Setup ──────────────────────────────────────────────────────────────────

policy = Policy("secrets-prod", description="Production secrets management permissions")
policy.add_builtin("vault")  # permissions=3, --ED only
policy.add_builtin("encryptor")  # permissions=10, H-E-  (ingest pipeline)
policy.add_builtin("audit")  # permissions=9,  H--D  (compliance read)


# ── vault role: encrypt + decrypt ─────────────────────────────────────────


@policy.enforce_op(role="vault", requires=Bit.ENCRYPT)
def seal_secret(plaintext: bytes, key_stub: bytes) -> bytes:
    """
    Encrypt (seal) a secret.
    In production: calls KMS.Encrypt or Vault Transit encrypt.
    Stub: XOR + base64 for illustration only.
    """
    keystream = (key_stub * (len(plaintext) // len(key_stub) + 1))[: len(plaintext)]
    ct = bytes(p ^ k for p, k in zip(plaintext, keystream))
    return base64.b64encode(ct)


@policy.enforce_op(role="vault", requires=Bit.DECRYPT)
def unseal_secret(ciphertext: bytes, key_stub: bytes) -> bytes:
    """Decrypt (unseal) a secret."""
    raw = base64.b64decode(ciphertext)
    keystream = (key_stub * (len(raw) // len(key_stub) + 1))[: len(raw)]
    return bytes(c ^ k for c, k in zip(raw, keystream))


# ── encryptor role: encrypt only, no decrypt ──────────────────────────────


@policy.enforce_op(role="encryptor", requires=Bit.ENCRYPT)
def ingest_and_seal(record: dict, key_stub: bytes) -> bytes:
    """Seal an ingest record. Encryptor cannot decrypt — write-only."""
    import json

    plaintext = json.dumps(record).encode()
    keystream = (key_stub * (len(plaintext) // len(key_stub) + 1))[: len(plaintext)]
    ct = bytes(p ^ k for p, k in zip(plaintext, keystream))
    return base64.b64encode(ct)


# ── audit role: decrypt only, no encrypt ──────────────────────────────────


@policy.enforce_op(role="audit", requires=Bit.DECRYPT)
def compliance_read(ciphertext: bytes, key_stub: bytes) -> bytes:
    """Auditor can decrypt for forensics but cannot create new ciphertext."""
    raw = base64.b64decode(ciphertext)
    keystream = (key_stub * (len(raw) // len(key_stub) + 1))[: len(raw)]
    return bytes(c ^ k for c, k in zip(raw, keystream))


# ── Main ───────────────────────────────────────────────────────────────────


def main():
    KEY = b"hsed-demo-key-32bytes-padding!!!"

    print("=== HSED Secrets Manager Example ===\n")
    print(f"vault:     {policy.get_role('vault')}")
    print(f"encryptor: {policy.get_role('encryptor')}")
    print(f"audit:     {policy.get_role('audit')}")
    print()

    # vault seals and unseals
    secret = b"db-password: s3cr3t!"
    sealed = seal_secret(secret, KEY)
    unsealed = unseal_secret(sealed, KEY)
    print(f"[vault]     seal:   {sealed[:32].decode()}...")
    print(f"[vault]     unseal: {unsealed.decode()}")
    assert unsealed == secret

    # encryptor can seal an ingest record
    record = {"user_id": 42, "api_key": "abc123", "ts": "2026-05-16"}
    sealed_record = ingest_and_seal(record, KEY)
    print(f"[encryptor] ingest: {sealed_record[:32].decode()}...")

    # encryptor cannot decrypt — blocked at decoration time (eager=True)
    print("\nBlocked operations:")
    try:

        @policy.enforce_op(role="encryptor", requires=Bit.DECRYPT)
        def encryptor_decrypt(ct, key):
            return ct
    except HSEDPermissionError as e:
        print(f"  [encryptor → DECRYPT] blocked: {e}")

    # audit can read the sealed record
    plaintext_audit = compliance_read(sealed_record, KEY)
    print(f"\n[audit]     read:   {plaintext_audit.decode()}")

    # audit cannot encrypt
    try:

        @policy.enforce_op(role="audit", requires=Bit.ENCRYPT)
        def audit_encrypt(pt, key):
            return pt
    except HSEDPermissionError as e:
        print(f"  [audit → ENCRYPT]    blocked: {e}")

    print("\nAll permission boundaries enforced correctly.")


if __name__ == "__main__":
    main()
