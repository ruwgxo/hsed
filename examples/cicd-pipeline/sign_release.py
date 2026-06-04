"""
examples/cicd-pipeline/sign_release.py
───────────────────────────────────────
Demonstrates HSED signer role (hsed:12 / HS--) in a CI/CD context.

The signer can hash and sign artifacts. It cannot encrypt or decrypt, 
so even if the CI environment is compromised, secrets remain sealed.

Run: python examples/cicd-pipeline/sign_release.py
"""

import hashlib
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from hsed import Bit, HSEDPermissionError, Policy, Role, enforce

# ── Setup ──────────────────────────────────────────────────────────────────

policy = Policy("ci-prod", description="Production CI/CD pipeline permissions")
policy.add_builtin("signer")    # permissions=12, H+S only


# ── Operations allowed for signer ─────────────────────────────────────────

@policy.enforce_op(role="signer", requires=Bit.HASH)
def compute_sha256(data: bytes) -> str:
    """Compute SHA-256 hash of an artifact."""
    return hashlib.sha256(data).hexdigest()


@policy.enforce_op(role="signer", requires=Bit.SIGN)
def sign_artifact(artifact: bytes, private_key_stub: str) -> bytes:
    """
    Sign an artifact.  In production this calls KMS:Sign or similar.
    Stub implementation for illustration.
    """
    digest = hashlib.sha256(artifact).digest()
    stub_sig = bytes([b ^ 0xAA for b in digest[:8]])  # NOT real crypto
    return stub_sig


# ── Operations blocked for signer ─────────────────────────────────────────
#
# These decorators will raise HSEDPermissionError at *import time*
# (eager=True is the default), so mis-configurations surface immediately
# rather than at the moment a pipeline step runs.

def attempt_decrypt_at_decoration_time():
    try:
        @policy.enforce_op(role="signer", requires=Bit.DECRYPT)
        def decrypt_secret(ct: bytes) -> bytes:
            return ct
    except HSEDPermissionError as exc:
        print(f"  [BLOCKED at decoration] {exc}")


# ── Main ───────────────────────────────────────────────────────────────────

def main():
    artifact = b"release-v1.2.3.tar.gz contents"

    print("=== HSED CI/CD Pipeline Example ===\n")
    print(f"Role: {policy.get_role('signer')}")
    print()

    # Allowed operations
    digest = compute_sha256(artifact)
    print(f"[ALLOWED] SHA-256: {digest}")

    sig = sign_artifact(artifact, private_key_stub="kms:arn:...")
    print(f"[ALLOWED] Signature stub: {sig.hex()}")

    print()
    print("Attempting disallowed operations:")
    attempt_decrypt_at_decoration_time()

    # Also demonstrate runtime check (eager=False)
    signer_role = policy.get_role("signer")

    @enforce(role=signer_role, requires=Bit.ENCRYPT, eager=False)
    def encrypt_data(pt: bytes) -> bytes:
        return pt

    try:
        encrypt_data(b"secret")
    except HSEDPermissionError as exc:
        print(f"  [BLOCKED at call time]  {exc}")

    print("\nAll permission checks behaved correctly.")


if __name__ == "__main__":
    main()
