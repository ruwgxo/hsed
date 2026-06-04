"""
examples/audit-trail/compliance_check.py
─────────────────────────────────────────
Demonstrates HSED audit role (hsed:9 / H--D) for compliance and forensics.

The audit role can Hash (verify integrity) and Decrypt (read sealed records)
— but cannot Sign (create attestations) or Encrypt (produce new ciphertext).
This ensures auditors can read everything they need but cannot tamper with
evidence or produce new signed artefacts.

Also demonstrates how to generate all cloud policies from one HSED policy
file and write them to an audit report.

Run: python examples/audit-trail/compliance_check.py
"""

import base64
import hashlib
import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from hsed import Bit, HSEDPermissionError, Policy, Role, enforce
from hsed.integrations.aws_kms import AWSKMSGenerator
from hsed.integrations.gcp_kms import GCPKMSGenerator
from hsed.integrations.azure_keyvault import AzureKeyVaultGenerator
from hsed.integrations.vault import VaultGenerator

# ── Setup ──────────────────────────────────────────────────────────────────

policy = Policy("compliance-audit", description="Audit and compliance environment")
policy.add_builtin("audit")  # H--D / 9  — primary role
policy.add_builtin("verifier")  # H---  / 8  — signature-only checks
policy.add_builtin("signer")  # HS--  / 12 — for comparison in report


# ── audit operations ───────────────────────────────────────────────────────


@policy.enforce_op(role="audit", requires=Bit.HASH)
def verify_integrity(data: bytes, expected_hash: str) -> bool:
    """Verify a data artefact's SHA-256 hash."""
    actual = hashlib.sha256(data).hexdigest()
    return actual == expected_hash


@policy.enforce_op(role="audit", requires=Bit.DECRYPT)
def read_sealed_record(ciphertext: bytes, key_stub: bytes) -> bytes:
    """Decrypt a sealed audit record for forensic review."""
    raw = base64.b64decode(ciphertext)
    keystream = (key_stub * (len(raw) // len(key_stub) + 1))[: len(raw)]
    return bytes(c ^ k for c, k in zip(raw, keystream))


# ── blocked operations (verify enforcement) ────────────────────────────────


def demonstrate_blocks():
    print("Permission boundary checks:")
    for role_name, bit, bit_name in [
        ("audit", Bit.SIGN, "SIGN"),
        ("audit", Bit.ENCRYPT, "ENCRYPT"),
        ("verifier", Bit.SIGN, "SIGN"),
        ("verifier", Bit.DECRYPT, "DECRYPT"),
    ]:
        try:

            @policy.enforce_op(role=role_name, requires=bit)
            def blocked_op(*a):
                pass

            print(f"  [{role_name} → {bit_name}] ✗ should have been blocked!")
        except HSEDPermissionError:
            print(f"  [{role_name} → {bit_name}] ✓ correctly blocked")


# ── multi-cloud policy report ──────────────────────────────────────────────


def generate_audit_report() -> dict:
    """Generate a full multi-cloud policy report for all roles."""
    KEY_ARN = "arn:aws:kms:us-east-1:123456789012:key/mrk-audit-key"
    GCP_RESOURCE = "projects/my-project/locations/global/keyRings/audit/cryptoKeys/audit-key"
    TENANT_ID = "00000000-0000-0000-0000-000000000000"

    report = {
        "policy": policy.name,
        "roles": {},
        "cloud_policies": {},
        "validation": policy.validate(),
    }

    for role in policy.roles():
        report["roles"][role.name] = role.to_dict()

    # AWS KMS
    kms_gen = AWSKMSGenerator(policy)
    report["cloud_policies"]["aws_kms"] = {
        role.name: json.loads(kms_gen.generate(role=role.name, key_arn=KEY_ARN).to_json())
        for role in policy.roles()
    }

    # GCP KMS
    gcp_gen = GCPKMSGenerator(policy)
    report["cloud_policies"]["gcp_kms"] = {
        role.name: gcp_gen.generate(
            role=role.name,
            member=f"serviceAccount:{role.name}@my-project.iam.gserviceaccount.com",
            resource=GCP_RESOURCE,
        ).to_dict()
        for role in policy.roles()
    }

    # Azure Key Vault
    az_gen = AzureKeyVaultGenerator(policy)
    report["cloud_policies"]["azure_keyvault"] = {
        role.name: az_gen.generate(
            role=role.name,
            tenant_id=TENANT_ID,
            object_id=f"00000000-0000-0000-0000-{role.permissions:012d}",
        ).to_dict()
        for role in policy.roles()
    }

    # Vault HCL (metadata only — full HCL is text, not JSON)
    vault_gen = VaultGenerator(policy)
    report["cloud_policies"]["hashicorp_vault"] = {
        role.name: vault_gen.generate(
            role=role.name, mount="transit", key_name="audit-key"
        ).metadata()
        for role in policy.roles()
    }

    return report


# ── Main ───────────────────────────────────────────────────────────────────


def main():
    KEY = b"audit-demo-key-32bytes-padding!!"

    print("=== HSED Audit Trail & Compliance Example ===\n")
    print(f"Policy: {policy}")
    print()

    # Seal some records (using vault role logic inline for demo)
    records = [
        {"event": "user_login", "user_id": 101, "ip": "10.0.0.1"},
        {"event": "data_export", "user_id": 202, "rows": 50000},
        {"event": "key_access", "user_id": 303, "key_arn": "arn:..."},
    ]
    sealed_records = []
    for rec in records:
        pt = json.dumps(rec).encode()
        ks = (KEY * (len(pt) // len(KEY) + 1))[: len(pt)]
        ct = base64.b64encode(bytes(p ^ k for p, k in zip(pt, ks)))
        digest = hashlib.sha256(pt).hexdigest()
        sealed_records.append({"ciphertext": ct, "sha256": digest, "plaintext": pt})

    print("Audit role reading sealed records:")
    for i, rec in enumerate(sealed_records):
        decrypted = read_sealed_record(rec["ciphertext"], KEY)
        integrity_ok = verify_integrity(decrypted, rec["sha256"])
        print(f"  [{i + 1}] {decrypted.decode()}")
        print(f"       integrity: {'✓' if integrity_ok else '✗'}")

    print()
    demonstrate_blocks()

    # Generate and save multi-cloud report
    print("\nGenerating multi-cloud policy report...")
    report = generate_audit_report()
    out = Path("/tmp/hsed-audit-report.json")
    out.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"  Report saved → {out}")
    print(f"  Roles: {list(report['roles'].keys())}")
    print(f"  Clouds: {list(report['cloud_policies'].keys())}")
    warnings = report["validation"]
    print(f"  Validation: {'✓ clean' if not warnings else f'{len(warnings)} warning(s)'}")
    print("\nAll checks passed.")


if __name__ == "__main__":
    main()
