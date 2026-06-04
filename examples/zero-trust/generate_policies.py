"""
examples/zero-trust/generate_policies.py
─────────────────────────────────────────
Demonstrates generating AWS KMS and Vault policies for a zero-trust
multi-role environment from a single HSED policy definition.

Run: python examples/zero-trust/generate_policies.py
"""

import json
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent.parent))

from hsed import Policy, Role
from hsed.integrations.aws_kms import AWSKMSGenerator
from hsed.integrations.vault import VaultGenerator

KEY_ARN = "arn:aws:kms:us-east-1:123456789012:key/mrk-0123456789abcdef"

def build_policy() -> Policy:
    p = Policy("zero-trust-prod", description="Zero-trust production environment")
    p.add_builtin("signer")     # CI/CD: can sign, cannot decrypt
    p.add_builtin("vault")      # Secrets manager: encrypt + decrypt only
    p.add_builtin("audit")      # Compliance: hash + decrypt, read-only
    p.add_builtin("encryptor")  # Ingest pipeline: hash + encrypt, no decrypt
    return p

def main():
    policy = build_policy()
    print("=== Zero-Trust HSED Policy ===\n")
    print(policy)
    print()

    # ── AWS KMS ────────────────────────────────────────────────────────
    print("─" * 60)
    print("AWS KMS IAM Policies")
    print("─" * 60)
    kms_gen = AWSKMSGenerator(policy)
    all_docs = kms_gen.generate_all(key_arn=KEY_ARN)
    for role_name, doc in sorted(all_docs.items()):
        iam = json.loads(doc.to_json())
        allow = next(s for s in iam["Statement"] if s["Effect"] == "Allow")
        print(f"\n[{role_name.upper()}]  hsed:{doc.hsed_label}/{doc.permissions}")
        print(f"  Actions: {', '.join(allow['Action'])}")

    # ── HashiCorp Vault ────────────────────────────────────────────────
    print("\n" + "─" * 60)
    print("HashiCorp Vault HCL Policies")
    print("─" * 60)
    vault_gen = VaultGenerator(policy)
    all_hcl = vault_gen.generate_all(mount="transit", key_name="prod-key")
    for role_name, doc in sorted(all_hcl.items()):
        paths = [p.path for p in doc.paths]
        print(f"\n[{role_name.upper()}]  hsed:{doc.metadata()['hsed_label']}/{doc.permissions}")
        for path in paths:
            print(f"  {path}")

    # ── Save policy ────────────────────────────────────────────────────
    saved = policy.save("/tmp/zero-trust-prod.hsed")
    print(f"\n✓ Policy saved → {saved}")
    warnings = policy.validate()
    if warnings:
        for w in warnings:
            print(f"  ⚠ {w}")
    else:
        print("✓ Policy validates cleanly (no warnings)")

if __name__ == "__main__":
    main()
