"""
tests/test_integrations_v2.py
─────────────────────────────
Tests for Azure Key Vault, GCP KMS, and live audit integrations.
Run with: python -m pytest tests/ -v
"""

from __future__ import annotations
import json
import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent))

from hsed import Policy, Role
from hsed.core.permissions import Bit, permission_string


# ── helpers ────────────────────────────────────────────────────────────────


def _policy(*role_specs: tuple[str, int]) -> Policy:
    p = Policy("test")
    for name, perm in role_specs:
        p.add_role(Role(name, permissions=perm))
    return p


# ===========================================================================
# Azure Key Vault
# ===========================================================================


class TestAzureKeyVaultGenerator:
    TENANT = "tenant-00000000"
    OBJECT = "object-11111111"

    def _gen(self, *role_specs):
        from hsed.integrations.azure_keyvault import AzureKeyVaultGenerator

        return AzureKeyVaultGenerator(_policy(*role_specs))

    def test_signer_has_sign_not_decrypt(self):
        doc = self._gen(("signer", 12)).generate(
            role="signer", tenant_id=self.TENANT, object_id=self.OBJECT
        )
        assert "sign" in doc.key_permissions
        assert "decrypt" not in doc.key_permissions
        assert "unwrapKey" not in doc.key_permissions

    def test_vault_has_encrypt_and_decrypt(self):
        doc = self._gen(("vault", 3)).generate(
            role="vault", tenant_id=self.TENANT, object_id=self.OBJECT
        )
        assert "encrypt" in doc.key_permissions
        assert "decrypt" in doc.key_permissions
        assert "wrapKey" in doc.key_permissions
        assert "unwrapKey" in doc.key_permissions

    def test_verifier_has_verify_not_sign(self):
        doc = self._gen(("verifier", 8)).generate(
            role="verifier", tenant_id=self.TENANT, object_id=self.OBJECT
        )
        assert "verify" in doc.key_permissions
        assert "sign" not in doc.key_permissions

    def test_full_role_has_all_permissions(self):
        doc = self._gen(("root", 15)).generate(
            role="root", tenant_id=self.TENANT, object_id=self.OBJECT
        )
        for perm in ("sign", "verify", "encrypt", "decrypt", "wrapKey", "unwrapKey"):
            assert perm in doc.key_permissions

    def test_to_dict_structure(self):
        doc = self._gen(("signer", 12)).generate(
            role="signer", tenant_id=self.TENANT, object_id=self.OBJECT
        )
        d = doc.to_dict()
        assert d["tenantId"] == self.TENANT
        assert d["objectId"] == self.OBJECT
        assert "keys" in d["permissions"]

    def test_valid_json(self):
        doc = self._gen(("vault", 3)).generate(
            role="vault", tenant_id=self.TENANT, object_id=self.OBJECT
        )
        parsed = json.loads(doc.to_json())
        assert "permissions" in parsed

    def test_rbac_signer_is_crypto_user(self):
        from hsed.integrations.azure_keyvault import AzureKeyVaultGenerator

        gen = AzureKeyVaultGenerator(_policy(("signer", 12)))
        rbac = gen.generate_rbac(
            role="signer",
            scope="/subscriptions/sub/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/v",
            principal_id="principal-aaa",
        )
        assert rbac.rbac_role_name == "Key Vault Crypto User"

    def test_rbac_root_is_crypto_officer(self):
        from hsed.integrations.azure_keyvault import AzureKeyVaultGenerator

        gen = AzureKeyVaultGenerator(_policy(("root", 15)))
        rbac = gen.generate_rbac(
            role="root", scope="/subscriptions/sub", principal_id="principal-bbb"
        )
        assert rbac.rbac_role_name == "Key Vault Crypto Officer"

    def test_rbac_verifier_is_reader(self):
        from hsed.integrations.azure_keyvault import AzureKeyVaultGenerator

        gen = AzureKeyVaultGenerator(_policy(("verifier", 8)))
        rbac = gen.generate_rbac(role="verifier", scope="/subscriptions/sub", principal_id="p-ccc")
        assert rbac.rbac_role_name == "Key Vault Reader"

    def test_rbac_assignment_id_generated(self):
        from hsed.integrations.azure_keyvault import AzureKeyVaultGenerator

        gen = AzureKeyVaultGenerator(_policy(("signer", 12)))
        rbac = gen.generate_rbac(role="signer", scope="/s", principal_id="p")
        assert len(rbac.assignment_id) == 36  # UUID format

    def test_generate_all(self):
        from hsed.integrations.azure_keyvault import AzureKeyVaultGenerator

        p = _policy(("signer", 12), ("vault", 3))
        gen = AzureKeyVaultGenerator(p)
        docs = gen.generate_all(tenant_id=self.TENANT)
        assert "signer" in docs
        assert "vault" in docs

    def test_metadata(self):
        doc = self._gen(("signer", 12)).generate(
            role="signer", tenant_id=self.TENANT, object_id=self.OBJECT
        )
        m = doc.metadata()
        assert m["hsed_role"] == "signer"
        assert m["hsed_permissions"] == 12
        assert m["hsed_label"] == "HS--"

    def test_no_permissions_role(self):
        doc = self._gen(("none", 0)).generate(
            role="none", tenant_id=self.TENANT, object_id=self.OBJECT
        )
        assert doc.key_permissions == []

    def test_arm_fragment_structure(self):
        doc = self._gen(("signer", 12)).generate(
            role="signer", tenant_id=self.TENANT, object_id=self.OBJECT
        )
        arm = doc.to_arm_fragment()
        assert arm["type"] == "Microsoft.KeyVault/vaults/accessPolicies"
        assert "accessPolicies" in arm["properties"]


# ===========================================================================
# GCP Cloud KMS
# ===========================================================================


class TestGCPKMSGenerator:
    RESOURCE = "projects/my-project/locations/global/keyRings/prod/cryptoKeys/signing-key"
    MEMBER = "serviceAccount:ci@project.iam.gserviceaccount.com"

    def _gen(self, *role_specs, predefined=True):
        from hsed.integrations.gcp_kms import GCPKMSGenerator

        return GCPKMSGenerator(_policy(*role_specs), use_predefined_roles=predefined)

    def test_signer_gets_signer_verifier_role(self):
        doc = self._gen(("signer", 12)).generate(
            role="signer", member=self.MEMBER, resource=self.RESOURCE
        )
        assert doc.bindings[0].role == "roles/cloudkms.signerVerifier"

    def test_vault_gets_encrypter_decrypter_role(self):
        doc = self._gen(("vault", 3)).generate(
            role="vault", member=self.MEMBER, resource=self.RESOURCE
        )
        assert doc.bindings[0].role == "roles/cloudkms.cryptoKeyEncrypterDecrypter"

    def test_verifier_gets_viewer_role(self):
        doc = self._gen(("verifier", 8)).generate(
            role="verifier", member=self.MEMBER, resource=self.RESOURCE
        )
        assert doc.bindings[0].role == "roles/cloudkms.viewer"

    def test_encryptor_gets_encrypter_role(self):
        doc = self._gen(("encryptor", 10)).generate(
            role="encryptor", member=self.MEMBER, resource=self.RESOURCE
        )
        assert doc.bindings[0].role == "roles/cloudkms.cryptoKeyEncrypter"

    def test_audit_gets_decrypter_role(self):
        doc = self._gen(("audit", 9)).generate(
            role="audit", member=self.MEMBER, resource=self.RESOURCE
        )
        assert doc.bindings[0].role == "roles/cloudkms.cryptoKeyDecrypter"

    def test_member_in_binding(self):
        doc = self._gen(("signer", 12)).generate(
            role="signer", member=self.MEMBER, resource=self.RESOURCE
        )
        assert self.MEMBER in doc.bindings[0].members

    def test_valid_json(self):
        doc = self._gen(("signer", 12)).generate(
            role="signer", member=self.MEMBER, resource=self.RESOURCE
        )
        parsed = json.loads(doc.to_json())
        assert "bindings" in parsed
        assert parsed["version"] == 1

    def test_set_iam_request(self):
        doc = self._gen(("signer", 12)).generate(
            role="signer", member=self.MEMBER, resource=self.RESOURCE
        )
        req = doc.to_setiam_request()
        assert "policy" in req
        assert "bindings" in req["policy"]

    def test_gcloud_command_contains_role(self):
        doc = self._gen(("signer", 12)).generate(
            role="signer", member=self.MEMBER, resource=self.RESOURCE
        )
        cmd = doc.to_gcloud_command()
        assert "roles/cloudkms.signerVerifier" in cmd
        assert "add-iam-policy-binding" in cmd

    def test_condition_passed_through(self):
        condition = {
            "title": "expire",
            "description": "expires",
            "expression": "request.time < timestamp('2027-01-01T00:00:00Z')",
        }
        doc = self._gen(("signer", 12)).generate(
            role="signer", member=self.MEMBER, resource=self.RESOURCE, condition=condition
        )
        assert doc.bindings[0].condition == condition

    def test_custom_role_placeholder(self):
        doc = self._gen(("signer", 12), predefined=False).generate(
            role="signer", member=self.MEMBER, resource=self.RESOURCE
        )
        assert "hsed_signer" in doc.bindings[0].role

    def test_generate_all(self):
        from hsed.integrations.gcp_kms import GCPKMSGenerator

        p = _policy(("signer", 12), ("vault", 3))
        docs = GCPKMSGenerator(p).generate_all(resource=self.RESOURCE)
        assert "signer" in docs
        assert "vault" in docs

    def test_merged_policy(self):
        from hsed.integrations.gcp_kms import GCPKMSGenerator

        p = _policy(("signer", 12), ("vault", 3))
        merged = GCPKMSGenerator(p).merged_policy(
            resource=self.RESOURCE,
            members={
                "signer": "serviceAccount:signer@p.iam",
                "vault": "serviceAccount:vault@p.iam",
            },
        )
        assert "policy" in merged
        roles = {b["role"] for b in merged["policy"]["bindings"]}
        assert "roles/cloudkms.signerVerifier" in roles

    def test_metadata(self):
        doc = self._gen(("signer", 12)).generate(
            role="signer", member=self.MEMBER, resource=self.RESOURCE
        )
        m = doc.metadata()
        assert m["hsed_role"] == "signer"
        assert m["gcp_member"] == self.MEMBER


# ===========================================================================
# Live audit (unit-testable parts — no boto3 call)
# ===========================================================================


class TestAuditResult:
    """Test AuditResult model without making AWS calls."""

    def _result(self, expected, actual):
        from hsed.integrations.live_audit import AuditResult, AuditFinding, FindingSeverity

        r = AuditResult(
            role_name="signer",
            permissions=12,
            key_arn="arn:aws:kms:us-east-1:123:key/x",
            expected_allow=expected,
            actual_allow=actual,
        )
        return r

    def test_missing_actions(self):
        r = self._result(["kms:Sign", "kms:Verify"], ["kms:Verify"])
        assert r.missing_actions == ["kms:Sign"]

    def test_extra_actions(self):
        r = self._result(["kms:Sign"], ["kms:Sign", "kms:Decrypt"])
        assert r.extra_actions == ["kms:Decrypt"]

    def test_passed_when_exact_match(self):
        from hsed.integrations.live_audit import AuditFinding, FindingSeverity

        r = self._result(["kms:Sign"], ["kms:Sign"])
        r.findings = [AuditFinding(severity=FindingSeverity.OK, message="ok")]
        assert r.passed is True

    def test_failed_when_missing(self):
        from hsed.integrations.live_audit import AuditFinding, FindingSeverity

        r = self._result(["kms:Sign", "kms:Verify"], ["kms:Verify"])
        r.findings = [AuditFinding(severity=FindingSeverity.FAIL, message="missing")]
        assert r.passed is False

    def test_summary_contains_role(self):
        r = self._result(["kms:Sign"], ["kms:Sign"])
        assert "signer" in r.summary()

    def test_to_dict(self):
        r = self._result(["kms:Sign"], ["kms:Sign", "kms:Decrypt"])
        d = r.to_dict()
        assert d["role"] == "signer"
        assert "kms:Decrypt" in d["extra"]
        assert d["missing"] == []


class TestAWSLiveAuditorUnit:
    """Test internal methods without boto3."""

    def _auditor(self):
        from hsed.integrations.live_audit import AWSLiveAuditor

        p = Policy("test")
        p.add_builtin("signer")
        return AWSLiveAuditor(p)

    def test_extract_allow_actions_basic(self):
        auditor = self._auditor()
        key_arn = "arn:aws:kms:us-east-1:123:key/x"
        policy_doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": ["kms:Sign", "kms:Verify"],
                    "Resource": key_arn,
                },
                {
                    "Effect": "Deny",
                    "Action": ["kms:DeleteAlias"],
                    "Resource": key_arn,
                },
            ]
        }
        actions = auditor._extract_allow_actions(policy_doc, key_arn)
        assert "kms:Sign" in actions
        assert "kms:Verify" in actions
        assert "kms:DeleteAlias" not in actions

    def test_extract_wildcard_resource(self):
        auditor = self._auditor()
        key_arn = "arn:aws:kms:us-east-1:123:key/x"
        policy_doc = {
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "kms:Encrypt",
                    "Resource": "*",
                    "Principal": {"AWS": "arn:aws:iam::123:role/app"},
                }
            ]
        }
        actions = auditor._extract_allow_actions(policy_doc, key_arn)
        assert "kms:Encrypt" in actions

    def test_import_error_without_boto3(self):
        """Accessing the KMS client without boto3 raises ImportError."""
        import unittest.mock as mock

        auditor = self._auditor()
        with mock.patch.dict("sys.modules", {"boto3": None}):
            # Force client to be None so it tries to import
            auditor._client = None
            with pytest.raises((ImportError, TypeError)):
                auditor._kms_client()


# ===========================================================================
# CLI integration — new commands
# ===========================================================================


class TestCLINewCommands:
    """Test new CLI commands produce valid output."""

    def _run(self, *args, policy_file=None):
        import subprocess, tempfile, json

        if policy_file:
            result = subprocess.run(
                ["python", "-m", "hsed.cli.main"] + list(args),
                capture_output=True,
                text=True,
                cwd=str(Path(__file__).parent.parent),
            )
        else:
            result = subprocess.run(
                ["python", "-m", "hsed.cli.main"] + list(args),
                capture_output=True,
                text=True,
                cwd=str(Path(__file__).parent.parent),
            )
        return result

    def test_generate_azure(self, tmp_path):
        import subprocess, tempfile

        # Create a policy file
        p = Policy("test")
        p.add_builtin("signer")
        pf = tmp_path / "test.hsed"
        p.save(str(pf))
        result = subprocess.run(
            [
                "python",
                "-m",
                "hsed.cli.main",
                "generate",
                "azure",
                "--policy",
                str(pf),
                "--role",
                "signer",
                "--tenant-id",
                "tid-123",
                "--object-id",
                "oid-456",
            ],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        assert result.returncode == 0
        parsed = json.loads(result.stdout)
        assert "sign" in parsed["permissions"]["keys"]

    def test_generate_gcp_kms(self, tmp_path):
        import subprocess

        p = Policy("test")
        p.add_builtin("signer")
        pf = tmp_path / "test.hsed"
        p.save(str(pf))
        result = subprocess.run(
            [
                "python",
                "-m",
                "hsed.cli.main",
                "generate",
                "gcp-kms",
                "--policy",
                str(pf),
                "--role",
                "signer",
                "--member",
                "serviceAccount:ci@p.iam.gserviceaccount.com",
                "--resource",
                "projects/p/locations/global/keyRings/k/cryptoKeys/key",
            ],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        assert result.returncode == 0
        parsed = json.loads(result.stdout)
        assert "bindings" in parsed

    def test_generate_gcp_gcloud(self, tmp_path):
        import subprocess

        p = Policy("test")
        p.add_builtin("signer")
        pf = tmp_path / "test.hsed"
        p.save(str(pf))
        result = subprocess.run(
            [
                "python",
                "-m",
                "hsed.cli.main",
                "generate",
                "gcp-kms",
                "--policy",
                str(pf),
                "--role",
                "signer",
                "--member",
                "serviceAccount:ci@p.iam.gserviceaccount.com",
                "--resource",
                "projects/p/locations/global/keyRings/k/cryptoKeys/key",
                "--gcloud",
            ],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        assert result.returncode == 0
        assert "gcloud kms keys add-iam-policy-binding" in result.stdout

    def test_generate_azure_rbac(self, tmp_path):
        import subprocess

        p = Policy("test")
        p.add_builtin("signer")
        pf = tmp_path / "test.hsed"
        p.save(str(pf))
        result = subprocess.run(
            [
                "python",
                "-m",
                "hsed.cli.main",
                "generate",
                "azure-rbac",
                "--policy",
                str(pf),
                "--role",
                "signer",
                "--scope",
                "/subscriptions/sub-id/resourceGroups/rg",
                "--principal-id",
                "principal-aaa",
            ],
            capture_output=True,
            text=True,
            cwd=str(Path(__file__).parent.parent),
        )
        assert result.returncode == 0
        parsed = json.loads(result.stdout)
        assert parsed["type"] == "Microsoft.Authorization/roleAssignments"
