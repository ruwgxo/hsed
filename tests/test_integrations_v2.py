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


# ===========================================================================
# AzureLiveAuditor — unit tests (no real Azure calls)
# ===========================================================================


class TestAzureLiveAuditorUnit:
    """Test AzureLiveAuditor internal methods and audit logic without cloud calls."""

    def _auditor(self):
        from hsed.integrations.live_audit import AzureLiveAuditor

        p = Policy('test')
        p.add_builtin('signer')   # permissions=12 → sign, verify, get
        p.add_builtin('vault')    # permissions=3  → decrypt, unwrapKey, encrypt, wrapKey, get
        return AzureLiveAuditor(p)

    # --- _extract_key_permissions ---

    def test_extract_matching_object_id(self):
        auditor = self._auditor()
        entry = type('E', (), {
            'object_id': 'aaaa-bbbb',
            'permissions': type('P', (), {'keys': ['sign', 'verify', 'get']})(),
        })()
        result = auditor._extract_key_permissions([entry], 'aaaa-bbbb')
        assert 'sign' in result
        assert 'verify' in result
        assert 'get' in result

    def test_extract_case_insensitive_object_id(self):
        auditor = self._auditor()
        entry = type('E', (), {
            'object_id': 'AAAA-BBBB',
            'permissions': type('P', (), {'keys': ['sign']})(),
        })()
        result = auditor._extract_key_permissions([entry], 'aaaa-bbbb')
        assert 'sign' in result

    def test_extract_no_matching_object_id(self):
        auditor = self._auditor()
        entry = type('E', (), {
            'object_id': 'other-id',
            'permissions': type('P', (), {'keys': ['sign']})(),
        })()
        result = auditor._extract_key_permissions([entry], 'aaaa-bbbb')
        assert result == []

    def test_extract_empty_access_policies(self):
        auditor = self._auditor()
        result = auditor._extract_key_permissions([], 'aaaa-bbbb')
        assert result == []

    def test_extract_normalises_to_lowercase(self):
        auditor = self._auditor()
        entry = type('E', (), {
            'object_id': 'obj-1',
            'permissions': type('P', (), {'keys': ['Sign', 'WrapKey', 'GET']})(),
        })()
        result = auditor._extract_key_permissions([entry], 'obj-1')
        assert 'sign' in result
        assert 'wrapkey' in result
        assert 'get' in result

    # --- audit() logic using mocked _fetch_access_policies ---

    def _mock_fetch(self, auditor, key_perms, object_id='obj-1'):
        """Patch _fetch_access_policies to return a synthetic policy."""
        import unittest.mock as mock

        entry = type('E', (), {
            'object_id': object_id,
            'permissions': type('P', (), {'keys': key_perms})(),
        })()
        auditor._fetch_access_policies = mock.Mock(return_value=[entry])

    def test_audit_pass_exact_match(self):
        from hsed.integrations.live_audit import FindingSeverity

        auditor = self._auditor()
        # signer expects: sign, verify, get (normalised)
        self._mock_fetch(auditor, ['sign', 'verify', 'get'])
        result = auditor.audit(
            role='signer',
            vault_uri='https://myvault.vault.azure.net',
            object_id='obj-1',
            subscription_id='sub-1',
            resource_group='rg-1',
            vault_name='myvault',
        )
        assert result.passed is True
        assert any(f.severity == FindingSeverity.OK for f in result.findings)

    def test_audit_fail_missing_permission(self):
        from hsed.integrations.live_audit import FindingSeverity

        auditor = self._auditor()
        # signer needs sign, verify, get — give only verify, get
        self._mock_fetch(auditor, ['verify', 'get'])
        result = auditor.audit(
            role='signer',
            vault_uri='https://myvault.vault.azure.net',
            object_id='obj-1',
            subscription_id='sub-1',
            resource_group='rg-1',
            vault_name='myvault',
        )
        assert result.passed is False
        assert any(f.severity == FindingSeverity.FAIL for f in result.findings)
        assert 'sign' in result.missing_actions

    def test_audit_warn_extra_permission_default(self):
        from hsed.integrations.live_audit import FindingSeverity

        auditor = self._auditor()
        # give signer extra 'decrypt' permission
        self._mock_fetch(auditor, ['sign', 'verify', 'get', 'decrypt'])
        result = auditor.audit(
            role='signer',
            vault_uri='https://myvault.vault.azure.net',
            object_id='obj-1',
            subscription_id='sub-1',
            resource_group='rg-1',
            vault_name='myvault',
        )
        assert result.passed is True  # WARN doesn't fail
        assert any(f.severity == FindingSeverity.WARN for f in result.findings)
        assert 'decrypt' in result.extra_actions

    def test_audit_fail_extra_permission_strict(self):
        from hsed.integrations.live_audit import FindingSeverity

        auditor = self._auditor()
        self._mock_fetch(auditor, ['sign', 'verify', 'get', 'decrypt'])
        result = auditor.audit(
            role='signer',
            vault_uri='https://myvault.vault.azure.net',
            object_id='obj-1',
            subscription_id='sub-1',
            resource_group='rg-1',
            vault_name='myvault',
            strict=True,
        )
        assert result.passed is False
        assert any(f.severity == FindingSeverity.FAIL for f in result.findings)

    def test_audit_fail_no_policy_entry(self):
        import unittest.mock as mock
        from hsed.integrations.live_audit import FindingSeverity

        auditor = self._auditor()
        # No entry for this object_id
        auditor._fetch_access_policies = mock.Mock(return_value=[])
        result = auditor.audit(
            role='signer',
            vault_uri='https://myvault.vault.azure.net',
            object_id='obj-1',
            subscription_id='sub-1',
            resource_group='rg-1',
            vault_name='myvault',
        )
        assert result.passed is False
        assert any(f.severity == FindingSeverity.FAIL for f in result.findings)

    def test_audit_error_on_fetch_failure(self):
        import unittest.mock as mock
        from hsed.integrations.live_audit import FindingSeverity

        auditor = self._auditor()
        auditor._fetch_access_policies = mock.Mock(
            side_effect=RuntimeError('403 Forbidden')
        )
        result = auditor.audit(
            role='signer',
            vault_uri='https://myvault.vault.azure.net',
            object_id='obj-1',
            subscription_id='sub-1',
            resource_group='rg-1',
            vault_name='myvault',
        )
        assert result.passed is False
        assert any(f.severity == FindingSeverity.ERROR for f in result.findings)

    def test_audit_result_key_arn_is_vault_uri(self):
        import unittest.mock as mock

        auditor = self._auditor()
        self._mock_fetch(auditor, ['sign', 'verify', 'get'])
        result = auditor.audit(
            role='signer',
            vault_uri='https://myvault.vault.azure.net',
            object_id='obj-1',
            subscription_id='sub-1',
            resource_group='rg-1',
            vault_name='myvault',
        )
        assert result.key_arn == 'https://myvault.vault.azure.net'

    def test_audit_summary_contains_role_and_vault(self):
        auditor = self._auditor()
        self._mock_fetch(auditor, ['sign', 'verify', 'get'])
        result = auditor.audit(
            role='signer',
            vault_uri='https://myvault.vault.azure.net',
            object_id='obj-1',
            subscription_id='sub-1',
            resource_group='rg-1',
            vault_name='myvault',
        )
        summary = result.summary()
        assert 'signer' in summary
        assert 'myvault' in summary

    def test_audit_all_skips_roles_without_object_ids(self):
        import unittest.mock as mock

        auditor = self._auditor()
        self._mock_fetch(auditor, ['sign', 'verify', 'get'], object_id='obj-signer')
        results = auditor.audit_all(
            vault_uri='https://myvault.vault.azure.net',
            object_ids={'signer': 'obj-signer'},   # 'vault' role intentionally omitted
            subscription_id='sub-1',
            resource_group='rg-1',
            vault_name='myvault',
        )
        assert 'signer' in results
        assert 'vault' not in results

    def test_import_error_without_azure_mgmt(self):
        import unittest.mock as mock

        auditor = self._auditor()
        with mock.patch.dict('sys.modules', {'azure.mgmt.keyvault': None}):
            with pytest.raises((ImportError, TypeError)):
                auditor._kv_management_client('sub-1')


# ===========================================================================
# GCPLiveAuditor — unit tests (no real GCP calls)
# ===========================================================================


class TestGCPLiveAuditorUnit:
    """Test GCPLiveAuditor internal methods and audit logic without cloud calls."""

    def _auditor(self):
        from hsed.integrations.live_audit import GCPLiveAuditor

        p = Policy('test')
        p.add_builtin('signer')    # permissions=12 → sign, verify perms
        p.add_builtin('vault')     # permissions=3  → encrypt, decrypt perms
        p.add_builtin('encryptor') # permissions=10 → encrypt only
        return GCPLiveAuditor(p)

    # --- _member_roles ---

    def test_member_roles_found(self):
        auditor = self._auditor()
        bindings = [
            {'role': 'roles/cloudkms.signerVerifier', 'members': ['serviceAccount:ci@p.iam.gserviceaccount.com']},
            {'role': 'roles/viewer', 'members': ['user:other@example.com']},
        ]
        roles = auditor._member_roles(bindings, 'serviceAccount:ci@p.iam.gserviceaccount.com')
        assert 'roles/cloudkms.signerVerifier' in roles
        assert 'roles/viewer' not in roles

    def test_member_roles_case_insensitive(self):
        auditor = self._auditor()
        bindings = [
            {'role': 'roles/cloudkms.signerVerifier', 'members': ['ServiceAccount:CI@P.IAM.GSERVICEACCOUNT.COM']},
        ]
        roles = auditor._member_roles(bindings, 'serviceAccount:ci@p.iam.gserviceaccount.com')
        assert 'roles/cloudkms.signerVerifier' in roles

    def test_member_roles_empty_bindings(self):
        auditor = self._auditor()
        roles = auditor._member_roles([], 'serviceAccount:ci@p.iam.gserviceaccount.com')
        assert roles == []

    def test_member_roles_not_present(self):
        auditor = self._auditor()
        bindings = [
            {'role': 'roles/cloudkms.signerVerifier', 'members': ['serviceAccount:other@p.iam.gserviceaccount.com']},
        ]
        roles = auditor._member_roles(bindings, 'serviceAccount:ci@p.iam.gserviceaccount.com')
        assert roles == []

    # --- _gcp_expand_roles (module-level helper) ---

    def test_expand_signer_verifier_role(self):
        from hsed.integrations.live_audit import _gcp_expand_roles

        perms = _gcp_expand_roles(['roles/cloudkms.signerVerifier'])
        assert 'cloudkms.cryptoKeyVersions.useToSign' in perms
        assert 'cloudkms.cryptoKeyVersions.useToVerify' in perms
        assert 'cloudkms.cryptoKeys.get' in perms
        # Must NOT include decrypt
        assert 'cloudkms.cryptoKeyVersions.useToDecrypt' not in perms

    def test_expand_encrypter_decrypter_role(self):
        from hsed.integrations.live_audit import _gcp_expand_roles

        perms = _gcp_expand_roles(['roles/cloudkms.cryptoKeyEncrypterDecrypter'])
        assert 'cloudkms.cryptoKeyVersions.useToEncrypt' in perms
        assert 'cloudkms.cryptoKeyVersions.useToDecrypt' in perms

    def test_expand_unknown_role_returns_empty(self):
        from hsed.integrations.live_audit import _gcp_expand_roles

        perms = _gcp_expand_roles(['roles/some.unknown'])
        assert perms == []

    def test_expand_multiple_roles_union(self):
        from hsed.integrations.live_audit import _gcp_expand_roles

        perms = _gcp_expand_roles([
            'roles/cloudkms.cryptoKeyEncrypter',
            'roles/cloudkms.cryptoKeyDecrypter',
        ])
        assert 'cloudkms.cryptoKeyVersions.useToEncrypt' in perms
        assert 'cloudkms.cryptoKeyVersions.useToDecrypt' in perms

    # --- audit() logic using mocked _fetch_iam_policy ---

    RESOURCE = 'projects/p/locations/global/keyRings/kr/cryptoKeys/k'
    MEMBER = 'serviceAccount:ci@p.iam.gserviceaccount.com'

    def _mock_fetch(self, auditor, bindings):
        import unittest.mock as mock
        auditor._fetch_iam_policy = mock.Mock(return_value=bindings)

    def test_audit_pass_signer_exact_role(self):
        from hsed.integrations.live_audit import FindingSeverity

        auditor = self._auditor()
        self._mock_fetch(auditor, [
            {'role': 'roles/cloudkms.signerVerifier', 'members': [self.MEMBER]},
        ])
        result = auditor.audit(role='signer', resource=self.RESOURCE, member=self.MEMBER)
        assert result.passed is True
        assert any(f.severity == FindingSeverity.OK for f in result.findings)

    def test_audit_fail_missing_permission(self):
        from hsed.integrations.live_audit import FindingSeverity

        auditor = self._auditor()
        # Give only viewer (no sign/verify ops)
        self._mock_fetch(auditor, [
            {'role': 'roles/cloudkms.viewer', 'members': [self.MEMBER]},
        ])
        result = auditor.audit(role='signer', resource=self.RESOURCE, member=self.MEMBER)
        assert result.passed is False
        assert any(f.severity == FindingSeverity.FAIL for f in result.findings)

    def test_audit_warn_extra_permissions_default(self):
        from hsed.integrations.live_audit import FindingSeverity

        auditor = self._auditor()
        # signer (HS-- = 12) expects: useToSign, useToVerify, get
        # give roles/owner which additionally includes useToEncrypt + useToDecrypt → over-grant
        self._mock_fetch(auditor, [
            {'role': 'roles/owner', 'members': [self.MEMBER]},
        ])
        result = auditor.audit(role='signer', resource=self.RESOURCE, member=self.MEMBER)
        assert result.passed is True  # extra perms → WARN, not FAIL
        assert any(f.severity == FindingSeverity.WARN for f in result.findings)
        # owner adds encrypt + decrypt which signer doesn't need
        assert len(result.extra_actions) > 0

    def test_audit_fail_extra_permissions_strict(self):
        from hsed.integrations.live_audit import FindingSeverity

        auditor = self._auditor()
        # Same over-grant scenario as above but strict=True → FAIL
        self._mock_fetch(auditor, [
            {'role': 'roles/owner', 'members': [self.MEMBER]},
        ])
        result = auditor.audit(
            role='signer', resource=self.RESOURCE, member=self.MEMBER, strict=True
        )
        assert result.passed is False

    def test_audit_fail_no_bindings_for_member(self):
        from hsed.integrations.live_audit import FindingSeverity

        auditor = self._auditor()
        self._mock_fetch(auditor, [
            {'role': 'roles/cloudkms.signerVerifier', 'members': ['serviceAccount:other@p.iam.gserviceaccount.com']},
        ])
        result = auditor.audit(role='signer', resource=self.RESOURCE, member=self.MEMBER)
        assert result.passed is False
        assert any(f.severity == FindingSeverity.FAIL for f in result.findings)

    def test_audit_error_on_fetch_failure(self):
        import unittest.mock as mock
        from hsed.integrations.live_audit import FindingSeverity

        auditor = self._auditor()
        auditor._fetch_iam_policy = mock.Mock(side_effect=RuntimeError('403 Forbidden'))
        result = auditor.audit(role='signer', resource=self.RESOURCE, member=self.MEMBER)
        assert result.passed is False
        assert any(f.severity == FindingSeverity.ERROR for f in result.findings)

    def test_audit_result_key_arn_is_resource_path(self):
        auditor = self._auditor()
        self._mock_fetch(auditor, [
            {'role': 'roles/cloudkms.signerVerifier', 'members': [self.MEMBER]},
        ])
        result = auditor.audit(role='signer', resource=self.RESOURCE, member=self.MEMBER)
        assert result.key_arn == self.RESOURCE

    def test_audit_summary_contains_role_and_resource(self):
        auditor = self._auditor()
        self._mock_fetch(auditor, [
            {'role': 'roles/cloudkms.signerVerifier', 'members': [self.MEMBER]},
        ])
        result = auditor.audit(role='signer', resource=self.RESOURCE, member=self.MEMBER)
        summary = result.summary()
        assert 'signer' in summary
        assert 'cryptoKeys' in summary

    def test_audit_all_skips_roles_without_members(self):
        auditor = self._auditor()
        self._mock_fetch(auditor, [
            {'role': 'roles/cloudkms.signerVerifier', 'members': [self.MEMBER]},
        ])
        results = auditor.audit_all(
            resource=self.RESOURCE,
            members={'signer': self.MEMBER},  # vault, encryptor intentionally omitted
        )
        assert 'signer' in results
        assert 'vault' not in results
        assert 'encryptor' not in results

    def test_to_dict_includes_expected_and_actual(self):
        auditor = self._auditor()
        self._mock_fetch(auditor, [
            {'role': 'roles/cloudkms.signerVerifier', 'members': [self.MEMBER]},
        ])
        result = auditor.audit(role='signer', resource=self.RESOURCE, member=self.MEMBER)
        d = result.to_dict()
        assert 'expected_allow' in d
        assert 'actual_allow' in d
        assert isinstance(d['passed'], bool)

    def test_import_error_without_gcp_kms(self):
        import unittest.mock as mock

        auditor = self._auditor()
        with mock.patch.dict('sys.modules', {'google.cloud': None, 'google.cloud.kms': None}):
            auditor._client = None
            with pytest.raises((ImportError, TypeError)):
                auditor._kms_client()
