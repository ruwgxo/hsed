"""
hsed.integrations.live_audit
────────────────────────────
Live audit: fetch actual cloud KMS/Key Vault policies and compare against
expected HSED policy definitions.

Supports:
    - AWS KMS           via boto3          pip install hsed[aws]
    - Azure Key Vault   via azure-mgmt-keyvault + azure-identity
                                           pip install hsed[azure]
    - GCP Cloud KMS     via google-cloud-kms
                                           pip install hsed[gcp]

All three auditors share the same interface:
    auditor.audit(role=..., resource_uri=..., ..., strict=False) → AuditResult
    auditor.audit_all(resource_uri=..., ..., strict=False)       → dict[str, AuditResult]

AWS KMS usage:

    from hsed import Policy
    from hsed.integrations.live_audit import AWSLiveAuditor

    policy = Policy.load('production.hsed')
    auditor = AWSLiveAuditor(policy, aws_profile='production')
    result  = auditor.audit(
        role='signer',
        key_arn='arn:aws:kms:us-east-1:123456789012:key/mrk-abc',
    )
    print(result.summary())

Azure Key Vault usage:

    from hsed.integrations.live_audit import AzureLiveAuditor

    auditor = AzureLiveAuditor(policy)
    result  = auditor.audit(
        role='signer',
        vault_uri='https://my-vault.vault.azure.net',
        object_id='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
        subscription_id='11111111-2222-3333-4444-555555555555',
        resource_group='rg-prod',
        vault_name='my-vault',
    )
    print(result.summary())

GCP Cloud KMS usage:

    from hsed.integrations.live_audit import GCPLiveAuditor

    auditor = GCPLiveAuditor(policy)
    result  = auditor.audit(
        role='signer',
        resource='projects/my-project/locations/global/keyRings/prod/cryptoKeys/signing-key',
        member='serviceAccount:ci-runner@my-project.iam.gserviceaccount.com',
    )
    print(result.summary())
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..core.permissions import permission_string
from ..core.policy import Policy
from ..integrations.aws_kms import _actions_for_permissions
from ..integrations.azure_keyvault import _key_permissions_for as _azure_key_permissions_for
from ..integrations.gcp_kms import _gcp_permissions_for

# ---------------------------------------------------------------------------
# Audit result model
# ---------------------------------------------------------------------------


class FindingSeverity(str, Enum):
    OK = "OK"
    WARN = "WARN"
    FAIL = "FAIL"
    ERROR = "ERROR"


@dataclass
class AuditFinding:
    severity: FindingSeverity
    message: str
    detail: str = ""


@dataclass
class AuditResult:
    """Result of a live audit comparison for one role against one KMS key."""

    role_name: str
    permissions: int
    key_arn: str
    expected_allow: list[str]
    actual_allow: list[str]
    findings: list[AuditFinding] = field(default_factory=list)
    raw_policy: dict | None = None

    @property
    def missing_actions(self) -> list[str]:
        """Actions expected by HSED but absent from the actual policy."""
        return sorted(set(self.expected_allow) - set(self.actual_allow))

    @property
    def extra_actions(self) -> list[str]:
        """Actions present in the actual policy but not required by HSED."""
        return sorted(set(self.actual_allow) - set(self.expected_allow))

    @property
    def passed(self) -> bool:
        return not any(
            f.severity in (FindingSeverity.FAIL, FindingSeverity.ERROR) for f in self.findings
        )

    def summary(self) -> str:
        label = permission_string(self.permissions)
        lines = [
            f"Live Audit — Role '{self.role_name}' (hsed:{label}/{self.permissions})",
            f"Key: {self.key_arn}",
            "",
        ]

        if not self.findings:
            lines.append("✓  No findings — policy matches HSED definition exactly")
            return "\n".join(lines)

        for f in self.findings:
            icon = {"OK": "✓", "WARN": "⚠", "FAIL": "✗", "ERROR": "✗"}[f.severity]
            lines.append(f"  {icon}  [{f.severity}] {f.message}")
            if f.detail:
                lines.append(f"       {f.detail}")

        lines.append("")
        if self.missing_actions:
            lines.append(f"  Missing actions ({len(self.missing_actions)}):")
            for a in self.missing_actions:
                lines.append(f"    - {a}")
        if self.extra_actions:
            lines.append(f"  Extra actions ({len(self.extra_actions)}):")
            for a in self.extra_actions:
                lines.append(f"    + {a}")

        status = "PASS" if self.passed else "FAIL"
        lines.append(f"\nResult: {status}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "role": self.role_name,
            "permissions": self.permissions,
            "label": permission_string(self.permissions),
            "key_arn": self.key_arn,
            "expected_allow": self.expected_allow,
            "actual_allow": self.actual_allow,
            "missing": self.missing_actions,
            "extra": self.extra_actions,
            "findings": [
                {"severity": f.severity, "message": f.message, "detail": f.detail}
                for f in self.findings
            ],
            "passed": self.passed,
        }


# ---------------------------------------------------------------------------
# AWS live auditor
# ---------------------------------------------------------------------------


class AWSLiveAuditor:
    """
    Fetch the actual AWS KMS key policy and compare it against the
    expected HSED policy for a named role.

    Requires boto3: `pip install hsed[aws]`

    Parameters
    ----------
    policy:
        HSED Policy containing the role definitions to audit against.
    aws_profile:
        Optional AWS credentials profile name (from ~/.aws/credentials).
    aws_region:
        AWS region override. If omitted, boto3 uses its default resolution.

    Examples
    --------
    >>> from hsed import Policy
    >>> from hsed.integrations.live_audit import AWSLiveAuditor
    >>> policy = Policy.load('production.hsed')
    >>> auditor = AWSLiveAuditor(policy, aws_profile='prod-readonly')
    >>> result = auditor.audit(
    ...     role='signer',
    ...     key_arn='arn:aws:kms:us-east-1:123:key/abc',
    ... )
    >>> result.passed
    True
    """

    def __init__(
        self,
        policy: Policy,
        *,
        aws_profile: str | None = None,
        aws_region: str | None = None,
    ) -> None:
        self.policy = policy
        self.aws_profile = aws_profile
        self.aws_region = aws_region
        self._client: Any = None

    def _kms_client(self) -> Any:
        if self._client is None:
            try:
                import boto3
            except ImportError:
                raise ImportError(
                    "boto3 is required for live audits. Install with: pip install hsed[aws]"
                ) from None

            session_kwargs: dict[str, Any] = {}
            if self.aws_profile:
                session_kwargs["profile_name"] = self.aws_profile
            if self.aws_region:
                session_kwargs["region_name"] = self.aws_region

            session = boto3.Session(**session_kwargs)
            self._client = session.client("kms")
        return self._client

    def _fetch_key_policy(self, key_arn: str) -> dict:
        """Fetch and parse the default key policy for a KMS key."""
        client = self._kms_client()
        try:
            response = client.get_key_policy(KeyId=key_arn, PolicyName="default")
        except Exception as exc:
            raise RuntimeError(f"Failed to fetch key policy for {key_arn}: {exc}") from exc
        return json.loads(response["Policy"])

    def _extract_allow_actions(self, policy_doc: dict, key_arn: str) -> list[str]:
        """Extract all Allow kms:* actions from a policy document."""
        actions: set[str] = set()
        for stmt in policy_doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            # Only include if scoped to this key or '*'
            if not any(r == "*" or r == key_arn or key_arn.endswith(r) for r in resources):
                # Skip root account wildcard entries
                if "root" in str(stmt.get("Principal", "")):
                    continue
            raw = stmt.get("Action", [])
            if isinstance(raw, str):
                raw = [raw]
            actions.update(a for a in raw if a.startswith("kms:"))
        return sorted(actions)

    def audit(
        self,
        *,
        role: str,
        key_arn: str,
        strict: bool = False,
    ) -> AuditResult:
        """
        Fetch the actual KMS key policy and compare against the HSED role.

        Parameters
        ----------
        role:
            HSED role name to audit against.
        key_arn:
            KMS key ARN to audit.
        strict:
            If True, extra permissions (over-grants) produce FAIL findings.
            If False (default), extra permissions produce WARN findings.

        Returns
        -------
        AuditResult
            Full comparison result with findings and action diff.
        """
        resolved = self.policy.get_role(role)
        expected = _actions_for_permissions(resolved.permissions)
        findings: list[AuditFinding] = []
        actual: list[str] = []
        raw_policy: dict | None = None

        try:
            raw_policy = self._fetch_key_policy(key_arn)
            actual = self._extract_allow_actions(raw_policy, key_arn)
        except RuntimeError as exc:
            findings.append(
                AuditFinding(
                    severity=FindingSeverity.ERROR,
                    message="Could not fetch key policy",
                    detail=str(exc),
                )
            )
            return AuditResult(
                role_name=resolved.name,
                permissions=resolved.permissions,
                key_arn=key_arn,
                expected_allow=expected,
                actual_allow=[],
                findings=findings,
                raw_policy=None,
            )

        result = AuditResult(
            role_name=resolved.name,
            permissions=resolved.permissions,
            key_arn=key_arn,
            expected_allow=expected,
            actual_allow=actual,
            raw_policy=raw_policy,
        )

        # Missing actions — FAIL
        for action in result.missing_actions:
            findings.append(
                AuditFinding(
                    severity=FindingSeverity.FAIL,
                    message=f"Missing required action: {action}",
                    detail=f"Expected by HSED role '{resolved.name}' ({permission_string(resolved.permissions)})",
                )
            )

        # Extra actions — WARN or FAIL
        for action in result.extra_actions:
            sev = FindingSeverity.FAIL if strict else FindingSeverity.WARN
            findings.append(
                AuditFinding(
                    severity=sev,
                    message=f"Over-grant: {action} is present but not required",
                    detail="Remove this action to enforce least privilege",
                )
            )

        if not findings:
            findings.append(
                AuditFinding(
                    severity=FindingSeverity.OK,
                    message="Policy matches HSED definition exactly",
                )
            )

        result.findings = findings
        return result

    def audit_all(
        self,
        *,
        key_arn: str,
        strict: bool = False,
    ) -> dict[str, AuditResult]:
        """Audit all roles in the policy against the same key ARN."""
        return {
            role.name: self.audit(role=role.name, key_arn=key_arn, strict=strict)
            for role in self.policy.roles()
        }


# ---------------------------------------------------------------------------
# Azure Key Vault permission mapping (used for comparison)
# ---------------------------------------------------------------------------

# Normalise Azure key permission strings to lowercase for comparison.
# The management API may return mixed-case values depending on SDK version.
_AZURE_EXPECTED_PERMISSIONS: dict[int, list[str]] = {}  # populated lazily below


def _azure_normalise(perms: list[str]) -> list[str]:
    """Lower-case Azure key permission strings for stable comparison."""
    return sorted(p.lower() for p in perms)


# ---------------------------------------------------------------------------
# GCP predefined role → constituent IAM permissions (static map)
# Only cloudkms.* permissions relevant to HSED operations are included.
# Sourced from: https://cloud.google.com/kms/docs/reference/permissions-and-roles
# ---------------------------------------------------------------------------

_GCP_ROLE_PERMISSIONS: dict[str, list[str]] = {
    'roles/cloudkms.cryptoKeyEncrypterDecrypter': [
        'cloudkms.cryptoKeyVersions.useToDecrypt',
        'cloudkms.cryptoKeyVersions.useToEncrypt',
        'cloudkms.cryptoKeys.get',
    ],
    'roles/cloudkms.signerVerifier': [
        'cloudkms.cryptoKeyVersions.useToSign',
        'cloudkms.cryptoKeyVersions.useToVerify',
        'cloudkms.cryptoKeys.get',
    ],
    'roles/cloudkms.cryptoKeyEncrypter': [
        'cloudkms.cryptoKeyVersions.useToEncrypt',
        'cloudkms.cryptoKeys.get',
    ],
    'roles/cloudkms.cryptoKeyDecrypter': [
        'cloudkms.cryptoKeyVersions.useToDecrypt',
        'cloudkms.cryptoKeys.get',
    ],
    'roles/cloudkms.viewer': [
        'cloudkms.cryptoKeys.get',
        'cloudkms.cryptoKeys.list',
        'cloudkms.keyRings.get',
        'cloudkms.keyRings.list',
    ],
    # Broad roles that include all crypto operations
    'roles/owner': [
        'cloudkms.cryptoKeyVersions.useToDecrypt',
        'cloudkms.cryptoKeyVersions.useToEncrypt',
        'cloudkms.cryptoKeyVersions.useToSign',
        'cloudkms.cryptoKeyVersions.useToVerify',
        'cloudkms.cryptoKeys.get',
    ],
    'roles/editor': [
        'cloudkms.cryptoKeyVersions.useToDecrypt',
        'cloudkms.cryptoKeyVersions.useToEncrypt',
        'cloudkms.cryptoKeyVersions.useToSign',
        'cloudkms.cryptoKeyVersions.useToVerify',
        'cloudkms.cryptoKeys.get',
    ],
}


def _gcp_expand_roles(roles: list[str]) -> list[str]:
    """Expand a list of GCP role strings to their constituent permissions."""
    perms: set[str] = set()
    for role in roles:
        perms.update(_GCP_ROLE_PERMISSIONS.get(role, []))
    return sorted(perms)


# ---------------------------------------------------------------------------
# Azure Key Vault live auditor
# ---------------------------------------------------------------------------


class AzureLiveAuditor:
    """
    Fetch the actual Azure Key Vault access policy for a principal and
    compare it against the expected HSED policy for a named role.

    Audits the classic Access Policy model (vault-level permissions).
    RBAC role assignment auditing will be added in a future release.

    Requires: pip install hsed[azure]

    Parameters
    ----------
    policy:
        HSED Policy containing the role definitions to audit against.
    credential:
        Optional azure-identity credential object. Defaults to
        DefaultAzureCredential() if not provided.

    Examples
    --------
    >>> from hsed import Policy
    >>> from hsed.integrations.live_audit import AzureLiveAuditor
    >>> policy = Policy.load('production.hsed')
    >>> auditor = AzureLiveAuditor(policy)
    >>> result = auditor.audit(
    ...     role='signer',
    ...     vault_uri='https://my-vault.vault.azure.net',
    ...     object_id='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
    ...     subscription_id='11111111-2222-3333-4444-555555555555',
    ...     resource_group='rg-prod',
    ...     vault_name='my-vault',
    ... )
    >>> result.passed
    True
    """

    def __init__(
        self,
        policy: Policy,
        *,
        credential: Any | None = None,
    ) -> None:
        self.policy = policy
        self._credential = credential
        self._client: Any | None = None

    def _get_credential(self) -> Any:
        if self._credential is not None:
            return self._credential
        try:
            from azure.identity import DefaultAzureCredential
        except ImportError:
            raise ImportError(
                'azure-identity is required for Azure live audits. '
                'Install with: pip install hsed[azure]'
            ) from None
        return DefaultAzureCredential()

    def _kv_management_client(self, subscription_id: str) -> Any:
        try:
            from azure.mgmt.keyvault import KeyVaultManagementClient
        except ImportError:
            raise ImportError(
                'azure-mgmt-keyvault is required for Azure live audits. '
                'Install with: pip install hsed[azure]'
            ) from None
        return KeyVaultManagementClient(
            credential=self._get_credential(),
            subscription_id=subscription_id,
        )

    def _fetch_access_policies(
        self,
        subscription_id: str,
        resource_group: str,
        vault_name: str,
    ) -> list[Any]:
        """Return the raw list of AccessPolicyEntry objects for the vault."""
        client = self._kv_management_client(subscription_id)
        try:
            vault = client.vaults.get(resource_group, vault_name)
        except Exception as exc:
            raise RuntimeError(
                f'Failed to fetch vault {vault_name} in {resource_group}: {exc}'
            ) from exc
        return list(vault.properties.access_policies or [])

    def _extract_key_permissions(
        self,
        access_policies: list[Any],
        object_id: str,
    ) -> list[str]:
        """
        Return normalised key permission strings for the given object_id.

        Returns an empty list if no policy entry matches the object_id.
        """
        object_id_lower = object_id.lower()
        for entry in access_policies:
            if (entry.object_id or '').lower() == object_id_lower:
                raw = getattr(entry.permissions, 'keys', None) or []
                return _azure_normalise([str(p) for p in raw])
        return []

    def audit(
        self,
        *,
        role: str,
        vault_uri: str,
        object_id: str,
        subscription_id: str,
        resource_group: str,
        vault_name: str,
        strict: bool = False,
    ) -> AuditResult:
        """
        Fetch the Azure Key Vault access policy and compare against the
        HSED role definition.

        Parameters
        ----------
        role:
            HSED role name to audit against.
        vault_uri:
            Azure Key Vault URI, e.g. 'https://my-vault.vault.azure.net'.
            Used as the resource identifier in the AuditResult.
        object_id:
            Azure AD object ID (user, group, or service principal) to check.
        subscription_id:
            Azure subscription GUID.
        resource_group:
            Resource group name containing the Key Vault.
        vault_name:
            Key Vault resource name.
        strict:
            If True, over-grants produce FAIL findings instead of WARN.
        """
        resolved = self.policy.get_role(role)
        expected = _azure_normalise(_azure_key_permissions_for(resolved.permissions))
        findings: list[AuditFinding] = []
        actual: list[str] = []

        try:
            access_policies = self._fetch_access_policies(
                subscription_id, resource_group, vault_name
            )
            actual = self._extract_key_permissions(access_policies, object_id)
        except RuntimeError as exc:
            findings.append(
                AuditFinding(
                    severity=FindingSeverity.ERROR,
                    message='Could not fetch vault access policies',
                    detail=str(exc),
                )
            )
            return AuditResult(
                role_name=resolved.name,
                permissions=resolved.permissions,
                key_arn=vault_uri,
                expected_allow=expected,
                actual_allow=[],
                findings=findings,
                raw_policy=None,
            )

        if not actual:
            findings.append(
                AuditFinding(
                    severity=FindingSeverity.FAIL,
                    message=f'No access policy entry found for object_id {object_id}',
                    detail='Principal has no key permissions in this vault',
                )
            )
            return AuditResult(
                role_name=resolved.name,
                permissions=resolved.permissions,
                key_arn=vault_uri,
                expected_allow=expected,
                actual_allow=[],
                findings=findings,
                raw_policy=None,
            )

        result = AuditResult(
            role_name=resolved.name,
            permissions=resolved.permissions,
            key_arn=vault_uri,
            expected_allow=expected,
            actual_allow=actual,
            raw_policy={'object_id': object_id, 'key_permissions': actual},
        )

        for action in result.missing_actions:
            findings.append(
                AuditFinding(
                    severity=FindingSeverity.FAIL,
                    message=f'Missing required permission: {action}',
                    detail=(
                        f"Expected by HSED role '{resolved.name}' "
                        f'({permission_string(resolved.permissions)})'
                    ),
                )
            )

        for action in result.extra_actions:
            sev = FindingSeverity.FAIL if strict else FindingSeverity.WARN
            findings.append(
                AuditFinding(
                    severity=sev,
                    message=f'Over-grant: {action} is present but not required',
                    detail='Remove this permission to enforce least privilege',
                )
            )

        if not findings:
            findings.append(
                AuditFinding(
                    severity=FindingSeverity.OK,
                    message='Access policy matches HSED definition exactly',
                )
            )

        result.findings = findings
        return result

    def audit_all(
        self,
        *,
        vault_uri: str,
        object_ids: dict[str, str],
        subscription_id: str,
        resource_group: str,
        vault_name: str,
        strict: bool = False,
    ) -> dict[str, AuditResult]:
        """
        Audit all roles in the policy against the same vault.

        Parameters
        ----------
        object_ids:
            Mapping of role_name → Azure AD object_id. Roles without an entry
            are skipped.
        """
        results: dict[str, AuditResult] = {}
        for role_obj in self.policy.roles():
            if role_obj.name not in object_ids:
                continue
            results[role_obj.name] = self.audit(
                role=role_obj.name,
                vault_uri=vault_uri,
                object_id=object_ids[role_obj.name],
                subscription_id=subscription_id,
                resource_group=resource_group,
                vault_name=vault_name,
                strict=strict,
            )
        return results


# ---------------------------------------------------------------------------
# GCP Cloud KMS live auditor
# ---------------------------------------------------------------------------


class GCPLiveAuditor:
    """
    Fetch the actual GCP Cloud KMS IAM policy for a CryptoKey resource and
    compare it against the expected HSED policy for a named role.

    Resolves the member's effective permissions by expanding all assigned
    predefined roles using a static permission map (no IAM API call required).

    Requires: pip install hsed[gcp]

    Parameters
    ----------
    policy:
        HSED Policy containing the role definitions to audit against.
    credentials:
        Optional google.oauth2 credentials object. Defaults to application
        default credentials if not provided.

    Examples
    --------
    >>> from hsed import Policy
    >>> from hsed.integrations.live_audit import GCPLiveAuditor
    >>> policy = Policy.load('production.hsed')
    >>> auditor = GCPLiveAuditor(policy)
    >>> result = auditor.audit(
    ...     role='signer',
    ...     resource='projects/my-project/locations/global/keyRings/prod/cryptoKeys/signing-key',
    ...     member='serviceAccount:ci-runner@my-project.iam.gserviceaccount.com',
    ... )
    >>> result.passed
    True
    """

    def __init__(
        self,
        policy: Policy,
        *,
        credentials: Any | None = None,
    ) -> None:
        self.policy = policy
        self._credentials = credentials
        self._client: Any | None = None

    def _kms_client(self) -> Any:
        if self._client is None:
            try:
                from google.cloud import kms
            except ImportError:
                raise ImportError(
                    'google-cloud-kms is required for GCP live audits. '
                    'Install with: pip install hsed[gcp]'
                ) from None
            kwargs: dict[str, Any] = {}
            if self._credentials is not None:
                kwargs['credentials'] = self._credentials
            self._client = kms.KeyManagementServiceClient(**kwargs)
        return self._client

    def _fetch_iam_policy(self, resource: str) -> list[dict[str, Any]]:
        """
        Fetch the IAM policy for a CryptoKey resource.

        Returns a list of binding dicts: [{'role': str, 'members': [str]}]
        """
        client = self._kms_client()
        try:
            # google-cloud-kms uses the REST API under the hood
            from google.iam.v1 import iam_policy_pb2  # type: ignore[import]
            request = iam_policy_pb2.GetIamPolicyRequest(resource=resource)
            policy = client.get_iam_policy(request=request)
        except Exception as exc:
            raise RuntimeError(
                f'Failed to fetch IAM policy for {resource}: {exc}'
            ) from exc

        bindings: list[dict[str, Any]] = []
        for binding in policy.bindings:
            bindings.append({
                'role': binding.role,
                'members': list(binding.members),
            })
        return bindings

    def _member_roles(self, bindings: list[dict[str, Any]], member: str) -> list[str]:
        """Return the list of GCP roles assigned to the given member."""
        member_lower = member.lower()
        roles: list[str] = []
        for binding in bindings:
            members_lower = [m.lower() for m in binding.get('members', [])]
            if member_lower in members_lower or 'allUsers' in binding.get('members', []):
                roles.append(binding['role'])
        return roles

    def audit(
        self,
        *,
        role: str,
        resource: str,
        member: str,
        strict: bool = False,
    ) -> AuditResult:
        """
        Fetch the GCP Cloud KMS IAM policy and compare against the HSED role.

        Parameters
        ----------
        role:
            HSED role name to audit against.
        resource:
            Full CryptoKey resource path:
            'projects/{p}/locations/{l}/keyRings/{kr}/cryptoKeys/{k}'.
            Used as the resource identifier in the AuditResult.
        member:
            GCP IAM member string, e.g.
            'serviceAccount:ci-runner@project.iam.gserviceaccount.com'.
        strict:
            If True, over-grants produce FAIL findings instead of WARN.
        """
        resolved = self.policy.get_role(role)
        expected = _gcp_permissions_for(resolved.permissions)
        findings: list[AuditFinding] = []
        actual: list[str] = []
        raw_bindings: list[dict[str, Any]] | None = None

        try:
            raw_bindings = self._fetch_iam_policy(resource)
            assigned_roles = self._member_roles(raw_bindings, member)
            actual = _gcp_expand_roles(assigned_roles)
        except RuntimeError as exc:
            findings.append(
                AuditFinding(
                    severity=FindingSeverity.ERROR,
                    message='Could not fetch IAM policy',
                    detail=str(exc),
                )
            )
            return AuditResult(
                role_name=resolved.name,
                permissions=resolved.permissions,
                key_arn=resource,
                expected_allow=expected,
                actual_allow=[],
                findings=findings,
                raw_policy=None,
            )

        if not actual:
            findings.append(
                AuditFinding(
                    severity=FindingSeverity.FAIL,
                    message=f'No IAM bindings found for member {member}',
                    detail='Member has no roles on this CryptoKey resource',
                )
            )
            return AuditResult(
                role_name=resolved.name,
                permissions=resolved.permissions,
                key_arn=resource,
                expected_allow=expected,
                actual_allow=[],
                findings=findings,
                raw_policy={'bindings': raw_bindings},
            )

        result = AuditResult(
            role_name=resolved.name,
            permissions=resolved.permissions,
            key_arn=resource,
            expected_allow=expected,
            actual_allow=actual,
            raw_policy={'bindings': raw_bindings},
        )

        for perm in result.missing_actions:
            findings.append(
                AuditFinding(
                    severity=FindingSeverity.FAIL,
                    message=f'Missing required permission: {perm}',
                    detail=(
                        f"Expected by HSED role '{resolved.name}' "
                        f'({permission_string(resolved.permissions)})'
                    ),
                )
            )

        for perm in result.extra_actions:
            sev = FindingSeverity.FAIL if strict else FindingSeverity.WARN
            findings.append(
                AuditFinding(
                    severity=sev,
                    message=f'Over-grant: {perm} is present but not required',
                    detail='Member has more permissions than HSED role requires',
                )
            )

        if not findings:
            findings.append(
                AuditFinding(
                    severity=FindingSeverity.OK,
                    message='IAM policy matches HSED definition exactly',
                )
            )

        result.findings = findings
        return result

    def audit_all(
        self,
        *,
        resource: str,
        members: dict[str, str],
        strict: bool = False,
    ) -> dict[str, AuditResult]:
        """
        Audit all roles in the policy against the same CryptoKey resource.

        Parameters
        ----------
        members:
            Mapping of role_name → GCP IAM member string. Roles without an
            entry are skipped.
        """
        results: dict[str, AuditResult] = {}
        for role_obj in self.policy.roles():
            if role_obj.name not in members:
                continue
            results[role_obj.name] = self.audit(
                role=role_obj.name,
                resource=resource,
                member=members[role_obj.name],
                strict=strict,
            )
        return results
