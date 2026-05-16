"""
hsed.integrations.aws_kms
─────────────────────────
Translate HSED Permission Policies → AWS KMS IAM JSON policies.

Mapping (HSED bit → KMS actions):

    H (Hash/Verify)  → kms:Verify, kms:GetPublicKey, kms:DescribeKey
    S (Sign)         → kms:Sign, kms:GetPublicKey, kms:DescribeKey
    E (Encrypt)      → kms:Encrypt, kms:GenerateDataKey,
                        kms:GenerateDataKeyWithoutPlaintext, kms:DescribeKey
    D (Decrypt)      → kms:Decrypt, kms:GenerateDataKey, kms:DescribeKey

Usage:

    from hsed import Policy, Role
    from hsed.integrations.aws_kms import AWSKMSGenerator

    policy = Policy('ci-prod')
    policy.add_role(Role('signer', permissions=12))

    gen = AWSKMSGenerator(policy)
    doc = gen.generate(role='signer', key_arn='arn:aws:kms:us-east-1:123:key/abc')
    print(doc.to_json())
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from ..core.permissions import Bit, Role, active_bits, permission_string
from ..core.policy import Policy, RoleNotFoundError

# ---------------------------------------------------------------------------
# KMS action mapping
# ---------------------------------------------------------------------------

# Actions per HSED bit, no duplicates within a bit block, deduplication
# happens at document assembly time across all active bits.
_BIT_ACTIONS: dict[Bit, list[str]] = {
    Bit.HASH: [
        "kms:Verify",
        "kms:GetPublicKey",
        "kms:DescribeKey",
    ],
    Bit.SIGN: [
        "kms:Sign",
        "kms:GetPublicKey",
        "kms:DescribeKey",
    ],
    Bit.ENCRYPT: [
        "kms:Encrypt",
        "kms:GenerateDataKey",
        "kms:GenerateDataKeyWithoutPlaintext",
        "kms:DescribeKey",
    ],
    Bit.DECRYPT: [
        "kms:Decrypt",
        "kms:GenerateDataKey",
        "kms:DescribeKey",
    ],
}

# Actions that should ALWAYS be denied regardless of permission level
_ALWAYS_DENY: list[str] = [
    "kms:DeleteAlias",
    "kms:DeleteImportedKeyMaterial",
    "kms:DisableKey",
    "kms:ScheduleKeyDeletion",
]


def _actions_for_permissions(permissions: int) -> list[str]:
    """Return a sorted, deduplicated list of KMS actions for a permission mask."""
    actions: set[str] = set()
    for bit in active_bits(permissions):
        actions.update(_BIT_ACTIONS.get(bit, []))
    return sorted(actions)


# ---------------------------------------------------------------------------
# IAM document model
# ---------------------------------------------------------------------------

@dataclass
class KMSStatement:
    """A single IAM policy Statement block."""

    effect: str                      # "Allow" | "Deny"
    actions: list[str]
    resources: list[str]
    sid: str = ""
    principals: list[str] = field(default_factory=list)
    conditions: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict:
        stmt: dict[str, Any] = {}
        if self.sid:
            stmt["Sid"] = self.sid
        stmt["Effect"] = self.effect
        if self.principals:
            stmt["Principal"] = (
                self.principals[0] if len(self.principals) == 1 else self.principals
            )
        stmt["Action"] = sorted(self.actions)
        stmt["Resource"] = (
            self.resources[0] if len(self.resources) == 1 else sorted(self.resources)
        )
        if self.conditions:
            stmt["Condition"] = self.conditions
        return stmt


@dataclass
class KMSPolicyDocument:
    """Full IAM policy document for a KMS key."""

    role_name: str
    permissions: int
    key_arn: str
    statements: list[KMSStatement]
    version: str = "2012-10-17"

    # Metadata (not in IAM output)
    hsed_label: str = ""
    policy_name: str = ""

    def to_dict(self) -> dict:
        return {
            "Version": self.version,
            "Statement": [s.to_dict() for s in self.statements],
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def metadata(self) -> dict:
        """Return HSED metadata dict (for comments / tagging)."""
        return {
            "hsed_role": self.role_name,
            "hsed_permissions": self.permissions,
            "hsed_label": self.hsed_label or permission_string(self.permissions),
            "hsed_policy": self.policy_name,
            "kms_key_arn": self.key_arn,
        }


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------

class AWSKMSGenerator:
    """
    Generates AWS KMS IAM policy documents from an HSED Policy.

    Parameters
    ----------
    policy:
        The HSED Policy containing roles to translate.
    include_deny_statement:
        If True (default), append an explicit Deny statement for destructive
        KMS operations regardless of the role's permissions.

    Examples
    --------
    >>> from hsed import Policy, Role
    >>> from hsed.integrations.aws_kms import AWSKMSGenerator
    >>> p = Policy('test')
    >>> p.add_role(Role('signer', permissions=12))
    >>> gen = AWSKMSGenerator(p)
    >>> doc = gen.generate(role='signer', key_arn='arn:aws:kms:us-east-1:000:key/x')
    >>> 'kms:Sign' in doc.to_json()
    True
    """

    def __init__(
        self,
        policy: Policy,
        *,
        include_deny_statement: bool = True,
    ) -> None:
        self.policy = policy
        self.include_deny_statement = include_deny_statement

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def generate(
        self,
        *,
        role: str,
        key_arn: str,
        principal: str | None = None,
    ) -> KMSPolicyDocument:
        """
        Generate an IAM policy document for a single role.

        Parameters
        ----------
        role:
            Name of the role in the Policy.
        key_arn:
            The KMS key ARN to scope the policy to. Use '*' for all keys
            (not recommended in production).
        principal:
            Optional IAM principal ARN (e.g. 'arn:aws:iam::123:role/ci').
            If omitted, no Principal block is emitted (resource-based policy).

        Returns
        -------
        KMSPolicyDocument
            The full IAM policy document.
        """
        resolved: Role = self.policy.get_role(role)
        return self._build_document(
            role=resolved,
            key_arn=key_arn,
            principal=principal,
            policy_name=self.policy.name,
        )

    def generate_all(
        self,
        *,
        key_arn: str,
        principals: dict[str, str] | None = None,
    ) -> dict[str, KMSPolicyDocument]:
        """
        Generate IAM policy documents for all roles in the Policy.

        Parameters
        ----------
        key_arn:
            KMS key ARN applied to all generated documents.
        principals:
            Optional mapping of role_name → principal ARN.

        Returns
        -------
        dict[str, KMSPolicyDocument]
            Keyed by role name.
        """
        principals = principals or {}
        return {
            role.name: self._build_document(
                role=role,
                key_arn=key_arn,
                principal=principals.get(role.name),
                policy_name=self.policy.name,
            )
            for role in self.policy.roles()
        }

    # ------------------------------------------------------------------
    # Internal builders
    # ------------------------------------------------------------------

    def _build_document(
        self,
        *,
        role: Role,
        key_arn: str,
        principal: str | None,
        policy_name: str,
    ) -> KMSPolicyDocument:
        actions = _actions_for_permissions(role.permissions)
        statements: list[KMSStatement] = []

        # Allow statement
        allow_stmt = KMSStatement(
            sid=f"HSED{permission_string(role.permissions).replace('-', '')}Allow",
            effect="Allow",
            actions=actions if actions else ["kms:DescribeKey"],
            resources=[key_arn],
            principals=[principal] if principal else [],
        )
        statements.append(allow_stmt)

        # Deny destructive operations
        if self.include_deny_statement:
            deny_stmt = KMSStatement(
                sid="HSEDDenyDestructive",
                effect="Deny",
                actions=_ALWAYS_DENY,
                resources=[key_arn],
                principals=[principal] if principal else [],
            )
            statements.append(deny_stmt)

        return KMSPolicyDocument(
            role_name=role.name,
            permissions=role.permissions,
            key_arn=key_arn,
            statements=statements,
            hsed_label=permission_string(role.permissions),
            policy_name=policy_name,
        )

    # ------------------------------------------------------------------
    # Convenience: inline key policy (resource-based)
    # ------------------------------------------------------------------

    def key_policy(
        self,
        *,
        role: str,
        key_arn: str,
        account_id: str,
        principal_arns: list[str],
    ) -> str:
        """
        Build an AWS KMS key resource policy (JSON string) that grants
        the HSED role permissions to the listed IAM principals.

        Always includes kms:* Allow for root (required by AWS).

        Parameters
        ----------
        role:
            HSED role name.
        key_arn:
            ARN of the KMS key.
        account_id:
            12-digit AWS account ID.
        principal_arns:
            List of IAM principal ARNs to grant permissions to.

        Returns
        -------
        str
            JSON key policy document.
        """
        resolved = self.policy.get_role(role)
        actions = _actions_for_permissions(resolved.permissions)

        root_stmt = KMSStatement(
            sid="EnableRootAccess",
            effect="Allow",
            actions=["kms:*"],
            resources=["*"],
            principals=[f"arn:aws:iam::{account_id}:root"],
        )

        role_stmt = KMSStatement(
            sid=f"HSED{permission_string(resolved.permissions).replace('-', '')}",
            effect="Allow",
            actions=actions or ["kms:DescribeKey"],
            resources=["*"],
            principals=principal_arns,
        )

        doc = {"Version": "2012-10-17", "Statement": [root_stmt.to_dict(), role_stmt.to_dict()]}
        return json.dumps(doc, indent=2)
