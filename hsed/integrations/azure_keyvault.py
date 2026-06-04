"""
hsed.integrations.azure_keyvault
─────────────────────────────────
Translate HSED Policies → Azure Key Vault access policies and RBAC
role assignments.

Two output modes:

1. Access Policy (classic vault model):
   Generates the `accessPolicies` block for ARM templates or az CLI.

2. RBAC Role Assignment (vault-level or key-level):
   Generates Azure RBAC role assignment JSON using built-in Key Vault
   data plane roles.

HSED bit → Azure key permissions:

    H (Hash/Verify)  → ["verify", "get"]
    S (Sign)         → ["sign", "get"]
    E (Encrypt)      → ["encrypt", "wrapKey", "get"]
    D (Decrypt)      → ["decrypt", "unwrapKey", "get"]

HSED bit → Azure RBAC built-in roles (closest fit):

    H+S              → Key Vault Crypto User (sign + verify)
    E+D              → Key Vault Crypto User (encrypt + decrypt)
    H+S+E+D (root)   → Key Vault Crypto Officer
    H only           → Key Vault Reader (read-only)

Usage:

    from hsed import Policy, Role
    from hsed.integrations.azure_keyvault import AzureKeyVaultGenerator

    policy = Policy('ci')
    policy.add_role(Role('signer', permissions=12))

    gen = AzureKeyVaultGenerator(policy)

    # Access policy document
    doc = gen.generate(
        role='signer',
        tenant_id='00000000-0000-0000-0000-000000000000',
        object_id='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
    )
    print(doc.to_json())

    # RBAC role assignment
    rbac = gen.generate_rbac(
        role='signer',
        scope='/subscriptions/.../resourceGroups/.../providers/Microsoft.KeyVault/vaults/my-vault',
        principal_id='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
    )
    print(rbac.to_json())
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field
from typing import Any

from ..core.permissions import Bit, Role, active_bits, permission_string
from ..core.policy import Policy


# ---------------------------------------------------------------------------
# Permission mapping
# ---------------------------------------------------------------------------

_BIT_KEY_PERMISSIONS: dict[Bit, list[str]] = {
    Bit.HASH: ["verify", "get"],
    Bit.SIGN: ["sign", "get"],
    Bit.ENCRYPT: ["encrypt", "wrapKey", "get"],
    Bit.DECRYPT: ["decrypt", "unwrapKey", "get"],
}

# Built-in Azure RBAC role IDs for Key Vault data plane
# https://learn.microsoft.com/en-us/azure/key-vault/general/rbac-guide
_RBAC_ROLES: dict[str, tuple[str, str]] = {
    # name → (role_definition_id, description)
    "Key Vault Crypto Officer": (
        "14b46e9e-c2b7-41b4-b07b-48a6ebf60603",
        "Full key management: create, read, update, delete, sign, verify, encrypt, decrypt",
    ),
    "Key Vault Crypto User": (
        "12338af0-0e69-4776-bea7-57ae8d297424",
        "Perform cryptographic operations using keys",
    ),
    "Key Vault Reader": (
        "21090545-7ca7-4776-b22c-e363652d74d2",
        "Read Key Vault metadata and certificates; cannot read secrets or keys",
    ),
    "Key Vault Secrets User": (
        "4633458b-17de-408a-b874-0445c86b69e6",
        "Read secret contents",
    ),
}


def _key_permissions_for(permissions: int) -> list[str]:
    """Return deduplicated, sorted Azure key permission strings for a mask."""
    perms: set[str] = set()
    for bit in active_bits(permissions):
        perms.update(_BIT_KEY_PERMISSIONS.get(bit, []))
    return sorted(perms)


def _rbac_role_for(permissions: int) -> str:
    """Map an HSED permission mask to the closest Azure RBAC built-in role name."""
    bits = set(active_bits(permissions))
    # Full crypto authority
    if bits >= {Bit.HASH, Bit.SIGN, Bit.ENCRYPT, Bit.DECRYPT}:
        return "Key Vault Crypto Officer"
    # Any active crypto op that isn't just reading
    if bits & {Bit.SIGN, Bit.ENCRYPT, Bit.DECRYPT}:
        return "Key Vault Crypto User"
    # Hash/verify only → reader
    if bits == {Bit.HASH}:
        return "Key Vault Reader"
    # No permissions
    return "Key Vault Reader"


# ---------------------------------------------------------------------------
# Access policy document
# ---------------------------------------------------------------------------


@dataclass
class AzureAccessPolicyDocument:
    """Azure Key Vault access policy block for one principal."""

    role_name: str
    permissions: int
    tenant_id: str
    object_id: str
    key_permissions: list[str]
    secret_permissions: list[str] = field(default_factory=list)
    certificate_permissions: list[str] = field(default_factory=list)
    policy_name: str = ""

    def to_dict(self) -> dict:
        return {
            "tenantId": self.tenant_id,
            "objectId": self.object_id,
            "permissions": {
                "keys": self.key_permissions,
                "secrets": self.secret_permissions,
                "certificates": self.certificate_permissions,
            },
        }

    def to_arm_fragment(self) -> dict:
        """ARM template accessPolicies array entry."""
        return {
            "type": "Microsoft.KeyVault/vaults/accessPolicies",
            "apiVersion": "2022-07-01",
            "properties": {"accessPolicies": [self.to_dict()]},
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def metadata(self) -> dict:
        return {
            "hsed_role": self.role_name,
            "hsed_permissions": self.permissions,
            "hsed_label": permission_string(self.permissions),
            "azure_object_id": self.object_id,
            "azure_tenant_id": self.tenant_id,
        }


# ---------------------------------------------------------------------------
# RBAC role assignment document
# ---------------------------------------------------------------------------


@dataclass
class AzureRBACAssignment:
    """Azure RBAC role assignment for a Key Vault scope."""

    role_name: str
    permissions: int
    scope: str
    principal_id: str
    rbac_role_name: str
    rbac_role_id: str
    assignment_id: str = field(default_factory=lambda: str(uuid.uuid4()))
    policy_name: str = ""

    def to_dict(self) -> dict:
        return {
            "type": "Microsoft.Authorization/roleAssignments",
            "apiVersion": "2022-04-01",
            "name": self.assignment_id,
            "properties": {
                "roleDefinitionId": self.rbac_role_id,
                "principalId": self.principal_id,
                "scope": self.scope,
                "description": (
                    f"HSED role '{self.role_name}' "
                    f"({permission_string(self.permissions)}/{self.permissions})"
                ),
            },
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def metadata(self) -> dict:
        return {
            "hsed_role": self.role_name,
            "hsed_permissions": self.permissions,
            "hsed_label": permission_string(self.permissions),
            "azure_rbac_role": self.rbac_role_name,
            "azure_rbac_role_id": self.rbac_role_id,
            "azure_scope": self.scope,
        }


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


class AzureKeyVaultGenerator:
    """
    Generates Azure Key Vault access policies and RBAC assignments
    from an HSED Policy.

    Parameters
    ----------
    policy:
        The HSED Policy containing roles to translate.

    Examples
    --------
    >>> from hsed import Policy, Role
    >>> from hsed.integrations.azure_keyvault import AzureKeyVaultGenerator
    >>> p = Policy('ci')
    >>> p.add_role(Role('signer', permissions=12))
    >>> gen = AzureKeyVaultGenerator(p)
    >>> doc = gen.generate(
    ...     role='signer',
    ...     tenant_id='tenant-123',
    ...     object_id='object-456',
    ... )
    >>> 'sign' in doc.key_permissions
    True
    >>> 'decrypt' in doc.key_permissions
    False
    """

    def __init__(self, policy: Policy) -> None:
        self.policy = policy

    def generate(
        self,
        *,
        role: str,
        tenant_id: str,
        object_id: str,
        secret_permissions: list[str] | None = None,
        certificate_permissions: list[str] | None = None,
    ) -> AzureAccessPolicyDocument:
        """
        Generate an Azure Key Vault access policy document for a role.

        Parameters
        ----------
        role:
            HSED role name in the policy.
        tenant_id:
            Azure AD tenant ID (GUID).
        object_id:
            Azure AD object ID of the principal (user, group, or service principal).
        secret_permissions / certificate_permissions:
            Optional explicit lists; defaults to empty (HSED only models keys).
        """
        resolved: Role = self.policy.get_role(role)
        return AzureAccessPolicyDocument(
            role_name=resolved.name,
            permissions=resolved.permissions,
            tenant_id=tenant_id,
            object_id=object_id,
            key_permissions=_key_permissions_for(resolved.permissions),
            secret_permissions=secret_permissions or [],
            certificate_permissions=certificate_permissions or [],
            policy_name=self.policy.name,
        )

    def generate_rbac(
        self,
        *,
        role: str,
        scope: str,
        principal_id: str,
        assignment_id: str | None = None,
    ) -> AzureRBACAssignment:
        """
        Generate an Azure RBAC role assignment for a Key Vault scope.

        Parameters
        ----------
        role:
            HSED role name in the policy.
        scope:
            Azure resource scope, e.g.
            '/subscriptions/{sub}/resourceGroups/{rg}/providers/
            Microsoft.KeyVault/vaults/{vault}'.
        principal_id:
            Azure AD object ID of the assignee.
        assignment_id:
            Optional explicit GUID for the role assignment; auto-generated if omitted.
        """
        resolved: Role = self.policy.get_role(role)
        rbac_role_name = _rbac_role_for(resolved.permissions)
        rbac_role_id, _ = _RBAC_ROLES[rbac_role_name]

        return AzureRBACAssignment(
            role_name=resolved.name,
            permissions=resolved.permissions,
            scope=scope,
            principal_id=principal_id,
            rbac_role_name=rbac_role_name,
            rbac_role_id=rbac_role_id,
            assignment_id=assignment_id or str(uuid.uuid4()),
            policy_name=self.policy.name,
        )

    def generate_all(
        self,
        *,
        tenant_id: str,
        object_ids: dict[str, str] | None = None,
    ) -> dict[str, AzureAccessPolicyDocument]:
        """
        Generate access policy documents for all roles.

        Parameters
        ----------
        tenant_id:
            Azure AD tenant ID applied to all documents.
        object_ids:
            Optional mapping of role_name → object_id. Roles without an entry
            receive a placeholder object_id.
        """
        object_ids = object_ids or {}
        return {
            role.name: self.generate(
                role=role.name,
                tenant_id=tenant_id,
                object_id=object_ids.get(role.name, f"<object-id-for-{role.name}>"),
            )
            for role in self.policy.roles()
        }
