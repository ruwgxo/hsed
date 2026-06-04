"""
hsed.integrations.gcp_kms
─────────────────────────
Translate HSED Policies → GCP Cloud KMS IAM policy bindings.

Two output modes:

1. IAM Policy Binding — `setIamPolicy` request body for a CryptoKey resource.
2. IAM Conditions — optional CEL expression bindings for fine-grained control.

HSED bit → GCP IAM permissions:

    H (Hash/Verify)  → cloudkms.cryptoKeyVersions.useToVerify
                        cloudkms.cryptoKeys.get
    S (Sign)         → cloudkms.cryptoKeyVersions.useToSign
                        cloudkms.cryptoKeys.get
    E (Encrypt)      → cloudkms.cryptoKeyVersions.useToEncrypt
                        cloudkms.cryptoKeys.get
    D (Decrypt)      → cloudkms.cryptoKeyVersions.useToDecrypt
                        cloudkms.cryptoKeys.get

HSED mask → closest GCP predefined role:

    H+S+E+D (15)    → roles/cloudkms.cryptoKeyEncrypterDecrypter  (+ sign/verify)
    H+S     (12)    → roles/cloudkms.signerVerifier
    E+D     ( 3)    → roles/cloudkms.cryptoKeyEncrypterDecrypter
    H+D     ( 9)    → roles/cloudkms.cryptoKeyDecrypter
    H+E     (10)    → roles/cloudkms.cryptoKeyEncrypter
    H       ( 8)    → roles/cloudkms.viewer

Usage:

    from hsed import Policy, Role
    from hsed.integrations.gcp_kms import GCPKMSGenerator

    policy = Policy('ci')
    policy.add_role(Role('signer', permissions=12))

    gen = GCPKMSGenerator(policy)
    doc = gen.generate(
        role='signer',
        member='serviceAccount:ci-runner@project.iam.gserviceaccount.com',
        resource='projects/my-project/locations/global/keyRings/prod/cryptoKeys/signing-key',
    )
    print(doc.to_json())
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any

from ..core.permissions import Bit, Role, active_bits, permission_string
from ..core.policy import Policy


# ---------------------------------------------------------------------------
# Permission mapping
# ---------------------------------------------------------------------------

_BIT_PERMISSIONS: dict[Bit, list[str]] = {
    Bit.HASH: [
        "cloudkms.cryptoKeyVersions.useToVerify",
        "cloudkms.cryptoKeys.get",
    ],
    Bit.SIGN: [
        "cloudkms.cryptoKeyVersions.useToSign",
        "cloudkms.cryptoKeys.get",
    ],
    Bit.ENCRYPT: [
        "cloudkms.cryptoKeyVersions.useToEncrypt",
        "cloudkms.cryptoKeys.get",
    ],
    Bit.DECRYPT: [
        "cloudkms.cryptoKeyVersions.useToDecrypt",
        "cloudkms.cryptoKeys.get",
    ],
}

# Predefined GCP roles closest to each HSED mask
# Maps exact permission mask → GCP predefined role
_PREDEFINED_ROLES: dict[int, str] = {
    15: "roles/cloudkms.cryptoKeyEncrypterDecrypter",  # full (no dedicated sign+encrypt)
    14: "roles/cloudkms.cryptoKeyEncrypterDecrypter",  # HSE- → closest
    12: "roles/cloudkms.signerVerifier",  # HS--
    11: "roles/cloudkms.cryptoKeyEncrypterDecrypter",  # -SED
    10: "roles/cloudkms.cryptoKeyEncrypter",  # H-E-
    9: "roles/cloudkms.cryptoKeyDecrypter",  # H--D
    8: "roles/cloudkms.viewer",  # H---
    7: "roles/cloudkms.cryptoKeyEncrypterDecrypter",  # -SED
    6: "roles/cloudkms.signerVerifier",  # -SE-
    5: "roles/cloudkms.signerVerifier",  # -S-D
    4: "roles/cloudkms.signerVerifier",  # -S--
    3: "roles/cloudkms.cryptoKeyEncrypterDecrypter",  # --ED
    2: "roles/cloudkms.cryptoKeyEncrypter",  # --E-
    1: "roles/cloudkms.cryptoKeyDecrypter",  # ---D
    0: "roles/cloudkms.viewer",  # none → viewer (least privilege)
}


def _gcp_permissions_for(permissions: int) -> list[str]:
    """Return deduplicated, sorted GCP IAM permissions for a mask."""
    perms: set[str] = set()
    for bit in active_bits(permissions):
        perms.update(_BIT_PERMISSIONS.get(bit, []))
    return sorted(perms)


def _predefined_role_for(permissions: int) -> str:
    """Return the closest GCP predefined role for an HSED mask."""
    return _PREDEFINED_ROLES.get(permissions, "roles/cloudkms.viewer")


# ---------------------------------------------------------------------------
# IAM binding / policy document
# ---------------------------------------------------------------------------


@dataclass
class GCPIAMBinding:
    """A single IAM binding block."""

    role: str
    members: list[str]
    condition: dict[str, str] | None = None

    def to_dict(self) -> dict:
        d: dict[str, Any] = {
            "role": self.role,
            "members": sorted(self.members),
        }
        if self.condition:
            d["condition"] = self.condition
        return d


@dataclass
class GCPKMSPolicyDocument:
    """GCP Cloud KMS IAM policy document for a CryptoKey resource."""

    role_name: str
    permissions: int
    resource: str
    member: str
    bindings: list[GCPIAMBinding]
    use_predefined_role: bool = True
    policy_name: str = ""

    def to_dict(self) -> dict:
        return {
            "bindings": [b.to_dict() for b in self.bindings],
            "version": 1,
        }

    def to_setiam_request(self) -> dict:
        """Full setIamPolicy request body."""
        return {"policy": self.to_dict()}

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)

    def to_gcloud_command(self) -> str:
        """Return the equivalent gcloud CLI command."""
        binding = self.bindings[0] if self.bindings else None
        if not binding:
            return "# No bindings to apply"
        role = binding.role
        member = self.member
        resource = self.resource
        return (
            f"gcloud kms keys add-iam-policy-binding \\\n"
            f"  {resource.split('/')[-1]} \\\n"
            f"  --keyring={self._keyring()} \\\n"
            f"  --location={self._location()} \\\n"
            f"  --project={self._project()} \\\n"
            f"  --role={role} \\\n"
            f"  --member={member}"
        )

    def metadata(self) -> dict:
        return {
            "hsed_role": self.role_name,
            "hsed_permissions": self.permissions,
            "hsed_label": permission_string(self.permissions),
            "gcp_resource": self.resource,
            "gcp_member": self.member,
        }

    # helpers for gcloud command
    def _project(self) -> str:
        parts = self.resource.split("/")
        try:
            return parts[parts.index("projects") + 1]
        except (ValueError, IndexError):
            return "<project>"

    def _location(self) -> str:
        parts = self.resource.split("/")
        try:
            return parts[parts.index("locations") + 1]
        except (ValueError, IndexError):
            return "<location>"

    def _keyring(self) -> str:
        parts = self.resource.split("/")
        try:
            return parts[parts.index("keyRings") + 1]
        except (ValueError, IndexError):
            return "<keyring>"


# ---------------------------------------------------------------------------
# Generator
# ---------------------------------------------------------------------------


class GCPKMSGenerator:
    """
    Generates GCP Cloud KMS IAM policy bindings from an HSED Policy.

    Parameters
    ----------
    policy:
        The HSED Policy containing roles to translate.
    use_predefined_roles:
        If True (default), use closest GCP predefined role.
        If False, generate a custom role binding with granular permissions
        (requires a custom role to exist in GCP).

    Examples
    --------
    >>> from hsed import Policy, Role
    >>> from hsed.integrations.gcp_kms import GCPKMSGenerator
    >>> p = Policy('ci')
    >>> p.add_role(Role('signer', permissions=12))
    >>> gen = GCPKMSGenerator(p)
    >>> doc = gen.generate(
    ...     role='signer',
    ...     member='serviceAccount:ci@project.iam.gserviceaccount.com',
    ...     resource='projects/p/locations/global/keyRings/k/cryptoKeys/key',
    ... )
    >>> doc.bindings[0].role
    'roles/cloudkms.signerVerifier'
    """

    def __init__(self, policy: Policy, *, use_predefined_roles: bool = True) -> None:
        self.policy = policy
        self.use_predefined_roles = use_predefined_roles

    def generate(
        self,
        *,
        role: str,
        member: str,
        resource: str,
        condition: dict[str, str] | None = None,
    ) -> GCPKMSPolicyDocument:
        """
        Generate a GCP IAM policy document for a single role.

        Parameters
        ----------
        role:
            HSED role name in the policy.
        member:
            GCP IAM member string, e.g.
            'serviceAccount:sa@project.iam.gserviceaccount.com'
            or 'group:sec-team@example.com'.
        resource:
            Full CryptoKey resource path:
            'projects/{p}/locations/{l}/keyRings/{kr}/cryptoKeys/{k}'.
        condition:
            Optional IAM condition dict with keys 'title', 'description', 'expression'.
        """
        resolved: Role = self.policy.get_role(role)

        if self.use_predefined_roles:
            gcp_role = _predefined_role_for(resolved.permissions)
            binding = GCPIAMBinding(
                role=gcp_role,
                members=[member],
                condition=condition,
            )
        else:
            # Custom role placeholder — user must create a GCP custom role with
            # these permissions and reference it as roles/custom.<name>
            custom_role = f"projects/<project>/roles/hsed_{resolved.name}"
            binding = GCPIAMBinding(
                role=custom_role,
                members=[member],
                condition=condition,
            )

        return GCPKMSPolicyDocument(
            role_name=resolved.name,
            permissions=resolved.permissions,
            resource=resource,
            member=member,
            bindings=[binding],
            use_predefined_role=self.use_predefined_roles,
            policy_name=self.policy.name,
        )

    def generate_all(
        self,
        *,
        resource: str,
        members: dict[str, str] | None = None,
    ) -> dict[str, GCPKMSPolicyDocument]:
        """
        Generate IAM policy documents for all roles.

        Parameters
        ----------
        resource:
            GCP CryptoKey resource path applied to all documents.
        members:
            Optional mapping of role_name → member string.
        """
        members = members or {}
        return {
            role.name: self.generate(
                role=role.name,
                member=members.get(role.name, f"serviceAccount:<sa-for-{role.name}>"),
                resource=resource,
            )
            for role in self.policy.roles()
        }

    def merged_policy(
        self,
        *,
        resource: str,
        members: dict[str, str],
    ) -> dict:
        """
        Generate a single merged IAM policy with all role bindings.
        Suitable for `setIamPolicy` calls that replace the entire policy.

        Parameters
        ----------
        resource:
            GCP CryptoKey resource path.
        members:
            Mapping of role_name → member string (all roles must be present).
        """
        bindings: list[dict] = []
        for role in self.policy.roles():
            doc = self.generate(
                role=role.name,
                member=members[role.name],
                resource=resource,
            )
            bindings.extend(b.to_dict() for b in doc.bindings)

        # Merge bindings with the same role
        merged: dict[str, set[str]] = {}
        for b in bindings:
            merged.setdefault(b["role"], set()).update(b["members"])

        return {
            "policy": {
                "bindings": [{"role": r, "members": sorted(m)} for r, m in sorted(merged.items())],
                "version": 1,
            }
        }
