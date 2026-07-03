"""
hsed - Hash | Sign | Encrypt | Decrypt
───────────────────────────────────────
A Unix chmod-inspired permission model for cryptographic operations.

    from hsed import Policy, Role, Bit
    from hsed.core.enforcement import enforce

    policy = Policy('ci')
    policy.add_role(Role('signer', permissions=12))  # H+S

    @policy.enforce_op(role='signer', requires=Bit.SIGN)
    def sign_artifact(data: bytes) -> bytes:
        ...

    @policy.enforce_op(role='signer', requires=Bit.DECRYPT)
    def decrypt_secret(ciphertext: bytes) -> bytes:
        ...  # raises HSEDPermissionError
"""

from .core.enforcement import PermissionScope, enforce

# Monkey-patch Policy with enforce_op from PolicyEnforcer
from .core.enforcement import PolicyEnforcer as _PE
from .core.permissions import (
    Bit,
    HSEDPermissionError,
    HSEDValidationError,
    Role,
    active_bits,
    builtin_role,
    combine,
    has_permission,
    intersect,
    parse_permission_string,
    permission_string,
    subtract,
    validate_permission,
)
from .core.policy import Policy, RoleConflictError, RoleNotFoundError


def _enforce_op(self, *, role: str, requires: Bit, eager: bool = True):
    return _PE(self).enforce_op(role=role, requires=requires, eager=eager)


Policy.enforce_op = _enforce_op  # type: ignore[attr-defined]

__version__ = "0.3.0"
__all__ = [
    # Bits / permissions
    "Bit",
    "Role",
    "Policy",
    # Exceptions
    "HSEDPermissionError",
    "HSEDValidationError",
    "RoleConflictError",
    "RoleNotFoundError",
    # Decorators / context managers
    "enforce",
    "PermissionScope",
    # Helpers
    "builtin_role",
    "permission_string",
    "parse_permission_string",
    "validate_permission",
    "has_permission",
    "active_bits",
    "combine",
    "intersect",
    "subtract",
]
