"""
hsed.core.permissions
─────────────────────
Permission model for cryptographic operations.

Bit layout (4 bits):
    H=8  S=4  E=2  D=1
    ─────────────────────
    1    1    1    1   = 15 (full authority)
    1    1    0    0   = 12 (sign only)
    0    0    1    1   =  3 (vault)
    1    0    0    1   =  9 (audit)
    1    0    1    0   = 10 (encryptor)

Like chmod: the number IS the authority.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import IntFlag, auto
from typing import ClassVar


# ---------------------------------------------------------------------------
# Permission bits
# ---------------------------------------------------------------------------

class Bit(IntFlag):
    """Individual HSED permission bits."""
    NONE    = 0
    DECRYPT = 1   # D - unseal data, read plaintext
    ENCRYPT = 2   # E - seal data, create ciphertext
    SIGN    = 4   # S - create digital signatures, attestations
    HASH    = 8   # H - compute hashes, verify signatures


# Human-readable labels for display
BIT_LABELS: dict[Bit, str] = {
    Bit.HASH:    "H",
    Bit.SIGN:    "S",
    Bit.ENCRYPT: "E",
    Bit.DECRYPT: "D",
}

# Ordered for display (H S E D)
DISPLAY_ORDER: list[Bit] = [Bit.HASH, Bit.SIGN, Bit.ENCRYPT, Bit.DECRYPT]


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class HSEDPermissionError(PermissionError):
    """Raised when an operation is attempted without the required permission."""

    def __init__(self, role: str, required: Bit, granted: int) -> None:
        self.role = role
        self.required = required
        self.granted = granted
        granted_str = permission_string(granted)
        super().__init__(
            f"Role '{role}' (hsed:{granted_str}/{granted}) lacks '{required.name}' "
            f"permission - required bit {required.value}"
        )


class HSEDValidationError(ValueError):
    """Raised when a permission value or role definition is invalid."""
    pass


# ---------------------------------------------------------------------------
# Core helpers
# ---------------------------------------------------------------------------

def validate_permission(value: int) -> None:
    """Raise HSEDValidationError if value is outside valid HSED range [0, 15]."""
    if not isinstance(value, int):
        raise HSEDValidationError(
            f"Permission value must be an integer, got {type(value).__name__}"
        )
    if value < 0 or value > 15:
        raise HSEDValidationError(
            f"Permission value {value} is out of range - valid range is 0–15 "
            f"(HSED uses 4 bits: H=8, S=4, E=2, D=1)"
        )


def has_permission(granted: int, required: Bit) -> bool:
    """Return True if the granted permission mask includes the required bit."""
    return bool(granted & required.value)


def permission_string(value: int) -> str:
    """
    Convert a numeric permission value to an HSED string.

    >>> permission_string(15)
    'HSED'
    >>> permission_string(12)
    'HS--'
    >>> permission_string(3)
    '--ED'
    >>> permission_string(0)
    '----'
    """
    validate_permission(value)
    return "".join(
        label if has_permission(value, bit) else "-"
        for bit, label in BIT_LABELS.items()
    )


def parse_permission_string(s: str) -> int:
    """
    Parse an HSED permission string (e.g. 'HS--') to its integer value.

    Accepts both compact ('HS') and padded ('HS--') forms.
    Case-insensitive.

    >>> parse_permission_string('HSED')
    15
    >>> parse_permission_string('hs--')
    12
    >>> parse_permission_string('ED')
    3
    """
    s = s.upper().strip()
    # Normalise: remove dashes so 'HS--' → 'HS'
    compact = s.replace("-", "")
    reverse_map = {v: k for k, v in BIT_LABELS.items()}
    result = 0
    for ch in compact:
        if ch not in reverse_map:
            raise HSEDValidationError(
                f"Unknown permission character '{ch}' - valid chars are H, S, E, D"
            )
        result |= reverse_map[ch].value
    return result


def active_bits(value: int) -> list[Bit]:
    """Return list of active Bit flags for a permission value."""
    validate_permission(value)
    return [bit for bit in DISPLAY_ORDER if has_permission(value, bit)]


def combine(*permissions: int) -> int:
    """Bitwise-OR multiple permission values together (union)."""
    result = 0
    for p in permissions:
        validate_permission(p)
        result |= p
    return result


def intersect(*permissions: int) -> int:
    """Bitwise-AND multiple permission values together (intersection)."""
    if not permissions:
        return 0
    result = 15  # all bits set
    for p in permissions:
        validate_permission(p)
        result &= p
    return result


def subtract(base: int, remove: int) -> int:
    """Remove bits in *remove* from *base* (set difference)."""
    validate_permission(base)
    validate_permission(remove)
    return base & ~remove & 0xF


# ---------------------------------------------------------------------------
# Role
# ---------------------------------------------------------------------------

@dataclass
class Role:
    """
    An HSED role: a named permission mask.

    Parameters
    ----------
    name:
        Identifier for this role (e.g. 'signer', 'vault').
    permissions:
        Integer in [0, 15] representing allowed HSED operations.
    description:
        Optional human-readable description.

    Examples
    --------
    >>> r = Role('signer', permissions=12)
    >>> r.can(Bit.SIGN)
    True
    >>> r.can(Bit.DECRYPT)
    False
    >>> str(r)
    "Role('signer', hsed:HS--/12)"
    """

    name: str
    permissions: int
    description: str = ""

    # Built-in named roles - populated below
    BUILTIN: ClassVar[dict[str, "Role"]] = {}

    def __post_init__(self) -> None:
        if not self.name or not self.name.strip():
            raise HSEDValidationError("Role name must be a non-empty string")
        validate_permission(self.permissions)

    # ------------------------------------------------------------------
    # Permission checks
    # ------------------------------------------------------------------

    def can(self, bit: Bit) -> bool:
        """Return True if this role has the given permission bit."""
        return has_permission(self.permissions, bit)

    def require(self, bit: Bit) -> None:
        """Raise HSEDPermissionError if this role lacks *bit*."""
        if not self.can(bit):
            raise HSEDPermissionError(self.name, bit, self.permissions)

    # ------------------------------------------------------------------
    # Derived views
    # ------------------------------------------------------------------

    @property
    def label(self) -> str:
        """Return the HSED permission string, e.g. 'HS--'."""
        return permission_string(self.permissions)

    @property
    def bits(self) -> list[Bit]:
        """Return list of active Bit flags."""
        return active_bits(self.permissions)

    # ------------------------------------------------------------------
    # Combination helpers
    # ------------------------------------------------------------------

    def grant(self, other: "Role | int") -> "Role":
        """Return a new Role with permissions from both (union)."""
        other_p = other.permissions if isinstance(other, Role) else other
        return Role(
            name=self.name,
            permissions=combine(self.permissions, other_p),
            description=self.description,
        )

    def revoke(self, other: "Role | int") -> "Role":
        """Return a new Role with permissions in *other* removed."""
        other_p = other.permissions if isinstance(other, Role) else other
        return Role(
            name=self.name,
            permissions=subtract(self.permissions, other_p),
            description=self.description,
        )

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "permissions": self.permissions,
            "label": self.label,
            "description": self.description,
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Role":
        return cls(
            name=d["name"],
            permissions=d["permissions"],
            description=d.get("description", ""),
        )

    def __str__(self) -> str:
        return f"Role('{self.name}', hsed:{self.label}/{self.permissions})"

    def __repr__(self) -> str:
        return (
            f"Role(name={self.name!r}, permissions={self.permissions}, "
            f"description={self.description!r})"
        )


# ---------------------------------------------------------------------------
# Built-in roles
# ---------------------------------------------------------------------------

_BUILTIN_DEFINITIONS: list[tuple[str, int, str]] = [
    ("root",      15, "Full authority - H+S+E+D"),
    ("admin",     14, "H+S+E, no decrypt - administrative operations"),
    ("signer",    12, "H+S - CI/CD pipelines, code signing"),
    ("vault",      3, "E+D - secrets management, sealed stores"),
    ("audit",      9, "H+D - compliance, forensics, read-only"),
    ("encryptor", 10, "H+E - data ingestion, DMZ encryptors"),
    ("verifier",   8, "H only - signature verification, integrity checks"),
    ("none",       0, "No permissions - placeholder / deny all"),
]

for _name, _perm, _desc in _BUILTIN_DEFINITIONS:
    Role.BUILTIN[_name] = Role(name=_name, permissions=_perm, description=_desc)


def builtin_role(name: str) -> Role:
    """
    Return a copy of a built-in HSED role by name.

    >>> builtin_role('signer').permissions
    12
    >>> builtin_role('vault').label
    '--ED'
    """
    try:
        r = Role.BUILTIN[name]
    except KeyError:
        available = ", ".join(sorted(Role.BUILTIN))
        raise HSEDValidationError(
            f"No built-in role named '{name}'. Available: {available}"
        ) from None
    # Return a copy so callers cannot mutate the registry
    return Role(name=r.name, permissions=r.permissions, description=r.description)
