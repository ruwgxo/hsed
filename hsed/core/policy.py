"""
hsed.core.policy
────────────────
Policy: a named collection of Roles with conflict detection,
serialisation, and factory helpers.

A Policy is the unit you hand off to integrations (aws_kms, vault, etc.)
and the thing persisted as a .hsed file.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Iterator

from .permissions import (
    Bit,
    HSEDPermissionError,
    HSEDValidationError,
    Role,
    builtin_role,
    permission_string,
)


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------

class RoleConflictError(HSEDValidationError):
    """Raised when a role name collision is detected during add_role."""
    pass


class RoleNotFoundError(HSEDValidationError):
    """Raised when a requested role does not exist in the policy."""
    pass


# ---------------------------------------------------------------------------
# Policy
# ---------------------------------------------------------------------------

class Policy:
    """
    A named container for HSED roles.

    Parameters
    ----------
    name:
        Human-readable identifier for this policy (e.g. 'production').
    description:
        Optional description stored in serialised output.

    Examples
    --------
    >>> p = Policy('ci')
    >>> p.add_role(Role('signer', permissions=12))
    >>> p.get_role('signer').label
    'HS--'
    >>> p.enforce(role='signer', bit=Bit.SIGN)   # passes silently
    >>> p.enforce(role='signer', bit=Bit.DECRYPT)  # raises HSEDPermissionError
    """

    def __init__(self, name: str = "default", description: str = "") -> None:
        if not name or not name.strip():
            raise HSEDValidationError("Policy name must be a non-empty string")
        self.name = name
        self.description = description
        self._roles: dict[str, Role] = {}

    # ------------------------------------------------------------------
    # Role management
    # ------------------------------------------------------------------

    def add_role(self, role: Role, *, overwrite: bool = False) -> None:
        """
        Register a Role in this policy.

        Parameters
        ----------
        role:
            The Role to add.
        overwrite:
            If True, silently replace an existing role with the same name.
            If False (default), raise RoleConflictError on collision.
        """
        if role.name in self._roles and not overwrite:
            raise RoleConflictError(
                f"Role '{role.name}' already exists in policy '{self.name}'. "
                f"Pass overwrite=True to replace it."
            )
        self._roles[role.name] = role

    def add_builtin(self, name: str, *, overwrite: bool = False) -> Role:
        """
        Add a built-in HSED role by name and return it.

        >>> p = Policy()
        >>> r = p.add_builtin('signer')
        >>> r.permissions
        12
        """
        role = builtin_role(name)
        self.add_role(role, overwrite=overwrite)
        return role

    def remove_role(self, name: str) -> Role:
        """Remove and return a role by name."""
        try:
            return self._roles.pop(name)
        except KeyError:
            raise RoleNotFoundError(
                f"No role '{name}' in policy '{self.name}'"
            ) from None

    def get_role(self, name: str) -> Role:
        """Return the Role for *name*, or raise RoleNotFoundError."""
        try:
            return self._roles[name]
        except KeyError:
            raise RoleNotFoundError(
                f"No role '{name}' in policy '{self.name}'"
            ) from None

    def has_role(self, name: str) -> bool:
        """Return True if *name* is registered in this policy."""
        return name in self._roles

    def roles(self) -> Iterator[Role]:
        """Iterate over all registered roles."""
        return iter(self._roles.values())

    def role_names(self) -> list[str]:
        """Return sorted list of role names."""
        return sorted(self._roles)

    # ------------------------------------------------------------------
    # Enforcement
    # ------------------------------------------------------------------

    def enforce(self, *, role: str, bit: Bit) -> None:
        """
        Assert that *role* has permission *bit*.

        Raises
        ------
        RoleNotFoundError
            If the role is not registered.
        HSEDPermissionError
            If the role lacks the required bit.
        """
        self.get_role(role).require(bit)

    def can(self, *, role: str, bit: Bit) -> bool:
        """Return True if *role* has *bit*, False if not, RoleNotFoundError if missing."""
        return self.get_role(role).can(bit)

    # ------------------------------------------------------------------
    # Validation / audit
    # ------------------------------------------------------------------

    def validate(self) -> list[str]:
        """
        Return a list of warning strings describing policy anomalies.
        An empty list means the policy is clean.

        Current checks:
        - Roles with zero permissions ('none' role is expected; others are suspicious)
        - Duplicate permission masks across different role names
        """
        warnings: list[str] = []

        # Zero-permission roles (other than intentional 'none')
        for role in self._roles.values():
            if role.permissions == 0 and role.name != "none":
                warnings.append(
                    f"Role '{role.name}' has zero permissions, it will always deny"
                )

        # Duplicate masks
        seen: dict[int, str] = {}
        for role in self._roles.values():
            if role.permissions in seen:
                warnings.append(
                    f"Roles '{seen[role.permissions]}' and '{role.name}' share "
                    f"identical permission mask {role.permissions} "
                    f"({permission_string(role.permissions)})"
                )
            else:
                seen[role.permissions] = role.name

        return warnings

    # ------------------------------------------------------------------
    # Serialisation
    # ------------------------------------------------------------------

    def to_dict(self) -> dict:
        return {
            "policy": self.name,
            "description": self.description,
            "roles": [r.to_dict() for r in sorted(self._roles.values(), key=lambda r: r.name)],
        }

    @classmethod
    def from_dict(cls, d: dict) -> "Policy":
        p = cls(name=d.get("policy", "default"), description=d.get("description", ""))
        for rd in d.get("roles", []):
            p.add_role(Role.from_dict(rd))
        return p

    def to_json(self, *, indent: int = 2) -> str:
        """Serialise to JSON string."""
        return json.dumps(self.to_dict(), indent=indent)

    @classmethod
    def from_json(cls, text: str) -> "Policy":
        """Deserialise from JSON string."""
        try:
            d = json.loads(text)
        except json.JSONDecodeError as exc:
            raise HSEDValidationError(f"Invalid JSON: {exc}") from exc
        return cls.from_dict(d)

    def save(self, path: str | Path) -> Path:
        """Write policy to a .hsed JSON file. Returns the resolved path."""
        path = Path(path)
        if path.suffix == "":
            path = path.with_suffix(".hsed")
        path.write_text(self.to_json(), encoding="utf-8")
        return path

    @classmethod
    def load(cls, path: str | Path) -> "Policy":
        """Load a policy from a .hsed JSON file."""
        path = Path(path)
        if not path.exists():
            raise FileNotFoundError(f"Policy file not found: {path}")
        return cls.from_json(path.read_text(encoding="utf-8"))

    # ------------------------------------------------------------------
    # Dunder
    # ------------------------------------------------------------------

    def __len__(self) -> int:
        return len(self._roles)

    def __contains__(self, name: str) -> bool:
        return self.has_role(name)

    def __repr__(self) -> str:
        return f"Policy(name={self.name!r}, roles={self.role_names()})"

    def __str__(self) -> str:
        lines = [f"Policy '{self.name}'"]
        if self.description:
            lines.append(f"  {self.description}")
        for role in sorted(self._roles.values(), key=lambda r: -r.permissions):
            lines.append(f"  {role.label}/{role.permissions:>2}  {role.name:<14}  {role.description}")
        return "\n".join(lines)
