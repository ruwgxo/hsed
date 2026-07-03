"""
hsed.core.diff
──────────────
Compare two HSED policy files and report what changed.

    from hsed import Policy
    from hsed.core.diff import diff

    a = Policy.load('main.hsed')
    b = Policy.load('pr.hsed')
    result = diff(a, b)

    print(result.summary())
    # Role added:   encryptor  (H-E-/10)
    # Role removed: audit      (H--D/9)
    # Bits changed: signer     12 (HS--) → 14 (HSE-)  ⚠ escalation

    if result.has_escalation:
        sys.exit(1)   # block PR
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    pass

from .permissions import permission_string
from .policy import Policy

# ---------------------------------------------------------------------------
# Result model
# ---------------------------------------------------------------------------


@dataclass
class RolePermissionChange:
    """A role whose permission bits changed between two policies."""

    name: str
    before: int
    after: int

    @property
    def is_escalation(self) -> bool:
        """True if permissions were *added* (bits gained)."""
        return bool(self.after & ~self.before)

    @property
    def is_reduction(self) -> bool:
        """True if permissions were *removed* (bits lost)."""
        return bool(self.before & ~self.after)

    @property
    def bits_added(self) -> int:
        """Mask of bits gained in `after`."""
        return self.after & ~self.before

    @property
    def bits_removed(self) -> int:
        """Mask of bits lost in `after`."""
        return self.before & ~self.after

    def to_dict(self) -> dict:
        return {
            'role': self.name,
            'before': self.before,
            'before_label': permission_string(self.before),
            'after': self.after,
            'after_label': permission_string(self.after),
            'escalation': self.is_escalation,
            'reduction': self.is_reduction,
            'bits_added': self.bits_added,
            'bits_removed': self.bits_removed,
        }


@dataclass
class PolicyDiff:
    """
    Result of comparing two HSED policies (a → b).

    Attributes
    ----------
    policy_a:
        Name of the source policy.
    policy_b:
        Name of the target policy.
    roles_added:
        Role names present in b but not in a.
    roles_removed:
        Role names present in a but not in b.
    permission_changes:
        Roles present in both policies whose permission bits differ.
    """

    policy_a: str
    policy_b: str
    roles_added: list[str] = field(default_factory=list)
    roles_removed: list[str] = field(default_factory=list)
    permission_changes: list[RolePermissionChange] = field(default_factory=list)

    @property
    def is_empty(self) -> bool:
        """True if there are no differences between the two policies."""
        return not (self.roles_added or self.roles_removed or self.permission_changes)

    @property
    def has_escalation(self) -> bool:
        """True if any role gained permission bits."""
        return any(c.is_escalation for c in self.permission_changes)

    @property
    def escalations(self) -> list[RolePermissionChange]:
        """Permission changes that represent privilege escalation."""
        return [c for c in self.permission_changes if c.is_escalation]

    def summary(self, *, color: bool = False) -> str:
        """Return a human-readable diff summary."""
        if self.is_empty:
            return f'No differences between {self.policy_a!r} and {self.policy_b!r}.'

        lines: list[str] = [
            f'Diff: {self.policy_a!r} → {self.policy_b!r}',
            '',
        ]

        if self.roles_added:
            lines.append(f'  Roles added ({len(self.roles_added)}):')
            for name in sorted(self.roles_added):
                lines.append(f'    + {name}')

        if self.roles_removed:
            lines.append(f'  Roles removed ({len(self.roles_removed)}):')
            for name in sorted(self.roles_removed):
                lines.append(f'    - {name}')

        if self.permission_changes:
            lines.append(f'  Permission changes ({len(self.permission_changes)}):')
            for c in sorted(self.permission_changes, key=lambda x: x.name):
                tag = ''
                if c.is_escalation and c.is_reduction:
                    tag = '  ↕ reshuffled'
                elif c.is_escalation:
                    tag = '  ⚠ escalation'
                elif c.is_reduction:
                    tag = '  ↓ reduction'
                lines.append(
                    f'    ~ {c.name:<16} '
                    f'{c.before} ({permission_string(c.before)}) → '
                    f'{c.after} ({permission_string(c.after)})'
                    f'{tag}'
                )

        if self.has_escalation:
            lines.append('')
            lines.append('  ⚠ Privilege escalation detected.')

        return '\n'.join(lines)

    def to_dict(self) -> dict:
        return {
            'policy_a': self.policy_a,
            'policy_b': self.policy_b,
            'roles_added': sorted(self.roles_added),
            'roles_removed': sorted(self.roles_removed),
            'permission_changes': [c.to_dict() for c in self.permission_changes],
            'has_escalation': self.has_escalation,
            'is_empty': self.is_empty,
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# ---------------------------------------------------------------------------
# Diff function
# ---------------------------------------------------------------------------


def diff(a: Policy, b: Policy) -> PolicyDiff:
    """
    Compare two HSED policies and return a PolicyDiff.

    Roles are compared by name. Permission changes are reported for any role
    present in both policies whose bit mask differs.

    Parameters
    ----------
    a:
        Source policy (the baseline — "before").
    b:
        Target policy (the candidate — "after").

    Returns
    -------
    PolicyDiff
        Contains added roles, removed roles, and per-role permission changes.

    Examples
    --------
    >>> from hsed import Policy, Role
    >>> from hsed.core.diff import diff
    >>> a = Policy('prod'); a.add_role(Role('signer', permissions=12))
    >>> b = Policy('prod'); b.add_role(Role('signer', permissions=14))
    >>> result = diff(a, b)
    >>> result.has_escalation
    True
    >>> result.escalations[0].name
    'signer'
    """
    names_a = set(a.role_names())
    names_b = set(b.role_names())

    roles_added = sorted(names_b - names_a)
    roles_removed = sorted(names_a - names_b)

    changes: list[RolePermissionChange] = []
    for name in sorted(names_a & names_b):
        perm_a = a.get_role(name).permissions
        perm_b = b.get_role(name).permissions
        if perm_a != perm_b:
            changes.append(RolePermissionChange(name=name, before=perm_a, after=perm_b))

    return PolicyDiff(
        policy_a=a.name,
        policy_b=b.name,
        roles_added=roles_added,
        roles_removed=roles_removed,
        permission_changes=changes,
    )
