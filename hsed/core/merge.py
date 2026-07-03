"""
hsed.core.merge
───────────────
Combine multiple HSED policy files into one.

Three strategies mirror common IAM merge approaches:

    strict          — fail if any role has conflicting permission bits.
                      Safe default for CI gates.

    least_privilege — take the bitwise AND (intersection) of bits across
                      all policies that define the role. A role only gets a
                      permission if *every* source policy grants it.

    most_permissive — take the bitwise OR (union) of bits. A role gets a
                      permission if *any* source policy grants it.

Usage:

    from hsed import Policy
    from hsed.core.merge import merge, MergeStrategy

    base    = Policy.load('base.hsed')
    overlay = Policy.load('overlay.hsed')

    merged = merge([base, overlay], strategy=MergeStrategy.LEAST_PRIVILEGE)
    merged.save('combined.hsed')

    # Fail fast on conflicts
    try:
        merged = merge([base, overlay])   # strict by default
    except MergeConflict as exc:
        print(exc)
"""

from __future__ import annotations

import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from enum import Enum

from .permissions import Role, permission_string
from .policy import Policy

# ---------------------------------------------------------------------------
# Strategy
# ---------------------------------------------------------------------------


class MergeStrategy(str, Enum):
    """
    How to resolve roles that appear in more than one source policy with
    differing permission bits.

    STRICT
        Raise MergeConflict on any disagreement. Use this as a CI gate.

    LEAST_PRIVILEGE
        Bitwise AND — keep only bits that all source policies agree on.
        Roles not in every source policy are included with their bits
        from whichever policies do define them.

    MOST_PERMISSIVE
        Bitwise OR — keep all bits from any source policy.
    """

    STRICT = 'strict'
    LEAST_PRIVILEGE = 'least-privilege'
    MOST_PERMISSIVE = 'most-permissive'


# ---------------------------------------------------------------------------
# Exceptions
# ---------------------------------------------------------------------------


class MergeConflict(ValueError):
    """
    Raised by merge() when strategy=STRICT and two source policies define
    the same role with different permission bits.

    Attributes
    ----------
    role:
        The conflicting role name.
    conflicts:
        Mapping of source policy name → permission value for this role.
    """

    def __init__(self, role: str, conflicts: dict[str, int]) -> None:
        self.role = role
        self.conflicts = conflicts
        detail = ', '.join(
            f'{policy!r}: {perm} ({permission_string(perm)})'
            for policy, perm in sorted(conflicts.items())
        )
        super().__init__(
            f"Merge conflict on role '{role}': {detail}. "
            f"Use strategy='least-privilege' or 'most-permissive' to resolve."
        )


# ---------------------------------------------------------------------------
# Merge result
# ---------------------------------------------------------------------------


@dataclass
class MergeResult:
    """Metadata about a completed merge operation."""

    policy: Policy
    strategy: MergeStrategy
    source_names: list[str]
    conflicts_resolved: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return {
            'policy': self.policy.to_dict(),
            'strategy': self.strategy.value,
            'sources': self.source_names,
            'conflicts_resolved': self.conflicts_resolved,
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# ---------------------------------------------------------------------------
# Merge function
# ---------------------------------------------------------------------------


def merge(
    policies: Sequence[Policy],
    *,
    strategy: MergeStrategy | str = MergeStrategy.STRICT,
    name: str | None = None,
    description: str = '',
) -> Policy:
    """
    Combine multiple HSED policies into one.

    Roles that appear in only one source policy are included as-is.
    Roles that appear in more than one source policy with *identical* bits
    are included unchanged regardless of strategy.
    Roles that appear in more than one source policy with *differing* bits
    are resolved according to the strategy.

    Parameters
    ----------
    policies:
        Ordered list of source Policy objects. Must contain at least one.
    strategy:
        How to resolve conflicting role definitions. Accepts a MergeStrategy
        enum value or a string ('strict', 'least-privilege', 'most-permissive').
        Defaults to MergeStrategy.STRICT.
    name:
        Name for the output policy. Defaults to the first source policy's name.
    description:
        Description for the output policy.

    Returns
    -------
    Policy
        A new Policy containing the merged role definitions.

    Raises
    ------
    MergeConflict
        If strategy is STRICT and any role has conflicting permissions across
        source policies.
    ValueError
        If policies is empty.

    Examples
    --------
    >>> from hsed import Policy, Role
    >>> from hsed.core.merge import merge, MergeStrategy
    >>> a = Policy('a'); a.add_role(Role('signer', permissions=12))
    >>> b = Policy('b'); b.add_role(Role('signer', permissions=12)); b.add_role(Role('vault', permissions=3))
    >>> m = merge([a, b])
    >>> sorted(m.role_names())
    ['signer', 'vault']
    """
    if not policies:
        raise ValueError('merge() requires at least one source policy.')

    if isinstance(strategy, str):
        strategy = MergeStrategy(strategy)

    out_name = name or policies[0].name

    # Collect all (policy_name, permissions) per role name
    role_sources: dict[str, list[tuple[str, int, str]]] = {}
    # role_name → [(policy_name, permissions, description)]
    for policy in policies:
        for role in policy.roles():
            role_sources.setdefault(role.name, []).append(
                (policy.name, role.permissions, role.description)
            )

    merged_roles: list[Role] = []
    conflicts_resolved: list[str] = []

    for role_name, sources in sorted(role_sources.items()):
        unique_perms = {perm for _, perm, _ in sources}

        if len(unique_perms) == 1:
            # Unanimous — use as-is, take the first description
            perm = next(iter(unique_perms))
            desc = sources[0][2]
            merged_roles.append(Role(name=role_name, permissions=perm, description=desc))
            continue

        # Conflict: multiple policies disagree
        if strategy is MergeStrategy.STRICT:
            raise MergeConflict(
                role=role_name,
                conflicts={policy_name: perm for policy_name, perm, _ in sources},
            )

        conflicts_resolved.append(role_name)

        if strategy is MergeStrategy.LEAST_PRIVILEGE:
            resolved = 0xFF  # start with all bits set, AND down
            for _, perm, _ in sources:
                resolved &= perm
        else:  # MOST_PERMISSIVE
            resolved = 0
            for _, perm, _ in sources:
                resolved |= perm

        # Use description from the first source that defines this role
        desc = sources[0][2]
        merged_roles.append(Role(name=role_name, permissions=resolved, description=desc))

    out = Policy(name=out_name, description=description)
    for role in merged_roles:
        out.add_role(role)

    return out
