"""
hsed.core.enforcement
─────────────────────
The @enforce decorator: attach HSED permission checks to any callable.

Two usage patterns:

1. Standalone (no Policy required) - checks a Role object directly:

    signer = Role('signer', permissions=12)

    @enforce(role=signer, requires=Bit.SIGN)
    def sign_artifact(data: bytes) -> bytes:
        ...

2. Policy-bound - the decorator is issued from a Policy instance:

    policy = Policy('ci')
    policy.add_role(Role('signer', permissions=12))

    @policy.enforce_op(role='signer', requires=Bit.DECRYPT)
    def decrypt_secret(ct: bytes) -> bytes:
        ...  # raises HSEDPermissionError at decoration time (eager) or call time (lazy)

Both patterns support eager=True (fail at decoration time, default)
or eager=False (fail at first call).
"""

from __future__ import annotations

import functools
from typing import Any, Callable, TypeVar

from .permissions import Bit, HSEDPermissionError, HSEDValidationError, Role

F = TypeVar("F", bound=Callable[..., Any])


# ---------------------------------------------------------------------------
# Standalone decorator
# ---------------------------------------------------------------------------

def enforce(
    *,
    role: Role,
    requires: Bit,
    eager: bool = True,
) -> Callable[[F], F]:
    """
    Decorator that enforces an HSED permission bit against a Role object.

    Parameters
    ----------
    role:
        The Role whose permissions are checked.
    requires:
        The Bit that must be present in role.permissions.
    eager:
        If True (default), the permission check runs at decoration time
        so failures surface immediately, not at first call.
        If False, the check runs on every invocation.

    Raises
    ------
    HSEDPermissionError
        If the role lacks the required bit (at decoration time if eager,
        else at call time).

    Examples
    --------
    >>> signer = Role('signer', permissions=12)  # H+S
    >>> @enforce(role=signer, requires=Bit.SIGN)
    ... def sign_data(data: bytes) -> bytes:
    ...     return b"signed:" + data
    >>> sign_data(b"hello")
    b'signed:hello'

    >>> @enforce(role=signer, requires=Bit.DECRYPT)
    ... def decrypt(ct: bytes) -> bytes:
    ...     return ct
    Traceback (most recent call last):
        ...
    hsed.core.permissions.HSEDPermissionError: Role 'signer' ...
    """
    if not isinstance(role, Role):
        raise HSEDValidationError(
            f"enforce() expects a Role instance, got {type(role).__name__}"
        )
    if not isinstance(requires, Bit):
        raise HSEDValidationError(
            f"enforce() 'requires' must be a Bit, got {type(requires).__name__}"
        )

    # Eager check - surfaces errors at import / decoration time
    if eager:
        role.require(requires)

    def decorator(fn: F) -> F:
        @functools.wraps(fn)
        def wrapper(*args: Any, **kwargs: Any) -> Any:
            if not eager:
                role.require(requires)
            return fn(*args, **kwargs)

        # Attach metadata for introspection / audit
        wrapper._hsed_role = role          # type: ignore[attr-defined]
        wrapper._hsed_requires = requires  # type: ignore[attr-defined]
        return wrapper  # type: ignore[return-value]

    return decorator


# ---------------------------------------------------------------------------
# Policy-bound decorator factory
# ---------------------------------------------------------------------------

class PolicyEnforcer:
    """
    Mixin / helper that adds .enforce_op() to a Policy-like object.

    Policy imports and uses this directly - it is not part of the public
    surface on its own.

    Usage:

        enforcer = PolicyEnforcer(policy)

        @enforcer.enforce_op(role='signer', requires=Bit.SIGN)
        def sign_artifact(data: bytes) -> bytes:
            ...
    """

    def __init__(self, policy: Any) -> None:
        # Circular import avoided by using Any; actual type is Policy
        self._policy = policy

    def enforce_op(
        self,
        *,
        role: str,
        requires: Bit,
        eager: bool = True,
    ) -> Callable[[F], F]:
        """
        Decorator factory that enforces a permission bit for a named role
        in the bound Policy.

        Parameters
        ----------
        role:
            Name of the role registered in the Policy.
        requires:
            The Bit that must be present.
        eager:
            Check at decoration time (True, default) or call time (False).

        Examples
        --------
        >>> policy = Policy('ci')
        >>> policy.add_builtin('signer')

        >>> @policy.enforce_op(role='signer', requires=Bit.SIGN)
        ... def sign_artifact(data: bytes) -> bytes:
        ...     return b"sig:" + data

        >>> @policy.enforce_op(role='signer', requires=Bit.DECRYPT)
        ... def decrypt(ct: bytes) -> bytes:
        ...     return ct
        Traceback (most recent call last):
            ...
        HSEDPermissionError: Role 'signer' (hsed:HS--/12) lacks 'DECRYPT' permission
        """
        resolved: Role = self._policy.get_role(role)
        return enforce(role=resolved, requires=requires, eager=eager)


# ---------------------------------------------------------------------------
# Context manager for temporary permission elevation / restriction
# ---------------------------------------------------------------------------

class PermissionScope:
    """
    Context manager that temporarily adjusts a Role's permissions.

    Useful in tests or auditing scenarios - NOT for production privilege
    escalation. The original permissions are restored on exit.

    Examples
    --------
    >>> r = Role('signer', permissions=12)
    >>> with PermissionScope(r, add=Bit.DECRYPT):
    ...     print(r.can(Bit.DECRYPT))   # True inside
    True
    >>> r.can(Bit.DECRYPT)              # False restored
    False
    """

    def __init__(
        self,
        role: Role,
        *,
        add: Bit | int = 0,
        remove: Bit | int = 0,
    ) -> None:
        self._role = role
        self._add = int(add)
        self._remove = int(remove)
        self._original: int = role.permissions

    def __enter__(self) -> Role:
        new_perm = (self._role.permissions | self._add) & ~self._remove & 0xF
        object.__setattr__(self._role, "permissions", new_perm)
        return self._role

    def __exit__(self, *_: Any) -> None:
        object.__setattr__(self._role, "permissions", self._original)
