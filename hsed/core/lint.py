"""
hsed.core.lint
──────────────
Static analysis of HSED policy files. Catches common mistakes before
they reach a cloud environment.

    from hsed import Policy
    from hsed.core.lint import lint

    policy = Policy.load('production.hsed')
    result = lint(policy)

    if not result.passed:
        print(result.summary())
        sys.exit(1)

Checks performed:

    EMPTY_POLICY            No roles defined — likely an incomplete file.
    ZERO_PERMISSIONS        A role with permissions=0 (deny-all). Almost always
                            a mistake; use explicit policy absence instead.
    ROOT_UNDOCUMENTED       permissions=15 (full authority) with no description.
                            Root roles should carry a justification.
    SIGN_WITHOUT_HASH       S bit set, H bit not set. Sign creates attestations
                            but the role cannot verify them.
    DECRYPT_WITHOUT_ENCRYPT D bit set, E bit not set. Decrypt-only is a valid
                            pattern for some key escrow designs but uncommon
                            enough to warrant a WARN.
    DUPLICATE_ROLE_NAMES    Two or more roles with the same name. Should not
                            occur via the Policy API but can appear in hand-
                            edited .hsed files.
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum

from .permissions import Bit, has_permission, permission_string
from .policy import Policy


# ---------------------------------------------------------------------------
# Severity and finding model
# ---------------------------------------------------------------------------


class LintSeverity(str, Enum):
    WARN = 'WARN'
    ERROR = 'ERROR'


@dataclass
class LintFinding:
    severity: LintSeverity
    code: str
    message: str
    role: str | None = None

    def to_dict(self) -> dict:
        d: dict = {
            'severity': self.severity.value,
            'code': self.code,
            'message': self.message,
        }
        if self.role is not None:
            d['role'] = self.role
        return d


# ---------------------------------------------------------------------------
# Lint result
# ---------------------------------------------------------------------------


@dataclass
class LintResult:
    """
    Result of linting a single HSED policy.

    A result is considered *passed* (clean enough to deploy) when it has no
    ERROR-severity findings. WARN findings are advisory only.
    """

    policy_name: str
    findings: list[LintFinding] = field(default_factory=list)

    @property
    def passed(self) -> bool:
        """True if there are no ERROR-severity findings."""
        return not any(f.severity is LintSeverity.ERROR for f in self.findings)

    @property
    def errors(self) -> list[LintFinding]:
        return [f for f in self.findings if f.severity is LintSeverity.ERROR]

    @property
    def warnings(self) -> list[LintFinding]:
        return [f for f in self.findings if f.severity is LintSeverity.WARN]

    def summary(self) -> str:
        if not self.findings:
            return f"lint: {self.policy_name!r} — OK (no findings)"

        lines = [f"lint: {self.policy_name!r}"]
        icon = {LintSeverity.ERROR: '✗', LintSeverity.WARN: '⚠'}
        for f in self.findings:
            role_tag = f" [{f.role}]" if f.role else ''
            lines.append(f"  {icon[f.severity]}  {f.severity.value}  {f.code}{role_tag}: {f.message}")

        status = 'PASS' if self.passed else 'FAIL'
        counts = []
        if self.errors:
            counts.append(f'{len(self.errors)} error(s)')
        if self.warnings:
            counts.append(f'{len(self.warnings)} warning(s)')
        lines.append(f"\nResult: {status} — {', '.join(counts)}")
        return '\n'.join(lines)

    def to_dict(self) -> dict:
        return {
            'policy': self.policy_name,
            'passed': self.passed,
            'findings': [f.to_dict() for f in self.findings],
            'error_count': len(self.errors),
            'warning_count': len(self.warnings),
        }

    def to_json(self, *, indent: int = 2) -> str:
        return json.dumps(self.to_dict(), indent=indent)


# ---------------------------------------------------------------------------
# Individual checks
# ---------------------------------------------------------------------------


def _check_empty_policy(policy: Policy) -> list[LintFinding]:
    if len(policy) == 0:
        return [LintFinding(
            severity=LintSeverity.ERROR,
            code='EMPTY_POLICY',
            message='Policy defines no roles.',
        )]
    return []


def _check_duplicate_role_names(policy: Policy) -> list[LintFinding]:
    """Catch hand-edited files with duplicate role names (bypasses Policy API)."""
    seen: dict[str, int] = {}
    for role in policy.roles():
        seen[role.name] = seen.get(role.name, 0) + 1
    findings: list[LintFinding] = []
    for name, count in seen.items():
        if count > 1:
            findings.append(LintFinding(
                severity=LintSeverity.ERROR,
                code='DUPLICATE_ROLE_NAMES',
                message=f"Role '{name}' appears {count} times in the policy.",
                role=name,
            ))
    return findings


def _check_zero_permissions(policy: Policy) -> list[LintFinding]:
    findings: list[LintFinding] = []
    for role in policy.roles():
        if role.permissions == 0:
            findings.append(LintFinding(
                severity=LintSeverity.ERROR,
                code='ZERO_PERMISSIONS',
                message=(
                    f"Role '{role.name}' has permissions=0 (deny-all). "
                    'Use explicit policy absence to deny access.'
                ),
                role=role.name,
            ))
    return findings


def _check_root_undocumented(policy: Policy) -> list[LintFinding]:
    findings: list[LintFinding] = []
    for role in policy.roles():
        if role.permissions == 15 and not role.description.strip():
            findings.append(LintFinding(
                severity=LintSeverity.WARN,
                code='ROOT_UNDOCUMENTED',
                message=(
                    f"Role '{role.name}' has full authority (HSED/15) but no "
                    'description. Add a justification for why root is required.'
                ),
                role=role.name,
            ))
    return findings


def _check_sign_without_hash(policy: Policy) -> list[LintFinding]:
    findings: list[LintFinding] = []
    for role in policy.roles():
        has_sign = has_permission(role.permissions, Bit.SIGN)
        has_hash = has_permission(role.permissions, Bit.HASH)
        if has_sign and not has_hash:
            findings.append(LintFinding(
                severity=LintSeverity.WARN,
                code='SIGN_WITHOUT_HASH',
                message=(
                    f"Role '{role.name}' ({permission_string(role.permissions)}) "
                    'can sign but not verify (H bit missing). '
                    'Signature verification requires the H bit.'
                ),
                role=role.name,
            ))
    return findings


def _check_decrypt_without_encrypt(policy: Policy) -> list[LintFinding]:
    findings: list[LintFinding] = []
    for role in policy.roles():
        has_decrypt = has_permission(role.permissions, Bit.DECRYPT)
        has_encrypt = has_permission(role.permissions, Bit.ENCRYPT)
        if has_decrypt and not has_encrypt:
            findings.append(LintFinding(
                severity=LintSeverity.WARN,
                code='DECRYPT_WITHOUT_ENCRYPT',
                message=(
                    f"Role '{role.name}' ({permission_string(role.permissions)}) "
                    'can decrypt but not encrypt. '
                    'Intentional for key escrow patterns; verify this is deliberate.'
                ),
                role=role.name,
            ))
    return findings


# ---------------------------------------------------------------------------
# Lint function
# ---------------------------------------------------------------------------

_CHECKS = [
    _check_empty_policy,
    _check_duplicate_role_names,
    _check_zero_permissions,
    _check_root_undocumented,
    _check_sign_without_hash,
    _check_decrypt_without_encrypt,
]


def lint(policy: Policy) -> LintResult:
    """
    Run all static checks against a Policy and return a LintResult.

    Checks are independent and all run regardless of earlier findings.
    ERROR findings indicate the policy should not be deployed as-is.
    WARN findings are advisory.

    Parameters
    ----------
    policy:
        The HSED Policy to lint.

    Returns
    -------
    LintResult
        Contains all findings grouped by severity.

    Examples
    --------
    >>> from hsed import Policy, Role
    >>> from hsed.core.lint import lint
    >>> p = Policy('prod')
    >>> p.add_role(Role('signer', permissions=4))   # sign without hash
    >>> result = lint(p)
    >>> result.passed
    True
    >>> result.warnings[0].code
    'SIGN_WITHOUT_HASH'
    """
    findings: list[LintFinding] = []
    for check in _CHECKS:
        findings.extend(check(policy))

    return LintResult(policy_name=policy.name, findings=findings)
