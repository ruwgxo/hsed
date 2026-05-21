"""
hsed.integrations.live_audit
────────────────────────────
Live audit: fetch actual cloud KMS policies and compare against expected
HSED policy definitions.

Currently supports:
    - AWS KMS (via boto3)

Planned: Azure Key Vault, GCP Cloud KMS.

Usage:

    from hsed import Policy
    from hsed.integrations.live_audit import AWSLiveAuditor

    policy = Policy.load('production.hsed')
    auditor = AWSLiveAuditor(policy, aws_profile='production')

    result = auditor.audit(
        role='signer',
        key_arn='arn:aws:kms:us-east-1:123456789012:key/mrk-abc',
    )
    print(result.summary())
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from ..core.permissions import Bit, permission_string
from ..core.policy import Policy
from ..integrations.aws_kms import _actions_for_permissions


# ---------------------------------------------------------------------------
# Audit result model
# ---------------------------------------------------------------------------


class FindingSeverity(str, Enum):
    OK = "OK"
    WARN = "WARN"
    FAIL = "FAIL"
    ERROR = "ERROR"


@dataclass
class AuditFinding:
    severity: FindingSeverity
    message: str
    detail: str = ""


@dataclass
class AuditResult:
    """Result of a live audit comparison for one role against one KMS key."""

    role_name: str
    permissions: int
    key_arn: str
    expected_allow: list[str]
    actual_allow: list[str]
    findings: list[AuditFinding] = field(default_factory=list)
    raw_policy: dict | None = None

    @property
    def missing_actions(self) -> list[str]:
        """Actions expected by HSED but absent from the actual policy."""
        return sorted(set(self.expected_allow) - set(self.actual_allow))

    @property
    def extra_actions(self) -> list[str]:
        """Actions present in the actual policy but not required by HSED."""
        return sorted(set(self.actual_allow) - set(self.expected_allow))

    @property
    def passed(self) -> bool:
        return not any(
            f.severity in (FindingSeverity.FAIL, FindingSeverity.ERROR) for f in self.findings
        )

    def summary(self) -> str:
        label = permission_string(self.permissions)
        lines = [
            f"Live Audit — Role '{self.role_name}' (hsed:{label}/{self.permissions})",
            f"Key: {self.key_arn}",
            "",
        ]

        if not self.findings:
            lines.append("✓  No findings — policy matches HSED definition exactly")
            return "\n".join(lines)

        for f in self.findings:
            icon = {"OK": "✓", "WARN": "⚠", "FAIL": "✗", "ERROR": "✗"}[f.severity]
            lines.append(f"  {icon}  [{f.severity}] {f.message}")
            if f.detail:
                lines.append(f"       {f.detail}")

        lines.append("")
        if self.missing_actions:
            lines.append(f"  Missing actions ({len(self.missing_actions)}):")
            for a in self.missing_actions:
                lines.append(f"    - {a}")
        if self.extra_actions:
            lines.append(f"  Extra actions ({len(self.extra_actions)}):")
            for a in self.extra_actions:
                lines.append(f"    + {a}")

        status = "PASS" if self.passed else "FAIL"
        lines.append(f"\nResult: {status}")
        return "\n".join(lines)

    def to_dict(self) -> dict:
        return {
            "role": self.role_name,
            "permissions": self.permissions,
            "label": permission_string(self.permissions),
            "key_arn": self.key_arn,
            "expected_allow": self.expected_allow,
            "actual_allow": self.actual_allow,
            "missing": self.missing_actions,
            "extra": self.extra_actions,
            "findings": [
                {"severity": f.severity, "message": f.message, "detail": f.detail}
                for f in self.findings
            ],
            "passed": self.passed,
        }


# ---------------------------------------------------------------------------
# AWS live auditor
# ---------------------------------------------------------------------------


class AWSLiveAuditor:
    """
    Fetch the actual AWS KMS key policy and compare it against the
    expected HSED policy for a named role.

    Requires boto3: `pip install hsed[aws]`

    Parameters
    ----------
    policy:
        HSED Policy containing the role definitions to audit against.
    aws_profile:
        Optional AWS credentials profile name (from ~/.aws/credentials).
    aws_region:
        AWS region override. If omitted, boto3 uses its default resolution.

    Examples
    --------
    >>> from hsed import Policy
    >>> from hsed.integrations.live_audit import AWSLiveAuditor
    >>> policy = Policy.load('production.hsed')
    >>> auditor = AWSLiveAuditor(policy, aws_profile='prod-readonly')
    >>> result = auditor.audit(
    ...     role='signer',
    ...     key_arn='arn:aws:kms:us-east-1:123:key/abc',
    ... )
    >>> result.passed
    True
    """

    def __init__(
        self,
        policy: Policy,
        *,
        aws_profile: str | None = None,
        aws_region: str | None = None,
    ) -> None:
        self.policy = policy
        self.aws_profile = aws_profile
        self.aws_region = aws_region
        self._client: Any = None

    def _kms_client(self) -> Any:
        if self._client is None:
            try:
                import boto3
            except ImportError:
                raise ImportError(
                    "boto3 is required for live audits. Install with: pip install hsed[aws]"
                ) from None

            session_kwargs: dict[str, Any] = {}
            if self.aws_profile:
                session_kwargs["profile_name"] = self.aws_profile
            if self.aws_region:
                session_kwargs["region_name"] = self.aws_region

            session = boto3.Session(**session_kwargs)
            self._client = session.client("kms")
        return self._client

    def _fetch_key_policy(self, key_arn: str) -> dict:
        """Fetch and parse the default key policy for a KMS key."""
        client = self._kms_client()
        try:
            response = client.get_key_policy(KeyId=key_arn, PolicyName="default")
        except Exception as exc:
            raise RuntimeError(f"Failed to fetch key policy for {key_arn}: {exc}") from exc
        return json.loads(response["Policy"])

    def _extract_allow_actions(self, policy_doc: dict, key_arn: str) -> list[str]:
        """Extract all Allow kms:* actions from a policy document."""
        actions: set[str] = set()
        for stmt in policy_doc.get("Statement", []):
            if stmt.get("Effect") != "Allow":
                continue
            resources = stmt.get("Resource", [])
            if isinstance(resources, str):
                resources = [resources]
            # Only include if scoped to this key or '*'
            if not any(r == "*" or r == key_arn or key_arn.endswith(r) for r in resources):
                # Skip root account wildcard entries
                if "root" in str(stmt.get("Principal", "")):
                    continue
            raw = stmt.get("Action", [])
            if isinstance(raw, str):
                raw = [raw]
            actions.update(a for a in raw if a.startswith("kms:"))
        return sorted(actions)

    def audit(
        self,
        *,
        role: str,
        key_arn: str,
        strict: bool = False,
    ) -> AuditResult:
        """
        Fetch the actual KMS key policy and compare against the HSED role.

        Parameters
        ----------
        role:
            HSED role name to audit against.
        key_arn:
            KMS key ARN to audit.
        strict:
            If True, extra permissions (over-grants) produce FAIL findings.
            If False (default), extra permissions produce WARN findings.

        Returns
        -------
        AuditResult
            Full comparison result with findings and action diff.
        """
        resolved = self.policy.get_role(role)
        expected = _actions_for_permissions(resolved.permissions)
        findings: list[AuditFinding] = []
        actual: list[str] = []
        raw_policy: dict | None = None

        try:
            raw_policy = self._fetch_key_policy(key_arn)
            actual = self._extract_allow_actions(raw_policy, key_arn)
        except RuntimeError as exc:
            findings.append(
                AuditFinding(
                    severity=FindingSeverity.ERROR,
                    message="Could not fetch key policy",
                    detail=str(exc),
                )
            )
            return AuditResult(
                role_name=resolved.name,
                permissions=resolved.permissions,
                key_arn=key_arn,
                expected_allow=expected,
                actual_allow=[],
                findings=findings,
                raw_policy=None,
            )

        result = AuditResult(
            role_name=resolved.name,
            permissions=resolved.permissions,
            key_arn=key_arn,
            expected_allow=expected,
            actual_allow=actual,
            raw_policy=raw_policy,
        )

        # Missing actions — FAIL
        for action in result.missing_actions:
            findings.append(
                AuditFinding(
                    severity=FindingSeverity.FAIL,
                    message=f"Missing required action: {action}",
                    detail=f"Expected by HSED role '{resolved.name}' ({permission_string(resolved.permissions)})",
                )
            )

        # Extra actions — WARN or FAIL
        for action in result.extra_actions:
            sev = FindingSeverity.FAIL if strict else FindingSeverity.WARN
            findings.append(
                AuditFinding(
                    severity=sev,
                    message=f"Over-grant: {action} is present but not required",
                    detail="Remove this action to enforce least privilege",
                )
            )

        if not findings:
            findings.append(
                AuditFinding(
                    severity=FindingSeverity.OK,
                    message="Policy matches HSED definition exactly",
                )
            )

        result.findings = findings
        return result

    def audit_all(
        self,
        *,
        key_arn: str,
        strict: bool = False,
    ) -> dict[str, AuditResult]:
        """Audit all roles in the policy against the same key ARN."""
        return {
            role.name: self.audit(role=role.name, key_arn=key_arn, strict=strict)
            for role in self.policy.roles()
        }
