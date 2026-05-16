"""
hsed.cli.main
─────────────
CLI for the HSED permission framework.

Commands:
    hsed role list
    hsed role show <name>
    hsed role create <name> --permissions <int> [--description <str>]

    hsed policy init [--name <str>] [--output <path>]
    hsed policy show <file>
    hsed policy validate <file>

    hsed generate aws-kms   --policy <file> --role <name> --key-arn <arn>
    hsed generate vault     --policy <file> --role <name> --mount <mount> --key <key>

    hsed audit <file>
"""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import NoReturn


# ---------------------------------------------------------------------------
# Lazy imports (avoid heavyweight imports on every invocation)
# ---------------------------------------------------------------------------

def _permissions():
    from hsed.core.permissions import (
        Bit, Role, builtin_role, permission_string, parse_permission_string,
        HSEDValidationError,
    )
    return locals()


def _policy_mod():
    from hsed.core.policy import Policy, RoleNotFoundError
    return locals()


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _err(msg: str) -> NoReturn:
    print(f"hsed: error: {msg}", file=sys.stderr)
    sys.exit(1)


def _ok(msg: str) -> None:
    print(msg)


def _load_policy(path: str):
    from hsed.core.policy import Policy
    try:
        return Policy.load(path)
    except FileNotFoundError:
        _err(f"Policy file not found: {path}")
    except Exception as exc:
        _err(f"Failed to load policy: {exc}")


# ---------------------------------------------------------------------------
# Subcommand handlers
# ---------------------------------------------------------------------------

# ── role ──────────────────────────────────────────────────────────────────

def cmd_role_list(_args: argparse.Namespace) -> None:
    from hsed.core.permissions import Role, permission_string
    _ok(f"{'NAME':<14} {'PERM':>4}  {'LABEL'}  DESCRIPTION")
    _ok("-" * 60)
    for name, role in sorted(Role.BUILTIN.items()):
        _ok(f"{name:<14} {role.permissions:>4}  {role.label}  {role.description}")


def cmd_role_show(args: argparse.Namespace) -> None:
    from hsed.core.permissions import builtin_role, HSEDValidationError, active_bits
    try:
        role = builtin_role(args.name)
    except HSEDValidationError as e:
        _err(str(e))
    _ok(f"Name:        {role.name}")
    _ok(f"Permissions: {role.permissions}  ({role.label})")
    _ok(f"Active bits: {', '.join(b.name for b in role.bits)}")
    _ok(f"Description: {role.description}")


def cmd_role_create(args: argparse.Namespace) -> None:
    from hsed.core.permissions import Role, HSEDValidationError, parse_permission_string
    try:
        # Accept integer or HSED string (e.g. 'HS--' or '12')
        perm_raw = args.permissions
        if perm_raw.isdigit():
            permissions = int(perm_raw)
        else:
            permissions = parse_permission_string(perm_raw)
        role = Role(args.name, permissions=permissions, description=args.description or "")
    except HSEDValidationError as e:
        _err(str(e))

    _ok(f"Created role '{role.name}': hsed:{role.label}/{role.permissions}")
    _ok(f"  Active bits: {', '.join(b.name for b in role.bits) or 'none'}")

    if args.policy:
        from hsed.core.policy import Policy, RoleConflictError
        p = _load_policy(args.policy)
        try:
            p.add_role(role, overwrite=args.force)
        except RoleConflictError as e:
            _err(str(e))
        saved = p.save(args.policy)
        _ok(f"  Saved to: {saved}")


# ── policy ────────────────────────────────────────────────────────────────

def cmd_policy_init(args: argparse.Namespace) -> None:
    from hsed.core.policy import Policy
    from hsed.core.permissions import Role

    name = args.name or "default"
    p = Policy(name=name, description=args.description or "")

    if args.roles:
        for role_spec in args.roles:
            # Accept "name:perm" pairs or just built-in names
            if ":" in role_spec:
                rname, rperm = role_spec.split(":", 1)
                p.add_role(Role(rname.strip(), permissions=int(rperm.strip())))
            else:
                p.add_builtin(role_spec.strip())

    output = args.output or f"{name}.hsed"
    saved = p.save(output)
    _ok(f"Initialised policy '{name}' → {saved}")
    _ok(str(p))


def cmd_policy_show(args: argparse.Namespace) -> None:
    p = _load_policy(args.file)
    _ok(str(p))


def cmd_policy_validate(args: argparse.Namespace) -> None:
    p = _load_policy(args.file)
    warnings = p.validate()
    if not warnings:
        _ok(f"✓  Policy '{p.name}' is valid ({len(p)} roles, no issues)")
    else:
        _ok(f"⚠  Policy '{p.name}' has {len(warnings)} warning(s):")
        for w in warnings:
            _ok(f"   • {w}")
        sys.exit(1)


# ── generate ──────────────────────────────────────────────────────────────

def cmd_generate_aws_kms(args: argparse.Namespace) -> None:
    from hsed.integrations.aws_kms import AWSKMSGenerator
    p = _load_policy(args.policy)
    gen = AWSKMSGenerator(p)
    try:
        doc = gen.generate(
            role=args.role,
            key_arn=args.key_arn,
            principal=args.principal,
        )
    except Exception as e:
        _err(str(e))

    output_json = doc.to_json()

    if args.output:
        path = Path(args.output)
        path.write_text(output_json, encoding="utf-8")
        _ok(f"Wrote AWS KMS policy → {path}")
        if args.metadata:
            _ok(json.dumps(doc.metadata(), indent=2))
    else:
        _ok(output_json)
        if args.metadata:
            _ok("\n# Metadata:")
            _ok(json.dumps(doc.metadata(), indent=2))


def cmd_generate_vault(args: argparse.Namespace) -> None:
    from hsed.integrations.vault import VaultGenerator
    p = _load_policy(args.policy)
    gen = VaultGenerator(p)
    try:
        doc = gen.generate(
            role=args.role,
            mount=args.mount or "transit",
            key_name=args.key or "*",
        )
    except Exception as e:
        _err(str(e))

    hcl = doc.to_hcl()

    if args.output:
        path = Path(args.output)
        path.write_text(hcl, encoding="utf-8")
        _ok(f"Wrote Vault HCL policy → {path}")
    else:
        _ok(hcl)


# ── audit ─────────────────────────────────────────────────────────────────

def cmd_audit(args: argparse.Namespace) -> None:
    p = _load_policy(args.file)
    _ok(f"Policy: {p.name}")
    _ok(f"Roles:  {len(p)}")
    _ok("")
    _ok(f"{'ROLE':<16} {'PERM':>4}  {'LABEL'}  {'H':>1} {'S':>1} {'E':>1} {'D':>1}  DESCRIPTION")
    _ok("-" * 72)
    from hsed.core.permissions import Bit
    for role in sorted(p.roles(), key=lambda r: -r.permissions):
        row = (
            f"{role.name:<16} {role.permissions:>4}  {role.label}  "
            f"{'✓' if role.can(Bit.HASH) else '·':>1} "
            f"{'✓' if role.can(Bit.SIGN) else '·':>1} "
            f"{'✓' if role.can(Bit.ENCRYPT) else '·':>1} "
            f"{'✓' if role.can(Bit.DECRYPT) else '·':>1}  "
            f"{role.description}"
        )
        _ok(row)

    warnings = p.validate()
    if warnings:
        _ok("")
        _ok(f"⚠  {len(warnings)} warning(s):")
        for w in warnings:
            _ok(f"   • {w}")


# ---------------------------------------------------------------------------
# Parser construction
# ---------------------------------------------------------------------------

def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="hsed",
        description="HSED - cryptographic permission framework (Hash|Sign|Encrypt|Decrypt)",
    )
    sub = root.add_subparsers(dest="command", required=True)

    # ── role ──────────────────────────────────────────────────────────
    role_p = sub.add_parser("role", help="Role operations")
    role_sub = role_p.add_subparsers(dest="role_cmd", required=True)

    role_sub.add_parser("list", help="List built-in HSED roles")

    show_p = role_sub.add_parser("show", help="Show details for a built-in role")
    show_p.add_argument("name", help="Role name (e.g. signer, vault)")

    create_p = role_sub.add_parser("create", help="Create a new role")
    create_p.add_argument("name", help="Role name")
    create_p.add_argument("--permissions", "-p", required=True,
                          help="Permission value: integer (12) or HSED string (HS--)")
    create_p.add_argument("--description", "-d", default="", help="Role description")
    create_p.add_argument("--policy", help="Path to .hsed policy file to add the role to")
    create_p.add_argument("--force", action="store_true",
                          help="Overwrite existing role of same name in policy")

    # ── policy ────────────────────────────────────────────────────────
    policy_p = sub.add_parser("policy", help="Policy file operations")
    policy_sub = policy_p.add_subparsers(dest="policy_cmd", required=True)

    init_p = policy_sub.add_parser("init", help="Create a new policy file")
    init_p.add_argument("--name", default="default", help="Policy name")
    init_p.add_argument("--description", default="", help="Policy description")
    init_p.add_argument("--roles", nargs="*",
                        help="Built-in role names or 'name:perm' pairs to include")
    init_p.add_argument("--output", "-o", help="Output path (default: <name>.hsed)")

    show2_p = policy_sub.add_parser("show", help="Display a policy file")
    show2_p.add_argument("file", help="Path to .hsed file")

    val_p = policy_sub.add_parser("validate", help="Validate a policy file")
    val_p.add_argument("file", help="Path to .hsed file")

    # ── generate ──────────────────────────────────────────────────────
    gen_p = sub.add_parser("generate", help="Generate cloud provider policies")
    gen_sub = gen_p.add_subparsers(dest="gen_target", required=True)

    aws_p = gen_sub.add_parser("aws-kms", help="Generate AWS KMS IAM policy")
    aws_p.add_argument("--policy", required=True, help="Path to .hsed policy file")
    aws_p.add_argument("--role", required=True, help="Role name")
    aws_p.add_argument("--key-arn", required=True, dest="key_arn", help="KMS key ARN")
    aws_p.add_argument("--principal", help="IAM principal ARN (optional)")
    aws_p.add_argument("--output", "-o", help="Output file path (default: stdout)")
    aws_p.add_argument("--metadata", action="store_true", help="Include HSED metadata")

    vault_p = gen_sub.add_parser("vault", help="Generate HashiCorp Vault HCL policy")
    vault_p.add_argument("--policy", required=True, help="Path to .hsed policy file")
    vault_p.add_argument("--role", required=True, help="Role name")
    vault_p.add_argument("--mount", default="transit", help="Vault transit mount (default: transit)")
    vault_p.add_argument("--key", default="*", help="Key name within mount (default: *)")
    vault_p.add_argument("--output", "-o", help="Output file path (default: stdout)")

    # ── audit ─────────────────────────────────────────────────────────
    audit_p = sub.add_parser("audit", help="Audit a policy file")
    audit_p.add_argument("file", help="Path to .hsed file")

    return root


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------

def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    dispatch = {
        ("role", "list"):       cmd_role_list,
        ("role", "show"):       cmd_role_show,
        ("role", "create"):     cmd_role_create,
        ("policy", "init"):     cmd_policy_init,
        ("policy", "show"):     cmd_policy_show,
        ("policy", "validate"): cmd_policy_validate,
        ("generate", "aws-kms"):cmd_generate_aws_kms,
        ("generate", "vault"):  cmd_generate_vault,
        ("audit", None):        cmd_audit,
    }

    key = (args.command, getattr(args, "role_cmd", None)
                          or getattr(args, "policy_cmd", None)
                          or getattr(args, "gen_target", None))

    handler = dispatch.get(key)
    if handler is None:
        _err(f"Unknown command: {args.command}")

    handler(args)


if __name__ == "__main__":
    main()
