"""
hsed.cli.main — full CLI with all integrations and live-audit
"""

from __future__ import annotations
import argparse, json, sys
from pathlib import Path
from typing import NoReturn


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


# ── role ──────────────────────────────────────────────────────────────────


def cmd_role_list(_args):
    from hsed.core.permissions import Role

    _ok(f"{'NAME':<14} {'PERM':>4}  {'LABEL'}  DESCRIPTION")
    _ok("-" * 60)
    for name, role in sorted(Role.BUILTIN.items()):
        _ok(f"{name:<14} {role.permissions:>4}  {role.label}  {role.description}")


def cmd_role_show(args):
    from hsed.core.permissions import builtin_role, HSEDValidationError

    try:
        role = builtin_role(args.name)
    except HSEDValidationError as e:
        _err(str(e))
    _ok(f"Name:        {role.name}")
    _ok(f"Permissions: {role.permissions}  ({role.label})")
    _ok(f"Active bits: {', '.join(b.name for b in role.bits)}")
    _ok(f"Description: {role.description}")


def cmd_role_create(args):
    from hsed.core.permissions import Role, HSEDValidationError, parse_permission_string

    try:
        perm_raw = args.permissions
        permissions = int(perm_raw) if perm_raw.isdigit() else parse_permission_string(perm_raw)
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


def cmd_policy_init(args):
    from hsed.core.policy import Policy
    from hsed.core.permissions import Role

    name = args.name or "default"
    p = Policy(name=name, description=args.description or "")
    if args.roles:
        for spec in args.roles:
            if ":" in spec:
                rname, rperm = spec.split(":", 1)
                p.add_role(Role(rname.strip(), permissions=int(rperm.strip())))
            else:
                p.add_builtin(spec.strip())
    output = args.output or f"{name}.hsed"
    saved = p.save(output)
    _ok(f"Initialised policy '{name}' → {saved}")
    _ok(str(p))


def cmd_policy_show(args):
    _ok(str(_load_policy(args.file)))


def cmd_policy_validate(args):
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


def cmd_generate_aws_kms(args):
    from hsed.integrations.aws_kms import AWSKMSGenerator

    p = _load_policy(args.policy)
    try:
        doc = AWSKMSGenerator(p).generate(
            role=args.role, key_arn=args.key_arn, principal=args.principal
        )
    except Exception as e:
        _err(str(e))
    out = doc.to_json()
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        _ok(f"Wrote AWS KMS policy → {args.output}")
        if args.metadata:
            _ok(json.dumps(doc.metadata(), indent=2))
    else:
        _ok(out)
        if args.metadata:
            _ok(json.dumps(doc.metadata(), indent=2))


def cmd_generate_vault(args):
    from hsed.integrations.vault import VaultGenerator

    p = _load_policy(args.policy)
    try:
        doc = VaultGenerator(p).generate(
            role=args.role, mount=args.mount or "transit", key_name=args.key or "*"
        )
    except Exception as e:
        _err(str(e))
    hcl = doc.to_hcl()
    if args.output:
        Path(args.output).write_text(hcl, encoding="utf-8")
        _ok(f"Wrote Vault HCL policy → {args.output}")
    else:
        _ok(hcl)


def cmd_generate_azure(args):
    from hsed.integrations.azure_keyvault import AzureKeyVaultGenerator

    p = _load_policy(args.policy)
    try:
        doc = AzureKeyVaultGenerator(p).generate(
            role=args.role, tenant_id=args.tenant_id, object_id=args.object_id
        )
    except Exception as e:
        _err(str(e))
    out = doc.to_json()
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        _ok(f"Wrote Azure Key Vault access policy → {args.output}")
    else:
        _ok(out)


def cmd_generate_azure_rbac(args):
    from hsed.integrations.azure_keyvault import AzureKeyVaultGenerator

    p = _load_policy(args.policy)
    try:
        doc = AzureKeyVaultGenerator(p).generate_rbac(
            role=args.role, scope=args.scope, principal_id=args.principal_id
        )
    except Exception as e:
        _err(str(e))
    out = doc.to_json()
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        _ok(f"Wrote Azure RBAC assignment → {args.output}")
    else:
        _ok(out)


def cmd_generate_gcp_kms(args):
    from hsed.integrations.gcp_kms import GCPKMSGenerator

    p = _load_policy(args.policy)
    try:
        doc = GCPKMSGenerator(p).generate(
            role=args.role, member=args.member, resource=args.resource
        )
    except Exception as e:
        _err(str(e))
    if args.gcloud:
        _ok(doc.to_gcloud_command())
        return
    out = doc.to_json()
    if args.output:
        Path(args.output).write_text(out, encoding="utf-8")
        _ok(f"Wrote GCP KMS IAM binding → {args.output}")
    else:
        _ok(out)


# ── audit ─────────────────────────────────────────────────────────────────


def cmd_audit_file(args):
    from hsed.core.permissions import Bit

    p = _load_policy(args.file)
    _ok(f"Policy: {p.name}")
    _ok(f"Roles:  {len(p)}")
    _ok("")
    _ok(f"{'ROLE':<16} {'PERM':>4}  {'LABEL'}  {'H':>1} {'S':>1} {'E':>1} {'D':>1}  DESCRIPTION")
    _ok("-" * 72)
    for role in sorted(p.roles(), key=lambda r: -r.permissions):
        _ok(
            f"{role.name:<16} {role.permissions:>4}  {role.label}  "
            f"{'✓' if role.can(Bit.HASH) else '·':>1} "
            f"{'✓' if role.can(Bit.SIGN) else '·':>1} "
            f"{'✓' if role.can(Bit.ENCRYPT) else '·':>1} "
            f"{'✓' if role.can(Bit.DECRYPT) else '·':>1}  "
            f"{role.description}"
        )
    warnings = p.validate()
    if warnings:
        _ok("")
        _ok(f"⚠  {len(warnings)} warning(s):")
        for w in warnings:
            _ok(f"   • {w}")


def cmd_live_audit_aws(args):
    from hsed.integrations.live_audit import AWSLiveAuditor

    p = _load_policy(args.policy)
    auditor = AWSLiveAuditor(p, aws_profile=args.profile, aws_region=args.region)
    roles_to_audit = [args.role] if args.role else list(p.role_names())
    all_passed = True
    for role_name in roles_to_audit:
        try:
            result = auditor.audit(role=role_name, key_arn=args.key_arn, strict=args.strict)
        except Exception as exc:
            _ok(f"[{role_name}] ERROR: {exc}")
            all_passed = False
            continue
        _ok(result.summary())
        _ok("")
        if args.json_out:
            _ok(json.dumps(result.to_dict(), indent=2))
        if not result.passed:
            all_passed = False
    sys.exit(0 if all_passed else 1)


# ── parser ────────────────────────────────────────────────────────────────


def build_parser() -> argparse.ArgumentParser:
    root = argparse.ArgumentParser(
        prog="hsed",
        description="HSED — cryptographic permission framework (Hash|Sign|Encrypt|Decrypt)",
    )
    sub = root.add_subparsers(dest="command", required=True)

    # role
    rp = sub.add_parser("role")
    rs = rp.add_subparsers(dest="role_cmd", required=True)
    rs.add_parser("list")
    sp = rs.add_parser("show")
    sp.add_argument("name")
    cp = rs.add_parser("create")
    cp.add_argument("name")
    cp.add_argument("--permissions", "-p", required=True)
    cp.add_argument("--description", "-d", default="")
    cp.add_argument("--policy")
    cp.add_argument("--force", action="store_true")

    # policy
    pp = sub.add_parser("policy")
    ps = pp.add_subparsers(dest="policy_cmd", required=True)
    ip = ps.add_parser("init")
    ip.add_argument("--name", default="default")
    ip.add_argument("--description", default="")
    ip.add_argument("--roles", nargs="*")
    ip.add_argument("--output", "-o")
    shp = ps.add_parser("show")
    shp.add_argument("file")
    vp = ps.add_parser("validate")
    vp.add_argument("file")

    # generate
    gp = sub.add_parser("generate")
    gs = gp.add_subparsers(dest="gen_target", required=True)

    ap = gs.add_parser("aws-kms")
    ap.add_argument("--policy", required=True)
    ap.add_argument("--role", required=True)
    ap.add_argument("--key-arn", required=True, dest="key_arn")
    ap.add_argument("--principal")
    ap.add_argument("--output", "-o")
    ap.add_argument("--metadata", action="store_true")

    vtp = gs.add_parser("vault")
    vtp.add_argument("--policy", required=True)
    vtp.add_argument("--role", required=True)
    vtp.add_argument("--mount", default="transit")
    vtp.add_argument("--key", default="*")
    vtp.add_argument("--output", "-o")

    azp = gs.add_parser("azure")
    azp.add_argument("--policy", required=True)
    azp.add_argument("--role", required=True)
    azp.add_argument("--tenant-id", required=True, dest="tenant_id")
    azp.add_argument("--object-id", required=True, dest="object_id")
    azp.add_argument("--output", "-o")

    azrp = gs.add_parser("azure-rbac")
    azrp.add_argument("--policy", required=True)
    azrp.add_argument("--role", required=True)
    azrp.add_argument("--scope", required=True)
    azrp.add_argument("--principal-id", required=True, dest="principal_id")
    azrp.add_argument("--output", "-o")

    gcpp = gs.add_parser("gcp-kms")
    gcpp.add_argument("--policy", required=True)
    gcpp.add_argument("--role", required=True)
    gcpp.add_argument("--member", required=True)
    gcpp.add_argument("--resource", required=True)
    gcpp.add_argument("--output", "-o")
    gcpp.add_argument("--gcloud", action="store_true")

    # audit (static file)
    audp = sub.add_parser("audit")
    audp.add_argument("file")

    # live-audit
    lap = sub.add_parser("live-audit")
    las = lap.add_subparsers(dest="live_target", required=True)
    laa = las.add_parser("aws-kms")
    laa.add_argument("--policy", required=True)
    laa.add_argument("--role")
    laa.add_argument("--key-arn", required=True, dest="key_arn")
    laa.add_argument("--profile")
    laa.add_argument("--region")
    laa.add_argument("--strict", action="store_true")
    laa.add_argument("--json", action="store_true", dest="json_out")

    return root


def main(argv: list[str] | None = None) -> None:
    parser = build_parser()
    args = parser.parse_args(argv)

    dispatch = {
        ("role", "list"): cmd_role_list,
        ("role", "show"): cmd_role_show,
        ("role", "create"): cmd_role_create,
        ("policy", "init"): cmd_policy_init,
        ("policy", "show"): cmd_policy_show,
        ("policy", "validate"): cmd_policy_validate,
        ("generate", "aws-kms"): cmd_generate_aws_kms,
        ("generate", "vault"): cmd_generate_vault,
        ("generate", "azure"): cmd_generate_azure,
        ("generate", "azure-rbac"): cmd_generate_azure_rbac,
        ("generate", "gcp-kms"): cmd_generate_gcp_kms,
        ("audit", None): cmd_audit_file,
        ("live-audit", "aws-kms"): cmd_live_audit_aws,
    }

    key = (
        args.command,
        getattr(args, "role_cmd", None)
        or getattr(args, "policy_cmd", None)
        or getattr(args, "gen_target", None)
        or getattr(args, "live_target", None),
    )
    handler = dispatch.get(key)
    if handler is None:
        _err(f"Unknown command: {key}")
    handler(args)


if __name__ == "__main__":
    main()
