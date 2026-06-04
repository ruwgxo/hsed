# Changelog

All notable changes to **hsed** are documented here.
Format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).
Versioning follows [Semantic Versioning](https://semver.org/).

---

## [0.2.0] — 2026-05-21

### Added

**Cloud integrations**

- `azure_keyvault.py` — Azure Key Vault access policies (classic vault model)
  and RBAC role assignments; maps HSED masks to Key Vault Crypto Officer /
  User / Reader built-in roles; `generate_all()` and `to_arm_fragment()`
- `gcp_kms.py` — GCP Cloud KMS IAM bindings; maps HSED masks to predefined
  roles (`signerVerifier`, `cryptoKeyEncrypterDecrypter`, etc.); custom role
  mode; `to_gcloud_command()` output; `merged_policy()` for multi-role
  `setIamPolicy` calls
- `live_audit.py` — `AWSLiveAuditor`: fetches actual KMS key policy via
  boto3, diffs against expected HSED definition, reports missing (FAIL) and
  extra (WARN / FAIL with `--strict`) actions with full severity model;
  graceful `ImportError` if boto3 not installed

**CLI additions**

- `hsed generate azure` — Azure Key Vault access policy JSON
- `hsed generate azure-rbac` — Azure RBAC role assignment JSON
- `hsed generate gcp-kms` — GCP IAM binding JSON or `--gcloud` command
- `hsed live-audit aws-kms` — live comparison against actual KMS key policy;
  supports `--profile`, `--region`, `--strict`, `--json`

**Templates**

- `templates/aws-kms/main.tf` — Terraform KMS key with HSED-labelled key
  policy statements and per-role IAM policies; dynamic blocks skip absent roles
- `templates/aws-kms/variables.tf` — principal ARNs per role, key spec, tags
- `templates/aws-kms/outputs.tf` — key ARN, policy ARNs, generated
  `hsed live-audit` command as output
- `templates/hashicorp-vault/policy.hcl` — Transit policy template with
  `{{KEY_NAME}}` placeholder
- `templates/kubernetes/rbac.yaml` — ClusterRole / ClusterRoleBinding /
  ServiceAccount per HSED role with Workload Identity (GKE) and IRSA (EKS)
  annotation stubs

**Examples**

- `examples/secrets-manager/seal_unseal.py` — vault, encryptor, audit roles
  demonstrating sealed-store permission boundaries
- `examples/audit-trail/compliance_check.py` — audit role with multi-cloud
  policy report generation across all four providers

**Tests**

- `tests/test_integrations_v2.py` — 41 new tests covering Azure, GCP, live
  audit internals, and new CLI commands (total: 129, was 88)

### Notes

- `pip install hsed[azure]` requires `azure-mgmt-keyvault` and
  `azure-identity`; `pip install hsed[gcp]` requires `google-cloud-kms`
- Live audit (`hsed live-audit aws-kms`) requires `pip install hsed[aws]`

---

## [0.1.0] — 2026-05-16

Initial public release.

### Added

**Core permission model** (`hsed/core/`)

- `Bit` — `IntFlag` enum: `HASH=8`, `SIGN=4`, `ENCRYPT=2`, `DECRYPT=1`
- `Role` — dataclass with `.can()`, `.require()`, `.grant()`, `.revoke()`,
  `.to_dict()` / `.from_dict()`
- 8 built-in roles: `root`, `admin`, `signer`, `vault`, `audit`, `encryptor`,
  `verifier`, `none`
- Helper functions: `permission_string`, `parse_permission_string`,
  `validate_permission`, `has_permission`, `active_bits`, `combine`,
  `intersect`, `subtract`
- `Policy` — typed role registry with `add_role`, `remove_role`, `get_role`,
  `enforce`, `validate`, `save` / `load` (`.hsed` JSON)
- `@enforce` decorator — eager (decoration-time) and lazy (call-time)
  permission checks
- `policy.enforce_op()` — policy-bound decorator factory
- `PermissionScope` — context manager for temporary permission elevation

**Cloud integrations**

- `aws_kms.py` — AWS KMS IAM policy documents; explicit Deny on destructive
  ops; `key_policy()` for resource-based policies
- `vault.py` — HashiCorp Vault Transit HCL policies

**CLI**

- `hsed role list / show / create`
- `hsed policy init / show / validate`
- `hsed generate aws-kms / vault`
- `hsed audit <file>` — static policy audit with per-bit matrix

**Examples**

- `examples/cicd-pipeline/sign_release.py`
- `examples/zero-trust/generate_policies.py`

**Tests**

- 88 tests in `tests/test_hsed.py`; zero external dependencies beyond pytest

### Notes

- Core has zero runtime dependencies — stdlib only
- `.hsed` policy files are plain JSON — human-readable, diff-friendly,
  version-control safe

---

## [Unreleased]

- `live_audit` support for Azure Key Vault and GCP Cloud KMS
- `hsed policy merge` — combine multiple `.hsed` files
- `hsed diff` — compare two policy files
