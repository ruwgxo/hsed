# hsed — Hash | Sign | Encrypt | Decrypt

A Unix `chmod`-inspired permission model for cryptographic operations. If
`chmod` taught `rwx`, `hsed` teaches who can touch cryptographic operations
and how.

```
hsed 15 → HSED → full authority (root)
hsed 12 → HS-- → sign only (CI/CD)
hsed  3 → --ED → vault (secrets manager)
hsed  9 → H--D → audit (forensics)
```

> since 2012

---

## The Model

Four permission bits on a 4-bit mask:

| Bit | Value | Operation                                         |
|-----|-------|---------------------------------------------------|
| H   | 8     | Hash / Verify — compute hashes, verify signatures |
| S   | 4     | Sign — create digital signatures, attestations    |
| E   | 2     | Encrypt — seal data, create ciphertext            |
| D   | 1     | Decrypt — unseal data, read plaintext             |

Combine them like octal: `hsed 12` = `H(8) + S(4)` = hash and sign only.

### Built-in Roles

| Role        | Value | Label | Description                      |
|-------------|-------|-------|----------------------------------|
| `root`      | 15    | HSED  | Full authority                   |
| `admin`     | 14    | HSE-  | H+S+E, no decrypt                |
| `signer`    | 12    | HS--  | CI/CD pipelines, code signing    |
| `vault`     | 3     | --ED  | Secrets management               |
| `audit`     | 9     | H--D  | Compliance, forensics, read-only |
| `encryptor` | 10    | H-E-  | Data ingestion, DMZ encryptors   |
| `verifier`  | 8     | H---  | Signature verification only      |
| `none`      | 0     | ----  | No permissions — deny all        |

---

## Install

```bash
pip install hsed                      # core (zero deps)
pip install hsed[aws]                 # + boto3 (AWS KMS)
pip install hsed[vault]               # + hvac (HashiCorp Vault)
pip install hsed[azure]               # + azure-mgmt-keyvault, azure-identity
pip install hsed[gcp]                 # + google-cloud-kms
pip install "hsed[aws,vault]"         # multiple integrations
pip install "hsed[all]"               # everything
```

---

## Python API

### Basic usage

```python
from hsed import Policy, Role, Bit, enforce

policy = Policy('ci-prod')
policy.add_role(Role('signer', permissions=12))   # H+S

@policy.enforce_op(role='signer', requires=Bit.SIGN)
def sign_artifact(data: bytes) -> bytes:
    return sign_data(data)          # ✓ allowed

@policy.enforce_op(role='signer', requires=Bit.DECRYPT)
def decrypt_secret(ct: bytes) -> bytes:
    return decrypt_data(ct)         # ✗ raises HSEDPermissionError immediately
```

### Standalone decorator

```python
from hsed import Role, Bit, enforce

signer = Role('signer', permissions=12)

@enforce(role=signer, requires=Bit.SIGN)
def sign(data: bytes) -> bytes:
    ...
```

### Built-in roles

```python
from hsed import Policy, builtin_role

p = Policy('production')
p.add_builtin('signer')     # adds Role('signer', permissions=12)
p.add_builtin('vault')      # adds Role('vault', permissions=3)
```

### Policy serialisation

```python
p = Policy('production', description='Prod crypto policy')
p.add_builtin('signer')
p.add_builtin('audit')

p.save('production.hsed')           # writes JSON
p2 = Policy.load('production.hsed') # roundtrip
```

### Permission helpers

```python
from hsed import permission_string, parse_permission_string, combine, intersect

permission_string(12)           # 'HS--'
parse_permission_string('H-E-') # 10
combine(8, 4)                   # 12  (union)
intersect(15, 12)               # 12  (intersection)
```

### Temporary scope (tests / auditing)

```python
from hsed import Role, Bit, PermissionScope

r = Role('signer', permissions=12)
with PermissionScope(r, add=Bit.DECRYPT):
    r.can(Bit.DECRYPT)   # True — temporarily elevated
r.can(Bit.DECRYPT)       # False — restored
```

---

## CLI

```bash
# List all built-in roles
hsed role list

# Inspect a role
hsed role show signer

# Create a policy file
hsed policy init --name ci-prod --roles signer audit --output ci-prod.hsed

# Validate a policy for anomalies
hsed policy validate ci-prod.hsed

# Audit a policy file (static)
hsed audit ci-prod.hsed

# Generate AWS KMS IAM policy
hsed generate aws-kms \
  --policy ci-prod.hsed \
  --role signer \
  --key-arn arn:aws:kms:us-east-1:123456789012:key/mrk-abc123

# Generate HashiCorp Vault HCL policy
hsed generate vault \
  --policy ci-prod.hsed \
  --role signer \
  --mount transit \
  --key ci-signing-key

# Generate Azure Key Vault access policy
hsed generate azure \
  --policy ci-prod.hsed \
  --role signer \
  --tenant-id 00000000-0000-0000-0000-000000000000 \
  --object-id aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee

# Generate Azure RBAC role assignment
hsed generate azure-rbac \
  --policy ci-prod.hsed \
  --role signer \
  --scope /subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{vault} \
  --principal-id aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee

# Generate GCP Cloud KMS IAM binding
hsed generate gcp-kms \
  --policy ci-prod.hsed \
  --role signer \
  --member serviceAccount:ci-runner@project.iam.gserviceaccount.com \
  --resource projects/my-project/locations/global/keyRings/prod/cryptoKeys/signing-key

# Generate GCP binding as gcloud command
hsed generate gcp-kms ... --gcloud

# Live audit: fetch actual AWS KMS key policy and diff against HSED definition
hsed live-audit aws-kms \
  --policy ci-prod.hsed \
  --role signer \
  --key-arn arn:aws:kms:us-east-1:123456789012:key/mrk-abc123 \
  --profile production
```

---

## AWS KMS Integration

```python
from hsed import Policy, Role
from hsed.integrations.aws_kms import AWSKMSGenerator

policy = Policy('ci')
policy.add_role(Role('signer', permissions=12))

gen = AWSKMSGenerator(policy)

doc = gen.generate(
    role='signer',
    key_arn='arn:aws:kms:us-east-1:123456789012:key/mrk-abc',
    principal='arn:aws:iam::123456789012:role/ci-runner',
)
print(doc.to_json())
```

HSED → KMS action mapping:

| Bit | KMS Actions |
|-----|-------------|
| H   | `kms:Verify`, `kms:GetPublicKey`, `kms:DescribeKey` |
| S   | `kms:Sign`, `kms:GetPublicKey`, `kms:DescribeKey` |
| E   | `kms:Encrypt`, `kms:GenerateDataKey`, `kms:GenerateDataKeyWithoutPlaintext`, `kms:DescribeKey` |
| D   | `kms:Decrypt`, `kms:GenerateDataKey`, `kms:DescribeKey` |

Destructive operations (`kms:DeleteAlias`, `kms:ScheduleKeyDeletion`, etc.) are
always denied via an explicit Deny statement regardless of role.

---

## HashiCorp Vault Integration

```python
from hsed.integrations.vault import VaultGenerator

gen = VaultGenerator(policy)
doc = gen.generate(role='signer', mount='transit', key_name='ci-signing-key')
print(doc.to_hcl())
```

---

## Azure Key Vault Integration

```python
from hsed.integrations.azure_keyvault import AzureKeyVaultGenerator

gen = AzureKeyVaultGenerator(policy)

# Access policy (classic vault model)
doc = gen.generate(
    role='signer',
    tenant_id='00000000-0000-0000-0000-000000000000',
    object_id='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
)
print(doc.to_json())

# RBAC role assignment
rbac = gen.generate_rbac(
    role='signer',
    scope='/subscriptions/{sub}/resourceGroups/{rg}/providers/Microsoft.KeyVault/vaults/{vault}',
    principal_id='aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee',
)
print(rbac.to_json())
```

HSED → Azure key permissions mapping:

| Bit | Azure Key Permissions                       |
|-----|---------------------------------------------|
| H   | `verify`, `get`                             |
| S   | `sign`, `get`                               |
| E   | `encrypt`, `wrapKey`, `get`                 |
| D   | `decrypt`, `unwrapKey`, `get`               |

HSED → Azure RBAC built-in role:

| HSED mask  | Azure Role                    |
|------------|-------------------------------|
| H+S+E+D    | Key Vault Crypto Officer      |
| H+S, E+D, others | Key Vault Crypto User   |
| H only     | Key Vault Reader              |

---

## GCP Cloud KMS Integration

```python
from hsed.integrations.gcp_kms import GCPKMSGenerator

gen = GCPKMSGenerator(policy)

doc = gen.generate(
    role='signer',
    member='serviceAccount:ci-runner@project.iam.gserviceaccount.com',
    resource='projects/my-project/locations/global/keyRings/prod/cryptoKeys/signing-key',
)
print(doc.to_json())

# As a gcloud command
print(doc.to_gcloud_command())
```

HSED → GCP predefined role mapping:

| HSED mask | GCP Role                                          |
|-----------|---------------------------------------------------|
| HS-- (12) | `roles/cloudkms.signerVerifier`                   |
| --ED ( 3) | `roles/cloudkms.cryptoKeyEncrypterDecrypter`      |
| H--D ( 9) | `roles/cloudkms.cryptoKeyDecrypter`               |
| H-E- (10) | `roles/cloudkms.cryptoKeyEncrypter`               |
| H--- ( 8) | `roles/cloudkms.viewer`                           |
| HSED (15) | `roles/cloudkms.cryptoKeyEncrypterDecrypter`      |

---

## Live Audit (AWS KMS)

Fetch the actual key policy from AWS and diff it against your HSED definition.

```python
from hsed.integrations.live_audit import AWSLiveAuditor

policy = Policy.load('production.hsed')
auditor = AWSLiveAuditor(policy, aws_profile='production')

result = auditor.audit(
    role='signer',
    key_arn='arn:aws:kms:us-east-1:123456789012:key/mrk-abc',
)
print(result.summary())
# Live Audit — Role 'signer' (hsed:HS--/12)
# Key: arn:aws:kms:...
#   ✓  [OK] Policy matches HSED definition exactly
# Result: PASS
```

Use `strict=True` to treat over-grants as `FAIL` instead of `WARN`.
Requires `pip install hsed[aws]`.

---

## Templates

Drop-in infrastructure templates for common deployment patterns:

```
templates/
├── aws-kms/
│   ├── main.tf          # KMS key + per-role IAM policies + key policy
│   ├── variables.tf     # principal ARNs per HSED role, key spec, tags
│   └── outputs.tf       # key ARN, policy ARNs, hsed audit command
├── hashicorp-vault/
│   └── policy.hcl       # Transit policy template (replace {{KEY_NAME}})
└── kubernetes/
    └── rbac.yaml        # ClusterRole + ServiceAccount per HSED role
                         # with Workload Identity / IRSA annotation stubs
```

---

## Repo Layout

```
hsed/
├── hsed/
│   ├── core/
│   │   ├── permissions.py       # Bit model, Role, helpers
│   │   ├── policy.py            # Policy — role registry + serialisation
│   │   └── enforcement.py       # @enforce, PolicyEnforcer, PermissionScope
│   ├── integrations/
│   │   ├── aws_kms.py           # AWS KMS IAM policy generation
│   │   ├── vault.py             # HashiCorp Vault HCL generation
│   │   ├── azure_keyvault.py    # Azure Key Vault access policy + RBAC
│   │   ├── gcp_kms.py           # GCP Cloud KMS IAM bindings
│   │   └── live_audit.py        # Live audit via boto3 (AWS KMS)
│   └── cli/
│       └── main.py              # CLI entry point
├── tests/
│   ├── test_hsed.py             # Core + AWS + Vault tests
│   └── test_integrations_v2.py  # Azure + GCP + live audit tests
├── templates/
│   ├── aws-kms/                 # Terraform
│   ├── hashicorp-vault/         # HCL
│   └── kubernetes/              # RBAC YAML
└── examples/
    ├── cicd-pipeline/           # signer role (HS--/12)
    ├── secrets-manager/         # vault + encryptor + audit roles
    ├── audit-trail/             # audit role + multi-cloud report
    └── zero-trust/              # all roles, all cloud providers
```

---

## Development

```bash
git clone https://github.com/ruwgxo/hsed
cd hsed
pip install -e ".[dev]"
pytest tests/ -v
```

See [SPECIFICATION.md](./SPECIFICATION.md) for the full design rationale and [CHANGELOG.md](./CHANGELOG.md) for version history.

---

## License

MIT
