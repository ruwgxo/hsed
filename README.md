[![CI](https://github.com/ruwgxo/hsed/actions/workflows/ci.yml/badge.svg)](https://github.com/ruwgxo/hsed/actions/workflows/ci.yml)

# hsed - Hash | Sign | Encrypt | Decrypt

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

| Bit | Value | Operation                                        |
|-----|-------|--------------------------------------------------|
| H   | 8     | Hash / Verify - compute hashes, verify signatures |
| S   | 4     | Sign - create digital signatures, attestations    |
| E   | 2     | Encrypt - seal data, create ciphertext            |
| D   | 1     | Decrypt - unseal data, read plaintext             |

Combine them like octal: `hsed 12` = `H(8) + S(4)` = hash and sign only.

### Built-in Roles

| Role        | Value | Label | Description                          |
|-------------|-------|-------|--------------------------------------|
| `root`      | 15    | HSED  | Full authority                       |
| `admin`     | 14    | HSE-  | H+S+E, no decrypt                    |
| `signer`    | 12    | HS--  | CI/CD pipelines, code signing        |
| `vault`     | 3     | --ED  | Secrets management                   |
| `audit`     | 9     | H--D  | Compliance, forensics, read-only     |
| `encryptor` | 10    | H-E-  | Data ingestion, DMZ encryptors       |
| `verifier`  | 8     | H---  | Signature verification only          |
| `none`      | 0     | ----  | No permissions - deny all            |

---

## Install

```bash
pip install hsed                    # core (zero deps)
pip install hsed[aws]               # + boto3
pip install hsed[vault]             # + hvac
pip install "hsed[aws,vault]"       # multiple integrations
```

---

## Python API

### Basic usage

```python
from hsed import Policy, Role, Bit, enforce

policy = Policy('ci-prod')
policy.add_role(Role('signer', permissions=12))   # H+S

# Decorator bound to the policy - fails at decoration time (eager=True)
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
    r.can(Bit.DECRYPT)   # True - temporarily elevated
r.can(Bit.DECRYPT)       # False - restored
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

# Show a policy
hsed policy show ci-prod.hsed

# Validate a policy for anomalies
hsed policy validate ci-prod.hsed

# Generate AWS KMS IAM policy (stdout)
hsed generate aws-kms \
  --policy ci-prod.hsed \
  --role signer \
  --key-arn arn:aws:kms:us-east-1:123456789012:key/mrk-abc123

# Generate and save to file
hsed generate aws-kms \
  --policy ci-prod.hsed \
  --role signer \
  --key-arn arn:aws:kms:us-east-1:123456789012:key/mrk-abc123 \
  --output signer-kms-policy.json

# Generate HashiCorp Vault HCL policy
hsed generate vault \
  --policy ci-prod.hsed \
  --role signer \
  --mount transit \
  --key ci-signing-key

# Audit a policy file
hsed audit ci-prod.hsed
```

---

## AWS KMS Integration

```python
from hsed import Policy, Role
from hsed.integrations.aws_kms import AWSKMSGenerator

policy = Policy('ci')
policy.add_role(Role('signer', permissions=12))

gen = AWSKMSGenerator(policy)

# Single role → IAM policy document
doc = gen.generate(
    role='signer',
    key_arn='arn:aws:kms:us-east-1:123456789012:key/mrk-abc',
    principal='arn:aws:iam::123456789012:role/ci-runner',
)
print(doc.to_json())

# KMS key resource policy (with root access)
kp = gen.key_policy(
    role='signer',
    key_arn='arn:aws:kms:us-east-1:123456789012:key/mrk-abc',
    account_id='123456789012',
    principal_arns=['arn:aws:iam::123456789012:role/ci-runner'],
)
```

HSED → KMS action mapping:

| Bit | KMS Actions |
|-----|-------------|
| H   | `kms:Verify`, `kms:GetPublicKey`, `kms:DescribeKey` |
| S   | `kms:Sign`, `kms:GetPublicKey`, `kms:DescribeKey` |
| E   | `kms:Encrypt`, `kms:GenerateDataKey`, `kms:GenerateDataKeyWithoutPlaintext`, `kms:DescribeKey` |
| D   | `kms:Decrypt`, `kms:GenerateDataKey`, `kms:DescribeKey` |

Destructive operations (`kms:DeleteAlias`, `kms:ScheduleKeyDeletion`, etc.) are
always denied via an explicit Deny statement.

---

## HashiCorp Vault Integration

```python
from hsed import Policy, Role
from hsed.integrations.vault import VaultGenerator

policy = Policy('ci')
policy.add_role(Role('signer', permissions=12))

gen = VaultGenerator(policy)
doc = gen.generate(role='signer', mount='transit', key_name='ci-signing-key')
print(doc.to_hcl())
```

---

## Repo Layout

```
hsed/
├── hsed/
│   ├── core/
│   │   ├── permissions.py     # Bit model, Role, helpers
│   │   ├── policy.py          # Policy - role registry + serialisation
│   │   └── enforcement.py     # @enforce, PolicyEnforcer, PermissionScope
│   ├── integrations/
│   │   ├── aws_kms.py         # AWS KMS IAM policy generation
│   │   └── vault.py           # HashiCorp Vault HCL generation
│   └── cli/
│       └── main.py            # CLI entry point
├── tests/
│   └── test_hsed.py           # 88 tests, zero deps beyond pytest
└── examples/
    ├── cicd-pipeline/
    ├── secrets-manager/
    ├── audit-trail/
    └── zero-trust/
```

---

## Development

```bash
git clone https://github.com/ruwgxo/hsed
cd hsed
pip install -e ".[dev]"
pytest tests/ -v
```

---

## License

MIT
