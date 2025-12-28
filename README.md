# HSED: Unix Permissions for Cryptography

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![PRs Welcome](https://img.shields.io/badge/PRs-welcome-brightgreen.svg)](CONTRIBUTING.md)

> If `chmod` taught us `rwx`, what's the permission model for cryptography?

**HSED: Hash | Sign | Encrypt | Decrypt**

---

## The Problem

You need to grant your CI/CD pipeline access to sign container images, but your cloud provider's IAM policy looks like this:
```json
{
  "Effect": "Allow",
  "Action": [
    "kms:Decrypt",
    "kms:Encrypt", 
    "kms:Sign",
    "kms:Verify",
    "kms:GenerateDataKey",
    "kms:CreateKey",
    "kms:DescribeKey"
  ],
  "Resource": "*"
}
```

**Translation:** "We gave up and granted everything."

Sound familiar?

---

## The Solution
```bash
# Your CI/CD pipeline should only sign
hsed:signer = 12   # H+S (Hash + Sign only)

# Your secrets manager should only encrypt/decrypt
hsed:vault = 3     # E+D (Encrypt + Decrypt only)

# Your audit team should verify and read
hsed:audit = 9     # H+D (Hash + Decrypt only)
```

Just like `chmod 755`, but for cryptographic operations.

---

## Quick Start

### Installation
```bash
pip install hsed
```

### CLI Usage
```bash
# Initialize HSED policy
hsed init

# Create a signer role (CI/CD)
hsed role create signer --permissions 12

# Generate AWS KMS policy
hsed generate aws-kms --role signer --key-arn arn:aws:kms:...

# Validate existing policies
hsed validate policy.hsed

# Audit your AWS KMS permissions
hsed audit aws-kms --profile production
```

### Python API
```python
from hsed import Policy, Role, Permissions

# Define roles
policy = Policy()
policy.add_role(Role('signer', permissions=12))  # H+S
policy.add_role(Role('vault', permissions=3))    # E+D
policy.add_role(Role('audit', permissions=9))    # H+D

# Enforce at runtime
@policy.enforce(role='signer')
def sign_artifact(data: bytes) -> bytes:
    return sign_data(data)  # ✓ Allowed
    
@policy.enforce(role='signer') 
def decrypt_secret(ciphertext: bytes) -> bytes:
    return decrypt_data(ciphertext)  # ✗ PermissionError!

# Generate cloud provider policies
aws_policy = policy.to_aws_kms(role='signer', key_arn='...')
vault_policy = policy.to_vault(role='signer', path='signing/*')
```

---

## The HSED Permission Model

### Permission Bits
```
H | S | E | D
8   4   2   1
```

- **H (8)** - Hash/Verify: Compute hashes, verify signatures
- **S (4)** - Sign: Create digital signatures, attestations
- **E (2)** - Encrypt: Seal data, create ciphertext
- **D (1)** - Decrypt: Unseal data, read plaintext

### Octal Notation (like chmod)
```bash
hsed 15  # 1111 = H+S+E+D = Full crypto authority (root)
hsed 12  # 1100 = H+S     = Sign only (CI/CD, code signing)
hsed 3   # 0011 = E+D     = Encrypt/Decrypt (vault, secrets)
hsed 9   # 1001 = H+D     = Verify + Read (audit, forensics)
hsed 10  # 1010 = H+E     = Hash + Encrypt (DMZ, ingress)
```

### Standard Roles

| Role | Permissions | Use Case |
|------|-------------|----------|
| `hsed:root` | 15 (H+S+E+D) | Full authority (break glass) |
| `hsed:admin` | 14 (H+S+E) | Admin without decrypt |
| `hsed:signer` | 12 (H+S) | CI/CD, code signing, attestation |
| `hsed:vault` | 3 (E+D) | Secrets management |
| `hsed:audit` | 9 (H+D) | Compliance, forensics |
| `hsed:encryptor` | 10 (H+E) | Data ingestion, sealing |
| `hsed:verifier` | 8 (H) | Signature verification only |

---

## Why HSED?

### 1. **Least Privilege by Design**
```python
# Without HSED: Overly permissive
"Action": ["kms:*"]  # 😱

# With HSED: Precise permissions
role = Role('signer', permissions=12)  # Only H+S ✓
```

### 2. **Separation of Duties**
```
Financial Transaction Flow:
┌─────────────────────────────────────┐
│ Initiator:  hsed 10 (H+E)          │  ← Can hash and seal request
│ Approver:   hsed 13 (H+S+D)        │  ← Can verify, sign, decrypt
│ Executor:   hsed 9  (H+D)          │  ← Can verify signature, decrypt
└─────────────────────────────────────┘

No single role can complete the transaction alone.
```

### 3. **Universal Application**

Works across:
- ✅ AWS KMS
- ✅ HashiCorp Vault
- ✅ Azure Key Vault
- ✅ GCP Cloud KMS
- ✅ Hardware Security Modules (HSMs)
- ✅ Custom key management systems

### 4. **Audit-Friendly**
```bash
# Find all god-mode access
grep "hsed:15" audit-trail.log

# Find all roles that can decrypt
hsed audit list --can-decrypt

# Compliance report
hsed report --soc2 --output compliance.pdf
```

### 5. **Memorable & Teachable**

If your team knows `chmod 755`, they'll understand `hsed 12`.

---

## Real-World Examples

### CI/CD Code Signing
```yaml
# GitHub Actions workflow
- name: Sign container image
  env:
    HSED_ROLE: signer  # permissions=12 (H+S)
  run: |
    hsed sign --key signing-key \
      --input image.tar \
      --output image.tar.sig
```

**Permissions enforced:**
- ✅ Can hash the image
- ✅ Can sign the hash
- ❌ Cannot decrypt production secrets
- ❌ Cannot encrypt (prevents data exfiltration)

### Secrets Management
```python
from hsed import enforce

@enforce(role='vault')  # permissions=3 (E+D)
def store_secret(name: str, value: str):
    encrypted = encrypt(value)
    save_to_store(name, encrypted)

@enforce(role='vault')
def retrieve_secret(name: str) -> str:
    encrypted = load_from_store(name)
    return decrypt(encrypted)
```

**Permissions enforced:**
- ✅ Can encrypt secrets
- ✅ Can decrypt secrets
- ❌ Cannot sign (prevents forging attestations)
- ❌ Cannot hash (focused role)

### Audit & Forensics
```bash
# Auditor role: hsed:audit (permissions=9, H+D)
hsed audit verify-logs \
  --role audit \
  --logs /var/log/audit/* \
  --key-id audit-key
```

**Permissions enforced:**
- ✅ Can verify log signatures
- ✅ Can decrypt evidence for investigation
- ❌ Cannot sign (prevents evidence tampering)
- ❌ Cannot encrypt (prevents hiding data)

---

## Documentation

### 📚 [Complete Book](chapters/README.md)

Comprehensive guide covering:
- Chapter 1: Introduction & Fundamentals
- Chapter 2: Core Concepts
- Chapter 3: Implementation Patterns
- Chapter 4: Cloud Provider Integration
- Chapter 5: Security & Compliance
- Chapter 6: Advanced Topics
- Chapter 7: Real-World Case Studies

### 📖 [Specification](SPECIFICATION.md)

RFC-style specification of the HSED permission model.

### 🚀 [Quick Start Guides](docs/guides/)

- [AWS KMS Integration](docs/guides/aws-kms.md)
- [HashiCorp Vault Setup](docs/guides/vault.md)
- [Azure Key Vault Configuration](docs/guides/azure-keyvault.md)
- [GCP Cloud KMS Setup](docs/guides/gcp-kms.md)

### 🛠️ [Examples](examples/)

Ready-to-use implementations:
- [CI/CD Pipeline Security](examples/cicd-pipeline/)
- [Secrets Management](examples/secrets-manager/)
- [Audit Trail Design](examples/audit-trail/)
- [Zero-Trust Architecture](examples/zero-trust/)

---

## Project Structure
```
hsed/
├── chapters/              # Complete book (YAML format)
│   ├── hsed_book_index.yaml
│   ├── chapter_1_index.yaml
│   ├── section_1_01_introduction.yaml
│   └── ...
│
├── hsed/                  # Python package
│   ├── core/             # Core permission engine
│   ├── enforcement/      # Runtime enforcement
│   ├── integrations/     # Cloud provider integrations
│   ├── cli/              # Command-line interface
│   └── utils/            # Utilities
│
├── examples/             # Real-world usage patterns
│   ├── cicd-pipeline/
│   ├── secrets-manager/
│   ├── audit-trail/
│   └── zero-trust/
│
├── templates/            # Ready-to-use templates
│   ├── aws-kms/
│   ├── hashicorp-vault/
│   └── kubernetes/
│
├── tests/                # Test suite
├── docs/                 # Generated documentation
└── bin/                  # CLI executable
```

---

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

**Areas we'd love help with:**
- Additional cloud provider integrations (IBM Cloud, Oracle Cloud)
- Language bindings (Go, Rust, Java)
- Terraform/CloudFormation modules
- Real-world case studies
- Documentation improvements

---

## Why "HSED"?

**H**ash | **S**ign | **E**ncrypt | **D**ecrypt

Four fundamental cryptographic operations. Four permission bits. Simple. Universal. Memorable.

Just like `chmod` taught us `rwx`, HSED teaches us who touches our crypto, and how.

---

## License

MIT License - see [LICENSE](LICENSE) for details.

---

## Citation

If you use HSED in your research or production systems, please cite:
```bibtex
@software{hsed2024,
  title = {HSED: Unix Permissions for Cryptographic Operations},
  author = {Your Name},
  year = {2024},
  url = {https://github.com/yourusername/hsed}
}
```

---

## Acknowledgments

Inspired by:
- Unix file permissions (`chmod`)
- Principle of least privilege
- Real-world pain of managing KMS/HSM permissions
- Need for simple, universal security abstractions

---

## Status

🚧 **Early Development** - API may change

- [x] Core permission model
- [x] Python implementation
- [x] CLI tool
- [ ] AWS KMS integration
- [ ] HashiCorp Vault integration
- [ ] Azure Key Vault integration
- [ ] GCP Cloud KMS integration
- [ ] Complete documentation
- [ ] Production-ready (v1.0.0)

**Star ⭐ this repo to follow progress!**

---

## Contact

- **Issues**: [GitHub Issues](https://github.com/yourusername/hsed/issues)
- **Discussions**: [GitHub Discussions](https://github.com/yourusername/hsed/discussions)
- **Security**: See [SECURITY.md](SECURITY.md) for responsible disclosure

---

<div align="center">

**If `chmod` taught you `rwx`, let HSED teach you crypto permissions.**

Made with ❤️ for security engineers who believe in least privilege.

</div>
