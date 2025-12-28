# HSED Permission Model Specification

**Version:** 1.0.0-draft  
**Status:** Draft  
**Authors:** [Your Name]  
**Created:** 2024-12-29

---

## Abstract

HSED (Hash|Sign|Encrypt|Decrypt) defines a permission model for cryptographic operations inspired by Unix file permissions. This specification provides a formal definition of the model, its semantics, and implementation guidelines.

---

## 1. Introduction

### 1.1 Motivation

Modern key management systems (KMS, HSM) lack a standardized permission model. Organizations struggle with:

1. **Overly permissive policies**: Granting full crypto access because fine-grained control is complex
2. **Inconsistent abstractions**: Each cloud provider uses different IAM models
3. **Poor auditability**: Hard to understand "who can do what" with cryptographic keys
4. **No separation of duties**: Single roles often have unnecessary combined permissions

HSED addresses these challenges with a simple, memorable, universal permission model.

### 1.2 Design Goals

1. **Simplicity**: As intuitive as `chmod 755`
2. **Universality**: Works across all KMS/HSM systems
3. **Least Privilege**: Encourages minimal necessary permissions
4. **Auditability**: Easy to verify and audit
5. **Composability**: Permissions combine predictably
6. **Separation of Duties**: Enforces multi-party authorization patterns

---

## 2. Core Concepts

### 2.1 Permission Bits

HSED defines four fundamental cryptographic operations as permission bits:
```
Bit   Value   Operation   Description
─────────────────────────────────────────────────────────
H     8       Hash        Compute cryptographic hashes, verify signatures
S     4       Sign        Create digital signatures, attestations
E     2       Encrypt     Convert plaintext to ciphertext
D     1       Decrypt     Convert ciphertext to plaintext
```

### 2.2 Bit Representation

Permissions are represented as 4-bit binary values:
```
Binary    Octal   Permissions
────────────────────────────────
0000      0       None
0001      1       D
0010      2       E
0011      3       E+D
0100      4       S
0101      5       S+D
0110      6       S+E
0111      7       S+E+D
1000      8       H
1001      9       H+D
1010      10      H+E
1011      11      H+E+D
1100      12      H+S
1101      13      H+S+D
1110      14      H+S+E
1111      15      H+S+E+D
```

### 2.3 Octal Notation

Following Unix conventions, HSED uses octal notation:
```
hsed 15    # Full authority (H+S+E+D)
hsed 12    # Signer (H+S)
hsed 3     # Vault (E+D)
hsed 9     # Auditor (H+D)
```

---

## 3. Permission Semantics

### 3.1 Hash (H=8)

**Operations allowed:**
- Compute cryptographic hashes (SHA-256, SHA-3, etc.)
- Verify digital signatures
- Verify message authentication codes (MACs)
- Compute checksums

**Security implications:**
- Read access to signed/verified data
- No ability to modify or forge signatures
- No access to encrypted data

**Typical use cases:**
- Signature verification
- Integrity checking
- Audit trail validation

### 3.2 Sign (S=4)

**Operations allowed:**
- Create digital signatures
- Generate attestations
- Create message authentication codes (MACs)
- Sign certificates

**Security implications:**
- Can prove authenticity
- Can forge attestations if compromised
- Should be combined with Hash (H) for verification

**Typical use cases:**
- Code signing
- Document attestation
- Certificate issuance
- API authentication

### 3.3 Encrypt (E=2)

**Operations allowed:**
- Convert plaintext to ciphertext
- Seal data
- Generate encrypted data keys
- Create encrypted envelopes

**Security implications:**
- Can protect data confidentiality
- Cannot read encrypted data without Decrypt
- May enable data exfiltration if not monitored

**Typical use cases:**
- Data at rest encryption
- Secrets sealing
- Secure communication (sender)
- Data ingestion

### 3.4 Decrypt (D=1)

**Operations allowed:**
- Convert ciphertext to plaintext
- Unseal data
- Decrypt data keys
- Open encrypted envelopes

**Security implications:**
- Full read access to encrypted data
- Most sensitive permission
- Should be granted sparingly

**Typical use cases:**
- Secrets retrieval
- Data at rest decryption
- Secure communication (receiver)
- Key unwrapping

---

## 4. Standard Roles

### 4.1 Role Definitions
```yaml
roles:
  root:
    permissions: 15  # H+S+E+D
    description: "Full cryptographic authority"
    use_case: "Break-glass emergency access"
    
  admin:
    permissions: 14  # H+S+E
    description: "Administrative operations without data access"
    use_case: "Key management, policy enforcement"
    
  signer:
    permissions: 12  # H+S
    description: "Sign and verify only"
    use_case: "CI/CD, code signing, attestation"
    
  vault:
    permissions: 3   # E+D
    description: "Encrypt and decrypt only"
    use_case: "Secrets management, credential storage"
    
  audit:
    permissions: 9   # H+D
    description: "Verify and read only"
    use_case: "Compliance, forensics, audit trail"
    
  encryptor:
    permissions: 10  # H+E
    description: "Hash and encrypt only"
    use_case: "Data ingestion, DMZ boundary"
    
  decryptor:
    permissions: 9   # H+D
    description: "Hash and decrypt only"
    use_case: "Data consumers, internal services"
    
  verifier:
    permissions: 8   # H
    description: "Verify signatures only"
    use_case: "Signature verification, integrity checks"
```

### 4.2 Role Selection Guidelines

**Choose `root` (15) when:**
- Emergency break-glass access required
- Temporary debugging (time-limited)
- Key ceremony operations

**Choose `admin` (14) when:**
- Managing key lifecycle
- Enforcing policies
- No data access needed

**Choose `signer` (12) when:**
- CI/CD pipelines
- Code signing systems
- Certificate authorities (signing operations)

**Choose `vault` (3) when:**
- Secrets management systems
- Credential vaults
- Symmetric encryption systems

**Choose `audit` (9) when:**
- Compliance verification
- Forensic analysis
- Audit trail validation

**Choose `encryptor` (10) when:**
- Data ingestion boundaries
- DMZ/perimeter systems
- One-way data flows

**Choose `verifier` (8) when:**
- Pure verification (no signing)
- Integrity checking
- Read-only audit

---

## 5. Permission Enforcement

### 5.1 Runtime Enforcement

Implementations MUST enforce permissions at runtime:
```python
def enforce(operation: Operation, granted: int) -> bool:
    """
    Returns True if operation is permitted by granted permissions.
    
    Args:
        operation: One of HASH, SIGN, ENCRYPT, DECRYPT
        granted: Octal permission value (0-15)
    
    Returns:
        True if operation permitted, False otherwise
    """
    return bool(granted & operation.value)
```

### 5.2 Policy Validation

Implementations SHOULD validate policies before deployment:

1. **No redundant permissions**: Warn if role grants unnecessary permissions
2. **Separation concerns**: Flag if single role violates separation of duties
3. **Privilege creep**: Detect if permissions exceed documented use case
4. **Audit compliance**: Verify audit roles cannot modify data

### 5.3 Audit Logging

All HSED operations MUST be logged with:
```json
{
  "timestamp": "2024-12-29T10:30:00Z",
  "principal": "service-account@example.com",
  "role": "signer",
  "permissions": 12,
  "operation": "sign",
  "resource": "arn:aws:kms:us-east-1:123456789012:key/xxx",
  "outcome": "success",
  "metadata": {
    "algorithm": "ECDSA_SHA_256",
    "message_digest": "sha256:abc123..."
  }
}
```

---

## 6. Cloud Provider Integration

### 6.1 General Mapping Principles

HSED roles map to cloud provider IAM policies following these principles:

1. **Minimal API surface**: Only grant APIs required for HSED operations
2. **Explicit deny**: Use explicit deny for operations outside permission set
3. **Conditional policies**: Use conditions to enforce context (time, IP, MFA)
4. **Audit trail**: Ensure all operations generate audit logs

### 6.2 AWS KMS Mapping
```yaml
HSED_to_AWS_KMS:
  Hash (8):
    - kms:Verify
    - kms:DescribeKey (metadata only)
    
  Sign (4):
    - kms:Sign
    - kms:GetPublicKey
    
  Encrypt (2):
    - kms:Encrypt
    - kms:GenerateDataKey
    - kms:GenerateDataKeyWithoutPlaintext
    
  Decrypt (1):
    - kms:Decrypt
```

Example policy for `hsed:signer` (12 = H+S):
```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Effect": "Allow",
      "Action": [
        "kms:Sign",
        "kms:Verify",
        "kms:GetPublicKey",
        "kms:DescribeKey"
      ],
      "Resource": "arn:aws:kms:*:*:key/*",
      "Condition": {
        "StringEquals": {
          "kms:KeyUsage": "SIGN_VERIFY"
        }
      }
    },
    {
      "Effect": "Deny",
      "Action": [
        "kms:Encrypt",
        "kms:Decrypt",
        "kms:GenerateDataKey"
      ],
      "Resource": "*"
    }
  ]
}
```

### 6.3 HashiCorp Vault Mapping
```hcl
# hsed:signer (12 = H+S)
path "transit/sign/*" {
  capabilities = ["create", "update"]
}

path "transit/verify/*" {
  capabilities = ["create", "update"]
}

path "transit/keys/*" {
  capabilities = ["read"]
}

# Explicit deny for encrypt/decrypt
path "transit/encrypt/*" {
  capabilities = ["deny"]
}

path "transit/decrypt/*" {
  capabilities = ["deny"]
}
```

### 6.4 Azure Key Vault Mapping
```yaml
HSED_to_Azure_KeyVault:
  Hash (8):
    - Microsoft.KeyVault/vaults/keys/verify/action
    - Microsoft.KeyVault/vaults/keys/read
    
  Sign (4):
    - Microsoft.KeyVault/vaults/keys/sign/action
    
  Encrypt (2):
    - Microsoft.KeyVault/vaults/keys/encrypt/action
    
  Decrypt (1):
    - Microsoft.KeyVault/vaults/keys/decrypt/action
```

### 6.5 GCP Cloud KMS Mapping
```yaml
HSED_to_GCP_KMS:
  Hash (8):
    - cloudkms.cryptoKeyVersions.useToVerify
    - cloudkms.cryptoKeys.get
    
  Sign (4):
    - cloudkms.cryptoKeyVersions.useToSign
    
  Encrypt (2):
    - cloudkms.cryptoKeyVersions.useToEncrypt
    
  Decrypt (1):
    - cloudkms.cryptoKeyVersions.useToDecrypt
```

---

## 7. Security Considerations

### 7.1 Threat Model

**Threats mitigated:**
1. **Over-privileged principals**: HSED enforces least privilege by design
2. **Lateral movement**: Limited permissions prevent escalation
3. **Data exfiltration**: Separation of encrypt/decrypt prevents abuse
4. **Insider threats**: Audit roles cannot modify evidence

**Threats NOT mitigated:**
1. **Compromised credentials**: HSED does not replace MFA/authentication
2. **Side-channel attacks**: HSED is permission model, not crypto implementation
3. **Social engineering**: Human factors remain outside scope

### 7.2 Separation of Duties Patterns

**Financial systems:**
```
Initiator:  hsed 10 (H+E)    # Can seal request
Approver:   hsed 13 (H+S+D)  # Can verify, sign, decrypt
Executor:   hsed 9  (H+D)    # Can verify signature, decrypt
```

**Code release pipeline:**
```
Builder:    hsed 10 (H+E)    # Can seal artifacts
Signer:     hsed 12 (H+S)    # Can sign releases
Verifier:   hsed 8  (H)      # Can verify signatures
```

### 7.3 Key Rotation

When rotating keys:

1. **Create new key** with same HSED permissions
2. **Grant dual access** (old + new) during transition
3. **Re-encrypt data** with new key
4. **Revoke old key** after validation
5. **Audit access** to both keys during rotation

### 7.4 Emergency Access

For break-glass scenarios:
```yaml
emergency_access:
  role: root
  permissions: 15  # H+S+E+D
  conditions:
    - MFA required
    - Time-limited (4 hours max)
    - Requires approval (2-person rule)
    - Full audit trail
    - Automatic revocation
```

---

## 8. Compliance Mapping

### 8.1 SOC 2

HSED addresses:
- **CC6.1**: Logical access controls → Least privilege enforcement
- **CC6.2**: Access management → Role-based permissions
- **CC6.3**: System operations → Audit logging
- **CC6.6**: Logical access removal → Time-limited emergency access

### 8.2 ISO 27001

HSED addresses:
- **A.9.1.2**: Access to systems → Permission model
- **A.9.2.3**: Privileged access management → Separation of duties
- **A.9.4.1**: Access restriction → Least privilege
- **A.10.1.1**: Cryptographic controls → Key access management

### 8.3 PCI-DSS

HSED addresses:
- **Requirement 7**: Restrict access to cardholder data → Decrypt permissions
- **Requirement 8**: Assign unique ID → Role-based model
- **Requirement 10**: Track access to network resources → Audit logging

---

## 9. Implementation Guidelines

### 9.1 Minimum Requirements

Conforming implementations MUST:

1. Support all four permission bits (H, S, E, D)
2. Enforce permissions at runtime
3. Provide audit logging
4. Support standard roles (root, admin, signer, vault, audit)
5. Validate policies before enforcement
6. Support at least one cloud provider integration

### 9.2 Recommended Features

Implementations SHOULD:

1. Support custom role definitions
2. Provide policy conversion tools
3. Generate compliance reports
4. Detect privilege escalation attempts
5. Support time-based access controls
6. Integrate with SIEM systems

### 9.3 Optional Extensions

Implementations MAY:

1. Support dynamic permission elevation
2. Implement context-aware policies
3. Provide risk scoring for permission combinations
4. Support multi-cloud policy generation
5. Offer graphical policy editors

---

## 10. References

### 10.1 Normative References

- [RFC 2119]: Key words for use in RFCs to Indicate Requirement Levels
- [NIST SP 800-57]: Recommendation for Key Management
- [NIST SP 800-130]: Framework for Designing Cryptographic Key Management Systems

### 10.2 Informative References

- Unix file permissions (chmod)
- AWS KMS documentation
- HashiCorp Vault documentation
- Azure Key Vault documentation
- GCP Cloud KMS documentation

---

## 11. Changelog

### Version 1.0.0-draft (2024-12-29)

- Initial specification
- Core permission model (H, S, E, D)
- Standard roles
- Cloud provider mappings
- Security considerations

---

## Appendix A: Permission Matrix

Complete permission matrix (0-15):

| Octal | Binary | Permissions | Common Name | Typical Use Case |
|-------|--------|-------------|-------------|------------------|
| 0     | 0000   | None        | -           | Revoked access   |
| 1     | 0001   | D           | decryptor   | Read-only secrets |
| 2     | 0010   | E           | encryptor   | Write-only secrets |
| 3     | 0011   | E+D         | vault       | Secrets management |
| 4     | 0100   | S           | signer-only | Attestation only |
| 5     | 0101   | S+D         | -           | Uncommon combination |
| 6     | 0110   | S+E         | sealer      | Blind signing |
| 7     | 0111   | S+E+D       | -           | Avoid (no verification) |
| 8     | 1000   | H           | verifier    | Signature verification |
| 9     | 1001   | H+D         | audit       | Compliance, forensics |
| 10    | 1010   | H+E         | dmz         | Ingress boundary |
| 11    | 1011   | H+E+D       | reader      | Internal services |
| 12    | 1100   | H+S         | signer      | CI/CD, code signing |
| 13    | 1101   | H+S+D       | operator    | Service operations |
| 14    | 1110   | H+S+E       | admin       | Key management |
| 15    | 1111   | H+S+E+D     | root        | Full authority |

---

## Appendix B: Example Policies

### B.1 Multi-Tier Web Application
```yaml
# Frontend (DMZ)
frontend:
  role: dmz
  permissions: 10  # H+E
  resources:
    - ingress-encryption-key
  
# Application (Internal)
application:
  role: operator
  permissions: 13  # H+S+D
  resources:
    - app-signing-key
    - app-encryption-key
  
# Database (Backend)
database:
  role: vault
  permissions: 3  # E+D
  resources:
    - db-encryption-key
  
# Audit (Monitoring)
audit:
  role: audit
  permissions: 9  # H+D
  resources:
    - all-keys
```

### B.2 CI/CD Pipeline
```yaml
# Build stage
builder:
  role: encryptor
  permissions: 10  # H+E
  operations:
    - hash-artifacts
    - seal-secrets
  
# Sign stage  
signer:
  role: signer
  permissions: 12  # H+S
  operations:
    - verify-artifacts
    - sign-release
  
# Deploy stage
deployer:
  role: operator
  permissions: 13  # H+S+D
  operations:
    - verify-signature
    - decrypt-secrets
    - attest-deployment
```

---

**End of Specification**
