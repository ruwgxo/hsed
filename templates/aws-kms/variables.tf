# templates/aws-kms/variables.tf

variable "project" {
  type        = string
  description = "Project name used in resource naming and tagging"
}

variable "env" {
  type        = string
  description = "Environment (production, staging, dev)"
  default     = "production"
}

variable "aws_region" {
  type        = string
  description = "AWS region for the KMS key"
  default     = "us-east-1"
}

variable "aws_profile" {
  type        = string
  description = "AWS credentials profile"
  default     = null
}

variable "hsed_policy_name" {
  type        = string
  description = "HSED policy name (for tagging / audit trail)"
  default     = "default"
}

variable "key_spec" {
  type        = string
  description = "KMS key spec: RSA_2048, RSA_4096, ECC_NIST_P256, SYMMETRIC_DEFAULT, etc."
  default     = "RSA_2048"
}

variable "deletion_window_days" {
  type        = number
  description = "Pending deletion window in days (7–30)"
  default     = 30
}

# ── HSED role principals ────────────────────────────────────────────────────
# Provide IAM ARNs for each HSED role you want to activate.
# Empty list = that role's KMS statement is omitted entirely.

variable "signer_principal_arns" {
  type        = list(string)
  description = "IAM ARNs for hsed:signer (HS--/12) — CI/CD, code signing"
  default     = []
}

variable "vault_principal_arns" {
  type        = list(string)
  description = "IAM ARNs for hsed:vault (--ED/3) — secrets management"
  default     = []
}

variable "audit_principal_arns" {
  type        = list(string)
  description = "IAM ARNs for hsed:audit (H--D/9) — compliance, forensics"
  default     = []
}

variable "encryptor_principal_arns" {
  type        = list(string)
  description = "IAM ARNs for hsed:encryptor (H-E-/10) — data ingestion"
  default     = []
}

variable "tags" {
  type        = map(string)
  description = "Additional tags applied to all resources"
  default     = {}
}

