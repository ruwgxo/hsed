# templates/aws-kms/outputs.tf

output "key_arn" {
  description = "ARN of the HSED-governed KMS key"
  value       = aws_kms_key.hsed.arn
}

output "key_id" {
  description = "ID of the HSED-governed KMS key"
  value       = aws_kms_key.hsed.key_id
}

output "key_alias" {
  description = "Alias ARN of the KMS key"
  value       = aws_kms_alias.hsed.arn
}

output "signer_policy_arn" {
  description = "ARN of the HSED signer IAM policy (if created)"
  value       = length(aws_iam_policy.hsed_signer) > 0 ? aws_iam_policy.hsed_signer[0].arn : null
}

output "vault_policy_arn" {
  description = "ARN of the HSED vault IAM policy (if created)"
  value       = length(aws_iam_policy.hsed_vault) > 0 ? aws_iam_policy.hsed_vault[0].arn : null
}

output "hsed_generate_command" {
  description = "Command to regenerate the signer KMS policy from your .hsed file"
  value       = "hsed generate aws-kms --policy <your>.hsed --role signer --key-arn ${aws_kms_key.hsed.arn}"
}

output "hsed_live_audit_command" {
  description = "Command to live-audit the signer role against this key"
  value       = "hsed live-audit aws-kms --policy <your>.hsed --role signer --key-arn ${aws_kms_key.hsed.arn}"
}

