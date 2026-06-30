output "secrets_arn_prefix" {
  value = "arn:aws:secretsmanager:${data.aws_region.current.name}:${data.aws_caller_identity.current.account_id}:secret:${var.project_name}/${var.environment}/"
}

output "app_secret_arns" {
  description = "Map of env var name → Secrets Manager ARN"
  value       = { for k, v in aws_secretsmanager_secret.app : k => v.arn }
}

output "database_secret_arn" {
  value = var.database_secret_arn
}

data "aws_region" "current" {}
data "aws_caller_identity" "current" {}
