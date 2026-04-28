# ─────────────────────────────────────────────────────────────────────────────
# AC3 Platform — Terraform Outputs
# Author: Harrison Cook — AceofCloud (https://aceofcloud.com)
# ─────────────────────────────────────────────────────────────────────────────

output "vpc_id" {
  description = "VPC ID"
  value       = module.networking.vpc_id
}

output "alb_dns_name" {
  description = "ALB DNS name (use for CNAME/alias record)"
  value       = module.networking.alb_dns_name
}

output "alb_zone_id" {
  description = "ALB hosted zone ID (for Route 53 alias)"
  value       = module.networking.alb_zone_id
}

output "ecr_repository_url" {
  description = "ECR repository URL for pushing images"
  value       = module.ecr.repository_url
}

output "ecs_cluster_name" {
  description = "ECS cluster name"
  value       = module.ecs.cluster_name
}

output "ecs_service_name" {
  description = "ECS service name"
  value       = module.ecs.service_name
}

output "database_endpoint" {
  description = "Aurora cluster writer endpoint"
  value       = module.database.cluster_endpoint
  sensitive   = true
}

output "database_reader_endpoint" {
  description = "Aurora cluster reader endpoint"
  value       = module.database.reader_endpoint
  sensitive   = true
}

output "secrets_arn_prefix" {
  description = "Secrets Manager ARN prefix for this environment"
  value       = module.secrets.secrets_arn_prefix
}

output "cloudwatch_log_group" {
  description = "CloudWatch log group for ECS tasks"
  value       = module.monitoring.log_group_name
}

output "kms_key_arn" {
  description = "KMS key ARN used for encryption"
  value       = module.security.kms_key_arn
}
