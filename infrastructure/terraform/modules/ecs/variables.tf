variable "environment" { type = string }
variable "project_name" { type = string }
variable "aws_region" { type = string }
variable "vpc_id" { type = string }
variable "private_subnet_ids" { type = list(string) }
variable "target_group_arn" { type = string }
variable "ecr_repository_url" { type = string }
variable "image_tag" { type = string }
variable "container_port" { type = number }
variable "cpu" { type = number }
variable "memory" { type = number }
variable "desired_count" { type = number }
variable "min_count" { type = number }
variable "max_count" { type = number }
variable "secrets_arn_prefix" { type = string }
variable "kms_key_arn" { type = string }
variable "log_group_name" { type = string }
variable "enable_execute_command" { type = bool }
variable "app_secrets" {
  type        = map(string)
  description = "Map of env var name → Secrets Manager ARN"
}
