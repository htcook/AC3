variable "environment" { type = string }
variable "project_name" { type = string }
variable "github_repo" {
  type        = string
  description = "GitHub repo in format 'owner/repo'"
}
variable "ecr_repository_arn" { type = string }
variable "task_execution_role_arn" { type = string }
variable "task_role_arn" { type = string }
