variable "aws_region" {
  description = "AWS region containing the target non-production environment."
  type        = string
  default     = "us-east-1"
}

variable "aws_account_id" {
  description = "Account guardrail. Terraform stops if the active identity is not this account."
  type        = string

  validation {
    condition     = can(regex("^[0-9]{12}$", var.aws_account_id))
    error_message = "aws_account_id must be a 12-digit AWS account ID."
  }
}

variable "environment" {
  description = "Non-production deployment environment."
  type        = string

  validation {
    condition     = contains(["dev-sandbox", "staging"], var.environment)
    error_message = "environment must be dev-sandbox or staging."
  }
}

variable "github_repository" {
  description = "Exact GitHub owner/repository permitted to assume the environment deployment role."
  type        = string
  default     = "aceofcloud/AC3-Plus"
}

variable "github_environment_name" {
  description = "GitHub Environment that supplies the OIDC subject claim for this environment."
  type        = string
}

variable "github_oidc_provider_arn" {
  description = "Pre-existing account-level GitHub Actions OIDC provider ARN. This module never takes ownership of the global provider."
  type        = string
}

variable "state_bucket_name" {
  description = "Dedicated S3 bucket holding only this environment's Terraform state."
  type        = string
}

variable "ecs_cluster_name" {
  description = "Existing ECS cluster to host the isolated AC3-Plus platform sandbox."
  type        = string
}

variable "vpc_id" {
  description = "Existing VPC ID for the selected environment."
  type        = string
}

variable "private_subnet_ids" {
  description = "Subnets for the sandbox ECS service. They are never changed by this module."
  type        = list(string)

  validation {
    condition     = length(var.private_subnet_ids) > 0
    error_message = "At least one ECS subnet is required."
  }
}

variable "assign_public_ip" {
  description = "Match the existing environment's ECS networking posture. Dev sandbox is private; staging currently requires a public IP for its existing routing design."
  type        = bool
  default     = false
}

variable "alb_security_group_id" {
  description = "Existing ALB security group allowed to reach the sandbox task."
  type        = string
}

variable "https_listener_arn" {
  description = "Existing HTTPS ALB listener that receives an isolated host-header rule."
  type        = string
}

variable "listener_rule_priority" {
  description = "Unused priority on the existing HTTPS listener."
  type        = number

  validation {
    condition     = var.listener_rule_priority >= 1 && var.listener_rule_priority <= 50000
    error_message = "listener_rule_priority must be between 1 and 50000."
  }
}

variable "host_names" {
  description = "Dedicated hostnames routed only to the AC3-Plus sandbox. DNS is intentionally managed outside this module."
  type        = list(string)

  validation {
    condition     = length(var.host_names) > 0 && alltrue([for name in var.host_names : can(regex("^[A-Za-z0-9.-]+$", name))])
    error_message = "host_names must contain at least one valid hostname."
  }
}

variable "reference_service_name" {
  description = "Protected reference service name. The module refuses to use this name for the sandbox."
  type        = string
  default     = "ac3-dev-app"
}

variable "container_port" {
  description = "Platform container port."
  type        = number
  default     = 8080
}

variable "health_check_path" {
  description = "Application health endpoint used by ECS and the ALB target group."
  type        = string
  default     = "/api/health"
}

variable "task_cpu" {
  description = "Fargate task CPU units."
  type        = number
  default     = 2048
}

variable "task_memory" {
  description = "Fargate task memory in MiB."
  type        = number
  default     = 4096
}

variable "desired_count" {
  description = "Desired sandbox task count once deploy_service is enabled."
  type        = number
  default     = 1
}

variable "image_uri" {
  description = "Immutable ECR image URI to deploy. Use a commit-addressed tag or digest; never latest."
  type        = string
  default     = "placeholder.invalid/ac3-plus-platform:bootstrap"

  validation {
    condition     = !var.deploy_service || (can(regex("@sha256:[a-f0-9]{64}$", var.image_uri)) || can(regex(":sha-[0-9a-f]{7,64}$", var.image_uri)))
    error_message = "A service deploy requires an immutable digest or a sha-<commit> image tag."
  }
}

variable "deploy_service" {
  description = "False creates only safe prerequisites. True registers the sandbox task definition and service."
  type        = bool
  default     = false
}

variable "app_secrets" {
  description = "Map of environment variable names to pre-existing Secrets Manager ARNs. Secret values never enter Terraform state or GitHub Actions."
  type        = map(string)
  default     = {}

  sensitive = true
}

variable "task_role_policy_json" {
  description = "Optional least-privilege runtime policy JSON for non-secret integrations."
  type        = string
  default     = ""
  sensitive   = true
}

variable "log_retention_days" {
  description = "CloudWatch log retention period."
  type        = number
  default     = 30
}

variable "tags" {
  description = "Additional tags for sandbox-owned resources."
  type        = map(string)
  default     = {}
}
