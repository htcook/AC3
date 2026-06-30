# ─────────────────────────────────────────────────────────────────────────────
# AC3 Platform — Terraform Variables
# Author: Harrison Cook — AceofCloud (https://aceofcloud.com)
# ─────────────────────────────────────────────────────────────────────────────

# ─── General ─────────────────────────────────────────────────────────────────
variable "environment" {
  description = "Deployment environment (dev, staging, prod)"
  type        = string
  validation {
    condition     = contains(["dev", "staging", "prod"], var.environment)
    error_message = "Environment must be one of: dev, staging, prod."
  }
}

variable "project_name" {
  description = "Project identifier used in resource naming"
  type        = string
  default     = "ac3"
}

variable "aws_region" {
  description = "AWS region for deployment"
  type        = string
  default     = "us-east-1"
}

# ─── Networking ──────────────────────────────────────────────────────────────
variable "vpc_cidr" {
  description = "CIDR block for the VPC"
  type        = string
  default     = "10.0.0.0/16"
}

variable "availability_zones" {
  description = "List of AZs (minimum 2 for HA)"
  type        = list(string)
  default     = ["us-east-1a", "us-east-1b", "us-east-1c"]
}

variable "public_subnet_cidrs" {
  description = "CIDR blocks for public subnets (ALB)"
  type        = list(string)
  default     = ["10.0.1.0/24", "10.0.2.0/24", "10.0.3.0/24"]
}

variable "private_subnet_cidrs" {
  description = "CIDR blocks for private subnets (ECS tasks)"
  type        = list(string)
  default     = ["10.0.11.0/24", "10.0.12.0/24", "10.0.13.0/24"]
}

variable "database_subnet_cidrs" {
  description = "CIDR blocks for isolated database subnets"
  type        = list(string)
  default     = ["10.0.21.0/24", "10.0.22.0/24", "10.0.23.0/24"]
}

variable "domain_name" {
  description = "Domain name for the application (used for ALB + ACM)"
  type        = string
  default     = ""
}

variable "certificate_arn" {
  description = "ARN of the ACM certificate for HTTPS (leave empty to create new)"
  type        = string
  default     = ""
}

variable "enable_waf" {
  description = "Enable AWS WAF on the ALB"
  type        = bool
  default     = true
}

# ─── Database ────────────────────────────────────────────────────────────────
variable "db_master_username" {
  description = "Master username for Aurora cluster"
  type        = string
  default     = "ac3admin"
}

variable "db_min_capacity" {
  description = "Aurora Serverless v2 minimum ACU"
  type        = number
  default     = 0.5
}

variable "db_max_capacity" {
  description = "Aurora Serverless v2 maximum ACU"
  type        = number
  default     = 4
}

variable "db_deletion_protection" {
  description = "Enable deletion protection on the database"
  type        = bool
  default     = false
}

variable "db_backup_retention_days" {
  description = "Number of days to retain automated backups"
  type        = number
  default     = 7
}

# ─── Cross-Account ECR (SharedServices) ───────────────────────────────────────
variable "ecr_account_id" {
  description = "AWS account ID where ECR lives (SharedServices). Leave empty to use local ECR."
  type        = string
  default     = ""
}

variable "ecr_repository_name" {
  description = "Cross-account ECR repository name (e.g., ace-c3/caldera-dashboard). Leave empty to use local ECR."
  type        = string
  default     = ""
}

variable "ecr_kms_key_arn" {
  description = "KMS key ARN used for ECR encryption in SharedServices account"
  type        = string
  default     = ""
}

# ─── Pre-Existing IAM Roles (optional, for admin-managed environments) ───────
variable "external_execution_role_arn" {
  description = "Pre-existing ECS execution role ARN. If set (with external_task_role_arn), skips role creation."
  type        = string
  default     = ""
}

variable "external_task_role_arn" {
  description = "Pre-existing ECS task role ARN. If set (with external_execution_role_arn), skips role creation."
  type        = string
  default     = ""
}

# ─── ECS / Fargate ──────────────────────────────────────────────────────────
variable "image_tag" {
  description = "Docker image tag to deploy"
  type        = string
  default     = "latest"
}

variable "container_port" {
  description = "Port the application listens on inside the container"
  type        = number
  default     = 8080
}

variable "ecs_cpu" {
  description = "CPU units for the Fargate task (1024 = 1 vCPU)"
  type        = number
  default     = 1024
}

variable "ecs_memory" {
  description = "Memory (MiB) for the Fargate task"
  type        = number
  default     = 2048
}

variable "ecs_desired_count" {
  description = "Desired number of ECS tasks"
  type        = number
  default     = 2
}

variable "ecs_min_count" {
  description = "Minimum number of ECS tasks for auto-scaling"
  type        = number
  default     = 1
}

variable "ecs_max_count" {
  description = "Maximum number of ECS tasks for auto-scaling"
  type        = number
  default     = 4
}

# ─── Security ────────────────────────────────────────────────────────────────
variable "enable_guardduty" {
  description = "Enable Amazon GuardDuty threat detection"
  type        = bool
  default     = true
}

variable "enable_security_hub" {
  description = "Enable AWS Security Hub"
  type        = bool
  default     = true
}

variable "enable_cloudtrail" {
  description = "Enable AWS CloudTrail audit logging"
  type        = bool
  default     = true
}

variable "enable_aws_config" {
  description = "Enable AWS Config compliance monitoring"
  type        = bool
  default     = true
}

# ─── Monitoring ──────────────────────────────────────────────────────────────
variable "alarm_sns_topic_arn" {
  description = "SNS topic ARN for CloudWatch alarm notifications"
  type        = string
  default     = ""
}
