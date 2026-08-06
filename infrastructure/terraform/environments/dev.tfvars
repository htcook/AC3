# ─────────────────────────────────────────────────────────────────────────────
# AC3 — Development Environment
# ─────────────────────────────────────────────────────────────────────────────

environment  = "dev"
project_name = "ac3"
aws_region   = "us-east-1"

# Networking
vpc_cidr              = "10.10.0.0/16"
availability_zones    = ["us-east-1a", "us-east-1b"]
public_subnet_cidrs   = ["10.10.1.0/24", "10.10.2.0/24"]
private_subnet_cidrs  = ["10.10.11.0/24", "10.10.12.0/24"]
database_subnet_cidrs = ["10.10.21.0/24", "10.10.22.0/24"]
enable_waf            = false

# Database (minimal for dev)
db_min_capacity       = 0.5
db_max_capacity       = 2
db_deletion_protection = false
db_backup_retention_days = 1

# Cross-Account ECR (SharedServices: 890319879326)
ecr_account_id      = "890319879326"
ecr_repository_name = "ace-c3/caldera-dashboard"
ecr_kms_key_arn     = "arn:aws:kms:us-east-1:890319879326:key/8e215533-9e88-4cae-b514-93a892e6e6c8"

# Pre-existing IAM Roles (Dev account: 808038814732)
external_execution_role_arn = "arn:aws:iam::808038814732:role/ac3-dev-ecs-execution-role"
external_task_role_arn      = "arn:aws:iam::808038814732:role/ac3-dev-app-task-role"

# ECS (small for dev)
ecs_cpu           = 512
ecs_memory        = 1024
ecs_desired_count = 1
ecs_min_count     = 1
ecs_max_count     = 2

# Security (reduced for dev — save cost)
enable_guardduty    = false
enable_security_hub = false
enable_cloudtrail   = true
enable_aws_config   = false
