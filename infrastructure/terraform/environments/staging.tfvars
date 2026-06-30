# ─────────────────────────────────────────────────────────────────────────────
# AC3 — Staging Environment
#
# Mirrors production sizing and security controls for pre-release validation.
# Uses the same cross-account ECR (SharedServices: 890319879326) and
# pre-existing IAM roles in the Staging account.
#
# Deploy:
#   cd infrastructure/terraform
#   terraform init -backend-config=environments/backend-staging.hcl
#   terraform plan  -var-file=environments/staging.tfvars
#   terraform apply -var-file=environments/staging.tfvars
# ─────────────────────────────────────────────────────────────────────────────

environment  = "staging"
project_name = "ac3"
aws_region   = "us-east-1"

# ── Networking ───────────────────────────────────────────────────────────────
# Staging uses 10.20.0.0/16 (dev=10.10, staging=10.20, prod=10.30)
# Three AZs for HA validation before prod promotion
vpc_cidr              = "10.20.0.0/16"
availability_zones    = ["us-east-1a", "us-east-1b", "us-east-1c"]
public_subnet_cidrs   = ["10.20.1.0/24", "10.20.2.0/24", "10.20.3.0/24"]
private_subnet_cidrs  = ["10.20.11.0/24", "10.20.12.0/24", "10.20.13.0/24"]
database_subnet_cidrs = ["10.20.21.0/24", "10.20.22.0/24", "10.20.23.0/24"]
enable_waf            = true

# ── Database (moderate — mirrors prod schema, smaller capacity) ──────────────
db_min_capacity        = 0.5
db_max_capacity        = 4
db_deletion_protection = false
db_backup_retention_days = 7

# ── Cross-Account ECR (SharedServices: 890319879326) ────────────────────────
# Same ECR repo as dev — images are promoted by tag (e.g., staging-v1.2.3)
ecr_account_id      = "890319879326"
ecr_repository_name = "ace-c3/caldera-dashboard"
ecr_kms_key_arn     = "arn:aws:kms:us-east-1:890319879326:key/8e215533-9e88-4cae-b514-93a892e6e6c8"

# ── Pre-existing IAM Roles (Staging account) ────────────────────────────────
# These roles were created by the platform team in the staging account.
# Update the account ID and role names when staging account roles are provisioned.
# Until then, Terraform will create its own roles (external_*_role_arn = "" → create).
#
# TODO: Replace with actual staging account role ARNs once provisioned:
#   external_execution_role_arn = "arn:aws:iam::<STAGING_ACCOUNT_ID>:role/ac3-staging-ecs-execution-role"
#   external_task_role_arn      = "arn:aws:iam::<STAGING_ACCOUNT_ID>:role/ac3-staging-app-task-role"
external_execution_role_arn = ""
external_task_role_arn      = ""

# ── ECS (mirrors prod sizing for realistic load testing) ─────────────────────
ecs_cpu           = 1024
ecs_memory        = 2048
ecs_desired_count = 2
ecs_min_count     = 1
ecs_max_count     = 4

# ── Security (full FedRAMP stack on staging for compliance validation) ───────
enable_guardduty    = true
enable_security_hub = true
enable_cloudtrail   = true
enable_aws_config   = true
