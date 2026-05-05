# ─────────────────────────────────────────────────────────────────────────────
# AC3 — Production Environment (FedRAMP High)
#
# Full FedRAMP controls, HA, encryption at rest, long retention.
# Uses the same cross-account ECR (SharedServices: 890319879326).
#
# Deploy:
#   cd infrastructure/terraform
#   terraform init -backend-config=environments/backend-prod.hcl
#   terraform plan  -var-file=environments/prod.tfvars
#   terraform apply -var-file=environments/prod.tfvars
# ─────────────────────────────────────────────────────────────────────────────

environment  = "prod"
project_name = "ac3"
aws_region   = "us-east-1"

# ── Networking ───────────────────────────────────────────────────────────────
vpc_cidr              = "10.30.0.0/16"
availability_zones    = ["us-east-1a", "us-east-1b", "us-east-1c"]
public_subnet_cidrs   = ["10.30.1.0/24", "10.30.2.0/24", "10.30.3.0/24"]
private_subnet_cidrs  = ["10.30.11.0/24", "10.30.12.0/24", "10.30.13.0/24"]
database_subnet_cidrs = ["10.30.21.0/24", "10.30.22.0/24", "10.30.23.0/24"]
enable_waf            = true

# Domain — production uses aceofcloud.io
domain_name     = "aceofcloud.io"
certificate_arn = ""  # Will be populated after ACM cert is created (see DNS module)

# ── Database (production — HA, encryption, long retention) ───────────────────
db_min_capacity        = 1
db_max_capacity        = 8
db_deletion_protection = true
db_backup_retention_days = 35

# ── Cross-Account ECR (SharedServices: 890319879326) ────────────────────────
ecr_account_id      = "890319879326"
ecr_repository_name = "ace-c3/caldera-dashboard"
ecr_kms_key_arn     = "arn:aws:kms:us-east-1:890319879326:key/8e215533-9e88-4cae-b514-93a892e6e6c8"

# ── Pre-existing IAM Roles (Prod account) ───────────────────────────────────
# TODO: Replace with actual production account role ARNs once provisioned:
#   external_execution_role_arn = "arn:aws:iam::<PROD_ACCOUNT_ID>:role/ac3-prod-ecs-execution-role"
#   external_task_role_arn      = "arn:aws:iam::<PROD_ACCOUNT_ID>:role/ac3-prod-app-task-role"
external_execution_role_arn = ""
external_task_role_arn      = ""

# ── ECS (production — HA, auto-scaling) ──────────────────────────────────────
ecs_cpu           = 1024
ecs_memory        = 2048
ecs_desired_count = 2
ecs_min_count     = 2
ecs_max_count     = 8

# ── Security (ALL FedRAMP controls enabled) ──────────────────────────────────
enable_guardduty    = true
enable_security_hub = true
enable_cloudtrail   = true
enable_aws_config   = true
