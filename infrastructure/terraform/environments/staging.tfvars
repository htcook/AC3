# ─────────────────────────────────────────────────────────────────────────────
# AC3 — Staging Environment
# ─────────────────────────────────────────────────────────────────────────────

environment  = "staging"
project_name = "ac3"
aws_region   = "us-east-1"

# Networking
vpc_cidr              = "10.20.0.0/16"
availability_zones    = ["us-east-1a", "us-east-1b", "us-east-1c"]
public_subnet_cidrs   = ["10.20.1.0/24", "10.20.2.0/24", "10.20.3.0/24"]
private_subnet_cidrs  = ["10.20.11.0/24", "10.20.12.0/24", "10.20.13.0/24"]
database_subnet_cidrs = ["10.20.21.0/24", "10.20.22.0/24", "10.20.23.0/24"]
enable_waf            = true

# Database (moderate for staging)
db_min_capacity       = 0.5
db_max_capacity       = 4
db_deletion_protection = false
db_backup_retention_days = 7

# ECS (mirrors prod sizing)
ecs_cpu           = 1024
ecs_memory        = 2048
ecs_desired_count = 2
ecs_min_count     = 1
ecs_max_count     = 4

# Security (full FedRAMP stack on staging for validation)
enable_guardduty    = true
enable_security_hub = true
enable_cloudtrail   = true
enable_aws_config   = true
