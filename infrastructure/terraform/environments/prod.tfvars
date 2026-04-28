# ─────────────────────────────────────────────────────────────────────────────
# AC3 — Production Environment (FedRAMP High)
# ─────────────────────────────────────────────────────────────────────────────

environment  = "prod"
project_name = "ac3"
aws_region   = "us-east-1"

# Networking
vpc_cidr              = "10.30.0.0/16"
availability_zones    = ["us-east-1a", "us-east-1b", "us-east-1c"]
public_subnet_cidrs   = ["10.30.1.0/24", "10.30.2.0/24", "10.30.3.0/24"]
private_subnet_cidrs  = ["10.30.11.0/24", "10.30.12.0/24", "10.30.13.0/24"]
database_subnet_cidrs = ["10.30.21.0/24", "10.30.22.0/24", "10.30.23.0/24"]
enable_waf            = true

# Domain (update with your production domain)
# domain_name     = "ac3.aceofcloud.com"
# certificate_arn = "arn:aws:acm:us-east-1:ACCOUNT_ID:certificate/CERT_ID"

# Database (production — HA, encryption, long retention)
db_min_capacity        = 1
db_max_capacity        = 8
db_deletion_protection = true
db_backup_retention_days = 35

# ECS (production — HA, auto-scaling)
ecs_cpu           = 1024
ecs_memory        = 2048
ecs_desired_count = 2
ecs_min_count     = 2
ecs_max_count     = 8

# Security (ALL FedRAMP controls enabled)
enable_guardduty    = true
enable_security_hub = true
enable_cloudtrail   = true
enable_aws_config   = true
