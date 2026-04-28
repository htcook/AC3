# ─────────────────────────────────────────────────────────────────────────────
# AC3 Platform — AWS Infrastructure (FedRAMP High Baseline)
# Author: Harrison Cook — AceofCloud (https://aceofcloud.com)
# ─────────────────────────────────────────────────────────────────────────────
# This root module composes all child modules into a complete deployment.
# Each environment (dev/staging/prod) passes its own .tfvars file.
# ─────────────────────────────────────────────────────────────────────────────

terraform {
  required_version = ">= 1.7.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }

  # Remote state in S3 with DynamoDB locking — configured per environment
  backend "s3" {}
}

# ─── Provider ────────────────────────────────────────────────────────────────
provider "aws" {
  region = var.aws_region

  default_tags {
    tags = {
      Project     = "ac3"
      Environment = var.environment
      ManagedBy   = "terraform"
      Owner       = "harrison.cook@aceofcloud.com"
      Compliance  = "fedramp-high"
    }
  }
}

# ─── Data Sources ────────────────────────────────────────────────────────────
data "aws_caller_identity" "current" {}
data "aws_region" "current" {}

# ─── Networking ──────────────────────────────────────────────────────────────
module "networking" {
  source = "./modules/networking"

  environment         = var.environment
  project_name        = var.project_name
  vpc_cidr            = var.vpc_cidr
  availability_zones  = var.availability_zones
  public_subnet_cidrs = var.public_subnet_cidrs
  private_subnet_cidrs = var.private_subnet_cidrs
  database_subnet_cidrs = var.database_subnet_cidrs
  domain_name         = var.domain_name
  certificate_arn     = var.certificate_arn
  enable_waf          = var.enable_waf
}

# ─── ECR (Container Registry) ───────────────────────────────────────────────
module "ecr" {
  source = "./modules/ecr"

  environment  = var.environment
  project_name = var.project_name
}

# ─── Database (Aurora MySQL Serverless v2) ───────────────────────────────────
module "database" {
  source = "./modules/database"

  environment           = var.environment
  project_name          = var.project_name
  vpc_id                = module.networking.vpc_id
  database_subnet_ids   = module.networking.database_subnet_ids
  ecs_security_group_id = module.ecs.ecs_security_group_id
  db_master_username    = var.db_master_username
  db_min_capacity       = var.db_min_capacity
  db_max_capacity       = var.db_max_capacity
  deletion_protection   = var.environment == "prod" ? true : var.db_deletion_protection
  backup_retention_days = var.environment == "prod" ? 35 : var.db_backup_retention_days
  kms_key_arn           = module.security.kms_key_arn
}

# ─── Secrets Manager ────────────────────────────────────────────────────────
module "secrets" {
  source = "./modules/secrets"

  environment  = var.environment
  project_name = var.project_name
  kms_key_arn  = module.security.kms_key_arn

  # Database connection string is auto-generated from Aurora outputs
  database_endpoint = module.database.cluster_endpoint
  database_port     = module.database.cluster_port
  database_name     = module.database.database_name
  database_secret_arn = module.database.master_secret_arn
}

# ─── ECS Fargate ─────────────────────────────────────────────────────────────
module "ecs" {
  source = "./modules/ecs"

  environment         = var.environment
  project_name        = var.project_name
  aws_region          = var.aws_region
  vpc_id              = module.networking.vpc_id
  private_subnet_ids  = module.networking.private_subnet_ids
  target_group_arn    = module.networking.target_group_arn
  ecr_repository_url  = module.ecr.repository_url
  image_tag           = var.image_tag
  container_port      = var.container_port
  cpu                 = var.ecs_cpu
  memory              = var.ecs_memory
  desired_count       = var.ecs_desired_count
  min_count           = var.ecs_min_count
  max_count           = var.ecs_max_count
  secrets_arn_prefix  = module.secrets.secrets_arn_prefix
  kms_key_arn         = module.security.kms_key_arn
  log_group_name      = module.monitoring.log_group_name
  enable_execute_command = var.environment != "prod"

  app_secrets = module.secrets.app_secret_arns
}

# ─── Security (GuardDuty, Security Hub, CloudTrail, Config, KMS) ────────────
module "security" {
  source = "./modules/security"

  environment    = var.environment
  project_name   = var.project_name
  aws_region     = var.aws_region
  account_id     = data.aws_caller_identity.current.account_id
  enable_guardduty    = var.enable_guardduty
  enable_security_hub = var.enable_security_hub
  enable_cloudtrail   = var.enable_cloudtrail
  enable_aws_config   = var.enable_aws_config
}

# ─── Monitoring (CloudWatch, Alarms, Dashboard) ─────────────────────────────
module "monitoring" {
  source = "./modules/monitoring"

  environment       = var.environment
  project_name      = var.project_name
  aws_region        = var.aws_region
  ecs_cluster_name  = module.ecs.cluster_name
  ecs_service_name  = module.ecs.service_name
  alb_arn_suffix    = module.networking.alb_arn_suffix
  target_group_arn_suffix = module.networking.target_group_arn_suffix
  db_cluster_id     = module.database.cluster_identifier
  alarm_sns_topic_arn = var.alarm_sns_topic_arn
}

# ─── OIDC (GitHub Actions → AWS Federation) ─────────────────────────────────
module "oidc" {
  source = "./modules/oidc"

  environment            = var.environment
  project_name           = var.project_name
  github_repo            = "hcook-aoc/AC3"
  ecr_repository_arn     = module.ecr.repository_arn
  task_execution_role_arn = module.ecs.task_execution_role_arn
  task_role_arn          = module.ecs.task_role_arn
}
