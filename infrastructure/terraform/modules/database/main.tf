# ─────────────────────────────────────────────────────────────────────────────
# Database Module — Aurora MySQL Serverless v2
# FedRAMP High: KMS encryption at rest, TLS in transit, isolated subnets,
#               automated backups, audit logging, deletion protection
# ─────────────────────────────────────────────────────────────────────────────

# ─── DB Subnet Group ─────────────────────────────────────────────────────────
resource "aws_db_subnet_group" "aurora" {
  name       = "${var.project_name}-${var.environment}-aurora-subnet-group"
  subnet_ids = var.database_subnet_ids
  tags       = { Name = "${var.project_name}-${var.environment}-aurora-subnet-group" }
}

# ─── Security Group ─────────────────────────────────────────────────────────
resource "aws_security_group" "aurora" {
  name_prefix = "${var.project_name}-${var.environment}-aurora-"
  vpc_id      = var.vpc_id
  description = "Aurora MySQL — only ECS tasks can connect"

  ingress {
    description     = "MySQL from ECS"
    from_port       = 3306
    to_port         = 3306
    protocol        = "tcp"
    security_groups = [var.ecs_security_group_id]
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle { create_before_destroy = true }
  tags = { Name = "${var.project_name}-${var.environment}-aurora-sg" }
}

# ─── Master Password (Secrets Manager) ──────────────────────────────────────
resource "aws_secretsmanager_secret" "db_master" {
  name       = "${var.project_name}/${var.environment}/aurora-master"
  kms_key_id = var.kms_key_arn

  tags = { Name = "${var.project_name}-${var.environment}-aurora-master-secret" }
}

resource "aws_secretsmanager_secret_version" "db_master" {
  secret_id = aws_secretsmanager_secret.db_master.id
  secret_string = jsonencode({
    username = var.db_master_username
    password = random_password.master.result
  })
}

resource "random_password" "master" {
  length           = 32
  special          = true
  override_special = "!#$%^&*()-_=+[]{}|:,.<>?"
}

# ─── Parameter Group (FedRAMP: audit logging, TLS enforcement) ──────────────
resource "aws_rds_cluster_parameter_group" "aurora" {
  name        = "${var.project_name}-${var.environment}-aurora-params"
  family      = "aurora-mysql8.0"
  description = "AC3 Aurora MySQL parameters — FedRAMP High"

  # Enforce TLS for all connections
  parameter {
    name  = "require_secure_transport"
    value = "ON"
  }

  # Enable audit logging
  parameter {
    name  = "server_audit_logging"
    value = "1"
  }

  parameter {
    name  = "server_audit_events"
    value = "CONNECT,QUERY_DCL,QUERY_DDL,QUERY_DML"
  }

  # Performance tuning
  parameter {
    name  = "max_connections"
    value = "1000"
  }

  tags = { Name = "${var.project_name}-${var.environment}-aurora-params" }
}

# ─── Aurora Cluster ─────────────────────────────────────────────────────────
resource "aws_rds_cluster" "aurora" {
  cluster_identifier = "${var.project_name}-${var.environment}-aurora"
  engine             = "aurora-mysql"
  engine_mode        = "provisioned"
  engine_version     = "8.0.mysql_aurora.3.07.1"
  database_name      = "${var.project_name}_${var.environment}"

  master_username                     = var.db_master_username
  master_password                     = random_password.master.result
  manage_master_user_password         = false

  db_subnet_group_name                = aws_db_subnet_group.aurora.name
  vpc_security_group_ids              = [aws_security_group.aurora.id]
  db_cluster_parameter_group_name     = aws_rds_cluster_parameter_group.aurora.name

  # FedRAMP: Encryption at rest with CMK
  storage_encrypted = true
  kms_key_id        = var.kms_key_arn

  # Backups
  backup_retention_period = var.backup_retention_days
  preferred_backup_window = "03:00-04:00"

  # Maintenance
  preferred_maintenance_window = "sun:04:00-sun:05:00"

  # Protection
  deletion_protection = var.deletion_protection
  skip_final_snapshot = var.environment != "prod"
  final_snapshot_identifier = var.environment == "prod" ? "${var.project_name}-${var.environment}-final-${formatdate("YYYY-MM-DD", timestamp())}" : null

  # Logging
  enabled_cloudwatch_logs_exports = ["audit", "error", "slowquery"]

  # Serverless v2 scaling
  serverlessv2_scaling_configuration {
    min_capacity = var.db_min_capacity
    max_capacity = var.db_max_capacity
  }

  tags = { Name = "${var.project_name}-${var.environment}-aurora" }

  lifecycle {
    ignore_changes = [final_snapshot_identifier]
  }
}

# ─── Aurora Instance (Serverless v2) ────────────────────────────────────────
resource "aws_rds_cluster_instance" "writer" {
  identifier         = "${var.project_name}-${var.environment}-aurora-writer"
  cluster_identifier = aws_rds_cluster.aurora.id
  instance_class     = "db.serverless"
  engine             = aws_rds_cluster.aurora.engine
  engine_version     = aws_rds_cluster.aurora.engine_version

  performance_insights_enabled    = true
  performance_insights_kms_key_id = var.kms_key_arn

  tags = { Name = "${var.project_name}-${var.environment}-aurora-writer" }
}

# Reader instance for prod (HA)
resource "aws_rds_cluster_instance" "reader" {
  count              = var.environment == "prod" ? 1 : 0
  identifier         = "${var.project_name}-${var.environment}-aurora-reader"
  cluster_identifier = aws_rds_cluster.aurora.id
  instance_class     = "db.serverless"
  engine             = aws_rds_cluster.aurora.engine
  engine_version     = aws_rds_cluster.aurora.engine_version

  performance_insights_enabled    = true
  performance_insights_kms_key_id = var.kms_key_arn

  tags = { Name = "${var.project_name}-${var.environment}-aurora-reader" }
}
