# ─────────────────────────────────────────────────────────────────────────────
# ECS Fargate Module — Cluster, Service, Task Definition, Auto-Scaling
# FedRAMP High: FIPS mode, encrypted logs, least-privilege IAM, private subnets
#
# Supports two modes:
#   1. Self-managed roles (default) — creates execution + task roles
#   2. External roles — uses pre-existing roles from admin (set external_*_role_arn)
# ─────────────────────────────────────────────────────────────────────────────

# ─── Role Resolution ─────────────────────────────────────────────────────────
locals {
  use_external_roles = var.external_execution_role_arn != "" && var.external_task_role_arn != ""
  execution_role_arn = local.use_external_roles ? var.external_execution_role_arn : aws_iam_role.task_execution[0].arn
  task_role_arn      = local.use_external_roles ? var.external_task_role_arn : aws_iam_role.task[0].arn
  create_roles       = local.use_external_roles ? 0 : 1
}

# ─── ECS Cluster ─────────────────────────────────────────────────────────────
resource "aws_ecs_cluster" "main" {
  name = "${var.project_name}-${var.environment}"

  setting {
    name  = "containerInsights"
    value = "enabled" # FedRAMP: AU-6 monitoring
  }

  configuration {
    execute_command_configuration {
      kms_key_id = var.kms_key_arn
      logging    = "OVERRIDE"
      log_configuration {
        cloud_watch_log_group_name = var.log_group_name
      }
    }
  }

  tags = { Name = "${var.project_name}-${var.environment}-cluster" }
}

# ─── Task Execution Role (pulls images, writes logs) ────────────────────────
# Skipped when external_execution_role_arn is provided
resource "aws_iam_role" "task_execution" {
  count = local.create_roles
  name  = "${var.project_name}-${var.environment}-task-execution"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "task_execution_base" {
  count      = local.create_roles
  role       = aws_iam_role.task_execution[0].name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

# Allow reading secrets from Secrets Manager
resource "aws_iam_role_policy" "task_execution_secrets" {
  count = local.create_roles
  name  = "${var.project_name}-${var.environment}-task-exec-secrets"
  role  = aws_iam_role.task_execution[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect = "Allow"
        Action = [
          "secretsmanager:GetSecretValue"
        ]
        Resource = "${var.secrets_arn_prefix}*"
      },
      {
        Effect = "Allow"
        Action = [
          "kms:Decrypt"
        ]
        Resource = var.kms_key_arn
      }
    ]
  })
}

# ─── Task Role (application permissions) ────────────────────────────────────
# Skipped when external_task_role_arn is provided
resource "aws_iam_role" "task" {
  count = local.create_roles
  name  = "${var.project_name}-${var.environment}-task"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action = "sts:AssumeRole"
      Effect = "Allow"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

# S3 access for report/evidence storage
resource "aws_iam_role_policy" "task_s3" {
  count = local.create_roles
  name  = "${var.project_name}-${var.environment}-task-s3"
  role  = aws_iam_role.task[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "s3:GetObject",
        "s3:PutObject",
        "s3:DeleteObject",
        "s3:ListBucket"
      ]
      Resource = [
        "arn:aws:s3:::${var.project_name}-${var.environment}-*",
        "arn:aws:s3:::${var.project_name}-${var.environment}-*/*"
      ]
    }]
  })
}

# ECS Exec for debugging (non-prod only)
resource "aws_iam_role_policy" "task_exec_command" {
  count = var.enable_execute_command && !local.use_external_roles ? 1 : 0
  name  = "${var.project_name}-${var.environment}-task-exec-cmd"
  role  = aws_iam_role.task[0].id
  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect = "Allow"
      Action = [
        "ssmmessages:CreateControlChannel",
        "ssmmessages:CreateDataChannel",
        "ssmmessages:OpenControlChannel",
        "ssmmessages:OpenDataChannel"
      ]
      Resource = "*"
    }]
  })
}

# ─── Security Group ─────────────────────────────────────────────────────────
resource "aws_security_group" "ecs" {
  name_prefix = "${var.project_name}-${var.environment}-ecs-"
  vpc_id      = var.vpc_id
  description = "ECS Fargate tasks — ALB ingress only"

  ingress {
    description = "From ALB"
    from_port   = var.container_port
    to_port     = var.container_port
    protocol    = "tcp"
    cidr_blocks = ["10.0.0.0/8"] # VPC-internal only
  }

  egress {
    description = "All outbound (API calls, DB, internet)"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle { create_before_destroy = true }
  tags = { Name = "${var.project_name}-${var.environment}-ecs-sg" }
}

# ─── Task Definition ────────────────────────────────────────────────────────
resource "aws_ecs_task_definition" "app" {
  family                   = "${var.project_name}-${var.environment}"
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = var.cpu
  memory                   = var.memory
  execution_role_arn       = local.execution_role_arn
  task_role_arn            = local.task_role_arn

  # FedRAMP: Enable FIPS mode on Fargate
  runtime_platform {
    operating_system_family = "LINUX"
    cpu_architecture        = "X86_64"
  }

  container_definitions = jsonencode([{
    name      = "${var.project_name}-app"
    image     = "${var.ecr_repository_url}:${var.image_tag}"
    essential = true

    portMappings = [{
      containerPort = var.container_port
      protocol      = "tcp"
    }]

    environment = [
      { name = "NODE_ENV", value = "production" },
      { name = "PORT", value = tostring(var.container_port) },
      { name = "NODE_OPTIONS", value = "--max-old-space-size=${floor(var.memory * 0.75)} --expose-gc" },
      { name = "AWS_REGION", value = var.aws_region },
    ]

    secrets = [for name, arn in var.app_secrets : {
      name      = name
      valueFrom = arn
    }]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        "awslogs-group"         = var.log_group_name
        "awslogs-region"        = var.aws_region
        "awslogs-stream-prefix" = "ecs"
      }
    }

    healthCheck = {
      command     = ["CMD-SHELL", "curl -f http://localhost:${var.container_port}/api/health || exit 1"]
      interval    = 30
      timeout     = 10
      retries     = 3
      startPeriod = 60
    }
  }])

  tags = { Name = "${var.project_name}-${var.environment}-task" }
}

# ─── ECS Service ─────────────────────────────────────────────────────────────
resource "aws_ecs_service" "app" {
  name            = "${var.project_name}-${var.environment}-service"
  cluster         = aws_ecs_cluster.main.id
  task_definition = aws_ecs_task_definition.app.arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  enable_execute_command = var.enable_execute_command

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.ecs.id]
    assign_public_ip = false # FedRAMP: private subnets only
  }

  load_balancer {
    target_group_arn = var.target_group_arn
    container_name   = "${var.project_name}-app"
    container_port   = var.container_port
  }

  deployment_configuration {
    minimum_healthy_percent = 50
    maximum_percent         = 200
  }

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  # Ignore desired_count changes from auto-scaling
  lifecycle {
    ignore_changes = [desired_count]
  }

  tags = { Name = "${var.project_name}-${var.environment}-service" }
}

# ─── Auto-Scaling ────────────────────────────────────────────────────────────
resource "aws_appautoscaling_target" "ecs" {
  max_capacity       = var.max_count
  min_capacity       = var.min_count
  resource_id        = "service/${aws_ecs_cluster.main.name}/${aws_ecs_service.app.name}"
  scalable_dimension = "ecs:service:DesiredCount"
  service_namespace  = "ecs"
}

resource "aws_appautoscaling_policy" "cpu" {
  name               = "${var.project_name}-${var.environment}-cpu-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageCPUUtilization"
    }
    target_value       = 70.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}

resource "aws_appautoscaling_policy" "memory" {
  name               = "${var.project_name}-${var.environment}-memory-scaling"
  policy_type        = "TargetTrackingScaling"
  resource_id        = aws_appautoscaling_target.ecs.resource_id
  scalable_dimension = aws_appautoscaling_target.ecs.scalable_dimension
  service_namespace  = aws_appautoscaling_target.ecs.service_namespace

  target_tracking_scaling_policy_configuration {
    predefined_metric_specification {
      predefined_metric_type = "ECSServiceAverageMemoryUtilization"
    }
    target_value       = 80.0
    scale_in_cooldown  = 300
    scale_out_cooldown = 60
  }
}
