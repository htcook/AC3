terraform {
  required_version = ">= 1.9.0"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 5.60"
    }
  }

  # Each non-production sandbox receives its own state key. Backend details are
  # supplied by CI during terraform init; never commit credentials here.
  backend "s3" {}
}

provider "aws" {
  region = var.aws_region

  default_tags {
    tags = merge({
      Project     = "AC3-Plus"
      Environment = var.environment
      Component   = "platform-sandbox"
      ManagedBy   = "Terraform"
      Purpose     = "non-production-troubleshooting"
    }, var.tags)
  }
}

data "aws_caller_identity" "current" {}

data "aws_ecs_cluster" "target" {
  cluster_name = var.ecs_cluster_name
}

data "aws_lb_listener" "https" {
  arn = var.https_listener_arn
}

data "aws_lb" "selected" {
  arn = data.aws_lb_listener.https.load_balancer_arn
}

locals {
  name_prefix      = "ac3-plus-${var.environment}-platform-sandbox"
  ecr_name         = "ac3-plus/${var.environment}-platform-sandbox"
  required_secrets = toset(["DATABASE_URL", "JWT_SECRET"])
}

check "target_account" {
  assert {
    condition     = data.aws_caller_identity.current.account_id == var.aws_account_id
    error_message = "The active AWS account does not match aws_account_id. Refusing to target the wrong account."
  }
}

check "target_listener" {
  assert {
    condition     = data.aws_lb_listener.https.port == 443 && data.aws_lb_listener.https.protocol == "HTTPS"
    error_message = "https_listener_arn must identify an HTTPS listener on port 443."
  }
}

# This repository is intentionally distinct from the existing AC3 / AC3-Plus
# production repositories. Immutable tags make every deploy attributable to a
# source commit and eliminate latest-tag drift.
resource "aws_ecr_repository" "platform" {
  name                 = local.ecr_name
  image_tag_mutability = "IMMUTABLE"

  image_scanning_configuration {
    scan_on_push = true
  }

  encryption_configuration {
    encryption_type = "AES256"
  }
}

resource "aws_ecr_lifecycle_policy" "platform" {
  repository = aws_ecr_repository.platform.name

  policy = jsonencode({
    rules = [
      {
        rulePriority = 1
        description  = "Keep the 30 most recent immutable commit images"
        selection = {
          tagStatus     = "tagged"
          tagPrefixList = ["sha-"]
          countType     = "imageCountMoreThan"
          countNumber   = 30
        }
        action = { type = "expire" }
      },
      {
        rulePriority = 2
        description  = "Remove untagged images after seven days"
        selection = {
          tagStatus   = "untagged"
          countType   = "sinceImagePushed"
          countUnit   = "days"
          countNumber = 7
        }
        action = { type = "expire" }
      }
    ]
  })
}

resource "aws_cloudwatch_log_group" "platform" {
  name              = "/ecs/${local.name_prefix}"
  retention_in_days = var.log_retention_days
}

resource "aws_security_group" "platform" {
  name_prefix = "${local.name_prefix}-"
  description = "AC3-Plus ${var.environment} sandbox platform; HTTPS ALB ingress only"
  vpc_id      = var.vpc_id

  ingress {
    description     = "Platform traffic from the selected application load balancer"
    protocol        = "tcp"
    from_port       = var.container_port
    to_port         = var.container_port
    security_groups = [var.alb_security_group_id]
  }

  egress {
    description = "HTTPS, package APIs, and private service egress"
    protocol    = "-1"
    from_port   = 0
    to_port     = 0
    cidr_blocks = ["0.0.0.0/0"]
  }

  lifecycle {
    create_before_destroy = true
  }
}

resource "aws_iam_role" "execution" {
  name = "${local.name_prefix}-execution"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy_attachment" "execution_base" {
  role       = aws_iam_role.execution.name
  policy_arn = "arn:aws:iam::aws:policy/service-role/AmazonECSTaskExecutionRolePolicy"
}

resource "aws_iam_role_policy" "execution_secrets" {
  count = length(var.app_secrets) > 0 ? 1 : 0
  name  = "${local.name_prefix}-read-config"
  role  = aws_iam_role.execution.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["secretsmanager:GetSecretValue"]
      Resource = values(var.app_secrets)
    }]
  })
}

resource "aws_iam_role" "task" {
  name = "${local.name_prefix}-task"

  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Action    = "sts:AssumeRole"
      Principal = { Service = "ecs-tasks.amazonaws.com" }
    }]
  })
}

resource "aws_iam_role_policy" "task_optional" {
  count = var.task_role_policy_json == "" ? 0 : 1
  name  = "${local.name_prefix}-runtime"
  role  = aws_iam_role.task.id

  policy = var.task_role_policy_json
}

resource "aws_lb_target_group" "platform" {
  name        = substr("${local.name_prefix}-tg", 0, 32)
  port        = var.container_port
  protocol    = "HTTP"
  target_type = "ip"
  vpc_id      = var.vpc_id

  health_check {
    enabled             = true
    path                = var.health_check_path
    port                = "traffic-port"
    protocol            = "HTTP"
    matcher             = "200"
    healthy_threshold   = 2
    unhealthy_threshold = 3
    interval            = 30
    timeout             = 10
  }

  deregistration_delay = 30
}

resource "aws_lb_listener_rule" "platform" {
  listener_arn = var.https_listener_arn
  priority     = var.listener_rule_priority

  action {
    type             = "forward"
    target_group_arn = aws_lb_target_group.platform.arn
  }

  condition {
    host_header {
      values = var.host_names
    }
  }
}

# deploy_service=false creates only the safe prerequisites (ECR, logging, IAM,
# security group, target group, and isolated host rule). The CI workflow turns
# this on only after it has pushed a commit-addressed image to the sandbox ECR.
resource "aws_ecs_task_definition" "platform" {
  count                    = var.deploy_service ? 1 : 0
  family                   = local.name_prefix
  network_mode             = "awsvpc"
  requires_compatibilities = ["FARGATE"]
  cpu                      = tostring(var.task_cpu)
  memory                   = tostring(var.task_memory)
  execution_role_arn       = aws_iam_role.execution.arn
  task_role_arn            = aws_iam_role.task.arn

  container_definitions = jsonencode([{
    name      = "platform"
    image     = var.image_uri
    essential = true

    portMappings = [{
      containerPort = var.container_port
      hostPort      = var.container_port
      protocol      = "tcp"
    }]

    environment = [
      { name = "NODE_ENV", value = "production" },
      { name = "PORT", value = tostring(var.container_port) },
      { name = "NODE_OPTIONS", value = "--max-old-space-size=${floor(var.task_memory * 0.75)} --expose-gc" },
      { name = "AWS_REGION", value = var.aws_region }
    ]

    secrets = [for name, arn in var.app_secrets : {
      name      = name
      valueFrom = arn
    }]

    logConfiguration = {
      logDriver = "awslogs"
      options = {
        awslogs-group         = aws_cloudwatch_log_group.platform.name
        awslogs-region        = var.aws_region
        awslogs-stream-prefix = "ecs"
      }
    }

    healthCheck = {
      command     = ["CMD-SHELL", "curl -fsS http://localhost:${var.container_port}${var.health_check_path} || exit 1"]
      interval    = 30
      timeout     = 10
      retries     = 3
      startPeriod = 120
    }
  }])

  lifecycle {
    precondition {
      condition     = length(setsubtract(local.required_secrets, toset(keys(var.app_secrets)))) == 0
      error_message = "A deploy requires at least DATABASE_URL and JWT_SECRET secret ARNs in app_secrets."
    }
  }
}

resource "aws_ecs_service" "platform" {
  count           = var.deploy_service ? 1 : 0
  name            = local.name_prefix
  cluster         = data.aws_ecs_cluster.target.id
  task_definition = aws_ecs_task_definition.platform[0].arn
  desired_count   = var.desired_count
  launch_type     = "FARGATE"

  deployment_circuit_breaker {
    enable   = true
    rollback = true
  }

  deployment_minimum_healthy_percent = 50
  deployment_maximum_percent         = 200

  network_configuration {
    subnets          = var.private_subnet_ids
    security_groups  = [aws_security_group.platform.id]
    assign_public_ip = var.assign_public_ip
  }

  load_balancer {
    target_group_arn = aws_lb_target_group.platform.arn
    container_name   = "platform"
    container_port   = var.container_port
  }

  lifecycle {
    precondition {
      condition     = local.name_prefix != var.reference_service_name
      error_message = "The sandbox service must never use the Dev reference service name."
    }
  }
}
