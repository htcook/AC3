# ─────────────────────────────────────────────────────────────────────────────
# Monitoring Module — CloudWatch Logs, Alarms, Dashboard
# FedRAMP High: AU-6 audit review, SI-4 monitoring, IR-5 incident tracking
# ─────────────────────────────────────────────────────────────────────────────

# ─── Log Group ───────────────────────────────────────────────────────────────
resource "aws_cloudwatch_log_group" "app" {
  name              = "/ecs/${var.project_name}-${var.environment}"
  retention_in_days = 365 # FedRAMP High: 1-year minimum retention

  tags = { Name = "${var.project_name}-${var.environment}-logs" }
}

# ─── SNS Topic for Alarms ───────────────────────────────────────────────────
resource "aws_sns_topic" "alarms" {
  count = var.alarm_sns_topic_arn == "" ? 1 : 0
  name  = "${var.project_name}-${var.environment}-alarms"
  tags  = { Name = "${var.project_name}-${var.environment}-alarms" }
}

locals {
  alarm_topic_arn = var.alarm_sns_topic_arn != "" ? var.alarm_sns_topic_arn : aws_sns_topic.alarms[0].arn
}

# ─── ECS Alarms ──────────────────────────────────────────────────────────────
resource "aws_cloudwatch_metric_alarm" "ecs_cpu_high" {
  alarm_name          = "${var.project_name}-${var.environment}-ecs-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/ECS"
  period              = 300
  statistic           = "Average"
  threshold           = 85
  alarm_description   = "ECS CPU utilization above 85% for 15 minutes"
  alarm_actions       = [local.alarm_topic_arn]
  ok_actions          = [local.alarm_topic_arn]

  dimensions = {
    ClusterName = var.ecs_cluster_name
    ServiceName = var.ecs_service_name
  }

  tags = { Name = "${var.project_name}-${var.environment}-ecs-cpu-alarm" }
}

resource "aws_cloudwatch_metric_alarm" "ecs_memory_high" {
  alarm_name          = "${var.project_name}-${var.environment}-ecs-memory-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "MemoryUtilization"
  namespace           = "AWS/ECS"
  period              = 300
  statistic           = "Average"
  threshold           = 90
  alarm_description   = "ECS memory utilization above 90% for 15 minutes"
  alarm_actions       = [local.alarm_topic_arn]
  ok_actions          = [local.alarm_topic_arn]

  dimensions = {
    ClusterName = var.ecs_cluster_name
    ServiceName = var.ecs_service_name
  }

  tags = { Name = "${var.project_name}-${var.environment}-ecs-memory-alarm" }
}

# ─── ALB Alarms ──────────────────────────────────────────────────────────────
resource "aws_cloudwatch_metric_alarm" "alb_5xx" {
  alarm_name          = "${var.project_name}-${var.environment}-alb-5xx"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "HTTPCode_Target_5XX_Count"
  namespace           = "AWS/ApplicationELB"
  period              = 300
  statistic           = "Sum"
  threshold           = 50
  alarm_description   = "ALB target 5xx errors exceed 50 in 5 minutes"
  alarm_actions       = [local.alarm_topic_arn]
  treat_missing_data  = "notBreaching"

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
    TargetGroup  = var.target_group_arn_suffix
  }

  tags = { Name = "${var.project_name}-${var.environment}-alb-5xx-alarm" }
}

resource "aws_cloudwatch_metric_alarm" "alb_unhealthy" {
  alarm_name          = "${var.project_name}-${var.environment}-alb-unhealthy"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "UnHealthyHostCount"
  namespace           = "AWS/ApplicationELB"
  period              = 60
  statistic           = "Maximum"
  threshold           = 0
  alarm_description   = "ALB has unhealthy targets"
  alarm_actions       = [local.alarm_topic_arn]

  dimensions = {
    LoadBalancer = var.alb_arn_suffix
    TargetGroup  = var.target_group_arn_suffix
  }

  tags = { Name = "${var.project_name}-${var.environment}-alb-unhealthy-alarm" }
}

# ─── Database Alarms ─────────────────────────────────────────────────────────
resource "aws_cloudwatch_metric_alarm" "db_cpu_high" {
  alarm_name          = "${var.project_name}-${var.environment}-db-cpu-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 3
  metric_name         = "CPUUtilization"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 80
  alarm_description   = "Aurora CPU above 80% for 15 minutes"
  alarm_actions       = [local.alarm_topic_arn]

  dimensions = {
    DBClusterIdentifier = var.db_cluster_id
  }

  tags = { Name = "${var.project_name}-${var.environment}-db-cpu-alarm" }
}

resource "aws_cloudwatch_metric_alarm" "db_connections_high" {
  alarm_name          = "${var.project_name}-${var.environment}-db-connections-high"
  comparison_operator = "GreaterThanThreshold"
  evaluation_periods  = 2
  metric_name         = "DatabaseConnections"
  namespace           = "AWS/RDS"
  period              = 300
  statistic           = "Average"
  threshold           = 800
  alarm_description   = "Aurora connections above 800"
  alarm_actions       = [local.alarm_topic_arn]

  dimensions = {
    DBClusterIdentifier = var.db_cluster_id
  }

  tags = { Name = "${var.project_name}-${var.environment}-db-connections-alarm" }
}

# ─── CloudWatch Dashboard ───────────────────────────────────────────────────
resource "aws_cloudwatch_dashboard" "main" {
  dashboard_name = "${var.project_name}-${var.environment}"

  dashboard_body = jsonencode({
    widgets = [
      {
        type   = "metric"
        x      = 0
        y      = 0
        width  = 12
        height = 6
        properties = {
          title   = "ECS CPU & Memory"
          region  = var.aws_region
          metrics = [
            ["AWS/ECS", "CPUUtilization", "ClusterName", var.ecs_cluster_name, "ServiceName", var.ecs_service_name],
            ["AWS/ECS", "MemoryUtilization", "ClusterName", var.ecs_cluster_name, "ServiceName", var.ecs_service_name]
          ]
          period = 300
          stat   = "Average"
        }
      },
      {
        type   = "metric"
        x      = 12
        y      = 0
        width  = 12
        height = 6
        properties = {
          title   = "ALB Request Count & Latency"
          region  = var.aws_region
          metrics = [
            ["AWS/ApplicationELB", "RequestCount", "LoadBalancer", var.alb_arn_suffix],
            ["AWS/ApplicationELB", "TargetResponseTime", "LoadBalancer", var.alb_arn_suffix]
          ]
          period = 300
          stat   = "Sum"
        }
      },
      {
        type   = "metric"
        x      = 0
        y      = 6
        width  = 12
        height = 6
        properties = {
          title   = "Aurora CPU & Connections"
          region  = var.aws_region
          metrics = [
            ["AWS/RDS", "CPUUtilization", "DBClusterIdentifier", var.db_cluster_id],
            ["AWS/RDS", "DatabaseConnections", "DBClusterIdentifier", var.db_cluster_id]
          ]
          period = 300
          stat   = "Average"
        }
      },
      {
        type   = "log"
        x      = 12
        y      = 6
        width  = 12
        height = 6
        properties = {
          title   = "Application Errors"
          region  = var.aws_region
          query   = "SOURCE '/ecs/${var.project_name}-${var.environment}' | filter @message like /ERROR|error|Error/ | sort @timestamp desc | limit 50"
        }
      }
    ]
  })
}
