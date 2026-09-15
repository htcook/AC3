output "ecr_repository_url" {
  description = "Sandbox ECR repository that GitHub Actions pushes to."
  value       = aws_ecr_repository.platform.repository_url
}

output "ecs_service_name" {
  description = "Sandbox ECS service name when deploy_service is enabled."
  value       = try(aws_ecs_service.platform[0].name, null)
}

output "ecs_cluster_name" {
  description = "Existing cluster hosting the sandbox service."
  value       = data.aws_ecs_cluster.target.cluster_name
}

output "task_definition_arn" {
  description = "Sandbox task definition when deploy_service is enabled."
  value       = try(aws_ecs_task_definition.platform[0].arn, null)
}

output "target_group_arn" {
  description = "Dedicated target group for the AC3-Plus sandbox."
  value       = aws_lb_target_group.platform.arn
}

output "sandbox_security_group_id" {
  description = "Dedicated security group for the AC3-Plus sandbox task."
  value       = aws_security_group.platform.id
}

output "host_names" {
  description = "Hostnames routed to the isolated sandbox service."
  value       = var.host_names
}

output "alb_dns_name" {
  description = "Existing ALB DNS name for DNS configuration and host-header smoke tests."
  value       = data.aws_lb.selected.dns_name
}
