output "cluster_name" { value = aws_ecs_cluster.main.name }
output "cluster_arn" { value = aws_ecs_cluster.main.arn }
output "service_name" { value = aws_ecs_service.app.name }
output "service_arn" { value = aws_ecs_service.app.id }
output "task_definition_arn" { value = aws_ecs_task_definition.app.arn }
output "ecs_security_group_id" { value = aws_security_group.ecs.id }
output "task_execution_role_arn" { value = aws_iam_role.task_execution.arn }
output "task_role_arn" { value = aws_iam_role.task.arn }
