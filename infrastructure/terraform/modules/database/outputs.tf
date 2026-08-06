output "cluster_endpoint" { value = aws_rds_cluster.aurora.endpoint }
output "reader_endpoint" { value = aws_rds_cluster.aurora.reader_endpoint }
output "cluster_port" { value = aws_rds_cluster.aurora.port }
output "database_name" { value = aws_rds_cluster.aurora.database_name }
output "cluster_identifier" { value = aws_rds_cluster.aurora.cluster_identifier }
output "master_secret_arn" { value = aws_secretsmanager_secret.db_master.arn }
output "security_group_id" { value = aws_security_group.aurora.id }
