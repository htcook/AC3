output "kms_key_arn" { value = aws_kms_key.main.arn }
output "kms_key_id" { value = aws_kms_key.main.key_id }
output "kms_alias_arn" { value = aws_kms_alias.main.arn }
output "cloudtrail_arn" { value = var.enable_cloudtrail ? aws_cloudtrail.main[0].arn : "" }
output "guardduty_detector_id" { value = var.enable_guardduty ? aws_guardduty_detector.main[0].id : "" }
