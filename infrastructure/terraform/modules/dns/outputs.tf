# ─────────────────────────────────────────────────────────────────────────────
# DNS Module — Outputs
# ─────────────────────────────────────────────────────────────────────────────

output "zone_id" {
  description = "Route53 hosted zone ID"
  value       = aws_route53_zone.main.zone_id
}

output "zone_name_servers" {
  description = "Name servers for the hosted zone (set these at your registrar)"
  value       = aws_route53_zone.main.name_servers
}

output "certificate_arn" {
  description = "ARN of the validated ACM certificate"
  value       = aws_acm_certificate_validation.main.certificate_arn
}

output "domain_name" {
  description = "The domain name configured"
  value       = var.domain_name
}
