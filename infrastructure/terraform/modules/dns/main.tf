# ─────────────────────────────────────────────────────────────────────────────
# DNS Module — Route53 Hosted Zone + ACM Certificate + ALB Alias Records
# FedRAMP High: SC-8 (Transmission Confidentiality via TLS)
# ─────────────────────────────────────────────────────────────────────────────

# ─── Route53 Hosted Zone ─────────────────────────────────────────────────────
resource "aws_route53_zone" "main" {
  name    = var.domain_name
  comment = "${var.project_name}-${var.environment} — managed by Terraform"

  tags = {
    Name        = "${var.project_name}-${var.environment}-zone"
    Environment = var.environment
    Project     = var.project_name
  }
}

# ─── ACM Certificate (wildcard + apex) ───────────────────────────────────────
resource "aws_acm_certificate" "main" {
  domain_name               = var.domain_name
  subject_alternative_names = ["*.${var.domain_name}"]
  validation_method         = "DNS"

  lifecycle {
    create_before_destroy = true
  }

  tags = {
    Name        = "${var.project_name}-${var.environment}-cert"
    Environment = var.environment
    Project     = var.project_name
  }
}

# ─── DNS Validation Records ──────────────────────────────────────────────────
resource "aws_route53_record" "cert_validation" {
  for_each = {
    for dvo in aws_acm_certificate.main.domain_validation_options : dvo.domain_name => {
      name   = dvo.resource_record_name
      record = dvo.resource_record_value
      type   = dvo.resource_record_type
    }
  }

  allow_overwrite = true
  name            = each.value.name
  records         = [each.value.record]
  ttl             = 60
  type            = each.value.type
  zone_id         = aws_route53_zone.main.zone_id
}

# ─── Certificate Validation ──────────────────────────────────────────────────
resource "aws_acm_certificate_validation" "main" {
  certificate_arn         = aws_acm_certificate.main.arn
  validation_record_fqdns = [for record in aws_route53_record.cert_validation : record.fqdn]
}

# ─── ALB Alias Records ───────────────────────────────────────────────────────
# Apex domain (aceofcloud.io) → ALB
resource "aws_route53_record" "apex" {
  zone_id = aws_route53_zone.main.zone_id
  name    = var.domain_name
  type    = "A"

  alias {
    name                   = var.alb_dns_name
    zone_id                = var.alb_zone_id
    evaluate_target_health = true
  }
}

# Wildcard subdomain (*.aceofcloud.io) → ALB
resource "aws_route53_record" "wildcard" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "*.${var.domain_name}"
  type    = "A"

  alias {
    name                   = var.alb_dns_name
    zone_id                = var.alb_zone_id
    evaluate_target_health = true
  }
}

# ─── Specific subdomain records ──────────────────────────────────────────────
# c3.aceofcloud.io → ALB (primary dashboard)
resource "aws_route53_record" "c3" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "c3.${var.domain_name}"
  type    = "A"

  alias {
    name                   = var.alb_dns_name
    zone_id                = var.alb_zone_id
    evaluate_target_health = true
  }
}

# dashboard.aceofcloud.io → ALB
resource "aws_route53_record" "dashboard" {
  zone_id = aws_route53_zone.main.zone_id
  name    = "dashboard.${var.domain_name}"
  type    = "A"

  alias {
    name                   = var.alb_dns_name
    zone_id                = var.alb_zone_id
    evaluate_target_health = true
  }
}
