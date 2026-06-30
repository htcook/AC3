# ─────────────────────────────────────────────────────────────────────────────
# DNS Module — Variables
# ─────────────────────────────────────────────────────────────────────────────

variable "project_name" {
  description = "Project name for resource tagging"
  type        = string
}

variable "environment" {
  description = "Environment name (dev, staging, prod)"
  type        = string
}

variable "domain_name" {
  description = "Root domain name (e.g., aceofcloud.io)"
  type        = string
}

variable "alb_dns_name" {
  description = "DNS name of the Application Load Balancer"
  type        = string
}

variable "alb_zone_id" {
  description = "Route53 zone ID of the ALB (for alias records)"
  type        = string
}
