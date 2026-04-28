# ─────────────────────────────────────────────────────────────────────────────
# Secrets Module — AWS Secrets Manager
# FedRAMP High: KMS-encrypted secrets, no plaintext in task definitions
# ─────────────────────────────────────────────────────────────────────────────

locals {
  prefix = "${var.project_name}/${var.environment}"

  # All application secrets that need to be injected into ECS tasks.
  # Values are populated via AWS Console or CLI — Terraform only creates
  # the secret shells. The DATABASE_URL is auto-constructed from Aurora outputs.
  app_secrets = {
    DATABASE_URL             = "mysql://${var.database_endpoint}:${var.database_port}/${var.project_name}_${var.environment}"
    JWT_SECRET               = ""
    OPENAI_API_KEY           = ""
    HACKERONE_API_KEY         = ""
    HACKERONE_API_USERNAME    = ""
    SHODAN_API_KEY           = ""
    CENSYS_API_ID            = ""
    CENSYS_API_SECRET        = ""
    URLSCAN_API_KEY          = ""
    SECURITYTRAILS_API_KEY   = ""
    ABUSEIPDB_API_KEY        = ""
    DEHASHED_API_KEY         = ""
    DEHASHED_EMAIL           = ""
    GOPHISH_API_KEY          = ""
    GOPHISH_BASE_URL         = ""
    CALDERA_API_KEY          = ""
    CALDERA_BASE_URL         = ""
    CALDERA_USERNAME         = ""
    CALDERA_PASSWORD         = ""
    GITHUB_PAT               = ""
    GITHUB_CLASSIC_TOKEN     = ""
    NVD_API_KEY              = ""
    DIGITALOCEAN_ACCESS_TOKEN = ""
    DO_SPACES_KEY            = ""
    DO_SPACES_SECRET         = ""
    DO_SPACES_BUCKET         = ""
    DO_SPACES_REGION         = ""
    DO_SPACES_ENDPOINT       = ""
    SCAN_SERVER_HOST         = ""
    SCAN_SERVER_USER         = ""
    ZAP_API_KEY              = ""
    ZAP_BASE_URL             = ""
  }
}

# Create a Secrets Manager secret for each app secret
resource "aws_secretsmanager_secret" "app" {
  for_each = local.app_secrets

  name       = "${local.prefix}/${each.key}"
  kms_key_id = var.kms_key_arn

  tags = {
    Name        = "${var.project_name}-${var.environment}-${each.key}"
    Environment = var.environment
  }
}

# Set initial values (DATABASE_URL is auto-populated, others are placeholders)
resource "aws_secretsmanager_secret_version" "app" {
  for_each = { for k, v in local.app_secrets : k => v if v != "" }

  secret_id     = aws_secretsmanager_secret.app[each.key].id
  secret_string = each.value
}
