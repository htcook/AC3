# ─────────────────────────────────────────────────────────────────────────────
# Secrets Module — AWS Secrets Manager
# FedRAMP High: KMS-encrypted secrets, no plaintext in task definitions
# ─────────────────────────────────────────────────────────────────────────────

locals {
  prefix = "${var.project_name}/${var.environment}"

  # All application secrets that need to be injected into ECS tasks.
  # Values are populated via AWS Console or CLI — Terraform only creates
  # the secret shells. The DATABASE_URL is auto-constructed from Aurora outputs.
  #
  # This list MUST stay in sync with server/_core/env.ts.
  # Last synced: 2026-04-28

  app_secrets = {
    # ── Core Platform ──────────────────────────────────────────────────────
    DATABASE_URL             = "mysql://${var.database_endpoint}:${var.database_port}/${var.project_name}_${var.environment}"
    JWT_SECRET               = ""
    OAUTH_SERVER_URL         = ""   # Manus OAuth backend base URL
    VITE_APP_ID              = ""   # Manus OAuth application ID
    OWNER_OPEN_ID            = ""   # Owner's Manus Open ID
    NODE_ENV                 = "production"

    # ── Manus Forge (LLM, storage, notifications) ─────────────────────────
    BUILT_IN_FORGE_API_URL   = ""
    BUILT_IN_FORGE_API_KEY   = ""

    # ── AI / LLM ──────────────────────────────────────────────────────────
    OPENAI_API_KEY           = ""

    # ── Cyber C2 (Caldera) ────────────────────────────────────────────────
    CALDERA_API_KEY          = ""
    CALDERA_BASE_URL         = ""
    CALDERA_USERNAME         = ""
    CALDERA_PASSWORD         = ""

    # ── GoPhish (Phishing Simulation) ─────────────────────────────────────
    GOPHISH_API_KEY          = ""
    GOPHISH_BASE_URL         = ""

    # ── Passive ASM Connectors ────────────────────────────────────────────
    SHODAN_API_KEY           = ""
    CENSYS_API_ID            = ""
    CENSYS_API_SECRET        = ""
    URLSCAN_API_KEY          = ""
    SECURITYTRAILS_API_KEY   = ""
    ABUSEIPDB_API_KEY        = ""
    DEHASHED_API_KEY         = ""
    DEHASHED_EMAIL           = ""
    NVD_API_KEY              = ""

    # ── OSINT Pipeline Expansion ──────────────────────────────────────────
    BINARYEDGE_API_KEY       = ""
    GREYNOISE_API_KEY        = ""
    VIRUSTOTAL_API_KEY       = ""
    HIBP_API_KEY             = ""
    WHOISXML_API_KEY         = ""
    LEAKIX_API_KEY           = ""
    FULLHUNT_API_KEY         = ""
    NETLAS_API_KEY           = ""
    HUNTER_API_KEY           = ""
    PASSIVETOTAL_API_KEY     = ""
    INTELX_API_KEY           = ""
    HUDSON_ROCK_API_KEY      = ""
    LEAKCHECK_API_KEY        = ""

    # ── GitHub Recon ──────────────────────────────────────────────────────
    GITHUB_PAT               = ""
    GITHUB_CLASSIC_TOKEN     = ""

    # ── HackerOne Bug Bounty Intelligence ─────────────────────────────────
    HACKERONE_API_KEY         = ""
    HACKERONE_API_USERNAME    = ""

    # ── DigitalOcean (domain purchasing + Spaces storage) ─────────────────
    DIGITALOCEAN_ACCESS_TOKEN = ""
    DO_SPACES_KEY            = ""
    DO_SPACES_SECRET         = ""
    DO_SPACES_BUCKET         = ""
    DO_SPACES_REGION         = ""
    DO_SPACES_ENDPOINT       = ""

    # ── Scan Server (offensive tools droplet) ─────────────────────────────
    SCAN_SERVER_HOST         = ""
    SCAN_SERVER_USER         = ""

    # ── ZAP (DAST) ────────────────────────────────────────────────────────
    ZAP_API_KEY              = ""
    ZAP_BASE_URL             = ""

    # ── Metasploit MSGRPC ─────────────────────────────────────────────────
    MSF_RPC_HOST             = ""
    MSF_RPC_PORT             = ""
    MSF_RPC_USER             = ""
    MSF_RPC_PASS             = ""
    MSF_RPC_SSL              = ""

    # ── Cobalt Strike Team Server ─────────────────────────────────────────
    CS_TEAM_SERVER_URL       = ""
    CS_TEAM_SERVER_PORT      = ""
    CS_API_KEY               = ""
    CS_API_PORT              = ""
    CS_USERNAME              = ""
    CS_PASSWORD              = ""

    # ── Empire C2 (BC Security / Starkiller) ──────────────────────────────
    EMPIRE_BASE_URL          = ""
    EMPIRE_API_KEY           = ""
    EMPIRE_USERNAME          = ""
    EMPIRE_PASSWORD          = ""

    # ── Sliver C2 (gRPC) ─────────────────────────────────────────────────
    SLIVER_SERVER_URL        = ""
    SLIVER_OPERATOR_TOKEN    = ""
    SLIVER_OPERATOR_CONFIG   = ""   # Base64-encoded operator config JSON

    # ── Manjusaka C2 (DEPRECATED — REC-LEGAL-001) ────────────────────────
    MANJUSAKA_SERVER_URL     = ""
    MANJUSAKA_API_TOKEN      = ""
    MANJUSAKA_ADMIN_PASSWORD = ""
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

# Set initial values (DATABASE_URL and NODE_ENV are auto-populated, others are placeholders)
resource "aws_secretsmanager_secret_version" "app" {
  for_each = { for k, v in local.app_secrets : k => v if v != "" }

  secret_id     = aws_secretsmanager_secret.app[each.key].id
  secret_string = each.value
}
