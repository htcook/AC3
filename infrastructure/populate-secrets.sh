#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# AC3 Platform — Populate Secrets Manager with App Environment Variables
# ═══════════════════════════════════════════════════════════════════════════════
# This script updates the ac3/dev/app secret with all required env vars.
# Run this BEFORE deploying the ECS service.
#
# Usage:
#   1. Export your DO App Platform env vars (from DO dashboard or doctl)
#   2. Edit the values below
#   3. Run: bash infrastructure/populate-secrets.sh
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

REGION="us-east-1"
SECRET_ID="ac3/dev/app"

# ─── RDS Connection ──────────────────────────────────────────────────────────
# The DATABASE_URL uses the RDS endpoint. SSL is required for Aurora MySQL.
RDS_HOST="ac3-dev-mysql.c2d8yioy4rye.us-east-1.rds.amazonaws.com"
RDS_PORT="3306"
RDS_DB="ac3dev"
RDS_USER="ac3admin"
RDS_PASS="vuwiXiPnhRl7W86PqBlopwImU9FHhQE"
DATABASE_URL="mysql://${RDS_USER}:${RDS_PASS}@${RDS_HOST}:${RDS_PORT}/${RDS_DB}?ssl={\"rejectUnauthorized\":true}"

# ─── Core App Secrets ────────────────────────────────────────────────────────
# IMPORTANT: Copy these values from your DO App Platform environment variables
# or from the Manus webdev secrets panel.

# Auth / Session
JWT_SECRET="${JWT_SECRET:-REPLACE_ME}"
VITE_APP_ID="${VITE_APP_ID:-REPLACE_ME}"
OAUTH_SERVER_URL="${OAUTH_SERVER_URL:-REPLACE_ME}"
VITE_OAUTH_PORTAL_URL="${VITE_OAUTH_PORTAL_URL:-REPLACE_ME}"
OWNER_OPEN_ID="${OWNER_OPEN_ID:-REPLACE_ME}"
OWNER_NAME="${OWNER_NAME:-Harrison Cook}"

# Forge API (Manus built-in)
BUILT_IN_FORGE_API_URL="${BUILT_IN_FORGE_API_URL:-REPLACE_ME}"
BUILT_IN_FORGE_API_KEY="${BUILT_IN_FORGE_API_KEY:-REPLACE_ME}"

# Caldera C2
CALDERA_API_KEY="${CALDERA_API_KEY:-kmpJNkws7KXEdyIc2K8FYAGdMoRgrZ4c3hvJ1F9SI94}"
CALDERA_BASE_URL="${CALDERA_BASE_URL:-https://caldera.aceofcloud.io}"
CALDERA_USERNAME="${CALDERA_USERNAME:-red}"
CALDERA_PASSWORD="${CALDERA_PASSWORD:-REPLACE_ME}"

# GoPhish
GOPHISH_API_KEY="${GOPHISH_API_KEY:-REPLACE_ME}"
GOPHISH_BASE_URL="${GOPHISH_BASE_URL:-https://137.184.7.224:3333}"

# Scan Server
SCAN_SERVER_HOST="${SCAN_SERVER_HOST:-137.184.71.192}"

# OSINT API Keys
SHODAN_API_KEY="${SHODAN_API_KEY:-REPLACE_ME}"
OPENAI_API_KEY="${OPENAI_API_KEY:-REPLACE_ME}"

# DO Spaces (legacy storage)
DO_SPACES_KEY="${DO_SPACES_KEY:-REPLACE_ME}"
DO_SPACES_SECRET="${DO_SPACES_SECRET:-REPLACE_ME}"
DO_SPACES_BUCKET="${DO_SPACES_BUCKET:-aceofcloud-reports}"
DO_SPACES_REGION="${DO_SPACES_REGION:-nyc3}"
DO_SPACES_ENDPOINT="${DO_SPACES_ENDPOINT:-https://nyc3.digitaloceanspaces.com}"

# AWS S3 (for AWS deployment — evidence/reports buckets)
S3_ENDPOINT="${S3_ENDPOINT:-https://s3.us-east-1.amazonaws.com}"
S3_REGION="${S3_REGION:-us-east-1}"
S3_ACCESS_KEY="${S3_ACCESS_KEY:-REPLACE_ME}"
S3_SECRET_KEY="${S3_SECRET_KEY:-REPLACE_ME}"
S3_BUCKET="${S3_BUCKET:-ac3-dev-evidence-808038814732}"

# ─── Build Secret JSON ───────────────────────────────────────────────────────
SECRET_JSON=$(cat <<EOF
{
  "DATABASE_URL": "${DATABASE_URL}",
  "JWT_SECRET": "${JWT_SECRET}",
  "VITE_APP_ID": "${VITE_APP_ID}",
  "OAUTH_SERVER_URL": "${OAUTH_SERVER_URL}",
  "VITE_OAUTH_PORTAL_URL": "${VITE_OAUTH_PORTAL_URL}",
  "OWNER_OPEN_ID": "${OWNER_OPEN_ID}",
  "OWNER_NAME": "${OWNER_NAME}",
  "BUILT_IN_FORGE_API_URL": "${BUILT_IN_FORGE_API_URL}",
  "BUILT_IN_FORGE_API_KEY": "${BUILT_IN_FORGE_API_KEY}",
  "CALDERA_API_KEY": "${CALDERA_API_KEY}",
  "CALDERA_BASE_URL": "${CALDERA_BASE_URL}",
  "CALDERA_USERNAME": "${CALDERA_USERNAME}",
  "CALDERA_PASSWORD": "${CALDERA_PASSWORD}",
  "GOPHISH_API_KEY": "${GOPHISH_API_KEY}",
  "GOPHISH_BASE_URL": "${GOPHISH_BASE_URL}",
  "SCAN_SERVER_HOST": "${SCAN_SERVER_HOST}",
  "SHODAN_API_KEY": "${SHODAN_API_KEY}",
  "OPENAI_API_KEY": "${OPENAI_API_KEY}",
  "DO_SPACES_KEY": "${DO_SPACES_KEY}",
  "DO_SPACES_SECRET": "${DO_SPACES_SECRET}",
  "DO_SPACES_BUCKET": "${DO_SPACES_BUCKET}",
  "DO_SPACES_REGION": "${DO_SPACES_REGION}",
  "DO_SPACES_ENDPOINT": "${DO_SPACES_ENDPOINT}",
  "S3_ENDPOINT": "${S3_ENDPOINT}",
  "S3_REGION": "${S3_REGION}",
  "S3_ACCESS_KEY": "${S3_ACCESS_KEY}",
  "S3_SECRET_KEY": "${S3_SECRET_KEY}",
  "S3_BUCKET": "${S3_BUCKET}"
}
EOF
)

echo "Updating secret: ${SECRET_ID}"
aws secretsmanager put-secret-value \
  --secret-id "${SECRET_ID}" \
  --secret-string "${SECRET_JSON}" \
  --region "${REGION}" \
  --no-cli-pager

echo ""
echo "✓ Secret ${SECRET_ID} updated successfully."
echo ""
echo "IMPORTANT: Review the values above and replace any 'REPLACE_ME' placeholders"
echo "with actual values from your DO App Platform environment or Manus secrets panel."
echo ""
echo "Keys that need real values:"
echo "${SECRET_JSON}" | python3 -c "
import sys, json
d = json.load(sys.stdin)
for k, v in d.items():
    if v == 'REPLACE_ME':
        print(f'  - {k}')
"
