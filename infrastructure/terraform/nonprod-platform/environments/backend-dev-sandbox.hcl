# Existing Dev remote state bucket. The Dev AWS identity has verified access.
bucket       = "ac3-terraform-state"
key          = "ac3-plus/nonprod-platform/dev-sandbox/terraform.tfstate"
region       = "us-east-1"
use_lockfile = true
encrypt      = true
