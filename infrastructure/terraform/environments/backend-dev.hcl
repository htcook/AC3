# Terraform backend config — dev environment
bucket         = "ac3-terraform-state"
key            = "dev/terraform.tfstate"
region         = "us-east-1"
dynamodb_table = "ac3-terraform-locks"
encrypt        = true
