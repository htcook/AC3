# Terraform backend config — prod environment
bucket         = "ac3-terraform-state"
key            = "prod/terraform.tfstate"
region         = "us-east-1"
dynamodb_table = "ac3-terraform-locks"
encrypt        = true
