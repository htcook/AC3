# Terraform backend config — staging environment
bucket         = "ac3-terraform-state"
key            = "staging/terraform.tfstate"
region         = "us-east-1"
dynamodb_table = "ac3-terraform-locks"
encrypt        = true
