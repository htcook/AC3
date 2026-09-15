# Staging receives a dedicated state bucket. Do not point this state at the Dev
# account's bucket. Create this bucket with ../bootstrap before initializing this module.
bucket       = "ac3-plus-staging-tfstate-238043187472"
key          = "ac3-plus/nonprod-platform/staging/terraform.tfstate"
region       = "us-east-1"
use_lockfile = true
encrypt      = true
