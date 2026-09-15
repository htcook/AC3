# AC3-Plus isolated Staging sandbox.
#
# This configuration creates only ac3-plus-staging-platform-sandbox-* resources.
# It does not manage the existing ac3-staging-app service, database, or target group.

aws_region               = "us-east-1"
aws_account_id           = "238043187472"
environment              = "staging"
github_repository        = "aceofcloud/AC3-Plus"
github_environment_name  = "ac3-plus-staging"
github_oidc_provider_arn = "arn:aws:iam::238043187472:oidc-provider/token.actions.githubusercontent.com"
state_bucket_name        = "ac3-plus-staging-tfstate-238043187472"

ecs_cluster_name   = "ac3-staging"
vpc_id             = "vpc-05aea7493fda4a2f4"
private_subnet_ids = ["subnet-0b13a6b3ffc4d628f", "subnet-082b9a4e851920dcb", "subnet-082a554ba4bcfb270"]
# This matches the existing staging service's networking posture. Review this
# setting when private-subnet NAT/VPC endpoint coverage is added.
assign_public_ip      = true
alb_security_group_id = "sg-0b7a518b27bb99465"
https_listener_arn    = "arn:aws:elasticloadbalancing:us-east-1:238043187472:listener/app/ac3-staging-alb/b352c70f5b7c409f/a669d5204778d325"

# Priority 100 is unused on the Staging HTTPS listener as of 2026-09-15.
listener_rule_priority = 100
host_names             = ["ac3-plus-staging.aceofcloud.io"]

deploy_service = false

log_retention_days = 30

tags = {
  ChangeBoundary = "ac3-plus-staging-sandbox-only"
}
