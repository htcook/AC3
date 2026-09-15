# AC3-Plus isolated Dev sandbox.
#
# Protection boundary: ac3.aceofcloud.io is served by ac3-dev-app, which is a
# reference service and is never imported, changed, replaced, or destroyed here.
# This configuration creates only ac3-plus-dev-sandbox-platform-* resources.

aws_region               = "us-east-1"
aws_account_id           = "808038814732"
environment              = "dev-sandbox"
github_repository        = "aceofcloud/AC3-Plus"
github_environment_name  = "ac3-plus-dev-sandbox"
github_oidc_provider_arn = "arn:aws:iam::808038814732:oidc-provider/token.actions.githubusercontent.com"
state_bucket_name        = "ac3-plus-dev-sandbox-tfstate-808038814732"

ecs_cluster_name      = "ac3-dev"
vpc_id                = "vpc-00ec183680e6a74ef"
private_subnet_ids    = ["subnet-00d25f8e4a7dcab53"]
assign_public_ip      = false
alb_security_group_id = "sg-063ffbb6c46c3aaca"
https_listener_arn    = "arn:aws:elasticloadbalancing:us-east-1:808038814732:listener/app/ac3-dev-alb/186065a622039a31/bf69f34a459d11cd"

# Priority 100 is unused on the Dev HTTPS listener as of 2026-09-15.
listener_rule_priority = 100
host_names             = ["ac3-plus-dev.aceofcloud.io"]

# Bootstrap intentionally does not create or touch a service. CI supplies an
# immutable image plus the two existing secret ARNs before turning this on.
deploy_service = false

log_retention_days = 30

tags = {
  ReferenceServiceProtected = "ac3-dev-app"
  ChangeBoundary            = "ac3-plus-dev-sandbox-only"
}
