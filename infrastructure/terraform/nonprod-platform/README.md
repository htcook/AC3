# AC3-Plus non-production platform deployment

**Purpose.** This Terraform root module deploys an isolated AC3-Plus platform sandbox into the existing Dev or Staging AWS account. It exists to test code changes and troubleshoot the platform without changing the existing Dev reference platform or production.

> **Hard protection boundary:** `ac3.aceofcloud.io` is served by Dev service `ac3-dev-app`. This module does not import, reference as a managed resource, replace, update, scale, or destroy that service. It creates only resources whose names begin with `ac3-plus-dev-sandbox-platform-sandbox` or `ac3-plus-staging-platform-sandbox`.

The module uses an existing ECS cluster, ALB, HTTPS listener, VPC, and subnets. It creates a separate ECR repository, IAM runtime roles, security group, CloudWatch log group, target group, host-header listener rule, task definition, and ECS service. The initial bootstrap runs with `deploy_service=false`, so it does not start an application task. The deployment workflow builds an immutable `sha-<commit>` image and is the only normal path that enables the sandbox service.

## What the current AWS inventory confirms

Production runs a multi-service ECS build. The active private platform service is `ac3-production-platform-private` on task definition revision 26, using a scanned immutable `ac3-plus/platform` image. The production service is outside this module’s scope.

Dev has the protected reference service `ac3-dev-app`, which is healthy with one task on revision 303 and fronts `ac3.aceofcloud.io`. The Dev account also has the existing `ac3-dev` cluster, `ac3-dev-alb`, and an HTTPS listener with priority 100 available. The sandbox will use a different service name and a new host rule at that priority.

Staging has `ac3-staging` and `ac3-staging-alb`; its existing `ac3-staging-app` service is currently scaled to zero. The staging sandbox uses a separate service and an unused HTTPS listener priority of 100. The existing Staging service currently assigns public IPs, so the staging sandbox preserves that network posture until private-subnet egress is verified.

| Target | AWS account | Existing reference workload | New sandbox service | Host rule | State bucket |
| --- | --- | --- | --- | --- | --- |
| Dev sandbox | `808038814732` | `ac3-dev-app` (**protected**) | `ac3-plus-dev-sandbox-platform-sandbox` | `ac3-plus-dev.aceofcloud.io` | `ac3-plus-dev-sandbox-tfstate-808038814732` |
| Staging | `238043187472` | `ac3-staging-app` (unmanaged) | `ac3-plus-staging-platform-sandbox` | `ac3-plus-staging.aceofcloud.io` | `ac3-plus-staging-tfstate-238043187472` |

## Bootstrap each environment once

Bootstrap must occur in the target account using an administrator or AWS Identity Center session that is allowed to create IAM roles and the state bucket. The existing configured Dev and Staging PowerUser sessions are appropriate for an interactive plan, but OIDC provider discovery is denied, so confirm the account-global provider exists with an administrator before the first apply.

First create the dedicated state bucket. This command has no remote Terraform backend because it creates the backend itself.

```bash
cd infrastructure/terraform/bootstrap
terraform init
terraform apply -var-file=environments/dev-sandbox.tfvars
# Repeat with environments/staging.tfvars in the Staging account.
```

Then initialize this module with the new backend and create **only prerequisites**. Do not set `deploy_service=true` during this step.

```bash
cd ../nonprod-platform
terraform init -reconfigure -backend-config=environments/backend-dev-sandbox.hcl
terraform plan -var-file=environments/dev-sandbox.tfvars -var='deploy_service=false'
terraform apply -var-file=environments/dev-sandbox.tfvars -var='deploy_service=false'
```

The apply creates the environment-scoped GitHub role. Its trust policy accepts only the GitHub Environment named in the relevant `.tfvars` file and only OIDC subject `repo:aceofcloud/AC3-Plus:environment:<environment>`. If the source repository has a different owner or name, change `github_repository` **before** the first apply.

The account must already have the GitHub Actions OIDC provider at `arn:aws:iam::<account-id>:oidc-provider/token.actions.githubusercontent.com`. This module deliberately does not create or own it because it is global to the AWS account.

## Configure the GitHub repository

Create two GitHub Environments in **`aceofcloud/AC3-Plus`**. Require review for `ac3-plus-staging`; Dev sandbox review is optional. Add the following environment secrets to each. The deployment workflow never reads static AWS access keys.

| Secret | Required value |
| --- | --- |
| `AWS_TERRAFORM_DEPLOY_ROLE_ARN` | `github_deploy_role_arn` Terraform output for that environment |
| `TF_VAR_APP_SECRETS` | JSON map with pre-existing Secrets Manager ARNs, at minimum `DATABASE_URL` and `JWT_SECRET` |
| `TF_VAR_TASK_ROLE_POLICY_JSON` | Optional least-privilege policy for non-secret runtime integrations; use an empty string if none is needed |

A valid `TF_VAR_APP_SECRETS` value contains **ARNs only**, not secret values:

```json
{
  "DATABASE_URL": "arn:aws:secretsmanager:us-east-1:123456789012:secret:ac3-plus/dev-sandbox/database-url-xxxxx",
  "JWT_SECRET": "arn:aws:secretsmanager:us-east-1:123456789012:secret:ac3-plus/shared/jwt-secret-xxxxx"
}
```

Create the referenced secrets outside Terraform before the first deploy. The sandbox has no database or migration resources in its plan. That separation prevents troubleshooting deployments from changing data stores or executing schema migrations.

Copy `.github/workflows/ac3-plus-nonprod-deploy.yml` into the reachable `aceofcloud/AC3-Plus` repository. The configured GitHub credential could not read that repository on 2026-09-15, so this repository copy is a reviewed handoff artifact rather than an installed workflow.

## Deploy and test

Run **AC3-Plus Non-Production Deploy** with `deploy` and either `dev-sandbox` or `staging`. The workflow performs these steps in sequence:

1. It validates and initializes Terraform state through the environment-specific OIDC role.
2. It reads the sandbox-only ECR repository created at bootstrap.
3. It builds `platform/Dockerfile.aws` using `platform/` as the Docker build context.
4. It pushes `sha-<full Git commit>` to the immutable sandbox repository.
5. It applies Terraform with `deploy_service=true` and that exact image tag.
6. It waits for the new sandbox service and sends a host-header request to `/api/health` through the selected ALB.

The build does not write `latest`, force a deployment of `ac3-dev-app`, or touch `ac3-staging-app`. A failed ECS rollout uses the service circuit breaker and rolls back the sandbox service only.

DNS is intentionally not managed by this module. Before browser testing, create a DNS record for each sandbox hostname to its existing environment ALB. The existing TLS certificate must cover that hostname. Until DNS is present, the workflow’s health test uses ALB connection routing with the intended host header.

## Operational controls

Use the `plan` workflow action before modifying Terraform. It has no apply step. Use the `deploy` action only after the current source repository and GitHub Environment configuration are confirmed. Do not use `terraform destroy` for this module without a deliberate environment decommissioning decision, because it would remove the sandbox resources and host rule.

The Dev production-like reference service is explicitly excluded from both the Terraform resource graph and the OIDC role’s naming boundary. If a plan names `ac3-dev-app`, `ac3.aceofcloud.io`, a production account, an RDS resource, an existing target group, or a shared secret resource, stop and correct the configuration before applying.

## Known readiness items

The Dev state bucket is reachable and the legacy lock table exists. The Staging identity received `403` on the legacy shared state bucket, so this design uses a dedicated state bucket per account and Terraform’s S3 lockfile mechanism rather than relying on the inconsistent legacy DynamoDB configuration. The OIDC provider exists by convention in the supplied configuration, but the current PowerUser sessions are not allowed to inspect it. An administrator must verify it before the role bootstrap.

The accessible GitHub identity did not have visibility into `aceofcloud/AC3-Plus` or `hcook-aoc/AC3-Plus`; therefore, no workflow, branch, or repository environment has been created there. The workflow has been implemented and validated in the available `htcook/AC3` checkout as an installation-ready artifact.

## References

[1]: https://docs.aws.amazon.com/IAM/latest/UserGuide/id_roles_providers_create_oidc.html "Creating OpenID Connect identity providers"
[2]: https://docs.github.com/actions/security-for-github-actions/security-hardening-your-deployments/configuring-openid-connect-in-amazon-web-services "Configuring OpenID Connect in Amazon Web Services"
[3]: https://developer.hashicorp.com/terraform/language/settings/backends/s3 "Terraform S3 backend"
[4]: https://docs.aws.amazon.com/AmazonECS/latest/developerguide/deployment-circuit-breaker.html "Amazon ECS deployment circuit breaker"
