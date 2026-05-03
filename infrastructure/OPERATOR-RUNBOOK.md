# AC3 Platform — Operator Deployment Runbook

**Author:** Harrison Cook — AceofCloud  
**Date:** May 3, 2026  
**Classification:** Internal — Operations  
**Accounts:** Dev (808038814732) | SharedServices/ECR (890319879326)

---

## Overview

This runbook walks an operator through three deployment steps for the AC3 Caldera Dashboard. All commands are designed to be copy-pasted into a terminal with properly configured AWS credentials.

**Estimated time:** 30–45 minutes for all three steps.

| Step | Description | Account | Required Permissions |
|------|-------------|---------|---------------------|
| 0 | Pre-flight permission check | Dev (808038814732) | Read-only across all services |
| 1 | Populate Secrets Manager | Dev (808038814732) | `secretsmanager:*`, `kms:Encrypt/Decrypt` |
| 2 | Deploy ECS stack via CloudFormation | Dev (808038814732) | `cloudformation:*`, `ec2:*`, `ecs:*`, `elasticloadbalancing:*`, `logs:*`, `iam:PassRole` |
| 3 | Create staging IAM roles | Staging account | `iam:CreateRole`, `iam:CreatePolicy`, `iam:AttachRolePolicy`, `cloudformation:*` |

---

## Prerequisites

Before starting, ensure you have:

1. **AWS CLI v2** installed (`aws --version` should show 2.x)
2. **jq** installed (`jq --version`)
3. **Docker** installed (for building container images)
4. **Git** clone of the `caldera-dashboard` repository
5. **AWS SSO credentials** with sufficient permissions (see Step 0)

```bash
# Clone the repo (if not already done)
git clone git@github.com:AceofCloud/caldera-dashboard.git
cd caldera-dashboard
```

---

## Step 0: Pre-Flight Permission Check

Run this first to verify your AWS credentials have all required permissions.

```bash
# Authenticate via SSO (choose a permission set with PowerUserAccess + IAMFullAccess)
aws sso login --profile ac3-dev

# Or export temporary credentials from the SSO portal:
export AWS_ACCESS_KEY_ID="<your-access-key>"
export AWS_SECRET_ACCESS_KEY="<your-secret-key>"
export AWS_SESSION_TOKEN="<your-session-token>"
export AWS_DEFAULT_REGION="us-east-1"

# Verify identity
aws sts get-caller-identity

# Run the pre-flight check
./infrastructure/scripts/preflight-check.sh --env dev --verbose
```

**Expected output:** All checks should show green checkmarks. If any fail, the script prints exactly which permissions are missing and how to fix them.

**If the pre-flight check fails**, ask your IAM Identity Center administrator to either:
- Attach the `PowerUserAccess` AWS managed policy to your permission set
- Or add these specific actions to the inline policy: `ec2:Describe*`, `secretsmanager:*`, `cloudformation:*`, `ecs:*`, `ecr:*`, `logs:*`, `elasticloadbalancing:*`, `iam:CreateRole`, `iam:CreatePolicy`, `iam:AttachRolePolicy`, `iam:PassRole`, `kms:Decrypt`, `kms:DescribeKey`

---

## Step 1: Populate Dev Secrets in AWS Secrets Manager

This step creates all application secrets in Secrets Manager using the naming convention `ac3/dev/<SECRET_NAME>`.

### 1a. Prepare the .env.dev file

```bash
# Copy the template
cp infrastructure/scripts/.env.template .env.dev

# Edit the file — fill in actual values for your environment
# At minimum, these are REQUIRED for the app to start:
#
#   DATABASE_URL=mysql://<user>:<pass>@<host>:3306/<db>?ssl={"rejectUnauthorized":true}
#   JWT_SECRET=<random-64-char-string>
#   CALDERA_API_KEY=<your-caldera-api-key>
#   CALDERA_BASE_URL=<your-caldera-url>
#   SHODAN_API_KEY=<your-shodan-key>
#   OPENAI_API_KEY=<your-openai-key>
#
# Generate a strong JWT secret:
#   openssl rand -hex 32
#
nano .env.dev
```

### 1b. Dry-run to preview what will be created

```bash
./infrastructure/scripts/seed-secrets.sh \
  --env dev \
  --from-env-file .env.dev \
  --dry-run
```

This prints every secret that would be created without actually writing to AWS. Review the output to confirm the naming and values are correct.

### 1c. Seed the secrets

```bash
# Without KMS (uses AWS-managed key — fine for dev)
./infrastructure/scripts/seed-secrets.sh \
  --env dev \
  --from-env-file .env.dev

# With KMS encryption (recommended for staging/prod)
./infrastructure/scripts/seed-secrets.sh \
  --env dev \
  --from-env-file .env.dev \
  --kms-key "arn:aws:kms:us-east-1:890319879326:key/8e215533-9e88-4cae-b514-93a892e6e6c8"
```

### 1d. Verify the secrets were created

```bash
./infrastructure/scripts/seed-secrets.sh --env dev --verify
```

**Expected output:** Each secret shows a green checkmark with its last-modified date.

### 1e. (Alternative) Interactive mode

If you prefer to enter secrets one-by-one with prompts:

```bash
./infrastructure/scripts/seed-secrets.sh --env dev --interactive
```

### 1f. List all expected secrets

```bash
./infrastructure/scripts/seed-secrets.sh --env dev --list
```

---

## Step 2: Deploy Dev ECS Stack via CloudFormation

This step creates the full ECS Fargate environment: cluster, task definition, service, ALB, security groups, auto-scaling, and CloudWatch logs.

### 2a. Build and push the Docker image to ECR

```bash
# Authenticate to the cross-account ECR (SharedServices: 890319879326)
aws ecr get-login-password --region us-east-1 | \
  docker login --username AWS --password-stdin \
  890319879326.dkr.ecr.us-east-1.amazonaws.com

# Build the image using the AWS-optimized Dockerfile
docker build -f Dockerfile.aws -t ac3-caldera-dashboard:latest .

# Tag for ECR
docker tag ac3-caldera-dashboard:latest \
  890319879326.dkr.ecr.us-east-1.amazonaws.com/ace-c3/caldera-dashboard:latest

docker tag ac3-caldera-dashboard:latest \
  890319879326.dkr.ecr.us-east-1.amazonaws.com/ace-c3/caldera-dashboard:dev-$(git rev-parse --short HEAD)

# Push both tags
docker push 890319879326.dkr.ecr.us-east-1.amazonaws.com/ace-c3/caldera-dashboard:latest
docker push 890319879326.dkr.ecr.us-east-1.amazonaws.com/ace-c3/caldera-dashboard:dev-$(git rev-parse --short HEAD)

# Verify the image is in ECR
aws ecr describe-images \
  --registry-id 890319879326 \
  --repository-name ace-c3/caldera-dashboard \
  --region us-east-1 \
  --query 'imageDetails | sort_by(@, &imagePushedAt) | [-3:].[imageTags[0], imageSizeInBytes, imagePushedAt]' \
  --output table
```

### 2b. Deploy with VPC auto-discovery

```bash
# Auto-discover VPC by Name tag (looks for "ac3-dev" by default)
./infrastructure/scripts/cfn-deploy-dev.sh --auto-discover

# Or specify a different VPC name
./infrastructure/scripts/cfn-deploy-dev.sh --auto-discover --vpc-name "my-vpc-name"
```

### 2c. Deploy with explicit VPC/subnet IDs

If auto-discovery doesn't find your VPC, or you want to specify exact subnets:

```bash
# First, find your VPC and subnets
aws ec2 describe-vpcs --region us-east-1 \
  --query 'Vpcs[*].{VpcId:VpcId,Name:Tags[?Key==`Name`].Value|[0],Cidr:CidrBlock}' \
  --output table

aws ec2 describe-subnets --region us-east-1 \
  --filters "Name=vpc-id,Values=<YOUR_VPC_ID>" \
  --query 'Subnets[*].{SubnetId:SubnetId,AZ:AvailabilityZone,Cidr:CidrBlock,Name:Tags[?Key==`Name`].Value|[0],Public:MapPublicIpOnLaunch}' \
  --output table

# Then deploy with explicit IDs
./infrastructure/scripts/cfn-deploy-dev.sh \
  --vpc-id vpc-XXXXXXXX \
  --private-subnets subnet-AAAA,subnet-BBBB \
  --public-subnets subnet-CCCC,subnet-DDDD \
  --secrets-arn-prefix "arn:aws:secretsmanager:us-east-1:808038814732:secret:ac3/dev/"
```

### 2d. Deploy with all options

```bash
./infrastructure/scripts/cfn-deploy-dev.sh \
  --vpc-id vpc-XXXXXXXX \
  --private-subnets subnet-AAAA,subnet-BBBB \
  --public-subnets subnet-CCCC,subnet-DDDD \
  --image-tag "dev-$(git rev-parse --short HEAD)" \
  --secrets-arn-prefix "arn:aws:secretsmanager:us-east-1:808038814732:secret:ac3/dev/" \
  --database-url "mysql://user:pass@host:3306/ac3_dev?ssl={\"rejectUnauthorized\":true}" \
  --jwt-secret "$(openssl rand -hex 32)"
```

### 2e. Verify the deployment

The deploy script automatically runs a health check against `/api/health`. If it passes, you'll see a green confirmation. If it fails:

```bash
# Check ECS service status
aws ecs describe-services \
  --cluster ac3-dev \
  --services ac3-dev-service \
  --region us-east-1 \
  --query 'services[0].{Status:status,Running:runningCount,Desired:desiredCount,Events:events[:3]}' \
  --output json

# Check CloudWatch logs
./infrastructure/scripts/ecs-logs.sh --cluster ac3-dev --service ac3-dev-service --lines 50

# Check ALB target health
ALB_TG=$(aws cloudformation describe-stacks \
  --stack-name ac3-dev \
  --region us-east-1 \
  --query 'Stacks[0].Outputs[?OutputKey==`TargetGroupArn`].OutputValue' \
  --output text)
aws elbv2 describe-target-health --target-group-arn "$ALB_TG" --region us-east-1

# Get the ALB URL
aws cloudformation describe-stacks \
  --stack-name ac3-dev \
  --region us-east-1 \
  --query 'Stacks[0].Outputs[?OutputKey==`AlbDnsName`].OutputValue' \
  --output text

# Test the health endpoint
ALB_DNS=$(aws cloudformation describe-stacks \
  --stack-name ac3-dev \
  --region us-east-1 \
  --query 'Stacks[0].Outputs[?OutputKey==`AlbDnsName`].OutputValue' \
  --output text)
curl -s "http://${ALB_DNS}/api/health" | jq .

# Interactive shell into a running container (for debugging)
./infrastructure/scripts/ecs-exec.sh --cluster ac3-dev --service ac3-dev-service
```

### 2f. Force a new deployment (after image update)

```bash
aws ecs update-service \
  --cluster ac3-dev \
  --service ac3-dev-service \
  --force-new-deployment \
  --region us-east-1
```

---

## Step 3: Create Staging IAM Roles

This step creates the ECS execution role and application task role in the staging account, matching the role structure already provisioned in dev.

### 3a. Switch to the staging account

```bash
# If using SSO, switch to the staging account profile
aws sso login --profile ac3-staging

# Or export staging account credentials
export AWS_ACCESS_KEY_ID="<staging-access-key>"
export AWS_SECRET_ACCESS_KEY="<staging-secret-key>"
export AWS_SESSION_TOKEN="<staging-session-token>"

# Verify you're in the correct account
aws sts get-caller-identity
# Expected: Account should be the staging account ID (NOT 808038814732)
```

### 3b. Validate the CloudFormation template

```bash
aws cloudformation validate-template \
  --template-body file://infrastructure/cloudformation/ac3-staging-iam-roles.yaml \
  --region us-east-1
```

### 3c. Deploy the staging IAM roles

```bash
aws cloudformation deploy \
  --template-file infrastructure/cloudformation/ac3-staging-iam-roles.yaml \
  --stack-name ac3-staging-iam-roles \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    Environment=staging \
    ProjectName=ac3 \
    EcrAccountId=890319879326 \
    EcrRepositoryName=ace-c3/caldera-dashboard \
    EcrKmsKeyArn="arn:aws:kms:us-east-1:890319879326:key/8e215533-9e88-4cae-b514-93a892e6e6c8" \
  --region us-east-1 \
  --tags \
    Key=Project,Value=ac3 \
    Key=Environment,Value=staging \
    Key=ManagedBy,Value=cloudformation
```

### 3d. Retrieve the role ARNs from the stack outputs

```bash
# Get the execution role ARN
aws cloudformation describe-stacks \
  --stack-name ac3-staging-iam-roles \
  --region us-east-1 \
  --query 'Stacks[0].Outputs[?OutputKey==`ExecutionRoleArn`].OutputValue' \
  --output text

# Get the task role ARN
aws cloudformation describe-stacks \
  --stack-name ac3-staging-iam-roles \
  --region us-east-1 \
  --query 'Stacks[0].Outputs[?OutputKey==`TaskRoleArn`].OutputValue' \
  --output text

# Get the ready-to-paste tfvars snippet
aws cloudformation describe-stacks \
  --stack-name ac3-staging-iam-roles \
  --region us-east-1 \
  --query 'Stacks[0].Outputs[?OutputKey==`TfvarsSnippet`].OutputValue' \
  --output text
```

### 3e. Update staging.tfvars with the actual role ARNs

Open `infrastructure/terraform/environments/staging.tfvars` and replace the placeholder lines:

```hcl
# BEFORE (placeholders):
external_execution_role_arn = ""
external_task_role_arn      = ""

# AFTER (paste the ARNs from step 3d):
external_execution_role_arn = "arn:aws:iam::<STAGING_ACCOUNT_ID>:role/ac3-staging-ecs-execution-role"
external_task_role_arn      = "arn:aws:iam::<STAGING_ACCOUNT_ID>:role/ac3-staging-app-task-role"
```

### 3f. (Optional) Create prod IAM roles

The same template works for production — just change the `Environment` parameter:

```bash
# Switch to prod account credentials first, then:
aws cloudformation deploy \
  --template-file infrastructure/cloudformation/ac3-staging-iam-roles.yaml \
  --stack-name ac3-prod-iam-roles \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameter-overrides \
    Environment=prod \
    ProjectName=ac3 \
    EcrAccountId=890319879326 \
    EcrRepositoryName=ace-c3/caldera-dashboard \
    EcrKmsKeyArn="arn:aws:kms:us-east-1:890319879326:key/8e215533-9e88-4cae-b514-93a892e6e6c8" \
  --region us-east-1
```

---

## Post-Deployment Checklist

After completing all three steps, verify the following:

| Check | Command | Expected |
|-------|---------|----------|
| Secrets exist | `./infrastructure/scripts/seed-secrets.sh --env dev --verify` | All green checkmarks |
| ECS service running | `aws ecs describe-services --cluster ac3-dev --services ac3-dev-service --query 'services[0].runningCount'` | `>= 1` |
| ALB health check | `curl -s http://<ALB_DNS>/api/health` | `{"status":"ok"}` |
| Staging roles exist | `aws iam get-role --role-name ac3-staging-ecs-execution-role` | Role details |
| staging.tfvars updated | `grep external_execution_role_arn infrastructure/terraform/environments/staging.tfvars` | Non-empty ARN |

---

## Rollback Procedures

### Rollback Secrets Manager

```bash
# List all AC3 dev secrets
aws secretsmanager list-secrets \
  --region us-east-1 \
  --filters Key=name,Values=ac3/dev/ \
  --query 'SecretList[*].Name' \
  --output text

# Delete a specific secret (with recovery window)
aws secretsmanager delete-secret \
  --secret-id "ac3/dev/DATABASE_URL" \
  --recovery-window-in-days 7 \
  --region us-east-1

# Force-delete without recovery (DESTRUCTIVE)
aws secretsmanager delete-secret \
  --secret-id "ac3/dev/DATABASE_URL" \
  --force-delete-without-recovery \
  --region us-east-1
```

### Rollback CloudFormation Stack

```bash
# Delete the entire ECS stack
aws cloudformation delete-stack --stack-name ac3-dev --region us-east-1

# Watch deletion progress
aws cloudformation wait stack-delete-complete --stack-name ac3-dev --region us-east-1
```

### Rollback Staging IAM Roles

```bash
# Delete the staging IAM roles stack
aws cloudformation delete-stack --stack-name ac3-staging-iam-roles --region us-east-1
aws cloudformation wait stack-delete-complete --stack-name ac3-staging-iam-roles --region us-east-1
```

---

## Troubleshooting

### "No VPC found with Name tag ac3-dev"

The VPC hasn't been created yet, or it has a different Name tag. Either:
- Create the VPC via Terraform: `cd infrastructure/terraform && terraform apply -var-file=environments/dev.tfvars`
- Or use `--vpc-id` and `--private-subnets`/`--public-subnets` to specify existing VPC resources

### "Task stopped: Essential container exited"

The application crashed on startup. Common causes:
1. **Missing DATABASE_URL** — ensure the secret exists in Secrets Manager
2. **Database unreachable** — check security group rules allow ECS → RDS
3. **Invalid JWT_SECRET** — ensure it's a valid string, not empty

Debug with:
```bash
./infrastructure/scripts/ecs-logs.sh --cluster ac3-dev --service ac3-dev-service --lines 100
```

### "Cross-account ECR pull failed"

The execution role needs `ecr:BatchGetImage` on the SharedServices ECR repo, and the ECR repo needs a resource-based policy allowing the dev account. Verify:
```bash
aws ecr get-repository-policy \
  --registry-id 890319879326 \
  --repository-name ace-c3/caldera-dashboard \
  --region us-east-1
```

### "KMS AccessDeniedException"

The execution role needs `kms:Decrypt` on the ECR KMS key. The key policy in SharedServices must allow the dev account's execution role. Verify:
```bash
aws kms describe-key \
  --key-id "arn:aws:kms:us-east-1:890319879326:key/8e215533-9e88-4cae-b514-93a892e6e6c8" \
  --region us-east-1
```

---

## File Reference

| File | Purpose |
|------|---------|
| `infrastructure/scripts/preflight-check.sh` | Validates AWS permissions before deployment |
| `infrastructure/scripts/seed-secrets.sh` | Populates Secrets Manager with application secrets |
| `infrastructure/scripts/.env.template` | Template for all secret values |
| `infrastructure/scripts/cfn-deploy-dev.sh` | Deploys ECS stack via CloudFormation (dev) |
| `infrastructure/scripts/cfn-deploy-staging.sh` | Deploys ECS stack via CloudFormation (staging) |
| `infrastructure/scripts/deploy-dev.sh` | Manual ECR push + ECS force-deploy |
| `infrastructure/scripts/ecs-exec.sh` | Interactive shell into running containers |
| `infrastructure/scripts/ecs-logs.sh` | Tail CloudWatch logs for ECS service |
| `infrastructure/cloudformation/ac3-dev-ecs.yaml` | CloudFormation template for full ECS environment |
| `infrastructure/cloudformation/ac3-staging-iam-roles.yaml` | CloudFormation template for staging/prod IAM roles |
| `infrastructure/terraform/environments/dev.tfvars` | Terraform variables for dev (with actual role ARNs) |
| `infrastructure/terraform/environments/staging.tfvars` | Terraform variables for staging (update after Step 3) |
| `infrastructure/terraform/environments/prod.tfvars` | Terraform variables for prod (update after Step 3f) |
