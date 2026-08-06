#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# AC3 C2 Services Deployment Script
# Deploys Caldera and GoPhish as internal-only ECS Fargate services
# with CloudMap service discovery for internal DNS resolution.
#
# Prerequisites:
#   - AWS CLI configured with valid credentials (PowerUserAccess)
#   - Target VPC, subnets, and ECS cluster already exist
#   - CALDERA_API_KEY and GOPHISH_API_KEY set in environment or passed as args
#
# Usage:
#   ./deploy-c2-services.sh [--caldera-key KEY] [--gophish-key KEY]
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ─── Configuration ────────────────────────────────────────────────────────────
REGION="${AWS_REGION:-us-east-1}"
PROJECT="ac3"
ENV="dev"
STACK_NAME="${PROJECT}-${ENV}-c2-services"

# Parse arguments
CALDERA_API_KEY="${CALDERA_API_KEY:-}"
GOPHISH_ADMIN_PASSWORD="${GOPHISH_ADMIN_PASSWORD:-}"

while [[ $# -gt 0 ]]; do
  case $1 in
    --caldera-key) CALDERA_API_KEY="$2"; shift 2 ;;
    --gophish-password) GOPHISH_ADMIN_PASSWORD="$2"; shift 2 ;;
    --region) REGION="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

# ─── Discover existing infrastructure ────────────────────────────────────────
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  AC3 C2 Services Deployment                                 ║"
echo "║  Stack: ${STACK_NAME}                                       ║"
echo "║  Region: ${REGION}                                          ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

echo "→ Discovering existing infrastructure..."

# Get VPC ID
VPC_ID=$(aws ec2 describe-vpcs --region "$REGION" \
  --filters "Name=tag:Name,Values=*${PROJECT}*${ENV}*" \
  --query "Vpcs[0].VpcId" --output text 2>/dev/null || echo "")

if [ -z "$VPC_ID" ] || [ "$VPC_ID" = "None" ]; then
  # Try by tag project
  VPC_ID=$(aws ec2 describe-vpcs --region "$REGION" \
    --filters "Name=tag:project,Values=${PROJECT}" \
    --query "Vpcs[0].VpcId" --output text 2>/dev/null || echo "")
fi

if [ -z "$VPC_ID" ] || [ "$VPC_ID" = "None" ]; then
  echo "ERROR: Could not find VPC for ${PROJECT}-${ENV}. Please check VPC tags."
  exit 1
fi
echo "  VPC: ${VPC_ID}"

# Get C2 subnets
C2_SUBNETS=$(aws ec2 describe-subnets --region "$REGION" \
  --filters "Name=vpc-id,Values=${VPC_ID}" "Name=tag:Name,Values=*c2*" \
  --query "Subnets[*].SubnetId" --output text 2>/dev/null || echo "")

if [ -z "$C2_SUBNETS" ]; then
  echo "ERROR: No C2 subnets found. Looking for subnets tagged with 'c2'."
  echo "  Available subnets:"
  aws ec2 describe-subnets --region "$REGION" \
    --filters "Name=vpc-id,Values=${VPC_ID}" \
    --query "Subnets[*].[SubnetId,Tags[?Key=='Name'].Value|[0]]" --output table
  exit 1
fi

C2_SUBNET_A=$(echo "$C2_SUBNETS" | awk '{print $1}')
C2_SUBNET_B=$(echo "$C2_SUBNETS" | awk '{print $2}')
echo "  C2 Subnet A: ${C2_SUBNET_A}"
echo "  C2 Subnet B: ${C2_SUBNET_B:-'(single AZ)'}"

# Get App security group (for inbound API access)
APP_SG=$(aws ec2 describe-security-groups --region "$REGION" \
  --filters "Name=vpc-id,Values=${VPC_ID}" "Name=tag:Name,Values=*${PROJECT}*${ENV}*app*" \
  --query "SecurityGroups[0].GroupId" --output text 2>/dev/null || echo "")

if [ -z "$APP_SG" ] || [ "$APP_SG" = "None" ]; then
  # Fallback: look for the ECS service's security group
  APP_SG=$(aws ec2 describe-security-groups --region "$REGION" \
    --filters "Name=vpc-id,Values=${VPC_ID}" "Name=group-name,Values=*${PROJECT}*ecs*" \
    --query "SecurityGroups[0].GroupId" --output text 2>/dev/null || echo "")
fi

if [ -z "$APP_SG" ] || [ "$APP_SG" = "None" ]; then
  echo "WARNING: Could not find App security group. Using VPC default."
  APP_SG=$(aws ec2 describe-security-groups --region "$REGION" \
    --filters "Name=vpc-id,Values=${VPC_ID}" "Name=group-name,Values=default" \
    --query "SecurityGroups[0].GroupId" --output text)
fi
echo "  App SG: ${APP_SG}"

# Get ECS cluster ARN
CLUSTER_ARN=$(aws ecs describe-clusters --region "$REGION" \
  --clusters "${PROJECT}-${ENV}" \
  --query "clusters[0].clusterArn" --output text 2>/dev/null || echo "")

if [ -z "$CLUSTER_ARN" ] || [ "$CLUSTER_ARN" = "None" ]; then
  echo "ERROR: ECS cluster '${PROJECT}-${ENV}' not found."
  exit 1
fi
echo "  ECS Cluster: ${CLUSTER_ARN}"

# Get execution role ARN
EXEC_ROLE_ARN=$(aws iam get-role --role-name "ecsTaskExecutionRole" \
  --query "Role.Arn" --output text 2>/dev/null || echo "")

if [ -z "$EXEC_ROLE_ARN" ] || [ "$EXEC_ROLE_ARN" = "None" ]; then
  EXEC_ROLE_ARN=$(aws iam get-role --role-name "${PROJECT}-${ENV}-ecs-execution-role" \
    --query "Role.Arn" --output text 2>/dev/null || echo "")
fi

if [ -z "$EXEC_ROLE_ARN" ] || [ "$EXEC_ROLE_ARN" = "None" ]; then
  echo "ERROR: Could not find ECS task execution role."
  exit 1
fi
echo "  Execution Role: ${EXEC_ROLE_ARN}"

echo ""
echo "→ Deploying CloudFormation stack: ${STACK_NAME}..."

# ─── Deploy CloudFormation ────────────────────────────────────────────────────
TEMPLATE_FILE="$(dirname "$0")/ac3-c2-services.yaml"

if [ ! -f "$TEMPLATE_FILE" ]; then
  echo "ERROR: Template file not found: ${TEMPLATE_FILE}"
  exit 1
fi

# Build parameters
PARAMS="ParameterKey=VpcId,ParameterValue=${VPC_ID}"
PARAMS="${PARAMS} ParameterKey=C2SubnetA,ParameterValue=${C2_SUBNET_A}"
PARAMS="${PARAMS} ParameterKey=C2SubnetB,ParameterValue=${C2_SUBNET_B:-${C2_SUBNET_A}}"
PARAMS="${PARAMS} ParameterKey=AppSecurityGroupId,ParameterValue=${APP_SG}"
PARAMS="${PARAMS} ParameterKey=EcsClusterArn,ParameterValue=${CLUSTER_ARN}"
PARAMS="${PARAMS} ParameterKey=ExecutionRoleArn,ParameterValue=${EXEC_ROLE_ARN}"

if [ -n "$CALDERA_API_KEY" ]; then
  PARAMS="${PARAMS} ParameterKey=CalderaApiKey,ParameterValue=${CALDERA_API_KEY}"
fi

if [ -n "$GOPHISH_ADMIN_PASSWORD" ]; then
  PARAMS="${PARAMS} ParameterKey=GophishAdminPassword,ParameterValue=${GOPHISH_ADMIN_PASSWORD}"
fi

# Check if stack exists
STACK_STATUS=$(aws cloudformation describe-stacks --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --query "Stacks[0].StackStatus" --output text 2>/dev/null || echo "DOES_NOT_EXIST")

if [ "$STACK_STATUS" = "DOES_NOT_EXIST" ]; then
  echo "  Creating new stack..."
  aws cloudformation create-stack --region "$REGION" \
    --stack-name "$STACK_NAME" \
    --template-body "file://${TEMPLATE_FILE}" \
    --parameters $PARAMS \
    --capabilities CAPABILITY_NAMED_IAM \
    --tags "Key=project,Value=${PROJECT}" "Key=environment,Value=${ENV}" "Key=purpose,Value=c2-services"

  echo "  Waiting for stack creation..."
  aws cloudformation wait stack-create-complete --region "$REGION" --stack-name "$STACK_NAME"
else
  echo "  Updating existing stack (current status: ${STACK_STATUS})..."
  aws cloudformation update-stack --region "$REGION" \
    --stack-name "$STACK_NAME" \
    --template-body "file://${TEMPLATE_FILE}" \
    --parameters $PARAMS \
    --capabilities CAPABILITY_NAMED_IAM 2>/dev/null || {
    echo "  No updates needed (stack is already up to date)."
  }

  echo "  Waiting for stack update..."
  aws cloudformation wait stack-update-complete --region "$REGION" --stack-name "$STACK_NAME" 2>/dev/null || true
fi

# ─── Get outputs ──────────────────────────────────────────────────────────────
echo ""
echo "→ Retrieving stack outputs..."

CALDERA_DNS=$(aws cloudformation describe-stacks --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --query "Stacks[0].Outputs[?OutputKey=='CalderaApiEndpoint'].OutputValue" --output text)

GOPHISH_DNS=$(aws cloudformation describe-stacks --region "$REGION" \
  --stack-name "$STACK_NAME" \
  --query "Stacks[0].Outputs[?OutputKey=='GophishApiEndpoint'].OutputValue" --output text)

echo ""
echo "╔══════════════════════════════════════════════════════════════╗"
echo "║  ✅ DEPLOYMENT COMPLETE                                     ║"
echo "╠══════════════════════════════════════════════════════════════╣"
echo "║  Caldera API: ${CALDERA_DNS}"
echo "║  GoPhish API: ${GOPHISH_DNS}"
echo "║                                                             ║"
echo "║  Internal DNS:                                              ║"
echo "║    caldera.ac3-dev.local:8888                                ║"
echo "║    gophish.ac3-dev.local:3333                                ║"
echo "║                                                             ║"
echo "║  Next Steps:                                                ║"
echo "║  1. Update CALDERA_BASE_URL in AC3 app secrets             ║"
echo "║  2. Update GOPHISH_BASE_URL in AC3 app secrets             ║"
echo "║  3. Redeploy AC3 app to pick up new env vars               ║"
echo "║  4. Verify health: curl ${CALDERA_DNS}/api/v2/health       ║"
echo "╚══════════════════════════════════════════════════════════════╝"

# ─── Wait for services to stabilize ──────────────────────────────────────────
echo ""
echo "→ Waiting for ECS services to reach RUNNING state..."

aws ecs wait services-stable --region "$REGION" \
  --cluster "${PROJECT}-${ENV}" \
  --services "${PROJECT}-${ENV}-caldera" "${PROJECT}-${ENV}-gophish" \
  --timeout 300 2>/dev/null && {
  echo "  ✅ Both services are stable and running!"
} || {
  echo "  ⚠️  Services may still be starting. Check ECS console for status."
  echo "     aws ecs describe-services --cluster ${PROJECT}-${ENV} --services ${PROJECT}-${ENV}-caldera ${PROJECT}-${ENV}-gophish --region ${REGION}"
}
