#!/bin/bash
# Run the Caldera seeding task as a one-shot ECS Fargate task
# Usage: ./run-seed-task.sh [--caldera-key KEY]
#
# Prerequisites:
# - AWS CLI configured with appropriate credentials
# - ac3-dev ECS cluster running
# - Caldera service running at caldera.ac3-dev.local:8888
# - Latest AC3 Docker image in ECR

set -euo pipefail

REGION="us-east-1"
CLUSTER="ac3-dev"
CALDERA_KEY="${CALDERA_API_KEY:-}"

# Parse args
while [[ $# -gt 0 ]]; do
  case $1 in
    --caldera-key) CALDERA_KEY="$2"; shift 2 ;;
    *) echo "Unknown option: $1"; exit 1 ;;
  esac
done

if [ -z "$CALDERA_KEY" ]; then
  echo "ERROR: CALDERA_API_KEY not set. Use --caldera-key or export CALDERA_API_KEY"
  exit 1
fi

echo "=== Discovering infrastructure ==="

# Get VPC and subnets (C2 subnets for internal access)
VPC_ID=$(aws ec2 describe-vpcs --region $REGION \
  --filters "Name=tag:Name,Values=*ac3*" \
  --query "Vpcs[0].VpcId" --output text 2>/dev/null || echo "")

if [ -z "$VPC_ID" ] || [ "$VPC_ID" = "None" ]; then
  VPC_ID=$(aws ec2 describe-vpcs --region $REGION \
    --query "Vpcs[?Tags[?contains(Value,'ac3')]].VpcId | [0]" --output text)
fi

# Use C2 subnets (same network as Caldera)
C2_SUBNETS=$(aws ec2 describe-subnets --region $REGION \
  --filters "Name=vpc-id,Values=$VPC_ID" "Name=tag:Name,Values=*c2*" \
  --query "Subnets[].SubnetId" --output text | tr '\t' ',')

if [ -z "$C2_SUBNETS" ]; then
  echo "ERROR: No C2 subnets found. Using app subnets instead."
  C2_SUBNETS=$(aws ec2 describe-subnets --region $REGION \
    --filters "Name=vpc-id,Values=$VPC_ID" "Name=tag:Name,Values=*app*" \
    --query "Subnets[].SubnetId" --output text | tr '\t' ',')
fi

# Get the app security group (needs DB access)
APP_SG=$(aws ec2 describe-security-groups --region $REGION \
  --filters "Name=vpc-id,Values=$VPC_ID" "Name=tag:Name,Values=*app*" \
  --query "SecurityGroups[0].GroupId" --output text)

echo "VPC: $VPC_ID"
echo "Subnets: $C2_SUBNETS"
echo "Security Group: $APP_SG"

echo ""
echo "=== Creating log group ==="
aws logs create-log-group --log-group-name /ecs/ac3-dev-caldera-seed --region $REGION 2>/dev/null || true

echo ""
echo "=== Updating task definition with Caldera API key ==="
TASK_DEF=$(cat "$(dirname "$0")/seed-task-definition.json" | \
  sed "s|REPLACE_WITH_CALDERA_API_KEY|$CALDERA_KEY|g")

# Register the task definition
echo "$TASK_DEF" > /tmp/seed-task-def.json
TASK_ARN=$(aws ecs register-task-definition --region $REGION \
  --cli-input-json file:///tmp/seed-task-def.json \
  --query "taskDefinition.taskDefinitionArn" --output text)
rm -f /tmp/seed-task-def.json

echo "Task Definition: $TASK_ARN"

echo ""
echo "=== Running seed task ==="
TASK_RESULT=$(aws ecs run-task --region $REGION \
  --cluster $CLUSTER \
  --task-definition "$TASK_ARN" \
  --launch-type FARGATE \
  --network-configuration "awsvpcConfiguration={subnets=[$C2_SUBNETS],securityGroups=[$APP_SG],assignPublicIp=DISABLED}" \
  --overrides "{\"containerOverrides\":[{\"name\":\"caldera-seed\",\"environment\":[{\"name\":\"CALDERA_API_KEY\",\"value\":\"$CALDERA_KEY\"}]}]}" \
  --query "tasks[0].taskArn" --output text)

echo "Task ARN: $TASK_RESULT"
echo ""
echo "=== Seed task started! ==="
echo "Monitor with:"
echo "  aws ecs describe-tasks --cluster $CLUSTER --tasks $TASK_RESULT --region $REGION"
echo ""
echo "View logs:"
echo "  aws logs tail /ecs/ac3-dev-caldera-seed --region $REGION --follow"
