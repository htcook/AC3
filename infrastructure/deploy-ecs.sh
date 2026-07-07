#!/bin/bash
# ═══════════════════════════════════════════════════════════════════════════════
# AC3 Platform — ECS Fargate Deployment Script
# ═══════════════════════════════════════════════════════════════════════════════
# Prerequisites:
#   1. AWS CLI configured with credentials that have iam:PassRole permission
#   2. Docker image pushed to ECR (via GitHub Actions or manual build)
#   3. Secrets Manager secret ac3/dev/app populated with all env vars
#   4. Run: source /home/ubuntu/aws-env.sh (or configure AWS SSO)
# ═══════════════════════════════════════════════════════════════════════════════
set -euo pipefail

# ─── Configuration ───────────────────────────────────────────────────────────
REGION="us-east-1"
ACCOUNT_ID="808038814732"
CLUSTER="ac3-dev"
SERVICE_NAME="ac3-dev-app"
TASK_FAMILY="ac3-dev-app"
ECR_REPO="${ACCOUNT_ID}.dkr.ecr.${REGION}.amazonaws.com/ac3/caldera-dashboard"
IMAGE_TAG="${1:-latest}"

# Network
APP_SUBNETS="subnet-00d25f8e4a7dcab53,subnet-0dcde6160e4f644ac"  # ac3-dev-app-a, ac3-dev-app-b
APP_SG="sg-047e3a22d780b0911"                                     # ac3-dev-sg-app

# ALB
TARGET_GROUP_ARN="arn:aws:elasticloadbalancing:us-east-1:808038814732:targetgroup/ac3-dev-app-tg/258e8561a0cf2ce3"

# IAM
EXECUTION_ROLE="arn:aws:iam::${ACCOUNT_ID}:role/ac3-dev-ecs-execution-role"
TASK_ROLE="arn:aws:iam::${ACCOUNT_ID}:role/ac3-dev-app-task-role"

# Secrets Manager
APP_SECRET_ARN="arn:aws:secretsmanager:${REGION}:${ACCOUNT_ID}:secret:ac3/dev/app-WlvTEQ"

echo "═══════════════════════════════════════════════════════════════"
echo "  AC3 ECS Deployment"
echo "  Image: ${ECR_REPO}:${IMAGE_TAG}"
echo "  Cluster: ${CLUSTER}"
echo "═══════════════════════════════════════════════════════════════"

# ─── Step 1: Verify image exists in ECR ──────────────────────────────────────
echo ""
echo "[1/4] Verifying ECR image..."
aws ecr describe-images \
  --repository-name ac3/caldera-dashboard \
  --image-ids imageTag="${IMAGE_TAG}" \
  --region "${REGION}" \
  --query 'imageDetails[0].{Tags:imageTags,Pushed:imagePushedAt,Size:imageSizeInBytes}' \
  --output table --no-cli-pager || {
    echo "ERROR: Image ${IMAGE_TAG} not found in ECR. Run the GitHub Actions build first."
    exit 1
  }

# ─── Step 2: Register Task Definition ────────────────────────────────────────
echo ""
echo "[2/4] Registering ECS task definition..."

# Build the task definition with all environment variables from Secrets Manager
TASK_DEF=$(cat <<EOF
{
  "family": "${TASK_FAMILY}",
  "networkMode": "awsvpc",
  "requiresCompatibilities": ["FARGATE"],
  "cpu": "2048",
  "memory": "4096",
  "executionRoleArn": "${EXECUTION_ROLE}",
  "taskRoleArn": "${TASK_ROLE}",
  "containerDefinitions": [
    {
      "name": "ac3-app",
      "image": "${ECR_REPO}:${IMAGE_TAG}",
      "essential": true,
      "portMappings": [
        {
          "containerPort": 8080,
          "protocol": "tcp"
        }
      ],
      "healthCheck": {
        "command": ["CMD-SHELL", "curl -f http://localhost:8080/api/health || exit 1"],
        "interval": 30,
        "timeout": 10,
        "retries": 3,
        "startPeriod": 120
      },
      "environment": [
        { "name": "NODE_ENV", "value": "production" },
        { "name": "PORT", "value": "8080" }
      ],
      "secrets": [
        { "name": "DATABASE_URL", "valueFrom": "${APP_SECRET_ARN}:DATABASE_URL::" },
        { "name": "JWT_SECRET", "valueFrom": "${APP_SECRET_ARN}:JWT_SECRET::" },
        { "name": "VITE_APP_ID", "valueFrom": "${APP_SECRET_ARN}:VITE_APP_ID::" },
        { "name": "OAUTH_SERVER_URL", "valueFrom": "${APP_SECRET_ARN}:OAUTH_SERVER_URL::" },
        { "name": "VITE_OAUTH_PORTAL_URL", "valueFrom": "${APP_SECRET_ARN}:VITE_OAUTH_PORTAL_URL::" },
        { "name": "OWNER_OPEN_ID", "valueFrom": "${APP_SECRET_ARN}:OWNER_OPEN_ID::" },
        { "name": "OWNER_NAME", "valueFrom": "${APP_SECRET_ARN}:OWNER_NAME::" },
        { "name": "BUILT_IN_FORGE_API_URL", "valueFrom": "${APP_SECRET_ARN}:BUILT_IN_FORGE_API_URL::" },
        { "name": "BUILT_IN_FORGE_API_KEY", "valueFrom": "${APP_SECRET_ARN}:BUILT_IN_FORGE_API_KEY::" },
        { "name": "CALDERA_API_KEY", "valueFrom": "${APP_SECRET_ARN}:CALDERA_API_KEY::" },
        { "name": "CALDERA_BASE_URL", "valueFrom": "${APP_SECRET_ARN}:CALDERA_BASE_URL::" },
        { "name": "CALDERA_USERNAME", "valueFrom": "${APP_SECRET_ARN}:CALDERA_USERNAME::" },
        { "name": "CALDERA_PASSWORD", "valueFrom": "${APP_SECRET_ARN}:CALDERA_PASSWORD::" },
        { "name": "GOPHISH_API_KEY", "valueFrom": "${APP_SECRET_ARN}:GOPHISH_API_KEY::" },
        { "name": "GOPHISH_BASE_URL", "valueFrom": "${APP_SECRET_ARN}:GOPHISH_BASE_URL::" },
        { "name": "SHODAN_API_KEY", "valueFrom": "${APP_SECRET_ARN}:SHODAN_API_KEY::" },
        { "name": "SCAN_SERVER_HOST", "valueFrom": "${APP_SECRET_ARN}:SCAN_SERVER_HOST::" },
        { "name": "SCANFORGE_URL", "valueFrom": "${APP_SECRET_ARN}:SCANFORGE_URL::" },
        { "name": "OPENAI_API_KEY", "valueFrom": "${APP_SECRET_ARN}:OPENAI_API_KEY::" },
        { "name": "DO_SPACES_KEY", "valueFrom": "${APP_SECRET_ARN}:DO_SPACES_KEY::" },
        { "name": "DO_SPACES_SECRET", "valueFrom": "${APP_SECRET_ARN}:DO_SPACES_SECRET::" },
        { "name": "DO_SPACES_BUCKET", "valueFrom": "${APP_SECRET_ARN}:DO_SPACES_BUCKET::" },
        { "name": "DO_SPACES_REGION", "valueFrom": "${APP_SECRET_ARN}:DO_SPACES_REGION::" },
        { "name": "DO_SPACES_ENDPOINT", "valueFrom": "${APP_SECRET_ARN}:DO_SPACES_ENDPOINT::" },
        { "name": "S3_ENDPOINT", "valueFrom": "${APP_SECRET_ARN}:S3_ENDPOINT::" },
        { "name": "S3_REGION", "valueFrom": "${APP_SECRET_ARN}:S3_REGION::" },
        { "name": "S3_ACCESS_KEY", "valueFrom": "${APP_SECRET_ARN}:S3_ACCESS_KEY::" },
        { "name": "S3_SECRET_KEY", "valueFrom": "${APP_SECRET_ARN}:S3_SECRET_KEY::" },
        { "name": "S3_BUCKET", "valueFrom": "${APP_SECRET_ARN}:S3_BUCKET::" }
      ],
      "logConfiguration": {
        "logDriver": "awslogs",
        "options": {
          "awslogs-group": "/ecs/ac3-dev",
          "awslogs-region": "${REGION}",
          "awslogs-stream-prefix": "app"
        }
      },
      "linuxParameters": {
        "initProcessEnabled": true
      },
      "ulimits": [
        {
          "name": "nofile",
          "softLimit": 65536,
          "hardLimit": 65536
        }
      ]
    }
  ]
}
EOF
)

# Write to temp file and register
echo "${TASK_DEF}" > /tmp/ac3-task-def.json
TASK_DEF_ARN=$(aws ecs register-task-definition \
  --cli-input-json file:///tmp/ac3-task-def.json \
  --region "${REGION}" \
  --query 'taskDefinition.taskDefinitionArn' \
  --output text --no-cli-pager)

echo "  Task definition registered: ${TASK_DEF_ARN}"

# ─── Step 3: Create or Update ECS Service ────────────────────────────────────
echo ""
echo "[3/4] Creating/updating ECS service..."

# Check if service exists
SERVICE_EXISTS=$(aws ecs describe-services \
  --cluster "${CLUSTER}" \
  --services "${SERVICE_NAME}" \
  --region "${REGION}" \
  --query 'services[?status!=`INACTIVE`].serviceName' \
  --output text --no-cli-pager 2>/dev/null || echo "")

if [ -z "${SERVICE_EXISTS}" ] || [ "${SERVICE_EXISTS}" = "None" ]; then
  echo "  Creating new ECS service..."
  aws ecs create-service \
    --cluster "${CLUSTER}" \
    --service-name "${SERVICE_NAME}" \
    --task-definition "${TASK_DEF_ARN}" \
    --desired-count 1 \
    --launch-type FARGATE \
    --platform-version LATEST \
    --network-configuration "awsvpcConfiguration={subnets=[${APP_SUBNETS}],securityGroups=[${APP_SG}],assignPublicIp=DISABLED}" \
    --load-balancers "targetGroupArn=${TARGET_GROUP_ARN},containerName=ac3-app,containerPort=8080" \
    --health-check-grace-period-seconds 120 \
    --deployment-configuration "maximumPercent=200,minimumHealthyPercent=100,deploymentCircuitBreaker={enable=true,rollback=true}" \
    --enable-execute-command \
    --region "${REGION}" \
    --query 'service.{Name:serviceName,Status:status,DesiredCount:desiredCount}' \
    --output table --no-cli-pager
  echo "  Service created."
else
  echo "  Updating existing ECS service..."
  aws ecs update-service \
    --cluster "${CLUSTER}" \
    --service "${SERVICE_NAME}" \
    --task-definition "${TASK_DEF_ARN}" \
    --force-new-deployment \
    --region "${REGION}" \
    --query 'service.{Name:serviceName,Status:status,DesiredCount:desiredCount,RunningCount:runningCount}' \
    --output table --no-cli-pager
  echo "  Service updated with new task definition."
fi

# ─── Step 4: Wait for Deployment ─────────────────────────────────────────────
echo ""
echo "[4/4] Waiting for service to stabilize (this may take 2-5 minutes)..."
aws ecs wait services-stable \
  --cluster "${CLUSTER}" \
  --services "${SERVICE_NAME}" \
  --region "${REGION}" 2>&1 || {
    echo "WARNING: Service did not stabilize within timeout. Check ECS console for details."
    echo "  Checking current task status..."
    aws ecs list-tasks --cluster "${CLUSTER}" --service-name "${SERVICE_NAME}" --region "${REGION}" --output table --no-cli-pager
    exit 1
  }

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  ✓ Deployment complete!"
echo "  ALB DNS: ac3-dev-alb-1142114658.us-east-1.elb.amazonaws.com"
echo "  Health check: http://ac3-dev-alb-1142114658.us-east-1.elb.amazonaws.com/api/health"
echo "═══════════════════════════════════════════════════════════════"
