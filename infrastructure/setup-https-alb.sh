#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# setup-https-alb.sh — Add HTTPS listener + HTTP→HTTPS redirect to ALB
# Author: Harrison Cook — AceofCloud (https://aceofcloud.com)
#
# Prerequisites:
#   1. ACM certificate must be ISSUED (DNS validation complete)
#   2. aws-env.sh must be sourced (AWS credentials)
#
# Usage:
#   source /home/ubuntu/aws-env.sh
#   bash infrastructure/setup-https-alb.sh
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ── Configuration ────────────────────────────────────────────────────────────
ACM_CERT_ARN="arn:aws:acm:us-east-1:808038814732:certificate/b5692f5a-9008-4002-8823-8be500870db4"
ALB_ARN="arn:aws:elasticloadbalancing:us-east-1:808038814732:loadbalancer/app/ac3-dev-alb/e3e2b0f4e4c7c49f"
TARGET_GROUP_ARN="arn:aws:elasticloadbalancing:us-east-1:808038814732:targetgroup/ac3-dev-app-tg/2e6f5b2e93d83a3c"

echo "═══════════════════════════════════════════════════════════════"
echo "  AC3 ALB HTTPS Setup"
echo "═══════════════════════════════════════════════════════════════"

# ── Step 1: Verify ACM certificate is ISSUED ─────────────────────────────────
echo ""
echo "▸ Checking ACM certificate status..."
CERT_STATUS=$(aws acm describe-certificate \
  --certificate-arn "$ACM_CERT_ARN" \
  --query 'Certificate.Status' \
  --output text)

if [ "$CERT_STATUS" != "ISSUED" ]; then
  echo "✗ Certificate status is '$CERT_STATUS' — must be ISSUED before proceeding."
  echo "  Make sure the DNS validation CNAME has been added to GoDaddy."
  echo "  Check: aws acm describe-certificate --certificate-arn $ACM_CERT_ARN"
  exit 1
fi
echo "✓ Certificate is ISSUED"

# ── Step 2: Check if HTTPS listener already exists ───────────────────────────
echo ""
echo "▸ Checking existing listeners..."
EXISTING_HTTPS=$(aws elbv2 describe-listeners \
  --load-balancer-arn "$ALB_ARN" \
  --query 'Listeners[?Port==`443`].ListenerArn' \
  --output text)

if [ -n "$EXISTING_HTTPS" ] && [ "$EXISTING_HTTPS" != "None" ]; then
  echo "✓ HTTPS listener already exists: $EXISTING_HTTPS"
  echo "  Skipping HTTPS listener creation."
else
  # ── Step 3: Create HTTPS listener on port 443 ─────────────────────────────
  echo ""
  echo "▸ Creating HTTPS listener on port 443..."
  HTTPS_LISTENER_ARN=$(aws elbv2 create-listener \
    --load-balancer-arn "$ALB_ARN" \
    --protocol HTTPS \
    --port 443 \
    --ssl-policy "ELBSecurityPolicy-TLS13-1-2-2021-06" \
    --certificates CertificateArn="$ACM_CERT_ARN" \
    --default-actions Type=forward,TargetGroupArn="$TARGET_GROUP_ARN" \
    --query 'Listeners[0].ListenerArn' \
    --output text)
  echo "✓ HTTPS listener created: $HTTPS_LISTENER_ARN"
  echo "  SSL Policy: ELBSecurityPolicy-TLS13-1-2-2021-06 (TLS 1.3 + 1.2 only)"
fi

# ── Step 4: Modify HTTP listener to redirect to HTTPS ────────────────────────
echo ""
echo "▸ Finding HTTP listener on port 80..."
HTTP_LISTENER_ARN=$(aws elbv2 describe-listeners \
  --load-balancer-arn "$ALB_ARN" \
  --query 'Listeners[?Port==`80`].ListenerArn' \
  --output text)

if [ -z "$HTTP_LISTENER_ARN" ] || [ "$HTTP_LISTENER_ARN" == "None" ]; then
  echo "✗ No HTTP listener found on port 80. Creating redirect listener..."
  aws elbv2 create-listener \
    --load-balancer-arn "$ALB_ARN" \
    --protocol HTTP \
    --port 80 \
    --default-actions 'Type=redirect,RedirectConfig={Protocol=HTTPS,Port=443,StatusCode=HTTP_301}' \
    --query 'Listeners[0].ListenerArn' \
    --output text
  echo "✓ HTTP redirect listener created"
else
  echo "  Found: $HTTP_LISTENER_ARN"
  echo "▸ Modifying HTTP listener to redirect all traffic to HTTPS..."
  aws elbv2 modify-listener \
    --listener-arn "$HTTP_LISTENER_ARN" \
    --default-actions 'Type=redirect,RedirectConfig={Protocol=HTTPS,Port=443,StatusCode=HTTP_301}'
  echo "✓ HTTP listener now redirects to HTTPS (301)"
fi

# ── Step 5: Verify security group allows port 443 ───────────────────────────
echo ""
echo "▸ Checking ALB security group for port 443 ingress..."
ALB_SG=$(aws elbv2 describe-load-balancers \
  --load-balancer-arns "$ALB_ARN" \
  --query 'LoadBalancers[0].SecurityGroups[0]' \
  --output text)

HTTPS_RULE=$(aws ec2 describe-security-group-rules \
  --filters "Name=group-id,Values=$ALB_SG" \
  --query "SecurityGroupRules[?FromPort==\`443\` && ToPort==\`443\` && IsEgress==\`false\`].SecurityGroupRuleId" \
  --output text)

if [ -z "$HTTPS_RULE" ] || [ "$HTTPS_RULE" == "None" ]; then
  echo "  Adding port 443 ingress rule to ALB security group $ALB_SG..."
  aws ec2 authorize-security-group-ingress \
    --group-id "$ALB_SG" \
    --protocol tcp \
    --port 443 \
    --cidr 0.0.0.0/0 \
    --tag-specifications 'ResourceType=security-group-rule,Tags=[{Key=Name,Value=ac3-alb-https-ingress}]'
  echo "✓ Port 443 ingress rule added"
else
  echo "✓ Port 443 ingress rule already exists"
fi

# ── Summary ──────────────────────────────────────────────────────────────────
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  HTTPS Setup Complete"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  HTTPS Listener:  Port 443 → Target Group (TLS 1.3/1.2)"
echo "  HTTP Listener:   Port 80  → 301 Redirect to HTTPS"
echo "  SSL Policy:      ELBSecurityPolicy-TLS13-1-2-2021-06"
echo "  Certificate:     $ACM_CERT_ARN"
echo ""
echo "  App-level enforcement:"
echo "    ✓ HSTS header (max-age=31536000; includeSubDomains; preload)"
echo "    ✓ X-Forwarded-Proto redirect middleware"
echo "    ✓ CSP upgrade-insecure-requests directive"
echo ""
echo "  Test with:"
echo "    curl -I http://dev.aceofcloud.io  → should get 301 to https://"
echo "    curl -I https://dev.aceofcloud.io → should get 200 + HSTS header"
echo ""
