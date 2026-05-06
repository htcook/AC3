#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# AC3 Test Lab — DigitalOcean Deployment Script
# Creates isolated VPC + firewall + Linux & Windows target droplets
# Author: AC3 Platform
# ─────────────────────────────────────────────────────────────────────────────
# Prerequisites:
#   - doctl CLI authenticated (doctl auth init)
#   - DIGITALOCEAN_ACCESS_TOKEN env var set
# ─────────────────────────────────────────────────────────────────────────────

set -e

# ─── Configuration ───────────────────────────────────────────────────────────
REGION="nyc1"
VPC_NAME="ac3-test-lab-vpc"
VPC_CIDR="10.130.0.0/20"
FW_NAME="ac3-test-lab-fw"
LINUX_DROPLET_NAME="ac3-lab-linux-target"
WINDOWS_DROPLET_NAME="ac3-lab-windows-target"
LINUX_SIZE="s-2vcpu-4gb"        # 2 vCPU, 4GB RAM
WINDOWS_SIZE="s-4vcpu-8gb"      # 4 vCPU, 8GB RAM (Windows needs more)
LINUX_IMAGE="ubuntu-14-04-x64"  # Ubuntu 14.04 for maximum vuln compatibility
WINDOWS_IMAGE="windows-2012-r2" # Windows Server 2012 R2
SSH_KEY_NAME="ac3-scan-server"   # Your existing SSH key in DO
TAG="ac3-test-lab"

echo "═══════════════════════════════════════════════════════════════"
echo "  AC3 Test Lab — DigitalOcean Deployment"
echo "═══════════════════════════════════════════════════════════════"
echo ""

# ─── Check Prerequisites ─────────────────────────────────────────────────────
if ! command -v doctl &> /dev/null; then
    echo "ERROR: doctl CLI not found. Install: https://docs.digitalocean.com/reference/doctl/how-to/install/"
    exit 1
fi

if ! doctl account get &> /dev/null; then
    echo "ERROR: doctl not authenticated. Run: doctl auth init"
    exit 1
fi

# Get SSH key ID
SSH_KEY_ID=$(doctl compute ssh-key list --format ID,Name --no-header | grep "$SSH_KEY_NAME" | awk '{print $1}')
if [ -z "$SSH_KEY_ID" ]; then
    echo "WARNING: SSH key '$SSH_KEY_NAME' not found. Listing available keys:"
    doctl compute ssh-key list --format ID,Name,FingerPrint
    echo ""
    read -p "Enter SSH key ID to use: " SSH_KEY_ID
fi

# ─── Step 1: Create VPC ──────────────────────────────────────────────────────
echo "[1/5] Creating isolated VPC..."
VPC_ID=$(doctl vpcs list --format ID,Name --no-header | grep "$VPC_NAME" | awk '{print $1}')
if [ -z "$VPC_ID" ]; then
    VPC_ID=$(doctl vpcs create \
        --name "$VPC_NAME" \
        --region "$REGION" \
        --ip-range "$VPC_CIDR" \
        --description "AC3 Test Lab — Isolated network for vulnerable targets" \
        --format ID --no-header)
    echo "  Created VPC: $VPC_ID"
else
    echo "  VPC already exists: $VPC_ID"
fi

# ─── Step 2: Create Firewall ─────────────────────────────────────────────────
echo "[2/5] Creating firewall (internal-only access)..."
FW_ID=$(doctl compute firewall list --format ID,Name --no-header | grep "$FW_NAME" | awk '{print $1}')
if [ -z "$FW_ID" ]; then
    # Allow ALL traffic from within the VPC CIDR (scan server can reach targets)
    # Block all inbound from public internet
    FW_ID=$(doctl compute firewall create \
        --name "$FW_NAME" \
        --tag-names "$TAG" \
        --inbound-rules "protocol:tcp,ports:all,address:10.130.0.0/20 protocol:udp,ports:all,address:10.130.0.0/20 protocol:icmp,address:10.130.0.0/20" \
        --outbound-rules "protocol:tcp,ports:all,address:0.0.0.0/0 protocol:udp,ports:all,address:0.0.0.0/0 protocol:icmp,address:0.0.0.0/0" \
        --format ID --no-header)
    echo "  Created Firewall: $FW_ID"
else
    echo "  Firewall already exists: $FW_ID"
fi

# ─── Step 3: Create Linux Target ─────────────────────────────────────────────
echo "[3/5] Creating Linux target droplet..."
LINUX_ID=$(doctl compute droplet list --format ID,Name --no-header | grep "$LINUX_DROPLET_NAME" | awk '{print $1}')
if [ -z "$LINUX_ID" ]; then
    LINUX_ID=$(doctl compute droplet create "$LINUX_DROPLET_NAME" \
        --region "$REGION" \
        --size "$LINUX_SIZE" \
        --image "$LINUX_IMAGE" \
        --vpc-uuid "$VPC_ID" \
        --ssh-keys "$SSH_KEY_ID" \
        --tag-names "$TAG" \
        --user-data-file "$(dirname "$0")/provision-linux-target.sh" \
        --wait \
        --format ID --no-header)
    echo "  Created Linux droplet: $LINUX_ID"
else
    echo "  Linux droplet already exists: $LINUX_ID"
fi

# Get Linux private IP
sleep 5
LINUX_PRIVATE_IP=$(doctl compute droplet get "$LINUX_ID" --format PrivateIPv4 --no-header)
LINUX_PUBLIC_IP=$(doctl compute droplet get "$LINUX_ID" --format PublicIPv4 --no-header)
echo "  Linux Target — Private: $LINUX_PRIVATE_IP | Public: $LINUX_PUBLIC_IP"

# ─── Step 4: Create Windows Target ───────────────────────────────────────────
echo "[4/5] Creating Windows target droplet..."
WINDOWS_ID=$(doctl compute droplet list --format ID,Name --no-header | grep "$WINDOWS_DROPLET_NAME" | awk '{print $1}')
if [ -z "$WINDOWS_ID" ]; then
    WINDOWS_ID=$(doctl compute droplet create "$WINDOWS_DROPLET_NAME" \
        --region "$REGION" \
        --size "$WINDOWS_SIZE" \
        --image "$WINDOWS_IMAGE" \
        --vpc-uuid "$VPC_ID" \
        --ssh-keys "$SSH_KEY_ID" \
        --tag-names "$TAG" \
        --wait \
        --format ID --no-header)
    echo "  Created Windows droplet: $WINDOWS_ID"
    echo ""
    echo "  ⚠️  Windows provisioning requires manual step:"
    echo "  1. RDP into the Windows droplet"
    echo "  2. Open PowerShell as Administrator"
    echo "  3. Run: Invoke-WebRequest -Uri 'https://raw.githubusercontent.com/htcook/caldera-dashboard/main/infrastructure/test-lab/provision-windows-target.ps1' -OutFile 'C:\\provision.ps1'; & 'C:\\provision.ps1'"
    echo ""
else
    echo "  Windows droplet already exists: $WINDOWS_ID"
fi

# Get Windows private IP
sleep 5
WINDOWS_PRIVATE_IP=$(doctl compute droplet get "$WINDOWS_ID" --format PrivateIPv4 --no-header)
WINDOWS_PUBLIC_IP=$(doctl compute droplet get "$WINDOWS_ID" --format PublicIPv4 --no-header)
echo "  Windows Target — Private: $WINDOWS_PRIVATE_IP | Public: $WINDOWS_PUBLIC_IP"

# ─── Step 5: Output Summary ──────────────────────────────────────────────────
echo ""
echo "[5/5] Deployment complete!"
echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  AC3 Test Lab — Deployment Summary"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  VPC:      $VPC_NAME ($VPC_CIDR)"
echo "  Firewall: $FW_NAME (VPC-internal only)"
echo ""
echo "  ┌─────────────────────────────────────────────────────────┐"
echo "  │ Linux Target (ub1404-equivalent)                        │"
echo "  │   Droplet: $LINUX_DROPLET_NAME                          │"
echo "  │   Private: $LINUX_PRIVATE_IP                            │"
echo "  │   Public:  $LINUX_PUBLIC_IP (blocked by firewall)       │"
echo "  │   SSH:     vagrant:vagrant                              │"
echo "  └─────────────────────────────────────────────────────────┘"
echo ""
echo "  ┌─────────────────────────────────────────────────────────┐"
echo "  │ Windows Target (win2k8-equivalent)                      │"
echo "  │   Droplet: $WINDOWS_DROPLET_NAME                        │"
echo "  │   Private: $WINDOWS_PRIVATE_IP                          │"
echo "  │   Public:  $WINDOWS_PUBLIC_IP (blocked by firewall)     │"
echo "  │   RDP:     vagrant:vagrant                              │"
echo "  └─────────────────────────────────────────────────────────┘"
echo ""
echo "  ─── Next Steps ───────────────────────────────────────────"
echo "  1. Ensure your scan server (137.184.71.192) is in the same VPC"
echo "     or add its IP to the firewall inbound rules"
echo "  2. For Windows: RDP in and run the provisioning script"
echo "  3. Create a test engagement in the dashboard with targets:"
echo "     - Linux:   $LINUX_PRIVATE_IP"
echo "     - Windows: $WINDOWS_PRIVATE_IP"
echo "  4. Run the engagement in 'blind' mode (no pre-seeded vulns)"
echo "═══════════════════════════════════════════════════════════════"

# ─── Save target IPs to file for engagement creation ─────────────────────────
cat > "$(dirname "$0")/lab-targets.env" << EOF
# AC3 Test Lab Target IPs — Generated $(date -u +"%Y-%m-%dT%H:%M:%SZ")
LINUX_TARGET_PRIVATE_IP=$LINUX_PRIVATE_IP
LINUX_TARGET_PUBLIC_IP=$LINUX_PUBLIC_IP
WINDOWS_TARGET_PRIVATE_IP=$WINDOWS_PRIVATE_IP
WINDOWS_TARGET_PUBLIC_IP=$WINDOWS_PUBLIC_IP
VPC_ID=$VPC_ID
FIREWALL_ID=$FW_ID
LINUX_DROPLET_ID=$LINUX_ID
WINDOWS_DROPLET_ID=$WINDOWS_ID
EOF

echo ""
echo "  Target IPs saved to: infrastructure/test-lab/lab-targets.env"
