#!/bin/bash
# ─────────────────────────────────────────────────────────────────────────────
# AC3 Test Lab — Teardown Script
# Destroys all test lab resources (droplets, firewall, VPC)
# ─────────────────────────────────────────────────────────────────────────────

set -e

TAG="ac3-test-lab"
VPC_NAME="ac3-test-lab-vpc"
FW_NAME="ac3-test-lab-fw"

echo "═══════════════════════════════════════════════════════════════"
echo "  AC3 Test Lab — Teardown"
echo "═══════════════════════════════════════════════════════════════"
echo ""
echo "  ⚠️  This will DESTROY all test lab resources!"
echo ""
read -p "  Are you sure? (yes/no): " CONFIRM
if [ "$CONFIRM" != "yes" ]; then
    echo "  Aborted."
    exit 0
fi

echo ""
echo "[1/3] Destroying droplets tagged '$TAG'..."
DROPLET_IDS=$(doctl compute droplet list --tag-name "$TAG" --format ID --no-header)
if [ -n "$DROPLET_IDS" ]; then
    for ID in $DROPLET_IDS; do
        echo "  Destroying droplet $ID..."
        doctl compute droplet delete "$ID" --force
    done
else
    echo "  No droplets found."
fi

echo "[2/3] Destroying firewall '$FW_NAME'..."
FW_ID=$(doctl compute firewall list --format ID,Name --no-header | grep "$FW_NAME" | awk '{print $1}')
if [ -n "$FW_ID" ]; then
    doctl compute firewall delete "$FW_ID" --force
    echo "  Destroyed firewall: $FW_ID"
else
    echo "  No firewall found."
fi

echo "[3/3] Destroying VPC '$VPC_NAME'..."
VPC_ID=$(doctl vpcs list --format ID,Name --no-header | grep "$VPC_NAME" | awk '{print $1}')
if [ -n "$VPC_ID" ]; then
    doctl vpcs delete "$VPC_ID" --force
    echo "  Destroyed VPC: $VPC_ID"
else
    echo "  No VPC found."
fi

echo ""
echo "═══════════════════════════════════════════════════════════════"
echo "  ✓ Test Lab Teardown Complete"
echo "═══════════════════════════════════════════════════════════════"

# Clean up local env file
rm -f "$(dirname "$0")/lab-targets.env"
