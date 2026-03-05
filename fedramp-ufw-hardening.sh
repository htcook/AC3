#!/bin/bash
###############################################################################
# FedRAMP-Aligned UFW Hardening Script for AceOfCloud Infrastructure
# ============================================================================
#
# PURPOSE:
#   Configures host-level UFW firewalls on all DigitalOcean droplets with
#   FedRAMP-compliant default-deny policies, explicit allow-lists, and
#   high-verbosity logging for audit trails.
#
# USAGE:
#   1. SSH into your bastion server:
#        ssh root@64.23.180.12
#   2. Copy this script to the bastion:
#        scp fedramp-ufw-hardening.sh root@64.23.180.12:/root/
#   3. Make executable and run:
#        chmod +x /root/fedramp-ufw-hardening.sh
#        bash /root/fedramp-ufw-hardening.sh
#
#   The script SSHes from the bastion into each droplet and applies UFW rules.
#   The bastion itself is hardened last (locally).
#
# FEDRAMP CONTROLS ADDRESSED:
#   AC-4   Information Flow Enforcement (default deny, explicit allow)
#   AU-2   Audit Events (UFW logging set to high)
#   SC-7   Boundary Protection (network segmentation via UFW)
#   CM-7   Least Functionality (only required ports open)
#   AC-17  Remote Access (SSH restricted to bastion only)
#
# INFRASTRUCTURE MAP:
#   Bastion:        64.23.180.12    / 10.124.0.6  (SFO3 VPC)
#   App Server:     134.199.213.248 / 10.124.0.7  (SFO3 VPC)
#   Mail Server:    137.184.7.224   / 10.124.0.2  (SFO3 VPC)
#   ZAP Scanner:    64.23.239.165   / 10.124.0.3  (SFO3 VPC)
#   Scan Server:    134.209.75.36   / 10.116.0.4  (NYC1 VPC)
#   MSF Primary:    174.138.80.102  / 10.108.0.4  (NYC3 VPC)
#   MSF Tunnel:     142.93.55.239   / 10.116.0.2  (NYC1 VPC)
#   MSF Server 012: 104.248.50.22   / 10.116.0.3  (NYC1 VPC)
#
# ROLLBACK:
#   If something goes wrong, SSH into the affected droplet and run:
#     ufw disable
#
# DATE: 2026-03-04
###############################################################################

set -euo pipefail

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log_info()  { echo -e "${CYAN}[INFO]${NC}  $1"; }
log_ok()    { echo -e "${GREEN}[ OK ]${NC}  $1"; }
log_warn()  { echo -e "${YELLOW}[WARN]${NC}  $1"; }
log_fail()  { echo -e "${RED}[FAIL]${NC}  $1"; }

SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=15 -o BatchMode=yes"

FAILED=0
TOTAL=0

###############################################################################
# Helper: Run UFW commands on a remote host via SSH
###############################################################################
harden_remote() {
    local HOST="$1"
    local NAME="$2"
    shift 2

    TOTAL=$((TOTAL+1))
    log_info "[$TOTAL/8] Hardening ${NAME} (${HOST})..."

    local CMD="set -e; "
    CMD+="echo '=== FedRAMP UFW Hardening: ${NAME} ==='; "
    CMD+="echo 'Host: '\$(hostname); "
    CMD+="echo 'Date: '\$(date -u '+%Y-%m-%d %H:%M:%S UTC'); "
    CMD+="apt-get install -y -qq ufw 2>/dev/null || true; "
    CMD+="ufw --force reset; "
    CMD+="ufw default deny incoming; "
    CMD+="ufw default allow outgoing; "
    CMD+="ufw logging high; "

    for rule in "$@"; do
        CMD+="${rule}; "
    done

    CMD+="ufw --force enable; "
    CMD+="echo ''; ufw status verbose; "
    CMD+="echo '=== Hardening Complete ==='"

    if ssh $SSH_OPTS "root@${HOST}" "$CMD" 2>&1; then
        log_ok "${NAME} hardened successfully"
    else
        log_fail "${NAME} hardening FAILED"
        FAILED=$((FAILED+1))
    fi
    echo ""
}

###############################################################################
echo ""
echo "============================================================"
echo "  FedRAMP UFW Hardening - AceOfCloud Infrastructure"
echo "  $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
echo ""
echo "This script will apply UFW firewall rules to 8 servers."
echo "It must be run from the bastion server (64.23.180.12)."
echo ""
echo "Press Ctrl+C within 5 seconds to abort..."
sleep 5
echo ""
###############################################################################

# ─────────────────────────────────────────────────────────────────────────────
# 1. msf-ace-c3-primary - NYC3 (no VPC peering, use public bastion IP)
#    Ports: SSH (bastion only), Meterpreter 4444 (VPC), MSFRPC 55553 (VPC)
# ─────────────────────────────────────────────────────────────────────────────
harden_remote "174.138.80.102" "msf-ace-c3-primary" \
    "ufw allow from 64.23.180.12 to any port 22 proto tcp comment 'FedRAMP AC-17: SSH from bastion'" \
    "ufw allow from 10.108.0.0/20 to any port 4444 proto tcp comment 'Meterpreter handler - NYC3 VPC only'" \
    "ufw allow from 10.108.0.0/20 to any port 55553 proto tcp comment 'MSFRPC API - NYC3 VPC only'"

# ─────────────────────────────────────────────────────────────────────────────
# 2. msf-tunnel-server - NYC1
#    Ports: SSH (bastion + VPC), Meterpreter 4444 (VPC)
# ─────────────────────────────────────────────────────────────────────────────
harden_remote "142.93.55.239" "msf-tunnel-server" \
    "ufw allow from 64.23.180.12 to any port 22 proto tcp comment 'FedRAMP AC-17: SSH from bastion'" \
    "ufw allow from 10.116.0.0/20 to any port 22 proto tcp comment 'SSH from NYC1 VPC'" \
    "ufw allow from 10.116.0.0/20 to any port 4444 proto tcp comment 'Meterpreter handler - NYC1 VPC only'"

# ─────────────────────────────────────────────────────────────────────────────
# 3. msf-msf-server-012 - NYC1
#    Ports: SSH (bastion + VPC), Meterpreter 4444 (VPC)
# ─────────────────────────────────────────────────────────────────────────────
harden_remote "104.248.50.22" "msf-msf-server-012" \
    "ufw allow from 64.23.180.12 to any port 22 proto tcp comment 'FedRAMP AC-17: SSH from bastion'" \
    "ufw allow from 10.116.0.0/20 to any port 22 proto tcp comment 'SSH from NYC1 VPC'" \
    "ufw allow from 10.116.0.0/20 to any port 4444 proto tcp comment 'Meterpreter handler - NYC1 VPC only'"

# ─────────────────────────────────────────────────────────────────────────────
# 4. caldera-scan-server - NYC1
#    Ports: SSH (bastion + VPC), Caldera API 8888 (VPC)
# ─────────────────────────────────────────────────────────────────────────────
harden_remote "134.209.75.36" "caldera-scan-server" \
    "ufw allow from 64.23.180.12 to any port 22 proto tcp comment 'FedRAMP AC-17: SSH from bastion'" \
    "ufw allow from 10.116.0.0/20 to any port 22 proto tcp comment 'SSH from NYC1 VPC'" \
    "ufw allow from 10.116.0.0/20 to any port 8888 proto tcp comment 'Caldera API - NYC1 VPC only'"

# ─────────────────────────────────────────────────────────────────────────────
# 5. zap-scanner - SFO3 (same VPC as bastion, use private IP)
#    Ports: SSH (bastion only), ZAP API 8080 (VPC)
# ─────────────────────────────────────────────────────────────────────────────
harden_remote "10.124.0.3" "zap-scanner" \
    "ufw allow from 10.124.0.6 to any port 22 proto tcp comment 'FedRAMP AC-17: SSH from bastion'" \
    "ufw allow from 10.124.0.0/20 to any port 8080 proto tcp comment 'ZAP API - SFO3 VPC only'"

# ─────────────────────────────────────────────────────────────────────────────
# 6. app.aceofcloud.io - SFO3
#    Ports: SSH (VPC + trusted IP), HTTP/HTTPS (public),
#           GoPhish 3333/8080 (VPC), Caldera API 8888 (VPC)
# ─────────────────────────────────────────────────────────────────────────────
harden_remote "10.124.0.7" "app.aceofcloud.io" \
    "ufw allow from 10.124.0.0/20 to any port 22 proto tcp comment 'FedRAMP AC-17: SSH from SFO3 VPC'" \
    "ufw allow from 98.84.162.55 to any port 22 proto tcp comment 'SSH from trusted IP'" \
    "ufw allow 80/tcp comment 'HTTP public'" \
    "ufw allow 443/tcp comment 'HTTPS public'" \
    "ufw allow from 10.124.0.0/20 to any port 3333 proto tcp comment 'GoPhish listener - SFO3 VPC only'" \
    "ufw allow from 10.124.0.0/20 to any port 8080 proto tcp comment 'GoPhish admin - SFO3 VPC only'" \
    "ufw allow from 10.124.0.0/20 to any port 8888 proto tcp comment 'Caldera API - SFO3 VPC only'"

# ─────────────────────────────────────────────────────────────────────────────
# 7. mail.aceofcloud.io - SFO3
#    Ports: SSH (bastion only), SMTP 25 (VPC), HTTPS 443 (public),
#           SMTP submission 587 (public), IMAPS 993 (public),
#           GoPhish 3333 (VPC)
# ─────────────────────────────────────────────────────────────────────────────
harden_remote "10.124.0.2" "mail.aceofcloud.io" \
    "ufw allow from 10.124.0.6 to any port 22 proto tcp comment 'FedRAMP AC-17: SSH from bastion'" \
    "ufw allow from 10.124.0.0/20 to any port 25 proto tcp comment 'SMTP internal relay - SFO3 VPC only'" \
    "ufw allow 443/tcp comment 'HTTPS public (webmail)'" \
    "ufw allow 587/tcp comment 'SMTP submission public'" \
    "ufw allow 993/tcp comment 'IMAPS public'" \
    "ufw allow from 10.124.0.0/20 to any port 3333 proto tcp comment 'GoPhish listener - SFO3 VPC only'"

# ─────────────────────────────────────────────────────────────────────────────
# 8. Bastion itself - SFO3 (run locally, not via SSH)
#    Ports: SSH 22 (public - this IS the entry point)
# ─────────────────────────────────────────────────────────────────────────────
TOTAL=$((TOTAL+1))
log_info "[$TOTAL/8] Hardening bastion (local)..."
echo "=== FedRAMP UFW Hardening: bastion ==="
echo "Host: $(hostname)"
echo "Date: $(date -u '+%Y-%m-%d %H:%M:%S UTC')"

ufw --force reset
ufw default deny incoming
ufw default allow outgoing
ufw logging high

ufw allow 22/tcp comment 'FedRAMP AC-17: SSH public (bastion entry point)'

ufw --force enable
echo ""
ufw status verbose
log_ok "bastion hardened successfully"
echo ""

###############################################################################
# Summary
###############################################################################
echo ""
echo "============================================================"
echo "  FedRAMP UFW Hardening - COMPLETE"
echo "  $(date -u '+%Y-%m-%d %H:%M:%S UTC')"
echo "============================================================"
echo ""
echo "  Total servers:  ${TOTAL}"
echo "  Succeeded:      $((TOTAL - FAILED))"
echo "  Failed:         ${FAILED}"
echo ""

if [ $FAILED -gt 0 ]; then
    log_warn "Some servers failed. Check output above and retry individually."
    log_warn "For failed servers, SSH in manually and run:"
    log_warn "  ufw --force reset && ufw default deny incoming && ufw default allow outgoing"
    log_warn "  ufw logging high && <add allow rules> && ufw --force enable"
    exit 1
else
    log_ok "All 8 servers hardened successfully!"
    echo ""
    echo "FedRAMP Controls Applied:"
    echo "  AC-4   Default deny incoming (information flow enforcement)"
    echo "  AC-17  SSH restricted to bastion/VPC only (remote access)"
    echo "  AU-2   UFW logging set to HIGH on all hosts (audit events)"
    echo "  SC-7   Service ports restricted to VPC (boundary protection)"
    echo "  CM-7   Only required ports open (least functionality)"
    echo ""
    echo "VERIFICATION: From an external host, confirm ports are blocked:"
    echo "  python3 -c \"import socket; s=socket.socket(); s.settimeout(5);\\"
    echo "    print('OPEN' if s.connect_ex(('174.138.80.102',4444))==0 else 'BLOCKED');\\"
    echo "    s.close()\""
    echo ""
fi
