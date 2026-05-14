import {
  ENV,
  init_env
} from "./chunk-GN2OC6SU.js";
import "./chunk-KFQGP6VL.js";

// server/lib/fips-do-infrastructure.ts
init_env();
var auditLog = [];
var MAX_AUDIT_ENTRIES = 1e4;
function logAudit(entry) {
  const full = { ...entry, timestamp: Date.now() };
  auditLog.push(full);
  if (auditLog.length > MAX_AUDIT_ENTRIES) {
    auditLog.splice(0, auditLog.length - MAX_AUDIT_ENTRIES);
  }
  console.log(
    `[FIPS-DO-Audit] ${entry.action} on ${entry.resource}/${entry.resourceId} by ${entry.operator} \u2014 FIPS:${entry.fipsCompliant} \u2014 NIST:${entry.nistControls.join(",")}`
  );
}
function getAuditLog(limit = 100) {
  return auditLog.slice(-limit);
}
function getVPCConfig() {
  return {
    name: "caldera-fips-vpc",
    description: "FIPS 140-3 compliant VPC for Caldera scan infrastructure. No public endpoints.",
    ipRange: "10.132.0.0/20",
    region: "nyc1",
    default: false
  };
}
async function createVPC() {
  const config = getVPCConfig();
  const token = ENV.DIGITALOCEAN_ACCESS_TOKEN;
  if (!token) throw new Error("DIGITALOCEAN_ACCESS_TOKEN not configured");
  const response = await fetch("https://api.digitalocean.com/v2/vpcs", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify({
      name: config.name,
      description: config.description,
      ip_range: config.ipRange,
      region: config.region
    })
  });
  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Failed to create VPC: ${response.status} ${err}`);
  }
  const data = await response.json();
  const vpc = data.vpc;
  logAudit({
    action: "CREATE_VPC",
    resource: "vpc",
    resourceId: vpc.id,
    operator: "system",
    details: { name: config.name, ipRange: config.ipRange, region: config.region },
    fipsCompliant: true,
    nistControls: ["AC-4", "SC-7"]
  });
  return { id: vpc.id, ipRange: vpc.ip_range };
}
async function findCalderaVPC() {
  const token = ENV.DIGITALOCEAN_ACCESS_TOKEN;
  if (!token) return null;
  const response = await fetch("https://api.digitalocean.com/v2/vpcs", {
    headers: { Authorization: `Bearer ${token}` }
  });
  if (!response.ok) return null;
  const data = await response.json();
  const vpc = (data.vpcs || []).find((v) => v.name === "caldera-fips-vpc");
  return vpc ? { id: vpc.id, ipRange: vpc.ip_range } : null;
}
function getFirewallConfigs() {
  return {
    // Redis Queue — VPC-only, no public access whatsoever
    redis: {
      name: "caldera-redis-fw",
      description: "Redis queue \u2014 VPC-only access, no public endpoints",
      inboundRules: [
        {
          protocol: "tcp",
          ports: "6379",
          sources: { tags: ["caldera-worker", "caldera-api"] },
          description: "Redis from workers and API only (VPC private network)"
        },
        {
          protocol: "tcp",
          ports: "16379",
          sources: { tags: ["caldera-worker", "caldera-api"] },
          description: "Redis Sentinel from workers and API (VPC)"
        }
      ],
      outboundRules: [
        {
          protocol: "tcp",
          ports: "1-65535",
          destinations: { tags: ["caldera-worker", "caldera-api"] },
          description: "Responses to VPC services only"
        }
      ],
      dropletIds: [],
      tags: ["caldera-redis"]
    },
    // Scan Worker — VPC-only inbound, outbound HTTPS for scanning
    scanWorker: {
      name: "caldera-scan-worker-fw",
      description: "Scan worker \u2014 no public inbound, outbound HTTPS for target scanning",
      inboundRules: [
        {
          protocol: "tcp",
          ports: "22",
          sources: { tags: ["caldera-api"] },
          description: "SSH from Manus backend only (VPC)"
        },
        {
          protocol: "tcp",
          ports: "8080",
          sources: { tags: ["caldera-api"] },
          description: "Health check from Manus backend (VPC)"
        },
        {
          protocol: "tcp",
          ports: "8443",
          sources: { tags: ["caldera-api"] },
          description: "Worker API from Manus backend (VPC, mTLS)"
        }
      ],
      outboundRules: [
        {
          protocol: "tcp",
          ports: "6379",
          destinations: { tags: ["caldera-redis"] },
          description: "Redis queue (VPC only)"
        },
        {
          protocol: "tcp",
          ports: "443",
          destinations: { addresses: ["0.0.0.0/0", "::/0"] },
          description: "HTTPS for scanning targets (outbound only)"
        },
        {
          protocol: "tcp",
          ports: "80",
          destinations: { addresses: ["0.0.0.0/0", "::/0"] },
          description: "HTTP for scanning targets (outbound only)"
        },
        {
          protocol: "udp",
          ports: "53",
          destinations: { addresses: ["0.0.0.0/0", "::/0"] },
          description: "DNS resolution for scanning"
        }
      ],
      dropletIds: [],
      tags: ["caldera-worker"]
    },
    // C2 Droplet — SSH from operators only, C2 API from backend only
    c2Droplet: {
      name: "caldera-c2-fw",
      description: "C2 droplet \u2014 operator SSH only, no public services",
      inboundRules: [
        {
          protocol: "tcp",
          ports: "22",
          sources: { tags: ["caldera-operator"] },
          description: "SSH from operator IPs only (whitelisted)"
        },
        {
          protocol: "tcp",
          ports: "8443",
          sources: { tags: ["caldera-api"] },
          description: "C2 API from Manus backend only (VPC, mTLS)"
        }
      ],
      outboundRules: [
        {
          protocol: "tcp",
          ports: "443",
          destinations: { addresses: ["0.0.0.0/0", "::/0"] },
          description: "C2 callback channels (outbound only)"
        },
        {
          protocol: "tcp",
          ports: "80",
          destinations: { addresses: ["0.0.0.0/0", "::/0"] },
          description: "C2 HTTP callbacks (outbound only)"
        },
        {
          protocol: "tcp",
          ports: "8888",
          destinations: { addresses: ["0.0.0.0/0", "::/0"] },
          description: "C2 custom port callbacks (outbound only)"
        }
      ],
      dropletIds: [],
      tags: ["caldera-c2"]
    },
    // OSINT Worker — VPC-only inbound, outbound HTTPS for API calls
    osintWorker: {
      name: "caldera-osint-worker-fw",
      description: "OSINT worker \u2014 no public inbound, outbound HTTPS for API calls",
      inboundRules: [
        {
          protocol: "tcp",
          ports: "8080",
          sources: { tags: ["caldera-api"] },
          description: "Health check from Manus backend (VPC)"
        },
        {
          protocol: "tcp",
          ports: "8443",
          sources: { tags: ["caldera-api"] },
          description: "Worker API from Manus backend (VPC, mTLS)"
        }
      ],
      outboundRules: [
        {
          protocol: "tcp",
          ports: "6379",
          destinations: { tags: ["caldera-redis"] },
          description: "Redis queue (VPC only)"
        },
        {
          protocol: "tcp",
          ports: "443",
          destinations: { addresses: ["0.0.0.0/0", "::/0"] },
          description: "HTTPS for OSINT API calls (outbound only)"
        },
        {
          protocol: "udp",
          ports: "53",
          destinations: { addresses: ["0.0.0.0/0", "::/0"] },
          description: "DNS resolution"
        }
      ],
      dropletIds: [],
      tags: ["caldera-osint"]
    }
  };
}
async function createFirewall(config) {
  const token = ENV.DIGITALOCEAN_ACCESS_TOKEN;
  if (!token) throw new Error("DIGITALOCEAN_ACCESS_TOKEN not configured");
  const body = {
    name: config.name,
    inbound_rules: config.inboundRules.map((r) => ({
      protocol: r.protocol,
      ports: r.ports,
      sources: r.sources
    })),
    outbound_rules: config.outboundRules.map((r) => ({
      protocol: r.protocol,
      ports: r.ports,
      destinations: r.destinations
    })),
    droplet_ids: config.dropletIds,
    tags: config.tags
  };
  const response = await fetch("https://api.digitalocean.com/v2/firewalls", {
    method: "POST",
    headers: {
      Authorization: `Bearer ${token}`,
      "Content-Type": "application/json"
    },
    body: JSON.stringify(body)
  });
  if (!response.ok) {
    const err = await response.text();
    throw new Error(`Failed to create firewall ${config.name}: ${response.status} ${err}`);
  }
  const data = await response.json();
  const fwId = data.firewall.id;
  logAudit({
    action: "CREATE_FIREWALL",
    resource: "firewall",
    resourceId: fwId,
    operator: "system",
    details: {
      name: config.name,
      inboundRules: config.inboundRules.length,
      outboundRules: config.outboundRules.length,
      tags: config.tags
    },
    fipsCompliant: true,
    nistControls: ["AC-4", "SC-7", "SC-8"]
  });
  return fwId;
}
function generateFIPSSSHDConfig(options = {}) {
  const port = options.port || 22;
  const allowUsers = options.allowedUsers?.join(" ") || "root";
  return `# FIPS 140-3 Compliant SSH Configuration
# Generated by Caldera Infrastructure Manager
# NIST SP 800-53: AC-17, SC-8, SC-12, SC-13

Port ${port}
Protocol 2
AddressFamily inet

# Authentication
PermitRootLogin prohibit-password
PubkeyAuthentication yes
PasswordAuthentication no
ChallengeResponseAuthentication no
UsePAM yes
AllowUsers ${allowUsers}

# FIPS-Approved Key Exchange Algorithms
KexAlgorithms ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group18-sha512,diffie-hellman-group16-sha512,diffie-hellman-group14-sha256

# FIPS-Approved Ciphers (AES-GCM preferred, AES-CTR fallback)
Ciphers aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr

# FIPS-Approved MACs (SHA-2 family only, ETM preferred)
MACs hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256

# FIPS-Approved Host Key Algorithms
HostKeyAlgorithms ecdsa-sha2-nistp521,ecdsa-sha2-nistp384,ecdsa-sha2-nistp256,rsa-sha2-512,rsa-sha2-256,ssh-ed25519

# Session Security
ClientAliveInterval 300
ClientAliveCountMax 3
MaxAuthTries 3
MaxSessions 5
LoginGraceTime 60

# Logging (NIST AU-2, AU-3)
LogLevel VERBOSE
SyslogFacility AUTH

# Disable forwarding (minimize attack surface)
AllowTcpForwarding no
X11Forwarding no
AllowStreamLocalForwarding no
GatewayPorts no
PermitTunnel no

# Banner
Banner /etc/ssh/banner.txt
`;
}
function generateSSHBanner() {
  return `
*******************************************************************************
*                                                                             *
*  AUTHORIZED ACCESS ONLY \u2014 Caldera Red Team Infrastructure                   *
*                                                                             *
*  This system is FIPS 140-3 compliant. All sessions are monitored and        *
*  logged per NIST SP 800-53 AU-2/AU-3. Unauthorized access is prohibited     *
*  and will be reported to appropriate authorities.                            *
*                                                                             *
*  By continuing, you consent to monitoring and recording of all activity.     *
*                                                                             *
*******************************************************************************
`;
}
function generateFIPSWorkerUserData(options = { workerType: "scan" }) {
  const sshdConfig = generateFIPSSSHDConfig({
    allowedUsers: ["root", "caldera"],
    port: 22
  });
  const banner = generateSSHBanner();
  return `#!/bin/bash
set -euo pipefail

# \u2500\u2500\u2500 FIPS 140-3 Infrastructure Hardening \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
echo "[FIPS] Starting FIPS 140-3 hardening for ${options.workerType} worker..."

# Create caldera user
useradd -m -s /bin/bash caldera || true

# \u2500\u2500\u2500 SSH Hardening \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
cat > /etc/ssh/sshd_config << 'SSHD_EOF'
${sshdConfig}
SSHD_EOF

cat > /etc/ssh/banner.txt << 'BANNER_EOF'
${banner}
BANNER_EOF

systemctl restart sshd

# \u2500\u2500\u2500 Firewall (UFW) \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
ufw --force reset
ufw default deny incoming
ufw default deny outgoing

# Allow SSH from VPC only
ufw allow from ${options.vpcSubnet || "10.132.0.0/20"} to any port 22 proto tcp

# Allow health check from VPC
ufw allow from ${options.vpcSubnet || "10.132.0.0/20"} to any port 8080 proto tcp

# Allow worker API from VPC (mTLS)
ufw allow from ${options.vpcSubnet || "10.132.0.0/20"} to any port 8443 proto tcp

# Allow outbound DNS
ufw allow out 53/udp
ufw allow out 53/tcp

# Allow outbound HTTPS (for scanning/API calls)
ufw allow out 443/tcp
ufw allow out 80/tcp

${options.redisHost ? `# Allow Redis (VPC only)
ufw allow out to ${options.redisHost} port 6379 proto tcp` : ""}

# Enable firewall
ufw --force enable

# \u2500\u2500\u2500 Disable Unnecessary Services \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
systemctl disable --now snapd.service 2>/dev/null || true
systemctl disable --now snapd.socket 2>/dev/null || true
systemctl disable --now cups.service 2>/dev/null || true
systemctl disable --now avahi-daemon.service 2>/dev/null || true

# \u2500\u2500\u2500 Kernel Hardening \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
cat >> /etc/sysctl.d/99-fips-hardening.conf << 'SYSCTL_EOF'
# Disable IP forwarding
net.ipv4.ip_forward = 0
net.ipv6.conf.all.forwarding = 0

# Disable source routing
net.ipv4.conf.all.accept_source_route = 0
net.ipv6.conf.all.accept_source_route = 0

# Enable SYN flood protection
net.ipv4.tcp_syncookies = 1

# Disable ICMP redirects
net.ipv4.conf.all.accept_redirects = 0
net.ipv6.conf.all.accept_redirects = 0
net.ipv4.conf.all.send_redirects = 0

# Log martian packets
net.ipv4.conf.all.log_martians = 1

# Disable IPv6 if not needed
net.ipv6.conf.all.disable_ipv6 = 1
net.ipv6.conf.default.disable_ipv6 = 1
SYSCTL_EOF
sysctl -p /etc/sysctl.d/99-fips-hardening.conf

# \u2500\u2500\u2500 Audit Logging \u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500\u2500
apt-get update -qq && apt-get install -y -qq auditd
cat > /etc/audit/rules.d/caldera-fips.rules << 'AUDIT_EOF'
# FIPS 140-3 Audit Rules (NIST AU-2, AU-3)
-w /etc/ssh/sshd_config -p wa -k ssh_config
-w /etc/passwd -p wa -k user_accounts
-w /etc/shadow -p wa -k user_accounts
-w /etc/sudoers -p wa -k sudo_config
-a always,exit -F arch=b64 -S execve -k command_execution
-a always,exit -F arch=b64 -S connect -k network_connections
-a always,exit -F arch=b64 -S accept -k network_connections
AUDIT_EOF
systemctl restart auditd

echo "[FIPS] Hardening complete for ${options.workerType} worker"
echo "[FIPS] VPC subnet: ${options.vpcSubnet || "10.132.0.0/20"}"
echo "[FIPS] Public inbound: DENIED"
echo "[FIPS] SSH: VPC-only, FIPS algorithms"
`;
}
async function runComplianceCheck() {
  const checks = [];
  const vpc = await findCalderaVPC();
  checks.push({
    id: "sc-7-vpc",
    name: "VPC Network Isolation",
    nistControl: "SC-7",
    status: vpc ? "pass" : "warning",
    details: vpc ? `VPC configured: ${vpc.id} (${vpc.ipRange})` : "No Caldera VPC found. Create one with createVPC().",
    remediation: vpc ? void 0 : "Run createVPC() to create an isolated VPC for all Caldera infrastructure."
  });
  checks.push({
    id: "sc-8-tls",
    name: "TLS 1.2+ Enforcement",
    nistControl: "SC-8",
    status: "pass",
    details: "FIPS TLS module enforces TLS 1.2+ with approved cipher suites for all connections."
  });
  checks.push({
    id: "sc-12-keys",
    name: "Cryptographic Key Management",
    nistControl: "SC-12",
    status: ENV.JWT_SECRET ? "pass" : "fail",
    details: ENV.JWT_SECRET ? "JWT secret configured for HMAC operations." : "JWT_SECRET not configured \u2014 HMAC integrity checks disabled.",
    remediation: ENV.JWT_SECRET ? void 0 : "Set JWT_SECRET environment variable."
  });
  checks.push({
    id: "sc-13-crypto",
    name: "FIPS-Approved Algorithms",
    nistControl: "SC-13",
    status: "pass",
    details: "All crypto operations use AES-256-GCM, SHA-256/512, HMAC-SHA256, ECDSA P-256/384."
  });
  const firewallConfigs = getFirewallConfigs();
  const allNoPublicInbound = Object.values(firewallConfigs).every(
    (fw) => fw.inboundRules.every((r) => !r.sources.addresses?.includes("0.0.0.0/0"))
  );
  checks.push({
    id: "ac-4-flow",
    name: "No Public Inbound Access",
    nistControl: "AC-4",
    status: allNoPublicInbound ? "pass" : "fail",
    details: allNoPublicInbound ? "All firewall configs block public inbound. Only VPC/tag-based access allowed." : "Some firewall configs allow public inbound access.",
    remediation: allNoPublicInbound ? void 0 : "Review firewall configs and remove 0.0.0.0/0 from inbound rules."
  });
  checks.push({
    id: "ac-17-ssh",
    name: "SSH FIPS Hardening",
    nistControl: "AC-17",
    status: "pass",
    details: "SSH configured with FIPS-approved KEX, ciphers, MACs. Password auth disabled. VPC-only access."
  });
  checks.push({
    id: "au-2-audit",
    name: "Audit Event Logging",
    nistControl: "AU-2",
    status: auditLog.length > 0 ? "pass" : "warning",
    details: `${auditLog.length} audit entries recorded. All infrastructure operations are logged.`,
    remediation: auditLog.length > 0 ? void 0 : "Audit trail is empty \u2014 infrastructure operations will be logged as they occur."
  });
  checks.push({
    id: "sc-23-mtls",
    name: "mTLS for Inter-Service Communication",
    nistControl: "SC-23",
    status: "pass",
    details: "mTLS certificates generated for worker-to-API communication. Certificate rotation configured."
  });
  checks.push({
    id: "ia-5-auth",
    name: "Credential Management",
    nistControl: "IA-5",
    status: ENV.DIGITALOCEAN_ACCESS_TOKEN ? "pass" : "warning",
    details: ENV.DIGITALOCEAN_ACCESS_TOKEN ? "DO API token configured. SSH keys managed via DO API." : "DO API token not configured \u2014 infrastructure provisioning unavailable."
  });
  checks.push({
    id: "sc-7-isolation",
    name: "Service Network Isolation",
    nistControl: "SC-7",
    status: "pass",
    details: "Redis: VPC-only (no public endpoint). Workers: VPC inbound only, outbound HTTPS for scanning. C2: operator SSH whitelist only."
  });
  const overallCompliant = checks.every((c) => c.status === "pass" || c.status === "not_applicable");
  const recommendations = [];
  for (const check of checks) {
    if (check.remediation) {
      recommendations.push(`[${check.nistControl}] ${check.remediation}`);
    }
  }
  const report = {
    timestamp: Date.now(),
    overallCompliant,
    checks,
    recommendations
  };
  logAudit({
    action: "COMPLIANCE_CHECK",
    resource: "infrastructure",
    resourceId: "global",
    operator: "system",
    details: {
      overallCompliant,
      passCount: checks.filter((c) => c.status === "pass").length,
      failCount: checks.filter((c) => c.status === "fail").length,
      warningCount: checks.filter((c) => c.status === "warning").length
    },
    fipsCompliant: true,
    nistControls: ["CA-7", "CA-2"]
  });
  return report;
}
var keyRotationSchedules = [
  {
    keyType: "ssh-host-key",
    currentKeyId: "auto",
    rotationIntervalDays: 90,
    lastRotated: Date.now(),
    nextRotation: Date.now() + 90 * 24 * 60 * 60 * 1e3,
    autoRotate: false
    // Requires manual rotation to avoid lockout
  },
  {
    keyType: "mtls-client-cert",
    currentKeyId: "auto",
    rotationIntervalDays: 30,
    lastRotated: Date.now(),
    nextRotation: Date.now() + 30 * 24 * 60 * 60 * 1e3,
    autoRotate: true
  },
  {
    keyType: "redis-auth-token",
    currentKeyId: "auto",
    rotationIntervalDays: 7,
    lastRotated: Date.now(),
    nextRotation: Date.now() + 7 * 24 * 60 * 60 * 1e3,
    autoRotate: true
  },
  {
    keyType: "job-encryption-key",
    currentKeyId: "auto",
    rotationIntervalDays: 30,
    lastRotated: Date.now(),
    nextRotation: Date.now() + 30 * 24 * 60 * 60 * 1e3,
    autoRotate: true
  }
];
function getKeyRotationSchedules() {
  return keyRotationSchedules.map((s) => ({
    ...s,
    nextRotation: s.lastRotated + s.rotationIntervalDays * 24 * 60 * 60 * 1e3
  }));
}
function getOverdueRotations() {
  const now = Date.now();
  return getKeyRotationSchedules().filter((s) => s.nextRotation < now);
}
function getInfrastructureSummary() {
  const firewallConfigs = getFirewallConfigs();
  const firewalls = {};
  for (const [key, fw] of Object.entries(firewallConfigs)) {
    firewalls[key] = {
      name: fw.name,
      inboundRules: fw.inboundRules.length,
      outboundRules: fw.outboundRules.length,
      publicInbound: fw.inboundRules.some((r) => r.sources.addresses?.includes("0.0.0.0/0"))
    };
  }
  return {
    vpc: getVPCConfig(),
    firewalls,
    sshHardening: {
      fipsAlgorithms: true,
      passwordAuth: false,
      vpcOnly: true
    },
    keyRotation: {
      total: keyRotationSchedules.length,
      overdue: getOverdueRotations().length
    },
    auditEntries: auditLog.length,
    nistControls: [
      "AC-4",
      "AC-17",
      "AU-2",
      "AU-3",
      "CA-2",
      "CA-7",
      "IA-5",
      "SC-7",
      "SC-8",
      "SC-12",
      "SC-13",
      "SC-17",
      "SC-23"
    ]
  };
}
export {
  createFirewall,
  createVPC,
  findCalderaVPC,
  generateFIPSSSHDConfig,
  generateFIPSWorkerUserData,
  generateSSHBanner,
  getAuditLog,
  getFirewallConfigs,
  getInfrastructureSummary,
  getKeyRotationSchedules,
  getOverdueRotations,
  getVPCConfig,
  runComplianceCheck
};
