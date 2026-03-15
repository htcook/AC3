/**
 * OpSec Hardening & Monitoring Engine
 * 
 * Based on Red Team Infrastructure Wiki principles:
 *   - iptables filtering between components
 *   - SSH public-key only + MFA
 *   - chattr to prevent cron modification
 *   - Regular updates and Docker containerization
 *   - Centralized logging (rsyslog, Splunk)
 *   - High-value event alerting
 *   - IR fingerprinting before assessment
 *   - Modify default response headers, restrict open ports
 * 
 * Provides:
 *   - Infrastructure security posture scoring
 *   - Hardening checklist with automated verification
 *   - Centralized log aggregation configuration
 *   - IR countermeasure recommendations
 *   - OpSec violation alerting
 */

export type HardeningCategory = "ssh" | "firewall" | "services" | "logging" | "containers" | "encryption" | "headers" | "dns" | "certificates" | "updates";
export type CheckStatus = "pass" | "fail" | "warn" | "not_checked" | "not_applicable";
export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type AlertType = "opsec_violation" | "health_degraded" | "certificate_expiry" | "suspicious_activity" | "config_drift";

export interface HardeningCheck {
  id: string;
  category: HardeningCategory;
  name: string;
  description: string;
  severity: Severity;
  /** The command or method to verify this check */
  verificationMethod: string;
  /** Remediation steps if check fails */
  remediation: string;
  /** Current status */
  status: CheckStatus;
  /** Last check timestamp */
  lastChecked?: number;
  /** Details from last check */
  details?: string;
  /** MITRE ATT&CK technique this mitigates */
  mitigates?: string[];
  /** Wiki reference section */
  wikiReference?: string;
}

export interface OpSecPosture {
  /** Overall score 0-100 */
  overallScore: number;
  /** Score breakdown by category */
  categoryScores: Record<HardeningCategory, { score: number; total: number; passed: number; failed: number }>;
  /** Critical failures that need immediate attention */
  criticalFindings: HardeningCheck[];
  /** Checks that passed */
  passedChecks: HardeningCheck[];
  /** All checks */
  allChecks: HardeningCheck[];
  /** Timestamp of assessment */
  assessedAt: number;
}

export interface LogSource {
  id: string;
  name: string;
  type: "syslog" | "auth_log" | "web_access" | "c2_log" | "phishing_log" | "dns_log" | "firewall_log";
  host: string;
  port: number;
  protocol: "tcp" | "udp" | "tls";
  status: "connected" | "disconnected" | "error";
  lastEvent?: number;
  eventsPerMinute: number;
}

export interface OpSecAlert {
  id: string;
  type: AlertType;
  severity: Severity;
  title: string;
  description: string;
  source: string;
  timestamp: number;
  acknowledged: boolean;
  /** Recommended response */
  recommendation: string;
}

export interface IRCountermeasure {
  id: string;
  name: string;
  description: string;
  category: "traffic_analysis" | "dns_analysis" | "endpoint_forensics" | "network_forensics" | "osint_investigation";
  /** What IR teams look for */
  irTechnique: string;
  /** How to counter/evade it */
  countermeasure: string;
  /** Implementation status */
  implemented: boolean;
  /** Difficulty to implement */
  difficulty: "easy" | "medium" | "hard";
  /** MITRE ATT&CK technique */
  mitreTechnique?: string;
}

// ── In-memory store ────────────────────────────────────────────────────

const alerts: OpSecAlert[] = [];
const logSources: LogSource[] = [];
let nextId = 1;

function genId(prefix: string): string {
  return `${prefix}-${Date.now()}-${nextId++}`;
}

// ── Hardening Checklist ────────────────────────────────────────────────

const HARDENING_CHECKS: HardeningCheck[] = [
  // SSH Hardening
  {
    id: "ssh-001", category: "ssh", name: "SSH Key-Only Authentication",
    description: "Disable password authentication and require SSH key-based login",
    severity: "critical",
    verificationMethod: "grep -i 'PasswordAuthentication no' /etc/ssh/sshd_config",
    remediation: "Set 'PasswordAuthentication no' in /etc/ssh/sshd_config and restart sshd",
    status: "not_checked",
    mitigates: ["T1110.001", "T1110.003"],
    wikiReference: "Infrastructure Security > SSH",
  },
  {
    id: "ssh-002", category: "ssh", name: "SSH Root Login Disabled",
    description: "Prevent direct root login via SSH",
    severity: "high",
    verificationMethod: "grep -i 'PermitRootLogin prohibit-password' /etc/ssh/sshd_config",
    remediation: "Set 'PermitRootLogin prohibit-password' in /etc/ssh/sshd_config",
    status: "not_checked",
    mitigates: ["T1078.003"],
  },
  {
    id: "ssh-003", category: "ssh", name: "SSH Non-Standard Port",
    description: "Move SSH to a non-standard port to reduce automated scanning",
    severity: "medium",
    verificationMethod: "grep -i '^Port' /etc/ssh/sshd_config | grep -v 22",
    remediation: "Change SSH port in /etc/ssh/sshd_config to a non-standard port (e.g., 2222)",
    status: "not_checked",
    mitigates: ["T1046"],
  },
  {
    id: "ssh-004", category: "ssh", name: "SSH MFA Enabled",
    description: "Enable multi-factor authentication for SSH access",
    severity: "medium",
    verificationMethod: "grep -i 'AuthenticationMethods publickey,keyboard-interactive' /etc/ssh/sshd_config",
    remediation: "Install libpam-google-authenticator and configure SSH for MFA",
    status: "not_checked",
    mitigates: ["T1078"],
  },

  // Firewall
  {
    id: "fw-001", category: "firewall", name: "Firewall Enabled (UFW/iptables)",
    description: "Ensure host-based firewall is active with default-deny policy",
    severity: "critical",
    verificationMethod: "ufw status | grep 'Status: active'",
    remediation: "Run 'ufw enable' and configure rules for required ports only",
    status: "not_checked",
    mitigates: ["T1046", "T1190"],
    wikiReference: "Infrastructure Security > iptables",
  },
  {
    id: "fw-002", category: "firewall", name: "Inter-Component Filtering",
    description: "iptables rules between redirectors and team servers to limit lateral movement",
    severity: "high",
    verificationMethod: "iptables -L -n | grep -c 'ACCEPT\\|DROP'",
    remediation: "Configure iptables rules to only allow necessary traffic between components",
    status: "not_checked",
    mitigates: ["T1021"],
  },
  {
    id: "fw-003", category: "firewall", name: "Egress Filtering",
    description: "Restrict outbound connections to only necessary destinations",
    severity: "medium",
    verificationMethod: "iptables -L OUTPUT -n | grep -c 'DROP'",
    remediation: "Add iptables OUTPUT rules to restrict egress to known-good destinations",
    status: "not_checked",
  },

  // Services
  {
    id: "svc-001", category: "services", name: "Unnecessary Services Disabled",
    description: "Only required services should be running on each component",
    severity: "high",
    verificationMethod: "systemctl list-units --type=service --state=running | wc -l",
    remediation: "Disable unnecessary services with 'systemctl disable <service>'",
    status: "not_checked",
    mitigates: ["T1190"],
  },
  {
    id: "svc-002", category: "services", name: "Cron Immutability (chattr)",
    description: "Use chattr +ia on crontab files to prevent modification by attackers",
    severity: "medium",
    verificationMethod: "lsattr /var/spool/cron/crontabs/* 2>/dev/null | grep -c 'i'",
    remediation: "Run 'chattr +ia /var/spool/cron/crontabs/*' to make cron files immutable",
    status: "not_checked",
    wikiReference: "Infrastructure Security > chattr",
  },
  {
    id: "svc-003", category: "services", name: "Docker Containerization",
    description: "Run services in Docker containers for isolation",
    severity: "medium",
    verificationMethod: "docker ps --format '{{.Names}}' | wc -l",
    remediation: "Containerize services using Docker for better isolation and reproducibility",
    status: "not_checked",
  },

  // Logging
  {
    id: "log-001", category: "logging", name: "Centralized Log Aggregation",
    description: "All component logs should be forwarded to a central log sink",
    severity: "high",
    verificationMethod: "grep -c 'remote' /etc/rsyslog.conf",
    remediation: "Configure rsyslog to forward logs to central log server",
    status: "not_checked",
    wikiReference: "Logging > Central Logging",
  },
  {
    id: "log-002", category: "logging", name: "Log Rotation Configured",
    description: "Ensure log rotation is configured to prevent disk exhaustion",
    severity: "medium",
    verificationMethod: "ls /etc/logrotate.d/ | wc -l",
    remediation: "Configure logrotate for all service logs",
    status: "not_checked",
  },
  {
    id: "log-003", category: "logging", name: "High-Value Event Alerting",
    description: "Configure alerts for critical events (new sessions, failed logins, config changes)",
    severity: "high",
    verificationMethod: "Check alerting configuration for critical events",
    remediation: "Set up Slack/email alerts for high-value events using log monitoring",
    status: "not_checked",
    wikiReference: "Logging > Alerting",
  },

  // Headers & Fingerprinting
  {
    id: "hdr-001", category: "headers", name: "Default Server Headers Removed",
    description: "Remove or modify default server response headers (Server, X-Powered-By)",
    severity: "high",
    verificationMethod: "curl -sI https://redirector | grep -i 'server\\|x-powered-by'",
    remediation: "Configure web server to remove/modify Server and X-Powered-By headers",
    status: "not_checked",
    mitigates: ["T1592.004"],
    wikiReference: "Infrastructure Obscuring > Modify Server Headers",
  },
  {
    id: "hdr-002", category: "headers", name: "Custom Error Pages",
    description: "Replace default error pages with generic/decoy content",
    severity: "medium",
    verificationMethod: "curl -s https://redirector/nonexistent | grep -c 'Apache\\|nginx'",
    remediation: "Configure custom error pages that don't reveal server technology",
    status: "not_checked",
    wikiReference: "Infrastructure Obscuring > Modify Landing Pages",
  },
  {
    id: "hdr-003", category: "headers", name: "Invalid URI Redirection",
    description: "Redirect requests to invalid URIs to a decoy site (e.g., google.com)",
    severity: "medium",
    verificationMethod: "curl -sI https://redirector/random-path | grep -i 'location'",
    remediation: "Configure mod_rewrite or nginx to redirect invalid URIs to a decoy",
    status: "not_checked",
    wikiReference: "Infrastructure Obscuring > Redirect Invalid URIs",
  },

  // Certificates
  {
    id: "cert-001", category: "certificates", name: "Valid SSL Certificates",
    description: "All HTTPS endpoints should have valid, non-expired SSL certificates",
    severity: "critical",
    verificationMethod: "openssl s_client -connect redirector:443 | openssl x509 -noout -dates",
    remediation: "Install/renew SSL certificates using Let's Encrypt (certbot)",
    status: "not_checked",
    mitigates: ["T1557"],
  },
  {
    id: "cert-002", category: "certificates", name: "Certificate Auto-Renewal",
    description: "SSL certificates should auto-renew before expiration",
    severity: "high",
    verificationMethod: "certbot certificates | grep -i 'expiry'",
    remediation: "Configure certbot auto-renewal cron job",
    status: "not_checked",
  },

  // DNS
  {
    id: "dns-001", category: "dns", name: "SPF Record Configured",
    description: "SPF DNS record configured for phishing domains to improve deliverability",
    severity: "high",
    verificationMethod: "dig TXT domain.com | grep 'v=spf1'",
    remediation: "Add SPF TXT record: v=spf1 ip4:<smtp-ip> -all",
    status: "not_checked",
    wikiReference: "Phishing Setup > SPF",
  },
  {
    id: "dns-002", category: "dns", name: "DKIM Signing Enabled",
    description: "DKIM signing configured for outbound phishing emails",
    severity: "high",
    verificationMethod: "dig TXT default._domainkey.domain.com",
    remediation: "Install opendkim and configure DKIM signing for the phishing domain",
    status: "not_checked",
    wikiReference: "Phishing Setup > DKIM",
  },
  {
    id: "dns-003", category: "dns", name: "DMARC Record Published",
    description: "DMARC DNS record published for phishing domains",
    severity: "medium",
    verificationMethod: "dig TXT _dmarc.domain.com",
    remediation: "Add DMARC TXT record: v=DMARC1; p=none; rua=mailto:dmarc@domain.com",
    status: "not_checked",
    wikiReference: "Phishing Setup > DMARC",
  },

  // Updates
  {
    id: "upd-001", category: "updates", name: "System Packages Updated",
    description: "All system packages should be up to date",
    severity: "high",
    verificationMethod: "apt list --upgradable 2>/dev/null | wc -l",
    remediation: "Run 'apt update && apt upgrade -y' on all components",
    status: "not_checked",
    wikiReference: "Infrastructure Security > Updates",
  },
  {
    id: "upd-002", category: "updates", name: "Automatic Security Updates",
    description: "Enable unattended-upgrades for automatic security patches",
    severity: "medium",
    verificationMethod: "dpkg -l | grep unattended-upgrades",
    remediation: "Install and configure unattended-upgrades package",
    status: "not_checked",
  },

  // Encryption
  {
    id: "enc-001", category: "encryption", name: "Disk Encryption (EBS/Volume)",
    description: "Cloud volumes should be encrypted at rest",
    severity: "high",
    verificationMethod: "Check cloud provider volume encryption settings",
    remediation: "Enable volume encryption in cloud provider settings",
    status: "not_checked",
    wikiReference: "Infrastructure Security > Encrypted Volumes",
  },
  {
    id: "enc-002", category: "encryption", name: "Encrypted Communications",
    description: "All inter-component communication should be encrypted (TLS/SSH)",
    severity: "critical",
    verificationMethod: "Verify all internal connections use TLS or SSH tunnels",
    remediation: "Configure TLS for all internal services or use SSH tunnels",
    status: "not_checked",
  },
];

// ── IR Countermeasures ─────────────────────────────────────────────────

export const IR_COUNTERMEASURES: IRCountermeasure[] = [
  {
    id: "ir-001", name: "JARM Fingerprint Randomization",
    description: "Randomize TLS JARM fingerprints to avoid C2 server identification",
    category: "traffic_analysis",
    irTechnique: "IR teams use JARM scanning to fingerprint C2 servers by their TLS implementation",
    countermeasure: "Use a CDN or reverse proxy (Cloudflare, nginx) in front of C2 to mask the real JARM fingerprint",
    implemented: false, difficulty: "medium",
    mitreTechnique: "T1071.001",
  },
  {
    id: "ir-002", name: "JA3/JA3S Hash Spoofing",
    description: "Modify TLS client/server hello to match legitimate software JA3 hashes",
    category: "traffic_analysis",
    irTechnique: "IR teams match JA3/JA3S hashes against known C2 framework fingerprints",
    countermeasure: "Configure C2 to use TLS libraries that produce JA3 hashes matching common browsers",
    implemented: false, difficulty: "hard",
    mitreTechnique: "T1071.001",
  },
  {
    id: "ir-003", name: "DNS Request Pattern Obfuscation",
    description: "Randomize DNS query timing and subdomain patterns for DNS-based C2",
    category: "dns_analysis",
    irTechnique: "IR teams detect DNS C2 by analyzing query frequency, entropy, and subdomain patterns",
    countermeasure: "Add jitter to DNS queries, use low-entropy subdomains, and mix with legitimate DNS traffic",
    implemented: false, difficulty: "medium",
    mitreTechnique: "T1071.004",
  },
  {
    id: "ir-004", name: "Beacon Interval Randomization",
    description: "Randomize C2 beacon intervals to avoid periodic traffic detection",
    category: "traffic_analysis",
    irTechnique: "IR teams detect C2 beacons by identifying periodic network connections",
    countermeasure: "Use high jitter (40-60%) and vary sleep times to break periodicity patterns",
    implemented: false, difficulty: "easy",
    mitreTechnique: "T1071.001",
  },
  {
    id: "ir-005", name: "Domain Age Verification",
    description: "Use aged domains (1+ years) to avoid newly-registered domain detection",
    category: "osint_investigation",
    irTechnique: "IR teams flag recently registered domains as suspicious infrastructure",
    countermeasure: "Acquire expired domains with established history and categorization",
    implemented: false, difficulty: "easy",
    mitreTechnique: "T1583.001",
  },
  {
    id: "ir-006", name: "Payload Link Expiration",
    description: "Expire phishing payload download links after first use or time limit",
    category: "endpoint_forensics",
    irTechnique: "IR teams attempt to download payloads from phishing links for analysis",
    countermeasure: "Configure one-time-use links or time-limited URLs for payload delivery",
    implemented: false, difficulty: "easy",
    mitreTechnique: "T1608.001",
  },
  {
    id: "ir-007", name: "Redirector Log Scrubbing",
    description: "Automatically scrub redirector logs to remove evidence of C2 traffic",
    category: "network_forensics",
    irTechnique: "IR teams analyze web server logs on seized redirectors to trace C2 traffic",
    countermeasure: "Configure log rotation with short retention, or forward logs to team server and scrub locally",
    implemented: false, difficulty: "easy",
    mitreTechnique: "T1070.002",
  },
  {
    id: "ir-008", name: "Cloud Provider Diversity",
    description: "Distribute infrastructure across multiple cloud providers and regions",
    category: "osint_investigation",
    irTechnique: "IR teams identify and block entire IP ranges from a single provider",
    countermeasure: "Use 2-3 different cloud providers and spread across multiple regions",
    implemented: false, difficulty: "medium",
    mitreTechnique: "T1583.003",
  },
  {
    id: "ir-009", name: "Certificate Transparency Monitoring",
    description: "Monitor CT logs for your operational domains to detect early IR discovery",
    category: "osint_investigation",
    irTechnique: "IR teams monitor Certificate Transparency logs to discover attacker infrastructure",
    countermeasure: "Use wildcard certificates or avoid CT logging where possible; monitor CT logs proactively",
    implemented: false, difficulty: "medium",
    mitreTechnique: "T1596.003",
  },
  {
    id: "ir-010", name: "Shodan/Censys Evasion",
    description: "Block known scanner IP ranges and avoid default service banners",
    category: "osint_investigation",
    irTechnique: "IR teams use Shodan/Censys to discover and fingerprint attacker infrastructure",
    countermeasure: "Block scanner IPs via iptables, modify default banners, restrict open ports",
    implemented: false, difficulty: "easy",
    mitreTechnique: "T1595.002",
  },
];

// ── Posture Assessment ─────────────────────────────────────────────────

export function assessPosture(targetHost?: string): OpSecPosture {
  // Run all checks (simulated for platform — in production would SSH to hosts)
  const checks = HARDENING_CHECKS.map(check => {
    const simulated = simulateCheck(check);
    return { ...check, ...simulated };
  });

  const categoryScores: OpSecPosture["categoryScores"] = {} as any;
  const categories: HardeningCategory[] = ["ssh", "firewall", "services", "logging", "containers", "encryption", "headers", "dns", "certificates", "updates"];
  
  for (const cat of categories) {
    const catChecks = checks.filter(c => c.category === cat);
    const passed = catChecks.filter(c => c.status === "pass").length;
    const failed = catChecks.filter(c => c.status === "fail").length;
    const total = catChecks.length;
    categoryScores[cat] = {
      score: total > 0 ? Math.round((passed / total) * 100) : 0,
      total,
      passed,
      failed,
    };
  }

  const totalChecks = checks.length;
  const totalPassed = checks.filter(c => c.status === "pass").length;
  const overallScore = Math.round((totalPassed / totalChecks) * 100);

  return {
    overallScore,
    categoryScores,
    criticalFindings: checks.filter(c => c.status === "fail" && (c.severity === "critical" || c.severity === "high")),
    passedChecks: checks.filter(c => c.status === "pass"),
    allChecks: checks,
    assessedAt: Date.now(),
  };
}

function simulateCheck(check: HardeningCheck): { status: CheckStatus; lastChecked: number; details: string } {
  // Simulate check results based on check ID for deterministic testing
  const hash = simpleHash(check.id);
  const passed = hash % 3 !== 0; // ~67% pass rate
  
  return {
    status: passed ? "pass" : "fail",
    lastChecked: Date.now(),
    details: passed
      ? `Check passed: ${check.name}`
      : `Check failed: ${check.remediation}`,
  };
}

function simpleHash(str: string): number {
  let hash = 0;
  for (let i = 0; i < str.length; i++) {
    hash = ((hash << 5) - hash) + str.charCodeAt(i);
    hash = hash & hash;
  }
  return Math.abs(hash);
}

// ── Alert Management ───────────────────────────────────────────────────

export function createAlert(input: Omit<OpSecAlert, "id" | "timestamp" | "acknowledged">): OpSecAlert {
  const alert: OpSecAlert = {
    ...input,
    id: genId("alert"),
    timestamp: Date.now(),
    acknowledged: false,
  };
  alerts.unshift(alert);
  if (alerts.length > 500) alerts.pop();
  return alert;
}

export function listAlerts(filters?: { type?: AlertType; severity?: Severity; acknowledged?: boolean }): OpSecAlert[] {
  let results = [...alerts];
  if (filters?.type) results = results.filter(a => a.type === filters.type);
  if (filters?.severity) results = results.filter(a => a.severity === filters.severity);
  if (filters?.acknowledged !== undefined) results = results.filter(a => a.acknowledged === filters.acknowledged);
  return results;
}

export function acknowledgeAlert(id: string): boolean {
  const alert = alerts.find(a => a.id === id);
  if (!alert) return false;
  alert.acknowledged = true;
  return true;
}

// ── Log Source Management ──────────────────────────────────────────────

export function addLogSource(input: Omit<LogSource, "id" | "status" | "eventsPerMinute">): LogSource {
  const source: LogSource = {
    ...input,
    id: genId("log"),
    status: "connected",
    eventsPerMinute: Math.floor(Math.random() * 100) + 10,
  };
  logSources.push(source);
  return source;
}

export function listLogSources(): LogSource[] {
  return [...logSources];
}

export function removeLogSource(id: string): boolean {
  const idx = logSources.findIndex(s => s.id === id);
  if (idx === -1) return false;
  logSources.splice(idx, 1);
  return true;
}

// ── IR Countermeasures ─────────────────────────────────────────────────

export function getIRCountermeasures(): IRCountermeasure[] {
  return [...IR_COUNTERMEASURES];
}

export function toggleCountermeasure(id: string): IRCountermeasure | null {
  const cm = IR_COUNTERMEASURES.find(c => c.id === id);
  if (!cm) return null;
  cm.implemented = !cm.implemented;
  return cm;
}

export function getCountermeasureStats(): {
  total: number;
  implemented: number;
  pending: number;
  byCategory: Record<string, { total: number; implemented: number }>;
  byDifficulty: Record<string, number>;
} {
  const total = IR_COUNTERMEASURES.length;
  const implemented = IR_COUNTERMEASURES.filter(c => c.implemented).length;
  
  const byCategory: Record<string, { total: number; implemented: number }> = {};
  const byDifficulty: Record<string, number> = { easy: 0, medium: 0, hard: 0 };

  for (const cm of IR_COUNTERMEASURES) {
    if (!byCategory[cm.category]) byCategory[cm.category] = { total: 0, implemented: 0 };
    byCategory[cm.category].total++;
    if (cm.implemented) byCategory[cm.category].implemented++;
    byDifficulty[cm.difficulty]++;
  }

  return { total, implemented, pending: total - implemented, byCategory, byDifficulty };
}

// ── Rsyslog Config Generator ───────────────────────────────────────────

export function generateRsyslogConfig(logSinkHost: string, logSinkPort: number): string {
  return `# rsyslog Configuration for Red Team Infrastructure
# Generated by AC3 OpSec Monitor
# Forward all logs to central log sink

# Load modules
module(load="imuxsock")
module(load="imklog")
module(load="imtcp")
module(load="imudp")

# Forward all logs to central server
*.* @@${logSinkHost}:${logSinkPort}

# Local logging
auth,authpriv.*     /var/log/auth.log
*.*;auth,authpriv.none  /var/log/syslog
kern.*              /var/log/kern.log

# High-value event alerting
# Uncomment and configure for Slack/email alerts
# :msg, contains, "Failed password" ^/usr/local/bin/alert-failed-login.sh
# :msg, contains, "session opened" ^/usr/local/bin/alert-new-session.sh
`;
}

// ── Reset (for testing) ────────────────────────────────────────────────

export function _resetForTesting(): void {
  alerts.length = 0;
  logSources.length = 0;
  nextId = 1;
  // Reset IR countermeasures
  for (const cm of IR_COUNTERMEASURES) {
    cm.implemented = false;
  }
}
