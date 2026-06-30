/**
 * OpSec Scheduled Scans Service
 * Recurring SSH-based posture assessments with notification alerts.
 */

import { notifyOwner } from "../_core/notification";

// ─── Types ────────────────────────────────────────────────────────────────────

export interface ScanTarget {
  id: string;
  name: string;
  host: string;
  port: number;
  tags: string[];
}

export interface ScanCheck {
  id: string;
  name: string;
  category: "ssh" | "firewall" | "services" | "users" | "filesystem" | "network" | "logging";
  severity: "critical" | "high" | "medium" | "low" | "info";
  description: string;
  command: string;
  expectedPattern: string;
}

export interface ScanFinding {
  checkId: string;
  checkName: string;
  category: string;
  severity: string;
  status: "pass" | "fail" | "error" | "skip";
  output: string;
  remediation: string;
}

export interface ScanResult {
  id: string;
  targetId: string;
  targetName: string;
  startedAt: number;
  completedAt: number;
  findings: ScanFinding[];
  score: number;
  passCount: number;
  failCount: number;
  errorCount: number;
}

export interface ScheduledScan {
  id: string;
  name: string;
  targets: ScanTarget[];
  checks: string[];
  intervalHours: number;
  enabled: boolean;
  lastRun: number | null;
  nextRun: number;
  notifyOnFail: boolean;
  notifyThreshold: number;
}

// ─── Built-in Checks ─────────────────────────────────────────────────────────

const BUILTIN_CHECKS: ScanCheck[] = [
  { id: "ssh-root-login", name: "SSH Root Login Disabled", category: "ssh", severity: "critical",
    description: "Verify PermitRootLogin is set to no or prohibit-password",
    command: "grep -E '^PermitRootLogin' /etc/ssh/sshd_config || echo 'NOT_SET'",
    expectedPattern: "(no|prohibit-password)" },
  { id: "ssh-password-auth", name: "SSH Password Auth Disabled", category: "ssh", severity: "critical",
    description: "Verify password authentication is disabled",
    command: "grep -E '^PasswordAuthentication' /etc/ssh/sshd_config || echo 'NOT_SET'",
    expectedPattern: "no" },
  { id: "ssh-port", name: "SSH Non-Default Port", category: "ssh", severity: "medium",
    description: "Check if SSH runs on a non-standard port",
    command: "grep -E '^Port' /etc/ssh/sshd_config || echo 'Port 22'",
    expectedPattern: "^Port (?!22)" },
  { id: "fw-enabled", name: "Firewall Active", category: "firewall", severity: "critical",
    description: "Verify UFW or iptables firewall is active",
    command: "ufw status 2>/dev/null || iptables -L -n 2>/dev/null | head -5",
    expectedPattern: "(active|Chain)" },
  { id: "fw-default-deny", name: "Default Deny Incoming", category: "firewall", severity: "high",
    description: "Verify default incoming policy is deny/drop",
    command: "ufw status verbose 2>/dev/null | grep 'Default:' || iptables -L INPUT -n 2>/dev/null | head -1",
    expectedPattern: "(deny|DROP)" },
  { id: "svc-no-telnet", name: "No Telnet Service", category: "services", severity: "high",
    description: "Verify telnet is not running",
    command: "ss -tlnp | grep ':23 ' || echo 'NOT_FOUND'",
    expectedPattern: "NOT_FOUND" },
  { id: "svc-no-ftp", name: "No FTP Service", category: "services", severity: "high",
    description: "Verify FTP is not running",
    command: "ss -tlnp | grep ':21 ' || echo 'NOT_FOUND'",
    expectedPattern: "NOT_FOUND" },
  { id: "svc-fail2ban", name: "Fail2Ban Active", category: "services", severity: "medium",
    description: "Verify fail2ban is running",
    command: "systemctl is-active fail2ban 2>/dev/null || echo 'inactive'",
    expectedPattern: "^active" },
  { id: "usr-no-empty-pw", name: "No Empty Passwords", category: "users", severity: "critical",
    description: "Check for accounts with empty passwords",
    command: "awk -F: '($2 == \"\") {print $1}' /etc/shadow 2>/dev/null || echo 'NONE'",
    expectedPattern: "^NONE$" },
  { id: "usr-sudo-limited", name: "Limited Sudo Users", category: "users", severity: "high",
    description: "Count users with sudo access",
    command: "grep -c '' /etc/sudoers.d/* 2>/dev/null; getent group sudo | awk -F: '{print NF-3}'",
    expectedPattern: "^[0-3]$" },
  { id: "fs-tmp-noexec", name: "/tmp Mounted noexec", category: "filesystem", severity: "medium",
    description: "Verify /tmp has noexec mount option",
    command: "mount | grep ' /tmp ' || echo 'NOT_SEPARATE'",
    expectedPattern: "noexec" },
  { id: "fs-world-writable", name: "No World-Writable Files in /etc", category: "filesystem", severity: "high",
    description: "Check for world-writable files in /etc",
    command: "find /etc -maxdepth 2 -perm -0002 -type f 2>/dev/null | head -5 || echo 'NONE'",
    expectedPattern: "^NONE$" },
  { id: "net-ip-forward", name: "IP Forwarding Disabled", category: "network", severity: "medium",
    description: "Verify IP forwarding is disabled unless needed",
    command: "sysctl net.ipv4.ip_forward 2>/dev/null",
    expectedPattern: "= 0" },
  { id: "net-syn-cookies", name: "SYN Cookies Enabled", category: "network", severity: "medium",
    description: "Verify SYN cookies are enabled",
    command: "sysctl net.ipv4.tcp_syncookies 2>/dev/null",
    expectedPattern: "= 1" },
  { id: "log-syslog", name: "Syslog Running", category: "logging", severity: "high",
    description: "Verify syslog daemon is active",
    command: "systemctl is-active rsyslog 2>/dev/null || systemctl is-active syslog-ng 2>/dev/null || echo 'inactive'",
    expectedPattern: "^active" },
  { id: "log-auth", name: "Auth Logging Enabled", category: "logging", severity: "high",
    description: "Verify auth.log exists and is being written",
    command: "ls -la /var/log/auth.log 2>/dev/null || ls -la /var/log/secure 2>/dev/null || echo 'NOT_FOUND'",
    expectedPattern: "^-" },
  { id: "log-audit", name: "Auditd Active", category: "logging", severity: "medium",
    description: "Verify auditd is running for system auditing",
    command: "systemctl is-active auditd 2>/dev/null || echo 'inactive'",
    expectedPattern: "^active" },
  { id: "svc-updates", name: "Unattended Upgrades", category: "services", severity: "medium",
    description: "Verify automatic security updates are configured",
    command: "dpkg -l unattended-upgrades 2>/dev/null | grep '^ii' || echo 'NOT_INSTALLED'",
    expectedPattern: "^ii" },
  { id: "ssh-max-auth", name: "SSH MaxAuthTries Limited", category: "ssh", severity: "medium",
    description: "Verify MaxAuthTries is set to 4 or less",
    command: "grep -E '^MaxAuthTries' /etc/ssh/sshd_config || echo 'MaxAuthTries 6'",
    expectedPattern: "MaxAuthTries [1-4]$" },
  { id: "net-open-ports", name: "Minimal Open Ports", category: "network", severity: "medium",
    description: "Count externally listening ports",
    command: "ss -tlnp | grep -c LISTEN || echo '0'",
    expectedPattern: "^[0-9]$" },
  { id: "fs-suid", name: "Limited SUID Binaries", category: "filesystem", severity: "medium",
    description: "Count SUID binaries on the system",
    command: "find / -perm -4000 -type f 2>/dev/null | wc -l",
    expectedPattern: "^[0-9]{1,2}$" },
  { id: "usr-login-defs", name: "Password Aging Policy", category: "users", severity: "medium",
    description: "Verify password aging is configured",
    command: "grep '^PASS_MAX_DAYS' /etc/login.defs || echo 'NOT_SET'",
    expectedPattern: "^PASS_MAX_DAYS\\s+[0-9]" },
  { id: "net-icmp-redirect", name: "ICMP Redirects Disabled", category: "network", severity: "low",
    description: "Verify ICMP redirects are not accepted",
    command: "sysctl net.ipv4.conf.all.accept_redirects 2>/dev/null",
    expectedPattern: "= 0" },
  { id: "log-remote", name: "Remote Logging Configured", category: "logging", severity: "low",
    description: "Check if remote syslog forwarding is configured",
    command: "grep -E '^\\*\\.\\*.*@' /etc/rsyslog.conf /etc/rsyslog.d/*.conf 2>/dev/null || echo 'NOT_CONFIGURED'",
    expectedPattern: "@" },
  { id: "svc-ntp", name: "NTP Synchronized", category: "services", severity: "low",
    description: "Verify time synchronization is active",
    command: "timedatectl status 2>/dev/null | grep 'synchronized' || echo 'NOT_SYNCED'",
    expectedPattern: "(yes|synchronized)" },
];

export function getBuiltinChecks(): ScanCheck[] {
  return [...BUILTIN_CHECKS];
}

export function getChecksByCategory(category: string): ScanCheck[] {
  return BUILTIN_CHECKS.filter((c) => c.category === category);
}

// ─── Scan Execution (simulated — real SSH would use ssh2 library) ─────────────

export async function executeScan(target: ScanTarget, checkIds?: string[]): Promise<ScanResult> {
  const checks = checkIds ? BUILTIN_CHECKS.filter((c) => checkIds.includes(c.id)) : BUILTIN_CHECKS;
  const startedAt = Date.now();
  const findings: ScanFinding[] = [];

  for (const check of checks) {
    findings.push(simulateCheck(check, target));
  }

  const passCount = findings.filter((f) => f.status === "pass").length;
  const failCount = findings.filter((f) => f.status === "fail").length;
  const errorCount = findings.filter((f) => f.status === "error").length;
  const score = checks.length > 0 ? Math.round((passCount / checks.length) * 100) : 0;

  return {
    id: `scan-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
    targetId: target.id, targetName: target.name, startedAt, completedAt: Date.now(),
    findings, score, passCount, failCount, errorCount,
  };
}

function simulateCheck(check: ScanCheck, target: ScanTarget): ScanFinding {
  const hasHardened = target.tags.includes("hardened");
  const isProduction = target.tags.includes("production");
  let status: "pass" | "fail" | "error" = "pass";
  let output = ""; let remediation = "";

  if (check.category === "ssh") {
    status = hasHardened ? "pass" : (Math.random() > 0.3 ? "pass" : "fail");
    output = status === "pass" ? `Check passed: ${check.name}` : `FINDING: ${check.description}`;
    remediation = status === "fail" ? "Update /etc/ssh/sshd_config and restart sshd" : "";
  } else if (check.category === "firewall") {
    status = hasHardened || isProduction ? "pass" : (Math.random() > 0.4 ? "pass" : "fail");
    output = status === "pass" ? "Firewall properly configured" : "Firewall misconfiguration detected";
    remediation = status === "fail" ? "Run: ufw enable && ufw default deny incoming" : "";
  } else if (check.category === "logging") {
    status = isProduction ? "pass" : (Math.random() > 0.5 ? "pass" : "fail");
    output = status === "pass" ? "Logging properly configured" : "Logging gap detected";
    remediation = status === "fail" ? "Install and configure rsyslog or auditd" : "";
  } else {
    status = Math.random() > 0.3 ? "pass" : "fail";
    output = status === "pass" ? `${check.name}: OK` : `${check.name}: FINDING`;
    remediation = status === "fail" ? check.description : "";
  }

  return { checkId: check.id, checkName: check.name, category: check.category, severity: check.severity, status, output, remediation };
}

// ─── Scheduled Scan Management (in-memory) ───────────────────────────────────

const scheduledScans = new Map<string, ScheduledScan>();
const scanHistory = new Map<string, ScanResult[]>();

export function createScheduledScan(opts: {
  name: string; targets: ScanTarget[]; checks?: string[]; intervalHours: number;
  notifyOnFail?: boolean; notifyThreshold?: number;
}): ScheduledScan {
  const id = `sched-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`;
  const scan: ScheduledScan = {
    id, name: opts.name, targets: opts.targets,
    checks: opts.checks ?? BUILTIN_CHECKS.map((c) => c.id),
    intervalHours: opts.intervalHours, enabled: true, lastRun: null,
    nextRun: Date.now() + opts.intervalHours * 3600_000,
    notifyOnFail: opts.notifyOnFail ?? true, notifyThreshold: opts.notifyThreshold ?? 70,
  };
  scheduledScans.set(id, scan);
  return scan;
}

export function listScheduledScans(): ScheduledScan[] {
  return Array.from(scheduledScans.values());
}

export function deleteScheduledScan(id: string): boolean {
  return scheduledScans.delete(id);
}

export function toggleScheduledScan(id: string, enabled: boolean): ScheduledScan | null {
  const scan = scheduledScans.get(id);
  if (!scan) return null;
  scan.enabled = enabled;
  return scan;
}

export async function runScheduledScan(id: string): Promise<ScanResult[]> {
  const scan = scheduledScans.get(id);
  if (!scan) throw new Error(`Scheduled scan ${id} not found`);

  const results: ScanResult[] = [];
  for (const target of scan.targets) {
    const result = await executeScan(target, scan.checks);
    results.push(result);
    const history = scanHistory.get(target.id) ?? [];
    history.push(result);
    if (history.length > 50) history.shift();
    scanHistory.set(target.id, history);

    if (scan.notifyOnFail && result.score < scan.notifyThreshold) {
      await notifyOwner({
        title: `OpSec Alert: ${target.name} scored ${result.score}%`,
        content: `Scheduled scan "${scan.name}" found ${result.failCount} failures on ${target.name} (${target.host}). Score: ${result.score}% (threshold: ${scan.notifyThreshold}%).`,
      });
    }
  }

  scan.lastRun = Date.now();
  scan.nextRun = Date.now() + scan.intervalHours * 3600_000;
  return results;
}

export function getScanHistory(targetId: string): ScanResult[] {
  return scanHistory.get(targetId) ?? [];
}

export function getAllScanHistory(): { targetId: string; results: ScanResult[] }[] {
  return Array.from(scanHistory.entries()).map(([targetId, results]) => ({ targetId, results }));
}
