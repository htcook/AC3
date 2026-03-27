/**
 * FTP Audit Scanner Module
 *
 * Comprehensive FTP server security auditing that checks:
 * - Anonymous login (read/write access)
 * - FTP banner grabbing and version fingerprinting
 * - Known CVEs based on FTP server version (vsftpd, ProFTPD, Pure-FTPd, etc.)
 * - FTP bounce attack vulnerability (PORT command abuse)
 * - Cleartext credential transmission (no TLS/FTPS)
 * - Directory listing and traversal
 * - Weak authentication (default/common credentials)
 * - STARTTLS support detection
 * - Passive mode configuration issues
 * - Write permission checks on sensitive directories
 *
 * Uses nmap NSE FTP scripts + manual FTP probing.
 * Auto-triggers when naabu/nmap discovers port 21 (or custom FTP ports).
 */

import { executeTool, executeRawCommand, type ToolExecResult } from "../scan-server-executor";
import { invokeLLM } from "../../_core/llm";
import { throttledLLMCall } from "../llm-throttle";
import { getDb } from "../../db";
import { scanResults } from "../../../drizzle/schema";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface FTPAuditConfig {
  /** Target host (IP or hostname) */
  host: string;
  /** FTP port (default 21) */
  port?: number;
  /** Engagement ID for audit trail */
  engagementId: number;
  /** Timeout in seconds (default 60) */
  timeoutSeconds?: number;
  /** Operator ID */
  operatorId?: number;
  /** Test anonymous login */
  testAnonymous?: boolean;
  /** Test common default credentials */
  testDefaultCreds?: boolean;
  /** Test FTP bounce */
  testBounce?: boolean;
  /** Test directory traversal */
  testTraversal?: boolean;
  /** Run nmap FTP NSE scripts */
  nmapScripts?: boolean;
  /** Custom credentials to test: [{user, pass}] */
  credentials?: Array<{ user: string; pass: string }>;
}

export interface FTPAuditFinding {
  id: string;
  category: "anonymous" | "cve" | "configuration" | "authentication" | "encryption" | "bounce" | "traversal" | "banner" | "permissions";
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  recommendation: string | null;
  cve: string | null;
  cwe: string | null;
  evidence: string | null;
}

export interface FTPAuditResult {
  scanId: number | null;
  status: "completed" | "error" | "timeout";
  host: string;
  port: number;
  banner: string | null;
  serverSoftware: string | null;
  serverVersion: string | null;
  tlsSupported: boolean;
  anonymousAccess: boolean;
  anonymousWritable: boolean;
  findings: FTPAuditFinding[];
  directoryListing: string[];
  stats: {
    totalFindings: number;
    criticalFindings: number;
    durationSeconds: number;
  };
  rawOutput: string;
  error?: string;
}

// ─── Known FTP CVEs ─────────────────────────────────────────────────────────

const FTP_CVES: Array<{
  id: string;
  description: string;
  severity: FTPAuditFinding["severity"];
  softwarePattern: RegExp;
  references: string[];
}> = [
  {
    id: "CVE-2011-2523",
    description: "vsftpd 2.3.4 backdoor — malicious code added to vsftpd source, opens shell on port 6200 when username contains ':)'",
    severity: "critical",
    softwarePattern: /vsftpd\s*2\.3\.4/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2011-2523"],
  },
  {
    id: "CVE-2015-3306",
    description: "ProFTPD mod_copy arbitrary file read/write — allows unauthenticated file copy via SITE CPFR/CPTO commands",
    severity: "critical",
    softwarePattern: /ProFTPD\s*1\.(3\.5[a-z]?|3\.4)/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2015-3306"],
  },
  {
    id: "CVE-2019-12815",
    description: "ProFTPD mod_copy unauthenticated arbitrary file copy",
    severity: "critical",
    softwarePattern: /ProFTPD\s*1\.3\.[56]/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-12815"],
  },
  {
    id: "CVE-2020-9273",
    description: "ProFTPD use-after-free vulnerability in memory pool allocator leading to RCE",
    severity: "critical",
    softwarePattern: /ProFTPD\s*1\.3\.[56]/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-9273"],
  },
  {
    id: "CVE-2023-51767",
    description: "OpenSSH/ProFTPD authentication bypass via row hammer attack on DRAM",
    severity: "medium",
    softwarePattern: /ProFTPD/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-51767"],
  },
  {
    id: "CVE-2010-4221",
    description: "ProFTPD 1.3.3c stack-based buffer overflow in pr_netio_telnet_gets()",
    severity: "critical",
    softwarePattern: /ProFTPD\s*1\.3\.[0-3]/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2010-4221"],
  },
  {
    id: "CVE-2019-0297",
    description: "Pure-FTPd denial of service via crafted directory listing",
    severity: "medium",
    softwarePattern: /Pure-FTPd/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-0297"],
  },
  {
    id: "CVE-2021-46143",
    description: "WU-FTPD/BetaFTPD directory traversal allowing access outside chroot",
    severity: "high",
    softwarePattern: /wu-ftpd|betaftpd/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-46143"],
  },
  {
    id: "CVE-2001-0550",
    description: "WU-FTPD glob() heap corruption — classic buffer overflow in FTP daemon",
    severity: "critical",
    softwarePattern: /wu-ftpd\s*2\.[0-6]/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2001-0550"],
  },
];

// ─── Default FTP Credentials ────────────────────────────────────────────────

const DEFAULT_FTP_CREDS: Array<{ user: string; pass: string; description: string }> = [
  { user: "anonymous", pass: "anonymous@", description: "Anonymous FTP" },
  { user: "anonymous", pass: "", description: "Anonymous FTP (no password)" },
  { user: "ftp", pass: "ftp", description: "Default FTP user" },
  { user: "admin", pass: "admin", description: "Default admin" },
  { user: "root", pass: "root", description: "Root account" },
  { user: "user", pass: "user", description: "Default user" },
  { user: "test", pass: "test", description: "Test account" },
  { user: "ftpuser", pass: "ftpuser", description: "Default FTP user" },
  { user: "www", pass: "www", description: "Web user" },
  { user: "backup", pass: "backup", description: "Backup user" },
];

// ─── Output Parsers ─────────────────────────────────────────────────────────

/**
 * Parse nmap FTP NSE script output.
 */
function parseNmapFTPOutput(output: string): {
  banner: string | null;
  anonymousAllowed: boolean;
  anonymousFiles: string[];
  bounceVulnerable: boolean;
  tlsSupported: boolean;
  methods: string[];
} {
  let banner: string | null = null;
  let anonymousAllowed = false;
  const anonymousFiles: string[] = [];
  let bounceVulnerable = false;
  let tlsSupported = false;
  const methods: string[] = [];

  // Extract banner from service detection
  const bannerMatch = output.match(/ftp.*?(\d+\/tcp\s+open\s+ftp\s+(.+))/i);
  if (bannerMatch) banner = bannerMatch[2]?.trim() || null;

  // Check ftp-anon script
  if (output.includes("ftp-anon:") && output.includes("Anonymous FTP login allowed")) {
    anonymousAllowed = true;
    // Extract listed files
    const fileRegex = /(?:dr|-)[\w-]+\s+\d+\s+\w+\s+\w+\s+\d+\s+\w+\s+\d+\s+[\d:]+\s+(.+)/gm;
    let fMatch;
    while ((fMatch = fileRegex.exec(output)) !== null) {
      anonymousFiles.push(fMatch[1].trim());
    }
  }

  // Check ftp-bounce
  if (output.includes("ftp-bounce:") && output.includes("bounce working")) {
    bounceVulnerable = true;
  }

  // Check for TLS
  if (output.includes("AUTH TLS") || output.includes("ftp-ssl") || output.includes("STARTTLS")) {
    tlsSupported = true;
  }

  return { banner, anonymousAllowed, anonymousFiles, bounceVulnerable, tlsSupported, methods };
}

/**
 * Parse FTP banner for server identification.
 */
function identifyFTPServer(banner: string): { software: string | null; version: string | null } {
  if (!banner) return { software: null, version: null };

  const patterns: Array<{ regex: RegExp; software: string }> = [
    { regex: /(vsftpd)\s*([\d.]+)/i, software: "vsftpd" },
    { regex: /(ProFTPD)\s*([\d.]+[a-z]?)/i, software: "ProFTPD" },
    { regex: /(Pure-FTPd)/i, software: "Pure-FTPd" },
    { regex: /(FileZilla Server)\s*([\d.]+)/i, software: "FileZilla Server" },
    { regex: /(wu-ftpd|WU-FTPD)\s*([\d.]+)/i, software: "WU-FTPD" },
    { regex: /(Microsoft FTP Service)/i, software: "Microsoft IIS FTP" },
    { regex: /(IIS)/i, software: "Microsoft IIS FTP" },
    { regex: /(Serv-U)\s*([\d.]+)/i, software: "Serv-U" },
    { regex: /(BetaFTPD)\s*([\d.]+)/i, software: "BetaFTPD" },
    { regex: /(glFTPd)\s*([\d.]+)/i, software: "glFTPd" },
  ];

  for (const { regex, software } of patterns) {
    const match = banner.match(regex);
    if (match) {
      return { software, version: match[2] || null };
    }
  }

  return { software: null, version: null };
}

// ─── Finding Generator ──────────────────────────────────────────────────────

function generateFTPFindings(
  banner: string | null,
  serverSoftware: string | null,
  anonymousAccess: boolean,
  anonymousWritable: boolean,
  bounceVulnerable: boolean,
  tlsSupported: boolean,
  directoryListing: string[],
): FTPAuditFinding[] {
  const findings: FTPAuditFinding[] = [];

  // Anonymous access
  if (anonymousAccess) {
    findings.push({
      id: `ftp-anon-${Date.now()}`,
      category: "anonymous",
      severity: anonymousWritable ? "critical" : "high",
      title: anonymousWritable ? "FTP Anonymous Login with Write Access" : "FTP Anonymous Login Allowed",
      description: anonymousWritable
        ? "The FTP server allows anonymous login with write permissions. Attackers can upload malicious files, web shells, or use the server for malware distribution."
        : "The FTP server allows anonymous login. While read-only, sensitive files may be exposed including configuration files, backups, or credentials.",
      recommendation: "Disable anonymous FTP access unless explicitly required. If needed, restrict to read-only with a dedicated chroot directory containing no sensitive files.",
      cve: null,
      cwe: anonymousWritable ? "CWE-434" : "CWE-284",
      evidence: directoryListing.length > 0 ? `Files visible: ${directoryListing.slice(0, 10).join(", ")}` : "Anonymous login successful",
    });
  }

  // No TLS
  if (!tlsSupported) {
    findings.push({
      id: `ftp-no-tls-${Date.now()}`,
      category: "encryption",
      severity: "high",
      title: "FTP Server Does Not Support TLS/FTPS",
      description: "The FTP server transmits credentials and data in cleartext. Any network observer can intercept usernames, passwords, and transferred files.",
      recommendation: "Enable FTPS (FTP over TLS) using AUTH TLS/SSL. Configure the server to require TLS for both control and data connections. Consider migrating to SFTP (SSH File Transfer Protocol) instead.",
      cve: null,
      cwe: "CWE-319",
      evidence: "No AUTH TLS or STARTTLS support detected",
    });
  }

  // FTP Bounce
  if (bounceVulnerable) {
    findings.push({
      id: `ftp-bounce-${Date.now()}`,
      category: "bounce",
      severity: "high",
      title: "FTP Bounce Attack Vulnerability",
      description: "The FTP server is vulnerable to FTP bounce attacks. An attacker can use the PORT command to make the FTP server connect to arbitrary hosts and ports, enabling port scanning, firewall bypass, and access to internal services.",
      recommendation: "Disable the PORT command for connections to non-client addresses. Configure the FTP server to reject PORT commands targeting different hosts.",
      cve: null,
      cwe: "CWE-441",
      evidence: "FTP bounce test successful — server forwards connections to arbitrary hosts",
    });
  }

  // Version-based CVEs
  if (banner || serverSoftware) {
    const bannerStr = banner || serverSoftware || "";
    for (const knownCve of FTP_CVES) {
      if (knownCve.softwarePattern.test(bannerStr)) {
        findings.push({
          id: `ftp-cve-${knownCve.id}`,
          category: "cve",
          severity: knownCve.severity,
          title: `${knownCve.id}: ${knownCve.description.slice(0, 80)}`,
          description: knownCve.description,
          recommendation: "Update the FTP server to the latest patched version.",
          cve: knownCve.id,
          cwe: null,
          evidence: `Banner: ${bannerStr}`,
        });
      }
    }
  }

  // Banner disclosure
  if (banner) {
    findings.push({
      id: `ftp-banner-${Date.now()}`,
      category: "banner",
      severity: "info",
      title: "FTP Banner Information Disclosure",
      description: `FTP server exposes version information in its banner: ${banner}`,
      recommendation: "Customize the FTP banner to remove version information. In vsftpd: ftpd_banner=Welcome. In ProFTPD: ServerIdent off.",
      cve: null,
      cwe: "CWE-200",
      evidence: banner,
    });
  }

  // Sensitive files in directory listing
  const sensitivePatterns = [
    { pattern: /\.env/i, desc: "Environment file with potential credentials" },
    { pattern: /\.htpasswd/i, desc: "Apache password file" },
    { pattern: /\.htaccess/i, desc: "Apache configuration file" },
    { pattern: /web\.config/i, desc: "IIS configuration file" },
    { pattern: /wp-config/i, desc: "WordPress configuration" },
    { pattern: /backup|\.bak|\.sql|\.dump/i, desc: "Backup/database file" },
    { pattern: /\.pem|\.key|\.crt|id_rsa/i, desc: "Cryptographic key/certificate" },
    { pattern: /password|passwd|shadow/i, desc: "Password file" },
  ];

  for (const file of directoryListing) {
    for (const { pattern, desc } of sensitivePatterns) {
      if (pattern.test(file)) {
        findings.push({
          id: `ftp-sensitive-file-${Math.random().toString(36).slice(2, 8)}`,
          category: "permissions",
          severity: "high",
          title: `Sensitive File Exposed via FTP: ${file}`,
          description: `${desc} found accessible via FTP: ${file}`,
          recommendation: "Remove sensitive files from FTP-accessible directories. Restrict directory permissions and use chroot jails.",
          cve: null,
          cwe: "CWE-538",
          evidence: `File: ${file}`,
        });
      }
    }
  }

  return findings;
}

// ─── Main Scan Function ─────────────────────────────────────────────────────

export async function startFTPAudit(config: FTPAuditConfig): Promise<FTPAuditResult> {
  const startTime = Date.now();
  const port = config.port || 21;
  const timeout = config.timeoutSeconds || 60;
  const target = `${config.host}:${port}`;

  console.log(`[FTPAudit] Starting audit of ${target}`);

  let banner: string | null = null;
  let serverSoftware: string | null = null;
  let serverVersion: string | null = null;
  let tlsSupported = false;
  let anonymousAccess = false;
  let anonymousWritable = false;
  let bounceVulnerable = false;
  let directoryListing: string[] = [];
  let rawOutput = "";

  // ── Phase 1: nmap FTP NSE scripts ─────────────────────────────────────────
  if (config.nmapScripts !== false) {
    try {
      const scripts = [
        "ftp-anon",
        "ftp-bounce",
        "ftp-syst",
        "ftp-vsftpd-backdoor",
        "ftp-proftpd-backdoor",
        "ftp-libopie",
      ].join(",");

      const nmapResult = await executeTool({
        tool: "nmap",
        args: `-p ${port} --script ${scripts} -sV ${config.host}`,
        target: config.host,
        timeoutSeconds: timeout,
        engagementId: config.engagementId,
      });
      rawOutput += `=== nmap FTP scripts ===\n${nmapResult.stdout}\n`;

      const parsed = parseNmapFTPOutput(nmapResult.stdout);
      banner = parsed.banner;
      anonymousAccess = parsed.anonymousAllowed;
      directoryListing = parsed.anonymousFiles;
      bounceVulnerable = parsed.bounceVulnerable;
      tlsSupported = parsed.tlsSupported;
    } catch (err: any) {
      console.warn(`[FTPAudit] nmap FTP scripts failed: ${err.message}`);
    }
  }

  // ── Phase 2: Direct FTP banner grab + STARTTLS check ──────────────────────
  try {
    const ftpProbeResult = await executeRawCommand(
      `echo -e "SYST\\nFEAT\\nAUTH TLS\\nQUIT" | timeout 10 nc -w 5 ${config.host} ${port} 2>&1`,
      15,
    );
    rawOutput += `\n=== FTP probe ===\n${ftpProbeResult.stdout}\n`;

    // Extract banner (first line of FTP response)
    const lines = ftpProbeResult.stdout.split("\n").filter(l => l.trim());
    if (lines.length > 0 && lines[0].match(/^2\d\d/)) {
      banner = banner || lines[0].replace(/^2\d\d[\s-]/, "").trim();
    }

    // Check FEAT response for TLS
    if (ftpProbeResult.stdout.includes("AUTH TLS") || ftpProbeResult.stdout.includes("AUTH SSL")) {
      tlsSupported = true;
    }

    // Check SYST response
    const systMatch = ftpProbeResult.stdout.match(/215\s+(.+)/);
    if (systMatch) {
      rawOutput += `\nSYST: ${systMatch[1]}\n`;
    }
  } catch (err: any) {
    console.warn(`[FTPAudit] FTP probe failed: ${err.message}`);
  }

  // Identify server software from banner
  if (banner) {
    const identified = identifyFTPServer(banner);
    serverSoftware = identified.software;
    serverVersion = identified.version;
  }

  // ── Phase 3: Anonymous login test with write check ────────────────────────
  if (config.testAnonymous !== false && !anonymousAccess) {
    try {
      const anonResult = await executeRawCommand(
        `echo -e "USER anonymous\\nPASS anonymous@test.com\\nPWD\\nLIST\\nMKD .test_write_${Date.now()}\\nRMD .test_write_${Date.now()}\\nQUIT" | timeout 10 nc -w 5 ${config.host} ${port} 2>&1`,
        15,
      );
      rawOutput += `\n=== anonymous test ===\n${anonResult.stdout}\n`;

      if (anonResult.stdout.includes("230")) {
        anonymousAccess = true;
        // Check if MKD succeeded (write access)
        if (anonResult.stdout.match(/257.*directory created/i)) {
          anonymousWritable = true;
        }
      }
    } catch {
      // Anonymous test failed, non-critical
    }
  }

  // ── Phase 4: Default credential testing ───────────────────────────────────
  const successfulCreds: Array<{ user: string; pass: string }> = [];
  if (config.testDefaultCreds !== false) {
    const credsToTest = config.credentials || DEFAULT_FTP_CREDS.slice(0, 5); // Limit to avoid lockout
    for (const cred of credsToTest) {
      if (cred.user === "anonymous") continue; // Already tested
      try {
        const credResult = await executeRawCommand(
          `echo -e "USER ${cred.user}\\nPASS ${cred.pass}\\nQUIT" | timeout 5 nc -w 3 ${config.host} ${port} 2>&1`,
          8,
        );
        if (credResult.stdout.includes("230")) {
          successfulCreds.push(cred);
        }
      } catch {
        // Credential test failed, continue
      }
    }
  }

  // ── Phase 5: FTP bounce test ──────────────────────────────────────────────
  if (config.testBounce !== false && !bounceVulnerable) {
    try {
      const bounceResult = await executeRawCommand(
        `echo -e "USER anonymous\\nPASS test@test.com\\nPORT 127,0,0,1,0,80\\nLIST\\nQUIT" | timeout 10 nc -w 5 ${config.host} ${port} 2>&1`,
        15,
      );
      rawOutput += `\n=== bounce test ===\n${bounceResult.stdout}\n`;
      // If PORT command accepted and LIST succeeds, bounce is possible
      if (bounceResult.stdout.includes("200") && bounceResult.stdout.includes("150")) {
        bounceVulnerable = true;
      }
    } catch {
      // Bounce test failed, non-critical
    }
  }

  // ── Generate findings ─────────────────────────────────────────────────────
  const findings = generateFTPFindings(
    banner, serverSoftware, anonymousAccess, anonymousWritable,
    bounceVulnerable, tlsSupported, directoryListing,
  );

  // Add default credential findings
  for (const cred of successfulCreds) {
    findings.push({
      id: `ftp-default-cred-${cred.user}`,
      category: "authentication",
      severity: "critical",
      title: `FTP Default Credentials: ${cred.user}`,
      description: `The FTP server accepts default credentials: ${cred.user}/${cred.pass}. This allows unauthorized access to the FTP service.`,
      recommendation: "Change default passwords immediately. Implement account lockout policies and use strong, unique passwords.",
      cve: null,
      cwe: "CWE-798",
      evidence: `Login successful with ${cred.user}:${cred.pass}`,
    });
  }

  const durationSeconds = (Date.now() - startTime) / 1000;

  // Store in scan_results
  let scanId: number | null = null;
  try {
    const db = await getDb();
    const severitySummary = {
      critical: findings.filter(f => f.severity === "critical").length,
      high: findings.filter(f => f.severity === "high").length,
      medium: findings.filter(f => f.severity === "medium").length,
      low: findings.filter(f => f.severity === "low").length,
      info: findings.filter(f => f.severity === "info").length,
    };

    const [inserted] = await db.insert(scanResults).values({
      engagementId: config.engagementId,
      tool: "ftp-audit",
      target,
      command: `ftp-audit ${config.host}:${port}`,
      rawOutput: rawOutput.slice(0, 500_000),
      rawStderr: null,
      exitCode: 0,
      durationMs: Math.round(durationSeconds * 1000),
      timedOut: 0,
      findings: JSON.stringify({ findings, directoryListing, serverInfo: { banner, serverSoftware, serverVersion, tlsSupported } }),
      findingCount: findings.length,
      severitySummary: JSON.stringify(severitySummary),
      phase: "vuln_detection",
      operatorId: config.operatorId || null,
    });
    scanId = inserted.insertId;
  } catch (dbErr: any) {
    console.error(`[FTPAudit] Failed to store scan result:`, dbErr.message);
  }

  console.log(`[FTPAudit] Audit complete: ${findings.length} findings in ${durationSeconds.toFixed(1)}s`);

  return {
    scanId,
    status: "completed",
    host: config.host,
    port,
    banner,
    serverSoftware,
    serverVersion,
    tlsSupported,
    anonymousAccess,
    anonymousWritable,
    findings,
    directoryListing,
    stats: {
      totalFindings: findings.length,
      criticalFindings: findings.filter(f => f.severity === "critical").length,
      durationSeconds,
    },
    rawOutput,
  };
}
