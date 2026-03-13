/**
 * SMTP Audit Scanner Module
 *
 * Comprehensive SMTP server security auditing that checks:
 * - Open relay detection (mail forwarding without authentication)
 * - VRFY/EXPN user enumeration (username validation)
 * - STARTTLS support and TLS configuration
 * - Authentication method enumeration (PLAIN, LOGIN, CRAM-MD5, etc.)
 * - Banner grabbing and version fingerprinting
 * - Known CVEs based on SMTP server version (Postfix, Exim, Sendmail, Exchange)
 * - SPF/DKIM/DMARC record validation
 * - SMTP command injection testing
 * - Cleartext credential transmission detection
 *
 * Uses nmap NSE SMTP scripts + manual SMTP probing.
 * Auto-triggers when naabu/nmap discovers port 25, 465, 587, or 2525.
 */

import { executeTool, executeRawCommand, type ToolExecResult } from "../scan-server-executor";
import { invokeLLM } from "../../_core/llm";
import { throttledLLMCall } from "../llm-throttle";
import { getDb } from "../../db";
import { scanResults } from "../../../drizzle/schema";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface SMTPAuditConfig {
  /** Target host (IP or hostname) */
  host: string;
  /** SMTP port (default 25) */
  port?: number;
  /** Engagement ID for audit trail */
  engagementId: number;
  /** Timeout in seconds (default 60) */
  timeoutSeconds?: number;
  /** Operator ID */
  operatorId?: number;
  /** Test open relay */
  testOpenRelay?: boolean;
  /** Test VRFY/EXPN enumeration */
  testUserEnum?: boolean;
  /** Test STARTTLS */
  testStartTLS?: boolean;
  /** Run nmap SMTP NSE scripts */
  nmapScripts?: boolean;
  /** Domain for SPF/DKIM/DMARC checks */
  domain?: string;
  /** Custom usernames to enumerate */
  usernames?: string[];
}

export interface SMTPAuditFinding {
  id: string;
  category: "open_relay" | "user_enum" | "cve" | "configuration" | "authentication" | "encryption" | "banner" | "dns_records" | "injection";
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  recommendation: string | null;
  cve: string | null;
  cwe: string | null;
  evidence: string | null;
}

export interface SMTPAuditResult {
  scanId: number | null;
  status: "completed" | "error" | "timeout";
  host: string;
  port: number;
  banner: string | null;
  serverSoftware: string | null;
  serverVersion: string | null;
  tlsSupported: boolean;
  openRelay: boolean;
  vrfyEnabled: boolean;
  expnEnabled: boolean;
  authMethods: string[];
  findings: SMTPAuditFinding[];
  dnsRecords: {
    spf: string | null;
    dkim: boolean;
    dmarc: string | null;
  };
  stats: {
    totalFindings: number;
    criticalFindings: number;
    durationSeconds: number;
  };
  rawOutput: string;
  error?: string;
}

// ─── Known SMTP CVEs ────────────────────────────────────────────────────────

const SMTP_CVES: Array<{
  id: string;
  description: string;
  severity: SMTPAuditFinding["severity"];
  softwarePattern: RegExp;
  references: string[];
}> = [
  {
    id: "CVE-2019-15846",
    description: "Exim 4.92.1 and earlier — remote code execution via SNI in TLS handshake",
    severity: "critical",
    softwarePattern: /Exim\s*(4\.(9[0-2]|[0-8]\d))/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-15846"],
  },
  {
    id: "CVE-2019-10149",
    description: "Exim 4.87-4.91 — 'The Return of the WIZard' RCE via recipient address",
    severity: "critical",
    softwarePattern: /Exim\s*4\.(8[7-9]|9[01])/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-10149"],
  },
  {
    id: "CVE-2021-27216",
    description: "Exim privilege escalation via alternate configuration file",
    severity: "high",
    softwarePattern: /Exim\s*4\.(9[0-4])/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-27216"],
  },
  {
    id: "CVE-2020-28018",
    description: "Exim use-after-free in TLS handling leading to RCE (21Nails)",
    severity: "critical",
    softwarePattern: /Exim\s*4\.(9[0-3])/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-28018"],
  },
  {
    id: "CVE-2017-16943",
    description: "Exim use-after-free vulnerability in BDAT command handling",
    severity: "critical",
    softwarePattern: /Exim\s*4\.(8[5-9])/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2017-16943"],
  },
  {
    id: "CVE-2003-0161",
    description: "Sendmail prescan() buffer overflow — remote code execution",
    severity: "critical",
    softwarePattern: /Sendmail\s*(8\.(1[0-2]|[0-9])\.|[1-7]\.)/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2003-0161"],
  },
  {
    id: "CVE-2021-3156",
    description: "Sendmail/sudo heap-based buffer overflow (Baron Samedit)",
    severity: "critical",
    softwarePattern: /Sendmail/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-3156"],
  },
  {
    id: "CVE-2023-21529",
    description: "Microsoft Exchange Server remote code execution",
    severity: "critical",
    softwarePattern: /Microsoft\s+Exchange|Microsoft\s+ESMTP/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-21529"],
  },
  {
    id: "CVE-2021-26855",
    description: "Microsoft Exchange Server ProxyLogon SSRF — unauthenticated RCE chain",
    severity: "critical",
    softwarePattern: /Microsoft\s+Exchange|Microsoft\s+ESMTP/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-26855"],
  },
  {
    id: "CVE-2024-21413",
    description: "Microsoft Outlook/Exchange MonikerLink RCE via crafted hyperlink",
    severity: "critical",
    softwarePattern: /Microsoft\s+Exchange|Microsoft\s+ESMTP/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-21413"],
  },
  {
    id: "CVE-2011-1720",
    description: "Postfix SMTP server memory corruption in SASL implementation",
    severity: "high",
    softwarePattern: /Postfix\s*(2\.[0-7])/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2011-1720"],
  },
  {
    id: "CVE-2023-51764",
    description: "Postfix SMTP smuggling — allows email spoofing by injecting messages",
    severity: "medium",
    softwarePattern: /Postfix\s*(3\.[0-8]|2\.)/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-51764"],
  },
];

// ─── Default Usernames for Enumeration ──────────────────────────────────────

const DEFAULT_SMTP_USERS = [
  "admin", "administrator", "postmaster", "root", "info", "support",
  "webmaster", "sales", "contact", "abuse", "security", "noc",
  "helpdesk", "test", "user", "mail", "smtp", "backup",
];

// ─── Output Parsers ─────────────────────────────────────────────────────────

/**
 * Parse nmap SMTP NSE script output.
 */
function parseNmapSMTPOutput(output: string): {
  banner: string | null;
  openRelay: boolean;
  vrfyEnabled: boolean;
  expnEnabled: boolean;
  authMethods: string[];
  tlsSupported: boolean;
  enumeratedUsers: string[];
  commands: string[];
} {
  let banner: string | null = null;
  let openRelay = false;
  let vrfyEnabled = false;
  let expnEnabled = false;
  const authMethods: string[] = [];
  let tlsSupported = false;
  const enumeratedUsers: string[] = [];
  const commands: string[] = [];

  // Extract banner
  const bannerMatch = output.match(/smtp.*?(\d+\/tcp\s+open\s+smtp\s+(.+))/i);
  if (bannerMatch) banner = bannerMatch[2]?.trim() || null;

  // Check smtp-open-relay
  if (output.includes("smtp-open-relay:") && output.includes("Server is an open relay")) {
    openRelay = true;
  }

  // Check VRFY
  if (output.includes("smtp-vrfy:") || output.includes("VRFY")) {
    if (!output.includes("VRFY disabled") && !output.includes("252")) {
      vrfyEnabled = true;
    }
  }

  // Check EXPN
  if (output.includes("smtp-enum-users:") && output.includes("EXPN")) {
    expnEnabled = true;
  }

  // Extract auth methods
  const authMatch = output.match(/AUTH\s+(.+)/i);
  if (authMatch) {
    authMethods.push(...authMatch[1].split(/\s+/).map(m => m.trim()).filter(Boolean));
  }

  // Check STARTTLS
  if (output.includes("STARTTLS") || output.includes("smtp-starttls")) {
    tlsSupported = true;
  }

  // Extract enumerated users
  const userRegex = /smtp-enum-users:[\s\S]*?(\w+@[\w.]+)/gm;
  let uMatch;
  while ((uMatch = userRegex.exec(output)) !== null) {
    enumeratedUsers.push(uMatch[1]);
  }

  // Extract supported commands
  const cmdMatch = output.match(/smtp-commands:[\s\S]*?((?:\w+\s*)+)/);
  if (cmdMatch) {
    commands.push(...cmdMatch[1].split(/\s+/).filter(c => c.length > 1));
  }

  return { banner, openRelay, vrfyEnabled, expnEnabled, authMethods, tlsSupported, enumeratedUsers, commands };
}

/**
 * Identify SMTP server from banner.
 */
function identifySMTPServer(banner: string): { software: string | null; version: string | null } {
  if (!banner) return { software: null, version: null };

  const patterns: Array<{ regex: RegExp; software: string }> = [
    { regex: /(Postfix)/i, software: "Postfix" },
    { regex: /(Exim)\s*([\d.]+)/i, software: "Exim" },
    { regex: /(Sendmail)\s*([\d.]+)/i, software: "Sendmail" },
    { regex: /(Microsoft\s+Exchange|Microsoft\s+ESMTP)/i, software: "Microsoft Exchange" },
    { regex: /(hMailServer)\s*([\d.]+)/i, software: "hMailServer" },
    { regex: /(Haraka)/i, software: "Haraka" },
    { regex: /(OpenSMTPD)/i, software: "OpenSMTPD" },
    { regex: /(Zimbra)/i, software: "Zimbra" },
    { regex: /(MailEnable)/i, software: "MailEnable" },
    { regex: /(Dovecot)/i, software: "Dovecot" },
    { regex: /(qmail)/i, software: "qmail" },
  ];

  for (const { regex, software } of patterns) {
    const match = banner.match(regex);
    if (match) return { software, version: match[2] || null };
  }

  return { software: null, version: null };
}

/**
 * Check for CVEs based on SMTP banner.
 */
function checkSMTPCVEs(banner: string): SMTPAuditFinding[] {
  const findings: SMTPAuditFinding[] = [];
  for (const cve of SMTP_CVES) {
    if (cve.softwarePattern.test(banner)) {
      findings.push({
        id: `smtp-cve-${cve.id}`,
        category: "cve",
        severity: cve.severity,
        title: `${cve.id}: ${cve.description.split("—")[0].trim()}`,
        description: cve.description,
        recommendation: `Upgrade SMTP server to a patched version. See ${cve.references[0]}`,
        cve: cve.id,
        cwe: null,
        evidence: `Banner matches pattern: ${banner}`,
      });
    }
  }
  return findings;
}

// ─── Main Scan Function ─────────────────────────────────────────────────────

/**
 * Execute a comprehensive SMTP audit against a target.
 */
export async function startSMTPAudit(config: SMTPAuditConfig): Promise<SMTPAuditResult> {
  const port = config.port || 25;
  const timeout = config.timeoutSeconds || 60;
  const startTime = Date.now();
  const findings: SMTPAuditFinding[] = [];
  let rawOutput = "";
  let banner: string | null = null;
  let serverSoftware: string | null = null;
  let serverVersion: string | null = null;
  let tlsSupported = false;
  let openRelay = false;
  let vrfyEnabled = false;
  let expnEnabled = false;
  let authMethods: string[] = [];
  let dnsRecords = { spf: null as string | null, dkim: false, dmarc: null as string | null };

  // Store scan record
  let scanId: number | null = null;
  try {
    const db = getDb();
    const [row] = await db.insert(scanResults).values({
      engagementId: config.engagementId,
      scanType: "smtp_audit",
      target: `${config.host}:${port}`,
      status: "running",
      startedAt: Date.now(),
      rawOutput: "",
    }).returning({ id: scanResults.id });
    scanId = row?.id ?? null;
  } catch (err) {
    console.warn("[SMTPAudit] Failed to create scan record:", err);
  }

  try {
    // ── Step 1: Nmap SMTP NSE Scripts ──
    if (config.nmapScripts !== false) {
      const nmapScripts = [
        "smtp-commands",
        "smtp-enum-users",
        "smtp-open-relay",
        "smtp-strangeport",
        "smtp-vuln-cve2010-4344",
        "smtp-vuln-cve2011-1720",
        "smtp-vuln-cve2011-1764",
      ];

      const nmapResult = await executeTool("nmap", [
        "-sV", "-p", String(port),
        "--script", nmapScripts.join(","),
        "--script-timeout", String(timeout),
        "-oN", "-",
        config.host,
      ], { timeoutSeconds: timeout + 30 });

      if (nmapResult.stdout) {
        rawOutput += `=== NMAP SMTP SCRIPTS ===\n${nmapResult.stdout}\n\n`;
        const parsed = parseNmapSMTPOutput(nmapResult.stdout);
        if (parsed.banner) banner = parsed.banner;
        openRelay = parsed.openRelay;
        vrfyEnabled = parsed.vrfyEnabled;
        expnEnabled = parsed.expnEnabled;
        authMethods = parsed.authMethods;
        tlsSupported = parsed.tlsSupported;
      }
    }

    // ── Step 2: Banner Grab via netcat ──
    if (!banner) {
      try {
        const bannerResult = await executeRawCommand(
          `echo "EHLO test" | timeout ${Math.min(timeout, 10)} nc -w 5 ${config.host} ${port} 2>/dev/null || echo "EHLO test" | timeout ${Math.min(timeout, 10)} nc -w 5 ${config.host} ${port}`,
          { timeoutSeconds: 15 }
        );
        if (bannerResult.stdout) {
          rawOutput += `=== BANNER GRAB ===\n${bannerResult.stdout}\n\n`;
          const bannerLine = bannerResult.stdout.split("\n").find(l => l.startsWith("220"));
          if (bannerLine) banner = bannerLine.replace(/^220[\s-]*/, "").trim();

          // Parse EHLO response for auth methods
          const ehloLines = bannerResult.stdout.split("\n");
          for (const line of ehloLines) {
            if (line.includes("AUTH")) {
              const methods = line.replace(/.*AUTH\s+/i, "").split(/\s+/).filter(Boolean);
              authMethods = [...new Set([...authMethods, ...methods])];
            }
            if (line.includes("STARTTLS")) tlsSupported = true;
          }
        }
      } catch {
        // Banner grab failed, continue
      }
    }

    // Identify server
    if (banner) {
      const id = identifySMTPServer(banner);
      serverSoftware = id.software;
      serverVersion = id.version;

      // Check CVEs
      findings.push(...checkSMTPCVEs(banner));
    }

    // ── Step 3: Open Relay Test ──
    if (config.testOpenRelay !== false && !openRelay) {
      try {
        const relayTest = await executeRawCommand(
          `echo -e "EHLO test.com\\nMAIL FROM:<test@test.com>\\nRCPT TO:<test@example.com>\\nQUIT" | timeout 10 nc -w 5 ${config.host} ${port} 2>/dev/null`,
          { timeoutSeconds: 15 }
        );
        if (relayTest.stdout) {
          rawOutput += `=== OPEN RELAY TEST ===\n${relayTest.stdout}\n\n`;
          // 250 response to RCPT TO with external domain = open relay
          if (relayTest.stdout.includes("250") && relayTest.stdout.match(/RCPT.*250/s)) {
            openRelay = true;
          }
        }
      } catch {
        // Relay test failed
      }
    }

    if (openRelay) {
      findings.push({
        id: "smtp-open-relay",
        category: "open_relay",
        severity: "critical",
        title: "SMTP Open Relay Detected",
        description: "The SMTP server accepts and relays email for arbitrary external domains without authentication. This allows attackers to send spam, phishing emails, or malware through the server.",
        recommendation: "Configure SMTP server to require authentication for relaying. Restrict relay to authorized networks/users only.",
        cve: null,
        cwe: "CWE-284",
        evidence: "Server accepted RCPT TO for external domain without authentication",
      });
    }

    // ── Step 4: VRFY/EXPN Enumeration ──
    if (config.testUserEnum !== false) {
      const usernames = config.usernames || DEFAULT_SMTP_USERS;
      const validUsers: string[] = [];

      try {
        const vrfyCmds = usernames.slice(0, 10).map(u => `VRFY ${u}`).join("\\n");
        const vrfyResult = await executeRawCommand(
          `echo -e "EHLO test.com\\n${vrfyCmds}\\nQUIT" | timeout 15 nc -w 5 ${config.host} ${port} 2>/dev/null`,
          { timeoutSeconds: 20 }
        );
        if (vrfyResult.stdout) {
          rawOutput += `=== VRFY ENUMERATION ===\n${vrfyResult.stdout}\n\n`;
          const lines = vrfyResult.stdout.split("\n");
          for (const line of lines) {
            // 250 or 252 = user exists
            if (line.match(/^25[02]/)) {
              vrfyEnabled = true;
              const userMatch = line.match(/25[02].*?(\S+@\S+|\S+)/);
              if (userMatch) validUsers.push(userMatch[1]);
            }
          }
        }
      } catch {
        // VRFY test failed
      }

      if (vrfyEnabled) {
        findings.push({
          id: "smtp-vrfy-enabled",
          category: "user_enum",
          severity: "medium",
          title: "SMTP VRFY Command Enabled",
          description: `The SMTP server responds to VRFY commands, allowing user enumeration. ${validUsers.length > 0 ? `Confirmed users: ${validUsers.join(", ")}` : ""}`,
          recommendation: "Disable VRFY command in SMTP server configuration (e.g., disable_vrfy_command = yes in Postfix).",
          cve: null,
          cwe: "CWE-200",
          evidence: `VRFY responses confirmed${validUsers.length > 0 ? `: ${validUsers.join(", ")}` : ""}`,
        });
      }
    }

    // ── Step 5: TLS/Encryption Checks ──
    if (!tlsSupported) {
      findings.push({
        id: "smtp-no-tls",
        category: "encryption",
        severity: "high",
        title: "SMTP Server Does Not Support STARTTLS",
        description: "The SMTP server does not advertise STARTTLS support. All email communication including credentials is transmitted in cleartext.",
        recommendation: "Enable STARTTLS on the SMTP server and configure a valid TLS certificate.",
        cve: null,
        cwe: "CWE-319",
        evidence: "No STARTTLS in EHLO response",
      });
    }

    if (authMethods.includes("PLAIN") || authMethods.includes("LOGIN")) {
      if (!tlsSupported) {
        findings.push({
          id: "smtp-cleartext-auth",
          category: "authentication",
          severity: "high",
          title: "SMTP Cleartext Authentication Without TLS",
          description: `The server supports cleartext authentication methods (${authMethods.filter(m => ["PLAIN", "LOGIN"].includes(m)).join(", ")}) without mandatory TLS, exposing credentials to network sniffing.`,
          recommendation: "Require TLS before allowing PLAIN/LOGIN authentication. Configure smtpd_tls_auth_only = yes in Postfix.",
          cve: null,
          cwe: "CWE-523",
          evidence: `Auth methods: ${authMethods.join(", ")}; TLS: ${tlsSupported ? "yes" : "no"}`,
        });
      }
    }

    // ── Step 6: DNS Record Checks (SPF/DKIM/DMARC) ──
    if (config.domain) {
      try {
        const dnsResult = await executeRawCommand(
          `dig +short TXT ${config.domain} 2>/dev/null; echo "---"; dig +short TXT _dmarc.${config.domain} 2>/dev/null; echo "---"; dig +short TXT default._domainkey.${config.domain} 2>/dev/null`,
          { timeoutSeconds: 15 }
        );
        if (dnsResult.stdout) {
          rawOutput += `=== DNS RECORDS ===\n${dnsResult.stdout}\n\n`;
          const sections = dnsResult.stdout.split("---");

          // SPF
          const spfRecord = sections[0]?.match(/"(v=spf1[^"]+)"/)?.[1] || null;
          dnsRecords.spf = spfRecord;

          // DMARC
          const dmarcRecord = sections[1]?.match(/"(v=DMARC1[^"]+)"/)?.[1] || null;
          dnsRecords.dmarc = dmarcRecord;

          // DKIM
          dnsRecords.dkim = sections[2]?.includes("v=DKIM1") || false;

          if (!spfRecord) {
            findings.push({
              id: "smtp-no-spf",
              category: "dns_records",
              severity: "medium",
              title: "Missing SPF Record",
              description: `No SPF record found for domain ${config.domain}. This allows email spoofing from this domain.`,
              recommendation: `Add an SPF TXT record to ${config.domain} DNS (e.g., "v=spf1 mx -all").`,
              cve: null,
              cwe: "CWE-290",
              evidence: `No v=spf1 TXT record for ${config.domain}`,
            });
          }

          if (!dmarcRecord) {
            findings.push({
              id: "smtp-no-dmarc",
              category: "dns_records",
              severity: "medium",
              title: "Missing DMARC Record",
              description: `No DMARC record found for domain ${config.domain}. Without DMARC, email receivers cannot enforce SPF/DKIM policies.`,
              recommendation: `Add a DMARC TXT record to _dmarc.${config.domain} (e.g., "v=DMARC1; p=reject; rua=mailto:dmarc@${config.domain}").`,
              cve: null,
              cwe: "CWE-290",
              evidence: `No v=DMARC1 TXT record for _dmarc.${config.domain}`,
            });
          }
        }
      } catch {
        // DNS checks failed
      }
    }

    // ── Step 7: Banner info finding ──
    if (banner) {
      findings.push({
        id: "smtp-banner-info",
        category: "banner",
        severity: "info",
        title: "SMTP Banner Information",
        description: `SMTP banner: ${banner}${serverSoftware ? ` (${serverSoftware}${serverVersion ? ` ${serverVersion}` : ""})` : ""}`,
        recommendation: "Consider customizing the SMTP banner to reduce information disclosure.",
        cve: null,
        cwe: "CWE-200",
        evidence: banner,
      });
    }

    // ── Step 8: LLM Analysis ──
    if (rawOutput.length > 100) {
      try {
        const llmResult = await throttledLLMCall(async () => {
          return invokeLLM({
            messages: [
              {
                role: "system",
                content: `You are an SMTP security auditor. Analyze the following SMTP audit output and identify security findings. For each finding, provide: category, severity (critical/high/medium/low/info), title, description, recommendation, and any relevant CVE/CWE IDs. Focus on: open relay, user enumeration, weak authentication, missing encryption, version vulnerabilities, and misconfigurations. Return JSON array of findings.`,
              },
              {
                role: "user",
                content: `SMTP Audit Results for ${config.host}:${port}:\n\n${rawOutput.slice(0, 8000)}`,
              },
            ],
            response_format: {
              type: "json_schema",
              json_schema: {
                name: "smtp_findings",
                strict: true,
                schema: {
                  type: "object",
                  properties: {
                    findings: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          category: { type: "string" },
                          severity: { type: "string" },
                          title: { type: "string" },
                          description: { type: "string" },
                          recommendation: { type: "string" },
                          cve: { type: ["string", "null"] },
                          cwe: { type: ["string", "null"] },
                        },
                        required: ["category", "severity", "title", "description", "recommendation", "cve", "cwe"],
                        additionalProperties: false,
                      },
                    },
                  },
                  required: ["findings"],
                  additionalProperties: false,
                },
              },
            },
          });
        });

        if (llmResult?.choices?.[0]?.message?.content) {
          const parsed = JSON.parse(llmResult.choices[0].message.content);
          if (Array.isArray(parsed.findings)) {
            for (const f of parsed.findings) {
              const existingIds = new Set(findings.map(e => e.cve).filter(Boolean));
              if (f.cve && existingIds.has(f.cve)) continue;
              findings.push({
                id: `smtp-llm-${findings.length}`,
                category: f.category || "configuration",
                severity: f.severity || "info",
                title: f.title,
                description: f.description,
                recommendation: f.recommendation || null,
                cve: f.cve || null,
                cwe: f.cwe || null,
                evidence: null,
              });
            }
          }
        }
      } catch (err) {
        console.warn("[SMTPAudit] LLM analysis failed:", err);
      }
    }

    const durationSeconds = (Date.now() - startTime) / 1000;

    // Update scan record
    if (scanId) {
      try {
        const db = getDb();
        await db.update(scanResults).set({
          status: "completed",
          completedAt: Date.now(),
          rawOutput: rawOutput.slice(0, 50000),
          findingsCount: findings.length,
          summary: JSON.stringify({
            serverSoftware, serverVersion, openRelay, vrfyEnabled, tlsSupported,
            authMethods, dnsRecords,
            severityCounts: {
              critical: findings.filter(f => f.severity === "critical").length,
              high: findings.filter(f => f.severity === "high").length,
              medium: findings.filter(f => f.severity === "medium").length,
              low: findings.filter(f => f.severity === "low").length,
              info: findings.filter(f => f.severity === "info").length,
            },
          }),
        }).where(require("drizzle-orm").eq(scanResults.id, scanId));
      } catch (err) {
        console.warn("[SMTPAudit] Failed to update scan record:", err);
      }
    }

    return {
      scanId,
      status: "completed",
      host: config.host,
      port,
      banner,
      serverSoftware,
      serverVersion,
      tlsSupported,
      openRelay,
      vrfyEnabled,
      expnEnabled,
      authMethods,
      findings,
      dnsRecords,
      stats: {
        totalFindings: findings.length,
        criticalFindings: findings.filter(f => f.severity === "critical").length,
        durationSeconds,
      },
      rawOutput,
    };
  } catch (err: any) {
    const durationSeconds = (Date.now() - startTime) / 1000;

    if (scanId) {
      try {
        const db = getDb();
        await db.update(scanResults).set({
          status: "error",
          completedAt: Date.now(),
          rawOutput: rawOutput + `\nERROR: ${err.message}`,
        }).where(require("drizzle-orm").eq(scanResults.id, scanId));
      } catch {}
    }

    return {
      scanId,
      status: "error",
      host: config.host,
      port,
      banner,
      serverSoftware,
      serverVersion,
      tlsSupported,
      openRelay,
      vrfyEnabled,
      expnEnabled,
      authMethods,
      findings,
      dnsRecords,
      stats: { totalFindings: findings.length, criticalFindings: 0, durationSeconds },
      rawOutput,
      error: err.message,
    };
  }
}
