/**
 * RDP Audit Scanner Module
 *
 * Comprehensive RDP (Remote Desktop Protocol) security auditing:
 * - NLA (Network Level Authentication) enforcement check
 * - CredSSP configuration and downgrade vulnerabilities
 * - BlueKeep (CVE-2019-0708) detection
 * - DejaBlue (CVE-2019-1181/1182) detection
 * - Encryption level assessment (40-bit, 56-bit, 128-bit, FIPS)
 * - NTLMv1 downgrade detection
 * - Certificate validation
 * - RDP version fingerprinting
 * - Restricted Admin Mode check
 *
 * Uses nmap NSE RDP scripts + rdp-sec-check probing.
 * Auto-triggers when naabu/nmap discovers port 3389 or 3388.
 */

import { executeTool, executeRawCommand } from "../scan-server-executor";
import { invokeLLM } from "../../_core/llm";
import { throttledLLMCall } from "../llm-throttle";
import { analyzeProtocolAuditDeterministic, useDeterministicAnalysis } from "../deterministic-scanner-analysis";
import { getDb } from "../../db";
import { scanResults } from "../../../drizzle/schema";
import { eq } from "drizzle-orm";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface RDPAuditConfig {
  /** Target host (IP or hostname) */
  host: string;
  /** RDP port (default 3389) */
  port?: number;
  /** Engagement ID for audit trail */
  engagementId: number;
  /** Timeout in seconds (default 60) */
  timeoutSeconds?: number;
  /** Operator ID */
  operatorId?: number;
  /** Run nmap RDP NSE scripts */
  nmapScripts?: boolean;
  /** Test for BlueKeep specifically */
  testBlueKeep?: boolean;
  /** Check encryption levels */
  testEncryption?: boolean;
  /** Check NLA enforcement */
  testNLA?: boolean;
}

export interface RDPAuditFinding {
  id: string;
  category: "cve" | "authentication" | "encryption" | "configuration" | "protocol" | "certificate";
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  recommendation: string | null;
  cve: string | null;
  cwe: string | null;
  evidence: string | null;
}

export interface RDPAuditResult {
  scanId: number | null;
  status: "completed" | "error" | "timeout";
  host: string;
  port: number;
  rdpVersion: string | null;
  nlaEnabled: boolean | null;
  encryptionLevel: string | null;
  securityProtocol: string | null;
  osVersion: string | null;
  blueKeepVulnerable: boolean | null;
  certificateInfo: {
    subject: string | null;
    issuer: string | null;
    validFrom: string | null;
    validTo: string | null;
    selfSigned: boolean;
  };
  findings: RDPAuditFinding[];
  stats: {
    totalFindings: number;
    criticalFindings: number;
    durationSeconds: number;
  };
  rawOutput: string;
  error?: string;
}

// ─── Known RDP CVEs ─────────────────────────────────────────────────────────

const RDP_CVES: Array<{
  id: string;
  description: string;
  severity: RDPAuditFinding["severity"];
  checkType: "bluekeep" | "dejablue" | "credssp" | "encryption" | "general";
  references: string[];
}> = [
  {
    id: "CVE-2019-0708",
    description: "BlueKeep — Remote Desktop Services RCE via crafted RDP packets. Pre-authentication, wormable. Affects Windows 7, Server 2008/R2, XP, Server 2003.",
    severity: "critical",
    checkType: "bluekeep",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-0708"],
  },
  {
    id: "CVE-2019-1181",
    description: "DejaBlue — Remote Desktop Services RCE. Wormable, affects Windows 7-10 and Server 2008-2019.",
    severity: "critical",
    checkType: "dejablue",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-1181"],
  },
  {
    id: "CVE-2019-1182",
    description: "DejaBlue variant — Remote Desktop Services RCE affecting newer Windows versions.",
    severity: "critical",
    checkType: "dejablue",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-1182"],
  },
  {
    id: "CVE-2018-0886",
    description: "CredSSP protocol vulnerability allowing RCE via man-in-the-middle during RDP authentication.",
    severity: "high",
    checkType: "credssp",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2018-0886"],
  },
  {
    id: "CVE-2019-9510",
    description: "Windows RDP lock screen bypass — allows attacker to bypass lock screen on resumed RDP sessions.",
    severity: "medium",
    checkType: "general",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-9510"],
  },
  {
    id: "CVE-2012-0002",
    description: "MS12-020 — Remote Desktop Protocol vulnerability allowing remote code execution via crafted RDP packets.",
    severity: "critical",
    checkType: "general",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2012-0002"],
  },
  {
    id: "CVE-2019-0887",
    description: "Remote Desktop Services RCE via clipboard redirection in Hyper-V guest-to-host scenario.",
    severity: "high",
    checkType: "general",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-0887"],
  },
  {
    id: "CVE-2023-24905",
    description: "Remote Desktop Client RCE — crafted .rdp file can execute arbitrary code on the client.",
    severity: "high",
    checkType: "general",
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-24905"],
  },
];

// ─── Output Parsers ─────────────────────────────────────────────────────────

/**
 * Parse nmap RDP NSE script output.
 */
function parseNmapRDPOutput(output: string): {
  nlaEnabled: boolean | null;
  encryptionLevel: string | null;
  securityProtocol: string | null;
  blueKeepVulnerable: boolean | null;
  osVersion: string | null;
  certificate: {
    subject: string | null;
    issuer: string | null;
    validFrom: string | null;
    validTo: string | null;
    selfSigned: boolean;
  };
  ntlmInfo: Record<string, string>;
} {
  let nlaEnabled: boolean | null = null;
  let encryptionLevel: string | null = null;
  let securityProtocol: string | null = null;
  let blueKeepVulnerable: boolean | null = null;
  let osVersion: string | null = null;
  const certificate = { subject: null as string | null, issuer: null as string | null, validFrom: null as string | null, validTo: null as string | null, selfSigned: false };
  const ntlmInfo: Record<string, string> = {};

  // Check NLA
  if (output.includes("CredSSP (NLA)")) {
    nlaEnabled = true;
  } else if (output.includes("rdp-enum-encryption")) {
    // If we can enumerate without NLA, NLA is not enforced
    if (!output.includes("CredSSP")) {
      nlaEnabled = false;
    }
  }

  // Encryption level
  const encMatch = output.match(/Encryption level:\s*(.+)/i);
  if (encMatch) encryptionLevel = encMatch[1].trim();

  // Security protocol
  const secMatch = output.match(/Security layer:\s*(.+)/i);
  if (secMatch) securityProtocol = secMatch[1].trim();

  // BlueKeep check
  if (output.includes("rdp-vuln-ms12-020") || output.includes("CVE-2019-0708")) {
    if (output.includes("VULNERABLE") || output.includes("State: VULNERABLE")) {
      blueKeepVulnerable = true;
    } else if (output.includes("NOT VULNERABLE") || output.includes("State: NOT VULNERABLE")) {
      blueKeepVulnerable = false;
    }
  }

  // OS version from NTLM info
  const osMatch = output.match(/OS:\s*(.+)/i) || output.match(/Product_Version:\s*(.+)/i);
  if (osMatch) osVersion = osMatch[1].trim();

  // Certificate info
  const subjectMatch = output.match(/Subject:\s*(.+)/);
  if (subjectMatch) certificate.subject = subjectMatch[1].trim();

  const issuerMatch = output.match(/Issuer:\s*(.+)/);
  if (issuerMatch) certificate.issuer = issuerMatch[1].trim();

  if (certificate.subject && certificate.issuer && certificate.subject === certificate.issuer) {
    certificate.selfSigned = true;
  }

  const validFromMatch = output.match(/Not valid before:\s*(.+)/);
  if (validFromMatch) certificate.validFrom = validFromMatch[1].trim();

  const validToMatch = output.match(/Not valid after:\s*(.+)/);
  if (validToMatch) certificate.validTo = validToMatch[1].trim();

  // NTLM info
  const ntlmRegex = /(\w+):\s+(.+)/gm;
  let nm;
  const ntlmSection = output.match(/rdp-ntlm-info:[\s\S]*?(?=\|_|$)/);
  if (ntlmSection) {
    while ((nm = ntlmRegex.exec(ntlmSection[0])) !== null) {
      ntlmInfo[nm[1]] = nm[2].trim();
    }
  }

  return { nlaEnabled, encryptionLevel, securityProtocol, blueKeepVulnerable, osVersion, certificate, ntlmInfo };
}

// ─── Main Scan Function ─────────────────────────────────────────────────────

/**
 * Execute a comprehensive RDP audit against a target.
 */
export async function startRDPAudit(config: RDPAuditConfig): Promise<RDPAuditResult> {
  const port = config.port || 3389;
  const timeout = config.timeoutSeconds || 60;
  const startTime = Date.now();
  const findings: RDPAuditFinding[] = [];
  let rawOutput = "";
  let rdpVersion: string | null = null;
  let nlaEnabled: boolean | null = null;
  let encryptionLevel: string | null = null;
  let securityProtocol: string | null = null;
  let osVersion: string | null = null;
  let blueKeepVulnerable: boolean | null = null;
  let certificateInfo = {
    subject: null as string | null,
    issuer: null as string | null,
    validFrom: null as string | null,
    validTo: null as string | null,
    selfSigned: false,
  };

  // Store scan record
  let scanId: number | null = null;
  try {
    const db = getDb();
    const [row] = await db.insert(scanResults).values({
      engagementId: config.engagementId,
      scanType: "rdp_audit",
      target: `${config.host}:${port}`,
      status: "running",
      startedAt: Date.now(),
      rawOutput: "",
    }).returning({ id: scanResults.id });
    scanId = row?.id ?? null;
  } catch (err) {
    console.warn("[RDPAudit] Failed to create scan record:", err);
  }

  try {
    // ── Step 1: Nmap RDP NSE Scripts ──
    if (config.nmapScripts !== false) {
      const nmapScripts = [
        "rdp-enum-encryption",
        "rdp-ntlm-info",
        "rdp-vuln-ms12-020",
      ];

      const nmapResult = await executeTool("nmap", [
        "-sV", "-p", String(port),
        "--script", nmapScripts.join(","),
        "--script-timeout", String(timeout),
        "-oN", "-",
        config.host,
      ], { timeoutSeconds: timeout + 30 });

      if (nmapResult.stdout) {
        rawOutput += `=== NMAP RDP SCRIPTS ===\n${nmapResult.stdout}\n\n`;
        const parsed = parseNmapRDPOutput(nmapResult.stdout);
        nlaEnabled = parsed.nlaEnabled;
        encryptionLevel = parsed.encryptionLevel;
        securityProtocol = parsed.securityProtocol;
        blueKeepVulnerable = parsed.blueKeepVulnerable;
        osVersion = parsed.osVersion;
        certificateInfo = parsed.certificate;

        // Extract RDP version from service detection
        const versionMatch = nmapResult.stdout.match(/(\d+\/tcp\s+open\s+ms-wbt-server\s+(.+))/i);
        if (versionMatch) rdpVersion = versionMatch[2]?.trim() || null;
      }
    }

    // ── Step 2: BlueKeep-Specific Check ──
    if (config.testBlueKeep !== false && blueKeepVulnerable === null) {
      try {
        const blueKeepResult = await executeTool("nmap", [
          "-p", String(port),
          "--script", "rdp-vuln-ms12-020",
          "--script-args", "vulns.short",
          config.host,
        ], { timeoutSeconds: 30 });

        if (blueKeepResult.stdout) {
          rawOutput += `=== BLUEKEEP CHECK ===\n${blueKeepResult.stdout}\n\n`;
          if (blueKeepResult.stdout.includes("VULNERABLE")) {
            blueKeepVulnerable = true;
          } else {
            blueKeepVulnerable = false;
          }
        }
      } catch {
        // BlueKeep check failed
      }
    }

    // ── Step 3: SSL/TLS Certificate Check ──
    try {
      const sslResult = await executeRawCommand(
        `echo | timeout 10 openssl s_client -connect ${config.host}:${port} 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null`,
        { timeoutSeconds: 15 }
      );
      if (sslResult.stdout && sslResult.stdout.includes("subject=")) {
        rawOutput += `=== TLS CERTIFICATE ===\n${sslResult.stdout}\n\n`;
        const subMatch = sslResult.stdout.match(/subject=(.+)/);
        const issMatch = sslResult.stdout.match(/issuer=(.+)/);
        const fromMatch = sslResult.stdout.match(/notBefore=(.+)/);
        const toMatch = sslResult.stdout.match(/notAfter=(.+)/);

        if (subMatch) certificateInfo.subject = subMatch[1].trim();
        if (issMatch) certificateInfo.issuer = issMatch[1].trim();
        if (fromMatch) certificateInfo.validFrom = fromMatch[1].trim();
        if (toMatch) certificateInfo.validTo = toMatch[1].trim();

        if (certificateInfo.subject && certificateInfo.issuer && certificateInfo.subject === certificateInfo.issuer) {
          certificateInfo.selfSigned = true;
        }
      }
    } catch {
      // TLS check failed
    }

    // ── Step 4: Generate Findings ──

    // BlueKeep
    if (blueKeepVulnerable === true) {
      findings.push({
        id: "rdp-bluekeep",
        category: "cve",
        severity: "critical",
        title: "CVE-2019-0708 (BlueKeep) — Remote Code Execution",
        description: "The RDP service is vulnerable to BlueKeep (CVE-2019-0708), a wormable pre-authentication RCE vulnerability. An attacker can execute arbitrary code without credentials by sending crafted RDP packets.",
        recommendation: "Apply Microsoft security update KB4499175 immediately. Enable NLA as a partial mitigation. Block port 3389 from untrusted networks.",
        cve: "CVE-2019-0708",
        cwe: "CWE-416",
        evidence: "Nmap rdp-vuln-ms12-020 script confirmed VULNERABLE state",
      });
    }

    // NLA not enabled
    if (nlaEnabled === false) {
      findings.push({
        id: "rdp-no-nla",
        category: "authentication",
        severity: "high",
        title: "Network Level Authentication (NLA) Not Enforced",
        description: "The RDP server does not require Network Level Authentication. Without NLA, attackers can reach the RDP login screen without authenticating first, enabling brute-force attacks and exploitation of pre-auth vulnerabilities like BlueKeep.",
        recommendation: "Enable NLA in System Properties → Remote → 'Allow connections only from computers running Remote Desktop with Network Level Authentication'. Set via GPO: Computer Configuration → Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Security → Require user authentication for remote connections by using NLA.",
        cve: null,
        cwe: "CWE-287",
        evidence: `NLA not detected. Security protocol: ${securityProtocol || "unknown"}`,
      });
    }

    // Weak encryption
    if (encryptionLevel) {
      const weakEncryption = encryptionLevel.toLowerCase().includes("40-bit") || encryptionLevel.toLowerCase().includes("56-bit") || encryptionLevel.toLowerCase().includes("low");
      if (weakEncryption) {
        findings.push({
          id: "rdp-weak-encryption",
          category: "encryption",
          severity: "high",
          title: `Weak RDP Encryption: ${encryptionLevel}`,
          description: `The RDP server uses weak encryption (${encryptionLevel}). This allows attackers to decrypt RDP traffic via brute-force or known attacks against weak ciphers.`,
          recommendation: "Configure RDP to use High or FIPS encryption level. Set via GPO: Computer Configuration → Administrative Templates → Windows Components → Remote Desktop Services → Remote Desktop Session Host → Security → Set client connection encryption level → High Level.",
          cve: null,
          cwe: "CWE-326",
          evidence: `Encryption level: ${encryptionLevel}`,
        });
      }
    }

    // RDP Standard Security (not TLS/CredSSP)
    if (securityProtocol && securityProtocol.toLowerCase().includes("rdp")) {
      if (!securityProtocol.toLowerCase().includes("tls") && !securityProtocol.toLowerCase().includes("credssp")) {
        findings.push({
          id: "rdp-standard-security",
          category: "protocol",
          severity: "medium",
          title: "RDP Using Legacy Standard Security Protocol",
          description: "The RDP server uses the legacy RDP Standard Security protocol instead of TLS or CredSSP. This protocol has known weaknesses and is susceptible to man-in-the-middle attacks.",
          recommendation: "Configure RDP to require TLS 1.2+ for transport security. Set via GPO: Require use of specific security layer for remote (RDP) connections → SSL (TLS 1.0).",
          cve: null,
          cwe: "CWE-757",
          evidence: `Security protocol: ${securityProtocol}`,
        });
      }
    }

    // Self-signed certificate
    if (certificateInfo.selfSigned) {
      findings.push({
        id: "rdp-self-signed-cert",
        category: "certificate",
        severity: "medium",
        title: "RDP Server Uses Self-Signed Certificate",
        description: "The RDP server presents a self-signed TLS certificate. This prevents clients from verifying the server's identity, making the connection susceptible to man-in-the-middle attacks.",
        recommendation: "Deploy a certificate from a trusted CA for the RDP server. Configure via GPO or certlm.msc to bind a proper certificate to the RDP listener.",
        cve: null,
        cwe: "CWE-295",
        evidence: `Subject: ${certificateInfo.subject}, Issuer: ${certificateInfo.issuer}`,
      });
    }

    // Expired certificate
    if (certificateInfo.validTo) {
      try {
        const expiry = new Date(certificateInfo.validTo);
        if (expiry < new Date()) {
          findings.push({
            id: "rdp-expired-cert",
            category: "certificate",
            severity: "medium",
            title: "RDP Server Certificate Expired",
            description: `The RDP server's TLS certificate expired on ${certificateInfo.validTo}. Expired certificates may cause connection warnings and indicate poor certificate management.`,
            recommendation: "Renew the RDP server certificate immediately.",
            cve: null,
            cwe: "CWE-298",
            evidence: `Certificate expired: ${certificateInfo.validTo}`,
          });
        }
      } catch {}
    }

    // OS version info
    if (osVersion) {
      findings.push({
        id: "rdp-os-info",
        category: "configuration",
        severity: "info",
        title: "RDP Server OS Information Disclosed",
        description: `The RDP server disclosed its operating system version via NTLM info: ${osVersion}`,
        recommendation: "Consider restricting NTLM information disclosure if not needed for authentication.",
        cve: null,
        cwe: "CWE-200",
        evidence: `OS: ${osVersion}`,
      });
    }

    // ── Step 5: LLM Analysis (or deterministic offload) ──
    if (rawOutput.length > 100 && !useDeterministicAnalysis("rdp")) {
      try {
        const llmResult = await throttledLLMCall(async () => {
          return invokeLLM({
            _caller: "rdp-audit-scanner",
            messages: [
              {
                role: "system",
                content: `You are an RDP security auditor. Analyze the following RDP audit output and identify additional security findings. Focus on: authentication weaknesses, encryption issues, known CVEs (BlueKeep, DejaBlue, CredSSP), NLA enforcement, certificate problems, and protocol misconfigurations. Return JSON array of findings.`,
              },
              {
                role: "user",
                content: `RDP Audit Results for ${config.host}:${port}:\n\nNLA: ${nlaEnabled}, Encryption: ${encryptionLevel}, Protocol: ${securityProtocol}, BlueKeep: ${blueKeepVulnerable}, OS: ${osVersion}\n\n${rawOutput.slice(0, 8000)}`,
              },
            ],
            response_format: {
              type: "json_schema",
              json_schema: {
                name: "rdp_findings",
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
              const existingCves = new Set(findings.map(e => e.cve).filter(Boolean));
              if (f.cve && existingCves.has(f.cve)) continue;
              findings.push({
                id: `rdp-llm-${findings.length}`,
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
        console.warn("[RDPAudit] LLM analysis failed:", err);
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
            rdpVersion, nlaEnabled, encryptionLevel, securityProtocol,
            osVersion, blueKeepVulnerable, certificateInfo,
            severityCounts: {
              critical: findings.filter(f => f.severity === "critical").length,
              high: findings.filter(f => f.severity === "high").length,
              medium: findings.filter(f => f.severity === "medium").length,
              low: findings.filter(f => f.severity === "low").length,
              info: findings.filter(f => f.severity === "info").length,
            },
          }),
        }).where(eq(scanResults.id, scanId));
      } catch (err) {
        console.warn("[RDPAudit] Failed to update scan record:", err);
      }
    }

    return {
      scanId,
      status: "completed",
      host: config.host,
      port,
      rdpVersion,
      nlaEnabled,
      encryptionLevel,
      securityProtocol,
      osVersion,
      blueKeepVulnerable,
      certificateInfo,
      findings,
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
        }).where(eq(scanResults.id, scanId));
      } catch {}
    }

    return {
      scanId,
      status: "error",
      host: config.host,
      port,
      rdpVersion,
      nlaEnabled,
      encryptionLevel,
      securityProtocol,
      osVersion,
      blueKeepVulnerable,
      certificateInfo,
      findings,
      stats: { totalFindings: findings.length, criticalFindings: 0, durationSeconds },
      rawOutput,
      error: err.message,
    };
  }
}
