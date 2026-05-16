import {
  init_deterministic_scanner_analysis,
  useDeterministicAnalysis
} from "./chunk-EILMWEUF.js";
import {
  init_llm_throttle,
  throttledLLMCall
} from "./chunk-GTXFXXF6.js";
import {
  executeRawCommand,
  executeTool,
  init_scan_server_executor
} from "./chunk-KW2CWOOD.js";
import {
  init_llm,
  invokeLLM
} from "./chunk-TCEHBLTC.js";
import {
  getDb,
  init_db
} from "./chunk-L5ZLWR7T.js";
import {
  init_schema,
  scanResults
} from "./chunk-L4JENJ4Z.js";

// server/lib/scanners/rdp-audit-scanner.ts
init_scan_server_executor();
init_llm();
init_llm_throttle();
init_deterministic_scanner_analysis();
init_db();
init_schema();
import { eq } from "drizzle-orm";
function parseScanForgeRDPOutput(output) {
  let nlaEnabled = null;
  let encryptionLevel = null;
  let securityProtocol = null;
  let blueKeepVulnerable = null;
  let osVersion = null;
  const certificate = { subject: null, issuer: null, validFrom: null, validTo: null, selfSigned: false };
  const ntlmInfo = {};
  if (output.includes("CredSSP (NLA)")) {
    nlaEnabled = true;
  } else if (output.includes("rdp-enum-encryption")) {
    if (!output.includes("CredSSP")) {
      nlaEnabled = false;
    }
  }
  const encMatch = output.match(/Encryption level:\s*(.+)/i);
  if (encMatch) encryptionLevel = encMatch[1].trim();
  const secMatch = output.match(/Security layer:\s*(.+)/i);
  if (secMatch) securityProtocol = secMatch[1].trim();
  if (output.includes("rdp-vuln-ms12-020") || output.includes("CVE-2019-0708")) {
    if (output.includes("VULNERABLE") || output.includes("State: VULNERABLE")) {
      blueKeepVulnerable = true;
    } else if (output.includes("NOT VULNERABLE") || output.includes("State: NOT VULNERABLE")) {
      blueKeepVulnerable = false;
    }
  }
  const osMatch = output.match(/OS:\s*(.+)/i) || output.match(/Product_Version:\s*(.+)/i);
  if (osMatch) osVersion = osMatch[1].trim();
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
async function startRDPAudit(config) {
  const port = config.port || 3389;
  const timeout = config.timeoutSeconds || 60;
  const startTime = Date.now();
  const findings = [];
  let rawOutput = "";
  let rdpVersion = null;
  let nlaEnabled = null;
  let encryptionLevel = null;
  let securityProtocol = null;
  let osVersion = null;
  let blueKeepVulnerable = null;
  let certificateInfo = {
    subject: null,
    issuer: null,
    validFrom: null,
    validTo: null,
    selfSigned: false
  };
  let scanId = null;
  try {
    const db = await getDb();
    const [row] = await db.insert(scanResults).values({
      engagementId: config.engagementId,
      scanType: "rdp_audit",
      target: `${config.host}:${port}`,
      status: "running",
      startedAt: Date.now(),
      rawOutput: ""
    }).returning({ id: scanResults.id });
    scanId = row?.id ?? null;
  } catch (err) {
    console.warn("[RDPAudit] Failed to create scan record:", err);
  }
  try {
    if (config.detectionTemplates !== false) {
      const detectionTemplates = [
        "rdp-enum-encryption",
        "rdp-ntlm-info",
        "rdp-vuln-ms12-020"
      ];
      const discoveryResult = await executeTool("naabu", [
        "-sV",
        "-p",
        String(port),
        "--script",
        detectionTemplates.join(","),
        "--script-timeout",
        String(timeout),
        "-oN",
        "-",
        config.host
      ], { timeoutSeconds: timeout + 30 });
      if (discoveryResult.stdout) {
        rawOutput += `=== SCANFORGE RDP SCRIPTS ===
${discoveryResult.stdout}

`;
        const parsed = parseScanForgeRDPOutput(discoveryResult.stdout);
        nlaEnabled = parsed.nlaEnabled;
        encryptionLevel = parsed.encryptionLevel;
        securityProtocol = parsed.securityProtocol;
        blueKeepVulnerable = parsed.blueKeepVulnerable;
        osVersion = parsed.osVersion;
        certificateInfo = parsed.certificate;
        const versionMatch = discoveryResult.stdout.match(/(\d+\/tcp\s+open\s+ms-wbt-server\s+(.+))/i);
        if (versionMatch) rdpVersion = versionMatch[2]?.trim() || null;
      }
    }
    if (config.testBlueKeep !== false && blueKeepVulnerable === null) {
      try {
        const blueKeepResult = await executeTool("naabu", [
          "-p",
          String(port),
          "--script",
          "rdp-vuln-ms12-020",
          "--script-args",
          "vulns.short",
          config.host
        ], { timeoutSeconds: 30 });
        if (blueKeepResult.stdout) {
          rawOutput += `=== BLUEKEEP CHECK ===
${blueKeepResult.stdout}

`;
          if (blueKeepResult.stdout.includes("VULNERABLE")) {
            blueKeepVulnerable = true;
          } else {
            blueKeepVulnerable = false;
          }
        }
      } catch {
      }
    }
    try {
      const sslResult = await executeRawCommand(
        `echo | timeout 10 openssl s_client -connect ${config.host}:${port} 2>/dev/null | openssl x509 -noout -subject -issuer -dates 2>/dev/null`,
        { timeoutSeconds: 15 }
      );
      if (sslResult.stdout && sslResult.stdout.includes("subject=")) {
        rawOutput += `=== TLS CERTIFICATE ===
${sslResult.stdout}

`;
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
    }
    if (blueKeepVulnerable === true) {
      findings.push({
        id: "rdp-bluekeep",
        category: "cve",
        severity: "critical",
        title: "CVE-2019-0708 (BlueKeep) \u2014 Remote Code Execution",
        description: "The RDP service is vulnerable to BlueKeep (CVE-2019-0708), a wormable pre-authentication RCE vulnerability. An attacker can execute arbitrary code without credentials by sending crafted RDP packets.",
        recommendation: "Apply Microsoft security update KB4499175 immediately. Enable NLA as a partial mitigation. Block port 3389 from untrusted networks.",
        cve: "CVE-2019-0708",
        cwe: "CWE-416",
        evidence: "ScanForge rdp-vuln-ms12-020 script confirmed VULNERABLE state"
      });
    }
    if (nlaEnabled === false) {
      findings.push({
        id: "rdp-no-nla",
        category: "authentication",
        severity: "high",
        title: "Network Level Authentication (NLA) Not Enforced",
        description: "The RDP server does not require Network Level Authentication. Without NLA, attackers can reach the RDP login screen without authenticating first, enabling brute-force attacks and exploitation of pre-auth vulnerabilities like BlueKeep.",
        recommendation: "Enable NLA in System Properties \u2192 Remote \u2192 'Allow connections only from computers running Remote Desktop with Network Level Authentication'. Set via GPO: Computer Configuration \u2192 Administrative Templates \u2192 Windows Components \u2192 Remote Desktop Services \u2192 Remote Desktop Session Host \u2192 Security \u2192 Require user authentication for remote connections by using NLA.",
        cve: null,
        cwe: "CWE-287",
        evidence: `NLA not detected. Security protocol: ${securityProtocol || "unknown"}`
      });
    }
    if (encryptionLevel) {
      const weakEncryption = encryptionLevel.toLowerCase().includes("40-bit") || encryptionLevel.toLowerCase().includes("56-bit") || encryptionLevel.toLowerCase().includes("low");
      if (weakEncryption) {
        findings.push({
          id: "rdp-weak-encryption",
          category: "encryption",
          severity: "high",
          title: `Weak RDP Encryption: ${encryptionLevel}`,
          description: `The RDP server uses weak encryption (${encryptionLevel}). This allows attackers to decrypt RDP traffic via brute-force or known attacks against weak ciphers.`,
          recommendation: "Configure RDP to use High or FIPS encryption level. Set via GPO: Computer Configuration \u2192 Administrative Templates \u2192 Windows Components \u2192 Remote Desktop Services \u2192 Remote Desktop Session Host \u2192 Security \u2192 Set client connection encryption level \u2192 High Level.",
          cve: null,
          cwe: "CWE-326",
          evidence: `Encryption level: ${encryptionLevel}`
        });
      }
    }
    if (securityProtocol && securityProtocol.toLowerCase().includes("rdp")) {
      if (!securityProtocol.toLowerCase().includes("tls") && !securityProtocol.toLowerCase().includes("credssp")) {
        findings.push({
          id: "rdp-standard-security",
          category: "protocol",
          severity: "medium",
          title: "RDP Using Legacy Standard Security Protocol",
          description: "The RDP server uses the legacy RDP Standard Security protocol instead of TLS or CredSSP. This protocol has known weaknesses and is susceptible to man-in-the-middle attacks.",
          recommendation: "Configure RDP to require TLS 1.2+ for transport security. Set via GPO: Require use of specific security layer for remote (RDP) connections \u2192 SSL (TLS 1.0).",
          cve: null,
          cwe: "CWE-757",
          evidence: `Security protocol: ${securityProtocol}`
        });
      }
    }
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
        evidence: `Subject: ${certificateInfo.subject}, Issuer: ${certificateInfo.issuer}`
      });
    }
    if (certificateInfo.validTo) {
      try {
        const expiry = new Date(certificateInfo.validTo);
        if (expiry < /* @__PURE__ */ new Date()) {
          findings.push({
            id: "rdp-expired-cert",
            category: "certificate",
            severity: "medium",
            title: "RDP Server Certificate Expired",
            description: `The RDP server's TLS certificate expired on ${certificateInfo.validTo}. Expired certificates may cause connection warnings and indicate poor certificate management.`,
            recommendation: "Renew the RDP server certificate immediately.",
            cve: null,
            cwe: "CWE-298",
            evidence: `Certificate expired: ${certificateInfo.validTo}`
          });
        }
      } catch {
      }
    }
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
        evidence: `OS: ${osVersion}`
      });
    }
    if (rawOutput.length > 100 && !useDeterministicAnalysis("rdp")) {
      try {
        const llmResult = await throttledLLMCall(async () => {
          return invokeLLM({
            _caller: "rdp-audit-scanner",
            messages: [
              {
                role: "system",
                content: `You are an RDP security auditor. Analyze the following RDP audit output and identify additional security findings. Focus on: authentication weaknesses, encryption issues, known CVEs (BlueKeep, DejaBlue, CredSSP), NLA enforcement, certificate problems, and protocol misconfigurations. Return JSON array of findings.`
              },
              {
                role: "user",
                content: `RDP Audit Results for ${config.host}:${port}:

NLA: ${nlaEnabled}, Encryption: ${encryptionLevel}, Protocol: ${securityProtocol}, BlueKeep: ${blueKeepVulnerable}, OS: ${osVersion}

${rawOutput.slice(0, 8e3)}`
              }
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
                          cwe: { type: ["string", "null"] }
                        },
                        required: ["category", "severity", "title", "description", "recommendation", "cve", "cwe"],
                        additionalProperties: false
                      }
                    }
                  },
                  required: ["findings"],
                  additionalProperties: false
                }
              }
            }
          });
        });
        if (llmResult?.choices?.[0]?.message?.content) {
          const parsed = JSON.parse(llmResult.choices[0].message.content);
          if (Array.isArray(parsed.findings)) {
            for (const f of parsed.findings) {
              const existingCves = new Set(findings.map((e) => e.cve).filter(Boolean));
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
                evidence: null
              });
            }
          }
        }
      } catch (err) {
        console.warn("[RDPAudit] LLM analysis failed:", err);
      }
    }
    const durationSeconds = (Date.now() - startTime) / 1e3;
    if (scanId) {
      try {
        const db = await getDb();
        await db.update(scanResults).set({
          status: "completed",
          completedAt: Date.now(),
          rawOutput: rawOutput.slice(0, 5e4),
          findingsCount: findings.length,
          summary: JSON.stringify({
            rdpVersion,
            nlaEnabled,
            encryptionLevel,
            securityProtocol,
            osVersion,
            blueKeepVulnerable,
            certificateInfo,
            severityCounts: {
              critical: findings.filter((f) => f.severity === "critical").length,
              high: findings.filter((f) => f.severity === "high").length,
              medium: findings.filter((f) => f.severity === "medium").length,
              low: findings.filter((f) => f.severity === "low").length,
              info: findings.filter((f) => f.severity === "info").length
            }
          })
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
        criticalFindings: findings.filter((f) => f.severity === "critical").length,
        durationSeconds
      },
      rawOutput
    };
  } catch (err) {
    const durationSeconds = (Date.now() - startTime) / 1e3;
    if (scanId) {
      try {
        const db = await getDb();
        await db.update(scanResults).set({
          status: "error",
          completedAt: Date.now(),
          rawOutput: rawOutput + `
ERROR: ${err.message}`
        }).where(eq(scanResults.id, scanId));
      } catch {
      }
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
      error: err.message
    };
  }
}

export {
  startRDPAudit
};
