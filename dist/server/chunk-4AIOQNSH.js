import {
  init_deterministic_scanner_analysis,
  useDeterministicAnalysis
} from "./chunk-EILMWEUF.js";
import {
  init_llm_throttle,
  throttledLLMCall
} from "./chunk-YKJATTT4.js";
import {
  executeRawCommand,
  executeTool,
  init_scan_server_executor
} from "./chunk-JSIGP7YU.js";
import {
  init_llm,
  invokeLLM
} from "./chunk-TP4TYLYW.js";
import {
  getDb,
  init_db
} from "./chunk-JP5I5SRV.js";
import {
  init_schema,
  scanResults
} from "./chunk-FLBHZBVD.js";

// server/lib/scanners/smtp-audit-scanner.ts
init_scan_server_executor();
init_llm();
init_llm_throttle();
init_deterministic_scanner_analysis();
init_db();
init_schema();
import { eq } from "drizzle-orm";
var SMTP_CVES = [
  {
    id: "CVE-2019-15846",
    description: "Exim 4.92.1 and earlier \u2014 remote code execution via SNI in TLS handshake",
    severity: "critical",
    softwarePattern: /Exim\s*(4\.(9[0-2]|[0-8]\d))/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-15846"]
  },
  {
    id: "CVE-2019-10149",
    description: "Exim 4.87-4.91 \u2014 'The Return of the WIZard' RCE via recipient address",
    severity: "critical",
    softwarePattern: /Exim\s*4\.(8[7-9]|9[01])/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2019-10149"]
  },
  {
    id: "CVE-2021-27216",
    description: "Exim privilege escalation via alternate configuration file",
    severity: "high",
    softwarePattern: /Exim\s*4\.(9[0-4])/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-27216"]
  },
  {
    id: "CVE-2020-28018",
    description: "Exim use-after-free in TLS handling leading to RCE (21Nails)",
    severity: "critical",
    softwarePattern: /Exim\s*4\.(9[0-3])/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-28018"]
  },
  {
    id: "CVE-2017-16943",
    description: "Exim use-after-free vulnerability in BDAT command handling",
    severity: "critical",
    softwarePattern: /Exim\s*4\.(8[5-9])/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2017-16943"]
  },
  {
    id: "CVE-2003-0161",
    description: "Sendmail prescan() buffer overflow \u2014 remote code execution",
    severity: "critical",
    softwarePattern: /Sendmail\s*(8\.(1[0-2]|[0-9])\.|[1-7]\.)/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2003-0161"]
  },
  {
    id: "CVE-2021-3156",
    description: "Sendmail/sudo heap-based buffer overflow (Baron Samedit)",
    severity: "critical",
    softwarePattern: /Sendmail/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-3156"]
  },
  {
    id: "CVE-2023-21529",
    description: "Microsoft Exchange Server remote code execution",
    severity: "critical",
    softwarePattern: /Microsoft\s+Exchange|Microsoft\s+ESMTP/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-21529"]
  },
  {
    id: "CVE-2021-26855",
    description: "Microsoft Exchange Server ProxyLogon SSRF \u2014 unauthenticated RCE chain",
    severity: "critical",
    softwarePattern: /Microsoft\s+Exchange|Microsoft\s+ESMTP/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-26855"]
  },
  {
    id: "CVE-2024-21413",
    description: "Microsoft Outlook/Exchange MonikerLink RCE via crafted hyperlink",
    severity: "critical",
    softwarePattern: /Microsoft\s+Exchange|Microsoft\s+ESMTP/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2024-21413"]
  },
  {
    id: "CVE-2011-1720",
    description: "Postfix SMTP server memory corruption in SASL implementation",
    severity: "high",
    softwarePattern: /Postfix\s*(2\.[0-7])/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2011-1720"]
  },
  {
    id: "CVE-2023-51764",
    description: "Postfix SMTP smuggling \u2014 allows email spoofing by injecting messages",
    severity: "medium",
    softwarePattern: /Postfix\s*(3\.[0-8]|2\.)/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-51764"]
  }
];
var DEFAULT_SMTP_USERS = [
  "admin",
  "administrator",
  "postmaster",
  "root",
  "info",
  "support",
  "webmaster",
  "sales",
  "contact",
  "abuse",
  "security",
  "noc",
  "helpdesk",
  "test",
  "user",
  "mail",
  "smtp",
  "backup"
];
function parseScanForgeSMTPOutput(output) {
  let banner = null;
  let openRelay = false;
  let vrfyEnabled = false;
  let expnEnabled = false;
  const authMethods = [];
  let tlsSupported = false;
  const enumeratedUsers = [];
  const commands = [];
  const bannerMatch = output.match(/smtp.*?(\d+\/tcp\s+open\s+smtp\s+(.+))/i);
  if (bannerMatch) banner = bannerMatch[2]?.trim() || null;
  if (output.includes("smtp-open-relay:") && output.includes("Server is an open relay")) {
    openRelay = true;
  }
  if (output.includes("smtp-vrfy:") || output.includes("VRFY")) {
    if (!output.includes("VRFY disabled") && !output.includes("252")) {
      vrfyEnabled = true;
    }
  }
  if (output.includes("smtp-enum-users:") && output.includes("EXPN")) {
    expnEnabled = true;
  }
  const authMatch = output.match(/AUTH\s+(.+)/i);
  if (authMatch) {
    authMethods.push(...authMatch[1].split(/\s+/).map((m) => m.trim()).filter(Boolean));
  }
  if (output.includes("STARTTLS") || output.includes("smtp-starttls")) {
    tlsSupported = true;
  }
  const userRegex = /smtp-enum-users:[\s\S]*?(\w+@[\w.]+)/gm;
  let uMatch;
  while ((uMatch = userRegex.exec(output)) !== null) {
    enumeratedUsers.push(uMatch[1]);
  }
  const cmdMatch = output.match(/smtp-commands:[\s\S]*?((?:\w+\s*)+)/);
  if (cmdMatch) {
    commands.push(...cmdMatch[1].split(/\s+/).filter((c) => c.length > 1));
  }
  return { banner, openRelay, vrfyEnabled, expnEnabled, authMethods, tlsSupported, enumeratedUsers, commands };
}
function identifySMTPServer(banner) {
  if (!banner) return { software: null, version: null };
  const patterns = [
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
    { regex: /(qmail)/i, software: "qmail" }
  ];
  for (const { regex, software } of patterns) {
    const match = banner.match(regex);
    if (match) return { software, version: match[2] || null };
  }
  return { software: null, version: null };
}
function checkSMTPCVEs(banner) {
  const findings = [];
  for (const cve of SMTP_CVES) {
    if (cve.softwarePattern.test(banner)) {
      findings.push({
        id: `smtp-cve-${cve.id}`,
        category: "cve",
        severity: cve.severity,
        title: `${cve.id}: ${cve.description.split("\u2014")[0].trim()}`,
        description: cve.description,
        recommendation: `Upgrade SMTP server to a patched version. See ${cve.references[0]}`,
        cve: cve.id,
        cwe: null,
        evidence: `Banner matches pattern: ${banner}`
      });
    }
  }
  return findings;
}
async function startSMTPAudit(config) {
  const port = config.port || 25;
  const timeout = config.timeoutSeconds || 60;
  const startTime = Date.now();
  const findings = [];
  let rawOutput = "";
  let banner = null;
  let serverSoftware = null;
  let serverVersion = null;
  let tlsSupported = false;
  let openRelay = false;
  let vrfyEnabled = false;
  let expnEnabled = false;
  let authMethods = [];
  let dnsRecords = { spf: null, dkim: false, dmarc: null };
  let scanId = null;
  try {
    const db = await getDb();
    const [row] = await db.insert(scanResults).values({
      engagementId: config.engagementId,
      scanType: "smtp_audit",
      target: `${config.host}:${port}`,
      status: "running",
      startedAt: Date.now(),
      rawOutput: ""
    }).returning({ id: scanResults.id });
    scanId = row?.id ?? null;
  } catch (err) {
    console.warn("[SMTPAudit] Failed to create scan record:", err);
  }
  try {
    if (config.detectionTemplates !== false) {
      const detectionTemplates = [
        "smtp-commands",
        "smtp-enum-users",
        "smtp-open-relay",
        "smtp-strangeport",
        "smtp-vuln-cve2010-4344",
        "smtp-vuln-cve2011-1720",
        "smtp-vuln-cve2011-1764"
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
        rawOutput += `=== SCANFORGE SMTP SCRIPTS ===
${discoveryResult.stdout}

`;
        const parsed = parseScanForgeSMTPOutput(discoveryResult.stdout);
        if (parsed.banner) banner = parsed.banner;
        openRelay = parsed.openRelay;
        vrfyEnabled = parsed.vrfyEnabled;
        expnEnabled = parsed.expnEnabled;
        authMethods = parsed.authMethods;
        tlsSupported = parsed.tlsSupported;
      }
    }
    if (!banner) {
      try {
        const bannerResult = await executeRawCommand(
          `echo "EHLO test" | timeout ${Math.min(timeout, 10)} nc -w 5 ${config.host} ${port} 2>/dev/null || echo "EHLO test" | timeout ${Math.min(timeout, 10)} nc -w 5 ${config.host} ${port}`,
          { timeoutSeconds: 15 }
        );
        if (bannerResult.stdout) {
          rawOutput += `=== BANNER GRAB ===
${bannerResult.stdout}

`;
          const bannerLine = bannerResult.stdout.split("\n").find((l) => l.startsWith("220"));
          if (bannerLine) banner = bannerLine.replace(/^220[\s-]*/, "").trim();
          const ehloLines = bannerResult.stdout.split("\n");
          for (const line of ehloLines) {
            if (line.includes("AUTH")) {
              const methods = line.replace(/.*AUTH\s+/i, "").split(/\s+/).filter(Boolean);
              authMethods = [.../* @__PURE__ */ new Set([...authMethods, ...methods])];
            }
            if (line.includes("STARTTLS")) tlsSupported = true;
          }
        }
      } catch {
      }
    }
    if (banner) {
      const id = identifySMTPServer(banner);
      serverSoftware = id.software;
      serverVersion = id.version;
      findings.push(...checkSMTPCVEs(banner));
    }
    if (config.testOpenRelay !== false && !openRelay) {
      try {
        const relayTest = await executeRawCommand(
          `echo -e "EHLO test.com\\nMAIL FROM:<test@test.com>\\nRCPT TO:<test@example.com>\\nQUIT" | timeout 10 nc -w 5 ${config.host} ${port} 2>/dev/null`,
          { timeoutSeconds: 15 }
        );
        if (relayTest.stdout) {
          rawOutput += `=== OPEN RELAY TEST ===
${relayTest.stdout}

`;
          if (relayTest.stdout.includes("250") && relayTest.stdout.match(/RCPT.*250/s)) {
            openRelay = true;
          }
        }
      } catch {
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
        evidence: "Server accepted RCPT TO for external domain without authentication"
      });
    }
    if (config.testUserEnum !== false) {
      const usernames = config.usernames || DEFAULT_SMTP_USERS;
      const validUsers = [];
      try {
        const vrfyCmds = usernames.slice(0, 10).map((u) => `VRFY ${u}`).join("\\n");
        const vrfyResult = await executeRawCommand(
          `echo -e "EHLO test.com\\n${vrfyCmds}\\nQUIT" | timeout 15 nc -w 5 ${config.host} ${port} 2>/dev/null`,
          { timeoutSeconds: 20 }
        );
        if (vrfyResult.stdout) {
          rawOutput += `=== VRFY ENUMERATION ===
${vrfyResult.stdout}

`;
          const lines = vrfyResult.stdout.split("\n");
          for (const line of lines) {
            if (line.match(/^25[02]/)) {
              vrfyEnabled = true;
              const userMatch = line.match(/25[02].*?(\S+@\S+|\S+)/);
              if (userMatch) validUsers.push(userMatch[1]);
            }
          }
        }
      } catch {
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
          evidence: `VRFY responses confirmed${validUsers.length > 0 ? `: ${validUsers.join(", ")}` : ""}`
        });
      }
    }
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
        evidence: "No STARTTLS in EHLO response"
      });
    }
    if (authMethods.includes("PLAIN") || authMethods.includes("LOGIN")) {
      if (!tlsSupported) {
        findings.push({
          id: "smtp-cleartext-auth",
          category: "authentication",
          severity: "high",
          title: "SMTP Cleartext Authentication Without TLS",
          description: `The server supports cleartext authentication methods (${authMethods.filter((m) => ["PLAIN", "LOGIN"].includes(m)).join(", ")}) without mandatory TLS, exposing credentials to network sniffing.`,
          recommendation: "Require TLS before allowing PLAIN/LOGIN authentication. Configure smtpd_tls_auth_only = yes in Postfix.",
          cve: null,
          cwe: "CWE-523",
          evidence: `Auth methods: ${authMethods.join(", ")}; TLS: ${tlsSupported ? "yes" : "no"}`
        });
      }
    }
    if (config.domain) {
      try {
        const dnsResult = await executeRawCommand(
          `dig +short TXT ${config.domain} 2>/dev/null; echo "---"; dig +short TXT _dmarc.${config.domain} 2>/dev/null; echo "---"; dig +short TXT default._domainkey.${config.domain} 2>/dev/null`,
          { timeoutSeconds: 15 }
        );
        if (dnsResult.stdout) {
          rawOutput += `=== DNS RECORDS ===
${dnsResult.stdout}

`;
          const sections = dnsResult.stdout.split("---");
          const spfRecord = sections[0]?.match(/"(v=spf1[^"]+)"/)?.[1] || null;
          dnsRecords.spf = spfRecord;
          const dmarcRecord = sections[1]?.match(/"(v=DMARC1[^"]+)"/)?.[1] || null;
          dnsRecords.dmarc = dmarcRecord;
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
              evidence: `No v=spf1 TXT record for ${config.domain}`
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
              evidence: `No v=DMARC1 TXT record for _dmarc.${config.domain}`
            });
          }
        }
      } catch {
      }
    }
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
        evidence: banner
      });
    }
    if (rawOutput.length > 100 && !useDeterministicAnalysis("smtp")) {
      try {
        const llmResult = await throttledLLMCall(async () => {
          return invokeLLM({
            _caller: "smtp-audit-scanner",
            messages: [
              {
                role: "system",
                content: `You are an SMTP security auditor. Analyze the following SMTP audit output and identify security findings. For each finding, provide: category, severity (critical/high/medium/low/info), title, description, recommendation, and any relevant CVE/CWE IDs. Focus on: open relay, user enumeration, weak authentication, missing encryption, version vulnerabilities, and misconfigurations. Return JSON array of findings.`
              },
              {
                role: "user",
                content: `SMTP Audit Results for ${config.host}:${port}:

${rawOutput.slice(0, 8e3)}`
              }
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
              const existingIds = new Set(findings.map((e) => e.cve).filter(Boolean));
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
                evidence: null
              });
            }
          }
        }
      } catch (err) {
        console.warn("[SMTPAudit] LLM analysis failed:", err);
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
            serverSoftware,
            serverVersion,
            openRelay,
            vrfyEnabled,
            tlsSupported,
            authMethods,
            dnsRecords,
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
      error: err.message
    };
  }
}

export {
  startSMTPAudit
};
