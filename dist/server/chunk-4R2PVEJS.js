import {
  init_deterministic_scanner_analysis,
  useDeterministicAnalysis
} from "./chunk-EILMWEUF.js";
import {
  init_llm_throttle,
  throttledLLMCall
} from "./chunk-2HOIKPO3.js";
import {
  executeRawCommand,
  executeTool,
  init_scan_server_executor
} from "./chunk-GS543EUU.js";
import {
  init_llm,
  invokeLLM
} from "./chunk-UAG3IV7V.js";
import {
  getDb,
  init_db
} from "./chunk-YEW6KKPA.js";
import {
  init_schema,
  scanResults
} from "./chunk-EMIPCWBF.js";

// server/lib/scanners/snmp-audit-scanner.ts
init_scan_server_executor();
init_llm();
init_llm_throttle();
init_deterministic_scanner_analysis();
init_db();
init_schema();
import { eq } from "drizzle-orm";
var DEFAULT_COMMUNITY_STRINGS = [
  "public",
  "private",
  "community",
  "snmp",
  "admin",
  "default",
  "password",
  "cisco",
  "monitor",
  "manager",
  "secret",
  "test",
  "network",
  "router",
  "switch",
  "read",
  "write",
  "all",
  "system",
  "access",
  "security",
  "internal",
  "guest",
  "ILMI",
  "Cisco",
  "cable-docsis",
  "rmon",
  "rmon_admin",
  "hp_admin",
  "NoGaH$@!",
  "0392a0",
  "agent",
  "netman",
  "superuser",
  "tech",
  "c0nfig",
  "ANYCOM",
  "xyzzy"
];
var SNMP_CVES = [
  {
    id: "CVE-2017-6742",
    description: "Cisco IOS/IOS XE SNMP remote code execution via crafted SNMP packets",
    severity: "critical",
    pattern: /Cisco\s+IOS/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2017-6742"]
  },
  {
    id: "CVE-2017-6736",
    description: "Cisco IOS SNMP buffer overflow allowing remote code execution",
    severity: "critical",
    pattern: /Cisco\s+IOS/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2017-6736"]
  },
  {
    id: "CVE-2002-0012",
    description: "Multiple SNMP implementations allow remote attackers to cause DoS or gain privileges via SNMPv1 trap handling",
    severity: "high",
    pattern: /SNMPv1/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2002-0012"]
  },
  {
    id: "CVE-2002-0013",
    description: "Multiple SNMP implementations allow remote attackers to cause DoS or gain privileges via SNMPv1 request handling",
    severity: "high",
    pattern: /SNMPv1/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2002-0013"]
  },
  {
    id: "CVE-2008-4309",
    description: "Net-SNMP 5.4.2.1 and earlier \u2014 integer overflow in netsnmp_create_subtree_cache",
    severity: "medium",
    pattern: /net-snmp\s*(5\.[0-4])/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2008-4309"]
  },
  {
    id: "CVE-2020-15862",
    description: "Net-SNMP privilege escalation via symlink attack on log file",
    severity: "high",
    pattern: /net-snmp\s*(5\.[0-8])/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-15862"]
  }
];
function parseScanForgeSNMPOutput(output) {
  const communityStrings = [];
  const systemInfo = {};
  const interfaces = [];
  const snmpVersions = [];
  const processes = [];
  const bruteMatch = output.match(/snmp-brute:[\s\S]*?((?:\|\s+\S+\s+-\s+Valid credentials\n?)+)/);
  if (bruteMatch) {
    const credRegex = /\|\s+(\S+)\s+-\s+Valid credentials/g;
    let m;
    while ((m = credRegex.exec(bruteMatch[1])) !== null) {
      communityStrings.push(m[1]);
    }
  }
  const sysDescrMatch = output.match(/snmp-sysdescr:[\s\S]*?\|\s+(.+)/);
  if (sysDescrMatch) systemInfo.sysDescr = sysDescrMatch[1].trim();
  const ifRegex = /snmp-interfaces:[\s\S]*?\|\s+(\S+)/gm;
  let ifMatch;
  while ((ifMatch = ifRegex.exec(output)) !== null) {
    if (!ifMatch[1].startsWith("|")) interfaces.push(ifMatch[1]);
  }
  if (output.includes("SNMPv1")) snmpVersions.push("v1");
  if (output.includes("SNMPv2c") || output.includes("snmpv2c")) snmpVersions.push("v2c");
  if (output.includes("SNMPv3")) snmpVersions.push("v3");
  const procRegex = /snmp-processes:[\s\S]*?\|\s+\d+:\s+(.+)/gm;
  let pMatch;
  while ((pMatch = procRegex.exec(output)) !== null) {
    processes.push(pMatch[1].trim());
  }
  return { communityStrings, systemInfo, interfaces, snmpVersions, processes };
}
function parseSNMPWalkOutput(output) {
  const info = {};
  const sysDescrMatch = output.match(/SNMPv2-MIB::sysDescr\.0\s+=\s+STRING:\s+"?(.+?)"?\s*$/m);
  if (sysDescrMatch) info.sysDescr = sysDescrMatch[1];
  const sysNameMatch = output.match(/SNMPv2-MIB::sysName\.0\s+=\s+STRING:\s+"?(.+?)"?\s*$/m);
  if (sysNameMatch) info.sysName = sysNameMatch[1];
  const sysContactMatch = output.match(/SNMPv2-MIB::sysContact\.0\s+=\s+STRING:\s+"?(.+?)"?\s*$/m);
  if (sysContactMatch) info.sysContact = sysContactMatch[1];
  const sysLocationMatch = output.match(/SNMPv2-MIB::sysLocation\.0\s+=\s+STRING:\s+"?(.+?)"?\s*$/m);
  if (sysLocationMatch) info.sysLocation = sysLocationMatch[1];
  const sysUpTimeMatch = output.match(/SNMPv2-MIB::sysUpTime\.0\s+=\s+Timeticks:\s+\((\d+)\)/);
  if (sysUpTimeMatch) info.sysUpTime = sysUpTimeMatch[1];
  return info;
}
async function startSNMPAudit(config) {
  const port = config.port || 161;
  const timeout = config.timeoutSeconds || 60;
  const startTime = Date.now();
  const findings = [];
  let rawOutput = "";
  const snmpVersions = [];
  const validCommunityStrings = [];
  let systemInfo = {
    sysDescr: null,
    sysObjectID: null,
    sysUpTime: null,
    sysContact: null,
    sysName: null,
    sysLocation: null,
    sysServices: null
  };
  const interfaces = [];
  let communityStringsTested = 0;
  let scanId = null;
  try {
    const db = await getDb();
    const [row] = await db.insert(scanResults).values({
      engagementId: config.engagementId,
      scanType: "snmp_audit",
      target: `${config.host}:${port}`,
      status: "running",
      startedAt: Date.now(),
      rawOutput: ""
    }).returning({ id: scanResults.id });
    scanId = row?.id ?? null;
  } catch (err) {
    console.warn("[SNMPAudit] Failed to create scan record:", err);
  }
  try {
    if (config.detectionTemplates !== false) {
      const detectionTemplates = [
        "snmp-brute",
        "snmp-info",
        "snmp-interfaces",
        "snmp-netstat",
        "snmp-processes",
        "snmp-sysdescr",
        "snmp-win32-services",
        "snmp-win32-shares",
        "snmp-win32-software",
        "snmp-win32-users"
      ];
      const discoveryResult = await executeTool("naabu", [
        "-sU",
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
        rawOutput += `=== SCANFORGE SNMP SCRIPTS ===
${discoveryResult.stdout}

`;
        const parsed = parseScanForgeSNMPOutput(discoveryResult.stdout);
        for (const cs of parsed.communityStrings) {
          if (!validCommunityStrings.find((v) => v.community === cs)) {
            validCommunityStrings.push({ community: cs, access: "read" });
          }
        }
        if (parsed.systemInfo.sysDescr) systemInfo.sysDescr = parsed.systemInfo.sysDescr;
        if (parsed.systemInfo.sysName) systemInfo.sysName = parsed.systemInfo.sysName;
        interfaces.push(...parsed.interfaces);
        snmpVersions.push(...parsed.snmpVersions);
      }
    }
    if (config.testCommunityStrings !== false) {
      const strings = config.communityStrings || DEFAULT_COMMUNITY_STRINGS;
      communityStringsTested = strings.length;
      for (const community of strings) {
        if (validCommunityStrings.find((v) => v.community === community)) continue;
        try {
          const snmpResult = await executeRawCommand(
            `snmpget -v2c -c "${community}" -t 3 -r 1 ${config.host}:${port} 1.3.6.1.2.1.1.1.0 2>&1`,
            { timeoutSeconds: 8 }
          );
          if (snmpResult.stdout && !snmpResult.stdout.includes("Timeout") && !snmpResult.stdout.includes("No Response")) {
            validCommunityStrings.push({ community, access: "read" });
            const sysDescrMatch = snmpResult.stdout.match(/STRING:\s+"?(.+?)"?\s*$/m);
            if (sysDescrMatch && !systemInfo.sysDescr) {
              systemInfo.sysDescr = sysDescrMatch[1];
            }
          }
        } catch {
        }
      }
    }
    if (config.testWriteAccess !== false) {
      for (const cs of validCommunityStrings) {
        try {
          const writeTest = await executeRawCommand(
            `snmpget -v2c -c "${cs.community}" -t 3 -r 1 ${config.host}:${port} 1.3.6.1.2.1.1.4.0 2>&1`,
            { timeoutSeconds: 8 }
          );
          if (writeTest.stdout && !writeTest.stdout.includes("Timeout")) {
            const currentContact = writeTest.stdout.match(/STRING:\s+"?(.+?)"?\s*$/m)?.[1] || "";
            const setTest = await executeRawCommand(
              `snmpset -v2c -c "${cs.community}" -t 3 -r 1 ${config.host}:${port} 1.3.6.1.2.1.1.4.0 s "${currentContact}" 2>&1`,
              { timeoutSeconds: 8 }
            );
            if (setTest.stdout && !setTest.stdout.includes("Error") && !setTest.stdout.includes("Timeout")) {
              cs.access = "write";
            }
          }
        } catch {
        }
      }
    }
    if (config.mibWalk !== false && validCommunityStrings.length > 0) {
      const bestCommunity = validCommunityStrings[0].community;
      try {
        const walkResult = await executeRawCommand(
          `snmpwalk -v2c -c "${bestCommunity}" -t 5 -r 1 ${config.host}:${port} 1.3.6.1.2.1.1 2>&1 | head -50`,
          { timeoutSeconds: 20 }
        );
        if (walkResult.stdout) {
          rawOutput += `=== SNMP MIB WALK (system) ===
${walkResult.stdout}

`;
          const walkInfo = parseSNMPWalkOutput(walkResult.stdout);
          systemInfo = { ...systemInfo, ...walkInfo };
        }
      } catch {
      }
      try {
        const ifWalk = await executeRawCommand(
          `snmpwalk -v2c -c "${bestCommunity}" -t 5 -r 1 ${config.host}:${port} 1.3.6.1.2.1.2.2.1.2 2>&1 | head -30`,
          { timeoutSeconds: 15 }
        );
        if (ifWalk.stdout) {
          rawOutput += `=== SNMP INTERFACES ===
${ifWalk.stdout}

`;
          const ifRegex = /STRING:\s+"?(.+?)"?\s*$/gm;
          let m;
          while ((m = ifRegex.exec(ifWalk.stdout)) !== null) {
            if (!interfaces.includes(m[1])) interfaces.push(m[1]);
          }
        }
      } catch {
      }
    }
    for (const cs of validCommunityStrings) {
      const isDefault = ["public", "private", "community", "snmp", "default"].includes(cs.community.toLowerCase());
      findings.push({
        id: `snmp-community-${cs.community}`,
        category: "community_string",
        severity: cs.access === "write" ? "critical" : isDefault ? "high" : "medium",
        title: `SNMP Community String Found: "${cs.community}" (${cs.access} access)`,
        description: `The community string "${cs.community}" provides ${cs.access} access to the SNMP agent. ${cs.access === "write" ? "Write access allows an attacker to modify device configuration remotely." : "Read access exposes system information, network topology, and running processes."}${isDefault ? " This is a well-known default community string." : ""}`,
        recommendation: cs.access === "write" ? "Immediately change write community strings. Migrate to SNMPv3 with authentication and encryption. Restrict SNMP access via ACLs." : "Change default community strings. Migrate to SNMPv3 with authentication. Restrict SNMP access to management networks only.",
        cve: null,
        cwe: cs.access === "write" ? "CWE-798" : "CWE-200",
        evidence: `Community: ${cs.community}, Access: ${cs.access}`
      });
    }
    if (snmpVersions.includes("v1") || snmpVersions.includes("v2c")) {
      if (!snmpVersions.includes("v3")) {
        findings.push({
          id: "snmp-no-v3",
          category: "version",
          severity: "high",
          title: "SNMP Agent Uses v1/v2c Without v3 Support",
          description: `The SNMP agent supports ${snmpVersions.join(", ")} but not SNMPv3. Versions 1 and 2c transmit community strings in cleartext, making them vulnerable to network sniffing.`,
          recommendation: "Upgrade to SNMPv3 with authPriv security level (SHA authentication + AES encryption). Disable SNMPv1/v2c if possible.",
          cve: null,
          cwe: "CWE-319",
          evidence: `Detected versions: ${snmpVersions.join(", ")}`
        });
      }
    }
    if (systemInfo.sysDescr || systemInfo.sysName || interfaces.length > 0) {
      findings.push({
        id: "snmp-info-disclosure",
        category: "information_disclosure",
        severity: "medium",
        title: "SNMP Information Disclosure",
        description: `The SNMP agent exposes system information: ${systemInfo.sysDescr ? `System: ${systemInfo.sysDescr}` : ""}${systemInfo.sysName ? `, Name: ${systemInfo.sysName}` : ""}${interfaces.length > 0 ? `, Interfaces: ${interfaces.slice(0, 5).join(", ")}` : ""}`,
        recommendation: "Restrict SNMP access to management networks. Use SNMPv3 with view-based access control to limit exposed OIDs.",
        cve: null,
        cwe: "CWE-200",
        evidence: JSON.stringify({ systemInfo, interfaceCount: interfaces.length })
      });
    }
    if (systemInfo.sysDescr) {
      for (const cve of SNMP_CVES) {
        if (cve.pattern.test(systemInfo.sysDescr)) {
          findings.push({
            id: `snmp-cve-${cve.id}`,
            category: "cve",
            severity: cve.severity,
            title: `${cve.id}: ${cve.description.split("\u2014")[0].trim()}`,
            description: cve.description,
            recommendation: `Apply vendor patches. See ${cve.references[0]}`,
            cve: cve.id,
            cwe: null,
            evidence: `System description matches: ${systemInfo.sysDescr}`
          });
        }
      }
    }
    if (rawOutput.length > 100 && !useDeterministicAnalysis("snmp")) {
      try {
        const llmResult = await throttledLLMCall(async () => {
          return invokeLLM({
            _caller: "snmp-audit-scanner",
            messages: [
              {
                role: "system",
                content: `You are an SNMP security auditor. Analyze the following SNMP audit output and identify additional security findings not already covered. Focus on: weak community strings, information disclosure, version vulnerabilities, write access risks, and misconfigurations. Return JSON array of findings.`
              },
              {
                role: "user",
                content: `SNMP Audit Results for ${config.host}:${port}:

Valid community strings: ${validCommunityStrings.map((c) => `${c.community}(${c.access})`).join(", ") || "none found"}
SNMP versions: ${snmpVersions.join(", ") || "unknown"}
System: ${systemInfo.sysDescr || "unknown"}

${rawOutput.slice(0, 6e3)}`
              }
            ],
            response_format: {
              type: "json_schema",
              json_schema: {
                name: "snmp_findings",
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
              findings.push({
                id: `snmp-llm-${findings.length}`,
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
        console.warn("[SNMPAudit] LLM analysis failed:", err);
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
            snmpVersions,
            communityStringsFound: validCommunityStrings.length,
            systemInfo,
            interfaceCount: interfaces.length,
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
        console.warn("[SNMPAudit] Failed to update scan record:", err);
      }
    }
    return {
      scanId,
      status: "completed",
      host: config.host,
      port,
      snmpVersions: [...new Set(snmpVersions)],
      validCommunityStrings,
      systemInfo,
      interfaces,
      findings,
      stats: {
        totalFindings: findings.length,
        criticalFindings: findings.filter((f) => f.severity === "critical").length,
        communityStringsTested,
        communityStringsFound: validCommunityStrings.length,
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
      snmpVersions,
      validCommunityStrings,
      systemInfo,
      interfaces,
      findings,
      stats: { totalFindings: findings.length, criticalFindings: 0, communityStringsTested, communityStringsFound: 0, durationSeconds },
      rawOutput,
      error: err.message
    };
  }
}

export {
  startSNMPAudit
};
