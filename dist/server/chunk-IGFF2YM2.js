import {
  executeRawCommand,
  executeTool,
  init_scan_server_executor
} from "./chunk-BDKAXPQT.js";
import {
  getDb,
  init_db
} from "./chunk-VL2KRLTM.js";
import {
  init_schema,
  scanResults
} from "./chunk-IG2G4XDA.js";

// server/lib/scanners/dns-audit-scanner.ts
init_scan_server_executor();
init_db();
init_schema();
var DNS_CVES = [
  {
    id: "CVE-2023-50387",
    description: "KeyTrap \u2014 DNSSEC validation CPU exhaustion, single DNS packet can stall resolvers for 16 hours",
    severity: "high",
    affectedPattern: /BIND[_ ](9\.(16\.[0-4][0-9]|18\.[0-2][0-9]|19\.[0-9]))/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-50387"]
  },
  {
    id: "CVE-2023-50868",
    description: "NSEC3 closest encloser proof CPU exhaustion in DNSSEC validation",
    severity: "high",
    affectedPattern: /BIND[_ ](9\.(16\.[0-4][0-9]|18\.[0-2][0-9]|19\.[0-9]))/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-50868"]
  },
  {
    id: "CVE-2023-3341",
    description: "BIND named stack exhaustion via recursive control channel messages",
    severity: "high",
    affectedPattern: /BIND[_ ](9\.(16\.[0-4][0-4]|18\.[0-1][0-8]|19\.[0-6]))/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2023-3341"]
  },
  {
    id: "CVE-2022-3094",
    description: "BIND named memory exhaustion via UPDATE message flood",
    severity: "high",
    affectedPattern: /BIND[_ ](9\.(16\.[0-3][0-5]|18\.[0-3]|19\.[0-1]))/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-3094"]
  },
  {
    id: "CVE-2021-25220",
    description: "BIND cache poisoning via forwarder configuration",
    severity: "medium",
    affectedPattern: /BIND[_ ](9\.(11\.[0-3][0-7]|16\.[0-2][0-7]|17\.|18\.0))/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-25220"]
  },
  {
    id: "CVE-2020-1350",
    description: "SIGRed \u2014 Windows DNS Server RCE via crafted SIG record (wormable)",
    severity: "critical",
    affectedPattern: /Microsoft DNS/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2020-1350"]
  },
  {
    id: "CVE-2022-30190",
    description: "dnsmasq heap buffer overflow in DNSSEC validation",
    severity: "high",
    affectedPattern: /dnsmasq[_ -](2\.[0-8][0-6])/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2022-30190"]
  },
  {
    id: "CVE-2021-3448",
    description: "dnsmasq DNS cache poisoning via reduced source port randomness",
    severity: "medium",
    affectedPattern: /dnsmasq[_ -](2\.[0-8][0-4])/i,
    references: ["https://nvd.nist.gov/vuln/detail/CVE-2021-3448"]
  }
];
function parseDigVersion(output) {
  const versionMatch = output.match(/version\.bind\.\s+\d+\s+CH\s+TXT\s+"([^"]+)"/i) || output.match(/version\.server\.\s+\d+\s+CH\s+TXT\s+"([^"]+)"/i);
  return versionMatch ? versionMatch[1] : null;
}
function detectSoftware(version) {
  if (!version) return null;
  if (/BIND/i.test(version)) return "ISC BIND";
  if (/PowerDNS/i.test(version)) return "PowerDNS";
  if (/dnsmasq/i.test(version)) return "dnsmasq";
  if (/Unbound/i.test(version)) return "Unbound";
  if (/Microsoft/i.test(version)) return "Microsoft DNS";
  if (/NSD/i.test(version)) return "NLnet Labs NSD";
  if (/Knot/i.test(version)) return "Knot DNS";
  if (/CoreDNS/i.test(version)) return "CoreDNS";
  return null;
}
function parseZoneTransfer(output) {
  const lines = output.split("\n").filter((l) => l.trim() && !l.startsWith(";") && !l.startsWith("<<"));
  const records = lines.filter((l) => /\s+(IN|CH|HS)\s+/.test(l));
  return {
    vulnerable: records.length > 2,
    recordCount: records.length,
    records: records.slice(0, 50)
    // Cap at 50 for storage
  };
}
function parseRecursionCheck(output) {
  return output.includes("NOERROR") && (output.includes("ANSWER SECTION") || output.includes("ANSWER:"));
}
function parseDnssecCheck(output) {
  const hasRRSIG = output.includes("RRSIG");
  const hasDNSKEY = output.includes("DNSKEY");
  const hasAD = output.includes("flags:") && output.includes(" ad");
  return {
    enabled: hasRRSIG || hasDNSKEY,
    validated: hasAD
  };
}
function parseNSRecords(output) {
  const nsRecords = [];
  const nsRegex = /\s+IN\s+NS\s+(\S+)/g;
  let match;
  while ((match = nsRegex.exec(output)) !== null) {
    nsRecords.push(match[1].replace(/\.$/, ""));
  }
  return [...new Set(nsRecords)];
}
function parseMXRecords(output) {
  const mxRecords = [];
  const mxRegex = /\s+IN\s+MX\s+\d+\s+(\S+)/g;
  let match;
  while ((match = mxRegex.exec(output)) !== null) {
    mxRecords.push(match[1].replace(/\.$/, ""));
  }
  return [...new Set(mxRecords)];
}
function parseTXTRecords(output) {
  const txtRecords = [];
  const txtRegex = /\s+IN\s+TXT\s+"([^"]+)"/g;
  let match;
  while ((match = txtRegex.exec(output)) !== null) {
    txtRecords.push(match[1]);
  }
  return txtRecords;
}
function parseSOARecord(output) {
  const soaMatch = output.match(/\s+IN\s+SOA\s+(.+)/);
  return soaMatch ? soaMatch[1].trim() : null;
}
function generateFindings(zoneTransferVulnerable, zoneTransferRecordCount, recursionEnabled, dnssecEnabled, dnssecValidated, serverVersion, serverSoftware, amplificationFactor, txtRecords) {
  const findings = [];
  if (zoneTransferVulnerable) {
    findings.push({
      id: `dns-axfr-${Date.now()}`,
      category: "zone_transfer",
      severity: "high",
      title: "DNS Zone Transfer (AXFR) Allowed",
      description: `The DNS server allows zone transfer requests, exposing ${zoneTransferRecordCount} DNS records. An attacker can enumerate all hostnames, IPs, mail servers, and internal infrastructure.`,
      recommendation: "Restrict zone transfers to authorized secondary DNS servers only. Configure 'allow-transfer' ACLs in BIND or equivalent settings in other DNS software.",
      cve: null,
      cwe: "CWE-200",
      evidence: `AXFR returned ${zoneTransferRecordCount} records`
    });
  }
  if (recursionEnabled === true) {
    findings.push({
      id: `dns-recursion-${Date.now()}`,
      category: "recursion",
      severity: "high",
      title: "DNS Open Resolver Detected",
      description: "The DNS server responds to recursive queries from external sources. Open resolvers can be abused for DNS amplification DDoS attacks and cache poisoning.",
      recommendation: "Disable recursion for external queries. If recursion is needed, restrict it to trusted internal networks using 'allow-recursion' ACLs.",
      cve: null,
      cwe: "CWE-406",
      evidence: "Server resolved external domain (google.com) via recursive query"
    });
  }
  if (dnssecEnabled === false) {
    findings.push({
      id: `dns-no-dnssec-${Date.now()}`,
      category: "dnssec",
      severity: "medium",
      title: "DNSSEC Not Enabled",
      description: "The DNS zone does not have DNSSEC signatures. Without DNSSEC, DNS responses can be spoofed via cache poisoning attacks.",
      recommendation: "Enable DNSSEC signing for the zone. Deploy DNSKEY and DS records, and configure automatic key rotation.",
      cve: null,
      cwe: "CWE-345",
      evidence: "No RRSIG or DNSKEY records found in zone"
    });
  } else if (dnssecEnabled === true && !dnssecValidated) {
    findings.push({
      id: `dns-dnssec-novalidate-${Date.now()}`,
      category: "dnssec",
      severity: "low",
      title: "DNSSEC Signatures Present but Not Validated",
      description: "The zone has DNSSEC records but the resolver does not set the AD (Authenticated Data) flag, suggesting validation may not be enforced.",
      recommendation: "Ensure the resolver is configured to validate DNSSEC signatures. Check the trust anchor configuration.",
      cve: null,
      cwe: "CWE-345",
      evidence: "RRSIG/DNSKEY present but AD flag not set"
    });
  }
  if (serverVersion) {
    findings.push({
      id: `dns-version-disclosure-${Date.now()}`,
      category: "version",
      severity: "low",
      title: "DNS Server Version Disclosed",
      description: `The DNS server reveals its version string: "${serverVersion}". This information helps attackers identify specific CVEs and exploits.`,
      recommendation: `Hide the DNS version string. In BIND, set 'version "none";' in the options block. In other software, use equivalent configuration.`,
      cve: null,
      cwe: "CWE-200",
      evidence: `version.bind TXT: "${serverVersion}"`
    });
    for (const knownCve of DNS_CVES) {
      if (knownCve.affectedPattern.test(serverVersion)) {
        findings.push({
          id: `dns-cve-${knownCve.id}`,
          category: "cve",
          severity: knownCve.severity,
          title: `${knownCve.id}: ${knownCve.description.slice(0, 80)}`,
          description: knownCve.description,
          recommendation: "Update DNS server software to the latest patched version.",
          cve: knownCve.id,
          cwe: null,
          evidence: `Server version: ${serverVersion}`
        });
      }
    }
  }
  if (amplificationFactor !== null && amplificationFactor > 10) {
    findings.push({
      id: `dns-amplification-${Date.now()}`,
      category: "amplification",
      severity: amplificationFactor > 50 ? "high" : "medium",
      title: `DNS Amplification Factor: ${amplificationFactor.toFixed(1)}x`,
      description: `The DNS server has an amplification factor of ${amplificationFactor.toFixed(1)}x, meaning a small query produces a response ${amplificationFactor.toFixed(1)} times larger. This can be exploited for DDoS amplification attacks.`,
      recommendation: "Implement Response Rate Limiting (RRL). Disable recursion for external queries. Consider deploying DNS cookies (RFC 7873).",
      cve: null,
      cwe: "CWE-406",
      evidence: `Amplification ratio: ${amplificationFactor.toFixed(1)}x`
    });
  }
  if (recursionEnabled === true && dnssecEnabled !== true) {
    findings.push({
      id: `dns-cache-poison-risk-${Date.now()}`,
      category: "cache_poisoning",
      severity: "high",
      title: "DNS Cache Poisoning Risk \u2014 Open Resolver Without DNSSEC",
      description: "The combination of open recursion and missing DNSSEC validation creates a high risk of DNS cache poisoning. An attacker can inject forged DNS responses to redirect traffic.",
      recommendation: "1) Restrict recursion to trusted networks. 2) Enable DNSSEC validation. 3) Implement source port randomization. 4) Deploy DNS cookies.",
      cve: null,
      cwe: "CWE-350",
      evidence: "Open recursion: yes, DNSSEC: not enabled"
    });
  }
  const hasSPF = txtRecords.some((t) => t.startsWith("v=spf1"));
  const hasDMARC = txtRecords.some((t) => t.startsWith("v=DMARC1"));
  if (!hasSPF) {
    findings.push({
      id: `dns-no-spf-${Date.now()}`,
      category: "config",
      severity: "medium",
      title: "No SPF Record Found",
      description: "The domain does not have an SPF (Sender Policy Framework) record. Without SPF, attackers can send spoofed emails appearing to come from this domain.",
      recommendation: "Add an SPF TXT record specifying authorized mail servers. Example: 'v=spf1 mx a -all'",
      cve: null,
      cwe: "CWE-290",
      evidence: "No TXT record starting with 'v=spf1' found"
    });
  }
  if (!hasDMARC) {
    findings.push({
      id: `dns-no-dmarc-${Date.now()}`,
      category: "config",
      severity: "medium",
      title: "No DMARC Record Found",
      description: "The domain does not have a DMARC (Domain-based Message Authentication, Reporting & Conformance) record. Without DMARC, email spoofing protection is incomplete.",
      recommendation: "Add a DMARC TXT record at _dmarc.domain. Example: 'v=DMARC1; p=reject; rua=mailto:dmarc@domain'",
      cve: null,
      cwe: "CWE-290",
      evidence: "No TXT record starting with 'v=DMARC1' found at _dmarc subdomain"
    });
  }
  return findings;
}
async function startDNSAudit(config) {
  const startTime = Date.now();
  const port = config.port || 53;
  const timeout = config.timeoutSeconds || 60;
  const target = `${config.host}:${port}`;
  const domain = config.domain || config.host;
  console.log(`[DNSAudit] Starting audit of ${target} (domain: ${domain})`);
  let serverVersion = null;
  let serverSoftware = null;
  let recursionEnabled = null;
  let zoneTransferVulnerable = false;
  let zoneTransferRecordCount = 0;
  let dnssecEnabled = null;
  let dnssecValidated = false;
  let amplificationFactor = null;
  let rawOutput = "";
  const nsRecords = [];
  const mxRecords = [];
  const txtRecords = [];
  let soaRecord = null;
  if (config.checkVersion !== false) {
    try {
      const versionResult = await executeRawCommand(
        `dig @${config.host} -p ${port} version.bind CH TXT +short 2>&1 && dig @${config.host} -p ${port} version.server CH TXT +short 2>&1`,
        15
      );
      rawOutput += `=== version check ===
${versionResult.stdout}
`;
      serverVersion = parseDigVersion(versionResult.stdout) || versionResult.stdout.replace(/"/g, "").trim().split("\n")[0] || null;
      if (serverVersion && serverVersion.length > 200) serverVersion = null;
      serverSoftware = detectSoftware(serverVersion);
    } catch (err) {
      console.warn(`[DNSAudit] Version check failed: ${err.message}`);
    }
  }
  if (config.checkRecursion !== false) {
    try {
      const recursionResult = await executeRawCommand(
        `dig @${config.host} -p ${port} google.com A +norecurse 2>&1 && echo "---SEPARATOR---" && dig @${config.host} -p ${port} google.com A +recurse 2>&1`,
        15
      );
      rawOutput += `
=== recursion check ===
${recursionResult.stdout}
`;
      const parts = recursionResult.stdout.split("---SEPARATOR---");
      if (parts.length >= 2) {
        recursionEnabled = parseRecursionCheck(parts[1]);
      }
    } catch (err) {
      console.warn(`[DNSAudit] Recursion check failed: ${err.message}`);
    }
  }
  if (config.checkZoneTransfer !== false) {
    try {
      const axfrResult = await executeRawCommand(
        `dig @${config.host} -p ${port} ${domain} AXFR +noall +answer 2>&1`,
        30
      );
      rawOutput += `
=== zone transfer ===
${axfrResult.stdout}
`;
      const axfrParsed = parseZoneTransfer(axfrResult.stdout);
      zoneTransferVulnerable = axfrParsed.vulnerable;
      zoneTransferRecordCount = axfrParsed.recordCount;
    } catch (err) {
      console.warn(`[DNSAudit] Zone transfer check failed: ${err.message}`);
    }
  }
  if (config.checkDnssec !== false) {
    try {
      const dnssecResult = await executeRawCommand(
        `dig @${config.host} -p ${port} ${domain} DNSKEY +dnssec 2>&1 && dig @${config.host} -p ${port} ${domain} SOA +dnssec 2>&1`,
        15
      );
      rawOutput += `
=== DNSSEC check ===
${dnssecResult.stdout}
`;
      const dnssecParsed = parseDnssecCheck(dnssecResult.stdout);
      dnssecEnabled = dnssecParsed.enabled;
      dnssecValidated = dnssecParsed.validated;
    } catch (err) {
      console.warn(`[DNSAudit] DNSSEC check failed: ${err.message}`);
    }
  }
  try {
    const recordResult = await executeRawCommand(
      `dig @${config.host} -p ${port} ${domain} NS +noall +answer 2>&1 && dig @${config.host} -p ${port} ${domain} MX +noall +answer 2>&1 && dig @${config.host} -p ${port} ${domain} TXT +noall +answer 2>&1 && dig @${config.host} -p ${port} ${domain} SOA +noall +answer 2>&1 && dig @${config.host} -p ${port} _dmarc.${domain} TXT +noall +answer 2>&1`,
      20
    );
    rawOutput += `
=== record enumeration ===
${recordResult.stdout}
`;
    nsRecords.push(...parseNSRecords(recordResult.stdout));
    mxRecords.push(...parseMXRecords(recordResult.stdout));
    txtRecords.push(...parseTXTRecords(recordResult.stdout));
    soaRecord = parseSOARecord(recordResult.stdout);
  } catch (err) {
    console.warn(`[DNSAudit] Record enumeration failed: ${err.message}`);
  }
  if (config.checkAmplification !== false) {
    try {
      const ampResult = await executeRawCommand(
        `dig @${config.host} -p ${port} ${domain} ANY +bufsize=4096 2>&1`,
        10
      );
      rawOutput += `
=== amplification check ===
${ampResult.stdout}
`;
      const rcvdMatch = ampResult.stdout.match(/rcvd:\s*(\d+)/);
      const querySize = 40;
      if (rcvdMatch) {
        const responseSize = parseInt(rcvdMatch[1], 10);
        amplificationFactor = responseSize / querySize;
      }
    } catch (err) {
      console.warn(`[DNSAudit] Amplification check failed: ${err.message}`);
    }
  }
  try {
    const discoveryResult = await executeTool({
      tool: "naabu",
      args: `-p ${port} --script dns-nsid,dns-recursion,dns-service-discovery,dns-cache-snoop -sV ${config.host}`,
      target: config.host,
      timeoutSeconds: timeout,
      engagementId: config.engagementId
    });
    rawOutput += `
=== ScanForge discovery DNS scripts ===
${discoveryResult.stdout}
`;
    if (!serverVersion) {
      const serviceVersion = discoveryResult.stdout.match(/BIND\s+[\d.]+/i) || discoveryResult.stdout.match(/dnsmasq\s+[\d.]+/i) || discoveryResult.stdout.match(/PowerDNS\s+[\d.]+/i);
      if (serviceVersion) {
        serverVersion = serviceVersion[0];
        serverSoftware = detectSoftware(serverVersion);
      }
    }
    if (recursionEnabled === null) {
      recursionEnabled = discoveryResult.stdout.includes("Recursion: Enabled") || discoveryResult.stdout.includes("dns-recursion:");
    }
  } catch (err) {
    console.warn(`[DNSAudit] ScanForge discovery DNS scripts failed: ${err.message}`);
  }
  const findings = generateFindings(
    zoneTransferVulnerable,
    zoneTransferRecordCount,
    recursionEnabled,
    dnssecEnabled,
    dnssecValidated,
    serverVersion,
    serverSoftware,
    amplificationFactor,
    txtRecords
  );
  const durationSeconds = (Date.now() - startTime) / 1e3;
  let scanId = null;
  try {
    const db = await getDb();
    const severitySummary = {
      critical: findings.filter((f) => f.severity === "critical").length,
      high: findings.filter((f) => f.severity === "high").length,
      medium: findings.filter((f) => f.severity === "medium").length,
      low: findings.filter((f) => f.severity === "low").length,
      info: findings.filter((f) => f.severity === "info").length
    };
    const [inserted] = await db.insert(scanResults).values({
      engagementId: config.engagementId,
      tool: "dns-audit",
      target,
      command: `dns-audit ${config.host} -p ${port}`,
      rawOutput: rawOutput.slice(0, 5e5),
      rawStderr: null,
      exitCode: 0,
      durationMs: Math.round(durationSeconds * 1e3),
      timedOut: 0,
      findings: JSON.stringify({
        findings,
        records: { ns: nsRecords, mx: mxRecords, txt: txtRecords, soa: soaRecord, axfrRecordCount: zoneTransferRecordCount },
        serverVersion,
        recursionEnabled,
        dnssecEnabled,
        amplificationFactor
      }),
      findingCount: findings.length,
      severitySummary: JSON.stringify(severitySummary),
      phase: "vuln_detection",
      operatorId: config.operatorId || null
    });
    scanId = inserted.insertId;
  } catch (dbErr) {
    console.error(`[DNSAudit] Failed to store scan result:`, dbErr.message);
  }
  console.log(`[DNSAudit] Audit complete: ${findings.length} findings in ${durationSeconds.toFixed(1)}s`);
  return {
    scanId,
    status: "completed",
    host: config.host,
    port,
    serverVersion,
    serverSoftware,
    recursionEnabled,
    zoneTransferVulnerable,
    dnssecEnabled,
    amplificationFactor,
    findings,
    records: {
      ns: nsRecords,
      mx: mxRecords,
      txt: txtRecords,
      soa: soaRecord,
      axfrRecordCount: zoneTransferRecordCount
    },
    stats: {
      totalFindings: findings.length,
      criticalFindings: findings.filter((f) => f.severity === "critical" || f.severity === "high").length,
      durationSeconds
    },
    rawOutput
  };
}

export {
  startDNSAudit
};
