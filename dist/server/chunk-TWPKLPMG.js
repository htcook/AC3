// server/lib/unified-pipeline.ts
var PIPELINE_STAGES = [
  {
    phase: "recon",
    tools: ["passive_osint", "zap_passive", "nuclei_info", "atomic_red_team", "amass", "scanforge-discovery"],
    description: "Passive discovery and enumeration \u2014 map the attack surface without touching the target directly. OSINT connectors gather DNS, certificates, breached credentials, and cloud assets. Web scanner passive spider discovers web application structure. Template scanner info-level templates fingerprint technology stacks. Adversary emulation recon techniques (T1595, T1592) validate what an attacker would see.",
    requiresPriorPhase: false,
    canRunParallel: true,
    estimatedDurationMinutes: 10
  },
  {
    phase: "enumeration",
    tools: ["zap_active", "nuclei_info", "api_security", "passive_osint", "amass", "scanforge-discovery", "service_fingerprinter"],
    description: "Active probing and deep enumeration \u2014 crawl web applications, discover API endpoints, enumerate services. Web scanner active/AJAX spider performs deep crawling of JavaScript-heavy apps. Template scanner medium templates enumerate services and configurations. API security engine tests OpenAPI/GraphQL endpoints. Active DNS and banner verification confirms passive findings. Amass active subdomain enumeration discovers additional attack surface via DNS brute-force and zone transfers. ScanForge port scanning and service detection identifies open ports. Service fingerprinter performs protocol-specific probing of SSH, SMTP, FTP, SNMP, RDP, SMB, LDAP, databases, and other administrative services.",
    requiresPriorPhase: true,
    canRunParallel: true,
    estimatedDurationMinutes: 20
  },
  {
    phase: "vulnerability_assessment",
    tools: ["zap_active", "nuclei_vuln", "nuclei_critical", "nvd_kev", "api_security", "corroboration"],
    description: "Comprehensive vulnerability detection \u2014 DAST scanning, template-based vuln detection, CVE matching. Web scanner active scan tests for OWASP Top 10 (XSS, SQLi, CSRF, etc.). Template scanner high/critical templates detect known CVEs and misconfigurations. NVD/KEV matching correlates discovered services with known vulnerabilities. Corroboration engine cross-validates findings across all sources to reduce false positives by 30-40%.",
    requiresPriorPhase: true,
    canRunParallel: true,
    estimatedDurationMinutes: 45
  },
  {
    phase: "exploitation",
    tools: ["metasploit", "sliver_c2", "caldera", "atomic_red_team", "gophish"],
    description: "Active exploitation and initial access \u2014 execute exploits, deploy implants, launch phishing campaigns. Exploit framework executes matched exploits against confirmed vulnerabilities. C2 framework deploys cross-platform implants via mTLS/HTTPS/DNS. Adversary emulation platform runs abilities mapped to ATT&CK techniques. Adversary validation tests execute atomic tests to validate detection gaps. Phishing engine launches social engineering campaigns for initial access.",
    requiresPriorPhase: true,
    canRunParallel: false,
    estimatedDurationMinutes: 60
  },
  {
    phase: "post_exploitation",
    tools: ["sliver_c2", "caldera", "metasploit", "atomic_red_team", "bloodhound"],
    description: "Post-exploitation operations \u2014 lateral movement, persistence, privilege escalation, credential harvesting. C2 framework manages implant sessions for ongoing access. Adversary emulation platform orchestrates multi-step operations. Exploit framework provides post-exploitation modules. Adversary validation tests validate detection of post-exploitation techniques. AD attack path analysis discovers privilege escalation paths.",
    requiresPriorPhase: true,
    canRunParallel: false,
    estimatedDurationMinutes: 90
  },
  {
    phase: "reporting",
    tools: ["corroboration", "scoring", "detection_rules", "atomic_red_team"],
    description: "Validation, scoring, and reporting \u2014 corroborate findings, compute risk scores, validate detection coverage. Corroboration engine performs final cross-source validation. Hybrid Risk scoring engine computes risk scores with all collected data. Detection rule validation runs adversary tests against SIEM/EDR rules. ATT&CK coverage heatmap shows tested vs. untested techniques. Evidence capture and report generation produce deliverables.",
    requiresPriorPhase: true,
    canRunParallel: true,
    estimatedDurationMinutes: 15
  }
];
var TOOL_PHASE_MATRIX = {
  passive_osint: {
    phases: ["recon", "enumeration"],
    role: "Passive discovery via 17 OSINT connectors (Shodan, Censys, crt.sh, etc.)",
    inputsFrom: [],
    outputsTo: ["zap_passive", "nuclei_info", "nvd_kev", "scoring", "corroboration"]
  },
  zap_passive: {
    phases: ["recon"],
    role: "Passive web spider \u2014 discovers web app structure, links, forms without active testing",
    inputsFrom: ["passive_osint"],
    outputsTo: ["zap_active", "nuclei_info", "api_security"]
  },
  zap_active: {
    phases: ["enumeration", "vulnerability_assessment"],
    role: "Active DAST scanner \u2014 OWASP Top 10 testing, AJAX spider, authenticated scanning",
    inputsFrom: ["zap_passive", "passive_osint", "api_security"],
    outputsTo: ["corroboration", "scoring", "metasploit", "detection_rules"]
  },
  nuclei_info: {
    phases: ["recon", "enumeration"],
    role: "Info/low template scanning \u2014 tech stack fingerprinting, service enumeration",
    inputsFrom: ["passive_osint", "zap_passive"],
    outputsTo: ["nuclei_vuln", "zap_active", "scoring"]
  },
  nuclei_vuln: {
    phases: ["vulnerability_assessment"],
    role: "High/critical template scanning \u2014 CVE detection, misconfiguration discovery",
    inputsFrom: ["nuclei_info", "passive_osint"],
    outputsTo: ["corroboration", "scoring", "metasploit", "detection_rules"]
  },
  nuclei_critical: {
    phases: ["vulnerability_assessment"],
    role: "Critical-only templates \u2014 RCE, auth bypass, SSRF, critical misconfigs",
    inputsFrom: ["nuclei_info"],
    outputsTo: ["metasploit", "corroboration", "scoring"]
  },
  metasploit: {
    phases: ["exploitation", "post_exploitation"],
    role: "Exploit execution and post-exploitation modules",
    inputsFrom: ["nuclei_vuln", "zap_active", "nvd_kev", "passive_osint"],
    outputsTo: ["sliver_c2", "caldera", "corroboration", "scoring"]
  },
  sliver_c2: {
    phases: ["exploitation", "post_exploitation"],
    role: "C2 implant deployment and session management via mTLS/HTTPS/DNS",
    inputsFrom: ["metasploit", "caldera"],
    outputsTo: ["caldera", "corroboration", "scoring", "detection_rules"]
  },
  caldera: {
    phases: ["exploitation", "post_exploitation"],
    role: "Adversary emulation \u2014 multi-step operations with ATT&CK-mapped abilities",
    inputsFrom: ["metasploit", "sliver_c2", "passive_osint"],
    outputsTo: ["corroboration", "scoring", "detection_rules"]
  },
  atomic_red_team: {
    phases: ["recon", "exploitation", "post_exploitation", "reporting"],
    role: "ATT&CK-mapped atomic tests for technique validation and detection gap analysis",
    inputsFrom: ["caldera", "metasploit", "sliver_c2"],
    outputsTo: ["detection_rules", "corroboration", "scoring"]
  },
  gophish: {
    phases: ["exploitation"],
    role: "Social engineering campaigns \u2014 phishing, credential harvesting, awareness testing",
    inputsFrom: ["passive_osint"],
    outputsTo: ["metasploit", "sliver_c2", "corroboration"]
  },
  bloodhound: {
    phases: ["post_exploitation"],
    role: "AD attack path discovery \u2014 privilege escalation paths, Kerberoasting targets",
    inputsFrom: ["caldera", "metasploit"],
    outputsTo: ["caldera", "scoring", "corroboration"]
  },
  api_security: {
    phases: ["enumeration", "vulnerability_assessment"],
    role: "API security testing \u2014 OpenAPI/GraphQL/SOAP spec import and targeted testing",
    inputsFrom: ["zap_passive", "nuclei_info"],
    outputsTo: ["zap_active", "corroboration", "scoring"]
  },
  nvd_kev: {
    phases: ["vulnerability_assessment"],
    role: "CVE matching against NVD and CISA KEV catalog for known exploited vulnerabilities",
    inputsFrom: ["passive_osint", "nuclei_info"],
    outputsTo: ["metasploit", "corroboration", "scoring"]
  },
  corroboration: {
    phases: ["vulnerability_assessment", "reporting"],
    role: "Cross-source finding validation \u2014 reduces false positives by 30-40%",
    inputsFrom: ["zap_active", "nuclei_vuln", "nuclei_critical", "metasploit", "caldera", "sliver_c2", "atomic_red_team", "passive_osint"],
    outputsTo: ["scoring"]
  },
  scoring: {
    phases: ["reporting"],
    role: "Hybrid Risk/CVSS hybrid risk scoring with all collected intelligence",
    inputsFrom: ["corroboration", "zap_active", "nuclei_vuln", "metasploit", "caldera", "sliver_c2", "atomic_red_team", "passive_osint"],
    outputsTo: []
  },
  detection_rules: {
    phases: ["reporting"],
    role: "Detection rule validation \u2014 test SIEM/EDR rules against atomic test results",
    inputsFrom: ["atomic_red_team", "caldera", "sliver_c2", "zap_active", "nuclei_vuln"],
    outputsTo: []
  },
  amass: {
    phases: ["recon", "enumeration"],
    role: "Subdomain enumeration \u2014 passive OSINT, active DNS brute-force, zone transfers, cert transparency scraping. Discovers additional attack surface beyond initial scope.",
    inputsFrom: ["passive_osint"],
    outputsTo: ["scanforge-discovery", "service_fingerprinter", "zap_passive", "nuclei_info", "scoring"]
  },
  discovery: {
    phases: ["recon", "enumeration"],
    role: "Port scanning and service detection \u2014 SYN/TCP/UDP scanning, OS fingerprinting, version detection, Nuclei template execution. Identifies open ports and running services on discovered hosts.",
    inputsFrom: ["passive_osint", "amass"],
    outputsTo: ["service_fingerprinter", "nuclei_info", "nuclei_vuln", "metasploit", "nvd_kev", "scoring"]
  },
  service_fingerprinter: {
    phases: ["enumeration"],
    role: "Protocol-specific service fingerprinting \u2014 SSH, SMTP, FTP, SNMP, RDP, SMB, LDAP, Telnet, MySQL, PostgreSQL, MSSQL, Redis, MongoDB, VNC. Extracts banners, versions, security flags, default credential checks, and risk indicators.",
    inputsFrom: ["scanforge-discovery", "passive_osint", "amass"],
    outputsTo: ["nuclei_vuln", "metasploit", "nvd_kev", "corroboration", "scoring"]
  },
  ssh_audit: {
    phases: ["enumeration", "vulnerability_assessment"],
    role: "SSH security audit \u2014 weak algorithms, key exchange, auth methods, known CVEs (regreSSHion, Terrapin)",
    inputsFrom: ["scanforge-discovery", "service_fingerprinter"],
    outputsTo: ["corroboration", "scoring"]
  },
  ftp_audit: {
    phases: ["enumeration", "vulnerability_assessment"],
    role: "FTP security audit \u2014 anonymous login, bounce attacks, default creds, TLS support, version CVEs",
    inputsFrom: ["scanforge-discovery", "service_fingerprinter"],
    outputsTo: ["corroboration", "scoring"]
  },
  smtp_audit: {
    phases: ["enumeration", "vulnerability_assessment"],
    role: "SMTP security audit \u2014 open relay, VRFY/EXPN enum, STARTTLS, auth methods, version CVEs",
    inputsFrom: ["scanforge-discovery", "service_fingerprinter"],
    outputsTo: ["corroboration", "scoring"]
  },
  snmp_audit: {
    phases: ["enumeration", "vulnerability_assessment"],
    role: "SNMP security audit \u2014 community string brute, v1/v2c weak auth, info disclosure, MIB walk",
    inputsFrom: ["scanforge-discovery", "service_fingerprinter"],
    outputsTo: ["corroboration", "scoring"]
  },
  rdp_audit: {
    phases: ["enumeration", "vulnerability_assessment"],
    role: "RDP security audit \u2014 NLA check, CredSSP/BlueKeep CVEs, encryption level, NTLMv1 downgrade",
    inputsFrom: ["scanforge-discovery", "service_fingerprinter"],
    outputsTo: ["corroboration", "scoring"]
  },
  dns_audit: {
    phases: ["enumeration", "vulnerability_assessment"],
    role: "DNS security audit \u2014 zone transfer (AXFR), DNSSEC, recursion, version disclosure, cache poisoning, amplification",
    inputsFrom: ["scanforge-discovery", "amass"],
    outputsTo: ["corroboration", "scoring"]
  },
  http_header_audit: {
    phases: ["enumeration", "vulnerability_assessment"],
    role: "HTTP header security audit \u2014 HSTS, CSP, X-Frame-Options, CORS, cookie flags, TLS config, server disclosure",
    inputsFrom: ["scanforge-discovery", "service_fingerprinter"],
    outputsTo: ["corroboration", "scoring", "zap_active"]
  },
  tls_deep_scan: {
    phases: ["enumeration", "vulnerability_assessment"],
    role: "SSL/TLS deep scan \u2014 cipher suites, certificate chain, OCSP stapling, protocol downgrades (Heartbleed, POODLE, DROWN, ROBOT)",
    inputsFrom: ["scanforge-discovery", "service_fingerprinter"],
    outputsTo: ["corroboration", "scoring"]
  },
  nikto: {
    phases: ["vulnerability_assessment"],
    role: "Nikto web server scanner \u2014 misconfigurations, dangerous files, outdated software, CGI vulnerabilities",
    inputsFrom: ["scanforge-discovery", "zap_passive"],
    outputsTo: ["corroboration", "scoring"]
  },
  wapiti: {
    phases: ["vulnerability_assessment"],
    role: "Wapiti web app scanner \u2014 XSS, SQL injection, command injection, file disclosure, SSRF",
    inputsFrom: ["scanforge-discovery", "zap_passive"],
    outputsTo: ["corroboration", "scoring"]
  },
  arachni: {
    phases: ["vulnerability_assessment"],
    role: "Arachni web app scanner \u2014 comprehensive OWASP testing, DOM-based XSS, path traversal",
    inputsFrom: ["scanforge-discovery", "zap_passive"],
    outputsTo: ["corroboration", "scoring"]
  }
};
function correlateFindings(findings) {
  const byHost = /* @__PURE__ */ new Map();
  const byCve = /* @__PURE__ */ new Map();
  const byCwe = /* @__PURE__ */ new Map();
  const byTechnique = /* @__PURE__ */ new Map();
  const byPortService = /* @__PURE__ */ new Map();
  for (const f of findings) {
    const hostKey = f.host.toLowerCase();
    if (!byHost.has(hostKey)) byHost.set(hostKey, []);
    byHost.get(hostKey).push(f);
    if (f.cveId) {
      const cveKey = f.cveId.toUpperCase();
      if (!byCve.has(cveKey)) byCve.set(cveKey, []);
      byCve.get(cveKey).push(f);
    }
    if (f.cweId) {
      if (!byCwe.has(f.cweId)) byCwe.set(f.cweId, []);
      byCwe.get(f.cweId).push(f);
    }
    if (f.attackTechnique) {
      if (!byTechnique.has(f.attackTechnique)) byTechnique.set(f.attackTechnique, []);
      byTechnique.get(f.attackTechnique).push(f);
    }
    if (f.port) {
      const psKey = `${hostKey}:${f.port}`;
      if (!byPortService.has(psKey)) byPortService.set(psKey, []);
      byPortService.get(psKey).push(f);
    }
  }
  return findings.map((f) => {
    const crossRefs = /* @__PURE__ */ new Set();
    const corroboratingTools = /* @__PURE__ */ new Set();
    if (f.cveId) {
      const cveMatches = byCve.get(f.cveId.toUpperCase()) || [];
      for (const m of cveMatches) {
        if (m.id !== f.id && m.tool !== f.tool && m.host.toLowerCase() === f.host.toLowerCase()) {
          crossRefs.add(m.id);
          corroboratingTools.add(m.tool);
        }
      }
    }
    if (f.cweId) {
      const cweMatches = byCwe.get(f.cweId) || [];
      for (const m of cweMatches) {
        if (m.id !== f.id && m.tool !== f.tool && m.host.toLowerCase() === f.host.toLowerCase()) {
          crossRefs.add(m.id);
          corroboratingTools.add(m.tool);
        }
      }
    }
    if (f.attackTechnique) {
      const techMatches = byTechnique.get(f.attackTechnique) || [];
      for (const m of techMatches) {
        if (m.id !== f.id && m.tool !== f.tool) {
          crossRefs.add(m.id);
          corroboratingTools.add(m.tool);
        }
      }
    }
    if (f.port) {
      const psKey = `${f.host.toLowerCase()}:${f.port}`;
      const psMatches = byPortService.get(psKey) || [];
      for (const m of psMatches) {
        if (m.id !== f.id && m.tool !== f.tool) {
          crossRefs.add(m.id);
          corroboratingTools.add(m.tool);
        }
      }
    }
    return {
      ...f,
      crossRefs: Array.from(crossRefs),
      corroborated: corroboratingTools.size > 0,
      corroboratingTools: Array.from(corroboratingTools),
      confidence: corroboratingTools.size > 0 ? Math.min(100, f.confidence + corroboratingTools.size * 10) : f.confidence
    };
  });
}
function getPhaseTools(phase, target, priorFindings) {
  const stage = PIPELINE_STAGES.find((s) => s.phase === phase);
  if (!stage) return [];
  const tools = [];
  for (const tool of stage.tools) {
    const toolConfig = TOOL_PHASE_MATRIX[tool];
    if (!toolConfig.phases.includes(phase)) continue;
    let reason = toolConfig.role;
    let priority = 50;
    switch (tool) {
      case "zap_active": {
        const webAssets = priorFindings.filter((f) => f.type === "asset" && (f.evidence?.assetType === "url" || f.evidence?.assetType === "web_app"));
        if (webAssets.length > 0) {
          priority = 90;
          reason = `${webAssets.length} web applications discovered in recon \u2014 DAST scanning recommended`;
        }
        if (target.openApiSpecUrl || target.graphqlEndpoint) {
          priority = 95;
          reason = "API spec available \u2014 targeted API security testing recommended";
        }
        break;
      }
      case "nuclei_vuln":
      case "nuclei_critical": {
        const services = priorFindings.filter((f) => f.evidence?.ports || f.evidence?.service);
        if (services.length > 0) {
          priority = 85;
          reason = `${services.length} services enumerated \u2014 template-based vulnerability scanning recommended`;
        }
        break;
      }
      case "metasploit": {
        const vulns = priorFindings.filter((f) => f.type === "vulnerability" && (f.severity === "critical" || f.severity === "high"));
        if (vulns.length > 0) {
          priority = 95;
          reason = `${vulns.length} high/critical vulnerabilities found \u2014 exploit execution recommended`;
        }
        break;
      }
      case "sliver_c2": {
        const exploitResults = priorFindings.filter((f) => f.type === "exploit_result" && f.evidence?.sessionId);
        if (exploitResults.length > 0) {
          priority = 90;
          reason = `${exploitResults.length} successful exploits \u2014 C2 implant deployment recommended`;
        }
        break;
      }
      case "caldera": {
        const sessions = priorFindings.filter((f) => f.type === "c2_session" || f.type === "exploit_result");
        if (sessions.length > 0) {
          priority = 85;
          reason = `${sessions.length} active sessions \u2014 adversary emulation operations recommended`;
        }
        break;
      }
      case "atomic_red_team": {
        if (phase === "recon") {
          priority = 40;
          reason = "Recon-phase atomic tests (T1595, T1592) for attack surface validation";
        } else if (phase === "reporting") {
          priority = 80;
          reason = "Detection gap analysis \u2014 validate SIEM/EDR rules against atomic tests";
        } else {
          const techniques = new Set(priorFindings.map((f) => f.attackTechnique).filter(Boolean));
          priority = 70;
          reason = `${techniques.size} ATT&CK techniques observed \u2014 atomic validation tests recommended`;
        }
        break;
      }
      case "gophish": {
        const emails = priorFindings.filter((f) => f.evidence?.emails || f.evidence?.assetType === "email");
        if (emails.length > 0) {
          priority = 75;
          reason = `Employee emails discovered \u2014 social engineering campaign recommended`;
        }
        break;
      }
      case "corroboration": {
        const multiSourceFindings = priorFindings.filter((f) => f.corroborated);
        priority = 90;
        reason = `Cross-source validation of ${priorFindings.length} findings from ${new Set(priorFindings.map((f) => f.tool)).size} tools`;
        break;
      }
      case "scoring": {
        priority = 95;
        reason = "Hybrid Risk/CVSS hybrid risk scoring with all collected intelligence";
        break;
      }
      case "amass": {
        if (phase === "recon") {
          priority = 80;
          reason = "Subdomain enumeration via passive OSINT, cert transparency, and DNS brute-force";
        } else {
          const subdomains = priorFindings.filter((f) => f.evidence?.assetType === "subdomain" || f.evidence?.assetType === "domain");
          if (subdomains.length > 0) {
            priority = 85;
            reason = `${subdomains.length} domains discovered \u2014 active subdomain enumeration recommended for deeper coverage`;
          } else {
            priority = 70;
            reason = "Active subdomain enumeration to expand attack surface";
          }
        }
        break;
      }
      case "scanforge-discovery": {
        if (phase === "recon") {
          priority = 75;
          reason = "Quick port scan for initial service discovery on known hosts";
        } else {
          const hosts = priorFindings.filter((f) => f.type === "asset" && (f.evidence?.assetType === "ip" || f.evidence?.assetType === "subdomain"));
          if (hosts.length > 0) {
            priority = 90;
            reason = `${hosts.length} hosts discovered \u2014 port scanning and service detection recommended`;
          } else {
            priority = 70;
            reason = "Port scanning and service detection on target hosts";
          }
        }
        break;
      }
      case "service_fingerprinter": {
        const openPorts = priorFindings.filter((f) => f.evidence?.ports || f.port && f.type === "asset");
        if (openPorts.length > 0) {
          priority = 85;
          reason = `${openPorts.length} open ports discovered \u2014 protocol-specific fingerprinting recommended for SSH, SMTP, FTP, SNMP, RDP, SMB, databases`;
        } else {
          priority = 60;
          reason = "Protocol-specific service fingerprinting for admin port enumeration";
        }
        break;
      }
      default:
        break;
    }
    tools.push({ tool, reason, priority });
  }
  return tools.sort((a, b) => b.priority - a.priority);
}
function convertZapFindings(zapAlerts, phase) {
  return (zapAlerts || []).map((alert, i) => ({
    id: `zap-${phase}-${alert.alertRef || i}`,
    phase,
    tool: phase === "recon" ? "zap_passive" : "zap_active",
    type: "vulnerability",
    severity: mapZapRisk(alert.risk || alert.riskcode),
    title: alert.alert || alert.name || "Unknown Alert",
    description: alert.description || "",
    host: alert.url || alert.uri || "",
    port: extractPort(alert.url || alert.uri || ""),
    cveId: alert.cveId || void 0,
    cweId: alert.cweid ? `CWE-${alert.cweid}` : void 0,
    attackTechnique: mapCweToAttack(alert.cweid),
    confidence: mapZapConfidence(alert.confidence),
    evidence: {
      solution: alert.solution,
      reference: alert.reference,
      param: alert.param,
      attack: alert.attack,
      evidence: alert.evidence,
      pluginId: alert.pluginid || alert.pluginId,
      wascid: alert.wascid
    },
    timestamp: Date.now(),
    crossRefs: [],
    corroborated: false,
    corroboratingTools: []
  }));
}
function convertNucleiFindings(nucleiResults, phase) {
  const toolMap = {
    "info": "nuclei_info",
    "low": "nuclei_info",
    "medium": "nuclei_vuln",
    "high": "nuclei_vuln",
    "critical": "nuclei_critical"
  };
  return (nucleiResults || []).map((result, i) => ({
    id: `nuclei-${phase}-${result.templateId || i}`,
    phase,
    tool: toolMap[result.severity?.toLowerCase() || "info"] || "nuclei_info",
    type: result.severity === "critical" || result.severity === "high" ? "vulnerability" : "misconfiguration",
    severity: result.severity?.toLowerCase() || "info",
    title: result.name || result.templateId || "Unknown Template Match",
    description: result.description || "",
    host: result.host || result.matched || "",
    port: result.port || extractPort(result.matched || ""),
    cveId: result.cveId || extractCve(result.tags),
    cweId: result.cweId || void 0,
    attackTechnique: result.attackTechnique || mapCweToAttack(result.cweId),
    confidence: result.severity === "critical" ? 90 : result.severity === "high" ? 80 : 60,
    evidence: {
      templateId: result.templateId,
      tags: result.tags,
      matcher: result.matcher,
      extractedResults: result.extractedResults,
      curl: result.curl,
      severity: result.severity
    },
    timestamp: Date.now(),
    crossRefs: [],
    corroborated: false,
    corroboratingTools: []
  }));
}
function convertSliverFindings(sessions, phase) {
  return (sessions || []).map((session, i) => ({
    id: `sliver-${phase}-${session.id || i}`,
    phase,
    tool: "sliver_c2",
    type: "c2_session",
    severity: "critical",
    title: `C2 Session Established: ${session.hostname || session.remoteAddress || "Unknown"}`,
    description: `Active implant session via ${session.transport || "unknown"} protocol. OS: ${session.os || "unknown"}, Arch: ${session.arch || "unknown"}`,
    host: session.remoteAddress || session.hostname || "",
    port: session.port,
    attackTechnique: session.transport === "dns" ? "T1071.004" : session.transport === "http" || session.transport === "https" ? "T1071.001" : "T1071",
    confidence: 100,
    evidence: {
      sessionId: session.id,
      transport: session.transport,
      os: session.os,
      arch: session.arch,
      hostname: session.hostname,
      username: session.username,
      pid: session.pid,
      implantName: session.name
    },
    timestamp: session.lastCheckin || Date.now(),
    crossRefs: [],
    corroborated: false,
    corroboratingTools: []
  }));
}
function convertAtomicFindings(executions, phase) {
  return (executions || []).map((exec, i) => ({
    id: `atomic-${phase}-${exec.id || i}`,
    phase,
    tool: "atomic_red_team",
    type: exec.detected === false ? "detection_gap" : "vulnerability",
    severity: exec.detected === false ? "high" : "info",
    title: exec.detected === false ? `Detection Gap: ${exec.techniqueName || exec.techniqueId} not detected` : `Validated: ${exec.techniqueName || exec.techniqueId} detected by defenses`,
    description: exec.testName || "",
    host: exec.targetHost || "local",
    attackTechnique: exec.techniqueId,
    confidence: 95,
    evidence: {
      techniqueId: exec.techniqueId,
      techniqueName: exec.techniqueName,
      testName: exec.testName,
      testGuid: exec.testGuid,
      executor: exec.executor,
      exitCode: exec.exitCode,
      detected: exec.detected,
      detectionSource: exec.detectionSource,
      output: exec.output?.substring(0, 500)
    },
    timestamp: exec.executedAt || Date.now(),
    crossRefs: [],
    corroborated: false,
    corroboratingTools: []
  }));
}
function convertMetasploitFindings(jobs, phase) {
  return (jobs || []).map((job, i) => ({
    id: `msf-${phase}-${job.id || i}`,
    phase,
    tool: "metasploit",
    type: "exploit_result",
    severity: job.status === "success" ? "critical" : "info",
    title: `Exploit ${job.status === "success" ? "Successful" : "Attempted"}: ${job.moduleName || job.module || "Unknown"}`,
    description: `${job.moduleName || job.module} against ${job.targetHost}:${job.targetPort}`,
    host: job.targetHost || "",
    port: job.targetPort,
    cveId: job.cveId,
    attackTechnique: "T1190",
    confidence: job.status === "success" ? 100 : 30,
    evidence: {
      module: job.module,
      moduleName: job.moduleName,
      sessionId: job.sessionId,
      sessionType: job.sessionType,
      payload: job.payload,
      status: job.status,
      lhost: job.lhost,
      lport: job.lport
    },
    timestamp: job.completedAt || job.startedAt || Date.now(),
    crossRefs: [],
    corroborated: false,
    corroboratingTools: []
  }));
}
function convertOsintFindings(observations, phase) {
  return (observations || []).map((obs, i) => ({
    id: `osint-${phase}-${obs.assetId || i}`,
    phase,
    tool: "passive_osint",
    type: "asset",
    severity: "info",
    title: `Discovered: ${obs.name || obs.assetId || "Unknown Asset"}`,
    description: `${obs.assetType} discovered via ${obs.source}`,
    host: obs.ip || obs.name || obs.domain || "",
    port: obs.evidence?.port,
    attackTechnique: obs.assetType === "subdomain" ? "T1590.002" : obs.assetType === "ip" ? "T1590.004" : void 0,
    confidence: 70,
    evidence: {
      assetType: obs.assetType,
      source: obs.source,
      tags: obs.tags,
      ...obs.evidence
    },
    timestamp: obs.observedAt?.getTime?.() || Date.now(),
    crossRefs: [],
    corroborated: false,
    corroboratingTools: []
  }));
}
function generatePipelineSummary(target, phaseResults) {
  const allFindings = phaseResults.flatMap((p) => p.findings);
  const correlated = correlateFindings(allFindings);
  const findingsBySeverity = {};
  const findingsByPhase = {};
  const findingsByTool = {};
  const techniquesUsed = /* @__PURE__ */ new Set();
  const tacticsUsed = /* @__PURE__ */ new Set();
  for (const f of correlated) {
    findingsBySeverity[f.severity] = (findingsBySeverity[f.severity] || 0) + 1;
    findingsByPhase[f.phase] = (findingsByPhase[f.phase] || 0) + 1;
    findingsByTool[f.tool] = (findingsByTool[f.tool] || 0) + 1;
    if (f.attackTechnique) techniquesUsed.add(f.attackTechnique);
  }
  return {
    target,
    phases: phaseResults,
    totalFindings: correlated.length,
    findingsBySeverity,
    findingsByPhase,
    findingsByTool,
    attackCoverage: {
      techniquesUsed: Array.from(techniquesUsed),
      tacticsUsed: Array.from(tacticsUsed),
      coveragePercent: Math.round(techniquesUsed.size / 200 * 100)
      // ~200 enterprise techniques
    },
    engagementId: target.engagementId
  };
}
function mapZapRisk(risk) {
  const r = typeof risk === "number" ? risk : parseInt(risk, 10);
  if (r >= 3) return "high";
  if (r === 2) return "medium";
  if (r === 1) return "low";
  return "info";
}
function mapZapConfidence(confidence) {
  const c = typeof confidence === "number" ? confidence : parseInt(confidence, 10);
  if (c >= 3) return 90;
  if (c === 2) return 70;
  if (c === 1) return 40;
  return 20;
}
function extractPort(url) {
  try {
    const u = new URL(url);
    if (u.port) return parseInt(u.port, 10);
    return u.protocol === "https:" ? 443 : 80;
  } catch {
    return void 0;
  }
}
function extractCve(tags) {
  if (!tags) return void 0;
  const tagStr = Array.isArray(tags) ? tags.join(",") : tags;
  const match = tagStr.match(/CVE-\d{4}-\d+/i);
  return match ? match[0].toUpperCase() : void 0;
}
function mapCweToAttack(cweId) {
  if (!cweId) return void 0;
  const id = typeof cweId === "string" ? parseInt(cweId.replace(/\D/g, ""), 10) : cweId;
  const CWE_TO_ATTACK = {
    79: "T1059.007",
    // XSS → JavaScript execution
    89: "T1190",
    // SQL Injection → Exploit Public-Facing App
    94: "T1059",
    // Code Injection → Command/Script Execution
    78: "T1059",
    // OS Command Injection
    22: "T1083",
    // Path Traversal → File Discovery
    352: "T1185",
    // CSRF → Browser Session Hijacking
    918: "T1190",
    // SSRF → Exploit Public-Facing App
    287: "T1078",
    // Auth Bypass → Valid Accounts
    306: "T1078",
    // Missing Auth → Valid Accounts
    502: "T1059",
    // Deserialization → Execution
    611: "T1190",
    // XXE → Exploit Public-Facing App
    434: "T1105",
    // File Upload → Ingress Tool Transfer
    200: "T1005",
    // Info Exposure → Data from Local System
    311: "T1557",
    // Missing Encryption → MITM
    319: "T1557",
    // Cleartext Transmission → MITM
    798: "T1552.001",
    // Hardcoded Credentials → Unsecured Credentials
    532: "T1005",
    // Log Info Exposure → Data Collection
    601: "T1566.002",
    // Open Redirect → Phishing Link
    1021: "T1185",
    // Clickjacking → Browser Session Hijacking
    16: "T1562.001",
    // Configuration → Disable Security Tools
    693: "T1562"
    // Protection Mechanism Failure → Impair Defenses
  };
  return CWE_TO_ATTACK[id];
}
var ACTIVE_DISCOVERY_SOURCES = {
  zap: {
    coversPriorities: [3, 4, 9],
    // Port Enum, Web/API Stack, Defensive Posture
    coverageTags: ["web_app", "api", "technology", "framework", "waf", "security_header", "port", "service"],
    description: "DAST scanner adds web application structure, API endpoints, and security header analysis"
  },
  nuclei: {
    coversPriorities: [3, 4, 8, 9, 10],
    // Port Enum, Web/API, Cloud Misconfig, Defensive Posture, Code Leaks
    coverageTags: ["technology", "service", "cloud", "misconfiguration", "config_leak", "security_header"],
    description: "Template scanner adds service fingerprinting, cloud misconfiguration detection, and config leak discovery"
  },
  sliver: {
    coversPriorities: [],
    // C2 doesn't contribute to discovery
    coverageTags: [],
    description: "C2 framework \u2014 contributes to exploitation and post-exploitation phases only"
  },
  atomic: {
    coversPriorities: [9],
    // Defensive Posture (detection gap analysis)
    coverageTags: ["edr", "siem", "detection_gap"],
    description: "Adversary validation tests reveal detection gaps in defensive tooling"
  },
  amass: {
    coversPriorities: [1, 2, 5],
    // Subdomain Enum, DNS Records, Network Topology
    coverageTags: ["subdomain", "dns", "ip", "asn", "certificate", "network_topology"],
    description: "Subdomain enumeration via passive OSINT, cert transparency, DNS brute-force, and zone transfers"
  },
  discovery: {
    coversPriorities: [3, 4, 6],
    // Port Enum, Service/Version, OS Fingerprinting
    coverageTags: ["port", "service", "version", "os", "banner", "nse_script", "vulnerability"],
    description: "Port scanning, service detection, OS fingerprinting, and Nuclei template execution"
  },
  service_fingerprinter: {
    coversPriorities: [3, 4, 7],
    // Port Enum, Service/Version, Admin Services
    coverageTags: ["protocol", "banner", "version", "security_flag", "default_cred", "admin_service", "risk_indicator"],
    description: "Protocol-specific fingerprinting for SSH, SMTP, FTP, SNMP, RDP, SMB, LDAP, databases with security flag analysis"
  }
};
var EXTENDED_SOURCE_WEIGHTS = {
  zap_passive: 0.65,
  zap_active: 0.85,
  nuclei_info: 0.6,
  nuclei_vuln: 0.8,
  nuclei_critical: 0.9,
  sliver_c2: 0.95,
  atomic_red_team: 0.9,
  metasploit: 0.95,
  caldera: 0.9,
  gophish: 0.7,
  bloodhound: 0.85,
  amass: 0.75,
  discovery: 0.85,
  service_fingerprinter: 0.8
};
function generateTimelineEvents(findings) {
  const phaseToKillChain = {
    recon: "reconnaissance",
    enumeration: "reconnaissance",
    vulnerability_assessment: "weaponization",
    exploitation: "exploitation",
    post_exploitation: "command_control",
    reporting: "actions_on_objectives"
  };
  const toolIcons = {
    zap_passive: "Globe",
    zap_active: "Shield",
    nuclei_info: "Search",
    nuclei_vuln: "AlertTriangle",
    nuclei_critical: "AlertOctagon",
    metasploit: "Crosshair",
    sliver_c2: "Radio",
    caldera: "Flame",
    atomic_red_team: "Atom",
    gophish: "Mail",
    passive_osint: "Eye",
    bloodhound: "GitBranch",
    corroboration: "CheckCircle",
    scoring: "BarChart",
    detection_rules: "FileSearch",
    api_security: "Lock",
    nvd_kev: "Database",
    amass: "Network",
    discovery: "Scan",
    service_fingerprinter: "Fingerprint"
  };
  const severityColors = {
    critical: "text-red-500",
    high: "text-orange-500",
    medium: "text-yellow-500",
    low: "text-blue-500",
    info: "text-slate-400"
  };
  return findings.map((f) => ({
    timestamp: f.timestamp,
    phase: phaseToKillChain[f.phase] || f.phase,
    source: f.tool,
    severity: f.severity,
    title: f.title,
    description: f.description,
    icon: toolIcons[f.tool] || "Activity",
    color: severityColors[f.severity] || "text-slate-400",
    status: f.type === "exploit_result" ? f.confidence >= 80 ? "success" : "failed" : "info",
    details: {
      ...f.evidence,
      crossRefs: f.crossRefs,
      corroborated: f.corroborated,
      corroboratingTools: f.corroboratingTools
    }
  }));
}
function convertScanForgeFindings(hosts, phase) {
  const findings = [];
  for (const host of hosts) {
    for (const port of host.ports) {
      const cveMatches = port.scripts.flatMap((s) => s.output.match(/CVE-\d{4}-\d{4,}/gi) || []).map((c) => c.toUpperCase());
      const hasCve = cveMatches.length > 0;
      findings.push({
        id: `discovery-${phase}-${host.host}-${port.port}-${port.protocol}`,
        phase,
        tool: "scanforge-discovery",
        type: hasCve ? "vulnerability" : "asset",
        severity: hasCve ? "medium" : "info",
        title: hasCve ? `ScanForge CVE detected on ${host.host}:${port.port} (${port.service || port.protocol})` : `Open port ${port.port}/${port.protocol} on ${host.host} \u2014 ${port.service || "unknown"}`,
        description: port.version ? `Service: ${port.service || "unknown"}, Version: ${port.version}${host.os ? `, OS: ${host.os}` : ""}` : `Service: ${port.service || "unknown"}${host.os ? `, OS: ${host.os}` : ""}`,
        host: host.host,
        port: port.port,
        cveId: cveMatches[0] || void 0,
        attackTechnique: "T1046",
        // Network Service Discovery
        confidence: Math.round(port.serviceConfidence * 100),
        evidence: {
          protocol: port.protocol,
          service: port.service,
          version: port.version,
          banner: port.banner,
          os: host.os,
          scripts: port.scripts,
          cves: cveMatches,
          scanRunId: host.scanRunId,
          policyProfile: host.policyProfile,
          assetType: "port",
          ports: [port.port]
        },
        timestamp: Date.now(),
        crossRefs: [],
        corroborated: false,
        corroboratingTools: []
      });
    }
  }
  return findings;
}
function convertAmassFindings(subdomains, phase) {
  return subdomains.map((sub, i) => ({
    id: `amass-${phase}-${sub.name}-${i}`,
    phase,
    tool: "amass",
    type: "asset",
    severity: "info",
    title: `Subdomain discovered: ${sub.name}`,
    description: `${sub.name} (${sub.ips.length} IPs, ${sub.sources.length} sources, tag: ${sub.tag}, mode: ${sub.mode})`,
    host: sub.ips[0] || sub.name,
    attackTechnique: "T1590.002",
    // Gather Victim Network Information: DNS
    confidence: sub.tag === "cert" ? 90 : sub.tag === "dns" ? 85 : 70,
    evidence: {
      assetType: "subdomain",
      subdomain: sub.name,
      domain: sub.domain,
      ips: sub.ips,
      asns: sub.asns,
      sources: sub.sources,
      tag: sub.tag,
      mode: sub.mode
    },
    timestamp: sub.discoveredAt || Date.now(),
    crossRefs: [],
    corroborated: false,
    corroboratingTools: []
  }));
}
function convertFingerprintFindings(results, phase) {
  return results.filter((r) => !r.error).map((r, i) => {
    const hasRisks = r.riskIndicators.length > 0;
    const hasCves = r.potentialCves.length > 0;
    const severity = hasCves ? "medium" : hasRisks ? r.riskIndicators.some((ri) => ri.severity === "critical" || ri.severity === "high") ? "medium" : "low" : "info";
    return {
      id: `fingerprint-${phase}-${r.host}-${r.port}-${r.protocol}-${i}`,
      phase,
      tool: "service_fingerprinter",
      type: hasCves || hasRisks ? "misconfiguration" : "asset",
      severity,
      title: hasRisks ? `${r.protocol.toUpperCase()} risk on ${r.host}:${r.port} \u2014 ${r.riskIndicators[0]?.description || "security issue"}` : `${r.protocol.toUpperCase()} service fingerprinted on ${r.host}:${r.port}`,
      description: [
        r.product && `Product: ${r.product}`,
        r.version && `Version: ${r.version}`,
        r.banner && `Banner: ${r.banner.substring(0, 200)}`,
        r.os && `OS: ${r.os}`,
        r.riskIndicators.length > 0 && `Risks: ${r.riskIndicators.map((ri) => ri.description).join("; ")}`
      ].filter(Boolean).join(", "),
      host: r.host,
      port: r.port,
      cveId: r.potentialCves[0] || void 0,
      attackTechnique: r.mitreRelevance[0] || "T1046",
      confidence: r.version ? 80 : r.banner ? 65 : 50,
      evidence: {
        protocol: r.protocol,
        banner: r.banner,
        version: r.version,
        product: r.product,
        os: r.os,
        securityFlags: r.securityFlags,
        riskIndicators: r.riskIndicators,
        mitreRelevance: r.mitreRelevance,
        potentialCves: r.potentialCves,
        assetType: "service",
        ports: [r.port]
      },
      timestamp: Date.now(),
      crossRefs: [],
      corroborated: false,
      corroboratingTools: []
    };
  });
}

export {
  PIPELINE_STAGES,
  TOOL_PHASE_MATRIX,
  correlateFindings,
  getPhaseTools,
  convertZapFindings,
  convertNucleiFindings,
  convertSliverFindings,
  convertAtomicFindings,
  convertMetasploitFindings,
  convertOsintFindings,
  generatePipelineSummary,
  ACTIVE_DISCOVERY_SOURCES,
  EXTENDED_SOURCE_WEIGHTS,
  generateTimelineEvents,
  convertScanForgeFindings,
  convertAmassFindings,
  convertFingerprintFindings
};
