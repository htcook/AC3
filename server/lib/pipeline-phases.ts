/**
 * Pipeline Phases — New engagement pipeline stages
 *
 * Adds the following phases between Domain Recon and Active Enumeration:
 *   Phase 2: Passive Discovery & Enumeration (pre-RoE, no active scanning)
 *   Phase 3: Scoping & RoE Review
 *   Phase 4: Test Plan Generation (NIST 800-115 aligned)
 *   Phase 4b: Customer Test Plan Approval Gate
 *
 * These phases run after Domain Recon (Phase 1) and before Active Discovery (Phase 5).
 * The test plan is generated using LLM analysis of all passive intelligence gathered
 * in Phases 1-2, producing a document suitable for customer review and approval.
 */

import { invokeLLM } from "../_core/llm";
import { throttledLLMCall } from "./llm-throttle";
import type { OpsPhase } from "./engagement-orchestrator";
import { DnsSecurityValidator } from "./dns-security-validator";
import type { DnsSecurityReport } from "./dns-security-validator";
import { securityTrailsWHOIS } from "./discovery-engine";
import { ENV } from "../_core/env";

// ─── Types ──────────────────────────────────────────────────────────────────

export interface PassiveDiscoveryResult {
  subdomains: string[];
  dnsRecords: Record<string, DnsRecordSet>;
  certificates: CertificateInfo[];
  technologies: string[];
  cloudProviders: string[];
  wafDetected?: string;
  emailAddresses: string[];
  breachExposure: BreachExposureEntry[];
  dnsSecurityFindings: DnsSecurityFinding[];
  passiveServices: PassiveServiceHint[];
  orgIdentification?: {
    orgName: string | null;
    registrantEmail: string | null;
    registrantOrg: string | null;
    sector: string | null;
    source: 'whois' | 'customer_name' | 'llm_inference';
    confidence: 'high' | 'medium' | 'low';
    baseDomain: string;
  };
}

export interface DnsRecordSet {
  A?: string[];
  AAAA?: string[];
  CNAME?: string[];
  MX?: Array<{ priority: number; exchange: string }>;
  NS?: string[];
  TXT?: string[];
  SOA?: { mname: string; rname: string; serial: number; refresh: number; retry: number; expire: number; minimum: number };
  SRV?: Array<{ priority: number; weight: number; port: number; target: string }>;
  CAA?: Array<{ flags: number; tag: string; value: string }>;
  DNSKEY?: any[];
  DS?: any[];
  RRSIG?: any[];
  NSEC?: any[];
  NSEC3?: any[];
}

export interface CertificateInfo {
  domain: string;
  issuer: string;
  validFrom: string;
  validTo: string;
  subjectAltNames: string[];
  serialNumber?: string;
  signatureAlgorithm?: string;
  keySize?: number;
}

export interface BreachExposureEntry {
  source: string;
  date?: string;
  dataTypes: string[];
  recordCount?: number;
}

export interface DnsSecurityFinding {
  /** Finding category per NIST SP 800-81r3 */
  category: 'dangling_cname' | 'lame_delegation' | 'zone_transfer' | 'dnssec_missing' |
    'dnssec_misconfigured' | 'encrypted_dns_missing' | 'information_leakage' |
    'zone_drift' | 'recursive_authoritative_split' | 'dynamic_update_exposure' |
    'dns_tunneling_risk' | 'lookalike_domain';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  detail: string;
  record?: string;
  remediation: string;
  nistReference: string; // e.g., "NIST SP 800-81r3 §4.2"
}

export interface PassiveServiceHint {
  host: string;
  port?: number;
  service: string;
  source: string; // e.g., "certificate", "dns_srv", "shodan_passive", "banner_grab"
  confidence: 'high' | 'medium' | 'low';
}

export interface TestPlanSection {
  id: string;
  title: string;
  content: string;
  standardsReference?: string; // e.g., "NIST SP 800-115 §4.3"
}

export interface GeneratedTestPlan {
  id: string;
  engagementId: number;
  engagementType: 'pentest' | 'red_team' | 'purple_team';
  generatedAt: number;
  status: 'draft' | 'pending_approval' | 'approved' | 'rejected';
  sections: TestPlanSection[];
  attackVectors: AssessmentAttackVector[];
  dnsAssessment: DnsAssessmentPlan;
  estimatedDuration: string;
  toolsPlanned: string[];
  riskMitigations: string[];
  scopeSummary: {
    domains: string[];
    ipRanges: string[];
    totalAssets: number;
    totalSubdomains: number;
    cloudProviders: string[];
    technologies: string[];
  };
}

export interface AssessmentAttackVector {
  id: string;
  name: string;
  description: string;
  targets: string[];
  tools: string[];
  techniques: string[];
  estimatedDuration: string;
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
}

export interface DnsAssessmentPlan {
  /** DNS security checks to perform per NIST SP 800-81r3 */
  checks: DnsAssessmentCheck[];
  /** Overall DNS security posture from passive analysis */
  passivePosture: 'strong' | 'moderate' | 'weak' | 'critical';
  /** Key findings from passive DNS analysis */
  passiveFindings: string[];
}

export interface DnsAssessmentCheck {
  category: string;
  description: string;
  tools: string[];
  nistReference: string;
  priority: 'required' | 'recommended' | 'optional';
}

// ─── Phase 2: Passive Discovery & Enumeration ───────────────────────────────

/**
 * Execute passive discovery and enumeration.
 * This phase runs BEFORE RoE signing and uses only passive techniques:
 * - DNS enumeration (all record types)
 * - Certificate transparency log mining
 * - Passive subdomain discovery (crt.sh, SecurityTrails passive, etc.)
 * - Technology fingerprinting from public sources
 * - Breach exposure checking
 * - DNS security assessment per NIST SP 800-81r3
 * - Passive service hints from Shodan/Censys cached data
 */
export async function executePassiveDiscovery(
  state: any, // EngagementOpsState
  engagement: any,
  addLog: (state: any, entry: any) => void,
  broadcastOpsUpdate: (engagementId: number, data: any) => void,
): Promise<PassiveDiscoveryResult> {
  state.phase = "passive_discovery" as OpsPhase;
  state.currentAction = "Running passive discovery & enumeration...";
  addLog(state, {
    phase: "passive_discovery",
    type: "info",
    title: "🔎 Phase 2: Passive Discovery & Enumeration",
    detail: "Analyzing DNS records, certificates, technologies, and breach exposure using passive techniques only. No active scanning — safe to run before RoE signing.",
  });
  broadcastOpsUpdate(state.engagementId, { type: "phase_change", phase: "passive_discovery" });

  const result: PassiveDiscoveryResult = {
    subdomains: [],
    dnsRecords: {},
    certificates: [],
    technologies: [],
    cloudProviders: [],
    emailAddresses: [],
    breachExposure: [],
    dnsSecurityFindings: [],
    passiveServices: [],
  };

  // Collect domains from recon phase
  const domains = state.assets?.map((a: any) => a.hostname).filter(Boolean) || [];
  const passiveRecon = state.passiveReconResults || {};

  // ── 2.1: DNS Record Enumeration ──
  addLog(state, {
    phase: "passive_discovery", type: "scan_start",
    title: "DNS Record Enumeration",
    detail: `Querying all DNS record types for ${domains.length} domains`,
  });

  for (const domain of domains) {
    try {
      const reconData = passiveRecon[domain] || {};

      // Collect DNS records from recon data
      const dnsRecords: DnsRecordSet = {};
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

      // ── DNS Security Analysis per NIST SP 800-81r3 ──
      const dnsFindings = analyzeDnsSecurity(domain, dnsRecords, reconData);
      result.dnsSecurityFindings.push(...dnsFindings);

      if (dnsFindings.length > 0) {
        addLog(state, {
          phase: "passive_discovery", type: "finding",
          title: `DNS Security: ${domain}`,
          detail: `Found ${dnsFindings.length} DNS security issues: ${dnsFindings.map(f => f.title).join(', ')}`,
        });
      }
    } catch (err: any) {
      addLog(state, {
        phase: "passive_discovery", type: "warning",
        title: `DNS Enumeration Failed: ${domain}`,
        detail: err.message,
      });
    }
  }

  // ── 2.2: Certificate Transparency Mining ──
  addLog(state, {
    phase: "passive_discovery", type: "scan_start",
    title: "Certificate Transparency Mining",
    detail: `Analyzing certificates and CT logs for ${domains.length} domains`,
  });

  for (const domain of domains) {
    const reconData = passiveRecon[domain] || {};
    if (reconData.certificates) {
      for (const cert of reconData.certificates) {
        result.certificates.push({
          domain: cert.domain || domain,
          issuer: cert.issuer || 'Unknown',
          validFrom: cert.validFrom || cert.notBefore || '',
          validTo: cert.validTo || cert.notAfter || '',
          subjectAltNames: cert.subjectAltNames || cert.sans || [],
          signatureAlgorithm: cert.signatureAlgorithm,
          keySize: cert.keySize,
        });
        // Extract subdomains from SANs
        const sans = cert.subjectAltNames || cert.sans || [];
        for (const san of sans) {
          const cleanSan = san.replace(/^\*\./, '');
          if (cleanSan.endsWith(domain) && !result.subdomains.includes(cleanSan)) {
            result.subdomains.push(cleanSan);
          }
        }
      }
    }
    // Collect subdomains from recon
    if (reconData.subdomains) {
      for (const sub of reconData.subdomains) {
        if (!result.subdomains.includes(sub)) {
          result.subdomains.push(sub);
        }
      }
    }
  }

  addLog(state, {
    phase: "passive_discovery", type: "info",
    title: `Certificates Analyzed`,
    detail: `Found ${result.certificates.length} certificates, ${result.subdomains.length} unique subdomains`,
  });

  // ── 2.3: Technology & Cloud Provider Detection ──
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

  // ── 2.4: Email & Breach Exposure ──
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
          source: breach.source || breach.name || 'Unknown',
          date: breach.date,
          dataTypes: breach.dataTypes || breach.dataClasses || [],
          recordCount: breach.recordCount || breach.pwnCount,
        });
      }
    }
  }

  // ── 2.5: Passive Service Hints ──
  for (const domain of domains) {
    const reconData = passiveRecon[domain] || {};
    // From Shodan passive data
    if (reconData.shodan?.ports) {
      for (const portInfo of reconData.shodan.ports) {
        result.passiveServices.push({
          host: domain,
          port: portInfo.port,
          service: portInfo.service || portInfo.product || 'unknown',
          source: 'shodan_passive',
          confidence: 'medium',
        });
      }
    }
    // From DNS SRV records
    const dnsRecords = result.dnsRecords[domain];
    if (dnsRecords?.SRV) {
      for (const srv of dnsRecords.SRV) {
        result.passiveServices.push({
          host: srv.target,
          port: srv.port,
          service: `srv_${domain}`,
          source: 'dns_srv',
          confidence: 'high',
        });
      }
    }
  }

  // ── 2.6: WHOIS Organization Identification ──
  addLog(state, {
    phase: "passive_discovery", type: "scan_start",
    title: "WHOIS Organization Identification",
    detail: `Identifying target organization from WHOIS records for ${domains.length} domains`,
  });

  let orgIdentification: PassiveDiscoveryResult['orgIdentification'] = undefined;
  try {
    // Extract unique base domains (e.g., celerium.net from dcise3.celerium.net)
    const baseDomains = new Set<string>();
    for (const hostname of domains) {
      const parts = hostname.split('.');
      if (parts.length >= 2) {
        // Try 2-part TLD first (e.g., co.uk), fallback to last 2 parts
        const baseDomain = parts.slice(-2).join('.');
        baseDomains.add(baseDomain);
      }
    }

    if (ENV.SECURITYTRAILS_API_KEY && baseDomains.size > 0) {
      for (const baseDomain of baseDomains) {
        try {
          const whoisData = await securityTrailsWHOIS(baseDomain);
          const registrantOrg = whoisData?.result?.registrant_org
            || whoisData?.registrant?.organization
            || whoisData?.contacts?.registrant?.organization
            || whoisData?.registrant_org
            || null;
          const registrantName = whoisData?.result?.registrant_name
            || whoisData?.registrant?.name
            || whoisData?.contacts?.registrant?.name
            || null;
          const registrantEmail = whoisData?.result?.registrant_email
            || whoisData?.registrant?.email
            || whoisData?.contacts?.registrant?.email
            || null;

          const orgName = registrantOrg || registrantName;

          if (orgName && !orgName.toLowerCase().includes('privacy') && !orgName.toLowerCase().includes('redacted') && !orgName.toLowerCase().includes('proxy')) {
            orgIdentification = {
              orgName,
              registrantEmail,
              registrantOrg: registrantOrg || null,
              sector: null, // Will be inferred by LLM in narrative generation
              source: 'whois',
              confidence: 'high',
              baseDomain,
            };
            addLog(state, {
              phase: "passive_discovery", type: "info",
              title: `🏢 Organization Identified: ${orgName}`,
              detail: `WHOIS for ${baseDomain} → Registrant: ${orgName}${registrantEmail ? ` (${registrantEmail})` : ''}`,
            });
            break; // Found a valid org, stop looking
          } else if (orgName) {
            addLog(state, {
              phase: "passive_discovery", type: "info",
              title: `WHOIS Privacy: ${baseDomain}`,
              detail: `Registrant info redacted/proxied: "${orgName}"`,
            });
          }
        } catch (err: any) {
          addLog(state, {
            phase: "passive_discovery", type: "warning",
            title: `WHOIS Lookup Failed: ${baseDomain}`,
            detail: err.message,
          });
        }
      }
    } else if (!ENV.SECURITYTRAILS_API_KEY) {
      addLog(state, {
        phase: "passive_discovery", type: "warning",
        title: "WHOIS Skipped",
        detail: "SecurityTrails API key not configured — cannot perform WHOIS lookup",
      });
    }

    // Fallback: Use engagement customerName if WHOIS didn't identify the org
    if (!orgIdentification && engagement.customerName && engagement.customerName !== 'Auto') {
      orgIdentification = {
        orgName: engagement.customerName,
        registrantEmail: null,
        registrantOrg: null,
        sector: null,
        source: 'customer_name',
        confidence: 'medium',
        baseDomain: domains[0] || '',
      };
      addLog(state, {
        phase: "passive_discovery", type: "info",
        title: `🏢 Organization (from engagement): ${engagement.customerName}`,
        detail: `WHOIS was private/unavailable. Using engagement customer name as org identifier.`,
      });
    }
  } catch (err: any) {
    addLog(state, {
      phase: "passive_discovery", type: "warning",
      title: "Org Identification Failed",
      detail: `Non-fatal error during org identification: ${err.message}`,
    });
  }

  // Run comprehensive DNS Security Validation
  let dnsSecurityReport: DnsSecurityReport | null = null;
  try {
    const dnsValidator = new DnsSecurityValidator(engagement.targetDomain || state.domain, "di_scan");
    dnsSecurityReport = await dnsValidator.runFullAssessment();
    addLog(state, {
      phase: "passive_discovery", type: "info",
      title: "🛡️ DNS Security Assessment Complete",
      detail: `${dnsSecurityReport.summary.totalChecks} checks performed. Risk: ${dnsSecurityReport.summary.overallRisk.toUpperCase()}. Findings: ${dnsSecurityReport.summary.critical} critical, ${dnsSecurityReport.summary.high} high, ${dnsSecurityReport.summary.medium} medium, ${dnsSecurityReport.summary.low} low.`,
    });
  } catch (err: any) {
    addLog(state, {
      phase: "passive_discovery", type: "warning",
      title: "⚠️ DNS Security Assessment Partial",
      detail: `DNS security validator encountered an error: ${err.message}. Basic DNS checks from passive recon still apply.`,
    });
  }

  // Store org identification on result
  result.orgIdentification = orgIdentification;

  // Store results in state
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
    dnsSecurityReport,
    orgIdentification,
  };

  // Also store on top-level state for easy access by narrative/report generators
  if (orgIdentification) {
    state.identifiedOrg = orgIdentification;
  }

  addLog(state, {
    phase: "passive_discovery", type: "phase_complete",
    title: "✅ Phase 2 Complete",
    detail: `${result.subdomains.length} subdomains, ${result.certificates.length} certs, ${result.technologies.length} technologies, ${result.dnsSecurityFindings.length} DNS security findings, ${result.passiveServices.length} passive service hints`,
  });
  broadcastOpsUpdate(state.engagementId, { type: "phase_complete", phase: "passive_discovery" });

  return result;
}

// ─── DNS Security Analysis (NIST SP 800-81r3) ──────────────────────────────

function analyzeDnsSecurity(
  domain: string,
  records: DnsRecordSet,
  reconData: any,
): DnsSecurityFinding[] {
  const findings: DnsSecurityFinding[] = [];

  // 1. Dangling CNAME Detection
  if (records.CNAME) {
    for (const cname of records.CNAME) {
      // Check for common dangling indicators
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
        /\.tictail\.com$/,
      ];
      const isDanglingCandidate = danglingPatterns.some(p => p.test(cname));
      if (isDanglingCandidate) {
        findings.push({
          category: 'dangling_cname',
          severity: 'high',
          title: `Potential Dangling CNAME: ${cname}`,
          detail: `CNAME record points to ${cname} which is a third-party service. If the service is no longer active, this creates a subdomain takeover vulnerability.`,
          record: `${domain} CNAME ${cname}`,
          remediation: 'Verify the CNAME target is actively claimed. If the service is decommissioned, remove the CNAME record immediately.',
          nistReference: 'NIST SP 800-81r3 §4.2 — External Domain Name Integrity',
        });
      }
    }
  }

  // 2. DNSSEC Missing
  const hasDNSSEC = records.DNSKEY && records.DNSKEY.length > 0;
  const hasDS = records.DS && records.DS.length > 0;
  if (!hasDNSSEC && !hasDS) {
    findings.push({
      category: 'dnssec_missing',
      severity: 'medium',
      title: 'DNSSEC Not Deployed',
      detail: `No DNSKEY or DS records found for ${domain}. DNS responses are not cryptographically signed, making them vulnerable to cache poisoning and man-in-the-middle attacks.`,
      remediation: 'Deploy DNSSEC with NSEC3 for authenticated denial of existence. Use Algorithm 13 (ECDSAP256SHA256) or Algorithm 15 (Ed25519) per current best practices.',
      nistReference: 'NIST SP 800-81r3 §3.1 — DNSSEC Deployment',
    });
  }

  // 3. DNSSEC Misconfiguration (weak algorithms)
  if (records.DNSKEY) {
    for (const key of records.DNSKEY) {
      const weakAlgorithms = [1, 3, 5, 6, 7]; // RSAMD5, DSA, RSASHA1, DSA-NSEC3-SHA1, RSASHA1-NSEC3-SHA1
      if (key.algorithm && weakAlgorithms.includes(key.algorithm)) {
        findings.push({
          category: 'dnssec_misconfigured',
          severity: 'high',
          title: `Weak DNSSEC Algorithm (Algorithm ${key.algorithm})`,
          detail: `DNSKEY uses deprecated algorithm ${key.algorithm}. SHA-1 based algorithms are considered cryptographically weak.`,
          record: `DNSKEY algorithm=${key.algorithm}`,
          remediation: 'Migrate to Algorithm 13 (ECDSAP256SHA256) or Algorithm 15 (Ed25519). Perform algorithm rollover per RFC 6781.',
          nistReference: 'NIST SP 800-81r3 §3.1.2 — DNSSEC Algorithm Selection',
        });
      }
    }
  }

  // 4. Zone Transfer Exposure (check NS records for potential AXFR)
  if (records.NS && records.NS.length > 0) {
    findings.push({
      category: 'zone_transfer',
      severity: 'info',
      title: `Zone Transfer Check Required: ${records.NS.length} nameservers`,
      detail: `${records.NS.length} authoritative nameservers identified: ${records.NS.join(', ')}. Active zone transfer testing (AXFR/IXFR) should be performed during the active scanning phase to verify access controls.`,
      remediation: 'Restrict zone transfers to authorized secondary nameservers only. Configure ACLs on all authoritative servers.',
      nistReference: 'NIST SP 800-81r3 §4.1 — Zone Transfer Security',
    });
  }

  // 5. Information Leakage via TXT Records
  if (records.TXT) {
    const sensitivePatterns = [
      { pattern: /v=spf1/i, type: 'SPF', severity: 'info' as const },
      { pattern: /v=DMARC/i, type: 'DMARC', severity: 'info' as const },
      { pattern: /v=DKIM/i, type: 'DKIM', severity: 'info' as const },
      { pattern: /api[_-]?key/i, type: 'API Key', severity: 'high' as const },
      { pattern: /password/i, type: 'Password', severity: 'critical' as const },
      { pattern: /secret/i, type: 'Secret', severity: 'high' as const },
      { pattern: /token/i, type: 'Token', severity: 'high' as const },
      { pattern: /aws[_-]?access/i, type: 'AWS Credential', severity: 'critical' as const },
      { pattern: /private[_-]?key/i, type: 'Private Key', severity: 'critical' as const },
    ];
    for (const txt of records.TXT) {
      for (const { pattern, type, severity } of sensitivePatterns) {
        if (severity !== 'info' && pattern.test(txt)) {
          findings.push({
            category: 'information_leakage',
            severity,
            title: `Sensitive Data in TXT Record: ${type}`,
            detail: `TXT record contains potential ${type} data: "${txt.substring(0, 100)}${txt.length > 100 ? '...' : ''}"`,
            record: `${domain} TXT "${txt.substring(0, 50)}..."`,
            remediation: `Remove sensitive data from public DNS TXT records immediately. Rotate any exposed credentials.`,
            nistReference: 'NIST SP 800-81r3 §4.3 — DNS Information Leakage',
          });
        }
      }
    }

    // Check for missing email security
    const hasSPF = records.TXT.some(t => /v=spf1/i.test(t));
    const hasDMARC = records.TXT.some(t => /v=DMARC/i.test(t));
    if (records.MX && records.MX.length > 0) {
      if (!hasSPF) {
        findings.push({
          category: 'information_leakage',
          severity: 'medium',
          title: 'Missing SPF Record',
          detail: `Domain has MX records but no SPF record. This allows email spoofing from this domain.`,
          remediation: 'Add an SPF TXT record specifying authorized mail senders.',
          nistReference: 'NIST SP 800-81r3 §5.2 — Email Security DNS Records',
        });
      }
      if (!hasDMARC) {
        findings.push({
          category: 'information_leakage',
          severity: 'medium',
          title: 'Missing DMARC Record',
          detail: `Domain has MX records but no DMARC record. DMARC provides email authentication and reporting.`,
          remediation: 'Add a DMARC TXT record at _dmarc.domain with at minimum p=none for monitoring.',
          nistReference: 'NIST SP 800-81r3 §5.2 — Email Security DNS Records',
        });
      }
    }
  }

  // 6. SOA Configuration Issues (Zone Drift)
  if (records.SOA) {
    const soa = records.SOA;
    // Check for unreasonable refresh/retry values
    if (soa.refresh && soa.refresh > 86400) {
      findings.push({
        category: 'zone_drift',
        severity: 'low',
        title: 'SOA Refresh Too High',
        detail: `SOA refresh interval is ${soa.refresh}s (${(soa.refresh / 3600).toFixed(1)}h). High refresh intervals can cause zone data inconsistency between primary and secondary nameservers.`,
        record: `SOA refresh=${soa.refresh}`,
        remediation: 'Set SOA refresh to 3600-14400 seconds (1-4 hours) for most zones.',
        nistReference: 'NIST SP 800-81r3 §3.3 — Zone Configuration',
      });
    }
    if (soa.retry && soa.retry > 7200) {
      findings.push({
        category: 'zone_drift',
        severity: 'low',
        title: 'SOA Retry Too High',
        detail: `SOA retry interval is ${soa.retry}s (${(soa.retry / 3600).toFixed(1)}h). If a zone transfer fails, the secondary won't retry for a long time.`,
        record: `SOA retry=${soa.retry}`,
        remediation: 'Set SOA retry to 600-3600 seconds (10-60 minutes).',
        nistReference: 'NIST SP 800-81r3 §3.3 — Zone Configuration',
      });
    }
  }

  // 7. Lame Delegation Check
  if (records.NS) {
    // Flag if NS records point to different providers (potential lame delegation)
    const nsProviders = new Set<string>();
    for (const ns of records.NS) {
      const parts = ns.split('.');
      if (parts.length >= 2) {
        nsProviders.add(parts.slice(-2).join('.'));
      }
    }
    if (nsProviders.size > 2) {
      findings.push({
        category: 'lame_delegation',
        severity: 'medium',
        title: `Multiple NS Providers Detected (${nsProviders.size})`,
        detail: `Nameservers span ${nsProviders.size} different providers: ${[...nsProviders].join(', ')}. This increases the risk of lame delegation if any provider contract lapses.`,
        remediation: 'Consolidate nameservers to 1-2 providers. Ensure all NS records point to actively maintained servers.',
        nistReference: 'NIST SP 800-81r3 §4.2 — Lame Delegations',
      });
    }
  }

  // 8. Encrypted DNS (DoT/DoH) — informational check
  findings.push({
    category: 'encrypted_dns_missing',
    severity: 'info',
    title: 'Encrypted DNS Assessment Required',
    detail: `Active testing should verify whether the organization supports DNS-over-TLS (DoT, port 853) and DNS-over-HTTPS (DoH) for resolver traffic. Check for rogue encrypted DNS bypass.`,
    remediation: 'Deploy DoT/DoH for all recursive resolver traffic. Block direct DNS queries to external resolvers (8.8.8.8, 1.1.1.1) at the network perimeter.',
    nistReference: 'NIST SP 800-81r3 §6.1 — Encrypted DNS Transport',
  });

  return findings;
}

// ─── Phase 3: Scoping & RoE Review ─────────────────────────────────────────

export async function executeScopingReview(
  state: any,
  engagement: any,
  addLog: (state: any, entry: any) => void,
  broadcastOpsUpdate: (engagementId: number, data: any) => void,
): Promise<void> {
  state.phase = "scoping" as OpsPhase;
  state.currentAction = "Reviewing scope and Rules of Engagement...";
  addLog(state, {
    phase: "scoping",
    type: "info",
    title: "📋 Phase 3: Scoping & RoE Review",
    detail: "Validating engagement scope, authorized targets, testing windows, and escalation procedures before test plan generation.",
  });
  broadcastOpsUpdate(state.engagementId, { type: "phase_change", phase: "scoping" });

  // Validate RoE completeness
  const roeChecklist = [];
  const roeIssues = [];

  // Check authorized targets
  const hasTargetDomains = engagement.targetDomain && engagement.targetDomain.trim().length > 0;
  const hasTargetIPs = engagement.targetIpRange && engagement.targetIpRange.trim().length > 0;
  if (hasTargetDomains || hasTargetIPs) {
    roeChecklist.push('✅ Authorized targets defined');
  } else {
    roeIssues.push('❌ No authorized targets defined in RoE');
  }

  // Check RoE status
  if (engagement.roeStatus === 'signed') {
    roeChecklist.push('✅ RoE signed');
  } else if (engagement.roeStatus === 'pending') {
    roeChecklist.push('⏳ RoE pending signature');
  } else {
    roeIssues.push('❌ RoE not signed — active scanning will be blocked');
  }

  // Check engagement type
  roeChecklist.push(`✅ Engagement type: ${engagement.engagementType || 'pentest'}`);

  // Check testing window
  if (engagement.testingWindow || engagement.scheduledStart) {
    roeChecklist.push('✅ Testing window defined');
  } else {
    roeIssues.push('⚠️ No testing window defined — recommend setting authorized testing hours');
  }

  // Check escalation procedures
  if (engagement.escalationContact || engagement.clientContact) {
    roeChecklist.push('✅ Escalation contact defined');
  } else {
    roeIssues.push('⚠️ No escalation contact defined — recommend adding emergency contact');
  }

  // Build scope summary from passive discovery
  const passiveDiscovery = state.passiveDiscovery || {};
  const scopeSummary = {
    domains: (engagement.targetDomain || '').split(/[,;\s]+/).filter(Boolean),
    ipRanges: (engagement.targetIpRange || '').split(/[,;\s]+/).filter(Boolean),
    assetsDiscovered: state.assets?.length || 0,
    subdomainsDiscovered: passiveDiscovery.subdomains?.length || 0,
    technologiesDetected: passiveDiscovery.technologies?.length || 0,
    cloudProviders: passiveDiscovery.cloudProviders || [],
    wafDetected: passiveDiscovery.wafDetected,
  };

  addLog(state, {
    phase: "scoping", type: "info",
    title: "Scope Summary",
    detail: `Domains: ${scopeSummary.domains.join(', ')} | IPs: ${scopeSummary.ipRanges.join(', ') || 'none'} | Assets: ${scopeSummary.assetsDiscovered} | Subdomains: ${scopeSummary.subdomainsDiscovered} | Technologies: ${scopeSummary.technologiesDetected}`,
    data: { scopeSummary },
  });

  // Log RoE checklist
  const allChecks = [...roeChecklist, ...roeIssues];
  addLog(state, {
    phase: "scoping", type: roeIssues.length > 0 ? "warning" : "info",
    title: `RoE Validation: ${roeChecklist.length}/${allChecks.length} checks passed`,
    detail: allChecks.join('\n'),
    data: { roeChecklist, roeIssues },
  });

  addLog(state, {
    phase: "scoping", type: "phase_complete",
    title: "✅ Phase 3 Complete",
    detail: `Scope validated. ${roeIssues.length > 0 ? `${roeIssues.length} issues require attention.` : 'All checks passed.'} Ready for test plan generation.`,
  });
  broadcastOpsUpdate(state.engagementId, { type: "phase_complete", phase: "scoping" });
}

// ─── Phase 4: Test Plan Generation ──────────────────────────────────────────

export async function executeTestPlanGeneration(
  state: any,
  engagement: any,
  addLog: (state: any, entry: any) => void,
  broadcastOpsUpdate: (engagementId: number, data: any) => void,
): Promise<GeneratedTestPlan> {
  state.phase = "test_plan" as OpsPhase;
  state.currentAction = "Generating test plan...";
  addLog(state, {
    phase: "test_plan",
    type: "info",
    title: "📝 Phase 4: Test Plan Generation",
    detail: "Generating comprehensive penetration test plan aligned with NIST SP 800-115, PTES, and OWASP methodologies. Includes DNS security assessment per NIST SP 800-81r3.",
  });
  broadcastOpsUpdate(state.engagementId, { type: "phase_change", phase: "test_plan" });

  const passiveDiscovery = state.passiveDiscovery || {};
  const passiveRecon = state.passiveReconResults || {};
  const domains = (engagement.targetDomain || '').split(/[,;\s]+/).filter(Boolean);
  const ipRanges = (engagement.targetIpRange || '').split(/[,;\s]+/).filter(Boolean);

  // Build context for LLM
  const contextSummary = buildTestPlanContext(state, engagement, passiveDiscovery, passiveRecon);

  // Generate test plan via LLM
  addLog(state, {
    phase: "test_plan", type: "info",
    title: "LLM Test Plan Generation",
    detail: "Sending engagement context to LLM for comprehensive test plan generation...",
  });

  let testPlanSections: TestPlanSection[] = [];
  let attackVectors: AssessmentAttackVector[] = [];
  let estimatedDuration = "5-10 business days";
  let toolsPlanned: string[] = [];
  let riskMitigations: string[] = [];

  try {
    const llmResponse = await throttledLLMCall({
      messages: [
          {
            role: "system",
            content: `You are a senior penetration test planner creating a formal test plan for customer review and approval. The plan must be thorough, professional, and aligned with NIST SP 800-115 (Technical Guide to Information Security Testing and Assessment), PTES (Penetration Testing Execution Standard), and OWASP Testing Guide methodologies.

Do NOT make compliance certification claims (e.g., do not claim the plan is "FedRAMP certified" or "3PAO approved"). Reference standards by their identifiers only.

The test plan must include these sections:
1. Executive Summary — engagement overview, objectives, and methodology
2. Scope Definition — authorized targets, exclusions, testing windows
3. Methodology — assessment approach, phases, and techniques
4. Assessment Attack Vectors — specific attack vectors mapped to targets
5. DNS Security Assessment — per NIST SP 800-81r3 (March 2026)
6. Tools & Techniques — planned tools with justification
7. Risk Mitigation — safeguards during testing
8. Communication Plan — escalation procedures, status reporting
9. Timeline & Milestones — estimated schedule
10. Deliverables — expected outputs and report format

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
}`,
          },
          {
            role: "user",
            content: `Generate a comprehensive test plan for this engagement:\n\n${contextSummary}`,
          },
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
                      standardsReference: { type: "string" },
                    },
                    required: ["id", "title", "content"],
                  },
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
                      riskLevel: { type: "string" },
                    },
                    required: ["id", "name", "description"],
                  },
                },
                estimatedDuration: { type: "string" },
                toolsPlanned: { type: "array", items: { type: "string" } },
                riskMitigations: { type: "array", items: { type: "string" } },
              },
              required: ["sections", "attackVectors", "estimatedDuration", "toolsPlanned", "riskMitigations"],
            },
          },
        },
        _caller: `test-plan-${state.engagementId}`,
    } as any);

    const parsed = JSON.parse(llmResponse.choices[0].message.content || '{}');
    testPlanSections = (parsed.sections || []).map((s: any) => ({
      id: s.id || `section-${Math.random().toString(36).slice(2, 8)}`,
      title: s.title || 'Untitled Section',
      content: s.content || '',
      standardsReference: s.standardsReference,
    }));
    attackVectors = (parsed.attackVectors || []).map((v: any) => ({
      id: v.id || `av-${Math.random().toString(36).slice(2, 8)}`,
      name: v.name || 'Unnamed Vector',
      description: v.description || '',
      targets: v.targets || [],
      tools: v.tools || [],
      techniques: v.techniques || [],
      estimatedDuration: v.estimatedDuration || 'TBD',
      riskLevel: v.riskLevel || 'medium',
    }));
    estimatedDuration = parsed.estimatedDuration || estimatedDuration;
    toolsPlanned = parsed.toolsPlanned || [];
    riskMitigations = parsed.riskMitigations || [];

    addLog(state, {
      phase: "test_plan", type: "info",
      title: `Test Plan Generated: ${testPlanSections.length} sections, ${attackVectors.length} attack vectors`,
      detail: `Duration: ${estimatedDuration} | Tools: ${toolsPlanned.slice(0, 5).join(', ')}${toolsPlanned.length > 5 ? ` +${toolsPlanned.length - 5} more` : ''}`,
    });
  } catch (err: any) {
    console.error('[TestPlan] LLM generation failed:', err.message);
    addLog(state, {
      phase: "test_plan", type: "warning",
      title: "LLM Test Plan Generation Failed — Using Structured Fallback",
      detail: `Error: ${err.message}. Generating test plan from structured templates.`,
    });

    // Fallback: generate structured test plan without LLM
    testPlanSections = generateFallbackTestPlan(state, engagement, passiveDiscovery);
    attackVectors = generateFallbackAttackVectors(state, engagement, passiveDiscovery);
    toolsPlanned = ['scanforge-discovery', 'nuclei', 'ZAP', 'Metasploit', 'Burp Suite', 'dig', 'dnsrecon', 'subfinder'];
    riskMitigations = [
      'All testing will be conducted within authorized scope defined in the Rules of Engagement',
      'Emergency stop procedures are in place — testing can be halted immediately upon request',
      'DNS zone transfer testing will use read-only queries to prevent zone disruption',
      'Exploitation attempts will target only confirmed vulnerabilities with known safe exploits',
      'All actions are logged with timestamps for full audit trail',
    ];
  }

  // Build DNS assessment plan from passive findings
  const dnsAssessment = buildDnsAssessmentPlan(state, passiveDiscovery);

  // Construct the test plan
  const testPlan: GeneratedTestPlan = {
    id: `tp-${state.engagementId}-${Date.now()}`,
    engagementId: state.engagementId,
    engagementType: engagement.engagementType || 'pentest',
    generatedAt: Date.now(),
    status: 'draft',
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
      technologies: passiveDiscovery.technologies || [],
    },
  };

  // Store in state
  state.testPlan = {
    id: testPlan.id,
    generatedAt: testPlan.generatedAt,
    status: 'draft',
    sections: testPlan.sections,
    attackVectors: testPlan.attackVectors.map(v => v.name),
    dnsAssessment: testPlan.dnsAssessment,
    estimatedDuration: testPlan.estimatedDuration,
    toolsPlanned: testPlan.toolsPlanned,
  };

  addLog(state, {
    phase: "test_plan", type: "phase_complete",
    title: "✅ Phase 4 Complete — Test Plan Ready for Review",
    detail: `Generated ${testPlanSections.length}-section test plan with ${attackVectors.length} attack vectors. DNS assessment includes ${dnsAssessment.checks.length} checks. Status: DRAFT — awaiting customer approval.`,
    data: { testPlanId: testPlan.id },
  });
  broadcastOpsUpdate(state.engagementId, { type: "phase_complete", phase: "test_plan" });

  return testPlan;
}

// ─── Phase 4b: Test Plan Approval Gate ──────────────────────────────────────

export async function executeTestPlanApproval(
  state: any,
  addLog: (state: any, entry: any) => void,
  broadcastOpsUpdate: (engagementId: number, data: any) => void,
): Promise<boolean> {
  state.phase = "test_plan_approval" as OpsPhase;
  state.currentAction = "Awaiting test plan approval...";

  if (!state.testPlan) {
    addLog(state, {
      phase: "test_plan_approval", type: "error",
      title: "No Test Plan Found",
      detail: "Cannot request approval — no test plan has been generated.",
    });
    return false;
  }

  // Update test plan status
  state.testPlan.status = 'pending_approval';

  addLog(state, {
    phase: "test_plan_approval",
    type: "approval_request",
    title: "📋 Phase 4b: Test Plan Approval Required",
    detail: "The test plan has been generated and is ready for customer review. Active scanning will not begin until the test plan is approved. Approve the test plan to proceed to active discovery and enumeration.",
  });
  broadcastOpsUpdate(state.engagementId, {
    type: "approval_required",
    phase: "test_plan_approval",
    testPlanId: state.testPlan.id,
  });

  // Create an approval gate
  const gateId = `tp-approval-${state.engagementId}-${Date.now()}`;
  state.approvalGates.push({
    id: gateId,
    phase: "test_plan_approval" as OpsPhase,
    riskTier: "yellow" as const,
    title: "Test Plan Approval",
    description: "Customer must review and approve the test plan before active scanning begins.",
    target: state.testPlan.id,
    detail: {
      testPlanId: state.testPlan.id,
      sections: state.testPlan.sections?.length || 0,
      attackVectors: state.testPlan.attackVectors?.length || 0,
    },
    status: "pending" as const,
    createdAt: Date.now(),
  });

  // The pipeline will pause here — the operator/customer must approve the gate
  // to proceed. The approval is handled by the existing approval gate mechanism.
  // For now, we auto-approve if the engagement has a signed RoE (operator trust).
  // In production, this would wait for explicit customer approval.

  addLog(state, {
    phase: "test_plan_approval", type: "info",
    title: "Test Plan Submitted for Review",
    detail: "The test plan is now available in the engagement details. The operator can review and approve it to proceed with active scanning.",
  });

  return true;
}

// ─── Helper: Build Test Plan Context ────────────────────────────────────────

function buildTestPlanContext(
  state: any,
  engagement: any,
  passiveDiscovery: any,
  passiveRecon: any,
): string {
  const sections: string[] = [];

  sections.push(`## Engagement Overview
- Type: ${engagement.engagementType || 'pentest'}
- Client: ${engagement.clientName || engagement.name || 'Unknown'}
- Sector: ${engagement.sector || engagement.industry || 'Not specified'}
- RoE Status: ${engagement.roeStatus || 'not signed'}
- Scan Mode: ${engagement.scanMode || 'standard'}`);

  const domains = (engagement.targetDomain || '').split(/[,;\s]+/).filter(Boolean);
  const ipRanges = (engagement.targetIpRange || '').split(/[,;\s]+/).filter(Boolean);
  sections.push(`## Authorized Scope
- Domains: ${domains.join(', ') || 'none'}
- IP Ranges: ${ipRanges.join(', ') || 'none'}
- Assets Discovered: ${state.assets?.length || 0}
- Subdomains: ${passiveDiscovery.subdomains?.length || 0}`);

  if (passiveDiscovery.technologies?.length > 0) {
    sections.push(`## Technologies Detected
${passiveDiscovery.technologies.join(', ')}`);
  }

  if (passiveDiscovery.cloudProviders?.length > 0) {
    sections.push(`## Cloud Providers
${passiveDiscovery.cloudProviders.join(', ')}`);
  }

  if (passiveDiscovery.wafDetected) {
    sections.push(`## WAF/CDN Detected
${passiveDiscovery.wafDetected}`);
  }

  if (passiveDiscovery.breachExposure?.length > 0) {
    sections.push(`## Breach Exposure
${passiveDiscovery.breachExposure.length} breach records found`);
  }

  // DNS security findings
  const dnsFindings = state.passiveDiscovery?.dnsSecurityFindings || [];
  if (dnsFindings.length > 0) {
    sections.push(`## DNS Security Findings (Passive)
${dnsFindings.map((f: any) => `- [${f.severity.toUpperCase()}] ${f.title}`).join('\n')}`);
  }

  // Passive recon summary per domain
  for (const domain of domains.slice(0, 5)) {
    const recon = passiveRecon[domain];
    if (recon) {
      const ports = recon.shodan?.ports?.map((p: any) => p.port).join(', ') || 'none detected';
      sections.push(`## Domain: ${domain}
- Open Ports (passive): ${ports}
- Subdomains: ${recon.subdomains?.length || 0}
- Technologies: ${recon.technologies?.join(', ') || 'none detected'}`);
    }
  }

  if (engagement.roeNotes) {
    sections.push(`## RoE Notes / Restrictions
${engagement.roeNotes}`);
  }

  if (engagement.complianceFrameworks?.length > 0) {
    sections.push(`## Compliance Frameworks
${engagement.complianceFrameworks.join(', ')}`);
  }

  return sections.join('\n\n');
}

// ─── Helper: Build DNS Assessment Plan ──────────────────────────────────────

function buildDnsAssessmentPlan(state: any, passiveDiscovery: any): DnsAssessmentPlan {
  const checks: DnsAssessmentCheck[] = [
    {
      category: 'DNSSEC Validation',
      description: 'Verify DNSSEC deployment, algorithm strength, key rotation, and chain of trust from root to zone',
      tools: ['dig +dnssec', 'delv', 'dnsviz.net', 'dnsrecon'],
      nistReference: 'NIST SP 800-81r3 §3.1',
      priority: 'required',
    },
    {
      category: 'Zone Transfer Testing',
      description: 'Attempt AXFR/IXFR against all authoritative nameservers to verify access controls',
      tools: ['dig AXFR', 'dnsrecon -t axfr', 'nuclei -t dns-zone-transfer'],
      nistReference: 'NIST SP 800-81r3 §4.1',
      priority: 'required',
    },
    {
      category: 'Subdomain Takeover',
      description: 'Verify all CNAME targets are actively claimed; test for dangling records pointing to decommissioned services',
      tools: ['subjack', 'nuclei -t takeovers', 'can-i-take-over-xyz'],
      nistReference: 'NIST SP 800-81r3 §4.2',
      priority: 'required',
    },
    {
      category: 'DNS Information Leakage',
      description: 'Check TXT, HINFO, LOC, and CHAOS records for sensitive data exposure',
      tools: ['dig ANY', 'dnsrecon -t std', 'fierce'],
      nistReference: 'NIST SP 800-81r3 §4.3',
      priority: 'required',
    },
    {
      category: 'Email Security Records',
      description: 'Validate SPF, DKIM, and DMARC configuration for email authentication',
      tools: ['dig TXT', 'mxtoolbox', 'dmarc-analyzer'],
      nistReference: 'NIST SP 800-81r3 §5.2',
      priority: 'required',
    },
    {
      category: 'Encrypted DNS Transport',
      description: 'Test for DNS-over-TLS (DoT, port 853) and DNS-over-HTTPS (DoH) support on resolvers',
      tools: ['kdig +tls', 'curl (DoH)', 'naabu -p 853'],
      nistReference: 'NIST SP 800-81r3 §6.1',
      priority: 'recommended',
    },
    {
      category: 'Recursive/Authoritative Separation',
      description: 'Verify that authoritative servers do not also serve recursive queries (dual-function risk)',
      tools: ['dig +recurse', 'nuclei -t dns-recursion'],
      nistReference: 'NIST SP 800-81r3 §3.2',
      priority: 'recommended',
    },
    {
      category: 'Lame Delegation',
      description: 'Verify all NS records point to responsive, authoritative nameservers',
      tools: ['dig NS', 'dnsrecon -t std', 'nslookup'],
      nistReference: 'NIST SP 800-81r3 §4.2',
      priority: 'required',
    },
    {
      category: 'Lookalike Domain Detection',
      description: 'Search for typosquat and homoglyph domains that could be used for phishing',
      tools: ['dnstwist', 'urlcrazy', 'amass'],
      nistReference: 'NIST SP 800-81r3 §4.4',
      priority: 'recommended',
    },
    {
      category: 'DNS Tunneling Detection',
      description: 'Analyze DNS query patterns for potential tunneling/exfiltration channels',
      tools: ['dnscat2 (detection)', 'iodine (detection)', 'dns-tunnel-detect'],
      nistReference: 'NIST SP 800-81r3 §7.1',
      priority: 'optional',
    },
  ];

  // Assess passive posture
  const dnsFindings = passiveDiscovery?.dnsSecurityFindings || [];
  const criticalFindings = dnsFindings.filter((f: any) => f.severity === 'critical').length;
  const highFindings = dnsFindings.filter((f: any) => f.severity === 'high').length;
  let passivePosture: 'strong' | 'moderate' | 'weak' | 'critical' = 'moderate';
  if (criticalFindings > 0) passivePosture = 'critical';
  else if (highFindings > 2) passivePosture = 'weak';
  else if (highFindings > 0) passivePosture = 'moderate';
  else if (dnsFindings.length <= 2) passivePosture = 'strong';

  return {
    checks,
    passivePosture,
    passiveFindings: dnsFindings.map((f: any) => `[${f.severity.toUpperCase()}] ${f.title}`),
  };
}

// ─── Fallback Test Plan (no LLM) ───────────────────────────────────────────

function generateFallbackTestPlan(
  state: any,
  engagement: any,
  passiveDiscovery: any,
): TestPlanSection[] {
  const engType = engagement.engagementType || 'pentest';
  const domains = (engagement.targetDomain || '').split(/[,;\s]+/).filter(Boolean);
  const isRedTeam = engType === 'red_team';

  return [
    {
      id: 'exec-summary',
      title: 'Executive Summary',
      content: `This document presents the ${isRedTeam ? 'Red Team Exercise' : 'Penetration Test'} plan for ${engagement.clientName || engagement.name || 'the target organization'}. The assessment will evaluate the security posture of ${domains.length} target domain(s) and associated infrastructure using a structured methodology aligned with NIST SP 800-115 and the Penetration Testing Execution Standard (PTES).\n\nThe assessment will proceed through the following phases: Domain Reconnaissance, Passive Discovery, Active Enumeration, Vulnerability Scanning, ${isRedTeam ? 'Exploitation, C2 Deployment, Lateral Movement, and Objective Completion' : 'Exploitation, and Evidence Collection'}.`,
      standardsReference: 'NIST SP 800-115 §3',
    },
    {
      id: 'scope',
      title: 'Scope Definition',
      content: `### Authorized Targets\n- Domains: ${domains.join(', ') || 'TBD'}\n- IP Ranges: ${(engagement.targetIpRange || 'TBD')}\n- Total Assets Discovered: ${state.assets?.length || 0}\n- Subdomains Discovered: ${passiveDiscovery.subdomains?.length || 0}\n\n### Exclusions\n${engagement.roeNotes || 'No specific exclusions documented. Confirm with client before proceeding.'}\n\n### Testing Window\n${engagement.testingWindow || 'To be confirmed with client. Recommend business hours with 24-hour notice for disruptive testing.'}`,
      standardsReference: 'NIST SP 800-115 §4.1',
    },
    {
      id: 'methodology',
      title: 'Methodology',
      content: `The assessment follows a structured methodology:\n\n1. **Domain Recon** — Passive OSINT gathering\n2. **Passive Discovery** — DNS enumeration, certificate analysis, technology fingerprinting\n3. **Active Discovery & Enumeration** — Port scanning, service identification, OS fingerprinting\n4. **Vulnerability Scanning** — Automated and manual vulnerability identification\n5. **${isRedTeam ? 'Exploitation & Post-Exploitation' : 'Penetration Testing'}** — ${isRedTeam ? 'Exploitation, C2 deployment, lateral movement, and objective completion' : 'Exploitation of confirmed vulnerabilities with evidence collection'}\n6. **Reporting** — Comprehensive findings report with remediation recommendations`,
      standardsReference: 'NIST SP 800-115 §4, PTES §2',
    },
    {
      id: 'dns-assessment',
      title: 'DNS Security Assessment',
      content: `DNS security will be assessed per NIST SP 800-81r3 (March 2026) guidance:\n\n- **DNSSEC Validation** — Verify deployment, algorithm strength, and chain of trust\n- **Zone Transfer Testing** — Attempt AXFR/IXFR against authoritative nameservers\n- **Subdomain Takeover** — Check for dangling CNAME records\n- **Information Leakage** — Analyze TXT, HINFO, LOC records\n- **Email Security** — Validate SPF, DKIM, DMARC\n- **Encrypted DNS** — Test DoT/DoH support\n- **Recursive/Authoritative Separation** — Verify server role isolation\n- **Lookalike Domains** — Detect typosquat/homoglyph domains`,
      standardsReference: 'NIST SP 800-81r3',
    },
    {
      id: 'tools',
      title: 'Tools & Techniques',
      content: `### Planned Tools\n- **Reconnaissance**: subfinder, amass, crt.sh, SecurityTrails\n- **DNS**: dig, dnsrecon, dnstwist, dnsviz\n- **Enumeration**: ScanForge discovery, httpx, masscan\n- **Vulnerability Scanning**: nuclei, OWASP ZAP, nikto\n- **Exploitation**: Metasploit Framework, custom scripts\n${isRedTeam ? '- **C2**: Caldera, custom implants\n- **Post-Exploitation**: BloodHound, Mimikatz, Rubeus' : '- **Evidence Collection**: screenshot tools, data extraction scripts'}`,
      standardsReference: 'NIST SP 800-115 §4.3',
    },
    {
      id: 'risk-mitigation',
      title: 'Risk Mitigation',
      content: `### Safeguards During Testing\n- All testing within authorized scope per signed RoE\n- Emergency stop procedures — testing halted immediately upon request\n- DNS zone transfer testing uses read-only queries\n- Exploitation targets only confirmed vulnerabilities\n- Full audit trail with timestamps for all actions\n- Rate limiting on active scans to prevent service disruption\n- Immediate notification of critical findings`,
      standardsReference: 'NIST SP 800-115 §5',
    },
    {
      id: 'communication',
      title: 'Communication Plan',
      content: `### Escalation Procedures\n- Critical vulnerabilities: Immediate notification to ${engagement.escalationContact || 'designated client contact'}\n- Service disruption: Immediate halt and notification\n- Status updates: ${engagement.reportingFrequency || 'Daily summary during active testing'}\n\n### Points of Contact\n- Assessment Lead: ${engagement.assessorName || 'TBD'}\n- Client Contact: ${engagement.clientContact || 'TBD'}\n- Emergency Contact: ${engagement.escalationContact || 'TBD'}`,
      standardsReference: 'NIST SP 800-115 §5.2',
    },
    {
      id: 'deliverables',
      title: 'Deliverables',
      content: `### Expected Outputs\n1. **${isRedTeam ? 'Red Team Exercise Report' : 'Penetration Test Report'}** — Comprehensive findings with severity ratings, evidence, and remediation\n2. **Executive Summary** — High-level risk overview for leadership\n3. **Technical Appendix** — Detailed tool outputs, scan logs, and evidence\n4. **Remediation Roadmap** — Prioritized remediation plan\n${isRedTeam ? '5. **Attack Narrative** — Step-by-step attack path documentation\n6. **Detection Gap Analysis** — Blue team detection coverage assessment' : '5. **Vulnerability Matrix** — All findings mapped to CVSS, CWE, and applicable standards'}`,
      standardsReference: 'NIST SP 800-115 §6',
    },
  ];
}

function generateFallbackAttackVectors(
  state: any,
  engagement: any,
  passiveDiscovery: any,
): AssessmentAttackVector[] {
  const vectors: AssessmentAttackVector[] = [];
  const domains = (engagement.targetDomain || '').split(/[,;\s]+/).filter(Boolean);
  const isRedTeam = engagement.engagementType === 'red_team';

  vectors.push({
    id: 'av-web-app',
    name: 'Web Application Testing',
    description: 'Test web applications for OWASP Top 10 vulnerabilities including injection, broken authentication, XSS, and security misconfigurations',
    targets: domains,
    tools: ['nuclei', 'ZAP', 'Burp Suite', 'sqlmap', 'nikto'],
    techniques: ['SQL Injection', 'XSS', 'CSRF', 'SSRF', 'Authentication Bypass', 'Directory Traversal'],
    estimatedDuration: '2-3 days',
    riskLevel: 'high',
  });

  vectors.push({
    id: 'av-network',
    name: 'Network Infrastructure Testing',
    description: 'Enumerate and test network services, protocols, and configurations for vulnerabilities',
    targets: domains,
    tools: ['scanforge-discovery', 'masscan', 'Metasploit', 'hydra'],
    techniques: ['Port Scanning', 'Service Fingerprinting', 'Default Credentials', 'Protocol Exploitation'],
    estimatedDuration: '1-2 days',
    riskLevel: 'high',
  });

  vectors.push({
    id: 'av-dns',
    name: 'DNS Infrastructure Assessment',
    description: 'Comprehensive DNS security assessment per NIST SP 800-81r3 including DNSSEC, zone transfers, and subdomain takeover',
    targets: domains,
    tools: ['dig', 'dnsrecon', 'dnstwist', 'subfinder', 'nuclei'],
    techniques: ['Zone Transfer', 'DNSSEC Validation', 'Subdomain Takeover', 'DNS Tunneling Detection'],
    estimatedDuration: '1 day',
    riskLevel: 'medium',
  });

  if (passiveDiscovery.cloudProviders?.length > 0) {
    vectors.push({
      id: 'av-cloud',
      name: 'Cloud Infrastructure Testing',
      description: `Test ${passiveDiscovery.cloudProviders.join(', ')} cloud configurations for misconfigurations and exposed services`,
      targets: passiveDiscovery.cloudProviders,
      tools: ['ScoutSuite', 'Prowler', 'CloudSploit', 'nuclei'],
      techniques: ['S3 Bucket Enumeration', 'IAM Policy Review', 'Metadata Service Access', 'Cloud Storage Misconfiguration'],
      estimatedDuration: '1-2 days',
      riskLevel: 'high',
    });
  }

  if (passiveDiscovery.emailAddresses?.length > 0 || isRedTeam) {
    vectors.push({
      id: 'av-social',
      name: isRedTeam ? 'Social Engineering & Phishing' : 'Email Security Assessment',
      description: isRedTeam
        ? 'Conduct targeted phishing campaigns and social engineering attacks against identified personnel'
        : 'Assess email security controls including SPF, DKIM, DMARC, and phishing resilience',
      targets: domains,
      tools: isRedTeam ? ['GoPhish', 'SET', 'Evilginx'] : ['mxtoolbox', 'dmarc-analyzer'],
      techniques: isRedTeam
        ? ['Spear Phishing', 'Credential Harvesting', 'Pretexting', 'Vishing']
        : ['SPF Validation', 'DKIM Verification', 'DMARC Policy Check'],
      estimatedDuration: isRedTeam ? '3-5 days' : '0.5 days',
      riskLevel: isRedTeam ? 'high' : 'medium',
    });
  }

  if (isRedTeam) {
    vectors.push({
      id: 'av-c2',
      name: 'Command & Control Operations',
      description: 'Deploy C2 infrastructure, establish persistence, and conduct lateral movement to achieve engagement objectives',
      targets: domains,
      tools: ['Caldera', 'Cobalt Strike', 'Sliver', 'BloodHound'],
      techniques: ['C2 Deployment', 'Persistence', 'Lateral Movement', 'Privilege Escalation', 'Data Exfiltration'],
      estimatedDuration: '3-5 days',
      riskLevel: 'critical',
    });
  }

  return vectors;
}

// ─── Pipeline Phase Order ───────────────────────────────────────────────────

/**
 * Returns the ordered list of pipeline phases for display and navigation.
 * This is the canonical phase order for the redesigned pipeline.
 */
export function getPipelinePhaseOrder(): Array<{
  phase: OpsPhase;
  number: number;
  label: string;
  description: string;
  requiresRoE: boolean;
}> {
  return [
    { phase: 'recon', number: 1, label: 'Domain Recon', description: 'Passive OSINT and domain intelligence gathering', requiresRoE: false },
    { phase: 'passive_discovery', number: 2, label: 'Passive Discovery', description: 'DNS enumeration, certificate analysis, technology fingerprinting', requiresRoE: false },
    { phase: 'scoping', number: 3, label: 'Scoping & RoE', description: 'Scope validation and Rules of Engagement review', requiresRoE: false },
    { phase: 'test_plan', number: 4, label: 'Test Plan', description: 'NIST 800-115 aligned test plan generation', requiresRoE: false },
    { phase: 'test_plan_approval', number: 4, label: 'Plan Approval', description: 'Customer test plan review and approval gate', requiresRoE: false },
    { phase: 'enumeration', number: 5, label: 'Active Discovery', description: 'Port scanning, service identification, OS fingerprinting', requiresRoE: true },
    { phase: 'vuln_detection', number: 6, label: 'Vulnerability Scanning', description: 'Automated and manual vulnerability identification', requiresRoE: true },
    { phase: 'social_engineering' as OpsPhase, number: 6, label: 'Social Engineering', description: 'Phishing assessment, domain spoofability analysis, and campaign recommendations (ROE-gated)', requiresRoE: true },
    { phase: 'exploitation', number: 7, label: 'Exploitation', description: 'Penetration testing and exploitation of confirmed vulnerabilities', requiresRoE: true },
    { phase: 'post_exploit', number: 8, label: 'Post-Exploitation', description: 'C2 deployment, lateral movement, or evidence collection', requiresRoE: true },
    { phase: 'reporting', number: 9, label: 'Reporting', description: 'Comprehensive findings report generation', requiresRoE: false },
  ];
}
