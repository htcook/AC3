/**
 * Unified Attack Lifecycle Pipeline
 * 
 * Central integration layer that wires ALL tool modules into the full
 * attack lifecycle:
 * 
 * Phase 1: RECON (Passive Discovery & Enumeration)
 *   - Passive OSINT connectors (existing 17 connectors)
 *   - ZAP passive spider (web app discovery)
 *   - Nuclei info/low templates (tech stack fingerprinting)
 *   - Atomic Red Team T1595/T1592 recon techniques
 * 
 * Phase 2: ENUMERATION (Active Probing)
 *   - ZAP active spider + AJAX spider (deep crawl)
 *   - Nuclei medium templates (service enumeration)
 *   - Active probes (DNS, banner, HTTP)
 *   - Shodan/Censys deep queries
 * 
 * Phase 3: VULNERABILITY ASSESSMENT (DAST + Vuln Scanning)
 *   - ZAP active scan (DAST)
 *   - Nuclei high/critical templates (vuln detection)
 *   - NVD/KEV CVE matching
 *   - API security testing (OpenAPI/GraphQL)
 * 
 * Phase 4: EXPLOITATION (Active Testing)
 *   - Metasploit exploit execution
 *   - Sliver C2 implant deployment
 *   - Caldera ability execution
 *   - Atomic Red Team validation tests
 * 
 * Phase 5: POST-EXPLOITATION (Persistence & Lateral Movement)
 *   - Sliver C2 session management
 *   - Cyber C2 operations (lateral movement, persistence)
 *   - Credential harvesting & rotation testing
 *   - AD attack paths (BloodHound)
 * 
 * Phase 6: REPORTING & VALIDATION
 *   - Corroboration across all sources
 *   - Hybrid Risk scoring with all inputs
 *   - ATT&CK coverage heatmap aggregation
 *   - Detection rule validation via Atomic tests
 *   - Evidence capture & report generation
 * 
 * @module unified-pipeline
 */

// ─── Types ───────────────────────────────────────────────────────────

export type PipelinePhase =
  | 'recon'
  | 'enumeration'
  | 'vulnerability_assessment'
  | 'exploitation'
  | 'post_exploitation'
  | 'reporting';

export type ToolModule =
  | 'passive_osint'
  | 'zap_passive'
  | 'zap_active'
  | 'nuclei_info'
  | 'nuclei_vuln'
  | 'nuclei_critical'
  | 'metasploit'
  | 'sliver_c2'
  | 'caldera'
  | 'atomic_red_team'
  | 'gophish'
  | 'bloodhound'
  | 'api_security'
  | 'nvd_kev'
  | 'corroboration'
  | 'scoring'
  | 'detection_rules'
  | 'amass'
  | 'nmap'
  | 'service_fingerprinter';

export interface PipelineStageConfig {
  phase: PipelinePhase;
  tools: ToolModule[];
  description: string;
  requiresPriorPhase: boolean;
  canRunParallel: boolean;
  estimatedDurationMinutes: number;
}

export interface PipelineTarget {
  domain: string;
  targetIps?: string[];
  targetUrls?: string[];
  openApiSpecUrl?: string;
  graphqlEndpoint?: string;
  credentials?: {
    type: 'form' | 'token' | 'oauth' | 'basic';
    config: Record<string, string>;
  };
  scope: {
    inScope: string[];
    outOfScope: string[];
  };
  engagementId?: number;
}

export interface PipelineFinding {
  id: string;
  phase: PipelinePhase;
  tool: ToolModule;
  type: 'asset' | 'vulnerability' | 'credential' | 'misconfiguration' | 'exposure' | 'exploit_result' | 'c2_session' | 'detection_gap';
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  title: string;
  description: string;
  host: string;
  port?: number;
  cveId?: string;
  cweId?: string;
  attackTechnique?: string;
  confidence: number;
  evidence: Record<string, any>;
  timestamp: number;
  /** Cross-references to findings from other tools */
  crossRefs: string[];
  /** Whether this finding was corroborated by another source */
  corroborated: boolean;
  corroboratingTools: ToolModule[];
}

export interface PipelinePhaseResult {
  phase: PipelinePhase;
  status: 'pending' | 'running' | 'completed' | 'failed' | 'skipped';
  toolResults: {
    tool: ToolModule;
    status: 'success' | 'failed' | 'skipped' | 'timeout';
    findingCount: number;
    durationMs: number;
    errors: string[];
  }[];
  findings: PipelineFinding[];
  startedAt: number;
  completedAt?: number;
  durationMs?: number;
}

export interface PipelineRun {
  id: string;
  target: PipelineTarget;
  phases: PipelinePhaseResult[];
  status: 'pending' | 'running' | 'completed' | 'failed' | 'cancelled';
  totalFindings: number;
  findingsBySeverity: Record<string, number>;
  findingsByPhase: Record<PipelinePhase, number>;
  findingsByTool: Record<string, number>;
  attackCoverage: {
    techniquesUsed: string[];
    tacticsUsed: string[];
    coveragePercent: number;
  };
  startedAt: number;
  completedAt?: number;
  engagementId?: number;
}

// ─── Pipeline Phase Definitions ──────────────────────────────────────

export const PIPELINE_STAGES: PipelineStageConfig[] = [
  {
    phase: 'recon',
    tools: ['passive_osint', 'zap_passive', 'nuclei_info', 'atomic_red_team', 'amass', 'nmap'],
    description: 'Passive discovery and enumeration — map the attack surface without touching the target directly. OSINT connectors gather DNS, certificates, breached credentials, and cloud assets. Web scanner passive spider discovers web application structure. Template scanner info-level templates fingerprint technology stacks. Adversary emulation recon techniques (T1595, T1592) validate what an attacker would see.',
    requiresPriorPhase: false,
    canRunParallel: true,
    estimatedDurationMinutes: 10,
  },
  {
    phase: 'enumeration',
    tools: ['zap_active', 'nuclei_info', 'api_security', 'passive_osint', 'amass', 'nmap', 'service_fingerprinter'],
    description: 'Active probing and deep enumeration — crawl web applications, discover API endpoints, enumerate services. Web scanner active/AJAX spider performs deep crawling of JavaScript-heavy apps. Template scanner medium templates enumerate services and configurations. API security engine tests OpenAPI/GraphQL endpoints. Active DNS and banner verification confirms passive findings. Amass active subdomain enumeration discovers additional attack surface via DNS brute-force and zone transfers. Nmap port scanning and service detection identifies open ports. Service fingerprinter performs protocol-specific probing of SSH, SMTP, FTP, SNMP, RDP, SMB, LDAP, databases, and other administrative services.',
    requiresPriorPhase: true,
    canRunParallel: true,
    estimatedDurationMinutes: 20,
  },
  {
    phase: 'vulnerability_assessment',
    tools: ['zap_active', 'nuclei_vuln', 'nuclei_critical', 'nvd_kev', 'api_security', 'corroboration'],
    description: 'Comprehensive vulnerability detection — DAST scanning, template-based vuln detection, CVE matching. Web scanner active scan tests for OWASP Top 10 (XSS, SQLi, CSRF, etc.). Template scanner high/critical templates detect known CVEs and misconfigurations. NVD/KEV matching correlates discovered services with known vulnerabilities. Corroboration engine cross-validates findings across all sources to reduce false positives by 30-40%.',
    requiresPriorPhase: true,
    canRunParallel: true,
    estimatedDurationMinutes: 45,
  },
  {
    phase: 'exploitation',
    tools: ['metasploit', 'sliver_c2', 'caldera', 'atomic_red_team', 'gophish'],
    description: 'Active exploitation and initial access — execute exploits, deploy implants, launch phishing campaigns. Exploit framework executes matched exploits against confirmed vulnerabilities. C2 framework deploys cross-platform implants via mTLS/HTTPS/DNS. Adversary emulation platform runs abilities mapped to ATT&CK techniques. Adversary validation tests execute atomic tests to validate detection gaps. Phishing engine launches social engineering campaigns for initial access.',
    requiresPriorPhase: true,
    canRunParallel: false,
    estimatedDurationMinutes: 60,
  },
  {
    phase: 'post_exploitation',
    tools: ['sliver_c2', 'caldera', 'metasploit', 'atomic_red_team', 'bloodhound'],
    description: 'Post-exploitation operations — lateral movement, persistence, privilege escalation, credential harvesting. C2 framework manages implant sessions for ongoing access. Adversary emulation platform orchestrates multi-step operations. Exploit framework provides post-exploitation modules. Adversary validation tests validate detection of post-exploitation techniques. AD attack path analysis discovers privilege escalation paths.',
    requiresPriorPhase: true,
    canRunParallel: false,
    estimatedDurationMinutes: 90,
  },
  {
    phase: 'reporting',
    tools: ['corroboration', 'scoring', 'detection_rules', 'atomic_red_team'],
    description: 'Validation, scoring, and reporting — corroborate findings, compute risk scores, validate detection coverage. Corroboration engine performs final cross-source validation. Hybrid Risk scoring engine computes risk scores with all collected data. Detection rule validation runs adversary tests against SIEM/EDR rules. ATT&CK coverage heatmap shows tested vs. untested techniques. Evidence capture and report generation produce deliverables.',
    requiresPriorPhase: true,
    canRunParallel: true,
    estimatedDurationMinutes: 15,
  },
];

// ─── Tool-to-Phase Matrix ────────────────────────────────────────────

/**
 * Complete mapping of which tools contribute to which phases.
 * Used by the UI to show tool availability per phase and by the
 * pipeline orchestrator to determine what to run.
 */
export const TOOL_PHASE_MATRIX: Record<ToolModule, {
  phases: PipelinePhase[];
  role: string;
  inputsFrom: ToolModule[];
  outputsTo: ToolModule[];
}> = {
  passive_osint: {
    phases: ['recon', 'enumeration'],
    role: 'Passive discovery via 17 OSINT connectors (Shodan, Censys, crt.sh, etc.)',
    inputsFrom: [],
    outputsTo: ['zap_passive', 'nuclei_info', 'nvd_kev', 'scoring', 'corroboration'],
  },
  zap_passive: {
    phases: ['recon'],
    role: 'Passive web spider — discovers web app structure, links, forms without active testing',
    inputsFrom: ['passive_osint'],
    outputsTo: ['zap_active', 'nuclei_info', 'api_security'],
  },
  zap_active: {
    phases: ['enumeration', 'vulnerability_assessment'],
    role: 'Active DAST scanner — OWASP Top 10 testing, AJAX spider, authenticated scanning',
    inputsFrom: ['zap_passive', 'passive_osint', 'api_security'],
    outputsTo: ['corroboration', 'scoring', 'metasploit', 'detection_rules'],
  },
  nuclei_info: {
    phases: ['recon', 'enumeration'],
    role: 'Info/low template scanning — tech stack fingerprinting, service enumeration',
    inputsFrom: ['passive_osint', 'zap_passive'],
    outputsTo: ['nuclei_vuln', 'zap_active', 'scoring'],
  },
  nuclei_vuln: {
    phases: ['vulnerability_assessment'],
    role: 'High/critical template scanning — CVE detection, misconfiguration discovery',
    inputsFrom: ['nuclei_info', 'passive_osint'],
    outputsTo: ['corroboration', 'scoring', 'metasploit', 'detection_rules'],
  },
  nuclei_critical: {
    phases: ['vulnerability_assessment'],
    role: 'Critical-only templates — RCE, auth bypass, SSRF, critical misconfigs',
    inputsFrom: ['nuclei_info'],
    outputsTo: ['metasploit', 'corroboration', 'scoring'],
  },
  metasploit: {
    phases: ['exploitation', 'post_exploitation'],
    role: 'Exploit execution and post-exploitation modules',
    inputsFrom: ['nuclei_vuln', 'zap_active', 'nvd_kev', 'passive_osint'],
    outputsTo: ['sliver_c2', 'caldera', 'corroboration', 'scoring'],
  },
  sliver_c2: {
    phases: ['exploitation', 'post_exploitation'],
    role: 'C2 implant deployment and session management via mTLS/HTTPS/DNS',
    inputsFrom: ['metasploit', 'caldera'],
    outputsTo: ['caldera', 'corroboration', 'scoring', 'detection_rules'],
  },
  caldera: {
    phases: ['exploitation', 'post_exploitation'],
    role: 'Adversary emulation — multi-step operations with ATT&CK-mapped abilities',
    inputsFrom: ['metasploit', 'sliver_c2', 'passive_osint'],
    outputsTo: ['corroboration', 'scoring', 'detection_rules'],
  },
  atomic_red_team: {
    phases: ['recon', 'exploitation', 'post_exploitation', 'reporting'],
    role: 'ATT&CK-mapped atomic tests for technique validation and detection gap analysis',
    inputsFrom: ['caldera', 'metasploit', 'sliver_c2'],
    outputsTo: ['detection_rules', 'corroboration', 'scoring'],
  },
  gophish: {
    phases: ['exploitation'],
    role: 'Social engineering campaigns — phishing, credential harvesting, awareness testing',
    inputsFrom: ['passive_osint'],
    outputsTo: ['metasploit', 'sliver_c2', 'corroboration'],
  },
  bloodhound: {
    phases: ['post_exploitation'],
    role: 'AD attack path discovery — privilege escalation paths, Kerberoasting targets',
    inputsFrom: ['caldera', 'metasploit'],
    outputsTo: ['caldera', 'scoring', 'corroboration'],
  },
  api_security: {
    phases: ['enumeration', 'vulnerability_assessment'],
    role: 'API security testing — OpenAPI/GraphQL/SOAP spec import and targeted testing',
    inputsFrom: ['zap_passive', 'nuclei_info'],
    outputsTo: ['zap_active', 'corroboration', 'scoring'],
  },
  nvd_kev: {
    phases: ['vulnerability_assessment'],
    role: 'CVE matching against NVD and CISA KEV catalog for known exploited vulnerabilities',
    inputsFrom: ['passive_osint', 'nuclei_info'],
    outputsTo: ['metasploit', 'corroboration', 'scoring'],
  },
  corroboration: {
    phases: ['vulnerability_assessment', 'reporting'],
    role: 'Cross-source finding validation — reduces false positives by 30-40%',
    inputsFrom: ['zap_active', 'nuclei_vuln', 'nuclei_critical', 'metasploit', 'caldera', 'sliver_c2', 'atomic_red_team', 'passive_osint'],
    outputsTo: ['scoring'],
  },
  scoring: {
    phases: ['reporting'],
    role: 'Hybrid Risk/CVSS hybrid risk scoring with all collected intelligence',
    inputsFrom: ['corroboration', 'zap_active', 'nuclei_vuln', 'metasploit', 'caldera', 'sliver_c2', 'atomic_red_team', 'passive_osint'],
    outputsTo: [],
  },
  detection_rules: {
    phases: ['reporting'],
    role: 'Detection rule validation — test SIEM/EDR rules against atomic test results',
    inputsFrom: ['atomic_red_team', 'caldera', 'sliver_c2', 'zap_active', 'nuclei_vuln'],
    outputsTo: [],
  },
  amass: {
    phases: ['recon', 'enumeration'],
    role: 'Subdomain enumeration — passive OSINT, active DNS brute-force, zone transfers, cert transparency scraping. Discovers additional attack surface beyond initial scope.',
    inputsFrom: ['passive_osint'],
    outputsTo: ['nmap', 'service_fingerprinter', 'zap_passive', 'nuclei_info', 'scoring'],
  },
  nmap: {
    phases: ['recon', 'enumeration'],
    role: 'Port scanning and service detection — SYN/TCP/UDP scanning, OS fingerprinting, version detection, NSE script execution. Identifies open ports and running services on discovered hosts.',
    inputsFrom: ['passive_osint', 'amass'],
    outputsTo: ['service_fingerprinter', 'nuclei_info', 'nuclei_vuln', 'metasploit', 'nvd_kev', 'scoring'],
  },
  service_fingerprinter: {
    phases: ['enumeration'],
    role: 'Protocol-specific service fingerprinting — SSH, SMTP, FTP, SNMP, RDP, SMB, LDAP, Telnet, MySQL, PostgreSQL, MSSQL, Redis, MongoDB, VNC. Extracts banners, versions, security flags, default credential checks, and risk indicators.',
    inputsFrom: ['nmap', 'passive_osint', 'amass'],
    outputsTo: ['nuclei_vuln', 'metasploit', 'nvd_kev', 'corroboration', 'scoring'],
  },
};

// ─── Cross-Module Finding Correlator ─────────────────────────────────

/**
 * Correlates findings across tools by matching on host, CVE, CWE,
 * port/service, and ATT&CK technique. Returns enriched findings
 * with cross-references and corroboration status.
 */
export function correlateFindings(findings: PipelineFinding[]): PipelineFinding[] {
  const byHost = new Map<string, PipelineFinding[]>();
  const byCve = new Map<string, PipelineFinding[]>();
  const byCwe = new Map<string, PipelineFinding[]>();
  const byTechnique = new Map<string, PipelineFinding[]>();
  const byPortService = new Map<string, PipelineFinding[]>();

  // Index findings
  for (const f of findings) {
    const hostKey = f.host.toLowerCase();
    if (!byHost.has(hostKey)) byHost.set(hostKey, []);
    byHost.get(hostKey)!.push(f);

    if (f.cveId) {
      const cveKey = f.cveId.toUpperCase();
      if (!byCve.has(cveKey)) byCve.set(cveKey, []);
      byCve.get(cveKey)!.push(f);
    }

    if (f.cweId) {
      if (!byCwe.has(f.cweId)) byCwe.set(f.cweId, []);
      byCwe.get(f.cweId)!.push(f);
    }

    if (f.attackTechnique) {
      if (!byTechnique.has(f.attackTechnique)) byTechnique.set(f.attackTechnique, []);
      byTechnique.get(f.attackTechnique)!.push(f);
    }

    if (f.port) {
      const psKey = `${hostKey}:${f.port}`;
      if (!byPortService.has(psKey)) byPortService.set(psKey, []);
      byPortService.get(psKey)!.push(f);
    }
  }

  // Correlate
  return findings.map(f => {
    const crossRefs = new Set<string>();
    const corroboratingTools = new Set<ToolModule>();

    // Same CVE on same host from different tools
    if (f.cveId) {
      const cveMatches = byCve.get(f.cveId.toUpperCase()) || [];
      for (const m of cveMatches) {
        if (m.id !== f.id && m.tool !== f.tool && m.host.toLowerCase() === f.host.toLowerCase()) {
          crossRefs.add(m.id);
          corroboratingTools.add(m.tool);
        }
      }
    }

    // Same CWE on same host from different tools
    if (f.cweId) {
      const cweMatches = byCwe.get(f.cweId) || [];
      for (const m of cweMatches) {
        if (m.id !== f.id && m.tool !== f.tool && m.host.toLowerCase() === f.host.toLowerCase()) {
          crossRefs.add(m.id);
          corroboratingTools.add(m.tool);
        }
      }
    }

    // Same ATT&CK technique from different tools
    if (f.attackTechnique) {
      const techMatches = byTechnique.get(f.attackTechnique) || [];
      for (const m of techMatches) {
        if (m.id !== f.id && m.tool !== f.tool) {
          crossRefs.add(m.id);
          corroboratingTools.add(m.tool);
        }
      }
    }

    // Same port/service on same host from different tools
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
      confidence: corroboratingTools.size > 0
        ? Math.min(100, f.confidence + (corroboratingTools.size * 10))
        : f.confidence,
    };
  });
}

// ─── Phase Transition Logic ──────────────────────────────────────────

/**
 * Determines which tools should run in a given phase based on
 * available findings from prior phases and target configuration.
 */
export function getPhaseTools(
  phase: PipelinePhase,
  target: PipelineTarget,
  priorFindings: PipelineFinding[]
): { tool: ToolModule; reason: string; priority: number }[] {
  const stage = PIPELINE_STAGES.find(s => s.phase === phase);
  if (!stage) return [];

  const tools: { tool: ToolModule; reason: string; priority: number }[] = [];

  for (const tool of stage.tools) {
    const toolConfig = TOOL_PHASE_MATRIX[tool];
    if (!toolConfig.phases.includes(phase)) continue;

    let reason = toolConfig.role;
    let priority = 50;

    // Boost priority based on prior findings
    switch (tool) {
      case 'zap_active': {
        const webAssets = priorFindings.filter(f => f.type === 'asset' && (f.evidence?.assetType === 'url' || f.evidence?.assetType === 'web_app'));
        if (webAssets.length > 0) {
          priority = 90;
          reason = `${webAssets.length} web applications discovered in recon — DAST scanning recommended`;
        }
        if (target.openApiSpecUrl || target.graphqlEndpoint) {
          priority = 95;
          reason = 'API spec available — targeted API security testing recommended';
        }
        break;
      }
      case 'nuclei_vuln':
      case 'nuclei_critical': {
        const services = priorFindings.filter(f => f.evidence?.ports || f.evidence?.service);
        if (services.length > 0) {
          priority = 85;
          reason = `${services.length} services enumerated — template-based vulnerability scanning recommended`;
        }
        break;
      }
      case 'metasploit': {
        const vulns = priorFindings.filter(f => f.type === 'vulnerability' && (f.severity === 'critical' || f.severity === 'high'));
        if (vulns.length > 0) {
          priority = 95;
          reason = `${vulns.length} high/critical vulnerabilities found — exploit execution recommended`;
        }
        break;
      }
      case 'sliver_c2': {
        const exploitResults = priorFindings.filter(f => f.type === 'exploit_result' && f.evidence?.sessionId);
        if (exploitResults.length > 0) {
          priority = 90;
          reason = `${exploitResults.length} successful exploits — C2 implant deployment recommended`;
        }
        break;
      }
      case 'caldera': {
        const sessions = priorFindings.filter(f => f.type === 'c2_session' || f.type === 'exploit_result');
        if (sessions.length > 0) {
          priority = 85;
          reason = `${sessions.length} active sessions — adversary emulation operations recommended`;
        }
        break;
      }
      case 'atomic_red_team': {
        if (phase === 'recon') {
          priority = 40;
          reason = 'Recon-phase atomic tests (T1595, T1592) for attack surface validation';
        } else if (phase === 'reporting') {
          priority = 80;
          reason = 'Detection gap analysis — validate SIEM/EDR rules against atomic tests';
        } else {
          const techniques = new Set(priorFindings.map(f => f.attackTechnique).filter(Boolean));
          priority = 70;
          reason = `${techniques.size} ATT&CK techniques observed — atomic validation tests recommended`;
        }
        break;
      }
      case 'gophish': {
        const emails = priorFindings.filter(f => f.evidence?.emails || f.evidence?.assetType === 'email');
        if (emails.length > 0) {
          priority = 75;
          reason = `Employee emails discovered — social engineering campaign recommended`;
        }
        break;
      }
      case 'corroboration': {
        const multiSourceFindings = priorFindings.filter(f => f.corroborated);
        priority = 90;
        reason = `Cross-source validation of ${priorFindings.length} findings from ${new Set(priorFindings.map(f => f.tool)).size} tools`;
        break;
      }
      case 'scoring': {
        priority = 95;
        reason = 'Hybrid Risk/CVSS hybrid risk scoring with all collected intelligence';
        break;
      }
      case 'amass': {
        if (phase === 'recon') {
          priority = 80;
          reason = 'Subdomain enumeration via passive OSINT, cert transparency, and DNS brute-force';
        } else {
          const subdomains = priorFindings.filter(f => f.evidence?.assetType === 'subdomain' || f.evidence?.assetType === 'domain');
          if (subdomains.length > 0) {
            priority = 85;
            reason = `${subdomains.length} domains discovered — active subdomain enumeration recommended for deeper coverage`;
          } else {
            priority = 70;
            reason = 'Active subdomain enumeration to expand attack surface';
          }
        }
        break;
      }
      case 'nmap': {
        if (phase === 'recon') {
          priority = 75;
          reason = 'Quick port scan for initial service discovery on known hosts';
        } else {
          const hosts = priorFindings.filter(f => f.type === 'asset' && (f.evidence?.assetType === 'ip' || f.evidence?.assetType === 'subdomain'));
          if (hosts.length > 0) {
            priority = 90;
            reason = `${hosts.length} hosts discovered — port scanning and service detection recommended`;
          } else {
            priority = 70;
            reason = 'Port scanning and service detection on target hosts';
          }
        }
        break;
      }
      case 'service_fingerprinter': {
        const openPorts = priorFindings.filter(f => f.evidence?.ports || (f.port && f.type === 'asset'));
        if (openPorts.length > 0) {
          priority = 85;
          reason = `${openPorts.length} open ports discovered — protocol-specific fingerprinting recommended for SSH, SMTP, FTP, SNMP, RDP, SMB, databases`;
        } else {
          priority = 60;
          reason = 'Protocol-specific service fingerprinting for admin port enumeration';
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

// ─── Finding Converters ──────────────────────────────────────────────

/**
 * Convert ZAP scan findings to pipeline findings format.
 */
export function convertZapFindings(zapAlerts: any[], phase: PipelinePhase): PipelineFinding[] {
  return (zapAlerts || []).map((alert, i) => ({
    id: `zap-${phase}-${alert.alertRef || i}`,
    phase,
    tool: phase === 'recon' ? 'zap_passive' as ToolModule : 'zap_active' as ToolModule,
    type: 'vulnerability' as const,
    severity: mapZapRisk(alert.risk || alert.riskcode),
    title: alert.alert || alert.name || 'Unknown Alert',
    description: alert.description || '',
    host: alert.url || alert.uri || '',
    port: extractPort(alert.url || alert.uri || ''),
    cveId: alert.cveId || undefined,
    cweId: alert.cweid ? `CWE-${alert.cweid}` : undefined,
    attackTechnique: mapCweToAttack(alert.cweid),
    confidence: mapZapConfidence(alert.confidence),
    evidence: {
      solution: alert.solution,
      reference: alert.reference,
      param: alert.param,
      attack: alert.attack,
      evidence: alert.evidence,
      pluginId: alert.pluginid || alert.pluginId,
      wascid: alert.wascid,
    },
    timestamp: Date.now(),
    crossRefs: [],
    corroborated: false,
    corroboratingTools: [],
  }));
}

/**
 * Convert Nuclei scan findings to pipeline findings format.
 */
export function convertNucleiFindings(nucleiResults: any[], phase: PipelinePhase): PipelineFinding[] {
  const toolMap: Record<string, ToolModule> = {
    'info': 'nuclei_info',
    'low': 'nuclei_info',
    'medium': 'nuclei_vuln',
    'high': 'nuclei_vuln',
    'critical': 'nuclei_critical',
  };

  return (nucleiResults || []).map((result, i) => ({
    id: `nuclei-${phase}-${result.templateId || i}`,
    phase,
    tool: toolMap[result.severity?.toLowerCase() || 'info'] || 'nuclei_info',
    type: result.severity === 'critical' || result.severity === 'high' ? 'vulnerability' as const : 'misconfiguration' as const,
    severity: (result.severity?.toLowerCase() || 'info') as PipelineFinding['severity'],
    title: result.name || result.templateId || 'Unknown Template Match',
    description: result.description || '',
    host: result.host || result.matched || '',
    port: result.port || extractPort(result.matched || ''),
    cveId: result.cveId || extractCve(result.tags),
    cweId: result.cweId || undefined,
    attackTechnique: result.attackTechnique || mapCweToAttack(result.cweId),
    confidence: result.severity === 'critical' ? 90 : result.severity === 'high' ? 80 : 60,
    evidence: {
      templateId: result.templateId,
      tags: result.tags,
      matcher: result.matcher,
      extractedResults: result.extractedResults,
      curl: result.curl,
      severity: result.severity,
    },
    timestamp: Date.now(),
    crossRefs: [],
    corroborated: false,
    corroboratingTools: [],
  }));
}

/**
 * Convert Sliver C2 session events to pipeline findings format.
 */
export function convertSliverFindings(sessions: any[], phase: PipelinePhase): PipelineFinding[] {
  return (sessions || []).map((session, i) => ({
    id: `sliver-${phase}-${session.id || i}`,
    phase,
    tool: 'sliver_c2' as ToolModule,
    type: 'c2_session' as const,
    severity: 'critical' as const,
    title: `C2 Session Established: ${session.hostname || session.remoteAddress || 'Unknown'}`,
    description: `Active implant session via ${session.transport || 'unknown'} protocol. OS: ${session.os || 'unknown'}, Arch: ${session.arch || 'unknown'}`,
    host: session.remoteAddress || session.hostname || '',
    port: session.port,
    attackTechnique: session.transport === 'dns' ? 'T1071.004' : session.transport === 'http' || session.transport === 'https' ? 'T1071.001' : 'T1071',
    confidence: 100,
    evidence: {
      sessionId: session.id,
      transport: session.transport,
      os: session.os,
      arch: session.arch,
      hostname: session.hostname,
      username: session.username,
      pid: session.pid,
      implantName: session.name,
    },
    timestamp: session.lastCheckin || Date.now(),
    crossRefs: [],
    corroborated: false,
    corroboratingTools: [],
  }));
}

/**
 * Convert Atomic Red Team test results to pipeline findings format.
 */
export function convertAtomicFindings(executions: any[], phase: PipelinePhase): PipelineFinding[] {
  return (executions || []).map((exec, i) => ({
    id: `atomic-${phase}-${exec.id || i}`,
    phase,
    tool: 'atomic_red_team' as ToolModule,
    type: exec.detected === false ? 'detection_gap' as const : 'vulnerability' as const,
    severity: exec.detected === false ? 'high' as const : 'info' as const,
    title: exec.detected === false
      ? `Detection Gap: ${exec.techniqueName || exec.techniqueId} not detected`
      : `Validated: ${exec.techniqueName || exec.techniqueId} detected by defenses`,
    description: exec.testName || '',
    host: exec.targetHost || 'local',
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
      output: exec.output?.substring(0, 500),
    },
    timestamp: exec.executedAt || Date.now(),
    crossRefs: [],
    corroborated: false,
    corroboratingTools: [],
  }));
}

/**
 * Convert Metasploit exploit results to pipeline findings format.
 */
export function convertMetasploitFindings(jobs: any[], phase: PipelinePhase): PipelineFinding[] {
  return (jobs || []).map((job, i) => ({
    id: `msf-${phase}-${job.id || i}`,
    phase,
    tool: 'metasploit' as ToolModule,
    type: 'exploit_result' as const,
    severity: job.status === 'success' ? 'critical' as const : 'info' as const,
    title: `Exploit ${job.status === 'success' ? 'Successful' : 'Attempted'}: ${job.moduleName || job.module || 'Unknown'}`,
    description: `${job.moduleName || job.module} against ${job.targetHost}:${job.targetPort}`,
    host: job.targetHost || '',
    port: job.targetPort,
    cveId: job.cveId,
    attackTechnique: 'T1190',
    confidence: job.status === 'success' ? 100 : 30,
    evidence: {
      module: job.module,
      moduleName: job.moduleName,
      sessionId: job.sessionId,
      sessionType: job.sessionType,
      payload: job.payload,
      status: job.status,
      lhost: job.lhost,
      lport: job.lport,
    },
    timestamp: job.completedAt || job.startedAt || Date.now(),
    crossRefs: [],
    corroborated: false,
    corroboratingTools: [],
  }));
}

/**
 * Convert passive OSINT observations to pipeline findings format.
 */
export function convertOsintFindings(observations: any[], phase: PipelinePhase): PipelineFinding[] {
  return (observations || []).map((obs, i) => ({
    id: `osint-${phase}-${obs.assetId || i}`,
    phase,
    tool: 'passive_osint' as ToolModule,
    type: 'asset' as const,
    severity: 'info' as const,
    title: `Discovered: ${obs.name || obs.assetId || 'Unknown Asset'}`,
    description: `${obs.assetType} discovered via ${obs.source}`,
    host: obs.ip || obs.name || obs.domain || '',
    port: obs.evidence?.port,
    attackTechnique: obs.assetType === 'subdomain' ? 'T1590.002' : obs.assetType === 'ip' ? 'T1590.004' : undefined,
    confidence: 70,
    evidence: {
      assetType: obs.assetType,
      source: obs.source,
      tags: obs.tags,
      ...obs.evidence,
    },
    timestamp: obs.observedAt?.getTime?.() || Date.now(),
    crossRefs: [],
    corroborated: false,
    corroboratingTools: [],
  }));
}

// ─── Pipeline Summary Generator ──────────────────────────────────────

/**
 * Generate a comprehensive pipeline run summary from all phase results.
 */
export function generatePipelineSummary(
  target: PipelineTarget,
  phaseResults: PipelinePhaseResult[]
): Omit<PipelineRun, 'id' | 'startedAt' | 'completedAt' | 'status'> {
  const allFindings = phaseResults.flatMap(p => p.findings);
  const correlated = correlateFindings(allFindings);

  const findingsBySeverity: Record<string, number> = {};
  const findingsByPhase: Record<PipelinePhase, number> = {} as any;
  const findingsByTool: Record<string, number> = {};
  const techniquesUsed = new Set<string>();
  const tacticsUsed = new Set<string>();

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
      coveragePercent: Math.round((techniquesUsed.size / 200) * 100), // ~200 enterprise techniques
    },
    engagementId: target.engagementId,
  };
}

// ─── Helper Functions ────────────────────────────────────────────────

function mapZapRisk(risk: string | number): PipelineFinding['severity'] {
  const r = typeof risk === 'number' ? risk : parseInt(risk, 10);
  if (r >= 3) return 'high';
  if (r === 2) return 'medium';
  if (r === 1) return 'low';
  return 'info';
}

function mapZapConfidence(confidence: string | number): number {
  const c = typeof confidence === 'number' ? confidence : parseInt(confidence, 10);
  if (c >= 3) return 90;
  if (c === 2) return 70;
  if (c === 1) return 40;
  return 20;
}

function extractPort(url: string): number | undefined {
  try {
    const u = new URL(url);
    if (u.port) return parseInt(u.port, 10);
    return u.protocol === 'https:' ? 443 : 80;
  } catch {
    return undefined;
  }
}

function extractCve(tags: string | string[] | undefined): string | undefined {
  if (!tags) return undefined;
  const tagStr = Array.isArray(tags) ? tags.join(',') : tags;
  const match = tagStr.match(/CVE-\d{4}-\d+/i);
  return match ? match[0].toUpperCase() : undefined;
}

/**
 * Maps common CWE IDs to MITRE ATT&CK techniques for web vulnerabilities.
 */
function mapCweToAttack(cweId: string | number | undefined): string | undefined {
  if (!cweId) return undefined;
  const id = typeof cweId === 'string' ? parseInt(cweId.replace(/\D/g, ''), 10) : cweId;
  
  const CWE_TO_ATTACK: Record<number, string> = {
    79: 'T1059.007',    // XSS → JavaScript execution
    89: 'T1190',        // SQL Injection → Exploit Public-Facing App
    94: 'T1059',        // Code Injection → Command/Script Execution
    78: 'T1059',        // OS Command Injection
    22: 'T1083',        // Path Traversal → File Discovery
    352: 'T1185',       // CSRF → Browser Session Hijacking
    918: 'T1190',       // SSRF → Exploit Public-Facing App
    287: 'T1078',       // Auth Bypass → Valid Accounts
    306: 'T1078',       // Missing Auth → Valid Accounts
    502: 'T1059',       // Deserialization → Execution
    611: 'T1190',       // XXE → Exploit Public-Facing App
    434: 'T1105',       // File Upload → Ingress Tool Transfer
    200: 'T1005',       // Info Exposure → Data from Local System
    311: 'T1557',       // Missing Encryption → MITM
    319: 'T1557',       // Cleartext Transmission → MITM
    798: 'T1552.001',   // Hardcoded Credentials → Unsecured Credentials
    532: 'T1005',       // Log Info Exposure → Data Collection
    601: 'T1566.002',   // Open Redirect → Phishing Link
    1021: 'T1185',      // Clickjacking → Browser Session Hijacking
    16: 'T1562.001',    // Configuration → Disable Security Tools
    693: 'T1562',       // Protection Mechanism Failure → Impair Defenses
  };

  return CWE_TO_ATTACK[id];
}

// ─── Discovery Coverage Extensions ──────────────────────────────────

/**
 * Additional discovery coverage sources from ZAP and Nuclei.
 * These extend the existing passive OSINT coverage with active scanning data.
 */
export const ACTIVE_DISCOVERY_SOURCES = {
  zap: {
    coversPriorities: [3, 4, 9],  // Port Enum, Web/API Stack, Defensive Posture
    coverageTags: ['web_app', 'api', 'technology', 'framework', 'waf', 'security_header', 'port', 'service'],
    description: 'DAST scanner adds web application structure, API endpoints, and security header analysis',
  },
  nuclei: {
    coversPriorities: [3, 4, 8, 9, 10],  // Port Enum, Web/API, Cloud Misconfig, Defensive Posture, Code Leaks
    coverageTags: ['technology', 'service', 'cloud', 'misconfiguration', 'config_leak', 'security_header'],
    description: 'Template scanner adds service fingerprinting, cloud misconfiguration detection, and config leak discovery',
  },
  sliver: {
    coversPriorities: [],  // C2 doesn't contribute to discovery
    coverageTags: [],
    description: 'C2 framework — contributes to exploitation and post-exploitation phases only',
  },
  atomic: {
    coversPriorities: [9],  // Defensive Posture (detection gap analysis)
    coverageTags: ['edr', 'siem', 'detection_gap'],
    description: 'Adversary validation tests reveal detection gaps in defensive tooling',
  },
  amass: {
    coversPriorities: [1, 2, 5],  // Subdomain Enum, DNS Records, Network Topology
    coverageTags: ['subdomain', 'dns', 'ip', 'asn', 'certificate', 'network_topology'],
    description: 'Subdomain enumeration via passive OSINT, cert transparency, DNS brute-force, and zone transfers',
  },
  nmap: {
    coversPriorities: [3, 4, 6],  // Port Enum, Service/Version, OS Fingerprinting
    coverageTags: ['port', 'service', 'version', 'os', 'banner', 'nse_script', 'vulnerability'],
    description: 'Port scanning, service detection, OS fingerprinting, and NSE script execution',
  },
  service_fingerprinter: {
    coversPriorities: [3, 4, 7],  // Port Enum, Service/Version, Admin Services
    coverageTags: ['protocol', 'banner', 'version', 'security_flag', 'default_cred', 'admin_service', 'risk_indicator'],
    description: 'Protocol-specific fingerprinting for SSH, SMTP, FTP, SNMP, RDP, SMB, LDAP, databases with security flag analysis',
  },
};

// ─── Corroboration Source Extensions ─────────────────────────────────

/**
 * Additional corroboration source weights for the new tools.
 * These extend the existing SOURCE_WEIGHTS in corroboration-engine.ts.
 */
export const EXTENDED_SOURCE_WEIGHTS: Record<string, number> = {
  zap_passive: 0.65,
  zap_active: 0.85,
  nuclei_info: 0.60,
  nuclei_vuln: 0.80,
  nuclei_critical: 0.90,
  sliver_c2: 0.95,
  atomic_red_team: 0.90,
  metasploit: 0.95,
  caldera: 0.90,
  gophish: 0.70,
  bloodhound: 0.85,
  amass: 0.75,
  nmap: 0.85,
  service_fingerprinter: 0.80,
};

// ─── Engagement Timeline Event Generators ────────────────────────────

/**
 * Generate timeline events from pipeline findings for the engagement timeline.
 */
export function generateTimelineEvents(findings: PipelineFinding[]): {
  timestamp: number;
  phase: string;
  source: string;
  severity: string;
  title: string;
  description: string;
  icon: string;
  color: string;
  status: string;
  details: Record<string, any>;
}[] {
  const phaseToKillChain: Record<PipelinePhase, string> = {
    recon: 'reconnaissance',
    enumeration: 'reconnaissance',
    vulnerability_assessment: 'weaponization',
    exploitation: 'exploitation',
    post_exploitation: 'command_control',
    reporting: 'actions_on_objectives',
  };

  const toolIcons: Record<string, string> = {
    zap_passive: 'Globe',
    zap_active: 'Shield',
    nuclei_info: 'Search',
    nuclei_vuln: 'AlertTriangle',
    nuclei_critical: 'AlertOctagon',
    metasploit: 'Crosshair',
    sliver_c2: 'Radio',
    caldera: 'Flame',
    atomic_red_team: 'Atom',
    gophish: 'Mail',
    passive_osint: 'Eye',
    bloodhound: 'GitBranch',
    corroboration: 'CheckCircle',
    scoring: 'BarChart',
    detection_rules: 'FileSearch',
    api_security: 'Lock',
    nvd_kev: 'Database',
    amass: 'Network',
    nmap: 'Scan',
    service_fingerprinter: 'Fingerprint',
  };

  const severityColors: Record<string, string> = {
    critical: 'text-red-500',
    high: 'text-orange-500',
    medium: 'text-yellow-500',
    low: 'text-blue-500',
    info: 'text-slate-400',
  };

  return findings.map(f => ({
    timestamp: f.timestamp,
    phase: phaseToKillChain[f.phase] || f.phase,
    source: f.tool,
    severity: f.severity,
    title: f.title,
    description: f.description,
    icon: toolIcons[f.tool] || 'Activity',
    color: severityColors[f.severity] || 'text-slate-400',
    status: f.type === 'exploit_result' ? (f.confidence >= 80 ? 'success' : 'failed') : 'info',
    details: {
      ...f.evidence,
      crossRefs: f.crossRefs,
      corroborated: f.corroborated,
      corroboratingTools: f.corroboratingTools,
    },
  }));
}

// ─── Nmap / Amass / Service Fingerprinter Finding Converters ────────

/**
 * Convert Nmap scan results to pipeline findings format.
 * Produces one finding per open port per host.
 */
export function convertNmapFindings(
  hosts: Array<{
    host: string;
    ports: Array<{
      port: number;
      protocol: string;
      service: string | null;
      version: string | null;
      banner: string | null;
      serviceConfidence: number;
      scripts: Array<{ id: string; output: string }>;
    }>;
    os: string | null;
    tags: string[];
    nmapVersion: string;
    scanRunId: string;
    policyProfile: string;
  }>,
  phase: PipelinePhase
): PipelineFinding[] {
  const findings: PipelineFinding[] = [];
  for (const host of hosts) {
    for (const port of host.ports) {
      const cveMatches = port.scripts
        .flatMap(s => (s.output.match(/CVE-\d{4}-\d{4,}/gi) || []))
        .map(c => c.toUpperCase());
      const hasCve = cveMatches.length > 0;
      findings.push({
        id: `nmap-${phase}-${host.host}-${port.port}-${port.protocol}`,
        phase,
        tool: 'nmap' as ToolModule,
        type: hasCve ? 'vulnerability' : 'asset',
        severity: hasCve ? 'medium' : 'info',
        title: hasCve
          ? `Nmap CVE detected on ${host.host}:${port.port} (${port.service || port.protocol})`
          : `Open port ${port.port}/${port.protocol} on ${host.host} — ${port.service || 'unknown'}`,
        description: port.version
          ? `Service: ${port.service || 'unknown'}, Version: ${port.version}${host.os ? `, OS: ${host.os}` : ''}`
          : `Service: ${port.service || 'unknown'}${host.os ? `, OS: ${host.os}` : ''}`,
        host: host.host,
        port: port.port,
        cveId: cveMatches[0] || undefined,
        attackTechnique: 'T1046', // Network Service Discovery
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
          assetType: 'port',
          ports: [port.port],
        },
        timestamp: Date.now(),
        crossRefs: [],
        corroborated: false,
        corroboratingTools: [],
      });
    }
  }
  return findings;
}

/**
 * Convert Amass subdomain enumeration results to pipeline findings format.
 * Produces one finding per discovered subdomain.
 */
export function convertAmassFindings(
  subdomains: Array<{
    type: 'subdomain';
    name: string;
    domain: string;
    ips: string[];
    asns: number[];
    sources: string[];
    tag: string;
    discoveredAt: number;
    tool: 'amass';
    mode: string;
  }>,
  phase: PipelinePhase
): PipelineFinding[] {
  return subdomains.map((sub, i) => ({
    id: `amass-${phase}-${sub.name}-${i}`,
    phase,
    tool: 'amass' as ToolModule,
    type: 'asset' as const,
    severity: 'info' as const,
    title: `Subdomain discovered: ${sub.name}`,
    description: `${sub.name} (${sub.ips.length} IPs, ${sub.sources.length} sources, tag: ${sub.tag}, mode: ${sub.mode})`,
    host: sub.ips[0] || sub.name,
    attackTechnique: 'T1590.002', // Gather Victim Network Information: DNS
    confidence: sub.tag === 'cert' ? 90 : sub.tag === 'dns' ? 85 : 70,
    evidence: {
      assetType: 'subdomain',
      subdomain: sub.name,
      domain: sub.domain,
      ips: sub.ips,
      asns: sub.asns,
      sources: sub.sources,
      tag: sub.tag,
      mode: sub.mode,
    },
    timestamp: sub.discoveredAt || Date.now(),
    crossRefs: [],
    corroborated: false,
    corroboratingTools: [],
  }));
}

/**
 * Convert Service Fingerprinter results to pipeline findings format.
 * Produces one finding per fingerprinted service.
 */
export function convertFingerprintFindings(
  results: Array<{
    protocol: string;
    host: string;
    port: number;
    banner: string | null;
    version: string | null;
    product: string | null;
    os: string | null;
    securityFlags: Record<string, any>;
    riskIndicators: Array<{ type: string; severity: string; description: string }>;
    mitreRelevance: string[];
    potentialCves: string[];
    error: string | null;
  }>,
  phase: PipelinePhase
): PipelineFinding[] {
  return results
    .filter(r => !r.error)
    .map((r, i) => {
      const hasRisks = r.riskIndicators.length > 0;
      const hasCves = r.potentialCves.length > 0;
      const severity: PipelineFinding['severity'] = hasCves
        ? 'medium'
        : hasRisks
          ? r.riskIndicators.some(ri => ri.severity === 'critical' || ri.severity === 'high') ? 'medium' : 'low'
          : 'info';
      return {
        id: `fingerprint-${phase}-${r.host}-${r.port}-${r.protocol}-${i}`,
        phase,
        tool: 'service_fingerprinter' as ToolModule,
        type: (hasCves || hasRisks ? 'misconfiguration' : 'asset') as PipelineFinding['type'],
        severity,
        title: hasRisks
          ? `${r.protocol.toUpperCase()} risk on ${r.host}:${r.port} — ${r.riskIndicators[0]?.description || 'security issue'}`
          : `${r.protocol.toUpperCase()} service fingerprinted on ${r.host}:${r.port}`,
        description: [
          r.product && `Product: ${r.product}`,
          r.version && `Version: ${r.version}`,
          r.banner && `Banner: ${r.banner.substring(0, 200)}`,
          r.os && `OS: ${r.os}`,
          r.riskIndicators.length > 0 && `Risks: ${r.riskIndicators.map(ri => ri.description).join('; ')}`,
        ].filter(Boolean).join(', '),
        host: r.host,
        port: r.port,
        cveId: r.potentialCves[0] || undefined,
        attackTechnique: r.mitreRelevance[0] || 'T1046',
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
          assetType: 'service',
          ports: [r.port],
        },
        timestamp: Date.now(),
        crossRefs: [],
        corroborated: false,
        corroboratingTools: [],
      };
    });
}

// ─── Exports ─────────────────────────────────────────────────────────

export {
  PIPELINE_STAGES as pipelineStages,
  TOOL_PHASE_MATRIX as toolPhaseMatrix,
};
