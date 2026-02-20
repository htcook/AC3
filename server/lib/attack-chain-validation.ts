/**
 * Attack Chain Validation
 * 
 * Identifies and validates multi-step attack chains where individually
 * low/medium-severity findings combine to create critical impact paths.
 * 
 * Example chains:
 * - Info disclosure → credential extraction → lateral movement → domain admin
 * - SSRF → internal service access → RCE on internal host
 * - Subdomain takeover → phishing → credential theft → VPN access
 * 
 * Maps chains to MITRE ATT&CK kill chain phases for reporting.
 * 
 * @module attack-chain-validation
 */

// ─── Types ─────────────────────────────────────────────────────────

export type ChainPhase =
  | "reconnaissance"
  | "initial_access"
  | "execution"
  | "persistence"
  | "privilege_escalation"
  | "defense_evasion"
  | "credential_access"
  | "discovery"
  | "lateral_movement"
  | "collection"
  | "exfiltration"
  | "impact";

export interface ChainLink {
  findingId: string;
  title: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  phase: ChainPhase;
  attackTechnique: string;    // MITRE ATT&CK technique ID (e.g., "T1190")
  target: string;
  port: number | null;
  prerequisite: string | null; // What this link needs from the previous link
  provides: string[];          // What this link enables for the next link
  validated: boolean;
}

export interface AttackChain {
  id: string;
  name: string;
  description: string;
  links: ChainLink[];
  chainSeverity: "critical" | "high" | "medium" | "low";
  chainScore: number;          // 0-10, based on combined impact
  impactDescription: string;
  killChainCoverage: ChainPhase[];
  mitreTechniques: string[];
  feasibility: "confirmed" | "likely" | "possible" | "theoretical";
  businessImpact: string;
}

export interface ChainPattern {
  id: string;
  name: string;
  description: string;
  phases: ChainPhase[];
  requiredCapabilities: string[]; // What findings must provide
  minimumLinks: number;
  severityBoost: number;          // How much to boost combined severity (0-4)
  businessImpact: string;
}

export interface ChainAnalysisResult {
  chains: AttackChain[];
  totalChainsFound: number;
  criticalChains: number;
  highChains: number;
  maxChainLength: number;
  coverageByPhase: Record<ChainPhase, number>;
  summary: string;
}

// ─── Known Attack Chain Patterns ───────────────────────────────────

export const CHAIN_PATTERNS: ChainPattern[] = [
  {
    id: "chain-info-to-rce",
    name: "Information Disclosure to RCE",
    description: "Information leak reveals credentials or internal details enabling remote code execution",
    phases: ["reconnaissance", "credential_access", "initial_access", "execution"],
    requiredCapabilities: ["info_disclosure", "credential_extraction", "code_execution"],
    minimumLinks: 2,
    severityBoost: 3,
    businessImpact: "Full system compromise via chained information disclosure",
  },
  {
    id: "chain-ssrf-to-internal",
    name: "SSRF to Internal Network Access",
    description: "Server-side request forgery enables access to internal services not directly exposed",
    phases: ["initial_access", "discovery", "lateral_movement"],
    requiredCapabilities: ["ssrf", "internal_access", "service_enumeration"],
    minimumLinks: 2,
    severityBoost: 2,
    businessImpact: "Internal network breach via SSRF pivot",
  },
  {
    id: "chain-subdomain-takeover-phishing",
    name: "Subdomain Takeover to Credential Theft",
    description: "Dangling DNS enables subdomain takeover for targeted phishing campaigns",
    phases: ["reconnaissance", "initial_access", "credential_access"],
    requiredCapabilities: ["subdomain_takeover", "phishing_platform", "credential_harvesting"],
    minimumLinks: 2,
    severityBoost: 2,
    businessImpact: "Brand impersonation and credential theft via subdomain takeover",
  },
  {
    id: "chain-privesc-to-domain-admin",
    name: "Privilege Escalation to Domain Admin",
    description: "Local privilege escalation chains to domain administrator access",
    phases: ["initial_access", "privilege_escalation", "credential_access", "lateral_movement"],
    requiredCapabilities: ["local_access", "privilege_escalation", "credential_dumping", "domain_admin"],
    minimumLinks: 3,
    severityBoost: 4,
    businessImpact: "Complete domain compromise via privilege escalation chain",
  },
  {
    id: "chain-exposed-api-data-exfil",
    name: "Exposed API to Data Exfiltration",
    description: "Unauthenticated or weakly authenticated API enables bulk data extraction",
    phases: ["reconnaissance", "initial_access", "collection", "exfiltration"],
    requiredCapabilities: ["api_exposure", "auth_bypass", "data_access"],
    minimumLinks: 2,
    severityBoost: 3,
    businessImpact: "Mass data exfiltration via exposed API endpoints",
  },
  {
    id: "chain-default-creds-lateral",
    name: "Default Credentials to Lateral Movement",
    description: "Default or weak credentials on one service enable pivot to other systems",
    phases: ["initial_access", "credential_access", "lateral_movement"],
    requiredCapabilities: ["default_credentials", "credential_reuse", "network_pivot"],
    minimumLinks: 2,
    severityBoost: 2,
    businessImpact: "Multi-system compromise via credential reuse",
  },
  {
    id: "chain-xss-to-account-takeover",
    name: "XSS to Account Takeover",
    description: "Cross-site scripting enables session hijacking or credential theft",
    phases: ["initial_access", "credential_access", "privilege_escalation"],
    requiredCapabilities: ["xss", "session_hijack", "account_takeover"],
    minimumLinks: 2,
    severityBoost: 2,
    businessImpact: "User account compromise via XSS chain",
  },
  {
    id: "chain-misconfig-to-persistence",
    name: "Misconfiguration to Persistent Access",
    description: "Service misconfiguration enables establishing persistent backdoor access",
    phases: ["initial_access", "execution", "persistence", "defense_evasion"],
    requiredCapabilities: ["misconfiguration", "code_execution", "backdoor_install"],
    minimumLinks: 3,
    severityBoost: 3,
    businessImpact: "Persistent unauthorized access via misconfiguration exploitation",
  },
];

// ─── Finding Capability Mapping ────────────────────────────────────

interface CapabilityMapping {
  keywords: string[];
  capabilities: string[];
  phase: ChainPhase;
}

const CAPABILITY_MAPPINGS: CapabilityMapping[] = [
  { keywords: ["information disclosure", "info leak", "directory listing", "phpinfo", "server-status", "stack trace"], capabilities: ["info_disclosure"], phase: "reconnaissance" },
  { keywords: ["ssrf", "server-side request forgery"], capabilities: ["ssrf", "internal_access"], phase: "initial_access" },
  { keywords: ["subdomain takeover", "dangling dns", "cname"], capabilities: ["subdomain_takeover", "phishing_platform"], phase: "reconnaissance" },
  { keywords: ["rce", "remote code execution", "command injection", "code injection"], capabilities: ["code_execution"], phase: "execution" },
  { keywords: ["sql injection", "sqli"], capabilities: ["data_access", "credential_extraction"], phase: "initial_access" },
  { keywords: ["xss", "cross-site scripting", "reflected xss", "stored xss"], capabilities: ["xss", "session_hijack"], phase: "initial_access" },
  { keywords: ["default credentials", "default password", "weak password"], capabilities: ["default_credentials", "credential_reuse"], phase: "credential_access" },
  { keywords: ["privilege escalation", "privesc", "local privilege"], capabilities: ["privilege_escalation", "local_access"], phase: "privilege_escalation" },
  { keywords: ["credential", "password", "token", "api key", "secret"], capabilities: ["credential_extraction", "credential_harvesting"], phase: "credential_access" },
  { keywords: ["exposed api", "unauthenticated api", "api without auth", "open api"], capabilities: ["api_exposure", "auth_bypass", "data_access"], phase: "initial_access" },
  { keywords: ["lateral movement", "pivot", "network spread"], capabilities: ["network_pivot", "lateral_movement"], phase: "lateral_movement" },
  { keywords: ["misconfiguration", "misconfig", "insecure config"], capabilities: ["misconfiguration"], phase: "initial_access" },
  { keywords: ["backdoor", "webshell", "persistence", "cron job"], capabilities: ["backdoor_install", "persistence"], phase: "persistence" },
  { keywords: ["data exfiltration", "data leak", "bulk download"], capabilities: ["data_access", "exfiltration"], phase: "exfiltration" },
  { keywords: [".env exposure", ".git exposure", "source code leak", "backup file"], capabilities: ["info_disclosure", "credential_extraction"], phase: "reconnaissance" },
  { keywords: ["authentication bypass", "auth bypass", "broken auth"], capabilities: ["auth_bypass", "account_takeover"], phase: "initial_access" },
];

// ─── Core Analysis Functions ───────────────────────────────────────

let chainCounter = 0;

/**
 * Analyze findings to identify potential attack chains.
 */
export function analyzeAttackChains(
  findings: Array<{
    id: string;
    title: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    description: string;
    target: string;
    port: number | null;
    cveId: string | null;
    validated: boolean;
    attackTechnique?: string;
  }>
): ChainAnalysisResult {
  // Step 1: Map findings to capabilities and phases
  const enrichedFindings = findings.map(f => {
    const mapping = findCapabilityMapping(f.title, f.description);
    return {
      ...f,
      capabilities: mapping.capabilities,
      phase: mapping.phase,
      provides: mapping.capabilities,
    };
  });
  
  // Step 2: Match against known chain patterns
  const chains: AttackChain[] = [];
  
  for (const pattern of CHAIN_PATTERNS) {
    const matchedChain = matchChainPattern(pattern, enrichedFindings);
    if (matchedChain) {
      chains.push(matchedChain);
    }
  }
  
  // Step 3: Discover ad-hoc chains (findings on same target that form a kill chain)
  const adHocChains = discoverAdHocChains(enrichedFindings);
  chains.push(...adHocChains);
  
  // Step 4: Deduplicate chains
  const uniqueChains = deduplicateChains(chains);
  
  // Step 5: Build summary
  const criticalChains = uniqueChains.filter(c => c.chainSeverity === "critical").length;
  const highChains = uniqueChains.filter(c => c.chainSeverity === "high").length;
  const maxChainLength = uniqueChains.reduce((max, c) => Math.max(max, c.links.length), 0);
  
  const coverageByPhase: Record<ChainPhase, number> = {
    reconnaissance: 0, initial_access: 0, execution: 0, persistence: 0,
    privilege_escalation: 0, defense_evasion: 0, credential_access: 0,
    discovery: 0, lateral_movement: 0, collection: 0, exfiltration: 0, impact: 0,
  };
  
  for (const chain of uniqueChains) {
    for (const phase of chain.killChainCoverage) {
      coverageByPhase[phase]++;
    }
  }
  
  const summary = uniqueChains.length > 0
    ? `Identified ${uniqueChains.length} attack chain(s): ${criticalChains} critical, ${highChains} high. Longest chain: ${maxChainLength} steps. ${uniqueChains.map(c => c.name).join("; ")}.`
    : "No multi-step attack chains identified from current findings.";
  
  return {
    chains: uniqueChains,
    totalChainsFound: uniqueChains.length,
    criticalChains,
    highChains,
    maxChainLength,
    coverageByPhase,
    summary,
  };
}

/**
 * Get the combined severity for a chain (individual findings may be low but chain is critical).
 */
export function calculateChainSeverity(
  links: ChainLink[],
  pattern?: ChainPattern
): { severity: "critical" | "high" | "medium" | "low"; score: number } {
  if (links.length === 0) return { severity: "low", score: 0 };
  
  // Base: highest individual severity
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const maxIndividual = Math.max(...links.map(l => severityOrder[l.severity]));
  
  // Chain length bonus: longer chains = more impactful
  const lengthBonus = Math.min(2, (links.length - 1) * 0.5);
  
  // Pattern boost
  const patternBoost = pattern ? pattern.severityBoost * 0.5 : 0;
  
  // Validation bonus: validated chains are more credible
  const validatedCount = links.filter(l => l.validated).length;
  const validationBonus = (validatedCount / links.length) * 0.5;
  
  const combinedLevel = Math.min(4, maxIndividual + lengthBonus + patternBoost + validationBonus);
  const score = Math.min(10, combinedLevel * 2.5);
  
  let severity: "critical" | "high" | "medium" | "low";
  if (combinedLevel >= 3.5) severity = "critical";
  else if (combinedLevel >= 2.5) severity = "high";
  else if (combinedLevel >= 1.5) severity = "medium";
  else severity = "low";
  
  return { severity, score: Math.round(score * 10) / 10 };
}

// ─── Internal Functions ────────────────────────────────────────────

function findCapabilityMapping(title: string, description: string): { capabilities: string[]; phase: ChainPhase } {
  const combined = `${title} ${description}`.toLowerCase();
  const allCapabilities: string[] = [];
  let primaryPhase: ChainPhase = "reconnaissance";
  
  for (const mapping of CAPABILITY_MAPPINGS) {
    if (mapping.keywords.some(kw => combined.includes(kw))) {
      allCapabilities.push(...mapping.capabilities);
      primaryPhase = mapping.phase;
    }
  }
  
  return {
    capabilities: Array.from(new Set(allCapabilities)),
    phase: primaryPhase,
  };
}

function matchChainPattern(
  pattern: ChainPattern,
  findings: Array<{
    id: string;
    title: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    target: string;
    port: number | null;
    capabilities: string[];
    phase: ChainPhase;
    provides: string[];
    validated: boolean;
    attackTechnique?: string;
  }>
): AttackChain | null {
  // Check if findings collectively provide the required capabilities
  const allCapabilities = new Set(findings.flatMap(f => f.capabilities));
  const requiredMet = pattern.requiredCapabilities.filter(rc => allCapabilities.has(rc));
  
  if (requiredMet.length < Math.ceil(pattern.requiredCapabilities.length * 0.5)) {
    return null; // Not enough capabilities matched
  }
  
  // Build chain links from matching findings
  const links: ChainLink[] = [];
  const usedFindings = new Set<string>();
  
  for (const phase of pattern.phases) {
    const matchingFinding = findings.find(f =>
      f.phase === phase && !usedFindings.has(f.id)
    );
    
    if (matchingFinding) {
      usedFindings.add(matchingFinding.id);
      links.push({
        findingId: matchingFinding.id,
        title: matchingFinding.title,
        severity: matchingFinding.severity,
        phase,
        attackTechnique: matchingFinding.attackTechnique || mapPhaseToTechnique(phase),
        target: matchingFinding.target,
        port: matchingFinding.port,
        prerequisite: links.length > 0 ? links[links.length - 1].provides.join(", ") : null,
        provides: matchingFinding.provides,
        validated: matchingFinding.validated,
      });
    }
  }
  
  if (links.length < pattern.minimumLinks) {
    return null;
  }
  
  const { severity, score } = calculateChainSeverity(links, pattern);
  const validatedLinks = links.filter(l => l.validated).length;
  const feasibility: AttackChain["feasibility"] =
    validatedLinks === links.length ? "confirmed" :
    validatedLinks > 0 ? "likely" :
    links.length >= 3 ? "possible" : "theoretical";
  
  return {
    id: `chain-${++chainCounter}`,
    name: pattern.name,
    description: pattern.description,
    links,
    chainSeverity: severity,
    chainScore: score,
    impactDescription: pattern.businessImpact,
    killChainCoverage: Array.from(new Set(links.map(l => l.phase))),
    mitreTechniques: Array.from(new Set(links.map(l => l.attackTechnique))),
    feasibility,
    businessImpact: pattern.businessImpact,
  };
}

function discoverAdHocChains(
  findings: Array<{
    id: string;
    title: string;
    severity: "critical" | "high" | "medium" | "low" | "info";
    target: string;
    port: number | null;
    capabilities: string[];
    phase: ChainPhase;
    provides: string[];
    validated: boolean;
    attackTechnique?: string;
  }>
): AttackChain[] {
  const chains: AttackChain[] = [];
  
  // Group findings by target
  const byTarget = new Map<string, typeof findings>();
  for (const f of findings) {
    const existing = byTarget.get(f.target) || [];
    existing.push(f);
    byTarget.set(f.target, existing);
  }
  
  // For each target with 3+ findings across different phases, try to form a chain
  for (const [target, targetFindings] of Array.from(byTarget.entries())) {
    if (targetFindings.length < 2) continue;
    
    const phases = new Set(targetFindings.map(f => f.phase));
    if (phases.size < 2) continue;
    
    // Sort by kill chain order
    const phaseOrder: ChainPhase[] = [
      "reconnaissance", "initial_access", "execution", "persistence",
      "privilege_escalation", "defense_evasion", "credential_access",
      "discovery", "lateral_movement", "collection", "exfiltration", "impact",
    ];
    
    const sorted = [...targetFindings].sort(
      (a, b) => phaseOrder.indexOf(a.phase) - phaseOrder.indexOf(b.phase)
    );
    
    // Take one finding per phase to form the chain
    const usedPhases = new Set<ChainPhase>();
    const links: ChainLink[] = [];
    
    for (const f of sorted) {
      if (usedPhases.has(f.phase)) continue;
      usedPhases.add(f.phase);
      
      links.push({
        findingId: f.id,
        title: f.title,
        severity: f.severity,
        phase: f.phase,
        attackTechnique: f.attackTechnique || mapPhaseToTechnique(f.phase),
        target: f.target,
        port: f.port,
        prerequisite: links.length > 0 ? links[links.length - 1].provides.join(", ") : null,
        provides: f.provides,
        validated: f.validated,
      });
    }
    
    if (links.length >= 2) {
      const { severity, score } = calculateChainSeverity(links);
      const validatedLinks = links.filter(l => l.validated).length;
      
      chains.push({
        id: `chain-adhoc-${++chainCounter}`,
        name: `Multi-Phase Attack Path on ${target}`,
        description: `${links.length}-step attack chain identified across ${links.map(l => l.phase).join(" → ")} phases on ${target}`,
        links,
        chainSeverity: severity,
        chainScore: score,
        impactDescription: `Combined exploitation of ${links.length} findings on ${target} creates a multi-phase attack path`,
        killChainCoverage: Array.from(usedPhases),
        mitreTechniques: Array.from(new Set(links.map(l => l.attackTechnique))),
        feasibility: validatedLinks === links.length ? "confirmed" : validatedLinks > 0 ? "likely" : "possible",
        businessImpact: `Multi-phase compromise of ${target} via ${links.length} chained vulnerabilities`,
      });
    }
  }
  
  return chains;
}

function deduplicateChains(chains: AttackChain[]): AttackChain[] {
  const seen = new Set<string>();
  return chains.filter(chain => {
    const key = chain.links.map(l => l.findingId).sort().join(",");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

function mapPhaseToTechnique(phase: ChainPhase): string {
  const mapping: Record<ChainPhase, string> = {
    reconnaissance: "TA0043",
    initial_access: "TA0001",
    execution: "TA0002",
    persistence: "TA0003",
    privilege_escalation: "TA0004",
    defense_evasion: "TA0005",
    credential_access: "TA0006",
    discovery: "TA0007",
    lateral_movement: "TA0008",
    collection: "TA0009",
    exfiltration: "TA0010",
    impact: "TA0040",
  };
  return mapping[phase] || "TA0001";
}

/**
 * Reset chain counter (for testing).
 */
export function resetChainCounter(): void {
  chainCounter = 0;
}
