/**
 * Red Team Discovery Coverage Module
 *
 * Maps the top-10 red team discovery priorities to the platform's OSINT
 * connectors and computes a per-scan coverage score showing how many of
 * the 10 areas were successfully covered.
 *
 * Based on: "Top 10 Things to Discover First" — standard red team
 * methodology (Rhino Security Labs, redteam.guide, CISA red team reports).
 *
 * Priority weights are derived from the document's ordering: items listed
 * first are weighted higher because "early, high-quality intel directly
 * determines success rates and stealth."
 */

// ─── Priority Definitions ──────────────────────────────────────────

export interface DiscoveryPriority {
  id: number;
  name: string;
  shortName: string;
  description: string;
  /** Weight 1.0 = highest priority, decays by rank */
  weight: number;
  /** Which connectors contribute to this priority */
  connectors: string[];
  /** Observation tags that indicate coverage */
  coverageTags: string[];
  /** Minimum observations needed to consider this priority "covered" */
  minObservations: number;
  /** MITRE ATT&CK Recon technique IDs */
  attackTechniques: string[];
}

export const RED_TEAM_PRIORITIES: DiscoveryPriority[] = [
  {
    id: 1,
    name: "Domains, Subdomains & DNS Footprint",
    shortName: "DNS Footprint",
    description: "Map the entire external perimeter — subdomains, dev/staging environments, wildcard certs, forgotten assets.",
    weight: 1.0,
    connectors: ["crtsh", "securitytrails", "dns-deep", "rdap"],
    coverageTags: ["subdomain", "certificate", "dns", "domain", "cname", "ns_record", "soa_record", "wildcard"],
    minObservations: 3,
    attackTechniques: ["T1590.002", "T1596.003"],
  },
  {
    id: 2,
    name: "IP Ranges, Netblocks & Hosting Providers",
    shortName: "IP/Netblocks",
    description: "Define what can be legally scanned, reveal cloud vs on-prem boundaries, expose misrouted or legacy ranges.",
    weight: 0.95,
    connectors: ["ripestat", "rdap", "censys", "shodan"],
    coverageTags: ["ip", "netblock", "asn", "hosting", "whois", "bgp"],
    minObservations: 2,
    attackTechniques: ["T1590.004", "T1590.005"],
  },
  {
    id: 3,
    name: "Live Hosts, Open Ports & Services",
    shortName: "Port Enumeration",
    description: "Identify internet-facing assets, banner versions, and low-hanging services (RDP, SSH, web servers).",
    weight: 0.90,
    connectors: ["shodan", "shodan-internetdb", "censys", "binaryedge"],
    coverageTags: ["port", "service", "banner", "open_port", "service_banner"],
    minObservations: 2,
    attackTechniques: ["T1046", "T1595.001"],
  },
  {
    id: 4,
    name: "Web Applications, APIs & Tech Stack",
    shortName: "Web/API Stack",
    description: "Reveal frameworks/versions with known CVEs, login portals, API keys in JS, misconfigured buckets.",
    weight: 0.85,
    connectors: ["urlscan", "wayback", "http-security"],
    coverageTags: ["technology", "web_app", "framework", "api", "tech_stack", "waf", "security_header", "csp"],
    minObservations: 2,
    attackTechniques: ["T1592.004", "T1595.002"],
  },
  {
    id: 5,
    name: "Employee Emails, Names & Roles",
    shortName: "People Intel",
    description: "Essential for targeted phishing/spear-phishing — people are the #1 vector in 80%+ of successful initial accesses.",
    weight: 0.80,
    connectors: ["dehashed"],
    coverageTags: ["email", "employee", "contact", "breach_email", "breach_summary"],
    minObservations: 1,
    attackTechniques: ["T1589.002", "T1589.003"],
  },
  {
    id: 6,
    name: "Key Personnel OSINT",
    shortName: "Personnel OSINT",
    description: "Build credible pretexts for vishing or social engineering. High-signal targets: execs, IT admins, helpdesk.",
    weight: 0.70,
    connectors: [],  // Not yet covered — requires social media connectors
    coverageTags: ["executive", "admin", "personnel", "social_media"],
    minObservations: 1,
    attackTechniques: ["T1593", "T1593.001"],
  },
  {
    id: 7,
    name: "Leaked/Breached Credentials",
    shortName: "Credential Leaks",
    description: "Password reuse or exposed API keys often grant immediate footholds without zero-days.",
    weight: 0.85,
    connectors: ["dehashed"],
    coverageTags: ["breach", "credential", "password", "breach_database", "breach_summary", "api_key_leak"],
    minObservations: 1,
    attackTechniques: ["T1589.001", "T1552.001"],
  },
  {
    id: 8,
    name: "Cloud Assets & Misconfigurations",
    shortName: "Cloud Misconfig",
    description: "Cloud sprawl is a top real-world breach vector — public buckets, open RDS instances, exposed storage.",
    weight: 0.80,
    connectors: ["cloud-assets"],
    coverageTags: ["cloud", "s3_bucket", "azure_blob", "gcp_bucket", "cloud_storage", "cloud_asset"],
    minObservations: 1,
    attackTechniques: ["T1530", "T1580"],
  },
  {
    id: 9,
    name: "Security Tooling & Defensive Posture",
    shortName: "Defensive Posture",
    description: "WAF fingerprints, EDR/AV banners, SIEM clues, email security (DMARC/SPF) — what to evade from day one.",
    weight: 0.75,
    connectors: ["email-security", "http-security"],
    coverageTags: ["waf", "dmarc", "spf", "dkim", "security_header", "edr", "av", "siem", "hsts", "csp", "email_security"],
    minObservations: 2,
    attackTechniques: ["T1518.001", "T1590.006"],
  },
  {
    id: 10,
    name: "Code Repositories & Configuration Leaks",
    shortName: "Code/Config Leaks",
    description: "GitHub, Pastebin, Confluence — hardcoded creds, internal IPs, architecture diagrams, .env files.",
    weight: 0.65,
    connectors: [],  // Not yet covered — requires GitHub API
    coverageTags: ["github", "pastebin", "code_leak", "config_leak", "env_file"],
    minObservations: 1,
    attackTechniques: ["T1593.003", "T1596.004"],
  },
];

// ─── Coverage Computation ──────────────────────────────────────────

export interface PriorityCoverageResult {
  id: number;
  name: string;
  shortName: string;
  weight: number;
  covered: boolean;
  /** How many relevant observations were found */
  observationCount: number;
  /** Which connectors contributed data */
  contributingConnectors: string[];
  /** Coverage quality: "full" (>= 2x minObs), "partial" (>= minObs), "none" */
  quality: "full" | "partial" | "none";
  /** Whether the priority has connectors available (false = structural gap) */
  hasConnectors: boolean;
  attackTechniques: string[];
}

export interface DiscoveryCoverageReport {
  /** 0-100 weighted coverage score */
  coverageScore: number;
  /** How many of the 10 priorities were covered */
  prioritiesCovered: number;
  /** Total priorities (always 10) */
  totalPriorities: number;
  /** Per-priority breakdown */
  priorities: PriorityCoverageResult[];
  /** Structural gaps — priorities with no connectors available */
  structuralGaps: string[];
  /** Actionable gaps — priorities with connectors but no data found */
  actionableGaps: string[];
  /** Coverage band: "comprehensive" (80+), "good" (60+), "partial" (40+), "limited" (<40) */
  coverageBand: string;
  /** Human-readable assessment */
  assessment: string;
}

/**
 * Compute discovery coverage from passive recon results.
 *
 * @param connectorResults - Results from all passive recon connectors
 * @param allObservations - Deduplicated observations from all connectors
 */
export function computeDiscoveryCoverage(
  connectorResults: Array<{ connector: string; observations: Array<{ tags: string[]; assetType?: string; source?: string }> }>,
  allObservations: Array<{ tags: string[]; assetType?: string; source?: string }>
): DiscoveryCoverageReport {

  // Build a lookup: connector name → observation count and tags
  const connectorData = new Map<string, { count: number; tags: Set<string>; assetTypes: Set<string> }>();
  for (const cr of connectorResults) {
    const data = { count: cr.observations.length, tags: new Set<string>(), assetTypes: new Set<string>() };
    for (const obs of cr.observations) {
      for (const tag of obs.tags) data.tags.add(tag);
      if (obs.assetType) data.assetTypes.add(obs.assetType);
    }
    connectorData.set(cr.connector, data);
  }

  // Build a global tag set from all observations
  const globalTags = new Set<string>();
  const globalAssetTypes = new Set<string>();
  for (const obs of allObservations) {
    for (const tag of obs.tags) globalTags.add(tag);
    if (obs.assetType) globalAssetTypes.add(obs.assetType);
  }

  const priorities: PriorityCoverageResult[] = [];
  let weightedCoveredSum = 0;
  let totalWeight = 0;
  const structuralGaps: string[] = [];
  const actionableGaps: string[] = [];

  for (const priority of RED_TEAM_PRIORITIES) {
    const hasConnectors = priority.connectors.length > 0;
    totalWeight += priority.weight;

    // Count relevant observations from contributing connectors
    let observationCount = 0;
    const contributingConnectors: string[] = [];

    for (const connName of priority.connectors) {
      const data = connectorData.get(connName);
      if (data && data.count > 0) {
        // Check if any of the connector's tags match the priority's coverage tags
        const tagOverlap = priority.coverageTags.some(t => data.tags.has(t)) ||
                           priority.coverageTags.some(t => data.assetTypes.has(t));
        if (tagOverlap || data.count > 0) {
          observationCount += data.count;
          contributingConnectors.push(connName);
        }
      }
    }

    // Also check global observations for tag matches (some connectors produce
    // observations that match priority tags even if the connector isn't in the list)
    if (observationCount === 0) {
      let globalMatchCount = 0;
      for (const obs of allObservations) {
        const hasTagMatch = priority.coverageTags.some(t => obs.tags.includes(t));
        const hasTypeMatch = priority.coverageTags.some(t => obs.assetType === t);
        if (hasTagMatch || hasTypeMatch) globalMatchCount++;
      }
      if (globalMatchCount > 0) {
        observationCount = globalMatchCount;
        contributingConnectors.push("cross-source");
      }
    }

    const covered = observationCount >= priority.minObservations;
    const quality: "full" | "partial" | "none" =
      observationCount >= priority.minObservations * 2 ? "full" :
      observationCount >= priority.minObservations ? "partial" : "none";

    if (covered) {
      // Full coverage gets full weight, partial gets 70%
      weightedCoveredSum += priority.weight * (quality === "full" ? 1.0 : 0.7);
    } else if (!hasConnectors) {
      structuralGaps.push(priority.name);
    } else {
      actionableGaps.push(priority.name);
    }

    priorities.push({
      id: priority.id,
      name: priority.name,
      shortName: priority.shortName,
      weight: priority.weight,
      covered,
      observationCount,
      contributingConnectors,
      quality,
      hasConnectors,
      attackTechniques: priority.attackTechniques,
    });
  }

  const prioritiesCovered = priorities.filter(p => p.covered).length;
  const coverageScore = totalWeight > 0
    ? Math.round((weightedCoveredSum / totalWeight) * 100)
    : 0;

  const coverageBand =
    coverageScore >= 80 ? "comprehensive" :
    coverageScore >= 60 ? "good" :
    coverageScore >= 40 ? "partial" : "limited";

  const assessment = generateAssessment(coverageScore, coverageBand, prioritiesCovered, structuralGaps, actionableGaps);

  return {
    coverageScore,
    prioritiesCovered,
    totalPriorities: RED_TEAM_PRIORITIES.length,
    priorities,
    structuralGaps,
    actionableGaps,
    coverageBand,
    assessment,
  };
}

function generateAssessment(
  score: number,
  band: string,
  covered: number,
  structuralGaps: string[],
  actionableGaps: string[]
): string {
  const parts: string[] = [];

  parts.push(`Discovery coverage: ${score}% (${band}) — ${covered}/10 red team priorities covered.`);

  if (structuralGaps.length > 0) {
    parts.push(`Structural gaps (no connectors available): ${structuralGaps.join(", ")}.`);
  }

  if (actionableGaps.length > 0) {
    parts.push(`Actionable gaps (connectors available but no data found): ${actionableGaps.join(", ")}.`);
  }

  if (score >= 80) {
    parts.push("This scan provides comprehensive recon coverage aligned with standard red team methodology.");
  } else if (score >= 60) {
    parts.push("Good coverage of core discovery areas. Consider adding missing connectors to close remaining gaps.");
  } else if (score >= 40) {
    parts.push("Partial coverage — several critical discovery areas are missing. Prioritize adding connectors for the highest-weight gaps.");
  } else {
    parts.push("Limited coverage — most red team discovery priorities are not covered. This scan provides an incomplete picture of the attack surface.");
  }

  return parts.join(" ");
}

// ─── Risk Weight Multipliers ───────────────────────────────────────

/**
 * Get the red team priority weight for a given finding category.
 * Used by the risk scoring engine to weight findings from higher-priority
 * discovery areas more heavily.
 *
 * Returns a multiplier between 0.65 and 1.0 based on which red team
 * priority the finding aligns with.
 */
export function getRedTeamPriorityWeight(findingTags: string[], findingCategory?: string): number {
  let maxWeight = 0.65; // Default weight for findings not matching any priority

  for (const priority of RED_TEAM_PRIORITIES) {
    const tagMatch = priority.coverageTags.some(t => findingTags.includes(t));
    const categoryMatch = findingCategory && priority.coverageTags.some(t =>
      findingCategory.toLowerCase().includes(t.toLowerCase())
    );

    if (tagMatch || categoryMatch) {
      maxWeight = Math.max(maxWeight, priority.weight);
    }
  }

  return maxWeight;
}

/**
 * Compute an overall red team alignment score for a set of findings.
 * This measures how well the findings align with what a red team would
 * prioritize — higher scores mean the findings are more operationally
 * relevant from an attacker's perspective.
 */
export function computeRedTeamAlignmentScore(
  findings: Array<{ tags?: string[]; category?: string; severity?: number }>
): number {
  if (findings.length === 0) return 0;

  let weightedSum = 0;
  let totalSeverity = 0;

  for (const f of findings) {
    const tags = f.tags || [];
    const weight = getRedTeamPriorityWeight(tags, f.category);
    const severity = f.severity || 5;
    weightedSum += weight * severity;
    totalSeverity += severity;
  }

  // Normalize to 0-100
  return totalSeverity > 0
    ? Math.round((weightedSum / totalSeverity) * 100)
    : 0;
}
