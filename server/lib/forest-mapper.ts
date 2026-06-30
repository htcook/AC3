/**
 * Multi-Domain Forest Mapping Engine
 * Manages multiple AD domain connections simultaneously,
 * maps forest hierarchies, and analyzes cross-forest trust relationships.
 */

// ============================================================
// Types
// ============================================================

export interface ForestDomain {
  id: number;
  forestName: string;
  domainName: string;
  connectionId: number | null;
  parentDomainId: number | null;
  domainSid: string | null;
  domainFunctionalLevel: string | null;
  forestFunctionalLevel: string | null;
  isForestRoot: boolean;
  totalUsers: number;
  totalGroups: number;
  totalComputers: number;
  privilegedUsers: number;
  lastEnumeratedAt: Date | null;
  metadata: Record<string, any> | null;
}

export interface ForestTrust {
  id: number;
  sourceDomainId: number;
  targetDomainId: number;
  direction: "inbound" | "outbound" | "bidirectional";
  trustType: "parent_child" | "tree_root" | "shortcut" | "forest" | "external" | "realm";
  isTransitive: boolean;
  sidFilteringEnabled: boolean;
  selectiveAuth: boolean;
  trustAttributes: number;
  isVulnerable: boolean;
  vulnerabilityNotes: string | null;
}

export interface ForestTopology {
  domains: ForestDomain[];
  trusts: ForestTrust[];
  forests: ForestSummary[];
  vulnerabilities: TrustVulnerability[];
  stats: ForestStats;
}

export interface ForestSummary {
  forestName: string;
  rootDomain: string;
  totalDomains: number;
  totalUsers: number;
  totalComputers: number;
  functionalLevel: string | null;
}

export interface TrustVulnerability {
  trustId: number;
  sourceDomain: string;
  targetDomain: string;
  vulnerabilityType: string;
  severity: "critical" | "high" | "medium" | "low";
  description: string;
  remediation: string;
}

export interface ForestStats {
  totalForests: number;
  totalDomains: number;
  totalTrusts: number;
  vulnerableTrusts: number;
  totalUsers: number;
  totalComputers: number;
  totalPrivilegedUsers: number;
  crossForestTrusts: number;
}

// ============================================================
// Trust Vulnerability Analysis
// ============================================================

/**
 * Known trust vulnerability patterns
 */
export const TRUST_VULNERABILITY_PATTERNS = [
  {
    id: "sid-filtering-disabled",
    name: "SID Filtering Disabled",
    severity: "critical" as const,
    check: (trust: ForestTrust) => !trust.sidFilteringEnabled,
    description: "SID filtering is disabled on this trust, allowing SID history injection attacks. " +
      "An attacker who compromises one domain can forge SID history to gain access to the trusted domain.",
    remediation: "Enable SID filtering (quarantine) on the trust using: netdom trust /quarantine:yes",
  },
  {
    id: "transitive-external-trust",
    name: "Transitive External Trust",
    severity: "high" as const,
    check: (trust: ForestTrust) => trust.trustType === "external" && trust.isTransitive,
    description: "External trust is configured as transitive, extending trust transitivity beyond the intended scope. " +
      "This can allow unintended access paths through intermediate domains.",
    remediation: "Convert to a non-transitive trust or use selective authentication to limit access.",
  },
  {
    id: "bidirectional-forest-trust",
    name: "Bidirectional Forest Trust Without Selective Auth",
    severity: "high" as const,
    check: (trust: ForestTrust) =>
      trust.trustType === "forest" && trust.direction === "bidirectional" && !trust.selectiveAuth,
    description: "Bidirectional forest trust without selective authentication allows any authenticated user " +
      "in either forest to access resources in the other forest.",
    remediation: "Enable selective authentication on the forest trust to require explicit permission grants.",
  },
  {
    id: "realm-trust-no-filtering",
    name: "Realm Trust Without SID Filtering",
    severity: "high" as const,
    check: (trust: ForestTrust) => trust.trustType === "realm" && !trust.sidFilteringEnabled,
    description: "Kerberos realm trust without SID filtering allows cross-realm ticket forgery attacks.",
    remediation: "Enable SID filtering on the realm trust and audit cross-realm authentication logs.",
  },
  {
    id: "shortcut-trust-exposure",
    name: "Shortcut Trust Bypasses Hierarchy",
    severity: "medium" as const,
    check: (trust: ForestTrust) => trust.trustType === "shortcut",
    description: "Shortcut trust creates a direct authentication path that bypasses the normal forest hierarchy, " +
      "potentially circumventing security controls applied at intermediate domains.",
    remediation: "Review if the shortcut trust is still needed. If so, enable selective authentication.",
  },
  {
    id: "inbound-trust-exposure",
    name: "Inbound Trust Allows External Access",
    severity: "medium" as const,
    check: (trust: ForestTrust) => trust.direction === "inbound" && !trust.selectiveAuth,
    description: "Inbound trust without selective authentication allows the trusted domain's users " +
      "to authenticate to any resource in this domain.",
    remediation: "Enable selective authentication and audit which resources external users can access.",
  },
];

/**
 * Analyze trusts for vulnerabilities
 */
export function analyzeTrustVulnerabilities(
  trusts: ForestTrust[],
  domains: ForestDomain[]
): TrustVulnerability[] {
  const vulnerabilities: TrustVulnerability[] = [];

  for (const trust of trusts) {
    const sourceDomain = domains.find(d => d.id === trust.sourceDomainId);
    const targetDomain = domains.find(d => d.id === trust.targetDomainId);

    for (const pattern of TRUST_VULNERABILITY_PATTERNS) {
      if (pattern.check(trust)) {
        vulnerabilities.push({
          trustId: trust.id,
          sourceDomain: sourceDomain?.domainName || `Domain #${trust.sourceDomainId}`,
          targetDomain: targetDomain?.domainName || `Domain #${trust.targetDomainId}`,
          vulnerabilityType: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          remediation: pattern.remediation,
        });
      }
    }
  }

  // Sort by severity
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  vulnerabilities.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);

  return vulnerabilities;
}

/**
 * Build forest topology from domains and trusts
 */
export function buildForestTopology(
  domains: ForestDomain[],
  trusts: ForestTrust[]
): ForestTopology {
  // Group domains by forest
  const forestMap = new Map<string, ForestDomain[]>();
  for (const domain of domains) {
    const key = domain.forestName;
    if (!forestMap.has(key)) forestMap.set(key, []);
    forestMap.get(key)!.push(domain);
  }

  // Build forest summaries
  const forests: ForestSummary[] = Array.from(forestMap.entries()).map(([forestName, forestDomains]) => {
    const root = forestDomains.find(d => d.isForestRoot);
    return {
      forestName,
      rootDomain: root?.domainName || forestDomains[0]?.domainName || forestName,
      totalDomains: forestDomains.length,
      totalUsers: forestDomains.reduce((sum, d) => sum + d.totalUsers, 0),
      totalComputers: forestDomains.reduce((sum, d) => sum + d.totalComputers, 0),
      functionalLevel: root?.forestFunctionalLevel || null,
    };
  });

  // Analyze trust vulnerabilities
  const vulnerabilities = analyzeTrustVulnerabilities(trusts, domains);

  // Count cross-forest trusts
  const crossForestTrusts = trusts.filter(t => {
    const source = domains.find(d => d.id === t.sourceDomainId);
    const target = domains.find(d => d.id === t.targetDomainId);
    return source && target && source.forestName !== target.forestName;
  }).length;

  const stats: ForestStats = {
    totalForests: forests.length,
    totalDomains: domains.length,
    totalTrusts: trusts.length,
    vulnerableTrusts: trusts.filter(t => t.isVulnerable).length + vulnerabilities.length,
    totalUsers: domains.reduce((sum, d) => sum + d.totalUsers, 0),
    totalComputers: domains.reduce((sum, d) => sum + d.totalComputers, 0),
    totalPrivilegedUsers: domains.reduce((sum, d) => sum + d.privilegedUsers, 0),
    crossForestTrusts,
  };

  return { domains, trusts, forests, vulnerabilities, stats };
}

/**
 * Generate a visual layout for forest topology
 * Returns positioned nodes and edges for SVG rendering
 */
export function generateForestLayout(topology: ForestTopology): {
  nodes: { id: string; label: string; x: number; y: number; type: "forest" | "domain" | "root"; forestName: string; stats: Record<string, number> }[];
  edges: { source: string; target: string; label: string; type: string; isVulnerable: boolean; direction: string }[];
} {
  const nodes: any[] = [];
  const edges: any[] = [];

  // Position forests horizontally
  const forestNames = Array.from(new Set(topology.domains.map(d => d.forestName)));
  const forestSpacing = 400;
  const domainSpacing = 180;

  forestNames.forEach((forestName, forestIdx) => {
    const forestX = forestIdx * forestSpacing + 200;
    const forestDomains = topology.domains.filter(d => d.forestName === forestName);
    const root = forestDomains.find(d => d.isForestRoot);

    // Add forest root node
    if (root) {
      nodes.push({
        id: `domain-${root.id}`,
        label: root.domainName,
        x: forestX,
        y: 100,
        type: "root",
        forestName,
        stats: {
          users: root.totalUsers,
          groups: root.totalGroups,
          computers: root.totalComputers,
          privileged: root.privilegedUsers,
        },
      });
    }

    // Add child domains
    const children = forestDomains.filter(d => !d.isForestRoot);
    children.forEach((child, childIdx) => {
      const childX = forestX - ((children.length - 1) * domainSpacing / 2) + childIdx * domainSpacing;
      nodes.push({
        id: `domain-${child.id}`,
        label: child.domainName,
        x: childX,
        y: 280,
        type: "domain",
        forestName,
        stats: {
          users: child.totalUsers,
          groups: child.totalGroups,
          computers: child.totalComputers,
          privileged: child.privilegedUsers,
        },
      });

      // Add parent-child edge
      if (root) {
        edges.push({
          source: `domain-${root.id}`,
          target: `domain-${child.id}`,
          label: "Parent-Child",
          type: "parent_child",
          isVulnerable: false,
          direction: "bidirectional",
        });
      }
    });
  });

  // Add trust edges
  for (const trust of topology.trusts) {
    const isVuln = topology.vulnerabilities.some(v => v.trustId === trust.id);
    edges.push({
      source: `domain-${trust.sourceDomainId}`,
      target: `domain-${trust.targetDomainId}`,
      label: `${trust.trustType.replace("_", " ")} (${trust.direction})`,
      type: trust.trustType,
      isVulnerable: trust.isVulnerable || isVuln,
      direction: trust.direction,
    });
  }

  return { nodes, edges };
}
