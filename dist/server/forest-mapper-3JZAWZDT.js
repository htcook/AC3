import "./chunk-KFQGP6VL.js";

// server/lib/forest-mapper.ts
var TRUST_VULNERABILITY_PATTERNS = [
  {
    id: "sid-filtering-disabled",
    name: "SID Filtering Disabled",
    severity: "critical",
    check: (trust) => !trust.sidFilteringEnabled,
    description: "SID filtering is disabled on this trust, allowing SID history injection attacks. An attacker who compromises one domain can forge SID history to gain access to the trusted domain.",
    remediation: "Enable SID filtering (quarantine) on the trust using: netdom trust /quarantine:yes"
  },
  {
    id: "transitive-external-trust",
    name: "Transitive External Trust",
    severity: "high",
    check: (trust) => trust.trustType === "external" && trust.isTransitive,
    description: "External trust is configured as transitive, extending trust transitivity beyond the intended scope. This can allow unintended access paths through intermediate domains.",
    remediation: "Convert to a non-transitive trust or use selective authentication to limit access."
  },
  {
    id: "bidirectional-forest-trust",
    name: "Bidirectional Forest Trust Without Selective Auth",
    severity: "high",
    check: (trust) => trust.trustType === "forest" && trust.direction === "bidirectional" && !trust.selectiveAuth,
    description: "Bidirectional forest trust without selective authentication allows any authenticated user in either forest to access resources in the other forest.",
    remediation: "Enable selective authentication on the forest trust to require explicit permission grants."
  },
  {
    id: "realm-trust-no-filtering",
    name: "Realm Trust Without SID Filtering",
    severity: "high",
    check: (trust) => trust.trustType === "realm" && !trust.sidFilteringEnabled,
    description: "Kerberos realm trust without SID filtering allows cross-realm ticket forgery attacks.",
    remediation: "Enable SID filtering on the realm trust and audit cross-realm authentication logs."
  },
  {
    id: "shortcut-trust-exposure",
    name: "Shortcut Trust Bypasses Hierarchy",
    severity: "medium",
    check: (trust) => trust.trustType === "shortcut",
    description: "Shortcut trust creates a direct authentication path that bypasses the normal forest hierarchy, potentially circumventing security controls applied at intermediate domains.",
    remediation: "Review if the shortcut trust is still needed. If so, enable selective authentication."
  },
  {
    id: "inbound-trust-exposure",
    name: "Inbound Trust Allows External Access",
    severity: "medium",
    check: (trust) => trust.direction === "inbound" && !trust.selectiveAuth,
    description: "Inbound trust without selective authentication allows the trusted domain's users to authenticate to any resource in this domain.",
    remediation: "Enable selective authentication and audit which resources external users can access."
  }
];
function analyzeTrustVulnerabilities(trusts, domains) {
  const vulnerabilities = [];
  for (const trust of trusts) {
    const sourceDomain = domains.find((d) => d.id === trust.sourceDomainId);
    const targetDomain = domains.find((d) => d.id === trust.targetDomainId);
    for (const pattern of TRUST_VULNERABILITY_PATTERNS) {
      if (pattern.check(trust)) {
        vulnerabilities.push({
          trustId: trust.id,
          sourceDomain: sourceDomain?.domainName || `Domain #${trust.sourceDomainId}`,
          targetDomain: targetDomain?.domainName || `Domain #${trust.targetDomainId}`,
          vulnerabilityType: pattern.name,
          severity: pattern.severity,
          description: pattern.description,
          remediation: pattern.remediation
        });
      }
    }
  }
  const severityOrder = { critical: 0, high: 1, medium: 2, low: 3 };
  vulnerabilities.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity]);
  return vulnerabilities;
}
function buildForestTopology(domains, trusts) {
  const forestMap = /* @__PURE__ */ new Map();
  for (const domain of domains) {
    const key = domain.forestName;
    if (!forestMap.has(key)) forestMap.set(key, []);
    forestMap.get(key).push(domain);
  }
  const forests = Array.from(forestMap.entries()).map(([forestName, forestDomains]) => {
    const root = forestDomains.find((d) => d.isForestRoot);
    return {
      forestName,
      rootDomain: root?.domainName || forestDomains[0]?.domainName || forestName,
      totalDomains: forestDomains.length,
      totalUsers: forestDomains.reduce((sum, d) => sum + d.totalUsers, 0),
      totalComputers: forestDomains.reduce((sum, d) => sum + d.totalComputers, 0),
      functionalLevel: root?.forestFunctionalLevel || null
    };
  });
  const vulnerabilities = analyzeTrustVulnerabilities(trusts, domains);
  const crossForestTrusts = trusts.filter((t) => {
    const source = domains.find((d) => d.id === t.sourceDomainId);
    const target = domains.find((d) => d.id === t.targetDomainId);
    return source && target && source.forestName !== target.forestName;
  }).length;
  const stats = {
    totalForests: forests.length,
    totalDomains: domains.length,
    totalTrusts: trusts.length,
    vulnerableTrusts: trusts.filter((t) => t.isVulnerable).length + vulnerabilities.length,
    totalUsers: domains.reduce((sum, d) => sum + d.totalUsers, 0),
    totalComputers: domains.reduce((sum, d) => sum + d.totalComputers, 0),
    totalPrivilegedUsers: domains.reduce((sum, d) => sum + d.privilegedUsers, 0),
    crossForestTrusts
  };
  return { domains, trusts, forests, vulnerabilities, stats };
}
function generateForestLayout(topology) {
  const nodes = [];
  const edges = [];
  const forestNames = Array.from(new Set(topology.domains.map((d) => d.forestName)));
  const forestSpacing = 400;
  const domainSpacing = 180;
  forestNames.forEach((forestName, forestIdx) => {
    const forestX = forestIdx * forestSpacing + 200;
    const forestDomains = topology.domains.filter((d) => d.forestName === forestName);
    const root = forestDomains.find((d) => d.isForestRoot);
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
          privileged: root.privilegedUsers
        }
      });
    }
    const children = forestDomains.filter((d) => !d.isForestRoot);
    children.forEach((child, childIdx) => {
      const childX = forestX - (children.length - 1) * domainSpacing / 2 + childIdx * domainSpacing;
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
          privileged: child.privilegedUsers
        }
      });
      if (root) {
        edges.push({
          source: `domain-${root.id}`,
          target: `domain-${child.id}`,
          label: "Parent-Child",
          type: "parent_child",
          isVulnerable: false,
          direction: "bidirectional"
        });
      }
    });
  });
  for (const trust of topology.trusts) {
    const isVuln = topology.vulnerabilities.some((v) => v.trustId === trust.id);
    edges.push({
      source: `domain-${trust.sourceDomainId}`,
      target: `domain-${trust.targetDomainId}`,
      label: `${trust.trustType.replace("_", " ")} (${trust.direction})`,
      type: trust.trustType,
      isVulnerable: trust.isVulnerable || isVuln,
      direction: trust.direction
    });
  }
  return { nodes, edges };
}
export {
  TRUST_VULNERABILITY_PATTERNS,
  analyzeTrustVulnerabilities,
  buildForestTopology,
  generateForestLayout
};
