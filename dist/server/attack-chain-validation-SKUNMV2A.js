import {
  getDbRequired,
  init_db
} from "./chunk-CEPCIPS7.js";
import "./chunk-NRYVRXXR.js";
import {
  attackChainRecords,
  init_schema
} from "./chunk-TAIMCRAB.js";
import "./chunk-KFQGP6VL.js";

// server/lib/attack-chain-validation.ts
init_db();
init_schema();
import { desc } from "drizzle-orm";
var CHAIN_PATTERNS = [
  {
    id: "chain-info-to-rce",
    name: "Information Disclosure to RCE",
    description: "Information leak reveals credentials or internal details enabling remote code execution",
    phases: ["reconnaissance", "credential_access", "initial_access", "execution"],
    requiredCapabilities: ["info_disclosure", "credential_extraction", "code_execution"],
    minimumLinks: 2,
    severityBoost: 3,
    businessImpact: "Full system compromise via chained information disclosure"
  },
  {
    id: "chain-ssrf-to-internal",
    name: "SSRF to Internal Network Access",
    description: "Server-side request forgery enables access to internal services not directly exposed",
    phases: ["initial_access", "discovery", "lateral_movement"],
    requiredCapabilities: ["ssrf", "internal_access", "service_enumeration"],
    minimumLinks: 2,
    severityBoost: 2,
    businessImpact: "Internal network breach via SSRF pivot"
  },
  {
    id: "chain-subdomain-takeover-phishing",
    name: "Subdomain Takeover to Credential Theft",
    description: "Dangling DNS enables subdomain takeover for targeted phishing campaigns",
    phases: ["reconnaissance", "initial_access", "credential_access"],
    requiredCapabilities: ["subdomain_takeover", "phishing_platform", "credential_harvesting"],
    minimumLinks: 2,
    severityBoost: 2,
    businessImpact: "Brand impersonation and credential theft via subdomain takeover"
  },
  {
    id: "chain-privesc-to-domain-admin",
    name: "Privilege Escalation to Domain Admin",
    description: "Local privilege escalation chains to domain administrator access",
    phases: ["initial_access", "privilege_escalation", "credential_access", "lateral_movement"],
    requiredCapabilities: ["local_access", "privilege_escalation", "credential_dumping", "domain_admin"],
    minimumLinks: 3,
    severityBoost: 4,
    businessImpact: "Complete domain compromise via privilege escalation chain"
  },
  {
    id: "chain-exposed-api-data-exfil",
    name: "Exposed API to Data Exfiltration",
    description: "Unauthenticated or weakly authenticated API enables bulk data extraction",
    phases: ["reconnaissance", "initial_access", "collection", "exfiltration"],
    requiredCapabilities: ["api_exposure", "auth_bypass", "data_access"],
    minimumLinks: 2,
    severityBoost: 3,
    businessImpact: "Mass data exfiltration via exposed API endpoints"
  },
  {
    id: "chain-default-creds-lateral",
    name: "Default Credentials to Lateral Movement",
    description: "Default or weak credentials on one service enable pivot to other systems",
    phases: ["initial_access", "credential_access", "lateral_movement"],
    requiredCapabilities: ["default_credentials", "credential_reuse", "network_pivot"],
    minimumLinks: 2,
    severityBoost: 2,
    businessImpact: "Multi-system compromise via credential reuse"
  },
  {
    id: "chain-xss-to-account-takeover",
    name: "XSS to Account Takeover",
    description: "Cross-site scripting enables session hijacking or credential theft",
    phases: ["initial_access", "credential_access", "privilege_escalation"],
    requiredCapabilities: ["xss", "session_hijack", "account_takeover"],
    minimumLinks: 2,
    severityBoost: 2,
    businessImpact: "User account compromise via XSS chain"
  },
  {
    id: "chain-misconfig-to-persistence",
    name: "Misconfiguration to Persistent Access",
    description: "Service misconfiguration enables establishing persistent backdoor access",
    phases: ["initial_access", "execution", "persistence", "defense_evasion"],
    requiredCapabilities: ["misconfiguration", "code_execution", "backdoor_install"],
    minimumLinks: 3,
    severityBoost: 3,
    businessImpact: "Persistent unauthorized access via misconfiguration exploitation"
  }
];
var CAPABILITY_MAPPINGS = [
  { keywords: ["information disclosure", "info leak", "directory listing", "phpinfo", "server-status", "stack trace"], capabilities: ["info_disclosure"], phase: "reconnaissance", techniqueId: "T1592" },
  { keywords: ["ssrf", "server-side request forgery"], capabilities: ["ssrf", "internal_access"], phase: "initial_access", techniqueId: "T1190" },
  { keywords: ["subdomain takeover", "dangling dns", "cname"], capabilities: ["subdomain_takeover", "phishing_platform"], phase: "reconnaissance", techniqueId: "T1584" },
  { keywords: ["rce", "remote code execution", "command injection", "code injection"], capabilities: ["code_execution"], phase: "execution", techniqueId: "T1059" },
  { keywords: ["sql injection", "sqli"], capabilities: ["data_access", "credential_extraction"], phase: "initial_access", techniqueId: "T1190" },
  { keywords: ["xss", "cross-site scripting", "reflected xss", "stored xss"], capabilities: ["xss", "session_hijack"], phase: "initial_access", techniqueId: "T1189" },
  { keywords: ["default credentials", "default password", "weak password"], capabilities: ["default_credentials", "credential_reuse"], phase: "credential_access", techniqueId: "T1078" },
  { keywords: ["privilege escalation", "privesc", "local privilege"], capabilities: ["privilege_escalation", "local_access"], phase: "privilege_escalation", techniqueId: "T1068" },
  { keywords: ["credential", "password", "token", "api key", "secret"], capabilities: ["credential_extraction", "credential_harvesting"], phase: "credential_access", techniqueId: "T1552" },
  { keywords: ["exposed api", "unauthenticated api", "api without auth", "open api"], capabilities: ["api_exposure", "auth_bypass", "data_access"], phase: "initial_access", techniqueId: "T1190" },
  { keywords: ["lateral movement", "pivot", "network spread"], capabilities: ["network_pivot", "lateral_movement"], phase: "lateral_movement", techniqueId: "T1021" },
  { keywords: ["misconfiguration", "misconfig", "insecure config"], capabilities: ["misconfiguration"], phase: "initial_access", techniqueId: "T1190" },
  { keywords: ["backdoor", "webshell", "persistence", "cron job"], capabilities: ["backdoor_install", "persistence"], phase: "persistence", techniqueId: "T1505" },
  { keywords: ["data exfiltration", "data leak", "bulk download"], capabilities: ["data_access", "exfiltration"], phase: "exfiltration", techniqueId: "T1041" },
  { keywords: [".env exposure", ".git exposure", "source code leak", "backup file"], capabilities: ["info_disclosure", "credential_extraction"], phase: "reconnaissance", techniqueId: "T1592" },
  { keywords: ["authentication bypass", "auth bypass", "broken auth"], capabilities: ["auth_bypass", "account_takeover"], phase: "initial_access", techniqueId: "T1078" },
  { keywords: ["dns zone transfer", "zone transfer"], capabilities: ["info_disclosure", "service_enumeration"], phase: "reconnaissance", techniqueId: "T1590" },
  { keywords: ["open redirect", "url redirect"], capabilities: ["phishing_platform", "credential_harvesting"], phase: "initial_access", techniqueId: "T1566" },
  { keywords: ["file upload", "unrestricted upload"], capabilities: ["code_execution", "backdoor_install"], phase: "execution", techniqueId: "T1105" },
  { keywords: ["idor", "insecure direct object"], capabilities: ["data_access", "auth_bypass"], phase: "collection", techniqueId: "T1530" }
];
function buildAttackGraph(enrichedFindings) {
  const nodes = enrichedFindings.map((f) => ({
    findingId: f.findingId,
    phase: f.phase,
    capabilities: f.capabilities,
    target: f.target,
    severity: f.severity
  }));
  const edges = [];
  const phaseOrder = [
    "reconnaissance",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "exfiltration",
    "impact"
  ];
  const severityWeight = { critical: 1, high: 2, medium: 3, low: 4, info: 5 };
  for (let i = 0; i < enrichedFindings.length; i++) {
    for (let j = 0; j < enrichedFindings.length; j++) {
      if (i === j) continue;
      const from = enrichedFindings[i];
      const to = enrichedFindings[j];
      const fromIdx = phaseOrder.indexOf(from.phase);
      const toIdx = phaseOrder.indexOf(to.phase);
      if (toIdx <= fromIdx) continue;
      const capabilityOverlap = from.provides.some(
        (p) => to.capabilities.some((c) => p === c || p.includes(c) || c.includes(p))
      );
      let weight = severityWeight[to.severity];
      let transitionType = "capability_chain";
      if (from.target === to.target) {
        weight *= 0.5;
        transitionType = "same_target";
      } else {
        weight *= 1.5;
        transitionType = "cross_target";
      }
      if (capabilityOverlap) {
        weight *= 0.5;
      }
      if (capabilityOverlap || from.target === to.target) {
        edges.push({
          from: from.findingId,
          to: to.findingId,
          weight,
          transitionType
        });
      }
    }
  }
  return { nodes, edges };
}
function findOptimalPaths(nodes, edges, maxPaths = 5) {
  if (nodes.length === 0) return [];
  const entryPhases = ["reconnaissance", "initial_access"];
  const entryNodes = nodes.filter((n) => entryPhases.includes(n.phase));
  const exitPhases = ["exfiltration", "impact", "lateral_movement", "collection"];
  const exitNodes = new Set(nodes.filter((n) => exitPhases.includes(n.phase)).map((n) => n.findingId));
  if (entryNodes.length === 0) return [];
  const adjacency = /* @__PURE__ */ new Map();
  for (const edge of edges) {
    const existing = adjacency.get(edge.from) || [];
    existing.push({ to: edge.to, weight: edge.weight });
    adjacency.set(edge.from, existing);
  }
  const allPaths = [];
  for (const entry of entryNodes) {
    const dist = /* @__PURE__ */ new Map();
    const prev = /* @__PURE__ */ new Map();
    const visited = /* @__PURE__ */ new Set();
    dist.set(entry.findingId, 0);
    prev.set(entry.findingId, null);
    const queue = [{ id: entry.findingId, cost: 0 }];
    while (queue.length > 0) {
      queue.sort((a, b) => a.cost - b.cost);
      const current = queue.shift();
      if (visited.has(current.id)) continue;
      visited.add(current.id);
      const neighbors = adjacency.get(current.id) || [];
      for (const neighbor of neighbors) {
        const newDist = current.cost + neighbor.weight;
        if (!dist.has(neighbor.to) || newDist < dist.get(neighbor.to)) {
          dist.set(neighbor.to, newDist);
          prev.set(neighbor.to, current.id);
          queue.push({ id: neighbor.to, cost: newDist });
        }
      }
    }
    for (const exitId of Array.from(exitNodes)) {
      if (!prev.has(exitId)) continue;
      const path = [];
      let current = exitId;
      while (current !== null) {
        path.unshift(current);
        current = prev.get(current) ?? null;
      }
      if (path.length >= 2 && path[0] === entry.findingId) {
        allPaths.push({ path, cost: dist.get(exitId) || Infinity });
      }
    }
  }
  allPaths.sort((a, b) => a.cost - b.cost);
  return allPaths.slice(0, maxPaths).map((p) => p.path);
}
var chainCounter = 0;
function analyzeAttackChains(findings) {
  const enrichedFindings = findings.map((f) => {
    const mapping = findCapabilityMapping(f.title, f.description);
    return {
      ...f,
      findingId: f.id,
      capabilities: mapping.capabilities,
      phase: mapping.phase,
      provides: mapping.capabilities,
      techniqueId: mapping.techniqueId
    };
  });
  const chains = [];
  for (const pattern of CHAIN_PATTERNS) {
    const matchedChain = matchChainPattern(pattern, enrichedFindings);
    if (matchedChain) {
      chains.push(matchedChain);
    }
  }
  const adHocChains = discoverAdHocChains(enrichedFindings);
  chains.push(...adHocChains);
  const crossTargetChains = discoverCrossTargetChains(enrichedFindings);
  chains.push(...crossTargetChains);
  const graph = buildAttackGraph(enrichedFindings);
  const optimalPaths = findOptimalPaths(graph.nodes, graph.edges);
  for (const path of optimalPaths) {
    const pathFindings = path.map((id) => enrichedFindings.find((f) => f.id === id)).filter(Boolean);
    if (pathFindings.length >= 2) {
      const graphChain = buildChainFromPath(pathFindings, "graph");
      if (graphChain) chains.push(graphChain);
    }
  }
  const uniqueChains = deduplicateChains(chains);
  const criticalChains = uniqueChains.filter((c) => c.chainSeverity === "critical").length;
  const highChains = uniqueChains.filter((c) => c.chainSeverity === "high").length;
  const maxChainLength = uniqueChains.reduce((max, c) => Math.max(max, c.links.length), 0);
  const coverageByPhase = {
    reconnaissance: 0,
    initial_access: 0,
    execution: 0,
    persistence: 0,
    privilege_escalation: 0,
    defense_evasion: 0,
    credential_access: 0,
    discovery: 0,
    lateral_movement: 0,
    collection: 0,
    exfiltration: 0,
    impact: 0
  };
  for (const chain of uniqueChains) {
    for (const phase of chain.killChainCoverage) {
      coverageByPhase[phase]++;
    }
  }
  const summary = uniqueChains.length > 0 ? `Identified ${uniqueChains.length} attack chain(s): ${criticalChains} critical, ${highChains} high. Longest chain: ${maxChainLength} steps. ${uniqueChains.map((c) => c.name).join("; ")}.` : "No multi-step attack chains identified from current findings.";
  return {
    chains: uniqueChains,
    totalChainsFound: uniqueChains.length,
    criticalChains,
    highChains,
    maxChainLength,
    coverageByPhase,
    summary
  };
}
async function analyzeAndPersistChains(findings, scanId) {
  const result = analyzeAttackChains(findings);
  const db = await getDbRequired().catch(() => null);
  if (db && result.chains.length > 0) {
    for (const chain of result.chains) {
      try {
        await db.insert(attackChainRecords).values({
          chainId: chain.id,
          scanId: scanId || null,
          chainType: chain.links.length > 1 && new Set(chain.links.map((l) => l.target)).size > 1 ? "cross_target" : "single_target",
          patternName: chain.name,
          steps: chain.links.map((l) => ({
            findingId: l.findingId,
            title: l.title,
            severity: l.severity,
            phase: l.phase,
            technique: l.attackTechnique,
            target: l.target,
            provides: l.provides
          })),
          entryPoint: chain.links[0]?.target || null,
          finalTarget: chain.links[chain.links.length - 1]?.target || null,
          overallConfidence: chain.feasibility === "confirmed" ? 1 : chain.feasibility === "likely" ? 0.75 : chain.feasibility === "possible" ? 0.5 : 0.25,
          riskScore: chain.chainScore,
          mitreTechniques: chain.mitreTechniques,
          validated: chain.feasibility === "confirmed"
        });
      } catch (err) {
        console.error(`[AttackChain] Failed to persist chain ${chain.id}:`, err);
      }
    }
  }
  return result;
}
async function getStoredChains(limit = 50) {
  const db = await getDbRequired();
  return db.select().from(attackChainRecords).orderBy(desc(attackChainRecords.createdAt)).limit(limit);
}
function calculateChainSeverity(links, pattern) {
  if (links.length === 0) return { severity: "low", score: 0 };
  const severityOrder = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  const maxIndividual = Math.max(...links.map((l) => severityOrder[l.severity]));
  const lengthBonus = Math.min(2, (links.length - 1) * 0.5);
  const patternBoost = pattern ? pattern.severityBoost * 0.5 : 0;
  const validatedCount = links.filter((l) => l.validated).length;
  const validationBonus = validatedCount / links.length * 0.5;
  const uniqueTargets = new Set(links.map((l) => l.target)).size;
  const crossTargetBonus = uniqueTargets > 1 ? 0.5 : 0;
  const combinedLevel = Math.min(4, maxIndividual + lengthBonus + patternBoost + validationBonus + crossTargetBonus);
  const score = Math.min(10, combinedLevel * 2.5);
  let severity;
  if (combinedLevel >= 3.5) severity = "critical";
  else if (combinedLevel >= 2.5) severity = "high";
  else if (combinedLevel >= 1.5) severity = "medium";
  else severity = "low";
  return { severity, score: Math.round(score * 10) / 10 };
}
function findCapabilityMapping(title, description) {
  const combined = `${title} ${description}`.toLowerCase();
  const allCapabilities = [];
  let primaryPhase = "reconnaissance";
  let techniqueId = "TA0043";
  for (const mapping of CAPABILITY_MAPPINGS) {
    if (mapping.keywords.some((kw) => combined.includes(kw))) {
      allCapabilities.push(...mapping.capabilities);
      primaryPhase = mapping.phase;
      techniqueId = mapping.techniqueId;
    }
  }
  return {
    capabilities: Array.from(new Set(allCapabilities)),
    phase: primaryPhase,
    techniqueId
  };
}
function matchChainPattern(pattern, findings) {
  const allCapabilities = new Set(findings.flatMap((f) => f.capabilities));
  const requiredMet = pattern.requiredCapabilities.filter((rc) => allCapabilities.has(rc));
  if (requiredMet.length < Math.ceil(pattern.requiredCapabilities.length * 0.5)) {
    return null;
  }
  const links = [];
  const usedFindings = /* @__PURE__ */ new Set();
  for (const phase of pattern.phases) {
    const matchingFinding = findings.find(
      (f) => f.phase === phase && !usedFindings.has(f.id)
    );
    if (matchingFinding) {
      usedFindings.add(matchingFinding.id);
      links.push({
        findingId: matchingFinding.id,
        title: matchingFinding.title,
        severity: matchingFinding.severity,
        phase,
        attackTechnique: matchingFinding.attackTechnique || matchingFinding.techniqueId || mapPhaseToTechnique(phase),
        target: matchingFinding.target,
        port: matchingFinding.port,
        prerequisite: links.length > 0 ? links[links.length - 1].provides.join(", ") : null,
        provides: matchingFinding.provides,
        validated: matchingFinding.validated
      });
    }
  }
  if (links.length < pattern.minimumLinks) {
    return null;
  }
  const { severity, score } = calculateChainSeverity(links, pattern);
  const validatedLinks = links.filter((l) => l.validated).length;
  const feasibility = validatedLinks === links.length ? "confirmed" : validatedLinks > 0 ? "likely" : links.length >= 3 ? "possible" : "theoretical";
  return {
    id: `chain-${++chainCounter}`,
    name: pattern.name,
    description: pattern.description,
    links,
    chainSeverity: severity,
    chainScore: score,
    impactDescription: pattern.businessImpact,
    killChainCoverage: Array.from(new Set(links.map((l) => l.phase))),
    mitreTechniques: Array.from(new Set(links.map((l) => l.attackTechnique))),
    feasibility,
    businessImpact: pattern.businessImpact
  };
}
function discoverAdHocChains(findings) {
  const chains = [];
  const byTarget = /* @__PURE__ */ new Map();
  for (const f of findings) {
    const existing = byTarget.get(f.target) || [];
    existing.push(f);
    byTarget.set(f.target, existing);
  }
  const phaseOrder = [
    "reconnaissance",
    "initial_access",
    "execution",
    "persistence",
    "privilege_escalation",
    "defense_evasion",
    "credential_access",
    "discovery",
    "lateral_movement",
    "collection",
    "exfiltration",
    "impact"
  ];
  for (const [target, targetFindings] of Array.from(byTarget.entries())) {
    if (targetFindings.length < 2) continue;
    const phases = new Set(targetFindings.map((f) => f.phase));
    if (phases.size < 2) continue;
    const sorted = [...targetFindings].sort(
      (a, b) => phaseOrder.indexOf(a.phase) - phaseOrder.indexOf(b.phase)
    );
    const usedPhases = /* @__PURE__ */ new Set();
    const links = [];
    for (const f of sorted) {
      if (usedPhases.has(f.phase)) continue;
      usedPhases.add(f.phase);
      links.push({
        findingId: f.id,
        title: f.title,
        severity: f.severity,
        phase: f.phase,
        attackTechnique: f.attackTechnique || f.techniqueId || mapPhaseToTechnique(f.phase),
        target: f.target,
        port: f.port,
        prerequisite: links.length > 0 ? links[links.length - 1].provides.join(", ") : null,
        provides: f.provides,
        validated: f.validated
      });
    }
    if (links.length >= 2) {
      const { severity, score } = calculateChainSeverity(links);
      const validatedLinks = links.filter((l) => l.validated).length;
      chains.push({
        id: `chain-adhoc-${++chainCounter}`,
        name: `Multi-Phase Attack Path on ${target}`,
        description: `${links.length}-step attack chain identified across ${links.map((l) => l.phase).join(" \u2192 ")} phases on ${target}`,
        links,
        chainSeverity: severity,
        chainScore: score,
        impactDescription: `Combined exploitation of ${links.length} findings on ${target} creates a multi-phase attack path`,
        killChainCoverage: Array.from(usedPhases),
        mitreTechniques: Array.from(new Set(links.map((l) => l.attackTechnique))),
        feasibility: validatedLinks === links.length ? "confirmed" : validatedLinks > 0 ? "likely" : "possible",
        businessImpact: `Multi-phase compromise of ${target} via ${links.length} chained vulnerabilities`
      });
    }
  }
  return chains;
}
function discoverCrossTargetChains(findings) {
  const chains = [];
  const pivotCapabilities = ["credential_reuse", "network_pivot", "lateral_movement", "credential_extraction", "credential_harvesting"];
  const entryCapabilities = ["code_execution", "ssrf", "internal_access", "default_credentials", "auth_bypass"];
  const pivotFindings = findings.filter(
    (f) => f.capabilities.some((c) => pivotCapabilities.includes(c))
  );
  for (const pivot of pivotFindings) {
    const otherTargetFindings = findings.filter(
      (f) => f.target !== pivot.target && f.capabilities.some((c) => entryCapabilities.includes(c))
    );
    for (const destination of otherTargetFindings) {
      const entryFinding = findings.find(
        (f) => f.target === pivot.target && f.id !== pivot.id && ["reconnaissance", "initial_access"].includes(f.phase)
      );
      const links = [];
      if (entryFinding) {
        links.push({
          findingId: entryFinding.id,
          title: entryFinding.title,
          severity: entryFinding.severity,
          phase: entryFinding.phase,
          attackTechnique: entryFinding.attackTechnique || entryFinding.techniqueId || mapPhaseToTechnique(entryFinding.phase),
          target: entryFinding.target,
          port: entryFinding.port,
          prerequisite: null,
          provides: entryFinding.provides,
          validated: entryFinding.validated
        });
      }
      links.push({
        findingId: pivot.id,
        title: pivot.title,
        severity: pivot.severity,
        phase: pivot.phase,
        attackTechnique: pivot.attackTechnique || pivot.techniqueId || mapPhaseToTechnique(pivot.phase),
        target: pivot.target,
        port: pivot.port,
        prerequisite: links.length > 0 ? links[links.length - 1].provides.join(", ") : null,
        provides: pivot.provides,
        validated: pivot.validated
      });
      links.push({
        findingId: destination.id,
        title: destination.title,
        severity: destination.severity,
        phase: "lateral_movement",
        attackTechnique: destination.attackTechnique || destination.techniqueId || "T1021",
        target: destination.target,
        port: destination.port,
        prerequisite: pivot.provides.join(", "),
        provides: destination.provides,
        validated: destination.validated
      });
      if (links.length >= 2) {
        const { severity, score } = calculateChainSeverity(links);
        const validatedLinks = links.filter((l) => l.validated).length;
        chains.push({
          id: `chain-pivot-${++chainCounter}`,
          name: `Cross-Target Pivot: ${pivot.target} \u2192 ${destination.target}`,
          description: `Lateral movement chain from ${pivot.target} to ${destination.target} via ${pivot.title}`,
          links,
          chainSeverity: severity,
          chainScore: score,
          impactDescription: `Network pivot from ${pivot.target} enables compromise of ${destination.target}`,
          killChainCoverage: Array.from(new Set(links.map((l) => l.phase))),
          mitreTechniques: Array.from(new Set(links.map((l) => l.attackTechnique))),
          feasibility: validatedLinks === links.length ? "confirmed" : validatedLinks > 0 ? "likely" : "possible",
          businessImpact: `Multi-host compromise via lateral movement from ${pivot.target} to ${destination.target}`
        });
      }
    }
  }
  return chains;
}
function buildChainFromPath(pathFindings, source) {
  if (pathFindings.length < 2) return null;
  const links = pathFindings.map((f, i) => ({
    findingId: f.id,
    title: f.title,
    severity: f.severity,
    phase: f.phase,
    attackTechnique: f.attackTechnique || f.techniqueId || mapPhaseToTechnique(f.phase),
    target: f.target,
    port: f.port,
    prerequisite: i > 0 ? pathFindings[i - 1].provides.join(", ") : null,
    provides: f.provides,
    validated: f.validated
  }));
  const { severity, score } = calculateChainSeverity(links);
  const validatedLinks = links.filter((l) => l.validated).length;
  const uniqueTargets = new Set(links.map((l) => l.target));
  return {
    id: `chain-${source}-${++chainCounter}`,
    name: uniqueTargets.size > 1 ? `Optimal Attack Path: ${Array.from(uniqueTargets).join(" \u2192 ")}` : `Optimal Attack Path on ${links[0].target}`,
    description: `Graph-optimized ${links.length}-step attack path across ${links.map((l) => l.phase).join(" \u2192 ")}`,
    links,
    chainSeverity: severity,
    chainScore: score,
    impactDescription: `Algorithmically-discovered optimal exploitation path with ${links.length} steps`,
    killChainCoverage: Array.from(new Set(links.map((l) => l.phase))),
    mitreTechniques: Array.from(new Set(links.map((l) => l.attackTechnique))),
    feasibility: validatedLinks === links.length ? "confirmed" : validatedLinks > 0 ? "likely" : "possible",
    businessImpact: `Optimal attack path exploiting ${links.length} vulnerabilities across ${uniqueTargets.size} target(s)`
  };
}
function deduplicateChains(chains) {
  const seen = /* @__PURE__ */ new Set();
  return chains.filter((chain) => {
    const key = chain.links.map((l) => l.findingId).sort().join(",");
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}
function mapPhaseToTechnique(phase) {
  const mapping = {
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
    impact: "TA0040"
  };
  return mapping[phase] || "TA0001";
}
function resetChainCounter() {
  chainCounter = 0;
}
export {
  CHAIN_PATTERNS,
  analyzeAndPersistChains,
  analyzeAttackChains,
  calculateChainSeverity,
  getStoredChains,
  resetChainCounter
};
