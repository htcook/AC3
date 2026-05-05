import {
  VULNERABILITY_CATALOG,
  buildTaxonomyContext,
  getProtocolKnowledge,
  getVulnsForTechnology,
  init_exploit_source_taxonomy
} from "./chunk-R3UICRXX.js";
import {
  __esm,
  __export
} from "./chunk-KFQGP6VL.js";

// server/lib/exploit-reasoning-engine.ts
var exploit_reasoning_engine_exports = {};
__export(exploit_reasoning_engine_exports, {
  buildAttackGraph: () => buildAttackGraph,
  buildReasoningPromptSection: () => buildReasoningPromptSection,
  runReasoningEngine: () => runReasoningEngine
});
function matchFindingToVulnClass(finding) {
  const title = finding.title.toLowerCase();
  const desc = (finding.description || "").toLowerCase();
  const combined = `${title} ${desc}`;
  const keywordMap = [
    { keywords: ["sql injection", "sqli", "sql syntax"], vulnId: "SW-INJ-001", weight: 10 },
    { keywords: ["command injection", "os command", "rce", "remote code execution", "code execution"], vulnId: "SW-INJ-002", weight: 10 },
    { keywords: ["cross-site scripting", "xss", "script injection"], vulnId: "SW-INJ-003", weight: 10 },
    { keywords: ["ssrf", "server-side request forgery", "server side request"], vulnId: "SW-INJ-004", weight: 10 },
    { keywords: ["buffer overflow", "stack overflow", "heap overflow", "memory corruption"], vulnId: "SW-MEM-001", weight: 10 },
    { keywords: ["use-after-free", "use after free", "uaf", "dangling pointer"], vulnId: "SW-MEM-002", weight: 10 },
    { keywords: ["deserialization", "deserializ", "java serializ", "pickle", "marshal"], vulnId: "SW-DESER-001", weight: 10 },
    { keywords: ["authentication bypass", "auth bypass", "broken auth", "idor", "insecure direct object"], vulnId: "SW-AUTH-001", weight: 10 },
    { keywords: ["default credential", "default password", "weak password", "factory default"], vulnId: "CFG-CRED-001", weight: 10 },
    { keywords: ["debug", "actuator", "phpinfo", "stack trace", "verbose error", "information disclosure", "api key leak", "api key exposure", "api key exposed", "sensitive data exposure", "sensitive information", "credential exposure", "credential leak", "secret exposed", "secret leak", ".env file", "hardcoded credential", "hardcoded secret", "hardcoded password", "exposed api key", "token leak", "token exposure", "api key in"], vulnId: "CFG-DEBUG-001", weight: 8 },
    { keywords: ["cors", "cross-origin", "access-control-allow-origin"], vulnId: "CFG-CORS-001", weight: 10 },
    { keywords: ["active directory", "ad trust", "domain trust", "sid history"], vulnId: "INTER-TRUST-001", weight: 10 },
    { keywords: ["saml", "sso bypass", "oauth", "oidc", "federation"], vulnId: "INTER-SSO-001", weight: 10 },
    { keywords: ["cloud iam", "iam policy", "s3 bucket", "aws credential", "instance metadata"], vulnId: "PLAT-CLOUD-001", weight: 10 },
    { keywords: ["container escape", "docker escape", "privileged container", "kubernetes"], vulnId: "PLAT-CONTAINER-001", weight: 10 },
    { keywords: ["segmentation", "lateral movement", "flat network", "vlan"], vulnId: "OP-SEG-001", weight: 8 },
    { keywords: ["privilege escalation", "privesc", "suid", "sudo", "local privilege"], vulnId: "OP-PRIV-001", weight: 10 },
    { keywords: ["firmware", "iot", "scada", "plc", "modbus", "bacnet"], vulnId: "DEV-FIRMWARE-001", weight: 10 },
    { keywords: ["dependency confusion", "typosquat", "supply chain"], vulnId: "SC-DEP-001", weight: 10 },
    { keywords: ["ci/cd", "pipeline poison", "github action", "jenkins"], vulnId: "SC-CICD-001", weight: 10 },
    { keywords: ["ntlm relay", "ntlm", "smb relay", "responder"], vulnId: "PROTO-NTLM-001", weight: 10 },
    { keywords: ["kerberoast", "as-rep", "golden ticket", "silver ticket", "kerberos"], vulnId: "PROTO-KERB-001", weight: 10 },
    // Security header findings — classify as configuration issues instead of leaving unknown
    { keywords: ["missing x-frame-options", "x-frame-options", "clickjacking", "anti-clickjacking"], vulnId: "CFG-CORS-001", weight: 3 },
    { keywords: ["missing x-content-type", "x-content-type-options", "content-type-options"], vulnId: "CFG-DEBUG-001", weight: 3 },
    { keywords: ["missing x-xss-protection", "x-xss-protection"], vulnId: "SW-INJ-003", weight: 2 },
    { keywords: ["strict-transport-security", "hsts", "missing hsts"], vulnId: "CFG-CORS-001", weight: 3 },
    { keywords: ["content-security-policy", "content security policy", "missing csp", "csp header"], vulnId: "CFG-CORS-001", weight: 3 },
    { keywords: ["referrer-policy", "permissions-policy", "feature-policy"], vulnId: "CFG-DEBUG-001", weight: 2 },
    { keywords: ["missing security header", "security header"], vulnId: "CFG-DEBUG-001", weight: 2 },
    { keywords: ["ssl", "tls", "certificate", "weak cipher", "self-signed"], vulnId: "CFG-DEBUG-001", weight: 5 },
    { keywords: ["directory listing", "directory indexing", "directory traversal", "path traversal"], vulnId: "CFG-DEBUG-001", weight: 8 },
    { keywords: ["open redirect", "url redirect"], vulnId: "SW-INJ-003", weight: 5 },
    // Exposed services — classify as configuration/segmentation issues
    { keywords: ["publicly accessible ssh", "ssh service", "exposed ssh", "open ssh"], vulnId: "OP-SEG-001", weight: 6 },
    { keywords: ["publicly accessible", "exposed service", "unnecessary service", "open port"], vulnId: "OP-SEG-001", weight: 4 },
    { keywords: ["ftp service", "exposed ftp", "anonymous ftp"], vulnId: "CFG-CRED-001", weight: 6 },
    { keywords: ["telnet", "exposed telnet"], vulnId: "OP-SEG-001", weight: 7 },
    { keywords: ["rdp", "remote desktop", "exposed rdp"], vulnId: "OP-SEG-001", weight: 6 },
    { keywords: ["smb", "exposed smb", "samba"], vulnId: "OP-SEG-001", weight: 6 },
    { keywords: ["snmp", "exposed snmp", "snmp community"], vulnId: "CFG-CRED-001", weight: 6 }
  ];
  let bestMatch = null;
  for (const entry of keywordMap) {
    for (const keyword of entry.keywords) {
      if (combined.includes(keyword)) {
        const score = entry.weight + (title.includes(keyword) ? 5 : 0);
        if (!bestMatch || score > bestMatch.score) {
          bestMatch = { vulnId: entry.vulnId, score };
        }
      }
    }
  }
  if (finding.cve) {
    for (const vuln of VULNERABILITY_CATALOG) {
      for (const tech of vuln.affectedTechnologies) {
        if (tech.knownCves?.includes(finding.cve)) {
          return vuln;
        }
      }
    }
  }
  if (bestMatch) {
    return VULNERABILITY_CATALOG.find((v) => v.id === bestMatch.vulnId) || null;
  }
  return null;
}
function severityToExploitability(severity) {
  switch (severity.toLowerCase()) {
    case "critical":
      return 0.9;
    case "high":
      return 0.75;
    case "medium":
      return 0.5;
    case "low":
      return 0.25;
    default:
      return 0.1;
  }
}
function severityToImpact(severity) {
  switch (severity.toLowerCase()) {
    case "critical":
      return 1;
    case "high":
      return 0.8;
    case "medium":
      return 0.5;
    case "low":
      return 0.2;
    default:
      return 0.1;
  }
}
function inferAccessGrants(vulnClass, target) {
  const grants = [];
  const id = vulnClass.id;
  if (["SW-INJ-001", "SW-INJ-002", "SW-DESER-001", "SW-MEM-001", "SW-MEM-002"].includes(id)) {
    grants.push({ type: "shell", scope: `app_user@${target}`, confidence: 0.7 });
  }
  if (["SW-INJ-001"].includes(id)) {
    grants.push({ type: "data", scope: `database@${target}`, confidence: 0.9 });
    grants.push({ type: "credentials", scope: `db_users@${target}`, confidence: 0.6 });
  }
  if (["SW-INJ-002", "SW-DESER-001"].includes(id)) {
    grants.push({ type: "shell", scope: `rce@${target}`, confidence: 0.8 });
  }
  if (["SW-INJ-003"].includes(id)) {
    grants.push({ type: "credentials", scope: `session_tokens@${target}`, confidence: 0.7 });
  }
  if (["SW-INJ-004"].includes(id)) {
    grants.push({ type: "network_access", scope: `internal_network@${target}`, confidence: 0.8 });
    grants.push({ type: "cloud_access", scope: `metadata@${target}`, confidence: 0.6 });
  }
  if (["SW-AUTH-001", "INTER-SSO-001"].includes(id)) {
    grants.push({ type: "credentials", scope: `auth_bypass@${target}`, confidence: 0.8 });
  }
  if (["CFG-CRED-001"].includes(id)) {
    grants.push({ type: "credentials", scope: `valid_creds@${target}`, confidence: 0.9 });
    grants.push({ type: "shell", scope: `authenticated@${target}`, confidence: 0.6 });
  }
  if (["CFG-DEBUG-001"].includes(id)) {
    grants.push({ type: "data", scope: `config_secrets@${target}`, confidence: 0.7 });
  }
  if (["PLAT-CLOUD-001"].includes(id)) {
    grants.push({ type: "cloud_access", scope: `iam_escalation@${target}`, confidence: 0.7 });
  }
  if (["PLAT-CONTAINER-001"].includes(id)) {
    grants.push({ type: "shell", scope: `host_root@${target}`, confidence: 0.7 });
  }
  if (["OP-PRIV-001"].includes(id)) {
    grants.push({ type: "privilege_escalation", scope: `root@${target}`, confidence: 0.8 });
  }
  if (["OP-SEG-001"].includes(id)) {
    grants.push({ type: "lateral_movement", scope: `internal_network`, confidence: 0.7 });
  }
  if (["PROTO-NTLM-001", "PROTO-KERB-001", "INTER-TRUST-001"].includes(id)) {
    grants.push({ type: "credentials", scope: `domain_creds`, confidence: 0.7 });
    grants.push({ type: "lateral_movement", scope: `domain_network`, confidence: 0.6 });
  }
  return grants;
}
function inferAccessRequirements(vulnClass) {
  const reqs = [];
  const layer = vulnClass.layer;
  if (["application", "logic"].includes(layer)) {
    reqs.push({ type: "network_access", scope: "target_port" });
  }
  if (layer === "binary") {
    reqs.push({ type: "network_access", scope: "target_service" });
  }
  if (layer === "identity") {
    reqs.push({ type: "network_access", scope: "domain_controller" });
    if (["PROTO-KERB-001"].includes(vulnClass.id)) {
      reqs.push({ type: "credentials", scope: "any_domain_user" });
    }
  }
  if (layer === "infrastructure") {
    reqs.push({ type: "shell", scope: "target_instance" });
  }
  if (layer === "operational") {
    if (vulnClass.id === "OP-PRIV-001") {
      reqs.push({ type: "shell", scope: "low_privilege_user" });
    }
  }
  return reqs;
}
function buildAttackGraph(input) {
  const nodes = /* @__PURE__ */ new Map();
  const edges = [];
  let nodeCounter = 0;
  const startTime = Date.now();
  for (const asset of input.assets) {
    for (const svc of asset.services) {
      if (nodes.size >= MAX_GRAPH_NODES) break;
      const portNodeId = `port-${asset.hostname}-${svc.port}`;
      if (!nodes.has(portNodeId)) {
        nodes.set(portNodeId, {
          id: portNodeId,
          source: "discovered",
          vulnClassId: "SVC-PORT",
          vulnClassName: `${svc.service || "unknown"}:${svc.port}`,
          finding: {
            title: `Open Port: ${svc.port}/${svc.service || "unknown"}${svc.version ? " " + svc.version : ""}`,
            severity: "info",
            port: svc.port,
            service: svc.service
          },
          target: asset.hostname,
          layer: "network",
          category: "configuration",
          exploitability: 0.15,
          impact: 0.2,
          techniques: [],
          activeDefenses: [],
          providesAccess: [{ type: "network", scope: `${asset.hostname}:${svc.port}`, confidence: 0.9 }],
          requiresAccess: [{ type: "network", scope: asset.hostname }]
        });
      }
    }
  }
  console.log(`[AttackGraph] Phase A0 complete: ${nodes.size} port/service nodes in ${Date.now() - startTime}ms`);
  let unmatchedCount = 0;
  for (const asset of input.assets) {
    for (const vuln of asset.vulns) {
      if (nodes.size >= MAX_GRAPH_NODES) break;
      const vulnClass = matchFindingToVulnClass(vuln);
      if (!vulnClass) {
        unmatchedCount++;
        if (vuln.title.startsWith("Open Port:") || vuln.title.startsWith("Risk Signal:")) continue;
        const fallbackNodeId = `recon-${++nodeCounter}`;
        nodes.set(fallbackNodeId, {
          id: fallbackNodeId,
          source: "discovered",
          vulnClassId: "RECON-UNCLASSIFIED",
          vulnClassName: vuln.title.slice(0, 60),
          finding: {
            title: vuln.title,
            severity: vuln.severity || "info",
            cve: vuln.cve,
            description: vuln.description,
            port: vuln.port,
            source: vuln.source
          },
          discoveredAt: vuln.discoveredAt || void 0,
          target: asset.hostname,
          layer: "application",
          category: "configuration",
          exploitability: severityToExploitability(vuln.severity || "info"),
          impact: severityToImpact(vuln.severity || "info"),
          techniques: [],
          activeDefenses: asset.wafDetected ? ["waf"] : [],
          providesAccess: [],
          requiresAccess: [{ type: "network", scope: asset.hostname }]
        });
        continue;
      }
      const nodeId = `discovered-${++nodeCounter}`;
      nodes.set(nodeId, {
        id: nodeId,
        source: "discovered",
        vulnClassId: vulnClass.id,
        vulnClassName: vulnClass.name,
        finding: {
          title: vuln.title,
          severity: vuln.severity,
          cve: vuln.cve,
          description: vuln.description,
          port: vuln.port,
          source: vuln.source
        },
        discoveredAt: vuln.discoveredAt || void 0,
        target: asset.hostname,
        layer: vulnClass.layer,
        category: vulnClass.category,
        exploitability: severityToExploitability(vuln.severity),
        impact: severityToImpact(vuln.severity),
        techniques: vulnClass.exploitTechniques,
        activeDefenses: asset.wafDetected ? ["waf"] : [],
        providesAccess: inferAccessGrants(vulnClass, asset.hostname),
        requiresAccess: inferAccessRequirements(vulnClass)
      });
    }
    if (nodes.size >= MAX_GRAPH_NODES) break;
    let hypothesizedForAsset = 0;
    for (const tech of asset.technologies) {
      if (nodes.size >= MAX_GRAPH_NODES || hypothesizedForAsset >= MAX_HYPOTHESIZED_PER_ASSET) break;
      const techVulns = getVulnsForTechnology(tech);
      for (const vulnClass of techVulns) {
        if (nodes.size >= MAX_GRAPH_NODES || hypothesizedForAsset >= MAX_HYPOTHESIZED_PER_ASSET) break;
        let alreadyDiscovered = false;
        for (const [, n] of nodes) {
          if (n.vulnClassId === vulnClass.id && n.target === asset.hostname && n.source === "discovered") {
            alreadyDiscovered = true;
            break;
          }
        }
        if (alreadyDiscovered) continue;
        const nodeId = `hypothesized-${++nodeCounter}`;
        nodes.set(nodeId, {
          id: nodeId,
          source: "hypothesized",
          vulnClassId: vulnClass.id,
          vulnClassName: vulnClass.name,
          target: asset.hostname,
          layer: vulnClass.layer,
          category: vulnClass.category,
          exploitability: 0.3,
          impact: severityToImpact(vulnClass.severity),
          techniques: vulnClass.exploitTechniques,
          activeDefenses: input.defenses || [],
          providesAccess: inferAccessGrants(vulnClass, asset.hostname),
          requiresAccess: inferAccessRequirements(vulnClass)
        });
        hypothesizedForAsset++;
      }
    }
    let inferredForAsset = 0;
    for (const svc of asset.services) {
      if (nodes.size >= MAX_GRAPH_NODES || inferredForAsset >= MAX_INFERRED_PER_ASSET) break;
      const proto = getProtocolKnowledge(svc.service);
      if (!proto) continue;
      for (const weakness of proto.inherentWeaknesses) {
        if (nodes.size >= MAX_GRAPH_NODES || inferredForAsset >= MAX_INFERRED_PER_ASSET) break;
        const matchingVuln = VULNERABILITY_CATALOG.find(
          (v) => v.detectionPatterns.some((d) => weakness.toLowerCase().includes(d.pattern.toLowerCase().split("|")[0])) || v.name.toLowerCase().includes(proto.protocol.toLowerCase().split("/")[0])
        );
        if (!matchingVuln) continue;
        let alreadyExists = false;
        for (const [, n] of nodes) {
          if (n.vulnClassId === matchingVuln.id && n.target === asset.hostname) {
            alreadyExists = true;
            break;
          }
        }
        if (alreadyExists) continue;
        const nodeId = `inferred-${++nodeCounter}`;
        nodes.set(nodeId, {
          id: nodeId,
          source: "inferred",
          vulnClassId: matchingVuln.id,
          vulnClassName: matchingVuln.name,
          finding: {
            title: `${proto.protocol} weakness: ${weakness}`,
            severity: matchingVuln.severity,
            port: svc.port,
            service: svc.service
          },
          target: asset.hostname,
          layer: matchingVuln.layer,
          category: matchingVuln.category,
          exploitability: 0.2,
          impact: severityToImpact(matchingVuln.severity),
          techniques: matchingVuln.exploitTechniques,
          activeDefenses: input.defenses || [],
          providesAccess: inferAccessGrants(matchingVuln, asset.hostname),
          requiresAccess: inferAccessRequirements(matchingVuln)
        });
        inferredForAsset++;
      }
    }
  }
  console.log(`[AttackGraph] Phase A1-A3 complete: ${nodes.size} nodes in ${Date.now() - startTime}ms`);
  const nodeList = Array.from(nodes.values());
  const discoveredAndHighImpact = nodeList.filter((n) => n.source === "discovered" || n.exploitability >= 0.5);
  let edgeCount = 0;
  for (const fromNode of discoveredAndHighImpact) {
    if (edgeCount >= MAX_GRAPH_EDGES) break;
    for (const toNode of nodeList) {
      if (edgeCount >= MAX_GRAPH_EDGES) break;
      if (fromNode.id === toNode.id) continue;
      let edgeAdded = false;
      for (const grant of fromNode.providesAccess) {
        if (edgeAdded || edgeCount >= MAX_GRAPH_EDGES) break;
        for (const req of toNode.requiresAccess) {
          if (edgeCount >= MAX_GRAPH_EDGES) break;
          if (accessGrantSatisfiesRequirement(grant, req)) {
            edges.push({
              from: fromNode.id,
              to: toNode.id,
              relationship: inferRelationship(fromNode, toNode),
              dataFlow: grant.type,
              probability: grant.confidence * fromNode.exploitability,
              reasoning: `${fromNode.vulnClassName} provides ${grant.type} (${grant.scope}) which satisfies ${toNode.vulnClassName}'s requirement for ${req.type} (${req.scope})`
            });
            edgeCount++;
            edgeAdded = true;
            break;
          }
        }
      }
      if (!edgeAdded && edgeCount < MAX_GRAPH_EDGES) {
        const fromVuln = VULNERABILITY_CATALOG.find((v) => v.id === fromNode.vulnClassId);
        if (fromVuln?.chainableWith.includes(toNode.vulnClassId)) {
          edges.push({
            from: fromNode.id,
            to: toNode.id,
            relationship: "chains_with",
            dataFlow: "taxonomy_chain",
            probability: 0.5 * fromNode.exploitability,
            reasoning: `Taxonomy indicates ${fromNode.vulnClassName} commonly chains with ${toNode.vulnClassName}`
          });
          edgeCount++;
        }
      }
    }
  }
  console.log(`[AttackGraph] Phase A4 complete: ${edges.length} edges in ${Date.now() - startTime}ms`);
  const paths = discoverPaths(nodes, edges, Math.min(input.maxPathDepth || 5, 4));
  console.log(`[AttackGraph] Phase A5 complete: ${paths.length} paths in ${Date.now() - startTime}ms`);
  const layersCovered = [...new Set(nodeList.map((n) => n.layer))];
  const categoriesCovered = [...new Set(nodeList.map((n) => n.category))];
  return {
    nodes,
    edges,
    paths,
    stats: {
      totalNodes: nodes.size,
      discoveredNodes: nodeList.filter((n) => n.source === "discovered").length,
      hypothesizedNodes: nodeList.filter((n) => n.source !== "discovered").length,
      totalEdges: edges.length,
      totalPaths: paths.length,
      maxPathDepth: paths.reduce((max, p) => Math.max(max, p.nodes.length), 0),
      layersCovered,
      categoriesCovered
    }
  };
}
function accessGrantSatisfiesRequirement(grant, req) {
  if (grant.type === req.type) return true;
  if (grant.type === "shell" && req.type === "network_access") return true;
  if (grant.type === "credentials" && req.type === "authenticated_session") return true;
  if (grant.type === "privilege_escalation" && req.type === "shell") return true;
  if (grant.type === "cloud_access" && req.type === "network_access") return true;
  if (grant.type === "lateral_movement" && req.type === "network_access") return true;
  return false;
}
function inferRelationship(from, to) {
  if (to.category === "operational" && to.vulnClassId === "OP-PRIV-001") return "escalates";
  if (from.target !== to.target) return "pivots";
  if (from.layer !== to.layer) return "chains_with";
  return "enables";
}
function discoverPaths(nodes, edges, maxDepth) {
  const paths = [];
  const adjacency = /* @__PURE__ */ new Map();
  for (const edge of edges) {
    if (!adjacency.has(edge.from)) adjacency.set(edge.from, []);
    adjacency.get(edge.from).push(edge);
  }
  const discoveredNodes = Array.from(nodes.values()).filter((n) => n.source === "discovered").sort((a, b) => b.exploitability - a.exploitability).slice(0, 10);
  let pathCounter = 0;
  let totalIterations = 0;
  let bailedOut = false;
  for (const startNode of discoveredNodes) {
    let dfs2 = function(nodeId, depth) {
      if (paths.length >= MAX_DFS_PATHS || totalIterations >= MAX_DFS_ITERATIONS) {
        bailedOut = true;
        return;
      }
      if (depth > maxDepth) return;
      if (visited.has(nodeId)) return;
      totalIterations++;
      visited.add(nodeId);
      currentPath.push(nodeId);
      if (currentPath.length >= 2) {
        const pathNodes = currentPath.map((id) => nodes.get(id)).filter(Boolean);
        if (pathNodes.length >= 2) {
          const layers = new Set(pathNodes.map((n) => n.layer));
          const categories = new Set(pathNodes.map((n) => n.category));
          if (layers.size >= 2 || categories.size >= 2 || currentPath.length >= 3) {
            const path = buildAttackPath(
              `path-${++pathCounter}`,
              [...currentPath],
              [...currentEdges],
              nodes
            );
            if (path.metrics.feasibility > 0.01) {
              paths.push(path);
            }
          }
        }
      }
      if (paths.length < MAX_DFS_PATHS && totalIterations < MAX_DFS_ITERATIONS) {
        const outEdges = adjacency.get(nodeId) || [];
        const sortedEdges = outEdges.filter((e) => !visited.has(e.to)).sort((a, b) => b.probability - a.probability).slice(0, 5);
        for (const edge of sortedEdges) {
          if (paths.length >= MAX_DFS_PATHS || totalIterations >= MAX_DFS_ITERATIONS) break;
          currentEdges.push(edge);
          dfs2(edge.to, depth + 1);
          currentEdges.pop();
        }
      }
      currentPath.pop();
      visited.delete(nodeId);
    };
    var dfs = dfs2;
    if (paths.length >= MAX_DFS_PATHS || bailedOut) break;
    const visited = /* @__PURE__ */ new Set();
    const currentPath = [];
    const currentEdges = [];
    dfs2(startNode.id, 0);
  }
  if (bailedOut) {
    console.log(`[AttackGraph] DFS bailed out after ${totalIterations} iterations, ${paths.length} paths found`);
  }
  paths.sort((a, b) => {
    const scoreA = a.metrics.feasibility * a.metrics.impact * (a.metrics.layersCrossed + 1);
    const scoreB = b.metrics.feasibility * b.metrics.impact * (b.metrics.layersCrossed + 1);
    return scoreB - scoreA;
  });
  return deduplicatePaths(paths, 20);
}
function buildAttackPath(id, nodeIds, edges, nodes) {
  const pathNodes = nodeIds.map((nid) => nodes.get(nid));
  const layers = new Set(pathNodes.map((n) => n.layer));
  const categories = new Set(pathNodes.map((n) => n.category));
  let feasibility = 1;
  for (const node of pathNodes) {
    feasibility *= node.exploitability;
  }
  for (const edge of edges) {
    feasibility *= edge.probability;
  }
  const impact = Math.max(...pathNodes.map((n) => n.impact));
  const maxOpsec = pathNodes.reduce((max, node) => {
    const nodeMaxOpsec = node.techniques.reduce((m, t) => {
      const opsecScore = t.opsecRisk === "high" ? 3 : t.opsecRisk === "medium" ? 2 : 1;
      return Math.max(m, opsecScore);
    }, 0);
    return Math.max(max, nodeMaxOpsec);
  }, 0);
  const opsecRisk = maxOpsec >= 3 ? "critical" : maxOpsec >= 2 ? "high" : maxOpsec >= 1 ? "medium" : "low";
  const steps = pathNodes.map((node, i) => {
    const bestTechnique = node.techniques[0];
    return {
      order: i + 1,
      nodeId: node.id,
      action: `Exploit ${node.vulnClassName} on ${node.target}`,
      tool: bestTechnique?.tooling[0] || "manual",
      expectedOutcome: bestTechnique?.successIndicators[0] || "Successful exploitation",
      successCriteria: node.providesAccess.length > 0 ? `Obtain ${node.providesAccess[0].type}: ${node.providesAccess[0].scope}` : "Confirm vulnerability",
      opsecConsiderations: bestTechnique?.opsecRisk === "high" ? "High detection risk \u2014 consider alternative technique or timing" : "Standard OPSEC precautions"
    };
  });
  const fallbacks = pathNodes.filter((node) => node.techniques.length > 1).map((node) => ({
    id: `fallback-${node.id}`,
    triggeredBy: node.id,
    alternativeAction: `Use ${node.techniques[1].name} instead of ${node.techniques[0].name}`,
    tool: node.techniques[1].tooling[0] || "manual",
    reasoning: `If primary technique fails, ${node.techniques[1].description}`
  }));
  const mitreMapping = [...new Set(
    pathNodes.flatMap((n) => {
      const vuln = VULNERABILITY_CATALOG.find((v) => v.id === n.vulnClassId);
      return vuln?.mitreIds || [];
    })
  )];
  const name = pathNodes.length <= 3 ? pathNodes.map((n) => n.vulnClassName).join(" \u2192 ") : `${pathNodes[0].vulnClassName} \u2192 ... \u2192 ${pathNodes[pathNodes.length - 1].vulnClassName} (${pathNodes.length} steps)`;
  return {
    id,
    name,
    description: `${pathNodes.length}-step attack path crossing ${layers.size} layer(s) and ${categories.size} category/ies. Starts with ${pathNodes[0].vulnClassName} and culminates in ${pathNodes[pathNodes.length - 1].vulnClassName}.`,
    nodes: nodeIds,
    edges: edges.map((e) => e.reasoning),
    metrics: {
      feasibility,
      impact,
      opsecRisk,
      estimatedTime: estimateTime(pathNodes),
      layersCrossed: layers.size,
      categoriesInvolved: [...categories]
    },
    steps,
    fallbacks,
    mitreMapping
  };
}
function estimateTime(nodes) {
  let totalMinutes = 0;
  for (const node of nodes) {
    const bestTechnique = node.techniques[0];
    if (!bestTechnique) {
      totalMinutes += 30;
      continue;
    }
    switch (bestTechnique.complexity) {
      case "low":
        totalMinutes += 10;
        break;
      case "medium":
        totalMinutes += 30;
        break;
      case "high":
        totalMinutes += 90;
        break;
    }
  }
  if (totalMinutes < 60) return `~${totalMinutes} minutes`;
  return `~${Math.round(totalMinutes / 60 * 10) / 10} hours`;
}
function deduplicatePaths(paths, maxPaths) {
  const seen = /* @__PURE__ */ new Set();
  const unique = [];
  for (const path of paths) {
    const sig = `${path.name}||${path.description}`;
    if (!seen.has(sig)) {
      seen.add(sig);
      unique.push(path);
      if (unique.length >= maxPaths) break;
    }
  }
  return unique;
}
function generateNovelHypotheses(graph, input) {
  const hypotheses = [];
  const nodeList = Array.from(graph.nodes.values());
  let counter = 0;
  const credentialNodes = nodeList.filter(
    (n) => n.providesAccess.some((a) => a.type === "credentials")
  );
  const authRequiringNodes = nodeList.filter(
    (n) => n.requiresAccess.some((r) => r.type === "credentials" || r.type === "authenticated_session")
  );
  if (credentialNodes.length > 0 && authRequiringNodes.length > 0) {
    hypotheses.push({
      id: `hypothesis-${++counter}`,
      title: "Credential Reuse Across Services",
      description: `Credentials obtained from ${credentialNodes[0].vulnClassName} may be reused against ${authRequiringNodes.length} other service(s) requiring authentication.`,
      confidence: "medium",
      involvedNodes: [credentialNodes[0].id, ...authRequiringNodes.slice(0, 3).map((n) => n.id)],
      reasoning: "Users frequently reuse passwords across services. Credentials from one breach often work on other services in the same environment.",
      suggestedValidation: "Try discovered credentials against all authenticated services (SSH, RDP, web admin panels, databases)."
    });
  }
  const ssrfNodes = nodeList.filter((n) => n.vulnClassId === "SW-INJ-004");
  const cloudNodes = nodeList.filter((n) => n.vulnClassId === "PLAT-CLOUD-001");
  if (ssrfNodes.length > 0 && (cloudNodes.length > 0 || input.assets.some((a) => a.technologies.some((t) => t.toLowerCase().includes("aws") || t.toLowerCase().includes("azure") || t.toLowerCase().includes("gcp"))))) {
    hypotheses.push({
      id: `hypothesis-${++counter}`,
      title: "SSRF to Cloud IAM Escalation",
      description: "SSRF vulnerability may allow access to cloud instance metadata service (169.254.169.254), potentially yielding IAM credentials for privilege escalation.",
      confidence: "high",
      involvedNodes: [...ssrfNodes.map((n) => n.id), ...cloudNodes.map((n) => n.id)],
      reasoning: "SSRF is the #1 vector for cloud metadata theft. If the application runs on a cloud instance with an IAM role, SSRF can extract temporary credentials.",
      suggestedValidation: "Test SSRF with http://169.254.169.254/latest/meta-data/ payload. If IMDSv2, try with PUT to get token first."
    });
  }
  const xssNodes = nodeList.filter((n) => n.vulnClassId === "SW-INJ-003");
  const authBypassNodes = nodeList.filter((n) => n.vulnClassId === "SW-AUTH-001");
  if (xssNodes.length > 0) {
    hypotheses.push({
      id: `hypothesis-${++counter}`,
      title: "XSS to Admin Session Hijacking",
      description: "XSS vulnerability can be weaponized to steal admin session cookies, potentially granting full application control.",
      confidence: xssNodes.some((n) => n.source === "discovered") ? "high" : "medium",
      involvedNodes: [...xssNodes.map((n) => n.id), ...authBypassNodes.map((n) => n.id)],
      reasoning: "Stored XSS viewed by admin users can exfiltrate session tokens. Even reflected XSS can be delivered via social engineering.",
      suggestedValidation: "Test XSS payload that exfiltrates document.cookie to OAST server. Check if HttpOnly flag is set on session cookies."
    });
  }
  const sqliNodes = nodeList.filter((n) => n.vulnClassId === "SW-INJ-001");
  if (sqliNodes.length > 0) {
    hypotheses.push({
      id: `hypothesis-${++counter}`,
      title: "SQL Injection to Credential Harvesting to Lateral Movement",
      description: "SQL injection can extract password hashes from the database, which may be cracked or reused for lateral movement to other systems.",
      confidence: sqliNodes.some((n) => n.source === "discovered") ? "high" : "medium",
      involvedNodes: sqliNodes.map((n) => n.id),
      reasoning: "Database user tables often contain password hashes. Cracked passwords frequently work on other services (SSH, RDP, VPN) due to password reuse.",
      suggestedValidation: "Use sqlmap to extract user table. Crack hashes with hashcat. Test credentials against SSH/RDP on all discovered hosts."
    });
  }
  const deserNodes = nodeList.filter((n) => n.vulnClassId === "SW-DESER-001");
  const containerNodes = nodeList.filter((n) => n.vulnClassId === "PLAT-CONTAINER-001");
  if (deserNodes.length > 0 && (containerNodes.length > 0 || input.assets.some((a) => a.technologies.some((t) => t.toLowerCase().includes("docker") || t.toLowerCase().includes("kubernetes"))))) {
    hypotheses.push({
      id: `hypothesis-${++counter}`,
      title: "Deserialization RCE to Container Escape",
      description: "Insecure deserialization provides RCE inside the application container. If the container has privileged capabilities or mounted volumes, escape to host is possible.",
      confidence: "medium",
      involvedNodes: [...deserNodes.map((n) => n.id), ...containerNodes.map((n) => n.id)],
      reasoning: "Modern applications often run in containers. RCE inside a container is the first step; checking for docker.sock, privileged mode, or host mounts enables escape.",
      suggestedValidation: "After RCE, check: ls -la /var/run/docker.sock, cat /proc/1/cgroup, capsh --print. Look for SYS_ADMIN capability."
    });
  }
  const defaultCredNodes = nodeList.filter((n) => n.vulnClassId === "CFG-CRED-001");
  const debugNodes = nodeList.filter((n) => n.vulnClassId === "CFG-DEBUG-001");
  if (defaultCredNodes.length > 0 || debugNodes.length > 0) {
    hypotheses.push({
      id: `hypothesis-${++counter}`,
      title: "Configuration Weakness Chain to RCE",
      description: "Default credentials or exposed debug interfaces can be chained: default creds \u2192 admin panel \u2192 code execution feature (file upload, eval, template injection).",
      confidence: "medium",
      involvedNodes: [...defaultCredNodes.map((n) => n.id), ...debugNodes.map((n) => n.id)],
      reasoning: "Admin panels often have features that enable code execution (file upload, database query, template editing). Debug interfaces may directly expose eval/exec.",
      suggestedValidation: "After admin access, look for: file upload (web shell), database query (stacked queries), template editor (SSTI), plugin installer."
    });
  }
  return hypotheses;
}
function runReasoningEngine(input) {
  const graph = buildAttackGraph(input);
  const novelHypotheses = generateNovelHypotheses(graph, input);
  const recommendedPaths = graph.paths.slice(0, 10);
  const allLayers = ["network", "transport", "application", "binary", "logic", "identity", "infrastructure", "operational"];
  const allCategories = ["software", "configuration", "interoperability", "platform", "operational", "device_iot_scada", "supply_chain", "protocol"];
  const layersCovered = graph.stats.layersCovered;
  const categoriesCovered = graph.stats.categoriesCovered;
  const layersUncovered = allLayers.filter((l) => !layersCovered.includes(l));
  const categoriesUncovered = allCategories.filter((c) => !categoriesCovered.includes(c));
  const discoveredVulnClassIds = new Set(
    Array.from(graph.nodes.values()).filter((n) => n.source === "discovered").map((n) => n.vulnClassId)
  );
  const taxonomyCoverage = discoveredVulnClassIds.size / VULNERABILITY_CATALOG.length;
  const allTechs = [...new Set(input.assets.flatMap((a) => a.technologies))];
  const allServices = input.assets.flatMap((a) => a.services);
  const allFindings = input.assets.flatMap((a) => a.vulns);
  const taxonomyContext = buildTaxonomyContext({
    technologies: allTechs,
    services: allServices,
    findings: allFindings,
    defenses: input.defenses,
    maxTokens: 8e3
  });
  return {
    graph,
    recommendedPaths,
    novelHypotheses,
    coverage: {
      layersCovered,
      layersUncovered,
      categoriesCovered,
      categoriesUncovered,
      taxonomyCoverage
    },
    taxonomyContext
  };
}
function buildReasoningPromptSection(output) {
  const sections = [];
  sections.push("## Cross-Layer Attack Analysis");
  sections.push(`Attack graph: ${output.graph.stats.totalNodes} nodes (${output.graph.stats.discoveredNodes} discovered, ${output.graph.stats.hypothesizedNodes} hypothesized), ${output.graph.stats.totalEdges} edges, ${output.graph.stats.totalPaths} paths`);
  sections.push(`Layers covered: ${output.coverage.layersCovered.join(", ")}`);
  sections.push(`Categories covered: ${output.coverage.categoriesCovered.join(", ")}`);
  sections.push(`Taxonomy coverage: ${Math.round(output.coverage.taxonomyCoverage * 100)}%`);
  if (output.recommendedPaths.length > 0) {
    sections.push("\n### Recommended Attack Paths");
    for (const path of output.recommendedPaths.slice(0, 5)) {
      sections.push(`
**${path.name}** (feasibility: ${(path.metrics.feasibility * 100).toFixed(1)}%, impact: ${(path.metrics.impact * 100).toFixed(0)}%, OPSEC: ${path.metrics.opsecRisk})`);
      sections.push(`${path.description}`);
      for (const step of path.steps) {
        sections.push(`  ${step.order}. ${step.action} [${step.tool}] \u2192 ${step.expectedOutcome}`);
      }
      if (path.mitreMapping.length > 0) {
        sections.push(`  MITRE: ${path.mitreMapping.join(", ")}`);
      }
    }
  }
  if (output.novelHypotheses.length > 0) {
    sections.push("\n### Novel Attack Hypotheses");
    for (const hyp of output.novelHypotheses.slice(0, 3)) {
      sections.push(`- **${hyp.title}** [${hyp.confidence}]: ${hyp.description}`);
      sections.push(`  Validation: ${hyp.suggestedValidation}`);
    }
  }
  if (output.coverage.layersUncovered.length > 0) {
    sections.push(`
### Coverage Gaps`);
    sections.push(`Uncovered layers: ${output.coverage.layersUncovered.join(", ")}`);
    sections.push(`Uncovered categories: ${output.coverage.categoriesUncovered.join(", ")}`);
  }
  return sections.join("\n");
}
var MAX_GRAPH_NODES, MAX_GRAPH_EDGES, MAX_HYPOTHESIZED_PER_ASSET, MAX_INFERRED_PER_ASSET, MAX_DFS_PATHS, MAX_DFS_ITERATIONS;
var init_exploit_reasoning_engine = __esm({
  "server/lib/exploit-reasoning-engine.ts"() {
    "use strict";
    init_exploit_source_taxonomy();
    MAX_GRAPH_NODES = 80;
    MAX_GRAPH_EDGES = 400;
    MAX_HYPOTHESIZED_PER_ASSET = 5;
    MAX_INFERRED_PER_ASSET = 3;
    MAX_DFS_PATHS = 50;
    MAX_DFS_ITERATIONS = 5e3;
  }
});

export {
  buildAttackGraph,
  runReasoningEngine,
  exploit_reasoning_engine_exports,
  init_exploit_reasoning_engine
};
