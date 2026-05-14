import "./chunk-KFQGP6VL.js";

// server/lib/attack-chain-correlator.ts
var MITRE_KILL_CHAIN_ORDER = {
  "reconnaissance": 0,
  "resource-development": 1,
  "initial-access": 2,
  "execution": 3,
  "persistence": 4,
  "privilege-escalation": 5,
  "defense-evasion": 6,
  "credential-access": 7,
  "discovery": 8,
  "lateral-movement": 9,
  "collection": 10,
  "command-and-control": 11,
  "exfiltration": 12,
  "impact": 13
};
var TECHNIQUE_TO_TACTIC = {
  "T1190": "initial-access",
  "T1133": "initial-access",
  "T1078": "initial-access",
  "T1059": "execution",
  "T1203": "execution",
  "T1047": "execution",
  "T1053": "persistence",
  "T1136": "persistence",
  "T1543": "persistence",
  "T1548": "privilege-escalation",
  "T1068": "privilege-escalation",
  "T1055": "privilege-escalation",
  "T1562": "defense-evasion",
  "T1070": "defense-evasion",
  "T1036": "defense-evasion",
  "T1110": "credential-access",
  "T1003": "credential-access",
  "T1558": "credential-access",
  "T1046": "discovery",
  "T1082": "discovery",
  "T1087": "discovery",
  "T1021": "lateral-movement",
  "T1570": "lateral-movement",
  "T1563": "lateral-movement",
  "T1005": "collection",
  "T1039": "collection",
  "T1114": "collection",
  "T1071": "command-and-control",
  "T1095": "command-and-control",
  "T1041": "exfiltration",
  "T1048": "exfiltration",
  "T1486": "impact",
  "T1489": "impact",
  "T1529": "impact"
};
var SEV_SCORE = {
  critical: 10,
  high: 8,
  medium: 6,
  moderate: 5,
  low: 3,
  info: 1,
  informational: 1
};
function correlateFindings(findings) {
  if (findings.length < 2) return [];
  const chains = [];
  const assetClusters = clusterByAsset(findings);
  for (const [hostname, cluster] of assetClusters) {
    if (cluster.length < 2) continue;
    const chain = buildAssetChain(hostname, cluster);
    if (chain && chain.steps.length >= 2) chains.push(chain);
  }
  const mitreChains = detectMitreProgression(findings);
  for (const chain of mitreChains) {
    if (!chains.some((c) => c.name === chain.name)) chains.push(chain);
  }
  const cveChains = detectCveChains(findings);
  for (const chain of cveChains) {
    if (!chains.some((c) => c.name === chain.name)) chains.push(chain);
  }
  const serviceChains = detectServiceDependencyChains(findings);
  for (const chain of serviceChains) {
    if (!chains.some((c) => c.name === chain.name)) chains.push(chain);
  }
  return chains.map((c) => ({ ...c, compositeRiskScore: calculateCompositeScore(c), compositeSeverity: calculateCompositeSeverity(c) })).sort((a, b) => b.compositeRiskScore - a.compositeRiskScore);
}
function clusterByAsset(findings) {
  const clusters = /* @__PURE__ */ new Map();
  for (const f of findings) {
    const key = f.hostname?.toLowerCase() || "unknown";
    if (!clusters.has(key)) clusters.set(key, []);
    clusters.get(key).push(f);
  }
  return clusters;
}
function buildAssetChain(hostname, findings) {
  const sorted = [...findings].sort((a, b) => {
    const sevDiff = (SEV_SCORE[b.severity] || 0) - (SEV_SCORE[a.severity] || 0);
    if (sevDiff !== 0) return sevDiff;
    const tacticA = a.mitreTechnique ? MITRE_KILL_CHAIN_ORDER[TECHNIQUE_TO_TACTIC[a.mitreTechnique.split(".")[0]] || ""] || 99 : 99;
    const tacticB = b.mitreTechnique ? MITRE_KILL_CHAIN_ORDER[TECHNIQUE_TO_TACTIC[b.mitreTechnique.split(".")[0]] || ""] || 99 : 99;
    return tacticA - tacticB;
  });
  const hasHighSev = sorted.some((f) => SEV_SCORE[f.severity] >= 8);
  if (!hasHighSev && sorted.length < 3) return null;
  const signals = [`${sorted.length} findings on shared asset ${hostname}`];
  const tactics = /* @__PURE__ */ new Set();
  const steps = sorted.slice(0, 10).map((f, i) => {
    const technique = f.mitreTechnique?.split(".")[0] || "";
    const tactic = TECHNIQUE_TO_TACTIC[technique] || inferTacticFromFinding(f);
    if (tactic) tactics.add(tactic);
    return {
      stepOrder: i + 1,
      title: f.title,
      description: f.description || `${f.severity} vulnerability on ${hostname}`,
      severity: f.severity,
      cveId: f.cve || void 0,
      cweId: f.cwe || void 0,
      affectedAsset: hostname,
      mitreTechnique: f.mitreTechnique || void 0,
      mitreTactic: tactic || void 0,
      findingType: inferFindingType(f),
      sourceFindingId: f.id
    };
  });
  if (tactics.size > 1) signals.push(`Spans ${tactics.size} MITRE tactics`);
  const highestSev = sorted[0];
  return {
    name: `Multi-Vulnerability Chain on ${hostname}`,
    description: `${sorted.length} related vulnerabilities discovered on ${hostname}, including ${highestSev.severity}-severity ${highestSev.title}. This chain represents the combined attack surface of a single asset with multiple exploitable weaknesses.`,
    entryPoint: hostname,
    finalTarget: hostname,
    mitreTactics: Array.from(tactics),
    compositeRiskScore: 0,
    // calculated later
    compositeSeverity: "moderate",
    // calculated later
    steps,
    correlationSignals: signals,
    confidence: Math.min(95, 50 + sorted.length * 5 + (hasHighSev ? 15 : 0))
  };
}
function detectMitreProgression(findings) {
  const chains = [];
  const withTactics = findings.filter((f) => f.mitreTechnique).map((f) => {
    const technique = f.mitreTechnique.split(".")[0];
    const tactic = TECHNIQUE_TO_TACTIC[technique] || "";
    const order = MITRE_KILL_CHAIN_ORDER[tactic] ?? 99;
    return { ...f, tactic, order };
  }).filter((f) => f.order < 99);
  if (withTactics.length < 2) return chains;
  withTactics.sort((a, b) => a.order - b.order);
  let currentChain = [withTactics[0]];
  for (let i = 1; i < withTactics.length; i++) {
    const prev = currentChain[currentChain.length - 1];
    const curr = withTactics[i];
    if (curr.order - prev.order <= 2 && curr.order >= prev.order) {
      currentChain.push(curr);
    } else {
      if (currentChain.length >= 3) {
        chains.push(buildMitreChain(currentChain));
      }
      currentChain = [curr];
    }
  }
  if (currentChain.length >= 3) {
    chains.push(buildMitreChain(currentChain));
  }
  return chains;
}
function buildMitreChain(findings) {
  const tactics = [...new Set(findings.map((f) => f.tactic))];
  const entry = findings[0];
  const target = findings[findings.length - 1];
  return {
    name: `Kill Chain: ${tactics[0]} \u2192 ${tactics[tactics.length - 1]}`,
    description: `MITRE ATT&CK kill chain progression spanning ${tactics.length} tactics from ${tactics[0]} to ${tactics[tactics.length - 1]}. This chain shows a realistic attack path through ${findings.length} linked techniques.`,
    entryPoint: entry.hostname || "External",
    finalTarget: target.hostname || "Internal Target",
    mitreTactics: tactics,
    compositeRiskScore: 0,
    compositeSeverity: "moderate",
    steps: findings.map((f, i) => ({
      stepOrder: i + 1,
      title: f.title,
      description: f.description || `${f.tactic} technique ${f.mitreTechnique}`,
      severity: f.severity,
      cveId: f.cve || void 0,
      cweId: f.cwe || void 0,
      affectedAsset: f.hostname || "Unknown",
      mitreTechnique: f.mitreTechnique || void 0,
      mitreTactic: f.tactic,
      findingType: inferFindingType(f),
      sourceFindingId: f.id
    })),
    correlationSignals: [
      `${tactics.length}-tactic kill chain progression`,
      `Spans ${findings.length} linked techniques`,
      `From ${tactics[0]} to ${tactics[tactics.length - 1]}`
    ],
    confidence: Math.min(95, 40 + tactics.length * 10 + findings.length * 3)
  };
}
function detectCveChains(findings) {
  const chains = [];
  const withCve = findings.filter((f) => f.cve);
  const rceFindings = withCve.filter(
    (f) => f.title.toLowerCase().includes("remote code execution") || f.title.toLowerCase().includes("rce") || f.cwe?.includes("CWE-94") || f.cwe?.includes("CWE-78")
  );
  const privescFindings = withCve.filter(
    (f) => f.title.toLowerCase().includes("privilege escalation") || f.title.toLowerCase().includes("privesc") || f.cwe?.includes("CWE-269") || f.cwe?.includes("CWE-250")
  );
  for (const rce of rceFindings) {
    for (const pe of privescFindings) {
      if (rce.id === pe.id) continue;
      const steps = [
        {
          stepOrder: 1,
          title: rce.title,
          description: rce.description || "Remote code execution vulnerability",
          severity: rce.severity,
          cveId: rce.cve || void 0,
          cweId: rce.cwe || void 0,
          affectedAsset: rce.hostname,
          mitreTechnique: rce.mitreTechnique || "T1190",
          mitreTactic: "initial-access",
          findingType: "vulnerability",
          sourceFindingId: rce.id
        },
        {
          stepOrder: 2,
          title: pe.title,
          description: pe.description || "Privilege escalation vulnerability",
          severity: pe.severity,
          cveId: pe.cve || void 0,
          cweId: pe.cwe || void 0,
          affectedAsset: pe.hostname,
          mitreTechnique: pe.mitreTechnique || "T1068",
          mitreTactic: "privilege-escalation",
          findingType: "privilege_escalation",
          sourceFindingId: pe.id
        }
      ];
      chains.push({
        name: `RCE \u2192 PrivEsc: ${rce.cve || rce.title.slice(0, 30)} + ${pe.cve || pe.title.slice(0, 30)}`,
        description: `Exploit chain combining remote code execution (${rce.cve || "N/A"}) with privilege escalation (${pe.cve || "N/A"}). An attacker could gain initial access via RCE then escalate to administrative privileges.`,
        entryPoint: rce.hostname,
        finalTarget: pe.hostname,
        mitreTactics: ["initial-access", "privilege-escalation"],
        compositeRiskScore: 0,
        compositeSeverity: "critical",
        steps,
        correlationSignals: ["RCE + PrivEsc exploit chain pattern", `CVEs: ${rce.cve || "?"}, ${pe.cve || "?"}`],
        confidence: 85
      });
    }
  }
  const sqliFindings = withCve.filter(
    (f) => f.title.toLowerCase().includes("sql injection") || f.cwe?.includes("CWE-89")
  );
  const dataFindings = withCve.filter(
    (f) => f.title.toLowerCase().includes("information disclosure") || f.title.toLowerCase().includes("data exposure") || f.cwe?.includes("CWE-200")
  );
  for (const sqli of sqliFindings.slice(0, 3)) {
    for (const data of dataFindings.slice(0, 3)) {
      if (sqli.id === data.id) continue;
      chains.push({
        name: `SQLi \u2192 Data Exfil: ${sqli.hostname}`,
        description: `SQL injection on ${sqli.hostname} combined with data exposure on ${data.hostname}. Attacker could leverage SQLi to access and exfiltrate sensitive data.`,
        entryPoint: sqli.hostname,
        finalTarget: data.hostname,
        mitreTactics: ["initial-access", "collection", "exfiltration"],
        compositeRiskScore: 0,
        compositeSeverity: "high",
        steps: [
          { stepOrder: 1, title: sqli.title, description: sqli.description || "", severity: sqli.severity, cveId: sqli.cve || void 0, affectedAsset: sqli.hostname, mitreTactic: "initial-access", findingType: "vulnerability", sourceFindingId: sqli.id },
          { stepOrder: 2, title: data.title, description: data.description || "", severity: data.severity, cveId: data.cve || void 0, affectedAsset: data.hostname, mitreTactic: "collection", findingType: "data_access", sourceFindingId: data.id }
        ],
        correlationSignals: ["SQLi \u2192 Data Exfiltration pattern"],
        confidence: 70
      });
    }
  }
  return chains.slice(0, 10);
}
function detectServiceDependencyChains(findings) {
  const chains = [];
  const webFindings = findings.filter((f) => f.port === 80 || f.port === 443 || f.port === 8080 || f.port === 8443);
  const dbFindings = findings.filter((f) => f.port === 3306 || f.port === 5432 || f.port === 1433 || f.port === 27017);
  const sshFindings = findings.filter((f) => f.port === 22 || f.port === 3389);
  const internalFindings = findings.filter(
    (f) => f.hostname?.match(/^(10\.|172\.(1[6-9]|2[0-9]|3[01])\.|192\.168\.)/) || f.hostname?.includes("internal") || f.hostname?.includes("intranet")
  );
  if (webFindings.length > 0 && dbFindings.length > 0) {
    const webEntry = webFindings.sort((a, b) => (SEV_SCORE[b.severity] || 0) - (SEV_SCORE[a.severity] || 0))[0];
    const dbTarget = dbFindings.sort((a, b) => (SEV_SCORE[b.severity] || 0) - (SEV_SCORE[a.severity] || 0))[0];
    chains.push({
      name: `Web App \u2192 Database: ${webEntry.hostname} \u2192 ${dbTarget.hostname}`,
      description: `Service dependency chain from web application (${webEntry.hostname}) to database server (${dbTarget.hostname}). Web application vulnerabilities could be leveraged to pivot to the database layer.`,
      entryPoint: webEntry.hostname,
      finalTarget: dbTarget.hostname,
      mitreTactics: ["initial-access", "lateral-movement", "collection"],
      compositeRiskScore: 0,
      compositeSeverity: "high",
      steps: [
        { stepOrder: 1, title: webEntry.title, description: webEntry.description || "", severity: webEntry.severity, cveId: webEntry.cve || void 0, affectedAsset: webEntry.hostname, mitreTactic: "initial-access", findingType: "vulnerability", sourceFindingId: webEntry.id },
        { stepOrder: 2, title: dbTarget.title, description: dbTarget.description || "", severity: dbTarget.severity, cveId: dbTarget.cve || void 0, affectedAsset: dbTarget.hostname, mitreTactic: "lateral-movement", findingType: "lateral_movement", sourceFindingId: dbTarget.id }
      ],
      correlationSignals: ["Web \u2192 Database service dependency", `Ports: ${webEntry.port} \u2192 ${dbTarget.port}`],
      confidence: 65
    });
  }
  if (webFindings.length > 0 && sshFindings.length > 0 && internalFindings.length > 0) {
    const entry = webFindings[0];
    const pivot = sshFindings[0];
    const target = internalFindings[0];
    chains.push({
      name: `External \u2192 Pivot \u2192 Internal: ${entry.hostname} \u2192 ${target.hostname}`,
      description: `Multi-hop attack chain from external web application through SSH/RDP pivot to internal network.`,
      entryPoint: entry.hostname,
      finalTarget: target.hostname,
      mitreTactics: ["initial-access", "credential-access", "lateral-movement"],
      compositeRiskScore: 0,
      compositeSeverity: "critical",
      steps: [
        { stepOrder: 1, title: entry.title, description: entry.description || "", severity: entry.severity, affectedAsset: entry.hostname, mitreTactic: "initial-access", findingType: "vulnerability", sourceFindingId: entry.id },
        { stepOrder: 2, title: pivot.title, description: pivot.description || "", severity: pivot.severity, affectedAsset: pivot.hostname, mitreTactic: "credential-access", findingType: "credential", sourceFindingId: pivot.id },
        { stepOrder: 3, title: target.title, description: target.description || "", severity: target.severity, affectedAsset: target.hostname, mitreTactic: "lateral-movement", findingType: "lateral_movement", sourceFindingId: target.id }
      ],
      correlationSignals: ["External \u2192 Pivot \u2192 Internal multi-hop pattern"],
      confidence: 60
    });
  }
  return chains;
}
function calculateCompositeScore(chain) {
  if (chain.steps.length === 0) return 0;
  const scores = chain.steps.map((s) => SEV_SCORE[s.severity] || 0);
  const maxSev = Math.max(...scores);
  const avgSev = scores.reduce((a, b) => a + b, 0) / scores.length;
  const chainLenBonus = Math.min(chain.steps.length * 0.3, 2);
  const tacticBonus = Math.min(chain.mitreTactics.length * 0.2, 1.5);
  const confidenceMultiplier = chain.confidence / 100;
  return Math.min(10, (maxSev * 0.5 + avgSev * 0.2 + chainLenBonus + tacticBonus) * confidenceMultiplier + 1);
}
function calculateCompositeSeverity(chain) {
  const score = chain.compositeRiskScore || calculateCompositeScore(chain);
  if (score >= 9) return "critical";
  if (score >= 7) return "high";
  if (score >= 4) return "moderate";
  if (score >= 2) return "low";
  return "informational";
}
function inferTacticFromFinding(f) {
  const title = (f.title || "").toLowerCase();
  const desc = (f.description || "").toLowerCase();
  const combined = title + " " + desc;
  if (combined.includes("remote code execution") || combined.includes("rce") || combined.includes("injection")) return "initial-access";
  if (combined.includes("privilege escalation") || combined.includes("privesc")) return "privilege-escalation";
  if (combined.includes("credential") || combined.includes("password") || combined.includes("brute force")) return "credential-access";
  if (combined.includes("lateral") || combined.includes("pivot")) return "lateral-movement";
  if (combined.includes("exfiltration") || combined.includes("data leak")) return "exfiltration";
  if (combined.includes("persistence") || combined.includes("backdoor")) return "persistence";
  if (combined.includes("discovery") || combined.includes("enumeration") || combined.includes("information disclosure")) return "discovery";
  if (combined.includes("command and control") || combined.includes("c2") || combined.includes("beacon")) return "command-and-control";
  if (combined.includes("denial of service") || combined.includes("dos") || combined.includes("ransomware")) return "impact";
  if (combined.includes("evasion") || combined.includes("bypass")) return "defense-evasion";
  return "";
}
function inferFindingType(f) {
  const title = (f.title || "").toLowerCase();
  if (title.includes("misconfiguration") || title.includes("config")) return "misconfiguration";
  if (title.includes("credential") || title.includes("password") || title.includes("auth")) return "credential";
  if (title.includes("exposure") || title.includes("disclosure")) return "exposure";
  if (title.includes("social engineering") || title.includes("phishing")) return "social_engineering";
  if (title.includes("privilege escalation") || title.includes("privesc")) return "privilege_escalation";
  if (title.includes("lateral") || title.includes("pivot")) return "lateral_movement";
  if (title.includes("data access") || title.includes("exfil")) return "data_access";
  return "vulnerability";
}
export {
  correlateFindings
};
