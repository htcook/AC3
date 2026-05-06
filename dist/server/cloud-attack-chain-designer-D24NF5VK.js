import {
  THREAT_ACTOR_PROFILES,
  generateGraphOnlyPlan,
  init_ai_attack_planner
} from "./chunk-VA2OWKPT.js";
import "./chunk-W537OLJR.js";
import {
  AWS_ATTACK_CATALOG,
  AZURE_ATTACK_CATALOG,
  FULL_CLOUD_CATALOG,
  GCP_ATTACK_CATALOG,
  getCloudMitreTechniques,
  init_cloud_attack_paths
} from "./chunk-VITPD4IQ.js";
import "./chunk-SSYKZXNO.js";
import "./chunk-WP62CKNZ.js";
import {
  init_llm,
  invokeLLM
} from "./chunk-7ZNGVPYR.js";
import "./chunk-RUIEEOYK.js";
import {
  getDb,
  init_db
} from "./chunk-CEPCIPS7.js";
import "./chunk-NRYVRXXR.js";
import {
  aiAttackPlans,
  init_schema
} from "./chunk-TAIMCRAB.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/cloud-attack-chain-designer.ts
async function designAttackChains(findings, options = {}) {
  const maxChains = options.maxChains ?? 3;
  const includeCloudPaths = options.includeCloudPaths ?? true;
  const context = buildFindingsContext(findings);
  let cloudPaths = [];
  if (includeCloudPaths && findings.cloudDetection && findings.cloudDetection.assetsFound > 0) {
    cloudPaths = identifyCloudExploitPaths(findings);
  }
  let graphPlan = null;
  try {
    const planRequest = {
      targetDescription: findings.targetDescription,
      threatActorProfile: options.threatActorProfile,
      environmentContext: {
        cloudProviders: [...new Set(findings.assets.flatMap((a) => a.cloudProviders || []))],
        knownVulnerabilities: findings.assets.flatMap((a) => a.vulns.filter((v) => v.cve).map((v) => v.cve)),
        securityTools: findings.assets.filter((a) => a.wafDetected).map((a) => a.wafDetected)
      },
      constraints: {
        maxSteps: 15,
        stealthLevel: options.stealthLevel || "medium"
      }
    };
    graphPlan = generateGraphOnlyPlan(planRequest);
  } catch {
  }
  const chains = await generateLLMAttackChains(
    context,
    cloudPaths,
    graphPlan,
    findings,
    maxChains,
    options.threatActorProfile
  );
  const summary = buildChainSummary(chains, findings);
  const cloudRiskAssessment = cloudPaths.length > 0 ? assessCloudRisk(findings, cloudPaths) : void 0;
  await persistAttackChains(findings, chains, summary);
  return { chains, summary, cloudRiskAssessment };
}
function buildFindingsContext(findings) {
  const sections = [];
  sections.push(`## Target: ${findings.targetDescription}`);
  sections.push(`## Engagement Type: ${findings.engagementType}`);
  sections.push(`## Assets Discovered: ${findings.assets.length}`);
  for (const asset of findings.assets) {
    const lines = [];
    lines.push(`
### ${asset.hostname}${asset.ip ? ` (${asset.ip})` : ""} [${asset.type}]`);
    if (asset.ports.length > 0) {
      lines.push(`Ports: ${asset.ports.map((p) => `${p.port}/${p.service}${p.version ? ` ${p.version}` : ""}`).join(", ")}`);
    }
    if (asset.vulns.length > 0) {
      lines.push(`Vulnerabilities (${asset.vulns.length}):`);
      for (const v of asset.vulns) {
        lines.push(`  - [${v.severity.toUpperCase()}] ${v.title}${v.cve ? ` (${v.cve})` : ""}`);
      }
    }
    if (asset.zapFindings.length > 0) {
      lines.push(`ZAP Findings (${asset.zapFindings.length}):`);
      for (const z of asset.zapFindings) {
        lines.push(`  - [${z.risk}] ${z.name}`);
      }
    }
    if (asset.wafDetected) {
      lines.push(`WAF Detected: ${asset.wafDetected}`);
    }
    if (asset.cloudProviders && asset.cloudProviders.length > 0) {
      lines.push(`Cloud Providers: ${asset.cloudProviders.join(", ")}`);
      if (asset.cloudServices) {
        lines.push(`Cloud Services: ${asset.cloudServices.join(", ")}`);
      }
    }
    sections.push(lines.join("\n"));
  }
  if (findings.cloudDetection && findings.cloudDetection.assetsFound > 0) {
    sections.push(`
## Cloud Infrastructure Detected`);
    sections.push(`Cloud assets: ${findings.cloudDetection.assetsFound}`);
    sections.push(`Storage endpoints: ${findings.cloudDetection.storageEndpoints}`);
    if (findings.cloudDetection.findings.length > 0) {
      sections.push(`Cloud Misconfigurations:`);
      for (const f of findings.cloudDetection.findings) {
        sections.push(`  - [${f.severity.toUpperCase()}] ${f.title} (${f.provider} / ${f.asset})`);
      }
    }
  }
  return sections.join("\n");
}
function identifyCloudExploitPaths(findings) {
  const paths = [];
  const cloudFindings = findings.cloudDetection?.findings || [];
  const cloudAssets = findings.assets.filter((a) => a.cloudProviders && a.cloudProviders.length > 0);
  for (const finding of cloudFindings) {
    const provider = finding.provider.toLowerCase();
    const catalog = provider === "aws" ? AWS_ATTACK_CATALOG : provider === "azure" ? AZURE_ATTACK_CATALOG : provider === "gcp" ? GCP_ATTACK_CATALOG : FULL_CLOUD_CATALOG;
    for (const attack of catalog) {
      const isStorageFinding = finding.title.toLowerCase().includes("bucket") || finding.title.toLowerCase().includes("blob") || finding.title.toLowerCase().includes("storage") || finding.title.toLowerCase().includes("public");
      const isIAMFinding = finding.title.toLowerCase().includes("iam") || finding.title.toLowerCase().includes("role") || finding.title.toLowerCase().includes("credential");
      if (isStorageFinding && (attack.attackType === "s3_public_access" || attack.attackType === "storage_misconfiguration") || isIAMFinding && (attack.attackType === "privilege_escalation" || attack.attackType === "role_chaining")) {
        paths.push({
          id: `${attack.id}-${finding.asset}`,
          name: `${attack.name} via ${finding.title}`,
          provider: finding.provider,
          entryPoint: `${finding.asset} \u2014 ${finding.title}`,
          pivotChain: [
            `Exploit ${finding.title} on ${finding.asset}`,
            ...attack.remediationSteps.map((s) => `Pivot: ${s}`).slice(0, 2),
            `Escalate via ${attack.name}`
          ],
          dataExfiltrationRisk: finding.severity === "critical" ? "critical" : finding.severity === "high" ? "high" : "medium",
          mitreTechniques: attack.mitreTechniques,
          requiredAccess: attack.prerequisites.join("; "),
          impact: attack.description
        });
      }
    }
  }
  const providers = [...new Set(cloudAssets.flatMap((a) => a.cloudProviders || []))];
  if (providers.length > 1) {
    paths.push({
      id: `cross-cloud-pivot-${providers.join("-")}`,
      name: `Cross-Cloud Pivot: ${providers.join(" \u2192 ")}`,
      provider: providers.join("+"),
      entryPoint: `Multi-cloud environment (${providers.join(", ")})`,
      pivotChain: [
        `Compromise credentials in ${providers[0]} environment`,
        `Extract cross-cloud service account keys or tokens`,
        `Pivot to ${providers[1]} using leaked credentials`,
        `Enumerate ${providers[1]} resources and escalate privileges`
      ],
      dataExfiltrationRisk: "critical",
      mitreTechniques: ["T1078.004", "T1550.001", "T1199"],
      requiredAccess: "Initial access to any cloud provider in the environment",
      impact: "Full cross-cloud compromise enabling data exfiltration from all providers"
    });
  }
  const cloudVMs = cloudAssets.filter(
    (a) => a.cloudServices?.some((s) => s.includes("EC2") || s.includes("Compute") || s.includes("VM"))
  );
  if (cloudVMs.length > 0) {
    paths.push({
      id: "metadata-service-exploit",
      name: "Cloud Metadata Service Exploitation (IMDS)",
      provider: providers[0] || "multi",
      entryPoint: `SSRF or RCE on ${cloudVMs.map((v) => v.hostname).join(", ")}`,
      pivotChain: [
        "Exploit SSRF or command injection on cloud-hosted application",
        "Query metadata service at 169.254.169.254",
        "Extract IAM role credentials from instance metadata",
        "Use temporary credentials to access cloud APIs",
        "Enumerate and exfiltrate data from cloud storage"
      ],
      dataExfiltrationRisk: "critical",
      mitreTechniques: ["T1552.005", "T1078.004", "T1530"],
      requiredAccess: "SSRF or RCE on a cloud-hosted VM/container",
      impact: "IAM role credential theft leading to cloud account compromise"
    });
  }
  return paths;
}
async function generateLLMAttackChains(context, cloudPaths, graphPlan, findings, maxChains, threatActorProfile) {
  const cloudContext = cloudPaths.length > 0 ? `
## Cloud-Specific Exploit Paths Identified
${cloudPaths.map((p) => `- **${p.name}** (${p.provider})
  Entry: ${p.entryPoint}
  Chain: ${p.pivotChain.join(" \u2192 ")}
  MITRE: ${p.mitreTechniques.join(", ")}
  Risk: ${p.dataExfiltrationRisk}`).join("\n\n")}` : "";
  const graphContext = graphPlan ? `
## Graph-Based Attack Plan Skeleton
Name: ${graphPlan.name}
Phases: ${graphPlan.phases.length}
Steps: ${graphPlan.totalSteps}
Techniques: ${graphPlan.phases.flatMap((p) => p.steps.map((s) => s.techniqueId)).join(", ")}` : "";
  const actorContext = threatActorProfile && THREAT_ACTOR_PROFILES[threatActorProfile] ? `
## Threat Actor Profile
${THREAT_ACTOR_PROFILES[threatActorProfile]}` : "";
  const userPrompt = `Design ${maxChains} realistic attack chains based on these engagement findings:

${context}
${cloudContext}
${graphContext}
${actorContext}
${CLOUD_ATTACK_CONTEXT}

For each chain, provide:
1. A descriptive name and summary
2. Kill chain phases with ordered steps mapped to MITRE ATT&CK
3. Cloud-specific exploit paths where applicable
4. Feasibility and stealth ratings
5. Detection opportunities for the blue team
6. Defensive recommendations

Prioritize chains by:
- Feasibility (most likely to succeed given the findings)
- Impact (highest damage potential)
- Stealth (hardest to detect)

For ${findings.engagementType}:
${findings.engagementType === "red_team" ? "Focus on finding the single best path to persistent access (C2 deployment). Prioritize stealth and lateral movement." : ""}
${findings.engagementType === "pentest" ? "Systematically cover all attack surfaces. Include both cloud and traditional vectors." : ""}
${findings.engagementType === "purple_team" ? "Design chains that test specific detection capabilities. Include both stealthy and noisy variants." : ""}`;
  try {
    const response = await invokeLLM({
      _caller: "cloud-attack-chain-designer",
      _priority: "essential",
      messages: [
        { role: "system", content: ATTACK_CHAIN_SYSTEM_PROMPT },
        { role: "user", content: userPrompt }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "attack_chains",
          strict: true,
          schema: {
            type: "object",
            properties: {
              chains: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    name: { type: "string" },
                    description: { type: "string" },
                    overallRisk: { type: "number" },
                    feasibility: { type: "number" },
                    stealthRating: { type: "number" },
                    estimatedDuration: { type: "string" },
                    targetAssets: { type: "array", items: { type: "string" } },
                    mitreTechniques: { type: "array", items: { type: "string" } },
                    detectionOpportunities: { type: "array", items: { type: "string" } },
                    recommendations: { type: "array", items: { type: "string" } },
                    killChainPhases: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          order: { type: "number" },
                          name: { type: "string" },
                          tactic: { type: "string" },
                          objective: { type: "string" },
                          steps: {
                            type: "array",
                            items: {
                              type: "object",
                              properties: {
                                order: { type: "number" },
                                techniqueId: { type: "string" },
                                techniqueName: { type: "string" },
                                description: { type: "string" },
                                target: { type: "string" },
                                tools: { type: "array", items: { type: "string" } },
                                prerequisites: { type: "array", items: { type: "string" } },
                                expectedOutcome: { type: "string" },
                                detectionRisk: { type: "string" },
                                isCloudSpecific: { type: "boolean" },
                                cloudProvider: { type: "string" },
                                exploitDetails: { type: "string" }
                              },
                              required: ["order", "techniqueId", "techniqueName", "description", "target", "tools", "prerequisites", "expectedOutcome", "detectionRisk", "isCloudSpecific", "cloudProvider", "exploitDetails"],
                              additionalProperties: false
                            }
                          }
                        },
                        required: ["order", "name", "tactic", "objective", "steps"],
                        additionalProperties: false
                      }
                    },
                    cloudExploitPaths: {
                      type: "array",
                      items: {
                        type: "object",
                        properties: {
                          id: { type: "string" },
                          name: { type: "string" },
                          provider: { type: "string" },
                          entryPoint: { type: "string" },
                          pivotChain: { type: "array", items: { type: "string" } },
                          dataExfiltrationRisk: { type: "string" },
                          mitreTechniques: { type: "array", items: { type: "string" } },
                          requiredAccess: { type: "string" },
                          impact: { type: "string" }
                        },
                        required: ["id", "name", "provider", "entryPoint", "pivotChain", "dataExfiltrationRisk", "mitreTechniques", "requiredAccess", "impact"],
                        additionalProperties: false
                      }
                    }
                  },
                  required: ["name", "description", "overallRisk", "feasibility", "stealthRating", "estimatedDuration", "targetAssets", "mitreTechniques", "detectionOpportunities", "recommendations", "killChainPhases", "cloudExploitPaths"],
                  additionalProperties: false
                }
              }
            },
            required: ["chains"],
            additionalProperties: false
          }
        }
      }
    });
    const rawContent = response.choices?.[0]?.message?.content;
    if (!rawContent) throw new Error("Empty LLM response");
    const content = typeof rawContent === "string" ? rawContent : JSON.stringify(rawContent);
    const parsed = JSON.parse(content);
    return (parsed.chains || []).map((chain, idx) => ({
      id: `chain-${Date.now()}-${idx}`,
      ...chain,
      totalSteps: chain.killChainPhases?.reduce((sum, p) => sum + (p.steps?.length || 0), 0) || 0
    }));
  } catch (err) {
    console.error("[AttackChainDesigner] LLM generation failed:", err.message);
    return generateFallbackChains(findings, cloudPaths, graphPlan);
  }
}
function generateFallbackChains(findings, cloudPaths, graphPlan) {
  const chains = [];
  if (graphPlan) {
    chains.push({
      id: `chain-fallback-traditional-${Date.now()}`,
      name: graphPlan.name,
      description: graphPlan.summary,
      killChainPhases: graphPlan.phases.map((p, idx) => ({
        order: idx + 1,
        name: p.name,
        tactic: p.steps[0]?.tactic || "unknown",
        objective: p.objective,
        steps: p.steps.map((s) => ({
          ...s,
          target: findings.assets[0]?.hostname || "unknown",
          isCloudSpecific: false
        }))
      })),
      totalSteps: graphPlan.totalSteps,
      estimatedDuration: graphPlan.estimatedDuration,
      overallRisk: graphPlan.estimatedRiskScore,
      feasibility: 7,
      stealthRating: 5,
      cloudExploitPaths: [],
      mitreTechniques: graphPlan.phases.flatMap((p) => p.steps.map((s) => s.techniqueId)),
      detectionOpportunities: graphPlan.detectionOpportunities,
      recommendations: graphPlan.recommendations,
      targetAssets: findings.assets.map((a) => a.hostname)
    });
  }
  if (cloudPaths.length > 0) {
    chains.push({
      id: `chain-fallback-cloud-${Date.now()}`,
      name: `Cloud Infrastructure Attack Chain`,
      description: `Exploits ${cloudPaths.length} cloud-specific attack paths across ${[...new Set(cloudPaths.map((p) => p.provider))].join(", ")} providers`,
      killChainPhases: [{
        order: 1,
        name: "Cloud Reconnaissance",
        tactic: "reconnaissance",
        objective: "Enumerate cloud storage and IAM configurations",
        steps: cloudPaths.slice(0, 5).map((p, idx) => ({
          order: idx + 1,
          techniqueId: p.mitreTechniques[0] || "T1530",
          techniqueName: p.name,
          description: p.impact,
          target: p.entryPoint,
          tools: ["cloud_enum", "s3scanner", "aws-cli"],
          prerequisites: [p.requiredAccess],
          expectedOutcome: `Access to ${p.provider} resources`,
          detectionRisk: "medium",
          isCloudSpecific: true,
          cloudProvider: p.provider
        }))
      }],
      totalSteps: Math.min(cloudPaths.length, 5),
      estimatedDuration: "1-3 days",
      overallRisk: 8,
      feasibility: 8,
      stealthRating: 6,
      cloudExploitPaths: cloudPaths,
      mitreTechniques: [...new Set(cloudPaths.flatMap((p) => p.mitreTechniques))],
      detectionOpportunities: ["Monitor cloud API access logs", "Alert on unusual S3/Blob access patterns"],
      recommendations: ["Enable cloud storage access logging", "Restrict public access to storage"],
      targetAssets: [...new Set(cloudPaths.map((p) => p.entryPoint.split(" \u2014 ")[0]))]
    });
  }
  return chains;
}
function buildChainSummary(chains, findings) {
  const allTechniques = [...new Set(chains.flatMap((c) => c.mitreTechniques))];
  const allRecs = [...new Set(chains.flatMap((c) => c.recommendations))];
  const cloudChains = chains.filter((c) => c.cloudExploitPaths.length > 0);
  const sorted_by_feasibility = [...chains].sort((a, b) => b.feasibility - a.feasibility);
  const sorted_by_stealth = [...chains].sort((a, b) => b.stealthRating - a.stealthRating);
  return {
    totalChains: chains.length,
    totalSteps: chains.reduce((sum, c) => sum + c.totalSteps, 0),
    uniqueTechniques: allTechniques.length,
    highestRisk: Math.max(...chains.map((c) => c.overallRisk), 0),
    mostFeasible: sorted_by_feasibility[0] ? { name: sorted_by_feasibility[0].name, feasibility: sorted_by_feasibility[0].feasibility } : { name: "N/A", feasibility: 0 },
    stealthiest: sorted_by_stealth[0] ? { name: sorted_by_stealth[0].name, stealthRating: sorted_by_stealth[0].stealthRating } : { name: "N/A", stealthRating: 0 },
    cloudChainsCount: cloudChains.length,
    criticalPaths: chains.filter((c) => c.overallRisk >= 8).map((c) => `${c.name} (risk: ${c.overallRisk}/10)`),
    topRecommendations: allRecs.slice(0, 10)
  };
}
function assessCloudRisk(findings, cloudPaths) {
  const cloudFindings = findings.cloudDetection?.findings || [];
  const providers = [...new Set(cloudFindings.map((f) => f.provider))];
  const publicStorage = cloudFindings.filter(
    (f) => f.title.toLowerCase().includes("public") || f.title.toLowerCase().includes("open") || f.title.toLowerCase().includes("anonymous")
  );
  const iamMisconfigs = cloudFindings.filter(
    (f) => f.title.toLowerCase().includes("iam") || f.title.toLowerCase().includes("role") || f.title.toLowerCase().includes("permission")
  );
  const hasMetadataExposure = cloudPaths.some((p) => p.id === "metadata-service-exploit");
  const hasCrossCloud = providers.length > 1;
  let riskScore = 0;
  riskScore += publicStorage.length * 15;
  riskScore += iamMisconfigs.length * 20;
  riskScore += hasMetadataExposure ? 25 : 0;
  riskScore += hasCrossCloud ? 15 : 0;
  riskScore += cloudFindings.filter((f) => f.severity === "critical").length * 10;
  riskScore += cloudFindings.filter((f) => f.severity === "high").length * 5;
  riskScore = Math.min(100, riskScore);
  const overallRisk = riskScore >= 75 ? "critical" : riskScore >= 50 ? "high" : riskScore >= 25 ? "medium" : "low";
  const remediationPriority = [];
  if (publicStorage.length > 0) {
    remediationPriority.push({ action: "Remove public access from all cloud storage buckets/containers", urgency: "immediate" });
  }
  if (iamMisconfigs.length > 0) {
    remediationPriority.push({ action: "Audit and restrict IAM policies \u2014 remove wildcard permissions", urgency: "immediate" });
  }
  if (hasMetadataExposure) {
    remediationPriority.push({ action: "Enable IMDSv2 on all EC2 instances to prevent metadata theft", urgency: "high" });
  }
  if (hasCrossCloud) {
    remediationPriority.push({ action: "Audit cross-cloud service account trust relationships", urgency: "high" });
  }
  remediationPriority.push({ action: "Enable cloud storage access logging and alerting", urgency: "medium" });
  remediationPriority.push({ action: "Implement cloud security posture management (CSPM)", urgency: "medium" });
  return {
    overallRisk,
    riskScore,
    exposedProviders: providers,
    publicStorageCount: publicStorage.length,
    iamMisconfigCount: iamMisconfigs.length,
    crossCloudRisk: hasCrossCloud,
    metadataExposure: hasMetadataExposure,
    topFindings: cloudFindings.sort((a, b) => {
      const sev = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
      return (sev[b.severity] || 0) - (sev[a.severity] || 0);
    }).slice(0, 5),
    remediationPriority
  };
}
async function persistAttackChains(findings, chains, summary) {
  const db = await getDb();
  if (!db) return;
  const validChains = chains.filter((c) => c && c.name && c.killChainPhases?.length > 0);
  if (validChains.length === 0) {
    console.warn("[AttackChainDesigner] No valid chains to persist (all empty or malformed)");
    return;
  }
  try {
    for (const chain of validChains) {
      await db.insert(aiAttackPlans).values({
        aapName: chain.name,
        aapTargetDesc: findings.targetDescription || "Unknown target",
        aapThreatActor: "cloud-aware-chain-designer",
        aapGeneratedPlan: chain,
        aapAttackSteps: chain.killChainPhases,
        aapRiskScore: chain.overallRisk || 0,
        aapStatus: "ready"
      });
    }
    console.log(`[AttackChainDesigner] Persisted ${validChains.length} attack chains to DB`);
  } catch (err) {
    console.error("[AttackChainDesigner] DB persist failed:", err);
  }
}
async function generateEngagementAttackChains(state, targetDescription) {
  const findings = {
    assets: state.assets.map((a) => ({
      hostname: a.hostname,
      ip: a.ip,
      type: a.type,
      ports: a.ports,
      vulns: a.vulns,
      zapFindings: a.zapFindings || [],
      wafDetected: a.wafDetected,
      cloudProviders: a.cloudProviders,
      cloudServices: a.cloudServices
    })),
    cloudDetection: state.cloudDetection,
    engagementType: state.engagementType,
    targetDescription
  };
  const result = await designAttackChains(findings, {
    maxChains: 3,
    includeCloudPaths: true,
    stealthLevel: state.engagementType === "red_team" ? "high" : "medium"
  });
  return result.chains;
}
var ATTACK_CHAIN_SYSTEM_PROMPT, CLOUD_ATTACK_CONTEXT;
var init_cloud_attack_chain_designer = __esm({
  "server/lib/cloud-attack-chain-designer.ts"() {
    init_llm();
    init_db();
    init_schema();
    init_cloud_attack_paths();
    init_ai_attack_planner();
    ATTACK_CHAIN_SYSTEM_PROMPT = `You are an elite red team attack chain designer specializing in hybrid cloud-traditional infrastructure attacks. You analyze vulnerability scan results, cloud misconfigurations, and service fingerprints to design realistic, multi-stage attack chains.

Your expertise includes:
- Cloud storage exploitation (S3 bucket enumeration, Azure Blob access, GCS misconfigs)
- IAM privilege escalation across AWS, Azure, and GCP
- Lateral movement from cloud to on-prem and vice versa
- Supply chain attack vectors through cloud services
- Container escape and Kubernetes exploitation
- Serverless function abuse and event injection
- Cross-account/cross-tenant pivoting

When designing attack chains:
1. Start from the most feasible entry point (lowest barrier, highest confidence)
2. Chain vulnerabilities across assets for maximum impact
3. Include cloud-specific pivot techniques when cloud assets are present
4. Map every step to MITRE ATT&CK techniques
5. Assess detection risk at each step
6. Provide realistic tool recommendations
7. Consider WAF evasion when web apps are involved
8. Include data exfiltration paths through cloud storage

You MUST respond with valid JSON matching the provided schema.`;
    CLOUD_ATTACK_CONTEXT = `
## Cloud Attack Knowledge Base

### S3 Bucket Misconfigurations
- Public READ: enumerate objects, download sensitive data (T1530)
- Public WRITE: upload malicious content, deface, or plant backdoors
- Public LIST: enumerate bucket contents for sensitive file discovery
- Misconfigured bucket policies: cross-account access, wildcard principals
- S3 \u2192 IAM escalation: bucket policies granting sts:AssumeRole

### Azure Blob Storage
- Anonymous container access: enumerate and download blobs
- SAS token exposure: long-lived tokens in code/configs
- Storage account key exposure: full account takeover
- Managed identity abuse: pivot from VM to storage

### GCP Cloud Storage
- allUsers/allAuthenticatedUsers ACLs: public bucket access
- Service account key exposure: pivot to other GCP services
- Uniform bucket-level access misconfigs

### Cross-Cloud Pivot Techniques
- Leaked credentials in public storage \u2192 access other cloud accounts
- Service account impersonation chains
- Metadata service exploitation (169.254.169.254)
- Cloud function/Lambda environment variable extraction
- Container registry access \u2192 supply chain compromise

### MITRE ATT&CK Cloud Techniques
${Object.entries(getCloudMitreTechniques()).map(([id, t]) => `- ${id}: ${t.name} (${t.tactic})`).join("\n")}
`;
  }
});
init_cloud_attack_chain_designer();
export {
  designAttackChains,
  generateEngagementAttackChains
};
