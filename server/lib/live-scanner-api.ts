// @ts-nocheck
/**
 * Live Scanner Integration Layer
 * 
 * Provides unified API clients for Caldera, GoPhish, ZAP, Shodan,
 * SecurityTrails, URLScan, and abuse.ch with graceful fallback,
 * connection health checks, and threat catalog cross-referencing.
 */

interface ScannerHealth {
  name: string;
  connected: boolean;
  lastChecked: number;
  version?: string;
  error?: string;
  agentCount?: number;
  operationCount?: number;
  campaignCount?: number;
}

interface CollectedEvidence {
  sourceModule: string;
  ksiIds: string[];
  title: string;
  description: string;
  evidenceData: Record<string, any>;
  threatActorIds?: string[];
  techniqueIds?: string[];
  severity: "critical" | "high" | "medium" | "low" | "info";
}

// ─── Caldera API Client ─────────────────────────────────────────────────────

async function getCalderaConfig() {
  const { ENV } = await import("../_core/env");
  return {
    baseUrl: ENV.calderaBaseUrl,
    apiKey: ENV.calderaApiKey,
  };
}

async function calderaFetch(endpoint: string, method = "GET", body?: any): Promise<any> {
  const { baseUrl, apiKey } = await getCalderaConfig();
  if (!baseUrl || !apiKey) return null;
  try {
    const res = await fetch(`${baseUrl}/api/v2${endpoint}`, {
      method,
      headers: {
        "KEY": apiKey,
        "Content-Type": "application/json",
      },
      body: body ? JSON.stringify(body) : undefined,
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

export async function checkCalderaHealth(): Promise<ScannerHealth> {
  const now = Date.now();
  try {
    const [agents, operations] = await Promise.all([
      calderaFetch("/agents"),
      calderaFetch("/operations"),
    ]);
    return {
      name: "Cyber C2",
      connected: agents !== null,
      lastChecked: now,
      agentCount: Array.isArray(agents) ? agents.length : 0,
      operationCount: Array.isArray(operations) ? operations.length : 0,
      version: "4.x",
    };
  } catch (err: any) {
    return { name: "Cyber C2", connected: false, lastChecked: now, error: err.message };
  }
}

export async function collectCalderaEvidence(): Promise<CollectedEvidence[]> {
  const evidence: CollectedEvidence[] = [];
  
  // Fetch operations with results
  const operations = await calderaFetch("/operations");
  if (!Array.isArray(operations)) return evidence;

  // Fetch all abilities for technique mapping
  const abilities = await calderaFetch("/abilities");
  const abilityMap = new Map<string, any>();
  if (Array.isArray(abilities)) {
    for (const a of abilities) {
      abilityMap.set(a.ability_id, a);
    }
  }

  // Fetch agents for host context
  const agents = await calderaFetch("/agents");
  const agentMap = new Map<string, any>();
  if (Array.isArray(agents)) {
    for (const a of agents) {
      agentMap.set(a.paw, a);
    }
  }

  for (const op of operations.slice(-20)) { // Last 20 operations
    const techniqueIds: string[] = [];
    const abilityNames: string[] = [];
    const hostPlatforms: string[] = [];

    // Extract techniques from operation chain
    if (Array.isArray(op.chain)) {
      for (const link of op.chain) {
        const ability = abilityMap.get(link.ability?.ability_id || link.ability_id);
        if (ability) {
          if (ability.technique_id) techniqueIds.push(ability.technique_id);
          abilityNames.push(ability.name || ability.ability_id);
        }
        const agent = agentMap.get(link.paw);
        if (agent?.platform && !hostPlatforms.includes(agent.platform)) {
          hostPlatforms.push(agent.platform);
        }
      }
    }

    // Map to KSIs based on operation type
    const ksiIds: string[] = [];
    if (techniqueIds.some(t => t.startsWith("T1190") || t.startsWith("T1133"))) ksiIds.push("KSI-SVC-VSR");
    if (techniqueIds.some(t => t.startsWith("T1059") || t.startsWith("T1053"))) ksiIds.push("KSI-SCR-PEN");
    if (techniqueIds.some(t => t.startsWith("T1078") || t.startsWith("T1110"))) ksiIds.push("KSI-IAM-MFA");
    if (techniqueIds.some(t => t.startsWith("T1071") || t.startsWith("T1105"))) ksiIds.push("KSI-MLA-OSM");
    if (techniqueIds.some(t => t.startsWith("T1547") || t.startsWith("T1543"))) ksiIds.push("KSI-CNA-HCI");
    if (techniqueIds.some(t => t.startsWith("T1486") || t.startsWith("T1565"))) ksiIds.push("KSI-INR-TIF");
    if (ksiIds.length === 0) ksiIds.push("KSI-SCR-APT"); // Default: APT simulation

    const completedLinks = Array.isArray(op.chain) ? op.chain.filter((l: any) => l.status === 0).length : 0;
    const totalLinks = Array.isArray(op.chain) ? op.chain.length : 0;

    evidence.push({
      sourceModule: "caldera",
      ksiIds,
      title: `Cyber C2 Operation: ${op.name || op.id}`,
      description: `Operation "${op.name}" executed ${completedLinks}/${totalLinks} links across ${hostPlatforms.join(", ") || "unknown"} platforms. Techniques: ${Array.from(new Set(techniqueIds)).join(", ") || "none mapped"}.`,
      evidenceData: {
        operationId: op.id,
        operationName: op.name,
        state: op.state,
        startTime: op.start,
        completedLinks,
        totalLinks,
        techniqueIds: Array.from(new Set(techniqueIds)),
        abilityNames: Array.from(new Set(abilityNames)),
        hostPlatforms,
        agentCount: new Set(Array.isArray(op.chain) ? op.chain.map((l: any) => l.paw) : []).size,
      },
      techniqueIds: Array.from(new Set(techniqueIds)),
      severity: completedLinks > 5 ? "high" : completedLinks > 2 ? "medium" : "low",
    });
  }

  return evidence;
}

// ─── GoPhish API Client ─────────────────────────────────────────────────────

async function getGophishConfig() {
  const { ENV } = await import("../_core/env");
  return {
    baseUrl: ENV.gophishBaseUrl,
    apiKey: ENV.gophishApiKey,
  };
}

async function gophishFetch(endpoint: string): Promise<any> {
  const { baseUrl, apiKey } = await getGophishConfig();
  if (!baseUrl || !apiKey) return null;
  try {
    const res = await fetch(`${baseUrl}${endpoint}`, {
      headers: {
        Authorization: `Bearer ${apiKey}`,
        "Content-Type": "application/json",
      },
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

export async function checkGophishHealth(): Promise<ScannerHealth> {
  const now = Date.now();
  try {
    const campaigns = await gophishFetch("/api/campaigns/?summary=true");
    return {
      name: "GoPhish",
      connected: campaigns !== null,
      lastChecked: now,
      campaignCount: Array.isArray(campaigns) ? campaigns.length : 0,
    };
  } catch (err: any) {
    return { name: "GoPhish", connected: false, lastChecked: now, error: err.message };
  }
}

export async function collectGophishEvidence(): Promise<CollectedEvidence[]> {
  const evidence: CollectedEvidence[] = [];
  const campaigns = await gophishFetch("/api/campaigns/?summary=true");
  if (!Array.isArray(campaigns)) return evidence;

  for (const campaign of campaigns.slice(-15)) { // Last 15 campaigns
    const detail = await gophishFetch(`/api/campaigns/${campaign.id}`);
    if (!detail) continue;

    const stats = detail.stats || campaign.stats || {};
    const totalTargets = stats.total || 0;
    const emailsSent = stats.sent || 0;
    const opened = stats.opened || 0;
    const clicked = stats.clicked || 0;
    const submitted = stats.submitted_data || 0;
    const reported = stats.email_reported || 0;

    // Map to KSIs
    const ksiIds = ["KSI-SCR-SAT"]; // Security Assessment Testing - phishing
    if (submitted > 0) ksiIds.push("KSI-IAM-MFA"); // Credential harvesting → MFA relevance
    if (clicked > 0) ksiIds.push("KSI-INR-TIU"); // Threat intel usage for user awareness

    // Technique mapping for social engineering
    const techniqueIds = ["T1566.001"]; // Phishing: Spearphishing Attachment
    if (submitted > 0) techniqueIds.push("T1078"); // Valid Accounts (credential harvest)
    if (clicked > 0) techniqueIds.push("T1204.001"); // User Execution: Malicious Link

    const clickRate = totalTargets > 0 ? ((clicked / totalTargets) * 100).toFixed(1) : "0";
    const submitRate = totalTargets > 0 ? ((submitted / totalTargets) * 100).toFixed(1) : "0";

    evidence.push({
      sourceModule: "gophish",
      ksiIds,
      title: `GoPhish Campaign: ${campaign.name || campaign.id}`,
      description: `Campaign "${campaign.name}" targeted ${totalTargets} users. ${emailsSent} emails sent, ${opened} opened (${totalTargets > 0 ? ((opened / totalTargets) * 100).toFixed(1) : 0}%), ${clicked} clicked (${clickRate}%), ${submitted} submitted credentials (${submitRate}%), ${reported} reported.`,
      evidenceData: {
        campaignId: campaign.id,
        campaignName: campaign.name,
        status: campaign.status || detail.status,
        launchDate: campaign.launch_date,
        completedDate: campaign.completed_date,
        stats: { totalTargets, emailsSent, opened, clicked, submitted, reported },
        clickRate: parseFloat(clickRate),
        submitRate: parseFloat(submitRate),
        reportRate: totalTargets > 0 ? parseFloat(((reported / totalTargets) * 100).toFixed(1)) : 0,
      },
      techniqueIds,
      severity: parseFloat(submitRate) > 20 ? "critical" : parseFloat(clickRate) > 30 ? "high" : parseFloat(clickRate) > 10 ? "medium" : "low",
    });
  }

  return evidence;
}

// ─── ZAP API Client ─────────────────────────────────────────────────────────

async function getZapConfig() {
  return {
    baseUrl: process.env.ZAP_BASE_URL || "",
    apiKey: process.env.ZAP_API_KEY || "",
  };
}

async function zapFetch(endpoint: string): Promise<any> {
  const { baseUrl, apiKey } = await getZapConfig();
  if (!baseUrl) return null;
  try {
    const separator = endpoint.includes("?") ? "&" : "?";
    const url = apiKey
      ? `${baseUrl}${endpoint}${separator}apikey=${apiKey}`
      : `${baseUrl}${endpoint}`;
    const res = await fetch(url, { signal: AbortSignal.timeout(15000) });
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

export async function checkZapHealth(): Promise<ScannerHealth> {
  const now = Date.now();
  try {
    const version = await zapFetch("/JSON/core/view/version/");
    return {
      name: "ZAP",
      connected: version !== null,
      lastChecked: now,
      version: version?.version || "unknown",
    };
  } catch (err: any) {
    return { name: "ZAP", connected: false, lastChecked: now, error: err.message };
  }
}

export async function collectZapEvidence(): Promise<CollectedEvidence[]> {
  const evidence: CollectedEvidence[] = [];
  
  // Fetch active scan alerts
  const alerts = await zapFetch("/JSON/alert/view/alerts/?start=0&count=100");
  if (!alerts?.alerts || !Array.isArray(alerts.alerts)) return evidence;

  // Group alerts by risk level for summary evidence
  const alertsByRisk: Record<string, any[]> = { High: [], Medium: [], Low: [], Informational: [] };
  for (const alert of alerts.alerts) {
    const risk = alert.risk || "Informational";
    if (alertsByRisk[risk]) alertsByRisk[risk].push(alert);
  }

  // ZAP CWE → MITRE technique mapping
  const cweToTechnique: Record<string, string> = {
    "79": "T1059.007",   // XSS → Command and Scripting Interpreter: JavaScript
    "89": "T1190",       // SQL Injection → Exploit Public-Facing Application
    "22": "T1083",       // Path Traversal → File and Directory Discovery
    "352": "T1185",      // CSRF → Browser Session Hijacking
    "200": "T1005",      // Information Exposure → Data from Local System
    "16": "T1574",       // Configuration → Hijack Execution Flow
    "311": "T1557",      // Missing Encryption → Adversary-in-the-Middle
    "614": "T1539",      // Sensitive Cookie w/o Secure → Steal Web Session Cookie
    "693": "T1548",      // Protection Mechanism Failure → Abuse Elevation Control
    "525": "T1005",      // Browser Cache → Data from Local System
  };

  for (const [risk, riskAlerts] of Object.entries(alertsByRisk)) {
    if (riskAlerts.length === 0) continue;

    const techniqueIds: string[] = [];
    const ksiIds: string[] = ["KSI-SVC-VSR"]; // Vulnerability scanning
    
    for (const alert of riskAlerts) {
      const cwe = String(alert.cweid || "");
      if (cweToTechnique[cwe]) techniqueIds.push(cweToTechnique[cwe]);
    }

    if (riskAlerts.some((a: any) => a.name?.includes("SQL") || a.name?.includes("Injection"))) {
      ksiIds.push("KSI-SVC-VRM"); // Vulnerability remediation
    }
    if (riskAlerts.some((a: any) => a.name?.includes("SSL") || a.name?.includes("TLS") || a.name?.includes("Encrypt"))) {
      ksiIds.push("KSI-CNA-EDE"); // Encryption of data in transit
    }

    const uniqueAlertNames = [...new Set(riskAlerts.map((a: any) => a.name))];

    evidence.push({
      sourceModule: "zap",
      ksiIds,
      title: `ZAP Scan: ${riskAlerts.length} ${risk}-Risk Findings`,
      description: `ZAP identified ${riskAlerts.length} ${risk.toLowerCase()}-risk vulnerabilities across ${new Set(riskAlerts.map((a: any) => a.url)).size} unique URLs. Finding types: ${uniqueAlertNames.slice(0, 5).join(", ")}${uniqueAlertNames.length > 5 ? ` (+${uniqueAlertNames.length - 5} more)` : ""}.`,
      evidenceData: {
        riskLevel: risk,
        alertCount: riskAlerts.length,
        uniqueUrls: [...new Set(riskAlerts.map((a: any) => a.url))].length,
        alertTypes: uniqueAlertNames,
        alerts: riskAlerts.slice(0, 10).map((a: any) => ({
          name: a.name,
          risk: a.risk,
          confidence: a.confidence,
          url: a.url,
          cweid: a.cweid,
          wascid: a.wascid,
          description: a.description?.slice(0, 200),
          solution: a.solution?.slice(0, 200),
        })),
      },
      techniqueIds: Array.from(new Set(techniqueIds)),
      severity: risk === "High" ? "critical" : risk === "Medium" ? "high" : risk === "Low" ? "medium" : "info",
    });
  }

  return evidence;
}

// ─── Shodan API Client ──────────────────────────────────────────────────────

async function getShodanConfig() {
  const { ENV } = await import("../_core/env");
  return { apiKey: ENV.SHODAN_API_KEY };
}

async function shodanFetch(endpoint: string): Promise<any> {
  const { apiKey } = await getShodanConfig();
  if (!apiKey) return null;
  try {
    const separator = endpoint.includes("?") ? "&" : "?";
    const res = await fetch(`https://api.shodan.io${endpoint}${separator}key=${apiKey}`, {
      signal: AbortSignal.timeout(15000),
    });
    if (!res.ok) return null;
    return res.json();
  } catch {
    return null;
  }
}

export async function checkShodanHealth(): Promise<ScannerHealth> {
  const now = Date.now();
  try {
    const info = await shodanFetch("/api-info");
    return {
      name: "Shodan",
      connected: info !== null,
      lastChecked: now,
      version: info?.plan || "unknown",
    };
  } catch (err: any) {
    return { name: "Shodan", connected: false, lastChecked: now, error: err.message };
  }
}

// ─── SecurityTrails API Client ──────────────────────────────────────────────

async function getSecurityTrailsConfig() {
  const { ENV } = await import("../_core/env");
  return { apiKey: ENV.SECURITYTRAILS_API_KEY };
}

export async function checkSecurityTrailsHealth(): Promise<ScannerHealth> {
  const now = Date.now();
  const { apiKey } = await getSecurityTrailsConfig();
  if (!apiKey) return { name: "SecurityTrails", connected: false, lastChecked: now, error: "No API key" };
  try {
    const res = await fetch("https://api.securitytrails.com/v1/ping", {
      headers: { APIKEY: apiKey },
      signal: AbortSignal.timeout(10000),
    });
    return { name: "SecurityTrails", connected: res.ok, lastChecked: now };
  } catch (err: any) {
    return { name: "SecurityTrails", connected: false, lastChecked: now, error: err.message };
  }
}

// ─── URLScan API Client ─────────────────────────────────────────────────────

export async function checkUrlscanHealth(): Promise<ScannerHealth> {
  const now = Date.now();
  const apiKey = process.env.URLSCAN_API_KEY || "";
  if (!apiKey) return { name: "URLScan", connected: false, lastChecked: now, error: "No API key" };
  try {
    const res = await fetch("https://urlscan.io/api/v1/search/?q=domain:example.com&size=1", {
      headers: { "API-Key": apiKey },
      signal: AbortSignal.timeout(10000),
    });
    return { name: "URLScan", connected: res.ok, lastChecked: now };
  } catch (err: any) {
    return { name: "URLScan", connected: false, lastChecked: now, error: err.message };
  }
}

// ─── abuse.ch API Client ────────────────────────────────────────────────────

export async function checkAbusechHealth(): Promise<ScannerHealth> {
  const now = Date.now();
  try {
    const res = await fetch("https://urlhaus-api.abuse.ch/v1/urls/recent/", {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: "limit=1",
      signal: AbortSignal.timeout(10000),
    });
    return { name: "abuse.ch", connected: res.ok, lastChecked: now };
  } catch (err: any) {
    return { name: "abuse.ch", connected: false, lastChecked: now, error: err.message };
  }
}

// ─── Threat Catalog Cross-Reference ─────────────────────────────────────────

/**
 * Cross-reference technique IDs from scanner evidence with the threat catalog
 * to identify which threat actors use these techniques.
 */
export async function crossRefThreatCatalog(
  techniqueIds: string[],
  db: any,
): Promise<{ actorId: string; actorName: string; matchedTechniques: string[]; threatLevel: string }[]> {
  if (!techniqueIds.length) return [];
  
  const { threatActors } = await import("../../drizzle/schema");
  const actors = await db.select({
    actorId: threatActors.actorId,
    name: threatActors.name,
    techniques: threatActors.techniques,
    threatLevel: threatActors.threatLevel,
  }).from(threatActors);

  const matches: { actorId: string; actorName: string; matchedTechniques: string[]; threatLevel: string }[] = [];

  for (const actor of actors) {
    const actorTechniques: any[] = Array.isArray(actor.techniques) ? actor.techniques : [];
    const matchedTechniques: string[] = [];

    for (const tid of techniqueIds) {
      const found = actorTechniques.some((t: any) => {
        const techId = t.id || t.techniqueId || "";
        return techId === tid || techId.startsWith(tid + ".") || tid.startsWith(techId + ".");
      });
      if (found) matchedTechniques.push(tid);
    }

    if (matchedTechniques.length > 0) {
      matches.push({
        actorId: actor.actorId,
        actorName: actor.name,
        matchedTechniques,
        threatLevel: actor.threatLevel || "medium",
      });
    }
  }

  // Sort by match count descending
  return matches.sort((a, b) => b.matchedTechniques.length - a.matchedTechniques.length);
}

/**
 * Cross-reference technique IDs with TTP knowledge base for detection rules and IOCs
 */
export async function crossRefTtpKnowledge(
  techniqueIds: string[],
  db: any,
): Promise<{ techniqueId: string; techniqueName: string; tactic: string; calderaAbilities: any[]; detectionRules: any[] }[]> {
  if (!techniqueIds.length) return [];

  const { ttpKnowledge } = await import("../../drizzle/schema");
  const { inArray } = await import("drizzle-orm");
  
  const ttps = await db.select().from(ttpKnowledge).where(inArray(ttpKnowledge.techniqueId, techniqueIds));

  return ttps.map((t: any) => ({
    techniqueId: t.techniqueId,
    techniqueName: t.techniqueName,
    tactic: t.tactic,
    calderaAbilities: Array.isArray(t.calderaAbilities) ? t.calderaAbilities : [],
    detectionRules: Array.isArray(t.detectionRules) ? t.detectionRules : [],
  }));
}

// ─── Unified Health Check ───────────────────────────────────────────────────

export async function checkAllScannerHealth(): Promise<ScannerHealth[]> {
  const results = await Promise.allSettled([
    checkCalderaHealth(),
    checkGophishHealth(),
    checkZapHealth(),
    checkShodanHealth(),
    checkSecurityTrailsHealth(),
    checkUrlscanHealth(),
    checkAbusechHealth(),
  ]);

  return results.map((r) =>
    r.status === "fulfilled"
      ? r.value
      : { name: "Unknown", connected: false, lastChecked: Date.now(), error: "Health check failed" }
  );
}

// ─── Unified Collection with Threat Cross-Reference ─────────────────────────

export async function collectAllLiveEvidence(db: any): Promise<{
  evidence: CollectedEvidence[];
  threatMatches: Map<string, { actorId: string; actorName: string; matchedTechniques: string[]; threatLevel: string }[]>;
}> {
  const [calderaEvidence, gophishEvidence, zapEvidence] = await Promise.allSettled([
    collectCalderaEvidence(),
    collectGophishEvidence(),
    collectZapEvidence(),
  ]);

  const allEvidence: CollectedEvidence[] = [
    ...(calderaEvidence.status === "fulfilled" ? calderaEvidence.value : []),
    ...(gophishEvidence.status === "fulfilled" ? gophishEvidence.value : []),
    ...(zapEvidence.status === "fulfilled" ? zapEvidence.value : []),
  ];

  // Cross-reference all techniques with threat catalog
  const allTechniques = [...new Set(allEvidence.flatMap(e => e.techniqueIds || []))];
  const threatMatches = new Map<string, { actorId: string; actorName: string; matchedTechniques: string[]; threatLevel: string }[]>();

  if (allTechniques.length > 0) {
    const actorMatches = await crossRefThreatCatalog(allTechniques, db);
    
    // Map threat matches per evidence item
    for (const ev of allEvidence) {
      if (ev.techniqueIds?.length) {
        const matches = actorMatches.filter(a =>
          a.matchedTechniques.some(t => ev.techniqueIds!.includes(t))
        );
        if (matches.length > 0) {
          threatMatches.set(ev.title, matches);
          ev.threatActorIds = matches.map(m => m.actorId);
        }
      }
    }
  }

  return { evidence: allEvidence, threatMatches };
}
