/**
 * Live Advisory Ingestion Scheduler
 * 
 * Automatically pulls CISA ICS-CERT, FBI PSA, and NSA advisories every 6 hours.
 * Parses advisory data, extracts CVEs/affected products, and cross-references
 * against client PLC/ICS device inventory to generate prioritized alerts.
 * 
 * Data Sources:
 * - CISA ICS-CERT Advisories (RSS + JSON API)
 * - CISA Known Exploited Vulnerabilities (KEV) updates
 * - FBI Private Industry Notifications (PIN)
 * - NSA Cybersecurity Advisories
 * - DHS CISA Alerts (AA-series)
 * 
 * Schedule: Every 6 hours (00:00, 06:00, 12:00, 18:00 UTC)
 */
import cron from "node-cron";
import { onAdvisoryIngested } from "./false-flag-auto-enrichment";
// ─── Types ───────────────────────────────────────────────────────────────────

export interface RawAdvisory {
  id: string;
  source: "CISA_ICS_CERT" | "CISA_ALERT" | "FBI_PSA" | "FBI_PIN" | "NSA_CSA" | "DHS_ALERT";
  title: string;
  url: string;
  publishedAt: Date;
  updatedAt?: Date;
  severity: "critical" | "high" | "medium" | "low" | "informational";
  cves: string[];
  affectedProducts: AffectedProduct[];
  mitigations: string[];
  threatActors: string[];
  sectors: string[];
  summary: string;
  rawContent?: string;
}

export interface AffectedProduct {
  vendor: string;
  product: string;
  versions?: string[];
  cpeUri?: string;
  isIcs: boolean;
  productType?: "plc" | "hmi" | "scada" | "rtu" | "dcs" | "switch" | "router" | "firewall" | "software";
}

export interface AdvisoryAlert {
  advisoryId: string;
  advisoryTitle: string;
  advisorySource: string;
  matchType: "exact_device" | "vendor_match" | "product_family" | "cve_overlap" | "sector_match";
  matchConfidence: number; // 0-1
  affectedClientDevices: string[]; // device IDs from ICS inventory
  urgency: "immediate" | "high" | "elevated" | "routine";
  recommendedActions: string[];
  generatedAt: Date;
}

export interface IngestionResult {
  source: string;
  advisoriesFetched: number;
  newAdvisories: number;
  updatedAdvisories: number;
  alertsGenerated: number;
  errors: string[];
  durationMs: number;
}

// ─── Advisory Source Fetchers ────────────────────────────────────────────────

const CISA_ICS_CERT_FEED = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json";
const CISA_ICS_ADVISORIES_RSS = "https://www.cisa.gov/cybersecurity-advisories/ics-advisories.xml";
const CISA_ALERTS_RSS = "https://www.cisa.gov/cybersecurity-advisories/alerts.xml";

/**
 * Fetch and parse CISA ICS-CERT advisories from RSS feed
 */
async function fetchCisaIcsAdvisories(): Promise<RawAdvisory[]> {
  const advisories: RawAdvisory[] = [];
  
  try {
    const response = await fetch(CISA_ICS_ADVISORIES_RSS, {
      signal: AbortSignal.timeout(30_000),
      headers: { "User-Agent": "AC3-ThreatIntel/2.0 (Advisory Monitor)" }
    });
    
    if (!response.ok) {
      console.warn(`[AdvisoryIngestion] CISA ICS RSS returned ${response.status}`);
      return advisories;
    }
    
    const xmlText = await response.text();
    const items = parseRssItems(xmlText);
    
    for (const item of items) {
      const advisory = parseCisaIcsItem(item);
      if (advisory) advisories.push(advisory);
    }
    
    console.log(`[AdvisoryIngestion] Fetched ${advisories.length} CISA ICS-CERT advisories`);
  } catch (err: any) {
    console.warn(`[AdvisoryIngestion] CISA ICS-CERT fetch failed: ${err.message}`);
  }
  
  return advisories;
}

/**
 * Fetch CISA Alerts (AA-series advisories — often joint FBI/NSA/CISA)
 */
async function fetchCisaAlerts(): Promise<RawAdvisory[]> {
  const advisories: RawAdvisory[] = [];
  
  try {
    const response = await fetch(CISA_ALERTS_RSS, {
      signal: AbortSignal.timeout(30_000),
      headers: { "User-Agent": "AC3-ThreatIntel/2.0 (Advisory Monitor)" }
    });
    
    if (!response.ok) {
      console.warn(`[AdvisoryIngestion] CISA Alerts RSS returned ${response.status}`);
      return advisories;
    }
    
    const xmlText = await response.text();
    const items = parseRssItems(xmlText);
    
    for (const item of items) {
      const advisory = parseCisaAlertItem(item);
      if (advisory) advisories.push(advisory);
    }
    
    console.log(`[AdvisoryIngestion] Fetched ${advisories.length} CISA Alerts`);
  } catch (err: any) {
    console.warn(`[AdvisoryIngestion] CISA Alerts fetch failed: ${err.message}`);
  }
  
  return advisories;
}

/**
 * Fetch FBI Private Industry Notifications and PSAs
 * Uses FBI IC3 and Internet Crime pages as proxy since direct API isn't public
 */
async function fetchFbiAdvisories(): Promise<RawAdvisory[]> {
  const advisories: RawAdvisory[] = [];
  
  try {
    // FBI PSAs are typically published through CISA joint advisories
    // We parse the CISA alerts for FBI-attributed content
    const response = await fetch("https://www.ic3.gov/PSA/RSS", {
      signal: AbortSignal.timeout(30_000),
      headers: { "User-Agent": "AC3-ThreatIntel/2.0 (Advisory Monitor)" }
    });
    
    if (response.ok) {
      const xmlText = await response.text();
      const items = parseRssItems(xmlText);
      
      for (const item of items) {
        const advisory = parseFbiItem(item);
        if (advisory) advisories.push(advisory);
      }
    }
    
    console.log(`[AdvisoryIngestion] Fetched ${advisories.length} FBI advisories`);
  } catch (err: any) {
    // FBI RSS may not always be available — this is expected
    console.log(`[AdvisoryIngestion] FBI feed unavailable (non-critical): ${err.message}`);
  }
  
  return advisories;
}

// ─── RSS Parsing Helpers ─────────────────────────────────────────────────────

interface RssItem {
  title: string;
  link: string;
  description: string;
  pubDate: string;
  guid?: string;
  category?: string[];
}

function parseRssItems(xml: string): RssItem[] {
  const items: RssItem[] = [];
  const itemRegex = /<item>([\s\S]*?)<\/item>/gi;
  let match;
  
  while ((match = itemRegex.exec(xml)) !== null) {
    const itemXml = match[1];
    const title = extractTag(itemXml, "title");
    const link = extractTag(itemXml, "link");
    const description = extractTag(itemXml, "description");
    const pubDate = extractTag(itemXml, "pubDate");
    const guid = extractTag(itemXml, "guid");
    
    if (title && link) {
      items.push({ title, link, description: description || "", pubDate: pubDate || "", guid });
    }
  }
  
  return items;
}

function extractTag(xml: string, tag: string): string {
  const regex = new RegExp(`<${tag}[^>]*><!\\[CDATA\\[([\\s\\S]*?)\\]\\]><\\/${tag}>|<${tag}[^>]*>([\\s\\S]*?)<\\/${tag}>`, "i");
  const match = regex.exec(xml);
  return match ? (match[1] || match[2] || "").trim() : "";
}

function parseCisaIcsItem(item: RssItem): RawAdvisory | null {
  if (!item.title || !item.link) return null;
  
  // Extract advisory ID from URL (e.g., ICSA-26-211-01)
  const idMatch = item.link.match(/icsa-[\d]+-[\d]+-[\d]+|icsma-[\d]+-[\d]+-[\d]+/i);
  const id = idMatch ? idMatch[0].toUpperCase() : `CISA-ICS-${Date.now()}`;
  
  // Extract CVEs from description
  const cves = extractCves(item.description);
  
  // Extract affected products from title and description
  const affectedProducts = extractAffectedProducts(item.title, item.description);
  
  // Determine severity from title keywords
  const severity = inferSeverity(item.title, item.description, cves.length);
  
  return {
    id,
    source: "CISA_ICS_CERT",
    title: item.title,
    url: item.link,
    publishedAt: item.pubDate ? new Date(item.pubDate) : new Date(),
    severity,
    cves,
    affectedProducts,
    mitigations: extractMitigations(item.description),
    threatActors: extractThreatActors(item.description),
    sectors: extractSectors(item.description),
    summary: item.description.slice(0, 500),
  };
}

function parseCisaAlertItem(item: RssItem): RawAdvisory | null {
  if (!item.title || !item.link) return null;
  
  const idMatch = item.link.match(/aa[\d]+-[\d]+[a-z]?/i);
  const id = idMatch ? idMatch[0].toUpperCase() : `CISA-ALERT-${Date.now()}`;
  
  const cves = extractCves(item.description);
  const affectedProducts = extractAffectedProducts(item.title, item.description);
  const severity = inferSeverity(item.title, item.description, cves.length);
  
  // Check if this is a joint advisory (FBI/NSA/CISA)
  const isJoint = /FBI|NSA|Five Eyes|CCCS|ASD|NCSC/i.test(item.title + item.description);
  
  return {
    id,
    source: isJoint ? "DHS_ALERT" : "CISA_ALERT",
    title: item.title,
    url: item.link,
    publishedAt: item.pubDate ? new Date(item.pubDate) : new Date(),
    severity: isJoint ? "critical" : severity,
    cves,
    affectedProducts,
    mitigations: extractMitigations(item.description),
    threatActors: extractThreatActors(item.description),
    sectors: extractSectors(item.description),
    summary: item.description.slice(0, 500),
  };
}

function parseFbiItem(item: RssItem): RawAdvisory | null {
  if (!item.title || !item.link) return null;
  
  return {
    id: `FBI-PSA-${Date.now()}-${Math.random().toString(36).slice(2, 6)}`,
    source: "FBI_PSA",
    title: item.title,
    url: item.link,
    publishedAt: item.pubDate ? new Date(item.pubDate) : new Date(),
    severity: "high",
    cves: extractCves(item.description),
    affectedProducts: extractAffectedProducts(item.title, item.description),
    mitigations: extractMitigations(item.description),
    threatActors: extractThreatActors(item.description),
    sectors: extractSectors(item.description),
    summary: item.description.slice(0, 500),
  };
}

// ─── Content Extraction Helpers ──────────────────────────────────────────────

function extractCves(text: string): string[] {
  const cveRegex = /CVE-\d{4}-\d{4,}/gi;
  const matches = text.match(cveRegex) || [];
  return [...new Set(matches.map(c => c.toUpperCase()))];
}

function extractAffectedProducts(title: string, description: string): AffectedProduct[] {
  const products: AffectedProduct[] = [];
  const combined = `${title} ${description}`;
  
  // Known ICS vendor/product patterns
  const icsPatterns: Array<{ vendor: string; products: string[]; type: AffectedProduct["productType"] }> = [
    { vendor: "Rockwell Automation", products: ["MicroLogix", "CompactLogix", "ControlLogix", "PLC5", "SLC500", "Studio 5000", "FactoryTalk"], type: "plc" },
    { vendor: "Siemens", products: ["SIMATIC S7", "S7-300", "S7-400", "S7-1200", "S7-1500", "WinCC", "TIA Portal", "SCALANCE"], type: "plc" },
    { vendor: "Schneider Electric", products: ["Modicon", "M340", "M580", "Quantum", "Unity Pro", "EcoStruxure", "Triconex"], type: "plc" },
    { vendor: "Unitronics", products: ["Vision", "Samba", "UniStream", "V130", "V230", "V350", "V570", "V700", "V1040", "V1210"], type: "plc" },
    { vendor: "ABB", products: ["AC500", "AC800M", "Freelance", "800xA", "Ability Symphony"], type: "plc" },
    { vendor: "Honeywell", products: ["Experion", "C300", "ControlEdge", "Safety Manager"], type: "dcs" },
    { vendor: "Emerson", products: ["DeltaV", "ROC800", "Ovation", "OpenBSI"], type: "dcs" },
    { vendor: "GE", products: ["Mark VIe", "PACSystems", "iFIX", "CIMPLICITY", "Proficy"], type: "plc" },
    { vendor: "Mitsubishi Electric", products: ["MELSEC", "iQ-R", "iQ-F", "FX5U", "GX Works"], type: "plc" },
    { vendor: "Omron", products: ["NJ/NX", "CJ2", "CP1", "Sysmac Studio"], type: "plc" },
    { vendor: "Yokogawa", products: ["CENTUM VP", "ProSafe-RS", "STARDOM", "FA-M3"], type: "dcs" },
    { vendor: "Cisco", products: ["Industrial Ethernet", "IE2000", "IE3000", "IE4000", "IE5000"], type: "switch" },
    { vendor: "Fortinet", products: ["FortiGate", "FortiSwitch", "FortiSIEM"], type: "firewall" },
  ];
  
  for (const pattern of icsPatterns) {
    for (const product of pattern.products) {
      if (combined.toLowerCase().includes(product.toLowerCase())) {
        products.push({
          vendor: pattern.vendor,
          product,
          isIcs: true,
          productType: pattern.type,
        });
      }
    }
  }
  
  return products;
}

function extractThreatActors(text: string): string[] {
  const actors: string[] = [];
  const knownActors = [
    "CyberAv3ngers", "Sandworm", "Volt Typhoon", "XENOTIME", "TRITON",
    "APT28", "APT29", "APT33", "APT34", "APT35", "APT41",
    "Lazarus", "Kimsuky", "Turla", "Cozy Bear", "Fancy Bear",
    "Handala", "MuddyWater", "OilRig", "Charming Kitten",
    "Flax Typhoon", "Salt Typhoon", "Brass Typhoon",
    "IRGC", "GRU", "FSB", "PLA", "MSS", "RGB",
    "TEMP.Veles", "ELECTRUM", "KAMACITE", "RASPITE",
  ];
  
  for (const actor of knownActors) {
    if (text.toLowerCase().includes(actor.toLowerCase())) {
      actors.push(actor);
    }
  }
  
  return [...new Set(actors)];
}

function extractSectors(text: string): string[] {
  const sectors: string[] = [];
  const sectorKeywords: Record<string, string[]> = {
    "Water/Wastewater": ["water", "wastewater", "water treatment", "water utility", "drinking water"],
    "Energy/Electric": ["energy", "electric", "power grid", "electric utility", "generation", "transmission"],
    "Oil/Gas": ["oil", "gas", "petroleum", "pipeline", "refinery", "lng"],
    "Manufacturing": ["manufacturing", "factory", "industrial", "production"],
    "Transportation": ["transportation", "rail", "aviation", "maritime", "port"],
    "Healthcare": ["healthcare", "hospital", "medical", "pharmaceutical"],
    "Government": ["government", "federal", "state", "municipal", "defense"],
    "Communications": ["telecom", "communications", "ISP", "cellular"],
    "Financial": ["financial", "banking", "payment"],
    "Food/Agriculture": ["food", "agriculture", "farming"],
  };
  
  const lowerText = text.toLowerCase();
  for (const [sector, keywords] of Object.entries(sectorKeywords)) {
    if (keywords.some(kw => lowerText.includes(kw))) {
      sectors.push(sector);
    }
  }
  
  return sectors;
}

function extractMitigations(text: string): string[] {
  const mitigations: string[] = [];
  const mitigationPatterns = [
    /(?:recommend|should|must|advise)[^.]*(?:patch|update|upgrade)[^.]*/gi,
    /(?:disable|restrict|limit)[^.]*(?:remote access|internet-facing|default password)[^.]*/gi,
    /(?:implement|enable|configure)[^.]*(?:MFA|multi-factor|network segmentation|firewall rules)[^.]*/gi,
    /(?:monitor|audit|review)[^.]*(?:logs|traffic|access|connections)[^.]*/gi,
  ];
  
  for (const pattern of mitigationPatterns) {
    const matches = text.match(pattern) || [];
    mitigations.push(...matches.map(m => m.trim().slice(0, 200)));
  }
  
  return mitigations.slice(0, 10);
}

function inferSeverity(title: string, description: string, cveCount: number): RawAdvisory["severity"] {
  const combined = `${title} ${description}`.toLowerCase();
  
  if (combined.includes("critical") || combined.includes("actively exploited") || combined.includes("emergency")) return "critical";
  if (combined.includes("high severity") || cveCount >= 5 || combined.includes("remote code execution")) return "high";
  if (combined.includes("medium") || cveCount >= 2) return "medium";
  if (combined.includes("low") || combined.includes("informational")) return "low";
  
  return cveCount > 0 ? "high" : "medium";
}

// ─── Client Inventory Cross-Reference ────────────────────────────────────────

/**
 * Cross-reference advisory affected products against client ICS device inventory.
 * Generates alerts when advisories match devices in active engagements.
 */
async function crossReferenceClientInventory(advisory: RawAdvisory): Promise<AdvisoryAlert[]> {
  const alerts: AdvisoryAlert[] = [];
  
  try {
    const { getDb } = await import("../db");
    const database = await getDb();
    if (!database) return alerts;
    
    const { icsDevices } = await import("../../drizzle/schema");
    const { like, or, sql } = await import("drizzle-orm");
    
    // Build search conditions based on affected products
    for (const product of advisory.affectedProducts) {
      if (!product.isIcs) continue;
      
      // Search for matching devices in client inventory
      const conditions = [];
      if (product.vendor) {
        conditions.push(like(icsDevices.vendor, `%${product.vendor}%`));
      }
      if (product.product) {
        conditions.push(like(icsDevices.model, `%${product.product}%`));
      }
      
      if (conditions.length === 0) continue;
      
      const matchingDevices = await database
        .select({ id: icsDevices.id, deviceName: icsDevices.deviceName, vendor: icsDevices.vendor, model: icsDevices.model })
        .from(icsDevices)
        .where(or(...conditions))
        .limit(50);
      
      if (matchingDevices.length > 0) {
        const urgency = determineUrgency(advisory, matchingDevices.length);
        
        alerts.push({
          advisoryId: advisory.id,
          advisoryTitle: advisory.title,
          advisorySource: advisory.source,
          matchType: product.vendor && product.product ? "exact_device" : "vendor_match",
          matchConfidence: product.vendor && product.product ? 0.95 : 0.7,
          affectedClientDevices: matchingDevices.map(d => d.id),
          urgency,
          recommendedActions: generateRecommendedActions(advisory, product),
          generatedAt: new Date(),
        });
      }
    }
    
    // Also check CVE overlap with known vulnerabilities on client devices
    if (advisory.cves.length > 0) {
      const cveAlerts = await checkCveOverlap(advisory, database);
      alerts.push(...cveAlerts);
    }
    
  } catch (err: any) {
    console.warn(`[AdvisoryIngestion] Inventory cross-reference failed: ${err.message}`);
  }
  
  return alerts;
}

function determineUrgency(advisory: RawAdvisory, deviceCount: number): AdvisoryAlert["urgency"] {
  // Critical advisory + multiple devices = immediate
  if (advisory.severity === "critical" && deviceCount >= 3) return "immediate";
  if (advisory.severity === "critical") return "high";
  if (advisory.severity === "high" && deviceCount >= 5) return "high";
  if (advisory.severity === "high") return "elevated";
  return "routine";
}

function generateRecommendedActions(advisory: RawAdvisory, product: AffectedProduct): string[] {
  const actions: string[] = [];
  
  actions.push(`Review ${advisory.source} advisory ${advisory.id}: ${advisory.title}`);
  actions.push(`Verify patch status for ${product.vendor} ${product.product} devices`);
  
  if (advisory.severity === "critical") {
    actions.push("Immediately assess network exposure of affected devices");
    actions.push("Verify network segmentation between IT and OT networks");
    actions.push("Check for indicators of compromise on affected systems");
  }
  
  if (advisory.threatActors.length > 0) {
    actions.push(`Active threat actor targeting: ${advisory.threatActors.join(", ")} — escalate to SOC`);
  }
  
  if (advisory.mitigations.length > 0) {
    actions.push(`Apply vendor mitigations: ${advisory.mitigations[0]}`);
  }
  
  return actions;
}

async function checkCveOverlap(advisory: RawAdvisory, database: any): Promise<AdvisoryAlert[]> {
  // Check if any advisory CVEs match vulnerabilities already discovered on client assets
  const alerts: AdvisoryAlert[] = [];
  
  try {
    const { sql } = await import("drizzle-orm");
    
    // Search for CVEs in existing scan results
    for (const cve of advisory.cves.slice(0, 10)) {
      const results = await database.execute(
        sql`SELECT DISTINCT target_domain, scan_id FROM di_scan_results 
            WHERE raw_data LIKE ${`%${cve}%`} 
            LIMIT 10`
      );
      
      if (results[0] && results[0].length > 0) {
        alerts.push({
          advisoryId: advisory.id,
          advisoryTitle: `${advisory.title} — CVE ${cve} found on client assets`,
          advisorySource: advisory.source,
          matchType: "cve_overlap",
          matchConfidence: 0.9,
          affectedClientDevices: results[0].map((r: any) => r.target_domain || r.scan_id),
          urgency: advisory.severity === "critical" ? "immediate" : "high",
          recommendedActions: [
            `CVE ${cve} from advisory ${advisory.id} matches existing vulnerability on client assets`,
            "Verify remediation status immediately",
            "Cross-reference with active engagement scope",
          ],
          generatedAt: new Date(),
        });
      }
    }
  } catch (err: any) {
    // Non-critical — CVE overlap check is supplementary
  }
  
  return alerts;
}

// ─── Persistence Layer ───────────────────────────────────────────────────────

/**
 * Store ingested advisory and generated alerts in the database
 */
async function persistAdvisoryAndAlerts(advisory: RawAdvisory, alerts: AdvisoryAlert[]): Promise<void> {
  try {
    const { getDb } = await import("../db");
    const database = await getDb();
    if (!database) return;
    
    const { sql } = await import("drizzle-orm");
    
    // Upsert advisory into advisory_correlation_events table
    await database.execute(sql`
      INSERT INTO advisory_correlation_events (id, advisory_id, source, title, severity, cves, affected_products, threat_actors, sectors, published_at, created_at)
      VALUES (
        ${crypto.randomUUID()},
        ${advisory.id},
        ${advisory.source},
        ${advisory.title},
        ${advisory.severity},
        ${JSON.stringify(advisory.cves)},
        ${JSON.stringify(advisory.affectedProducts)},
        ${JSON.stringify(advisory.threatActors)},
        ${JSON.stringify(advisory.sectors)},
        ${advisory.publishedAt.toISOString()},
        ${new Date().toISOString()}
      )
      ON DUPLICATE KEY UPDATE
        title = VALUES(title),
        severity = VALUES(severity),
        cves = VALUES(cves),
        affected_products = VALUES(affected_products)
    `);
    
    // Store alerts
    for (const alert of alerts) {
      await database.execute(sql`
        INSERT INTO advisory_alerts (id, advisory_id, match_type, match_confidence, urgency, affected_devices, recommended_actions, generated_at)
        VALUES (
          ${crypto.randomUUID()},
          ${alert.advisoryId},
          ${alert.matchType},
          ${alert.matchConfidence},
          ${alert.urgency},
          ${JSON.stringify(alert.affectedClientDevices)},
          ${JSON.stringify(alert.recommendedActions)},
          ${alert.generatedAt.toISOString()}
        )
      `);
    }
    
  } catch (err: any) {
    // Table may not exist yet — log but don't crash
    console.warn(`[AdvisoryIngestion] Persistence failed (table may not exist): ${err.message}`);
  }
}

// ─── Main Ingestion Pipeline ─────────────────────────────────────────────────

let ingestionRunning = false;

/**
 * Run the full advisory ingestion pipeline
 */
export async function runAdvisoryIngestion(trigger: "scheduled" | "manual" = "scheduled"): Promise<IngestionResult[]> {
  if (ingestionRunning) {
    console.log("[AdvisoryIngestion] Skipping — previous ingestion still running");
    return [];
  }
  
  ingestionRunning = true;
  const results: IngestionResult[] = [];
  const startTime = Date.now();
  
  console.log(`[AdvisoryIngestion] Starting ${trigger} ingestion cycle...`);
  
  try {
    // Fetch from all sources in parallel
    const [cisaIcs, cisaAlerts, fbiAdvisories] = await Promise.allSettled([
      fetchCisaIcsAdvisories(),
      fetchCisaAlerts(),
      fetchFbiAdvisories(),
    ]);
    
    const allAdvisories: RawAdvisory[] = [];
    
    if (cisaIcs.status === "fulfilled") allAdvisories.push(...cisaIcs.value);
    if (cisaAlerts.status === "fulfilled") allAdvisories.push(...cisaAlerts.value);
    if (fbiAdvisories.status === "fulfilled") allAdvisories.push(...fbiAdvisories.value);
    
    console.log(`[AdvisoryIngestion] Total advisories fetched: ${allAdvisories.length}`);
    
    // Filter to only advisories from the last 7 days (avoid re-processing old ones)
    const sevenDaysAgo = new Date(Date.now() - 7 * 24 * 60 * 60 * 1000);
    const recentAdvisories = allAdvisories.filter(a => a.publishedAt >= sevenDaysAgo);
    
    console.log(`[AdvisoryIngestion] Recent advisories (last 7 days): ${recentAdvisories.length}`);
    
    // Cross-reference each advisory against client inventory
    let totalAlerts = 0;
    for (const advisory of recentAdvisories) {
      const alerts = await crossReferenceClientInventory(advisory);
      
      if (alerts.length > 0) {
        console.log(`[AdvisoryIngestion] ALERT: ${advisory.id} matches ${alerts.length} client device(s) — urgency: ${alerts[0].urgency}`);
        totalAlerts += alerts.length;
        
        // Persist advisory and alerts
        await persistAdvisoryAndAlerts(advisory, alerts);
        
        // If immediate urgency, notify operators
        if (alerts.some(a => a.urgency === "immediate")) {
          await notifyOperatorsOfCriticalAdvisory(advisory, alerts);
        }
      }
    }
    
    const result: IngestionResult = {
      source: "all",
      advisoriesFetched: allAdvisories.length,
      newAdvisories: recentAdvisories.length,
      updatedAdvisories: 0,
      alertsGenerated: totalAlerts,
      errors: [],
      durationMs: Date.now() - startTime,
    };
    
    results.push(result);
    console.log(`[AdvisoryIngestion] Cycle complete: ${result.advisoriesFetched} fetched, ${result.alertsGenerated} alerts generated in ${result.durationMs}ms`);
    
    // ─── False Flag Enrichment Hook ─────────────────────────────────────────
    // Run enrichment pipeline on all recent advisories to detect potential
    // false flag operations for the case library
    try {
      const enrichmentInput = recentAdvisories.map(a => ({
        id: a.id,
        title: a.title,
        source: a.source,
        publishDate: a.publishedAt.getTime(),
        content: `${a.title} ${a.description} ${a.mitigations?.join(" ") || ""}`,
        url: a.url,
        cves: a.cves,
        attributedActor: a.threatActors?.[0] || undefined,
      }));
      
      const enrichmentResult = await onAdvisoryIngested(enrichmentInput);
      if (enrichmentResult.candidatesGenerated > 0) {
        console.log(`[AdvisoryIngestion] False flag enrichment: ${enrichmentResult.candidatesGenerated} candidate(s) detected for review`);
      }
    } catch (enrichErr: any) {
      console.warn(`[AdvisoryIngestion] False flag enrichment error (non-fatal): ${enrichErr.message}`);
    }
    // ────────────────────────────────────────────────────────────────────────
    
  } catch (err: any) {
    console.error(`[AdvisoryIngestion] Pipeline error: ${err.message}`);
    results.push({
      source: "all",
      advisoriesFetched: 0,
      newAdvisories: 0,
      updatedAdvisories: 0,
      alertsGenerated: 0,
      errors: [err.message],
      durationMs: Date.now() - startTime,
    });
  } finally {
    ingestionRunning = false;
  }
  
  return results;
}

/**
 * Notify operators when a critical advisory matches client devices
 */
async function notifyOperatorsOfCriticalAdvisory(advisory: RawAdvisory, alerts: AdvisoryAlert[]): Promise<void> {
  try {
    const { notifyOwner } = await import("../_core/notification");
    
    const deviceCount = alerts.reduce((sum, a) => sum + a.affectedClientDevices.length, 0);
    const actorStr = advisory.threatActors.length > 0 ? ` (${advisory.threatActors.join(", ")})` : "";
    
    await notifyOwner({
      title: `🚨 CRITICAL ADVISORY MATCH: ${advisory.id}`,
      content: [
        `**${advisory.title}**${actorStr}`,
        `Source: ${advisory.source} | Severity: ${advisory.severity.toUpperCase()}`,
        `Matched ${deviceCount} client device(s) across ${alerts.length} alert(s)`,
        `CVEs: ${advisory.cves.slice(0, 5).join(", ") || "None listed"}`,
        `Sectors: ${advisory.sectors.join(", ") || "General"}`,
        ``,
        `Urgency: ${alerts[0].urgency.toUpperCase()}`,
        `Action Required: Review advisory and verify client device exposure immediately.`,
        `Link: ${advisory.url}`,
      ].join("\n"),
    });
  } catch (err: any) {
    console.warn(`[AdvisoryIngestion] Notification failed: ${err.message}`);
  }
}

// ─── Scheduler Init ──────────────────────────────────────────────────────────

/**
 * Initialize the advisory ingestion scheduler.
 * Runs every 6 hours: 00:00, 06:00, 12:00, 18:00 UTC
 */
export function initAdvisoryIngestionScheduler() {
  const task = cron.schedule("0 */6 * * *", async () => {
    try {
      await runAdvisoryIngestion("scheduled");
    } catch (err) {
      console.error("[AdvisoryIngestion Cron] Scheduled ingestion failed:", err);
    }
  }, {
    timezone: "UTC",
  });
  
  console.log("[AdvisoryIngestion] Scheduled advisory ingestion every 6 hours (00:00, 06:00, 12:00, 18:00 UTC)");
  return task;
}
