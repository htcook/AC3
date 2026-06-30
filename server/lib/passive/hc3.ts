/**
 * HC3 (Health Sector Cybersecurity Coordination Center) Connector — Free, No API Key
 * 
 * Monitors HHS HC3 threat briefings, analyst notes, and sector alerts
 * for healthcare-related threat intelligence. Relevant when the target
 * organization operates in the healthcare/HIPAA sector.
 * 
 * Data source: https://www.hhs.gov/about/agencies/asa/ocio/hc3/index.html
 * RSS Feed: https://www.hhs.gov/about/agencies/asa/ocio/hc3/products/index.html
 */
import { createHash } from "crypto";
import { rateLimitedFetch } from "./rate-limiter";
import type { AssetObservation, ConnectorConfig, ConnectorResult, PassiveConnector } from "./types";

function makeAssetId(domain: string, name: string, source: string): string {
  return createHash("sha256").update(`${domain}|${name}|${source}`).digest("hex").slice(0, 20);
}

// HC3 products page and CISA healthcare-specific alerts
const HC3_PRODUCTS_URL = "https://www.hhs.gov/about/agencies/asa/ocio/hc3/products/index.html";
const CISA_HEALTHCARE_URL = "https://www.cisa.gov/news-events/cybersecurity-advisories?f%5B0%5D=advisory_type%3A94";

// Healthcare-related keywords for relevance filtering
const HEALTHCARE_KEYWORDS = [
  "healthcare", "hospital", "medical", "hipaa", "phi", "ehr", "emr",
  "health system", "clinic", "pharmaceutical", "biotech", "life sciences",
  "patient data", "medical device", "telehealth", "health insurance",
  "medicare", "medicaid", "hhs", "fda", "cms",
];

// Known healthcare threat groups tracked by HC3
const HC3_THREAT_GROUPS = [
  { name: "Royal/BlackSuit", aliases: ["Royal", "BlackSuit", "Zeon"], targets: "healthcare", severity: 9 },
  { name: "ALPHV/BlackCat", aliases: ["ALPHV", "BlackCat", "Noberus"], targets: "healthcare", severity: 9 },
  { name: "Clop/Cl0p", aliases: ["Clop", "Cl0p", "TA505"], targets: "healthcare", severity: 9 },
  { name: "LockBit", aliases: ["LockBit", "LockBit 3.0", "LockBit Black"], targets: "healthcare", severity: 9 },
  { name: "Rhysida", aliases: ["Rhysida"], targets: "healthcare", severity: 8 },
  { name: "Scattered Spider", aliases: ["Scattered Spider", "UNC3944", "0ktapus"], targets: "healthcare", severity: 8 },
  { name: "Lazarus Group", aliases: ["Lazarus", "HIDDEN COBRA", "APT38"], targets: "healthcare", severity: 9 },
  { name: "Volt Typhoon", aliases: ["Volt Typhoon", "BRONZE SILHOUETTE"], targets: "critical_infrastructure", severity: 10 },
  { name: "Qilin", aliases: ["Qilin", "Agenda"], targets: "healthcare", severity: 8 },
  { name: "INC Ransom", aliases: ["INC Ransom", "INC"], targets: "healthcare", severity: 7 },
];

export const hc3Connector: PassiveConnector = {
  name: "hc3",
  description: "HC3 (HHS Health Sector Cybersecurity) — healthcare sector threat intelligence, HIPAA-relevant alerts",
  requiresApiKey: false,
  freeUrl: "https://www.hhs.gov/about/agencies/asa/ocio/hc3/index.html",

  async collect(domain: string, config?: ConnectorConfig): Promise<ConnectorResult> {
    const observations: AssetObservation[] = [];
    const start = Date.now();
    const errors: string[] = [];
    let rateLimited = false;
    const now = new Date();

    try {
      // Determine if the target is healthcare-related
      const isHealthcare = config?.context?.sector?.toLowerCase().includes("health") ||
                           config?.context?.complianceFlags?.some((f: string) => f.toLowerCase().includes("hipaa")) ||
                           HEALTHCARE_KEYWORDS.some(kw => domain.toLowerCase().includes(kw));

      // Step 1: Check for known healthcare threat groups relevant to this target
      const relevantThreats: typeof HC3_THREAT_GROUPS = [];

      // Cross-reference with any threat actor matches from other connectors
      const knownActors = config?.context?.threatActorMatches || [];
      for (const group of HC3_THREAT_GROUPS) {
        const matched = group.aliases.some(alias =>
          knownActors.some((actor: any) =>
            actor.name?.toLowerCase().includes(alias.toLowerCase()) ||
            actor.aliases?.some((a: string) => a.toLowerCase().includes(alias.toLowerCase()))
          )
        );
        if (matched) relevantThreats.push(group);
      }

      // Step 2: Fetch recent HC3 products page for latest alerts
      let recentAlerts: Array<{ title: string; date?: string; url?: string; type?: string }> = [];
      try {
        const resp = await rateLimitedFetch("hc3", HC3_PRODUCTS_URL, {
          headers: { "User-Agent": "AC3-SecurityScanner/1.0" },
          signal: AbortSignal.timeout(15000),
        });

        if (resp.ok) {
          const html = await resp.text();
          // Parse alert titles and dates from the products page
          const alertRegex = /<a[^>]*href="([^"]*)"[^>]*>([^<]+)<\/a>/gi;
          let match;
          while ((match = alertRegex.exec(html)) !== null && recentAlerts.length < 20) {
            const [, url, title] = match;
            if (title.length > 10 && (
              title.includes("Alert") || title.includes("Briefing") ||
              title.includes("Analyst Note") || title.includes("Threat") ||
              title.includes("Ransomware") || title.includes("Vulnerability")
            )) {
              recentAlerts.push({
                title: title.trim(),
                url: url.startsWith("http") ? url : `https://www.hhs.gov${url}`,
                type: title.includes("Alert") ? "alert" :
                      title.includes("Briefing") ? "briefing" :
                      title.includes("Analyst Note") ? "analyst_note" : "advisory",
              });
            }
          }
        }
      } catch (err: any) {
        errors.push(`HC3 products fetch: ${err.message}`);
      }

      // Step 3: Generate observations

      // Observation 1: Healthcare sector threat landscape
      if (isHealthcare || relevantThreats.length > 0) {
        const name = `HC3 Sector Intel: ${relevantThreats.length > 0 ? `${relevantThreats.length} active threat groups targeting healthcare` : "Healthcare sector threat landscape"}`;

        observations.push({
          assetId: makeAssetId(domain, name, "hc3"),
          domain,
          assetType: "threat_intel",
          name,
          source: "hc3",
          observedAt: now,
          tags: ["hc3", "healthcare", "sector_intel", "hipaa", ...(isHealthcare ? ["target_is_healthcare"] : [])],
          evidence: {
            severity: relevantThreats.length > 0 ? 9 : (isHealthcare ? 6 : 3),
            confidence: relevantThreats.length > 0 ? 85 : 60,
            value: relevantThreats.length > 0
              ? `${relevantThreats.length} known healthcare-targeting threat groups matched: ${relevantThreats.map(t => t.name).join(", ")}`
              : `Healthcare sector threat landscape — HC3 tracks ${HC3_THREAT_GROUPS.length} active groups targeting the health sector`,
            is_healthcare_target: isHealthcare,
            matched_threat_groups: relevantThreats.map(t => ({
              name: t.name,
              aliases: t.aliases,
              severity: t.severity,
            })),
            total_tracked_groups: HC3_THREAT_GROUPS.length,
            tracked_groups: HC3_THREAT_GROUPS.map(g => g.name),
          },
          attribution: {
            provider: "HC3 (HHS Health Sector Cybersecurity Coordination Center)",
            url: "https://www.hhs.gov/about/agencies/asa/ocio/hc3/index.html",
            method: "threat_intel",
          },
        });
      }

      // Observation 2: Recent HC3 alerts
      if (recentAlerts.length > 0) {
        const name = `HC3 Alerts: ${recentAlerts.length} recent healthcare security advisories`;

        observations.push({
          assetId: makeAssetId(domain, name, "hc3"),
          domain,
          assetType: "threat_intel",
          name,
          source: "hc3",
          observedAt: now,
          tags: ["hc3", "healthcare_alerts", "sector_advisories"],
          evidence: {
            severity: 4,
            confidence: 80,
            value: `${recentAlerts.length} recent HC3 advisories — latest: ${recentAlerts[0]?.title || "N/A"}`,
            alert_count: recentAlerts.length,
            alerts: recentAlerts.slice(0, 10).map(a => ({
              title: a.title,
              type: a.type,
              url: a.url,
            })),
          },
          attribution: {
            provider: "HC3 (HHS Health Sector Cybersecurity Coordination Center)",
            url: "https://www.hhs.gov/about/agencies/asa/ocio/hc3/index.html",
            method: "web_scrape",
          },
        });
      }

      // Observation 3: HIPAA compliance context
      if (isHealthcare) {
        const name = `HC3 HIPAA Context: ${domain} identified as healthcare entity`;
        observations.push({
          assetId: makeAssetId(domain, name, "hc3"),
          domain,
          assetType: "compliance",
          name,
          source: "hc3",
          observedAt: now,
          tags: ["hc3", "hipaa", "compliance", "healthcare"],
          evidence: {
            severity: 5,
            confidence: 70,
            value: "Target identified as healthcare entity — HIPAA Security Rule and Breach Notification Rule apply. HC3 recommends enhanced monitoring for ransomware, credential theft, and supply chain attacks.",
            compliance_frameworks: ["HIPAA Security Rule", "HIPAA Breach Notification Rule", "HITECH Act"],
            recommended_controls: [
              "Multi-factor authentication for all remote access",
              "Network segmentation for medical devices and EHR systems",
              "Encrypted backup with offline/immutable copies",
              "Incident response plan with HHS OCR notification procedures",
              "Regular vulnerability scanning of internet-facing assets",
              "Phishing-resistant authentication (FIDO2/WebAuthn)",
            ],
          },
          attribution: {
            provider: "HC3 (HHS Health Sector Cybersecurity Coordination Center)",
            url: "https://www.hhs.gov/about/agencies/asa/ocio/hc3/index.html",
            method: "knowledge_base",
          },
        });
      }
    } catch (err: any) {
      if (err.message?.includes("Rate limit")) rateLimited = true;
      errors.push(err.message || "Unknown error during HC3 lookup");
    }

    return {
      connector: "hc3",
      domain,
      observations,
      errors,
      durationMs: Date.now() - start,
      rateLimited,
    };
  },
};
