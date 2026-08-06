/**
 * DHS/FBI Advisory Auto-Correlation Engine
 * 
 * Automatically correlates CISA/FBI/DHS advisories with:
 * - Active client engagements (target sectors, equipment, threat actors)
 * - Monitored PLC fleet (affected vendors/models)
 * - Exploit arsenal (matching CVEs)
 * - Threat actor database (attribution links)
 * - Utility attack playbooks (matching TTPs)
 * 
 * Generates actionable intelligence briefs when new advisories match
 * client infrastructure or active operations.
 * 
 * Author: Harrison Cook / AC3 Platform
 */

// ─── Types ──────────────────────────────────────────────────────────────────────

export type AdvisorySource = "cisa" | "fbi" | "nsa" | "epa" | "doe" | "uscybercom" | "treasury" | "joint";
export type AdvisorySeverity = "critical" | "high" | "medium" | "low";
export type CorrelationConfidence = "high" | "moderate" | "low";

export interface Advisory {
  id: string;
  title: string;
  source: AdvisorySource[];
  publishedDate: Date;
  lastUpdated: Date;
  severity: AdvisorySeverity;
  summary: string;
  threatActors: string[];
  targetedSectors: string[];
  targetedVendors: string[];
  targetedProducts: string[];
  cves: string[];
  mitreIcsIds: string[];
  mitreAttackIds: string[];
  iocs: AdvisoryIoc[];
  mitigations: string[];
  url: string;
  rawContent?: string;
}

export interface AdvisoryIoc {
  type: "ip" | "domain" | "hash_md5" | "hash_sha256" | "url" | "email" | "file_path" | "registry_key" | "yara" | "snort";
  value: string;
  context: string;
}

export interface CorrelationResult {
  advisoryId: string;
  advisoryTitle: string;
  correlationType: CorrelationType;
  confidence: CorrelationConfidence;
  matchedEntity: string;
  matchedEntityType: string;
  impactAssessment: string;
  recommendedActions: string[];
  urgency: "immediate" | "24h" | "7d" | "informational";
  relatedPlaybooks: string[];
  relatedExploits: string[];
}

export type CorrelationType =
  | "client_sector_match"       // Advisory targets same sector as active client
  | "client_equipment_match"    // Advisory targets equipment in client's inventory
  | "plc_fleet_match"           // Advisory targets monitored PLC models
  | "cve_exploit_match"         // Advisory CVEs match our exploit arsenal
  | "threat_actor_match"        // Advisory threat actor is targeting our clients
  | "active_campaign_match"     // Advisory describes campaign we're emulating
  | "ioc_match"                 // Advisory IOCs found in our telemetry
  | "geographic_match";         // Advisory targets same region as client operations

// ─── Known Advisory Database ────────────────────────────────────────────────────

const ADVISORY_DATABASE: Advisory[] = [
  {
    id: "AA26-097A",
    title: "IRGC-Affiliated Cyber Actors Exploit PLCs in Multiple Sectors",
    source: ["cisa", "fbi", "nsa", "epa", "doe", "uscybercom", "treasury"],
    publishedDate: new Date("2026-04-07"),
    lastUpdated: new Date("2026-07-22"),
    severity: "critical",
    summary: "IRGC-CEC-affiliated CyberAv3ngers actors are exploiting internet-accessible PLCs across water, energy, and government sectors. Updated July 22 to include Schneider Electric and Siemens equipment, and detection guidance for AOI tampering that disables safety systems.",
    threatActors: ["CyberAv3ngers", "IRGC-CEC", "Storm-0784", "Bauxite"],
    targetedSectors: ["water", "wastewater", "energy", "government", "food_agriculture"],
    targetedVendors: ["Rockwell Automation", "Schneider Electric", "Siemens", "Unitronics"],
    targetedProducts: ["MicroLogix 1100", "MicroLogix 1400", "CompactLogix", "ControlLogix", "Modicon M340", "S7-1200", "Vision V570"],
    cves: ["CVE-2021-22681", "CVE-2022-1159", "CVE-2022-45789", "CVE-2023-3595"],
    mitreIcsIds: ["T0883", "T0886", "T0859", "T0836", "T0821", "T0839", "T0832", "T0880", "T0882"],
    mitreAttackIds: ["T1190", "T1078", "T1021"],
    iocs: [
      { type: "ip", value: "185.220.101.0/24", context: "Tor exit nodes used for PLC scanning" },
      { type: "ip", value: "91.92.240.0/23", context: "Hosting infrastructure for engineering software connections" },
      { type: "domain", value: "update-service.cyberav3ngers.net", context: "C2 infrastructure" },
      { type: "hash_sha256", value: "a1b2c3d4e5f6...", context: "IOCONTROL malware sample" },
    ],
    mitigations: [
      "Remove PLCs from direct internet access immediately",
      "Place behind VPN/firewall with strict ACL",
      "Set physical key switch to RUN mode",
      "Implement CIP Security for authenticated communications",
      "Monitor for engineering software connections from non-authorized IPs",
      "Periodic integrity checks of PLC project files and AOIs",
      "Maintain offline backups of all PLC programs",
    ],
    url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa26-097a",
  },
  {
    id: "FBI-PSA-260730",
    title: "Malicious Cyber Actors Targeting Water and Wastewater Sector Internet-Facing PLCs",
    source: ["fbi", "epa"],
    publishedDate: new Date("2026-07-30"),
    lastUpdated: new Date("2026-07-30"),
    severity: "critical",
    summary: "Since July 27, 2026, actors have remotely accessed internet-facing Rockwell MicroLogix 1100 and 1400 controllers at water utilities in at least seven states, changing IP addresses and passwords to lock operators out. Reported effects include loss of pressure and flooding.",
    threatActors: ["Unknown (Iran-linked assessed)", "CyberAv3ngers (likely)"],
    targetedSectors: ["water", "wastewater"],
    targetedVendors: ["Rockwell Automation"],
    targetedProducts: ["MicroLogix 1100", "MicroLogix 1400"],
    cves: [],
    mitreIcsIds: ["T0883", "T0859", "T0836", "T0826"],
    mitreAttackIds: [],
    iocs: [
      { type: "ip", value: "Various foreign hosting providers", context: "Source of unauthorized PLC connections" },
    ],
    mitigations: [
      "Remove PLCs from direct internet exposure",
      "Use strong, unique passwords on all PLCs",
      "Limit communications through access control lists",
      "Place PLCs behind secure gateways and firewalls",
      "Monitor for unauthorized configuration changes",
      "Maintain offline project file backups",
    ],
    url: "https://www.ic3.gov/PSA/2026/PSA260730.pdf",
  },
  {
    id: "AA23-335A",
    title: "IRGC-Affiliated Cyber Actors Exploit PLCs in Multiple Sectors (Original)",
    source: ["cisa", "fbi", "nsa", "epa"],
    publishedDate: new Date("2023-12-01"),
    lastUpdated: new Date("2024-02-01"),
    severity: "high",
    summary: "CyberAv3ngers actors affiliated with IRGC-CEC are actively targeting and compromising Unitronics Vision Series PLCs using default credentials. 75+ devices compromised globally.",
    threatActors: ["CyberAv3ngers", "IRGC-CEC"],
    targetedSectors: ["water", "wastewater", "energy", "food_agriculture"],
    targetedVendors: ["Unitronics"],
    targetedProducts: ["Vision V570", "Vision V130", "Vision V350"],
    cves: [],
    mitreIcsIds: ["T0883", "T0859", "T0832"],
    mitreAttackIds: ["T1078.001"],
    iocs: [
      { type: "ip", value: "Various", context: "Scanning for port 20256 (PCOM)" },
    ],
    mitigations: [
      "Change default password from '1111'",
      "Remove PLCs from internet",
      "Disable SSH on Unitronics devices",
      "Implement network monitoring for PCOM protocol",
    ],
    url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa23-335a",
  },
  {
    id: "AA22-110A",
    title: "Russian State-Sponsored and Criminal Cyber Threats to Critical Infrastructure",
    source: ["cisa", "fbi", "nsa"],
    publishedDate: new Date("2022-04-20"),
    lastUpdated: new Date("2022-04-20"),
    severity: "critical",
    summary: "Russian state-sponsored actors have demonstrated capability to compromise industrial control systems, including Sandworm's attacks on Ukrainian power grid using Industroyer/CrashOverride malware.",
    threatActors: ["Sandworm", "ELECTRUM", "Voodoo Bear", "GRU Unit 74455"],
    targetedSectors: ["energy", "water", "government", "defense", "transportation"],
    targetedVendors: ["Siemens", "ABB", "Schneider Electric", "GE"],
    targetedProducts: ["SIPROTEC", "REF615", "Modicon", "UR family"],
    cves: ["CVE-2015-5374", "CVE-2018-4832"],
    mitreIcsIds: ["T0855", "T0836", "T0809", "T0886"],
    mitreAttackIds: ["T1566", "T1078", "T1021"],
    iocs: [],
    mitigations: [
      "Implement IEC 62443 network segmentation",
      "Deploy OT-specific intrusion detection",
      "Maintain offline backups of all IED/relay configurations",
      "Implement physical interlocks on critical breakers",
    ],
    url: "https://www.cisa.gov/news-events/cybersecurity-advisories/aa22-110a",
  },
  {
    id: "CISA-ALERT-260730",
    title: "CISA Urges Water and Wastewater Systems Sector to Protect OT Against Activity Targeting PLCs",
    source: ["cisa"],
    publishedDate: new Date("2026-07-30"),
    lastUpdated: new Date("2026-07-30"),
    severity: "critical",
    summary: "CISA is currently observing a significant increase in cyber threat actors targeting PLCs in the Water and Wastewater Systems Sector. Urges operators to immediately remove exposed PLCs from the internet.",
    threatActors: ["CyberAv3ngers (assessed)", "Iran-linked actors"],
    targetedSectors: ["water", "wastewater"],
    targetedVendors: ["Rockwell Automation", "Schneider Electric", "Siemens"],
    targetedProducts: ["MicroLogix 1100", "MicroLogix 1400", "CompactLogix"],
    cves: ["CVE-2021-22681"],
    mitreIcsIds: ["T0883", "T0859", "T0836"],
    mitreAttackIds: [],
    iocs: [],
    mitigations: [
      "Remove internet-exposed PLCs immediately",
      "Implement VPN for remote access",
      "Enable multi-factor authentication where possible",
      "Monitor for unauthorized configuration changes",
      "Report incidents to CISA",
    ],
    url: "https://www.cisa.gov/news-events/alerts/2026/07/30/cisa-urges-water-and-wastewater-systems-sector-protect-ot-against-activity-targeting-plcs",
  },
];

// ─── Correlation Engine ─────────────────────────────────────────────────────────

interface ClientProfile {
  id: number;
  name: string;
  sector: string;
  equipment: { vendor: string; model: string }[];
  region: string;
  threatActorsOfConcern: string[];
}

interface PlcFleetProfile {
  devices: { vendor: string; model: string; sector: string; isExposed: boolean }[];
}

interface ExploitArsenalProfile {
  cves: string[];
  targetVendors: string[];
}

let clientProfiles: ClientProfile[] = [];
let plcFleet: PlcFleetProfile = { devices: [] };
let exploitArsenal: ExploitArsenalProfile = { cves: [], targetVendors: [] };

/**
 * Register client profiles for correlation
 */
export function registerClientProfiles(profiles: ClientProfile[]): void {
  clientProfiles = profiles;
}

/**
 * Register PLC fleet for correlation
 */
export function registerPlcFleet(fleet: PlcFleetProfile): void {
  plcFleet = fleet;
}

/**
 * Register exploit arsenal for correlation
 */
export function registerExploitArsenal(arsenal: ExploitArsenalProfile): void {
  exploitArsenal = arsenal;
}

/**
 * Correlate a single advisory against all registered profiles
 */
export function correlateAdvisory(advisoryId: string): CorrelationResult[] {
  const advisory = ADVISORY_DATABASE.find(a => a.id === advisoryId);
  if (!advisory) return [];

  const results: CorrelationResult[] = [];

  // 1. Client sector matches
  for (const client of clientProfiles) {
    if (advisory.targetedSectors.includes(client.sector)) {
      results.push({
        advisoryId: advisory.id,
        advisoryTitle: advisory.title,
        correlationType: "client_sector_match",
        confidence: "high",
        matchedEntity: client.name,
        matchedEntityType: `Client (${client.sector} sector)`,
        impactAssessment: `Client "${client.name}" operates in the ${client.sector} sector, which is explicitly targeted by ${advisory.threatActors.join(", ")}`,
        recommendedActions: [
          `Brief ${client.name} on advisory ${advisory.id}`,
          "Verify client's OT equipment is not internet-exposed",
          "Review client's PLC inventory against targeted products",
          ...advisory.mitigations.slice(0, 3),
        ],
        urgency: advisory.severity === "critical" ? "immediate" : "24h",
        relatedPlaybooks: getRelatedPlaybooks(advisory),
        relatedExploits: advisory.cves,
      });
    }

    // Client equipment matches
    for (const equipment of client.equipment) {
      if (advisory.targetedVendors.some(v => v.toLowerCase().includes(equipment.vendor.toLowerCase())) ||
          advisory.targetedProducts.some(p => p.toLowerCase().includes(equipment.model.toLowerCase()))) {
        results.push({
          advisoryId: advisory.id,
          advisoryTitle: advisory.title,
          correlationType: "client_equipment_match",
          confidence: "high",
          matchedEntity: `${client.name} — ${equipment.vendor} ${equipment.model}`,
          matchedEntityType: "Client Equipment",
          impactAssessment: `Client "${client.name}" has ${equipment.vendor} ${equipment.model} in their inventory, which is directly targeted by this advisory.`,
          recommendedActions: [
            `URGENT: Verify ${equipment.vendor} ${equipment.model} at ${client.name} is not internet-exposed`,
            "Capture integrity baseline of affected equipment immediately",
            "Implement recommended mitigations from advisory",
            "Consider emergency engagement to assess exposure",
          ],
          urgency: "immediate",
          relatedPlaybooks: getRelatedPlaybooks(advisory),
          relatedExploits: advisory.cves,
        });
      }
    }

    // Threat actor matches
    for (const actor of advisory.threatActors) {
      if (client.threatActorsOfConcern.some(a => a.toLowerCase().includes(actor.toLowerCase()))) {
        results.push({
          advisoryId: advisory.id,
          advisoryTitle: advisory.title,
          correlationType: "threat_actor_match",
          confidence: "moderate",
          matchedEntity: `${client.name} — ${actor}`,
          matchedEntityType: "Threat Actor of Concern",
          impactAssessment: `${actor} is listed as a threat actor of concern for ${client.name} and is attributed in this advisory.`,
          recommendedActions: [
            `Update threat model for ${client.name} with new TTPs from advisory`,
            "Review detection coverage against documented techniques",
            "Consider adversary emulation exercise using advisory TTPs",
          ],
          urgency: "24h",
          relatedPlaybooks: getRelatedPlaybooks(advisory),
          relatedExploits: advisory.cves,
        });
      }
    }
  }

  // 2. PLC fleet matches
  for (const device of plcFleet.devices) {
    if (advisory.targetedVendors.some(v => v.toLowerCase().includes(device.vendor.toLowerCase())) ||
        advisory.targetedProducts.some(p => p.toLowerCase().includes(device.model.toLowerCase()))) {
      results.push({
        advisoryId: advisory.id,
        advisoryTitle: advisory.title,
        correlationType: "plc_fleet_match",
        confidence: "high",
        matchedEntity: `${device.vendor} ${device.model} (${device.sector})`,
        matchedEntityType: "Monitored PLC Device",
        impactAssessment: `Monitored PLC ${device.vendor} ${device.model} is directly targeted. ${device.isExposed ? "CRITICAL: Device is internet-exposed!" : "Device is behind network controls."}`,
        recommendedActions: device.isExposed ? [
          "IMMEDIATE: Disconnect from internet",
          "Capture integrity baseline before any changes",
          "Check for signs of compromise (IP changes, password changes, project file modifications)",
          "Apply all advisory mitigations",
        ] : [
          "Verify network segmentation is effective",
          "Capture/verify integrity baseline",
          "Monitor for unauthorized access attempts",
        ],
        urgency: device.isExposed ? "immediate" : "24h",
        relatedPlaybooks: getRelatedPlaybooks(advisory),
        relatedExploits: advisory.cves,
      });
    }
  }

  // 3. Exploit arsenal matches
  for (const cve of advisory.cves) {
    if (exploitArsenal.cves.includes(cve)) {
      results.push({
        advisoryId: advisory.id,
        advisoryTitle: advisory.title,
        correlationType: "cve_exploit_match",
        confidence: "high",
        matchedEntity: cve,
        matchedEntityType: "Exploit in Arsenal",
        impactAssessment: `${cve} is in our exploit arsenal and is being actively exploited by ${advisory.threatActors.join(", ")} per this advisory.`,
        recommendedActions: [
          "Prioritize this exploit for client assessments in affected sectors",
          "Update exploit metadata with advisory attribution",
          "Consider proactive scanning of client infrastructure for this CVE",
        ],
        urgency: "24h",
        relatedPlaybooks: getRelatedPlaybooks(advisory),
        relatedExploits: [cve],
      });
    }
  }

  return results;
}

/**
 * Correlate ALL advisories against registered profiles
 */
export function correlateAllAdvisories(): {
  totalCorrelations: number;
  byUrgency: Record<string, number>;
  byType: Record<string, number>;
  results: CorrelationResult[];
} {
  const allResults: CorrelationResult[] = [];

  for (const advisory of ADVISORY_DATABASE) {
    const results = correlateAdvisory(advisory.id);
    allResults.push(...results);
  }

  const byUrgency: Record<string, number> = {};
  const byType: Record<string, number> = {};

  for (const r of allResults) {
    byUrgency[r.urgency] = (byUrgency[r.urgency] || 0) + 1;
    byType[r.correlationType] = (byType[r.correlationType] || 0) + 1;
  }

  return {
    totalCorrelations: allResults.length,
    byUrgency,
    byType,
    results: allResults.sort((a, b) => {
      const urgencyOrder = { immediate: 0, "24h": 1, "7d": 2, informational: 3 };
      return (urgencyOrder[a.urgency] || 3) - (urgencyOrder[b.urgency] || 3);
    }),
  };
}

/**
 * Get all advisories in the database
 */
export function getAdvisories(filters?: {
  source?: AdvisorySource;
  severity?: AdvisorySeverity;
  sector?: string;
  vendor?: string;
  threatActor?: string;
  since?: Date;
}): Advisory[] {
  let filtered = [...ADVISORY_DATABASE];

  if (filters?.source) filtered = filtered.filter(a => a.source.includes(filters.source!));
  if (filters?.severity) filtered = filtered.filter(a => a.severity === filters.severity);
  if (filters?.sector) filtered = filtered.filter(a => a.targetedSectors.includes(filters.sector!));
  if (filters?.vendor) filtered = filtered.filter(a => a.targetedVendors.some(v => v.toLowerCase().includes(filters.vendor!.toLowerCase())));
  if (filters?.threatActor) filtered = filtered.filter(a => a.threatActors.some(t => t.toLowerCase().includes(filters.threatActor!.toLowerCase())));
  if (filters?.since) filtered = filtered.filter(a => a.lastUpdated >= filters.since!);

  return filtered.sort((a, b) => b.lastUpdated.getTime() - a.lastUpdated.getTime());
}

/**
 * Get advisory by ID
 */
export function getAdvisoryById(id: string): Advisory | undefined {
  return ADVISORY_DATABASE.find(a => a.id === id);
}

/**
 * Get advisory statistics
 */
export function getAdvisoryStats(): {
  total: number;
  bySource: Record<string, number>;
  bySeverity: Record<string, number>;
  bySector: Record<string, number>;
  byThreatActor: Record<string, number>;
  recentUpdates: Advisory[];
} {
  const bySource: Record<string, number> = {};
  const bySeverity: Record<string, number> = {};
  const bySector: Record<string, number> = {};
  const byThreatActor: Record<string, number> = {};

  for (const a of ADVISORY_DATABASE) {
    for (const s of a.source) bySource[s] = (bySource[s] || 0) + 1;
    bySeverity[a.severity] = (bySeverity[a.severity] || 0) + 1;
    for (const sec of a.targetedSectors) bySector[sec] = (bySector[sec] || 0) + 1;
    for (const ta of a.threatActors) byThreatActor[ta] = (byThreatActor[ta] || 0) + 1;
  }

  return {
    total: ADVISORY_DATABASE.length,
    bySource,
    bySeverity,
    bySector,
    byThreatActor,
    recentUpdates: ADVISORY_DATABASE.sort((a, b) => b.lastUpdated.getTime() - a.lastUpdated.getTime()).slice(0, 5),
  };
}

// ─── Helper Functions ───────────────────────────────────────────────────────────

function getRelatedPlaybooks(advisory: Advisory): string[] {
  const playbooks: string[] = [];

  if (advisory.targetedSectors.includes("water") || advisory.targetedSectors.includes("wastewater")) {
    if (advisory.threatActors.some(a => a.includes("CyberAv3ngers"))) {
      playbooks.push("WTR-001", "WTR-002");
    }
    if (advisory.targetedProducts.some(p => p.includes("Unitronics"))) {
      playbooks.push("WTR-003");
    }
    if (advisory.targetedSectors.includes("wastewater")) {
      playbooks.push("WW-001");
    }
  }

  if (advisory.targetedSectors.includes("energy")) {
    if (advisory.threatActors.some(a => a.includes("Sandworm"))) {
      playbooks.push("ELC-001");
    }
    if (advisory.mitreIcsIds.includes("T0855")) {
      playbooks.push("ELC-002");
    }
  }

  return [...new Set(playbooks)];
}
