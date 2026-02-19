/**
 * STIX 2.1 Bundle Generator
 * 
 * Converts Ace C3 threat intelligence data into STIX 2.1 compliant bundles
 * for sharing with ISACs, SOC teams, and partner organizations.
 * 
 * Supports: Intrusion Set, Indicator, Vulnerability, Campaign, Malware,
 *           Attack Pattern, Identity, Relationship objects
 * 
 * Reference: https://docs.oasis-open.org/cti/stix/v2.1/stix-v2.1.html
 */

import { createHash } from "crypto";

// ─── STIX 2.1 Types ──────────────────────────────────────────────────────────

export interface StixObject {
  type: string;
  spec_version: "2.1";
  id: string;
  created: string;
  modified: string;
  [key: string]: any;
}

export interface StixBundle {
  type: "bundle";
  id: string;
  objects: StixObject[];
}

export interface StixRelationship extends StixObject {
  type: "relationship";
  relationship_type: string;
  source_ref: string;
  target_ref: string;
}

// ─── Helpers ──────────────────────────────────────────────────────────────────

function generateStixId(type: string, seed: string): string {
  // Generate deterministic STIX IDs using SHA-256 so the same data always produces the same ID
  const hash = createHash("sha256").update(seed).digest("hex");
  // Format as UUID v5-like: 8-4-4-4-12
  const uuid = [
    hash.slice(0, 8),
    hash.slice(8, 12),
    "5" + hash.slice(13, 16), // version 5
    "a" + hash.slice(17, 20), // variant
    hash.slice(20, 32),
  ].join("-");
  return `${type}--${uuid}`;
}

function isoNow(): string {
  return new Date().toISOString();
}

function toIso(dateStr: string | null | undefined): string {
  if (!dateStr) return isoNow();
  try {
    const d = new Date(dateStr);
    if (isNaN(d.getTime())) return isoNow();
    return d.toISOString();
  } catch {
    return isoNow();
  }
}

function safeArray(val: unknown): any[] {
  if (Array.isArray(val)) return val;
  if (typeof val === "string") {
    try { const p = JSON.parse(val); return Array.isArray(p) ? p : []; } catch { return []; }
  }
  return [];
}

// ─── Ace C3 Identity (source of all intelligence) ─────────────────────────────

export function createAceC3Identity(): StixObject {
  return {
    type: "identity",
    spec_version: "2.1",
    id: "identity--ace-c3-00000000-0000-4000-a000-000000000001",
    created: "2026-01-01T00:00:00.000Z",
    modified: isoNow(),
    name: "Ace C3 - Cyber Campaign Command",
    description: "Unified red team operations, threat intelligence, and engagement management platform by AceofCloud",
    identity_class: "organization",
    sectors: ["technology"],
    contact_information: "https://aceofcloud.com",
  };
}

// ─── Threat Actor → STIX Intrusion Set ────────────────────────────────────────

export interface ThreatActorInput {
  id: number;
  actorId: string;
  name: string;
  aliases?: any;
  type: string;
  origin?: string | null;
  description?: string | null;
  motivation?: string | null;
  firstSeen?: string | null;
  lastActive?: string | null;
  threatLevel?: string | null;
  sophistication?: string | null;
  targetSectors?: any;
  targetRegions?: any;
  techniques?: any;
  tools?: any;
  malware?: any;
  stixId?: string | null;
  confidence?: number | null;
  createdAt?: Date | null;
  updatedAt?: Date | null;
}

export function threatActorToStix(actor: ThreatActorInput): StixObject[] {
  const objects: StixObject[] = [];
  const now = isoNow();
  const created = actor.createdAt ? new Date(actor.createdAt).toISOString() : now;
  const modified = actor.updatedAt ? new Date(actor.updatedAt).toISOString() : now;

  // Map actor type to STIX resource_level
  const resourceLevelMap: Record<string, string> = {
    apt: "government",
    cybercrime: "organization",
    ransomware: "organization",
    hacktivist: "club",
    access_broker: "individual",
    influence_ops: "government",
    unknown: "unknown",
  };

  // Map sophistication to STIX sophistication
  const sophMap: Record<string, string> = {
    "nation-state": "strategic",
    advanced: "expert",
    intermediate: "intermediate",
    basic: "minimal",
  };

  // Map motivation
  const motivationMap: Record<string, string[]> = {
    espionage: ["espionage"],
    financial: ["personal-gain"],
    disruption: ["disruption"],
    destruction: ["destruction"],
    ideology: ["ideology"],
    dominance: ["dominance"],
  };

  const aliases = safeArray(actor.aliases);
  const primaryMotivations = actor.motivation
    ? (motivationMap[actor.motivation.toLowerCase()] || ["personal-gain"])
    : [];

  const intrusionSet: StixObject = {
    type: "intrusion-set",
    spec_version: "2.1",
    id: actor.stixId || generateStixId("intrusion-set", `ace-c3:actor:${actor.actorId}`),
    created,
    modified,
    name: actor.name,
    description: actor.description || `Threat actor tracked by Ace C3: ${actor.name}`,
    aliases: aliases.length > 0 ? aliases : undefined,
    first_seen: toIso(actor.firstSeen),
    last_seen: toIso(actor.lastActive),
    resource_level: resourceLevelMap[actor.type] || "unknown",
    primary_motivation: primaryMotivations[0] || "personal-gain",
    goals: actor.targetSectors
      ? safeArray(actor.targetSectors).map((s: string) => `Target: ${s}`)
      : undefined,
    confidence: actor.confidence || 50,
    object_marking_refs: ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"], // TLP:WHITE
    created_by_ref: "identity--ace-c3-00000000-0000-4000-a000-000000000001",
    external_references: [
      {
        source_name: "Ace C3",
        external_id: actor.actorId,
        description: `Ace C3 actor ID: ${actor.actorId}`,
      },
    ],
  };

  // Add sophistication if available
  if (actor.sophistication && sophMap[actor.sophistication]) {
    (intrusionSet as any).sophistication = sophMap[actor.sophistication];
  }

  objects.push(intrusionSet);

  // Generate Attack Pattern objects for techniques
  const techniques = safeArray(actor.techniques);
  for (const tech of techniques.slice(0, 50)) { // Limit to 50 techniques per actor
    if (!tech.id) continue;
    const attackPattern: StixObject = {
      type: "attack-pattern",
      spec_version: "2.1",
      id: generateStixId("attack-pattern", `mitre:${tech.id}`),
      created,
      modified,
      name: tech.name || tech.id,
      description: tech.description || `MITRE ATT&CK technique ${tech.id}`,
      external_references: [
        {
          source_name: "mitre-attack",
          external_id: tech.id,
          url: `https://attack.mitre.org/techniques/${tech.id.replace(".", "/")}/`,
        },
      ],
      kill_chain_phases: tech.tactic ? [{
        kill_chain_name: "mitre-attack",
        phase_name: tech.tactic.toLowerCase().replace(/\s+/g, "-"),
      }] : undefined,
    };
    objects.push(attackPattern);

    // Relationship: intrusion-set uses attack-pattern
    objects.push(createRelationship(
      intrusionSet.id,
      attackPattern.id,
      "uses",
      created,
      modified,
    ));
  }

  // Generate Malware objects
  const malwareList = safeArray(actor.malware);
  for (const mal of malwareList.slice(0, 20)) {
    const malName = typeof mal === "string" ? mal : mal.name || String(mal);
    if (!malName) continue;
    const malwareObj: StixObject = {
      type: "malware",
      spec_version: "2.1",
      id: generateStixId("malware", `ace-c3:malware:${malName.toLowerCase()}`),
      created,
      modified,
      name: malName,
      is_family: true,
      malware_types: ["unknown"],
      created_by_ref: "identity--ace-c3-00000000-0000-4000-a000-000000000001",
    };
    objects.push(malwareObj);

    // Relationship: intrusion-set uses malware
    objects.push(createRelationship(
      intrusionSet.id,
      malwareObj.id,
      "uses",
      created,
      modified,
    ));
  }

  // Generate Tool objects
  const tools = safeArray(actor.tools);
  for (const tool of tools.slice(0, 20)) {
    const toolName = typeof tool === "string" ? tool : tool.name || String(tool);
    if (!toolName) continue;
    const toolObj: StixObject = {
      type: "tool",
      spec_version: "2.1",
      id: generateStixId("tool", `ace-c3:tool:${toolName.toLowerCase()}`),
      created,
      modified,
      name: toolName,
      tool_types: ["unknown"],
      created_by_ref: "identity--ace-c3-00000000-0000-4000-a000-000000000001",
    };
    objects.push(toolObj);

    objects.push(createRelationship(
      intrusionSet.id,
      toolObj.id,
      "uses",
      created,
      modified,
    ));
  }

  return objects;
}

// ─── IOC → STIX Indicator ────────────────────────────────────────────────────

export interface IocInput {
  id: number;
  type: string; // hash_md5, hash_sha256, domain, ip, url, email, filename
  value: string;
  description?: string | null;
  confidence?: string | null;
  firstSeen?: string | null;
  lastSeen?: string | null;
  source?: string | null;
  actorId?: string | null;
}

function iocToStixPattern(type: string, value: string): string | null {
  const patternMap: Record<string, string> = {
    hash_md5: `[file:hashes.MD5 = '${value}']`,
    hash_sha1: `[file:hashes.'SHA-1' = '${value}']`,
    hash_sha256: `[file:hashes.'SHA-256' = '${value}']`,
    domain: `[domain-name:value = '${value}']`,
    ip: `[ipv4-addr:value = '${value}']`,
    ipv4: `[ipv4-addr:value = '${value}']`,
    ipv6: `[ipv6-addr:value = '${value}']`,
    url: `[url:value = '${value}']`,
    email: `[email-addr:value = '${value}']`,
    filename: `[file:name = '${value}']`,
    registry: `[windows-registry-key:key = '${value}']`,
    mutex: `[mutex:name = '${value}']`,
  };
  return patternMap[type.toLowerCase()] || null;
}

export function iocToStix(ioc: IocInput): StixObject | null {
  const pattern = iocToStixPattern(ioc.type, ioc.value);
  if (!pattern) return null;

  const now = isoNow();
  const confidenceMap: Record<string, number> = {
    high: 85,
    medium: 50,
    low: 25,
  };

  const indicator: StixObject = {
    type: "indicator",
    spec_version: "2.1",
    id: generateStixId("indicator", `ace-c3:ioc:${ioc.type}:${ioc.value}`),
    created: toIso(ioc.firstSeen) || now,
    modified: now,
    name: `${ioc.type.toUpperCase()}: ${ioc.value}`,
    description: ioc.description || `IOC indicator from Ace C3 (${ioc.source || "unknown source"})`,
    indicator_types: ["malicious-activity"],
    pattern,
    pattern_type: "stix",
    valid_from: toIso(ioc.firstSeen) || now,
    valid_until: undefined, // IOCs don't expire by default
    confidence: confidenceMap[ioc.confidence || "medium"] || 50,
    created_by_ref: "identity--ace-c3-00000000-0000-4000-a000-000000000001",
    external_references: [
      {
        source_name: ioc.source || "Ace C3",
        description: `IOC from ${ioc.source || "Ace C3 platform"}`,
      },
    ],
    object_marking_refs: ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"], // TLP:WHITE
  };

  return indicator;
}

// ─── IOC Feed Entry → STIX Indicator ──────────────────────────────────────────

export interface IocFeedInput {
  id: number;
  feedSource: string;
  feedType: string;
  title?: string | null;
  description?: string | null;
  severity?: string | null;
  iocType?: string | null;
  iocValue?: string | null;
  cveId?: string | null;
  vendorProduct?: string | null;
  knownRansomware?: boolean | null;
  dateAdded?: string | null;
  linkedActors?: any;
  tags?: any;
  createdAt?: Date | null;
}

export function iocFeedToStix(entry: IocFeedInput): StixObject[] {
  const objects: StixObject[] = [];
  const now = isoNow();
  const created = entry.createdAt ? new Date(entry.createdAt).toISOString() : now;

  // If it has an IOC value, create an Indicator
  if (entry.iocValue && entry.iocType) {
    const pattern = iocToStixPattern(entry.iocType, entry.iocValue);
    if (pattern) {
      const indicator: StixObject = {
        type: "indicator",
        spec_version: "2.1",
        id: generateStixId("indicator", `ace-c3:feed:${entry.feedSource}:${entry.iocValue}`),
        created,
        modified: now,
        name: entry.title || `${entry.iocType}: ${entry.iocValue}`,
        description: entry.description || `Feed indicator from ${entry.feedSource}`,
        indicator_types: entry.knownRansomware ? ["malicious-activity", "attribution"] : ["malicious-activity"],
        pattern,
        pattern_type: "stix",
        valid_from: toIso(entry.dateAdded) || created,
        confidence: entry.severity === "critical" ? 90 : entry.severity === "high" ? 75 : entry.severity === "medium" ? 50 : 30,
        labels: safeArray(entry.tags),
        created_by_ref: "identity--ace-c3-00000000-0000-4000-a000-000000000001",
        external_references: [
          {
            source_name: entry.feedSource,
            description: `From ${entry.feedSource} feed`,
          },
        ],
        object_marking_refs: ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"],
      };
      objects.push(indicator);
    }
  }

  // If it has a CVE, create a Vulnerability
  if (entry.cveId) {
    const vuln: StixObject = {
      type: "vulnerability",
      spec_version: "2.1",
      id: generateStixId("vulnerability", `cve:${entry.cveId}`),
      created,
      modified: now,
      name: entry.cveId,
      description: entry.description || `Vulnerability ${entry.cveId}`,
      external_references: [
        {
          source_name: "cve",
          external_id: entry.cveId,
          url: `https://nvd.nist.gov/vuln/detail/${entry.cveId}`,
        },
      ],
      created_by_ref: "identity--ace-c3-00000000-0000-4000-a000-000000000001",
    };
    objects.push(vuln);
  }

  return objects;
}

// ─── Engagement → STIX Campaign ──────────────────────────────────────────────

export interface EngagementInput {
  id: number;
  name: string;
  customerName: string;
  description?: string | null;
  engagementType: string;
  status: string;
  targetDomain?: string | null;
  createdAt?: Date | null;
  updatedAt?: Date | null;
}

export function engagementToStix(engagement: EngagementInput): StixObject {
  const now = isoNow();
  const created = engagement.createdAt ? new Date(engagement.createdAt).toISOString() : now;
  const modified = engagement.updatedAt ? new Date(engagement.updatedAt).toISOString() : now;

  return {
    type: "campaign",
    spec_version: "2.1",
    id: generateStixId("campaign", `ace-c3:engagement:${engagement.id}`),
    created,
    modified,
    name: engagement.name,
    description: engagement.description || `${engagement.engagementType} engagement for ${engagement.customerName}`,
    first_seen: created,
    objective: `${engagement.engagementType.replace("_", " ")} assessment`,
    created_by_ref: "identity--ace-c3-00000000-0000-4000-a000-000000000001",
    external_references: [
      {
        source_name: "Ace C3",
        external_id: `engagement-${engagement.id}`,
        description: `Ace C3 engagement: ${engagement.name}`,
      },
    ],
    object_marking_refs: ["marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9"],
  };
}

// ─── Exploit → STIX Vulnerability / Attack Pattern ────────────────────────────

export interface ExploitInput {
  id: number;
  catalogId: string;
  name: string;
  description?: string | null;
  category: string;
  source: string;
  cveIds?: any;
  cvssScore?: number | null;
  severity?: string | null;
  mitreId?: string | null;
  mitreName?: string | null;
  mitreTactic?: string | null;
  platform?: string | null;
}

export function exploitToStix(exploit: ExploitInput): StixObject[] {
  const objects: StixObject[] = [];
  const now = isoNow();

  // Create Attack Pattern for the exploit technique
  if (exploit.mitreId) {
    const attackPattern: StixObject = {
      type: "attack-pattern",
      spec_version: "2.1",
      id: generateStixId("attack-pattern", `mitre:${exploit.mitreId}`),
      created: now,
      modified: now,
      name: exploit.mitreName || exploit.name,
      description: exploit.description || `Exploit technique: ${exploit.name}`,
      external_references: [
        {
          source_name: "mitre-attack",
          external_id: exploit.mitreId,
          url: `https://attack.mitre.org/techniques/${exploit.mitreId.replace(".", "/")}/`,
        },
        {
          source_name: exploit.source,
          external_id: exploit.catalogId,
        },
      ],
      kill_chain_phases: exploit.mitreTactic ? [{
        kill_chain_name: "mitre-attack",
        phase_name: exploit.mitreTactic.toLowerCase().replace(/\s+/g, "-"),
      }] : undefined,
      created_by_ref: "identity--ace-c3-00000000-0000-4000-a000-000000000001",
    };
    objects.push(attackPattern);
  }

  // Create Vulnerability objects for CVEs
  const cves = safeArray(exploit.cveIds);
  for (const cve of cves.slice(0, 10)) {
    const cveId = typeof cve === "string" ? cve : String(cve);
    if (!cveId.startsWith("CVE-")) continue;
    const vuln: StixObject = {
      type: "vulnerability",
      spec_version: "2.1",
      id: generateStixId("vulnerability", `cve:${cveId}`),
      created: now,
      modified: now,
      name: cveId,
      description: `${cveId} — ${exploit.name}${exploit.cvssScore ? ` (CVSS: ${exploit.cvssScore})` : ""}`,
      external_references: [
        {
          source_name: "cve",
          external_id: cveId,
          url: `https://nvd.nist.gov/vuln/detail/${cveId}`,
        },
      ],
      created_by_ref: "identity--ace-c3-00000000-0000-4000-a000-000000000001",
    };
    objects.push(vuln);
  }

  return objects;
}

// ─── Relationship Helper ──────────────────────────────────────────────────────

function createRelationship(
  sourceRef: string,
  targetRef: string,
  relationshipType: string,
  created: string,
  modified: string,
): StixRelationship {
  return {
    type: "relationship",
    spec_version: "2.1",
    id: generateStixId("relationship", `${sourceRef}:${relationshipType}:${targetRef}`),
    created,
    modified,
    relationship_type: relationshipType,
    source_ref: sourceRef,
    target_ref: targetRef,
    created_by_ref: "identity--ace-c3-00000000-0000-4000-a000-000000000001",
  };
}

// ─── Bundle Builder ───────────────────────────────────────────────────────────

export function createStixBundle(objects: StixObject[]): StixBundle {
  // Deduplicate by ID
  const seen = new Set<string>();
  const deduped: StixObject[] = [];
  
  // Always include the Ace C3 identity and TLP marking
  const identity = createAceC3Identity();
  deduped.push(identity);
  seen.add(identity.id);

  // Add TLP:WHITE marking definition
  const tlpWhite: StixObject = {
    type: "marking-definition",
    spec_version: "2.1",
    id: "marking-definition--613f2e26-407d-48c7-9eca-b8e91df99dc9",
    created: "2017-01-20T00:00:00.000Z",
    modified: "2017-01-20T00:00:00.000Z",
    name: "TLP:WHITE",
    definition_type: "tlp",
    definition: { tlp: "white" },
  };
  deduped.push(tlpWhite);
  seen.add(tlpWhite.id);

  for (const obj of objects) {
    if (!seen.has(obj.id)) {
      seen.add(obj.id);
      deduped.push(obj);
    }
  }

  // Clean undefined values from objects
  const cleaned = deduped.map(obj => {
    const clean: any = {};
    for (const [k, v] of Object.entries(obj)) {
      if (v !== undefined && v !== null) {
        clean[k] = v;
      }
    }
    return clean;
  });

  return {
    type: "bundle",
    id: generateStixId("bundle", `ace-c3:bundle:${Date.now()}`),
    objects: cleaned,
  };
}

// ─── Collection Types for TAXII ───────────────────────────────────────────────

export interface TaxiiCollection {
  id: string;
  title: string;
  description: string;
  can_read: boolean;
  can_write: boolean;
  media_types: string[];
}

export const TAXII_COLLECTIONS: TaxiiCollection[] = [
  {
    id: "ace-c3-threat-actors",
    title: "Ace C3 Threat Actors",
    description: "Threat actor profiles (intrusion sets) from the Ace C3 threat catalog",
    can_read: true,
    can_write: false,
    media_types: ["application/stix+json;version=2.1"],
  },
  {
    id: "ace-c3-indicators",
    title: "Ace C3 Indicators",
    description: "IOC indicators from Ace C3 feeds (Abuse.ch, ThreatFox, CISA KEV)",
    can_read: true,
    can_write: false,
    media_types: ["application/stix+json;version=2.1"],
  },
  {
    id: "ace-c3-vulnerabilities",
    title: "Ace C3 Vulnerabilities",
    description: "Vulnerability data from KEV, NVD, and exploit catalog",
    can_read: true,
    can_write: false,
    media_types: ["application/stix+json;version=2.1"],
  },
  {
    id: "ace-c3-campaigns",
    title: "Ace C3 Campaigns",
    description: "Red team engagement campaigns from Ace C3",
    can_read: true,
    can_write: false,
    media_types: ["application/stix+json;version=2.1"],
  },
  {
    id: "ace-c3-all",
    title: "Ace C3 Complete Intelligence",
    description: "All threat intelligence from the Ace C3 platform",
    can_read: true,
    can_write: false,
    media_types: ["application/stix+json;version=2.1"],
  },
];

// ─── Export Stats ─────────────────────────────────────────────────────────────

export interface StixExportStats {
  totalObjects: number;
  byType: Record<string, number>;
  bundleSize: number;
  generatedAt: string;
}

export function getBundleStats(bundle: StixBundle): StixExportStats {
  const byType: Record<string, number> = {};
  for (const obj of bundle.objects) {
    byType[obj.type] = (byType[obj.type] || 0) + 1;
  }
  const json = JSON.stringify(bundle);
  return {
    totalObjects: bundle.objects.length,
    byType,
    bundleSize: json.length,
    generatedAt: isoNow(),
  };
}
