/**
 * ICS/IoT Device Discovery Engine
 *
 * Discovers and fingerprints ICS/IoT/OT devices using:
 * 1. Shodan ICS-specific queries (Modbus, S7comm, BACnet, DNP3, EtherNet/IP, etc.)
 * 2. Censys IoT device search
 * 3. Protocol-specific fingerprinting and banner analysis
 * 4. Device classification (PLC, RTU, HMI, DCS, SCADA, Safety Systems)
 * 5. Purdue model level assignment
 */

import { getDbRequired } from "../db";
import { icsDevices, type InsertIcsDevice } from "../../drizzle/schema";
import { eq, and, sql } from "drizzle-orm";

// ─── ICS Protocol Definitions ─────────────────────────────────────────────────

export interface IcsProtocol {
  name: string;
  port: number;
  altPorts?: number[];
  description: string;
  shodanQuery: string;
  deviceTypes: string[];
  sectors: string[];
  riskLevel: "critical" | "high" | "medium" | "low";
  authRequired: boolean;
}

export const ICS_PROTOCOLS: Record<string, IcsProtocol> = {
  modbus: {
    name: "Modbus TCP",
    port: 502,
    description: "Industrial automation protocol for PLCs and RTUs. No built-in authentication.",
    shodanQuery: "port:502",
    deviceTypes: ["plc", "rtu", "gateway"],
    sectors: ["energy", "water", "manufacturing", "oil_gas"],
    riskLevel: "critical",
    authRequired: false,
  },
  s7comm: {
    name: "Siemens S7",
    port: 102,
    description: "Siemens proprietary protocol for S7 family PLCs (S7-300, S7-400, S7-1200, S7-1500).",
    shodanQuery: "port:102",
    deviceTypes: ["plc", "hmi", "engineering_workstation"],
    sectors: ["manufacturing", "energy", "water", "chemical"],
    riskLevel: "critical",
    authRequired: false,
  },
  dnp3: {
    name: "DNP3",
    port: 20000,
    description: "Distributed Network Protocol for electric and water utilities SCADA.",
    shodanQuery: 'port:20000 source address',
    deviceTypes: ["rtu", "scada_server", "gateway"],
    sectors: ["energy", "water"],
    riskLevel: "critical",
    authRequired: false,
  },
  bacnet: {
    name: "BACnet",
    port: 47808,
    description: "Building Automation and Control Networks protocol for HVAC, lighting, fire.",
    shodanQuery: "port:47808",
    deviceTypes: ["building_automation", "gateway", "sensor"],
    sectors: ["building_automation", "healthcare"],
    riskLevel: "high",
    authRequired: false,
  },
  ethernetip: {
    name: "EtherNet/IP",
    port: 44818,
    description: "Industrial Ethernet protocol by ODVA for Allen-Bradley/Rockwell PLCs.",
    shodanQuery: "port:44818",
    deviceTypes: ["plc", "hmi", "gateway"],
    sectors: ["manufacturing", "oil_gas", "food_agriculture"],
    riskLevel: "critical",
    authRequired: false,
  },
  mqtt: {
    name: "MQTT",
    port: 1883,
    altPorts: [8883],
    description: "Lightweight IoT messaging protocol. Often exposed without authentication.",
    shodanQuery: "port:1883",
    deviceTypes: ["iot_device", "gateway", "sensor"],
    sectors: ["building_automation", "manufacturing", "healthcare"],
    riskLevel: "high",
    authRequired: false,
  },
  coap: {
    name: "CoAP",
    port: 5683,
    description: "Constrained Application Protocol for resource-constrained IoT devices.",
    shodanQuery: "port:5683",
    deviceTypes: ["iot_device", "sensor", "actuator"],
    sectors: ["building_automation", "manufacturing"],
    riskLevel: "medium",
    authRequired: false,
  },
  opcua: {
    name: "OPC-UA",
    port: 4840,
    description: "Open Platform Communications Unified Architecture for industrial interoperability.",
    shodanQuery: "port:4840",
    deviceTypes: ["scada_server", "hmi", "historian", "gateway"],
    sectors: ["manufacturing", "energy", "oil_gas"],
    riskLevel: "high",
    authRequired: true,
  },
  niagara_fox: {
    name: "Tridium Niagara Fox",
    port: 1911,
    altPorts: [4911],
    description: "Tridium Niagara building automation framework protocol.",
    shodanQuery: "port:1911,4911 product:Niagara",
    deviceTypes: ["building_automation", "gateway"],
    sectors: ["building_automation"],
    riskLevel: "high",
    authRequired: false,
  },
  ge_srtp: {
    name: "GE-SRTP",
    port: 18245,
    altPorts: [18246],
    description: "GE Service Request Transport Protocol for GE Fanuc PLCs.",
    shodanQuery: 'port:18245,18246 product:"general electric"',
    deviceTypes: ["plc", "rtu"],
    sectors: ["energy", "manufacturing"],
    riskLevel: "critical",
    authRequired: false,
  },
  hart_ip: {
    name: "HART-IP",
    port: 5094,
    description: "Highway Addressable Remote Transducer protocol for field instrumentation.",
    shodanQuery: "port:5094 hart-ip",
    deviceTypes: ["sensor", "actuator", "gateway"],
    sectors: ["oil_gas", "chemical", "manufacturing"],
    riskLevel: "medium",
    authRequired: false,
  },
  iec104: {
    name: "IEC 60870-5-104",
    port: 2404,
    description: "Telecontrol protocol for power system SCADA, widely used in European grids.",
    shodanQuery: "port:2404 asdu address",
    deviceTypes: ["rtu", "scada_server", "gateway"],
    sectors: ["energy"],
    riskLevel: "critical",
    authRequired: false,
  },
  mitsubishi_melsec: {
    name: "Mitsubishi MELSEC-Q",
    port: 5006,
    altPorts: [5007],
    description: "Mitsubishi Electric proprietary protocol for MELSEC-Q series PLCs.",
    shodanQuery: "port:5006,5007 product:mitsubishi",
    deviceTypes: ["plc"],
    sectors: ["manufacturing"],
    riskLevel: "critical",
    authRequired: false,
  },
  omron_fins: {
    name: "Omron FINS",
    port: 9600,
    description: "Factory Interface Network Service for Omron PLCs.",
    shodanQuery: "port:9600 response code",
    deviceTypes: ["plc"],
    sectors: ["manufacturing"],
    riskLevel: "critical",
    authRequired: false,
  },
  codesys: {
    name: "CODESYS",
    port: 2455,
    description: "CODESYS runtime used by 250+ device manufacturers.",
    shodanQuery: "port:2455 operating system",
    deviceTypes: ["plc", "gateway"],
    sectors: ["manufacturing", "building_automation"],
    riskLevel: "critical",
    authRequired: false,
  },
  pcworx: {
    name: "PCWorx",
    port: 1962,
    description: "Phoenix Contact PCWorx protocol for ILC PLCs.",
    shodanQuery: "port:1962 PLC",
    deviceTypes: ["plc"],
    sectors: ["manufacturing"],
    riskLevel: "high",
    authRequired: false,
  },
  proconos: {
    name: "ProConOS",
    port: 20547,
    description: "ProConOS PLC runtime engine for embedded and PC-based control.",
    shodanQuery: "port:20547 PLC",
    deviceTypes: ["plc"],
    sectors: ["manufacturing"],
    riskLevel: "high",
    authRequired: false,
  },
  redlion: {
    name: "Red Lion Controls",
    port: 789,
    description: "Red Lion Crimson HMI protocol.",
    shodanQuery: 'port:789 product:"Red Lion Controls"',
    deviceTypes: ["hmi"],
    sectors: ["manufacturing"],
    riskLevel: "high",
    authRequired: false,
  },
};

// ─── Vendor Fingerprinting Database ───────────────────────────────────────────

export interface VendorFingerprint {
  vendor: string;
  patterns: RegExp[];
  deviceType: string;
  products: string[];
}

export const VENDOR_FINGERPRINTS: VendorFingerprint[] = [
  {
    vendor: "Siemens",
    patterns: [/siemens/i, /simatic/i, /s7-\d+/i, /wincc/i, /scalance/i, /sinema/i, /logo!/i],
    deviceType: "plc",
    products: ["S7-300", "S7-400", "S7-1200", "S7-1500", "WinCC", "SCALANCE", "LOGO!"],
  },
  {
    vendor: "Rockwell Automation",
    patterns: [/rockwell/i, /allen-bradley/i, /controllogix/i, /compactlogix/i, /micrologix/i, /factorytalk/i],
    deviceType: "plc",
    products: ["ControlLogix", "CompactLogix", "MicroLogix", "FactoryTalk", "PanelView"],
  },
  {
    vendor: "Schneider Electric",
    patterns: [/schneider/i, /modicon/i, /triconex/i, /quantum/i, /m340/i, /m580/i, /unity/i, /ecostruxure/i],
    deviceType: "plc",
    products: ["Modicon M340", "Modicon M580", "Quantum", "Triconex", "EcoStruxure"],
  },
  {
    vendor: "ABB",
    patterns: [/\babb\b/i, /ac500/i, /ac800m/i, /800xa/i, /freelance/i],
    deviceType: "plc",
    products: ["AC500", "AC800M", "800xA", "Freelance"],
  },
  {
    vendor: "Honeywell",
    patterns: [/honeywell/i, /experion/i, /c300/i, /safety\s*manager/i],
    deviceType: "dcs",
    products: ["Experion PKS", "C300", "Safety Manager"],
  },
  {
    vendor: "Emerson",
    patterns: [/emerson/i, /deltav/i, /ovation/i, /fisher/i, /rosemount/i],
    deviceType: "dcs",
    products: ["DeltaV", "Ovation", "Fisher", "Rosemount"],
  },
  {
    vendor: "GE",
    patterns: [/general electric/i, /\bge\b/i, /fanuc/i, /mark vi/i, /ifix/i, /cimplicity/i],
    deviceType: "plc",
    products: ["PACSystems", "Mark VIe", "iFIX", "CIMPLICITY"],
  },
  {
    vendor: "Mitsubishi Electric",
    patterns: [/mitsubishi/i, /melsec/i, /got\d+/i, /fx\d+/i],
    deviceType: "plc",
    products: ["MELSEC-Q", "MELSEC iQ-R", "GOT2000", "FX5U"],
  },
  {
    vendor: "Omron",
    patterns: [/omron/i, /sysmac/i, /cj\d+/i, /cp\d+/i, /nx\d+/i],
    deviceType: "plc",
    products: ["Sysmac NJ", "CJ2M", "CP1L", "NX1P"],
  },
  {
    vendor: "Yokogawa",
    patterns: [/yokogawa/i, /centum/i, /prosafe/i, /stardom/i],
    deviceType: "dcs",
    products: ["CENTUM VP", "ProSafe-RS", "STARDOM"],
  },
  {
    vendor: "Phoenix Contact",
    patterns: [/phoenix contact/i, /ilc\s*\d+/i, /axc/i, /plcnext/i],
    deviceType: "plc",
    products: ["ILC 2050", "AXC F 2152", "PLCnext"],
  },
  {
    vendor: "Beckhoff",
    patterns: [/beckhoff/i, /twincat/i, /cx\d+/i, /ethercat/i],
    deviceType: "plc",
    products: ["CX2020", "CX5140", "TwinCAT"],
  },
  {
    vendor: "Moxa",
    patterns: [/moxa/i, /nport/i, /eds-/i, /awk-/i],
    deviceType: "gateway",
    products: ["NPort", "EDS", "AWK"],
  },
  {
    vendor: "Tridium",
    patterns: [/tridium/i, /niagara/i, /jace/i],
    deviceType: "building_automation",
    products: ["JACE 8000", "Niagara 4"],
  },
  {
    vendor: "Johnson Controls",
    patterns: [/johnson controls/i, /metasys/i, /facility explorer/i],
    deviceType: "building_automation",
    products: ["Metasys", "Facility Explorer"],
  },
  {
    vendor: "WAGO",
    patterns: [/wago/i, /pfc\d+/i, /750-/i],
    deviceType: "plc",
    products: ["PFC100", "PFC200", "750-8xxx"],
  },
  {
    vendor: "Red Lion Controls",
    patterns: [/red lion/i, /crimson/i, /graphite/i],
    deviceType: "hmi",
    products: ["Graphite", "CR1000", "DA10D"],
  },
  {
    vendor: "Advantech",
    patterns: [/advantech/i, /adam-/i, /webaccess/i, /wise-/i],
    deviceType: "iot_device",
    products: ["ADAM-6000", "WebAccess", "WISE-4000"],
  },
  {
    vendor: "Hikvision",
    patterns: [/hikvision/i, /ds-\d+/i, /hik/i],
    deviceType: "camera",
    products: ["DS-2CD", "DS-7600", "DS-9600"],
  },
  {
    vendor: "Dahua",
    patterns: [/dahua/i, /dh-/i],
    deviceType: "camera",
    products: ["DH-IPC", "DH-NVR"],
  },
];

// ─── Shodan ICS Discovery ─────────────────────────────────────────────────────

export interface ShodanIcsResult {
  ip: string;
  port: number;
  protocol: string;
  hostnames: string[];
  org: string;
  os: string | null;
  product: string | null;
  version: string | null;
  data: string;
  location: {
    country_code: string;
    country_name: string;
    city: string | null;
    latitude: number;
    longitude: number;
  };
  vulns?: string[];
  tags?: string[];
}

export async function discoverViaShodan(
  query: string,
  apiKey: string,
  maxResults: number = 100
): Promise<ShodanIcsResult[]> {
  const results: ShodanIcsResult[] = [];
  const pages = Math.ceil(maxResults / 100);

  for (let page = 1; page <= pages; page++) {
    try {
      const url = `https://api.shodan.io/shodan/host/search?key=${apiKey}&query=${encodeURIComponent(query)}&page=${page}`;
      const res = await fetch(url);
      if (!res.ok) {
        if (res.status === 401) throw new Error("Invalid Shodan API key");
        if (res.status === 429) {
          await new Promise(r => setTimeout(r, 2000));
          continue;
        }
        break;
      }
      const data = await res.json() as any;
      if (!data.matches) break;

      for (const match of data.matches) {
        results.push({
          ip: match.ip_str,
          port: match.port,
          protocol: match.transport || "tcp",
          hostnames: match.hostnames || [],
          org: match.org || "Unknown",
          os: match.os || null,
          product: match.product || null,
          version: match.version || null,
          data: match.data || "",
          location: {
            country_code: match.location?.country_code || "",
            country_name: match.location?.country_name || "",
            city: match.location?.city || null,
            latitude: match.location?.latitude || 0,
            longitude: match.location?.longitude || 0,
          },
          vulns: match.vulns ? Object.keys(match.vulns) : undefined,
          tags: match.tags || undefined,
        });
      }

      if (data.matches.length < 100) break;
    } catch (err: any) {
      if (err.message?.includes("Invalid Shodan API key")) throw err;
      break;
    }
  }

  return results;
}

/**
 * Run ICS-specific Shodan queries for a target (IP, CIDR, or org)
 */
export async function discoverIcsDevices(
  target: string,
  apiKey: string,
  protocols?: string[],
  maxPerProtocol: number = 50
): Promise<ShodanIcsResult[]> {
  const allResults: ShodanIcsResult[] = [];
  const protocolsToScan = protocols || Object.keys(ICS_PROTOCOLS);

  for (const protoKey of protocolsToScan) {
    const proto = ICS_PROTOCOLS[protoKey];
    if (!proto) continue;

    // Build query with target filter
    let query = proto.shodanQuery;
    if (target.includes("/")) {
      query += ` net:${target}`;
    } else if (target.match(/^\d+\.\d+\.\d+\.\d+$/)) {
      query += ` host:${target}`;
    } else {
      query += ` org:"${target}"`;
    }

    try {
      const results = await discoverViaShodan(query, apiKey, maxPerProtocol);
      for (const r of results) {
        (r as any).detectedProtocol = protoKey;
      }
      allResults.push(...results);
    } catch (err: any) {
      if (err.message?.includes("Invalid Shodan API key")) throw err;
      // Continue with other protocols on non-auth errors
    }

    // Rate limit between queries
    await new Promise(r => setTimeout(r, 1500));
  }

  return allResults;
}

// ─── Censys IoT Discovery ─────────────────────────────────────────────────────

export async function discoverViaCensys(
  query: string,
  apiId: string,
  apiSecret: string,
  maxResults: number = 100
): Promise<any[]> {
  const results: any[] = [];
  let cursor: string | null = null;

  while (results.length < maxResults) {
    try {
      const body: any = { q: query, per_page: Math.min(100, maxResults - results.length) };
      if (cursor) body.cursor = cursor;

      const res = await fetch("https://search.censys.io/api/v2/hosts/search", {
        method: "POST",
        headers: {
          "Content-Type": "application/json",
          "Authorization": "Basic " + Buffer.from(`${apiId}:${apiSecret}`).toString("base64"),
        },
        body: JSON.stringify(body),
      });

      if (!res.ok) {
        if (res.status === 401) throw new Error("Invalid Censys API credentials");
        break;
      }

      const data = await res.json() as any;
      if (!data.result?.hits) break;

      results.push(...data.result.hits);
      cursor = data.result.links?.next || null;
      if (!cursor) break;
    } catch (err: any) {
      if (err.message?.includes("Invalid Censys")) throw err;
      break;
    }
  }

  return results;
}

// ─── Device Fingerprinting ────────────────────────────────────────────────────

export interface FingerprintResult {
  vendor: string | null;
  model: string | null;
  firmwareVersion: string | null;
  deviceType: string;
  protocols: string[];
  purdueLevel: string;
  criticality: "critical" | "high" | "medium" | "low";
  riskFactors: string[];
}

export function fingerprintDevice(
  banner: string,
  port: number,
  product?: string | null,
  version?: string | null,
  vulns?: string[]
): FingerprintResult {
  const combinedText = `${banner} ${product || ""} ${version || ""}`.toLowerCase();
  const riskFactors: string[] = [];
  const detectedProtocols: string[] = [];

  // Detect protocols from port
  for (const [key, proto] of Object.entries(ICS_PROTOCOLS)) {
    if (proto.port === port || proto.altPorts?.includes(port)) {
      detectedProtocols.push(key);
      if (!proto.authRequired) {
        riskFactors.push(`${proto.name}: No authentication required`);
      }
    }
  }

  // Vendor fingerprinting
  let matchedVendor: VendorFingerprint | null = null;
  for (const vf of VENDOR_FINGERPRINTS) {
    if (vf.patterns.some(p => p.test(combinedText))) {
      matchedVendor = vf;
      break;
    }
  }

  // Extract firmware version from banner
  let firmwareVersion: string | null = version || null;
  if (!firmwareVersion) {
    const fwMatch = combinedText.match(/(?:firmware|fw|version|v)\s*[:=]?\s*([\d.]+[a-z]?\d*)/i);
    if (fwMatch) firmwareVersion = fwMatch[1];
  }

  // Determine device type
  let deviceType = matchedVendor?.deviceType || "unknown";
  if (combinedText.match(/\b(hmi|human.machine|panel.?view|touch.?screen)\b/i)) deviceType = "hmi";
  else if (combinedText.match(/\b(plc|programmable.logic|controller)\b/i)) deviceType = "plc";
  else if (combinedText.match(/\b(rtu|remote.terminal)\b/i)) deviceType = "rtu";
  else if (combinedText.match(/\b(dcs|distributed.control)\b/i)) deviceType = "dcs";
  else if (combinedText.match(/\b(scada|supervisory)\b/i)) deviceType = "scada_server";
  else if (combinedText.match(/\b(historian|data.?archive|pi.?server)\b/i)) deviceType = "historian";
  else if (combinedText.match(/\b(safety|sis|triconex|prosafe|himax)\b/i)) deviceType = "safety_system";
  else if (combinedText.match(/\b(gateway|router|bridge|converter)\b/i)) deviceType = "gateway";
  else if (combinedText.match(/\b(switch|scalance|stratix)\b/i)) deviceType = "switch";
  else if (combinedText.match(/\b(camera|ipc|nvr|dvr|hikvision|dahua)\b/i)) deviceType = "camera";
  else if (combinedText.match(/\b(mqtt|coap|zigbee|zwave|lora)\b/i)) deviceType = "iot_device";
  else if (combinedText.match(/\b(bacnet|hvac|thermostat|niagara|jace)\b/i)) deviceType = "building_automation";
  else if (combinedText.match(/\b(meter|smart.?meter|ami)\b/i)) deviceType = "smart_meter";

  // Assign Purdue level based on device type
  const purdueMap: Record<string, string> = {
    sensor: "level_0", actuator: "level_0",
    plc: "level_1", rtu: "level_1", safety_system: "level_1",
    hmi: "level_2", engineering_workstation: "level_2",
    scada_server: "level_3", historian: "level_3", dcs: "level_2",
    gateway: "level_3_5", switch: "level_3_5",
    iot_device: "level_1", camera: "level_2",
    building_automation: "level_2", smart_meter: "level_1",
    unknown: "level_2",
  };
  const purdueLevel = purdueMap[deviceType] || "level_2";

  // Risk assessment
  if (vulns && vulns.length > 0) {
    riskFactors.push(`${vulns.length} known CVEs detected`);
  }
  if (combinedText.match(/default|admin|password|1234|root/i)) {
    riskFactors.push("Possible default credentials detected");
  }
  if (detectedProtocols.some(p => ICS_PROTOCOLS[p]?.riskLevel === "critical")) {
    riskFactors.push("Critical ICS protocol exposed");
  }

  // Criticality scoring
  let criticality: "critical" | "high" | "medium" | "low" = "medium";
  if (deviceType === "safety_system" || riskFactors.length >= 3) criticality = "critical";
  else if (deviceType === "plc" || deviceType === "dcs" || riskFactors.length >= 2) criticality = "high";
  else if (deviceType === "hmi" || deviceType === "scada_server") criticality = "high";
  else if (deviceType === "camera" || deviceType === "iot_device") criticality = "low";

  return {
    vendor: matchedVendor?.vendor || null,
    model: product || null,
    firmwareVersion,
    deviceType,
    protocols: detectedProtocols,
    purdueLevel,
    criticality,
    riskFactors,
  };
}

// ─── Risk Scoring ─────────────────────────────────────────────────────────────

export function calculateIcsRiskScore(device: {
  exposedToInternet: boolean;
  hasDefaultCredentials: boolean;
  hasKnownVulns: boolean;
  deviceType: string;
  protocols: string[];
  purdueLevel: string;
  riskFactors: string[];
}): number {
  let score = 0;

  // Base score by device type
  const typeScores: Record<string, number> = {
    safety_system: 40, plc: 35, rtu: 35, dcs: 35,
    scada_server: 30, hmi: 25, historian: 20,
    engineering_workstation: 25, gateway: 20, switch: 15,
    building_automation: 15, smart_meter: 10, camera: 10,
    iot_device: 10, sensor: 10, actuator: 10, unknown: 15,
  };
  score += typeScores[device.deviceType] || 15;

  // Internet exposure
  if (device.exposedToInternet) score += 25;

  // Default credentials
  if (device.hasDefaultCredentials) score += 15;

  // Known vulnerabilities
  if (device.hasKnownVulns) score += 15;

  // Unauthenticated protocols
  const unauthProtos = device.protocols.filter(p => ICS_PROTOCOLS[p] && !ICS_PROTOCOLS[p].authRequired);
  score += Math.min(unauthProtos.length * 5, 15);

  // Purdue level (lower = more critical)
  const levelScores: Record<string, number> = {
    level_0: 10, level_1: 8, level_2: 6, level_3: 4,
    level_3_5: 2, level_4: 0, level_5: 0,
  };
  score += levelScores[device.purdueLevel] || 0;

  return Math.min(Math.round(score), 100);
}

// ─── Store Discovered Devices ─────────────────────────────────────────────────

export async function storeDiscoveredDevice(
  userId: number,
  assessmentId: number | null,
  shodanResult: ShodanIcsResult,
  fingerprint: FingerprintResult
): Promise<number> {
  const db = await getDbRequired();

  const deviceData: InsertIcsDevice = {
    userId,
    assessmentId,
    ipAddress: shodanResult.ip,
    hostname: shodanResult.hostnames?.[0] || null,
    deviceType: fingerprint.deviceType as any,
    vendor: fingerprint.vendor,
    model: fingerprint.model,
    firmwareVersion: fingerprint.firmwareVersion,
    protocols: fingerprint.protocols,
    openPorts: [shodanResult.port],
    purdueLevel: fingerprint.purdueLevel as any,
    sector: null,
    geolocation: shodanResult.location ? {
      lat: shodanResult.location.latitude,
      lon: shodanResult.location.longitude,
      country: shodanResult.location.country_name,
      city: shodanResult.location.city || "",
    } : undefined,
    criticality: fingerprint.criticality,
    exposedToInternet: true,
    hasDefaultCredentials: fingerprint.riskFactors.some(r => r.includes("default credentials")),
    hasKnownVulns: (shodanResult.vulns?.length || 0) > 0,
    riskScore: calculateIcsRiskScore({
      exposedToInternet: true,
      hasDefaultCredentials: fingerprint.riskFactors.some(r => r.includes("default credentials")),
      hasKnownVulns: (shodanResult.vulns?.length || 0) > 0,
      deviceType: fingerprint.deviceType,
      protocols: fingerprint.protocols,
      purdueLevel: fingerprint.purdueLevel,
      riskFactors: fingerprint.riskFactors,
    }),
    discoverySource: "shodan",
    shodanData: shodanResult as any,
    lastSeen: new Date(),
  };

  const result = await db.insert(icsDevices).values(deviceData);
  return (result as any)[0]?.insertId || 0;
}

// ─── Protocol Port Map (for quick lookups) ────────────────────────────────────

export function getProtocolByPort(port: number): IcsProtocol | null {
  for (const proto of Object.values(ICS_PROTOCOLS)) {
    if (proto.port === port || proto.altPorts?.includes(port)) {
      return proto;
    }
  }
  return null;
}

export function getAllProtocolPorts(): number[] {
  const ports: Set<number> = new Set();
  for (const proto of Object.values(ICS_PROTOCOLS)) {
    ports.add(proto.port);
    if (proto.altPorts) proto.altPorts.forEach(p => ports.add(p));
  }
  return Array.from(ports);
}

/**
 * Get a summary of all supported ICS protocols
 */
export function getProtocolSummary(): {
  name: string;
  key: string;
  port: number;
  riskLevel: string;
  authRequired: boolean;
  sectors: string[];
}[] {
  return Object.entries(ICS_PROTOCOLS).map(([key, proto]) => ({
    name: proto.name,
    key,
    port: proto.port,
    riskLevel: proto.riskLevel,
    authRequired: proto.authRequired,
    sectors: proto.sectors,
  }));
}
