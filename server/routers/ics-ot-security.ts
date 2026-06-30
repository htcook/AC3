import * as db from "../db";
/**
 * ICS/OT Security Router
 *
 * Exposes all ICS/IoT/OT capabilities:
 * - Device discovery (Shodan ICS, Censys, protocol fingerprinting)
 * - ICS exploit catalog (ICS-CERT, ExploitDB SCADA, Metasploit ICS)
 * - APT threat matching (11 ICS-targeting APT groups)
 * - OT protocol vulnerability analysis (9 protocols)
 * - OT network assessment management
 * - MITRE ATT&CK for ICS technique mapping
 */

import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { getDb, getDbRequired } from "../db";
import {
  icsDevices, otNetworks, icsExploits, aptIcsMappings,
  icsAssessments, protocolFindings, threatActors,
  type InsertIcsDevice, type InsertOtNetwork, type InsertIcsAssessment,
} from "../../drizzle/schema";
import { eq, like, sql, desc, and, or } from "drizzle-orm";

import {
  discoverViaShodan,
  discoverViaCensys,
  fingerprintDevice,
  ICS_PROTOCOLS,
} from "../lib/ics-device-discovery";
import {
  getIcsMalwareFamilies,
  getIcsOpenSourceTools,
  getIcsVendors,
  getIcsKeywords,
  ICS_MALWARE_FAMILIES,
  ICS_OPEN_SOURCE_TOOLS,
} from "../lib/ics-scada-intel";

import {
  matchAptGroups,
  seedAptGroups,
  storeIcsExploit,
  searchIcsExploits,
  getAptGroups,
  fetchIcsCertAdvisories,
  getTechniquesForDeviceType,
  getTechniquesByTactic,
  getIcsTactics,
  ICS_APT_GROUPS,
  MITRE_ICS_TECHNIQUES,
} from "../lib/ics-exploit-catalog";

import {
  analyzeProtocol,
  analyzeAllProtocols,
  getAggregateProtocolRisk,
} from "../lib/ot-protocol-analyzer";

export const icsOtSecurityRouter = router({

  // ─── Device Discovery ─────────────────────────────────────────────────────

  discoverDevicesShodan: protectedProcedure
    .input(z.object({
      query: z.string().min(1),
      protocol: z.string().optional(),
      limit: z.number().min(1).max(100).default(25),
    }))
    .mutation(async ({ input }) => {
      const apiKey = process.env.SHODAN_API_KEY || "";
      const results = await discoverViaShodan(input.query, apiKey, input.limit);
      return { devices: results, count: results.length };
    }),

  discoverDevicesCensys: protectedProcedure
    .input(z.object({
      query: z.string().min(1),
      limit: z.number().min(1).max(100).default(25),
    }))
    .mutation(async ({ input }) => {
      const apiId = process.env.CENSYS_API_ID || "";
      const apiSecret = process.env.CENSYS_API_SECRET || "";
      const results = await discoverViaCensys(input.query, apiId, apiSecret, input.limit);
      return { devices: results, count: results.length };
    }),

  fingerprintDevice: protectedProcedure
    .input(z.object({
      ip: z.string().min(1),
      port: z.number().optional(),
      engagementId: z.number().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      // ── ROE Scope Enforcement: validate target IP ──
      if (input.engagementId && input.ip) {
        const { enforceTargetScope } = await import("../lib/scope-enforcement-middleware");
        await enforceTargetScope(input.engagementId, input.ip, "ICS/OT Device Fingerprint", ctx);
      }
      return fingerprintDevice(input.ip || "", input.port || 502);
    }),

  // ─── Device Inventory CRUD ────────────────────────────────────────────────

  listDevices: protectedProcedure
    .input(z.object({
      networkId: z.number().optional(),
      deviceType: z.string().optional(),
      protocol: z.string().optional(),
      limit: z.number().default(100),
      offset: z.number().default(0),
    }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return { devices: [], total: 0 };

      const conditions: any[] = [];
      if (input.networkId) conditions.push(eq(icsDevices.assessmentId, input.networkId));
      if (input.deviceType) conditions.push(eq(icsDevices.deviceType, input.deviceType as any));

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const [devices, countResult] = await Promise.all([
        where
          ? db.select().from(icsDevices).where(where).limit(input.limit).offset(input.offset).orderBy(desc(icsDevices.createdAt))
          : db.select().from(icsDevices).limit(input.limit).offset(input.offset).orderBy(desc(icsDevices.createdAt)),
        db.select({ count: sql<number>`count(*)` }).from(icsDevices),
      ]);

      return { devices, total: Number(countResult[0]?.count || 0) };
    }),

  addDevice: protectedProcedure
    .input(z.object({
      networkId: z.number().optional(),
      ipAddress: z.string(),
      hostname: z.string().optional(),
      deviceType: z.string(),
      vendor: z.string().optional(),
      model: z.string().optional(),
      firmwareVersion: z.string().optional(),
      protocols: z.array(z.string()).default([]),
      openPorts: z.array(z.number()).default([]),
      location: z.string().optional(),
      zone: z.string().optional(),
      criticality: z.string().default("medium"),
      description: z.string().optional(),
      engagementId: z.number().optional(),
    }))
    .mutation(async ({ ctx, input }) => {
      // ── ROE Scope Enforcement: validate device IP is in scope ──
      if (input.engagementId) {
        const { enforceTargetScope } = await import("../lib/scope-enforcement-middleware");
        await enforceTargetScope(input.engagementId, input.ipAddress, "ICS/OT Device Registration", ctx);
        if (input.hostname) {
          await enforceTargetScope(input.engagementId, input.hostname, "ICS/OT Device Registration", ctx);
        }
      }
      const db = await getDbRequired();
      const result = await db.insert(icsDevices).values({
        userId: ctx.user!.id,
        ipAddress: input.ipAddress,
        hostname: input.hostname,
        deviceType: input.deviceType as any,
        vendor: input.vendor,
        model: input.model,
        firmwareVersion: input.firmwareVersion,
        protocols: input.protocols,
        openPorts: input.openPorts,
        criticality: input.criticality as any,
        networkSegment: input.zone,
        facilityName: input.location,
      } as unknown as InsertIcsDevice);
      return { id: (result as any)[0]?.insertId || 0 };
    }),

  importDiscoveredDevices: protectedProcedure
    .input(z.object({
      networkId: z.number().optional(),
      devices: z.array(z.object({
        ipAddress: z.string(),
        hostname: z.string().optional(),
        deviceType: z.string(),
        vendor: z.string().optional(),
        model: z.string().optional(),
        firmwareVersion: z.string().optional(),
        protocols: z.array(z.string()).default([]),
        openPorts: z.array(z.number()).default([]),
        bannerData: z.string().optional(),
      })),
    }))
    .mutation(async ({ ctx, input }) => {
      const db = await getDbRequired();
      let imported = 0;
      let skipped = 0;

      for (const device of input.devices) {
        // Check if device already exists by IP
        const existing = await db.select().from(icsDevices)
          .where(eq(icsDevices.ipAddress, device.ipAddress))
          .limit(1);

        if (existing.length > 0) {
          // Update existing device
          await db.update(icsDevices)
            .set({
              deviceType: device.deviceType as any,
              vendor: device.vendor,
              model: device.model,
              firmwareVersion: device.firmwareVersion,
              protocols: device.protocols,
              openPorts: device.openPorts,
              lastSeen: new Date(),
            })
            .where(eq(icsDevices.ipAddress, device.ipAddress));
          skipped++;
        } else {
          await db.insert(icsDevices).values({
            userId: ctx.user!.id,
            ipAddress: device.ipAddress,
            hostname: device.hostname,
            deviceType: device.deviceType as any,
            vendor: device.vendor,
            model: device.model,
            firmwareVersion: device.firmwareVersion,
            protocols: device.protocols,
            openPorts: device.openPorts,
            assessmentId: input.networkId,
          } as unknown as InsertIcsDevice);
          imported++;
        }
      }

      return { imported, updated: skipped, total: input.devices.length };
    }),

  deleteDevice: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      await db.delete(icsDevices).where(eq(icsDevices.id, input.id));
      return { success: true };
    }),

  // ─── OT Network Management ───────────────────────────────────────────────

  listNetworks: protectedProcedure
    .query(async () => {
      const db = await getDb();
      if (!db) return [];
      return db.select().from(otNetworks).orderBy(desc(otNetworks.createdAt));
    }),

  createNetwork: protectedProcedure
    .input(z.object({
      name: z.string().min(1),
      description: z.string().optional(),
      networkType: z.string().default("scada"),
      ipRange: z.string().optional(),
      sector: z.string().optional(),
      location: z.string().optional(),
      purdueLevel: z.number().min(0).max(5).optional(),
      securityZone: z.string().optional(),
    }))
    .mutation(async ({ ctx, input }) => {
      const db = await getDbRequired();
      const result = await db.insert(otNetworks).values({
        userId: ctx.user!.id,
        name: input.name,
        description: input.description,
        networkType: input.networkType as any,
        cidr: input.ipRange,
        purdueLevel: input.purdueLevel ? `level_${input.purdueLevel}` as any : undefined,
      } as unknown as InsertOtNetwork);
      return { id: (result as any)[0]?.insertId || 0 };
    }),

  deleteNetwork: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      await db.delete(otNetworks).where(eq(otNetworks.id, input.id));
      return { success: true };
    }),

  getNetworkStats: protectedProcedure
    .input(z.object({ networkId: z.number() }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return { deviceCount: 0, criticalDevices: 0, protocols: [], assessmentCount: 0 };

      const [deviceCount, criticalCount, assessmentCount] = await Promise.all([
        db.select({ count: sql<number>`count(*)` }).from(icsDevices).where(eq(icsDevices.assessmentId, input.networkId)),
        db.select({ count: sql<number>`count(*)` }).from(icsDevices).where(and(eq(icsDevices.assessmentId, input.networkId), eq(icsDevices.criticality, "critical" as any))),
        db.select({ count: sql<number>`count(*)` }).from(icsAssessments).where(eq(icsAssessments.id, input.networkId)),
      ]);

      return {
        deviceCount: Number(deviceCount[0]?.count || 0),
        criticalDevices: Number(criticalCount[0]?.count || 0),
        protocols: [],
        assessmentCount: Number(assessmentCount[0]?.count || 0),
      };
    }),

  // ─── APT Threat Matching ──────────────────────────────────────────────────

  matchAptThreats: protectedProcedure
    .input(z.object({
      vendors: z.array(z.string()).optional(),
      protocols: z.array(z.string()).optional(),
      deviceTypes: z.array(z.string()).optional(),
      sectors: z.array(z.string()).optional(),
      countries: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      const results = matchAptGroups(input);
      return { matches: results, totalGroups: ICS_APT_GROUPS.length };
    }),

  listAptGroups: protectedProcedure
    .query(async () => {
      // Return the built-in APT groups catalog
      return ICS_APT_GROUPS.map(g => ({
        name: g.aptGroupName,
        aliases: g.aliases,
        attribution: g.attribution,
        threatLevel: g.threatLevel,
        activeStatus: g.activeStatus,
        targetedSectors: g.targetedSectors,
        targetedProtocols: g.targetedProtocols,
        targetedVendors: g.targetedVendors,
        targetedCountries: g.targetedCountries,
        malwareCount: (g.malwareTools as any[])?.length || 0,
        campaignCount: (g.knownCampaigns as any[])?.length || 0,
        lastKnownActivity: g.lastKnownActivity,
        description: g.description,
      }));
    }),

  getAptGroupDetail: protectedProcedure
    .input(z.object({ name: z.string() }))
    .query(async ({ input }) => {
      const group = ICS_APT_GROUPS.find(g => g.aptGroupName === input.name);
      if (!group) return null;

      const techniques = MITRE_ICS_TECHNIQUES.filter(t =>
        (group.mitreAttackIcsTechniques as string[])?.includes(t.id)
      );

      return { ...group, resolvedTechniques: techniques };
    }),

  seedAptDatabase: protectedProcedure
    .mutation(async () => {
      const count = await seedAptGroups();
      return { seeded: count, total: ICS_APT_GROUPS.length };
    }),

  matchAptForNetwork: protectedProcedure
    .input(z.object({ networkId: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      const devices = await db.select().from(icsDevices)
        .where(eq(icsDevices.assessmentId, input.networkId));

      if (devices.length === 0) return { matches: [], message: "No devices in network" };

      // Aggregate device attributes for matching
      const vendors = Array.from(new Set(devices.map(d => d.vendor).filter(Boolean) as string[]));
      const protocols = Array.from(new Set(devices.flatMap(d => {
        const p = d.protocols;
        return Array.isArray(p) ? p : [];
      })));
      const deviceTypes = Array.from(new Set(devices.map(d => d.deviceType)));

      const results = matchAptGroups({ vendors, protocols, deviceTypes });
      return { matches: results, deviceCount: devices.length };
    }),

  // ─── OT Protocol Analysis ────────────────────────────────────────────────

  analyzeProtocol: protectedProcedure
    .input(z.object({
      protocol: z.string(),
      bannerData: z.string().default(""),
      port: z.number().optional(),
    }))
    .mutation(async ({ input }) => {
      const result = analyzeProtocol(input.protocol, input.bannerData, input.port);
      if (!result) return { error: `Unknown protocol: ${input.protocol}` };
      return result;
    }),

  analyzeDeviceProtocols: protectedProcedure
    .input(z.object({ deviceId: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      const [device] = await db.select().from(icsDevices).where(eq(icsDevices.id, input.deviceId)).limit(1);
      if (!device) return { error: "Device not found" };

      const protocols = Array.isArray(device.protocols) ? device.protocols as string[] : [];
      const results = analyzeAllProtocols(protocols, (device.shodanData as any)?.banner || "");
      const aggregate = getAggregateProtocolRisk(results);

      // Store findings
      for (const result of results) {
        for (const vuln of result.vulnerabilities) {
          await db.insert(protocolFindings).values({
            assessmentId: 0, // standalone analysis
            deviceId: device.id,
            protocol: result.protocol,
            findingType: vuln.findingType as any,
            severity: vuln.severity as any,
            title: vuln.title,
            description: vuln.description,
            evidence: vuln.evidence,
            safetyImpact: vuln.safetyImpact,
            processImpact: vuln.processImpact,
            remediation: vuln.remediation,
            compensatingControls: vuln.compensatingControls,
            relevantAptGroups: vuln.relevantAptGroups,
            relevantMitreTechniques: vuln.relevantMitreTechniques,
          });
        }
      }

      return { protocolResults: results, aggregate, findingsStored: results.reduce((sum, r) => sum + r.vulnerabilities.length, 0) };
    }),

  getProtocolFindings: protectedProcedure
    .input(z.object({
      deviceId: z.number().optional(),
      protocol: z.string().optional(),
      severity: z.string().optional(),
      limit: z.number().default(100),
    }))
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return [];

      const conditions: any[] = [];
      if (input.deviceId) conditions.push(eq(protocolFindings.deviceId, input.deviceId));
      if (input.protocol) conditions.push(eq(protocolFindings.protocol, input.protocol));
      if (input.severity) conditions.push(eq(protocolFindings.severity, input.severity as any));

      const where = conditions.length > 0 ? and(...conditions) : undefined;
      return where
        ? db.select().from(protocolFindings).where(where).limit(input.limit).orderBy(desc(protocolFindings.createdAt))
        : db.select().from(protocolFindings).limit(input.limit).orderBy(desc(protocolFindings.createdAt));
    }),

  getSupportedProtocols: protectedProcedure
    .query(() => {
      return Object.entries(ICS_PROTOCOLS).map(([name, info]) => ({
        name,
        ...(info as any),
      }));
    }),

  // ─── ICS Exploit Catalog ──────────────────────────────────────────────────

  searchExploits: protectedProcedure
    .input(z.object({
      vendor: z.string().optional(),
      product: z.string().optional(),
      cveId: z.string().optional(),
      protocol: z.string().optional(),
      limit: z.number().default(50),
    }))
    .query(async ({ input }) => {
      return searchIcsExploits(input);
    }),

  fetchAdvisories: protectedProcedure
    .input(z.object({
      vendor: z.string().optional(),
      limit: z.number().default(25),
    }))
    .mutation(async ({ input }) => {
      const advisories = await fetchIcsCertAdvisories(input.vendor, input.limit);
      return { advisories, count: advisories.length };
    }),

  addExploit: protectedProcedure
    .input(z.object({
      title: z.string(),
      cveId: z.string().optional(),
      affectedVendor: z.string(),
      affectedProduct: z.string(),
      affectedVersions: z.string().optional(),
      exploitType: z.string().default("remote"),
      protocol: z.string().optional(),
      severity: z.string().default("high"),
      cvssScore: z.number().optional(),
      description: z.string(),
      sourceUrl: z.string().optional(),
      exploitCode: z.string().optional(),
      mitigations: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const id = await storeIcsExploit(input as any);
      return { id };
    }),

  // ─── ICS Assessments ──────────────────────────────────────────────────────

  listAssessments: protectedProcedure
    .query(async () => {
      const db = await getDb();
      if (!db) return [];
      return db.select().from(icsAssessments).orderBy(desc(icsAssessments.createdAt));
    }),

  createAssessment: protectedProcedure
    .input(z.object({
      name: z.string().min(1),
      networkId: z.number().optional(),
      assessmentType: z.string().default("vulnerability_scan"),
      scope: z.string().optional(),
      methodology: z.string().optional(),
      notes: z.string().optional(),
    }))
    .mutation(async ({ ctx, input }) => {
      const db = await getDbRequired();
      const result = await db.insert(icsAssessments).values({
        userId: ctx.user!.id,
        name: input.name,
        description: input.notes || null,
        targetNetwork: input.scope || null,
        targetSector: null,
        status: "running",
      } as InsertIcsAssessment);
      return { id: (result as any)[0]?.insertId || 0 };
    }),

  completeAssessment: protectedProcedure
    .input(z.object({
      id: z.number(),
      findings: z.any().optional(),
      riskScore: z.number().optional(),
      recommendations: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      await db.update(icsAssessments)
        .set({
          status: "completed" as const,
          overallRiskScore: input.riskScore,
          protocolAnalysis: input.findings,
          completedAt: new Date(),
        })
        .where(eq(icsAssessments.id, input.id));
      return { success: true };
    }),

  // ─── MITRE ATT&CK for ICS ────────────────────────────────────────────────

  getMitreIcsTechniques: protectedProcedure
    .input(z.object({
      tactic: z.string().optional(),
      deviceType: z.string().optional(),
    }))
    .query(({ input }) => {
      if (input.tactic) return getTechniquesByTactic(input.tactic);
      if (input.deviceType) return getTechniquesForDeviceType(input.deviceType);
      return MITRE_ICS_TECHNIQUES;
    }),

  getMitreIcsTactics: protectedProcedure
    .query(() => {
      return getIcsTactics();
    }),

  // ─── Dashboard Stats ──────────────────────────────────────────────────────

  getDashboardStats: protectedProcedure
    .query(async () => {
      const db = await getDb();
      if (!db) return {
        totalDevices: 0, totalNetworks: 0, totalExploits: 0,
        totalAssessments: 0, totalFindings: 0, criticalFindings: 0,
        aptGroupsTracked: ICS_APT_GROUPS.length,
        protocolsCovered: 9,
        mitreTechniques: MITRE_ICS_TECHNIQUES.length,
      };

      const [devices, networks, exploits, assessments, findings, criticalFindings] = await Promise.all([
        db.select({ count: sql<number>`count(*)` }).from(icsDevices),
        db.select({ count: sql<number>`count(*)` }).from(otNetworks),
        db.select({ count: sql<number>`count(*)` }).from(icsExploits),
        db.select({ count: sql<number>`count(*)` }).from(icsAssessments),
        db.select({ count: sql<number>`count(*)` }).from(protocolFindings),
        db.select({ count: sql<number>`count(*)` }).from(protocolFindings).where(eq(protocolFindings.severity, "critical")),
      ]);

      return {
        totalDevices: Number(devices[0]?.count || 0),
        totalNetworks: Number(networks[0]?.count || 0),
        totalExploits: Number(exploits[0]?.count || 0),
        totalAssessments: Number(assessments[0]?.count || 0),
        totalFindings: Number(findings[0]?.count || 0),
        criticalFindings: Number(criticalFindings[0]?.count || 0),
        aptGroupsTracked: ICS_APT_GROUPS.length,
        protocolsCovered: 9,
        mitreTechniques: MITRE_ICS_TECHNIQUES.length,
      };
    }),

  // ─── ICS Threat Intelligence Procedures ──────────────────────────────────────

  /** Get ICS malware families knowledge base */
  getIcsMalwareFamilies: protectedProcedure.query(() => {
    return ICS_MALWARE_FAMILIES;
  }),

  /** Get ICS open-source tool catalog */
  getIcsTools: protectedProcedure
    .input(z.object({
      category: z.string().optional(),
      protocol: z.string().optional(),
    }).optional())
    .query(({ input }) => {
      let tools = [...ICS_OPEN_SOURCE_TOOLS];
      if (input?.category) {
        tools = tools.filter(t => t.category === input.category);
      }
      if (input?.protocol) {
        tools = tools.filter(t => t.protocols.includes(input.protocol!));
      }
      return tools;
    }),

  /** Get ICS-capable threat actors (tagged with [ICS/SCADA-CAPABLE]) */
  getIcsCapableActors: protectedProcedure.query(async () => {
    const db = await getDb();
    if (!db) return [];
    const actors = await db.select({
      id: threatActors.id,
      actorId: threatActors.actorId,
      name: threatActors.name,
      aliases: threatActors.aliases,
      actorType: threatActors.actorType,
      origin: threatActors.origin,
      description: threatActors.description,
      threatLevel: threatActors.threatLevel,
      sophistication: threatActors.sophistication,
      targetSectors: threatActors.targetSectors,
      lastActive: threatActors.lastActive,
      malware: threatActors.malware,
      tools: threatActors.tools,
    }).from(threatActors)
      .where(like(threatActors.description, '%[ICS/SCADA-CAPABLE]%'))
      .orderBy(desc(threatActors.updatedAt))
      .limit(100);
    return actors;
  }),

  /** Get recent ICS advisories from the icsExploits table */
  getRecentIcsAdvisories: protectedProcedure
    .input(z.object({
      limit: z.number().min(1).max(200).default(50),
      vendor: z.string().optional(),
      minCvss: z.number().optional(),
      safetyImpact: z.string().optional(),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDb();
      if (!db) return [];
      const conditions = [];
      if (input?.vendor) {
        conditions.push(like(icsExploits.iceAffectedVendor, `%${input.vendor}%`));
      }
      if (input?.safetyImpact) {
        conditions.push(eq(icsExploits.iceSafetyImpact, input.safetyImpact as any));
      }
      const query = db.select().from(icsExploits)
        .orderBy(desc(icsExploits.iceCreatedAt))
        .limit(input?.limit || 50);
      if (conditions.length > 0) {
        return query.where(and(...conditions));
      }
      return query;
    }),

  /** Get ICS vendors list */
  getIcsVendors: protectedProcedure.query(() => {
    return getIcsVendors();
  }),

  /** Get ICS keywords used for detection */
  getIcsKeywords: protectedProcedure.query(() => {
    return getIcsKeywords();
  }),

  /** Get ICS tool categories for filtering */
  getIcsToolCategories: protectedProcedure.query(() => {
    const categories = [...new Set(ICS_OPEN_SOURCE_TOOLS.map(t => t.category))];
    return categories.map(c => ({
      value: c,
      label: c.replace(/_/g, ' ').replace(/\b\w/g, l => l.toUpperCase()),
      count: ICS_OPEN_SOURCE_TOOLS.filter(t => t.category === c).length,
    }));
  }),

  /** Get ICS protocols covered by tools */
  getIcsToolProtocols: protectedProcedure.query(() => {
    const protocols = [...new Set(ICS_OPEN_SOURCE_TOOLS.flatMap(t => t.protocols))];
    return protocols.sort();
  }),
});
