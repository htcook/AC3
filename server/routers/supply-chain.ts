/**
 * Supply Chain Threat Intelligence Router
 * 
 * Endpoints for managing defense suppliers, running threat correlations,
 * and viewing/managing supply chain threat alerts.
 */

import { z } from "zod";
import { router, protectedProcedure } from "../_core/trpc";
import { getDbRequired } from "../db";
import { eq, and, or, like, desc, asc, sql, inArray, isNull, isNotNull } from "drizzle-orm";
import {
  defenseSuppliers,
  supplierTechStacks,
  supplyChainRelationships,
  supplierThreatAlerts,
  supplierAssessmentHistory,
} from "../../drizzle/schema";
import {
  correlateThreats,
  correlateRecentAdvisories,
  recalculateSupplierRisk,
  getSupplyChainImpact,
  extractAffectedProducts,
  type ThreatIndicator,
} from "../lib/supply-chain-correlation";
import crypto from "crypto";

export const supplyChainRouter = router({
  // ═══════════════════════════════════════════════════════════════════════════
  // SUPPLIER MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════════════

  /** List all defense suppliers with filtering */
  listSuppliers: protectedProcedure
    .input(z.object({
      search: z.string().optional(),
      tier: z.enum(['prime', 'tier1', 'tier2', 'tier3', 'unknown']).optional(),
      sector: z.string().optional(),
      riskBand: z.enum(['critical', 'high', 'medium', 'low']).optional(),
      status: z.enum(['active', 'inactive', 'under_review']).optional(),
      limit: z.number().min(1).max(200).default(50),
      offset: z.number().min(0).default(0),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbRequired();
      const params = input || {};
      const conditions = [];

      if (params.search) {
        conditions.push(or(
          like(defenseSuppliers.name, `%${params.search}%`),
          like(defenseSuppliers.cageCode, `%${params.search}%`),
          like(defenseSuppliers.primaryDomain, `%${params.search}%`)
        ));
      }
      if (params.tier) conditions.push(eq(defenseSuppliers.tier, params.tier));
      if (params.sector) conditions.push(like(defenseSuppliers.sector, `%${params.sector}%`));
      if (params.riskBand) conditions.push(eq(defenseSuppliers.riskBand, params.riskBand));
      if (params.status) conditions.push(eq(defenseSuppliers.status, params.status));

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const [suppliers, countResult] = await Promise.all([
        db.select().from(defenseSuppliers)
          .where(where)
          .orderBy(desc(defenseSuppliers.riskScore))
          .limit(params.limit)
          .offset(params.offset),
        db.select({ count: sql<number>`count(*)` }).from(defenseSuppliers).where(where),
      ]);

      return {
        suppliers,
        total: countResult[0]?.count || 0,
      };
    }),

  /** Get a single supplier with full details */
  getSupplier: protectedProcedure
    .input(z.object({ supplierId: z.string() }))
    .query(async ({ input }) => {
      const db = await getDbRequired();
      const [supplier] = await db.select().from(defenseSuppliers)
        .where(eq(defenseSuppliers.supplierId, input.supplierId))
        .limit(1);

      if (!supplier) return null;

      const [techStack, relationships, alerts, assessments] = await Promise.all([
        db.select().from(supplierTechStacks)
          .where(eq(supplierTechStacks.supplierId, input.supplierId)),
        db.select().from(supplyChainRelationships)
          .where(or(
            eq(supplyChainRelationships.primeContractorId, input.supplierId),
            eq(supplyChainRelationships.subcontractorId, input.supplierId)
          )),
        db.select().from(supplierThreatAlerts)
          .where(eq(supplierThreatAlerts.supplierId, input.supplierId))
          .orderBy(desc(supplierThreatAlerts.detectedAt))
          .limit(20),
        db.select().from(supplierAssessmentHistory)
          .where(eq(supplierAssessmentHistory.supplierId, input.supplierId))
          .orderBy(desc(supplierAssessmentHistory.createdAt))
          .limit(10),
      ]);

      return { ...supplier, techStack, relationships, alerts, assessments };
    }),

  /** Create a new defense supplier */
  createSupplier: protectedProcedure
    .input(z.object({
      name: z.string().min(1),
      cageCode: z.string().optional(),
      dunsNumber: z.string().optional(),
      naicsCode: z.string().optional(),
      sector: z.string().optional(),
      tier: z.enum(['prime', 'tier1', 'tier2', 'tier3', 'unknown']).default('unknown'),
      headquarters: z.string().optional(),
      country: z.string().max(3).optional(),
      employeeCount: z.number().optional(),
      annualRevenue: z.string().optional(),
      primaryDomain: z.string().optional(),
      additionalDomains: z.array(z.string()).optional(),
      ipRanges: z.array(z.string()).optional(),
      contractVehicles: z.array(z.string()).optional(),
      criticalProducts: z.array(z.string()).optional(),
      complianceCerts: z.array(z.string()).optional(),
      notes: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbRequired();
      const supplierId = `sup-${crypto.randomBytes(8).toString('hex')}`;

      await db.insert(defenseSuppliers).values({
        supplierId,
        name: input.name,
        cageCode: input.cageCode || null,
        dunsNumber: input.dunsNumber || null,
        naicsCode: input.naicsCode || null,
        sector: input.sector || null,
        tier: input.tier,
        headquarters: input.headquarters || null,
        country: input.country || null,
        employeeCount: input.employeeCount || null,
        annualRevenue: input.annualRevenue || null,
        primaryDomain: input.primaryDomain || null,
        additionalDomains: input.additionalDomains ? JSON.stringify(input.additionalDomains) : null,
        ipRanges: input.ipRanges ? JSON.stringify(input.ipRanges) : null,
        contractVehicles: input.contractVehicles ? JSON.stringify(input.contractVehicles) : null,
        criticalProducts: input.criticalProducts ? JSON.stringify(input.criticalProducts) : null,
        complianceCerts: input.complianceCerts ? JSON.stringify(input.complianceCerts) : null,
        notes: input.notes || null,
        status: 'active',
        createdBy: ctx.user?.openId || null,
      });

      return { supplierId };
    }),

  /** Update an existing supplier */
  updateSupplier: protectedProcedure
    .input(z.object({
      supplierId: z.string(),
      name: z.string().optional(),
      tier: z.enum(['prime', 'tier1', 'tier2', 'tier3', 'unknown']).optional(),
      sector: z.string().optional(),
      primaryDomain: z.string().optional(),
      status: z.enum(['active', 'inactive', 'under_review']).optional(),
      notes: z.string().optional(),
      cageCode: z.string().optional(),
      headquarters: z.string().optional(),
      country: z.string().max(3).optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      const { supplierId, ...updates } = input;
      const cleanUpdates = Object.fromEntries(
        Object.entries(updates).filter(([_, v]) => v !== undefined)
      );

      if (Object.keys(cleanUpdates).length > 0) {
        await db.update(defenseSuppliers)
          .set({ ...cleanUpdates, updatedAt: new Date().toISOString() })
          .where(eq(defenseSuppliers.supplierId, supplierId));
      }

      return { success: true };
    }),

  // ═══════════════════════════════════════════════════════════════════════════
  // TECH STACK MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════════════

  /** Add a technology to a supplier's tech stack */
  addTechStack: protectedProcedure
    .input(z.object({
      supplierId: z.string(),
      product: z.string(),
      vendor: z.string(),
      version: z.string().optional(),
      category: z.enum(['email', 'vpn', 'firewall', 'web_server', 'database', 'erp', 'cloud', 'os', 'endpoint', 'identity', 'collaboration', 'scada', 'other']),
      deploymentType: z.enum(['on_premise', 'cloud', 'hybrid', 'saas']).optional(),
      criticality: z.enum(['critical', 'high', 'medium', 'low']).default('medium'),
      confidence: z.number().min(0).max(1).default(0.7),
      source: z.enum(['manual', 'osint', 'di_scan', 'vendor_disclosure', 'contract_review']),
      evidenceUrl: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      await db.insert(supplierTechStacks).values({
        supplierId: input.supplierId,
        product: input.product,
        vendor: input.vendor,
        version: input.version || null,
        category: input.category,
        deploymentType: input.deploymentType || null,
        criticality: input.criticality,
        confidence: input.confidence,
        source: input.source,
        evidenceUrl: input.evidenceUrl || null,
        lastVerifiedAt: new Date().toISOString(),
      });

      return { success: true };
    }),

  /** Bulk add tech stack entries (e.g., from DI scan results) */
  bulkAddTechStack: protectedProcedure
    .input(z.object({
      supplierId: z.string(),
      entries: z.array(z.object({
        product: z.string(),
        vendor: z.string(),
        version: z.string().optional(),
        category: z.string(),
        criticality: z.enum(['critical', 'high', 'medium', 'low']).default('medium'),
        confidence: z.number().min(0).max(1).default(0.5),
        source: z.string(),
      })),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      let added = 0;
      for (const entry of input.entries) {
        try {
          await db.insert(supplierTechStacks).values({
            supplierId: input.supplierId,
            product: entry.product,
            vendor: entry.vendor,
            version: entry.version || null,
            category: entry.category,
            criticality: entry.criticality,
            confidence: entry.confidence,
            source: entry.source,
            lastVerifiedAt: new Date().toISOString(),
          });
          added++;
        } catch (err) {
          // Skip duplicates
        }
      }
      return { added, total: input.entries.length };
    }),

  /** Remove a tech stack entry */
  removeTechStack: protectedProcedure
    .input(z.object({ id: z.number() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      await db.delete(supplierTechStacks).where(eq(supplierTechStacks.id, input.id));
      return { success: true };
    }),

  // ═══════════════════════════════════════════════════════════════════════════
  // SUPPLY CHAIN RELATIONSHIPS
  // ═══════════════════════════════════════════════════════════════════════════

  /** Add a supply chain relationship between two suppliers */
  addRelationship: protectedProcedure
    .input(z.object({
      primeContractorId: z.string(),
      subcontractorId: z.string(),
      relationshipType: z.enum(['prime_sub', 'sub_sub', 'material_supplier', 'service_provider', 'technology_partner']),
      programName: z.string().optional(),
      contractNumber: z.string().optional(),
      materialsProvided: z.array(z.string()).optional(),
      criticalityToProgram: z.enum(['critical', 'high', 'medium', 'low']).default('medium'),
      singleSourceRisk: z.boolean().default(false),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      const relationshipId = `scr-${crypto.randomBytes(8).toString('hex')}`;

      await db.insert(supplyChainRelationships).values({
        relationshipId,
        primeContractorId: input.primeContractorId,
        subcontractorId: input.subcontractorId,
        relationshipType: input.relationshipType,
        programName: input.programName || null,
        contractNumber: input.contractNumber || null,
        materialsProvided: input.materialsProvided ? JSON.stringify(input.materialsProvided) : null,
        criticalityToProgram: input.criticalityToProgram,
        singleSourceRisk: input.singleSourceRisk ? 1 : 0,
        status: 'active',
      });

      return { relationshipId };
    }),

  /** Get supply chain graph for a supplier (upstream and downstream) */
  getSupplyChainGraph: protectedProcedure
    .input(z.object({ supplierId: z.string(), depth: z.number().min(1).max(5).default(2) }))
    .query(async ({ input }) => {
      const db = await getDbRequired();
      const nodes: Array<{ id: string; name: string; tier: string; riskBand: string | null }> = [];
      const edges: Array<{ from: string; to: string; type: string; program: string | null; critical: boolean }> = [];
      const visited = new Set<string>();

      async function traverse(supplierId: string, currentDepth: number) {
        if (visited.has(supplierId) || currentDepth > input.depth) return;
        visited.add(supplierId);

        const [supplier] = await db.select().from(defenseSuppliers)
          .where(eq(defenseSuppliers.supplierId, supplierId)).limit(1);
        if (!supplier) return;

        nodes.push({ id: supplier.supplierId, name: supplier.name, tier: supplier.tier, riskBand: supplier.riskBand });

        const rels = await db.select().from(supplyChainRelationships)
          .where(or(
            eq(supplyChainRelationships.primeContractorId, supplierId),
            eq(supplyChainRelationships.subcontractorId, supplierId)
          ));

        for (const rel of rels) {
          edges.push({
            from: rel.primeContractorId,
            to: rel.subcontractorId,
            type: rel.relationshipType,
            program: rel.programName,
            critical: rel.criticalityToProgram === 'critical' || rel.singleSourceRisk === 1,
          });

          const nextId = rel.primeContractorId === supplierId ? rel.subcontractorId : rel.primeContractorId;
          await traverse(nextId, currentDepth + 1);
        }
      }

      await traverse(input.supplierId, 0);
      return { nodes, edges };
    }),

  // ═══════════════════════════════════════════════════════════════════════════
  // THREAT CORRELATION
  // ═══════════════════════════════════════════════════════════════════════════

  /** Run correlation for a specific CVE/advisory against all suppliers */
  runCorrelation: protectedProcedure
    .input(z.object({
      type: z.enum(['cve', 'advisory', 'threat_actor', 'breach']),
      id: z.string(),
      title: z.string(),
      description: z.string().optional(),
      severity: z.enum(['critical', 'high', 'medium', 'low', 'info']).default('medium'),
      affectedProducts: z.array(z.object({
        vendor: z.string(),
        product: z.string(),
        versions: z.array(z.string()).optional(),
      })).optional(),
      threatActorName: z.string().optional(),
      exploitAvailable: z.boolean().optional(),
      activeExploitation: z.boolean().optional(),
      sourceUrl: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      // If no affected products provided, try to extract from title/description
      let affectedProducts = input.affectedProducts || [];
      if (affectedProducts.length === 0 && input.description) {
        affectedProducts = extractAffectedProducts(input.title, input.description);
      }

      const indicator: ThreatIndicator = {
        type: input.type,
        id: input.id,
        title: input.title,
        description: input.description,
        severity: input.severity,
        affectedProducts,
        threatActorName: input.threatActorName,
        exploitAvailable: input.exploitAvailable,
        activeExploitation: input.activeExploitation,
        sourceUrl: input.sourceUrl,
      };

      const result = await correlateThreats(indicator);
      return result;
    }),

  /** Get supply chain impact for a specific CVE/advisory/actor */
  getImpact: protectedProcedure
    .input(z.object({
      cveId: z.string().optional(),
      advisoryId: z.string().optional(),
      threatActorName: z.string().optional(),
    }))
    .query(async ({ input }) => {
      const db = await getDbRequired();
      return getSupplyChainImpact(input);
    }),

  // ═══════════════════════════════════════════════════════════════════════════
  // ALERTS MANAGEMENT
  // ═══════════════════════════════════════════════════════════════════════════

  /** List threat alerts with filtering */
  listAlerts: protectedProcedure
    .input(z.object({
      supplierId: z.string().optional(),
      severity: z.enum(['critical', 'high', 'medium', 'low']).optional(),
      mitigationStatus: z.enum(['unmitigated', 'in_progress', 'mitigated', 'accepted', 'false_positive']).optional(),
      alertType: z.string().optional(),
      limit: z.number().min(1).max(200).default(50),
      offset: z.number().min(0).default(0),
    }).optional())
    .query(async ({ input }) => {
      const db = await getDbRequired();
      const params = input || {};
      const conditions = [];

      if (params.supplierId) conditions.push(eq(supplierThreatAlerts.supplierId, params.supplierId));
      if (params.severity) conditions.push(eq(supplierThreatAlerts.severity, params.severity));
      if (params.mitigationStatus) conditions.push(eq(supplierThreatAlerts.mitigationStatus, params.mitigationStatus));
      if (params.alertType) conditions.push(eq(supplierThreatAlerts.alertType, params.alertType));

      const where = conditions.length > 0 ? and(...conditions) : undefined;

      const [alerts, countResult] = await Promise.all([
        db.select().from(supplierThreatAlerts)
          .where(where)
          .orderBy(desc(supplierThreatAlerts.detectedAt))
          .limit(params.limit)
          .offset(params.offset),
        db.select({ count: sql<number>`count(*)` }).from(supplierThreatAlerts).where(where),
      ]);

      return { alerts, total: countResult[0]?.count || 0 };
    }),

  /** Update alert mitigation status */
  updateAlertStatus: protectedProcedure
    .input(z.object({
      alertId: z.string(),
      mitigationStatus: z.enum(['unmitigated', 'in_progress', 'mitigated', 'accepted', 'false_positive']),
      mitigationNotes: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      const db = await getDbRequired();
      const updates: any = { mitigationStatus: input.mitigationStatus };
      if (input.mitigationNotes) updates.mitigationNotes = input.mitigationNotes;

      if (input.mitigationStatus === 'mitigated' || input.mitigationStatus === 'false_positive') {
        updates.resolvedAt = new Date().toISOString();
        updates.resolvedBy = ctx.user?.openId || null;
      } else if (input.mitigationStatus !== 'unmitigated') {
        updates.acknowledgedAt = new Date().toISOString();
        updates.acknowledgedBy = ctx.user?.openId || null;
      }

      await db.update(supplierThreatAlerts)
        .set(updates)
        .where(eq(supplierThreatAlerts.alertId, input.alertId));

      // Recalculate supplier risk after status change
      const [alert] = await db.select().from(supplierThreatAlerts)
        .where(eq(supplierThreatAlerts.alertId, input.alertId)).limit(1);
      if (alert) {
        await recalculateSupplierRisk(alert.supplierId);
      }

      return { success: true };
    }),

  // ═══════════════════════════════════════════════════════════════════════════
  // DASHBOARD & ANALYTICS
  // ═══════════════════════════════════════════════════════════════════════════

  /** Get supply chain threat dashboard summary */
  getDashboard: protectedProcedure.query(async () => {
      const db = await getDbRequired();
    const [
      totalSuppliers,
      suppliersByTier,
      suppliersByRisk,
      recentAlerts,
      alertsByStatus,
      topRiskSuppliers,
    ] = await Promise.all([
      db.select({ count: sql<number>`count(*)` }).from(defenseSuppliers)
        .where(eq(defenseSuppliers.status, 'active')),
      db.select({ tier: defenseSuppliers.tier, count: sql<number>`count(*)` })
        .from(defenseSuppliers)
        .where(eq(defenseSuppliers.status, 'active'))
        .groupBy(defenseSuppliers.tier),
      db.select({ band: defenseSuppliers.riskBand, count: sql<number>`count(*)` })
        .from(defenseSuppliers)
        .where(and(eq(defenseSuppliers.status, 'active'), isNotNull(defenseSuppliers.riskBand)))
        .groupBy(defenseSuppliers.riskBand),
      db.select().from(supplierThreatAlerts)
        .orderBy(desc(supplierThreatAlerts.detectedAt))
        .limit(10),
      db.select({ status: supplierThreatAlerts.mitigationStatus, count: sql<number>`count(*)` })
        .from(supplierThreatAlerts)
        .groupBy(supplierThreatAlerts.mitigationStatus),
      db.select().from(defenseSuppliers)
        .where(and(eq(defenseSuppliers.status, 'active'), isNotNull(defenseSuppliers.riskScore)))
        .orderBy(desc(defenseSuppliers.riskScore))
        .limit(10),
    ]);

    return {
      totalSuppliers: totalSuppliers[0]?.count || 0,
      suppliersByTier: Object.fromEntries(suppliersByTier.map(r => [r.tier, r.count])),
      suppliersByRisk: Object.fromEntries(suppliersByRisk.map(r => [r.band || 'unassessed', r.count])),
      recentAlerts,
      alertsByStatus: Object.fromEntries(alertsByStatus.map(r => [r.status, r.count])),
      topRiskSuppliers,
    };
  }),

  /** Recalculate risk for a specific supplier */
  recalculateRisk: protectedProcedure
    .input(z.object({ supplierId: z.string() }))
    .mutation(async ({ input }) => {
      const db = await getDbRequired();
      return recalculateSupplierRisk(input.supplierId);
    }),

  /** Import SBOM (CycloneDX/SPDX) to populate supplier tech stack */
  importSBOM: protectedProcedure
    .input(z.object({
      supplierId: z.string(),
      content: z.string().max(10_000_000),
      filename: z.string().optional(),
      overwrite: z.boolean().optional().default(false),
      minCriticality: z.enum(['low', 'medium', 'high', 'critical']).optional(),
      filterTypes: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input }) => {
      const { importSBOMToSupplier } = await import("../lib/sbom-parser");
      return importSBOMToSupplier(input.supplierId, input.content, {
        filename: input.filename,
        overwrite: input.overwrite,
        minCriticality: input.minCriticality,
        filterTypes: input.filterTypes,
      });
    }),

  /** Parse SBOM without importing (preview) */
  parseSBOMPreview: protectedProcedure
    .input(z.object({
      content: z.string().max(10_000_000),
      filename: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const { parseSBOM } = await import("../lib/sbom-parser");
      const result = parseSBOM(input.content, input.filename);
      return {
        format: result.format,
        specVersion: result.specVersion,
        subject: result.subject,
        totalComponents: result.components.length,
        componentsByType: result.components.reduce((acc, c) => {
          acc[c.type] = (acc[c.type] || 0) + 1;
          return acc;
        }, {} as Record<string, number>),
        sampleComponents: result.components.slice(0, 20).map(c => ({
          name: c.name,
          vendor: c.vendor,
          version: c.version,
          type: c.type,
          purl: c.purl,
        })),
        errors: result.errors,
      };
    }),
});
