/**
 * Service Fingerprinter Router
 * 
 * tRPC endpoints for protocol-specific service fingerprinting:
 * - Single service fingerprinting (SSH, SMTP, FTP, SNMP, RDP, SMB, LDAP, etc.)
 * - Batch fingerprinting across multiple targets/ports
 * - Auto-fingerprinting from Nmap/Naabu port scan results
 * - Summary and risk analysis of fingerprinted services
 * 
 * All operations enforce ROE scope boundaries via the scope guard.
 */
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  fingerprintService,
  batchFingerprint,
  autoFingerprint,
  summarizeFingerprints,
  detectProtocol,
  PORT_PROTOCOL_MAP,
  type FingerprintResult,
  type ServiceProtocol,
} from "../lib/service-fingerprinter";
import {
  diffFingerprints,
  buildDiffSummaryText,
  type CachedFingerprint,
} from "../lib/fingerprint-diff";
import { getCpeMatchStats } from "../lib/dynamic-cpe-matcher";
import { enforceTargetScope, enforceMultiTargetScope } from "../lib/scope-enforcement-middleware";
import { getDb } from "../db";
import { fingerprintCache } from "../../drizzle/schema";
import { eq, desc } from "drizzle-orm";

const protocolEnum = z.enum([
  "ssh", "smtp", "ftp", "snmp", "rdp", "smb", "ldap", "telnet",
  "mysql", "mssql", "postgresql", "redis", "mongodb", "vnc",
  "sftp", "pop3", "imap", "dns", "ntp", "sip",
]);

// In-memory store for fingerprint scan history
const scanHistory: Array<{
  id: string;
  engagementId: number;
  host: string;
  results: FingerprintResult[];
  summary: ReturnType<typeof summarizeFingerprints>;
  startedAt: number;
  completedAt: number;
}> = [];
let scanCounter = 0;

export const serviceFingerprintRouter = router({
  /**
   * Fingerprint a single service on a specific host:port.
   * Enforces ROE scope before probing.
   */
  fingerprint: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      host: z.string().min(1),
      port: z.number().int().min(1).max(65535),
      protocol: protocolEnum.optional(),
      timeoutMs: z.number().int().min(1000).max(60000).optional(),
      tryDefaultCreds: z.boolean().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      // Scope enforcement
      await enforceTargetScope(
        input.engagementId,
        input.host,
        "service_fingerprinter",
        ctx,
      );

      const result = await fingerprintService({
        host: input.host,
        port: input.port,
        protocol: input.protocol as ServiceProtocol | undefined,
        timeoutMs: input.timeoutMs,
        engagementId: input.engagementId,
        operatorId: String(ctx.user.id),
        tryDefaultCreds: input.tryDefaultCreds,
      });

      return result;
    }),

  /**
   * Batch fingerprint multiple targets at once.
   * Enforces ROE scope for all targets before probing.
   */
  batchFingerprint: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      targets: z.array(z.object({
        host: z.string().min(1),
        port: z.number().int().min(1).max(65535),
        protocol: protocolEnum.optional(),
      })).min(1).max(500),
      timeoutMs: z.number().int().min(1000).max(60000).optional(),
      concurrency: z.number().int().min(1).max(50).optional(),
      tryDefaultCreds: z.boolean().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      // Scope enforcement — validate all unique hosts
      const uniqueHosts = [...new Set(input.targets.map(t => t.host))];
      await enforceMultiTargetScope(
        input.engagementId,
        uniqueHosts,
        "service_fingerprinter_batch",
        ctx,
      );

      const results = await batchFingerprint({
        targets: input.targets.map(t => ({
          host: t.host,
          port: t.port,
          protocol: t.protocol as ServiceProtocol | undefined,
        })),
        engagementId: input.engagementId,
        operatorId: String(ctx.user.id),
        timeoutMs: input.timeoutMs,
        concurrency: input.concurrency,
        tryDefaultCreds: input.tryDefaultCreds,
      });

      const summary = summarizeFingerprints(results);

      // Store in history
      const scanId = `fp-${++scanCounter}-${Date.now()}`;
      scanHistory.push({
        id: scanId,
        engagementId: input.engagementId,
        host: uniqueHosts.join(", "),
        results,
        summary,
        startedAt: Date.now() - results.reduce((sum, r) => sum + r.durationMs, 0),
        completedAt: Date.now(),
      });

      return { scanId, results, summary };
    }),

  /**
   * Auto-fingerprint all open ports on a host.
   * Takes a host and list of open ports (from Nmap/Naabu scan results),
   * detects the protocol for each port, and fingerprints all services.
   */
  autoFingerprint: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      host: z.string().min(1),
      openPorts: z.array(z.number().int().min(1).max(65535)).min(1).max(1000),
      timeoutMs: z.number().int().min(1000).max(60000).optional(),
      tryDefaultCreds: z.boolean().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      // Scope enforcement
      await enforceTargetScope(
        input.engagementId,
        input.host,
        "service_fingerprinter_auto",
        ctx,
      );

      const results = await autoFingerprint(
        input.host,
        input.openPorts,
        {
          engagementId: input.engagementId,
          operatorId: String(ctx.user.id),
          timeoutMs: input.timeoutMs,
          tryDefaultCreds: input.tryDefaultCreds,
        },
      );

      const summary = summarizeFingerprints(results);

      // Store in history
      const scanId = `fp-auto-${++scanCounter}-${Date.now()}`;
      scanHistory.push({
        id: scanId,
        engagementId: input.engagementId,
        host: input.host,
        results,
        summary,
        startedAt: Date.now() - results.reduce((sum, r) => sum + r.durationMs, 0),
        completedAt: Date.now(),
      });

      return { scanId, results, summary };
    }),

  /**
   * Get the port-to-protocol mapping for UI display.
   */
  getPortProtocolMap: protectedProcedure
    .query(() => {
      return PORT_PROTOCOL_MAP;
    }),

  /**
   * Detect the likely protocol for a given port number.
   */
  detectProtocol: protectedProcedure
    .input(z.object({ port: z.number().int().min(1).max(65535) }))
    .query(({ input }) => {
      return { port: input.port, protocol: detectProtocol(input.port) };
    }),

  /**
   * Get scan history for an engagement.
   */
  getScanHistory: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(({ input }) => {
      return scanHistory
        .filter(s => s.engagementId === input.engagementId)
        .map(s => ({
          id: s.id,
          host: s.host,
          totalServices: s.summary.totalServices,
          criticalRisks: s.summary.criticalRisks,
          highRisks: s.summary.highRisks,
          startedAt: s.startedAt,
          completedAt: s.completedAt,
        }))
        .reverse();
    }),

  /**
   * Get detailed scan result by ID.
   */
  getScanResult: protectedProcedure
    .input(z.object({ scanId: z.string() }))
    .query(({ input }) => {
      const scan = scanHistory.find(s => s.id === input.scanId);
      if (!scan) return null;
      return scan;
    }),

  /**
   * Get fingerprint diff report for an engagement.
   * Compares the latest scan against the previous cached scan.
   */
  getFingerprintDiff: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(async ({ input }) => {
      const db = await getDb();
      const cached = await db
        .select()
        .from(fingerprintCache)
        .where(eq(fingerprintCache.fcEngagementId, String(input.engagementId)))
        .orderBy(desc(fingerprintCache.fcFingerprintedAt));

      if (cached.length === 0) {
        return { hasDiff: false as const, report: null, summary: null, currentScan: null, previousScan: null };
      }

      // Group by scan time (fingerprints within 60s are same scan)
      const scanGroups: Array<{ time: number; entries: typeof cached }> = [];
      let currentGroup: { time: number; entries: typeof cached } | null = null;
      for (const entry of cached) {
        const t = entry.fcFingerprintedAt;
        if (!currentGroup || Math.abs(t - currentGroup.time) > 60000) {
          currentGroup = { time: t, entries: [] };
          scanGroups.push(currentGroup);
        }
        currentGroup.entries.push(entry);
      }

      if (scanGroups.length < 2) {
        const entries = scanGroups[0]?.entries || [];
        return {
          hasDiff: false as const,
          currentScan: {
            time: scanGroups[0]?.time || 0,
            serviceCount: entries.length,
            services: entries.map(e => ({
              host: e.fcHost, port: e.fcPort, protocol: e.fcProtocol,
              product: e.fcProduct, version: e.fcVersion,
              confidence: e.fcConfidence,
              cves: (e.fcPotentialCves as string[] | null) || [],
            })),
          },
          previousScan: null,
          report: null,
          summary: "Only one scan recorded — no previous data to compare against.",
        };
      }

      const latestEntries = scanGroups[0].entries;
      const previousEntries = scanGroups[1].entries;

      const currentResults: FingerprintResult[] = latestEntries.map(e => ({
        host: e.fcHost, port: e.fcPort,
        protocol: (e.fcProtocol || "unknown") as any,
        product: e.fcProduct || null, version: e.fcVersion || null,
        banner: e.fcBanner || null, os: e.fcOs || null,
        securityFlags: (e.fcSecurityFlags as Record<string, boolean>) || {},
        riskIndicators: (e.fcRiskIndicators as any[]) || [],
        potentialCves: (e.fcPotentialCves as string[]) || [],
        confidence: e.fcConfidence || 0, error: false, rawOutput: "",
      }));

      const previousCached: CachedFingerprint[] = previousEntries.map(e => ({
        host: e.fcHost, port: e.fcPort,
        protocol: e.fcProtocol || null, product: e.fcProduct || null,
        version: e.fcVersion || null, banner: e.fcBanner || null,
        os: e.fcOs || null,
        securityFlags: (e.fcSecurityFlags as Record<string, boolean>) || null,
        riskIndicators: (e.fcRiskIndicators as any[]) || [],
        potentialCves: (e.fcPotentialCves as string[]) || [],
        confidence: e.fcConfidence || 0,
        fingerprintedAt: e.fcFingerprintedAt,
        engagementId: e.fcEngagementId || "",
      }));

      const report = diffFingerprints(currentResults, previousCached, input.engagementId);
      const summary = buildDiffSummaryText(report);

      return {
        hasDiff: true as const, report, summary,
        currentScan: { time: scanGroups[0].time, serviceCount: latestEntries.length },
        previousScan: { time: scanGroups[1].time, serviceCount: previousEntries.length },
      };
    }),

  /**
   * Get CPE dictionary stats.
   */
  getCpeStats: protectedProcedure
    .query(() => getCpeMatchStats()),

  /**
   * Get CPE dictionary statistics including update history and unmapped technologies.
   */
  getCpeDictionaryStats: protectedProcedure
    .query(async () => {
      const { getDictionaryStats } = await import("../lib/cpe-dictionary-updater");
      return getDictionaryStats();
    }),

  /**
   * Get all CPE dictionary entries.
   */
  getCpeDictionaryEntries: protectedProcedure
    .query(async () => {
      const { getDictionaryEntries } = await import("../lib/cpe-dictionary-updater");
      return getDictionaryEntries();
    }),

  /**
   * Trigger a manual CPE dictionary update.
   */
  triggerCpeDictionaryUpdate: protectedProcedure
    .mutation(async () => {
      const { runDictionaryUpdate } = await import("../lib/cpe-dictionary-updater");
      return runDictionaryUpdate();
    }),

  /**
   * Manually add a CPE mapping.
   */
  addCpeMapping: protectedProcedure
    .input(z.object({
      technology: z.string().min(1),
      vendor: z.string().min(1),
      product: z.string().min(1),
    }))
    .mutation(async ({ input }) => {
      const { addManualMapping, lookupCpe } = await import("../lib/cpe-dictionary-updater");
      addManualMapping(input.technology, input.vendor, input.product);
      return lookupCpe(input.technology);
    }),
});
