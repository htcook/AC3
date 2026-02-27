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
import { enforceTargetScope, enforceMultiTargetScope } from "../lib/scope-enforcement-middleware";

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
});
