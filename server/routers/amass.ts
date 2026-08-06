/**
 * Amass Router
 * 
 * tRPC endpoints for OWASP Amass subdomain enumeration:
 * - Passive enumeration (OSINT sources only, no target contact)
 * - Active enumeration (DNS resolution, cert grabbing, zone transfers)
 * - Brute-force enumeration (DNS brute-force with wordlists)
 * - Full enumeration (active + brute-force combined)
 * - Intel mode (org/ASN/CIDR/WHOIS discovery)
 * - Scan diffing for attack surface change tracking
 * - Preflight checks for scan server availability
 * 
 * Amass runs on operator scan servers via SSH (same pattern as Nmap orchestrator).
 * All active operations enforce ROE scope boundaries.
 */
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";
import {
  executeAmassEnum,
  executeAmassIntel,
  preflightCheck,
  diffAmassResults,
  toUnifiedDiscoveryFormat,
  deployBuiltInWordlist,
  BUILT_IN_WORDLIST,
  type AmassResult,
  type AmassMode,
} from "../lib/amass-engine";
import { enforceMultiTargetScope } from "../lib/scope-enforcement-middleware";

// In-memory store for scan results
const scanResults: Map<string, AmassResult> = new Map();
const scanQueue: Array<{
  id: string;
  engagementId: number;
  domains: string[];
  mode: AmassMode;
  status: "queued" | "running" | "completed" | "failed";
  startedAt: number;
  completedAt?: number;
}> = [];

const serverSchema = z.object({
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535).optional(),
  username: z.string().min(1),
  privateKey: z.string().optional(),
  privateKeyPath: z.string().optional(),
});

export const amassRouter = router({
  /**
   * Execute an Amass enumeration scan.
   * Supports passive, active, brute, and full modes.
   * Active/brute/full modes enforce ROE scope.
   */
  enumerate: protectedProcedure
    .input(z.object({
      engagementId: z.number(),
      domains: z.array(z.string().min(1)).min(1).max(50),
      mode: z.enum(["passive", "active", "brute", "full"]),
      server: serverSchema,
      wordlistPath: z.string().optional(),
      useBuiltInWordlist: z.boolean().optional(),
      ports: z.array(z.number().int().min(1).max(65535)).optional(),
      resolvers: z.array(z.string()).optional(),
      resolverFilePath: z.string().optional(),
      blacklist: z.array(z.string()).optional(),
      noAlts: z.boolean().optional(),
      noRecursive: z.boolean().optional(),
      minForRecursive: z.number().int().optional(),
      includeUnresolvable: z.boolean().optional(),
      showSources: z.boolean().optional(),
      timeoutMinutes: z.number().int().min(1).max(120).optional(),
      configPath: z.string().optional(),
      amassPath: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      // Scope enforcement for active modes
      if (input.mode !== "passive") {
        await enforceMultiTargetScope(
          input.engagementId,
          input.domains,
          `amass_${input.mode}`,
          ctx,
        );
      }

      // Deploy built-in wordlist if requested
      let wordlistPath = input.wordlistPath;
      if (input.useBuiltInWordlist && (input.mode === "brute" || input.mode === "full")) {
        wordlistPath = await deployBuiltInWordlist(input.server);
      }

      // Queue the scan
      const queueEntry = {
        id: `amass-${Date.now()}`,
        engagementId: input.engagementId,
        domains: input.domains,
        mode: input.mode,
        status: "running" as const,
        startedAt: Date.now(),
      };
      scanQueue.push(queueEntry);

      try {
        const result = await executeAmassEnum({
          domains: input.domains,
          mode: input.mode,
          server: input.server,
          engagementId: String(input.engagementId),
          wordlistPath,
          ports: input.ports,
          resolvers: input.resolvers,
          resolverFilePath: input.resolverFilePath,
          blacklist: input.blacklist,
          noAlts: input.noAlts,
          noRecursive: input.noRecursive,
          minForRecursive: input.minForRecursive,
          includeUnresolvable: input.includeUnresolvable,
          showSources: input.showSources,
          timeoutMinutes: input.timeoutMinutes,
          configPath: input.configPath,
          amassPath: input.amassPath,
        });

        // Store result
        scanResults.set(result.scanId, result);
        queueEntry.status = result.status === "completed" ? "completed" : "failed";
        queueEntry.completedAt = Date.now();
        (queueEntry as any).scanId = result.scanId;

        return {
          scanId: result.scanId,
          status: result.status,
          totalSubdomains: result.summary.totalSubdomains,
          totalUniqueIps: result.summary.totalUniqueIps,
          totalAsns: result.summary.totalAsns,
          totalSources: result.summary.totalSources,
          durationMs: result.durationMs,
          command: result.command,
          error: result.error,
        };
      } catch (err: any) {
        queueEntry.status = "failed";
        queueEntry.completedAt = Date.now();
        throw err;
      }
    }),

  /**
   * Execute Amass intel subcommand for organization discovery.
   * Discovers domains by org name, ASN, CIDR, or reverse WHOIS.
   */
  intel: protectedProcedure
    .input(z.object({
      intelMode: z.enum(["org", "asn", "cidr", "whois"]),
      query: z.string().min(1),
      server: serverSchema,
      amassPath: z.string().optional(),
    }))
    .mutation(async ({ input }) => {
      const result = await executeAmassIntel({
        intelMode: input.intelMode,
        query: input.query,
        server: input.server,
        amassPath: input.amassPath,
      });

      return result;
    }),

  /**
   * Get full scan results by scan ID.
   */
  getResult: protectedProcedure
    .input(z.object({ scanId: z.string() }))
    .query(({ input }) => {
      const result = scanResults.get(input.scanId);
      if (!result) return null;
      return result;
    }),

  /**
   * Get scan results in unified discovery format for SSIL pipeline ingestion.
   */
  getUnifiedResults: protectedProcedure
    .input(z.object({ scanId: z.string() }))
    .query(({ input }) => {
      const result = scanResults.get(input.scanId);
      if (!result) return [];
      return toUnifiedDiscoveryFormat(result);
    }),

  /**
   * Compare two scan results to identify attack surface changes.
   */
  diff: protectedProcedure
    .input(z.object({
      previousScanId: z.string(),
      currentScanId: z.string(),
    }))
    .query(({ input }) => {
      const previous = scanResults.get(input.previousScanId);
      const current = scanResults.get(input.currentScanId);
      if (!previous || !current) return null;
      return diffAmassResults(previous, current);
    }),

  /**
   * Preflight check — verify Amass is installed on the scan server.
   */
  preflight: protectedProcedure
    .input(z.object({ server: serverSchema }))
    .mutation(async ({ input }) => {
      return await preflightCheck(input.server);
    }),

  /**
   * Get scan history for an engagement.
   */
  getScanHistory: protectedProcedure
    .input(z.object({ engagementId: z.number() }))
    .query(({ input }) => {
      return scanQueue
        .filter(s => s.engagementId === input.engagementId)
        .map(s => ({
          id: s.id,
          scanId: (s as any).scanId,
          domains: s.domains,
          mode: s.mode,
          status: s.status,
          startedAt: s.startedAt,
          completedAt: s.completedAt,
        }))
        .reverse();
    }),

  /**
   * Get the built-in wordlist for display/customization.
   */
  getBuiltInWordlist: protectedProcedure
    .query(() => {
      return {
        wordCount: BUILT_IN_WORDLIST.length,
        words: BUILT_IN_WORDLIST,
      };
    }),
});
