/**
 * ScanForge Discovery Router
 *
 * tRPC endpoints for ScanForge multi-tool network scanning via SSH-based remote execution:
 * - Full scan with configurable profiles (quick/standard/deep/stealth/service/udp/full-pipeline/custom)
 * - Quick scan (top 100 ports, fast turnaround)
 * - Service discovery scan (common admin ports)
 * - Scan history and result retrieval
 * - Predefined scan profiles query
 * - Preflight server checks
 *
 * Tools: Masscan, Naabu, RustScan, ZMap (auto-selected or operator-specified)
 * All operations enforce ROE scope boundaries before execution.
 */
import { z } from "zod";
import { TRPCError } from "@trpc/server";
import { protectedProcedure, router } from "../_core/trpc";
import {
  executeScanforgeScan,
  scanWithScopeEnforcement,
  preflightCheck,
  autoSelectTool,
  toScanforgeRawResults,
  type ScanforgeConfig,
  type ScanforgeResult,
  type ScanforgeProfile,
  type ScanforgeTool,
  type ScanServerConfig,
} from "../lib/scanforge-discovery";
import { enforceMultiTargetScope } from "../lib/scope-enforcement-middleware";

// ─── In-Memory Scan Store ───────────────────────────────────────────────────

interface ScanHistoryEntry {
  id: string;
  engagementId: number;
  targets: string[];
  profile: ScanforgeProfile;
  tool: ScanforgeTool;
  status: "queued" | "running" | "completed" | "failed" | "timeout";
  startedAt: number;
  completedAt?: number;
  durationMs?: number;
  hostsUp?: number;
  openPorts?: number;
  command?: string;
  error?: string;
  operatorId: string;
  operatorName?: string;
}

const scanResults: Map<string, ScanforgeResult> = new Map();
const scanHistory: ScanHistoryEntry[] = [];

// ─── Shared Schemas ─────────────────────────────────────────────────────────

const serverSchema = z.object({
  host: z.string().min(1),
  port: z.number().int().min(1).max(65535).optional(),
  username: z.string().min(1),
  privateKey: z.string().optional(),
  privateKeyPath: z.string().optional(),
});

const profileSchema = z.enum([
  "quick", "standard", "deep", "stealth", "service", "udp", "full-pipeline", "custom",
]);

const toolSchema = z.enum(["masscan", "naabu", "rustscan", "zmap"]).optional();

// ─── Scan Profile Descriptions ──────────────────────────────────────────────

const SCAN_PROFILE_DESCRIPTIONS: Record<ScanforgeProfile, {
  name: string;
  description: string;
  tools: string;
  estimatedDuration: string;
  useCase: string;
  portsScanned: string;
  requiresSudo: boolean;
}> = {
  quick: {
    name: "Quick Scan",
    description: "Fast port scan of top 1000 ports using Naabu or RustScan",
    tools: "Naabu (default), RustScan (single host)",
    estimatedDuration: "10s - 1min per host",
    useCase: "Initial reconnaissance, large target ranges, time-constrained engagements",
    portsScanned: "Top 1000 TCP",
    requiresSudo: false,
  },
  standard: {
    name: "Standard Scan",
    description: "Balanced port scan with auto-selected tool based on target context",
    tools: "Auto-selected: Naabu (versatile), Masscan (ranges), RustScan (single host)",
    estimatedDuration: "30s - 5min per host",
    useCase: "General-purpose scanning, most engagements",
    portsScanned: "Top 1000 TCP + common admin ports",
    requiresSudo: false,
  },
  deep: {
    name: "Deep Scan",
    description: "Full port range scan (0-65535) using Masscan or RustScan",
    tools: "Masscan (ranges), RustScan (single host)",
    estimatedDuration: "2 - 15min per host",
    useCase: "Thorough enumeration, high-value targets, compliance audits",
    portsScanned: "All 65535 TCP",
    requiresSudo: true,
  },
  stealth: {
    name: "Stealth Scan",
    description: "Low-rate SYN scan using Naabu with rate limiting to evade IDS/IPS",
    tools: "Naabu (best rate control)",
    estimatedDuration: "5 - 30min per host",
    useCase: "Evasion testing, IDS/IPS validation, red team operations",
    portsScanned: "Top 1000 TCP",
    requiresSudo: false,
  },
  service: {
    name: "Service Discovery Scan",
    description: "Targeted scan of common admin/service ports",
    tools: "Naabu (default)",
    estimatedDuration: "10s - 2min per host",
    useCase: "Known service enumeration, admin port fingerprinting, post-discovery deep dive",
    portsScanned: "Common admin ports (21,22,23,25,53,80,110,135,139,143,443,445,993,995,1433,1521,3306,3389,5432,5900,6379,8080,8443,27017)",
    requiresSudo: false,
  },
  udp: {
    name: "UDP Scan",
    description: "UDP port scan using Naabu — catches DNS, SNMP, TFTP, NTP, SSDP",
    tools: "Naabu (only tool supporting UDP)",
    estimatedDuration: "2 - 15min per host",
    useCase: "UDP service discovery, SNMP enumeration, DNS/NTP amplification checks",
    portsScanned: "Top 100 UDP",
    requiresSudo: false,
  },
  "full-pipeline": {
    name: "Full Pipeline",
    description: "Discovery → httpx fingerprinting → Nuclei vulnerability detection in one pipeline",
    tools: "Naabu → httpx → Nuclei (chained)",
    estimatedDuration: "5 - 30min per host",
    useCase: "Complete reconnaissance pipeline, automated vulnerability assessment",
    portsScanned: "Top 1000 TCP + web service fingerprinting + vuln detection",
    requiresSudo: false,
  },
  custom: {
    name: "Custom Scan",
    description: "User-defined arguments for specialized scanning needs",
    tools: "User-specified tool",
    estimatedDuration: "Varies",
    useCase: "Specialized scans, custom port ranges, specific tool flags",
    portsScanned: "User-defined",
    requiresSudo: false,
  },
};

// ─── Router ─────────────────────────────────────────────────────────────────

export const scanforgeDiscoveryRouter = router({
  /**
   * Full scan — configurable profile, auto-selected or specified tool.
   */
  scan: protectedProcedure
    .input(z.object({
      targets: z.array(z.string().min(1)).min(1),
      profile: profileSchema.default("standard"),
      tool: toolSchema,
      ports: z.string().optional(),
      customArgs: z.string().optional(),
      engagementId: z.number().int(),
      server: serverSchema,
      timeoutSeconds: z.number().int().min(30).max(3600).optional(),
      rate: z.number().int().min(1).max(100000).optional(),
      stealthLevel: z.enum(["minimal", "low", "medium", "high", "maximum"]).optional(),
      excludeHosts: z.array(z.string()).optional(),
      chainHttpx: z.boolean().optional(),
      chainNuclei: z.boolean().optional(),
      nucleiTags: z.array(z.string()).optional(),
      nucleiSeverity: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      // Enforce scope
      await enforceMultiTargetScope(
        input.engagementId,
        input.targets.map(t => ({ value: t })),
        `scanforge:${input.tool || 'auto'}:${input.profile}`,
        ctx.user.openId,
        ctx.user.name || undefined,
      );

      const tool = input.tool || autoSelectTool({
        targets: input.targets,
        stealthLevel: input.stealthLevel,
        profile: input.profile,
      });

      // Create history entry
      const historyEntry: ScanHistoryEntry = {
        id: `sf-${Date.now()}`,
        engagementId: input.engagementId,
        targets: input.targets,
        profile: input.profile,
        tool,
        status: "running",
        startedAt: Date.now(),
        operatorId: ctx.user.openId,
        operatorName: ctx.user.name || undefined,
      };
      scanHistory.unshift(historyEntry);

      try {
        const result = await executeScanforgeScan({
          targets: input.targets,
          profile: input.profile,
          tool,
          ports: input.ports,
          customArgs: input.customArgs,
          engagementId: input.engagementId,
          operatorId: ctx.user.openId,
          operatorName: ctx.user.name || undefined,
          server: input.server,
          timeoutSeconds: input.timeoutSeconds,
          rate: input.rate,
          stealthLevel: input.stealthLevel,
          excludeHosts: input.excludeHosts,
          chainHttpx: input.chainHttpx,
          chainNuclei: input.chainNuclei,
          nucleiTags: input.nucleiTags,
          nucleiSeverity: input.nucleiSeverity,
        });

        // Store result
        scanResults.set(result.scanId, result);
        historyEntry.id = result.scanId;
        historyEntry.status = result.status;
        historyEntry.completedAt = result.completedAt;
        historyEntry.durationMs = result.durationMs;
        historyEntry.hostsUp = result.summary.hostsUp;
        historyEntry.openPorts = result.summary.openPorts;
        historyEntry.command = result.command;
        historyEntry.error = result.error;

        return result;
      } catch (err: any) {
        historyEntry.status = "failed";
        historyEntry.error = err.message;
        throw new TRPCError({
          code: "INTERNAL_SERVER_ERROR",
          message: `ScanForge scan failed: ${err.message}`,
        });
      }
    }),

  /**
   * Quick scan — top ports, fastest turnaround.
   */
  quickScan: protectedProcedure
    .input(z.object({
      targets: z.array(z.string().min(1)).min(1),
      engagementId: z.number().int(),
      server: serverSchema,
    }))
    .mutation(async ({ input, ctx }) => {
      await enforceMultiTargetScope(
        input.engagementId,
        input.targets.map(t => ({ value: t })),
        "scanforge:auto:quick",
        ctx.user.openId,
        ctx.user.name || undefined,
      );

      const tool = autoSelectTool({ targets: input.targets });

      const result = await executeScanforgeScan({
        targets: input.targets,
        profile: "quick",
        tool,
        engagementId: input.engagementId,
        operatorId: ctx.user.openId,
        operatorName: ctx.user.name || undefined,
        server: input.server,
        timeoutSeconds: 120,
      });

      scanResults.set(result.scanId, result);
      scanHistory.unshift({
        id: result.scanId,
        engagementId: input.engagementId,
        targets: input.targets,
        profile: "quick",
        tool,
        status: result.status,
        startedAt: result.startedAt,
        completedAt: result.completedAt,
        durationMs: result.durationMs,
        hostsUp: result.summary.hostsUp,
        openPorts: result.summary.openPorts,
        command: result.command,
        operatorId: ctx.user.openId,
      });

      return result;
    }),

  /**
   * Service discovery scan — common admin/service ports.
   */
  serviceScan: protectedProcedure
    .input(z.object({
      targets: z.array(z.string().min(1)).min(1),
      engagementId: z.number().int(),
      server: serverSchema,
      ports: z.string().optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      await enforceMultiTargetScope(
        input.engagementId,
        input.targets.map(t => ({ value: t })),
        "scanforge:naabu:service",
        ctx.user.openId,
        ctx.user.name || undefined,
      );

      const result = await executeScanforgeScan({
        targets: input.targets,
        profile: "service",
        tool: "naabu",
        ports: input.ports,
        engagementId: input.engagementId,
        operatorId: ctx.user.openId,
        operatorName: ctx.user.name || undefined,
        server: input.server,
        timeoutSeconds: 300,
      });

      scanResults.set(result.scanId, result);
      scanHistory.unshift({
        id: result.scanId,
        engagementId: input.engagementId,
        targets: input.targets,
        profile: "service",
        tool: "naabu",
        status: result.status,
        startedAt: result.startedAt,
        completedAt: result.completedAt,
        durationMs: result.durationMs,
        hostsUp: result.summary.hostsUp,
        openPorts: result.summary.openPorts,
        command: result.command,
        operatorId: ctx.user.openId,
      });

      return result;
    }),

  /**
   * Full pipeline scan — Discovery → httpx → Nuclei in one call.
   */
  pipelineScan: protectedProcedure
    .input(z.object({
      targets: z.array(z.string().min(1)).min(1),
      engagementId: z.number().int(),
      server: serverSchema,
      nucleiTags: z.array(z.string()).optional(),
      nucleiSeverity: z.array(z.string()).optional(),
    }))
    .mutation(async ({ input, ctx }) => {
      await enforceMultiTargetScope(
        input.engagementId,
        input.targets.map(t => ({ value: t })),
        "scanforge:naabu:full-pipeline",
        ctx.user.openId,
        ctx.user.name || undefined,
      );

      const result = await executeScanforgeScan({
        targets: input.targets,
        profile: "full-pipeline",
        tool: "naabu",
        engagementId: input.engagementId,
        operatorId: ctx.user.openId,
        operatorName: ctx.user.name || undefined,
        server: input.server,
        timeoutSeconds: 1800,
        chainHttpx: true,
        chainNuclei: true,
        nucleiTags: input.nucleiTags,
        nucleiSeverity: input.nucleiSeverity,
      });

      scanResults.set(result.scanId, result);
      scanHistory.unshift({
        id: result.scanId,
        engagementId: input.engagementId,
        targets: input.targets,
        profile: "full-pipeline",
        tool: "naabu",
        status: result.status,
        startedAt: result.startedAt,
        completedAt: result.completedAt,
        durationMs: result.durationMs,
        hostsUp: result.summary.hostsUp,
        openPorts: result.summary.openPorts,
        command: result.command,
        operatorId: ctx.user.openId,
      });

      return result;
    }),

  /**
   * Get a stored scan result by ID.
   */
  getResult: protectedProcedure
    .input(z.object({ scanId: z.string() }))
    .query(({ input }) => {
      const result = scanResults.get(input.scanId);
      if (!result) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Scan result not found" });
      }
      return result;
    }),

  /**
   * Get scan result formatted as SSIL observations (backward compatible).
   */
  getResultAsObservations: protectedProcedure
    .input(z.object({
      scanId: z.string(),
      policyProfile: z.string().optional(),
    }))
    .query(({ input }) => {
      const result = scanResults.get(input.scanId);
      if (!result) {
        throw new TRPCError({ code: "NOT_FOUND", message: "Scan result not found" });
      }
      return toScanforgeRawResults(result, input.policyProfile);
    }),

  /**
   * Get scan history, optionally filtered by engagement.
   */
  getHistory: protectedProcedure
    .input(z.object({
      engagementId: z.number().int().optional(),
      limit: z.number().int().min(1).max(100).default(50),
    }))
    .query(({ input }) => {
      let history = scanHistory;
      if (input.engagementId) {
        history = history.filter(h => h.engagementId === input.engagementId);
      }
      return history.slice(0, input.limit);
    }),

  /**
   * Get available scan profiles with descriptions.
   */
  getProfiles: protectedProcedure
    .query(() => {
      return SCAN_PROFILE_DESCRIPTIONS;
    }),

  /**
   * Get tool selection recommendation for given targets.
   */
  recommendTool: protectedProcedure
    .input(z.object({
      targets: z.array(z.string().min(1)).min(1),
      stealthLevel: z.enum(["minimal", "low", "medium", "high", "maximum"]).optional(),
      profile: profileSchema.optional(),
    }))
    .query(({ input }) => {
      const recommended = autoSelectTool({
        targets: input.targets,
        stealthLevel: input.stealthLevel,
        profile: input.profile,
      });
      return {
        recommended,
        reasoning: getToolRecommendationReasoning(input.targets, recommended, input.stealthLevel),
      };
    }),

  /**
   * Preflight check — verify ScanForge tools are installed on the scan server.
   */
  preflight: protectedProcedure
    .input(z.object({ server: serverSchema }))
    .mutation(async ({ input }) => {
      return preflightCheck(input.server);
    }),
});

// ─── Helpers ────────────────────────────────────────────────────────────────

function getToolRecommendationReasoning(
  targets: string[],
  recommended: ScanforgeTool,
  stealthLevel?: string,
): string {
  const reasons: string[] = [];

  if (stealthLevel === 'high' || stealthLevel === 'maximum') {
    reasons.push(`Stealth level "${stealthLevel}" requires precise rate control — Naabu provides the best rate-limiting options`);
  }

  if (targets.length === 1 && !targets[0].includes('/')) {
    reasons.push(`Single host target — ${recommended === 'rustscan' ? 'RustScan is fastest for individual hosts' : 'Naabu provides reliable results'}`);
  }

  if (targets.length > 5) {
    reasons.push(`${targets.length} targets — Masscan handles multiple targets efficiently with high packet rates`);
  }

  if (targets.some(t => t.includes('/'))) {
    const cidr = targets.find(t => t.includes('/'));
    const prefix = parseInt(cidr!.split('/')[1], 10);
    if (prefix < 24) {
      reasons.push(`Large CIDR range (/${prefix}) — Masscan is optimized for high-speed scanning of large IP ranges`);
    } else {
      reasons.push(`Small CIDR range (/${prefix}) — Naabu handles /24 and smaller ranges efficiently`);
    }
  }

  if (reasons.length === 0) {
    reasons.push(`${recommended} selected as the default versatile scanner for this target configuration`);
  }

  return reasons.join('. ');
}
