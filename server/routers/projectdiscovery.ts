/**
 * ProjectDiscovery Router
 *
 * tRPC endpoints for subfinder, httpx, and naabu integrations.
 * Supports PDCP Cloud API mode and local simulation mode.
 */
import { z } from "zod";
import { protectedProcedure, router } from "../_core/trpc";

// In-memory scan history
interface ScanRecord {
  id: number;
  tool: "subfinder" | "httpx" | "naabu";
  targets: string[];
  status: "running" | "completed" | "failed";
  startedAt: number;
  completedAt: number | null;
  result: any;
  error?: string;
}

let scanCounter = 0;
const scanHistory: ScanRecord[] = [];

export const projectDiscoveryRouter = router({
  // ─── Status ───────────────────────────────────────────────────────
  getStatus: protectedProcedure.query(async () => {
    const { getPdcpStatus } = await import("../lib/projectdiscovery");
    return {
      ...getPdcpStatus(),
      tools: {
        subfinder: { available: true, description: "Fast passive subdomain enumeration tool" },
        httpx: { available: true, description: "Fast and multi-purpose HTTP toolkit" },
        naabu: { available: true, description: "Fast port scanner written in Go" },
      },
      recentScans: scanHistory.slice(-10).reverse(),
    };
  }),

  // ─── Scan History ─────────────────────────────────────────────────
  listScans: protectedProcedure
    .input(z.object({
      tool: z.enum(["subfinder", "httpx", "naabu"]).optional(),
      limit: z.number().default(20),
    }).optional())
    .query(({ input }) => {
      let filtered = [...scanHistory].sort((a, b) => b.startedAt - a.startedAt);
      if (input?.tool) {
        filtered = filtered.filter((s) => s.tool === input.tool);
      }
      return {
        total: filtered.length,
        scans: filtered.slice(0, input?.limit || 20),
      };
    }),

  getScan: protectedProcedure
    .input(z.object({ scanId: z.number() }))
    .query(({ input }) => {
      const scan = scanHistory.find((s) => s.id === input.scanId);
      if (!scan) throw new Error(`Scan ${input.scanId} not found`);
      return scan;
    }),

  // ─── Subfinder ────────────────────────────────────────────────────
  subfinder: router({
    run: protectedProcedure
      .input(z.object({
        domain: z.string().min(1),
        sources: z.array(z.string()).optional(),
        recursive: z.boolean().default(false),
        maxEnumerationTime: z.number().default(300),
        rateLimit: z.number().default(100),
        engagementId: z.number().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        // ── ROE Scope Enforcement ──
        if (input.engagementId) {
          const { enforceTargetScope } = await import("../lib/scope-enforcement-middleware");
          await enforceTargetScope(input.engagementId, input.domain, "Subfinder", ctx);
        }
        const record: ScanRecord = {
          id: ++scanCounter,
          tool: "subfinder",
          targets: [input.domain],
          status: "running",
          startedAt: Date.now(),
          completedAt: null,
          result: null,
        };
        scanHistory.push(record);

        try {
          const { runSubfinder } = await import("../lib/projectdiscovery");
          const result = await runSubfinder({
            domain: input.domain,
            sources: input.sources,
            recursive: input.recursive,
            maxEnumerationTime: input.maxEnumerationTime,
            rateLimit: input.rateLimit,
          });

          record.status = "completed";
          record.completedAt = Date.now();
          record.result = result;

          // Auto-ingest into SSIL observation normalizer
          try {
            const { ingestSubfinderResults } = await import("../lib/observation-ingestor");
            const ingestion = await ingestSubfinderResults(result);
            console.log(`[Subfinder→SSIL] Ingested ${ingestion.observations} observations, ${ingestion.signals} signals`);
          } catch (err: any) {
            console.error(`[Subfinder→SSIL] Ingestion failed (non-fatal): ${err.message}`);
          }

          return { scanId: record.id, ...result };
        } catch (err: any) {
          record.status = "failed";
          record.completedAt = Date.now();
          record.error = err.message;
          throw err;
        }
      }),

    getResults: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(({ input }) => {
        const scan = scanHistory.find(
          (s) => s.id === input.scanId && s.tool === "subfinder"
        );
        if (!scan) throw new Error(`Subfinder scan ${input.scanId} not found`);
        return scan;
      }),
  }),

  // ─── httpx ────────────────────────────────────────────────────────
  httpx: router({
    run: protectedProcedure
      .input(z.object({
        targets: z.array(z.string()).min(1).max(100),
        ports: z.string().default("80,443,8080,8443"),
        threads: z.number().default(50),
        timeout: z.number().default(10),
        followRedirects: z.boolean().default(true),
        statusCode: z.boolean().default(true),
        contentLength: z.boolean().default(true),
        title: z.boolean().default(true),
        webServer: z.boolean().default(true),
        tech: z.boolean().default(true),
        tlsProbe: z.boolean().default(true),
        favicon: z.boolean().default(false),
        jarm: z.boolean().default(false),
        responseTime: z.boolean().default(true),
        method: z.string().default("GET"),
        matchCodes: z.array(z.number()).optional(),
        filterCodes: z.array(z.number()).optional(),
        engagementId: z.number().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        // ── ROE Scope Enforcement ──
        if (input.engagementId) {
          const { enforceMultiTargetScope } = await import("../lib/scope-enforcement-middleware");
          await enforceMultiTargetScope(input.engagementId, input.targets, "httpx", ctx);
        }
        const record: ScanRecord = {
          id: ++scanCounter,
          tool: "httpx",
          targets: input.targets,
          status: "running",
          startedAt: Date.now(),
          completedAt: null,
          result: null,
        };
        scanHistory.push(record);

        try {
          const { runHttpx } = await import("../lib/projectdiscovery");
          const result = await runHttpx({
            targets: input.targets,
            ports: input.ports,
            threads: input.threads,
            timeout: input.timeout,
            followRedirects: input.followRedirects,
            statusCode: input.statusCode,
            contentLength: input.contentLength,
            title: input.title,
            webServer: input.webServer,
            tech: input.tech,
            tlsProbe: input.tlsProbe,
            favicon: input.favicon,
            jarm: input.jarm,
            responseTime: input.responseTime,
            method: input.method,
            matchCodes: input.matchCodes,
            filterCodes: input.filterCodes,
          });

          record.status = "completed";
          record.completedAt = Date.now();
          record.result = result;

          // Auto-ingest into SSIL observation normalizer
          try {
            const { ingestHttpxResults } = await import("../lib/observation-ingestor");
            const ingestion = await ingestHttpxResults(result);
            console.log(`[httpx→SSIL] Ingested ${ingestion.observations} observations, ${ingestion.signals} signals`);
          } catch (err: any) {
            console.error(`[httpx→SSIL] Ingestion failed (non-fatal): ${err.message}`);
          }

          return { scanId: record.id, ...result };
        } catch (err: any) {
          record.status = "failed";
          record.completedAt = Date.now();
          record.error = err.message;
          throw err;
        }
      }),

    getResults: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(({ input }) => {
        const scan = scanHistory.find(
          (s) => s.id === input.scanId && s.tool === "httpx"
        );
        if (!scan) throw new Error(`httpx scan ${input.scanId} not found`);
        return scan;
      }),
  }),

  // ─── Naabu ────────────────────────────────────────────────────────
  naabu: router({
    run: protectedProcedure
      .input(z.object({
        targets: z.array(z.string()).min(1).max(100),
        ports: z.string().optional(),
        topPorts: z.number().default(100),
        excludePorts: z.string().optional(),
        scanType: z.enum(["syn", "connect"]).default("connect"),
        rate: z.number().default(1000),
        timeout: z.number().default(5),
        retries: z.number().default(3),
        hostDiscovery: z.boolean().default(true),
        serviceDiscovery: z.boolean().default(true),
        serviceVersion: z.boolean().default(false),
        passiveMode: z.boolean().default(false),
        engagementId: z.number().optional(),
      }))
      .mutation(async ({ input, ctx }) => {
        // ── ROE Scope Enforcement ──
        if (input.engagementId) {
          const { enforceMultiTargetScope } = await import("../lib/scope-enforcement-middleware");
          await enforceMultiTargetScope(input.engagementId, input.targets, "Naabu Port Scanner", ctx);
        }
        const record: ScanRecord = {
          id: ++scanCounter,
          tool: "naabu",
          targets: input.targets,
          status: "running",
          startedAt: Date.now(),
          completedAt: null,
          result: null,
        };
        scanHistory.push(record);

        try {
          const { runNaabu } = await import("../lib/projectdiscovery");
          const result = await runNaabu({
            targets: input.targets,
            ports: input.ports,
            topPorts: input.topPorts,
            excludePorts: input.excludePorts,
            scanType: input.scanType,
            rate: input.rate,
            timeout: input.timeout,
            retries: input.retries,
            hostDiscovery: input.hostDiscovery,
            serviceDiscovery: input.serviceDiscovery,
            serviceVersion: input.serviceVersion,
            passiveMode: input.passiveMode,
          });

          record.status = "completed";
          record.completedAt = Date.now();
          record.result = result;

          // Auto-ingest into SSIL observation normalizer
          try {
            const { ingestNaabuResults } = await import("../lib/observation-ingestor");
            const ingestion = await ingestNaabuResults(result);
            console.log(`[Naabu→SSIL] Ingested ${ingestion.observations} observations, ${ingestion.signals} signals`);
          } catch (err: any) {
            console.error(`[Naabu→SSIL] Ingestion failed (non-fatal): ${err.message}`);
          }

          return { scanId: record.id, ...result };
        } catch (err: any) {
          record.status = "failed";
          record.completedAt = Date.now();
          record.error = err.message;
          throw err;
        }
      }),

    getResults: protectedProcedure
      .input(z.object({ scanId: z.number() }))
      .query(({ input }) => {
        const scan = scanHistory.find(
          (s) => s.id === input.scanId && s.tool === "naabu"
        );
        if (!scan) throw new Error(`Naabu scan ${input.scanId} not found`);
        return scan;
      }),
  }),

  // ─── Combined Stats ───────────────────────────────────────────────
  getStats: protectedProcedure.query(() => {
    const subfinderScans = scanHistory.filter((s) => s.tool === "subfinder");
    const httpxScans = scanHistory.filter((s) => s.tool === "httpx");
    const naabuScans = scanHistory.filter((s) => s.tool === "naabu");

    return {
      subfinder: {
        totalScans: subfinderScans.length,
        completedScans: subfinderScans.filter((s) => s.status === "completed").length,
        totalSubdomains: subfinderScans
          .filter((s) => s.result)
          .reduce((sum, s) => sum + (s.result?.stats?.total || 0), 0),
      },
      httpx: {
        totalScans: httpxScans.length,
        completedScans: httpxScans.filter((s) => s.status === "completed").length,
        totalProbes: httpxScans
          .filter((s) => s.result)
          .reduce((sum, s) => sum + (s.result?.stats?.total || 0), 0),
      },
      naabu: {
        totalScans: naabuScans.length,
        completedScans: naabuScans.filter((s) => s.status === "completed").length,
        totalPorts: naabuScans
          .filter((s) => s.result)
          .reduce((sum, s) => sum + (s.result?.stats?.totalOpenPorts || 0), 0),
      },
    };
  }),
});
