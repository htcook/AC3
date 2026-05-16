import { protectedProcedure, router } from "../_core/trpc";
import { z } from "zod";
import { not } from "drizzle-orm";
// DO infra audit kept for backward compatibility — audits customer DO environments (not our infra)
import { runDoInfraAudit, runDoFirewallAudit } from "../lib/do-infra-audit";

export const scanServerRouter = router({
    health: protectedProcedure.query(async () => {
      try {
        const { getScanServerConfig, executeTool } = await import('../lib/scan-server-executor');
        const config = await getScanServerConfig();
        if (!config) {
          return { status: 'unconfigured' as const, host: null, tools: [], uptime: null, disk: null, memory: null, error: 'Scan server not configured' };
        }

        // Run health check commands
        const [uptimeResult, diskResult, memResult, toolResult] = await Promise.allSettled([
          executeTool({ tool: 'uptime', args: '', timeoutSeconds: 10 }),
          executeTool({ tool: 'df', args: '-h /', timeoutSeconds: 10 }),
          executeTool({ tool: 'free', args: '-h', timeoutSeconds: 10 }),
          executeTool({ tool: 'cat', args: '/opt/tool-manifest.json', timeoutSeconds: 10 }),
        ]);

        const uptime = uptimeResult.status === 'fulfilled' ? uptimeResult.value.stdout.trim() : null;
        const disk = diskResult.status === 'fulfilled' ? diskResult.value.stdout.trim() : null;
        const memory = memResult.status === 'fulfilled' ? memResult.value.stdout.trim() : null;

        let tools: Array<{ name: string; version: string; path: string }> = [];
        if (toolResult.status === 'fulfilled' && toolResult.value.stdout) {
          try {
            tools = JSON.parse(toolResult.value.stdout);
          } catch {
            // Manifest not available, detect tools manually
            const detectResult = await executeTool({
              tool: 'bash',
              args: `-c "echo '[' && for t in ScanForge discovery nuclei nikto hydra httpx subfinder gobuster enum4linux smbclient ldapsearch nbtscan onesixtyone dig whois sqlmap; do which \$t 2>/dev/null && echo \"  {\\\"name\\\": \\\"\$t\\\", \\\"version\\\": \\\"installed\\\", \\\"path\\\": \\\"$(which \$t 2>/dev/null)\\\"}\"; done && echo ']'"`,
              timeoutSeconds: 15,
            });
            // Parse tool detection output
            const lines = detectResult.stdout.split('\n').filter((l: string) => l.includes('"name"'));
            tools = lines.map((l: string) => { try { return JSON.parse(l.replace(/,$/, '')); } catch { return null; } }).filter(Boolean);
          }
        }

        return {
          status: 'online' as const,
          host: config.host,
          tools,
          uptime,
          disk,
          memory,
          error: null,
        };
      } catch (err: any) {
        return {
          status: 'offline' as const,
          host: null,
          tools: [],
          uptime: null,
          disk: null,
          memory: null,
          error: err.message || 'Failed to connect to scan server',
        };
      }
    }),

    /** Run a quick connectivity test to the scan server */
    ping: protectedProcedure.mutation(async () => {
      try {
        const { executeTool } = await import('../lib/scan-server-executor');
        const start = Date.now();
        const result = await executeTool({ tool: 'echo', args: 'pong', timeoutSeconds: 10 });
        const latencyMs = Date.now() - start;
        return { success: true, latencyMs, output: result.stdout.trim() };
      } catch (err: any) {
        return { success: false, latencyMs: -1, output: err.message };
      }
    }),

    /** Check Docker container status for training targets */
    containerHealth: protectedProcedure.query(async () => {
      try {
        const { executeTool } = await import('../lib/scan-server-executor');
        const result = await executeTool({
          tool: 'docker',
          args: 'ps -a --format {{.Names}}\t{{.Status}}\t{{.Ports}}',
          timeoutSeconds: 15,
        });
        const containers = result.stdout.trim().split('\n').filter(Boolean).map((line: string) => {
          const [name, status, ports] = line.split('\t');
          return {
            name: name || '',
            status: status || 'unknown',
            ports: ports || '',
            healthy: (status || '').toLowerCase().startsWith('up'),
          };
        });
        return { containers, error: null };
      } catch (err: any) {
        return { containers: [], error: err.message };
      }
    }),

    /** Run a full DigitalOcean infrastructure security audit */
    doInfraAudit: protectedProcedure.mutation(async () => {
      return await runDoInfraAudit();
    }),

    /** Run a targeted DigitalOcean firewall-only audit */
    doFirewallAudit: protectedProcedure.mutation(async () => {
      return await runDoFirewallAudit();
    }),

    /** Check the DO scan service HTTP API health */
    doApiHealth: protectedProcedure.query(async () => {
      try {
        const { checkDoScanServiceHealth, getDoApiMetrics } = await import('../lib/do-scan-api');
        const [health, metrics] = await Promise.all([
          checkDoScanServiceHealth(),
          Promise.resolve(getDoApiMetrics()),
        ]);
        return { ...health, metrics };
      } catch (err: any) {
        return { healthy: false, error: err.message, metrics: null };
      }
    }),

    /** Get tool versions from the scan server */
    toolVersions: protectedProcedure.query(async () => {
      try {
        const { executeTool } = await import('../lib/scan-server-executor');
        const versionChecks = [
          { name: 'scanforge-discovery', cmd: 'naabu -version 2>&1 | head -1' },
          { name: 'nuclei', cmd: 'nuclei --version 2>&1 | head -1' },
          { name: 'nikto', cmd: 'nikto -Version 2>&1 | head -1' },
          { name: 'hydra', cmd: 'hydra -h 2>&1 | head -1' },
          { name: 'httpx', cmd: 'httpx -version 2>&1 | head -1' },
          { name: 'subfinder', cmd: 'subfinder -version 2>&1 | head -1' },
          { name: 'gobuster', cmd: 'gobuster version 2>&1 | head -1' },
          { name: 'sqlmap', cmd: 'sqlmap --version 2>&1 | head -1' },
          { name: 'enum4linux', cmd: 'which enum4linux && echo installed || echo missing' },
          { name: 'smbclient', cmd: 'smbclient --version 2>&1 | head -1' },
          { name: 'ldapsearch', cmd: 'ldapsearch -VV 2>&1 | head -1' },
          { name: 'dig', cmd: 'dig -v 2>&1 | head -1' },
          { name: 'whois', cmd: 'whois --version 2>&1 | head -1' },
        ];

        const results = await Promise.allSettled(
          versionChecks.map(async (vc) => {
            const r = await executeTool({ tool: 'bash', args: `-c "${vc.cmd}"`, timeoutSeconds: 10 });
            return { name: vc.name, version: r.stdout.trim() || r.stderr.trim() || 'unknown', installed: r.exitCode === 0 };
          })
        );

        return results.map((r, i) =>
          r.status === 'fulfilled'
            ? r.value
            : { name: versionChecks[i].name, version: 'error', installed: false }
        );
      } catch (err: any) {
         return [];
      }
    }),

    // ─── Tool Manifest Sync ────────────────────────────────────────────────

    /** Run a full manifest sync — compare registry against actual scan server tools */
    manifestSync: protectedProcedure
      .input(z.object({ forceRefresh: z.boolean().optional() }).optional())
      .mutation(async ({ input }) => {
        const { runManifestSync } = await import('../lib/tool-manifest-sync');
        return runManifestSync({ forceRefresh: input?.forceRefresh ?? true });
      }),

    /** Get the cached manifest sync report (fast, no scan server calls) */
    manifestReport: protectedProcedure.query(async () => {
      const { getCachedReport, runManifestSync } = await import('../lib/tool-manifest-sync');
      const cached = getCachedReport();
      if (cached) return cached;
      // No cache — run a sync
      return runManifestSync();
    }),

    /** Get category readiness breakdown */
    categoryReadiness: protectedProcedure.query(async () => {
      const { getCachedReport, runManifestSync } = await import('../lib/tool-manifest-sync');
      const report = getCachedReport() || await runManifestSync();
      return {
        categories: report.categoryReadiness,
        overallReadiness: report.overallReadiness,
        overallStatus: report.overallStatus,
      };
    }),

    /** Get remediation plan for missing tools */
    remediationPlan: protectedProcedure.query(async () => {
      const { getCachedReport, runManifestSync } = await import('../lib/tool-manifest-sync');
      const report = getCachedReport() || await runManifestSync();
      return {
        steps: report.remediationPlan,
        criticalGaps: report.criticalGaps,
        totalMissing: report.missingTools,
      };
    }),
    // ─── Tool Inventory (Enhanced) ──────────────────────────────────────
    /** Get comprehensive tool inventory with categories, versions, and paths */
    toolInventory: protectedProcedure
      .input(z.object({ forceRefresh: z.boolean().optional() }).optional())
      .query(async ({ input }) => {
        const { getToolInventory } = await import('../lib/scan-server-inventory');
        return getToolInventory(input?.forceRefresh ?? false);
      }),
    /** Get LLM-formatted tool inventory string for scan plan generation */
    toolInventoryForLLM: protectedProcedure.query(async () => {
      const { getToolInventory, getInventoryForLLM } = await import('../lib/scan-server-inventory');
      const inventory = await getToolInventory();
      return { summary: getInventoryForLLM(inventory), lastRefreshed: inventory.lastRefreshed };
    }),
    /** Invalidate the tool inventory cache (e.g., after installing new tools) */
    invalidateInventoryCache: protectedProcedure.mutation(async () => {
      const { invalidateInventoryCache } = await import('../lib/scan-server-inventory');
      invalidateInventoryCache();
      return { success: true };
    }),
  });
