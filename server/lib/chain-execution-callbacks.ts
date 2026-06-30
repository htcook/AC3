/**
 * Chain Execution Callbacks — Real Tool Wiring
 * 
 * Connects the discovery chain orchestrator to actual tool engines:
 * - Amass → amass-engine.ts executeAmassEnum
 * - ScanForge → scanforge-discovery.ts executeScanforgeScan
 * - Service Fingerprinter → service-fingerprinter.ts batchFingerprint
 * - Nuclei → ScanForge HTTP API (nuclei v3.7.1 with background execution)
 * 
 * Each callback adapts the chain's generic interface to the specific
 * tool engine's config/result types, handling server config resolution
 * and result normalization.
 */

import type { ChainExecutionCallbacks } from "./discovery-chain-orchestrator";
import { enforceMultiTargetScope } from "./scope-enforcement-middleware";
import { executeToolViaHttp } from "./do-scan-api";

// ─── Server Config Resolution ────────────────────────────────────────────

/**
 * Resolve scan server config from environment or DB.
 * The chain doesn't carry server SSH details — we resolve them at execution time.
 */
async function resolveAmassServer(): Promise<{
  host: string;
  port?: number;
  username: string;
  privateKey?: string;
  privateKeyPath?: string;
}> {
  // Try to get the first available server config from DB
  try {
    const { getServerConfigs, getCredentialsByServerId } = await import("../db");
    const servers = await getServerConfigs();
    const activeServer = servers.find(s => s.status === "online") || servers[0];
    if (activeServer) {
      const creds = await getCredentialsByServerId(activeServer.id);
      const sshCred = creds.find(c => c.credentialType === "ssh_key");
      return {
        host: activeServer.ipAddress,
        port: 22,
        username: sshCred?.username || "root",
        privateKey: sshCred?.apiKey || undefined,
        privateKeyPath: sshCred?.sshKeyPath || undefined,
      };
    }
  } catch {
    // Fall through to env-based config
  }

  // Fallback to environment variables
  return {
    host: process.env.SCAN_SERVER_HOST || "localhost",
    port: Number(process.env.SCAN_SERVER_PORT) || 22,
    username: process.env.SCAN_SERVER_USER || "root",
    privateKeyPath: process.env.SCAN_SERVER_KEY_PATH || undefined,
  };
}

async function resolveScanforgeServer(): Promise<{
  host: string;
  port?: number;
  username: string;
  privateKey?: string;
  privateKeyPath?: string;
}> {
  return resolveAmassServer();
}

// ─── Helpers ───────────────────────────────────────────────────────────────

/** Extract CVE ID from nuclei tags array or template ID */
function extractCveFromTags(tags?: string[], templateId?: string): string | undefined {
  // Check tags for CVE references
  if (tags) {
    for (const tag of tags) {
      const match = tag.match(/cve-\d{4}-\d+/i);
      if (match) return match[0].toUpperCase();
    }
  }
  // Check template ID for CVE pattern (e.g., "CVE-2021-44228")
  if (templateId) {
    const match = templateId.match(/cve-\d{4}-\d+/i);
    if (match) return match[0].toUpperCase();
  }
  return undefined;
}

// ─── Callback Factory ────────────────────────────────────────────────────

/**
 * Build real execution callbacks for the discovery chain.
 * These connect to actual tool engines and return normalized results.
 */
export function buildRealCallbacks(options?: {
  onProgress?: (run: any) => void;
  onStageComplete?: (run: any, stageId: string) => void;
}): ChainExecutionCallbacks {
  return {
    // ─── Amass ─────────────────────────────────────────────────────
    executeAmass: async (config) => {
      const { executeAmassEnum } = await import("./amass-engine");
      const server = await resolveAmassServer();

      const result = await executeAmassEnum({
        domains: config.domains,
        mode: config.mode as any,
        server,
        engagementId: config.engagementId ? String(config.engagementId) : undefined,
        timeoutMinutes: config.timeout ? Math.ceil(config.timeout / 60) : 30,
        maxEnumerations: config.maxSubdomains,
      });

      return {
        subdomains: result.subdomains || [],
        rawResult: {
          scanId: result.scanId,
          status: result.status,
          domains: result.domains,
          subdomainCount: result.subdomains?.length || 0,
          uniqueIps: result.uniqueIps || [],
          uniqueAsns: result.uniqueAsns || [],
          dataSources: result.dataSources || [],
          durationMs: result.durationMs,
          // Include full subdomain data for downstream extraction
          subdomains: result.subdomains?.map(s => ({
            name: s.name,
            domain: s.domain,
            addresses: s.addresses,
            sources: s.sources,
            tag: s.tag,
          })) || [],
        },
      };
    },

    // ─── ScanForge Discovery ─────────────────────────────────────
    executeNmap: async (config) => {
      const { executeScanforgeScan, autoSelectTool } = await import("./scanforge-discovery");
      const server = await resolveScanforgeServer();

      const tool = autoSelectTool({ targets: config.targets, profile: config.profile as any });
      const result = await executeScanforgeScan({
        targets: config.targets,
        profile: (config.profile || 'standard') as any,
        tool,
        engagementId: config.engagementId || 0,
        operatorId: config.operatorId || "chain-orchestrator",
        server,
        timeoutSeconds: config.timeout || 600,
        ports: config.topPorts ? `1-${config.topPorts}` : undefined,
      });

      return {
        hosts: result.hosts || [],
        rawResult: {
          scanId: result.scanId,
          status: result.status,
          command: result.command,
          durationMs: result.durationMs,
          summary: result.summary,
          hosts: result.hosts?.map(h => ({
            ip: h.ip,
            hostnames: h.hostnames,
            status: h.status,
            ports: h.ports?.map(p => ({
              port: p.port,
              protocol: p.protocol,
              state: p.state,
              service: p.service,
              version: p.version,
              product: p.product,
              extraInfo: undefined,
            })) || [],
            os: undefined,
          })) || [],
        },
      };
    },

    // ─── Service Fingerprinter ─────────────────────────────────────
    executeFingerprint: async (config) => {
      const { batchFingerprint } = await import("./service-fingerprinter");

      const results = await batchFingerprint({
        targets: config.targets.map(t => ({
          host: t.host,
          port: t.port,
          protocol: t.protocol as any,
        })),
        engagementId: config.engagementId,
        operatorId: config.operatorId,
        timeoutMs: (config.timeout || 30) * 1000,
        concurrency: config.concurrency || 5,
        tryDefaultCreds: config.tryDefaultCreds || false,
      });

      return {
        results: results || [],
        rawResult: results?.map(r => ({
          host: r.host,
          port: r.port,
          protocol: r.protocol,
          banner: r.banner,
          version: r.version,
          product: r.product,
          os: r.os,
          error: r.error,
          securityFlags: r.securityFlags,
          riskIndicators: r.riskIndicators,
          potentialCves: r.potentialCves,
          mitreRelevance: r.mitreRelevance,
          durationMs: r.durationMs,
        })) || [],
      };
    },

    // ─── Nuclei (Real ScanForge API) ─────────────────────────────
    executeNuclei: async (config) => {
      // Execute nuclei via ScanForge HTTP API with real template scanning.
      // ScanForge v2.2.0 uses background execution to work around nuclei v3.7.1
      // hang-after-completion bug (metrics server on localhost:9092 blocks exit).
      const findings: any[] = [];
      const allErrors: string[] = [];

      const templateCategories = config.categories || ["cves", "vulnerabilities", "misconfiguration"];
      const severityFilter = config.severity || ["critical", "high", "medium"];

      // Map category names to nuclei template paths/tags
      const categoryToNucleiArgs: Record<string, string> = {
        cves: "-t /root/nuclei-templates/http/cves/",
        vulnerabilities: "-severity critical,high,medium",
        misconfiguration: "-t /root/nuclei-templates/http/misconfiguration/",
        exposures: "-t /root/nuclei-templates/http/exposures/",
        technologies: "-t /root/nuclei-templates/http/technologies/",
        "default-logins": "-t /root/nuclei-templates/http/default-logins/",
        network: "-t /root/nuclei-templates/network/",
      };

      // Build nuclei args: combine severity filter with template categories
      const severityArg = `-severity ${severityFilter.join(",")}`;
      const tagArgs = config.tags?.length ? `-tags ${config.tags.join(",")}` : "";
      const rateLimit = config.rateLimit || 50;
      const timeout = config.timeout || 10;

      // Run nuclei against each target (or batch if few targets)
      const targetList = config.targets.slice(0, 20); // Cap at 20 targets for chain scans

      for (const target of targetList) {
        try {
          // Determine if target is a URL or hostname
          const targetUrl = target.startsWith("http") ? target : `http://${target}`;

          // Build nuclei command args
          let nucleiArgs = `-u ${targetUrl} ${severityArg} -no-interactsh -jsonl -timeout ${timeout} -nc -duc -ni -c 10 -rl ${rateLimit} -retries 1`;
          if (tagArgs) nucleiArgs += ` ${tagArgs}`;

          // If specific categories requested, add template paths
          if (templateCategories.length > 0 && !templateCategories.includes("vulnerabilities")) {
            const templateArgs = templateCategories
              .map(c => categoryToNucleiArgs[c])
              .filter(Boolean)
              .join(" ");
            if (templateArgs) nucleiArgs += ` ${templateArgs}`;
          }

          console.log(`[ChainCallbacks] Nuclei scanning ${target} with args: ${nucleiArgs.slice(0, 150)}...`);

          const result = await executeToolViaHttp({
            tool: "nuclei",
            args: nucleiArgs,
            target: target,
            timeoutSeconds: 300,
            engagementId: config.engagementId,
          });

          // Parse JSONL output from nuclei
          if (result.stdout) {
            const lines = result.stdout.split("\n").filter(l => l.trim());
            for (const line of lines) {
              try {
                const raw = JSON.parse(line);
                const info = raw.info || {};
                findings.push({
                  templateId: raw["template-id"] || "unknown",
                  templateName: info.name || raw["template-id"] || "Unknown Template",
                  name: info.name || raw["template-id"] || "Unknown Template",
                  description: info.description || "",
                  severity: (info.severity || "info").toLowerCase(),
                  type: info.severity === "critical" || info.severity === "high" ? "vulnerability" : "misconfiguration",
                  host: raw.host || target,
                  port: raw.port || undefined,
                  matched: raw["matched-at"] || raw.url || target,
                  matchedAt: raw["matched-at"] || raw.url || target,
                  matcher: raw["matcher-name"] || undefined,
                  extractedResults: raw["extracted-results"] || [],
                  curl: raw["curl-command"] || undefined,
                  timestamp: raw.timestamp ? new Date(raw.timestamp).getTime() : Date.now(),
                  category: templateCategories[0] || "vulnerabilities",
                  tags: info.tags || config.tags || [],
                  cveId: extractCveFromTags(info.tags, raw["template-id"]),
                  cweId: info.classification?.cwe_id?.[0] || undefined,
                  ip: raw.ip || undefined,
                  scheme: raw.scheme || undefined,
                  // Raw nuclei data for evidence
                  _raw: {
                    request: raw.request?.slice(0, 2000),
                    response: raw.response?.slice(0, 5000),
                    matcherName: raw["matcher-name"],
                    templatePath: raw["template-path"],
                  },
                });
              } catch (parseErr) {
                // Skip non-JSON lines (nuclei banner, stats, etc.)
              }
            }
          }

          if (result.exitCode !== 0 && !result.stdout) {
            allErrors.push(`Nuclei failed for ${target}: exit=${result.exitCode} ${result.error || result.stderr?.slice(0, 200) || ""}`);
          }
        } catch (err: any) {
          allErrors.push(`Nuclei error for ${target}: ${err.message}`);
        }
      }

      console.log(`[ChainCallbacks] Nuclei completed: ${findings.length} findings from ${targetList.length} targets, ${allErrors.length} errors`);

      return {
        findings,
        rawResult: {
          status: allErrors.length === targetList.length ? "failed" : "completed",
          targetsScanned: targetList.length,
          templateCategories,
          findingCount: findings.length,
          findings,
          errors: allErrors.length > 0 ? allErrors : undefined,
        },
      };
    },

    // ─── Service Audit Pipeline ─────────────────────────────
    executeServiceAudit: async (config) => {
      const { runServiceAuditPipeline } = await import("./scanners/service-audit-pipeline");

      console.log(`[DiscoveryChain] Running service audit pipeline on ${config.services.length} discovered services`);

      const result = await runServiceAuditPipeline(config.services, {
        engagementId: config.engagementId,
        operatorId: config.operatorId,
        concurrency: config.concurrency || 3,
        timeoutPerAudit: config.timeoutPerAudit || 300,
        profile: config.profile || "standard",
        enabledScanners: config.enabledScanners as any,
      });

      return {
        results: result.results,
        totalFindings: result.totalFindings,
        severitySummary: result.severitySummary,
      };
    },

    // ─── Scope Enforcement ─────────────────────────────────
    enforceScope: async (scopeConfig) => {
      try {
        await enforceMultiTargetScope(
          scopeConfig.engagementId,
          scopeConfig.targets,
          scopeConfig.tool,
          { user: { id: Number(scopeConfig.operatorId) || 0, name: "chain", role: "admin" } },
        );
        return {
          inScope: scopeConfig.targets,
          outOfScope: [],
        };
      } catch (err: any) {
        // Parse scope enforcement errors to identify which targets are out of scope
        const outOfScope: string[] = [];
        const inScope = scopeConfig.targets.filter(t => {
          if (err.message?.includes(t)) {
            outOfScope.push(t);
            return false;
          }
          return true;
        });

        // If we can't determine which are out of scope, allow all to avoid blocking
        if (outOfScope.length === 0) {
          return {
            inScope: scopeConfig.targets,
            outOfScope: [],
          };
        }

        return { inScope, outOfScope };
      }
    },

    // ─── Progress Callbacks ────────────────────────────────────────
    onProgress: options?.onProgress,
    onStageComplete: options?.onStageComplete,
  };
}

/**
 * Build callbacks with DB persistence hooks.
 * Wraps the real callbacks to also persist stage results to the database.
 */
export function buildPersistentCallbacks(
  chainId: string,
  options?: {
    onProgress?: (run: any) => void;
    onStageComplete?: (run: any, stageId: string) => void;
  }
): ChainExecutionCallbacks {
  const realCallbacks = buildRealCallbacks(options);

  return {
    ...realCallbacks,

    onProgress: async (run) => {
      // Persist run state to DB
      try {
        const { updateChainRunDb } = await import("../db");
        await updateChainRunDb(chainId, {
          status: run.status,
          progress: run.progress,
          currentStage: run.currentStage || null,
        });
      } catch (err) {
        console.warn(`[DiscoveryChain] Failed to persist progress for ${chainId}:`, err);
      }

      options?.onProgress?.(run);
    },

    onStageComplete: async (run, stageId) => {
      // Persist stage result to DB
      try {
        const { upsertChainStageResultDb, updateChainRunDb } = await import("../db");
        const stage = run.stages?.find((s: any) => s.stageId === stageId);
        if (stage) {
          await upsertChainStageResultDb({
            chainId,
            stageId,
            status: stage.status,
            inputTargetCount: stage.inputTargetCount || 0,
            outputCount: stage.outputCount || 0,
            findingCount: stage.findings?.length || 0,
            errors: stage.errors || [],
            findings: stage.findings || [],
            rawOutput: stage.rawOutput ? JSON.stringify(stage.rawOutput) : null,
            startedAt: stage.startedAt || 0,
            completedAt: stage.completedAt || null,
            durationMs: stage.durationMs || null,
          });
        }

        // Update run summary
        await updateChainRunDb(chainId, {
          progress: run.progress,
          currentStage: run.currentStage || null,
          totalFindings: run.allFindings?.length || 0,
          stagesCompleted: run.summary?.stagesCompleted || 0,
          stagesFailed: run.summary?.stagesFailed || 0,
          stagesSkipped: run.summary?.stagesSkipped || 0,
        });
      } catch (err) {
        console.warn(`[DiscoveryChain] Failed to persist stage ${stageId} for ${chainId}:`, err);
      }

      options?.onStageComplete?.(run, stageId);
    },
  };
}
