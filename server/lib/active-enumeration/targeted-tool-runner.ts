/**
 * Phase 5 Sub-module: Targeted Tool Deployment (Phase B)
 *
 * Runs specialized security tools per asset based on discovery data:
 * - Tool selection (scan plan or auto-suggest)
 * - Command sanitization (nuclei, httpx, gobuster, nikto)
 * - Context-aware strategy augmentation
 * - Evasion profile application
 * - Parallel execution with concurrency limit
 * - Auto-escalation on block detection
 */

import type { EnumerationHelpers, EngagementOpsState } from "./enumeration-context";
import {
  addLog,
  fmtTarget,
  isInRoeScope,
  getEffectiveTarget,
  pushVulnDeduped,
  parseToolOutput,
  executeRawCommandViaQueue,
  getScanProfile,
  buildGobusterCommand,
} from "./enumeration-context";
import type { ParsedFinding } from "../tool-output-parsers";

/**
 * Build a human-readable evidence string from parsed tool output.
 * Replaces generic "Confirmed by X" with actual proof data.
 */
function buildToolEvidenceDetail(f: ParsedFinding, toolName: string): string {
  const parts: string[] = [];

  if (f.matched_at || f.endpoint) {
    parts.push(`MATCHED AT: ${f.matched_at || f.endpoint}`);
  }
  if (f.evidence?.proofText) {
    const proof = f.evidence.proofText.length > 500
      ? f.evidence.proofText.slice(0, 500) + '...'
      : f.evidence.proofText;
    parts.push(`EXTRACTED DATA:\n${proof}`);
  }
  if (f.evidence?.matchedPattern) {
    parts.push(`MATCHED PATTERN: ${f.evidence.matchedPattern}`);
  }
  if (f.evidence?.request) {
    const req = f.evidence.request;
    const method = req.method || 'GET';
    const url = req.url || f.matched_at || '';
    parts.push(`REQUEST: ${method} ${url}`);
  }
  if (f.evidence?.response) {
    const resp = f.evidence.response;
    if (resp.statusCode) parts.push(`RESPONSE: HTTP ${resp.statusCode}`);
    if (resp.body) {
      const body = resp.body.length > 500 ? resp.body.slice(0, 500) + '...' : resp.body;
      parts.push(`RESPONSE BODY:\n${body}`);
    }
  }
  if (f.evidence?.attackPayload) {
    parts.push(`ATTACK PAYLOAD: ${f.evidence.attackPayload}`);
  }

  if (parts.length === 0) {
    if (f.description) parts.push(f.description);
    parts.push(`Source: ${toolName} scan${f.cve ? ` (${f.cve})` : ''}`);
  }

  return parts.join('\n\n');
}

// Known infrastructure IPs that need vhost injection for nikto
const KNOWN_INFRA_IPS = new Set([
  // Add scan server IPs here
]);

function genId(): string {
  return Math.random().toString(36).substring(2, 10);
}

/**
 * Execute Phase B: Targeted tool deployment on all assets.
 */
export async function executeTargetedToolDeployment(
  state: EngagementOpsState,
  helpers: EnumerationHelpers
): Promise<void> {
  addLog(state, {
    phase: "enumeration",
    type: "info",
    title: "🎯 Phase B: Targeted Tool Deployment",
    detail: "Running targeted ScanForge discovery scripts and specialized tools per asset based on combined passive recon + discovery data",
  });

  const { suggestToolCommands } = await import("../scan-server-executor");

  for (const asset of state.assets) {
    if ((asset.ports || []).length === 0) continue;

    // ═══ RoE SCOPE GUARD ═══
    if (!isInRoeScope(state, asset.hostname, asset.ip)) {
      addLog(state, {
        phase: "enumeration",
        type: "warning",
        title: `🛡️ Skipped: ${asset.hostname} (out of scope)`,
        detail: "Asset not in RoE authorized target list",
      });
      continue;
    }

    // Classify asset type
    const webPorts = (asset.ports || []).filter(
      (p: any) =>
        ["http", "https", "http-proxy", "http-alt"].includes(p.service) ||
        [80, 443, 8080, 8443, 8000, 3000, 5000].includes(p.port)
    );
    if (webPorts.length > 0) asset.type = "web_app";

    const target = getEffectiveTarget(asset, "discovery");
    const httpTarget = getEffectiveTarget(asset, "http");
    const assetPlan = state.scanPlan?.assetPlans.find(
      (ap: any) => ap.hostname === asset.hostname || ap.ip === target
    );

    // Auto-select scan tool
    const { autoSelectTool: autoSelectToolB } = await import("../scanforge-discovery");
    const sfTool = autoSelectToolB({
      targets: [target],
      stealthLevel: assetPlan?.evasionTechniques?.length ? "medium" : "minimal",
    });

    // ── Targeted ScanForge discovery ──
    await runTargetedDiscovery(state, asset, target, httpTarget, assetPlan, sfTool, helpers);

    // ── Build tool command list ──
    let cmdsToRun = await buildToolCommandList(state, asset, target, httpTarget, assetPlan, helpers);

    // ── Merge context-aware strategy tools ──
    cmdsToRun = mergeContextAwareTools(state, asset, httpTarget, cmdsToRun, helpers);

    // ── Filter and sanitize commands ──
    const highPriorityCmds = filterAndSanitize(state, asset, target, httpTarget, cmdsToRun, helpers);

    // ── Apply evasion profile flags ──
    await applyEvasionFlags(state, asset, highPriorityCmds);

    // ── Parallel execution ──
    await executeToolsInParallel(state, asset, highPriorityCmds, helpers);
  }

  state.progress = 35;
  helpers.broadcastOpsUpdate({ type: "stats_update", stats: { ...state.stats } });
}

// ─── Internal helpers ───────────────────────────────────────────────────────

async function runTargetedDiscovery(
  state: EngagementOpsState,
  asset: any,
  target: string,
  httpTarget: string,
  assetPlan: any,
  sfTool: string,
  helpers: EnumerationHelpers
): Promise<void> {
  if (!assetPlan?.discoveryFlags) return;

  const discoveredPortList = (asset.ports || []).map((p: any) => p.port).join(",");
  let targetedFlags = assetPlan.discoveryFlags
    .replace(/(?:^|\s)-p\s*(?:\{[^}]+\}|[\d,\-]+)(?=\s|$)/g, "")
    .replace(/\s*-p-/g, "")
    .replace(/\{[^}]+\}/g, "")
    .replace(/\s+/g, " ")
    .trim();

  if (discoveredPortList) {
    targetedFlags = `${targetedFlags} -p ${discoveredPortList}`;
  } else {
    targetedFlags = `${targetedFlags} --top-ports 1000`;
  }

  addLog(state, {
    phase: "enumeration",
    type: "scan_start",
    title: `🎯 Targeted ScanForge: ${fmtTarget(asset, target)}`,
    detail: `Phase B flags: ${targetedFlags}\nRationale: ${assetPlan.discoveryRationale}`,
  });

  try {
    const startTime = Date.now();
    const discoveryArgs = `${targetedFlags} ${target}`;
    const discoveryResult = await helpers.executeTool({
      tool: sfTool || "naabu",
      args: discoveryArgs,
      timeoutSeconds: 300,
      sudo: true,
    });
    const durationMs = Date.now() - startTime;

    const findings = parseToolOutput("scanforge-discovery", discoveryResult.stdout || "", asset);

    asset.toolResults.push({
      tool: sfTool || "naabu",
      command: `${sfTool} ${discoveryArgs}`,
      exitCode: discoveryResult.exitCode ?? 0,
      durationMs,
      timedOut: discoveryResult.timedOut || false,
      findingCount: findings.length,
      findings: findings.map((f: any) => ({
        severity: f.severity,
        title: f.title,
        cve: f.cve,
        evidence: f.evidence?.proofText || undefined,
      })),
      outputPreview: (discoveryResult.stdout || "").slice(0, 1024),
      executedAt: Date.now(),
      phase: "targeted_enum",
    });

    addLog(state, {
      phase: "enumeration",
      type: "scan_result",
      title: `Targeted ScanForge Complete: ${fmtTarget(asset, target)}`,
      detail: `${findings.length} findings from targeted scripts in ${Math.round(durationMs / 1000)}s`,
      data: { findings, outputPreview: (discoveryResult.stdout || "").slice(0, 500) },
    });

    for (const f of findings) {
      if (
        pushVulnDeduped(asset, {
          id: genId(),
          severity: f.severity,
          title: f.title,
          cve: f.cve,
          description: f.description,
          cvss: f.cvss,
          cwe: f.cwe,
          corroborationTier: "confirmed",
          evidenceDetail: buildToolEvidenceDetail(f, "active_scan"),
          rawEvidence: f.evidence ? JSON.stringify(f.evidence).slice(0, 4000) : undefined,
          source: "active_scan",
        })
      ) {
        state.stats.vulnsFound++;
      }
    }
  } catch (e: any) {
    addLog(state, {
      phase: "enumeration",
      type: "error",
      title: `Targeted ScanForge Failed: ${fmtTarget(asset, target)}`,
      detail: e.message,
    });
  }
}

async function buildToolCommandList(
  state: EngagementOpsState,
  asset: any,
  target: string,
  httpTarget: string,
  assetPlan: any,
  helpers: EnumerationHelpers
): Promise<Array<{ tool: string; command: string; purpose: string; priority: number }>> {
  const { suggestToolCommands } = await import("../scan-server-executor");
  let cmdsToRun: Array<{ tool: string; command: string; purpose: string; priority: number }>;

  if (assetPlan && assetPlan.activeTools.length > 0) {
    cmdsToRun = assetPlan.activeTools.map((t: any) => ({
      tool: t.tool,
      command: t.command
        .replace(/\{target\}/g, httpTarget)
        .replace(/\{[^}]*host[^}]*\}/gi, httpTarget)
        .replace(/\{[^}]*ip[^}]*\}/gi, httpTarget)
        .replace(/\{[^}]*naabu[^}]*\}/gi, "")
        .replace(/\s+/g, " ")
        .trim(),
      purpose: t.rationale,
      priority: t.priority,
    }));
    addLog(state, {
      phase: "enumeration",
      type: "tool_match",
      title: `Scan Plan Tools: ${fmtTarget(asset)}`,
      detail: `${cmdsToRun.length} tools from LLM scan plan: ${cmdsToRun.map((c) => c.tool).join(", ")}\nRisk: ${assetPlan.riskNotes}`,
      data: {
        source: "scan_plan",
        tools: cmdsToRun.map((c) => c.tool),
        ports: (asset.ports || []).map((p: any) => `${p.port}/${p.service}`),
        assetType: asset.type,
        riskNotes: assetPlan.riskNotes,
      },
    });
  } else {
    const suggestedCmds = await suggestToolCommands({
      hostname: asset.hostname,
      ip: asset.ip,
      type: asset.type,
      ports: asset.ports || [],
    });
    cmdsToRun = suggestedCmds.map((c: any) => ({
      tool: c.tool,
      command: `${c.tool} ${c.args}`,
      purpose: c.purpose,
      priority: c.priority,
    }));
    const toolNames = Array.from(new Set(cmdsToRun.map((c) => c.tool)));
    addLog(state, {
      phase: "enumeration",
      type: "tool_match",
      title: `Tool Match: ${fmtTarget(asset)}`,
      detail: `${cmdsToRun.length} commands queued using ${toolNames.length} tools: ${toolNames.join(", ")}`,
      data: {
        source: "auto_suggest",
        tools: toolNames,
        ports: (asset.ports || []).map((p: any) => `${p.port}/${p.service}`),
        assetType: asset.type,
      },
    });
  }

  return cmdsToRun;
}

function mergeContextAwareTools(
  state: EngagementOpsState,
  asset: any,
  httpTarget: string,
  cmdsToRun: Array<{ tool: string; command: string; purpose: string; priority: number }>,
  helpers: EnumerationHelpers
): Array<{ tool: string; command: string; purpose: string; priority: number }> {
  const targetProfile = state.targetProfiles?.[asset.hostname];
  if (!targetProfile?.recommendedStrategy) return cmdsToRun;

  const existingTools = new Set(cmdsToRun.map((c) => c.tool));
  const strategyPhases = targetProfile.recommendedStrategy.phases;
  let augmentedCount = 0;

  for (const phase of strategyPhases) {
    for (const tool of phase.tools) {
      if (!existingTools.has(tool.tool)) {
        const resolvedFlags = tool.flags
          .replace(/HOST|TARGET/g, httpTarget)
          .replace(/DISCOVERED_PORTS/g, (asset.ports || []).map((p: any) => p.port).join(","))
          .replace(/TARGET_URL/g, `https://${asset.hostname}`)
          .replace(/TARGET:PORT/g, `${asset.hostname}:443`);
        cmdsToRun.push({
          tool: tool.tool,
          command: `${tool.tool} ${resolvedFlags}`,
          purpose: `[Context-Aware] ${tool.purpose}`,
          priority: phase.requiresApproval ? 3 : 2,
        });
        existingTools.add(tool.tool);
        augmentedCount++;
      }
    }
  }

  if (augmentedCount > 0) {
    addLog(state, {
      phase: "enumeration",
      type: "info",
      title: `🧠 Context-Aware Augmentation: ${fmtTarget(asset)}`,
      detail: `Added ${augmentedCount} tools from ${targetProfile.recommendedStrategy.name} strategy (${targetProfile.recommendedStrategy.riskLevel} risk)\nEvasion: ${targetProfile.recommendedStrategy.evasionProfile.name} (${targetProfile.recommendedStrategy.evasionProfile.rateLimit} req/s)`,
    });
  }

  return cmdsToRun;
}

function filterAndSanitize(
  state: EngagementOpsState,
  asset: any,
  target: string,
  httpTarget: string,
  cmdsToRun: Array<{ tool: string; command: string; purpose: string; priority: number }>,
  helpers: EnumerationHelpers
): Array<{ tool: string; command: string; purpose: string; priority: number }> {
  const isScoped = state.assets.length > 0;
  const highPriorityCmds = cmdsToRun
    .filter((c) => c.priority <= 2)
    .filter((c) => {
      if (c.tool === "subfinder" && isScoped) {
        addLog(state, {
          phase: "enumeration",
          type: "info",
          title: "Skipped: subfinder (scoped engagement)",
          detail: "Subfinder skipped — targets are already defined in scope.",
        });
        return false;
      }
      return true;
    });

  for (const cmd of highPriorityCmds) {
    // ── Nuclei sanitization ──
    if (cmd.tool === "nuclei") {
      sanitizeNucleiCommand(cmd, asset, httpTarget);
    }

    // ── httpx sanitization ──
    if (cmd.tool === "httpx") {
      sanitizeHttpxCommand(cmd);
    }

    // ── Gobuster sanitization ──
    if (cmd.tool === "gobuster") {
      sanitizeGobusterCommand(cmd, state, asset, httpTarget);
    }

    // ── Nikto sanitization ──
    if (cmd.tool === "nikto") {
      sanitizeNiktoCommand(cmd, state, asset);
    }
  }

  return highPriorityCmds;
}

function sanitizeNucleiCommand(cmd: any, asset: any, httpTarget: string): void {
  let nucleiCmd = cmd.command.replace(/\bnuclei\b/g, "").trim();
  const targetMatch = nucleiCmd.match(/-(?:target|u)\s+(\S+)/) || nucleiCmd.match(/(https?:\/\/\S+)/);
  let nucleiTarget = targetMatch?.[1] || httpTarget;

  if (nucleiTarget && !nucleiTarget.startsWith("http")) {
    const webPorts = (asset.ports || []).filter(
      (p: any) =>
        ["http", "https", "http-proxy", "http-alt"].includes(p.service) ||
        [80, 443, 8080, 8443, 8000, 3000, 5000].includes(p.port)
    );
    if (webPorts.length > 0) {
      const scheme = webPorts[0].port === 443 || webPorts[0].port === 8443 ? "https" : "http";
      nucleiTarget = `${scheme}://${nucleiTarget}:${webPorts[0].port}`;
    }
  }

  nucleiCmd = nucleiCmd.replace(/-target\s+\S+/g, "").replace(/-u\s+\S+/g, "").trim();
  if (!nucleiCmd.includes("-severity")) nucleiCmd += " -severity critical,high,medium";
  if (!nucleiCmd.includes("-jsonl")) nucleiCmd += " -jsonl";
  if (!nucleiCmd.includes("-nc")) nucleiCmd += " -nc";
  if (!nucleiCmd.includes("-duc")) nucleiCmd += " -duc";
  if (!nucleiCmd.includes("-ni")) nucleiCmd += " -ni";
  if (!nucleiCmd.includes("-timeout")) nucleiCmd += " -timeout 10";
  if (!nucleiCmd.includes("-retries")) nucleiCmd += " -retries 1";

  const detectedTechs = asset.passiveRecon?.technologies || [];
  const techLower = detectedTechs.map((t: string) => t.toLowerCase());
  const techTags: string[] = [];
  if (techLower.some((t: string) => t.includes("wordpress"))) techTags.push("wordpress");
  if (techLower.some((t: string) => t.includes("nginx"))) techTags.push("nginx");
  if (techLower.some((t: string) => t.includes("apache"))) techTags.push("apache");
  if (techLower.some((t: string) => t.includes("php"))) techTags.push("php");
  if (techLower.some((t: string) => t.includes("node") || t.includes("next"))) techTags.push("nodejs");
  if (techLower.some((t: string) => t.includes("cloudfront") || t.includes("aws"))) techTags.push("aws");
  if (!nucleiCmd.includes("-tags") && techTags.length > 0) nucleiCmd += ` -tags ${techTags.join(",")}`;

  cmd.command = `nuclei -u ${nucleiTarget} ${nucleiCmd}`.replace(/\s+/g, " ").trim();
}

function sanitizeHttpxCommand(cmd: any): void {
  let httpxCmd = cmd.command.replace(/\bhttpx\b/g, "").trim();
  const pipeMatch = httpxCmd.match(/^echo\s+(\S+)\s*\|\s*(.*)$/);
  if (pipeMatch) {
    const httpxUrl = pipeMatch[1];
    const httpxFlags = pipeMatch[2].replace(/\becho\b/g, "").replace(/\|/g, "").trim();
    cmd.command = `echo ${httpxUrl} | httpx ${httpxFlags}`.replace(/\s+/g, " ").trim();
  } else {
    const urlMatch = httpxCmd.match(/-u\s+(\S+)/);
    if (urlMatch) {
      const httpxUrl = urlMatch[1];
      const httpxFlags = httpxCmd.replace(/-u\s+\S+/, "").trim();
      cmd.command = `echo ${httpxUrl} | httpx ${httpxFlags}`.replace(/\s+/g, " ").trim();
    } else {
      const bareUrl = httpxCmd.match(/(https?:\/\/\S+)/);
      if (bareUrl) {
        const httpxUrl = bareUrl[1];
        const httpxFlags = httpxCmd.replace(/(https?:\/\/\S+)/, "").trim();
        cmd.command = `echo ${httpxUrl} | httpx ${httpxFlags}`.replace(/\s+/g, " ").trim();
      } else {
        cmd.command = `httpx ${httpxCmd}`.replace(/\s+/g, " ").trim();
      }
    }
  }
}

function sanitizeGobusterCommand(
  cmd: any,
  state: EngagementOpsState,
  asset: any,
  httpTarget: string
): void {
  const gobUrlMatch = cmd.command.match(/-u\s+(\S+)/) || cmd.command.match(/(https?:\/\/\S+)/);
  const gobTargetUrl = gobUrlMatch?.[1] || httpTarget;

  const wafDetected = !!(asset.wafDetected && asset.wafDetected !== "none");
  const detectedTech = asset.passiveRecon?.technologies || [];
  const isApiTarget =
    asset.type === "api" ||
    (asset.ports || []).some((p: any) => /api|graphql|rest/i.test(p.service || "")) ||
    /\/api\/|\/v[0-9]+\//i.test(gobTargetUrl);

  // Get auth cookie
  let authCookie = "";
  const webCreds = (asset.confirmedCredentials || []).filter((c: any) =>
    ["http", "web", "form", "http-get", "http-post-form"].includes(c.service)
  );
  if (webCreds.length > 0 && (webCreds[0] as any).sessionCookie) {
    authCookie = (webCreds[0] as any).sessionCookie;
  } else if ((asset as any).trainingLabCreds?.sessionCookie) {
    authCookie = (asset as any).trainingLabCreds.sessionCookie;
  }

  // Build command using scan profile helper
  const profile = getScanProfile(state.scanProfile || "standard");
  cmd.command = buildGobusterCommand(profile, gobTargetUrl, {
    wafDetected,
    authCookie: authCookie || undefined,
    detectedTech,
    isApiTarget,
  });
}

function sanitizeNiktoCommand(cmd: any, state: EngagementOpsState, asset: any): void {
  const niktoUrlMatch = cmd.command.match(/-h\s+(https?:\/\/\S+)/);
  if (niktoUrlMatch) {
    const niktoUrl = niktoUrlMatch[1];
    const isNiktoHttps =
      niktoUrl.startsWith("https://") || /:(443|8443|8444|8445|8447|9443)\b/.test(niktoUrl);
    if (isNiktoHttps && !cmd.command.includes("-ssl")) {
      cmd.command = cmd.command.replace(/-h\s+\S+/, "$& -ssl");
    }
  }

  // Reverse-proxy vhost fix
  if (!cmd.command.includes("-vhost") && asset.hostname && asset.ip && asset.hostname !== asset.ip) {
    if (KNOWN_INFRA_IPS.has(asset.ip)) {
      cmd.command += ` -vhost ${asset.hostname}`;
    }
  }

  if (!cmd.command.includes("-maxtime")) {
    cmd.command += " -maxtime 300";
  }

  // Inject session cookie for authenticated scanning
  if (!cmd.command.includes("Cookie:") && !cmd.command.includes("-id ")) {
    let niktoCookie = "";
    if ((asset as any).trainingLabCreds?.sessionCookie) {
      niktoCookie = (asset as any).trainingLabCreds.sessionCookie;
    } else {
      const niktoWebCreds = (asset.confirmedCredentials || []).filter((c: any) =>
        ["http", "web", "form", "http-get", "http-post-form"].includes(c.service)
      );
      if (niktoWebCreds.length > 0 && (niktoWebCreds[0] as any).sessionCookie) {
        niktoCookie = (niktoWebCreds[0] as any).sessionCookie;
      }
    }
    if (niktoCookie) {
      cmd.command += ` -H "Cookie: ${niktoCookie}"`;
    }
  }

  cmd.command = cmd.command.replace(/\s+/g, " ").trim();
}

async function applyEvasionFlags(
  state: EngagementOpsState,
  asset: any,
  highPriorityCmds: Array<{ tool: string; command: string; purpose: string; priority: number }>
): Promise<void> {
  if (!state.targetProfiles) return;
  const targetProfile = state.targetProfiles[asset.hostname];
  if (!targetProfile) return;

  try {
    const { augmentCommandWithEvasion } = await import("../evasion-cli-adapter.js");
    for (const cmd of highPriorityCmds) {
      const augmentation = augmentCommandWithEvasion(cmd.tool, cmd.command, targetProfile);
      if (augmentation.flagsAdded.length > 0) {
        cmd.command = augmentation.augmentedCommand;
      }
    }
  } catch {
    /* evasion augmentation is best-effort */
  }
}

async function executeToolsInParallel(
  state: EngagementOpsState,
  asset: any,
  highPriorityCmds: Array<{ tool: string; command: string; purpose: string; priority: number }>,
  helpers: EnumerationHelpers
): Promise<void> {
  const CONCURRENCY_LIMIT = 2;
  addLog(state, {
    phase: "enumeration",
    type: "info",
    title: `⚡ Parallel Execution: ${fmtTarget(asset)}`,
    detail: `Running ${highPriorityCmds.length} tools with concurrency=${CONCURRENCY_LIMIT} (${highPriorityCmds.map((c) => c.tool).join(", ")})`,
  });

  async function executeToolCmd(cmd: { tool: string; command: string; purpose: string; priority: number }) {
    addLog(state, {
      phase: "enumeration",
      type: "scan_start",
      title: `Running: ${cmd.tool}`,
      detail: `${cmd.purpose} — ${cmd.command.slice(0, 120)}`,
      data: { tool: cmd.tool, fullCommand: cmd.command },
    });

    const toolTimeout = cmd.tool === "nuclei" ? 300 : 180;
    let result: any;

    const isPipeCommand =
      cmd.tool === "raw" ||
      (cmd.tool === "httpx" && cmd.command.includes("echo ")) ||
      (cmd.tool === "nuclei" && cmd.command.includes("echo "));

    if (isPipeCommand) {
      const rawCmd = cmd.command.startsWith("raw ") ? cmd.command.slice(4) : cmd.command;
      const startTimeRaw = Date.now();
      result = await executeRawCommandViaQueue(rawCmd + " 2>&1", toolTimeout, {
        engagementId: state.engagementId,
      });
      result.durationMs = Date.now() - startTimeRaw;
    } else {
      const cmdArgs = cmd.command.startsWith(cmd.tool)
        ? cmd.command.slice(cmd.tool.length).trim()
        : cmd.command;
      const startTime = Date.now();
      result = await helpers.executeTool({
        tool: cmd.tool,
        args: cmdArgs,
        timeoutSeconds: toolTimeout,
        engagementId: state.engagementId,
      });
      if (!result.durationMs) result.durationMs = Date.now() - startTime;
    }

    // Truncate large outputs
    if (result.stdout && result.stdout.length > 100_000) {
      result.stdout = result.stdout.slice(0, 100_000);
    }
    if (result.stderr && result.stderr.length > 50_000) {
      result.stderr = result.stderr.slice(0, 50_000);
    }

    const findings = parseToolOutput(cmd.tool, result.stdout || "", asset);

    asset.toolResults.push({
      tool: cmd.tool,
      command: cmd.command,
      exitCode: result.exitCode,
      durationMs: result.durationMs,
      timedOut: result.timedOut,
      findingCount: findings.length,
      findings: findings.map((f: any) => ({
        severity: f.severity,
        title: f.title,
        cve: f.cve,
        evidence: f.evidence?.proofText || undefined,
      })),
      outputPreview: (result.stdout || "").slice(0, 512),
      executedAt: Date.now(),
      phase: "targeted_enum",
    });

    addLog(state, {
      phase: "enumeration",
      type: "scan_result",
      title: `${cmd.tool} Complete: ${fmtTarget(asset)}`,
      detail: `Exit code ${result.exitCode}, ${result.durationMs}ms, ${findings.length} findings${result.timedOut ? " (TIMED OUT)" : ""}`,
      data: { tool: cmd.tool, exitCode: result.exitCode, durationMs: result.durationMs, findings },
    });

    let newCount = 0;
    for (const f of findings) {
      if (
        pushVulnDeduped(asset, {
          id: genId(),
          severity: f.severity,
          title: f.title,
          cve: f.cve,
          description: f.description,
          cvss: f.cvss,
          cwe: f.cwe,
          corroborationTier: "confirmed",
          evidenceDetail: buildToolEvidenceDetail(f, cmd.tool),
          rawEvidence: f.evidence ? JSON.stringify(f.evidence).slice(0, 4000) : undefined,
          source: cmd.tool,
        })
      ) {
        state.stats.vulnsFound++;
        newCount++;
      }
    }

    return { tool: cmd.tool, findings: newCount, timedOut: result.timedOut };
  }

  // Run in batches
  const parallelStartTime = Date.now();
  for (let i = 0; i < highPriorityCmds.length; i += CONCURRENCY_LIMIT) {
    const batch = highPriorityCmds.slice(i, i + CONCURRENCY_LIMIT);
    const batchResults = await Promise.allSettled(
      batch.map((cmd) =>
        executeToolCmd(cmd).catch((e) => {
          addLog(state, { phase: "enumeration", type: "error", title: `${cmd.tool} Error`, detail: e.message });
          return null;
        })
      )
    );

    const succeeded = batchResults.filter((r) => r.status === "fulfilled" && r.value).length;
    const failed = batchResults.length - succeeded;
    if (batch.length > 1) {
      addLog(state, {
        phase: "enumeration",
        type: "info",
        title: `Batch ${Math.floor(i / CONCURRENCY_LIMIT) + 1} complete`,
        detail: `${succeeded}/${batch.length} tools finished (${failed} errors). Tools: ${batch.map((c) => c.tool).join(", ")}`,
      });
    }

    // Memory relief
    try {
      const { midScanCleanup } = await import("../memory-manager");
      midScanCleanup(state);
    } catch {
      if (global.gc) global.gc();
    }

    // Auto-escalate evasion on blocks
    if (failed > 0 && state.targetProfiles) {
      await autoEscalateEvasion(state, asset, batch.length);
    }
  }

  const parallelDuration = Date.now() - parallelStartTime;
  addLog(state, {
    phase: "enumeration",
    type: "info",
    title: `⚡ Parallel execution complete: ${fmtTarget(asset)}`,
    detail: `${highPriorityCmds.length} tools finished in ${Math.round(parallelDuration / 1000)}s (parallel batches of ${CONCURRENCY_LIMIT})`,
  });
}

async function autoEscalateEvasion(
  state: EngagementOpsState,
  asset: any,
  batchSize: number
): Promise<void> {
  try {
    const { escalateEvasionProfile: evaluateAndEscalate } = await import("../evasion-escalation-engine.js");
    const profile = state.targetProfiles?.[asset.hostname];
    if (!profile) return;

    const recentResults = asset.toolResults.slice(-batchSize);
    for (const tr of recentResults) {
      const output = tr.outputPreview || "";
      const isBlocked =
        tr.exitCode !== 0 ||
        tr.timedOut ||
        /403|blocked|captcha|rate.limit|connection.reset|ip.ban/i.test(output);
      if (isBlocked) {
        const blockReason = tr.timedOut
          ? ("rate_limit" as const)
          : /403|blocked|waf/i.test(output)
          ? ("waf_block" as const)
          : /captcha/i.test(output)
          ? ("captcha" as const)
          : /rate.limit/i.test(output)
          ? ("rate_limit" as const)
          : /connection.reset|rst/i.test(output)
          ? ("connection_reset" as const)
          : /ban/i.test(output)
          ? ("ip_ban" as const)
          : ("waf_block" as const);

        const escalationResult = evaluateAndEscalate(profile, blockReason, { toolOutput: output });
        if (
          escalationResult.escalation.currentLevel >
          ((profile as any).evasionEscalation?.currentLevel || 1)
        ) {
          state.targetProfiles![asset.hostname] = {
            ...profile,
            evasionEscalation: escalationResult.escalation,
          };
          addLog(state, {
            phase: "enumeration",
            type: "warning",
            title: `⚡ Evasion auto-escalated: ${asset.hostname}`,
            detail: `Level ${escalationResult.escalation.currentLevel}: ${escalationResult.escalation.action} (trigger: ${blockReason})`,
          });
          break;
        }
      }
    }
  } catch {
    /* Non-critical */
  }
}
