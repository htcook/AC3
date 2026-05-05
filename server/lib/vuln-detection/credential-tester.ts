/**
 * Vulnerability Detection — Credential Testing
 *
 * Extracted from engagement-orchestrator.ts executeVulnDetection (lines 5670-5966).
 *
 * Responsibilities:
 *   - Vendor/OEM default credential testing via Hydra
 *   - Common wordlist credential testing
 *   - Pre-flight TCP port check (skip unreachable services)
 *   - Resume checkpoint (skip already-completed tests)
 *   - Post-Hydra HTTP credential verification (false positive elimination)
 *   - OEM credential fallback storage for downstream auth scanning
 *   - Job queue routing for credential testing
 */

import type { VulnDetectionContext } from "./index";

// ─── Result Types ───────────────────────────────────────────────────────────

export interface CredentialTestResult {
  /** Total credentials confirmed */
  credentialsConfirmed: number;
  /** Total credential tests executed */
  testsExecuted: number;
  /** Tests skipped (already completed or port unreachable) */
  testsSkipped: number;
  /** False positives eliminated by HTTP verification */
  falsePositivesEliminated: number;
  /** OEM fallback credentials stored */
  oemFallbacksStored: number;
  /** Number of services tested */
  servicesTested: number;
  /** Number of credential pairs attempted */
  attemptsTotal: number;
}

// ─── Pre-flight Port Check ──────────────────────────────────────────────────

/**
 * Check if a TCP port is reachable before running Hydra.
 * Prevents exit code 255 from connection refused.
 */
export async function checkPortReachable(host: string, port: number, timeoutMs: number = 5000): Promise<boolean> {
  const netMod = await import("net");
  return new Promise<boolean>((resolve) => {
    const sock = new netMod.default.Socket();
    sock.setTimeout(timeoutMs);
    sock.once("connect", () => { sock.destroy(); resolve(true); });
    sock.once("timeout", () => { sock.destroy(); resolve(false); });
    sock.once("error", () => { sock.destroy(); resolve(false); });
    sock.connect(port, host);
  });
}

// ─── HTTP Credential Verification ───────────────────────────────────────────

/**
 * Verify HTTP Basic Auth credentials by comparing responses with and without auth.
 * If responses are identical, the server doesn't use HTTP Basic Auth → false positive.
 */
export async function verifyHttpCredentials(
  asset: any,
  execTool: (config: any) => Promise<any>,
  engagementId: number,
): Promise<{ isValid: boolean; baselineResp: string; authResp: string }> {
  const httpCreds = (asset.confirmedCredentials || []).filter(
    (c: any) => c.source === "hydra" && (c.service === "http-get" || c.service === "https-get")
  );
  if (httpCreds.length === 0) return { isValid: true, baselineResp: "", authResp: "" };

  const scheme = httpCreds[0].service === "https-get" ? "https" : "http";
  const verifyTarget = asset.hostname || asset.ip;
  const verifyUrl = `${scheme}://${verifyTarget}:${httpCreds[0].port}/`;

  const baselineResult = await execTool({
    tool: "curl",
    args: `-s -o /dev/null -w '%{http_code}:%{size_download}' --connect-timeout 5 --max-time 10 -L ${verifyUrl}`,
    target: verifyTarget, timeoutSeconds: 30, engagementId,
  });
  const authResult = await execTool({
    tool: "curl",
    args: `-s -o /dev/null -w '%{http_code}:%{size_download}' --connect-timeout 5 --max-time 10 -L -u '${httpCreds[0].username}:${httpCreds[0].password}' ${verifyUrl}`,
    target: verifyTarget, timeoutSeconds: 30, engagementId,
  });

  const baselineResp = baselineResult.stdout.trim();
  const authResp = authResult.stdout.trim();
  return { isValid: baselineResp !== authResp, baselineResp, authResp };
}

// ─── OEM Credential Fallback ────────────────────────────────────────────────

/**
 * When Hydra fails on OEM default creds (connection refused), store them as
 * unconfirmed fallbacks so ZAP/Burp can still attempt authenticated scanning.
 */
export function storeOemFallback(asset: any, cmdArgs: string): boolean {
  const oemUserMatch = cmdArgs.match(/-l\s+'([^']+)'/);
  const oemPassMatch = cmdArgs.match(/-p\s+'([^']+)'/);
  const oemPortMatch = cmdArgs.match(/-s\s+(\d+)/);
  if (!oemUserMatch || !oemPassMatch) return false;

  if (!Array.isArray(asset.confirmedCredentials)) asset.confirmedCredentials = [];
  const oemUser = oemUserMatch[1];
  const oemPass = oemPassMatch[1];
  const exists = asset.confirmedCredentials.some((c: any) => c.username === oemUser && c.password === oemPass);
  if (exists) return false;

  asset.confirmedCredentials.push({
    username: oemUser, password: oemPass, service: "http-form",
    port: oemPortMatch ? parseInt(oemPortMatch[1]) : 80,
    protocol: "http", accessLevel: "unconfirmed",
    source: "oem_default_fallback", confirmedAt: Date.now(),
  } as any);
  return true;
}

// ─── Main Credential Testing Pipeline ───────────────────────────────────────

/**
 * Execute credential testing on all in-scope assets with login services.
 *
 * Pipeline:
 *   1. Build technology list for OEM default credential lookup
 *   2. Suggest credential testing commands (priority 3)
 *   3. Pre-flight TCP port check
 *   4. Execute Hydra with approval gating
 *   5. Post-Hydra HTTP credential verification (FP elimination)
 *   6. Recalculate stats from actual asset data
 */
export async function executeCredentialTesting(ctx: VulnDetectionContext): Promise<CredentialTestResult> {
  const { state, addLog, genId, isInRoeScope, requestApproval, executeToolViaQueue, persistScanResult, parseToolOutput, getEffectiveTarget, fmtTarget, pushVulnDeduped } = ctx;

  const result: CredentialTestResult = { credentialsConfirmed: 0, testsExecuted: 0, testsSkipped: 0, falsePositivesEliminated: 0, oemFallbacksStored: 0, servicesTested: 0, attemptsTotal: 0 };

  addLog(state, { phase: "vuln_detection", type: "info", title: "🔑 Credential Testing", detail: "Testing vendor/OEM default credentials first, then common wordlists on discovered login services" });

  try {
    const { suggestToolCommands: suggestCred } = await import("../scan-server-executor");
    const roeScope = [...(state.roeScopeGuard?.authorizedDomains || []), ...(state.roeScopeGuard?.authorizedIps || [])];
    const execToolCred = (config: any) => executeToolViaQueue(config, { engagementId: state.engagementId, roeScope });

    // Resume checkpoint
    const hydraAlreadyDone = state.completedScans.hydraCompleted.size;
    if (hydraAlreadyDone > 0) {
      addLog(state, { phase: "vuln_detection", type: "info", title: "🔄 Resume: Hydra Checkpoint", detail: `Skipping ${hydraAlreadyDone} already-completed credential test(s)` });
      result.testsSkipped += hydraAlreadyDone;
    }

    for (const asset of state.assets) {
      if (asset.ports.length === 0) continue;
      if (!isInRoeScope(state, asset.hostname, asset.ip)) continue;

      // Build technology list for OEM default lookup
      const techList = (asset.passiveRecon?.technologies || []).map((t: string) => {
        const parts = t.split(/[\s\/]+/);
        return { name: t, vendor: parts[0], version: parts.length > 1 ? parts[parts.length - 1] : undefined };
      });
      for (const p of asset.ports) {
        if (p.version) techList.push({ name: `${p.service} ${p.version}`, vendor: p.version.split(/[\s\/]+/)[0], version: p.version, port: p.port, protocol: p.service } as any);
      }

      const credCmds = (await suggestCred({ hostname: asset.hostname, ip: asset.ip, type: asset.type, ports: asset.ports, technologies: techList.length > 0 ? techList : undefined })).filter((c: any) => c.priority === 3);
      result.servicesTested += credCmds.length;

      for (const cmd of credCmds) {
        const hydraKey = `${cmd.tool}:${getEffectiveTarget(asset, "metadata")}:${cmd.purpose}`;
        if (state.completedScans.hydraCompleted.has(hydraKey)) { result.testsSkipped++; continue; }

        const approved = await requestApproval(state, { phase: "vuln_detection", riskTier: "orange", title: `Credential Test: ${cmd.purpose}`, description: `Running ${cmd.tool} against ${asset.hostname} for ${cmd.purpose}`, target: asset.hostname, module: cmd.tool, detail: { tool: cmd.tool, args: cmd.args, purpose: cmd.purpose } });
        if (!approved) { result.testsSkipped++; continue; }

        // Pre-flight TCP port check for Hydra
        if (cmd.tool === "hydra") {
          const portMatch = cmd.args.match(/-s\s+(\d+)/);
          const targetPort = portMatch ? Number(portMatch[1]) : (cmd.args.includes("ssh") ? 22 : 80);
          const targetHost = getEffectiveTarget(asset, "discovery");
          const reachable = await checkPortReachable(targetHost, targetPort);
          if (!reachable) {
            addLog(state, { phase: "vuln_detection", type: "warning", title: `⏭️ Skipped: ${cmd.tool} (port ${targetPort} unreachable)`, detail: `Pre-flight TCP check failed for ${targetHost}:${targetPort}` });
            result.testsSkipped++;
            continue;
          }
        }

        addLog(state, { phase: "vuln_detection", type: "scan_start", title: `Running: ${cmd.tool}`, detail: cmd.purpose, data: { tool: cmd.tool, fullCommand: `${cmd.tool} ${cmd.args}` } });

        try {
          const toolResult = await execToolCred({ tool: cmd.tool, args: cmd.args, target: getEffectiveTarget(asset, "discovery"), timeoutSeconds: 120, engagementId: state.engagementId });
          if (toolResult.stdout && toolResult.stdout.length > 100_000) toolResult.stdout = toolResult.stdout.slice(0, 100_000);
          if (toolResult.stderr && toolResult.stderr.length > 50_000) toolResult.stderr = toolResult.stderr.slice(0, 50_000);

          const findings = parseToolOutput(cmd.tool, toolResult.stdout, asset);
          result.attemptsTotal++;
          for (const f of findings) {
            if (pushVulnDeduped(asset, { id: genId(), severity: f.severity, title: f.title, cve: f.cve, description: f.description, corroborationTier: "confirmed", evidenceDetail: `Confirmed by ${cmd.tool}`, rawEvidence: f.evidence ? JSON.stringify(f.evidence).slice(0, 4000) : undefined, source: cmd.tool })) {
              state.stats.vulnsFound++;
              result.credentialsConfirmed++;
            }
          }

          asset.toolResults.push({ tool: cmd.tool, command: `${cmd.tool} ${cmd.args}`, exitCode: toolResult.exitCode, durationMs: toolResult.durationMs, timedOut: toolResult.timedOut, findingCount: findings.length, findings: findings.map((f: any) => ({ severity: f.severity, title: f.title })), outputPreview: toolResult.stdout.slice(0, 512), executedAt: Date.now(), phase: "credential_testing" });

          // Hydra exit 255 = connection refused → store OEM fallback
          if (cmd.tool === "hydra" && toolResult.exitCode === 255 && cmd.purpose.includes("[OEM Default]")) {
            if (storeOemFallback(asset, cmd.args)) result.oemFallbacksStored++;
          } else {
            addLog(state, { phase: "vuln_detection", type: "scan_result", title: `${cmd.tool} Complete: ${fmtTarget(asset)}`, detail: `${findings.length} findings, exit code ${toolResult.exitCode}` });
          }

          await persistScanResult({ engagementId: state.engagementId, tool: cmd.tool, target: getEffectiveTarget(asset, "metadata"), command: `${cmd.tool} ${cmd.args}`, stdout: toolResult.stdout, stderr: toolResult.stderr, exitCode: toolResult.exitCode, durationMs: toolResult.durationMs, timedOut: toolResult.timedOut, findings, phase: "credential_testing" });

          state.completedScans.hydraCompleted.add(hydraKey);
          state.completedScans.lastCheckpointAt = Date.now();
          result.testsExecuted++;
        } catch (e: any) {
          state.completedScans.hydraCompleted.add(hydraKey);
          state.completedScans.lastCheckpointAt = Date.now();
          addLog(state, { phase: "vuln_detection", type: "error", title: `${cmd.tool} Error: ${asset.hostname}`, detail: e.message });
        }
      }
    }

    // Post-Hydra HTTP credential verification (FP elimination)
    for (const asset of state.assets) {
      const httpCreds = (asset.confirmedCredentials || []).filter((c: any) => c.source === "hydra" && (c.service === "http-get" || c.service === "https-get"));
      if (httpCreds.length === 0) continue;
      try {
        const { isValid } = await verifyHttpCredentials(asset, execToolCred, state.engagementId);
        if (!isValid) {
          asset.confirmedCredentials = (asset.confirmedCredentials || []).filter((c: any) => !(c.source === "hydra" && (c.service === "http-get" || c.service === "https-get")));
          for (const vuln of asset.vulns) {
            if (vuln.title?.includes("[Hydra]") && vuln.title?.includes("http-get")) {
              vuln.severity = "info";
              vuln.title = vuln.title.replace("[Hydra] Valid credentials found:", "[Hydra] FALSE POSITIVE:");
              vuln.corroborationTier = "unverified";
            }
          }
          result.falsePositivesEliminated += httpCreds.length;
          addLog(state, { phase: "vuln_detection", type: "llm_decision", title: "⚠️ HTTP Credential Verification: FALSE POSITIVE", detail: `Removed ${httpCreds.length} false positive(s)` });
        }
      } catch { /* non-fatal */ }
    }
  } catch (e: any) {
    addLog(state, { phase: "vuln_detection", type: "error", title: "Credential Testing Error", detail: e.message });
  }

  // Recalculate stats
  state.stats.vulnsFound = state.assets.reduce((sum: number, a: any) => sum + a.vulns.length, 0);
  state.stats.portsFound = state.assets.reduce((sum: number, a: any) => sum + a.ports.length, 0);

  return result;
}
