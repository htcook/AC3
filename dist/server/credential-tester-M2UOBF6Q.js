import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/vuln-detection/credential-tester.ts
async function checkPortReachable(host, port, timeoutMs = 5e3) {
  const netMod = await import("net");
  return new Promise((resolve) => {
    const sock = new netMod.default.Socket();
    sock.setTimeout(timeoutMs);
    sock.once("connect", () => {
      sock.destroy();
      resolve(true);
    });
    sock.once("timeout", () => {
      sock.destroy();
      resolve(false);
    });
    sock.once("error", () => {
      sock.destroy();
      resolve(false);
    });
    sock.connect(port, host);
  });
}
async function verifyHttpCredentials(asset, execTool, engagementId) {
  const httpCreds = (asset.confirmedCredentials || []).filter(
    (c) => c.source === "hydra" && (c.service === "http-get" || c.service === "https-get")
  );
  if (httpCreds.length === 0) return { isValid: true, baselineResp: "", authResp: "" };
  const scheme = httpCreds[0].service === "https-get" ? "https" : "http";
  const verifyTarget = asset.hostname || asset.ip;
  const verifyUrl = `${scheme}://${verifyTarget}:${httpCreds[0].port}/`;
  const baselineResult = await execTool({
    tool: "curl",
    args: `-s -o /dev/null -w '%{http_code}:%{size_download}' --connect-timeout 5 --max-time 10 -L ${verifyUrl}`,
    target: verifyTarget,
    timeoutSeconds: 30,
    engagementId
  });
  const authResult = await execTool({
    tool: "curl",
    args: `-s -o /dev/null -w '%{http_code}:%{size_download}' --connect-timeout 5 --max-time 10 -L -u '${httpCreds[0].username}:${httpCreds[0].password}' ${verifyUrl}`,
    target: verifyTarget,
    timeoutSeconds: 30,
    engagementId
  });
  const baselineResp = baselineResult.stdout.trim();
  const authResp = authResult.stdout.trim();
  return { isValid: baselineResp !== authResp, baselineResp, authResp };
}
function storeOemFallback(asset, cmdArgs) {
  const oemUserMatch = cmdArgs.match(/-l\s+'([^']+)'/);
  const oemPassMatch = cmdArgs.match(/-p\s+'([^']+)'/);
  const oemPortMatch = cmdArgs.match(/-s\s+(\d+)/);
  if (!oemUserMatch || !oemPassMatch) return false;
  if (!Array.isArray(asset.confirmedCredentials)) asset.confirmedCredentials = [];
  const oemUser = oemUserMatch[1];
  const oemPass = oemPassMatch[1];
  const exists = asset.confirmedCredentials.some((c) => c.username === oemUser && c.password === oemPass);
  if (exists) return false;
  asset.confirmedCredentials.push({
    username: oemUser,
    password: oemPass,
    service: "http-form",
    port: oemPortMatch ? parseInt(oemPortMatch[1]) : 80,
    protocol: "http",
    accessLevel: "unconfirmed",
    source: "oem_default_fallback",
    confirmedAt: Date.now()
  });
  return true;
}
async function executeCredentialTesting(ctx) {
  const { state, addLog, genId, isInRoeScope, requestApproval, executeToolViaQueue, persistScanResult, parseToolOutput, getEffectiveTarget, fmtTarget, pushVulnDeduped } = ctx;
  const result = { credentialsConfirmed: 0, testsExecuted: 0, testsSkipped: 0, falsePositivesEliminated: 0, oemFallbacksStored: 0, servicesTested: 0, attemptsTotal: 0 };
  addLog(state, { phase: "vuln_detection", type: "info", title: "\u{1F511} Credential Testing", detail: "Testing vendor/OEM default credentials first, then common wordlists on discovered login services" });
  try {
    const { suggestToolCommands: suggestCred } = await import("./scan-server-executor-6TKRZBDI.js");
    const roeScope = [...state.roeScopeGuard?.authorizedDomains || [], ...state.roeScopeGuard?.authorizedIps || []];
    const execToolCred = (config) => executeToolViaQueue(config, { engagementId: state.engagementId, roeScope });
    const hydraAlreadyDone = state.completedScans.hydraCompleted.size;
    if (hydraAlreadyDone > 0) {
      addLog(state, { phase: "vuln_detection", type: "info", title: "\u{1F504} Resume: Hydra Checkpoint", detail: `Skipping ${hydraAlreadyDone} already-completed credential test(s)` });
      result.testsSkipped += hydraAlreadyDone;
    }
    for (const asset of state.assets) {
      if (asset.ports.length === 0) continue;
      if (!isInRoeScope(state, asset.hostname, asset.ip)) continue;
      const techList = (asset.passiveRecon?.technologies || []).map((t) => {
        const parts = t.split(/[\s\/]+/);
        return { name: t, vendor: parts[0], version: parts.length > 1 ? parts[parts.length - 1] : void 0 };
      });
      for (const p of asset.ports) {
        if (p.version) techList.push({ name: `${p.service} ${p.version}`, vendor: p.version.split(/[\s\/]+/)[0], version: p.version, port: p.port, protocol: p.service });
      }
      const credCmds = (await suggestCred({ hostname: asset.hostname, ip: asset.ip, type: asset.type, ports: asset.ports, technologies: techList.length > 0 ? techList : void 0 })).filter((c) => c.priority === 3);
      result.servicesTested += credCmds.length;
      for (const cmd of credCmds) {
        const hydraKey = `${cmd.tool}:${getEffectiveTarget(asset, "metadata")}:${cmd.purpose}`;
        if (state.completedScans.hydraCompleted.has(hydraKey)) {
          result.testsSkipped++;
          continue;
        }
        const approved = await requestApproval(state, { phase: "vuln_detection", riskTier: "orange", title: `Credential Test: ${cmd.purpose}`, description: `Running ${cmd.tool} against ${asset.hostname} for ${cmd.purpose}`, target: asset.hostname, module: cmd.tool, detail: { tool: cmd.tool, args: cmd.args, purpose: cmd.purpose } });
        if (!approved) {
          result.testsSkipped++;
          continue;
        }
        if (cmd.tool === "hydra") {
          const portMatch = cmd.args.match(/-s\s+(\d+)/);
          const targetPort = portMatch ? Number(portMatch[1]) : cmd.args.includes("ssh") ? 22 : 80;
          const targetHost = getEffectiveTarget(asset, "discovery");
          const reachable = await checkPortReachable(targetHost, targetPort);
          if (!reachable) {
            addLog(state, { phase: "vuln_detection", type: "warning", title: `\u23ED\uFE0F Skipped: ${cmd.tool} (port ${targetPort} unreachable)`, detail: `Pre-flight TCP check failed for ${targetHost}:${targetPort}` });
            result.testsSkipped++;
            continue;
          }
        }
        addLog(state, { phase: "vuln_detection", type: "scan_start", title: `Running: ${cmd.tool}`, detail: cmd.purpose, data: { tool: cmd.tool, fullCommand: `${cmd.tool} ${cmd.args}` } });
        try {
          const toolResult = await execToolCred({ tool: cmd.tool, args: cmd.args, target: getEffectiveTarget(asset, "discovery"), timeoutSeconds: 120, engagementId: state.engagementId });
          if (toolResult.stdout && toolResult.stdout.length > 1e5) toolResult.stdout = toolResult.stdout.slice(0, 1e5);
          if (toolResult.stderr && toolResult.stderr.length > 5e4) toolResult.stderr = toolResult.stderr.slice(0, 5e4);
          const findings = parseToolOutput(cmd.tool, toolResult.stdout, asset);
          result.attemptsTotal++;
          for (const f of findings) {
            if (pushVulnDeduped(asset, { id: genId(), severity: f.severity, title: f.title, cve: f.cve, description: f.description, corroborationTier: "confirmed", evidenceDetail: `Confirmed by ${cmd.tool}`, rawEvidence: f.evidence ? JSON.stringify(f.evidence).slice(0, 4e3) : void 0, source: cmd.tool })) {
              state.stats.vulnsFound++;
              result.credentialsConfirmed++;
            }
          }
          asset.toolResults.push({ tool: cmd.tool, command: `${cmd.tool} ${cmd.args}`, exitCode: toolResult.exitCode, durationMs: toolResult.durationMs, timedOut: toolResult.timedOut, findingCount: findings.length, findings: findings.map((f) => ({ severity: f.severity, title: f.title })), outputPreview: toolResult.stdout.slice(0, 512), executedAt: Date.now(), phase: "credential_testing" });
          if (cmd.tool === "hydra" && toolResult.exitCode === 255 && cmd.purpose.includes("[OEM Default]")) {
            if (storeOemFallback(asset, cmd.args)) result.oemFallbacksStored++;
          } else {
            addLog(state, { phase: "vuln_detection", type: "scan_result", title: `${cmd.tool} Complete: ${fmtTarget(asset)}`, detail: `${findings.length} findings, exit code ${toolResult.exitCode}` });
          }
          await persistScanResult({ engagementId: state.engagementId, tool: cmd.tool, target: getEffectiveTarget(asset, "metadata"), command: `${cmd.tool} ${cmd.args}`, stdout: toolResult.stdout, stderr: toolResult.stderr, exitCode: toolResult.exitCode, durationMs: toolResult.durationMs, timedOut: toolResult.timedOut, findings, phase: "credential_testing" });
          state.completedScans.hydraCompleted.add(hydraKey);
          state.completedScans.lastCheckpointAt = Date.now();
          result.testsExecuted++;
        } catch (e) {
          state.completedScans.hydraCompleted.add(hydraKey);
          state.completedScans.lastCheckpointAt = Date.now();
          addLog(state, { phase: "vuln_detection", type: "error", title: `${cmd.tool} Error: ${asset.hostname}`, detail: e.message });
        }
      }
    }
    for (const asset of state.assets) {
      const httpCreds = (asset.confirmedCredentials || []).filter((c) => c.source === "hydra" && (c.service === "http-get" || c.service === "https-get"));
      if (httpCreds.length === 0) continue;
      try {
        const { isValid } = await verifyHttpCredentials(asset, execToolCred, state.engagementId);
        if (!isValid) {
          asset.confirmedCredentials = (asset.confirmedCredentials || []).filter((c) => !(c.source === "hydra" && (c.service === "http-get" || c.service === "https-get")));
          for (const vuln of asset.vulns) {
            if (vuln.title?.includes("[Hydra]") && vuln.title?.includes("http-get")) {
              vuln.severity = "info";
              vuln.title = vuln.title.replace("[Hydra] Valid credentials found:", "[Hydra] FALSE POSITIVE:");
              vuln.corroborationTier = "unverified";
            }
          }
          result.falsePositivesEliminated += httpCreds.length;
          addLog(state, { phase: "vuln_detection", type: "llm_decision", title: "\u26A0\uFE0F HTTP Credential Verification: FALSE POSITIVE", detail: `Removed ${httpCreds.length} false positive(s)` });
        }
      } catch {
      }
    }
  } catch (e) {
    addLog(state, { phase: "vuln_detection", type: "error", title: "Credential Testing Error", detail: e.message });
  }
  state.stats.vulnsFound = state.assets.reduce((sum, a) => sum + a.vulns.length, 0);
  state.stats.portsFound = state.assets.reduce((sum, a) => sum + a.ports.length, 0);
  return result;
}
var init_credential_tester = __esm({
  "server/lib/vuln-detection/credential-tester.ts"() {
  }
});
init_credential_tester();
export {
  checkPortReachable,
  executeCredentialTesting,
  storeOemFallback,
  verifyHttpCredentials
};
