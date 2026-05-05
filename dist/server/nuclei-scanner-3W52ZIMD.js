import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/vuln-detection/nuclei-scanner.ts
function buildTechTags(detectedTechs) {
  const techTags = [];
  const techLower = detectedTechs.map((t) => t.toLowerCase());
  for (const { match, tag } of TAG_MAPPINGS) {
    if (techLower.some((t) => t.includes(match)) && !techTags.includes(tag)) {
      techTags.push(tag);
    }
  }
  return techTags;
}
function isTrainingLabTarget(hostname, trainingLabMode) {
  if (trainingLabMode) return true;
  const lower = hostname.toLowerCase();
  return TRAINING_LAB_INDICATORS.some((lab) => lower.includes(lab));
}
function buildNucleiArgs(config) {
  const { url, techTags, isTrainingLab, rateLimit, authHeaderArg, evasionHeaders } = config;
  const tagArgs = techTags.length > 0 ? `-tags ${techTags.join(",")}` : "";
  const severityArg = isTrainingLab ? "-severity critical,high,medium,low" : "-severity critical,high,medium";
  const timeoutArg = isTrainingLab ? "-timeout 15" : "-timeout 10";
  return `-u ${url} ${severityArg} ${tagArgs} -jsonl -nc -duc -ni ${timeoutArg} -retries 1 -rate-limit ${rateLimit}${authHeaderArg}${evasionHeaders}`;
}
function getEvasionConfig(targetProfile, baseRateLimit) {
  let rateLimit = baseRateLimit;
  let evasionHeaders = "";
  if (!targetProfile) return { rateLimit, evasionHeaders };
  const esc = targetProfile.evasionEscalation;
  if (esc && esc.currentLevel > 1) {
    const ep = targetProfile.recommendedStrategy?.evasionProfile;
    if (ep) {
      rateLimit = Math.min(rateLimit, ep.rateLimit);
      if (ep.headerManipulation) {
        for (const [k, v] of Object.entries(ep.headerManipulation)) {
          evasionHeaders += ` -H "${k}: ${v}"`;
        }
      }
      if (ep.userAgentStrategy === "browser_mimic") {
        evasionHeaders += ` -H "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36"`;
      }
    }
  }
  return { rateLimit, evasionHeaders };
}
function getAuthHeaderArg(asset) {
  const assetCreds = (asset.confirmedCredentials || []).filter(
    (c) => ["http", "web", "form", "http-get", "http-post-form"].includes(c.service)
  );
  if (assetCreds.length > 0 && assetCreds[0].sessionCookie) {
    return ` -H "Cookie: ${assetCreds[0].sessionCookie}"`;
  }
  if (asset.trainingLabCreds?.sessionCookie) {
    return ` -H "Cookie: ${asset.trainingLabCreds.sessionCookie}"`;
  }
  return "";
}
function buildExistingVulnKeys(assets) {
  const keys = /* @__PURE__ */ new Map();
  for (const asset of assets) {
    const set = /* @__PURE__ */ new Set();
    for (const v of asset.vulns) {
      set.add(`${v.severity}::${v.title}::${v.cve || ""}`);
    }
    keys.set(asset.hostname, set);
  }
  return keys;
}
async function executeNucleiWithRetry(executeTool, nucleiArgs, target, engagementId, maxRetries = 2, addLog) {
  for (let attempt = 0; attempt <= maxRetries; attempt++) {
    const result = await executeTool({
      tool: "nuclei",
      args: nucleiArgs,
      target,
      timeoutSeconds: 300,
      engagementId
    });
    const isSSHFailure = result.exitCode === -1 && !result.stdout && result.durationMs < 2e4;
    if (isSSHFailure && attempt < maxRetries) {
      if (addLog) {
        addLog({
          phase: "vuln_detection",
          type: "warning",
          title: `Nuclei SSH retry (attempt ${attempt + 2}/${maxRetries + 1})`,
          detail: `SSH connection failed for ${target}. Retrying after 3s cooldown...`
        });
      }
      await new Promise((r) => setTimeout(r, 3e3));
      continue;
    }
    return result;
  }
  return { stdout: "", stderr: "All retries exhausted", exitCode: -1, durationMs: 0, timedOut: false, error: "All retries exhausted" };
}
async function applyMemoryBackpressure(heapLimitMB = 768) {
  const mem = process.memoryUsage();
  const heapMB = mem.heapUsed / 1024 / 1024;
  if (heapMB > heapLimitMB * 0.6) {
    console.warn(`[MemoryBackpressure] Heap at ${heapMB.toFixed(0)}MB/${heapLimitMB}MB \u2014 pausing 2s`);
    await new Promise((r) => setTimeout(r, 2e3));
    if (global.gc) global.gc();
    return true;
  }
  return false;
}
function resolveTrainingLabZapUrl(hostname, trainingLabMode) {
  if (!trainingLabMode) return null;
  return TRAINING_LAB_ZAP_URL_MAP[hostname.toLowerCase()] || null;
}
async function executeNucleiScanning(ctx) {
  const {
    state,
    addLog,
    executeToolViaQueue,
    acquireScanSlot,
    persistScanResult,
    persistOpsStateDebounced,
    parseToolOutput,
    genId,
    broadcastReconFinding,
    broadcastOpsUpdate,
    isInRoeScope,
    getEffectiveTarget,
    getScanConcurrencyMetrics,
    getEngagementAbortSignal,
    executeScanForgePhase
  } = ctx;
  const result = {
    findingsCount: 0,
    errorsCount: 0,
    assetsScanned: 0,
    networkScansRun: 0,
    scanforgeResult: null
  };
  const nucleiAssets = state.assets.filter(
    (a) => a.ports.length > 0 && isInRoeScope(state, a.hostname, a.ip)
  );
  result.assetsScanned = nucleiAssets.length;
  if (nucleiAssets.length === 0) {
    addLog(state, { phase: "vuln_detection", type: "info", title: "Nuclei: No eligible targets", detail: "No assets with open ports within RoE scope" });
    return result;
  }
  const existingVulnKeys = buildExistingVulnKeys(state.assets);
  const baseRateLimit = state.engagementType === "red_team" ? 50 : 150;
  const nucleiScanTasks = [];
  for (const asset of nucleiAssets) {
    const target = getEffectiveTarget(asset, "http");
    const webPorts = asset.ports.filter(
      (p) => (["http", "https", "http-proxy", "http-alt"].includes(p.service) || [80, 443, 8080, 8443, 8e3, 3e3, 5e3].includes(p.port)) && !NUCLEI_INFRA_PORTS.has(p.port)
    );
    const nucleiTargetUrls = webPorts.length > 0 ? webPorts.map((p) => {
      const scheme = p.port === 443 || p.port === 8443 ? "https" : "http";
      return `${scheme}://${asset.hostname}:${p.port}`;
    }) : [`http://${asset.hostname}`, `https://${asset.hostname}`];
    const techTags = buildTechTags(asset.passiveRecon?.technologies || []);
    try {
      const { getServiceBasedTags } = await import("./service-template-mapper-PFXGSFMH.js");
      const fpResults = asset.fingerprintResults;
      if (fpResults?.length > 0) {
        const { tags: serviceTags } = getServiceBasedTags(fpResults);
        for (const tag of serviceTags) {
          if (!techTags.includes(tag)) techTags.push(tag);
        }
      }
    } catch {
    }
    const vulnTargetProfile = state.targetProfiles?.[asset.hostname];
    if (vulnTargetProfile) {
      const fp = vulnTargetProfile.fingerprint;
      if (fp?.cms?.name) {
        const cmsTag = fp.cms.name.toLowerCase().replace(/\s+/g, "-");
        if (!techTags.includes(cmsTag)) techTags.push(cmsTag);
      }
      if (fp?.appFramework?.name) {
        const fwTag = fp.appFramework.name.toLowerCase().replace(/[\s.]+/g, "-");
        if (!techTags.includes(fwTag)) techTags.push(fwTag);
      }
      if (vulnTargetProfile.waf?.detected) {
        if (!techTags.includes("waf-detect")) techTags.push("waf-detect");
        if (!techTags.includes("waf-bypass")) techTags.push("waf-bypass");
      }
      if (vulnTargetProfile.environment === "cloud" && !techTags.includes("cloud")) {
        techTags.push("cloud");
      }
    }
    const isTrainingLab = isTrainingLabTarget(asset.hostname, state.trainingLabMode === true);
    if (isTrainingLab) {
      for (const tag of TRAINING_LAB_VULN_TAGS) {
        if (!techTags.includes(tag)) techTags.push(tag);
      }
    }
    const evasion = getEvasionConfig(vulnTargetProfile, baseRateLimit);
    const authHeaderArg = getAuthHeaderArg(asset);
    const assetVulnKeys = existingVulnKeys.get(asset.hostname) || /* @__PURE__ */ new Set();
    for (const url of nucleiTargetUrls) {
      if (state.completedScans?.nucleiCompleted.has(url)) continue;
      const nucleiArgs = buildNucleiArgs({ url, techTags, isTrainingLab, rateLimit: evasion.rateLimit, authHeaderArg, evasionHeaders: evasion.evasionHeaders });
      nucleiScanTasks.push({ asset, url, nucleiArgs, target, techTags, assetVulnKeys });
    }
  }
  const NUCLEI_BATCH_SIZE = 2;
  const concurrencyMetrics = getScanConcurrencyMetrics();
  const alreadyCompleted = state.completedScans?.nucleiCompleted.size || 0;
  addLog(state, {
    phase: "vuln_detection",
    type: "info",
    title: `\u26A1 Parallel Nuclei: ${nucleiScanTasks.length} scans across ${nucleiAssets.length} assets${alreadyCompleted > 0 ? ` (${alreadyCompleted} resumed)` : ""}`,
    detail: `Concurrency: ${concurrencyMetrics.activeTotal} active, batch=${NUCLEI_BATCH_SIZE}`
  });
  const roeScope = [...state.roeScopeGuard?.authorizedDomains || [], ...state.roeScopeGuard?.authorizedIps || []];
  const abortSignal = getEngagementAbortSignal(state.engagementId);
  const executeTool = (config) => executeToolViaQueue(config, { engagementId: state.engagementId, roeScope, engagementAbortSignal: abortSignal });
  async function executeNucleiTask(task) {
    const { asset, url, nucleiArgs, target, techTags, assetVulnKeys } = task;
    let release = null;
    try {
      release = await acquireScanSlot("nuclei", state.engagementId);
      if (state._heartbeatRef) state._heartbeatRef.lastActivityAt = Date.now();
      addLog(state, {
        phase: "vuln_detection",
        type: "scan_start",
        title: `Nuclei: ${url}`,
        detail: `Scanning${techTags.length > 0 ? ` (tags: ${techTags.join(", ")})` : " (broad)"}`
      });
      const execResult = await executeNucleiWithRetry(executeTool, nucleiArgs, target, state.engagementId, 2, (entry) => addLog(state, entry));
      if (state._heartbeatRef) state._heartbeatRef.lastActivityAt = Date.now();
      if (execResult.stdout?.length > 1e5) execResult.stdout = execResult.stdout.slice(0, 1e5);
      if (execResult.stderr?.length > 5e4) execResult.stderr = execResult.stderr.slice(0, 5e4);
      if (execResult.exitCode === -1 && !execResult.stdout) {
        result.errorsCount++;
        addLog(state, { phase: "vuln_detection", type: "warning", title: `Nuclei Failed: ${url}`, detail: `SSH failed. Error: ${execResult.error || "timeout"}` });
      }
      const findings = parseToolOutput("nuclei", execResult.stdout, asset);
      let newFindings = 0;
      for (const f of findings) {
        const key = `${f.severity}::${f.title}::${f.cve || ""}`;
        if (!assetVulnKeys.has(key)) {
          asset.vulns.push({
            id: genId(),
            severity: f.severity,
            title: f.title,
            cve: f.cve,
            description: f.description,
            cvss: f.cvss,
            cwe: f.cwe,
            source: "nuclei",
            corroborationTier: "confirmed",
            evidenceDetail: "Confirmed by nuclei scan",
            rawEvidence: f.evidence ? JSON.stringify(f.evidence).slice(0, 4e3) : void 0
          });
          assetVulnKeys.add(key);
          state.stats.vulnsFound++;
          newFindings++;
        }
      }
      result.findingsCount += newFindings;
      const nucleiCmd = `nuclei ${nucleiArgs}`;
      asset.toolResults.push({
        tool: "nuclei",
        command: nucleiCmd,
        exitCode: execResult.exitCode,
        durationMs: execResult.durationMs,
        timedOut: execResult.timedOut,
        findingCount: findings.length,
        findings: findings.map((f) => ({
          severity: f.severity,
          title: f.title,
          cve: f.cve,
          evidence: f.evidence?.proofText,
          attack: f.evidence?.attackPayload,
          method: f.evidence?.request?.method,
          url: f.evidence?.request?.url,
          param: f.evidence?.vulnerableParam,
          matchedPattern: f.evidence?.matchedPattern
        })),
        outputPreview: execResult.stdout.slice(0, 512),
        executedAt: Date.now(),
        phase: "vuln_detection"
      });
      addLog(state, {
        phase: "vuln_detection",
        type: "scan_result",
        title: `Nuclei Complete: ${url}`,
        detail: `${newFindings} new findings, exit ${execResult.exitCode}, ${execResult.durationMs}ms${execResult.timedOut ? " (TIMED OUT)" : ""}`
      });
      await persistScanResult({
        engagementId: state.engagementId,
        tool: "nuclei",
        target: url,
        command: nucleiCmd,
        stdout: execResult.stdout,
        stderr: execResult.stderr,
        exitCode: execResult.exitCode,
        durationMs: execResult.durationMs,
        timedOut: execResult.timedOut,
        findings,
        phase: "vuln_detection"
      });
      if (state.completedScans) {
        state.completedScans.nucleiCompleted.add(url);
        state.completedScans.lastCheckpointAt = Date.now();
      }
    } catch (e) {
      result.errorsCount++;
      addLog(state, { phase: "vuln_detection", type: "error", title: `Nuclei Error: ${url}`, detail: e.message });
      if (state.completedScans) {
        state.completedScans.nucleiCompleted.add(url);
        state.completedScans.lastCheckpointAt = Date.now();
      }
    } finally {
      if (release) release();
    }
  }
  for (let i = 0; i < nucleiScanTasks.length; i += NUCLEI_BATCH_SIZE) {
    const batch = nucleiScanTasks.slice(i, i + NUCLEI_BATCH_SIZE);
    if (state._heartbeatRef) state._heartbeatRef.lastActivityAt = Date.now();
    await Promise.allSettled(batch.map((task) => executeNucleiTask(task)));
    if (state._heartbeatRef) state._heartbeatRef.lastActivityAt = Date.now();
    persistOpsStateDebounced(state.engagementId, 200);
    try {
      const { midScanCleanup } = await import("./memory-manager-VARXZ63M.js");
      midScanCleanup(state);
    } catch {
      if (global.gc) global.gc();
    }
    await applyMemoryBackpressure();
  }
  addLog(state, {
    phase: "vuln_detection",
    type: "scan_result",
    title: "Nuclei Scan Complete",
    detail: `${result.findingsCount} new vulns across ${nucleiAssets.length} targets${result.errorsCount > 0 ? ` (${result.errorsCount} failed)` : ""}. Total: ${state.stats.vulnsFound}`
  });
  for (const asset of nucleiAssets) {
    for (const v of asset.vulns || []) {
      broadcastReconFinding(state.engagementId, {
        target: asset.hostname || asset.ip,
        vulnerability: v.title || v.id,
        cve: v.cve,
        severity: v.severity || "info",
        port: v.port,
        tool: "nuclei"
      });
    }
  }
  try {
    const { generateServiceScanTasks, getTemplateMappingSummary } = await import("./service-template-mapper-PFXGSFMH.js");
    const networkScanTasks = [];
    for (const asset of nucleiAssets) {
      const fpResults = asset.fingerprintResults;
      if (!fpResults?.length) continue;
      const nonHttpFps = fpResults.filter(
        (fp) => !fp.error && fp.protocol && !["http", "https", "http-proxy", "http-alt"].includes(fp.protocol) && ![80, 443, 8080, 8443, 8e3, 3e3, 5e3].includes(fp.port)
      );
      if (nonHttpFps.length === 0) continue;
      const target = getEffectiveTarget(asset, "discovery");
      const serviceTasks = generateServiceScanTasks(target, nonHttpFps, { rateLimit: baseRateLimit, maxTasks: 10 });
      const assetVulnKeys = existingVulnKeys.get(asset.hostname) || /* @__PURE__ */ new Set();
      for (const st of serviceTasks) {
        const networkUrl = `${target}:${st.port}/${st.protocol}`;
        if (state.completedScans?.nucleiCompleted.has(networkUrl)) continue;
        networkScanTasks.push({ asset, url: networkUrl, nucleiArgs: st.nucleiArgs, target, techTags: st.mapping.tags, assetVulnKeys });
      }
    }
    if (networkScanTasks.length > 0) {
      result.networkScansRun = networkScanTasks.length;
      addLog(state, { phase: "vuln_detection", type: "info", title: `\u{1F50C} Network Nuclei: ${networkScanTasks.length} service scans`, detail: "Non-HTTP services via fingerprint-based templates" });
      for (let i = 0; i < networkScanTasks.length; i += NUCLEI_BATCH_SIZE) {
        const batch = networkScanTasks.slice(i, i + NUCLEI_BATCH_SIZE);
        if (state._heartbeatRef) state._heartbeatRef.lastActivityAt = Date.now();
        await Promise.allSettled(batch.map((task) => executeNucleiTask(task)));
        persistOpsStateDebounced(state.engagementId, 200);
        try {
          const { midScanCleanup } = await import("./memory-manager-VARXZ63M.js");
          midScanCleanup(state);
        } catch {
          if (global.gc) global.gc();
        }
      }
      addLog(state, { phase: "vuln_detection", type: "scan_result", title: "Network Nuclei Complete", detail: `${networkScanTasks.length} tasks. Total vulns: ${state.stats.vulnsFound}` });
    }
  } catch (err) {
    addLog(state, { phase: "vuln_detection", type: "warning", title: "Network Nuclei Skipped", detail: err.message });
  }
  if (state.trainingLabMode === true) {
    const broadTasks = [];
    for (const asset of nucleiAssets) {
      const webPorts = asset.ports.filter(
        (p) => ["http", "https", "http-proxy", "http-alt"].includes(p.service) || [80, 443, 8080, 8443, 8e3, 3e3, 5e3].includes(p.port)
      );
      const urls = webPorts.length > 0 ? webPorts.map((p) => `${p.port === 443 || p.port === 8443 ? "https" : "http"}://${asset.hostname}:${p.port}`) : [`http://${asset.hostname}`, `https://${asset.hostname}`];
      const assetVulnKeys = existingVulnKeys.get(asset.hostname) || /* @__PURE__ */ new Set();
      const target = getEffectiveTarget(asset, "http");
      for (const url of urls) {
        broadTasks.push({ asset, url, nucleiArgs: `-u ${url} -severity critical,high -jsonl -nc -duc -ni -timeout 15 -retries 1 -rate-limit 150`, target, techTags: [], assetVulnKeys });
      }
    }
    if (broadTasks.length > 0) {
      addLog(state, { phase: "vuln_detection", type: "info", title: "\u{1F3AF} Training Lab Broad Scan", detail: `${broadTasks.length} scans without tag filter` });
      for (let i = 0; i < broadTasks.length; i += NUCLEI_BATCH_SIZE) {
        await Promise.allSettled(broadTasks.slice(i, i + NUCLEI_BATCH_SIZE).map((t) => executeNucleiTask(t)));
        persistOpsStateDebounced(state.engagementId, 500);
        try {
          const { midScanCleanup } = await import("./memory-manager-VARXZ63M.js");
          midScanCleanup(state);
        } catch {
          if (global.gc) global.gc();
        }
      }
      addLog(state, { phase: "vuln_detection", type: "scan_result", title: "Broad Scan Complete", detail: `Total vulns: ${state.stats.vulnsFound}` });
    }
  }
  if (executeScanForgePhase) {
    try {
      const sfTargets = state.assets.filter((a) => a.status !== "pending").map((a) => ({
        url: a.ports.some((p) => [80, 443, 8080, 8443].includes(p.port)) ? `${a.ports.some((p) => p.port === 443) ? "https" : "http"}://${a.hostname}` : `http://${a.hostname}`,
        ip: a.ip,
        hostname: a.hostname,
        isInternal: (a.hostname.endsWith(".internal") || a.hostname.endsWith(".local") || a.hostname.includes(".lab.")) && !a.hostname.includes("aceofcloud.io") && !a.hostname.includes("aceofcloud.com"),
        technologies: a.passiveRecon?.technologies || [],
        credentials: (a.confirmedCredentials || []).length > 0 ? (a.confirmedCredentials || []).map((c) => ({ username: c.username, password: c.password, service: c.service || "http", source: c.source || "hydra", loginPath: c.loginPath, confirmedAt: c.confirmedAt ? new Date(c.confirmedAt).getTime() : Date.now() })) : void 0
      }));
      if (sfTargets.length > 0) {
        const targetsWithCreds = sfTargets.filter((t) => t.credentials?.length > 0);
        addLog(state, { phase: "vuln_detection", type: "scan_start", title: "ScanForge Engine Starting", detail: `${sfTargets.length} targets` });
        const sfResult = await executeScanForgePhase(
          {
            engagementId: String(state.engagementId),
            targets: sfTargets,
            scope: (state.roeScopeGuard?.authorizedDomains || []).join(", "),
            targetType: state.engagementType === "red_team" ? "network" : "web_app",
            enableProofVerification: true,
            enableEmberRouting: sfTargets.some((t) => t.isInternal),
            enableAuthenticatedScanning: targetsWithCreds.length > 0,
            maxConcurrency: 5,
            timeoutPerTarget: 3e4
          },
          (entry) => addLog(state, { ...entry, phase: entry.phase || "vuln_detection", type: entry.type || "info" }),
          (finding) => {
            const asset = state.assets.find((a) => finding.target.includes(a.hostname));
            if (asset) {
              const exists = asset.vulns.some((v) => v.title.toLowerCase() === finding.title.toLowerCase() || v.cve && v.cve === finding.cve);
              if (!exists) {
                asset.vulns.push({
                  id: `sf-${finding.templateId}-${Date.now()}`,
                  severity: finding.severity,
                  title: `[ScanForge] ${finding.title}`,
                  cve: finding.cve,
                  description: finding.description,
                  cvss: finding.cvss,
                  cwe: finding.cwe,
                  evidence: finding.evidence,
                  source: "scanforge",
                  corroborationTier: "confirmed",
                  evidenceDetail: "Confirmed by ScanForge reasoning pipeline",
                  rawEvidence: finding.evidence ? (typeof finding.evidence === "string" ? finding.evidence : JSON.stringify(finding.evidence)).slice(0, 4e3) : void 0
                });
                state.stats.vulnsFound++;
              }
            }
          }
        );
        result.scanforgeResult = sfResult;
        state._scanforgeResult = sfResult;
        addLog(state, { phase: "vuln_detection", type: "scan_result", title: "ScanForge Complete", detail: `${sfResult.stats.findingsTotal} findings (${sfResult.stats.findingsVerified} verified)` });
        broadcastOpsUpdate(state.engagementId, { type: "stats_update", stats: { ...state.stats } });
      }
    } catch (sfErr) {
      addLog(state, { phase: "vuln_detection", type: "warning", title: "ScanForge Error (non-fatal)", detail: sfErr.message });
    }
  }
  return result;
}
var TAG_MAPPINGS, TRAINING_LAB_VULN_TAGS, TRAINING_LAB_INDICATORS, NUCLEI_INFRA_PORTS, TRAINING_LAB_ZAP_URL_MAP;
var init_nuclei_scanner = __esm({
  "server/lib/vuln-detection/nuclei-scanner.ts"() {
    TAG_MAPPINGS = [
      { match: "wordpress", tag: "wordpress" },
      { match: "joomla", tag: "joomla" },
      { match: "drupal", tag: "drupal" },
      { match: "nginx", tag: "nginx" },
      { match: "apache", tag: "apache" },
      { match: "iis", tag: "iis" },
      { match: "php", tag: "php" },
      { match: "laravel", tag: "laravel" },
      { match: "spring", tag: "springboot" },
      { match: "tomcat", tag: "tomcat" },
      { match: "jenkins", tag: "jenkins" },
      { match: "grafana", tag: "grafana" },
      { match: "gitlab", tag: "gitlab" },
      { match: "cloudfront", tag: "aws" },
      { match: "aws", tag: "aws" },
      { match: "react", tag: "nodejs" },
      { match: "next.js", tag: "nodejs" },
      { match: "node", tag: "nodejs" }
    ];
    TRAINING_LAB_VULN_TAGS = [
      "sqli",
      "xss",
      "ssti",
      "xxe",
      "ssrf",
      "lfi",
      "rfi",
      "redirect",
      "exposure",
      "default-login",
      "ftp",
      "cve",
      "misconfig",
      "unauth",
      "injection",
      "file-inclusion",
      "traversal",
      "upload",
      "deserialization",
      "oast",
      "headless",
      "jwt",
      "idor",
      "csrf",
      "cors",
      "command-injection",
      "open-redirect",
      "ldap"
    ];
    TRAINING_LAB_INDICATORS = [
      "brokencrystals",
      "broken-crystals",
      "dvwa",
      "juiceshop",
      "juice-shop",
      "bwapp",
      "altoro",
      "hackazon",
      "testphp",
      "webgoat",
      "mutillidae",
      "bodgeit",
      "gruyere"
    ];
    NUCLEI_INFRA_PORTS = /* @__PURE__ */ new Set([1337, 31337, 8834, 9392, 5432, 3306, 27017, 6379]);
    TRAINING_LAB_ZAP_URL_MAP = {
      "juiceshop.lab.aceofcloud.io": { zapBaseUrl: "https://scan.aceofcloud.io/lab/juice-shop", skipPortScan: true },
      "altoro.lab.aceofcloud.io": { zapBaseUrl: "http://altoro.lab.aceofcloud.io/altoromutual", skipPortScan: true },
      "brokencrystals.lab.aceofcloud.io": { zapBaseUrl: "https://scan.aceofcloud.io/lab/broken-crystals", skipPortScan: true }
    };
  }
});
init_nuclei_scanner();
export {
  NUCLEI_INFRA_PORTS,
  TRAINING_LAB_INDICATORS,
  TRAINING_LAB_VULN_TAGS,
  TRAINING_LAB_ZAP_URL_MAP,
  applyMemoryBackpressure,
  buildExistingVulnKeys,
  buildNucleiArgs,
  buildTechTags,
  executeNucleiScanning,
  executeNucleiWithRetry,
  getAuthHeaderArg,
  getEvasionConfig,
  isTrainingLabTarget,
  resolveTrainingLabZapUrl
};
