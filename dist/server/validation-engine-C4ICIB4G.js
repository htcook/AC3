import "./chunk-KFQGP6VL.js";

// server/lib/validation-engine.ts
function computeCandidatePriority(candidate) {
  let score = 0;
  if (candidate.kevListed) score += 40;
  if (candidate.cvssScore) score += candidate.cvssScore / 10 * 30;
  if (candidate.msfModule) score += 15;
  if (candidate.supportsCheck) score += 10;
  score += candidate.discoveryConfidence * 5;
  return Math.round(score * 100) / 100;
}
function selectCandidates(assets, exploitCatalog, maxCandidates = 10) {
  const candidates = [];
  const cveToModules = /* @__PURE__ */ new Map();
  for (const entry of exploitCatalog) {
    const cveIds = entry.cveIds || [];
    for (const cve of cveIds) {
      const existing = cveToModules.get(cve) || [];
      existing.push(entry);
      cveToModules.set(cve, existing);
    }
  }
  for (const asset of assets) {
    if (asset.excluded) continue;
    const findings = asset.postureFindings || [];
    for (const finding of findings) {
      const cveIds = finding.cveIds || [];
      for (const cveId of cveIds) {
        const modules = cveToModules.get(cveId) || [];
        const bestModule = modules.filter((m) => m.msfModule).sort((a, b) => (b.msfRank ?? 0) - (a.msfRank ?? 0))[0];
        if (!bestModule?.msfModule && !finding.kevListed) continue;
        const ipAddress = asset.ipAddress || asset.hostname;
        if (!ipAddress) continue;
        const partial = {
          assetId: asset.id,
          hostname: asset.hostname || asset.ipAddress || "unknown",
          ipAddress: asset.ipAddress || null,
          port: finding.port || asset.port || null,
          cveId,
          kevListed: !!finding.kevListed,
          cvssScore: finding.cvssScore || null,
          source: finding.evidenceBasis || "vuln_feed",
          msfModule: bestModule?.msfModule || null,
          msfRank: bestModule?.msfRank || null,
          supportsCheck: false,
          // Will be determined at runtime
          currentRiskScore: asset.hybridRiskScore || 0,
          findingId: finding.id || `${asset.id}:${cveId}`,
          discoveryConfidence: (finding.confidence ?? asset.confidence ?? 50) / 100
        };
        const priorityScore = computeCandidatePriority(partial);
        candidates.push({
          ...partial,
          priorityScore
        });
      }
    }
  }
  const seen = /* @__PURE__ */ new Map();
  for (const c of candidates) {
    const key = `${c.assetId}:${c.cveId}`;
    const existing = seen.get(key);
    if (!existing || c.priorityScore > existing.priorityScore) {
      seen.set(key, c);
    }
  }
  return Array.from(seen.values()).sort((a, b) => b.priorityScore - a.priorityScore).slice(0, maxCandidates);
}
async function validateCandidate(candidate, msfClient, config) {
  const startTime = Date.now();
  const candidateId = `${candidate.assetId}:${candidate.cveId}`;
  if (config.scopeRestrictions.length > 0 && candidate.ipAddress) {
    const inScope = config.scopeRestrictions.some(
      (scope) => isInScope(candidate.ipAddress, scope)
    );
    if (!inScope) {
      return makeResult(candidate, candidateId, "skipped", false, null, "Target out of scope", startTime);
    }
  }
  if (!candidate.msfModule) {
    return makeResult(candidate, candidateId, "skipped", false, null, "No MSF module available", startTime);
  }
  try {
    await msfClient.ensureAuth();
    if (config.mode === "check_only" || config.mode === "auxiliary_scan") {
      return await runModuleCheck(candidate, candidateId, msfClient, config, startTime);
    }
    if (config.mode === "safe_exploit") {
      if (config.requireApproval) {
        return makeResult(candidate, candidateId, "approved_pending", false, null, "Awaiting operator approval", startTime);
      }
      return await runSafeExploit(candidate, candidateId, msfClient, config, startTime);
    }
    return makeResult(candidate, candidateId, "error", false, null, `Unknown mode: ${config.mode}`, startTime);
  } catch (err) {
    return makeResult(candidate, candidateId, "error", false, null, err.message || String(err), startTime);
  }
}
async function runModuleCheck(candidate, candidateId, msfClient, config, startTime) {
  const options = {
    RHOSTS: candidate.ipAddress || candidate.hostname
  };
  if (candidate.port) {
    options.RPORT = String(candidate.port);
  }
  try {
    const { moduleType, moduleName } = parseModulePath(candidate.msfModule);
    const checkResult = await Promise.race([
      msfClient.checkModule(moduleType, moduleName, options),
      timeout(config.timeoutPerCandidate * 1e3)
    ]);
    if (!checkResult || typeof checkResult === "string") {
      return makeResult(
        candidate,
        candidateId,
        "inconclusive",
        false,
        null,
        typeof checkResult === "string" ? checkResult : "Check timed out",
        startTime
      );
    }
    const jobId = checkResult.job_id;
    if (jobId !== void 0) {
      const output = await waitForJobCompletion(msfClient, String(jobId), config.timeoutPerCandidate);
      const isVulnerable = parseCheckOutput(output);
      const evidence = {
        target: `${candidate.ipAddress || candidate.hostname}:${candidate.port || "auto"}`,
        method: `module.check(${candidate.msfModule})`,
        finding: isVulnerable ? "Vulnerable" : output.includes("safe") || output.includes("not vulnerable") ? "Not Vulnerable" : "Inconclusive",
        confidence: isVulnerable ? 0.9 : 0.7,
        msfOutput: output.slice(0, 2e3),
        sessionObtained: false,
        sessionId: null,
        mitreId: null,
        artifacts: []
      };
      const status = isVulnerable ? "validated" : "not_vulnerable";
      const scoreAdj = isVulnerable ? computeScoreAdjustment(candidate, true) : 0;
      return {
        candidateId,
        assetId: candidate.assetId,
        cveId: candidate.cveId,
        hostname: candidate.hostname,
        msfModule: candidate.msfModule,
        mode: "check_only",
        status,
        exploitable: isVulnerable,
        rawOutput: output.slice(0, 4e3),
        evidence,
        scoreAdjustment: scoreAdj,
        durationMs: Date.now() - startTime,
        errorMessage: null,
        timestamp: /* @__PURE__ */ new Date()
      };
    }
    return makeResult(candidate, candidateId, "inconclusive", false, null, "Check returned no job ID", startTime);
  } catch (err) {
    if (config.mode === "auxiliary_scan" && err.message?.includes("check is not supported")) {
      return await runAuxiliaryScan(candidate, candidateId, msfClient, config, startTime);
    }
    return makeResult(candidate, candidateId, "error", false, null, err.message || String(err), startTime);
  }
}
async function runAuxiliaryScan(candidate, candidateId, msfClient, config, startTime) {
  const auxModule = mapToAuxiliaryScanner(candidate.msfModule);
  if (!auxModule) {
    return makeResult(
      candidate,
      candidateId,
      "skipped",
      false,
      null,
      "No auxiliary scanner available for this module",
      startTime
    );
  }
  const options = {
    RHOSTS: candidate.ipAddress || candidate.hostname
  };
  if (candidate.port) {
    options.RPORT = String(candidate.port);
  }
  try {
    const result = await Promise.race([
      msfClient.executeModule("auxiliary", auxModule, options),
      timeout(config.timeoutPerCandidate * 1e3)
    ]);
    if (!result || typeof result === "string") {
      return makeResult(
        candidate,
        candidateId,
        "inconclusive",
        false,
        null,
        "Auxiliary scan timed out",
        startTime
      );
    }
    const output = await waitForJobCompletion(msfClient, String(result.job_id), config.timeoutPerCandidate);
    const isVulnerable = parseCheckOutput(output);
    const scoreAdj = isVulnerable ? computeScoreAdjustment(candidate, true) : 0;
    const evidence = {
      target: `${candidate.ipAddress || candidate.hostname}:${candidate.port || "auto"}`,
      method: `auxiliary/${auxModule}`,
      finding: isVulnerable ? "Vulnerable (auxiliary scan)" : "Not confirmed",
      confidence: isVulnerable ? 0.75 : 0.5,
      msfOutput: output.slice(0, 2e3),
      sessionObtained: false,
      sessionId: null,
      mitreId: null,
      artifacts: []
    };
    return {
      candidateId,
      assetId: candidate.assetId,
      cveId: candidate.cveId,
      hostname: candidate.hostname,
      msfModule: candidate.msfModule,
      mode: "auxiliary_scan",
      status: isVulnerable ? "validated" : "inconclusive",
      exploitable: isVulnerable,
      rawOutput: output.slice(0, 4e3),
      evidence,
      scoreAdjustment: scoreAdj,
      durationMs: Date.now() - startTime,
      errorMessage: null,
      timestamp: /* @__PURE__ */ new Date()
    };
  } catch (err) {
    return makeResult(candidate, candidateId, "error", false, null, err.message || String(err), startTime);
  }
}
async function runSafeExploit(candidate, candidateId, msfClient, config, startTime) {
  const { moduleType, moduleName } = parseModulePath(candidate.msfModule);
  const options = {
    RHOSTS: candidate.ipAddress || candidate.hostname
  };
  if (candidate.port) {
    options.RPORT = String(candidate.port);
  }
  try {
    const result = await Promise.race([
      msfClient.executeModule(moduleType, moduleName, options),
      timeout(config.timeoutPerCandidate * 1e3)
    ]);
    if (!result || typeof result === "string") {
      return makeResult(
        candidate,
        candidateId,
        "inconclusive",
        false,
        null,
        "Exploit execution timed out",
        startTime
      );
    }
    await sleep(3e3);
    const sessions = await msfClient.listSessions();
    let sessionObtained = false;
    let sessionId = null;
    for (const [sid, session] of Object.entries(sessions)) {
      if (session.tunnel_peer?.includes(candidate.ipAddress || candidate.hostname)) {
        sessionObtained = true;
        sessionId = parseInt(sid);
        try {
          await msfClient.stopSession(sid);
        } catch {
        }
        break;
      }
    }
    if (result.job_id !== void 0) {
      try {
        await msfClient.stopJob(String(result.job_id));
      } catch {
      }
    }
    const output = sessionObtained ? `Session ${sessionId} obtained on ${candidate.ipAddress}:${candidate.port || "auto"} via ${candidate.msfModule}. Session immediately terminated.` : `Exploit executed but no session obtained. Job ID: ${result.job_id}`;
    const evidence = {
      target: `${candidate.ipAddress || candidate.hostname}:${candidate.port || "auto"}`,
      method: `safe_exploit(${candidate.msfModule})`,
      finding: sessionObtained ? "Exploitable \u2014 session obtained and terminated" : "Exploit executed, no session",
      confidence: sessionObtained ? 0.99 : 0.4,
      msfOutput: output,
      sessionObtained,
      sessionId,
      mitreId: null,
      artifacts: []
    };
    const scoreAdj = sessionObtained ? computeScoreAdjustment(candidate, true) : 0;
    return {
      candidateId,
      assetId: candidate.assetId,
      cveId: candidate.cveId,
      hostname: candidate.hostname,
      msfModule: candidate.msfModule,
      mode: "safe_exploit",
      status: sessionObtained ? "validated" : "inconclusive",
      exploitable: sessionObtained,
      rawOutput: output,
      evidence,
      scoreAdjustment: scoreAdj,
      durationMs: Date.now() - startTime,
      errorMessage: null,
      timestamp: /* @__PURE__ */ new Date()
    };
  } catch (err) {
    return makeResult(candidate, candidateId, "error", false, null, err.message || String(err), startTime);
  }
}
function computeScoreAdjustment(candidate, exploitable) {
  if (!exploitable) return 0;
  let adjustment = 5;
  if (candidate.kevListed) {
    adjustment += 10;
  }
  if (candidate.cvssScore) {
    if (candidate.cvssScore >= 9) adjustment += 10;
    else if (candidate.cvssScore >= 7) adjustment += 5;
    else if (candidate.cvssScore >= 4) adjustment += 2;
  }
  return Math.min(adjustment, 25);
}
function computeAssetValidationScore(results) {
  if (results.length === 0) return 0;
  const validated = results.filter((r) => r.status === "validated");
  const notVulnerable = results.filter((r) => r.status === "not_vulnerable");
  const total = results.filter((r) => r.status !== "skipped" && r.status !== "error");
  if (total.length === 0) return 0;
  if (validated.length === 0) {
    return Math.min(30, 10 + notVulnerable.length * 5);
  }
  const maxAdjustment = Math.max(...validated.map((r) => r.scoreAdjustment));
  const exploitRatio = validated.length / total.length;
  return Math.min(100, Math.round(30 + exploitRatio * 40 + maxAdjustment));
}
function parseModulePath(fullPath) {
  const parts = fullPath.split("/");
  const moduleType = parts[0];
  const moduleName = parts.slice(1).join("/");
  return { moduleType, moduleName };
}
function mapToAuxiliaryScanner(exploitModule) {
  const mappings = {
    // SMB
    "exploit/windows/smb/ms17_010_eternalblue": "scanner/smb/smb_ms17_010",
    "exploit/windows/smb/ms08_067_netapi": "scanner/smb/smb_ms08_067",
    // HTTP
    "exploit/multi/http/apache_mod_cgi_bash_env_exec": "scanner/http/apache_mod_cgi_bash_env",
    "exploit/unix/webapp/drupal_drupalgeddon2": "scanner/http/drupal_modules",
    // SSH
    "exploit/linux/ssh/libssh_auth_bypass": "scanner/ssh/libssh_auth_bypass"
  };
  if (mappings[exploitModule]) return mappings[exploitModule];
  const parts = exploitModule.split("/");
  if (parts.length >= 3) {
    const service = parts[2];
    const moduleName = parts[parts.length - 1];
    const scannerPatterns = [
      `scanner/${service}/${moduleName}`,
      `scanner/${service}/${service}_${moduleName}`
    ];
    return scannerPatterns[0];
  }
  return null;
}
function isInScope(target, scope) {
  if (scope === target) return true;
  if (scope.startsWith("*.")) {
    const domain = scope.slice(2);
    return target.endsWith(domain);
  }
  if (scope.includes("/")) {
    const [network, bits] = scope.split("/");
    const mask = parseInt(bits);
    if (isNaN(mask)) return false;
    const targetParts = target.split(".").map(Number);
    const networkParts = network.split(".").map(Number);
    if (targetParts.length !== 4 || networkParts.length !== 4) return false;
    const targetNum = targetParts[0] << 24 | targetParts[1] << 16 | targetParts[2] << 8 | targetParts[3];
    const networkNum = networkParts[0] << 24 | networkParts[1] << 16 | networkParts[2] << 8 | networkParts[3];
    const maskNum = ~((1 << 32 - mask) - 1);
    return (targetNum & maskNum) === (networkNum & maskNum);
  }
  return false;
}
function parseCheckOutput(output) {
  const lower = output.toLowerCase();
  if (lower.includes("is vulnerable") || lower.includes("appears to be vulnerable")) return true;
  if (lower.includes("vulnerable!") || lower.includes("[+]")) return true;
  if (lower.includes("exploitable")) return true;
  if (lower.includes("not vulnerable") || lower.includes("is not vulnerable")) return false;
  if (lower.includes("safe") || lower.includes("patched")) return false;
  if (lower.includes("[-]") && !lower.includes("[+]")) return false;
  return false;
}
async function waitForJobCompletion(msfClient, jobId, timeoutSeconds) {
  const deadline = Date.now() + timeoutSeconds * 1e3;
  let output = "";
  while (Date.now() < deadline) {
    try {
      const jobs = await msfClient.listJobs();
      if (!jobs[jobId]) {
        return output || "Job completed (no output captured)";
      }
    } catch {
    }
    await sleep(2e3);
  }
  return output || "Job timed out";
}
function makeResult(candidate, candidateId, status, exploitable, evidence, message, startTime) {
  return {
    candidateId,
    assetId: candidate.assetId,
    cveId: candidate.cveId,
    hostname: candidate.hostname,
    msfModule: candidate.msfModule,
    mode: "check_only",
    status,
    exploitable,
    rawOutput: message,
    evidence,
    scoreAdjustment: exploitable ? computeScoreAdjustment(candidate, true) : 0,
    durationMs: Date.now() - startTime,
    errorMessage: status === "error" ? message : null,
    timestamp: /* @__PURE__ */ new Date()
  };
}
function timeout(ms) {
  return new Promise((resolve) => setTimeout(() => resolve("timeout"), ms));
}
function sleep(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}
export {
  computeAssetValidationScore,
  computeCandidatePriority,
  computeScoreAdjustment,
  mapToAuxiliaryScanner,
  parseModulePath,
  selectCandidates,
  validateCandidate
};
