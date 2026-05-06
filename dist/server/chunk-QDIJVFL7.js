import {
  executeRawCommand,
  init_scan_server_executor
} from "./chunk-OR6TJBFA.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/exploit-sandbox.ts
async function captureExploitScreenshot(targetHost, targetPort, engagementId, exploitId) {
  try {
    const port = targetPort || 443;
    const protocol = [443, 8443].includes(port) ? "https" : "http";
    const portSuffix = [80, 443].includes(port) ? "" : `:${port}`;
    const url = `${protocol}://${targetHost}${portSuffix}`;
    const screenshotPath = `/tmp/screenshot_${Date.now()}_${Math.random().toString(36).slice(2, 6)}.png`;
    const chromeCmd = [
      "timeout 15",
      "chromium-browser --headless --disable-gpu --no-sandbox --disable-dev-shm-usage",
      `--screenshot=${screenshotPath}`,
      "--window-size=1280,900",
      "--hide-scrollbars",
      `"${url}"`,
      "2>/dev/null"
    ].join(" ");
    const fallbackCmd = `(which chromium-browser > /dev/null 2>&1 && ${chromeCmd}) || (which google-chrome > /dev/null 2>&1 && ${chromeCmd.replace("chromium-browser", "google-chrome")}) || (which cutycapt > /dev/null 2>&1 && timeout 15 cutycapt --url="${url}" --out=${screenshotPath} --min-width=1280 2>/dev/null) || echo "NO_SCREENSHOT_TOOL"`;
    const result = await executeRawCommand(fallbackCmd, 20);
    if (result.stdout.includes("NO_SCREENSHOT_TOOL") || result.exitCode !== 0) {
      console.log(`[ExploitScreenshot] No screenshot tool available on scan server for ${url}`);
      return null;
    }
    const catResult = await executeRawCommand(`cat ${screenshotPath} | base64 && rm -f ${screenshotPath}`, 15);
    if (!catResult.stdout || catResult.exitCode !== 0) {
      console.log(`[ExploitScreenshot] Failed to read screenshot file`);
      return null;
    }
    const { doStoragePut } = await import("./do-storage-7IGBORB7.js");
    const suffix = Math.random().toString(36).slice(2, 8);
    const key = `exploit-evidence/${engagementId || "unknown"}/${exploitId || "unknown"}-${suffix}.png`;
    const buffer = Buffer.from(catResult.stdout.trim(), "base64");
    const { url: s3Url } = await doStoragePut(key, buffer, "image/png");
    console.log(`[ExploitScreenshot] Captured screenshot for ${url} -> ${s3Url}`);
    return s3Url;
  } catch (err) {
    console.error(`[ExploitScreenshot] Failed to capture screenshot:`, err.message);
    return null;
  }
}
function classifyExploitResult(stdout, stderr, exitCode) {
  const combined = (stdout + "\n" + stderr).toLowerCase();
  const lines = stdout.split("\n").filter((l) => l.trim());
  const proofLines = [];
  const shellPatterns = [/\$\s*$/, /root@/, /uid=\d+/, /whoami/, /shell.*obtained/i, /reverse.*shell/i, /bind.*shell/i, /meterpreter/i];
  for (const line of lines) {
    if (shellPatterns.some((p) => p.test(line))) proofLines.push(line);
  }
  if (proofLines.length > 0 || combined.includes("shell obtained") || combined.includes("meterpreter")) {
    return { achievedAccess: "shell", resultType: "shell", shellObtained: true, proofLines };
  }
  const rcePatterns = [/command.*executed/i, /rce.*confirmed/i, /remote.*code.*execution/i, /os\.system/i, /exec\(/i];
  for (const line of lines) {
    if (rcePatterns.some((p) => p.test(line))) proofLines.push(line);
  }
  if (proofLines.length > 0) {
    return { achievedAccess: "rce", resultType: "rce", shellObtained: false, proofLines };
  }
  const credPatterns = [/password/i, /credential/i, /token/i, /api.?key/i, /secret/i, /hash.*:/i, /username.*:/i];
  for (const line of lines) {
    if (credPatterns.some((p) => p.test(line)) && !line.includes("error") && !line.includes("failed")) proofLines.push(line);
  }
  if (proofLines.length > 0) {
    return { achievedAccess: "credential", resultType: "credential", shellObtained: false, proofLines };
  }
  const filePatterns = [/file.*read/i, /directory.*listing/i, /path.*traversal/i, /lfi/i, /file.*download/i, /etc\/passwd/i];
  for (const line of lines) {
    if (filePatterns.some((p) => p.test(line))) proofLines.push(line);
  }
  if (proofLines.length > 0) {
    return { achievedAccess: "file_access", resultType: "file_access", shellObtained: false, proofLines };
  }
  const infoPatterns = [/version/i, /server.*header/i, /disclosure/i, /information.*leak/i, /internal.*ip/i, /stack.*trace/i, /debug/i, /\[info\]/i, /\[vuln\]/i, /\[found\]/i, /vulnerable/i, /detected/i];
  for (const line of lines) {
    if (infoPatterns.some((p) => p.test(line))) proofLines.push(line);
  }
  if (exitCode === 0 && proofLines.length > 0) {
    return { achievedAccess: "info_leak", resultType: "info_leak", shellObtained: false, proofLines };
  }
  if (exitCode === 0 && lines.length > 0) {
    const meaningful = lines.filter((l) => l.trim() && !l.startsWith("#") && !l.startsWith("//"));
    proofLines.push(...meaningful.slice(-5));
    return { achievedAccess: "info_leak", resultType: "info_leak", shellObtained: false, proofLines };
  }
  return { achievedAccess: "none", resultType: "none", shellObtained: false, proofLines: [] };
}
async function executeExploit(engagementId, request) {
  const {
    exploitId,
    code,
    language,
    targetHost,
    targetPort,
    timeoutSeconds = 60,
    dryRun = false
  } = request;
  const memoryLimitMb = 256;
  const cpuTimeLimitSec = 30;
  const ext = LANGUAGE_EXTENSIONS[language] || ".py";
  const interpreter = LANGUAGE_COMMANDS[language] || "python3";
  const execId = `exploit_${Date.now()}_${Math.random().toString(36).slice(2, 8)}`;
  const tmpDir = `/tmp/sandbox_${execId}`;
  const startTime = Date.now();
  if (!dryRun && (language === "python" || language === "bash" || language === "ruby")) {
    try {
      const syntaxResult = await validateExploitSyntax(code, language);
      if (!syntaxResult.valid) {
        const durationMs = Date.now() - startTime;
        const result = {
          exploitId,
          status: "error",
          exitCode: 1,
          stdout: "",
          stderr: `Pre-execution syntax validation failed:
${syntaxResult.errors.join("\n")}`,
          durationMs,
          executedAt: (/* @__PURE__ */ new Date()).toISOString(),
          language,
          dryRun: false,
          failureAnalysis: {
            category: "syntax_error",
            description: `${language} syntax validation failed before execution`,
            indicators: syntaxResult.errors,
            retryable: true,
            suggestedFix: "Fix the syntax errors and re-generate or improve the exploit code"
          }
        };
        executionHistory.push(result);
        return result;
      }
    } catch {
    }
  }
  let execCode = code;
  if (dryRun) {
    if (language === "python") {
      execCode = `# DRY RUN MODE - Syntax validation only
import sys
print("[DRY RUN] Exploit script parsed successfully")
print("[DRY RUN] Target: ${targetHost || "not specified"}:${targetPort || "not specified"}")
# Original code follows (not executed):
'''
${code}
'''
print("[DRY RUN] Validation complete - no connections made")
sys.exit(0)`;
    } else if (language === "bash") {
      execCode = `#!/bin/bash
# DRY RUN MODE
echo "[DRY RUN] Exploit script parsed successfully"
echo "[DRY RUN] Target: ${targetHost || "not specified"}:${targetPort || "not specified"}"
echo "[DRY RUN] Validation complete - no connections made"
exit 0`;
    } else if (language === "ruby") {
      execCode = `# DRY RUN MODE
puts "[DRY RUN] Exploit script parsed successfully"
puts "[DRY RUN] Target: ${targetHost || "not specified"}:${targetPort || "not specified"}"
puts "[DRY RUN] Validation complete - no connections made"
exit 0`;
    }
  }
  const preHeredoc = `mkdir -p ${tmpDir}`;
  const heredocBlock = `cat > ${tmpDir}/exploit${ext} << 'EXPLOIT_EOF'
${execCode}
EXPLOIT_EOF`;
  const postHeredoc = [
    `chmod +x ${tmpDir}/exploit${ext}`,
    `cd ${tmpDir} && ulimit -v $((${memoryLimitMb} * 1024)) -t ${cpuTimeLimitSec} -f $((10 * 1024)) 2>/dev/null; timeout ${timeoutSeconds} ${interpreter} ${tmpDir}/exploit${ext} 2>&1`,
    `rm -rf ${tmpDir}`
  ].join(" && ");
  const sandboxCmd = `${preHeredoc} && ${heredocBlock}
${postHeredoc}`;
  let dbRecordId;
  try {
    const { insertExploitationAttempt } = await import("./db-F33RXQPM.js");
    const { id } = await insertExploitationAttempt({
      engagementId,
      targetHost: targetHost || "unknown",
      targetPort: targetPort || 443,
      vulnerabilityCve: request.vulnerabilityCve,
      vulnerabilityId: request.vulnerabilityId,
      exploitSource: "custom",
      exploitModule: request.exploitModule || exploitId,
      exploitConfig: { language, dryRun, code: (code || "").slice(0, 2e3) },
      eaStatus: "running",
      eaAttackTechnique: request.attackTechnique,
      matchConfidence: request.confidence,
      eaOpsecRisk: request.opsecRisk,
      eaAttemptedAt: startTime
    });
    dbRecordId = id;
  } catch (dbErr) {
    console.error(`[ExploitSandbox] Failed to insert running record:`, dbErr.message);
  }
  try {
    const result = await executeRawCommand(sandboxCmd, timeoutSeconds + 10);
    const durationMs = Date.now() - startTime;
    const completedAt = Date.now();
    const classification = classifyExploitResult(result.stdout, result.stderr, result.exitCode);
    const evidence = {
      proofOfConcept: classification.proofLines.join("\n") || result.stdout.slice(0, 2e3),
      proofLines: classification.proofLines.slice(0, 20),
      timestamps: {
        started: new Date(startTime).toISOString(),
        completed: new Date(completedAt).toISOString(),
        durationMs
      },
      targetSnapshot: {
        host: targetHost || "unknown",
        port: targetPort || 443
      },
      achievedAccess: classification.achievedAccess,
      rawOutput: (result.stdout + (result.stderr ? "\n---STDERR---\n" + result.stderr : "")).slice(0, 5e4),
      isDryRun: dryRun
    };
    let failureAnalysis;
    if (result.exitCode !== 0 || result.timedOut) {
      try {
        const { analyzeFailure } = await import("./exploit-retry-engine-WLZO7OHT.js");
        const analysis = analyzeFailure(
          result.stdout + "\n" + result.stderr,
          result.timedOut ? "Execution timed out" : void 0
        );
        failureAnalysis = {
          category: analysis.category,
          description: analysis.description,
          indicators: analysis.indicators,
          retryable: analysis.retryable,
          retryConfidence: analysis.retryConfidence,
          suggestedAdjustments: analysis.suggestedAdjustments.slice(0, 5)
        };
      } catch (faErr) {
        console.warn(`[ExploitSandbox] Failure analysis error (non-fatal):`, faErr.message);
      }
    }
    const execResult = {
      exploitId,
      status: result.timedOut ? "timeout" : result.exitCode === 0 ? "success" : "error",
      exitCode: result.exitCode,
      stdout: result.stdout.slice(0, 1e5),
      stderr: result.stderr.slice(0, 5e4),
      durationMs,
      executedAt: new Date(startTime).toISOString(),
      language,
      dryRun,
      dbRecordId,
      evidence,
      failureAnalysis,
      sandboxInfo: {
        memoryLimitMb,
        cpuTimeLimitSec,
        timeoutSec: timeoutSeconds,
        networkRestricted: dryRun
      }
    };
    let screenshotUrls = [];
    if (result.exitCode === 0 && !dryRun && targetHost) {
      try {
        const screenshotUrl = await captureExploitScreenshot(
          targetHost,
          targetPort,
          engagementId,
          exploitId
        );
        if (screenshotUrl) {
          screenshotUrls.push(screenshotUrl);
          evidence.screenshotUrl = screenshotUrl;
        }
      } catch (ssErr) {
        console.error(`[ExploitSandbox] Screenshot capture failed (non-fatal):`, ssErr.message);
      }
    }
    if (dbRecordId) {
      try {
        const { updateExploitationAttempt } = await import("./db-F33RXQPM.js");
        await updateExploitationAttempt(dbRecordId, {
          eaStatus: result.timedOut ? "error" : result.exitCode === 0 ? "succeeded" : "failed",
          resultType: classification.resultType,
          resultOutput: (result.stdout + "\n" + result.stderr).slice(0, 1e5),
          shellObtained: classification.shellObtained ? 1 : 0,
          eaAccessLevel: classification.achievedAccess === "shell" ? "user" : classification.achievedAccess === "rce" ? "user" : "none",
          eaEvidence: evidence,
          durationMs,
          eaCompletedAt: completedAt,
          screenshotUrls: screenshotUrls.length > 0 ? screenshotUrls : void 0
        });
      } catch (dbErr) {
        console.error(`[ExploitSandbox] Failed to update DB record:`, dbErr.message);
      }
    }
    if (!executionHistory.has(engagementId)) {
      executionHistory.set(engagementId, []);
    }
    const history = executionHistory.get(engagementId);
    history.push(execResult);
    if (history.length > 50) history.splice(0, history.length - 50);
    return execResult;
  } catch (err) {
    const durationMs = Date.now() - startTime;
    let catchFailureAnalysis;
    try {
      const { analyzeFailure } = await import("./exploit-retry-engine-WLZO7OHT.js");
      const analysis = analyzeFailure(err.message || "Unknown error");
      catchFailureAnalysis = {
        category: analysis.category,
        description: analysis.description,
        indicators: analysis.indicators,
        retryable: analysis.retryable,
        retryConfidence: analysis.retryConfidence,
        suggestedAdjustments: analysis.suggestedAdjustments.slice(0, 5)
      };
    } catch {
    }
    const execResult = {
      exploitId,
      status: "error",
      exitCode: -1,
      stdout: "",
      stderr: err.message || "Unknown error",
      durationMs,
      executedAt: new Date(startTime).toISOString(),
      language,
      dryRun,
      dbRecordId,
      failureAnalysis: catchFailureAnalysis,
      sandboxInfo: {
        memoryLimitMb,
        cpuTimeLimitSec,
        timeoutSec: timeoutSeconds,
        networkRestricted: dryRun
      }
    };
    if (dbRecordId) {
      try {
        const { updateExploitationAttempt } = await import("./db-F33RXQPM.js");
        await updateExploitationAttempt(dbRecordId, {
          eaStatus: "error",
          resultType: "none",
          resultOutput: err.message || "Unknown error",
          eaEvidence: {
            proofOfConcept: "Execution failed",
            proofLines: [],
            timestamps: { started: new Date(startTime).toISOString(), completed: (/* @__PURE__ */ new Date()).toISOString(), durationMs },
            targetSnapshot: { host: targetHost || "unknown", port: targetPort || 443 },
            achievedAccess: "none",
            rawOutput: err.message || "Unknown error",
            isDryRun: dryRun
          },
          durationMs,
          eaCompletedAt: Date.now()
        });
      } catch (dbErr) {
        console.error(`[ExploitSandbox] Failed to update error record:`, dbErr.message);
      }
    }
    if (!executionHistory.has(engagementId)) {
      executionHistory.set(engagementId, []);
    }
    executionHistory.get(engagementId).push(execResult);
    return execResult;
  }
}
async function getExecutionHistory(engagementId) {
  const memHistory = executionHistory.get(engagementId);
  if (memHistory && memHistory.length > 0) return memHistory;
  try {
    const { getExploitationAttempts } = await import("./db-F33RXQPM.js");
    const dbRows = await getExploitationAttempts(engagementId);
    return dbRows.map((row) => ({
      exploitId: row.exploitModule || `db_${row.id}`,
      status: row.eaStatus === "succeeded" ? "success" : row.eaStatus === "failed" ? "error" : "error",
      exitCode: row.eaStatus === "succeeded" ? 0 : 1,
      stdout: row.resultOutput || "",
      stderr: "",
      durationMs: row.durationMs || 0,
      executedAt: row.eaCreatedAt || (/* @__PURE__ */ new Date()).toISOString(),
      language: row.exploitConfig?.language || "python",
      dryRun: row.exploitConfig?.dryRun || false,
      dbRecordId: row.id,
      evidence: row.eaEvidence,
      sandboxInfo: { memoryLimitMb: 256, cpuTimeLimitSec: 30, timeoutSec: 60, networkRestricted: false }
    }));
  } catch {
    return [];
  }
}
async function validateExploitSyntax(code, language) {
  const ext = LANGUAGE_EXTENSIONS[language] || ".py";
  const tmpFile = `/tmp/syntax_check_${Date.now()}${ext}`;
  let checkCmd;
  switch (language) {
    case "python":
      checkCmd = `cat > ${tmpFile} << 'EOF'
${code}
EOF
python3 -m py_compile ${tmpFile} 2>&1; rm -f ${tmpFile} ${tmpFile}c`;
      break;
    case "ruby":
      checkCmd = `cat > ${tmpFile} << 'EOF'
${code}
EOF
ruby -c ${tmpFile} 2>&1; rm -f ${tmpFile}`;
      break;
    case "bash":
      checkCmd = `cat > ${tmpFile} << 'EOF'
${code}
EOF
bash -n ${tmpFile} 2>&1; rm -f ${tmpFile}`;
      break;
    default:
      return { valid: true, errors: [] };
  }
  try {
    const result = await executeRawCommand(checkCmd, 15);
    const isValid = result.exitCode === 0;
    const errors = isValid ? [] : [result.stdout || result.stderr].filter(Boolean);
    return { valid: isValid, errors };
  } catch {
    return { valid: true, errors: [] };
  }
}
var executionHistory, LANGUAGE_COMMANDS, LANGUAGE_EXTENSIONS;
var init_exploit_sandbox = __esm({
  "server/lib/exploit-sandbox.ts"() {
    init_scan_server_executor();
    executionHistory = /* @__PURE__ */ new Map();
    LANGUAGE_COMMANDS = {
      python: "python3",
      bash: "bash",
      ruby: "ruby",
      powershell: "pwsh"
    };
    LANGUAGE_EXTENSIONS = {
      python: ".py",
      bash: ".sh",
      ruby: ".rb",
      powershell: ".ps1"
    };
  }
});

export {
  executeExploit,
  getExecutionHistory,
  validateExploitSyntax,
  init_exploit_sandbox
};
