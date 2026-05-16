import {
  addJsonFlag,
  assessNucleiAccessLevel,
  init_nuclei_output_parser,
  parseNucleiJsonOutput
} from "./chunk-JR2BIHC4.js";
import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/nuclei-verification-engine.ts
async function runNucleiVerification(params) {
  const startTime = Date.now();
  const { target, port, cve, vulnClass, service, sessionCookie, scanServerHost, timeoutSec = 60 } = params;
  try {
    const { buildNucleiCommand } = await import("./exploit-selection-intelligence-HZRINSFL.js");
    const nucleiCmd = buildNucleiCommand({
      target,
      port,
      cve,
      vulnClass,
      cookie: sessionCookie
    });
    if (!nucleiCmd) {
      return {
        confirmed: false,
        confidenceAdjustment: 0,
        nucleiAccessLevel: "none",
        parseResult: { findings: [], stats: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }, cves: [], cwes: [], matchedTemplates: [], hasExploitableFindings: false, highestSeverity: "unknown", allExtractedData: [], curlCommands: [], parseErrors: [] },
        summary: `No Nuclei template available for vulnClass=${vulnClass}, CVE=${cve || "none"}. Verification skipped.`,
        durationMs: Date.now() - startTime,
        command: ""
      };
    }
    const jsonCommand = addJsonFlag(nucleiCmd.command);
    const { executeRawCommand } = await import("./scan-server-executor-LFT6VWBD.js");
    const result = await executeRawCommand(jsonCommand, scanServerHost, timeoutSec);
    const rawOutput = result.stdout || "";
    const parseResult = parseNucleiJsonOutput(rawOutput);
    const accessAssessment = assessNucleiAccessLevel(parseResult);
    let confirmed = false;
    let confidenceAdjustment = 0;
    if (parseResult.hasExploitableFindings) {
      confirmed = true;
      confidenceAdjustment = 20;
    } else if (parseResult.stats.total > 0 && (parseResult.stats.critical > 0 || parseResult.stats.high > 0)) {
      confirmed = true;
      confidenceAdjustment = 15;
    } else if (parseResult.stats.total > 0) {
      confirmed = false;
      confidenceAdjustment = 5;
    } else {
      confirmed = false;
      confidenceAdjustment = -10;
    }
    const summary = confirmed ? `Nuclei CONFIRMED: ${parseResult.stats.total} findings (${parseResult.stats.critical} critical, ${parseResult.stats.high} high). Templates: ${parseResult.matchedTemplates.join(", ")}. Access: ${accessAssessment.accessLevel} (${accessAssessment.confidence}% confidence).` : parseResult.stats.total > 0 ? `Nuclei found ${parseResult.stats.total} findings but none exploitable. Confidence adjustment: ${confidenceAdjustment}.` : `Nuclei found NO matching vulnerabilities. LLM exploit may be a false positive. Confidence reduced by ${Math.abs(confidenceAdjustment)}.`;
    return {
      confirmed,
      confidenceAdjustment,
      nucleiAccessLevel: accessAssessment.accessLevel,
      parseResult,
      summary,
      durationMs: Date.now() - startTime,
      command: jsonCommand
    };
  } catch (err) {
    return {
      confirmed: false,
      confidenceAdjustment: 0,
      nucleiAccessLevel: "none",
      parseResult: { findings: [], stats: { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 }, cves: [], cwes: [], matchedTemplates: [], hasExploitableFindings: false, highestSeverity: "unknown", allExtractedData: [], curlCommands: [], parseErrors: [`Execution error: ${err.message}`] },
      summary: `Nuclei verification failed: ${err.message}`,
      durationMs: Date.now() - startTime,
      command: ""
    };
  }
}
function adjustVerificationWithNuclei(existing, nucleiResult) {
  const adjusted = { ...existing };
  adjusted.confidence = Math.min(100, Math.max(0, adjusted.confidence + nucleiResult.confidenceAdjustment));
  if (nucleiResult.confirmed) {
    if (adjusted.status === "unverified" || adjusted.status === "probable_success") {
      adjusted.status = "confirmed_success";
    }
    const nucleiAccessNum = ACCESS_LEVEL_RANK[nucleiResult.nucleiAccessLevel] || 0;
    const existingAccessNum = ACCESS_LEVEL_RANK[adjusted.accessLevel] || 0;
    if (nucleiAccessNum > existingAccessNum) {
      adjusted.accessLevel = nucleiResult.nucleiAccessLevel;
    }
  } else if (!nucleiResult.confirmed && nucleiResult.confidenceAdjustment < 0) {
    if (adjusted.status === "probable_success" && adjusted.confidence < 40) {
      adjusted.status = "unverified";
    }
  }
  adjusted.explanation = `${adjusted.explanation} | Nuclei: ${nucleiResult.summary.slice(0, 200)}`;
  return adjusted;
}
function extractSessionCookie(asset) {
  if (!asset) return void 0;
  if (asset.confirmedCredentials) {
    for (const cred of asset.confirmedCredentials) {
      if (cred.sessionCookie) {
        return cred.sessionCookie;
      }
    }
  }
  if (asset.trainingLabCreds?.sessionCookie) {
    return asset.trainingLabCreds.sessionCookie;
  }
  if (asset.confirmedCredentials?.length) {
    const httpCred = asset.confirmedCredentials.find(
      (c) => c.service === "http" || c.service === "https" || c.service === "http-form"
    );
    if (httpCred && httpCred.password) {
      return void 0;
    }
  }
  return void 0;
}
function buildCookieHeader(cookies) {
  if (typeof cookies === "string") return cookies;
  return cookies.map((c) => `${c.name}=${c.value}`).join("; ");
}
var ACCESS_LEVEL_RANK;
var init_nuclei_verification_engine = __esm({
  "server/lib/nuclei-verification-engine.ts"() {
    init_nuclei_output_parser();
    ACCESS_LEVEL_RANK = {
      "none": 0,
      "info_disclosure": 1,
      "file_read": 2,
      "file_write": 3,
      "credential_access": 4,
      "database_access": 5,
      "command_execution": 6,
      "service_account": 7,
      "user_shell": 8,
      "root_shell": 9
    };
  }
});
init_nuclei_verification_engine();
export {
  adjustVerificationWithNuclei,
  buildCookieHeader,
  extractSessionCookie,
  runNucleiVerification
};
