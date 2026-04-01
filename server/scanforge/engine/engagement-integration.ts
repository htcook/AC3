/**
 * ScanForge Engagement Integration Module
 * 
 * Lightweight in-process integration that runs ScanForge templates directly
 * inside the engagement orchestrator as a parallel scan layer alongside Nuclei/ZAP.
 * 
 * Architecture:
 *   - Runs in-process (no queue, no Redis, no IPC overhead)
 *   - Uses the template engine directly for HTTP/TCP detection
 *   - Routes internal targets through Ember agents via the bridge
 *   - Logs findings alongside Nuclei/ZAP for side-by-side comparison
 *   - Feeds results into the accuracy tracker for self-improvement
 *   - Respects engagement scope (ROE) and checkpoint tracking
 * 
 * This module is imported by the engagement orchestrator and called during
 * the vuln detection phase.
 */

import { TemplateEngine } from "./template-engine";
import { ProofEngine } from "./proof-engine";
import { ScanForgeEmberBridge } from "./ember-bridge";
import { logFinding, assessFindings, generateEngagementReport } from "./accuracy-tracker";
import { runAutoPromotion } from "./auto-promoter";
import { runTargetedResearch } from "./deep-research-agent";
import { getTemplateConfidenceMap } from "./confidence-tuner";
import { AuthScanner, type AuthConfig, type AuthSession } from "./auth-scanner";
import * as path from "path";
import * as fs from "fs";
import { fileURLToPath } from "url";
import { dirname } from "path";

// ESM-compatible __dirname (tsx runs as ESM, so __dirname is not available)
const __esm_dirname = dirname(fileURLToPath(import.meta.url));

// ─── Types ──────────────────────────────────────────────────────────────────

export interface ScanForgeCredential {
  username: string;
  password: string;
  service: string;
  source: string; // 'hydra' | 'training_lab' | 'manual'
  loginPath?: string;
  confirmedAt?: number;
}

export interface ScanForgeTarget {
  url: string;
  ip?: string;
  port?: number;
  hostname?: string;
  isInternal?: boolean;
  technologies?: string[];
  /** Discovered credentials from credential testing phase (Hydra, training lab defaults, etc.) */
  credentials?: ScanForgeCredential[];
}

export interface ScanForgeEngagementConfig {
  engagementId: string;
  targets: ScanForgeTarget[];
  scope: string;
  targetType: "web_app" | "network" | "api" | "cloud" | "training_lab";
  enableProofVerification: boolean;
  enableEmberRouting: boolean;
  emberAgentIds?: string[];
  templateCategories?: string[]; // Filter to specific categories
  maxConcurrency: number;
  timeoutPerTarget: number; // ms
  /** Enable authenticated scanning using discovered credentials */
  enableAuthenticatedScanning?: boolean;
}

export interface ScanForgeFinding {
  templateId: string;
  templateName: string;
  target: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  evidence: string;
  confidence: number;
  verified: boolean; // proof-based verification
  cve?: string;
  cwe?: string;
  cvss?: number;
  remediation?: string;
  references?: string[];
  rawResponse?: string;
}

export interface ScanForgeResult {
  engagementId: string;
  findings: ScanForgeFinding[];
  stats: {
    templatesExecuted: number;
    targetsScanned: number;
    findingsTotal: number;
    findingsVerified: number;
    findingsBySeverity: Record<string, number>;
    executionTimeMs: number;
    emberRoutedScans: number;
  };
  comparison?: {
    scanforgeOnly: string[];
    legacyOnly: string[];
    overlap: string[];
  };
}

// ─── Main Integration ───────────────────────────────────────────────────────

/**
 * Execute ScanForge scan phase for an engagement.
 * This is the main entry point called by the engagement orchestrator.
 */
export async function executeScanForgePhase(
  config: ScanForgeEngagementConfig,
  addLog: (entry: { phase: string; type: string; title: string; detail: string }) => void,
  onFinding: (finding: ScanForgeFinding) => void,
): Promise<ScanForgeResult> {
  const startTime = Date.now();
  
  addLog({
    phase: "vuln_detection",
    type: "scan_start",
    title: "ScanForge Scan Phase Started",
    detail: `Scanning ${config.targets.length} targets with template-based detection engine`,
  });

  const result: ScanForgeResult = {
    engagementId: config.engagementId,
    findings: [],
    stats: {
      templatesExecuted: 0,
      targetsScanned: 0,
      findingsTotal: 0,
      findingsVerified: 0,
      findingsBySeverity: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
      executionTimeMs: 0,
      emberRoutedScans: 0,
    },
  };

  try {
    // Step 1: Load templates
    const templateEngine = new TemplateEngine();
    const templatesDir = path.join(__esm_dirname, "../templates/definitions");
    
    if (!fs.existsSync(templatesDir)) {
      addLog({ phase: "vuln_detection", type: "warning", title: "ScanForge Templates Missing", detail: `Template directory not found: ${templatesDir}` });
      return result;
    }

    const templateFiles = fs.readdirSync(templatesDir).filter(f => f.endsWith(".json"));
    const templates: any[] = [];
    
    for (const file of templateFiles) {
      try {
        const content = fs.readFileSync(path.join(templatesDir, file), "utf-8");
        const tmpl = JSON.parse(content);
        
        // Filter by category if specified
        if (config.templateCategories && config.templateCategories.length > 0) {
          if (!config.templateCategories.includes(tmpl.category)) continue;
        }

        // Normalize: templates use `request` (singular object) but the execution
        // loop iterates over `requests` (plural array). Convert singular → array.
        if (tmpl.request && !tmpl.requests) {
          tmpl.requests = [tmpl.request];
        }
        
        templates.push(tmpl);
      } catch {}
    }

    addLog({
      phase: "vuln_detection",
      type: "info",
      title: "ScanForge Templates Loaded",
      detail: `Loaded ${templates.length} detection templates from ${templateFiles.length} files`,
    });

    // Step 2: Get confidence thresholds from tuner
    const templateIds = templates.map(t => t.id || t.templateId);
    const confidenceMap = await getTemplateConfidenceMap(templateIds);

    // Step 3: Run targeted research for engagement targets
    const targetUrls = config.targets.map(t => t.url || t.ip || "");
    try {
      const researchInputs = await runTargetedResearch(
        config.engagementId,
        targetUrls.filter(Boolean),
        config.targetType
      );
      if (researchInputs.length > 0) {
        addLog({
          phase: "vuln_detection",
          type: "info",
          title: "ScanForge Deep Research Complete",
          detail: `Gathered ${researchInputs.length} intelligence inputs from TI feeds for targeted scanning`,
        });
      }
    } catch (err) {
      // Research is optional — don't fail the scan
      console.warn("[ScanForge Integration] Targeted research failed:", (err as Error).message);
    }

    // Step 4: Initialize proof engine if enabled
    let proofEngine: ProofEngine | null = null;
    if (config.enableProofVerification) {
      proofEngine = new ProofEngine();
    }

    // Step 5: Initialize Ember bridge if enabled and agents available
    let emberBridge: ScanForgeEmberBridge | null = null;
    if (config.enableEmberRouting && config.emberAgentIds && config.emberAgentIds.length > 0) {
      emberBridge = new ScanForgeEmberBridge(config.engagementId);
      addLog({
        phase: "vuln_detection",
        type: "info",
        title: "ScanForge Ember Bridge Active",
        detail: `Routing internal scans through ${config.emberAgentIds.length} Ember agent(s)`,
      });
    }

    // Step 6: Establish authenticated sessions for targets with discovered credentials
    const authScanner = new AuthScanner();
    const targetAuthSessions: Map<string, { sessionId: string; config: AuthConfig }> = new Map();

    if (config.enableAuthenticatedScanning !== false) {
      for (const target of config.targets) {
        const creds = target.credentials || [];
        const webCreds = creds.filter(c => ['http', 'web', 'form', 'http-get', 'http-post-form'].includes(c.service));

        if (webCreds.length > 0) {
          const cred = webCreds[0]; // Use the first confirmed web credential
          const targetUrl = target.url || `http://${target.ip}:${target.port || 80}`;
          const loginUrl = cred.loginPath
            ? `${targetUrl}${cred.loginPath.startsWith('/') ? '' : '/'}${cred.loginPath}`
            : `${targetUrl}/login`;

          const authConfig: AuthConfig = {
            strategy: 'form_login',
            loginUrl,
            credentials: {
              username: cred.username,
              password: cred.password,
            },
            reAuthAfterRequests: 200, // Re-authenticate after 200 requests
            reAuthIntervalMs: 5 * 60 * 1000, // Re-authenticate every 5 minutes
          };

          try {
            const session = await authScanner.authenticate(authConfig);
            targetAuthSessions.set(targetUrl, { sessionId: session.id, config: authConfig });

            addLog({
              phase: 'vuln_detection',
              type: 'info',
              title: `🔑 ScanForge Auth: ${target.hostname || target.ip}`,
              detail: `Authenticated as ${cred.username} via ${cred.source} credentials (${session.cookies.size} cookies) — scanning authenticated attack surface`,
            });
          } catch (authErr: any) {
            addLog({
              phase: 'vuln_detection',
              type: 'warning',
              title: `⚠️ ScanForge Auth Failed: ${target.hostname || target.ip}`,
              detail: `Could not authenticate as ${cred.username}: ${authErr.message} — falling back to unauthenticated scanning`,
            });
          }
        }
      }

      if (targetAuthSessions.size > 0) {
        addLog({
          phase: 'vuln_detection',
          type: 'info',
          title: 'ScanForge Authenticated Scanning Active',
          detail: `${targetAuthSessions.size} target(s) with authenticated sessions — scanning both authenticated and unauthenticated attack surface`,
        });
      }
    }

    // Step 7: Execute templates against targets
    const internalTargets = config.targets.filter(t => t.isInternal);
    const externalTargets = config.targets.filter(t => !t.isInternal);

    // External targets — scan directly from this server
    for (const target of externalTargets) {
      const targetUrl = target.url || `http://${target.ip}:${target.port || 80}`;
      const authSession = targetAuthSessions.get(targetUrl);
      
      for (const template of templates) {
        try {
          // Run unauthenticated scan first
          const findings = await executeTemplate(templateEngine, template, targetUrl, confidenceMap);

          // If we have an authenticated session, also run authenticated scan to find additional vulns
          if (authSession) {
            try {
              // Ensure session is still valid before authenticated scan
              await authScanner.ensureAuthenticated(authSession.sessionId, authSession.config);
              const authFindings = await executeAuthenticatedTemplate(
                templateEngine, template, targetUrl, confidenceMap, authScanner, authSession.sessionId
              );
              // Only add findings that weren't already found in the unauthenticated scan
              for (const af of authFindings) {
                const isDuplicate = findings.some(f =>
                  f.templateId === af.templateId && f.title === af.title
                );
                if (!isDuplicate) {
                  af.title = `[Auth] ${af.title}`;
                  af.evidence = `[Authenticated as ${target.credentials?.[0]?.username}] ${af.evidence}`;
                  findings.push(af);
                }
              }
            } catch (authErr: any) {
              console.debug(`[ScanForge] Authenticated template execution failed for ${template.id}:`, authErr.message);
            }
          }
          
          for (const finding of findings) {
            // Proof-based verification
            if (proofEngine && finding.severity !== "info") {
              try {
                const verified = await proofEngine.verify({
                  templateId: finding.templateId,
                  target: finding.target,
                  originalEvidence: finding.evidence,
                  severity: finding.severity,
                });
                finding.verified = verified;
                if (verified) result.stats.findingsVerified++;
              } catch {
                finding.verified = false;
              }
            }

            result.findings.push(finding);
            result.stats.findingsTotal++;
            result.stats.findingsBySeverity[finding.severity] = (result.stats.findingsBySeverity[finding.severity] || 0) + 1;

            // Log to accuracy tracker
            await logFinding({
              engagementId: config.engagementId,
              templateId: finding.templateId,
              findingTitle: finding.title,
              target: finding.target,
              severity: finding.severity,
              confidence: finding.confidence,
              verified: finding.verified,
              evidence: finding.evidence,
              cve: finding.cve,
            });

            // Notify orchestrator
            onFinding(finding);
          }

          result.stats.templatesExecuted++;
        } catch (err) {
          // Individual template failure shouldn't stop the scan
          console.warn(`[ScanForge] Template ${template.id} failed on ${targetUrl}:`, (err as Error).message);
        }
      }
      
      result.stats.targetsScanned++;
    }

    // Internal targets — route through Ember agents
    if (emberBridge && internalTargets.length > 0) {
      addLog({
        phase: "vuln_detection",
        type: "scan_start",
        title: "ScanForge Internal Scan via Ember",
        detail: `Routing ${internalTargets.length} internal targets through Ember agents`,
      });

      for (const target of internalTargets) {
        const targetUrl = target.url || `http://${target.ip}:${target.port || 80}`;
        
        try {
          // Use Ember bridge for internal scanning
          const emberFindings = await emberBridge.scanTarget(
            targetUrl,
            templates.map(t => t.id || t.templateId),
            config.emberAgentIds![0]
          );

          for (const finding of emberFindings) {
            result.findings.push(finding);
            result.stats.findingsTotal++;
            result.stats.findingsBySeverity[finding.severity] = (result.stats.findingsBySeverity[finding.severity] || 0) + 1;
            result.stats.emberRoutedScans++;

            await logFinding({
              engagementId: config.engagementId,
              templateId: finding.templateId,
              findingTitle: finding.title,
              target: finding.target,
              severity: finding.severity,
              confidence: finding.confidence,
              verified: finding.verified,
              evidence: finding.evidence,
            });

            onFinding(finding);
          }
        } catch (err) {
          console.warn(`[ScanForge] Ember scan failed for ${targetUrl}:`, (err as Error).message);
        }

        result.stats.targetsScanned++;
      }
    }

    result.stats.executionTimeMs = Date.now() - startTime;

    addLog({
      phase: "vuln_detection",
      type: "scan_result",
      title: "ScanForge Scan Phase Complete",
      detail: `Found ${result.stats.findingsTotal} findings (${result.stats.findingsVerified} verified) across ${result.stats.targetsScanned} targets in ${(result.stats.executionTimeMs / 1000).toFixed(1)}s | Templates executed: ${result.stats.templatesExecuted} | Ember-routed: ${result.stats.emberRoutedScans}`,
    });

  } catch (err) {
    addLog({
      phase: "vuln_detection",
      type: "error",
      title: "ScanForge Scan Phase Error",
      detail: `ScanForge scan failed: ${(err as Error).message}`,
    });
    result.stats.executionTimeMs = Date.now() - startTime;
  }

  return result;
}

// ─── Template Execution ─────────────────────────────────────────────────────

/**
 * Execute a template with authenticated session — uses AuthScanner to inject
 * session cookies/tokens into every request for authenticated attack surface scanning.
 */
async function executeAuthenticatedTemplate(
  engine: TemplateEngine,
  template: any,
  targetUrl: string,
  confidenceMap: Map<string, number>,
  authScanner: AuthScanner,
  sessionId: string,
): Promise<ScanForgeFinding[]> {
  const findings: ScanForgeFinding[] = [];
  const templateId = template.id || template.templateId;
  const confidenceThreshold = confidenceMap.get(templateId) || 0.5;

  for (const request of (template.requests || [])) {
    try {
      const url = `${targetUrl}${request.path || ""}`;

      // Use AuthScanner to make the request with session credentials
      const result = await authScanner.authenticatedFetch(
        sessionId,
        url,
        request.method || "GET",
        (request.body && request.method !== "GET") ? request.body : undefined,
        {
          "User-Agent": "ScanForge/1.0 (Security Scanner)",
          ...(request.headers || {}),
        },
        10_000
      );

      // Check matchers
      let matched = false;
      const matchResults: string[] = [];

      for (const matcher of (template.matchers || [])) {
        const matchResult = checkMatcher(matcher, result.status, result.body, result.headers);
        if (matchResult.matched) {
          matched = true;
          matchResults.push(matchResult.evidence);
        }
      }

      if (matched) {
        const severity = template.severity || "medium";
        const confidence = calculateConfidence(template, matchResults, confidenceThreshold);

        if (confidence >= confidenceThreshold) {
          findings.push({
            templateId,
            templateName: template.name || templateId,
            target: targetUrl,
            severity,
            title: template.name || `${templateId} Detection`,
            description: template.description || `Vulnerability detected by template ${templateId} (authenticated)`,
            evidence: matchResults.join(" | "),
            confidence,
            verified: false,
            cve: template.metadata?.cve,
            cwe: template.metadata?.cwe,
            cvss: template.metadata?.cvss,
            remediation: template.remediation,
            references: template.metadata?.references || [],
            rawResponse: result.body.slice(0, 500),
          });
        }
      }
    } catch (err) {
      if ((err as Error).name !== "AbortError") {
        console.debug(`[ScanForge Auth] Request failed for ${templateId}:`, (err as Error).message);
      }
    }
  }

  return findings;
}

async function executeTemplate(
  engine: TemplateEngine,
  template: any,
  targetUrl: string,
  confidenceMap: Map<string, number>,
): Promise<ScanForgeFinding[]> {
  const findings: ScanForgeFinding[] = [];
  const templateId = template.id || template.templateId;
  const confidenceThreshold = confidenceMap.get(templateId) || 0.5;

  // Skip non-HTTP templates — DNS/TCP/multi-protocol templates cannot be executed via fetch
  const protocol = (template.protocol || 'http').toLowerCase();
  if (!['http', 'https'].includes(protocol)) {
    return findings;
  }

  // Execute each request in the template
  for (const request of (template.requests || [])) {
    try {
      const url = `${targetUrl}${request.path || ""}`;
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 10000); // 10s timeout

      const fetchOpts: RequestInit = {
        method: request.method || "GET",
        headers: {
          "User-Agent": "ScanForge/1.0 (Security Scanner)",
          ...(request.headers || {}),
        },
        signal: controller.signal,
        redirect: "follow",
      };

      if (request.body && request.method !== "GET") {
        fetchOpts.body = request.body;
      }

      const response = await fetch(url, fetchOpts);
      clearTimeout(timeout);

      const responseBody = await response.text();
      const responseHeaders = Object.fromEntries(response.headers.entries());

      // Check matchers
      let matched = false;
      const matchResults: string[] = [];

      for (const matcher of (template.matchers || [])) {
        const matchResult = checkMatcher(matcher, response.status, responseBody, responseHeaders);
        if (matchResult.matched) {
          matched = true;
          matchResults.push(matchResult.evidence);
        }
      }

      if (matched) {
        const severity = template.severity || "medium";
        const confidence = calculateConfidence(template, matchResults, confidenceThreshold);

        // Only report if confidence exceeds the tuned threshold
        if (confidence >= confidenceThreshold) {
          findings.push({
            templateId,
            templateName: template.name || templateId,
            target: targetUrl,
            severity,
            title: template.name || `${templateId} Detection`,
            description: template.description || `Vulnerability detected by template ${templateId}`,
            evidence: matchResults.join(" | "),
            confidence,
            verified: false,
            cve: template.metadata?.cve,
            cwe: template.metadata?.cwe,
            cvss: template.metadata?.cvss,
            remediation: template.remediation,
            references: template.metadata?.references || [],
            rawResponse: responseBody.slice(0, 500),
          });
        }
      }
    } catch (err) {
      // Request-level failure — skip silently
      if ((err as Error).name !== "AbortError") {
        console.debug(`[ScanForge] Request failed for ${templateId}:`, (err as Error).message);
      }
    }
  }

  return findings;
}

function checkMatcher(
  matcher: any,
  statusCode: number,
  body: string,
  headers: Record<string, string>,
): { matched: boolean; evidence: string } {
  const values = matcher.values || [];
  const matchType = matcher.type || "body";

  switch (matchType) {
    case "status": {
      const matched = values.some((v: string) => String(statusCode) === String(v));
      return { matched, evidence: matched ? `Status: ${statusCode}` : "" };
    }
    case "body": {
      for (const val of values) {
        if (body.includes(val)) {
          const idx = body.indexOf(val);
          const context = body.slice(Math.max(0, idx - 50), idx + val.length + 50);
          return { matched: true, evidence: `Body match: ...${context}...` };
        }
      }
      return { matched: false, evidence: "" };
    }
    case "header": {
      const headerStr = Object.entries(headers).map(([k, v]) => `${k}: ${v}`).join("\n");
      for (const val of values) {
        if (headerStr.toLowerCase().includes(val.toLowerCase())) {
          return { matched: true, evidence: `Header match: ${val}` };
        }
      }
      return { matched: false, evidence: "" };
    }
    case "regex": {
      for (const val of values) {
        try {
          const regex = new RegExp(val, "i");
          const match = body.match(regex);
          if (match) {
            return { matched: true, evidence: `Regex match: ${match[0].slice(0, 100)}` };
          }
        } catch {}
      }
      return { matched: false, evidence: "" };
    }
    case "negative_header": {
      // Match when header is MISSING (for security header checks)
      for (const val of values) {
        const headerExists = Object.keys(headers).some(k => k.toLowerCase() === val.toLowerCase());
        if (!headerExists) {
          return { matched: true, evidence: `Missing header: ${val}` };
        }
      }
      return { matched: false, evidence: "" };
    }
    default:
      return { matched: false, evidence: "" };
  }
}

function calculateConfidence(
  template: any,
  matchResults: string[],
  baseConfidence: number,
): number {
  let confidence = baseConfidence;

  // More matchers matched = higher confidence
  const totalMatchers = (template.matchers || []).length;
  if (totalMatchers > 0) {
    const matchRatio = matchResults.length / totalMatchers;
    confidence = confidence * (0.7 + 0.3 * matchRatio);
  }

  // Severity affects base confidence (critical vulns need higher evidence)
  const severityMultiplier: Record<string, number> = {
    critical: 0.85, high: 0.9, medium: 0.95, low: 1.0, info: 1.0,
  };
  confidence *= severityMultiplier[template.severity] || 1.0;

  return Math.min(0.99, Math.max(0.1, confidence));
}

// ─── Comparison Engine ──────────────────────────────────────────────────────

/**
 * Compare ScanForge findings with Nuclei/ZAP findings for the same engagement.
 * Returns overlap analysis for the accuracy tracker.
 */
export function compareFindings(
  scanforgeFindings: ScanForgeFinding[],
  legacyFindings: Array<{ tool: string; title: string; target: string; severity: string }>,
): { scanforgeOnly: string[]; legacyOnly: string[]; overlap: string[] } {
  const sfSet = new Set(scanforgeFindings.map(f => normalizeKey(f.title, f.target)));
  const legacySet = new Set(legacyFindings.map(f => normalizeKey(f.title, f.target)));

  const overlap: string[] = [];
  const scanforgeOnly: string[] = [];
  const legacyOnly: string[] = [];

  for (const key of sfSet) {
    if (legacySet.has(key)) overlap.push(key);
    else scanforgeOnly.push(key);
  }
  for (const key of legacySet) {
    if (!sfSet.has(key)) legacyOnly.push(key);
  }

  return { scanforgeOnly, legacyOnly, overlap };
}

function normalizeKey(title: string, target: string): string {
  // Normalize finding titles for comparison across tools
  return `${title.toLowerCase().replace(/[^a-z0-9]/g, "")}@${target.replace(/^https?:\/\//, "").split("/")[0]}`;
}

// ─── Post-Engagement Hook ───────────────────────────────────────────────────

/**
 * Run post-engagement analysis: compare findings, update metrics, trigger reassessment.
 * Called by the engagement orchestrator after all scans complete.
 */
export async function runPostEngagementAnalysis(
  engagementId: string,
  scanforgeResult: ScanForgeResult,
  legacyFindings: Array<{ tool: string; title: string; target: string; severity: string; cve?: string; evidence?: string }>,
  addLog: (entry: { phase: string; type: string; title: string; detail: string }) => void,
): Promise<void> {
  addLog({
    phase: "vuln_detection",
    type: "info",
    title: "ScanForge Post-Engagement Analysis",
    detail: `Comparing ${scanforgeResult.stats.findingsTotal} ScanForge findings vs ${legacyFindings.length} legacy tool findings`,
  });

  // Compare findings
  const comparison = compareFindings(scanforgeResult.findings, legacyFindings);
  scanforgeResult.comparison = comparison;

  // Log false negatives (found by legacy, missed by ScanForge)
  for (const key of comparison.legacyOnly) {
    const legacyFinding = legacyFindings.find(f => normalizeKey(f.title, f.target) === key);
    if (legacyFinding) {
      await logFinding({
        engagementId,
        templateId: "MISSED",
        findingTitle: legacyFinding.title,
        target: legacyFinding.target,
        severity: legacyFinding.severity as any,
        confidence: 0,
        verified: false,
        evidence: `Found by ${legacyFinding.tool} but missed by ScanForge`,
        crossToolMatches: [{ tool: legacyFinding.tool, findingId: key }],
      });
    }
  }

  // Auto-assess findings
  const verdicts = await assessFindings(engagementId, legacyFindings as any, "auto-crossref");

  // Generate engagement report
  const nucleiCount = legacyFindings.filter(f => f.tool === "nuclei").length;
  const zapCount = legacyFindings.filter(f => f.tool === "zap").length;
  await generateEngagementReport(engagementId, { nuclei: nucleiCount, zap: zapCount });

  addLog({
    phase: "vuln_detection",
    type: "scan_result",
    title: "ScanForge Comparison Report",
    detail: `Overlap: ${comparison.overlap.length} | ScanForge-only: ${comparison.scanforgeOnly.length} | Legacy-only: ${comparison.legacyOnly.length} | Verdicts: TP=${verdicts.tp} FP=${verdicts.fp} FN=${verdicts.fn}`,
  });

  // Run auto-promotion evaluation for all eligible generated templates
  try {
    const promotionResults = await runAutoPromotion(engagementId);
    const promoted = promotionResults.filter(r => r.decision === "promoted");
    const rejected = promotionResults.filter(r => r.decision === "rejected");
    const deferred = promotionResults.filter(r => r.decision === "deferred");

    if (promotionResults.length > 0) {
      addLog({
        phase: "vuln_detection",
        type: "info",
        title: "ScanForge Auto-Promotion Evaluation",
        detail: `Evaluated ${promotionResults.length} templates: ${promoted.length} promoted, ${deferred.length} deferred, ${rejected.length} rejected` +
          (promoted.length > 0 ? ` | Promoted: ${promoted.map(p => p.templateId).join(", ")}` : ""),
      });
    }
  } catch (err: any) {
    addLog({
      phase: "vuln_detection",
      type: "warning",
      title: "ScanForge Auto-Promotion Error",
      detail: `Auto-promotion evaluation failed: ${err?.message ?? "unknown error"}`,
    });
  }
}
