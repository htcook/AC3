/**
 * Report Validation Linter
 * 
 * Final-stage validation pass that runs after report data assembly
 * but before PDF emission. Catches systemic quality issues identified
 * in Claude's feedback analysis (May 2026).
 * 
 * Each check returns PASS/WARN/FAIL:
 * - FAIL: blocks report emission (credibility-killing issues)
 * - WARN: adds "Quality Advisory" note to report cover
 * - PASS: no action needed
 * 
 * @author Harrison Cook — AceofCloud
 */

// ─────────────────────────────────────────────────────────────────────────────
// Types
// ─────────────────────────────────────────────────────────────────────────────

export type LintSeverity = "pass" | "warn" | "fail";

export interface LintResult {
  check: string;
  severity: LintSeverity;
  message: string;
  details?: string;
  location?: string;
}

export interface LintReport {
  results: LintResult[];
  passed: number;
  warnings: number;
  failures: number;
  overallStatus: "PASS" | "WARN" | "FAIL";
  timestamp: string;
}

export interface ReportData {
  type: "di" | "pentest";
  // Cover page claims
  coverMetrics?: {
    discoveredAssets?: number;
    confirmedFindings?: number;
    potentialFindings?: number;
    totalFindings?: number;
    riskRating?: string;
    dataSources?: number;
  };
  // Exec summary claims
  execSummaryMetrics?: {
    discoveredAssets?: number;
    confirmedFindings?: number;
    potentialFindings?: number;
    totalFindings?: number;
    riskRating?: string;
    kevMatches?: number;
    dnsblListings?: number;
  };
  // Actual data counts
  actualCounts?: {
    assetTableRows?: number;
    findingTableRows?: number;
    confirmedFindingRows?: number;
    potentialFindingRows?: number;
    kevConfirmedRows?: number;
    openPortRows?: number;
    claimedOpenPorts?: number;
  };
  // Asset data
  assets?: Array<{
    hostname: string;
    isVendorManaged?: boolean;
    includedInGrading?: boolean;
    source?: string; // "mx_target", "ns_target", "subdomain", etc.
  }>;
  // Findings data
  findings?: Array<{
    id: string;
    title: string;
    sourceType?: "scanner" | "llm_inference" | "manual";
    tool?: string;
    confidence?: "high" | "medium" | "low";
    inMainCount?: boolean;
    inRiskMatrix?: boolean;
    likelihood?: string;
  }>;
  // Exploit results (pentest only)
  exploitResults?: Array<{
    id: string;
    status: string; // "SUCCEEDED", "FAILED", "BLOCKED_AUTH"
    accessLevel?: string;
    shell?: boolean;
    proofContains?: string[];
    httpStatus?: number;
    errorMessages?: string[];
  }>;
  // Tool execution results
  toolExecutions?: Array<{
    tool: string;
    exitCode: number;
    durationMs: number;
    output?: string;
    error?: string;
  }>;
  // DNSBL results
  dnsblResults?: Array<{
    provider: string;
    listed: boolean;
    txtRecord?: string;
    responseType?: "listing" | "query_error" | "refused";
  }>;
  // Narrative text sections (for template residual detection)
  narrativeSections?: Array<{
    section: string;
    text: string;
  }>;
  // Rendered text (for serialization bug detection)
  renderedText?: string;
  // Risk rating
  computedRiskRating?: string;
  // Engagement metadata
  engagement?: {
    status?: string;
    toolSuccessRate?: number;
    scanKeyConfigured?: boolean;
    c2Agents?: number;
    roeUploaded?: boolean;
    roeSigner?: string;
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Vendor Domain Allowlist
// ─────────────────────────────────────────────────────────────────────────────

const VENDOR_DOMAIN_PATTERNS = [
  // Google
  /^(.*\.)?google\.com$/i,
  /^(.*\.)?googlemail\.com$/i,
  /^(.*\.)?googleapis\.com$/i,
  /^(.*\.)?gstatic\.com$/i,
  /^(.*\.)?googleusercontent\.com$/i,
  /^(.*\.)?google-analytics\.com$/i,
  // Microsoft
  /^(.*\.)?outlook\.com$/i,
  /^(.*\.)?office365\.com$/i,
  /^(.*\.)?microsoft\.com$/i,
  /^(.*\.)?microsoftonline\.com$/i,
  /^(.*\.)?office\.com$/i,
  /^(.*\.)?live\.com$/i,
  /^(.*\.)?hotmail\.com$/i,
  // Amazon/AWS
  /^(.*\.)?amazonaws\.com$/i,
  /^(.*\.)?amazonses\.com$/i,
  /^(.*\.)?awsdns-.*$/i,
  // Cloudflare
  /^(.*\.)?cloudflare\.com$/i,
  /^(.*\.)?cloudflare-dns\.com$/i,
  // Other common vendors
  /^(.*\.)?akamai\.net$/i,
  /^(.*\.)?akamaitechnologies\.com$/i,
  /^(.*\.)?fastly\.net$/i,
  /^(.*\.)?incapsula\.com$/i,
  /^(.*\.)?sucuri\.net$/i,
  /^(.*\.)?zendesk\.com$/i,
  /^(.*\.)?sendgrid\.net$/i,
  /^(.*\.)?mailgun\.org$/i,
  /^(.*\.)?mimecast\.com$/i,
  /^(.*\.)?proofpoint\.com$/i,
];

function isVendorDomain(hostname: string): boolean {
  return VENDOR_DOMAIN_PATTERNS.some(pattern => pattern.test(hostname));
}

// ─────────────────────────────────────────────────────────────────────────────
// DNSBL False Positive Patterns
// ─────────────────────────────────────────────────────────────────────────────

const DNSBL_REFUSED_PATTERNS = [
  /query\s*refused/i,
  /rate\s*limit/i,
  /blocked/i,
  /not\s*authorized/i,
  /refused\.shtml/i,
  /abuse\s*page/i,
  /exceeded/i,
  /try\s*again\s*later/i,
];

function isDnsblQueryError(txtRecord: string): boolean {
  return DNSBL_REFUSED_PATTERNS.some(pattern => pattern.test(txtRecord));
}

// ─────────────────────────────────────────────────────────────────────────────
// Check Implementations
// ─────────────────────────────────────────────────────────────────────────────

function checkCountReconciliation(data: ReportData): LintResult[] {
  const results: LintResult[] = [];

  // Cover vs Exec Summary asset count
  if (data.coverMetrics?.discoveredAssets != null && data.execSummaryMetrics?.discoveredAssets != null) {
    if (data.coverMetrics.discoveredAssets !== data.execSummaryMetrics.discoveredAssets) {
      results.push({
        check: "count_reconciliation",
        severity: "fail",
        message: `Asset count mismatch: cover says ${data.coverMetrics.discoveredAssets}, exec summary says ${data.execSummaryMetrics.discoveredAssets}`,
        location: "Cover Page vs Executive Summary",
      });
    }
  }

  // Cover vs actual table rows
  if (data.coverMetrics?.discoveredAssets != null && data.actualCounts?.assetTableRows != null) {
    if (data.coverMetrics.discoveredAssets !== data.actualCounts.assetTableRows) {
      results.push({
        check: "count_reconciliation",
        severity: "warn",
        message: `Cover claims ${data.coverMetrics.discoveredAssets} assets but table has ${data.actualCounts.assetTableRows} rows`,
        details: "If vendor-excluded assets explain the difference, add a footnote",
        location: "Cover Page vs Attack Surface Inventory",
      });
    }
  }

  // Confirmed findings count
  if (data.coverMetrics?.confirmedFindings != null && data.actualCounts?.confirmedFindingRows != null) {
    if (data.coverMetrics.confirmedFindings !== data.actualCounts.confirmedFindingRows) {
      results.push({
        check: "count_reconciliation",
        severity: "fail",
        message: `Confirmed findings mismatch: cover says ${data.coverMetrics.confirmedFindings}, actual data has ${data.actualCounts.confirmedFindingRows}`,
        location: "Cover Page vs Vulnerability Section",
      });
    }
  }

  // KEV matches
  if (data.execSummaryMetrics?.kevMatches != null && data.actualCounts?.kevConfirmedRows != null) {
    if (data.execSummaryMetrics.kevMatches !== data.actualCounts.kevConfirmedRows) {
      results.push({
        check: "count_reconciliation",
        severity: "warn",
        message: `KEV count mismatch: exec summary says ${data.execSummaryMetrics.kevMatches}, actual confirmed KEV rows: ${data.actualCounts.kevConfirmedRows}`,
        details: "Only count KEV matches where product AND version are confirmed",
        location: "Executive Summary vs Vulnerability Section",
      });
    }
  }

  // Open ports
  if (data.actualCounts?.claimedOpenPorts != null && data.actualCounts?.openPortRows != null) {
    if (data.actualCounts.claimedOpenPorts !== data.actualCounts.openPortRows) {
      results.push({
        check: "count_reconciliation",
        severity: "warn",
        message: `Open ports header claims ${data.actualCounts.claimedOpenPorts} but only ${data.actualCounts.openPortRows} rows shown`,
        details: "Either show all rows or add 'showing top N of M'",
        location: "Risky Service Exposure",
      });
    }
  }

  if (results.length === 0) {
    results.push({
      check: "count_reconciliation",
      severity: "pass",
      message: "All claimed counts match actual data",
    });
  }

  return results;
}

function checkRatingConsistency(data: ReportData): LintResult[] {
  const results: LintResult[] = [];
  const computedRating = data.computedRiskRating?.toUpperCase();

  if (!computedRating || !data.narrativeSections?.length) {
    results.push({
      check: "rating_consistency",
      severity: "pass",
      message: "No rating data to validate",
    });
    return results;
  }

  const ratingWords = ["LOW", "MEDIUM", "HIGH", "CRITICAL", "VERY HIGH"];
  const ratingPattern = new RegExp(`\\b(${ratingWords.join("|")})\\s+risk\\s+rating\\b`, "gi");

  for (const section of data.narrativeSections) {
    const matches = section.text.matchAll(ratingPattern);
    for (const match of matches) {
      const foundRating = match[1].toUpperCase();
      if (foundRating !== computedRating) {
        results.push({
          check: "rating_consistency",
          severity: "fail",
          message: `Rating word "${foundRating}" in narrative doesn't match computed rating "${computedRating}"`,
          details: "Likely a stale LLM prompt template value that wasn't updated when rating was recalculated",
          location: section.section,
        });
      }
    }
  }

  if (results.length === 0) {
    results.push({
      check: "rating_consistency",
      severity: "pass",
      message: `All narrative rating references match computed rating: ${computedRating}`,
    });
  }

  return results;
}

function checkExploitStatusValidation(data: ReportData): LintResult[] {
  const results: LintResult[] = [];

  if (!data.exploitResults?.length) {
    results.push({
      check: "exploit_status_validate",
      severity: "pass",
      message: "No exploit results to validate",
    });
    return results;
  }

  for (const exploit of data.exploitResults) {
    // SUCCEEDED but access_level=none
    if (exploit.status === "SUCCEEDED" && exploit.accessLevel === "none") {
      results.push({
        check: "exploit_status_validate",
        severity: "fail",
        message: `Exploit ${exploit.id} marked SUCCEEDED but access_level=none`,
        details: "Cannot mark exploit as successful without achieving access",
        location: `Exploitation Evidence ${exploit.id}`,
      });
    }

    // SUCCEEDED but proof contains FAILED
    if (exploit.status === "SUCCEEDED" && exploit.proofContains?.some(p =>
      /EXPLOIT_FAILED|FAILED|error|Invalid or missing/i.test(p)
    )) {
      results.push({
        check: "exploit_status_validate",
        severity: "fail",
        message: `Exploit ${exploit.id} marked SUCCEEDED but proof contains failure indicators`,
        details: "PoC output contradicts success classification",
        location: `Exploitation Evidence ${exploit.id}`,
      });
    }

    // Auth blocked (X-Scan-Key error)
    if (exploit.errorMessages?.some(e => /X-Scan-Key|Invalid or missing.*Key/i.test(e))) {
      results.push({
        check: "exploit_status_validate",
        severity: "fail",
        message: `Exploit ${exploit.id} blocked by scanner gateway auth (X-Scan-Key not configured)`,
        details: "Exploit never reached target — should be BLOCKED_AUTH, not SUCCEEDED",
        location: `Exploitation Evidence ${exploit.id}`,
      });
    }
  }

  if (results.length === 0) {
    results.push({
      check: "exploit_status_validate",
      severity: "pass",
      message: "All exploit status classifications are consistent with evidence",
    });
  }

  return results;
}

function checkVendorAssetExclusion(data: ReportData): LintResult[] {
  const results: LintResult[] = [];

  if (!data.assets?.length) {
    results.push({
      check: "vendor_asset_exclusion",
      severity: "pass",
      message: "No asset data to validate",
    });
    return results;
  }

  for (const asset of data.assets) {
    if (isVendorDomain(asset.hostname) && asset.includedInGrading) {
      results.push({
        check: "vendor_asset_exclusion",
        severity: "fail",
        message: `Vendor domain "${asset.hostname}" included in customer grading`,
        details: `Source: ${asset.source || "unknown"}. Vendor assets must be excluded from customer security grades.`,
        location: "Attack Surface / Web Security Analysis",
      });
    }

    // MX/NS targets in customer asset list
    if ((asset.source === "mx_target" || asset.source === "ns_target") && !asset.isVendorManaged) {
      if (isVendorDomain(asset.hostname)) {
        results.push({
          check: "vendor_asset_exclusion",
          severity: "fail",
          message: `MX/NS target "${asset.hostname}" treated as customer asset`,
          details: "MX/NS resolution targets of vendor services should not appear in customer attack surface",
          location: "Asset Discovery",
        });
      }
    }
  }

  if (results.length === 0) {
    results.push({
      check: "vendor_asset_exclusion",
      severity: "pass",
      message: "No vendor domains found in customer grading sections",
    });
  }

  return results;
}

function checkDnsblFalsePositives(data: ReportData): LintResult[] {
  const results: LintResult[] = [];

  if (!data.dnsblResults?.length) {
    results.push({
      check: "dnsbl_response_validate",
      severity: "pass",
      message: "No DNSBL data to validate",
    });
    return results;
  }

  for (const dnsbl of data.dnsblResults) {
    if (dnsbl.listed && dnsbl.txtRecord && isDnsblQueryError(dnsbl.txtRecord)) {
      results.push({
        check: "dnsbl_response_validate",
        severity: "fail",
        message: `DNSBL "${dnsbl.provider}" marked as listed but TXT record indicates query error`,
        details: `TXT: "${dnsbl.txtRecord.substring(0, 100)}..." — this is a rate-limit/refused response, not a real listing`,
        location: "Domain Reputation / DNSBL",
      });
    }
  }

  if (results.length === 0) {
    results.push({
      check: "dnsbl_response_validate",
      severity: "pass",
      message: "All DNSBL listings appear to be genuine (no query-error false positives)",
    });
  }

  return results;
}

function checkLlmContentQuarantine(data: ReportData): LintResult[] {
  const results: LintResult[] = [];

  if (!data.findings?.length) {
    results.push({
      check: "llm_content_quarantine",
      severity: "pass",
      message: "No findings to validate",
    });
    return results;
  }

  for (const finding of data.findings) {
    // LLM-inferred findings in main count
    if (finding.sourceType === "llm_inference" && finding.inMainCount) {
      results.push({
        check: "llm_content_quarantine",
        severity: "fail",
        message: `Finding ${finding.id} ("${finding.title}") is LLM-inferred but included in main findings count`,
        details: "LLM-inferred findings must be quarantined to 'Hypotheses for Investigation' section",
        location: "Findings Summary / Risk Matrix",
      });
    }

    // LLM-inferred findings in Risk Matrix
    if (finding.sourceType === "llm_inference" && finding.inRiskMatrix) {
      results.push({
        check: "llm_content_quarantine",
        severity: "fail",
        message: `LLM-inferred finding ${finding.id} appears in Risk Matrix`,
        details: "Inferred findings should not receive CVSS scores or appear in the risk matrix",
        location: "Risk Matrix",
      });
    }

    // Low confidence + Very High Likelihood
    if (finding.confidence === "low" && finding.likelihood?.toLowerCase().includes("very high")) {
      results.push({
        check: "llm_content_quarantine",
        severity: "fail",
        message: `Finding ${finding.id} has low confidence but "Very High" likelihood in Risk Matrix`,
        details: "Low-confidence findings cannot have Very High likelihood by definition",
        location: "Risk Matrix",
      });
    }

    // Tool = "LLM Inference Engine" without proper labeling
    if (finding.tool?.toLowerCase().includes("llm") && finding.sourceType !== "llm_inference") {
      results.push({
        check: "llm_content_quarantine",
        severity: "warn",
        message: `Finding ${finding.id} uses LLM tool but source_type is not "llm_inference"`,
        details: "Ensure all LLM-generated findings are properly tagged",
        location: `Finding ${finding.id}`,
      });
    }
  }

  if (results.length === 0) {
    results.push({
      check: "llm_content_quarantine",
      severity: "pass",
      message: "All LLM-inferred content is properly quarantined from main findings",
    });
  }

  return results;
}

function checkObjectSerialization(data: ReportData): LintResult[] {
  const results: LintResult[] = [];

  if (!data.renderedText) {
    results.push({
      check: "object_serialization",
      severity: "pass",
      message: "No rendered text to validate",
    });
    return results;
  }

  // Check for [object Object]
  const objectMatches = data.renderedText.match(/\[object Object\]/g);
  if (objectMatches) {
    results.push({
      check: "object_serialization",
      severity: "fail",
      message: `Found ${objectMatches.length} instance(s) of "[object Object]" in rendered text`,
      details: "JavaScript object not properly serialized before rendering",
      location: "Rendered output",
    });
  }

  // Check for undefined/null rendered as text
  const undefinedMatches = data.renderedText.match(/\bundefined\b|\bnull\b/g);
  if (undefinedMatches && undefinedMatches.length > 3) {
    results.push({
      check: "object_serialization",
      severity: "warn",
      message: `Found ${undefinedMatches.length} instance(s) of "undefined" or "null" in rendered text`,
      details: "May indicate missing data fields rendered as literal text",
      location: "Rendered output",
    });
  }

  if (results.length === 0) {
    results.push({
      check: "object_serialization",
      severity: "pass",
      message: "No serialization artifacts detected in rendered text",
    });
  }

  return results;
}

function checkTemplateResiduals(data: ReportData): LintResult[] {
  const results: LintResult[] = [];

  if (!data.narrativeSections?.length) {
    results.push({
      check: "template_residual",
      severity: "pass",
      message: "No narrative sections to validate",
    });
    return results;
  }

  // Common template placeholder patterns
  const placeholderPatterns = [
    /\{\{[^}]+\}\}/g,           // {{variable}}
    /\$\{[^}]+\}/g,            // ${variable}
    /\[INSERT.*?\]/gi,          // [INSERT X HERE]
    /\[TODO.*?\]/gi,            // [TODO: ...]
    /PLACEHOLDER/gi,            // PLACEHOLDER
    /EXAMPLE_/gi,               // EXAMPLE_VALUE
    /lorem ipsum/gi,            // Lorem ipsum
    /processing error/gi,       // "could not be generated due to a processing error"
  ];

  for (const section of data.narrativeSections) {
    for (const pattern of placeholderPatterns) {
      const matches = section.text.match(pattern);
      if (matches) {
        results.push({
          check: "template_residual",
          severity: matches[0].toLowerCase().includes("processing error") ? "fail" : "warn",
          message: `Template residual detected: "${matches[0]}" in ${section.section}`,
          details: "Placeholder or error message left in customer-facing text",
          location: section.section,
        });
      }
    }
  }

  if (results.length === 0) {
    results.push({
      check: "template_residual",
      severity: "pass",
      message: "No template residuals or placeholder text detected",
    });
  }

  return results;
}

function checkToolFailureThreshold(data: ReportData): LintResult[] {
  const results: LintResult[] = [];

  if (!data.toolExecutions?.length) {
    results.push({
      check: "tool_failure_threshold",
      severity: "pass",
      message: "No tool execution data to validate",
    });
    return results;
  }

  const total = data.toolExecutions.length;
  const failed = data.toolExecutions.filter(t =>
    t.exitCode !== 0 || t.durationMs < 100 // <100ms = didn't actually run
  ).length;
  const failureRate = failed / total;

  if (failureRate > 0.5) {
    results.push({
      check: "tool_failure_threshold",
      severity: "fail",
      message: `Tool failure rate: ${Math.round(failureRate * 100)}% (${failed}/${total} tools failed)`,
      details: "Engagement should be marked DEGRADED, not completed. Add prominent banner to report.",
      location: "Engagement Status / Appendix D",
    });
  } else if (failureRate > 0.25) {
    results.push({
      check: "tool_failure_threshold",
      severity: "warn",
      message: `Tool failure rate: ${Math.round(failureRate * 100)}% (${failed}/${total} tools had issues)`,
      details: "Consider adding a coverage advisory note",
      location: "Appendix D",
    });
  }

  // Check for command-not-found (exit 127)
  const notFound = data.toolExecutions.filter(t => t.exitCode === 127);
  if (notFound.length > 0) {
    results.push({
      check: "tool_failure_threshold",
      severity: "fail",
      message: `${notFound.length} tool(s) returned exit 127 (command not found): ${notFound.map(t => t.tool).join(", ")}`,
      details: "Tools are not installed on the scan server",
      location: "Scan Server Configuration",
    });
  }

  // Check for X-Scan-Key issues
  if (data.engagement?.scanKeyConfigured === false) {
    results.push({
      check: "tool_failure_threshold",
      severity: "fail",
      message: "X-Scan-Key is not configured (still using default placeholder)",
      details: "All exploit attempts will be blocked by scanner gateway authentication",
      location: "Pre-Engagement Configuration",
    });
  }

  if (results.length === 0) {
    results.push({
      check: "tool_failure_threshold",
      severity: "pass",
      message: `Tool success rate: ${Math.round((1 - failureRate) * 100)}% (${total - failed}/${total})`,
    });
  }

  return results;
}

function checkSectionContradictions(data: ReportData): LintResult[] {
  const results: LintResult[] = [];

  if (!data.narrativeSections?.length) {
    results.push({
      check: "section_contradiction",
      severity: "pass",
      message: "No narrative sections to validate",
    });
    return results;
  }

  // Check for manual verification contradictions
  const verifiedClaims = data.narrativeSections.filter(s =>
    /validated through manual testing|manually verified|operator-confirmed/i.test(s.text)
  );
  const unverifiedClaims = data.narrativeSections.filter(s =>
    /have not been manually verified|not.*manually.*validated|automated.*only/i.test(s.text)
  );

  if (verifiedClaims.length > 0 && unverifiedClaims.length > 0) {
    results.push({
      check: "section_contradiction",
      severity: "fail",
      message: "Contradictory manual verification claims",
      details: `"${verifiedClaims[0].section}" claims manual verification, but "${unverifiedClaims[0].section}" says findings are not manually verified`,
      location: "Analytical Confidence / Appendix",
    });
  }

  // Check C2 section with 0 agents
  if (data.engagement?.c2Agents === 0) {
    const c2Sections = data.narrativeSections.filter(s =>
      /c2|command.*control|caldera.*operation/i.test(s.section)
    );
    if (c2Sections.length > 0) {
      results.push({
        check: "section_contradiction",
        severity: "warn",
        message: "C2 section present but 0 agents deployed",
        details: "Remove C2 section or replace with 'No C2 activity occurred during this engagement'",
        location: "C2 Evidence",
      });
    }
  }

  if (results.length === 0) {
    results.push({
      check: "section_contradiction",
      severity: "pass",
      message: "No contradictions detected between sections",
    });
  }

  return results;
}

// ─────────────────────────────────────────────────────────────────────────────
// Main Linter Entry Point
// ─────────────────────────────────────────────────────────────────────────────

export function validateReport(data: ReportData): LintReport {
  const allResults: LintResult[] = [];

  // Run all checks
  allResults.push(...checkCountReconciliation(data));
  allResults.push(...checkRatingConsistency(data));
  allResults.push(...checkExploitStatusValidation(data));
  allResults.push(...checkVendorAssetExclusion(data));
  allResults.push(...checkDnsblFalsePositives(data));
  allResults.push(...checkLlmContentQuarantine(data));
  allResults.push(...checkObjectSerialization(data));
  allResults.push(...checkTemplateResiduals(data));
  allResults.push(...checkToolFailureThreshold(data));
  allResults.push(...checkSectionContradictions(data));

  const passed = allResults.filter(r => r.severity === "pass").length;
  const warnings = allResults.filter(r => r.severity === "warn").length;
  const failures = allResults.filter(r => r.severity === "fail").length;

  let overallStatus: "PASS" | "WARN" | "FAIL";
  if (failures > 0) overallStatus = "FAIL";
  else if (warnings > 0) overallStatus = "WARN";
  else overallStatus = "PASS";

  return {
    results: allResults,
    passed,
    warnings,
    failures,
    overallStatus,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Quick validation for the most critical checks only (P0 issues).
 * Use this for fast pre-flight validation before full report generation.
 */
export function validateReportCritical(data: ReportData): LintReport {
  const allResults: LintResult[] = [];

  allResults.push(...checkExploitStatusValidation(data));
  allResults.push(...checkVendorAssetExclusion(data));
  allResults.push(...checkToolFailureThreshold(data));
  allResults.push(...checkObjectSerialization(data));

  const passed = allResults.filter(r => r.severity === "pass").length;
  const warnings = allResults.filter(r => r.severity === "warn").length;
  const failures = allResults.filter(r => r.severity === "fail").length;

  let overallStatus: "PASS" | "WARN" | "FAIL";
  if (failures > 0) overallStatus = "FAIL";
  else if (warnings > 0) overallStatus = "WARN";
  else overallStatus = "PASS";

  return {
    results: allResults,
    passed,
    warnings,
    failures,
    overallStatus,
    timestamp: new Date().toISOString(),
  };
}

/**
 * Format lint report as human-readable text for inclusion in report cover
 * or operator review.
 */
export function formatLintReport(report: LintReport): string {
  const lines: string[] = [];
  lines.push(`═══ Report Validation Results ═══`);
  lines.push(`Status: ${report.overallStatus} | ${report.passed} passed, ${report.warnings} warnings, ${report.failures} failures`);
  lines.push(`Timestamp: ${report.timestamp}`);
  lines.push(``);

  if (report.failures > 0) {
    lines.push(`── FAILURES (blocks emission) ──`);
    for (const r of report.results.filter(r => r.severity === "fail")) {
      lines.push(`  ✗ [${r.check}] ${r.message}`);
      if (r.details) lines.push(`    → ${r.details}`);
      if (r.location) lines.push(`    @ ${r.location}`);
    }
    lines.push(``);
  }

  if (report.warnings > 0) {
    lines.push(`── WARNINGS (quality advisory) ──`);
    for (const r of report.results.filter(r => r.severity === "warn")) {
      lines.push(`  ⚠ [${r.check}] ${r.message}`);
      if (r.details) lines.push(`    → ${r.details}`);
      if (r.location) lines.push(`    @ ${r.location}`);
    }
    lines.push(``);
  }

  return lines.join("\n");
}

// Export individual check functions for targeted use
export {
  checkCountReconciliation,
  checkRatingConsistency,
  checkExploitStatusValidation,
  checkVendorAssetExclusion,
  checkDnsblFalsePositives,
  checkLlmContentQuarantine,
  checkObjectSerialization,
  checkTemplateResiduals,
  checkToolFailureThreshold,
  checkSectionContradictions,
  isVendorDomain,
  isDnsblQueryError,
};
