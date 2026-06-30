/**
 * Nuclei JSON Output Parser
 * ═════════════════════════
 * Parses Nuclei's structured JSON output (from the `-json` or `-jsonl` flag)
 * to extract severity, matched template, extracted data, matched-at URL,
 * curl command, and other rich metadata for exploit result recording.
 *
 * Nuclei JSON output format (one JSON object per line):
 * {
 *   "template-id": "CVE-2021-41773",
 *   "template-path": "/root/nuclei-templates/cves/2021/CVE-2021-41773.yaml",
 *   "info": {
 *     "name": "Apache HTTP Server Path Traversal",
 *     "author": ["dhiyaneshdk"],
 *     "tags": ["cve","cve2021","apache","rce","lfi","kev"],
 *     "severity": "critical",
 *     "description": "A flaw was found in a change made to path normalization...",
 *     "reference": ["https://nvd.nist.gov/vuln/detail/CVE-2021-41773"],
 *     "classification": {
 *       "cve-id": "CVE-2021-41773",
 *       "cwe-id": ["CWE-22"],
 *       "cvss-metrics": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
 *       "cvss-score": 9.8
 *     }
 *   },
 *   "type": "http",
 *   "host": "http://10.0.0.1:80",
 *   "matched-at": "http://10.0.0.1:80/cgi-bin/.%2e/.%2e/.%2e/.%2e/etc/passwd",
 *   "extracted-results": ["root:x:0:0:root:/root:/bin/bash"],
 *   "ip": "10.0.0.1",
 *   "timestamp": "2024-01-15T10:30:00.000Z",
 *   "curl-command": "curl -X GET 'http://10.0.0.1/cgi-bin/.%2e/...'",
 *   "matcher-status": true,
 *   "matched-line": null
 * }
 */

// ═══════════════════════════════════════════════════════════════════════
// §1 — TYPES
// ═══════════════════════════════════════════════════════════════════════

export interface NucleiJsonFinding {
  /** Nuclei template ID (e.g. "CVE-2021-41773", "apache-detect") */
  templateId: string;
  /** Full template path on disk */
  templatePath?: string;
  /** Template info block */
  info: {
    name: string;
    author: string[];
    tags: string[];
    severity: NucleiSeverity;
    description?: string;
    reference?: string[];
    classification?: {
      cveId?: string;
      cweId?: string[];
      cvssMetrics?: string;
      cvssScore?: number;
    };
  };
  /** Protocol type (http, tcp, dns, ssl, etc.) */
  type: string;
  /** Target host URL */
  host: string;
  /** Exact URL/endpoint where the vulnerability was matched */
  matchedAt: string;
  /** Extracted data from the response (e.g. file contents, version strings) */
  extractedResults: string[];
  /** Target IP address */
  ip?: string;
  /** Timestamp of the finding */
  timestamp: string;
  /** Curl command to reproduce the finding */
  curlCommand?: string;
  /** Whether the matcher status is true (confirmed match) */
  matcherStatus: boolean;
  /** Matched line from response body */
  matchedLine?: string;
  /** Interaction data for OOB testing */
  interaction?: {
    protocol: string;
    uniqueId: string;
    fullId: string;
    qType?: string;
    rawRequest?: string;
    rawResponse?: string;
    remoteAddress?: string;
    timestamp?: string;
  };
}

export type NucleiSeverity = 'critical' | 'high' | 'medium' | 'low' | 'info' | 'unknown';

export interface NucleiParseResult {
  /** All parsed findings */
  findings: NucleiJsonFinding[];
  /** Summary statistics */
  stats: {
    total: number;
    critical: number;
    high: number;
    medium: number;
    low: number;
    info: number;
  };
  /** Unique CVEs found */
  cves: string[];
  /** Unique CWEs found */
  cwes: string[];
  /** Unique templates that matched */
  matchedTemplates: string[];
  /** Whether any findings indicate confirmed exploitation (not just detection) */
  hasExploitableFindings: boolean;
  /** Highest severity found */
  highestSeverity: NucleiSeverity;
  /** Extracted data across all findings (file contents, credentials, etc.) */
  allExtractedData: string[];
  /** All curl commands for reproduction */
  curlCommands: string[];
  /** Raw parse errors (for debugging) */
  parseErrors: string[];
}

export interface NucleiAccessAssessment {
  /** Inferred access level from Nuclei findings */
  accessLevel: 'none' | 'info_disclosure' | 'file_read' | 'file_write' | 'credential_access' | 'command_execution' | 'user_shell' | 'root_shell' | 'database_access';
  /** Confidence in the access assessment (0-100) */
  confidence: number;
  /** Explanation of how access level was determined */
  reasoning: string;
  /** Evidence strings supporting the assessment */
  evidence: string[];
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — JSON PARSER
// ═══════════════════════════════════════════════════════════════════════

/**
 * Parse Nuclei JSON/JSONL output into structured findings.
 * Handles both single JSON objects and newline-delimited JSON (JSONL).
 * Also handles mixed output where some lines are plain text (Nuclei progress/stats).
 */
export function parseNucleiJsonOutput(rawOutput: string): NucleiParseResult {
  const findings: NucleiJsonFinding[] = [];
  const parseErrors: string[] = [];
  const stats = { total: 0, critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  const cveSet = new Set<string>();
  const cweSet = new Set<string>();
  const templateSet = new Set<string>();
  const allExtractedData: string[] = [];
  const curlCommands: string[] = [];

  if (!rawOutput || rawOutput.trim().length === 0) {
    return {
      findings, stats, cves: [], cwes: [], matchedTemplates: [],
      hasExploitableFindings: false, highestSeverity: 'unknown',
      allExtractedData: [], curlCommands: [], parseErrors: [],
    };
  }

  // Split by newlines and try to parse each line as JSON
  const lines = rawOutput.split('\n').filter(l => l.trim().length > 0);

  for (const line of lines) {
    const trimmed = line.trim();
    // Skip non-JSON lines (progress bars, stats, empty lines)
    if (!trimmed.startsWith('{')) continue;

    try {
      const raw = JSON.parse(trimmed);
      const finding = normalizeNucleiJson(raw);
      if (finding) {
        findings.push(finding);

        // Update stats
        stats.total++;
        const sev = finding.info.severity;
        if (sev === 'critical') stats.critical++;
        else if (sev === 'high') stats.high++;
        else if (sev === 'medium') stats.medium++;
        else if (sev === 'low') stats.low++;
        else stats.info++;

        // Collect CVEs
        if (finding.info.classification?.cveId) {
          cveSet.add(finding.info.classification.cveId);
        }
        // Also check template ID for CVE pattern
        if (/^CVE-\d{4}-\d+$/i.test(finding.templateId)) {
          cveSet.add(finding.templateId.toUpperCase());
        }

        // Collect CWEs
        if (finding.info.classification?.cweId) {
          for (const cwe of finding.info.classification.cweId) {
            cweSet.add(cwe);
          }
        }

        // Collect templates
        templateSet.add(finding.templateId);

        // Collect extracted data
        if (finding.extractedResults.length > 0) {
          allExtractedData.push(...finding.extractedResults);
        }

        // Collect curl commands
        if (finding.curlCommand) {
          curlCommands.push(finding.curlCommand);
        }
      }
    } catch (err: any) {
      // Only log parse errors for lines that look like they should be JSON
      if (trimmed.startsWith('{') && trimmed.endsWith('}')) {
        parseErrors.push(`Failed to parse JSON line: ${trimmed.slice(0, 100)}... Error: ${err.message}`);
      }
    }
  }

  // Determine highest severity
  const severityOrder: NucleiSeverity[] = ['critical', 'high', 'medium', 'low', 'info', 'unknown'];
  let highestSeverity: NucleiSeverity = 'unknown';
  for (const sev of severityOrder) {
    if (findings.some(f => f.info.severity === sev)) {
      highestSeverity = sev;
      break;
    }
  }

  // Determine if any findings are exploitable (not just info/detection)
  const hasExploitableFindings = findings.some(f =>
    (f.info.severity === 'critical' || f.info.severity === 'high') &&
    f.matcherStatus &&
    (f.extractedResults.length > 0 ||
     f.info.tags.some(t => /rce|lfi|sqli|xss|ssrf|cmdi|upload|deserialization|auth.?bypass/i.test(t)))
  );

  return {
    findings, stats,
    cves: Array.from(cveSet),
    cwes: Array.from(cweSet),
    matchedTemplates: Array.from(templateSet),
    hasExploitableFindings,
    highestSeverity,
    allExtractedData,
    curlCommands,
    parseErrors,
  };
}

/**
 * Normalize a raw Nuclei JSON object into our structured type.
 * Handles both kebab-case (Nuclei v2/v3) and camelCase field names.
 */
function normalizeNucleiJson(raw: any): NucleiJsonFinding | null {
  if (!raw || typeof raw !== 'object') return null;

  // Template ID is required
  const templateId = raw['template-id'] || raw.templateId || raw.template_id;
  if (!templateId) return null;

  const info = raw.info || {};
  const classification = info.classification || {};

  return {
    templateId,
    templatePath: raw['template-path'] || raw.templatePath || raw.template_path,
    info: {
      name: info.name || templateId,
      author: Array.isArray(info.author) ? info.author : (info.author ? [info.author] : []),
      tags: Array.isArray(info.tags) ? info.tags : (info.tags ? String(info.tags).split(',').map((t: string) => t.trim()) : []),
      severity: normalizeSeverity(info.severity),
      description: info.description,
      reference: Array.isArray(info.reference) ? info.reference : (info.reference ? [info.reference] : []),
      classification: {
        cveId: classification['cve-id'] || classification.cveId || classification.cve_id,
        cweId: Array.isArray(classification['cwe-id'] || classification.cweId || classification.cwe_id)
          ? (classification['cwe-id'] || classification.cweId || classification.cwe_id)
          : (classification['cwe-id'] || classification.cweId || classification.cwe_id)
            ? [classification['cwe-id'] || classification.cweId || classification.cwe_id]
            : undefined,
        cvssMetrics: classification['cvss-metrics'] || classification.cvssMetrics || classification.cvss_metrics,
        cvssScore: classification['cvss-score'] || classification.cvssScore || classification.cvss_score,
      },
    },
    type: raw.type || 'http',
    host: raw.host || '',
    matchedAt: raw['matched-at'] || raw.matchedAt || raw.matched_at || '',
    extractedResults: Array.isArray(raw['extracted-results'] || raw.extractedResults || raw.extracted_results)
      ? (raw['extracted-results'] || raw.extractedResults || raw.extracted_results)
      : [],
    ip: raw.ip,
    timestamp: raw.timestamp || new Date().toISOString(),
    curlCommand: raw['curl-command'] || raw.curlCommand || raw.curl_command,
    matcherStatus: raw['matcher-status'] ?? raw.matcherStatus ?? raw.matcher_status ?? true,
    matchedLine: raw['matched-line'] || raw.matchedLine || raw.matched_line || null,
    interaction: raw.interaction,
  };
}

function normalizeSeverity(sev: any): NucleiSeverity {
  if (!sev) return 'unknown';
  const s = String(sev).toLowerCase().trim();
  if (s === 'critical') return 'critical';
  if (s === 'high') return 'high';
  if (s === 'medium') return 'medium';
  if (s === 'low') return 'low';
  if (s === 'info' || s === 'informational') return 'info';
  return 'unknown';
}

// ═══════════════════════════════════════════════════════════════════════
// §3 — ACCESS LEVEL ASSESSMENT
// ═══════════════════════════════════════════════════════════════════════

/**
 * Assess the access level achieved based on Nuclei findings.
 * Analyzes template tags, extracted data, and severity to determine
 * what level of access the findings represent.
 */
export function assessNucleiAccessLevel(result: NucleiParseResult): NucleiAccessAssessment {
  if (result.findings.length === 0) {
    return { accessLevel: 'none', confidence: 90, reasoning: 'No Nuclei findings', evidence: [] };
  }

  const evidence: string[] = [];
  let accessLevel: NucleiAccessAssessment['accessLevel'] = 'info_disclosure';
  let confidence = 50;

  // Check extracted data for access indicators
  const allExtracted = result.allExtractedData.join('\n');

  // Root shell indicators
  if (/uid=0\(root\)|root:x:0:0/i.test(allExtracted)) {
    accessLevel = 'root_shell';
    confidence = 85;
    evidence.push('Root user information extracted (uid=0 or /etc/passwd root entry)');
  }

  // Command execution indicators
  if (/uid=\d+|whoami|hostname|uname/i.test(allExtracted) && accessLevel !== 'root_shell') {
    accessLevel = 'command_execution';
    confidence = 80;
    evidence.push('OS command output extracted (uid, whoami, hostname, or uname)');
  }

  // File read indicators
  if (/root:.*:0:0|\/bin\/bash|\/etc\/|\/var\/|\/home\//i.test(allExtracted) && accessLevel === 'info_disclosure') {
    accessLevel = 'file_read';
    confidence = 80;
    evidence.push('File system content extracted (passwd entries, file paths)');
  }

  // Credential access indicators
  if (/password[=:]\s*\S+|credentials|api[_-]?key|secret[_-]?key|token[=:]\s*\S+/i.test(allExtracted)) {
    if (accessLevel === 'info_disclosure' || accessLevel === 'file_read') {
      accessLevel = 'credential_access';
      confidence = 75;
      evidence.push('Credentials or API keys extracted from response');
    }
  }

  // Database access indicators
  if (/SELECT|INSERT|UPDATE|DELETE|information_schema|mysql|postgresql/i.test(allExtracted)) {
    accessLevel = 'database_access';
    confidence = 80;
    evidence.push('SQL query results or database information extracted');
  }

  // Check tags for exploit type indicators
  const allTags = result.findings.flatMap(f => f.info.tags);

  if (allTags.some(t => /^rce$/i.test(t))) {
    if (accessLevel === 'info_disclosure' || accessLevel === 'file_read') {
      accessLevel = 'command_execution';
      confidence = Math.max(confidence, 70);
      evidence.push('Template tagged as RCE (Remote Code Execution)');
    }
  }

  if (allTags.some(t => /^lfi$/i.test(t) || /^file-inclusion$/i.test(t))) {
    if (accessLevel === 'info_disclosure') {
      accessLevel = 'file_read';
      confidence = Math.max(confidence, 70);
      evidence.push('Template tagged as LFI (Local File Inclusion)');
    }
  }

  if (allTags.some(t => /^sqli$/i.test(t) || /^sql-injection$/i.test(t))) {
    if (accessLevel === 'info_disclosure') {
      accessLevel = 'database_access';
      confidence = Math.max(confidence, 65);
      evidence.push('Template tagged as SQLi (SQL Injection)');
    }
  }

  if (allTags.some(t => /^auth.?bypass$/i.test(t) || /^default.?login$/i.test(t))) {
    if (accessLevel === 'info_disclosure') {
      accessLevel = 'credential_access';
      confidence = Math.max(confidence, 65);
      evidence.push('Template tagged as auth bypass or default login');
    }
  }

  // Boost confidence for critical/high severity with extracted data
  if (result.highestSeverity === 'critical' && result.allExtractedData.length > 0) {
    confidence = Math.min(95, confidence + 15);
    evidence.push(`Critical severity with ${result.allExtractedData.length} extracted data items`);
  } else if (result.highestSeverity === 'high' && result.allExtractedData.length > 0) {
    confidence = Math.min(90, confidence + 10);
    evidence.push(`High severity with ${result.allExtractedData.length} extracted data items`);
  }

  // If only info-level findings with no extracted data, stay at info_disclosure
  if (result.highestSeverity === 'info' && result.allExtractedData.length === 0) {
    accessLevel = 'info_disclosure';
    confidence = 60;
    evidence.push('Only informational findings with no extracted data');
  }

  const reasoning = evidence.length > 0
    ? `Access level ${accessLevel} determined from: ${evidence.join('; ')}`
    : `Default info_disclosure — ${result.stats.total} findings at ${result.highestSeverity} severity`;

  return { accessLevel, confidence, reasoning, evidence };
}

// ═══════════════════════════════════════════════════════════════════════
// §4 — RICH EXPLOIT RESULT FORMATTING
// ═══════════════════════════════════════════════════════════════════════

/**
 * Format Nuclei findings into a rich exploit output string
 * suitable for recording in the exploit results database.
 */
export function formatNucleiExploitOutput(result: NucleiParseResult): string {
  if (result.findings.length === 0) return '';

  const sections: string[] = [];

  // Header
  sections.push(`═══ Nuclei Scan Results ═══`);
  sections.push(`Total: ${result.stats.total} findings (Critical: ${result.stats.critical}, High: ${result.stats.high}, Medium: ${result.stats.medium}, Low: ${result.stats.low}, Info: ${result.stats.info})`);

  if (result.cves.length > 0) {
    sections.push(`CVEs: ${result.cves.join(', ')}`);
  }

  sections.push('');

  // Individual findings (sorted by severity)
  const severityOrder: Record<NucleiSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3, info: 4, unknown: 5 };
  const sorted = [...result.findings].sort((a, b) =>
    (severityOrder[a.info.severity] ?? 5) - (severityOrder[b.info.severity] ?? 5)
  );

  for (const finding of sorted.slice(0, 20)) { // Limit to top 20 findings
    const sev = finding.info.severity.toUpperCase();
    sections.push(`[${sev}] ${finding.info.name} (${finding.templateId})`);
    sections.push(`  Matched: ${finding.matchedAt}`);

    if (finding.info.classification?.cveId) {
      sections.push(`  CVE: ${finding.info.classification.cveId}`);
    }
    if (finding.info.classification?.cvssScore) {
      sections.push(`  CVSS: ${finding.info.classification.cvssScore}`);
    }
    if (finding.extractedResults.length > 0) {
      sections.push(`  Extracted: ${finding.extractedResults.slice(0, 5).join(' | ').slice(0, 300)}`);
    }
    if (finding.curlCommand) {
      sections.push(`  Reproduce: ${finding.curlCommand.slice(0, 200)}`);
    }
    sections.push('');
  }

  if (sorted.length > 20) {
    sections.push(`... and ${sorted.length - 20} more findings`);
  }

  return sections.join('\n');
}

/**
 * Build a `-json` flag variant of a Nuclei command.
 * Takes an existing Nuclei command and adds `-json` flag for structured output.
 */
export function addJsonFlag(nucleiCommand: string): string {
  // If already has -json or -jsonl, return as-is
  if (/-json\b|-jsonl\b/.test(nucleiCommand)) return nucleiCommand;

  // Remove the pipe to head (we need full JSON output)
  let cmd = nucleiCommand.replace(/\s*2>&1\s*\|\s*head\s+-\d+/, '');

  // Add -json flag before any remaining pipe or end of command
  const pipeIdx = cmd.indexOf('|');
  if (pipeIdx > 0) {
    cmd = cmd.slice(0, pipeIdx).trim() + ' -json ' + cmd.slice(pipeIdx);
  } else {
    cmd = cmd.trim() + ' -json';
  }

  return cmd;
}
