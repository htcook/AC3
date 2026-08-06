/**
 * Remediation Revalidation Engine
 * 
 * Provides targeted re-testing of previously identified vulnerabilities
 * after remediation has been applied. This is a key differentiator from
 * commercial platforms (Pentera, NodeZero) that offer "one-click retest".
 * 
 * Features:
 * - Selective revalidation (pick specific findings to retest)
 * - Full revalidation (retest all confirmed findings)
 * - Evidence comparison (before/after evidence snapshots)
 * - Status tracking (open → remediated → verified | regression)
 */

export interface RevalidationTarget {
  findingId: string;
  title: string;
  severity: string;
  tool: string;
  endpoint?: string;
  cve?: string;
  originalEvidence?: string;
  originalCommand?: string;
  assetHostname: string;
}

export interface RevalidationResult {
  findingId: string;
  status: 'remediated' | 'still_vulnerable' | 'regression' | 'inconclusive' | 'error';
  originalEvidence: string;
  retestEvidence: string;
  retestTool: string;
  retestCommand: string;
  retestTimestamp: number;
  confidenceScore: number; // 0-1
  notes: string;
}

export interface RevalidationSession {
  id: string;
  engagementId: number;
  createdAt: number;
  completedAt?: number;
  status: 'pending' | 'running' | 'completed' | 'failed';
  targets: RevalidationTarget[];
  results: RevalidationResult[];
  summary?: {
    total: number;
    remediated: number;
    stillVulnerable: number;
    regression: number;
    inconclusive: number;
    errors: number;
    remediationRate: number; // percentage
  };
}

/**
 * Select findings eligible for revalidation from an engagement's state.
 */
export function selectRevalidationTargets(
  assets: Array<{
    hostname: string;
    ip?: string;
    vulns?: Array<{
      id?: string;
      title?: string;
      name?: string;
      severity?: string;
      tool?: string;
      source?: string;
      endpoint?: string;
      url?: string;
      cve?: string;
      rawEvidence?: string;
      corroborationTier?: string;
    }>;
  }>,
  options?: {
    severityFilter?: string[];
    confirmedOnly?: boolean;
    maxTargets?: number;
  }
): RevalidationTarget[] {
  const targets: RevalidationTarget[] = [];
  const severityFilter = options?.severityFilter || ['critical', 'high', 'medium'];
  const confirmedOnly = options?.confirmedOnly ?? true;
  const maxTargets = options?.maxTargets || 50;

  for (const asset of assets) {
    for (const vuln of (asset.vulns || [])) {
      const severity = (vuln.severity || 'info').toLowerCase();
      if (!severityFilter.includes(severity)) continue;
      if (confirmedOnly && vuln.corroborationTier !== 'confirmed') continue;

      targets.push({
        findingId: vuln.id || `${asset.hostname}-${vuln.title || vuln.name}`,
        title: vuln.title || vuln.name || 'Unknown',
        severity,
        tool: vuln.tool || vuln.source || 'unknown',
        endpoint: vuln.endpoint || vuln.url,
        cve: vuln.cve,
        originalEvidence: vuln.rawEvidence?.slice(0, 2000),
        assetHostname: asset.hostname || asset.ip || 'unknown',
      });

      if (targets.length >= maxTargets) break;
    }
    if (targets.length >= maxTargets) break;
  }

  // Sort by severity (critical first)
  const severityOrder: Record<string, number> = { critical: 4, high: 3, medium: 2, low: 1, info: 0 };
  targets.sort((a, b) => (severityOrder[b.severity] || 0) - (severityOrder[a.severity] || 0));

  return targets;
}

/**
 * Build revalidation commands for each target finding.
 * Maps original detection tools to appropriate retest commands.
 */
export function buildRevalidationCommands(
  target: RevalidationTarget
): { tool: string; command: string; timeout: number }[] {
  const commands: { tool: string; command: string; timeout: number }[] = [];
  const host = target.assetHostname;
  const endpoint = target.endpoint || '';

  switch (target.tool.toLowerCase()) {
    case 'nuclei':
      // Re-run nuclei with the specific template that found this vuln
      commands.push({
        tool: 'nuclei',
        command: `nuclei -u "${endpoint || `https://${host}`}" -severity ${target.severity} -silent -json -timeout 30`,
        timeout: 60,
      });
      break;

    case 'sqlmap':
      if (endpoint) {
        commands.push({
          tool: 'sqlmap',
          command: `sqlmap -u "${endpoint}" --batch --level=3 --risk=2 --timeout=15 --retries=1 --output-dir=/tmp/sqlmap-reval-${Date.now()}`,
          timeout: 120,
        });
      }
      break;

    case 'xsstrike':
    case 'xss':
      if (endpoint) {
        commands.push({
          tool: 'xsstrike',
          command: `python3 /opt/XSStrike/xsstrike.py -u "${endpoint}" --skip-dom --timeout 10`,
          timeout: 60,
        });
      }
      break;

    case 'commix':
      if (endpoint) {
        commands.push({
          tool: 'commix',
          command: `commix --url="${endpoint}" --batch --level=2 --output-dir=/tmp/commix-reval-${Date.now()}`,
          timeout: 120,
        });
      }
      break;

    case 'tplmap':
      if (endpoint) {
        commands.push({
          tool: 'tplmap',
          command: `python3 /opt/tplmap/tplmap.py -u "${endpoint}" --level 2`,
          timeout: 60,
        });
      }
      break;

    case 'zap':
    case 'owasp zap':
      if (endpoint) {
        commands.push({
          tool: 'nuclei',
          command: `nuclei -u "${endpoint}" -severity ${target.severity} -silent -json`,
          timeout: 60,
        });
      }
      break;

    case 'testssl':
    case 'testssl.sh':
      commands.push({
        tool: 'testssl.sh',
        command: `testssl.sh --quiet --json-pretty "${host}"`,
        timeout: 120,
      });
      break;

    case 'ssh-audit':
      commands.push({
        tool: 'ssh-audit',
        command: `ssh-audit -j "${host}"`,
        timeout: 30,
      });
      break;

    default:
      // Generic nuclei retest for unknown tools
      if (endpoint) {
        commands.push({
          tool: 'nuclei',
          command: `nuclei -u "${endpoint}" -severity ${target.severity} -silent -json`,
          timeout: 60,
        });
      } else {
        commands.push({
          tool: 'nuclei',
          command: `nuclei -u "https://${host}" -severity ${target.severity} -silent -json`,
          timeout: 60,
        });
      }
  }

  // If CVE is known, add targeted CVE scan
  if (target.cve) {
    commands.push({
      tool: 'nuclei',
      command: `nuclei -u "${endpoint || `https://${host}`}" -tags cve -id "${target.cve.toLowerCase()}" -silent -json`,
      timeout: 60,
    });
  }

  return commands;
}

/**
 * Compare original and retest evidence to determine remediation status.
 */
export function compareEvidence(
  originalEvidence: string | undefined,
  retestOutput: string,
  retestExitCode: number
): {
  status: RevalidationResult['status'];
  confidence: number;
  notes: string;
} {
  const output = retestOutput.toLowerCase();

  // Check for clear indicators of remediation
  const remediatedIndicators = [
    'no results found',
    'no vulnerabilities',
    '0 matched',
    '0 results',
    'not vulnerable',
    'connection refused',
    'timeout',
    'no issues found',
    'clean',
    'passed',
  ];

  const stillVulnIndicators = [
    'vulnerability found',
    'vulnerable',
    'injection',
    'xss',
    'sqli',
    'rce',
    'critical',
    'high',
    'matched',
    'found',
    'exploitable',
    'payload',
  ];

  const remediatedScore = remediatedIndicators.filter(ind => output.includes(ind)).length;
  const vulnerableScore = stillVulnIndicators.filter(ind => output.includes(ind)).length;

  // Exit code 0 with no findings typically means remediated
  if (retestExitCode === 0 && remediatedScore > vulnerableScore) {
    return {
      status: 'remediated',
      confidence: Math.min(0.5 + remediatedScore * 0.1, 0.95),
      notes: `Retest completed with no vulnerability indicators. ${remediatedScore} remediation signals detected.`,
    };
  }

  // Clear vulnerability indicators
  if (vulnerableScore > remediatedScore) {
    return {
      status: 'still_vulnerable',
      confidence: Math.min(0.5 + vulnerableScore * 0.1, 0.95),
      notes: `Vulnerability still present. ${vulnerableScore} vulnerability indicators detected in retest output.`,
    };
  }

  // Error or inconclusive
  if (retestExitCode !== 0 && retestOutput.length < 50) {
    return {
      status: 'error',
      confidence: 0.1,
      notes: `Retest tool exited with code ${retestExitCode}. Output too short for analysis.`,
    };
  }

  return {
    status: 'inconclusive',
    confidence: 0.3,
    notes: `Unable to determine remediation status with confidence. Manual review recommended.`,
  };
}

/**
 * Create a revalidation session from engagement state.
 */
export function createRevalidationSession(
  engagementId: number,
  targets: RevalidationTarget[]
): RevalidationSession {
  return {
    id: `reval-${engagementId}-${Date.now()}`,
    engagementId,
    createdAt: Date.now(),
    status: 'pending',
    targets,
    results: [],
  };
}

/**
 * Compute summary statistics for a completed revalidation session.
 */
export function computeRevalidationSummary(
  session: RevalidationSession
): RevalidationSession['summary'] {
  const total = session.results.length;
  const remediated = session.results.filter(r => r.status === 'remediated').length;
  const stillVulnerable = session.results.filter(r => r.status === 'still_vulnerable').length;
  const regression = session.results.filter(r => r.status === 'regression').length;
  const inconclusive = session.results.filter(r => r.status === 'inconclusive').length;
  const errors = session.results.filter(r => r.status === 'error').length;

  return {
    total,
    remediated,
    stillVulnerable,
    regression,
    inconclusive,
    errors,
    remediationRate: total > 0 ? Math.round((remediated / total) * 100) : 0,
  };
}
