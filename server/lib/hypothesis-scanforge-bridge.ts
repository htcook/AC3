// ─────────────────────────────────────────────────────────────────────────────
// Hypothesis → ScanForge Bridge
// ─────────────────────────────────────────────────────────────────────────────
// Wires high-confidence vulnerability hypotheses from the post-recon hypothesis
// generator into the ScanForge active scan plan, so active scanning automatically
// focuses on endpoints flagged by the hypothesis engine.
//
// Integration points:
//   1. Priority boost: Elevates target priority scores in ActiveScanPlan
//   2. Nuclei tag injection: Adds vuln-class-specific nuclei templates
//   3. ScanForge flag augmentation: Adds targeted port/script flags
//   4. Provenance: Links hypothesis → scan config for audit trail
//
// Author: Harrison Cook — AceofCloud (https://aceofcloud.com)
// ─────────────────────────────────────────────────────────────────────────────

import type { ActiveScanPlan, ActiveScanTarget, HandoffProvenance, ScanForgeScanConfig, NucleiScanConfig } from './passive/active-handoff';

// ─── Types ───────────────────────────────────────────────────────────────────

export interface HypothesisPriorityAdjustment {
  endpoint: string;
  vulnClass: string;
  priority: 'critical' | 'high' | 'medium';
  reason: string;
}

export interface HypothesisScanEnrichment {
  /** Number of targets whose priority was boosted */
  targetsEnriched: number;
  /** Number of new nuclei tags injected */
  nucleiTagsInjected: number;
  /** Number of ScanForge configs augmented */
  scanforgeConfigsAugmented: number;
  /** Number of provenance records added */
  provenanceRecordsAdded: number;
  /** Details of each enrichment applied */
  enrichments: Array<{
    target: string;
    action: string;
    detail: string;
  }>;
}

// ─── Vuln Class → Nuclei Tag Mapping ─────────────────────────────────────────

const VULN_CLASS_TO_NUCLEI_TAGS: Record<string, string[]> = {
  'xss': ['xss', 'dom-xss', 'reflected-xss', 'stored-xss'],
  'sqli': ['sqli', 'sql-injection', 'blind-sqli', 'error-based-sqli'],
  'ssrf': ['ssrf', 'server-side-request-forgery'],
  'idor': ['idor', 'insecure-direct-object-reference', 'broken-access-control'],
  'rce': ['rce', 'remote-code-execution', 'command-injection', 'code-injection'],
  'lfi': ['lfi', 'local-file-inclusion', 'path-traversal', 'directory-traversal'],
  'rfi': ['rfi', 'remote-file-inclusion'],
  'xxe': ['xxe', 'xml-external-entity'],
  'ssti': ['ssti', 'server-side-template-injection', 'template-injection'],
  'auth-bypass': ['auth-bypass', 'authentication-bypass', 'broken-authentication'],
  'csrf': ['csrf', 'cross-site-request-forgery'],
  'open-redirect': ['open-redirect', 'redirect'],
  'file-upload': ['file-upload', 'unrestricted-upload'],
  'deserialization': ['deserialization', 'insecure-deserialization'],
  'jwt': ['jwt', 'json-web-token'],
  'cors': ['cors', 'misconfiguration'],
  'information-disclosure': ['exposure', 'disclosure', 'information-disclosure'],
  'privilege-escalation': ['privilege-escalation', 'broken-access-control'],
  'race-condition': ['race-condition', 'toctou'],
  'business-logic': ['business-logic', 'logic-flaw'],
  'api-abuse': ['api', 'graphql', 'rest-api'],
  'subdomain-takeover': ['takeover', 'subdomain-takeover'],
  'cache-poisoning': ['cache-poisoning', 'web-cache'],
  'prototype-pollution': ['prototype-pollution'],
  'crlf-injection': ['crlf', 'header-injection'],
};

// ─── Vuln Class → ScanForge Script Categories ───────────────────────────────

const VULN_CLASS_TO_SCANFORGE_SCRIPTS: Record<string, string[]> = {
  'xss': ['--script=http-stored-xss,http-dombased-xss,http-phpself-xss'],
  'sqli': ['--script=http-sql-injection'],
  'rce': ['--script=http-shellshock,http-vuln-cve*'],
  'lfi': ['--script=http-passwd'],
  'xxe': ['--script=http-xml-external-entity'],
  'auth-bypass': ['--script=http-auth-finder,http-default-accounts,http-brute'],
  'information-disclosure': ['--script=http-headers,http-methods,http-trace,http-config-backup'],
  'subdomain-takeover': ['--script=dns-nsid,dns-zone-transfer'],
};

// ─── Priority Boost Values ───────────────────────────────────────────────────

const PRIORITY_BOOST: Record<string, number> = {
  critical: 25,
  high: 15,
  medium: 8,
};

// ─── Core Bridge Functions ───────────────────────────────────────────────────

/**
 * Enrich an ActiveScanPlan with hypothesis-derived priority adjustments.
 * This is the main integration point — call after generateActiveScanPlan()
 * and before the scan configs are dispatched to the scan server.
 *
 * Mutations applied to the plan:
 *   1. Target priority scores are boosted based on hypothesis confidence
 *   2. Nuclei configs get additional vuln-class-specific template tags
 *   3. ScanForge configs get targeted script flags
 *   4. Provenance records link hypotheses to scan configs
 *   5. Targets are re-sorted by updated priority
 */
export function enrichScanPlanWithHypotheses(
  plan: ActiveScanPlan,
  adjustments: HypothesisPriorityAdjustment[],
): HypothesisScanEnrichment {
  if (!adjustments.length || !plan.targets.length) {
    return {
      targetsEnriched: 0,
      nucleiTagsInjected: 0,
      scanforgeConfigsAugmented: 0,
      provenanceRecordsAdded: 0,
      enrichments: [],
    };
  }

  const enrichments: HypothesisScanEnrichment['enrichments'] = [];
  let nucleiTagsInjected = 0;
  let scanforgeConfigsAugmented = 0;
  let provenanceRecordsAdded = 0;
  const enrichedTargets = new Set<string>();

  // Group adjustments by target hostname for efficient lookup
  const adjustmentsByTarget = new Map<string, HypothesisPriorityAdjustment[]>();
  for (const adj of adjustments) {
    // Extract hostname from endpoint (e.g., "https://example.com/api/v1" → "example.com")
    const hostname = extractHostname(adj.endpoint);
    if (!hostname) continue;

    if (!adjustmentsByTarget.has(hostname)) {
      adjustmentsByTarget.set(hostname, []);
    }
    adjustmentsByTarget.get(hostname)!.push(adj);
  }

  // ── Step 1: Boost target priorities ──────────────────────────────────────
  for (const target of plan.targets) {
    const targetAdjs = findMatchingAdjustments(target.hostname, adjustmentsByTarget);
    if (!targetAdjs.length) continue;

    enrichedTargets.add(target.hostname);
    const originalPriority = target.priority;

    // Apply the highest boost from matching hypotheses
    const maxBoost = Math.max(...targetAdjs.map(a => PRIORITY_BOOST[a.priority] || 0));
    target.priority = Math.min(100, target.priority + maxBoost);

    // Append hypothesis signals to triggering signals
    for (const adj of targetAdjs) {
      target.triggeringSignals.push(`[HYPOTHESIS] ${adj.vulnClass}: ${adj.reason}`);
    }

    // Update rationale
    target.rationale += ` | Hypothesis boost: +${maxBoost} (${targetAdjs.length} hypotheses)`;

    enrichments.push({
      target: target.hostname,
      action: 'priority_boost',
      detail: `Priority ${originalPriority} → ${target.priority} (+${maxBoost}) from ${targetAdjs.length} hypothesis(es)`,
    });
  }

  // ── Step 2: Inject nuclei template tags ─────────────────────────────────
  for (const nucleiCfg of plan.nucleiConfigs) {
    const targetAdjs = findMatchingAdjustments(nucleiCfg.target, adjustmentsByTarget);
    if (!targetAdjs.length) continue;

    const existingTags = new Set(nucleiCfg.tags);
    const newTags: string[] = [];

    for (const adj of targetAdjs) {
      const vulnKey = normalizeVulnClass(adj.vulnClass);
      const mappedTags = VULN_CLASS_TO_NUCLEI_TAGS[vulnKey] || [];
      for (const tag of mappedTags) {
        if (!existingTags.has(tag)) {
          newTags.push(tag);
          existingTags.add(tag);
        }
      }
    }

    if (newTags.length > 0) {
      nucleiCfg.tags.push(...newTags);
      nucleiTagsInjected += newTags.length;

      // Elevate severity filter if hypothesis is critical
      const hasCritical = targetAdjs.some(a => a.priority === 'critical');
      if (hasCritical && nucleiCfg.severityFilter !== 'info,low,medium,high,critical') {
        nucleiCfg.severityFilter = 'info,low,medium,high,critical';
      }

      nucleiCfg.rationale += ` | Hypothesis-injected tags: ${newTags.join(', ')}`;

      enrichments.push({
        target: nucleiCfg.target,
        action: 'nuclei_tag_injection',
        detail: `Added ${newTags.length} hypothesis-derived template tags: ${newTags.slice(0, 5).join(', ')}${newTags.length > 5 ? '...' : ''}`,
      });
    }
  }

  // ── Step 3: Augment ScanForge configs ───────────────────────────────────
  for (const scanCfg of plan.scanConfigs) {
    const targetAdjs = findMatchingAdjustments(scanCfg.target, adjustmentsByTarget);
    if (!targetAdjs.length) continue;

    const additionalFlags: string[] = [];
    for (const adj of targetAdjs) {
      const vulnKey = normalizeVulnClass(adj.vulnClass);
      const scripts = VULN_CLASS_TO_SCANFORGE_SCRIPTS[vulnKey];
      if (scripts) {
        for (const flag of scripts) {
          if (!scanCfg.flags.includes(flag)) {
            additionalFlags.push(flag);
          }
        }
      }
    }

    if (additionalFlags.length > 0) {
      scanCfg.flags += ' ' + additionalFlags.join(' ');
      scanCfg.rationale += ` | Hypothesis-targeted scripts: ${additionalFlags.join(', ')}`;
      scanforgeConfigsAugmented++;

      enrichments.push({
        target: scanCfg.target,
        action: 'scanforge_augmentation',
        detail: `Added ${additionalFlags.length} hypothesis-targeted script flags`,
      });
    }
  }

  // ── Step 4: Add provenance records ──────────────────────────────────────
  for (const adj of adjustments) {
    const hostname = extractHostname(adj.endpoint);
    if (!hostname) continue;

    // Only add provenance for targets that exist in the plan
    const targetExists = plan.targets.some(t => t.hostname === hostname || hostname.includes(t.hostname) || t.hostname.includes(hostname));
    if (!targetExists) continue;

    plan.provenance.push({
      passiveObservationId: `hypothesis-${hostname}-${normalizeVulnClass(adj.vulnClass)}`,
      passiveSignal: `Hypothesis: ${adj.vulnClass} vulnerability predicted at ${adj.endpoint}`,
      activeTool: mapVulnClassToTool(adj.vulnClass),
      target: hostname,
      rationale: adj.reason,
    });
    provenanceRecordsAdded++;
  }

  // ── Step 5: Re-sort targets by updated priority ─────────────────────────
  plan.targets.sort((a, b) => b.priority - a.priority);

  return {
    targetsEnriched: enrichedTargets.size,
    nucleiTagsInjected,
    scanforgeConfigsAugmented,
    provenanceRecordsAdded,
    enrichments,
  };
}

// ─── Helper Functions ────────────────────────────────────────────────────────

/**
 * Extract hostname from a URL or endpoint string.
 */
function extractHostname(endpoint: string): string {
  try {
    if (endpoint.startsWith('http://') || endpoint.startsWith('https://')) {
      return new URL(endpoint).hostname;
    }
    // Might already be a hostname
    return endpoint.split('/')[0].split(':')[0];
  } catch {
    return endpoint.split('/')[0].split(':')[0];
  }
}

/**
 * Normalize vulnerability class names to match our mapping keys.
 */
function normalizeVulnClass(vulnClass: string): string {
  const normalized = vulnClass
    .toLowerCase()
    .replace(/[_\s]+/g, '-')
    .replace(/cross-site-scripting/g, 'xss')
    .replace(/sql-injection/g, 'sqli')
    .replace(/server-side-request-forgery/g, 'ssrf')
    .replace(/insecure-direct-object-reference/g, 'idor')
    .replace(/remote-code-execution/g, 'rce')
    .replace(/local-file-inclusion/g, 'lfi')
    .replace(/remote-file-inclusion/g, 'rfi')
    .replace(/xml-external-entity/g, 'xxe')
    .replace(/server-side-template-injection/g, 'ssti')
    .replace(/cross-site-request-forgery/g, 'csrf');

  return normalized;
}

/**
 * Find adjustments that match a target hostname (fuzzy match).
 */
function findMatchingAdjustments(
  hostname: string,
  adjustmentsByTarget: Map<string, HypothesisPriorityAdjustment[]>,
): HypothesisPriorityAdjustment[] {
  // Direct match
  const direct = adjustmentsByTarget.get(hostname);
  if (direct) return direct;

  // Fuzzy match: check if any adjustment hostname contains or is contained by the target
  const matches: HypothesisPriorityAdjustment[] = [];
  for (const [adjHostname, adjs] of adjustmentsByTarget) {
    if (hostname.includes(adjHostname) || adjHostname.includes(hostname)) {
      matches.push(...adjs);
    }
  }
  return matches;
}

/**
 * Map a vulnerability class to the most appropriate active scanning tool.
 */
function mapVulnClassToTool(vulnClass: string): 'scanforge-discovery' | 'nuclei' | 'zap' | 'dast' {
  const normalized = normalizeVulnClass(vulnClass);
  const nucleiVulns = ['xss', 'sqli', 'ssrf', 'lfi', 'rfi', 'xxe', 'ssti', 'cors', 'information-disclosure', 'subdomain-takeover', 'crlf-injection', 'prototype-pollution', 'cache-poisoning'];
  const zapVulns = ['xss', 'csrf', 'auth-bypass', 'business-logic', 'api-abuse'];
  const scanforgeVulns = ['rce', 'deserialization'];

  if (scanforgeVulns.includes(normalized)) return 'scanforge-discovery';
  if (zapVulns.includes(normalized)) return 'zap';
  if (nucleiVulns.includes(normalized)) return 'nuclei';
  return 'nuclei'; // Default to nuclei for unknown vuln classes
}

/**
 * Generate a human-readable summary of hypothesis enrichments applied to a scan plan.
 */
export function formatHypothesisEnrichmentSummary(enrichment: HypothesisScanEnrichment): string {
  if (enrichment.targetsEnriched === 0) {
    return 'No hypothesis-based enrichments applied (no matching targets in scan plan).';
  }

  const lines = [
    `Hypothesis-driven scan enrichment: ${enrichment.targetsEnriched} targets boosted`,
    `  Nuclei tags injected: ${enrichment.nucleiTagsInjected}`,
    `  ScanForge configs augmented: ${enrichment.scanforgeConfigsAugmented}`,
    `  Provenance records added: ${enrichment.provenanceRecordsAdded}`,
  ];

  if (enrichment.enrichments.length > 0) {
    lines.push('  Details:');
    for (const e of enrichment.enrichments.slice(0, 10)) {
      lines.push(`    [${e.action}] ${e.target}: ${e.detail}`);
    }
    if (enrichment.enrichments.length > 10) {
      lines.push(`    ... and ${enrichment.enrichments.length - 10} more`);
    }
  }

  return lines.join('\n');
}
