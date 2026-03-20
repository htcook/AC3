/**
 * False Positive Suppression Ruleset
 * 
 * Configurable rules to filter out known false positives from engagement findings.
 * Based on analysis of the Full Red Team engagement (184 findings, ~65% FP rate).
 * 
 * FP Breakdown:
 *   nikto_header: 65 (35%) — Informational header presence/absence
 *   nmap_service: 30 (16%) — Service banner enumeration (not vulns)
 *   nikto_other: 22 (12%) — robots.txt, redirects, ETags, powered-by
 *   nuclei_cve: 19 (10%) — CVEs with empty descriptions (unverified)
 *   shodan_cve: 16 (9%) — Shodan-reported CVEs (unverified against target)
 *   config_finding: 14 (8%) — Informational config observations
 *   nikto_robots: 13 (7%) — robots.txt entries
 *   nikto_cookie: 3 (2%) — Cookie flag observations
 *   nikto_method: 1 (1%) — HTTP method observations
 */

export interface FPSuppressionRule {
  id: string;
  name: string;
  description: string;
  category: FPCategory;
  enabledByDefault: boolean;
  severityFilter: ("critical" | "high" | "medium" | "low" | "info")[];
  sourcePatterns: string[];
  titlePatterns: RegExp[];
  agentClassPatterns: string[];
  estimatedSuppression: number;
  tpRisk: "low" | "medium" | "high";
  rationale: string;
}

export type FPCategory =
  | "informational_header"
  | "service_banner"
  | "unverified_cve"
  | "config_observation"
  | "robots_disclosure"
  | "cookie_flag"
  | "http_method"
  | "etag_leak"
  | "redirect_info"
  | "duplicate_finding";

export const FP_SUPPRESSION_RULES: FPSuppressionRule[] = [
  {
    id: "nikto-uncommon-header",
    name: "Nikto Uncommon Header Reports",
    description: "Suppress Nikto findings that report standard security headers as 'uncommon'.",
    category: "informational_header",
    enabledByDefault: true,
    severityFilter: ["info", "low"],
    sourcePatterns: ["nikto"],
    titlePatterns: [
      /\[Nikto\] Uncommon header '(x-frame-options|x-xss-protection|x-content-type-options|referrer-policy|strict-transport-security|access-control-allow-origin|access-control-allow-credentials|content-security-policy)'/i,
    ],
    agentClassPatterns: [],
    estimatedSuppression: 45,
    tpRisk: "low",
    rationale: "Nikto flags standard security headers as 'uncommon'. Their presence is a security best practice, not a vulnerability.",
  },
  {
    id: "nikto-missing-header",
    name: "Nikto Missing Header Reports",
    description: "Suppress Nikto findings about missing anti-clickjacking or security headers.",
    category: "informational_header",
    enabledByDefault: true,
    severityFilter: ["info", "low"],
    sourcePatterns: ["nikto"],
    titlePatterns: [
      /\[Nikto\] The anti-clickjacking X-Frame-Options header is not present/i,
      /\[Nikto\] The X-Content-Type-Options header is not set/i,
      /\[Nikto\] The X-XSS-Protection header is not defined/i,
    ],
    agentClassPatterns: [],
    estimatedSuppression: 10,
    tpRisk: "low",
    rationale: "Missing security headers are hardening recommendations, not exploitable vulnerabilities.",
  },
  {
    id: "nikto-powered-by",
    name: "Nikto X-Powered-By Header",
    description: "Suppress Nikto findings about X-Powered-By headers revealing server technology.",
    category: "informational_header",
    enabledByDefault: true,
    severityFilter: ["info", "low"],
    sourcePatterns: ["nikto"],
    titlePatterns: [/\[Nikto\] Retrieved x-powered-by header/i],
    agentClassPatterns: [],
    estimatedSuppression: 5,
    tpRisk: "low",
    rationale: "X-Powered-By disclosure is informational. While it aids fingerprinting, it's not directly exploitable.",
  },
  {
    id: "nmap-service-banner",
    name: "Nmap Service Banner Enumeration",
    description: "Suppress nmap service detection findings that report what service is running on a port.",
    category: "service_banner",
    enabledByDefault: true,
    severityFilter: ["info"],
    sourcePatterns: ["nmap"],
    titlePatterns: [/\[nmap\] \d+\/tcp\s+\S+\s+/i],
    agentClassPatterns: [],
    estimatedSuppression: 30,
    tpRisk: "low",
    rationale: "Nmap service banners are enumeration data, not vulnerabilities.",
  },
  {
    id: "nikto-robots-txt",
    name: "Nikto robots.txt Entries",
    description: "Suppress Nikto findings about robots.txt entries.",
    category: "robots_disclosure",
    enabledByDefault: true,
    severityFilter: ["info", "low"],
    sourcePatterns: ["nikto"],
    titlePatterns: [
      /\[Nikto\].*robots\.txt/i,
      /\[Nikto\] File\/dir '.*' in robots\.txt/i,
    ],
    agentClassPatterns: [],
    estimatedSuppression: 13,
    tpRisk: "low",
    rationale: "robots.txt entries are public by design and informational findings.",
  },
  {
    id: "nikto-etag-leak",
    name: "Nikto ETag Inode Leaks",
    description: "Suppress Nikto findings about ETag headers leaking inode information.",
    category: "etag_leak",
    enabledByDefault: true,
    severityFilter: ["info", "low"],
    sourcePatterns: ["nikto"],
    titlePatterns: [/\[Nikto\] Server leaks inodes via ETags/i],
    agentClassPatterns: [],
    estimatedSuppression: 5,
    tpRisk: "low",
    rationale: "ETag inode leaks are extremely low risk and rarely useful for exploitation.",
  },
  {
    id: "nikto-redirect-info",
    name: "Nikto Redirect Information",
    description: "Suppress Nikto findings about root page redirects and missing web servers.",
    category: "redirect_info",
    enabledByDefault: true,
    severityFilter: ["info"],
    sourcePatterns: ["nikto"],
    titlePatterns: [
      /\[Nikto\] Root page \/ redirects to/i,
      /\[Nikto\] No web server found on/i,
      /\[Nikto\] lines$/i,
      /\[Nikto\] \/crossdomain\.xml contains/i,
    ],
    agentClassPatterns: [],
    estimatedSuppression: 5,
    tpRisk: "low",
    rationale: "Redirects and missing web servers are normal operational behavior.",
  },
  {
    id: "unverified-cve-empty-desc",
    name: "Unverified CVEs with Empty Descriptions",
    description: "Suppress CVE findings with empty or placeholder descriptions (version-only matches).",
    category: "unverified_cve",
    enabledByDefault: true,
    severityFilter: [],
    sourcePatterns: ["nuclei", "shodan"],
    titlePatterns: [/^CVE-\d{4}-\d+:\s*CVE-\d{4}-\d+\s*\(\s*\)\s*$/i],
    agentClassPatterns: [],
    estimatedSuppression: 19,
    tpRisk: "medium",
    rationale: "CVEs with empty descriptions were matched by version string only, without verification.",
  },
  {
    id: "shodan-unverified-cve",
    name: "Shodan-Reported Unverified CVEs",
    description: "Suppress CVEs reported by Shodan based on service version matching.",
    category: "unverified_cve",
    enabledByDefault: false,
    severityFilter: [],
    sourcePatterns: ["shodan"],
    titlePatterns: [/Detected by Shodan on/i],
    agentClassPatterns: [],
    estimatedSuppression: 16,
    tpRisk: "medium",
    rationale: "Shodan CVEs are based on banner/version matching and may be patched or mitigated.",
  },
  {
    id: "nikto-cookie-flags",
    name: "Nikto Cookie Flag Observations",
    description: "Suppress Nikto findings about cookies missing HttpOnly or Secure flags.",
    category: "cookie_flag",
    enabledByDefault: true,
    severityFilter: ["info", "low"],
    sourcePatterns: ["nikto"],
    titlePatterns: [/\[Nikto\] Cookie .* created without the (httponly|secure) flag/i],
    agentClassPatterns: [],
    estimatedSuppression: 3,
    tpRisk: "low",
    rationale: "Missing cookie flags are hardening recommendations, not directly exploitable.",
  },
  {
    id: "nikto-http-methods",
    name: "Nikto HTTP Method Observations",
    description: "Suppress Nikto findings about allowed HTTP methods (PUT, DELETE).",
    category: "http_method",
    enabledByDefault: false,
    severityFilter: ["info", "low", "medium"],
    sourcePatterns: ["nikto"],
    titlePatterns: [/\[Nikto\] (Allowed HTTP Methods|OSVDB-397|OSVDB-5646)/i],
    agentClassPatterns: [],
    estimatedSuppression: 3,
    tpRisk: "medium",
    rationale: "PUT/DELETE methods may be intentional (REST APIs) or dangerous. Disabled by default for manual review.",
  },
  {
    id: "config-exposed-port",
    name: "Exposed Port/Service Observations",
    description: "Suppress generic 'exposed to internet' findings for standard web ports.",
    category: "config_observation",
    enabledByDefault: true,
    severityFilter: ["info", "low"],
    sourcePatterns: [],
    titlePatterns: [
      /exposed to internet$/i,
      /^Exposed web server$/i,
      /^Multiple .* services exposed/i,
    ],
    agentClassPatterns: ["config"],
    estimatedSuppression: 5,
    tpRisk: "low",
    rationale: "Web applications are expected to have HTTP/HTTPS ports exposed.",
  },
  {
    id: "config-potential-xss",
    name: "Generic 'Potential XSS' Without Evidence",
    description: "Suppress generic XSS warnings without specific payloads or evidence.",
    category: "config_observation",
    enabledByDefault: true,
    severityFilter: ["info", "low"],
    sourcePatterns: [],
    titlePatterns: [/^Potential exposure to XSS$/i],
    agentClassPatterns: ["config"],
    estimatedSuppression: 1,
    tpRisk: "medium",
    rationale: "Generic XSS warnings without specific payloads are not actionable.",
  },
  {
    id: "gobuster-401-dirs",
    name: "Gobuster 401 Unauthorized Directories",
    description: "Suppress Gobuster findings for directories returning 401 Unauthorized.",
    category: "config_observation",
    enabledByDefault: true,
    severityFilter: ["info", "low"],
    sourcePatterns: ["gobuster"],
    titlePatterns: [/\[Gobuster\] .* \(401\)/i],
    agentClassPatterns: [],
    estimatedSuppression: 4,
    tpRisk: "low",
    rationale: "401 responses indicate proper access control, not vulnerabilities.",
  },
  {
    id: "duplicate-across-hosts",
    name: "Duplicate Findings Across Shared Infrastructure",
    description: "Suppress duplicate findings on hosts sharing the same infrastructure.",
    category: "duplicate_finding",
    enabledByDefault: false,
    severityFilter: [],
    sourcePatterns: [],
    titlePatterns: [],
    agentClassPatterns: [],
    estimatedSuppression: 10,
    tpRisk: "medium",
    rationale: "Infrastructure-level findings get duplicated per app when sharing reverse proxy.",
  },
  {
    id: "nikto-directory-indexing",
    name: "Nikto Directory Indexing (Intentional Lab)",
    description: "Suppress directory indexing findings on known vulnerable lab applications.",
    category: "config_observation",
    enabledByDefault: false,
    severityFilter: ["medium"],
    sourcePatterns: ["nikto"],
    titlePatterns: [/\[Nikto\] OSVDB-3268:.*Directory indexing found/i],
    agentClassPatterns: [],
    estimatedSuppression: 2,
    tpRisk: "high",
    rationale: "Directory indexing is a real finding in production. Only suppress for known lab environments.",
  },
];

export interface SuppressionProfile {
  name: string;
  description: string;
  rules: Record<string, boolean>;
}

export const SUPPRESSION_PROFILES: Record<string, SuppressionProfile> = {
  aggressive: {
    name: "Aggressive",
    description: "Maximum FP suppression. Removes all informational and unverified findings. Best for executive reports.",
    rules: Object.fromEntries(FP_SUPPRESSION_RULES.map(r => [r.id, true])),
  },
  balanced: {
    name: "Balanced",
    description: "Suppress clear FPs while keeping medium-risk findings for review. Recommended for most engagements.",
    rules: Object.fromEntries(FP_SUPPRESSION_RULES.map(r => [r.id, r.enabledByDefault])),
  },
  conservative: {
    name: "Conservative",
    description: "Only suppress the most obvious FPs (info-level headers and banners).",
    rules: Object.fromEntries(FP_SUPPRESSION_RULES.map(r => [
      r.id,
      r.enabledByDefault && r.tpRisk === "low" && r.severityFilter.every(s => s === "info" || s === "low"),
    ])),
  },
  none: {
    name: "None",
    description: "No suppression. All findings are kept as-is.",
    rules: Object.fromEntries(FP_SUPPRESSION_RULES.map(r => [r.id, false])),
  },
};

function findingMatchesRule(
  finding: { title?: string; source?: string; severity?: string },
  agentClass: string,
  rule: FPSuppressionRule
): boolean {
  if (rule.severityFilter.length > 0) {
    const sev = (finding.severity || "").toLowerCase();
    if (!rule.severityFilter.includes(sev as any)) return false;
  }
  if (rule.sourcePatterns.length > 0) {
    const src = (finding.source || "").toLowerCase();
    const title = (finding.title || "").toLowerCase();
    const matchesSource = rule.sourcePatterns.some(
      p => src.includes(p.toLowerCase()) || title.includes(`[${p.toLowerCase()}]`)
    );
    if (!matchesSource) return false;
  }
  if (rule.agentClassPatterns.length > 0) {
    if (!rule.agentClassPatterns.includes(agentClass)) return false;
  }
  if (rule.titlePatterns.length > 0) {
    const title = finding.title || "";
    const matchesTitle = rule.titlePatterns.some(p => p.test(title));
    if (!matchesTitle) return false;
  }
  return true;
}

export function applySuppressionRules(
  findings: Array<{ finding: Record<string, any>; agentClass: string; analysis?: Record<string, any> }>,
  profileName: string = "balanced",
  customRules?: Record<string, boolean>
): {
  kept: typeof findings;
  suppressed: typeof findings;
  stats: {
    total: number;
    kept: number;
    suppressed: number;
    byRule: Record<string, number>;
    byCategory: Record<string, number>;
  };
} {
  const profile = SUPPRESSION_PROFILES[profileName] || SUPPRESSION_PROFILES.balanced;
  const activeRules = customRules || profile.rules;

  const kept: typeof findings = [];
  const suppressed: typeof findings = [];
  const byRule: Record<string, number> = {};
  const byCategory: Record<string, number> = {};

  for (const item of findings) {
    let wasSuppressed = false;

    for (const rule of FP_SUPPRESSION_RULES) {
      if (!activeRules[rule.id]) continue;

      // Never suppress critical or high severity findings
      const sev = (item.finding?.severity || "").toLowerCase();
      if (sev === "critical" || sev === "high") break;

      if (findingMatchesRule(item.finding, item.agentClass, rule)) {
        suppressed.push(item);
        byRule[rule.id] = (byRule[rule.id] || 0) + 1;
        byCategory[rule.category] = (byCategory[rule.category] || 0) + 1;
        wasSuppressed = true;
        break;
      }
    }

    if (!wasSuppressed) {
      kept.push(item);
    }
  }

  return {
    kept,
    suppressed,
    stats: {
      total: findings.length,
      kept: kept.length,
      suppressed: suppressed.length,
      byRule,
      byCategory,
    },
  };
}

export function getSuppressionRuleSummary(): Array<{
  id: string;
  name: string;
  description: string;
  category: string;
  enabledByDefault: boolean;
  estimatedSuppression: number;
  tpRisk: string;
}> {
  return FP_SUPPRESSION_RULES.map(r => ({
    id: r.id,
    name: r.name,
    description: r.description,
    category: r.category,
    enabledByDefault: r.enabledByDefault,
    estimatedSuppression: r.estimatedSuppression,
    tpRisk: r.tpRisk,
  }));
}

export function getSuppressionProfiles(): Array<{
  id: string;
  name: string;
  description: string;
  enabledCount: number;
  totalRules: number;
}> {
  return Object.entries(SUPPRESSION_PROFILES).map(([id, profile]) => ({
    id,
    name: profile.name,
    description: profile.description,
    enabledCount: Object.values(profile.rules).filter(Boolean).length,
    totalRules: FP_SUPPRESSION_RULES.length,
  }));
}

export function buildFPSuppressionContext(): string {
  const rules = FP_SUPPRESSION_RULES.filter(r => r.enabledByDefault);
  let ctx = `## False Positive Suppression Knowledge\n\n`;
  ctx += `The following finding patterns are known false positives based on analysis of previous engagements.\n`;
  ctx += `When evaluating findings, deprioritize or flag these patterns:\n\n`;

  for (const rule of rules) {
    ctx += `### ${rule.name}\n`;
    ctx += `- Category: ${rule.category}\n`;
    ctx += `- Rationale: ${rule.rationale}\n`;
    ctx += `- Severity filter: ${rule.severityFilter.join(", ") || "all"}\n`;
    ctx += `- TP Risk: ${rule.tpRisk}\n\n`;
  }

  return ctx;
}
