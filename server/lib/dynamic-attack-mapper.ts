/**
 * Dynamic ATT&CK Mapper — Proactive Technique Mapping (Gap R-4)
 * ═══════════════════════════════════════════════════════════════
 * Unlike the existing nist-mitre-cwe-mapper which maps AFTER a finding
 * is discovered (reactive), this engine maps BEFORE exploitation begins
 * (proactive). Given a vulnerability context, it:
 *
 *   1. Predicts which ATT&CK techniques are relevant to the exploitation
 *   2. Suggests technique-specific exploitation approaches
 *   3. Tracks demonstrated techniques during an engagement
 *   4. Identifies coverage gaps in the kill chain
 *   5. Recommends next techniques to maximize ATT&CK coverage
 *   6. Generates Navigator layer JSON for visual reporting
 *
 * Integration points:
 *   - exploit-chain-reasoner.ts: feeds technique suggestions into decision tree
 *   - exploit-reasoning-prompts.ts: enriches prompts with ATT&CK context
 *   - scanforge-enhanced-pipeline.ts: tracks coverage across the engagement
 *   - ability-graph-engine.ts: maps to Caldera abilities
 */

import type { MitreTechnique } from './nist-mitre-cwe-mapper';

// ═══════════════════════════════════════════════════════════════════════
// §1 — TYPES
// ═══════════════════════════════════════════════════════════════════════

export interface AttackTechniqueProfile {
  techniqueId: string;
  techniqueName: string;
  tactic: AttackTactic;
  /** Sub-technique parent, if applicable */
  parentId?: string;
  /** Exploitation guidance specific to this technique */
  exploitGuidance: string;
  /** Common tools/methods for this technique */
  tools: string[];
  /** Detection difficulty (higher = harder to detect) */
  detectionDifficulty: 1 | 2 | 3 | 4 | 5;
  /** Prerequisites for this technique */
  prerequisites: string[];
  /** What access level is needed */
  requiredAccess: 'none' | 'web_user' | 'authenticated' | 'shell' | 'root';
  /** Data sources that detect this technique */
  dataSources: string[];
  /** Related CWE IDs */
  relatedCWEs: string[];
  /** OWASP WSTG test IDs */
  relatedWSTG: string[];
}

export type AttackTactic =
  | 'reconnaissance'
  | 'resource-development'
  | 'initial-access'
  | 'execution'
  | 'persistence'
  | 'privilege-escalation'
  | 'defense-evasion'
  | 'credential-access'
  | 'discovery'
  | 'lateral-movement'
  | 'collection'
  | 'command-and-control'
  | 'exfiltration'
  | 'impact';

export interface TechniqueRecommendation {
  technique: AttackTechniqueProfile;
  /** Why this technique is relevant */
  rationale: string;
  /** Confidence that this technique applies (0-1) */
  confidence: number;
  /** Priority order for execution */
  priority: number;
  /** Whether this technique has already been demonstrated */
  demonstrated: boolean;
}

export interface KillChainCoverage {
  /** Tactics covered by demonstrated techniques */
  coveredTactics: AttackTactic[];
  /** Tactics not yet covered */
  uncoveredTactics: AttackTactic[];
  /** Coverage percentage (0-100) */
  coveragePercent: number;
  /** Recommended techniques to fill gaps */
  gapFillers: TechniqueRecommendation[];
}

export interface NavigatorLayer {
  name: string;
  versions: { attack: string; navigator: string; layer: string };
  domain: string;
  description: string;
  techniques: Array<{
    techniqueID: string;
    tactic: string;
    color: string;
    comment: string;
    score: number;
    enabled: boolean;
  }>;
  gradient: { colors: string[]; minValue: number; maxValue: number };
  legendItems: Array<{ label: string; color: string }>;
}

export interface EngagementAttackTracker {
  engagementId: string;
  /** All techniques recommended for this engagement */
  recommendedTechniques: TechniqueRecommendation[];
  /** Techniques that have been demonstrated */
  demonstratedTechniques: Map<string, DemonstratedTechnique>;
  /** Kill chain coverage analysis */
  coverage: KillChainCoverage;
}

export interface DemonstratedTechnique {
  techniqueId: string;
  techniqueName: string;
  tactic: AttackTactic;
  /** Evidence of demonstration */
  evidence: string;
  /** When it was demonstrated */
  timestamp: number;
  /** Quality of the demonstration */
  quality: 'definitive' | 'strong' | 'moderate' | 'weak';
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — VULNERABILITY-TO-TECHNIQUE MAPPING
// ═══════════════════════════════════════════════════════════════════════

/**
 * Maps vulnerability classes to the ATT&CK techniques most relevant
 * for their exploitation. This is the PROACTIVE mapping — given a vuln,
 * what techniques should we plan to demonstrate?
 */
const VULN_TO_TECHNIQUE_MAP: Record<string, AttackTechniqueProfile[]> = {
  sqli: [
    {
      techniqueId: 'T1190',
      techniqueName: 'Exploit Public-Facing Application',
      tactic: 'initial-access',
      exploitGuidance: 'Use SQL injection to gain initial access. For UNION-based: enumerate columns, extract data. For blind: use boolean/time-based inference. For stacked queries: attempt command execution via xp_cmdshell (MSSQL) or LOAD_FILE/INTO OUTFILE (MySQL).',
      tools: ['sqlmap', 'manual UNION crafting', 'time-based blind scripts'],
      detectionDifficulty: 2,
      prerequisites: ['injectable parameter identified', 'database type known'],
      requiredAccess: 'none',
      dataSources: ['Application Log', 'Network Traffic'],
      relatedCWEs: ['CWE-89', 'CWE-564'],
      relatedWSTG: ['WSTG-INPV-05'],
    },
    {
      techniqueId: 'T1005',
      techniqueName: 'Data from Local System',
      tactic: 'collection',
      exploitGuidance: 'After confirming SQLi, extract database contents to demonstrate data access. Use UNION SELECT to read from information_schema, then target tables with sensitive data (users, credentials, PII). Document table names and column names as proof without extracting actual PII.',
      tools: ['UNION SELECT queries', 'database-specific metadata tables'],
      detectionDifficulty: 2,
      prerequisites: ['confirmed SQL injection'],
      requiredAccess: 'none',
      dataSources: ['Application Log', 'Database Log'],
      relatedCWEs: ['CWE-89'],
      relatedWSTG: ['WSTG-INPV-05'],
    },
    {
      techniqueId: 'T1078',
      techniqueName: 'Valid Accounts',
      tactic: 'persistence',
      exploitGuidance: 'If SQLi extracts credential hashes, attempt offline cracking or use pass-the-hash to authenticate as a legitimate user. This demonstrates persistence via valid account compromise.',
      tools: ['hashcat', 'john', 'credential extraction queries'],
      detectionDifficulty: 4,
      prerequisites: ['credential hashes extracted via SQLi'],
      requiredAccess: 'none',
      dataSources: ['Authentication Log', 'Account Audit'],
      relatedCWEs: ['CWE-89', 'CWE-522'],
      relatedWSTG: ['WSTG-INPV-05', 'WSTG-ATHN-02'],
    },
    {
      techniqueId: 'T1059',
      techniqueName: 'Command and Scripting Interpreter',
      tactic: 'execution',
      exploitGuidance: 'For MSSQL: use xp_cmdshell for OS command execution. For MySQL: use INTO OUTFILE to write webshell, or LOAD_FILE to read system files. For PostgreSQL: use COPY TO/FROM or pg_read_file(). This escalates SQLi from data access to RCE.',
      tools: ['xp_cmdshell', 'INTO OUTFILE', 'COPY TO', 'pg_read_file'],
      detectionDifficulty: 2,
      prerequisites: ['confirmed SQLi with sufficient privileges'],
      requiredAccess: 'none',
      dataSources: ['Process Monitoring', 'File Monitoring'],
      relatedCWEs: ['CWE-89', 'CWE-78'],
      relatedWSTG: ['WSTG-INPV-05'],
    },
  ],

  xss: [
    {
      techniqueId: 'T1190',
      techniqueName: 'Exploit Public-Facing Application',
      tactic: 'initial-access',
      exploitGuidance: 'Inject JavaScript via XSS to execute in victim browser context. For reflected: craft URL with payload. For stored: inject into persistent storage. For DOM-based: manipulate client-side JavaScript.',
      tools: ['browser developer tools', 'XSS payload generators', 'Burp Suite'],
      detectionDifficulty: 3,
      prerequisites: ['injectable parameter identified', 'output context known'],
      requiredAccess: 'none',
      dataSources: ['Application Log', 'Network Traffic'],
      relatedCWEs: ['CWE-79'],
      relatedWSTG: ['WSTG-INPV-01', 'WSTG-INPV-02'],
    },
    {
      techniqueId: 'T1539',
      techniqueName: 'Steal Web Session Cookie',
      tactic: 'credential-access',
      exploitGuidance: 'Use XSS to exfiltrate session cookies via document.cookie. If HttpOnly flag is set, demonstrate the XSS with document.domain instead and note that cookie theft is mitigated by HttpOnly. Check for other sensitive tokens in localStorage/sessionStorage.',
      tools: ['JavaScript payload', 'OOB exfiltration server'],
      detectionDifficulty: 3,
      prerequisites: ['confirmed XSS execution'],
      requiredAccess: 'none',
      dataSources: ['Application Log'],
      relatedCWEs: ['CWE-79', 'CWE-614'],
      relatedWSTG: ['WSTG-INPV-01', 'WSTG-SESS-02'],
    },
    {
      techniqueId: 'T1185',
      techniqueName: 'Browser Session Hijacking',
      tactic: 'collection',
      exploitGuidance: 'Use XSS to perform actions as the victim user — modify profile, change email, initiate transactions. This demonstrates the full impact beyond just cookie theft.',
      tools: ['XMLHttpRequest/fetch payloads', 'BeEF framework'],
      detectionDifficulty: 4,
      prerequisites: ['confirmed XSS in authenticated context'],
      requiredAccess: 'none',
      dataSources: ['Application Log', 'Network Traffic'],
      relatedCWEs: ['CWE-79'],
      relatedWSTG: ['WSTG-INPV-01'],
    },
  ],

  command_injection: [
    {
      techniqueId: 'T1190',
      techniqueName: 'Exploit Public-Facing Application',
      tactic: 'initial-access',
      exploitGuidance: 'Inject OS commands via vulnerable parameter. Test all injection operators: ;, |, &&, ||, `, $(). For blind injection, use DNS OOB or time-based detection.',
      tools: ['manual payload crafting', 'Burp Suite', 'commix'],
      detectionDifficulty: 2,
      prerequisites: ['injectable parameter identified', 'OS type known'],
      requiredAccess: 'none',
      dataSources: ['Process Monitoring', 'Application Log'],
      relatedCWEs: ['CWE-78', 'CWE-77'],
      relatedWSTG: ['WSTG-INPV-12'],
    },
    {
      techniqueId: 'T1059.004',
      techniqueName: 'Unix Shell',
      tactic: 'execution',
      parentId: 'T1059',
      exploitGuidance: 'After confirming command injection on Linux, execute system enumeration commands: whoami, id, hostname, uname -a. Use DNS OOB for blind exfiltration. Avoid reverse shells unless specifically authorized.',
      tools: ['bash commands', 'DNS OOB exfiltration'],
      detectionDifficulty: 2,
      prerequisites: ['confirmed command injection on Linux'],
      requiredAccess: 'none',
      dataSources: ['Process Monitoring', 'Command Execution'],
      relatedCWEs: ['CWE-78'],
      relatedWSTG: ['WSTG-INPV-12'],
    },
    {
      techniqueId: 'T1068',
      techniqueName: 'Exploitation for Privilege Escalation',
      tactic: 'privilege-escalation',
      exploitGuidance: 'If command injection runs as non-root, check for privilege escalation vectors: SUID binaries, sudo misconfigurations, kernel exploits, writable cron jobs. Use `sudo -l`, `find / -perm -4000`, and kernel version checks.',
      tools: ['LinPEAS', 'sudo -l', 'find SUID', 'kernel exploit databases'],
      detectionDifficulty: 2,
      prerequisites: ['shell access via command injection'],
      requiredAccess: 'shell',
      dataSources: ['Process Monitoring', 'File Monitoring'],
      relatedCWEs: ['CWE-269'],
      relatedWSTG: ['WSTG-INPV-12'],
    },
  ],

  ssrf: [
    {
      techniqueId: 'T1190',
      techniqueName: 'Exploit Public-Facing Application',
      tactic: 'initial-access',
      exploitGuidance: 'Exploit SSRF to access internal services. Test all IP bypass techniques: decimal IP, hex IP, IPv6, DNS rebinding, URL parser differentials. Primary targets: cloud metadata (169.254.169.254), internal APIs, admin panels.',
      tools: ['Burp Suite', 'IP format converters', 'DNS rebinding tools'],
      detectionDifficulty: 3,
      prerequisites: ['URL/host parameter identified', 'cloud environment detected'],
      requiredAccess: 'none',
      dataSources: ['Network Traffic', 'Application Log'],
      relatedCWEs: ['CWE-918'],
      relatedWSTG: ['WSTG-INPV-19'],
    },
    {
      techniqueId: 'T1552.005',
      techniqueName: 'Cloud Instance Metadata API',
      tactic: 'credential-access',
      parentId: 'T1552',
      exploitGuidance: 'Use SSRF to reach cloud metadata services: AWS (169.254.169.254/latest/meta-data/iam/security-credentials/), GCP (metadata.google.internal/computeMetadata/v1/), Azure (169.254.169.254/metadata/identity/oauth2/token). Extract IAM credentials without using them.',
      tools: ['SSRF payload', 'cloud metadata endpoints'],
      detectionDifficulty: 3,
      prerequisites: ['confirmed SSRF', 'cloud environment'],
      requiredAccess: 'none',
      dataSources: ['Cloud API Logs', 'Network Traffic'],
      relatedCWEs: ['CWE-918'],
      relatedWSTG: ['WSTG-INPV-19'],
    },
    {
      techniqueId: 'T1046',
      techniqueName: 'Network Service Discovery',
      tactic: 'discovery',
      exploitGuidance: 'Use SSRF as an internal port scanner. Iterate through common ports on internal IP ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) to map internal services. Response timing and error messages reveal open/closed ports.',
      tools: ['SSRF-based port scanning scripts', 'response timing analysis'],
      detectionDifficulty: 3,
      prerequisites: ['confirmed SSRF'],
      requiredAccess: 'none',
      dataSources: ['Network Traffic'],
      relatedCWEs: ['CWE-918'],
      relatedWSTG: ['WSTG-INPV-19'],
    },
  ],

  idor: [
    {
      techniqueId: 'T1190',
      techniqueName: 'Exploit Public-Facing Application',
      tactic: 'initial-access',
      exploitGuidance: 'Access resources belonging to other users by manipulating object references (IDs, UUIDs, filenames). Test all CRUD operations: GET (read), PUT/PATCH (modify), DELETE (destroy). Always use two accounts you control.',
      tools: ['Burp Suite', 'API testing tools', 'Autorize extension'],
      detectionDifficulty: 4,
      prerequisites: ['two test accounts', 'API endpoint with object references'],
      requiredAccess: 'authenticated',
      dataSources: ['Application Log', 'API Audit'],
      relatedCWEs: ['CWE-639', 'CWE-284'],
      relatedWSTG: ['WSTG-ATHZ-04'],
    },
    {
      techniqueId: 'T1530',
      techniqueName: 'Data from Cloud Storage',
      tactic: 'collection',
      exploitGuidance: 'If IDOR exposes file storage references (S3 keys, blob paths), enumerate and access files belonging to other users. Document the scope of accessible data without downloading actual files.',
      tools: ['API requests with modified references', 'S3 enumeration'],
      detectionDifficulty: 4,
      prerequisites: ['confirmed IDOR on file/storage endpoints'],
      requiredAccess: 'authenticated',
      dataSources: ['Cloud Storage Logs', 'API Audit'],
      relatedCWEs: ['CWE-639'],
      relatedWSTG: ['WSTG-ATHZ-04'],
    },
  ],

  auth_bypass: [
    {
      techniqueId: 'T1190',
      techniqueName: 'Exploit Public-Facing Application',
      tactic: 'initial-access',
      exploitGuidance: 'Bypass authentication mechanisms: JWT manipulation (alg:none, key confusion), session fixation, default credentials, forced browsing to authenticated endpoints. Test each bypass independently.',
      tools: ['JWT tools', 'Burp Suite', 'forced browsing wordlists'],
      detectionDifficulty: 3,
      prerequisites: ['authentication mechanism identified'],
      requiredAccess: 'none',
      dataSources: ['Authentication Log', 'Application Log'],
      relatedCWEs: ['CWE-287', 'CWE-306'],
      relatedWSTG: ['WSTG-ATHN-04', 'WSTG-ATHN-06'],
    },
    {
      techniqueId: 'T1078',
      techniqueName: 'Valid Accounts',
      tactic: 'persistence',
      exploitGuidance: 'If authentication bypass grants access to account creation or credential reset, create a persistent backdoor account. Document the capability without actually creating production accounts.',
      tools: ['API requests', 'admin panel access'],
      detectionDifficulty: 5,
      prerequisites: ['confirmed auth bypass with admin access'],
      requiredAccess: 'none',
      dataSources: ['Authentication Log', 'Account Audit'],
      relatedCWEs: ['CWE-287'],
      relatedWSTG: ['WSTG-ATHN-04'],
    },
  ],

  file_upload: [
    {
      techniqueId: 'T1190',
      techniqueName: 'Exploit Public-Facing Application',
      tactic: 'initial-access',
      exploitGuidance: 'Upload malicious files to achieve code execution. Test bypass techniques: double extensions (.php.jpg), null bytes (.php%00.jpg), content-type manipulation, polyglot files. Verify the uploaded file is accessible and executable.',
      tools: ['Burp Suite', 'polyglot file generators', 'webshell templates'],
      detectionDifficulty: 2,
      prerequisites: ['file upload endpoint identified', 'server-side language known'],
      requiredAccess: 'none',
      dataSources: ['Application Log', 'File Monitoring'],
      relatedCWEs: ['CWE-434'],
      relatedWSTG: ['WSTG-BUSL-08'],
    },
    {
      techniqueId: 'T1505.003',
      techniqueName: 'Web Shell',
      tactic: 'persistence',
      parentId: 'T1505',
      exploitGuidance: 'After successful file upload, deploy a minimal webshell to demonstrate persistent access. Use a one-liner that executes a single command (whoami) rather than a full-featured shell. Document the upload path and execution proof.',
      tools: ['minimal webshell', 'curl for execution verification'],
      detectionDifficulty: 3,
      prerequisites: ['successful malicious file upload', 'file is web-accessible'],
      requiredAccess: 'none',
      dataSources: ['File Monitoring', 'Process Monitoring'],
      relatedCWEs: ['CWE-434'],
      relatedWSTG: ['WSTG-BUSL-08'],
    },
  ],

  misconfig: [
    {
      techniqueId: 'T1190',
      techniqueName: 'Exploit Public-Facing Application',
      tactic: 'initial-access',
      exploitGuidance: 'Exploit misconfigurations: exposed admin panels, default credentials, directory listing, debug mode enabled, unnecessary HTTP methods, missing security headers.',
      tools: ['Nikto', 'directory brute-forcing', 'HTTP method testing'],
      detectionDifficulty: 4,
      prerequisites: ['misconfiguration identified'],
      requiredAccess: 'none',
      dataSources: ['Application Log', 'Network Traffic'],
      relatedCWEs: ['CWE-16', 'CWE-1188'],
      relatedWSTG: ['WSTG-CONF-02', 'WSTG-CONF-04', 'WSTG-CONF-06'],
    },
  ],

  info_disclosure: [
    {
      techniqueId: 'T1592',
      techniqueName: 'Gather Victim Host Information',
      tactic: 'reconnaissance',
      exploitGuidance: 'Collect exposed information: stack traces, version numbers, internal IPs, API keys in source code, .git exposure, backup files. Each piece of information feeds into further exploitation planning.',
      tools: ['browser source view', 'directory brute-forcing', 'git-dumper'],
      detectionDifficulty: 5,
      prerequisites: ['target URL identified'],
      requiredAccess: 'none',
      dataSources: ['Application Log'],
      relatedCWEs: ['CWE-200', 'CWE-209'],
      relatedWSTG: ['WSTG-INFO-01', 'WSTG-INFO-02', 'WSTG-INFO-05'],
    },
  ],

  business_logic: [
    {
      techniqueId: 'T1190',
      techniqueName: 'Exploit Public-Facing Application',
      tactic: 'initial-access',
      exploitGuidance: 'Exploit business logic flaws: race conditions (concurrent requests), price manipulation, workflow bypass, parameter tampering, forced browsing. These require understanding the application business flow.',
      tools: ['Turbo Intruder', 'Burp Suite', 'async HTTP clients'],
      detectionDifficulty: 5,
      prerequisites: ['business flow understood', 'application-specific knowledge'],
      requiredAccess: 'none',
      dataSources: ['Application Log', 'Business Logic Monitoring'],
      relatedCWEs: ['CWE-840', 'CWE-362'],
      relatedWSTG: ['WSTG-BUSL-01', 'WSTG-BUSL-07'],
    },
  ],
};

// ═══════════════════════════════════════════════════════════════════════
// §3 — TACTIC ORDERING & KILL CHAIN
// ═══════════════════════════════════════════════════════════════════════

const TACTIC_ORDER: AttackTactic[] = [
  'reconnaissance',
  'resource-development',
  'initial-access',
  'execution',
  'persistence',
  'privilege-escalation',
  'defense-evasion',
  'credential-access',
  'discovery',
  'lateral-movement',
  'collection',
  'command-and-control',
  'exfiltration',
  'impact',
];

const TACTIC_COLORS: Record<AttackTactic, string> = {
  'reconnaissance': '#a1d99b',
  'resource-development': '#74c476',
  'initial-access': '#e6550d',
  'execution': '#fd8d3c',
  'persistence': '#fdae6b',
  'privilege-escalation': '#d62728',
  'defense-evasion': '#9467bd',
  'credential-access': '#ff7f0e',
  'discovery': '#2ca02c',
  'lateral-movement': '#1f77b4',
  'collection': '#8c564b',
  'command-and-control': '#e377c2',
  'exfiltration': '#7f7f7f',
  'impact': '#bcbd22',
};

// ═══════════════════════════════════════════════════════════════════════
// §4 — PROACTIVE TECHNIQUE RECOMMENDATION
// ═══════════════════════════════════════════════════════════════════════

/**
 * Given a vulnerability context, recommend ATT&CK techniques to demonstrate.
 * This is the PROACTIVE mapping — called before exploitation begins.
 */
export function recommendTechniques(params: {
  vulnClass: string;
  accessLevel: string;
  techStack: string[];
  hasWaf: boolean;
  isCloudEnvironment: boolean;
  safeModeEnabled: boolean;
  demonstratedTechniques: string[];
}): TechniqueRecommendation[] {
  const {
    vulnClass,
    accessLevel,
    techStack,
    hasWaf,
    isCloudEnvironment,
    safeModeEnabled,
    demonstratedTechniques,
  } = params;

  // Get base techniques for this vuln class
  const baseTechniques = VULN_TO_TECHNIQUE_MAP[vulnClass.toLowerCase()] || [];

  // Add cloud-specific techniques if applicable
  const allTechniques = [...baseTechniques];
  if (isCloudEnvironment && vulnClass === 'ssrf') {
    // Cloud metadata is already in SSRF mapping
  }

  // Filter by access level requirements
  const accessOrder = ['none', 'web_user', 'authenticated', 'shell', 'root'];
  const currentAccessIdx = accessOrder.indexOf(accessLevel);

  const recommendations: TechniqueRecommendation[] = allTechniques
    .filter(t => {
      const requiredIdx = accessOrder.indexOf(t.requiredAccess);
      return requiredIdx <= currentAccessIdx || requiredIdx <= 0; // Allow 'none' always
    })
    .filter(t => {
      // In safe mode, filter out high-impact techniques
      if (safeModeEnabled) {
        const riskyTactics: AttackTactic[] = ['persistence', 'impact', 'lateral-movement', 'exfiltration'];
        return !riskyTactics.includes(t.tactic);
      }
      return true;
    })
    .map((technique, idx) => ({
      technique,
      rationale: buildRationale(technique, vulnClass, techStack, hasWaf),
      confidence: calculateConfidence(technique, vulnClass, techStack),
      priority: idx + 1,
      demonstrated: demonstratedTechniques.includes(technique.techniqueId),
    }))
    .sort((a, b) => {
      // Prioritize undemonstrated techniques
      if (a.demonstrated !== b.demonstrated) return a.demonstrated ? 1 : -1;
      // Then by tactic order (kill chain progression)
      const tacticA = TACTIC_ORDER.indexOf(a.technique.tactic);
      const tacticB = TACTIC_ORDER.indexOf(b.technique.tactic);
      if (tacticA !== tacticB) return tacticA - tacticB;
      // Then by confidence
      return b.confidence - a.confidence;
    });

  // Re-assign priority after sorting
  return recommendations.map((r, idx) => ({ ...r, priority: idx + 1 }));
}

function buildRationale(
  technique: AttackTechniqueProfile,
  vulnClass: string,
  techStack: string[],
  hasWaf: boolean,
): string {
  const parts: string[] = [];
  parts.push(`${technique.techniqueName} (${technique.techniqueId}) is relevant because ${vulnClass} vulnerabilities commonly enable ${technique.tactic} activities.`);

  if (hasWaf && technique.detectionDifficulty >= 3) {
    parts.push('This technique has moderate-to-high detection difficulty, making it suitable against WAF-protected targets.');
  }

  if (technique.relatedWSTG.length > 0) {
    parts.push(`Aligns with OWASP WSTG tests: ${technique.relatedWSTG.join(', ')}.`);
  }

  return parts.join(' ');
}

function calculateConfidence(
  technique: AttackTechniqueProfile,
  vulnClass: string,
  techStack: string[],
): number {
  let confidence = 0.5; // base

  // Higher confidence if technique is directly in the vuln's mapping
  if (VULN_TO_TECHNIQUE_MAP[vulnClass]?.some(t => t.techniqueId === technique.techniqueId)) {
    confidence += 0.3;
  }

  // Adjust based on tech stack match
  const techStackLower = techStack.map(t => t.toLowerCase()).join(' ');
  if (technique.tools.some(tool => techStackLower.includes(tool.toLowerCase()))) {
    confidence += 0.1;
  }

  // Cap at 0.95
  return Math.min(confidence, 0.95);
}

// ═══════════════════════════════════════════════════════════════════════
// §5 — KILL CHAIN COVERAGE ANALYSIS
// ═══════════════════════════════════════════════════════════════════════

/**
 * Analyze kill chain coverage for an engagement.
 * Identifies which tactics have been demonstrated and which have gaps.
 */
export function analyzeKillChainCoverage(params: {
  vulnClass: string;
  demonstratedTechniques: DemonstratedTechnique[];
  accessLevel: string;
  safeModeEnabled: boolean;
}): KillChainCoverage {
  const { vulnClass, demonstratedTechniques, accessLevel, safeModeEnabled } = params;

  // Determine which tactics are covered
  const coveredTactics = new Set<AttackTactic>();
  for (const dt of demonstratedTechniques) {
    coveredTactics.add(dt.tactic);
  }

  // Determine which tactics are relevant for this vuln class
  const relevantTechniques = VULN_TO_TECHNIQUE_MAP[vulnClass.toLowerCase()] || [];
  const relevantTactics = new Set<AttackTactic>(relevantTechniques.map(t => t.tactic));

  // Always include initial-access as relevant
  relevantTactics.add('initial-access');

  const uncoveredTactics = [...relevantTactics].filter(t => !coveredTactics.has(t));

  // Calculate coverage
  const coveragePercent = relevantTactics.size > 0
    ? Math.round((coveredTactics.size / relevantTactics.size) * 100)
    : 0;

  // Recommend gap-filling techniques
  const demonstratedIds = demonstratedTechniques.map(dt => dt.techniqueId);
  const gapFillers = recommendTechniques({
    vulnClass,
    accessLevel,
    techStack: [],
    hasWaf: false,
    isCloudEnvironment: false,
    safeModeEnabled,
    demonstratedTechniques: demonstratedIds,
  }).filter(r => !r.demonstrated && uncoveredTactics.includes(r.technique.tactic));

  return {
    coveredTactics: [...coveredTactics],
    uncoveredTactics,
    coveragePercent,
    gapFillers,
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §6 — NAVIGATOR LAYER GENERATION
// ═══════════════════════════════════════════════════════════════════════

/**
 * Generate an ATT&CK Navigator layer JSON for visual reporting.
 * This can be imported directly into MITRE ATT&CK Navigator.
 */
export function generateNavigatorLayer(params: {
  engagementName: string;
  demonstratedTechniques: DemonstratedTechnique[];
  recommendedTechniques?: TechniqueRecommendation[];
}): NavigatorLayer {
  const { engagementName, demonstratedTechniques, recommendedTechniques } = params;

  const techniques: NavigatorLayer['techniques'] = [];

  // Add demonstrated techniques (scored and colored)
  for (const dt of demonstratedTechniques) {
    const qualityScore: Record<string, number> = {
      definitive: 100,
      strong: 75,
      moderate: 50,
      weak: 25,
    };

    techniques.push({
      techniqueID: dt.techniqueId,
      tactic: dt.tactic,
      color: '#e60000', // Red for demonstrated
      comment: `Demonstrated: ${dt.evidence} (${dt.quality} quality)`,
      score: qualityScore[dt.quality] || 50,
      enabled: true,
    });
  }

  // Add recommended but not demonstrated techniques (if provided)
  if (recommendedTechniques) {
    for (const rt of recommendedTechniques) {
      if (!rt.demonstrated) {
        techniques.push({
          techniqueID: rt.technique.techniqueId,
          tactic: rt.technique.tactic,
          color: '#ffcc00', // Yellow for recommended but not demonstrated
          comment: `Recommended: ${rt.rationale}`,
          score: Math.round(rt.confidence * 100),
          enabled: true,
        });
      }
    }
  }

  return {
    name: `${engagementName} — Exploitation Coverage`,
    versions: {
      attack: '14',
      navigator: '4.9.1',
      layer: '4.5',
    },
    domain: 'enterprise-attack',
    description: `ATT&CK technique coverage for engagement: ${engagementName}. Red = demonstrated, Yellow = recommended.`,
    techniques,
    gradient: {
      colors: ['#ffffff', '#ffcc00', '#e60000'],
      minValue: 0,
      maxValue: 100,
    },
    legendItems: [
      { label: 'Demonstrated', color: '#e60000' },
      { label: 'Recommended', color: '#ffcc00' },
      { label: 'Not Applicable', color: '#ffffff' },
    ],
  };
}

// ═══════════════════════════════════════════════════════════════════════
// §7 — ENGAGEMENT TRACKER
// ═══════════════════════════════════════════════════════════════════════

/**
 * Create a new engagement ATT&CK tracker.
 */
export function createEngagementTracker(
  engagementId: string,
  vulnClass: string,
  accessLevel: string,
  techStack: string[],
): EngagementAttackTracker {
  const recommendations = recommendTechniques({
    vulnClass,
    accessLevel,
    techStack,
    hasWaf: false,
    isCloudEnvironment: false,
    safeModeEnabled: false,
    demonstratedTechniques: [],
  });

  return {
    engagementId,
    recommendedTechniques: recommendations,
    demonstratedTechniques: new Map(),
    coverage: analyzeKillChainCoverage({
      vulnClass,
      demonstratedTechniques: [],
      accessLevel,
      safeModeEnabled: false,
    }),
  };
}

/**
 * Record a demonstrated technique in the tracker.
 */
export function recordDemonstration(
  tracker: EngagementAttackTracker,
  technique: DemonstratedTechnique,
  vulnClass: string,
): EngagementAttackTracker {
  const newDemonstrated = new Map(tracker.demonstratedTechniques);
  newDemonstrated.set(technique.techniqueId, technique);

  const demonstratedList = [...newDemonstrated.values()];
  const demonstratedIds = demonstratedList.map(d => d.techniqueId);

  // Update recommendations
  const updatedRecommendations = tracker.recommendedTechniques.map(r => ({
    ...r,
    demonstrated: demonstratedIds.includes(r.technique.techniqueId),
  }));

  // Update coverage
  const updatedCoverage = analyzeKillChainCoverage({
    vulnClass,
    demonstratedTechniques: demonstratedList,
    accessLevel: 'none', // Will be overridden by actual state
    safeModeEnabled: false,
  });

  return {
    ...tracker,
    recommendedTechniques: updatedRecommendations,
    demonstratedTechniques: newDemonstrated,
    coverage: updatedCoverage,
  };
}

/**
 * Get the next recommended technique to demonstrate.
 */
export function getNextRecommendation(tracker: EngagementAttackTracker): TechniqueRecommendation | null {
  return tracker.recommendedTechniques.find(r => !r.demonstrated) || null;
}

// ═══════════════════════════════════════════════════════════════════════
// §8 — PROMPT ENRICHMENT
// ═══════════════════════════════════════════════════════════════════════

/**
 * Generate ATT&CK context for LLM prompt enrichment.
 * This is injected into exploit generation prompts to guide the LLM
 * toward technique-aware exploitation.
 */
export function generateAttackContextForPrompt(params: {
  vulnClass: string;
  accessLevel: string;
  demonstratedTechniques: string[];
  safeModeEnabled: boolean;
}): string {
  const recommendations = recommendTechniques({
    ...params,
    techStack: [],
    hasWaf: false,
    isCloudEnvironment: false,
  });

  const nextTechniques = recommendations.filter(r => !r.demonstrated).slice(0, 3);

  if (nextTechniques.length === 0) {
    return 'All relevant ATT&CK techniques have been demonstrated for this vulnerability class.';
  }

  const lines: string[] = [
    '## ATT&CK Technique Guidance',
    '',
    'The following MITRE ATT&CK techniques should be demonstrated during exploitation:',
    '',
  ];

  for (const rec of nextTechniques) {
    lines.push(`### ${rec.technique.techniqueId}: ${rec.technique.techniqueName} (${rec.technique.tactic})`);
    lines.push(`**Guidance:** ${rec.technique.exploitGuidance}`);
    lines.push(`**Tools:** ${rec.technique.tools.join(', ')}`);
    lines.push(`**WSTG:** ${rec.technique.relatedWSTG.join(', ')}`);
    lines.push('');
  }

  if (params.demonstratedTechniques.length > 0) {
    lines.push(`**Already demonstrated:** ${params.demonstratedTechniques.join(', ')}`);
    lines.push('Focus on the techniques listed above that have NOT been demonstrated yet.');
  }

  return lines.join('\n');
}

/**
 * Get all supported vulnerability classes.
 */
export function getSupportedVulnClasses(): string[] {
  return Object.keys(VULN_TO_TECHNIQUE_MAP);
}

/**
 * Get all techniques for a vulnerability class.
 */
export function getTechniquesForVulnClass(vulnClass: string): AttackTechniqueProfile[] {
  return VULN_TO_TECHNIQUE_MAP[vulnClass.toLowerCase()] || [];
}
