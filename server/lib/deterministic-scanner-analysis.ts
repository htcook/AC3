/**
 * Deterministic Scanner Analysis Engine
 *
 * Tier 1 LLM-to-App Offload: Replaces LLM-powered finding analysis in 7 scanner
 * modules with rule-based, deterministic logic. Each scanner's `analyze*Findings`
 * function was previously calling invokeLLM to produce:
 *   1. Risk summary text
 *   2. Exploitability / injection vector / exploit chain assessments
 *   3. Remediation recommendations
 *
 * This module provides the same output shapes using:
 *   - Keyword-based severity/exploitability scoring
 *   - CVE/CWE lookup tables for known vulnerability context
 *   - Template-based risk summary generation
 *   - Rule-based remediation recommendation mapping
 *
 * Benefits:
 *   - ~0 latency (vs 3-8s per LLM call)
 *   - $0 token cost (vs ~$0.02-0.08 per analysis)
 *   - 100% deterministic (same input → same output)
 *   - Works offline / during LLM outages
 *
 * The LLM analysis functions remain available as fallback for edge cases
 * or when the operator explicitly requests AI-enhanced analysis.
 */

// ─── Shared Types ──────────────────────────────────────────────────────────

export interface ExploitabilityAssessment {
  score: number; // 0-10 CVSS-like
  level: "critical" | "high" | "medium" | "low" | "none";
  rationale: string;
}

export interface RemediationRecommendation {
  priority: number; // 1 = highest
  action: string;
  effort: "immediate" | "short-term" | "long-term";
  category: string;
}

// ─── Exploitability Scoring Rules ──────────────────────────────────────────

const EXPLOITABILITY_PATTERNS: Array<{
  pattern: RegExp;
  score: number;
  level: ExploitabilityAssessment["level"];
  rationale: string;
}> = [
  // Critical — trivially exploitable
  { pattern: /remote\s*code\s*execution|rce\b|command\s*injection|os\s*command/i, score: 9.5, level: "critical", rationale: "Allows arbitrary command execution on the server" },
  { pattern: /sql\s*injection.*union|blind\s*sql\s*injection|time-based\s*sql/i, score: 9.0, level: "critical", rationale: "Confirmed SQL injection with data extraction capability" },
  { pattern: /backdoor|web\s*shell|reverse\s*shell/i, score: 10, level: "critical", rationale: "Backdoor or shell access detected — immediate compromise possible" },
  { pattern: /authentication\s*bypass|auth\s*bypass/i, score: 9.0, level: "critical", rationale: "Authentication can be bypassed entirely" },
  { pattern: /default\s*(password|credential|login)/i, score: 8.5, level: "critical", rationale: "Default credentials allow immediate unauthorized access" },
  { pattern: /bluekeep|CVE-2019-0708/i, score: 9.8, level: "critical", rationale: "BlueKeep (CVE-2019-0708) — wormable RCE in RDP" },
  { pattern: /dejablue|CVE-2019-1181|CVE-2019-1182/i, score: 9.0, level: "critical", rationale: "DejaBlue — RCE in RDP without authentication" },
  { pattern: /eternalblue|CVE-2017-0144/i, score: 9.8, level: "critical", rationale: "EternalBlue — wormable SMB RCE" },

  // High — exploitable with moderate skill
  { pattern: /sql\s*injection/i, score: 8.0, level: "high", rationale: "SQL injection detected — data theft or manipulation possible" },
  { pattern: /file\s*inclusion|lfi\b|rfi\b/i, score: 8.0, level: "high", rationale: "File inclusion allows reading sensitive files or executing code" },
  { pattern: /directory\s*traversal|path\s*traversal|\.\.\//i, score: 7.5, level: "high", rationale: "Path traversal allows access to files outside web root" },
  { pattern: /xxe|xml\s*external\s*entity/i, score: 7.5, level: "high", rationale: "XXE can read local files or perform SSRF" },
  { pattern: /ssrf|server.side\s*request/i, score: 7.5, level: "high", rationale: "SSRF can access internal services and cloud metadata" },
  { pattern: /deserialization|unserialize/i, score: 8.5, level: "high", rationale: "Insecure deserialization can lead to RCE" },
  { pattern: /config\s*file|\.env\s*file|\.git\s*exposed/i, score: 7.0, level: "high", rationale: "Sensitive configuration files exposed — may contain credentials" },
  { pattern: /open\s*relay/i, score: 7.5, level: "high", rationale: "Open SMTP relay allows sending spam/phishing from this server" },
  { pattern: /write\s*access.*community|community.*write/i, score: 7.5, level: "high", rationale: "SNMP write access allows device reconfiguration" },
  { pattern: /sslv2|sslv3|ssl\s*v2|ssl\s*v3/i, score: 7.0, level: "high", rationale: "Obsolete SSL version — vulnerable to POODLE, DROWN attacks" },
  { pattern: /rc4|des\b|3des|export.*cipher/i, score: 6.5, level: "high", rationale: "Weak cipher suite — vulnerable to cryptographic attacks" },
  { pattern: /heartbleed|CVE-2014-0160/i, score: 9.0, level: "critical", rationale: "Heartbleed — memory disclosure of private keys and session data" },

  // Medium — requires specific conditions
  { pattern: /cross.site\s*scripting|xss\b|reflected\s*xss|stored\s*xss/i, score: 6.0, level: "medium", rationale: "XSS can steal session cookies or perform actions as the user" },
  { pattern: /csrf|cross.site\s*request/i, score: 5.5, level: "medium", rationale: "CSRF allows unauthorized actions on behalf of authenticated users" },
  { pattern: /open\s*redirect/i, score: 4.5, level: "medium", rationale: "Open redirect useful for phishing but limited direct impact" },
  { pattern: /phpinfo/i, score: 5.0, level: "medium", rationale: "phpinfo() exposes server configuration, paths, and module versions" },
  { pattern: /admin\s*panel|admin\s*interface|admin\s*console/i, score: 5.5, level: "medium", rationale: "Exposed admin interface increases attack surface" },
  { pattern: /backup\s*file|\.bak\b|\.old\b|\.orig\b/i, score: 5.0, level: "medium", rationale: "Backup files may contain source code or credentials" },
  { pattern: /user\s*enumeration|username\s*enumeration|vrfy|expn/i, score: 5.0, level: "medium", rationale: "User enumeration aids brute-force and social engineering attacks" },
  { pattern: /weak.*password|password.*weak|brute.?force/i, score: 5.5, level: "medium", rationale: "Weak password policy enables credential attacks" },
  { pattern: /self.signed\s*cert/i, score: 4.5, level: "medium", rationale: "Self-signed certificate — no trust chain validation" },
  { pattern: /nla.*disabled|disabled.*nla|network\s*level\s*auth.*not/i, score: 5.5, level: "medium", rationale: "NLA disabled — pre-authentication attacks possible" },
  { pattern: /tlsv1\.0|tls\s*1\.0/i, score: 5.0, level: "medium", rationale: "TLS 1.0 deprecated — vulnerable to BEAST and other attacks" },
  { pattern: /public\b.*community|community.*public/i, score: 5.0, level: "medium", rationale: "Default 'public' SNMP community string — information disclosure" },

  // Low — informational with minor risk
  { pattern: /directory\s*(listing|indexing)/i, score: 3.0, level: "low", rationale: "Directory listing reveals file structure but limited direct impact" },
  { pattern: /information\s*disclosure/i, score: 2.5, level: "low", rationale: "Information disclosure aids reconnaissance but not directly exploitable" },
  { pattern: /missing.*header|header.*missing|x-frame-options|x-content-type|content-security-policy|strict-transport/i, score: 2.0, level: "low", rationale: "Missing security header — defense-in-depth gap" },
  { pattern: /server\s*version|banner\s*disclosure|server\s*banner/i, score: 1.5, level: "low", rationale: "Server version disclosure aids fingerprinting" },
  { pattern: /robots\.txt|sitemap/i, score: 1.0, level: "low", rationale: "Informational — standard web files" },
  { pattern: /tlsv1\.1|tls\s*1\.1/i, score: 3.5, level: "low", rationale: "TLS 1.1 deprecated but not immediately exploitable" },
  { pattern: /compression.*enabled|crime|breach/i, score: 3.0, level: "low", rationale: "TLS compression may enable CRIME/BREACH attacks under specific conditions" },
];

export function assessExploitability(description: string, additionalContext?: string): ExploitabilityAssessment {
  const text = `${description} ${additionalContext || ""}`.toLowerCase();

  for (const rule of EXPLOITABILITY_PATTERNS) {
    if (rule.pattern.test(text)) {
      return { score: rule.score, level: rule.level, rationale: rule.rationale };
    }
  }

  return { score: 1.0, level: "none", rationale: "No known exploitability pattern matched" };
}

// ─── Remediation Knowledge Base ────────────────────────────────────────────

const REMEDIATION_RULES: Array<{
  pattern: RegExp;
  recommendations: RemediationRecommendation[];
}> = [
  {
    pattern: /sql\s*injection/i,
    recommendations: [
      { priority: 1, action: "Use parameterized queries (prepared statements) for all database operations", effort: "immediate", category: "injection" },
      { priority: 2, action: "Implement input validation with allowlists for expected data types", effort: "short-term", category: "injection" },
      { priority: 3, action: "Deploy a Web Application Firewall (WAF) with SQL injection rules", effort: "short-term", category: "injection" },
      { priority: 4, action: "Apply principle of least privilege to database accounts", effort: "short-term", category: "hardening" },
    ],
  },
  {
    pattern: /cross.site\s*scripting|xss\b/i,
    recommendations: [
      { priority: 1, action: "Encode all user-supplied output using context-appropriate encoding (HTML, JS, URL, CSS)", effort: "immediate", category: "injection" },
      { priority: 2, action: "Implement Content-Security-Policy header to restrict script sources", effort: "short-term", category: "headers" },
      { priority: 3, action: "Use HttpOnly and Secure flags on session cookies", effort: "immediate", category: "session" },
    ],
  },
  {
    pattern: /remote\s*code\s*execution|rce\b|command\s*(injection|execution)/i,
    recommendations: [
      { priority: 1, action: "Remove or disable the vulnerable component immediately", effort: "immediate", category: "critical-fix" },
      { priority: 2, action: "Apply vendor patches or upgrade to a non-vulnerable version", effort: "immediate", category: "patching" },
      { priority: 3, action: "Implement network segmentation to limit blast radius", effort: "short-term", category: "architecture" },
      { priority: 4, action: "Deploy application-level sandboxing (containers, seccomp, AppArmor)", effort: "long-term", category: "hardening" },
    ],
  },
  {
    pattern: /file\s*inclusion|lfi\b|rfi\b|directory\s*traversal|path\s*traversal/i,
    recommendations: [
      { priority: 1, action: "Validate and sanitize all file path inputs — reject '..' sequences", effort: "immediate", category: "injection" },
      { priority: 2, action: "Use allowlists for permitted file paths instead of blocklists", effort: "short-term", category: "injection" },
      { priority: 3, action: "Run web server with minimal filesystem permissions (chroot/container)", effort: "long-term", category: "hardening" },
    ],
  },
  {
    pattern: /default\s*(password|credential|login)/i,
    recommendations: [
      { priority: 1, action: "Change all default credentials immediately", effort: "immediate", category: "authentication" },
      { priority: 2, action: "Implement account lockout after failed login attempts", effort: "short-term", category: "authentication" },
      { priority: 3, action: "Deploy multi-factor authentication (MFA)", effort: "short-term", category: "authentication" },
    ],
  },
  {
    pattern: /authentication\s*bypass|auth\s*bypass/i,
    recommendations: [
      { priority: 1, action: "Patch the authentication bypass vulnerability immediately", effort: "immediate", category: "critical-fix" },
      { priority: 2, action: "Implement defense-in-depth with secondary authentication checks", effort: "short-term", category: "authentication" },
      { priority: 3, action: "Add audit logging for all authentication events", effort: "short-term", category: "monitoring" },
    ],
  },
  {
    pattern: /missing.*x-frame-options|x-frame-options.*missing/i,
    recommendations: [
      { priority: 1, action: "Add X-Frame-Options: DENY or SAMEORIGIN header", effort: "immediate", category: "headers" },
    ],
  },
  {
    pattern: /missing.*content-security-policy|csp.*missing/i,
    recommendations: [
      { priority: 1, action: "Implement Content-Security-Policy header with restrictive directives", effort: "short-term", category: "headers" },
    ],
  },
  {
    pattern: /missing.*strict-transport|hsts.*missing/i,
    recommendations: [
      { priority: 1, action: "Add Strict-Transport-Security header with max-age of at least 31536000", effort: "immediate", category: "headers" },
    ],
  },
  {
    pattern: /missing.*x-content-type/i,
    recommendations: [
      { priority: 1, action: "Add X-Content-Type-Options: nosniff header", effort: "immediate", category: "headers" },
    ],
  },
  {
    pattern: /directory\s*(listing|indexing)/i,
    recommendations: [
      { priority: 1, action: "Disable directory listing in web server configuration (Options -Indexes)", effort: "immediate", category: "misconfiguration" },
    ],
  },
  {
    pattern: /server\s*version|banner\s*disclosure/i,
    recommendations: [
      { priority: 1, action: "Configure server to suppress version information in headers and error pages", effort: "immediate", category: "hardening" },
    ],
  },
  {
    pattern: /phpinfo/i,
    recommendations: [
      { priority: 1, action: "Remove phpinfo() files from production servers", effort: "immediate", category: "sensitive-files" },
    ],
  },
  {
    pattern: /\.env\s*file|config\s*file.*exposed|\.git\s*exposed/i,
    recommendations: [
      { priority: 1, action: "Remove sensitive files from web-accessible directories immediately", effort: "immediate", category: "sensitive-files" },
      { priority: 2, action: "Add server rules to block access to dotfiles and config files", effort: "immediate", category: "hardening" },
      { priority: 3, action: "Rotate all credentials that may have been exposed", effort: "immediate", category: "incident-response" },
    ],
  },
  {
    pattern: /open\s*relay/i,
    recommendations: [
      { priority: 1, action: "Configure SMTP server to reject relay attempts from unauthorized sources", effort: "immediate", category: "misconfiguration" },
      { priority: 2, action: "Implement SPF, DKIM, and DMARC records", effort: "short-term", category: "email-security" },
      { priority: 3, action: "Restrict SMTP access to authorized IP ranges", effort: "short-term", category: "network" },
    ],
  },
  {
    pattern: /user\s*enumeration|vrfy|expn/i,
    recommendations: [
      { priority: 1, action: "Disable VRFY and EXPN SMTP commands", effort: "immediate", category: "hardening" },
      { priority: 2, action: "Return generic error messages that don't reveal user existence", effort: "short-term", category: "hardening" },
    ],
  },
  {
    pattern: /community.*string|snmp.*default|public.*community/i,
    recommendations: [
      { priority: 1, action: "Change default SNMP community strings to complex, unique values", effort: "immediate", category: "authentication" },
      { priority: 2, action: "Upgrade to SNMPv3 with authentication and encryption", effort: "short-term", category: "protocol-upgrade" },
      { priority: 3, action: "Restrict SNMP access to management network only via ACLs", effort: "short-term", category: "network" },
    ],
  },
  {
    pattern: /write\s*access.*snmp|snmp.*write/i,
    recommendations: [
      { priority: 1, action: "Remove or restrict SNMP write community strings", effort: "immediate", category: "authentication" },
      { priority: 2, action: "Implement SNMPv3 with HMAC-SHA authentication", effort: "short-term", category: "protocol-upgrade" },
    ],
  },
  {
    pattern: /bluekeep|CVE-2019-0708/i,
    recommendations: [
      { priority: 1, action: "Apply Microsoft security update KB4499175 immediately", effort: "immediate", category: "patching" },
      { priority: 2, action: "Enable Network Level Authentication (NLA)", effort: "immediate", category: "hardening" },
      { priority: 3, action: "Restrict RDP access to VPN or jump host only", effort: "short-term", category: "network" },
    ],
  },
  {
    pattern: /nla.*disabled|network\s*level\s*auth/i,
    recommendations: [
      { priority: 1, action: "Enable Network Level Authentication (NLA) on all RDP servers", effort: "immediate", category: "hardening" },
      { priority: 2, action: "Restrict RDP access to authorized networks via firewall rules", effort: "short-term", category: "network" },
    ],
  },
  {
    pattern: /sslv2|sslv3|ssl\s*v[23]/i,
    recommendations: [
      { priority: 1, action: "Disable SSLv2 and SSLv3 — use TLS 1.2+ only", effort: "immediate", category: "protocol-upgrade" },
      { priority: 2, action: "Test with tools like testssl.sh to verify protocol configuration", effort: "immediate", category: "validation" },
    ],
  },
  {
    pattern: /tlsv1\.0|tls\s*1\.0/i,
    recommendations: [
      { priority: 1, action: "Disable TLS 1.0 — migrate to TLS 1.2 or 1.3", effort: "short-term", category: "protocol-upgrade" },
      { priority: 2, action: "Update client compatibility requirements to support TLS 1.2+", effort: "long-term", category: "planning" },
    ],
  },
  {
    pattern: /self.signed\s*cert/i,
    recommendations: [
      { priority: 1, action: "Replace self-signed certificate with one from a trusted CA", effort: "short-term", category: "certificate" },
      { priority: 2, action: "Implement automated certificate management (Let's Encrypt / ACME)", effort: "long-term", category: "certificate" },
    ],
  },
  {
    pattern: /expired\s*cert|certificate.*expir/i,
    recommendations: [
      { priority: 1, action: "Renew the expired certificate immediately", effort: "immediate", category: "certificate" },
      { priority: 2, action: "Set up certificate expiration monitoring and alerts", effort: "short-term", category: "monitoring" },
    ],
  },
  {
    pattern: /weak.*cipher|rc4|des\b|3des|export.*cipher/i,
    recommendations: [
      { priority: 1, action: "Disable weak cipher suites (RC4, DES, 3DES, export ciphers)", effort: "immediate", category: "cryptography" },
      { priority: 2, action: "Configure cipher suite preference order with AEAD ciphers first (AES-GCM, ChaCha20)", effort: "short-term", category: "cryptography" },
    ],
  },
  {
    pattern: /heartbleed|CVE-2014-0160/i,
    recommendations: [
      { priority: 1, action: "Upgrade OpenSSL to a patched version immediately", effort: "immediate", category: "patching" },
      { priority: 2, action: "Revoke and reissue all TLS certificates", effort: "immediate", category: "incident-response" },
      { priority: 3, action: "Force password resets for all users", effort: "immediate", category: "incident-response" },
    ],
  },
  {
    pattern: /xxe|xml\s*external\s*entity/i,
    recommendations: [
      { priority: 1, action: "Disable external entity processing in XML parsers", effort: "immediate", category: "injection" },
      { priority: 2, action: "Use JSON instead of XML where possible", effort: "long-term", category: "architecture" },
    ],
  },
  {
    pattern: /ssrf|server.side\s*request/i,
    recommendations: [
      { priority: 1, action: "Validate and sanitize all URLs before server-side requests", effort: "immediate", category: "injection" },
      { priority: 2, action: "Implement allowlist of permitted domains/IPs for outbound requests", effort: "short-term", category: "network" },
      { priority: 3, action: "Block access to cloud metadata endpoints (169.254.169.254)", effort: "immediate", category: "cloud" },
    ],
  },
];

export function getRemediation(description: string): RemediationRecommendation[] {
  const results: RemediationRecommendation[] = [];
  const seen = new Set<string>();

  for (const rule of REMEDIATION_RULES) {
    if (rule.pattern.test(description)) {
      for (const rec of rule.recommendations) {
        if (!seen.has(rec.action)) {
          results.push(rec);
          seen.add(rec.action);
        }
      }
    }
  }

  if (results.length === 0) {
    results.push({
      priority: 1,
      action: "Review the finding and apply appropriate security controls based on the vulnerability type",
      effort: "short-term",
      category: "general",
    });
  }

  return results.sort((a, b) => a.priority - b.priority);
}

// ─── Risk Summary Generator ───────────────────────────────────────────────

interface SeverityCounts {
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

function countSeverities(findings: Array<{ severity: string }>): SeverityCounts {
  const counts: SeverityCounts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
  for (const f of findings) {
    const sev = f.severity?.toLowerCase() as keyof SeverityCounts;
    if (sev in counts) counts[sev]++;
  }
  return counts;
}

function getRiskLevel(counts: SeverityCounts): "critical" | "high" | "medium" | "low" | "minimal" {
  if (counts.critical > 0) return "critical";
  if (counts.high > 0) return "high";
  if (counts.medium > 0) return "medium";
  if (counts.low > 0) return "low";
  return "minimal";
}

export function generateRiskSummary(
  findings: Array<{ severity: string; description: string }>,
  scannerName: string,
  targetInfo: string,
): string {
  if (findings.length === 0) {
    return `${scannerName} scan of ${targetInfo} completed with no findings. The target appears to have a clean security posture based on this scan.`;
  }

  const counts = countSeverities(findings);
  const riskLevel = getRiskLevel(counts);
  const total = findings.length;

  const severityBreakdown = [
    counts.critical > 0 ? `${counts.critical} critical` : null,
    counts.high > 0 ? `${counts.high} high` : null,
    counts.medium > 0 ? `${counts.medium} medium` : null,
    counts.low > 0 ? `${counts.low} low` : null,
    counts.info > 0 ? `${counts.info} informational` : null,
  ].filter(Boolean).join(", ");

  const riskDescriptions: Record<string, string> = {
    critical: `The target presents a critical security risk with ${total} findings (${severityBreakdown}). Immediate remediation is required — critical findings indicate exploitable vulnerabilities that could lead to full system compromise.`,
    high: `The target has significant security concerns with ${total} findings (${severityBreakdown}). High-severity issues should be addressed promptly as they represent exploitable attack vectors.`,
    medium: `The target shows moderate security concerns with ${total} findings (${severityBreakdown}). While no critical or high-severity issues were found, the medium-severity findings should be addressed to reduce attack surface.`,
    low: `The target has minor security observations with ${total} findings (${severityBreakdown}). These are primarily hardening recommendations and informational disclosures.`,
    minimal: `The target has a relatively clean security posture with only ${total} informational findings. No actionable vulnerabilities were detected.`,
  };

  // Add top finding context
  const topFindings = findings
    .filter(f => ["critical", "high"].includes(f.severity?.toLowerCase()))
    .slice(0, 3);

  let summary = riskDescriptions[riskLevel];

  if (topFindings.length > 0) {
    const topDescriptions = topFindings
      .map(f => f.description.slice(0, 100))
      .join("; ");
    summary += ` Key concerns include: ${topDescriptions}.`;
  }

  return summary;
}

// ─── Attack Surface Identification ─────────────────────────────────────────

const ATTACK_SURFACE_PATTERNS: Array<{ pattern: RegExp; surface: string }> = [
  { pattern: /admin|management|console|dashboard/i, surface: "Administrative interfaces exposed" },
  { pattern: /api|endpoint|graphql|rest/i, surface: "API endpoints accessible" },
  { pattern: /upload|file.*upload/i, surface: "File upload functionality present" },
  { pattern: /login|auth|sign.?in|session/i, surface: "Authentication mechanisms exposed" },
  { pattern: /database|sql|mysql|postgres|mongo/i, surface: "Database services or interfaces detected" },
  { pattern: /ftp|sftp|scp/i, surface: "File transfer services running" },
  { pattern: /smtp|mail|email|postfix|sendmail/i, surface: "Email services exposed" },
  { pattern: /snmp|community/i, surface: "SNMP management interface accessible" },
  { pattern: /rdp|remote\s*desktop|terminal\s*service/i, surface: "Remote desktop services exposed" },
  { pattern: /ssh|openssh/i, surface: "SSH service accessible" },
  { pattern: /ssl|tls|certificate|https/i, surface: "TLS/SSL configuration surface" },
  { pattern: /cgi|cgi-bin|perl|php/i, surface: "Legacy CGI/scripting interfaces present" },
  { pattern: /proxy|reverse\s*proxy|load\s*balancer/i, surface: "Proxy/load balancer infrastructure" },
  { pattern: /debug|trace|verbose/i, surface: "Debug/diagnostic interfaces enabled" },
  { pattern: /backup|\.bak|\.old|\.orig/i, surface: "Backup files accessible" },
  { pattern: /git|svn|\.git|\.svn/i, surface: "Version control artifacts exposed" },
  { pattern: /docker|kubernetes|container/i, surface: "Container orchestration interfaces" },
  { pattern: /jenkins|gitlab|ci.*cd/i, surface: "CI/CD pipeline interfaces" },
];

export function identifyAttackSurface(findings: Array<{ description: string; uri?: string }>): string[] {
  const surfaces = new Set<string>();

  for (const finding of findings) {
    const text = `${finding.description} ${finding.uri || ""}`;
    for (const rule of ATTACK_SURFACE_PATTERNS) {
      if (rule.pattern.test(text)) {
        surfaces.add(rule.surface);
      }
    }
  }

  return Array.from(surfaces);
}

// ─── Exploit Chain Detection ───────────────────────────────────────────────

interface ExploitChain {
  chain: string[];
  impact: string;
  likelihood: string;
}

const CHAIN_RULES: Array<{
  requires: RegExp[];
  chain: string[];
  impact: string;
  likelihood: string;
}> = [
  {
    requires: [/information\s*disclosure|server\s*version/, /sql\s*injection|rce|command\s*injection/],
    chain: ["Information disclosure reveals technology stack", "Targeted exploit using known version vulnerabilities"],
    impact: "Full system compromise via targeted exploit after fingerprinting",
    likelihood: "High",
  },
  {
    requires: [/directory\s*(listing|traversal)/, /config\s*file|\.env|credential/],
    chain: ["Directory traversal or listing reveals file structure", "Access sensitive configuration files containing credentials"],
    impact: "Credential theft leading to unauthorized access",
    likelihood: "High",
  },
  {
    requires: [/xss|cross.site\s*scripting/, /session|cookie|csrf/],
    chain: ["XSS payload steals session cookies", "Session hijacking grants authenticated access"],
    impact: "Account takeover via session hijacking",
    likelihood: "Medium",
  },
  {
    requires: [/user\s*enumeration|vrfy|expn/, /weak.*password|default.*password|brute/],
    chain: ["User enumeration reveals valid usernames", "Brute-force or credential stuffing against known accounts"],
    impact: "Unauthorized access via credential attacks",
    likelihood: "Medium",
  },
  {
    requires: [/open\s*relay/, /spf.*missing|dmarc.*missing|no.*spf/],
    chain: ["Open relay allows sending emails as any address", "Missing SPF/DMARC allows spoofed emails to pass validation"],
    impact: "Phishing campaigns using the organization's mail infrastructure",
    likelihood: "High",
  },
  {
    requires: [/snmp.*community|public.*community/, /write\s*access/],
    chain: ["Default community string provides read access", "Write access allows device reconfiguration"],
    impact: "Network device takeover via SNMP write access",
    likelihood: "High",
  },
  {
    requires: [/nla.*disabled/, /weak.*encryption|rdp.*encryption/],
    chain: ["NLA disabled allows pre-authentication connection", "Weak encryption enables man-in-the-middle attacks"],
    impact: "RDP session interception and credential theft",
    likelihood: "Medium",
  },
  {
    requires: [/sslv[23]|weak.*cipher/, /self.signed|expired.*cert/],
    chain: ["Weak protocol/cipher enables cryptographic attacks", "Certificate issues prevent proper validation"],
    impact: "Man-in-the-middle attack with traffic decryption",
    likelihood: "Medium",
  },
];

export function detectExploitChains(findings: Array<{ description: string; severity: string }>): ExploitChain[] {
  const chains: ExploitChain[] = [];
  const allDescriptions = findings.map(f => f.description).join(" ");

  for (const rule of CHAIN_RULES) {
    const allMatch = rule.requires.every(pattern => pattern.test(allDescriptions));
    if (allMatch) {
      chains.push({
        chain: rule.chain,
        impact: rule.impact,
        likelihood: rule.likelihood,
      });
    }
  }

  return chains;
}

// ─── Scanner-Specific Analysis Functions ───────────────────────────────────
// These match the exact return types of the LLM-powered analyze* functions

/**
 * Deterministic replacement for analyzeNiktoFindings
 * Same return type as the LLM version in nikto-scanner.ts
 */
export function analyzeNiktoFindingsDeterministic(
  findings: Array<{ severity: string; description: string; method: string; uri: string; category: string; id: string; osvdbId: string | null; references: string[] }>,
  targetUrl: string,
  serverBanner: string | null,
): {
  riskSummary: string;
  prioritizedFindings: Array<{ severity: string; description: string; uri: string; exploitability: string; recommendation: string }>;
  attackSurface: string[];
} {
  const riskSummary = generateRiskSummary(findings, "Nikto", `${targetUrl}${serverBanner ? ` (${serverBanner})` : ""}`);

  const prioritizedFindings = findings
    .map(f => {
      const exploit = assessExploitability(f.description, f.uri);
      const remediation = getRemediation(f.description);
      return {
        ...f,
        exploitability: `${exploit.level} (${exploit.score}/10) — ${exploit.rationale}`,
        recommendation: remediation[0]?.action || "Review and apply appropriate security controls",
        _score: exploit.score,
      };
    })
    .sort((a, b) => b._score - a._score)
    .map(({ _score, ...rest }) => rest);

  const attackSurface = identifyAttackSurface(findings);

  return { riskSummary, prioritizedFindings, attackSurface };
}

/**
 * Deterministic replacement for analyzeWapitiFindings
 * Same return type as the LLM version in wapiti-scanner.ts
 */
export function analyzeWapitiFindingsDeterministic(
  findings: Array<{ severity: string; description: string; module: string; method: string; path: string; parameter: string }>,
  targetUrl: string,
): {
  riskSummary: string;
  injectionVectors: Array<{ path: string; parameter: string; type: string; severity: string; exploitability: string }>;
  recommendations: string[];
} {
  const riskSummary = generateRiskSummary(findings, "Wapiti", targetUrl);

  const injectionVectors = findings
    .filter(f => f.parameter)
    .map(f => {
      const exploit = assessExploitability(f.description, f.module);
      return {
        path: f.path,
        parameter: f.parameter,
        type: f.module,
        severity: f.severity,
        exploitability: `${exploit.level} — ${exploit.rationale}`,
      };
    });

  // Collect unique recommendations
  const recSet = new Set<string>();
  for (const f of findings) {
    const recs = getRemediation(f.description);
    for (const r of recs) recSet.add(r.action);
  }

  return { riskSummary, injectionVectors, recommendations: Array.from(recSet).slice(0, 10) };
}

/**
 * Deterministic replacement for analyzeArachniFindings
 * Same return type as the LLM version in arachni-scanner.ts
 */
export function analyzeArachniFindingsDeterministic(
  findings: Array<{ severity: string; description: string; name: string; module: string; method: string; url: string; parameter: string; proof?: string }>,
  targetUrl: string,
): {
  riskSummary: string;
  exploitChains: ExploitChain[];
  recommendations: string[];
} {
  const riskSummary = generateRiskSummary(findings, "Arachni", targetUrl);
  const exploitChains = detectExploitChains(findings);

  const recSet = new Set<string>();
  for (const f of findings) {
    const recs = getRemediation(f.description);
    for (const r of recs) recSet.add(r.action);
  }

  return { riskSummary, exploitChains, recommendations: Array.from(recSet).slice(0, 10) };
}

/**
 * Deterministic replacement for SMTP/SNMP/RDP LLM analysis
 * These scanners use LLM to generate additional findings from raw output.
 * The deterministic version generates findings from structured data instead.
 */
export function generateProtocolFindings(
  protocol: "smtp" | "snmp" | "rdp" | "tls",
  structuredData: Record<string, any>,
): Array<{
  category: string;
  severity: string;
  title: string;
  description: string;
  recommendation: string;
  cve: string | null;
  cwe: string | null;
}> {
  const findings: Array<{
    category: string;
    severity: string;
    title: string;
    description: string;
    recommendation: string;
    cve: string | null;
    cwe: string | null;
  }> = [];

  if (protocol === "smtp") {
    const { banner, starttls, authMethods, vrfyEnabled, expnEnabled, openRelay } = structuredData;

    if (openRelay) {
      findings.push({
        category: "relay",
        severity: "high",
        title: "SMTP Open Relay Detected",
        description: "The SMTP server accepts and relays email from unauthorized sources. This can be abused for spam, phishing, and email spoofing campaigns.",
        recommendation: "Configure SMTP server to only relay mail from authenticated and authorized sources.",
        cve: null,
        cwe: "CWE-284",
      });
    }
    if (vrfyEnabled) {
      findings.push({
        category: "enumeration",
        severity: "medium",
        title: "SMTP VRFY Command Enabled",
        description: "The VRFY command is enabled, allowing attackers to enumerate valid email addresses on the server.",
        recommendation: "Disable the VRFY command in SMTP server configuration.",
        cve: null,
        cwe: "CWE-200",
      });
    }
    if (expnEnabled) {
      findings.push({
        category: "enumeration",
        severity: "medium",
        title: "SMTP EXPN Command Enabled",
        description: "The EXPN command is enabled, allowing attackers to enumerate mailing list members.",
        recommendation: "Disable the EXPN command in SMTP server configuration.",
        cve: null,
        cwe: "CWE-200",
      });
    }
    if (!starttls) {
      findings.push({
        category: "encryption",
        severity: "medium",
        title: "STARTTLS Not Supported",
        description: "The SMTP server does not support STARTTLS, meaning email communications are transmitted in plaintext.",
        recommendation: "Enable STARTTLS support and configure TLS certificates.",
        cve: null,
        cwe: "CWE-319",
      });
    }
    if (authMethods && !authMethods.includes("PLAIN") && authMethods.length === 0) {
      findings.push({
        category: "authentication",
        severity: "medium",
        title: "No SMTP Authentication Required",
        description: "The SMTP server does not require authentication, potentially allowing unauthorized email sending.",
        recommendation: "Require SMTP authentication (SMTP AUTH) for all outbound email.",
        cve: null,
        cwe: "CWE-306",
      });
    }
    if (banner && /postfix|sendmail|exim|exchange/i.test(banner)) {
      const match = banner.match(/(postfix|sendmail|exim|exchange)[\s\/]*([\d.]+)?/i);
      if (match) {
        findings.push({
          category: "fingerprinting",
          severity: "info",
          title: "SMTP Server Software Identified",
          description: `SMTP server identified as ${match[1]}${match[2] ? ` version ${match[2]}` : ""}. This information aids targeted attacks.`,
          recommendation: "Customize the SMTP banner to remove software version information.",
          cve: null,
          cwe: "CWE-200",
        });
      }
    }
  }

  if (protocol === "snmp") {
    const { validCommunityStrings, snmpVersions, systemInfo } = structuredData;

    if (validCommunityStrings) {
      for (const cs of validCommunityStrings) {
        if (["public", "private", "community", "snmp", "default"].includes(cs.community?.toLowerCase())) {
          findings.push({
            category: "authentication",
            severity: cs.access === "write" ? "critical" : "medium",
            title: `Default SNMP Community String: "${cs.community}" (${cs.access} access)`,
            description: `The default community string "${cs.community}" provides ${cs.access} access to the SNMP agent. ${cs.access === "write" ? "Write access allows device reconfiguration by attackers." : "Read access exposes system information and network topology."}`,
            recommendation: cs.access === "write"
              ? "Immediately change write community strings and restrict SNMP access via ACLs."
              : "Change default community strings and upgrade to SNMPv3 with authentication.",
            cve: null,
            cwe: cs.access === "write" ? "CWE-798" : "CWE-200",
          });
        }
      }
    }
    if (snmpVersions && (snmpVersions.includes("v1") || snmpVersions.includes("1"))) {
      findings.push({
        category: "protocol",
        severity: "medium",
        title: "SNMPv1 Enabled",
        description: "SNMPv1 transmits community strings in plaintext and lacks authentication. It is vulnerable to sniffing and spoofing attacks.",
        recommendation: "Disable SNMPv1 and upgrade to SNMPv3 with HMAC-SHA authentication and AES encryption.",
        cve: null,
        cwe: "CWE-319",
      });
    }
    if (systemInfo?.sysDescr) {
      findings.push({
        category: "fingerprinting",
        severity: "info",
        title: "SNMP System Description Disclosed",
        description: `System description via SNMP: ${systemInfo.sysDescr.slice(0, 200)}`,
        recommendation: "Restrict SNMP access to management networks and limit exposed OIDs.",
        cve: null,
        cwe: "CWE-200",
      });
    }
  }

  if (protocol === "rdp") {
    const { nlaEnabled, encryptionLevel, securityProtocol, blueKeepVulnerable, osVersion } = structuredData;

    if (blueKeepVulnerable) {
      findings.push({
        category: "vulnerability",
        severity: "critical",
        title: "BlueKeep Vulnerability (CVE-2019-0708)",
        description: "The RDP server is vulnerable to BlueKeep, a wormable remote code execution vulnerability that requires no authentication.",
        recommendation: "Apply Microsoft security update KB4499175 immediately and enable NLA.",
        cve: "CVE-2019-0708",
        cwe: "CWE-416",
      });
    }
    if (!nlaEnabled) {
      findings.push({
        category: "authentication",
        severity: "medium",
        title: "Network Level Authentication (NLA) Disabled",
        description: "NLA is not enforced, allowing unauthenticated users to reach the RDP login screen. This increases exposure to pre-authentication attacks.",
        recommendation: "Enable NLA on all RDP servers to require authentication before session establishment.",
        cve: null,
        cwe: "CWE-306",
      });
    }
    if (encryptionLevel && /low|none|client/i.test(encryptionLevel)) {
      findings.push({
        category: "encryption",
        severity: "high",
        title: `Weak RDP Encryption Level: ${encryptionLevel}`,
        description: `RDP encryption level is set to "${encryptionLevel}", which may allow traffic interception or man-in-the-middle attacks.`,
        recommendation: "Set RDP encryption level to 'High' and require TLS for all connections.",
        cve: null,
        cwe: "CWE-326",
      });
    }
    if (securityProtocol && /rdp\b/i.test(securityProtocol) && !/tls|ssl|nla/i.test(securityProtocol)) {
      findings.push({
        category: "protocol",
        severity: "medium",
        title: "RDP Using Legacy Security Protocol",
        description: "The RDP server is using the legacy RDP security protocol instead of TLS/SSL. This provides weaker encryption.",
        recommendation: "Configure RDP to require TLS (SSL) security layer.",
        cve: null,
        cwe: "CWE-327",
      });
    }
  }

  if (protocol === "tls") {
    const { protocols, cipherSuites, certificate, vulnerabilities, compression, secureRenegotiation } = structuredData;

    if (protocols) {
      for (const p of protocols) {
        if (p.supported && /sslv[23]|ssl\s*v[23]/i.test(p.name)) {
          findings.push({
            category: "protocol",
            severity: "high",
            title: `Obsolete Protocol Supported: ${p.name}`,
            description: `${p.name} is supported but has known vulnerabilities (POODLE, DROWN). It should be disabled immediately.`,
            recommendation: `Disable ${p.name} and use TLS 1.2 or 1.3 only.`,
            cve: p.name.includes("3") ? "CVE-2014-3566" : null,
            cwe: "CWE-327",
          });
        }
      }
    }
    if (compression) {
      findings.push({
        category: "configuration",
        severity: "low",
        title: "TLS Compression Enabled",
        description: "TLS compression is enabled, which may be vulnerable to CRIME/BREACH attacks.",
        recommendation: "Disable TLS compression on the server.",
        cve: "CVE-2012-4929",
        cwe: "CWE-310",
      });
    }
    if (secureRenegotiation === false) {
      findings.push({
        category: "configuration",
        severity: "medium",
        title: "Insecure TLS Renegotiation",
        description: "The server does not support secure renegotiation, making it vulnerable to man-in-the-middle attacks during renegotiation.",
        recommendation: "Enable secure renegotiation (RFC 5746) on the server.",
        cve: "CVE-2009-3555",
        cwe: "CWE-310",
      });
    }
  }

  return findings;
}

// ─── Feature Flag: Use Deterministic vs LLM ────────────────────────────────

/**
 * Check whether to use deterministic analysis for a given scanner.
 * This allows gradual rollout via environment variable or database flag.
 *
 * Default: deterministic ON for all Tier 1 scanners
 * Override: set SCANNER_ANALYSIS_MODE=llm to force LLM for all
 * Per-scanner: set SCANNER_ANALYSIS_MODE_NIKTO=llm to force LLM for Nikto only
 */
export function useDeterministicAnalysis(scannerName: string): boolean {
  const globalMode = process.env.SCANNER_ANALYSIS_MODE?.toLowerCase();
  if (globalMode === "llm") return false;
  if (globalMode === "deterministic") return true;

  const perScanner = process.env[`SCANNER_ANALYSIS_MODE_${scannerName.toUpperCase()}`]?.toLowerCase();
  if (perScanner === "llm") return false;
  if (perScanner === "deterministic") return true;

  // Default: use deterministic for Tier 1 scanners
  const TIER_1_SCANNERS = ["nikto", "wapiti", "arachni", "smtp", "snmp", "rdp", "tls"];
  return TIER_1_SCANNERS.includes(scannerName.toLowerCase());
}

// ─── TLS Deterministic Analysis ──────────────────────────────────────────

/**
 * Deterministic replacement for TLS deep scanner LLM analysis.
 * Generates a text summary from structured TLS scan data.
 */
export function analyzeTLSDeterministic(
  protocols: Array<{ name: string; supported: boolean }>,
  cipherSuites: Array<{ name: string; grade: string }>,
  certificate: { subject: string; notAfter: string; selfSigned: boolean; issuer?: string; keySize?: number } | null,
  vulnerabilities: Array<{ name: string; affected: boolean; severity: string }>,
  compression: boolean,
  secureRenegotiation: boolean,
): string {
  const lines: string[] = [];

  // Protocol assessment
  const supportedProtos = protocols.filter(p => p.supported).map(p => p.name);
  const hasLegacy = supportedProtos.some(p => /sslv|tls.*1\.[01]/i.test(p));
  const hasTLS13 = supportedProtos.some(p => /tls.*1\.3/i.test(p));

  if (hasLegacy) {
    lines.push("WARNING: Legacy protocols detected. Disable SSLv2, SSLv3, TLS 1.0, and TLS 1.1 immediately.");
  }
  if (hasTLS13) {
    lines.push("TLS 1.3 is supported — this is the recommended protocol version.");
  } else {
    lines.push("TLS 1.3 is not supported. Consider enabling it for improved security and performance.");
  }

  // Cipher assessment
  const insecureCiphers = cipherSuites.filter(c => c.grade === "insecure");
  const weakCiphers = cipherSuites.filter(c => c.grade === "weak");
  if (insecureCiphers.length > 0) {
    lines.push(`${insecureCiphers.length} insecure cipher suites detected. Remove: ${insecureCiphers.slice(0, 3).map(c => c.name).join(", ")}${insecureCiphers.length > 3 ? "..." : ""}`);
  }
  if (weakCiphers.length > 0) {
    lines.push(`${weakCiphers.length} weak cipher suites should be reviewed for deprecation.`);
  }

  // Certificate assessment
  if (certificate) {
    if (certificate.selfSigned) {
      lines.push("CRITICAL: Self-signed certificate detected. Replace with a certificate from a trusted CA.");
    }
    const expiry = new Date(certificate.notAfter);
    const daysUntilExpiry = Math.floor((expiry.getTime() - Date.now()) / (1000 * 60 * 60 * 24));
    if (daysUntilExpiry < 0) {
      lines.push(`CRITICAL: Certificate expired ${Math.abs(daysUntilExpiry)} days ago. Renew immediately.`);
    } else if (daysUntilExpiry < 30) {
      lines.push(`WARNING: Certificate expires in ${daysUntilExpiry} days. Schedule renewal.`);
    }
    if (certificate.keySize && certificate.keySize < 2048) {
      lines.push(`WARNING: Certificate key size (${certificate.keySize} bits) is below the recommended 2048-bit minimum.`);
    }
  } else {
    lines.push("Certificate information not available for analysis.");
  }

  // Vulnerability summary
  const affectedVulns = vulnerabilities.filter(v => v.affected);
  if (affectedVulns.length > 0) {
    lines.push(`${affectedVulns.length} known vulnerabilities detected: ${affectedVulns.map(v => `${v.name} (${v.severity})`).join(", ")}.`);
  }

  // Compression and renegotiation
  if (compression) {
    lines.push("TLS compression is enabled — vulnerable to CRIME/BREACH attacks. Disable compression.");
  }
  if (!secureRenegotiation) {
    lines.push("Secure renegotiation not supported — vulnerable to CVE-2009-3555. Enable RFC 5746.");
  }

  // Overall grade
  const criticalCount = affectedVulns.filter(v => v.severity === "critical").length + (certificate?.selfSigned ? 1 : 0) + insecureCiphers.length;
  if (criticalCount > 0) {
    lines.push(`\nOverall: POOR — ${criticalCount} critical issues require immediate attention.`);
  } else if (hasLegacy || weakCiphers.length > 2) {
    lines.push("\nOverall: FAIR — legacy protocols or weak ciphers should be addressed.");
  } else {
    lines.push("\nOverall: GOOD — TLS configuration follows current best practices.");
  }

  return lines.join("\n");
}

// ─── Protocol Audit Deterministic Analysis ───────────────────────────────

/**
 * Deterministic replacement for SMTP/SNMP/RDP inline LLM analysis.
 * Wraps generateProtocolFindings with the same interface.
 */
export function analyzeProtocolAuditDeterministic(
  protocol: "smtp" | "snmp" | "rdp",
  structuredData: Record<string, any>,
): Array<{
  category: string;
  severity: string;
  title: string;
  description: string;
  recommendation: string;
  cve: string | null;
  cwe: string | null;
}> {
  return generateProtocolFindings(protocol, structuredData);
}

/**
 * Deterministic replacement for analyzeSqlmapFindings LLM call.
 * Same return type as the LLM version in sqlmap-scanner.ts.
 * Maps SQLMap finding types to risk summaries, exploit chains, and remediation.
 */
export function analyzeSqlmapFindingsDeterministic(
  findings: Array<{
    type: string;
    severity: string;
    title: string;
    description: string;
    url: string;
    parameter?: string;
    payload?: string;
    dbms?: string;
  }>,
  targetUrl: string,
): {
  riskSummary: string;
  exploitChains: string[];
  recommendations: string[];
} {
  const riskSummary = generateRiskSummary(
    findings.map(f => ({
      severity: f.severity,
      description: `${f.title}: ${f.description}`,
    })),
    "SQLMap",
    targetUrl,
  );

  // Build exploit chains from SQLi findings
  const exploitChains: string[] = [];
  const seenChains = new Set<string>();

  for (const f of findings) {
    const typeLower = (f.type || "").toLowerCase();
    const param = f.parameter || "unknown";
    const dbms = f.dbms || "unknown";

    // Union-based SQLi → data exfiltration chain
    if (typeLower.includes("union") && !seenChains.has("union-exfil")) {
      exploitChains.push(
        `Union-based SQLi on '${param}' (${dbms}) → enumerate databases → dump tables → exfiltrate credentials/PII`,
      );
      seenChains.add("union-exfil");
    }

    // Boolean/time-blind SQLi → blind data extraction
    if ((typeLower.includes("blind") || typeLower.includes("boolean") || typeLower.includes("time")) && !seenChains.has("blind-exfil")) {
      exploitChains.push(
        `Blind SQLi on '${param}' → bit-by-bit data extraction → credential harvesting (slower but stealthy)`,
      );
      seenChains.add("blind-exfil");
    }

    // Error-based SQLi → info disclosure + data extraction
    if (typeLower.includes("error") && !seenChains.has("error-exfil")) {
      exploitChains.push(
        `Error-based SQLi on '${param}' → database version/schema disclosure → targeted data extraction`,
      );
      seenChains.add("error-exfil");
    }

    // Stacked queries → RCE potential
    if (typeLower.includes("stacked") && !seenChains.has("stacked-rce")) {
      exploitChains.push(
        `Stacked queries on '${param}' (${dbms}) → INSERT/UPDATE/DELETE arbitrary data → potential OS command execution via xp_cmdshell/sys_exec`,
      );
      seenChains.add("stacked-rce");
    }

    // Auth bypass
    if ((typeLower.includes("auth") || f.title.toLowerCase().includes("login") || f.title.toLowerCase().includes("auth")) && !seenChains.has("auth-bypass")) {
      exploitChains.push(
        `SQLi on authentication parameter '${param}' → bypass login → admin access → full application compromise`,
      );
      seenChains.add("auth-bypass");
    }
  }

  // If we found injectable params but no specific chains, add generic ones
  if (exploitChains.length === 0 && findings.length > 0) {
    exploitChains.push(
      `SQL injection detected on ${targetUrl} → database enumeration → credential/data exfiltration`,
    );
  }

  // Build remediation recommendations
  const recommendations = [
    "Use parameterized queries (prepared statements) for all database interactions — never concatenate user input into SQL strings",
    "Implement input validation with strict allowlists for expected data types, lengths, and character sets",
    "Apply the principle of least privilege to database accounts — web app DB users should not have DBA/admin rights",
    "Deploy a Web Application Firewall (WAF) with SQL injection rule sets as a defense-in-depth measure",
    "Enable database query logging and monitoring to detect exploitation attempts in real-time",
  ];

  // Add DBMS-specific recommendations
  const dbmsTypes = new Set(findings.map(f => (f.dbms || "").toLowerCase()).filter(Boolean));
  if (dbmsTypes.has("mysql") || dbmsTypes.has("mariadb")) {
    recommendations.push("MySQL: Disable FILE privilege and LOAD_FILE() for web application database users");
  }
  if (dbmsTypes.has("mssql") || dbmsTypes.has("microsoft sql server")) {
    recommendations.push("MSSQL: Disable xp_cmdshell and remove sysadmin role from application accounts");
  }
  if (dbmsTypes.has("postgresql")) {
    recommendations.push("PostgreSQL: Restrict COPY command access and disable lo_import/lo_export for web users");
  }

  return { riskSummary, exploitChains, recommendations: recommendations.slice(0, 8) };
}
