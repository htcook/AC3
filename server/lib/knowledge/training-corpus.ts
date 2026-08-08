/**
 * Training Corpus Module
 * 
 * Generates structured training data from tool outputs and scan results.
 * Uses the public demo sites from the pentest training bundle as reference
 * targets for building annotated examples.
 * 
 * The corpus is designed for RAG integration — each entry pairs a tool output
 * with the expected LLM triage response (hypotheses, next steps, severity).
 */

import { readFileSync } from "fs";
import { join, dirname } from "path";
import { fileURLToPath } from "url";

const KNOWLEDGE_DIR = dirname(fileURLToPath(import.meta.url));

// ─── Types ───────────────────────────────────────────────────────────────────

export interface CorpusEntry {
  id: string;
  tool: string;
  target: string;
  target_type: string;
  raw_output_snippet: string;
  parsed_findings: Array<{
    severity: string;
    title: string;
    cve?: string;
  }>;
  expected_triage: {
    hypotheses: string[];
    next_tests: string[];
    priority: "critical" | "high" | "medium" | "low" | "info";
    reasoning: string;
  };
  owasp_categories: string[];
  mitre_techniques: string[];
  tags: string[];
}

export interface DemoSite {
  host: string;
  name: string;
  purpose: string;
  reference: string;
}

// ─── Demo Sites ──────────────────────────────────────────────────────────────

const DEMO_SITES: DemoSite[] = [
  {
    host: "testphp.vulnweb.com",
    name: "Acunetix VulnWeb (PHP)",
    purpose: "Intentionally vulnerable PHP app for scanner testing",
    reference: "https://www.vulnweb.com/",
  },
  {
    host: "testasp.vulnweb.com",
    name: "Acunetix VulnWeb (ASP)",
    purpose: "Intentionally vulnerable ASP/IIS app for scanner testing",
    reference: "https://www.vulnweb.com/",
  },
  {
    host: "testhtml5.vulnweb.com",
    name: "Acunetix VulnWeb (HTML5)",
    purpose: "Intentionally vulnerable HTML5/Flask app for scanner testing",
    reference: "https://www.vulnweb.com/",
  },
  {
    host: "demo.testfire.net",
    name: "Altoro Mutual",
    purpose: "Deliberately vulnerable demo banking site (HCL/IBM AppScan)",
    reference: "https://support.hcl-software.com/csm?id=kb_article&sysparm_article=KB0010981",
  },
  {
    host: "zero.webappsecurity.com",
    name: "OWASP BWA Demo",
    purpose: "Intentionally vulnerable demo banking site (Broken Web Apps)",
    reference: "https://sourceforge.net/projects/owaspbwa/",
  },
];

// ─── Pre-built corpus entries ────────────────────────────────────────────────
// These are annotated examples of what tool outputs look like against known
// vulnerable targets, paired with the expected LLM triage response.

const PREBUILT_CORPUS: CorpusEntry[] = [
  // ─── Nuclei findings on PHP vulnweb ─────────────────────────────────────
  {
    id: "CORPUS-NUCLEI-PHP-001",
    tool: "nuclei",
    target: "testphp.vulnweb.com",
    target_type: "web_application",
    raw_output_snippet: `{"template-id":"CVE-2023-XXXX","info":{"name":"PHP Info Disclosure","severity":"medium"},"matched-at":"http://testphp.vulnweb.com/phpinfo.php"}`,
    parsed_findings: [
      { severity: "medium", title: "[Nuclei] PHP Info Disclosure @ http://testphp.vulnweb.com/phpinfo.php" },
    ],
    expected_triage: {
      hypotheses: [
        "PHP info page exposes server configuration, installed modules, and environment variables",
        "May reveal internal paths, database connection strings, or API keys",
        "Indicates weak server hardening — other misconfigurations likely present",
      ],
      next_tests: [
        "Check for other common info disclosure paths (/server-status, /server-info, /.env)",
        "Run directory brute-force (ffuf/feroxbuster) to find additional exposed files",
        "Check PHP version for known CVEs",
        "Test for local file inclusion via PHP wrappers",
      ],
      priority: "medium",
      reasoning: "PHP info disclosure is a medium-severity finding that provides reconnaissance value. It's not directly exploitable but reveals attack surface details that inform subsequent testing phases.",
    },
    owasp_categories: ["Security Misconfiguration"],
    mitre_techniques: ["T1592"],
    tags: ["info_disclosure", "php", "server_hardening"],
  },
  // ─── Nikto findings on banking demo ─────────────────────────────────────
  {
    id: "CORPUS-NIKTO-BANK-001",
    tool: "nikto",
    target: "demo.testfire.net",
    target_type: "web_application",
    raw_output_snippet: `+ The anti-clickjacking X-Frame-Options header is not present.\n+ The X-Content-Type-Options header is not set.\n+ Cookie JSESSIONID created without the httponly flag\n+ OSVDB-3092: /admin/: This might be interesting...\n+ OSVDB-3233: /icons/README: Apache default file found.`,
    parsed_findings: [
      { severity: "low", title: "[Nikto] The anti-clickjacking X-Frame-Options header is not present." },
      { severity: "low", title: "[Nikto] The X-Content-Type-Options header is not set." },
      { severity: "medium", title: "[Nikto] Cookie JSESSIONID created without the httponly flag" },
      { severity: "medium", title: "[Nikto] /admin/: This might be interesting..." },
      { severity: "low", title: "[Nikto] Apache default file found." },
    ],
    expected_triage: {
      hypotheses: [
        "Missing security headers indicate weak hardening — clickjacking and MIME-sniffing attacks possible",
        "HttpOnly flag missing on session cookie — XSS could lead to session hijacking",
        "Admin interface exposed — test for default credentials and access control bypass",
        "Apache default files present — server not properly cleaned after deployment",
      ],
      next_tests: [
        "Test /admin/ for default credentials (admin/admin, admin/password)",
        "Test for XSS on input fields — if found, session cookie is stealable",
        "Run feroxbuster/ffuf against /admin/ for deeper directory enumeration",
        "Check all cookies for Secure and SameSite attributes",
        "Test X-Frame-Options absence with clickjacking PoC",
      ],
      priority: "medium",
      reasoning: "The combination of missing security headers, exposed admin interface, and insecure cookie flags suggests a poorly hardened application. The admin interface is the highest-priority finding — if accessible, it could lead to full application compromise.",
    },
    owasp_categories: ["Security Misconfiguration", "Broken Access Control"],
    mitre_techniques: ["T1190", "T1078"],
    tags: ["headers", "cookies", "admin_exposure", "hardening"],
  },
  // ─── SQLMap findings ────────────────────────────────────────────────────
  {
    id: "CORPUS-SQLMAP-PHP-001",
    tool: "sqlmap",
    target: "testphp.vulnweb.com",
    target_type: "web_application",
    raw_output_snippet: `[INFO] Parameter 'id' is vulnerable. Do you want to keep testing the others?\nback-end DBMS: MySQL >= 5.0\n[INFO] retrieved: acuart\navailable databases [2]:\n[*] acuart\n[*] information_schema`,
    parsed_findings: [
      { severity: "critical", title: "[sqlmap] SQL Injection Confirmed: Parameter 'id' is vulnerable" },
      { severity: "high", title: "[sqlmap] back-end DBMS: MySQL >= 5.0" },
      { severity: "critical", title: "[sqlmap] Database Enumerated: available databases [2]" },
    ],
    expected_triage: {
      hypotheses: [
        "Confirmed SQL injection — full database access achieved",
        "MySQL 5.0+ supports UNION, stacked queries, and file operations",
        "Potential for data exfiltration, authentication bypass, and possibly OS command execution",
        "Other parameters on the same application likely share the same vulnerability pattern",
      ],
      next_tests: [
        "Enumerate tables and columns in the 'acuart' database",
        "Check for --os-shell capability (MySQL FILE privilege)",
        "Test other parameters on the same endpoint for additional injection points",
        "Check if the database user has DBA privileges",
        "Attempt to read sensitive files (/etc/passwd, application config)",
      ],
      priority: "critical",
      reasoning: "Confirmed SQL injection with database enumeration is a critical finding. The attacker has full read access to the database and potentially write access. This should be the top priority for exploitation and reporting.",
    },
    owasp_categories: ["Injection"],
    mitre_techniques: ["T1190", "T1505"],
    tags: ["sqli", "mysql", "database", "data_exfiltration"],
  },
  // ─── ScanForge Discovery service scan ──────────────────────────────────────────────────
  {
    id: "CORPUS-SCANFORGE-INFRA-001",
    tool: "scanforge-discovery",
    target: "testphp.vulnweb.com",
    target_type: "infrastructure",
    raw_output_snippet: `22/tcp   open  ssh     OpenSSH 8.2p1\n80/tcp   open  http    nginx 1.19.0\n443/tcp  open  https   nginx 1.19.0\n3306/tcp open  mysql   MySQL 5.7.33\n8080/tcp open  http    Apache Tomcat 9.0.41`,
    parsed_findings: [
      { severity: "info", title: "[ScanForge] 22/tcp ssh OpenSSH 8.2p1" },
      { severity: "info", title: "[ScanForge] 80/tcp http nginx 1.19.0" },
      { severity: "info", title: "[ScanForge] 443/tcp https nginx 1.19.0" },
      { severity: "info", title: "[ScanForge] 3306/tcp mysql MySQL 5.7.33" },
      { severity: "info", title: "[ScanForge] 8080/tcp http Apache Tomcat 9.0.41" },
    ],
    expected_triage: {
      hypotheses: [
        "MySQL port (3306) exposed to internet — test for default credentials and remote access",
        "Apache Tomcat 9.0.41 on 8080 — check for manager interface and known CVEs",
        "nginx 1.19.0 — check for known vulnerabilities and misconfigurations",
        "Multiple web services suggest complex architecture — potential for SSRF between services",
      ],
      next_tests: [
        "Test MySQL 3306 for remote authentication (default creds, anonymous access)",
        "Check Tomcat /manager/html for default credentials (tomcat/tomcat)",
        "Run nuclei against all HTTP ports for known CVEs",
        "Check nginx for path traversal and alias misconfiguration",
        "Run testssl.sh against 443 for TLS configuration issues",
      ],
      priority: "high",
      reasoning: "Exposed MySQL port is the highest-risk finding — database services should never be internet-facing. Tomcat manager interface is the second priority. The combination of multiple services increases the attack surface significantly.",
    },
    owasp_categories: ["Security Misconfiguration"],
    mitre_techniques: ["T1046", "T1190", "T1078"],
    tags: ["port_scan", "mysql_exposed", "tomcat", "service_enumeration"],
  },
  // ─── ffuf directory discovery ───────────────────────────────────────────
  {
    id: "CORPUS-FFUF-WEB-001",
    tool: "ffuf",
    target: "demo.testfire.net",
    target_type: "web_application",
    raw_output_snippet: `{"results":[{"url":"http://demo.testfire.net/admin/","status":200,"length":4521},{"url":"http://demo.testfire.net/api/","status":301,"length":0},{"url":"http://demo.testfire.net/backup/","status":403,"length":287},{"url":"http://demo.testfire.net/.git/","status":200,"length":1234}]}`,
    parsed_findings: [
      { severity: "info", title: "[ffuf] http://demo.testfire.net/admin/ (200, 4521B)" },
      { severity: "info", title: "[ffuf] http://demo.testfire.net/api/ (301, 0B)" },
      { severity: "info", title: "[ffuf] http://demo.testfire.net/backup/ (403, 287B)" },
      { severity: "info", title: "[ffuf] http://demo.testfire.net/.git/ (200, 1234B)" },
    ],
    expected_triage: {
      hypotheses: [
        "Exposed .git directory — full source code and commit history may be downloadable",
        "Admin interface accessible (200) — test for authentication bypass or default credentials",
        "Backup directory exists (403) — may be accessible via path traversal or alternate methods",
        "API endpoint discovered — test for authentication requirements and parameter fuzzing",
      ],
      next_tests: [
        "Download .git directory using git-dumper and analyze source code for secrets",
        "Test /admin/ for default credentials and authentication bypass",
        "Attempt to access /backup/ files directly (backup.zip, backup.sql, db.sql)",
        "Enumerate /api/ endpoints and test for IDOR, injection, and auth bypass",
        "Run trufflehog on downloaded .git repository for leaked secrets",
      ],
      priority: "critical",
      reasoning: "Exposed .git directory is critical — it typically contains full source code, configuration files, and potentially hardcoded credentials. This should be exploited immediately as it provides a massive information advantage for subsequent testing.",
    },
    owasp_categories: ["Security Misconfiguration", "Broken Access Control"],
    mitre_techniques: ["T1213", "T1190", "T1552"],
    tags: ["directory_discovery", "git_exposure", "admin_panel", "backup_files"],
  },
  // ─── WhatWeb technology fingerprinting ──────────────────────────────────
  {
    id: "CORPUS-WHATWEB-TECH-001",
    tool: "whatweb",
    target: "testphp.vulnweb.com",
    target_type: "web_application",
    raw_output_snippet: `http://testphp.vulnweb.com [200 OK] Apache[2.4.41], Country[UNITED STATES], HTML5, HTTPServer[Ubuntu Linux][Apache/2.4.41 (Ubuntu)], IP[44.228.249.3], JQuery[1.4.2], PHP[5.6.40], Script, Title[Home of Acunetix Art], X-Powered-By[PHP/5.6.40]`,
    parsed_findings: [
      { severity: "info", title: "[whatweb] Apache/2.4.41 @ http://testphp.vulnweb.com" },
      { severity: "info", title: "[whatweb] PHP/5.6.40 @ http://testphp.vulnweb.com" },
      { severity: "info", title: "[whatweb] JQuery/1.4.2 @ http://testphp.vulnweb.com" },
    ],
    expected_triage: {
      hypotheses: [
        "PHP 5.6.40 is EOL since Dec 2018 — multiple known CVEs and no security patches",
        "jQuery 1.4.2 is severely outdated — known XSS vulnerabilities in older jQuery versions",
        "Apache 2.4.41 may have known vulnerabilities depending on modules loaded",
        "X-Powered-By header leaks PHP version — information disclosure",
      ],
      next_tests: [
        "Search for PHP 5.6.40 CVEs and test applicable ones with nuclei",
        "Test for jQuery XSS via DOM-based vectors",
        "Check for PHP-specific vulnerabilities (type juggling, deserialization, file inclusion)",
        "Run nuclei with -tags php,apache,jquery for targeted vulnerability scanning",
        "Test for PHP info disclosure (/phpinfo.php, /info.php)",
      ],
      priority: "high",
      reasoning: "EOL PHP version is a high-priority finding because it guarantees unpatched vulnerabilities. Combined with outdated jQuery, this application has a large known-vulnerability surface. Technology fingerprinting results should directly inform the nuclei template selection.",
    },
    owasp_categories: ["Vulnerable and Outdated Components"],
    mitre_techniques: ["T1592", "T1190"],
    tags: ["technology_fingerprint", "eol_software", "outdated_components"],
  },
  // ─── testssl TLS analysis ───────────────────────────────────────────────
  {
    id: "CORPUS-TESTSSL-TLS-001",
    tool: "testssl",
    target: "demo.testfire.net",
    target_type: "infrastructure",
    raw_output_snippet: `Testing protocols via sockets\n TLS 1      offered (deprecated)\n TLS 1.1    offered (deprecated)\n TLS 1.2    offered (OK)\n TLS 1.3    not offered\n\nTesting vulnerabilities\n Heartbleed (CVE-2014-0160)    not vulnerable (OK)\n POODLE, SSL (CVE-2014-3566)   VULNERABLE -- usesass SSL v3\n ROBOT                         not vulnerable (OK)\n\nTesting cipher categories\n NULL ciphers                  not offered (OK)\n Export ciphers                not offered (OK)\n RC4 ciphers                   VULNERABLE -- offered`,
    parsed_findings: [
      { severity: "critical", title: "[testssl] POODLE, SSL (CVE-2014-3566) VULNERABLE", cve: "CVE-2014-3566" },
      { severity: "high", title: "[testssl] RC4 ciphers VULNERABLE" },
      { severity: "medium", title: "[testssl] TLS configuration issues" },
    ],
    expected_triage: {
      hypotheses: [
        "POODLE vulnerability allows decryption of TLS traffic via SSLv3 downgrade attack",
        "RC4 cipher support enables known plaintext attacks on encrypted communications",
        "Deprecated TLS 1.0/1.1 support increases attack surface for protocol downgrade attacks",
        "Missing TLS 1.3 indicates outdated TLS stack — may have other crypto weaknesses",
      ],
      next_tests: [
        "Verify POODLE exploitability with targeted SSLv3 connection attempt",
        "Check if HSTS is configured to prevent protocol downgrade",
        "Test for certificate issues (expiry, self-signed, wrong CN)",
        "Check for client certificate authentication bypass",
        "Verify if the application handles TLS termination or if it's at a load balancer",
      ],
      priority: "high",
      reasoning: "POODLE and RC4 vulnerabilities are well-understood crypto weaknesses. While exploitation requires MITM positioning, they represent compliance failures and indicate an outdated TLS configuration. The missing TLS 1.3 and deprecated protocol support compound the risk.",
    },
    owasp_categories: ["Cryptographic Failures"],
    mitre_techniques: ["T1557", "T1040"],
    tags: ["tls", "poodle", "rc4", "crypto", "ssl"],
  },
  // ─── WPScan WordPress analysis ──────────────────────────────────────────
  {
    id: "CORPUS-WPSCAN-WP-001",
    tool: "wpscan",
    target: "example-wordpress.com",
    target_type: "web_application",
    raw_output_snippet: `[+] WordPress version 5.8.1 identified (Insecure, released on 2021-09-09)\n[!] 12 vulnerabilities identified\n[+] WordPress theme in use: flavor\n[!] The WordPress 'flavor' theme (v 1.0) is out of date\n[+] Enumerating Users\n[i] User(s) Identified:\n[+] admin\n[+] editor`,
    parsed_findings: [
      { severity: "medium", title: "[wpscan] [+] WordPress version 5.8.1 identified (Insecure, released on 2021-09-09)" },
      { severity: "high", title: "[wpscan] [!] 12 vulnerabilities identified" },
      { severity: "medium", title: "[wpscan] [!] The WordPress 'flavor' theme (v 1.0) is out of date" },
    ],
    expected_triage: {
      hypotheses: [
        "Outdated WordPress 5.8.1 has 12 known vulnerabilities — likely includes auth bypass and XSS",
        "Outdated theme may have its own vulnerabilities (XSS, file upload, LFI)",
        "User enumeration successful — 'admin' account exists for brute-force targeting",
        "Default WordPress login at /wp-login.php likely accessible",
      ],
      next_tests: [
        "Run wpscan with --enumerate vp to list vulnerable plugins",
        "Test /wp-login.php with common admin passwords",
        "Check for XML-RPC brute-force via /xmlrpc.php",
        "Test the 'flavor' theme for known vulnerabilities",
        "Check for wp-config.php backup files (.bak, .old, ~)",
        "Run nuclei with -tags wordpress for comprehensive CVE testing",
      ],
      priority: "high",
      reasoning: "Outdated WordPress with 12 known vulnerabilities and user enumeration is a high-priority finding. The 'admin' user combined with potential XML-RPC brute-force makes credential attacks viable. Plugin enumeration should be the immediate next step as plugins are the most common WordPress attack vector.",
    },
    owasp_categories: ["Vulnerable and Outdated Components", "Identification and Authentication Failures"],
    mitre_techniques: ["T1190", "T1078", "T1110"],
    tags: ["wordpress", "outdated_cms", "user_enumeration", "brute_force"],
  },
];

// ─── Public API ──────────────────────────────────────────────────────────────

/**
 * Get corpus entries relevant to a specific tool.
 */
export function getCorpusForTool(tool: string): CorpusEntry[] {
  return PREBUILT_CORPUS.filter((e) => e.tool === tool);
}

/**
 * Get corpus entries relevant to specific OWASP categories.
 */
export function getCorpusForOwasp(categories: string[]): CorpusEntry[] {
  const lowerCats = categories.map((c) => c.toLowerCase());
  return PREBUILT_CORPUS.filter((e) =>
    e.owasp_categories.some((oc) => lowerCats.includes(oc.toLowerCase()))
  );
}

/**
 * Get all corpus entries as LLM context for scan triage.
 * Returns a formatted string suitable for injection into system prompts.
 */
export function getTriageCorpusContext(
  toolFilter?: string,
  maxEntries: number = 4
): string {
  let entries = toolFilter
    ? PREBUILT_CORPUS.filter((e) => e.tool === toolFilter)
    : PREBUILT_CORPUS;

  entries = entries.slice(0, maxEntries);

  if (entries.length === 0) return "";

  const formatted = entries
    .map(
      (e) =>
        `### ${e.id} (${e.tool} → ${e.target})
**Findings:** ${e.parsed_findings.map((f) => `${f.severity}: ${f.title}`).join("; ")}
**Triage Priority:** ${e.expected_triage.priority}
**Hypotheses:** ${e.expected_triage.hypotheses.join("; ")}
**Next Tests:** ${e.expected_triage.next_tests.slice(0, 3).join("; ")}
**Reasoning:** ${e.expected_triage.reasoning}`
    )
    .join("\n\n");

  return `## Scan Triage Training Examples
The following are annotated examples of how to triage tool outputs. Use these as reference for your analysis:

${formatted}`;
}

/**
 * Get demo sites list for reference.
 */
export function getDemoSites(): DemoSite[] {
  return DEMO_SITES;
}

/**
 * Get the full corpus for export/persistence.
 */
export function getFullCorpus(): CorpusEntry[] {
  return [...PREBUILT_CORPUS];
}
