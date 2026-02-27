/**
 * ZAP Attack Playbook System
 *
 * Provides the LLM with structured knowledge about every ZAP active scan
 * rule, mapped to the technologies they target, so the orchestrator can
 * dial ZAP sessions into the discovered tech stack on each target.
 *
 * Playbook categories:
 *   1. Technology Fingerprinting & WAF Detection
 *   2. Site Crawling & Spidering (AJAX, auth, deep)
 *   3. Secrets & Credential Discovery
 *   4. Injection Testing (SQLi, XSS, SSTI, OS Cmd, XXE, LDAP, NoSQL)
 *   5. Authentication & Session Attacks
 *   6. Backend Infrastructure Enumeration (S3, APIs, cloud metadata)
 *   7. API Security Testing (REST, GraphQL, SOAP)
 *   8. Server-Side Exploitation (SSRF, LFI/RFI, RCE, deserialization)
 *   9. Foothold Acquisition (chaining findings → MSF/C2 handoff)
 *
 * Each playbook produces a ZapPlaybookConfig that the orchestrator
 * applies via the ZAP API before launching the active scan.
 *
 * Author: Harrison Cook — AceofCloud
 */

// ─── ZAP Scan Rule Registry ────────────────────────────────────────────────
// Every active scan rule ID mapped to its name, category, and target technologies.

export interface ZapScanRule {
  id: number;
  name: string;
  category: ZapRuleCategory;
  /** Technologies this rule is most effective against. Empty = universal. */
  technologies: string[];
  /** ZAP threshold: OFF, LOW, MEDIUM, HIGH */
  defaultThreshold: "OFF" | "LOW" | "MEDIUM" | "HIGH";
  /** ZAP strength: LOW, MEDIUM, HIGH, INSANE */
  defaultStrength: "LOW" | "MEDIUM" | "HIGH" | "INSANE";
  /** Whether this rule can help establish a foothold (RCE, file upload, etc.) */
  footholdCapable: boolean;
  /** Whether this rule discovers secrets/credentials */
  secretsDiscovery: boolean;
  /** CWE ID for correlation */
  cweId?: number;
  /** Metasploit modules that can exploit findings from this rule */
  msfModules?: string[];
  /** MITRE ATT&CK technique ID */
  mitreId?: string;
  /** Estimated scan time impact: low/medium/high */
  timeImpact: "low" | "medium" | "high";
}

export type ZapRuleCategory =
  | "injection"
  | "xss"
  | "auth"
  | "info_disclosure"
  | "config"
  | "rce"
  | "file_inclusion"
  | "ssrf"
  | "deserialization"
  | "crypto"
  | "session"
  | "header"
  | "api"
  | "cve"
  | "misc";

// ─── Complete ZAP Active Scan Rule Registry ─────────────────────────────────
// Release + Beta + Alpha rules with technology targeting

export const ZAP_SCAN_RULES: ZapScanRule[] = [
  // ── Secrets & Credential Discovery ──────────────────────────────────────
  {
    id: 40034, name: ".env Information Leak", category: "info_disclosure",
    technologies: ["Node.js", "Laravel", "Django", "Flask", "Ruby on Rails", "PHP"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: true,
    cweId: 215, mitreId: "T1552",
    timeImpact: "low",
  },
  {
    id: 40032, name: ".htaccess Information Leak", category: "info_disclosure",
    technologies: ["Apache", "PHP", "WordPress", "Drupal", "Joomla"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: true,
    cweId: 215, mitreId: "T1552",
    timeImpact: "low",
  },
  {
    id: 40035, name: "Hidden File Finder", category: "info_disclosure",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: true,
    cweId: 538, mitreId: "T1083",
    timeImpact: "medium",
  },
  {
    id: 10095, name: "Backup File Disclosure", category: "info_disclosure",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: true,
    cweId: 530, mitreId: "T1552",
    timeImpact: "medium",
  },
  {
    id: 0, name: "Directory Browsing", category: "info_disclosure",
    technologies: ["Apache", "IIS", "Nginx"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: true,
    cweId: 548, mitreId: "T1083",
    timeImpact: "low",
  },
  {
    id: 42, name: "Source Code Disclosure - SVN", category: "info_disclosure",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: true,
    cweId: 541, mitreId: "T1552",
    timeImpact: "medium",
  },
  {
    id: 41, name: "Source Code Disclosure - Git", category: "info_disclosure",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: true,
    cweId: 541, mitreId: "T1552",
    timeImpact: "medium",
  },
  {
    id: 43, name: "Source Code Disclosure - File Inclusion", category: "file_inclusion",
    technologies: ["PHP", "Java", "ASP.NET"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: true,
    cweId: 541, mitreId: "T1005",
    timeImpact: "medium",
  },
  {
    id: 10045, name: "Source Code Disclosure - /WEB-INF", category: "info_disclosure",
    technologies: ["Java", "Spring", "Tomcat", "JBoss", "WebLogic", "WebSphere"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: true,
    cweId: 541, mitreId: "T1552",
    timeImpact: "medium",
  },
  {
    id: 40028, name: "ELMAH Information Leak", category: "info_disclosure",
    technologies: ["ASP.NET", "IIS"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: true,
    cweId: 215, mitreId: "T1552",
    timeImpact: "low",
  },
  {
    id: 40029, name: "Trace.axd Information Leak", category: "info_disclosure",
    technologies: ["ASP.NET", "IIS"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: true,
    cweId: 215, mitreId: "T1552",
    timeImpact: "low",
  },

  // ── Cloud & Infrastructure Discovery ────────────────────────────────────
  {
    id: 90034, name: "Cloud Metadata Attack", category: "ssrf",
    technologies: ["AWS", "GCP", "Azure", "Alibaba Cloud", "Nginx"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: true,
    cweId: 918, mitreId: "T1552.005",
    msfModules: ["post/multi/gather/aws_keys", "auxiliary/cloud/aws/enum_iam"],
    timeImpact: "low",
  },
  {
    id: 40042, name: "Spring Actuator Information Leak", category: "info_disclosure",
    technologies: ["Spring Boot", "Java", "Spring"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: true,
    cweId: 215, mitreId: "T1552",
    timeImpact: "low",
  },
  {
    id: 10048, name: "Spring Actuator Detailed Info", category: "info_disclosure",
    technologies: ["Spring Boot", "Java", "Spring"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: true,
    cweId: 215, mitreId: "T1552",
    timeImpact: "low",
  },

  // ── Injection Attacks ───────────────────────────────────────────────────
  {
    id: 40018, name: "SQL Injection", category: "injection",
    technologies: [],  // universal — any app with a database
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: true,
    cweId: 89, mitreId: "T1190",
    msfModules: ["exploit/multi/http/sqli_generic", "auxiliary/sqli/oracle/dbms_xmlquery_getxml"],
    timeImpact: "high",
  },
  {
    id: 40019, name: "SQL Injection - MySQL (Time Based)", category: "injection",
    technologies: ["MySQL", "MariaDB", "PHP", "WordPress", "Drupal", "Laravel"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: true,
    cweId: 89, mitreId: "T1190",
    msfModules: ["exploit/multi/http/sqli_generic"],
    timeImpact: "high",
  },
  {
    id: 40020, name: "SQL Injection - Hypersonic (Time Based)", category: "injection",
    technologies: ["Java", "HSQLDB", "Spring"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: true,
    cweId: 89, mitreId: "T1190",
    timeImpact: "high",
  },
  {
    id: 40021, name: "SQL Injection - Oracle (Time Based)", category: "injection",
    technologies: ["Oracle", "Java", "PL/SQL"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: true,
    cweId: 89, mitreId: "T1190",
    msfModules: ["auxiliary/sqli/oracle/dbms_xmlquery_getxml"],
    timeImpact: "high",
  },
  {
    id: 40022, name: "SQL Injection - PostgreSQL (Time Based)", category: "injection",
    technologies: ["PostgreSQL", "Django", "Ruby on Rails", "Node.js"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: true,
    cweId: 89, mitreId: "T1190",
    timeImpact: "high",
  },
  {
    id: 40027, name: "SQL Injection - MsSQL (Time Based)", category: "injection",
    technologies: ["MSSQL", "ASP.NET", "IIS", ".NET"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: true,
    cweId: 89, mitreId: "T1190",
    msfModules: ["exploit/windows/mssql/mssql_payload"],
    timeImpact: "high",
  },
  {
    id: 40033, name: "NoSQL Injection - MongoDB", category: "injection",
    technologies: ["MongoDB", "Node.js", "Express.js", "MEAN", "MERN"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: true,
    cweId: 943, mitreId: "T1190",
    timeImpact: "medium",
  },
  {
    id: 90039, name: "NoSQL Injection - MongoDB (Time Based)", category: "injection",
    technologies: ["MongoDB", "Node.js", "Express.js"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: true,
    cweId: 943, mitreId: "T1190",
    timeImpact: "high",
  },
  {
    id: 90019, name: "Code Injection (PHP/ASP)", category: "rce",
    technologies: ["PHP", "ASP", "ASP.NET"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: false,
    cweId: 94, mitreId: "T1059",
    msfModules: ["exploit/unix/webapp/php_eval", "exploit/multi/http/php_cgi_arg_injection"],
    timeImpact: "medium",
  },
  {
    id: 90020, name: "Remote OS Command Injection", category: "rce",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: false,
    cweId: 78, mitreId: "T1059",
    msfModules: ["exploit/multi/http/oscommand_generic"],
    timeImpact: "medium",
  },
  {
    id: 90037, name: "Remote OS Command Injection (Time Based)", category: "rce",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "HIGH",
    footholdCapable: true, secretsDiscovery: false,
    cweId: 78, mitreId: "T1059",
    msfModules: ["exploit/multi/http/oscommand_generic"],
    timeImpact: "high",
  },
  {
    id: 90035, name: "Server Side Template Injection (SSTI)", category: "rce",
    technologies: ["Jinja2", "Django", "Flask", "Twig", "PHP", "Freemarker", "Java", "Thymeleaf", "Pebble", "ERB", "Ruby on Rails", "Handlebars", "Node.js", "Mako", "Python"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: false,
    cweId: 1336, mitreId: "T1059",
    timeImpact: "medium",
  },
  {
    id: 90036, name: "Server Side Template Injection (Blind/OAST)", category: "rce",
    technologies: ["Jinja2", "Django", "Flask", "Twig", "PHP", "Freemarker", "Java", "Thymeleaf", "ERB", "Ruby on Rails"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: false,
    cweId: 1336, mitreId: "T1059",
    timeImpact: "medium",
  },
  {
    id: 90025, name: "Expression Language Injection", category: "rce",
    technologies: ["Java", "Spring", "JSP", "JSF", "Struts"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: false,
    cweId: 917, mitreId: "T1059",
    timeImpact: "medium",
  },
  {
    id: 90017, name: "XML External Entity (XXE)", category: "injection",
    technologies: ["Java", "PHP", ".NET", "ASP.NET"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: true,
    cweId: 611, mitreId: "T1190",
    msfModules: ["exploit/multi/http/xxe_generic", "auxiliary/scanner/http/xxe"],
    timeImpact: "medium",
  },
  {
    id: 90023, name: "XML External Entity (XXE, OAST)", category: "injection",
    technologies: ["Java", "PHP", ".NET", "ASP.NET"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: true,
    cweId: 611, mitreId: "T1190",
    timeImpact: "medium",
  },
  {
    id: 90021, name: "XPath Injection", category: "injection",
    technologies: ["Java", "PHP", ".NET", "XML"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: true,
    cweId: 643, mitreId: "T1190",
    timeImpact: "medium",
  },

  // ── XSS ─────────────────────────────────────────────────────────────────
  {
    id: 40012, name: "Cross Site Scripting (Reflected)", category: "xss",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: false,
    cweId: 79, mitreId: "T1189",
    timeImpact: "medium",
  },
  {
    id: 40014, name: "Cross Site Scripting (Persistent)", category: "xss",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: false,
    cweId: 79, mitreId: "T1189",
    timeImpact: "high",
  },
  {
    id: 40031, name: "Out of Band XSS", category: "xss",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: false,
    cweId: 79, mitreId: "T1189",
    timeImpact: "medium",
  },

  // ── File Inclusion & Path Traversal ─────────────────────────────────────
  {
    id: 6, name: "Path Traversal", category: "file_inclusion",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: true,
    cweId: 22, mitreId: "T1005",
    msfModules: ["exploit/multi/http/lfi_generic", "auxiliary/scanner/http/dir_traversal"],
    timeImpact: "medium",
  },
  {
    id: 7, name: "Remote File Inclusion", category: "file_inclusion",
    technologies: ["PHP"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: false,
    cweId: 98, mitreId: "T1190",
    msfModules: ["exploit/multi/http/rfi_generic", "exploit/unix/webapp/php_include"],
    timeImpact: "medium",
  },

  // ── SSRF ────────────────────────────────────────────────────────────────
  {
    id: 40046, name: "Server Side Request Forgery (SSRF)", category: "ssrf",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: true,
    cweId: 918, mitreId: "T1090",
    msfModules: ["auxiliary/scanner/http/ssrf_detector"],
    timeImpact: "medium",
  },

  // ── CVE-Specific Exploits ───────────────────────────────────────────────
  {
    id: 40043, name: "Log4Shell (CVE-2021-44228)", category: "cve",
    technologies: ["Java", "Spring", "Tomcat", "JBoss", "WebLogic", "Elasticsearch", "Solr", "Kafka", "Struts"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: false,
    cweId: 917, mitreId: "T1190",
    msfModules: ["exploit/multi/http/log4shell_header_injection"],
    timeImpact: "low",
  },
  {
    id: 40045, name: "Spring4Shell (CVE-2022-22965)", category: "cve",
    technologies: ["Spring", "Spring Boot", "Java", "Tomcat"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: false,
    cweId: 94, mitreId: "T1190",
    msfModules: ["exploit/multi/http/spring_framework_rce_spring4shell"],
    timeImpact: "low",
  },
  {
    id: 40047, name: "Text4Shell (CVE-2022-42889)", category: "cve",
    technologies: ["Java", "Apache Commons Text"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: false,
    cweId: 94, mitreId: "T1190",
    timeImpact: "low",
  },
  {
    id: 40048, name: "Next.js RCE (React Server Components)", category: "cve",
    technologies: ["Next.js", "React", "Node.js"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: false,
    cweId: 94, mitreId: "T1190",
    timeImpact: "low",
  },
  {
    id: 20018, name: "Remote Code Execution - CVE-2012-1823 (PHP-CGI)", category: "cve",
    technologies: ["PHP", "Apache"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: false,
    cweId: 78, mitreId: "T1059",
    msfModules: ["exploit/multi/http/php_cgi_arg_injection"],
    timeImpact: "low",
  },
  {
    id: 20015, name: "Heartbleed (CVE-2014-0160)", category: "cve",
    technologies: ["OpenSSL"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: true,
    cweId: 119, mitreId: "T1190",
    msfModules: ["auxiliary/scanner/ssl/openssl_heartbleed"],
    timeImpact: "low",
  },

  // ── Authentication & Session ────────────────────────────────────────────
  {
    id: 40013, name: "Session Fixation", category: "session",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: false,
    cweId: 384, mitreId: "T1078",
    timeImpact: "medium",
  },
  {
    id: 20012, name: "CSRF Token Missing", category: "session",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: false,
    cweId: 352, mitreId: "T1185",
    timeImpact: "low",
  },
  {
    id: 40023, name: "Username Enumeration", category: "auth",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: true,
    cweId: 200, mitreId: "T1078",
    timeImpact: "medium",
  },
  {
    id: 10058, name: "GET for POST", category: "auth",
    technologies: [],  // universal
    defaultThreshold: "LOW", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: false,
    cweId: 16, mitreId: "T1190",
    timeImpact: "low",
  },

  // ── Configuration & Headers ─────────────────────────────────────────────
  {
    id: 40003, name: "CRLF Injection", category: "header",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: false,
    cweId: 113, mitreId: "T1190",
    timeImpact: "low",
  },
  {
    id: 40040, name: "CORS Misconfiguration", category: "config",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: false,
    cweId: 942, mitreId: "T1557",
    timeImpact: "low",
  },
  {
    id: 20016, name: "Cross-Domain Misconfiguration", category: "config",
    technologies: ["Flash", "Silverlight"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: false,
    cweId: 264, mitreId: "T1557",
    timeImpact: "low",
  },
  {
    id: 90028, name: "Insecure HTTP Method", category: "config",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: false,
    cweId: 200, mitreId: "T1190",
    timeImpact: "low",
  },
  {
    id: 10107, name: "HttPoxy - Proxy Header Misuse", category: "config",
    technologies: ["PHP", "CGI", "Python"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: false,
    cweId: 20, mitreId: "T1190",
    timeImpact: "low",
  },

  // ── Deserialization & Buffer Overflow ────────────────────────────────────
  {
    id: 30001, name: "Buffer Overflow", category: "rce",
    technologies: ["C", "C++", "CGI"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: false,
    cweId: 120, mitreId: "T1190",
    timeImpact: "medium",
  },
  {
    id: 30002, name: "Format String Error", category: "rce",
    technologies: ["C", "C++", "CGI"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: false,
    cweId: 134, mitreId: "T1190",
    timeImpact: "medium",
  },
  {
    id: 30003, name: "Integer Overflow Error", category: "rce",
    technologies: ["C", "C++", "CGI"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: false,
    cweId: 190, mitreId: "T1190",
    timeImpact: "medium",
  },
  {
    id: 40044, name: "Exponential Entity Expansion (Billion Laughs)", category: "misc",
    technologies: ["Java", "PHP", ".NET", "XML"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: false,
    cweId: 776, mitreId: "T1499",
    timeImpact: "low",
  },

  // ── Redirect & Miscellaneous ────────────────────────────────────────────
  {
    id: 20019, name: "External Redirect", category: "misc",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: false,
    cweId: 601, mitreId: "T1189",
    timeImpact: "low",
  },
  {
    id: 40009, name: "Server Side Include (SSI)", category: "rce",
    technologies: ["Apache", "Nginx", "IIS"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: false,
    cweId: 97, mitreId: "T1059",
    timeImpact: "medium",
  },
  {
    id: 40008, name: "Parameter Tampering", category: "misc",
    technologies: ["Java", "PHP", "ASP.NET", "Tomcat"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: false,
    cweId: 472, mitreId: "T1190",
    timeImpact: "low",
  },
  {
    id: 90024, name: "Padding Oracle", category: "crypto",
    technologies: ["ASP.NET", "Java", "Mono"],
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: true, secretsDiscovery: true,
    cweId: 209, mitreId: "T1190",
    timeImpact: "high",
  },
  {
    id: 10104, name: "User Agent Fuzzer", category: "misc",
    technologies: [],  // universal
    defaultThreshold: "LOW", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: false,
    cweId: 0, mitreId: "T1190",
    timeImpact: "medium",
  },
  {
    id: 10106, name: "HTTP Only Site", category: "crypto",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: false,
    cweId: 311, mitreId: "T1557",
    timeImpact: "low",
  },
  {
    id: 10047, name: "HTTPS Content Available via HTTP", category: "crypto",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: false,
    cweId: 311, mitreId: "T1557",
    timeImpact: "low",
  },
  {
    id: 20014, name: "HTTP Parameter Pollution (HPP)", category: "injection",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: false,
    cweId: 235, mitreId: "T1190",
    timeImpact: "medium",
  },
  {
    id: 10051, name: "Relative Path Confusion", category: "misc",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: false,
    cweId: 0, mitreId: "T1190",
    timeImpact: "low",
  },
  {
    id: 90027, name: "Cookie Slack Detector", category: "session",
    technologies: [],  // universal
    defaultThreshold: "LOW", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: false,
    cweId: 200, mitreId: "T1539",
    timeImpact: "low",
  },
  {
    id: 40025, name: "Proxy Disclosure", category: "info_disclosure",
    technologies: [],  // universal
    defaultThreshold: "MEDIUM", defaultStrength: "MEDIUM",
    footholdCapable: false, secretsDiscovery: false,
    cweId: 200, mitreId: "T1590",
    timeImpact: "low",
  },
];

// ─── Technology → Rule Mapping ──────────────────────────────────────────────

/** Get all scan rules that are relevant for a given set of technologies */
export function getRulesForTechStack(technologies: string[]): ZapScanRule[] {
  if (!technologies.length) return ZAP_SCAN_RULES; // all rules if no tech detected
  const techSet = new Set(technologies.map(t => t.toLowerCase()));
  return ZAP_SCAN_RULES.filter(rule => {
    if (rule.technologies.length === 0) return true; // universal rules always included
    return rule.technologies.some(t => techSet.has(t.toLowerCase()));
  });
}

/** Get rules that can help establish a foothold (RCE, file upload, deserialization) */
export function getFootholdRules(technologies?: string[]): ZapScanRule[] {
  const base = technologies?.length ? getRulesForTechStack(technologies) : ZAP_SCAN_RULES;
  return base.filter(r => r.footholdCapable);
}

/** Get rules that discover secrets, credentials, API keys */
export function getSecretsRules(technologies?: string[]): ZapScanRule[] {
  const base = technologies?.length ? getRulesForTechStack(technologies) : ZAP_SCAN_RULES;
  return base.filter(r => r.secretsDiscovery);
}

/** Get CVE-specific exploit rules for a tech stack */
export function getCVERules(technologies?: string[]): ZapScanRule[] {
  const base = technologies?.length ? getRulesForTechStack(technologies) : ZAP_SCAN_RULES;
  return base.filter(r => r.category === "cve");
}

// ─── Playbook Definitions ───────────────────────────────────────────────────

export interface ZapPlaybookConfig {
  /** Playbook name for logging */
  name: string;
  /** Human-readable description */
  description: string;
  /** ZAP scan rules to enable (by ID) with threshold/strength overrides */
  enabledRules: Array<{
    id: number;
    threshold: "LOW" | "MEDIUM" | "HIGH";
    strength: "LOW" | "MEDIUM" | "HIGH" | "INSANE";
  }>;
  /** ZAP scan rules to explicitly disable */
  disabledRuleIds: number[];
  /** Spider configuration overrides */
  spiderOverrides?: Partial<{
    maxDepth: number;
    maxChildren: number;
    threadCount: number;
    parseComments: boolean;
    parseGit: boolean;
    parseSitemapXml: boolean;
    postForm: boolean;
    parseSVNEntries: boolean;
    parseRobotsTxt: boolean;
  }>;
  /** AJAX spider configuration overrides */
  ajaxSpiderOverrides?: Partial<{
    maxCrawlDepth: number;
    maxCrawlStates: number;
    maxDuration: number;
    numberOfBrowsers: number;
    clickDefaultElems: boolean;
  }>;
  /** Context technology filter — only scan for these technologies */
  contextTechnologies?: string[];
  /** Additional ZAP API calls to make before scanning */
  preflightApiCalls?: Array<{
    endpoint: string;
    params: Record<string, string>;
  }>;
  /** Estimated time multiplier relative to default scan */
  timeMultiplier: number;
  /** Kill chain phase this playbook supports */
  killChainPhase: "reconnaissance" | "weaponization" | "delivery" | "exploitation" | "installation" | "c2" | "actions";
}

// ─── Playbook 1: Technology Fingerprinting & WAF Detection ──────────────────

export function buildFingerprintingPlaybook(technologies: string[]): ZapPlaybookConfig {
  return {
    name: "tech_fingerprinting",
    description: "Identify web server, framework, CMS, WAF, CDN, and JavaScript libraries. Detect technology versions for CVE correlation.",
    enabledRules: [
      { id: 40008, threshold: "LOW", strength: "LOW" },     // Parameter Tampering (reveals error pages with tech info)
      { id: 10104, threshold: "LOW", strength: "MEDIUM" },   // User Agent Fuzzer (WAF detection)
      { id: 40042, threshold: "LOW", strength: "LOW" },      // Spring Actuator
      { id: 10048, threshold: "LOW", strength: "LOW" },      // Spring Actuator Detailed
      { id: 40028, threshold: "LOW", strength: "LOW" },      // ELMAH (ASP.NET)
      { id: 40029, threshold: "LOW", strength: "LOW" },      // Trace.axd (ASP.NET)
      { id: 0, threshold: "LOW", strength: "LOW" },          // Directory Browsing
      { id: 40025, threshold: "LOW", strength: "LOW" },      // Proxy Disclosure
    ],
    disabledRuleIds: getAllInjectionRuleIds(), // disable heavy injection tests during fingerprinting
    spiderOverrides: {
      maxDepth: 3,
      maxChildren: 20,
      parseComments: true,
      parseGit: true,
      parseSitemapXml: true,
      parseSVNEntries: true,
      parseRobotsTxt: true,
    },
    contextTechnologies: technologies.length ? technologies : undefined,
    timeMultiplier: 0.3,
    killChainPhase: "reconnaissance",
  };
}

// ─── Playbook 2: Deep Crawling & Spidering ──────────────────────────────────

export function buildCrawlingPlaybook(technologies: string[], useAjaxSpider: boolean): ZapPlaybookConfig {
  const isSPA = technologies.some(t =>
    ["React", "Angular", "Vue.js", "Next.js", "Nuxt", "Svelte", "Ember"].includes(t)
  );

  return {
    name: "deep_crawling",
    description: "Maximum URL discovery via traditional spider, AJAX spider for SPAs, form submission, comment/git parsing, and sitemap extraction.",
    enabledRules: [
      { id: 0, threshold: "MEDIUM", strength: "MEDIUM" },    // Directory Browsing
      { id: 10051, threshold: "LOW", strength: "LOW" },       // Relative Path Confusion
    ],
    disabledRuleIds: getAllInjectionRuleIds(), // crawling phase — no attacks
    spiderOverrides: {
      maxDepth: 10,
      maxChildren: 100,
      threadCount: 10,
      parseComments: true,
      parseGit: true,
      parseSitemapXml: true,
      parseSVNEntries: true,
      parseRobotsTxt: true,
      postForm: true,
    },
    ajaxSpiderOverrides: (isSPA || useAjaxSpider) ? {
      maxCrawlDepth: 10,
      maxCrawlStates: 100000,
      maxDuration: 30,
      numberOfBrowsers: 3,
      clickDefaultElems: true,
    } : undefined,
    contextTechnologies: technologies.length ? technologies : undefined,
    timeMultiplier: 0.5,
    killChainPhase: "reconnaissance",
  };
}

// ─── Playbook 3: Secrets & Credential Discovery ────────────────────────────

export function buildSecretsPlaybook(technologies: string[]): ZapPlaybookConfig {
  const secretsRules = getSecretsRules(technologies);

  return {
    name: "secrets_discovery",
    description: "Hunt for exposed credentials, API keys, tokens, .env files, backup files, source code, cloud metadata, and configuration files.",
    enabledRules: secretsRules.map(r => ({
      id: r.id,
      threshold: "LOW" as const,   // LOW threshold = maximum sensitivity for secrets
      strength: "HIGH" as const,    // HIGH strength = thorough checking
    })),
    disabledRuleIds: ZAP_SCAN_RULES
      .filter(r => !r.secretsDiscovery && r.category !== "info_disclosure")
      .map(r => r.id),
    spiderOverrides: {
      maxDepth: 5,
      parseComments: true,
      parseGit: true,
      parseSVNEntries: true,
      parseSitemapXml: true,
      parseRobotsTxt: true,
    },
    preflightApiCalls: [
      // Force ZAP to check common backup extensions
      { endpoint: "/JSON/ascan/action/setOptionTargetParamsInjectable/", params: { Integer: "15" } },
      // Enable all passive scan rules for header/cookie/token detection
      { endpoint: "/JSON/pscan/action/enableAllScanners/", params: {} },
    ],
    contextTechnologies: technologies.length ? technologies : undefined,
    timeMultiplier: 0.6,
    killChainPhase: "reconnaissance",
  };
}

// ─── Playbook 4: Injection Testing ──────────────────────────────────────────

export function buildInjectionPlaybook(technologies: string[]): ZapPlaybookConfig {
  const techSet = new Set(technologies.map(t => t.toLowerCase()));

  // Select DB-specific SQLi rules based on detected tech
  const sqliRules: Array<{ id: number; threshold: "LOW" | "MEDIUM" | "HIGH"; strength: "LOW" | "MEDIUM" | "HIGH" | "INSANE" }> = [
    { id: 40018, threshold: "MEDIUM", strength: "HIGH" }, // Generic SQLi (always)
  ];

  if (techSet.has("mysql") || techSet.has("mariadb") || techSet.has("php") || techSet.has("wordpress") || techSet.has("laravel")) {
    sqliRules.push({ id: 40019, threshold: "MEDIUM", strength: "HIGH" }); // MySQL time-based
  }
  if (techSet.has("postgresql") || techSet.has("django") || techSet.has("ruby on rails") || techSet.has("node.js")) {
    sqliRules.push({ id: 40022, threshold: "MEDIUM", strength: "HIGH" }); // PostgreSQL time-based
  }
  if (techSet.has("mssql") || techSet.has("asp.net") || techSet.has("iis") || techSet.has(".net")) {
    sqliRules.push({ id: 40027, threshold: "MEDIUM", strength: "HIGH" }); // MsSQL time-based
  }
  if (techSet.has("oracle") || techSet.has("java")) {
    sqliRules.push({ id: 40021, threshold: "MEDIUM", strength: "HIGH" }); // Oracle time-based
  }
  if (techSet.has("java") || techSet.has("hsqldb")) {
    sqliRules.push({ id: 40020, threshold: "MEDIUM", strength: "HIGH" }); // Hypersonic time-based
  }
  if (techSet.has("mongodb") || techSet.has("node.js") || techSet.has("express.js")) {
    sqliRules.push({ id: 40033, threshold: "MEDIUM", strength: "HIGH" }); // MongoDB NoSQL
    sqliRules.push({ id: 90039, threshold: "MEDIUM", strength: "HIGH" }); // MongoDB time-based
  }

  // If no specific DB detected, enable all SQLi variants
  if (sqliRules.length === 1) {
    sqliRules.push(
      { id: 40019, threshold: "MEDIUM", strength: "MEDIUM" },
      { id: 40022, threshold: "MEDIUM", strength: "MEDIUM" },
      { id: 40027, threshold: "MEDIUM", strength: "MEDIUM" },
      { id: 40021, threshold: "MEDIUM", strength: "MEDIUM" },
      { id: 40033, threshold: "MEDIUM", strength: "MEDIUM" },
    );
  }

  // Template injection rules based on tech
  const templateRules: Array<{ id: number; threshold: "LOW" | "MEDIUM" | "HIGH"; strength: "LOW" | "MEDIUM" | "HIGH" | "INSANE" }> = [];
  if (techSet.has("jinja2") || techSet.has("django") || techSet.has("flask") || techSet.has("twig") ||
      techSet.has("php") || techSet.has("java") || techSet.has("ruby on rails") || techSet.has("node.js") ||
      techSet.has("thymeleaf") || techSet.has("freemarker") || techSet.has("handlebars") || technologies.length === 0) {
    templateRules.push(
      { id: 90035, threshold: "MEDIUM", strength: "HIGH" }, // SSTI
      { id: 90036, threshold: "MEDIUM", strength: "HIGH" }, // SSTI Blind
    );
  }
  if (techSet.has("java") || techSet.has("spring") || techSet.has("jsp") || techSet.has("jsf") || techSet.has("struts")) {
    templateRules.push({ id: 90025, threshold: "MEDIUM", strength: "HIGH" }); // EL Injection
  }

  return {
    name: "injection_testing",
    description: "Comprehensive injection testing: SQL injection (DB-specific), NoSQL injection, XSS (reflected + persistent), SSTI, OS command injection, XXE, XPath, LDAP, and Expression Language injection — tuned to the discovered technology stack.",
    enabledRules: [
      ...sqliRules,
      ...templateRules,
      { id: 40012, threshold: "MEDIUM", strength: "HIGH" },  // Reflected XSS
      { id: 40014, threshold: "MEDIUM", strength: "HIGH" },  // Persistent XSS
      { id: 40031, threshold: "MEDIUM", strength: "MEDIUM" }, // Out of Band XSS
      { id: 90020, threshold: "MEDIUM", strength: "HIGH" },  // OS Command Injection
      { id: 90037, threshold: "MEDIUM", strength: "HIGH" },  // OS Command Injection (Time Based)
      { id: 90017, threshold: "MEDIUM", strength: "HIGH" },  // XXE
      { id: 90023, threshold: "MEDIUM", strength: "HIGH" },  // XXE OAST
      { id: 90021, threshold: "MEDIUM", strength: "HIGH" },  // XPath Injection
      { id: 40003, threshold: "MEDIUM", strength: "MEDIUM" }, // CRLF Injection
      { id: 20014, threshold: "MEDIUM", strength: "MEDIUM" }, // HTTP Parameter Pollution
    ],
    disabledRuleIds: ZAP_SCAN_RULES
      .filter(r => r.category === "info_disclosure" || r.category === "config" || r.category === "crypto")
      .map(r => r.id),
    contextTechnologies: technologies.length ? technologies : undefined,
    preflightApiCalls: [
      // Enable anti-CSRF token handling for injection tests
      { endpoint: "/JSON/ascan/action/setOptionHandleAntiCSRFTokens/", params: { Boolean: "true" } },
      // Scan headers for injection points
      { endpoint: "/JSON/ascan/action/setOptionScanHeadersAllRequests/", params: { Boolean: "true" } },
    ],
    timeMultiplier: 2.0, // injection testing is the most time-intensive
    killChainPhase: "exploitation",
  };
}

// ─── Playbook 5: Authentication & Session Attacks ───────────────────────────

export function buildAuthPlaybook(technologies: string[]): ZapPlaybookConfig {
  return {
    name: "auth_session_attacks",
    description: "Test authentication mechanisms: session fixation, CSRF bypass, username enumeration, cookie security, forced browsing to admin panels, and authentication bypass via parameter manipulation.",
    enabledRules: [
      { id: 40013, threshold: "MEDIUM", strength: "HIGH" },  // Session Fixation
      { id: 20012, threshold: "MEDIUM", strength: "MEDIUM" }, // CSRF Token Missing
      { id: 40023, threshold: "MEDIUM", strength: "HIGH" },  // Username Enumeration
      { id: 10058, threshold: "LOW", strength: "MEDIUM" },    // GET for POST
      { id: 90027, threshold: "LOW", strength: "MEDIUM" },    // Cookie Slack Detector
      { id: 90024, threshold: "MEDIUM", strength: "HIGH" },  // Padding Oracle (session cookies)
      { id: 90028, threshold: "MEDIUM", strength: "MEDIUM" }, // Insecure HTTP Method
      { id: 10047, threshold: "MEDIUM", strength: "MEDIUM" }, // HTTPS Content via HTTP
      { id: 10106, threshold: "MEDIUM", strength: "MEDIUM" }, // HTTP Only Site
    ],
    disabledRuleIds: getAllInjectionRuleIds(),
    contextTechnologies: technologies.length ? technologies : undefined,
    timeMultiplier: 0.8,
    killChainPhase: "exploitation",
  };
}

// ─── Playbook 6: Backend Infrastructure Enumeration ─────────────────────────

export function buildInfraEnumPlaybook(technologies: string[]): ZapPlaybookConfig {
  return {
    name: "infra_enumeration",
    description: "Discover backend infrastructure: S3 buckets, cloud metadata endpoints, API documentation (Swagger/OpenAPI), Spring Actuators, admin panels, debug endpoints, and storage URLs in HTML/JS/headers.",
    enabledRules: [
      { id: 90034, threshold: "LOW", strength: "HIGH" },     // Cloud Metadata Attack
      { id: 40042, threshold: "LOW", strength: "HIGH" },     // Spring Actuator
      { id: 10048, threshold: "LOW", strength: "HIGH" },     // Spring Actuator Detailed
      { id: 40046, threshold: "MEDIUM", strength: "HIGH" },  // SSRF (can reach internal infra)
      { id: 0, threshold: "LOW", strength: "MEDIUM" },       // Directory Browsing
      { id: 40025, threshold: "LOW", strength: "MEDIUM" },   // Proxy Disclosure
      { id: 40035, threshold: "LOW", strength: "HIGH" },     // Hidden File Finder
      { id: 10095, threshold: "LOW", strength: "HIGH" },     // Backup File Disclosure
      { id: 40034, threshold: "LOW", strength: "HIGH" },     // .env leak
      { id: 40032, threshold: "LOW", strength: "HIGH" },     // .htaccess leak
    ],
    disabledRuleIds: getAllInjectionRuleIds(),
    spiderOverrides: {
      maxDepth: 5,
      parseComments: true,
      parseGit: true,
      parseSitemapXml: true,
      parseRobotsTxt: true,
    },
    contextTechnologies: technologies.length ? technologies : undefined,
    preflightApiCalls: [
      // Enable passive scanning for API endpoint discovery in responses
      { endpoint: "/JSON/pscan/action/enableAllScanners/", params: {} },
    ],
    timeMultiplier: 0.5,
    killChainPhase: "reconnaissance",
  };
}

// ─── Playbook 7: API Security Testing ───────────────────────────────────────

export function buildApiSecurityPlaybook(technologies: string[], apiSpec?: { type: "openapi" | "graphql" | "soap"; url: string }): ZapPlaybookConfig {
  const preflightCalls: Array<{ endpoint: string; params: Record<string, string> }> = [];

  // Import API spec if provided
  if (apiSpec) {
    if (apiSpec.type === "openapi") {
      preflightCalls.push({
        endpoint: "/JSON/openapi/action/importUrl/",
        params: { url: apiSpec.url },
      });
    } else if (apiSpec.type === "graphql") {
      preflightCalls.push({
        endpoint: "/JSON/graphql/action/importUrl/",
        params: { url: apiSpec.url },
      });
    }
  }

  return {
    name: "api_security",
    description: "Test API endpoints: BOLA/IDOR via parameter manipulation, mass assignment, injection in JSON/XML payloads, authentication bypass, rate limiting, and CORS misconfiguration. Imports OpenAPI/GraphQL/SOAP specs for comprehensive endpoint coverage.",
    enabledRules: [
      { id: 40018, threshold: "MEDIUM", strength: "HIGH" },  // SQLi in API params
      { id: 40033, threshold: "MEDIUM", strength: "HIGH" },  // NoSQL in API params
      { id: 90020, threshold: "MEDIUM", strength: "HIGH" },  // OS Command in API params
      { id: 90017, threshold: "MEDIUM", strength: "HIGH" },  // XXE in XML APIs
      { id: 40046, threshold: "MEDIUM", strength: "HIGH" },  // SSRF via API params
      { id: 40040, threshold: "MEDIUM", strength: "HIGH" },  // CORS Misconfiguration
      { id: 90028, threshold: "MEDIUM", strength: "MEDIUM" }, // Insecure HTTP Method
      { id: 40003, threshold: "MEDIUM", strength: "MEDIUM" }, // CRLF Injection
      { id: 10058, threshold: "LOW", strength: "MEDIUM" },    // GET for POST
      { id: 40044, threshold: "MEDIUM", strength: "MEDIUM" }, // Billion Laughs (XML APIs)
    ],
    disabledRuleIds: [
      // Disable browser-oriented rules for API testing
      40012, 40014, 40031, // XSS (not relevant for API-only)
      40013, // Session Fixation (API uses tokens)
    ],
    contextTechnologies: technologies.length ? technologies : undefined,
    preflightApiCalls: [
      ...preflightCalls,
      // Scan headers (Authorization, API keys in headers)
      { endpoint: "/JSON/ascan/action/setOptionScanHeadersAllRequests/", params: { Boolean: "true" } },
    ],
    timeMultiplier: 1.2,
    killChainPhase: "exploitation",
  };
}

// ─── Playbook 8: Server-Side Exploitation ───────────────────────────────────

export function buildServerExploitPlaybook(technologies: string[]): ZapPlaybookConfig {
  const footholdRules = getFootholdRules(technologies);
  const cveRules = getCVERules(technologies);

  // Merge and deduplicate
  const allRuleIds = new Set([...footholdRules.map(r => r.id), ...cveRules.map(r => r.id)]);
  const allRules = ZAP_SCAN_RULES.filter(r => allRuleIds.has(r.id));

  return {
    name: "server_exploitation",
    description: "Maximum-intensity exploitation: all RCE vectors (command injection, code injection, SSTI, deserialization, file inclusion), CVE-specific exploits (Log4Shell, Spring4Shell, Text4Shell, Next.js RCE, PHP-CGI RCE), SSRF for internal network access, and path traversal for sensitive file reads. Findings are correlated with Metasploit modules for C2 handoff.",
    enabledRules: allRules.map(r => ({
      id: r.id,
      threshold: "LOW" as const,     // LOW threshold = maximum sensitivity
      strength: "INSANE" as const,    // INSANE strength = exhaustive testing
    })),
    disabledRuleIds: ZAP_SCAN_RULES
      .filter(r => !allRuleIds.has(r.id))
      .map(r => r.id),
    contextTechnologies: technologies.length ? technologies : undefined,
    preflightApiCalls: [
      // Enable anti-CSRF handling
      { endpoint: "/JSON/ascan/action/setOptionHandleAntiCSRFTokens/", params: { Boolean: "true" } },
      // Scan all headers
      { endpoint: "/JSON/ascan/action/setOptionScanHeadersAllRequests/", params: { Boolean: "true" } },
      // Inject plugin ID for tracking which rule found what
      { endpoint: "/JSON/ascan/action/setOptionInjectPluginIdInHeader/", params: { Boolean: "true" } },
    ],
    timeMultiplier: 3.0, // most intensive playbook
    killChainPhase: "exploitation",
  };
}

// ─── Playbook 9: Full Engagement (All Phases) ──────────────────────────────

export function buildFullEngagementPlaybook(technologies: string[]): ZapPlaybookConfig {
  const techRules = getRulesForTechStack(technologies);

  return {
    name: "full_engagement",
    description: "Complete DAST engagement: all scan rules enabled and tuned to the discovered technology stack. Universal rules at MEDIUM, technology-specific rules at HIGH strength. Includes all injection, secrets, infrastructure, and CVE-specific tests.",
    enabledRules: techRules.map(r => ({
      id: r.id,
      threshold: r.footholdCapable ? "LOW" as const : "MEDIUM" as const,
      strength: (r.technologies.length > 0 ? "HIGH" : "MEDIUM") as "LOW" | "MEDIUM" | "HIGH" | "INSANE",
    })),
    disabledRuleIds: ZAP_SCAN_RULES
      .filter(r => !techRules.some(tr => tr.id === r.id))
      .map(r => r.id),
    spiderOverrides: {
      maxDepth: 8,
      maxChildren: 50,
      threadCount: 8,
      parseComments: true,
      parseGit: true,
      parseSitemapXml: true,
      parseSVNEntries: true,
      parseRobotsTxt: true,
      postForm: true,
    },
    contextTechnologies: technologies.length ? technologies : undefined,
    preflightApiCalls: [
      { endpoint: "/JSON/ascan/action/setOptionHandleAntiCSRFTokens/", params: { Boolean: "true" } },
      { endpoint: "/JSON/ascan/action/setOptionScanHeadersAllRequests/", params: { Boolean: "true" } },
      { endpoint: "/JSON/pscan/action/enableAllScanners/", params: {} },
    ],
    timeMultiplier: 2.5,
    killChainPhase: "exploitation",
  };
}

// ─── LLM System Prompt Enhancement ──────────────────────────────────────────

/**
 * Generate an enhanced LLM system prompt that includes the complete scan rule
 * registry and technology mapping, so the LLM can make informed decisions
 * about which rules to enable/disable based on the target's tech stack.
 */
export function generateEnhancedSystemPrompt(discoveredTechnologies: string[]): string {
  const relevantRules = getRulesForTechStack(discoveredTechnologies);
  const footholdRules = relevantRules.filter(r => r.footholdCapable);
  const secretsRules = relevantRules.filter(r => r.secretsDiscovery);
  const cveRules = relevantRules.filter(r => r.category === "cve");

  return `
## ZAP Scan Rule Intelligence for Detected Tech Stack

### Detected Technologies: ${discoveredTechnologies.join(", ") || "Unknown"}

### Relevant Active Scan Rules (${relevantRules.length} of ${ZAP_SCAN_RULES.length} total):
${relevantRules.map(r => `- **${r.id}**: ${r.name} [${r.category}] — ${r.technologies.length ? `Targets: ${r.technologies.join(", ")}` : "Universal"}`).join("\n")}

### Foothold-Capable Rules (${footholdRules.length} rules that can achieve RCE/file upload/code execution):
${footholdRules.map(r => `- **${r.id}**: ${r.name}${r.msfModules?.length ? ` → MSF: ${r.msfModules.join(", ")}` : ""}`).join("\n")}

### Secrets Discovery Rules (${secretsRules.length} rules that find credentials/API keys/tokens):
${secretsRules.map(r => `- **${r.id}**: ${r.name}`).join("\n")}

### CVE-Specific Exploits (${cveRules.length} rules targeting known vulnerabilities):
${cveRules.map(r => `- **${r.id}**: ${r.name}${r.msfModules?.length ? ` → MSF: ${r.msfModules.join(", ")}` : ""}`).join("\n")}

### Rule Configuration API:
To enable/disable specific rules and set their threshold/strength, use these ZAP API calls:
- Enable rule: \`/JSON/ascan/action/enableScanners/\` with \`ids\` parameter (comma-separated IDs)
- Disable rule: \`/JSON/ascan/action/disableScanners/\` with \`ids\` parameter
- Set threshold: \`/JSON/ascan/action/setScannerAlertThreshold/\` with \`id\` and \`alertThreshold\` (OFF/LOW/MEDIUM/HIGH)
- Set strength: \`/JSON/ascan/action/setScannerAttackStrength/\` with \`id\` and \`attackStrength\` (LOW/MEDIUM/HIGH/INSANE)

### Technology Context API:
To filter scanning by technology, create a context and set its technology:
- Create context: \`/JSON/context/action/newContext/\` with \`contextName\`
- Include URL: \`/JSON/context/action/includeInContext/\` with \`contextName\` and \`regex\`
- Set technology: \`/JSON/context/action/includeTechnologyList/\` with \`contextName\` and \`technologyNames\` (comma-separated)
- Exclude technology: \`/JSON/context/action/excludeTechnologyList/\` with \`contextName\` and \`technologyNames\`

### Recommended Scan Strategy:
1. **Phase 1 — Fingerprint**: Run tech fingerprinting playbook to confirm/discover technologies
2. **Phase 2 — Crawl**: Deep spider + AJAX spider (if SPA detected) to maximize URL coverage
3. **Phase 3 — Secrets**: Run secrets discovery playbook with LOW threshold for maximum sensitivity
4. **Phase 4 — Inject**: Run injection playbook with DB-specific SQLi rules for detected database
5. **Phase 5 — Exploit**: Run server exploitation playbook with CVE-specific rules for detected stack
6. **Phase 6 — Handoff**: Correlate findings with Metasploit modules for C2 foothold establishment
`;
}

// ─── ZAP API Application Functions ──────────────────────────────────────────

/**
 * Apply a playbook's rule configuration to ZAP via its API.
 * This is the missing piece — the current codebase generates LLM configs
 * but never applies the per-rule enable/disable/threshold/strength settings.
 */
export interface ZapApiConfig {
  baseUrl: string;
  apiKey: string;
}

export async function applyPlaybookToZap(
  playbook: ZapPlaybookConfig,
  zapConfig: ZapApiConfig,
  zapRequest: (endpoint: string, params: Record<string, string>, config: any) => Promise<any>,
): Promise<{ applied: boolean; errors: string[] }> {
  const errors: string[] = [];

  // 1. Disable all rules first for a clean slate
  try {
    await zapRequest("/JSON/ascan/action/disableAllScanners/", {}, zapConfig);
  } catch (err: any) {
    errors.push(`Failed to disable all scanners: ${err.message}`);
  }

  // 2. Enable the playbook's selected rules
  if (playbook.enabledRules.length > 0) {
    const ruleIds = playbook.enabledRules.map(r => r.id).join(",");
    try {
      await zapRequest("/JSON/ascan/action/enableScanners/", { ids: ruleIds }, zapConfig);
    } catch (err: any) {
      errors.push(`Failed to enable scanners: ${err.message}`);
    }

    // 3. Set threshold and strength for each enabled rule
    for (const rule of playbook.enabledRules) {
      try {
        await zapRequest("/JSON/ascan/action/setScannerAlertThreshold/", {
          id: String(rule.id),
          alertThreshold: rule.threshold,
        }, zapConfig);
        await zapRequest("/JSON/ascan/action/setScannerAttackStrength/", {
          id: String(rule.id),
          attackStrength: rule.strength,
        }, zapConfig);
      } catch (err: any) {
        errors.push(`Failed to configure rule ${rule.id}: ${err.message}`);
      }
    }
  }

  // 4. Apply preflight API calls
  if (playbook.preflightApiCalls) {
    for (const call of playbook.preflightApiCalls) {
      try {
        await zapRequest(call.endpoint, call.params, zapConfig);
      } catch (err: any) {
        errors.push(`Preflight call ${call.endpoint} failed: ${err.message}`);
      }
    }
  }

  // 5. Create context with technology filter if specified
  if (playbook.contextTechnologies?.length) {
    try {
      const contextName = `playbook_${playbook.name}_${Date.now()}`;
      await zapRequest("/JSON/context/action/newContext/", { contextName }, zapConfig);
      await zapRequest("/JSON/context/action/includeTechnologyList/", {
        contextName,
        technologyNames: playbook.contextTechnologies.join(","),
      }, zapConfig);
    } catch (err: any) {
      errors.push(`Failed to create technology context: ${err.message}`);
    }
  }

  return { applied: errors.length === 0, errors };
}

// ─── Playbook Orchestrator ──────────────────────────────────────────────────

export type PlaybookPhase =
  | "fingerprinting"
  | "crawling"
  | "secrets"
  | "injection"
  | "auth"
  | "infra_enum"
  | "api_security"
  | "server_exploit"
  | "full";

/**
 * Select the appropriate playbook based on the current pipeline phase
 * and discovered technology stack.
 */
export function selectPlaybook(
  phase: PlaybookPhase,
  technologies: string[],
  options?: {
    useAjaxSpider?: boolean;
    apiSpec?: { type: "openapi" | "graphql" | "soap"; url: string };
  },
): ZapPlaybookConfig {
  switch (phase) {
    case "fingerprinting":
      return buildFingerprintingPlaybook(technologies);
    case "crawling":
      return buildCrawlingPlaybook(technologies, options?.useAjaxSpider ?? false);
    case "secrets":
      return buildSecretsPlaybook(technologies);
    case "injection":
      return buildInjectionPlaybook(technologies);
    case "auth":
      return buildAuthPlaybook(technologies);
    case "infra_enum":
      return buildInfraEnumPlaybook(technologies);
    case "api_security":
      return buildApiSecurityPlaybook(technologies, options?.apiSpec);
    case "server_exploit":
      return buildServerExploitPlaybook(technologies);
    case "full":
      return buildFullEngagementPlaybook(technologies);
    default:
      return buildFullEngagementPlaybook(technologies);
  }
}

/**
 * Generate the recommended playbook execution order for a full engagement.
 * Returns playbooks in kill-chain order with estimated time multipliers.
 */
export function getEngagementPlaybookSequence(
  technologies: string[],
  options?: {
    useAjaxSpider?: boolean;
    apiSpec?: { type: "openapi" | "graphql" | "soap"; url: string };
    skipPhases?: PlaybookPhase[];
  },
): ZapPlaybookConfig[] {
  const phases: PlaybookPhase[] = [
    "fingerprinting",
    "crawling",
    "secrets",
    "infra_enum",
    "injection",
    "auth",
    "server_exploit",
  ];

  // Add API security if we have an API spec or detect API-oriented tech
  const apiTechs = ["Express.js", "Django REST", "Flask", "FastAPI", "Spring Boot", "GraphQL", "Node.js"];
  if (options?.apiSpec || technologies.some(t => apiTechs.includes(t))) {
    phases.splice(5, 0, "api_security"); // insert before auth
  }

  const skip = new Set(options?.skipPhases || []);
  return phases
    .filter(p => !skip.has(p))
    .map(p => selectPlaybook(p, technologies, options));
}

// ─── Helper Functions ───────────────────────────────────────────────────────

function getAllInjectionRuleIds(): number[] {
  return ZAP_SCAN_RULES
    .filter(r => ["injection", "rce", "xss", "file_inclusion", "ssrf", "deserialization"].includes(r.category))
    .map(r => r.id);
}

/** Get all Metasploit modules that can exploit ZAP findings for a tech stack */
export function getMsfModulesForTechStack(technologies: string[]): Array<{ ruleId: number; ruleName: string; msfModules: string[] }> {
  const rules = getRulesForTechStack(technologies);
  return rules
    .filter(r => r.msfModules && r.msfModules.length > 0)
    .map(r => ({
      ruleId: r.id,
      ruleName: r.name,
      msfModules: r.msfModules!,
    }));
}

/** Get a summary of what a playbook will do, for display to the operator */
export function getPlaybookSummary(playbook: ZapPlaybookConfig): string {
  const ruleNames = playbook.enabledRules
    .map(r => ZAP_SCAN_RULES.find(rule => rule.id === r.id)?.name || `Rule ${r.id}`)
    .join(", ");
  return `[${playbook.name}] ${playbook.description}\n` +
    `Enabled rules (${playbook.enabledRules.length}): ${ruleNames}\n` +
    `Disabled rules: ${playbook.disabledRuleIds.length}\n` +
    `Time multiplier: ${playbook.timeMultiplier}x\n` +
    `Kill chain phase: ${playbook.killChainPhase}`;
}
