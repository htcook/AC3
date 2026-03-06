/**
 * OWASP Top 10:2025 Knowledge Module
 * 
 * Provides structured OWASP Top 10 knowledge for LLM prompt injection across
 * scan plan generation, vulnerability correlation, hunt hypothesis generation,
 * and asset classification.
 * 
 * Based on OWASP Top 10:2025 (latest release):
 * A01: Broken Access Control
 * A02: Security Misconfiguration
 * A03: Software Supply Chain Failures (NEW)
 * A04: Cryptographic Failures
 * A05: Injection
 * A06: Insecure Design
 * A07: Authentication Failures
 * A08: Software or Data Integrity Failures
 * A09: Security Logging and Alerting Failures
 * A10: Mishandling of Exceptional Conditions (NEW)
 */

// ─── OWASP Category Definitions ────────────────────────────────────────────

export interface OwaspCategory {
  id: string;
  name: string;
  rank: number;
  description: string;
  keyCWEs: string[];
  riskLevel: 'critical' | 'high' | 'medium' | 'low';
  prevalence: string;
  primaryTools: string[];
  nmapScripts: string[];
  nucleiTags: string[];
  otherTools: string[];
  detectionSignals: string[];
  attackPatterns: string[];
  mitreTechniques: string[];
  testingCommands: ToolCommand[];
}

export interface ToolCommand {
  tool: string;
  command: string;
  purpose: string;
  phase: 'recon' | 'discovery' | 'vuln-detection' | 'exploitation';
}

export interface OwaspFinding {
  category: string;
  categoryId: string;
  severity: 'critical' | 'high' | 'medium' | 'low' | 'info';
  confidence: 'confirmed' | 'likely' | 'possible';
  falsePositiveIndicators: string[];
}

// ─── OWASP Top 10:2025 Categories ──────────────────────────────────────────

const OWASP_CATEGORIES: OwaspCategory[] = [
  {
    id: 'A01:2025',
    name: 'Broken Access Control',
    rank: 1,
    description: 'Access control enforces policy such that users cannot act outside of their intended permissions. Failures lead to unauthorized information disclosure, modification, or destruction of data. Includes SSRF, CSRF, IDOR, path traversal, and privilege escalation.',
    keyCWEs: ['CWE-200', 'CWE-201', 'CWE-918 (SSRF)', 'CWE-352 (CSRF)', 'CWE-22 (Path Traversal)', 'CWE-639 (IDOR)', 'CWE-862 (Missing AuthZ)', 'CWE-863 (Incorrect AuthZ)', 'CWE-601 (Open Redirect)'],
    riskLevel: 'critical',
    prevalence: '100% of tested apps had some form of broken access control. 40 CWEs mapped, 1.8M occurrences, 32K CVEs.',
    primaryTools: ['nuclei', 'ffuf', 'gobuster', 'feroxbuster', 'nikto'],
    nmapScripts: ['http-enum', 'http-methods', 'http-auth-finder', 'http-open-proxy', 'http-internal-ip-disclosure'],
    nucleiTags: ['idor', 'ssrf', 'lfi', 'rfi', 'traversal', 'cors', 'redirect', 'auth-bypass', 'exposure'],
    otherTools: ['Burp Suite (AuthMatrix, Authorize)', 'curl (manual IDOR testing)', 'wfuzz'],
    detectionSignals: [
      'HTTP 200 on admin/debug endpoints without auth',
      'IDOR: sequential IDs in API responses',
      'Directory listing enabled',
      '.git/.env/.htaccess exposed',
      'CORS: Access-Control-Allow-Origin: *',
      'Open redirect parameters (url=, redirect=, next=)',
      'SSRF: internal IP in response when manipulating URL params'
    ],
    attackPatterns: [
      'Modify URL parameters to access other users data (IDOR)',
      'Force browse to /admin, /debug, /status, /actuator endpoints',
      'Manipulate JWT claims to escalate privileges',
      'SSRF via URL parameters to access internal services (169.254.169.254)',
      'Path traversal via ../../../etc/passwd in file parameters',
      'CSRF to perform state-changing operations'
    ],
    mitreTechniques: ['T1190 (Exploit Public-Facing Application)', 'T1078 (Valid Accounts)', 'T1552 (Unsecured Credentials)'],
    testingCommands: [
      { tool: 'ffuf', command: 'ffuf -u https://TARGET/FUZZ -w /usr/share/wordlists/dirb/common.txt -mc 200,301,302,403', purpose: 'Forced browsing to discover hidden endpoints', phase: 'discovery' },
      { tool: 'nuclei', command: 'nuclei -u https://TARGET -tags idor,ssrf,lfi,traversal,cors,redirect,auth-bypass', purpose: 'Automated OWASP A01 vulnerability detection', phase: 'vuln-detection' },
      { tool: 'nmap', command: 'nmap -p 80,443 --script http-enum,http-methods,http-auth-finder TARGET', purpose: 'Enumerate web directories and HTTP methods', phase: 'discovery' },
      { tool: 'curl', command: 'curl -s -o /dev/null -w "%{http_code}" https://TARGET/admin', purpose: 'Check for unprotected admin endpoints', phase: 'discovery' },
      { tool: 'nikto', command: 'nikto -h https://TARGET -Tuning 4', purpose: 'Check for information disclosure and access control issues', phase: 'vuln-detection' }
    ]
  },
  {
    id: 'A02:2025',
    name: 'Security Misconfiguration',
    rank: 2,
    description: 'Application is missing appropriate security hardening or has improperly configured permissions on cloud services. Includes unnecessary features enabled, default accounts, overly informative error messages, and missing security headers.',
    keyCWEs: ['CWE-16 (Configuration)', 'CWE-611 (XXE)', 'CWE-1004 (Sensitive Cookie No HttpOnly)', 'CWE-1032 (OWASP Top 10 2017 A6)', 'CWE-209 (Error Info Leak)'],
    riskLevel: 'high',
    prevalence: 'Previously at #5 in 2021, moved up to #2 in 2025. High incidence across all application types.',
    primaryTools: ['nikto', 'nmap', 'nuclei', 'testssl.sh'],
    nmapScripts: ['http-security-headers', 'http-default-accounts', 'http-config-backup', 'ssl-enum-ciphers', 'http-server-header', 'http-trace', 'http-methods', 'http-git', 'http-robots.txt'],
    nucleiTags: ['misconfig', 'exposure', 'default-login', 'debug', 'backup', 'config', 'panel', 'tech'],
    otherTools: ['skipfish', 'testssl.sh', 'sslyze', 'securityheaders.com'],
    detectionSignals: [
      'Missing security headers (HSTS, CSP, X-Frame-Options, X-Content-Type-Options)',
      'Default credentials working on admin panels',
      'Stack traces in error responses',
      'Server version disclosed in headers',
      'Directory listing enabled',
      'Backup files accessible (.bak, .old, .swp, ~)',
      'Debug mode enabled (/debug, /phpinfo, /server-status)',
      'XXE in XML parsers',
      'TRACE method enabled'
    ],
    attackPatterns: [
      'Access /phpinfo.php, /server-status, /debug for configuration leaks',
      'Try default credentials on admin panels',
      'Check for .git, .env, .htaccess, web.config exposure',
      'XXE injection in XML upload/API endpoints',
      'HTTP TRACE for XST (Cross-Site Tracing)',
      'Check for backup files (.bak, .old, .sql, .tar.gz)'
    ],
    mitreTechniques: ['T1190 (Exploit Public-Facing App)', 'T1592 (Gather Victim Host Information)', 'T1589 (Gather Victim Identity Info)'],
    testingCommands: [
      { tool: 'nikto', command: 'nikto -h https://TARGET -Tuning 2', purpose: 'Scan for misconfigurations and default files', phase: 'vuln-detection' },
      { tool: 'nmap', command: 'nmap -p 80,443 --script http-security-headers,http-default-accounts,http-config-backup,http-git,http-trace TARGET', purpose: 'Check security headers, defaults, and exposed configs', phase: 'vuln-detection' },
      { tool: 'nuclei', command: 'nuclei -u https://TARGET -tags misconfig,exposure,default-login,debug,backup,config', purpose: 'Automated misconfiguration detection', phase: 'vuln-detection' },
      { tool: 'testssl.sh', command: 'testssl.sh --severity HIGH https://TARGET', purpose: 'Check TLS/SSL configuration issues', phase: 'vuln-detection' },
      { tool: 'curl', command: 'curl -sI https://TARGET | grep -iE "server|x-powered|x-aspnet|x-frame|strict-transport|content-security"', purpose: 'Quick security header check', phase: 'recon' }
    ]
  },
  {
    id: 'A03:2025',
    name: 'Software Supply Chain Failures',
    rank: 3,
    description: 'NEW in 2025. Focuses on risks from third-party components, libraries, and dependencies. Includes vulnerable and outdated components, dependency confusion, and compromised build pipelines.',
    keyCWEs: ['CWE-1104 (Unmaintained Third-Party Components)', 'CWE-937 (OWASP Top 10 2013 A9)'],
    riskLevel: 'high',
    prevalence: 'New category in 2025. Previously "Vulnerable and Outdated Components" (A06:2021). Average age of CVEs in this category is 3+ years.',
    primaryTools: ['nuclei', 'wpscan', 'searchsploit'],
    nmapScripts: ['http-wordpress-enum', 'http-drupal-enum', 'http-joomla-brute', 'http-server-header'],
    nucleiTags: ['cve', 'outdated', 'component', 'wordpress', 'joomla', 'drupal', 'apache', 'nginx', 'iis', 'tomcat', 'tech'],
    otherTools: ['npm audit', 'snyk', 'retire.js', 'OWASP Dependency-Check', 'Trivy'],
    detectionSignals: [
      'Outdated server version in headers (Apache 2.2, nginx 1.x, IIS 7)',
      'Known vulnerable CMS version (WordPress < 6.x, Joomla < 4.x)',
      'Outdated JavaScript libraries (jQuery < 3.5, Angular < 14)',
      'Known vulnerable framework versions in headers/responses',
      'CVE matches from version fingerprinting'
    ],
    attackPatterns: [
      'Identify component versions from headers, HTML, JavaScript files',
      'Match versions against CVE databases (NVD, Exploit-DB)',
      'Check for known exploits via searchsploit',
      'Dependency confusion attacks on package managers',
      'Exploit known CMS plugin vulnerabilities'
    ],
    mitreTechniques: ['T1190 (Exploit Public-Facing App)', 'T1195 (Supply Chain Compromise)', 'T1059 (Command and Scripting Interpreter)'],
    testingCommands: [
      { tool: 'nuclei', command: 'nuclei -u https://TARGET -tags cve,tech,wordpress,joomla,drupal,apache,nginx,tomcat', purpose: 'Detect known CVEs in identified components', phase: 'vuln-detection' },
      { tool: 'wpscan', command: 'wpscan --url https://TARGET --enumerate vp,vt,u', purpose: 'WordPress vulnerability and plugin enumeration', phase: 'vuln-detection' },
      { tool: 'nmap', command: 'nmap -sV -p 80,443 --script http-wordpress-enum,http-drupal-enum TARGET', purpose: 'CMS version and plugin enumeration', phase: 'discovery' },
      { tool: 'searchsploit', command: 'searchsploit apache 2.4', purpose: 'Search for known exploits for detected versions', phase: 'vuln-detection' },
      { tool: 'curl', command: 'curl -s https://TARGET/ | grep -oP "(?<=ver=)[\\d.]+" | sort -u', purpose: 'Extract version numbers from page source', phase: 'recon' }
    ]
  },
  {
    id: 'A04:2025',
    name: 'Cryptographic Failures',
    rank: 4,
    description: 'Failures related to cryptography which often lead to sensitive data exposure. Includes weak algorithms, insufficient key length, improper certificate validation, and data transmitted in cleartext.',
    keyCWEs: ['CWE-259 (Hard-coded Password)', 'CWE-327 (Broken Crypto Algorithm)', 'CWE-328 (Reversible One-Way Hash)', 'CWE-330 (Insufficient Randomness)', 'CWE-311 (Missing Encryption)', 'CWE-312 (Cleartext Storage)'],
    riskLevel: 'high',
    prevalence: 'Previously #2 in 2021, moved to #4 in 2025. Still highly prevalent in web applications.',
    primaryTools: ['testssl.sh', 'sslyze', 'nmap'],
    nmapScripts: ['ssl-enum-ciphers', 'ssl-cert', 'ssl-dh-params', 'ssl-heartbleed', 'ssl-poodle', 'ssl-ccs-injection', 'ssl-known-key', 'ssl-date'],
    nucleiTags: ['ssl', 'tls', 'weak-crypto', 'heartbleed', 'poodle', 'exposed-panels', 'http'],
    otherTools: ['sslscan', 'openssl s_client', 'Qualys SSL Labs'],
    detectionSignals: [
      'TLS 1.0/1.1 still supported',
      'Weak cipher suites (RC4, DES, 3DES, NULL)',
      'Self-signed or expired certificates',
      'Missing HSTS header',
      'HTTP (no TLS) for sensitive data',
      'Weak DH parameters (< 2048 bits)',
      'Known TLS vulnerabilities (Heartbleed, POODLE, BEAST, CRIME)',
      'Hard-coded credentials in source code',
      'MD5/SHA1 used for password hashing'
    ],
    attackPatterns: [
      'SSL stripping via missing HSTS',
      'Exploit Heartbleed for memory disclosure',
      'Downgrade attacks (POODLE, DROWN)',
      'Certificate impersonation with weak validation',
      'Brute-force weak encryption keys',
      'Harvest credentials from cleartext HTTP traffic'
    ],
    mitreTechniques: ['T1557 (Adversary-in-the-Middle)', 'T1040 (Network Sniffing)', 'T1552 (Unsecured Credentials)'],
    testingCommands: [
      { tool: 'testssl.sh', command: 'testssl.sh --severity HIGH --sneaky https://TARGET', purpose: 'Comprehensive TLS/SSL vulnerability assessment', phase: 'vuln-detection' },
      { tool: 'nmap', command: 'nmap -p 443 --script ssl-enum-ciphers,ssl-cert,ssl-heartbleed,ssl-poodle,ssl-ccs-injection,ssl-dh-params TARGET', purpose: 'Check for weak ciphers and known TLS vulnerabilities', phase: 'vuln-detection' },
      { tool: 'sslyze', command: 'sslyze --regular TARGET:443', purpose: 'SSL/TLS configuration analysis', phase: 'vuln-detection' },
      { tool: 'curl', command: 'curl -sI http://TARGET | grep -i "location\\|strict-transport"', purpose: 'Check HTTP to HTTPS redirect and HSTS', phase: 'recon' },
      { tool: 'openssl', command: 'openssl s_client -connect TARGET:443 -tls1 2>/dev/null | grep "Protocol"', purpose: 'Test for deprecated TLS 1.0 support', phase: 'vuln-detection' }
    ]
  },
  {
    id: 'A05:2025',
    name: 'Injection',
    rank: 5,
    description: 'Injection flaws occur when untrusted data is sent to an interpreter as part of a command or query. Includes SQL injection, NoSQL injection, OS command injection, LDAP injection, XSS, SSTI, and XXE.',
    keyCWEs: ['CWE-79 (XSS)', 'CWE-89 (SQL Injection)', 'CWE-78 (OS Command Injection)', 'CWE-94 (Code Injection)', 'CWE-917 (Expression Language Injection)', 'CWE-77 (Command Injection)'],
    riskLevel: 'critical',
    prevalence: 'Previously #3 in 2021, moved to #5 in 2025. Still one of the most dangerous categories with direct RCE potential.',
    primaryTools: ['sqlmap', 'nuclei', 'commix', 'XSStrike'],
    nmapScripts: ['http-sql-injection', 'http-stored-xss', 'http-dombased-xss', 'http-phpself-xss', 'http-shellshock', 'http-vuln-cve2014-3704'],
    nucleiTags: ['sqli', 'xss', 'ssti', 'rce', 'injection', 'lfi', 'rfi', 'xxe', 'command-injection', 'el-injection'],
    otherTools: ['tplmap (SSTI)', 'commix (OS command)', 'XSStrike (XSS)', 'NoSQLMap', 'Burp Suite'],
    detectionSignals: [
      'SQL errors in responses (syntax error, mysql_fetch, ORA-)',
      'Reflected input in HTML without encoding (XSS)',
      'Template engine errors (Jinja2, Twig, Freemarker)',
      'OS command output in responses',
      'LDAP errors when injecting special characters',
      'XML parsing errors suggesting XXE potential',
      'Error-based information disclosure'
    ],
    attackPatterns: [
      'SQL injection: UNION SELECT, blind boolean, time-based',
      'XSS: reflected, stored, DOM-based via user input fields',
      'SSTI: {{7*7}} in template engines (Jinja2, Twig, Freemarker)',
      'OS command injection: ; | && ` $() in parameters',
      'XXE: external entity injection in XML parsers',
      'LDAP injection: * ) ( | in search parameters',
      'NoSQL injection: {$gt:""} in MongoDB queries'
    ],
    mitreTechniques: ['T1190 (Exploit Public-Facing App)', 'T1059 (Command and Scripting Interpreter)', 'T1203 (Exploitation for Client Execution)'],
    testingCommands: [
      { tool: 'sqlmap', command: 'sqlmap -u "https://TARGET/page?id=1" --batch --risk=2 --level=3', purpose: 'Automated SQL injection detection and exploitation', phase: 'vuln-detection' },
      { tool: 'nuclei', command: 'nuclei -u https://TARGET -tags sqli,xss,ssti,rce,injection,xxe,command-injection', purpose: 'Automated injection vulnerability detection', phase: 'vuln-detection' },
      { tool: 'nmap', command: 'nmap -p 80,443 --script http-sql-injection,http-stored-xss,http-dombased-xss,http-shellshock TARGET', purpose: 'NSE-based injection detection', phase: 'vuln-detection' },
      { tool: 'commix', command: 'commix --url="https://TARGET/page?cmd=test" --batch', purpose: 'OS command injection testing', phase: 'vuln-detection' },
      { tool: 'curl', command: 'curl -s "https://TARGET/page?id=1\'" | grep -iE "error|syntax|mysql|ora-|warning"', purpose: 'Quick SQL error detection', phase: 'recon' }
    ]
  },
  {
    id: 'A06:2025',
    name: 'Insecure Design',
    rank: 6,
    description: 'Focuses on risks related to design and architectural flaws. Insecure design cannot be fixed by a perfect implementation — the flaw is in the design itself. Includes missing rate limiting, insufficient anti-automation, and business logic flaws.',
    keyCWEs: ['CWE-209 (Error Info Leak)', 'CWE-256 (Plaintext Storage of Password)', 'CWE-501 (Trust Boundary Violation)', 'CWE-522 (Insufficiently Protected Credentials)'],
    riskLevel: 'medium',
    prevalence: 'Introduced in 2021. Focuses on pre-code design flaws that require threat modeling to identify.',
    primaryTools: ['Manual review', 'nuclei', 'nikto'],
    nmapScripts: ['http-default-accounts', 'http-auth-finder', 'http-form-brute'],
    nucleiTags: ['exposure', 'default-login', 'info-disclosure', 'panel', 'login'],
    otherTools: ['Threat modeling tools', 'Burp Suite (business logic testing)'],
    detectionSignals: [
      'No rate limiting on login/API endpoints',
      'Password reset via predictable tokens',
      'Business logic bypass (negative quantities, price manipulation)',
      'Missing CAPTCHA on sensitive forms',
      'Insufficient anti-automation controls',
      'Trust boundary violations (client-side validation only)'
    ],
    attackPatterns: [
      'Brute-force login without lockout',
      'Manipulate business logic (negative prices, skip steps)',
      'Predictable password reset tokens',
      'Race conditions in financial transactions',
      'Abuse lack of rate limiting for enumeration'
    ],
    mitreTechniques: ['T1110 (Brute Force)', 'T1078 (Valid Accounts)', 'T1589 (Gather Victim Identity Info)'],
    testingCommands: [
      { tool: 'nuclei', command: 'nuclei -u https://TARGET -tags exposure,default-login,info-disclosure,panel', purpose: 'Detect design-level exposures', phase: 'vuln-detection' },
      { tool: 'ffuf', command: 'ffuf -u https://TARGET/api/user/FUZZ -w /usr/share/wordlists/seclists/Usernames/top-usernames-shortlist.txt -mc 200', purpose: 'Test for user enumeration without rate limiting', phase: 'vuln-detection' },
      { tool: 'hydra', command: 'hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect"', purpose: 'Test for missing account lockout', phase: 'vuln-detection' },
      { tool: 'curl', command: 'for i in $(seq 1 50); do curl -s -o /dev/null -w "%{http_code}" "https://TARGET/api/login" -d "user=test&pass=wrong$i"; done', purpose: 'Check rate limiting on login endpoint', phase: 'vuln-detection' }
    ]
  },
  {
    id: 'A07:2025',
    name: 'Authentication Failures',
    rank: 7,
    description: 'Confirmation of the user identity, authentication, and session management is critical. Includes credential stuffing, brute force, weak passwords, session fixation, and missing MFA.',
    keyCWEs: ['CWE-287 (Improper Authentication)', 'CWE-384 (Session Fixation)', 'CWE-613 (Insufficient Session Expiration)', 'CWE-640 (Weak Password Recovery)'],
    riskLevel: 'high',
    prevalence: 'Previously "Identification and Authentication Failures" (A07:2021). Renamed to "Authentication Failures" in 2025.',
    primaryTools: ['hydra', 'medusa', 'nmap', 'nuclei'],
    nmapScripts: ['http-brute', 'http-form-brute', 'ssh-brute', 'ftp-brute', 'http-auth-finder', 'http-default-accounts', 'ssh-auth-methods'],
    nucleiTags: ['auth-bypass', 'default-login', 'brute-force', 'token', 'session', 'login'],
    otherTools: ['john', 'hashcat', 'CeWL (custom wordlists)', 'Burp Suite Intruder'],
    detectionSignals: [
      'Login form without rate limiting or CAPTCHA',
      'Default credentials working',
      'Session tokens in URL parameters',
      'Session not invalidated after logout',
      'Weak password policy (no complexity requirements)',
      'Password reset without proper verification',
      'Missing MFA on sensitive operations'
    ],
    attackPatterns: [
      'Credential stuffing with leaked databases',
      'Brute force with common password lists',
      'Session fixation via URL parameter injection',
      'Session hijacking via XSS or network sniffing',
      'Password spraying across multiple accounts',
      'Account enumeration via different error messages'
    ],
    mitreTechniques: ['T1110 (Brute Force)', 'T1078 (Valid Accounts)', 'T1539 (Steal Web Session Cookie)', 'T1556 (Modify Authentication Process)'],
    testingCommands: [
      { tool: 'hydra', command: 'hydra -l admin -P /usr/share/wordlists/rockyou.txt TARGET http-post-form "/login:user=^USER^&pass=^PASS^:F=incorrect" -t 4', purpose: 'Brute force login credentials', phase: 'vuln-detection' },
      { tool: 'nmap', command: 'nmap -p 22,80,443 --script http-brute,http-form-brute,ssh-brute,http-default-accounts,ssh-auth-methods TARGET', purpose: 'Check for brute-forceable services and default accounts', phase: 'vuln-detection' },
      { tool: 'nuclei', command: 'nuclei -u https://TARGET -tags auth-bypass,default-login,token,session', purpose: 'Automated authentication vulnerability detection', phase: 'vuln-detection' },
      { tool: 'curl', command: 'curl -s -D- "https://TARGET/login" -d "user=admin&pass=admin" | grep -i "set-cookie\\|location"', purpose: 'Test default credentials and session handling', phase: 'vuln-detection' }
    ]
  },
  {
    id: 'A08:2025',
    name: 'Software or Data Integrity Failures',
    rank: 8,
    description: 'Relates to code and infrastructure that does not protect against integrity violations. Includes insecure deserialization, unsigned updates, CI/CD pipeline compromise, and auto-update without integrity verification.',
    keyCWEs: ['CWE-502 (Deserialization of Untrusted Data)', 'CWE-829 (Inclusion of Functionality from Untrusted Control Sphere)'],
    riskLevel: 'high',
    prevalence: 'Previously "Software and Data Integrity Failures" (A08:2021). Deserialization attacks can lead to RCE.',
    primaryTools: ['nuclei', 'ysoserial', 'custom scripts'],
    nmapScripts: [],
    nucleiTags: ['deserialization', 'rce', 'java', 'upload', 'ci-cd'],
    otherTools: ['ysoserial (Java)', 'phpggc (PHP)', 'Burp Suite (deserialization detection)'],
    detectionSignals: [
      'Java serialized objects in requests (rO0AB, aced0005)',
      'PHP serialized data (O:4:"User")',
      '.NET ViewState without MAC validation',
      'Unsigned software updates',
      'CI/CD pipeline accessible without auth',
      'File upload without integrity checks'
    ],
    attackPatterns: [
      'Java deserialization RCE via ysoserial gadget chains',
      'PHP object injection via unserialize()',
      '.NET ViewState deserialization',
      'Tamper with CI/CD pipeline to inject malicious code',
      'Supply chain attack via compromised dependencies'
    ],
    mitreTechniques: ['T1059 (Command and Scripting Interpreter)', 'T1195 (Supply Chain Compromise)', 'T1190 (Exploit Public-Facing App)'],
    testingCommands: [
      { tool: 'nuclei', command: 'nuclei -u https://TARGET -tags deserialization,rce,java,upload', purpose: 'Detect deserialization and integrity vulnerabilities', phase: 'vuln-detection' },
      { tool: 'curl', command: 'curl -s https://TARGET/ | grep -oP "rO0AB|aced0005|O:\\d+:" | head -5', purpose: 'Check for serialized objects in responses', phase: 'recon' },
      { tool: 'nmap', command: 'nmap -sV -p 8080,8443,9090 --script http-server-header TARGET', purpose: 'Identify Java application servers (Tomcat, JBoss, WebLogic)', phase: 'discovery' }
    ]
  },
  {
    id: 'A09:2025',
    name: 'Security Logging and Alerting Failures',
    rank: 9,
    description: 'Without sufficient logging and monitoring, breaches cannot be detected. Includes insufficient logging, missing alerting, log injection, and logs not monitored for suspicious activity.',
    keyCWEs: ['CWE-117 (Log Injection)', 'CWE-223 (Omission of Security-Relevant Info)', 'CWE-532 (Sensitive Info in Log)', 'CWE-778 (Insufficient Logging)'],
    riskLevel: 'medium',
    prevalence: 'Previously "Security Logging and Monitoring Failures" (A09:2021). Renamed with "Alerting" emphasis in 2025.',
    primaryTools: ['Manual review', 'log analysis tools'],
    nmapScripts: [],
    nucleiTags: ['log', 'exposure', 'debug', 'stacktrace'],
    otherTools: ['ELK Stack', 'Splunk', 'Graylog'],
    detectionSignals: [
      'No logging of authentication events',
      'No alerting on suspicious activity',
      'Logs stored only locally (no centralized logging)',
      'Sensitive data in logs (passwords, tokens)',
      'Log injection possible via user input',
      'No log integrity protection'
    ],
    attackPatterns: [
      'Log injection to forge entries or hide tracks',
      'Exploit lack of monitoring to maintain persistence',
      'Tamper with local log files to cover tracks',
      'Abuse verbose error logging for information gathering'
    ],
    mitreTechniques: ['T1070 (Indicator Removal)', 'T1562 (Impair Defenses)', 'T1530 (Data from Cloud Storage)'],
    testingCommands: [
      { tool: 'nuclei', command: 'nuclei -u https://TARGET -tags log,exposure,debug,stacktrace', purpose: 'Detect exposed logs and debug information', phase: 'vuln-detection' },
      { tool: 'curl', command: 'curl -s https://TARGET/logs/ https://TARGET/log/ https://TARGET/debug/ | head -20', purpose: 'Check for exposed log endpoints', phase: 'discovery' }
    ]
  },
  {
    id: 'A10:2025',
    name: 'Mishandling of Exceptional Conditions',
    rank: 10,
    description: 'NEW in 2025. Focuses on improper error handling, uncaught exceptions, and failure to handle edge cases. Includes stack trace disclosure, unhandled exceptions leading to denial of service, and error-based information leakage.',
    keyCWEs: ['CWE-252 (Unchecked Return Value)', 'CWE-280 (Improper Handling of Insufficient Permissions)', 'CWE-391 (Unchecked Error Condition)', 'CWE-754 (Improper Check for Unusual Conditions)', 'CWE-755 (Improper Handling of Exceptional Conditions)'],
    riskLevel: 'medium',
    prevalence: 'New category in 2025. Contains 24 CWEs. Focuses on how applications handle unexpected inputs and error conditions.',
    primaryTools: ['fuzzing tools', 'nuclei', 'wfuzz'],
    nmapScripts: ['http-errors'],
    nucleiTags: ['error', 'stacktrace', 'debug', 'info-disclosure', 'dos'],
    otherTools: ['wfuzz', 'ffuf', 'Burp Suite (Intruder for fuzzing)'],
    detectionSignals: [
      'Stack traces in HTTP responses',
      'Detailed error messages revealing internal paths',
      'Application crashes on malformed input',
      'Different error responses for valid vs invalid resources',
      'Unhandled exceptions causing 500 errors',
      'Debug information in production responses'
    ],
    attackPatterns: [
      'Fuzz input parameters to trigger unhandled exceptions',
      'Send malformed data types to cause crashes',
      'Exploit error-based information disclosure for further attacks',
      'Trigger DoS via resource exhaustion from error handling',
      'Use stack traces to map internal architecture'
    ],
    mitreTechniques: ['T1499 (Endpoint Denial of Service)', 'T1592 (Gather Victim Host Information)'],
    testingCommands: [
      { tool: 'nuclei', command: 'nuclei -u https://TARGET -tags error,stacktrace,debug,info-disclosure', purpose: 'Detect error handling and information disclosure issues', phase: 'vuln-detection' },
      { tool: 'wfuzz', command: 'wfuzz -c -z file,/usr/share/wordlists/seclists/Fuzzing/special-chars.txt -d "param=FUZZ" https://TARGET/api/endpoint', purpose: 'Fuzz parameters for error handling issues', phase: 'vuln-detection' },
      { tool: 'curl', command: 'curl -s "https://TARGET/api/test" -H "Content-Type: application/json" -d "{{invalid json}}" | grep -iE "error|exception|stack|trace"', purpose: 'Test error handling with malformed input', phase: 'vuln-detection' },
      { tool: 'ffuf', command: 'ffuf -u https://TARGET/FUZZ -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-small-words.txt -fc 404 -mc 500', purpose: 'Find endpoints that return 500 errors', phase: 'discovery' }
    ]
  }
];

// ─── Context Builders ──────────────────────────────────────────────────────

/**
 * Returns OWASP Top 10 context for scan plan generation.
 * Helps LLM select the right tools and techniques per detected technology.
 */
export function getOwaspScanPlanContext(detectedTech?: string[]): string {
  const sections: string[] = [];

  sections.push(`## OWASP Top 10:2025 — Scan Plan Knowledge

You MUST design scan plans that cover ALL relevant OWASP Top 10:2025 categories based on the target's technology stack. Each category has specific tools and techniques that MUST be included when applicable.`);

  // Build a condensed tool selection matrix
  sections.push(`### OWASP Category → Tool Selection Matrix

| Category | Primary Test | Nmap Scripts | Nuclei Tags |
|----------|-------------|--------------|-------------|
${OWASP_CATEGORIES.map(c => 
    `| ${c.id} ${c.name} | ${c.primaryTools.slice(0, 2).join(', ')} | ${c.nmapScripts.slice(0, 3).join(', ') || 'N/A'} | ${c.nucleiTags.slice(0, 4).join(', ')} |`
  ).join('\n')}`);

  // Technology-specific OWASP priorities
  if (detectedTech && detectedTech.length > 0) {
    const techLower = detectedTech.map(t => t.toLowerCase());
    const priorities: string[] = [];

    if (techLower.some(t => t.includes('php') || t.includes('wordpress') || t.includes('joomla') || t.includes('drupal'))) {
      priorities.push('**PHP/CMS detected**: Prioritize A03 (Supply Chain — wpscan/nuclei CVE), A05 (Injection — sqlmap, XSS), A02 (Misconfig — phpinfo, debug)');
    }
    if (techLower.some(t => t.includes('java') || t.includes('tomcat') || t.includes('spring') || t.includes('jboss') || t.includes('weblogic'))) {
      priorities.push('**Java detected**: Prioritize A08 (Deserialization — ysoserial), A05 (Injection — SSTI, EL injection), A03 (Supply Chain — Log4Shell, Struts CVEs)');
    }
    if (techLower.some(t => t.includes('asp') || t.includes('.net') || t.includes('iis'))) {
      priorities.push('**ASP.NET/IIS detected**: Prioritize A02 (Misconfig — web.config, trace.axd), A08 (ViewState deserialization), A04 (Crypto — TLS config)');
    }
    if (techLower.some(t => t.includes('node') || t.includes('express') || t.includes('react') || t.includes('angular') || t.includes('vue'))) {
      priorities.push('**Node.js/SPA detected**: Prioritize A01 (Broken Access — API auth bypass), A05 (Injection — NoSQL, SSTI), A02 (Misconfig — exposed .env, debug)');
    }
    if (techLower.some(t => t.includes('python') || t.includes('django') || t.includes('flask'))) {
      priorities.push('**Python detected**: Prioritize A05 (Injection — SSTI Jinja2), A02 (Misconfig — debug mode), A01 (Broken Access — Django admin)');
    }
    if (techLower.some(t => t.includes('api') || t.includes('rest') || t.includes('graphql'))) {
      priorities.push('**API detected**: Prioritize A01 (Broken Access — IDOR, missing auth), A05 (Injection — GraphQL injection), A07 (Auth — JWT weaknesses)');
    }
    if (techLower.some(t => t.includes('aws') || t.includes('azure') || t.includes('gcp') || t.includes('cloud'))) {
      priorities.push('**Cloud detected**: Prioritize A02 (Misconfig — cloud storage, IMDS), A01 (Broken Access — IAM, SSRF), A04 (Crypto — TLS on cloud services)');
    }

    if (priorities.length > 0) {
      sections.push(`### Technology-Specific OWASP Priorities\n\n${priorities.join('\n')}`);
    }
  }

  // Mandatory testing rules
  sections.push(`### Mandatory OWASP Coverage Rules

1. **EVERY scan plan MUST include nuclei** with tags covering at least A01, A02, A04, A05
2. **EVERY web target MUST have**: http-security-headers (A02), ssl-enum-ciphers (A04), http-enum (A01)
3. **If login form detected**: MUST test A07 (auth) with http-brute or hydra
4. **If file upload detected**: MUST test A08 (integrity) with upload bypass techniques
5. **If API endpoints detected**: MUST test A01 (access control) with IDOR and auth bypass
6. **If CMS detected**: MUST test A03 (supply chain) with version-specific CVE checks
7. **If error pages show stack traces**: MUST flag A10 (exception handling) and A02 (misconfig)

### Recommended Nuclei Tag Combinations by Scan Type

- **Quick web scan**: \`nuclei -tags misconfig,exposure,cve,tech\`
- **Full OWASP coverage**: \`nuclei -tags sqli,xss,ssrf,idor,misconfig,default-login,cve,ssl,auth-bypass,rce,lfi,deserialization\`
- **Cloud-focused**: \`nuclei -tags cloud,s3,misconfig,exposure,ssrf,iam\`
- **API-focused**: \`nuclei -tags api,idor,auth-bypass,injection,graphql,token\``);

  return sections.join('\n\n');
}

/**
 * Returns OWASP context for vulnerability correlation.
 * Helps LLM classify findings into OWASP categories and assess severity.
 */
export function getOwaspVulnCorrelationContext(): string {
  const sections: string[] = [];

  sections.push(`## OWASP Top 10:2025 — Vulnerability Correlation Guide

When correlating scan findings to vulnerabilities, classify each finding into the appropriate OWASP category. This affects severity scoring, remediation priority, and reporting.`);

  // Finding-to-category mapping
  sections.push(`### Finding → OWASP Category Mapping

| Finding Type | OWASP Category | Default Severity | Notes |
|-------------|---------------|-----------------|-------|
| SQL injection confirmed | A05 Injection | Critical | Confirmed SQLi = always critical |
| XSS (reflected/stored) | A05 Injection | High/Critical | Stored XSS = critical, reflected = high |
| SSRF to internal services | A01 Broken Access | Critical | Especially if reaching cloud metadata |
| IDOR (data access) | A01 Broken Access | High | Critical if PII/financial data exposed |
| Directory listing | A02 Misconfig | Medium | High if sensitive files visible |
| Missing security headers | A02 Misconfig | Low/Info | Medium if missing HSTS on sensitive app |
| Weak TLS (1.0/1.1) | A04 Crypto | Medium | High if handling sensitive data |
| Heartbleed/POODLE | A04 Crypto | Critical | Known exploited vulnerabilities |
| Default credentials | A07 Auth | Critical | Immediate compromise possible |
| Session fixation | A07 Auth | High | Requires user interaction |
| Deserialization RCE | A08 Integrity | Critical | Direct code execution |
| Outdated component CVE | A03 Supply Chain | Varies | Match CVE severity from NVD |
| Stack trace in response | A10 Exception | Low/Medium | Info disclosure aids further attacks |
| Missing rate limiting | A06 Insecure Design | Medium | Enables brute force attacks |
| Exposed .git/.env | A02 Misconfig | High/Critical | Critical if contains credentials |
| Open redirect | A01 Broken Access | Medium | High if used in phishing chain |`);

  // False positive indicators per category
  sections.push(`### False Positive Indicators by OWASP Category

| Category | Common False Positives |
|----------|----------------------|
| A01 | 403 on admin pages (access control working), CORS headers present but restrictive |
| A02 | Server header present but not version-specific, security headers on non-sensitive pages |
| A04 | TLS 1.0 supported but not preferred (may be for legacy compatibility) |
| A05 | SQL-like errors from WAF/honeypot, XSS in non-rendered contexts (JSON API) |
| A07 | Rate limiting at CDN level (not visible in direct test), CAPTCHA after N failures |
| A10 | Custom error pages that include debug info only in dev mode |`);

  return sections.join('\n\n');
}

/**
 * Returns OWASP context for hunt hypothesis generation.
 * Maps OWASP categories to MITRE ATT&CK techniques for threat hunting.
 */
export function getOwaspHuntContext(): string {
  const sections: string[] = [];

  sections.push(`## OWASP Top 10:2025 — Threat Hunt Mapping

Map discovered OWASP vulnerabilities to MITRE ATT&CK techniques for threat hunting hypotheses.`);

  sections.push(`### OWASP → MITRE ATT&CK Mapping

| OWASP Category | MITRE Techniques | Hunt Hypothesis |
|---------------|-----------------|-----------------|
${OWASP_CATEGORIES.map(c => 
    `| ${c.id} ${c.name} | ${c.mitreTechniques.join(', ')} | ${c.attackPatterns[0]} |`
  ).join('\n')}`);

  sections.push(`### OWASP-Driven Detection Rules

- **A01 indicators**: Unusual API access patterns, sequential ID enumeration, internal IP in logs
- **A02 indicators**: Access to /admin, /debug, /phpinfo from external IPs, default credential attempts
- **A03 indicators**: Known CVE exploitation attempts matching detected component versions
- **A04 indicators**: TLS downgrade attempts, certificate errors, cleartext credential transmission
- **A05 indicators**: SQL syntax in parameters, script tags in input, template expressions in requests
- **A07 indicators**: High-volume login failures, credential stuffing patterns, session token reuse
- **A08 indicators**: Serialized object payloads in requests, unexpected binary data in parameters
- **A10 indicators**: High 500 error rates, stack traces in responses, application crashes`);

  return sections.join('\n\n');
}

/**
 * Returns OWASP context for asset classification and scoring.
 * Helps assess risk based on OWASP exposure surface.
 */
export function getOwaspAssetClassificationContext(): string {
  return `## OWASP Top 10:2025 — Asset Risk Classification

When classifying assets, consider their OWASP exposure surface:

### Risk Multipliers by OWASP Category
- **A01 (Broken Access)**: +30% risk if API endpoints detected without auth
- **A02 (Misconfig)**: +20% risk if debug/admin endpoints exposed
- **A03 (Supply Chain)**: +25% risk if outdated CMS/framework detected
- **A04 (Crypto)**: +15% risk if weak TLS or missing HSTS
- **A05 (Injection)**: +40% risk if input fields without validation detected
- **A07 (Auth)**: +35% risk if login form without rate limiting
- **A08 (Integrity)**: +30% risk if Java/PHP deserialization endpoints detected

### Technology → OWASP Risk Profile
| Technology | Highest Risk Categories | Risk Level |
|-----------|----------------------|------------|
| PHP + MySQL | A05, A03, A02 | High |
| Java (Tomcat/Spring) | A08, A05, A03 | High |
| ASP.NET + IIS | A02, A08, A04 | Medium-High |
| Node.js + Express | A01, A05, A02 | Medium |
| Python (Django/Flask) | A05, A02, A01 | Medium |
| WordPress/Joomla | A03, A05, A07 | High |
| API-only (REST/GraphQL) | A01, A05, A07 | Medium-High |
| Cloud-hosted (AWS/Azure) | A02, A01, A04 | Medium-High |`;
}

/**
 * Returns all OWASP knowledge combined for comprehensive LLM injection.
 */
export function getFullOwaspContext(detectedTech?: string[]): string {
  return [
    getOwaspScanPlanContext(detectedTech),
    getOwaspVulnCorrelationContext(),
    getOwaspHuntContext(),
    getOwaspAssetClassificationContext()
  ].join('\n\n---\n\n');
}

/**
 * Look up which OWASP categories are most relevant for a given technology.
 */
export function getOwaspPrioritiesForTech(technology: string): OwaspCategory[] {
  const techLower = technology.toLowerCase();
  
  return OWASP_CATEGORIES.filter(cat => {
    // Every web target should test A01, A02, A04, A05
    if (['A01:2025', 'A02:2025', 'A04:2025', 'A05:2025'].includes(cat.id)) return true;
    
    // Tech-specific priorities
    if (techLower.includes('php') || techLower.includes('wordpress')) {
      return ['A03:2025', 'A07:2025'].includes(cat.id);
    }
    if (techLower.includes('java') || techLower.includes('tomcat')) {
      return ['A03:2025', 'A08:2025'].includes(cat.id);
    }
    if (techLower.includes('asp') || techLower.includes('iis')) {
      return ['A08:2025'].includes(cat.id);
    }
    if (techLower.includes('api') || techLower.includes('graphql')) {
      return ['A07:2025'].includes(cat.id);
    }
    return false;
  });
}

/**
 * Get testing commands for a specific OWASP category.
 */
export function getTestingCommandsForCategory(categoryId: string): ToolCommand[] {
  const cat = OWASP_CATEGORIES.find(c => c.id === categoryId);
  return cat?.testingCommands ?? [];
}

/**
 * Get all OWASP categories.
 */
export function getAllOwaspCategories(): OwaspCategory[] {
  return [...OWASP_CATEGORIES];
}

/**
 * Classify a finding into an OWASP category based on keywords.
 */
export function classifyFindingToOwasp(findingTitle: string, findingDescription?: string): string {
  const text = `${findingTitle} ${findingDescription ?? ''}`.toLowerCase();
  
  if (text.includes('sql injection') || text.includes('sqli') || text.includes('xss') || text.includes('cross-site scripting') || text.includes('command injection') || text.includes('ssti') || text.includes('xxe')) {
    return 'A05:2025';
  }
  if (text.includes('ssrf') || text.includes('idor') || text.includes('path traversal') || text.includes('directory traversal') || text.includes('lfi') || text.includes('rfi') || text.includes('open redirect') || text.includes('cors') || text.includes('access control') || text.includes('authorization')) {
    return 'A01:2025';
  }
  if (text.includes('misconfig') || text.includes('default') || text.includes('security header') || text.includes('directory listing') || text.includes('debug') || text.includes('phpinfo') || text.includes('.git') || text.includes('.env') || text.includes('server-status')) {
    return 'A02:2025';
  }
  if (text.includes('ssl') || text.includes('tls') || text.includes('cipher') || text.includes('heartbleed') || text.includes('poodle') || text.includes('certificate') || text.includes('crypto') || text.includes('hsts')) {
    return 'A04:2025';
  }
  if (text.includes('outdated') || text.includes('vulnerable component') || text.includes('cve-') || text.includes('wordpress') || text.includes('joomla') || text.includes('drupal') || text.includes('supply chain')) {
    return 'A03:2025';
  }
  if (text.includes('brute') || text.includes('credential') || text.includes('authentication') || text.includes('login') || text.includes('session') || text.includes('password')) {
    return 'A07:2025';
  }
  if (text.includes('deserialization') || text.includes('integrity') || text.includes('upload')) {
    return 'A08:2025';
  }
  if (text.includes('stack trace') || text.includes('exception') || text.includes('error') || text.includes('500')) {
    return 'A10:2025';
  }
  if (text.includes('log') || text.includes('monitoring') || text.includes('alerting')) {
    return 'A09:2025';
  }
  if (text.includes('rate limit') || text.includes('design') || text.includes('business logic')) {
    return 'A06:2025';
  }
  
  return 'A02:2025'; // Default to misconfiguration for unclassified findings
}
