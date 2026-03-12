/**
 * Offensive Security Tools Knowledge Module
 *
 * Comprehensive taxonomy of offensive security tools organized by category,
 * extracted from Offensive Linux Security Tools (hackingarticles.in) and
 * Bug Bounty Tools reference charts. Provides context injection for the
 * AI attack planner and engagement orchestrator.
 */

// ─── Tool Categories ──────────────────────────────────────────────────────

export interface OffensiveTool {
  name: string;
  category: ToolCategory;
  subcategory?: string;
  description: string;
  /** When to use this tool */
  useCase: string;
  /** CLI command pattern */
  cliPattern?: string;
  /** Applicable training labs */
  applicableLabs?: string[];
  /** MITRE ATT&CK tactics */
  tactics?: string[];
}

export type ToolCategory =
  | "reconnaissance"
  | "vulnerability_scanning"
  | "exploitation"
  | "post_exploitation"
  | "wireless"
  | "social_engineering"
  | "webapp_pentesting"
  | "reporting"
  | "network_attacks"
  | "password_bruteforce"
  | "mobile_security"
  | "reverse_engineering"
  | "content_discovery"
  | "api_testing"
  | "cloud_security"
  | "container_security"
  | "fuzzing"
  | "proxy_interception"
  | "sast_dast";

// ─── Complete Tool Database ───────────────────────────────────────────────

export const OFFENSIVE_TOOLS: OffensiveTool[] = [
  // ── Reconnaissance ──
  { name: "Nmap", category: "reconnaissance", description: "Network mapper for host discovery, port scanning, service/OS detection", useCase: "Initial network reconnaissance, port scanning, service enumeration", cliPattern: "nmap -sV -sC -T4 {target}", applicableLabs: ["dvwa", "bwapp", "mutillidae", "crapi", "juice-shop", "webgoat"], tactics: ["TA0043"] },
  { name: "Masscan", category: "reconnaissance", description: "Fastest Internet port scanner, transmits 10M packets/sec", useCase: "Large-scale port scanning, fast initial recon of wide IP ranges", cliPattern: "masscan {target} -p1-65535 --rate=10000", tactics: ["TA0043"] },
  { name: "Recon-ng", category: "reconnaissance", description: "Full-featured web reconnaissance framework", useCase: "OSINT gathering, domain enumeration, contact harvesting", cliPattern: "recon-ng -w {workspace}", tactics: ["TA0043"] },
  { name: "theHarvester", category: "reconnaissance", description: "E-mail, subdomain, and name harvester from public sources", useCase: "Email harvesting, subdomain enumeration from search engines", cliPattern: "theHarvester -d {domain} -b all", tactics: ["TA0043"] },
  { name: "Amass", category: "reconnaissance", description: "In-depth attack surface mapping and asset discovery", useCase: "Subdomain enumeration, DNS brute forcing, ASN discovery", cliPattern: "amass enum -d {domain}", tactics: ["TA0043"] },
  { name: "Subfinder", category: "reconnaissance", description: "Fast passive subdomain enumeration tool", useCase: "Quick subdomain discovery from passive sources", cliPattern: "subfinder -d {domain} -o subs.txt", tactics: ["TA0043"] },
  { name: "DNSRecon", category: "reconnaissance", description: "DNS enumeration and zone transfer testing", useCase: "DNS record enumeration, zone transfer attempts, DNSSEC testing", cliPattern: "dnsrecon -d {domain} -t std,brt", tactics: ["TA0043"] },
  { name: "Maltego", category: "reconnaissance", description: "Interactive data mining and link analysis", useCase: "Visual OSINT analysis, relationship mapping between entities", tactics: ["TA0043"] },
  { name: "Shodan", category: "reconnaissance", description: "Search engine for Internet-connected devices", useCase: "Finding exposed services, IoT devices, known vulnerabilities on targets", cliPattern: "shodan search hostname:{target}", applicableLabs: ["crapi"], tactics: ["TA0043"] },
  { name: "Censys", category: "reconnaissance", description: "Internet-wide scanning and certificate transparency search", useCase: "Certificate discovery, exposed service enumeration", tactics: ["TA0043"] },
  { name: "SpiderFoot", category: "reconnaissance", description: "Automated OSINT collection tool", useCase: "Automated reconnaissance across 200+ data sources", cliPattern: "spiderfoot -s {target} -t all", tactics: ["TA0043"] },
  { name: "ZMap", category: "reconnaissance", description: "Fast single-packet network scanner", useCase: "Internet-wide scanning for specific ports", cliPattern: "zmap -p {port} {target_range}", tactics: ["TA0043"] },
  { name: "Netdiscover", category: "reconnaissance", description: "Active/passive ARP reconnaissance tool", useCase: "LAN host discovery via ARP scanning", cliPattern: "netdiscover -r {subnet}", tactics: ["TA0043"] },
  { name: "p0f", category: "reconnaissance", description: "Passive OS fingerprinting tool", useCase: "Passive OS detection without sending packets", tactics: ["TA0043"] },

  // ── Vulnerability Scanning ──
  { name: "Nuclei", category: "vulnerability_scanning", description: "Fast vulnerability scanner based on YAML templates", useCase: "Template-based vuln scanning, CVE detection, misconfig detection", cliPattern: "nuclei -u {target} -severity critical,high -t cves/", applicableLabs: ["dvwa", "bwapp", "mutillidae", "crapi", "juice-shop", "webgoat"], tactics: ["TA0043"] },
  { name: "Nikto", category: "vulnerability_scanning", description: "Web server scanner for dangerous files, outdated software", useCase: "Web server misconfiguration detection, default file discovery", cliPattern: "nikto -h {target}", applicableLabs: ["dvwa", "bwapp", "mutillidae"], tactics: ["TA0043"] },
  { name: "OpenVAS", category: "vulnerability_scanning", description: "Full-featured vulnerability scanner (Greenbone)", useCase: "Comprehensive vulnerability assessment with authenticated scans", tactics: ["TA0043"] },
  { name: "Nessus", category: "vulnerability_scanning", description: "Commercial vulnerability scanner by Tenable", useCase: "Enterprise vulnerability scanning, compliance checks", tactics: ["TA0043"] },
  { name: "w3af", category: "vulnerability_scanning", description: "Web application attack and audit framework", useCase: "Automated web app vulnerability scanning", cliPattern: "w3af_console", applicableLabs: ["dvwa", "bwapp", "mutillidae"], tactics: ["TA0043"] },
  { name: "Vuls", category: "vulnerability_scanning", description: "Agentless vulnerability scanner for Linux/FreeBSD", useCase: "Server vulnerability scanning without agents", tactics: ["TA0043"] },
  { name: "OWASP ZAP", category: "vulnerability_scanning", description: "Web app security scanner with active/passive scanning", useCase: "Automated web app scanning, spider, active scan, fuzzing", cliPattern: "zap-cli quick-scan {target}", applicableLabs: ["dvwa", "bwapp", "mutillidae", "crapi", "juice-shop", "webgoat"], tactics: ["TA0043"] },
  { name: "Burp Suite", category: "vulnerability_scanning", description: "Integrated platform for web app security testing", useCase: "Manual + automated web testing, proxy interception, scanning", applicableLabs: ["dvwa", "bwapp", "mutillidae", "crapi", "juice-shop", "webgoat"], tactics: ["TA0043"] },

  // ── Exploitation ──
  { name: "Metasploit", category: "exploitation", description: "Penetration testing framework with 2000+ exploits", useCase: "Exploit development and delivery, post-exploitation, pivoting", cliPattern: "msfconsole -x 'use {module}; set RHOSTS {target}; exploit'", applicableLabs: ["dvwa", "bwapp", "mutillidae"], tactics: ["TA0002", "TA0004"] },
  { name: "sqlmap", category: "exploitation", description: "Automatic SQL injection and database takeover tool", useCase: "SQL injection detection, exploitation, database dumping", cliPattern: "sqlmap -u '{url}' --batch --dbs", applicableLabs: ["dvwa", "bwapp", "mutillidae", "juice-shop"], tactics: ["TA0001"] },
  { name: "Commix", category: "exploitation", description: "Automated OS command injection exploitation", useCase: "Command injection detection and exploitation", cliPattern: "commix --url='{url}' --data='{params}'", applicableLabs: ["bwapp", "mutillidae"], tactics: ["TA0002"] },
  { name: "XSSer", category: "exploitation", description: "Automatic XSS detection and exploitation framework", useCase: "Cross-site scripting vulnerability detection and exploitation", cliPattern: "xsser --url '{url}' --auto", applicableLabs: ["dvwa", "bwapp", "mutillidae", "juice-shop"], tactics: ["TA0001"] },
  { name: "BeEF", category: "exploitation", description: "Browser Exploitation Framework for client-side attacks", useCase: "Browser hooking, XSS exploitation, client-side attack delivery", applicableLabs: ["dvwa", "bwapp", "mutillidae"], tactics: ["TA0001"] },
  { name: "SearchSploit", category: "exploitation", description: "Command-line search for Exploit-DB exploits", useCase: "Finding known exploits for identified services/versions", cliPattern: "searchsploit {service} {version}", tactics: ["TA0001"] },
  { name: "RouterSploit", category: "exploitation", description: "Exploitation framework for embedded devices/routers", useCase: "Router and IoT device exploitation", tactics: ["TA0001"] },
  { name: "Armitage", category: "exploitation", description: "GUI for Metasploit with visualization", useCase: "Visual exploitation management, team collaboration", tactics: ["TA0002"] },
  { name: "ysoserial", category: "exploitation", description: "Java deserialization exploit generator", useCase: "Generating payloads for Java deserialization vulnerabilities", cliPattern: "java -jar ysoserial.jar {gadget} '{command}'", tactics: ["TA0002"] },
  { name: "Pwntools", category: "exploitation", description: "CTF framework and exploit development library (Python)", useCase: "Binary exploitation, ROP chain building, shellcode generation", tactics: ["TA0002"] },
  { name: "Ropper", category: "exploitation", description: "ROP gadget finder and chain builder", useCase: "Finding ROP/JOP gadgets for binary exploitation", tactics: ["TA0002"] },
  { name: "ShellNoob", category: "exploitation", description: "Shellcode writing toolkit", useCase: "Writing, testing, and converting shellcode", tactics: ["TA0002"] },
  { name: "jSQL Injection", category: "exploitation", description: "Java-based automatic SQL injection tool", useCase: "GUI-based SQL injection testing", applicableLabs: ["dvwa", "bwapp", "mutillidae"], tactics: ["TA0001"] },
  { name: "NoSQLMap", category: "exploitation", description: "Automated NoSQL injection and exploitation", useCase: "MongoDB, CouchDB injection testing", cliPattern: "nosqlmap -u '{url}'", applicableLabs: ["crapi"], tactics: ["TA0001"] },
  { name: "Dalfox", category: "exploitation", description: "Fast XSS scanning and parameter analysis tool", useCase: "Advanced XSS detection with DOM analysis", cliPattern: "dalfox url '{url}'", applicableLabs: ["dvwa", "bwapp", "mutillidae", "juice-shop"], tactics: ["TA0001"] },
  { name: "SSRFmap", category: "exploitation", description: "Automatic SSRF fuzzer and exploitation tool", useCase: "SSRF detection and exploitation with various protocols", cliPattern: "ssrfmap -r request.txt -p url", applicableLabs: ["bwapp", "crapi"], tactics: ["TA0001"] },

  // ── Post-Exploitation ──
  { name: "Meterpreter", category: "post_exploitation", description: "Advanced Metasploit payload for post-exploitation", useCase: "Post-exploitation: file system access, pivoting, credential harvesting", tactics: ["TA0005", "TA0006", "TA0008"] },
  { name: "Mimikatz", category: "post_exploitation", description: "Windows credential extraction tool", useCase: "Extracting passwords, hashes, Kerberos tickets from memory", cliPattern: "mimikatz.exe 'sekurlsa::logonpasswords'", tactics: ["TA0006"] },
  { name: "BloodHound", category: "post_exploitation", description: "Active Directory attack path mapping", useCase: "AD enumeration, finding shortest paths to domain admin", tactics: ["TA0007"] },
  { name: "Empire", category: "post_exploitation", description: "Post-exploitation framework (PowerShell/Python agents)", useCase: "C2 framework, lateral movement, persistence", tactics: ["TA0011", "TA0008"] },
  { name: "Koadic", category: "post_exploitation", description: "COM Command & Control framework (JScript RAT)", useCase: "Windows post-exploitation via COM objects", tactics: ["TA0011"] },
  { name: "Pupy", category: "post_exploitation", description: "Cross-platform remote administration tool", useCase: "Multi-platform C2, in-memory execution", tactics: ["TA0011"] },
  { name: "Pwncat", category: "post_exploitation", description: "Fancy reverse/bind shell handler with auto-enumeration", useCase: "Shell stabilization, auto-enumeration, file transfer", cliPattern: "pwncat-cs -lp {port}", tactics: ["TA0011"] },
  { name: "BeRoot", category: "post_exploitation", description: "Privilege escalation path finder", useCase: "Finding privilege escalation vectors on Windows/Linux", tactics: ["TA0004"] },
  { name: "Dnscat2", category: "post_exploitation", description: "DNS tunneling for C2 communication", useCase: "Exfiltration and C2 over DNS to bypass firewalls", tactics: ["TA0011", "TA0010"] },

  // ── WebApp Pentesting ──
  { name: "WFuzz", category: "webapp_pentesting", description: "Web application fuzzer for brute forcing parameters", useCase: "Parameter fuzzing, directory brute forcing, filter bypass", cliPattern: "wfuzz -c -z file,wordlist.txt --hc 404 {url}/FUZZ", applicableLabs: ["dvwa", "bwapp", "mutillidae", "crapi", "juice-shop"], tactics: ["TA0043"] },
  { name: "ffuf", category: "webapp_pentesting", description: "Fast web fuzzer written in Go", useCase: "Content discovery, parameter fuzzing, virtual host discovery", cliPattern: "ffuf -u {url}/FUZZ -w wordlist.txt -mc 200,301,302", applicableLabs: ["dvwa", "bwapp", "mutillidae", "crapi", "juice-shop", "webgoat"], tactics: ["TA0043"] },
  { name: "Gobuster", category: "webapp_pentesting", description: "Directory/file & DNS busting tool", useCase: "Directory brute forcing, DNS subdomain enumeration", cliPattern: "gobuster dir -u {url} -w wordlist.txt", applicableLabs: ["dvwa", "bwapp", "mutillidae", "crapi", "juice-shop"], tactics: ["TA0043"] },
  { name: "Feroxbuster", category: "webapp_pentesting", description: "Fast, recursive content discovery tool", useCase: "Recursive directory discovery with auto-filtering", cliPattern: "feroxbuster -u {url} -w wordlist.txt", applicableLabs: ["dvwa", "bwapp", "mutillidae", "crapi", "juice-shop"], tactics: ["TA0043"] },
  { name: "Skipfish", category: "webapp_pentesting", description: "Active web application security reconnaissance tool", useCase: "Automated web app crawling and security assessment", cliPattern: "skipfish -o output {url}", applicableLabs: ["dvwa", "bwapp", "mutillidae"], tactics: ["TA0043"] },
  { name: "Whatweb", category: "webapp_pentesting", description: "Web technology fingerprinting tool", useCase: "Identifying web technologies, frameworks, CMS versions", cliPattern: "whatweb {url}", applicableLabs: ["dvwa", "bwapp", "mutillidae", "crapi", "juice-shop", "webgoat"], tactics: ["TA0043"] },
  { name: "Arjun", category: "webapp_pentesting", description: "HTTP parameter discovery suite", useCase: "Finding hidden GET/POST parameters in web apps", cliPattern: "arjun -u {url}", applicableLabs: ["bwapp", "mutillidae", "crapi"], tactics: ["TA0043"] },
  { name: "Kiterunner", category: "webapp_pentesting", description: "API endpoint discovery tool", useCase: "Discovering API routes and endpoints", cliPattern: "kr scan {url} -w routes.kite", applicableLabs: ["crapi"], tactics: ["TA0043"] },

  // ── Content Discovery ──
  { name: "Dirsearch", category: "content_discovery", description: "Web path scanner for directories and files", useCase: "Finding hidden directories, backup files, admin panels", cliPattern: "dirsearch -u {url} -e php,html,js", applicableLabs: ["dvwa", "bwapp", "mutillidae"], tactics: ["TA0043"] },

  // ── Password & Brute Force ──
  { name: "Hydra", category: "password_bruteforce", description: "Fast network logon cracker supporting 50+ protocols", useCase: "Brute forcing login forms, SSH, FTP, HTTP auth", cliPattern: "hydra -l admin -P passwords.txt {target} http-post-form '/login:user=^USER^&pass=^PASS^:F=incorrect'", applicableLabs: ["dvwa", "bwapp", "mutillidae", "juice-shop", "webgoat"], tactics: ["TA0006"] },
  { name: "John the Ripper", category: "password_bruteforce", description: "Password cracker supporting many hash types", useCase: "Cracking password hashes (MD5, SHA, bcrypt, etc.)", cliPattern: "john --wordlist=rockyou.txt hashes.txt", tactics: ["TA0006"] },
  { name: "Hashcat", category: "password_bruteforce", description: "GPU-accelerated password recovery", useCase: "High-speed hash cracking with GPU acceleration", cliPattern: "hashcat -m {mode} -a 0 hashes.txt wordlist.txt", tactics: ["TA0006"] },
  { name: "CeWL", category: "password_bruteforce", description: "Custom wordlist generator from target website", useCase: "Building target-specific wordlists from web content", cliPattern: "cewl {url} -d 2 -m 5 -w wordlist.txt", applicableLabs: ["dvwa", "bwapp", "mutillidae"], tactics: ["TA0006"] },
  { name: "Medusa", category: "password_bruteforce", description: "Speedy, parallel, modular login brute-forcer", useCase: "Parallel brute forcing across multiple protocols", cliPattern: "medusa -h {target} -u admin -P passwords.txt -M http", tactics: ["TA0006"] },
  { name: "Patator", category: "password_bruteforce", description: "Multi-purpose brute-forcer with modular design", useCase: "Flexible brute forcing with custom modules", tactics: ["TA0006"] },
  { name: "crowbar", category: "password_bruteforce", description: "Brute forcing tool for RDP, VNC, SSH key auth", useCase: "Brute forcing services that don't support traditional tools", tactics: ["TA0006"] },

  // ── API Testing ──
  { name: "Postman", category: "api_testing", description: "API development and testing platform", useCase: "Manual API testing, request crafting, collection running", applicableLabs: ["crapi"], tactics: ["TA0043"] },
  { name: "jwt_tool", category: "api_testing", description: "JWT security testing toolkit", useCase: "JWT token analysis, algorithm confusion, none algorithm attacks", cliPattern: "jwt_tool {token} -C -d wordlist.txt", applicableLabs: ["crapi", "juice-shop"], tactics: ["TA0006"] },
  { name: "GraphQL Voyager", category: "api_testing", description: "GraphQL API visual explorer", useCase: "GraphQL schema introspection and visualization", applicableLabs: ["crapi"], tactics: ["TA0043"] },
  { name: "InQL", category: "api_testing", description: "GraphQL security testing tool (Burp extension)", useCase: "GraphQL introspection, query generation, batch attacks", tactics: ["TA0043"] },

  // ── Cloud Security ──
  { name: "ScoutSuite", category: "cloud_security", description: "Multi-cloud security auditing tool", useCase: "AWS/Azure/GCP security configuration auditing", cliPattern: "scout --provider aws", tactics: ["TA0043"] },
  { name: "Prowler", category: "cloud_security", description: "AWS/Azure/GCP security best practices assessment", useCase: "Cloud compliance checking, CIS benchmark auditing", cliPattern: "prowler -M csv", tactics: ["TA0043"] },
  { name: "Pacu", category: "cloud_security", description: "AWS exploitation framework", useCase: "AWS post-exploitation, privilege escalation, data exfiltration", tactics: ["TA0004", "TA0010"] },
  { name: "CloudSploit", category: "cloud_security", description: "Cloud security configuration scanner", useCase: "Detecting misconfigurations in cloud environments", tactics: ["TA0043"] },

  // ── Container Security ──
  { name: "Trivy", category: "container_security", description: "Comprehensive vulnerability scanner for containers", useCase: "Container image scanning, IaC scanning, SBOM generation", cliPattern: "trivy image {image_name}", tactics: ["TA0043"] },
  { name: "Docker Bench", category: "container_security", description: "Docker security best practices checker", useCase: "Auditing Docker host and container configurations", cliPattern: "docker-bench-security", tactics: ["TA0043"] },

  // ── Social Engineering ──
  { name: "Gophish", category: "social_engineering", description: "Open-source phishing framework", useCase: "Phishing campaign management, email template creation", applicableLabs: [], tactics: ["TA0001"] },
  { name: "SET", category: "social_engineering", description: "Social Engineering Toolkit by TrustedSec", useCase: "Spear phishing, website cloning, credential harvesting", cliPattern: "setoolkit", tactics: ["TA0001"] },
  { name: "King Phisher", category: "social_engineering", description: "Phishing campaign toolkit with server/client architecture", useCase: "Advanced phishing campaigns with tracking", tactics: ["TA0001"] },

  // ── Network Attacks ──
  { name: "Wireshark", category: "network_attacks", description: "Network protocol analyzer and packet capture", useCase: "Traffic analysis, credential sniffing, protocol debugging", tactics: ["TA0009"] },
  { name: "Ettercap", category: "network_attacks", description: "Comprehensive suite for MITM attacks", useCase: "ARP poisoning, DNS spoofing, traffic interception", cliPattern: "ettercap -T -M arp:remote /{target1}// /{target2}//", tactics: ["TA0009"] },
  { name: "Scapy", category: "network_attacks", description: "Packet manipulation library and tool (Python)", useCase: "Custom packet crafting, network scanning, protocol testing", tactics: ["TA0043", "TA0009"] },
  { name: "hping3", category: "network_attacks", description: "TCP/IP packet assembler and analyzer", useCase: "Firewall testing, port scanning, packet crafting", cliPattern: "hping3 -S {target} -p {port}", tactics: ["TA0043"] },
  { name: "NetCat", category: "network_attacks", description: "TCP/UDP networking utility (Swiss army knife)", useCase: "Reverse shells, port scanning, file transfer, banner grabbing", cliPattern: "nc -lvnp {port}", tactics: ["TA0011"] },
  { name: "bettercap", category: "network_attacks", description: "Swiss army knife for network attacks and monitoring", useCase: "MITM, WiFi attacks, BLE attacks, network recon", tactics: ["TA0009"] },

  // ── Wireless ──
  { name: "Aircrack-ng", category: "wireless", description: "WiFi security auditing suite", useCase: "WiFi cracking (WEP/WPA/WPA2), packet capture, deauth", cliPattern: "aircrack-ng -w wordlist.txt capture.cap", tactics: ["TA0001"] },
  { name: "Wifite", category: "wireless", description: "Automated WiFi auditing tool", useCase: "Automated WiFi attack workflows", cliPattern: "wifite --kill", tactics: ["TA0001"] },
  { name: "Kismet", category: "wireless", description: "Wireless network detector, sniffer, and IDS", useCase: "Passive WiFi reconnaissance, hidden network detection", tactics: ["TA0043"] },
  { name: "Reaver", category: "wireless", description: "WPS brute force attack tool", useCase: "Cracking WPS-enabled routers", cliPattern: "reaver -i {interface} -b {bssid} -vv", tactics: ["TA0001"] },

  // ── Proxy/Interception ──
  { name: "mitmproxy", category: "proxy_interception", description: "Interactive HTTPS proxy for debugging and testing", useCase: "HTTP/S traffic interception, modification, replay", cliPattern: "mitmproxy -p 8080", applicableLabs: ["crapi", "juice-shop"], tactics: ["TA0009"] },
  { name: "Caido", category: "proxy_interception", description: "Lightweight web security auditing toolkit", useCase: "Modern alternative to Burp Suite for web testing", applicableLabs: ["dvwa", "bwapp", "mutillidae", "crapi"], tactics: ["TA0043"] },

  // ── Fuzzing ──
  { name: "AFL", category: "fuzzing", description: "American Fuzzy Lop - coverage-guided fuzzer", useCase: "Binary fuzzing for crash/vulnerability discovery", tactics: ["TA0043"] },
  { name: "Boofuzz", category: "fuzzing", description: "Network protocol fuzzing framework (successor to Sulley)", useCase: "Protocol fuzzing, server crash testing", tactics: ["TA0043"] },
  { name: "Radamsa", category: "fuzzing", description: "General-purpose test case mutator/fuzzer", useCase: "File format fuzzing, input mutation", tactics: ["TA0043"] },
  { name: "CRLFuzz", category: "fuzzing", description: "CRLF injection vulnerability scanner", useCase: "Finding CRLF injection points in HTTP headers", cliPattern: "crlfuzz -u {url}", applicableLabs: ["bwapp", "mutillidae"], tactics: ["TA0001"] },

  // ── SAST/DAST ──
  { name: "Semgrep", category: "sast_dast", description: "Lightweight static analysis for many languages", useCase: "Source code security scanning, custom rule writing", cliPattern: "semgrep --config=auto {path}", tactics: ["TA0043"] },
  { name: "SonarQube", category: "sast_dast", description: "Continuous code quality and security platform", useCase: "CI/CD integrated code security scanning", tactics: ["TA0043"] },

  // ── Reporting ──
  { name: "DefectDojo", category: "reporting", description: "Vulnerability management and reporting platform", useCase: "Aggregating scan results, tracking remediation, generating reports", tactics: [] },
  { name: "Faraday", category: "reporting", description: "Collaborative penetration test IDE", useCase: "Multi-user pentest management, tool integration, reporting", tactics: [] },
  { name: "Serpico", category: "reporting", description: "Penetration testing report generation", useCase: "Professional pentest report creation with templates", tactics: [] },
  { name: "Dradis", category: "reporting", description: "Collaboration and reporting for security teams", useCase: "Team collaboration, evidence collection, report generation", tactics: [] },

  // ── Reverse Engineering ──
  { name: "Ghidra", category: "reverse_engineering", description: "NSA's software reverse engineering framework", useCase: "Binary analysis, decompilation, malware analysis", tactics: ["TA0043"] },
  { name: "Radare2", category: "reverse_engineering", description: "Portable reversing framework", useCase: "Binary analysis, debugging, disassembly", cliPattern: "r2 {binary}", tactics: ["TA0043"] },
  { name: "Frida", category: "reverse_engineering", description: "Dynamic instrumentation toolkit", useCase: "Runtime hooking, API tracing, mobile app analysis", cliPattern: "frida -U -f {package} -l script.js", tactics: ["TA0043"] },
  { name: "Angr", category: "reverse_engineering", description: "Binary analysis platform (Python)", useCase: "Symbolic execution, vulnerability discovery in binaries", tactics: ["TA0043"] },

  // ── Mobile Security ──
  { name: "MobSF", category: "mobile_security", description: "Mobile Security Framework - automated analysis", useCase: "Android/iOS app static and dynamic analysis", tactics: ["TA0043"] },
  { name: "Drozer", category: "mobile_security", description: "Android security assessment framework", useCase: "Android app attack surface analysis, IPC testing", cliPattern: "drozer console connect", tactics: ["TA0043"] },
  { name: "Apktool", category: "mobile_security", description: "Android APK reverse engineering tool", useCase: "Decompiling and rebuilding Android apps", cliPattern: "apktool d {apk_file}", tactics: ["TA0043"] },
];

// ─── Context Builders ─────────────────────────────────────────────────────

/**
 * Get tools recommended for a specific training lab target.
 */
export function getToolsForLab(labId: string): OffensiveTool[] {
  return OFFENSIVE_TOOLS.filter(t => t.applicableLabs?.includes(labId));
}

/**
 * Get tools by category.
 */
export function getToolsByCategory(category: ToolCategory): OffensiveTool[] {
  return OFFENSIVE_TOOLS.filter(t => t.category === category);
}

/**
 * Build a context string for the LLM with tool recommendations based on the engagement phase.
 */
export function buildToolRecommendationContext(params: {
  phase: string;
  targetLab?: string;
  detectedTech?: string[];
  hasWebApp?: boolean;
  hasAPI?: boolean;
}): string {
  const sections: string[] = [];

  // Phase-specific tool recommendations
  const phaseToolMap: Record<string, ToolCategory[]> = {
    reconnaissance: ["reconnaissance", "content_discovery"],
    enumeration: ["vulnerability_scanning", "webapp_pentesting", "content_discovery", "api_testing"],
    scanning: ["vulnerability_scanning", "webapp_pentesting", "fuzzing"],
    exploitation: ["exploitation", "password_bruteforce"],
    post_exploit: ["post_exploitation", "network_attacks"],
  };

  const relevantCategories = phaseToolMap[params.phase] || ["vulnerability_scanning", "exploitation"];

  // Get phase-relevant tools
  let tools = OFFENSIVE_TOOLS.filter(t => relevantCategories.includes(t.category));

  // Filter by lab if specified
  if (params.targetLab) {
    const labTools = tools.filter(t => t.applicableLabs?.includes(params.targetLab!));
    if (labTools.length > 0) tools = labTools;
  }

  // Add API-specific tools if API target detected
  if (params.hasAPI) {
    const apiTools = OFFENSIVE_TOOLS.filter(t => t.category === "api_testing");
    tools = [...tools, ...apiTools];
  }

  // Deduplicate
  const seen = new Set<string>();
  tools = tools.filter(t => {
    if (seen.has(t.name)) return false;
    seen.add(t.name);
    return true;
  });

  // Build context string
  sections.push(`## Offensive Security Tools — ${params.phase} Phase`);

  if (params.targetLab) {
    sections.push(`\nRecommended tools for ${params.targetLab}:`);
  }

  // Group by category
  const grouped: Record<string, OffensiveTool[]> = {};
  for (const t of tools.slice(0, 25)) {
    const cat = t.category;
    if (!grouped[cat]) grouped[cat] = [];
    grouped[cat].push(t);
  }

  for (const [cat, catTools] of Object.entries(grouped)) {
    const catName = cat.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
    sections.push(`\n### ${catName}`);
    for (const t of catTools) {
      let line = `- **${t.name}**: ${t.useCase}`;
      if (t.cliPattern) line += ` | CLI: \`${t.cliPattern}\``;
      sections.push(line);
    }
  }

  return sections.join("\n");
}

/**
 * Build a comprehensive tool knowledge context for the AI attack planner.
 */
export function buildAttackPlannerToolContext(targetLab?: string): string {
  const sections: string[] = [];
  sections.push("## Available Offensive Security Tools");
  sections.push("The following tools are available for use during engagements:\n");

  // Summarize by category
  const categories = [...new Set(OFFENSIVE_TOOLS.map(t => t.category))];
  for (const cat of categories) {
    const catTools = OFFENSIVE_TOOLS.filter(t => t.category === cat);
    const catName = cat.replace(/_/g, " ").replace(/\b\w/g, c => c.toUpperCase());
    const toolNames = catTools.map(t => t.name).join(", ");
    sections.push(`- **${catName}** (${catTools.length}): ${toolNames}`);
  }

  // Lab-specific recommendations
  if (targetLab) {
    const labTools = getToolsForLab(targetLab);
    if (labTools.length > 0) {
      sections.push(`\n### Recommended for ${targetLab}:`);
      for (const t of labTools) {
        let line = `- **${t.name}** (${t.category}): ${t.useCase}`;
        if (t.cliPattern) line += `\n  CLI: \`${t.cliPattern}\``;
        sections.push(line);
      }
    }
  }

  return sections.join("\n");
}

/**
 * Search tools by name or description keyword.
 */
export function searchTools(query: string): OffensiveTool[] {
  const q = query.toLowerCase();
  return OFFENSIVE_TOOLS.filter(t =>
    t.name.toLowerCase().includes(q) ||
    t.description.toLowerCase().includes(q) ||
    t.useCase.toLowerCase().includes(q) ||
    t.category.includes(q)
  );
}

/**
 * Get tool statistics summary.
 */
export function getToolStats(): { totalTools: number; categories: Record<string, number>; labCoverage: Record<string, number> } {
  const categories: Record<string, number> = {};
  const labCoverage: Record<string, number> = {};

  for (const t of OFFENSIVE_TOOLS) {
    categories[t.category] = (categories[t.category] || 0) + 1;
    for (const lab of (t.applicableLabs || [])) {
      labCoverage[lab] = (labCoverage[lab] || 0) + 1;
    }
  }

  return { totalTools: OFFENSIVE_TOOLS.length, categories, labCoverage };
}
