/**
 * Offensive Techniques Knowledge Module
 *
 * Structured knowledge extracted from curated offensive security cheat sheets:
 *   1. Living Off the Land (LOTL) resources — binary abuse, driver abuse, API abuse
 *   2. File Upload Extension Filter Bypass — extension splitting, null bytes, encoding tricks
 *   3. Firewall Testing & Evasion — 25 tools mapped to techniques
 *   4. Social Engineering Attack Taxonomy — 5 categories, 35 sub-techniques
 *   5. Shodan Filters & Queries — CLI commands, filters, pre-built search queries
 *   6. Subdomain Enumeration Tools — 40+ tools with descriptions
 *
 * Each section exports a context-builder function that returns a formatted string
 * suitable for injection into LLM system prompts. The orchestrator picks the
 * relevant sections based on engagement phase and target characteristics.
 */

// ─── 1. Living Off the Land (LOTL) Resources ───────────────────────────────

export interface LOTLResource {
  name: string;
  url: string;
  platform: "windows" | "linux" | "macos" | "cross-platform";
  category: string;
  description: string;
  mitreTechniques: string[];
}

const LOTL_RESOURCES: LOTLResource[] = [
  {
    name: "GTFOBins",
    url: "https://gtfobins.github.io",
    platform: "linux",
    category: "Unix binary abuse",
    description: "Curated list of Unix binaries that can be used to bypass local security restrictions in misconfigured systems. Covers SUID, sudo, capabilities, file read/write, reverse shells, and bind shells.",
    mitreTechniques: ["T1059.004", "T1548.001", "T1548.003", "T1222"],
  },
  {
    name: "LOLBAS",
    url: "https://lolbas-project.github.io",
    platform: "windows",
    category: "Windows LOTL binaries",
    description: "Documents every Windows binary, script, and library that can be used for Living Off The Land techniques including execution, persistence, lateral movement, and defense evasion.",
    mitreTechniques: ["T1218", "T1216", "T1202", "T1059.001"],
  },
  {
    name: "LOLDrivers",
    url: "https://loldrivers.io",
    platform: "windows",
    category: "Windows driver abuse",
    description: "Curated list of Windows drivers used by adversaries to bypass security controls (EDR, AV) and carry out kernel-level attacks. Includes vulnerable and malicious drivers.",
    mitreTechniques: ["T1068", "T1014", "T1562.001"],
  },
  {
    name: "LOOBins",
    url: "https://www.loobins.io",
    platform: "macos",
    category: "macOS binary abuse",
    description: "Living Off the Orchard: macOS built-in binaries that can be used by threat actors for malicious purposes including execution, persistence, and exfiltration.",
    mitreTechniques: ["T1059.002", "T1543.004", "T1547.011"],
  },
  {
    name: "MalAPI.io",
    url: "https://malapi.io",
    platform: "windows",
    category: "Windows API abuse",
    description: "Maps Windows APIs to common malware techniques. Useful for understanding how legitimate APIs are weaponized for process injection, credential dumping, and defense evasion.",
    mitreTechniques: ["T1055", "T1003", "T1562"],
  },
  {
    name: "HijackLibs",
    url: "https://hijacklibs.net",
    platform: "windows",
    category: "DLL hijacking",
    description: "Curated list of DLL hijacking candidates. Documents which legitimate applications load DLLs from writable locations, enabling persistence and privilege escalation.",
    mitreTechniques: ["T1574.001", "T1574.002"],
  },
  {
    name: "WADComs",
    url: "https://wadcoms.github.io",
    platform: "windows",
    category: "AD/Windows offensive commands",
    description: "Interactive cheat sheet of offensive security tools and commands for Windows/Active Directory environments. Covers enumeration, exploitation, and lateral movement.",
    mitreTechniques: ["T1087", "T1069", "T1021", "T1558"],
  },
  {
    name: "LOTS Project",
    url: "https://lots-project.com",
    platform: "cross-platform",
    category: "Legitimate domain abuse",
    description: "Catalogs popular legitimate domains that attackers use for phishing, C2, exfiltration, and tool downloading to evade detection. Includes cloud storage, CDNs, and SaaS platforms.",
    mitreTechniques: ["T1102", "T1071.001", "T1567"],
  },
  {
    name: "FileSec.io",
    url: "https://filesec.io",
    platform: "cross-platform",
    category: "Malicious file extensions",
    description: "Catalogs file extensions commonly used by attackers for payload delivery, including double extensions, polyglot files, and uncommon executable formats.",
    mitreTechniques: ["T1204.002", "T1036.007"],
  },
  {
    name: "LoFP",
    url: "https://br0k3nlab/LoFP/",
    platform: "cross-platform",
    category: "False positive identification",
    description: "Auto-generated collection of false positives from popular detection rule sets, categorized by ATT&CK technique, rule source, and data source. Helps distinguish real threats from noise.",
    mitreTechniques: [],
  },
];

export function getLOTLContext(platform?: "windows" | "linux" | "macos"): string {
  const relevant = platform
    ? LOTL_RESOURCES.filter(r => r.platform === platform || r.platform === "cross-platform")
    : LOTL_RESOURCES;

  const formatted = relevant.map(r =>
    `- **${r.name}** (${r.platform}): ${r.description}${r.mitreTechniques.length ? ` [MITRE: ${r.mitreTechniques.join(", ")}]` : ""}`
  ).join("\n");

  return `## Living Off the Land (LOTL) Resources
When planning post-exploitation or lateral movement, leverage legitimate system binaries and drivers to avoid detection:

${formatted}

**Key Principle:** Prefer LOTL techniques over dropping custom tools. They blend with normal system activity and are harder to detect.${platform === 'windows' ? ' Check LOLBAS for Windows binaries, LOLDrivers for driver abuse, and WADComs for AD attacks.' : platform === 'linux' ? ' Check GTFOBins for Unix binary abuse and privilege escalation.' : platform === 'macos' ? ' Check LOOBins for macOS native binary abuse.' : ' Check GTFOBins (Linux), LOLBAS (Windows), or LOOBins (macOS) before writing custom payloads.'}`;
}

// ─── 2. File Upload Extension Filter Bypass ─────────────────────────────────

export interface FileUploadBypassCategory {
  name: string;
  description: string;
  character: string;
  hexValue: string;
  payloads: string[];
}

const FILE_UPLOAD_BYPASS_TECHNIQUES: FileUploadBypassCategory[] = [
  {
    name: "Null Byte Injection",
    description: "Terminates the filename string early, causing the server to ignore the safe extension",
    character: "NULL (0x00)",
    hexValue: "0x00",
    payloads: ["shell.php%00.png", "shell.php\\x00.png", "shell.php\\00.png", "shell.php&#00;.png", "shell.php&#x00;.png", "shell.php\\u0000.png"],
  },
  {
    name: "Newline (LF) Injection",
    description: "Injects line feed character between extensions to confuse parsers",
    character: "LF (0x0A)",
    hexValue: "0x0A",
    payloads: ["shell.php%0a.png", "shell.php\\n.png", "shell.php\\x0a.png", "shell.php&#10;.png", "shell.php&#x0a;.png", "shell.php\\u000a.png"],
  },
  {
    name: "Carriage Return (CR) Injection",
    description: "Injects carriage return character to split the extension parsing",
    character: "CR (0x0D)",
    hexValue: "0x0D",
    payloads: ["shell.php%0d.png", "shell.php\\r.png", "shell.php\\x0d.png", "shell.php&#13;.png", "shell.php&#x0d;.png", "shell.php\\u000d.png"],
  },
  {
    name: "Tab Injection",
    description: "Injects horizontal tab character between extensions",
    character: "TAB (0x09)",
    hexValue: "0x09",
    payloads: ["shell.php%09.png", "shell.php\\t.png", "shell.php\\x09.png", "shell.php&#09;.png", "shell.php&#x09;.png", "shell.php\\u0009.png"],
  },
  {
    name: "Hash/Fragment Injection",
    description: "Uses URL fragment identifier to truncate the safe extension",
    character: "# (0x23)",
    hexValue: "0x23",
    payloads: ["shell.php#.png", "shell.php%23.png", "shell.php\\x23.png", "shell.php&#35;.png", "shell.php&#x23;.png", "shell.php\\u0023.png"],
  },
  {
    name: "Semicolon Injection",
    description: "Uses semicolon to split filename interpretation (Apache, IIS)",
    character: "; (0x3B)",
    hexValue: "0x3B",
    payloads: ["shell.php;.png", "shell.php%3B.png", "shell.php\\x3B.png", "shell.php&#59;.png", "shell.php&#x3b;.png", "shell.php\\u003b.png"],
  },
  {
    name: "Space Injection",
    description: "Trailing space can cause extension mismatch on certain OS/servers",
    character: "SPACE (0x20)",
    hexValue: "0x20",
    payloads: ["shell.php .png", "shell.php%20.png", "shell.php\\x20.png", "shell.php&#20;.png", "shell.php&#x20;.png", "shell.php\\u0020.png"],
  },
  {
    name: "Unicode Overlong Encoding",
    description: "Uses overlong UTF-8 sequences to bypass ASCII-based extension checks",
    character: "Various",
    hexValue: "multi-byte",
    payloads: ["shell.php%C0%8d.png", "shell.php%C0%8a.png", "shell.php%C0%80.png", "shell.php%E5%98%8d.png", "shell.php%E0%80%8d.png"],
  },
];

export function getFileUploadBypassContext(): string {
  const formatted = FILE_UPLOAD_BYPASS_TECHNIQUES.map(t =>
    `### ${t.name}
**Character:** ${t.character} | **Hex:** ${t.hexValue}
**Description:** ${t.description}
**Payloads:** ${t.payloads.slice(0, 4).join(", ")}`
  ).join("\n\n");

  return `## File Upload Extension Filter Bypass Techniques
When testing file upload functionality, use extension splitting to bypass server-side filters:

${formatted}

**Strategy:** Start with null byte (%00), then newline/CR, then Unicode overlong. Test each encoding variant. Goal: server sees ".php" while filter sees ".png".

**Additional Techniques:**
- Double extensions: shell.php.png, shell.png.php
- Case variation: shell.pHp, shell.PHP
- Alternate extensions: shell.phtml, shell.php5, shell.phar
- Content-Type mismatch: Upload .php with Content-Type: image/png
- Magic bytes: Prepend PNG header to PHP file`;
}

// ─── 3. Firewall Testing & Evasion ─────────────────────────────────────────

export interface FirewallTestingTool {
  id: number;
  technique: string;
  tool: string;
  url: string;
  category: "scanning" | "evasion" | "tunneling" | "interception" | "injection" | "waf";
  mitreTechniques: string[];
}

const FIREWALL_TESTING_TOOLS: FirewallTestingTool[] = [
  { id: 1, technique: "Port scanning", tool: "Nmap", url: "https://nmap.org/", category: "scanning", mitreTechniques: ["T1046"] },
  { id: 2, technique: "OS fingerprinting", tool: "Xprobe2", url: "http://xprobe.sourceforge.net/", category: "scanning", mitreTechniques: ["T1082"] },
  { id: 3, technique: "Firewall rule testing", tool: "Firewalk", url: "https://github.com/defunkt/firewalk", category: "evasion", mitreTechniques: ["T1046"] },
  { id: 4, technique: "Packet fragmentation evasion", tool: "Fragroute", url: "https://github.com/plitex/fragroute", category: "evasion", mitreTechniques: ["T1027.013"] },
  { id: 5, technique: "IP spoofing", tool: "Hping3", url: "https://github.com/antirez/hping", category: "evasion", mitreTechniques: ["T1090"] },
  { id: 6, technique: "Protocol-specific evasion", tool: "Metasploit", url: "https://www.metasploit.com/", category: "evasion", mitreTechniques: ["T1190"] },
  { id: 7, technique: "ICMP tunneling", tool: "ICMPTX", url: "http://thomer.com/icmptx/", category: "tunneling", mitreTechniques: ["T1572"] },
  { id: 8, technique: "DNS tunneling", tool: "Dns2tcp", url: "https://github.com/alex-sector/dns2tcp", category: "tunneling", mitreTechniques: ["T1572", "T1071.004"] },
  { id: 9, technique: "HTTP tunneling", tool: "HTTPTunnel", url: "https://github.com/larsbrinkhoff/httptunnel", category: "tunneling", mitreTechniques: ["T1572", "T1071.001"] },
  { id: 10, technique: "IPv6 tunneling", tool: "Teredo", url: "https://tools.ietf.org/html/rfc4380", category: "tunneling", mitreTechniques: ["T1572"] },
  { id: 11, technique: "ARP spoofing", tool: "Ettercap", url: "https://www.ettercap-project.org/", category: "interception", mitreTechniques: ["T1557.002"] },
  { id: 12, technique: "SSL/TLS interception", tool: "SSLstrip", url: "https://github.com/moxie0/sslstrip", category: "interception", mitreTechniques: ["T1557.002"] },
  { id: 13, technique: "SSL/TLS decryption", tool: "Wireshark", url: "https://www.wireshark.org/", category: "interception", mitreTechniques: ["T1040"] },
  { id: 14, technique: "SSH tunneling", tool: "OpenSSH", url: "https://www.openssh.com/", category: "tunneling", mitreTechniques: ["T1572"] },
  { id: 15, technique: "Proxy server evasion", tool: "Proxychains", url: "https://github.com/rofl0r/proxychains-ng", category: "evasion", mitreTechniques: ["T1090.003"] },
  { id: 16, technique: "TOR network evasion", tool: "Tor Browser", url: "https://www.torproject.org/", category: "evasion", mitreTechniques: ["T1090.003"] },
  { id: 17, technique: "WAF testing", tool: "Wafw00f", url: "https://github.com/EnableSecurity/wafw00f", category: "waf", mitreTechniques: ["T1595.002"] },
  { id: 18, technique: "Session hijacking", tool: "Cookie Cadger", url: "https://github.com/cookiecadger/CookieCadger", category: "interception", mitreTechniques: ["T1539"] },
  { id: 19, technique: "Man-in-the-middle", tool: "Bettercap", url: "https://www.bettercap.org/", category: "interception", mitreTechniques: ["T1557"] },
  { id: 20, technique: "VPN detection", tool: "Iodine", url: "https://github.com/yarrick/iodine", category: "tunneling", mitreTechniques: ["T1572"] },
  { id: 21, technique: "Firewall evasion (encrypted)", tool: "Veil-Evasion", url: "https://github.com/Veil-Framework/Veil", category: "evasion", mitreTechniques: ["T1027", "T1140"] },
  { id: 22, technique: "SQL injection evasion", tool: "SQLMap", url: "https://sqlmap.org/", category: "injection", mitreTechniques: ["T1190"] },
  { id: 23, technique: "XSS evasion", tool: "XSSer", url: "https://github.com/epsylon/xsser", category: "injection", mitreTechniques: ["T1059.007"] },
  { id: 24, technique: "File type evasion", tool: "FuzzDB", url: "https://github.com/fuzzdb-project/fuzzdb", category: "evasion", mitreTechniques: ["T1036"] },
  { id: 25, technique: "Web service scanning", tool: "Nikto", url: "https://github.com/sullo/nikto", category: "scanning", mitreTechniques: ["T1595.002"] },
];

export function getFirewallEvasionContext(hasFirewall?: boolean, hasWAF?: boolean): string {
  let tools = FIREWALL_TESTING_TOOLS;
  if (hasWAF) {
    tools = [
      ...tools.filter(t => t.category === "waf"),
      ...tools.filter(t => t.category === "evasion"),
      ...tools.filter(t => t.category === "tunneling"),
      ...tools.filter(t => t.category !== "waf" && t.category !== "evasion" && t.category !== "tunneling"),
    ];
  } else if (hasFirewall) {
    tools = [
      ...tools.filter(t => t.category === "evasion"),
      ...tools.filter(t => t.category === "tunneling"),
      ...tools.filter(t => t.category !== "evasion" && t.category !== "tunneling"),
    ];
  }

  const formatted = tools.map(t =>
    `${t.id}. **${t.technique}** -> ${t.tool} [${t.category}] [MITRE: ${t.mitreTechniques.join(", ")}]`
  ).join("\n");

  return `## Firewall & WAF Testing/Evasion Checklist
${hasWAF ? "WAF DETECTED - prioritize WAF bypass techniques before active scanning." : ""}
${hasFirewall ? "Firewall detected - consider evasion and tunneling techniques." : ""}

${formatted}

**Evasion Strategy:**
1. Detect first: Use Wafw00f to identify WAF vendor, then tailor bypass payloads
2. Fragment packets: Use Fragroute/Nmap -f to split payloads across fragments
3. Tunnel traffic: If ports are filtered, try DNS tunneling (Dns2tcp/Iodine) or HTTP tunneling
4. Encode payloads: Use Veil-Evasion for encrypted payloads that bypass signature detection
5. Timing: Use slow scan rates (Nmap -T1/-T2) to avoid rate-based detection
6. Source spoofing: Use decoy IPs (Nmap -D) and source port spoofing (--source-port 53/80)`;
}

// ─── 4. Social Engineering Attack Taxonomy ──────────────────────────────────

export interface SocialEngineeringCategory {
  name: string;
  description: string;
  mitreTechnique: string;
  subTechniques: Array<{ name: string; description: string; indicators: string[] }>;
}

const SOCIAL_ENGINEERING_TAXONOMY: SocialEngineeringCategory[] = [
  {
    name: "Phishing",
    description: "Deceptive communications designed to trick targets into revealing credentials, clicking malicious links, or downloading malware.",
    mitreTechnique: "T1566",
    subTechniques: [
      { name: "Spear Phishing", description: "Targeted phishing aimed at specific individuals using personalized content", indicators: ["personalized greeting", "internal knowledge", "urgency"] },
      { name: "Vishing", description: "Voice-based phishing via phone calls impersonating trusted entities", indicators: ["caller ID spoofing", "urgency", "request for credentials"] },
      { name: "Smishing", description: "SMS-based phishing with malicious links or social engineering", indicators: ["shortened URLs", "urgency", "unknown sender"] },
      { name: "Clone Phishing", description: "Duplicating a legitimate email and replacing links/attachments with malicious ones", indicators: ["re-sent email", "updated attachment", "similar sender"] },
      { name: "Link Manipulation", description: "Using URL obfuscation, homograph attacks, or open redirects to disguise malicious links", indicators: ["punycode domains", "URL shorteners", "open redirects"] },
      { name: "Watering Hole Attack", description: "Compromising websites frequently visited by the target group", indicators: ["compromised trusted site", "drive-by download", "exploit kit"] },
      { name: "Business Email Compromise (BEC)", description: "Impersonating executives or vendors to authorize fraudulent transactions", indicators: ["CEO impersonation", "wire transfer request", "domain lookalike"] },
    ],
  },
  {
    name: "Pretexting",
    description: "Creating a fabricated scenario to engage the target and extract information or gain access.",
    mitreTechnique: "T1598",
    subTechniques: [
      { name: "Tech Support Scam", description: "Impersonating IT support to gain remote access or credentials", indicators: ["unsolicited call", "remote access request", "urgency"] },
      { name: "CEO Fraud Scam", description: "Impersonating C-level executives to authorize actions", indicators: ["executive impersonation", "confidentiality request", "wire transfer"] },
      { name: "Trust Scam", description: "Building long-term trust before exploiting the relationship", indicators: ["gradual escalation", "personal relationship", "delayed request"] },
      { name: "Job Scam", description: "Fake job offers to extract personal information or install malware", indicators: ["too-good-to-be-true offer", "upfront payment", "personal data request"] },
      { name: "Relationship Scam", description: "Romance-based social engineering for financial exploitation", indicators: ["online-only relationship", "financial requests", "emotional manipulation"] },
      { name: "Charity Scam", description: "Exploiting charitable instincts during disasters or crises", indicators: ["disaster timing", "emotional appeal", "unverified organization"] },
      { name: "Lottery Scam", description: "False prize notifications requiring fees or personal information", indicators: ["unsolicited win", "advance fee", "personal data request"] },
    ],
  },
  {
    name: "Baiting",
    description: "Luring targets with something enticing to deliver malware or gain access.",
    mitreTechnique: "T1091",
    subTechniques: [
      { name: "USB Drop Attack", description: "Leaving infected USB drives in target locations", indicators: ["found USB drive", "curiosity trigger", "auto-run payload"] },
      { name: "Fake WiFi Hotspot", description: "Setting up rogue access points to intercept traffic", indicators: ["free WiFi", "no password", "similar SSID"] },
      { name: "Evil Twin Attack", description: "Cloning a legitimate WiFi network to capture credentials", indicators: ["duplicate SSID", "stronger signal", "captive portal"] },
      { name: "QR Code Scam", description: "Malicious QR codes placed over legitimate ones", indicators: ["sticker over original", "redirects to unknown site", "requests permissions"] },
      { name: "Social Media Scam", description: "Malicious content distributed via social platforms", indicators: ["viral content", "click-bait", "shortened URLs"] },
      { name: "Free Gift Scam", description: "Offering free items in exchange for personal information", indicators: ["too-good-to-be-true", "personal data request", "shipping fee"] },
      { name: "Black Hat SEO", description: "Poisoning search results to lead targets to malicious sites", indicators: ["trending topics", "SEO-optimized malware pages", "drive-by downloads"] },
    ],
  },
  {
    name: "Quid Pro Quo",
    description: "Offering a service or benefit in exchange for information or access.",
    mitreTechnique: "T1598.003",
    subTechniques: [
      { name: "Conference Scam", description: "Fake conference invitations to extract registration data", indicators: ["fake event", "registration fee", "personal data collection"] },
      { name: "Customer Service Scam", description: "Impersonating customer service to extract account details", indicators: ["unsolicited contact", "account verification", "credential request"] },
      { name: "Fake Software Scam", description: "Offering free software that contains malware", indicators: ["cracked software", "free premium tools", "unsigned executables"] },
      { name: "IT Support Scam", description: "Offering fake IT assistance to install backdoors or steal credentials", indicators: ["unsolicited help", "remote access tool", "credential request"] },
    ],
  },
  {
    name: "Tailgating",
    description: "Physical social engineering techniques to gain unauthorized access to restricted areas.",
    mitreTechnique: "T1200",
    subTechniques: [
      { name: "Piggybacking", description: "Following authorized personnel through secured doors", indicators: ["holding door", "carrying items", "confident demeanor"] },
      { name: "Dumpster Diving", description: "Searching through discarded materials for sensitive information", indicators: ["unshredded documents", "discarded hardware", "printed credentials"] },
      { name: "Shoulder Surfing", description: "Observing targets entering credentials or viewing sensitive data", indicators: ["crowded area", "visible screen", "PIN entry"] },
      { name: "Eavesdropping", description: "Listening to private conversations for intelligence gathering", indicators: ["public spaces", "phone calls", "meeting rooms"] },
    ],
  },
];

export function getSocialEngineeringContext(category?: string): string {
  const relevant = category
    ? SOCIAL_ENGINEERING_TAXONOMY.filter(c => c.name.toLowerCase() === category.toLowerCase())
    : SOCIAL_ENGINEERING_TAXONOMY;

  const formatted = relevant.map(cat => {
    const subs = cat.subTechniques.map(st =>
      `  - **${st.name}:** ${st.description}`
    ).join("\n");
    return `### ${cat.name} [MITRE: ${cat.mitreTechnique}]
${cat.description}
${subs}`;
  }).join("\n\n");

  return `## Social Engineering Attack Taxonomy
Use this taxonomy when planning phishing campaigns, assessing social engineering risk, or generating awareness training content:

${formatted}

**Campaign Planning Tips:**
- Match the attack vector to the target's role (executives -> BEC, IT staff -> tech support scam, general staff -> phishing)
- Layer multiple techniques: spear phishing email -> fake login page -> credential harvest -> BEC follow-up
- Use pretexting to establish trust before the primary attack vector`;
}

// ─── 5. Shodan Filters & Queries ────────────────────────────────────────────

export interface ShodanQuery {
  target: string;
  query: string;
  category: string;
}

const SHODAN_QUERIES: ShodanQuery[] = [
  { target: "MongoDB servers", query: "mongodb", category: "databases" },
  { target: "Mongo Express GUI", query: '"Set-Cookie: mongo-express=" "200 OK"', category: "databases" },
  { target: "MySQL databases", query: "mysql port:3306", category: "databases" },
  { target: "ElasticSearch", query: 'port:9200 all:"elastic indices"', category: "databases" },
  { target: "PostgreSQL", query: "port:5432 PostgreSQL", category: "databases" },
  { target: "FTP (proftpd)", query: "proftpd port:21", category: "exposed_ports" },
  { target: "Anonymous FTP", query: '"220" "230 Login successful." port:21', category: "exposed_ports" },
  { target: "OpenSSH", query: "openssh port:22", category: "exposed_ports" },
  { target: "Telnet", query: "port:23", category: "exposed_ports" },
  { target: "EXIM mail", query: 'port:25 product:"exim"', category: "exposed_ports" },
  { target: "Memcached", query: 'port:11211 product:"Memcached"', category: "exposed_ports" },
  { target: "Apache httpd", query: 'product:"Apache httpd" port:80', category: "web_servers" },
  { target: "Microsoft IIS", query: 'product:"Microsoft IIS httpd"', category: "web_servers" },
  { target: "Nginx", query: 'product:"nginx"', category: "web_servers" },
  { target: "Jenkins CI", query: '"X-Jenkins" "Set-Cookie: JSESSIONID" http.title:"Dashboard"', category: "web_servers" },
  { target: "MikroTik RouterOS", query: 'port:8291 os:"MikroTik RouterOS 6.45.9"', category: "network_infrastructure" },
  { target: "Webcams", query: "Server: SQ-WEBCAM", category: "iot" },
  { target: "XZERES Wind Turbines", query: 'title:"xzeres wind"', category: "ics" },
  { target: "EV Chargers", query: 'Server: gSOAP/2.8 "Content-Length: 583"', category: "ics" },
  { target: "Tesla Powerpack", query: 'http.title:"Tesla PowerPack System" http.component:"d3"', category: "ics" },
  { target: "Remote Desktop (RDP)", query: "remote desktop port:3389", category: "remote_access" },
  { target: "VNC (no auth)", query: '"authentication disabled" "RFB 003.008"', category: "remote_access" },
  { target: "Samba (no auth)", query: '"authentication disabled" port:445', category: "remote_access" },
  { target: "Android Debug Bridge", query: '"Android Debug Bridge" "Device" port:5555', category: "remote_access" },
  { target: "Plex servers", query: '"X-Plex-Protocol" "200 OK" port:32400', category: "nas" },
  { target: "HP printers", query: '"Serial Number:" "Built:" "Server: HP HTTP"', category: "printers" },
  { target: "EPSON printers", query: '"SERVER: EPSON_Linux UPnP" "200 OK"', category: "printers" },
  { target: "Xerox printers", query: 'ssl:"Xerox Generic Root"', category: "printers" },
  { target: "Ethereum miners", query: '"ETH - Total speed"', category: "crypto" },
];

const SHODAN_FILTERS: Record<string, string[]> = {
  general: ["ip", "hostname", "link", "net", "has_vuln", "has_ssl", "has_screenshot", "has_ipv6", "port", "geo", "product", "device", "region", "cpe", "country", "org", "os"],
  http: ["http.html_hash", "http.html", "http.robots_hash", "http.headers_hash", "http.favicon.hash", "http.status", "http.title", "http.component", "http.waf"],
  cloud: ["cloud.provider", "cloud.region", "cloud.service"],
  ssl: ["ssl.cert.serial", "ssl.cert.subject.cn", "ssl.cert.issuer.cn", "ssl.cipher.bits", "ssl.cert.fingerprint", "ssl.cert.expired", "ssl.ja3s", "ssl.jarm", "ssl.version"],
  ssh: ["ssh.hash", "ssh.type"],
  restricted: ["tag", "vuln"],
};

export function getShodanReconContext(targetType?: string): string {
  let queries = SHODAN_QUERIES;
  if (targetType) {
    queries = SHODAN_QUERIES.filter(q => q.category === targetType);
    if (queries.length === 0) queries = SHODAN_QUERIES;
  }

  const formatted = queries.map(q => `- **${q.target}:** \`${q.query}\``).join("\n");

  const filterSummary = Object.entries(SHODAN_FILTERS).map(([cat, filters]) =>
    `- **${cat}:** ${filters.slice(0, 8).join(", ")}${filters.length > 8 ? ` (+${filters.length - 8} more)` : ""}`
  ).join("\n");

  return `## Shodan Reconnaissance Queries
Use these pre-built Shodan queries to discover exposed services and attack surface:

${formatted}

### Available Shodan Filters
${filterSummary}

**Recon Strategy:**
1. Start with broad service discovery: hostname:target.com or org:"Target Corp"
2. Narrow by exposed databases, remote access, and IoT/ICS systems
3. Check for authentication-disabled services (VNC, Samba, FTP anonymous)
4. Use has_vuln:true filter to find hosts with known CVEs
5. Cross-reference Shodan findings with nmap results for validation`;
}

// ─── 6. Subdomain Enumeration Tools ─────────────────────────────────────────

export interface SubdomainTool {
  name: string;
  description: string;
  tier: "primary" | "secondary" | "specialized";
  method: "passive" | "active" | "both";
}

const SUBDOMAIN_TOOLS: SubdomainTool[] = [
  { name: "Amass", description: "In-depth attack surface mapping and asset discovery with multiple data sources", tier: "primary", method: "both" },
  { name: "Subfinder", description: "Fast passive subdomain discovery using multiple APIs and sources", tier: "primary", method: "passive" },
  { name: "Sublist3r", description: "Fast subdomain enumeration using search engines and APIs", tier: "primary", method: "passive" },
  { name: "Massdns", description: "High-performance DNS stub resolver for bulk lookups and brute-force", tier: "primary", method: "active" },
  { name: "Assetfinder", description: "Find domains and subdomains related to a given domain", tier: "primary", method: "passive" },
  { name: "dnsx", description: "Fast multi-purpose DNS toolkit for queries with user-supplied resolvers", tier: "primary", method: "active" },
  { name: "Findomain", description: "Fastest cross-platform subdomain enumerator", tier: "secondary", method: "passive" },
  { name: "Knockpy", description: "Python tool designed to enumerate subdomains via wordlist", tier: "secondary", method: "active" },
  { name: "Aquatone", description: "Tool for domain flyovers and visual inspection of subdomains", tier: "secondary", method: "passive" },
  { name: "shuffledns", description: "Wrapper around massdns for valid subdomain enumeration", tier: "secondary", method: "active" },
  { name: "altdns", description: "Generates permutations, alterations, and mutations of subdomains then resolves them", tier: "secondary", method: "active" },
  { name: "hakrevdns", description: "Fast reverse DNS lookups en masse", tier: "secondary", method: "active" },
  { name: "dnsenum", description: "Multithreaded perl script for DNS enumeration and IP discovery", tier: "secondary", method: "both" },
  { name: "censys-subdomain-finder", description: "Subdomain enumeration via Censys certificate transparency logs", tier: "specialized", method: "passive" },
  { name: "Substr3am", description: "Passive recon by watching SSL certificates being issued in real-time", tier: "specialized", method: "passive" },
  { name: "chaos-client", description: "Go client for ProjectDiscovery Chaos DNS API", tier: "specialized", method: "passive" },
  { name: "sub3suite", description: "Research-grade suite for subdomain enumeration and attack surface mapping", tier: "specialized", method: "both" },
  { name: "brutesubs", description: "Automation framework for multiple subdomain bruteforcing tools via Docker", tier: "specialized", method: "active" },
  { name: "dns-parallel-prober", description: "Parallelised domain name prober for fast brute-force", tier: "specialized", method: "active" },
];

export function getSubdomainEnumContext(): string {
  const byTier = (tier: "primary" | "secondary" | "specialized") =>
    SUBDOMAIN_TOOLS.filter(t => t.tier === tier)
      .map(t => `  - **${t.name}** (${t.method}): ${t.description}`)
      .join("\n");

  return `## Subdomain Enumeration Strategy
Use a layered approach combining passive and active enumeration:

### Tier 1: Primary Tools (always use)
${byTier("primary")}

### Tier 2: Secondary Tools (additional coverage)
${byTier("secondary")}

### Tier 3: Specialized Tools (specific scenarios)
${byTier("specialized")}

**Recommended Workflow:**
1. Passive first: Run Subfinder + Amass passive + Assetfinder in parallel
2. Certificate transparency: Query crt.sh and Censys for CT log entries
3. DNS brute-force: Use Massdns + dnsx with quality wordlist (SecLists dns)
4. Permutation: Run altdns on discovered subdomains to find variations
5. Validation: Resolve all discovered subdomains with dnsx, filter live hosts
6. Visual recon: Run Aquatone/httpx on live subdomains for screenshots and tech detection
7. Reverse DNS: Use hakrevdns on IP ranges to find additional hostnames`;
}

// ─── Unified Context Builder ────────────────────────────────────────────────

export function buildOffensiveTechniquesContext(params: {
  phase: "recon" | "enumeration" | "vuln_detection" | "exploitation" | "post_exploitation" | "reporting";
  platform?: "windows" | "linux" | "macos";
  hasFirewall?: boolean;
  hasWAF?: boolean;
  hasFileUpload?: boolean;
  includePhishing?: boolean;
  includeShodan?: boolean;
}): string {
  const sections: string[] = [];

  if (params.phase === "recon" || params.phase === "enumeration") {
    sections.push(getSubdomainEnumContext());
    if (params.includeShodan !== false) {
      sections.push(getShodanReconContext());
    }
  }

  if (params.phase === "enumeration" || params.phase === "vuln_detection") {
    if (params.hasFirewall || params.hasWAF) {
      sections.push(getFirewallEvasionContext(params.hasFirewall, params.hasWAF));
    }
    if (params.hasFileUpload) {
      sections.push(getFileUploadBypassContext());
    }
  }

  if (params.phase === "exploitation" || params.phase === "post_exploitation") {
    sections.push(getLOTLContext(params.platform));
    if (params.hasFileUpload) {
      sections.push(getFileUploadBypassContext());
    }
  }

  if (params.phase === "post_exploitation") {
    if (params.hasFirewall || params.hasWAF) {
      sections.push(getFirewallEvasionContext(params.hasFirewall, params.hasWAF));
    }
  }

  if (params.includePhishing) {
    sections.push(getSocialEngineeringContext());
  }

  if (sections.length === 0) return "";

  return `# Offensive Techniques Knowledge Base\n\n${sections.join("\n\n---\n\n")}`;
}
