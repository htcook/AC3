/**
 * scanforge-knowledge.ts — ScanForge-Native Tool Knowledge Module
 *
 * Comprehensive knowledge module for expert-level knowledge for the
 * ScanForge discovery toolchain: Masscan, Naabu, RustScan, ZMap.
 *
 * Provides the LLM with:
 * - Tool selection matrix based on target context
 * - Evasion technique profiles for each tool
 * - CLI cheat sheets and flag reference
 * - Scan profile templates for different engagement types
 * - Vulnerability correlation context
 * - MITRE ATT&CK mapping for findings
 * - WAF/firewall-aware tuning guidance
 * - Integration patterns (tool chaining)
 *
 * This module is injected into LLM prompts during:
 * - Scan plan generation (engagement-orchestrator)
 * - Discovery chain orchestration
 * - Vulnerability correlation
 * - Hunt hypothesis generation
 * - Asset classification
 *
 * Author: Harrison Cook — AceofCloud
 */

// ─── Tool Selection Matrix ────────────────────────────────────────────────────

export interface ScanforgeTool {
  name: string;
  binary: string;
  description: string;
  primaryUseCase: string;
  speed: 'ultra-fast' | 'fast' | 'moderate';
  accuracy: 'high' | 'medium' | 'low';
  stealthCapability: 'high' | 'medium' | 'low';
  bestFor: string[];
  limitations: string[];
  outputFormat: string;
  /** Ports: 'all' means 0-65535, 'top-N' means top N common ports */
  defaultPortRange: string;
}

export const SCANFORGE_TOOLS: ScanforgeTool[] = [
  {
    name: 'Masscan',
    binary: 'masscan',
    description: 'Asynchronous TCP SYN scanner capable of scanning the entire internet in under 6 minutes. Sends raw packets without a full TCP stack, achieving speeds of 10M+ packets/sec.',
    primaryUseCase: 'High-speed initial port discovery across large target ranges',
    speed: 'ultra-fast',
    accuracy: 'medium',
    stealthCapability: 'low',
    bestFor: [
      'Large CIDR ranges (/16 and above)',
      'Internet-wide scanning',
      'Initial port discovery before detailed fingerprinting',
      'Time-constrained engagements',
      'Finding all open ports across many hosts quickly',
    ],
    limitations: [
      'No service version detection (SYN-only)',
      'No OS detection',
      'High packet rate can trigger IDS/WAF',
      'Stateless — may miss ports under packet loss',
      'No scripting engine',
      'Requires root/raw socket privileges',
    ],
    outputFormat: '-oJ (JSON) or -oX (XML) or -oL (list)',
    defaultPortRange: '0-65535',
  },
  {
    name: 'Naabu',
    binary: 'naabu',
    description: 'ProjectDiscovery fast port scanner written in Go. Supports SYN, CONNECT, and UDP scanning with built-in host discovery. Integrates natively with other ProjectDiscovery tools (httpx, nuclei, subfinder).',
    primaryUseCase: 'Balanced port scanning with native ProjectDiscovery pipeline integration',
    speed: 'fast',
    accuracy: 'high',
    stealthCapability: 'medium',
    bestFor: [
      'Bug bounty and pentest workflows',
      'Pipeline integration with httpx → nuclei',
      'Targets requiring both TCP and UDP scanning',
      'Stdin/stdout chaining with other tools',
      'Rate-limited scanning for stealth',
      'Scanning from target lists and CIDR ranges',
    ],
    limitations: [
      'Slower than Masscan for very large ranges',
      'No built-in scripting engine',
      'UDP scanning is slower and less reliable',
      'No OS fingerprinting',
    ],
    outputFormat: '-json (JSON lines) or -o (plain text)',
    defaultPortRange: 'Top 100 (configurable with -p or -top-ports)',
  },
  {
    name: 'RustScan',
    binary: 'rustscan',
    description: 'Ultra-fast port scanner written in Rust. Designed as a speed layer that discovers open ports and can hand off to ScanForge for service detection. Adaptive scanning adjusts batch size based on target responsiveness.',
    primaryUseCase: 'Fast port discovery with optional service detection handoff',
    speed: 'ultra-fast',
    accuracy: 'high',
    stealthCapability: 'low',
    bestFor: [
      'Single host full port scans (all 65535 ports in seconds)',
      'Small to medium target ranges',
      'Quick initial discovery before detailed analysis',
      'CTF and lab environments',
      'Adaptive scanning that adjusts to target capacity',
    ],
    limitations: [
      'No built-in service version detection (relies on handoff)',
      'High connection rate can overwhelm targets',
      'No UDP scanning',
      'No scripting engine',
      'Less suitable for very large CIDR ranges',
    ],
    outputFormat: '-g (greppable) or stdout (default)',
    defaultPortRange: '1-65535',
  },
  {
    name: 'ZMap',
    binary: 'zmap',
    description: 'Stateless internet-wide network scanner from University of Michigan. Uses cyclic multiplicative groups for random permutation of target addresses. Can scan the entire IPv4 address space in under 45 minutes on a 1Gbps connection.',
    primaryUseCase: 'Internet-scale scanning and large network reconnaissance',
    speed: 'ultra-fast',
    accuracy: 'low',
    stealthCapability: 'low',
    bestFor: [
      'Internet-wide scanning for specific services',
      'Large-scale reconnaissance (/8 and above)',
      'Finding all instances of a specific port globally',
      'Research-grade network measurement',
      'Single-port sweeps across massive ranges',
    ],
    limitations: [
      'Single port per scan (no multi-port in one pass)',
      'No service detection or version identification',
      'No OS detection',
      'Stateless — single probe per host',
      'Requires root privileges and raw socket access',
      'Can easily overwhelm networks — use bandwidth limits',
    ],
    outputFormat: '-O csv or -O json or stdout',
    defaultPortRange: 'Single port per scan',
  },
];

// ─── Evasion Technique Profiles ────────────────────────────────────────────

export interface EvasionProfile {
  name: string;
  risk: 'low' | 'medium' | 'high';
  description: string;
  tools: string[];
  flags: Record<string, string[]>;
  bypassCapability: string[];
  limitations: string[];
  bestFor: string[];
}

export const EVASION_PROFILES: EvasionProfile[] = [
  {
    name: 'Rate-Limited Stealth',
    risk: 'low',
    description: 'Reduce scan rate to stay below IDS/WAF detection thresholds. All ScanForge tools support rate limiting. Masscan uses --rate, Naabu uses -rate, RustScan uses --batch-size and --timeout.',
    tools: ['masscan', 'naabu', 'rustscan'],
    flags: {
      masscan: ['--rate 100', '--rate 50', '--rate 10'],
      naabu: ['-rate 100', '-rate 50', '-rate 10'],
      rustscan: ['--batch-size 128', '--batch-size 64', '--timeout 3000'],
    },
    bypassCapability: ['Rate-based IDS alerts', 'Threshold-based anomaly detection', 'Connection-rate firewalls'],
    limitations: ['Significantly slower scan times', 'Does not evade content-based detection', 'Still detectable by stateful inspection'],
    bestFor: ['Monitored environments', 'Cloud WAF targets', 'Avoiding rate-limit triggers', 'Long-term covert recon'],
  },
  {
    name: 'Source Port Manipulation',
    risk: 'medium',
    description: 'Set source port to commonly trusted ports (53/DNS, 80/HTTP, 443/HTTPS). Firewalls often allow return traffic from these ports. Masscan supports --source-port.',
    tools: ['masscan'],
    flags: {
      masscan: ['--source-port 53', '--source-port 80', '--source-port 443'],
    },
    bypassCapability: ['Firewalls trusting DNS return traffic', 'Port-based ACLs', 'Stateless packet filters'],
    limitations: ['Only works with Masscan', 'ISPs may filter spoofed source ports', 'Stateful firewalls still detect'],
    bestFor: ['Bypassing DNS-trusting firewalls', 'DMZ environments', 'Internal network scanning'],
  },
  {
    name: 'Randomized Targeting',
    risk: 'low',
    description: 'Randomize the order of target addresses to avoid triggering sequential-scan detection. ZMap does this by default via cyclic groups. Masscan uses --randomize-hosts.',
    tools: ['masscan', 'zmap'],
    flags: {
      masscan: ['--randomize-hosts'],
      zmap: ['(default behavior)'],
    },
    bypassCapability: ['Sequential scan detection', 'Pattern-based IDS rules', 'Simple threshold-based blocking'],
    limitations: ['Does not reduce total traffic volume', 'Still detectable by volume-based monitoring'],
    bestFor: ['Large range scans', 'Avoiding sequential scan alerts', 'Combined with rate limiting'],
  },
  {
    name: 'Bandwidth Throttling',
    risk: 'low',
    description: 'Limit bandwidth consumption to avoid network congestion alerts and QoS triggers. Masscan uses --max-rate, ZMap uses -B (bandwidth limit).',
    tools: ['masscan', 'zmap'],
    flags: {
      masscan: ['--max-rate 1000', '--max-rate 500'],
      zmap: ['-B 1M', '-B 10M', '-B 100M'],
    },
    bypassCapability: ['Bandwidth-based anomaly detection', 'QoS triggers', 'Network congestion alerts'],
    limitations: ['Slower scan completion', 'Does not evade packet-level inspection'],
    bestFor: ['Shared network environments', 'Cloud targets with bandwidth monitoring', 'Avoiding DoS conditions'],
  },
  {
    name: 'CONNECT Scan (Non-Raw)',
    risk: 'low',
    description: 'Use full TCP CONNECT instead of SYN scan. Does not require root privileges. Appears as normal TCP connections. Naabu supports -scan-type connect.',
    tools: ['naabu'],
    flags: {
      naabu: ['-scan-type connect'],
    },
    bypassCapability: ['SYN-only IDS rules', 'Raw packet detection', 'Environments blocking raw sockets'],
    limitations: ['Slower than SYN scanning', 'Leaves connection logs on target', 'More detectable at application layer'],
    bestFor: ['Environments where raw sockets are blocked', 'Non-root scanning', 'Targets with SYN-specific detection'],
  },
  {
    name: 'Multi-Probe Reliability',
    risk: 'low',
    description: 'Send multiple probes per port to improve accuracy under packet loss. ZMap uses -P for probe count. Masscan uses --retries.',
    tools: ['masscan', 'zmap'],
    flags: {
      masscan: ['--retries 2', '--retries 3'],
      zmap: ['-P 2', '-P 3'],
    },
    bypassCapability: [],
    limitations: ['Increases total traffic volume', 'Slower scan completion'],
    bestFor: ['Lossy networks', 'Targets behind load balancers', 'Improving accuracy on unreliable connections'],
  },
  {
    name: 'Interface and Adapter Selection',
    risk: 'low',
    description: 'Specify network interface and adapter for scanning. Useful for multi-homed hosts or when scanning from specific VLANs. Masscan uses --interface, ZMap uses -i.',
    tools: ['masscan', 'zmap', 'naabu'],
    flags: {
      masscan: ['--interface eth0', '--adapter-ip 10.0.0.5'],
      zmap: ['-i eth0'],
      naabu: ['-interface eth0'],
    },
    bypassCapability: ['VLAN-based access controls', 'Source-network restrictions'],
    limitations: ['Requires knowledge of network topology', 'May require specific routing'],
    bestFor: ['Multi-homed scan servers', 'VLAN-specific scanning', 'Controlled source IP selection'],
  },
  {
    name: 'Combined Layered Evasion',
    risk: 'medium',
    description: 'Combine rate limiting + source port manipulation + randomization for maximum stealth. Uses Masscan with all evasion flags.',
    tools: ['masscan'],
    flags: {
      masscan: ['--rate 50 --source-port 53 --randomize-hosts --retries 1'],
    },
    bypassCapability: ['Multi-layer defense stacks', 'Rate + pattern + source detection', 'SOC analyst manual review'],
    limitations: ['Very slow', 'Complex to configure', 'Only available with Masscan'],
    bestFor: ['Red team operations against hardened targets', 'Testing defense-in-depth', 'Maximum stealth requirement'],
  },
];

// ─── Scan Profile Templates ───────────────────────────────────────────────

export interface ScanProfile {
  name: string;
  description: string;
  tool: string;
  command: string;
  useCase: string;
  stealthLevel: 'minimal' | 'low' | 'medium' | 'high';
  estimatedDuration: string;
  riskLevel: 'safe' | 'low' | 'medium' | 'high';
}

export const SCAN_PROFILES: ScanProfile[] = [
  // ── Masscan Profiles ──
  {
    name: 'Masscan Quick Discovery',
    description: 'Ultra-fast top port discovery. Finds open ports across large ranges in seconds.',
    tool: 'masscan',
    command: 'masscan {target} -p1-1024,3306,3389,5432,5900,6379,8080,8443,27017 --rate 1000 -oJ -',
    useCase: 'Initial port discovery on authorized targets',
    stealthLevel: 'minimal',
    estimatedDuration: '5-30 sec per /24',
    riskLevel: 'low',
  },
  {
    name: 'Masscan Full Port Sweep',
    description: 'Complete 0-65535 port scan. Finds every open port including non-standard services.',
    tool: 'masscan',
    command: 'masscan {target} -p0-65535 --rate 5000 -oJ -',
    useCase: 'Comprehensive port enumeration',
    stealthLevel: 'minimal',
    estimatedDuration: '1-5 min per /24',
    riskLevel: 'low',
  },
  {
    name: 'Masscan Stealth Recon',
    description: 'Rate-limited scan with source port spoofing for monitored environments.',
    tool: 'masscan',
    command: 'masscan {target} -p1-1024,3306,3389,5432,8080,8443 --rate 50 --source-port 53 --randomize-hosts -oJ -',
    useCase: 'Scanning monitored/hardened targets',
    stealthLevel: 'high',
    estimatedDuration: '10-30 min per /24',
    riskLevel: 'low',
  },

  // ── Naabu Profiles ──
  {
    name: 'Naabu Standard Scan',
    description: 'Balanced port scan with host discovery. Good default for most engagements.',
    tool: 'naabu',
    command: 'naabu -host {target} -top-ports 1000 -rate 500 -json',
    useCase: 'Standard authorized assessment',
    stealthLevel: 'low',
    estimatedDuration: '1-5 min',
    riskLevel: 'low',
  },
  {
    name: 'Naabu Full Port Scan',
    description: 'Complete port scan with service detection via built-in probes.',
    tool: 'naabu',
    command: 'naabu -host {target} -p - -rate 1000 -json',
    useCase: 'Comprehensive port enumeration with service hints',
    stealthLevel: 'low',
    estimatedDuration: '3-10 min',
    riskLevel: 'low',
  },
  {
    name: 'Naabu Stealth Scan',
    description: 'Low-rate SYN scan for monitored environments.',
    tool: 'naabu',
    command: 'naabu -host {target} -top-ports 1000 -rate 50 -scan-type s -json',
    useCase: 'Scanning monitored targets',
    stealthLevel: 'high',
    estimatedDuration: '10-30 min',
    riskLevel: 'low',
  },
  {
    name: 'Naabu Pipeline (httpx chain)',
    description: 'Port discovery piped to httpx for web service fingerprinting.',
    tool: 'naabu',
    command: 'naabu -host {target} -top-ports 1000 -silent | httpx -json -title -tech-detect -status-code -follow-redirects',
    useCase: 'Web service discovery and fingerprinting',
    stealthLevel: 'low',
    estimatedDuration: '2-8 min',
    riskLevel: 'low',
  },

  // ── RustScan Profiles ──
  {
    name: 'RustScan Blitz',
    description: 'Ultra-fast full port scan of a single host. Scans all 65535 ports in seconds.',
    tool: 'rustscan',
    command: 'rustscan -a {target} --range 1-65535 -b 4500 -t 2000 -g',
    useCase: 'Single host full port discovery',
    stealthLevel: 'minimal',
    estimatedDuration: '3-15 sec',
    riskLevel: 'low',
  },
  {
    name: 'RustScan Adaptive',
    description: 'Adaptive batch scanning that adjusts to target responsiveness.',
    tool: 'rustscan',
    command: 'rustscan -a {target} --range 1-65535 -b 1000 -t 3000 -g',
    useCase: 'Balanced speed/reliability scanning',
    stealthLevel: 'low',
    estimatedDuration: '10-60 sec',
    riskLevel: 'low',
  },
  {
    name: 'RustScan Careful',
    description: 'Conservative batch size for fragile targets or monitored environments.',
    tool: 'rustscan',
    command: 'rustscan -a {target} --range 1-65535 -b 128 -t 5000 -g',
    useCase: 'Scanning fragile or monitored targets',
    stealthLevel: 'medium',
    estimatedDuration: '2-10 min',
    riskLevel: 'low',
  },

  // ── ZMap Profiles ──
  {
    name: 'ZMap Single Port Sweep',
    description: 'Internet-scale single port discovery. Scans entire /16 in seconds.',
    tool: 'zmap',
    command: 'zmap -p {port} {target} -B 10M -O json --output-fields=saddr,sport',
    useCase: 'Large-scale single port reconnaissance',
    stealthLevel: 'minimal',
    estimatedDuration: '1-30 sec per /16',
    riskLevel: 'medium',
  },
  {
    name: 'ZMap Stealth Sweep',
    description: 'Low-bandwidth single port sweep for monitored networks.',
    tool: 'zmap',
    command: 'zmap -p {port} {target} -B 1M -O json --output-fields=saddr,sport',
    useCase: 'Stealthy large-range reconnaissance',
    stealthLevel: 'medium',
    estimatedDuration: '5-60 min per /16',
    riskLevel: 'low',
  },

  // ── Combined Pipeline Profiles ──
  {
    name: 'ScanForge Full Pipeline',
    description: 'Complete discovery chain: Masscan port discovery → httpx web fingerprinting → Nuclei vulnerability detection.',
    tool: 'pipeline',
    command: 'masscan {target} -p1-65535 --rate 5000 -oJ /tmp/ports.json && cat /tmp/ports.json | jq -r \'.[] | .ip + ":" + (.ports[0].port|tostring)\' | httpx -json -title -tech-detect -status-code | nuclei -json -severity medium,high,critical',
    useCase: 'Full automated discovery and vulnerability detection',
    stealthLevel: 'minimal',
    estimatedDuration: '5-30 min',
    riskLevel: 'medium',
  },
  {
    name: 'ScanForge Stealth Pipeline',
    description: 'Rate-limited discovery chain for monitored environments.',
    tool: 'pipeline',
    command: 'naabu -host {target} -top-ports 1000 -rate 50 -silent | httpx -json -title -tech-detect -status-code -rate-limit 10 | nuclei -json -severity medium,high,critical -rate-limit 10',
    useCase: 'Stealthy automated discovery',
    stealthLevel: 'high',
    estimatedDuration: '30-120 min',
    riskLevel: 'low',
  },
];

// ─── Technology-Specific Scan Guidance ─────────────────────────────────────

export interface TechSignature {
  technology: string;
  indicators: string[];
  recommendedTools: string[];
  scanPorts: string;
  httpxFlags: string;
  nucleiTags: string;
  notes: string;
}

export const TECH_SIGNATURES: TechSignature[] = [
  {
    technology: 'WordPress',
    indicators: ['wordpress', 'wp-content', 'wp-admin', 'wp-includes', 'wp-json'],
    recommendedTools: ['naabu', 'httpx', 'nuclei'],
    scanPorts: '80,443,8080,8443',
    httpxFlags: '-title -tech-detect -status-code -follow-redirects',
    nucleiTags: 'wordpress,wp-plugin,cve',
    notes: 'Nuclei has 500+ WordPress-specific templates. Always run nuclei -tags wordpress after httpx fingerprinting.',
  },
  {
    technology: 'Apache',
    indicators: ['apache', 'httpd', 'mod_ssl', 'mod_php'],
    recommendedTools: ['naabu', 'httpx', 'nuclei', 'nikto'],
    scanPorts: '80,443,8080,8443',
    httpxFlags: '-title -tech-detect -status-code -server',
    nucleiTags: 'apache,cve',
    notes: 'Check for mod_status, mod_info exposure. Nuclei detects Struts, Tomcat behind Apache.',
  },
  {
    technology: 'Nginx',
    indicators: ['nginx', 'openresty'],
    recommendedTools: ['naabu', 'httpx', 'nuclei'],
    scanPorts: '80,443,8080,8443',
    httpxFlags: '-title -tech-detect -status-code -server',
    nucleiTags: 'nginx,cve,misconfig',
    notes: 'Check for off-by-slash misconfiguration, alias traversal. Nuclei has nginx-specific templates.',
  },
  {
    technology: 'Microsoft IIS',
    indicators: ['iis', 'asp.net', 'aspx', 'microsoft-iis'],
    recommendedTools: ['naabu', 'httpx', 'nuclei'],
    scanPorts: '80,443,8080,8443',
    httpxFlags: '-title -tech-detect -status-code -server',
    nucleiTags: 'iis,aspnet,cve,misconfig',
    notes: 'Check for short filename disclosure, WebDAV, debug mode. Nuclei detects IIS-specific vulns.',
  },
  {
    technology: 'SSH',
    indicators: ['ssh', 'openssh', 'dropbear'],
    recommendedTools: ['naabu', 'masscan'],
    scanPorts: '22,2222,22222',
    httpxFlags: 'N/A',
    nucleiTags: 'ssh,cve',
    notes: 'Naabu can detect SSH version via banner grab. Nuclei has SSH-specific vulnerability templates.',
  },
  {
    technology: 'Database Services',
    indicators: ['mysql', 'postgresql', 'mssql', 'oracle', 'mongodb', 'redis', 'elasticsearch'],
    recommendedTools: ['masscan', 'naabu'],
    scanPorts: '3306,5432,1433,1521,27017,6379,9200,9300',
    httpxFlags: 'N/A',
    nucleiTags: 'database,cve,misconfig,default-login',
    notes: 'Exposed database ports are critical findings. Nuclei can test for default credentials and known CVEs.',
  },
  {
    technology: 'Docker/Kubernetes',
    indicators: ['docker', 'kubernetes', 'k8s', 'containerd'],
    recommendedTools: ['masscan', 'naabu', 'nuclei'],
    scanPorts: '2375,2376,6443,10250,10255,8001,8080',
    httpxFlags: '-title -tech-detect -status-code',
    nucleiTags: 'docker,kubernetes,cve,misconfig,exposure',
    notes: 'Exposed Docker API (2375) = full host compromise. Kubelet API (10250) = container escape. Critical findings.',
  },
  {
    technology: 'Cloud Services',
    indicators: ['aws', 'azure', 'gcp', 'cloudflare', 'akamai'],
    recommendedTools: ['naabu', 'httpx', 'nuclei'],
    scanPorts: '80,443,8080,8443',
    httpxFlags: '-title -tech-detect -status-code -cdn -server',
    nucleiTags: 'cloud,aws,azure,gcp,s3,misconfig',
    notes: 'Use httpx -cdn to detect CDN/WAF. Rate limit scans for cloud targets. Check for IMDS at 169.254.169.254.',
  },
  {
    technology: 'Mail Services',
    indicators: ['smtp', 'pop3', 'imap', 'exchange', 'postfix', 'sendmail'],
    recommendedTools: ['masscan', 'naabu'],
    scanPorts: '25,110,143,465,587,993,995,2525',
    httpxFlags: 'N/A',
    nucleiTags: 'mail,smtp,cve',
    notes: 'Check for open relay, VRFY/EXPN commands, STARTTLS downgrade. Nuclei has mail-specific templates.',
  },
  {
    technology: 'VPN/Remote Access',
    indicators: ['vpn', 'openvpn', 'wireguard', 'ipsec', 'rdp', 'vnc', 'citrix'],
    recommendedTools: ['masscan', 'naabu'],
    scanPorts: '443,500,1194,1723,3389,4443,5900,8443',
    httpxFlags: '-title -tech-detect -status-code',
    nucleiTags: 'vpn,rdp,vnc,citrix,cve',
    notes: 'VPN endpoints often have web portals. Check for Fortinet, Pulse Secure, Citrix ADC vulns via Nuclei.',
  },
];

// ─── Admin/Service Ports ──────────────────────────────────────────────────

/** Admin/service ports for targeted fingerprinting — standard admin/service ports */
export const ADMIN_SERVICE_PORTS: Record<string, number[]> = {
  ssh: [22, 2222, 22222],
  ftp: [20, 21, 990],
  sftp: [22, 115],
  smtp: [25, 465, 587, 2525],
  dns: [53],
  http: [80, 8080, 8000, 8888],
  https: [443, 8443, 4443],
  pop3: [110, 995],
  imap: [143, 993],
  smb: [139, 445],
  rdp: [3389],
  vnc: [5900, 5901, 5902],
  telnet: [23, 992],
  snmp: [161, 162],
  ldap: [389, 636],
  mysql: [3306],
  mssql: [1433, 1434],
  postgresql: [5432],
  oracle: [1521, 1630],
  redis: [6379],
  mongodb: [27017, 27018],
  elasticsearch: [9200, 9300],
  docker: [2375, 2376],
  kubernetes: [6443, 10250],
  winrm: [5985, 5986],
  nfs: [111, 2049],
  kerberos: [88, 464],
};

/** Get all unique admin ports as a comma-separated string */
export function getAllAdminPorts(): string {
  const ports = new Set<number>();
  for (const group of Object.values(ADMIN_SERVICE_PORTS)) {
    for (const port of group) ports.add(port);
  }
  return Array.from(ports).sort((a, b) => a - b).join(",");
}

// ─── LLM Prompt Context Builders ───────────────────────────────────────────

/**
 * Returns comprehensive ScanForge tool knowledge for LLM scan plan generation.
 * Replaces getScanForgeScanPlanContext().
 */
export function getScanforgeScanPlanContext(targetInfo?: {
  detectedTech?: string[];
  cloudProvider?: string;
  hasFirewall?: boolean;
  hasIDS?: boolean;
  stealthRequired?: boolean;
  targetSize?: 'single' | 'small' | 'medium' | 'large' | 'internet';
}): string {
  const sections: string[] = [];

  sections.push(`## ScanForge Discovery Engine — Expert Knowledge for Scan Planning

You have access to four high-speed discovery tools. Select the optimal tool(s) based on target context, then chain with httpx for fingerprinting and Nuclei for vulnerability detection.

### Tool Selection Matrix

| Scenario | Primary Tool | Reason | Command Pattern |
|----------|-------------|--------|-----------------|
| Single host, all ports | RustScan | Fastest for single targets | \`rustscan -a {target} --range 1-65535 -b 4500 -t 2000 -g\` |
| Small range (/24-/16) | Masscan | Best balance of speed and coverage | \`masscan {target} -p0-65535 --rate 5000 -oJ -\` |
| Large range (/16+) | Masscan or ZMap | Handles massive ranges efficiently | \`masscan {target} -p{ports} --rate 10000 -oJ -\` |
| Internet-wide, single port | ZMap | Purpose-built for internet scanning | \`zmap -p {port} -B 100M -O json\` |
| Pipeline integration | Naabu | Native stdin/stdout chaining | \`naabu -host {target} -top-ports 1000 -silent \\| httpx\` |
| Stealth required | Naabu or Masscan | Rate limiting + evasion flags | \`naabu -host {target} -rate 50\` |
| UDP scanning needed | Naabu | Only ScanForge tool with UDP support | \`naabu -host {target} -scan-type udp -top-ports 50\` |

### Discovery Chain Architecture

The ScanForge pipeline follows a 4-stage architecture:

1. **Port Discovery** (Masscan/Naabu/RustScan/ZMap) → Open ports
2. **Service Fingerprinting** (httpx) → Web technologies, server headers, status codes
3. **Vulnerability Detection** (Nuclei) → CVEs, misconfigs, exposures
4. **Verification** (ZAP active scan) → Confirmed exploitable vulnerabilities

Each stage feeds the next. The LLM should select tools for stage 1 based on target context, then always chain httpx (stage 2) and Nuclei (stage 3).`);

  // Evasion guidance
  if (targetInfo?.stealthRequired || targetInfo?.hasFirewall || targetInfo?.hasIDS) {
    sections.push(`### Evasion Technique Selection Guide

Target has defensive controls detected. Apply evasion techniques:

| Defense Detected | Recommended Approach | Tool + Flags |
|-----------------|---------------------|--------------|
| Rate-based IDS | Slow rate scanning | Masscan: \`--rate 50\`, Naabu: \`-rate 50\` |
| Stateless firewall | Source port spoofing | Masscan: \`--source-port 53\` |
| Cloud WAF | Very low rate + randomization | Naabu: \`-rate 10\`, Masscan: \`--rate 10 --randomize-hosts\` |
| Stateful firewall | CONNECT scan (full TCP) | Naabu: \`-scan-type connect\` |
| SOC monitoring | Combined layered evasion | Masscan: \`--rate 50 --source-port 53 --randomize-hosts\` |
| Bandwidth monitoring | Bandwidth throttling | Masscan: \`--max-rate 500\`, ZMap: \`-B 1M\` |

Key evasion principles:
1. **Rate limit first** — most effective single evasion technique
2. **Source port 53** (DNS) is the most effective port spoof for Masscan
3. **CONNECT scan** via Naabu avoids raw packet detection
4. **Randomize hosts** to avoid sequential scan detection
5. **Layer techniques** for maximum stealth (rate + source port + randomization)
6. **Use Naabu for stealth** — it has the best rate control granularity`);
  }

  // Technology-specific guidance
  if (targetInfo?.detectedTech?.length) {
    const matchedTechs = TECH_SIGNATURES.filter(t =>
      targetInfo.detectedTech!.some(dt =>
        t.indicators.some(ind => dt.toLowerCase().includes(ind.toLowerCase())) ||
        t.technology.toLowerCase().includes(dt.toLowerCase())
      )
    );

    if (matchedTechs.length > 0) {
      sections.push(`### Detected Technology — Recommended Scan Configuration\n`);
      for (const tech of matchedTechs) {
        sections.push(`**${tech.technology}:**
- Tools: ${tech.recommendedTools.join(', ')}
- Ports: ${tech.scanPorts}
- httpx flags: ${tech.httpxFlags}
- Nuclei tags: \`nuclei -tags ${tech.nucleiTags}\`
- Notes: ${tech.notes}`);
      }
    }
  }

  // Scan profile templates
  sections.push(`### Scan Profile Templates

Select the appropriate profile based on authorization level and target context:

${SCAN_PROFILES.map(p => `**${p.name}** (Tool: ${p.tool}, Stealth: ${p.stealthLevel}, Risk: ${p.riskLevel})
\`${p.command}\`
Use case: ${p.useCase}`).join('\n\n')}`);

  // Cloud-specific guidance
  if (targetInfo?.cloudProvider) {
    sections.push(`### Cloud-Specific Scanning Notes (${targetInfo.cloudProvider})

**MANDATORY for cloud targets — include these in the scan plan:**
- **httpx -cdn** — REQUIRED to detect CDN/WAF (CloudFlare, Akamai, AWS CloudFront)
- **nuclei -tags cloud,s3,misconfig** — REQUIRED for cloud misconfiguration detection
- **cloud_enum -k <domain_keyword>** — REQUIRED to discover S3 buckets, Azure Blobs, GCS buckets

Additional cloud scanning rules:
- Cloud security groups are **stateful** — rate limit to avoid blocking
- Use **Naabu -rate 50** or **Masscan --rate 100** for cloud targets
- Check for **IMDS at 169.254.169.254** via SSRF if web app found
- Look for **exposed storage** (S3 buckets, Blob containers, GCS buckets)
- **SSL cert SANs** reveal infrastructure scope (httpx -tls-grab)
- Cloud WAFs may require **very slow scanning** (rate 10-50)
- Check for **exposed .env, .git, /debug, /status** endpoints via Nuclei
- For AWS: check for exposed EC2 metadata, IAM role credentials, S3 bucket policies
- For Azure: check for exposed Blob storage, Key Vault misconfigs, RBAC issues
- For GCP: check for exposed GCS buckets, service account keys, Compute metadata`);
  }

  // Tool chaining rules
  sections.push(`### Tool Chaining Rules

1. **Always chain httpx after port discovery** for web service fingerprinting
2. **Always chain Nuclei after httpx** for vulnerability detection
3. **Use Naabu for pipeline integration** — native stdin/stdout support
4. **Masscan JSON output** can be parsed and fed to httpx via jq
5. **RustScan greppable output** can be parsed for port lists
6. **ZMap output** feeds directly to httpx for web service discovery
7. **Nuclei severity filter**: use \`-severity medium,high,critical\` for actionable findings
8. **httpx tech-detect** provides technology fingerprinting without active scanning
9. **Rate limit the entire pipeline** — not just the port scanner`);

  return sections.join('\n\n');
}

/**
 * Returns vulnerability correlation context for ScanForge findings.
 * Replaces getScanForgeVulnCorrelationContext().
 */
export function getScanforgeVulnCorrelationContext(): string {
  return `## ScanForge Vulnerability Correlation Guide

When correlating ScanForge discovery results with vulnerabilities, use these rules:

### Critical Findings (Immediate Action Required)
- **Exposed Docker API (port 2375/2376)** → Full host compromise. Container escape to host.
- **Exposed Kubernetes API (port 6443/10250)** → Cluster compromise. Pod escape possible.
- **Exposed Redis without auth (port 6379)** → Full server compromise via CONFIG SET.
- **Exposed MongoDB without auth (port 27017)** → Full database exposure and exfiltration.
- **Exposed Elasticsearch without auth (port 9200)** → Full index access and data theft.
- **Nuclei critical severity finding** → Confirmed exploitable vulnerability. Immediate action.
- **httpx detecting exposed .git** → Source code and credential disclosure.
- **httpx detecting exposed .env** → Environment variables with API keys and secrets.

### High Findings (Urgent Remediation)
- **SMB exposed to internet (port 445)** → EternalBlue and relay attack surface.
- **RDP exposed to internet (port 3389)** → Brute force and BlueKeep attack surface.
- **FTP exposed (port 21)** → Anonymous login check required. Credential interception.
- **Nuclei high severity finding** → Likely exploitable. Prioritize remediation.
- **httpx detecting admin panels** → Unauthorized access risk. Check for default credentials.
- **Multiple database ports open** → Lateral movement risk. Check for default credentials.
- **VPN portal exposed** → Check for Fortinet, Pulse Secure, Citrix ADC CVEs via Nuclei.

### Medium Findings (Scheduled Remediation)
- **httpx missing security headers** → HSTS, CSP, X-Frame-Options absent.
- **httpx detecting outdated server versions** → Known CVE exposure.
- **Nuclei medium severity finding** → Exploitable under specific conditions.
- **Non-standard ports with web services** → Shadow IT or misconfigured services.
- **DNS ports exposed (53)** → Open resolver abuse for DDoS amplification.
- **SNMP exposed (161/162)** → Community string brute force possible.

### Informational (Document and Monitor)
- **httpx title and technology detection** → Technology fingerprinting data.
- **SSL certificate details** → Infrastructure scope mapping via SANs.
- **Open ports with no identified service** → Requires manual investigation.
- **CDN/WAF detected by httpx** → Note for scan tuning and evasion planning.

### False Positive Indicators
- **Nuclei info severity** — Often informational, not vulnerabilities
- **httpx status 403** — May indicate WAF blocking, not actual service
- **Masscan showing filtered ports** — Stateless scanner, verify with Naabu CONNECT scan
- **RustScan timeout on specific ports** — May indicate rate limiting, not closed port`;
}

/**
 * Returns threat hunting context based on ScanForge findings.
 * Replaces getScanForgeHuntContext().
 */
export function getScanforgeHuntContext(): string {
  return `## ScanForge-Based Threat Hunting Context

### MITRE ATT&CK Mapping for ScanForge Findings

| Finding | MITRE Technique | Hunt Hypothesis |
|---------|----------------|-----------------|
| Exposed Docker API | T1610 (Deploy Container) | Adversary may deploy malicious containers for persistence |
| Exposed Kubernetes API | T1609 (Container Administration Command) | Adversary may execute commands in pods |
| Redis no auth | T1059 (Command and Scripting Interpreter) | Adversary may write SSH keys via CONFIG SET |
| MongoDB no auth | T1005 (Data from Local System) | Adversary may exfiltrate database contents |
| Exposed .git | T1213 (Data from Information Repositories) | Adversary may extract credentials from git history |
| Exposed .env | T1552 (Unsecured Credentials) | Adversary may steal API keys and secrets |
| SMB exposed | T1210 (Exploitation of Remote Services) | Adversary may exploit EternalBlue for lateral movement |
| RDP exposed | T1021 (Remote Services: RDP) | Adversary may brute force or exploit BlueKeep |
| VPN portal | T1133 (External Remote Services) | Adversary may exploit VPN vulnerabilities for initial access |
| Cloud metadata | T1552.005 (Cloud Instance Metadata API) | Adversary may steal cloud credentials via SSRF |
| Admin panel exposed | T1078 (Valid Accounts) | Adversary may use default or brute-forced credentials |
| Multiple DB ports | T1021 (Remote Services) | Adversary may pivot through database connections |
| Weak SSL/TLS | T1557 (Adversary-in-the-Middle) | Adversary may perform TLS downgrade for interception |
| Open DNS recursion | T1498 (Network DoS: Reflection Amplification) | Server may be used as DDoS reflector |

### Discovery-Based Hunt Queries
- Look for hosts with exposed management ports (2375, 6443, 9200, 27017) → likely misconfigured
- Look for hosts with both web and database ports open → potential direct DB access
- Look for SSL certs with many SANs → map infrastructure scope via httpx -tls-grab
- Look for hosts responding on cloud metadata ports → SSRF candidates
- Look for non-standard web ports (8080, 8443, 8888) → shadow IT or dev environments
- Look for hosts with multiple exposed services → high-value targets for lateral movement`;
}

/**
 * Returns the full ScanForge knowledge context for comprehensive LLM injection.
 * Replaces getFullScanForgeContext().
 */
export function getFullScanforgeContext(targetInfo?: {
  detectedTech?: string[];
  cloudProvider?: string;
  hasFirewall?: boolean;
  hasIDS?: boolean;
  stealthRequired?: boolean;
  targetSize?: 'single' | 'small' | 'medium' | 'large' | 'internet';
}): string {
  return [
    getScanforgeScanPlanContext(targetInfo),
    getScanforgeVulnCorrelationContext(),
    getScanforgeHuntContext()
  ].join('\n\n---\n\n');
}

/**
 * Given detected technologies and context, returns the optimal ScanForge command pipeline.
 * Replaces buildOptimalScanForgeCommand().
 */
export function buildOptimalScanforgeCommand(params: {
  detectedTech: string[];
  stealthLevel: 'minimal' | 'low' | 'medium' | 'high' | 'maximum';
  scanType: 'recon' | 'vuln' | 'full';
  target: string;
  targetSize?: 'single' | 'small' | 'medium' | 'large';
}): { discoveryCmd: string; fingerprintCmd: string; vulnCmd: string; pipeline: string } {
  const { detectedTech, stealthLevel, scanType, target, targetSize } = params;

  // Collect tech-specific Nuclei tags
  const matchedTechs = TECH_SIGNATURES.filter(t =>
    detectedTech.some(dt =>
      t.indicators.some(ind => dt.toLowerCase().includes(ind.toLowerCase())) ||
      t.technology.toLowerCase().includes(dt.toLowerCase())
    )
  );

  const nucleiTags = new Set<string>();
  const ports = new Set<string>();

  for (const tech of matchedTechs) {
    for (const tag of tech.nucleiTags.split(',')) {
      nucleiTags.add(tag.trim());
    }
    for (const port of tech.scanPorts.split(',')) {
      ports.add(port.trim());
    }
  }

  // Add base tags based on scan type
  if (scanType === 'vuln' || scanType === 'full') {
    nucleiTags.add('cve');
    nucleiTags.add('misconfig');
    nucleiTags.add('exposure');
  }

  const portList = ports.size > 0 ? Array.from(ports).join(',') : '1-1024,3306,3389,5432,5900,6379,8080,8443,27017';

  // Select discovery tool based on target size and stealth
  let discoveryCmd: string;
  let rate: number;

  switch (stealthLevel) {
    case 'maximum': rate = 10; break;
    case 'high': rate = 50; break;
    case 'medium': rate = 200; break;
    case 'low': rate = 1000; break;
    case 'minimal': rate = 5000; break;
  }

  if (targetSize === 'single') {
    // RustScan for single hosts
    const batchSize = stealthLevel === 'maximum' || stealthLevel === 'high' ? 128 : stealthLevel === 'medium' ? 500 : 4500;
    discoveryCmd = `rustscan -a ${target} --range 1-65535 -b ${batchSize} -t ${stealthLevel === 'maximum' ? 5000 : 2000} -g`;
  } else if (stealthLevel === 'high' || stealthLevel === 'maximum') {
    // Naabu for stealth
    discoveryCmd = `naabu -host ${target} -p ${portList} -rate ${rate} -scan-type s -json`;
  } else {
    // Masscan for speed
    const evasionFlags = stealthLevel === 'medium' ? '--source-port 53 --randomize-hosts' : '';
    discoveryCmd = `masscan ${target} -p${portList} --rate ${rate} ${evasionFlags} -oJ -`.trim();
  }

  // Fingerprinting command
  const httpxRate = stealthLevel === 'maximum' || stealthLevel === 'high' ? '-rate-limit 10' : '';
  const fingerprintCmd = `httpx -json -title -tech-detect -status-code -server -follow-redirects ${httpxRate}`.trim();

  // Vulnerability detection command
  const nucleiTagList = Array.from(nucleiTags).join(',');
  const nucleiRate = stealthLevel === 'maximum' || stealthLevel === 'high' ? '-rate-limit 10' : '';
  const vulnCmd = scanType === 'recon'
    ? ''
    : `nuclei -json -tags ${nucleiTagList || 'cve,misconfig'} -severity medium,high,critical ${nucleiRate}`.trim();

  // Full pipeline
  const pipeline = vulnCmd
    ? `${discoveryCmd} | ${fingerprintCmd} | ${vulnCmd}`
    : `${discoveryCmd} | ${fingerprintCmd}`;

  return { discoveryCmd, fingerprintCmd, vulnCmd, pipeline };
}
