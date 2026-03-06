/**
 * nmap-knowledge.ts — Comprehensive Nmap Knowledge Module
 * 
 * Provides the LLM with expert-level nmap knowledge including:
 * - Evasion technique profiles for IDS/IPS/firewall bypass
 * - NSE script catalog organized by service and technology
 * - Technology-specific scan plan templates
 * - Scan profile recommendations based on target context
 * 
 * This module is injected into LLM prompts during:
 * - Scan plan generation (engagement-orchestrator)
 * - Vulnerability correlation
 * - Hunt hypothesis generation
 * - Asset classification
 */

// ─── Evasion Technique Profiles ────────────────────────────────────────────

export interface EvasionProfile {
  name: string;
  risk: 'low' | 'medium' | 'high';
  description: string;
  flags: string[];
  bypassCapability: string[];
  limitations: string[];
  bestFor: string[];
}

export const EVASION_PROFILES: EvasionProfile[] = [
  {
    name: 'Stealth SYN',
    risk: 'low',
    description: 'Half-open SYN scan. Default stealth mode — sends SYN, reads SYN/ACK or RST, never completes handshake. Leaves no application-layer log on most targets.',
    flags: ['-sS'],
    bypassCapability: ['Application-layer logging', 'Connection-based IDS rules'],
    limitations: ['Detected by stateful firewalls', 'Requires root/raw socket privileges'],
    bestFor: ['Initial port discovery', 'Production network recon', 'Any authorized assessment']
  },
  {
    name: 'ACK Probe',
    risk: 'low',
    description: 'Sends TCP ACK packets only. Cannot determine open/closed ports but maps firewall rules by checking which ports are filtered vs unfiltered. Firewalls cannot determine if ACK is part of an established connection.',
    flags: ['-sA', '-Pn', '-n', '--disable-arp-ping'],
    bypassCapability: ['Stateful firewalls (appears as established connection)', 'SYN-based IDS rules', 'Connection tracking that only logs SYN'],
    limitations: ['Cannot determine if port is open or closed', 'Only shows filtered vs unfiltered', 'Stateless packet filters still detect'],
    bestFor: ['Firewall rule mapping', 'Determining which ports bypass firewall', 'Pre-scan reconnaissance']
  },
  {
    name: 'FIN/NULL/XMAS Stealth',
    risk: 'medium',
    description: 'Sends packets with unusual flag combinations (FIN only, no flags, or FIN+PSH+URG). RFC 793 says closed ports respond RST, open ports stay silent. Sneaks through non-stateful firewalls and packet filtering routers.',
    flags: ['-sF', '-sN', '-sX'],
    bypassCapability: ['Non-stateful firewalls', 'Packet filtering routers', 'SYN-only IDS rules'],
    limitations: ['Does not work against Windows (sends RST for all)', 'Blocked by stateful firewalls', 'Cannot distinguish open from filtered'],
    bestFor: ['Linux/Unix targets behind simple firewalls', 'Confirming firewall type (stateful vs stateless)', 'Secondary validation scan']
  },
  {
    name: 'Idle/Zombie Scan',
    risk: 'high',
    description: 'Ultimate stealth — uses a zombie host with predictable IP ID sequence. No packets sent from real scanner IP. Completely anonymous port scanning by exploiting IP ID increment behavior.',
    flags: ['-sI <zombie_host>'],
    bypassCapability: ['All IP-based logging', 'All source-based IDS rules', 'Firewall source whitelists (if zombie is trusted)'],
    limitations: ['Requires finding suitable zombie host with predictable IP ID', 'Slow and complex', 'Zombie must be idle', 'Only discovers open ports'],
    bestFor: ['Maximum attribution avoidance', 'Scanning from trusted zombie IP', 'Bypassing source-IP whitelists']
  },
  {
    name: 'Window Scan',
    risk: 'low',
    description: 'Like ACK scan but examines the TCP window field in RST responses. Some implementations return positive window for open ports and zero for closed. More informative than pure ACK scan.',
    flags: ['-sW'],
    bypassCapability: ['Same as ACK scan — appears as established connection traffic'],
    limitations: ['Implementation-dependent', 'Not reliable on all OS types', 'Same limitations as ACK scan'],
    bestFor: ['Follow-up to ACK scan for more detail', 'Systems where ACK shows unfiltered ports']
  },
  {
    name: 'Source Port Spoofing',
    risk: 'medium',
    description: 'Sets source port to a commonly trusted port (53/DNS, 80/HTTP, 88/Kerberos). Many firewalls allow return traffic from these ports, especially DNS port 53 which is often whitelisted for zone transfers.',
    flags: ['--source-port 53', '-g 53'],
    bypassCapability: ['Firewalls that trust DNS return traffic', 'Port-based ACLs', 'Firewalls allowing established DNS connections'],
    limitations: ['Only works if firewall trusts the spoofed port', 'ISPs may filter spoofed source ports', 'Single source port for all probes'],
    bestFor: ['Bypassing DNS-trusting firewalls', 'DMZ environments', 'Internal network scanning']
  },
  {
    name: 'Fragmentation',
    risk: 'medium',
    description: 'Splits TCP headers across multiple IP fragments (8-byte or 16-byte chunks). Signature-based IDS cannot match patterns across fragments. Legacy systems often fail to reassemble for inspection.',
    flags: ['-f', '-f -f', '--mtu 16', '--mtu 24'],
    bypassCapability: ['Signature-based IDS/IPS', 'Deep packet inspection (legacy)', 'Pattern-matching firewalls'],
    limitations: ['Modern IDS reassemble fragments', 'Some firewalls drop all fragments', 'Can cause scan unreliability'],
    bestFor: ['Legacy IDS/IPS environments', 'Combined with other evasion techniques', 'Testing DPI capabilities']
  },
  {
    name: 'Decoy Swarm',
    risk: 'medium',
    description: 'Injects multiple spoofed source IPs into scan traffic. Real scanner IP is hidden among 3-10 decoy IPs. Makes attribution extremely difficult for defenders analyzing logs.',
    flags: ['-D RND:5', '-D decoy1,decoy2,ME,decoy3'],
    bypassCapability: ['Source-IP attribution', 'Manual log analysis', 'Simple IDS source tracking'],
    limitations: ['Decoy IPs should be live to avoid SYN flood detection', 'ISPs may drop spoofed packets', 'Increases scan traffic volume'],
    bestFor: ['Attribution masking', 'Red team operations', 'Combined with SYN or ACK scans']
  },
  {
    name: 'Timing Control',
    risk: 'low',
    description: 'Controls scan speed to stay below IDS rate thresholds. T0 (Paranoid) sends one probe every 5 minutes. T1 (Sneaky) every 15 seconds. T2 (Polite) every 0.4 seconds. Combined with --max-rate for precise control.',
    flags: ['-T0', '-T1', '-T2', '--max-rate 10', '--scan-delay 1s', '--max-retries 1'],
    bypassCapability: ['Rate-based IDS alerts', 'Threshold-based anomaly detection', 'Connection-rate firewalls'],
    limitations: ['Extremely slow (T0 can take hours for small scans)', 'May timeout on large port ranges', 'Does not evade content-based detection'],
    bestFor: ['Long-term covert recon', 'Monitored environments', 'Avoiding rate-limit triggers']
  },
  {
    name: 'DNS Manipulation',
    risk: 'low',
    description: 'Controls DNS resolution to avoid internal DNS logging. Uses external resolvers (8.8.8.8, 1.1.1.1) or disables DNS entirely. Prevents reverse DNS queries from alerting internal DNS monitoring.',
    flags: ['--dns-servers 8.8.8.8,1.1.1.1', '-n', '--system-dns'],
    bypassCapability: ['Internal DNS monitoring', 'DNS-based anomaly detection', 'Reverse DNS logging'],
    limitations: ['External DNS may be slower', 'Some networks block external DNS', 'Disabling DNS loses hostname context'],
    bestFor: ['DMZ scanning', 'Cloud environments', 'Avoiding DNS-based detection']
  },
  {
    name: 'MAC/Data Spoofing',
    risk: 'medium',
    description: 'Alters MAC address and packet payload size to evade fingerprinting. Can mimic trusted vendor MACs (Apple, Cisco, HP). Random data padding changes packet signatures.',
    flags: ['--spoof-mac 0', '--spoof-mac Apple', '--data-length 50', '--badsum'],
    bypassCapability: ['MAC-based ACLs', 'Device fingerprinting', 'Packet signature matching'],
    limitations: ['MAC spoofing only works on local network', 'Data padding increases traffic', '--badsum packets dropped by most hosts (useful for firewall detection)'],
    bestFor: ['Local network scanning', 'Bypassing MAC whitelists', 'Testing NAC systems']
  },
  {
    name: 'Combined Layered Evasion',
    risk: 'high',
    description: 'Combines multiple evasion techniques for maximum stealth: ACK scan + decoys + DNS proxy + fragmentation + slow timing. Each layer defeats a different detection mechanism.',
    flags: ['-sA', '-f', '-T1', '-D RND:3', '--source-port 53', '-n', '--data-length 24', '-Pn'],
    bypassCapability: ['Multi-layer defense stacks', 'Stateful firewalls + IDS + logging', 'SOC analyst manual review'],
    limitations: ['Very slow', 'Complex to configure', 'May produce unreliable results', 'Requires careful tuning per target'],
    bestFor: ['Red team operations against hardened targets', 'Testing defense-in-depth', 'Maximum stealth requirement']
  }
];

// ─── NSE Script Catalog ────────────────────────────────────────────────────

export interface NseScript {
  name: string;
  category: string[];
  description: string;
  ports: string;
  cve?: string;
  riskLevel: 'safe' | 'low' | 'medium' | 'high' | 'critical';
  techTargets: string[];
  evasionCompatible: boolean;
  args?: string;
}

export const NSE_SCRIPT_CATALOG: NseScript[] = [
  // ── HTTP/Web Application Scripts ──
  { name: 'http-title', category: ['default', 'safe'], description: 'Grabs webpage titles for technology fingerprinting', ports: '80,443,8080,8443', riskLevel: 'safe', techTargets: ['any-web'], evasionCompatible: true },
  { name: 'http-headers', category: ['default', 'safe'], description: 'Retrieves HTTP response headers revealing server tech, framework, and security headers', ports: '80,443,8080,8443', riskLevel: 'safe', techTargets: ['any-web'], evasionCompatible: true },
  { name: 'http-methods', category: ['default', 'safe'], description: 'Checks allowed HTTP methods (PUT, DELETE, TRACE, OPTIONS). Dangerous methods indicate misconfiguration', ports: '80,443,8080,8443', riskLevel: 'safe', techTargets: ['any-web'], evasionCompatible: true },
  { name: 'http-enum', category: ['discovery', 'vuln'], description: 'Enumerates directories and files used by popular web apps (WordPress, Joomla, phpMyAdmin, etc.)', ports: '80,443,8080,8443', riskLevel: 'low', techTargets: ['any-web', 'cms'], evasionCompatible: true },
  { name: 'http-security-headers', category: ['safe', 'discovery'], description: 'Checks for HSTS, CSP, X-Frame-Options, X-Content-Type-Options, X-XSS-Protection headers', ports: '80,443,8080,8443', riskLevel: 'safe', techTargets: ['any-web', 'cloud'], evasionCompatible: true },
  { name: 'http-cors', category: ['safe', 'discovery'], description: 'Checks CORS configuration for overly permissive Access-Control-Allow-Origin', ports: '80,443,8080,8443', riskLevel: 'safe', techTargets: ['any-web', 'api', 'cloud'], evasionCompatible: true },
  { name: 'http-cookie-flags', category: ['vuln', 'safe'], description: 'Reports session cookies missing httponly or secure flags', ports: '80,443,8080,8443', riskLevel: 'safe', techTargets: ['any-web'], evasionCompatible: true },
  { name: 'http-robots.txt', category: ['default', 'safe'], description: 'Parses robots.txt for hidden directories and sensitive paths', ports: '80,443,8080,8443', riskLevel: 'safe', techTargets: ['any-web'], evasionCompatible: true },
  { name: 'http-git', category: ['vuln', 'safe'], description: 'Checks for exposed .git repository in document root — reveals source code, credentials, history', ports: '80,443,8080,8443', riskLevel: 'low', techTargets: ['any-web', 'cloud'], evasionCompatible: true },
  { name: 'http-shellshock', category: ['vuln'], description: 'Tests for Shellshock (CVE-2014-6271, CVE-2014-7169) in CGI scripts', ports: '80,443,8080,8443', cve: 'CVE-2014-6271', riskLevel: 'medium', techTargets: ['apache', 'cgi', 'linux'], evasionCompatible: true, args: '--script-args uri=/cgi-bin/status' },
  { name: 'http-sql-injection', category: ['vuln', 'intrusive'], description: 'Spiders HTTP server looking for SQL injection in URL parameters and form fields', ports: '80,443,8080,8443', riskLevel: 'medium', techTargets: ['any-web', 'php', 'asp'], evasionCompatible: true },
  { name: 'http-stored-xss', category: ['vuln', 'intrusive'], description: 'Detects potential stored XSS by finding unfiltered special characters in responses', ports: '80,443,8080,8443', riskLevel: 'medium', techTargets: ['any-web'], evasionCompatible: true },
  { name: 'http-dombased-xss', category: ['vuln'], description: 'Detects DOM-based XSS where attacker-controlled input affects JavaScript execution', ports: '80,443,8080,8443', riskLevel: 'low', techTargets: ['any-web', 'javascript'], evasionCompatible: true },
  { name: 'http-csrf', category: ['vuln'], description: 'Detects Cross-Site Request Forgery vulnerabilities in forms', ports: '80,443,8080,8443', riskLevel: 'low', techTargets: ['any-web'], evasionCompatible: true },
  { name: 'http-slowloris-check', category: ['vuln'], description: 'Tests for Slowloris DoS vulnerability without launching actual attack', ports: '80,443,8080,8443', riskLevel: 'low', techTargets: ['apache', 'any-web'], evasionCompatible: true },
  { name: 'http-internal-ip-disclosure', category: ['vuln', 'safe'], description: 'Detects internal IP address leakage via HTTP/1.0 request without Host header', ports: '80,443,8080,8443', riskLevel: 'safe', techTargets: ['any-web', 'cloud'], evasionCompatible: true },
  { name: 'http-cross-domain-policy', category: ['vuln', 'safe'], description: 'Checks crossdomain.xml and clientaccesspolicy.xml for overly permissive trusted domains', ports: '80,443,8080,8443', riskLevel: 'safe', techTargets: ['any-web', 'flash'], evasionCompatible: true },
  { name: 'http-jsonp-detection', category: ['vuln'], description: 'Discovers JSONP endpoints that can bypass Same-Origin Policy', ports: '80,443,8080,8443', riskLevel: 'low', techTargets: ['api', 'javascript'], evasionCompatible: true },
  { name: 'http-method-tamper', category: ['vuln'], description: 'Attempts HTTP verb tampering to bypass password-protected resources (401)', ports: '80,443,8080,8443', riskLevel: 'medium', techTargets: ['any-web'], evasionCompatible: true },
  { name: 'http-passwd', category: ['vuln'], description: 'Tests for directory traversal by attempting to retrieve /etc/passwd or \\boot.ini', ports: '80,443,8080,8443', riskLevel: 'medium', techTargets: ['any-web', 'linux', 'windows'], evasionCompatible: true },
  { name: 'http-default-accounts', category: ['auth'], description: 'Tests for default credentials on web management interfaces (Tomcat, Jenkins, etc.)', ports: '80,443,8080,8443', riskLevel: 'medium', techTargets: ['tomcat', 'jenkins', 'any-web'], evasionCompatible: true },
  { name: 'http-config-backup', category: ['discovery'], description: 'Checks for backup configuration files (.bak, .old, .orig, ~) that may contain credentials', ports: '80,443,8080,8443', riskLevel: 'low', techTargets: ['any-web'], evasionCompatible: true },
  { name: 'http-trace', category: ['vuln'], description: 'Checks if HTTP TRACE method is enabled — can be used for XST attacks', ports: '80,443,8080,8443', riskLevel: 'low', techTargets: ['any-web'], evasionCompatible: true },

  // ── CMS-Specific Scripts ──
  { name: 'http-wordpress-enum', category: ['discovery'], description: 'Enumerates WordPress plugins, themes, and users — identifies outdated/vulnerable components', ports: '80,443', riskLevel: 'low', techTargets: ['wordpress'], evasionCompatible: true },
  { name: 'http-wordpress-brute', category: ['brute'], description: 'Brute forces WordPress login credentials', ports: '80,443', riskLevel: 'high', techTargets: ['wordpress'], evasionCompatible: false },
  { name: 'http-vuln-cve2017-1001000', category: ['vuln'], description: 'WordPress REST API content injection (WordPress < 4.7.2)', ports: '80,443', cve: 'CVE-2017-1001000', riskLevel: 'medium', techTargets: ['wordpress'], evasionCompatible: true },
  { name: 'http-vuln-cve2014-3704', category: ['vuln'], description: 'Drupal SQLi (Drupalgeddon) — pre-auth SQL injection in Drupal 7', ports: '80,443', cve: 'CVE-2014-3704', riskLevel: 'high', techTargets: ['drupal'], evasionCompatible: true },
  { name: 'http-vuln-cve2017-8917', category: ['vuln'], description: 'Joomla SQL injection in com_fields component', ports: '80,443', cve: 'CVE-2017-8917', riskLevel: 'high', techTargets: ['joomla'], evasionCompatible: true },

  // ── Server-Specific Vulnerability Scripts ──
  { name: 'http-vuln-cve2017-5638', category: ['vuln'], description: 'Apache Struts RCE via Content-Type header manipulation', ports: '80,443,8080', cve: 'CVE-2017-5638', riskLevel: 'critical', techTargets: ['struts', 'java', 'tomcat'], evasionCompatible: true },
  { name: 'http-vuln-cve2015-1635', category: ['vuln'], description: 'IIS HTTP.sys RCE (MS15-034) — remote code execution via Range header', ports: '80,443', cve: 'CVE-2015-1635', riskLevel: 'critical', techTargets: ['iis', 'windows'], evasionCompatible: true },
  { name: 'http-vuln-cve2010-0738', category: ['vuln'], description: 'JBoss authentication bypass via HTTP verb tampering', ports: '8080,8443', cve: 'CVE-2010-0738', riskLevel: 'high', techTargets: ['jboss', 'java'], evasionCompatible: true },
  { name: 'http-vuln-cve2012-1823', category: ['vuln'], description: 'PHP-CGI query string parameter injection RCE', ports: '80,443', cve: 'CVE-2012-1823', riskLevel: 'critical', techTargets: ['php', 'cgi'], evasionCompatible: true },
  { name: 'http-vuln-cve2013-0156', category: ['vuln'], description: 'Ruby on Rails XML parsing RCE', ports: '80,443,3000', cve: 'CVE-2013-0156', riskLevel: 'critical', techTargets: ['rails', 'ruby'], evasionCompatible: true },
  { name: 'http-vuln-cve2015-1427', category: ['vuln'], description: 'Elasticsearch Groovy sandbox bypass RCE', ports: '9200,9300', cve: 'CVE-2015-1427', riskLevel: 'critical', techTargets: ['elasticsearch'], evasionCompatible: true },
  { name: 'http-aspnet-debug', category: ['vuln'], description: 'Detects ASP.NET debug mode enabled in production', ports: '80,443', riskLevel: 'low', techTargets: ['aspnet', 'iis'], evasionCompatible: true },
  { name: 'http-iis-webdav-vuln', category: ['vuln'], description: 'IIS 5.1/6.0 WebDAV authentication bypass (MS09-020)', ports: '80,443', cve: 'MS09-020', riskLevel: 'high', techTargets: ['iis', 'webdav'], evasionCompatible: true },
  { name: 'http-vuln-cve2017-5689', category: ['vuln'], description: 'Intel AMT authentication bypass — remote management access', ports: '16992,16993', cve: 'CVE-2017-5689', riskLevel: 'critical', techTargets: ['intel-amt', 'bmc'], evasionCompatible: true },

  // ── SSL/TLS Scripts ──
  { name: 'ssl-heartbleed', category: ['vuln', 'safe'], description: 'Tests for Heartbleed (CVE-2014-0160) — memory disclosure via TLS heartbeat extension', ports: '443,8443,993,995,465', cve: 'CVE-2014-0160', riskLevel: 'safe', techTargets: ['openssl', 'any-tls'], evasionCompatible: true },
  { name: 'ssl-poodle', category: ['vuln', 'safe'], description: 'Tests for POODLE (CVE-2014-3566) — SSLv3 CBC padding oracle attack', ports: '443,8443', cve: 'CVE-2014-3566', riskLevel: 'safe', techTargets: ['any-tls'], evasionCompatible: true },
  { name: 'ssl-cert', category: ['default', 'safe'], description: 'Retrieves SSL certificate details: issuer, subject, SANs, expiry, key size. Reveals infrastructure and domain scope.', ports: '443,8443,993,995,465,636', riskLevel: 'safe', techTargets: ['any-tls', 'cloud'], evasionCompatible: true },
  { name: 'ssl-enum-ciphers', category: ['safe', 'discovery'], description: 'Lists all supported cipher suites with security grades (A-F). Identifies weak ciphers, export-grade crypto, and protocol versions.', ports: '443,8443', riskLevel: 'safe', techTargets: ['any-tls'], evasionCompatible: true },
  { name: 'ssl-dh-params', category: ['vuln', 'safe'], description: 'Checks Diffie-Hellman parameters for Logjam vulnerability and weak key sizes', ports: '443,8443', riskLevel: 'safe', techTargets: ['any-tls'], evasionCompatible: true },
  { name: 'ssl-known-key', category: ['vuln', 'safe'], description: 'Checks if SSL certificate uses a known compromised private key', ports: '443,8443', riskLevel: 'safe', techTargets: ['any-tls'], evasionCompatible: true },
  { name: 'ssl-ccs-injection', category: ['vuln', 'safe'], description: 'Tests for CCS injection (CVE-2014-0224) — MITM via ChangeCipherSpec', ports: '443,8443', cve: 'CVE-2014-0224', riskLevel: 'safe', techTargets: ['openssl', 'any-tls'], evasionCompatible: true },
  { name: 'sslv2-drown', category: ['vuln'], description: 'Tests for DROWN attack (CVE-2016-0800) — cross-protocol attack using SSLv2', ports: '443,8443', cve: 'CVE-2016-0800', riskLevel: 'low', techTargets: ['any-tls'], evasionCompatible: true },
  { name: 'tls-ticketbleed', category: ['vuln'], description: 'Tests for Ticketbleed (CVE-2016-9244) in F5 BIG-IP products', ports: '443,8443', cve: 'CVE-2016-9244', riskLevel: 'low', techTargets: ['f5', 'bigip'], evasionCompatible: true },

  // ── SMB/Windows Scripts ──
  { name: 'smb-vuln-ms17-010', category: ['vuln'], description: 'EternalBlue — SMBv1 RCE. One of the most critical Windows vulns. Used by WannaCry/NotPetya.', ports: '445', cve: 'MS17-010', riskLevel: 'critical', techTargets: ['windows', 'smb'], evasionCompatible: true },
  { name: 'smb-vuln-ms08-067', category: ['vuln'], description: 'Conficker/Downadup — Server Service RCE. Classic Windows worm vector.', ports: '445', cve: 'MS08-067', riskLevel: 'critical', techTargets: ['windows', 'smb'], evasionCompatible: true },
  { name: 'smb-vuln-cve-2017-7494', category: ['vuln'], description: 'SambaCry — Samba RCE via writable share. Linux equivalent of EternalBlue.', ports: '445', cve: 'CVE-2017-7494', riskLevel: 'critical', techTargets: ['linux', 'samba'], evasionCompatible: true },
  { name: 'smb-double-pulsar-backdoor', category: ['vuln'], description: 'Detects DoublePulsar backdoor implant (NSA tool leaked by Shadow Brokers)', ports: '445', riskLevel: 'critical', techTargets: ['windows', 'smb'], evasionCompatible: true },
  { name: 'smb-enum-shares', category: ['discovery'], description: 'Enumerates SMB shared folders — reveals file shares, permissions, potential data exposure', ports: '445,139', riskLevel: 'low', techTargets: ['windows', 'samba', 'smb'], evasionCompatible: true },
  { name: 'smb-enum-users', category: ['discovery'], description: 'Enumerates user accounts via SMB — useful for password spray target lists', ports: '445,139', riskLevel: 'low', techTargets: ['windows', 'smb'], evasionCompatible: true },
  { name: 'smb-os-discovery', category: ['default', 'safe'], description: 'Determines OS version, computer name, domain, workgroup via SMB', ports: '445,139', riskLevel: 'safe', techTargets: ['windows', 'samba'], evasionCompatible: true },
  { name: 'smb-protocols', category: ['safe', 'discovery'], description: 'Lists supported SMB protocol versions (1, 2, 3) — SMBv1 is a critical risk', ports: '445', riskLevel: 'safe', techTargets: ['windows', 'samba', 'smb'], evasionCompatible: true },
  { name: 'smb-security-mode', category: ['safe', 'discovery'], description: 'Checks SMB signing requirements — unsigned SMB enables relay attacks', ports: '445', riskLevel: 'safe', techTargets: ['windows', 'smb'], evasionCompatible: true },

  // ── SSH Scripts ──
  { name: 'ssh2-enum-algos', category: ['safe', 'discovery'], description: 'Lists SSH key exchange, encryption, MAC, and compression algorithms. Identifies weak crypto.', ports: '22', riskLevel: 'safe', techTargets: ['ssh', 'linux', 'unix'], evasionCompatible: true },
  { name: 'ssh-auth-methods', category: ['safe', 'discovery'], description: 'Lists supported SSH authentication methods (password, publickey, keyboard-interactive)', ports: '22', riskLevel: 'safe', techTargets: ['ssh'], evasionCompatible: true },
  { name: 'ssh-hostkey', category: ['default', 'safe'], description: 'Retrieves SSH host key fingerprints for verification and tracking', ports: '22', riskLevel: 'safe', techTargets: ['ssh'], evasionCompatible: true },

  // ── DNS Scripts ──
  { name: 'dns-zone-transfer', category: ['vuln', 'discovery'], description: 'Attempts AXFR zone transfer — reveals all DNS records if misconfigured', ports: '53', riskLevel: 'low', techTargets: ['dns'], evasionCompatible: true },
  { name: 'dns-brute', category: ['discovery'], description: 'Brute forces subdomains using wordlist — discovers hidden hosts', ports: '53', riskLevel: 'low', techTargets: ['dns'], evasionCompatible: true },
  { name: 'dns-recursion', category: ['safe', 'discovery'], description: 'Checks if DNS server allows recursive queries — open resolver abuse risk', ports: '53', riskLevel: 'safe', techTargets: ['dns'], evasionCompatible: true },
  { name: 'dns-cache-snoop', category: ['discovery'], description: 'DNS cache snooping — reveals which domains the server has recently resolved', ports: '53', riskLevel: 'low', techTargets: ['dns'], evasionCompatible: true },

  // ── FTP Scripts ──
  { name: 'ftp-anon', category: ['default', 'safe'], description: 'Checks for anonymous FTP login — common misconfiguration exposing files', ports: '21', riskLevel: 'safe', techTargets: ['ftp'], evasionCompatible: true },
  { name: 'ftp-vsftpd-backdoor', category: ['vuln', 'exploit'], description: 'Tests for vsFTPd 2.3.4 backdoor (CVE-2011-2523) — opens shell on port 6200', ports: '21', cve: 'CVE-2011-2523', riskLevel: 'high', techTargets: ['vsftpd'], evasionCompatible: true },
  { name: 'ftp-proftpd-backdoor', category: ['vuln', 'exploit'], description: 'Tests for ProFTPD 1.3.3c backdoor', ports: '21', riskLevel: 'high', techTargets: ['proftpd'], evasionCompatible: true },

  // ── Database Scripts ──
  { name: 'mysql-info', category: ['default', 'safe'], description: 'Retrieves MySQL server version, capabilities, and status', ports: '3306', riskLevel: 'safe', techTargets: ['mysql', 'mariadb'], evasionCompatible: true },
  { name: 'mysql-enum', category: ['discovery'], description: 'Enumerates MySQL user accounts', ports: '3306', riskLevel: 'low', techTargets: ['mysql', 'mariadb'], evasionCompatible: true },
  { name: 'mysql-vuln-cve2012-2122', category: ['vuln'], description: 'MySQL/MariaDB authentication bypass via timing attack', ports: '3306', cve: 'CVE-2012-2122', riskLevel: 'high', techTargets: ['mysql', 'mariadb'], evasionCompatible: true },
  { name: 'mysql-empty-password', category: ['auth'], description: 'Checks for MySQL root account with empty password', ports: '3306', riskLevel: 'medium', techTargets: ['mysql', 'mariadb'], evasionCompatible: true },
  { name: 'ms-sql-info', category: ['default', 'safe'], description: 'Retrieves Microsoft SQL Server instance information', ports: '1433', riskLevel: 'safe', techTargets: ['mssql', 'windows'], evasionCompatible: true },
  { name: 'pgsql-brute', category: ['brute'], description: 'PostgreSQL password brute force', ports: '5432', riskLevel: 'high', techTargets: ['postgresql'], evasionCompatible: false },
  { name: 'redis-info', category: ['default', 'safe'], description: 'Retrieves Redis server info — version, memory, connected clients', ports: '6379', riskLevel: 'safe', techTargets: ['redis'], evasionCompatible: true },
  { name: 'mongodb-info', category: ['default', 'safe'], description: 'Retrieves MongoDB server info and build details', ports: '27017', riskLevel: 'safe', techTargets: ['mongodb'], evasionCompatible: true },
  { name: 'mongodb-databases', category: ['discovery'], description: 'Lists MongoDB databases — reveals data exposure if auth disabled', ports: '27017', riskLevel: 'low', techTargets: ['mongodb'], evasionCompatible: true },

  // ── RDP Scripts ──
  { name: 'rdp-enum-encryption', category: ['safe', 'discovery'], description: 'Checks RDP encryption level and security protocol', ports: '3389', riskLevel: 'safe', techTargets: ['rdp', 'windows'], evasionCompatible: true },
  { name: 'rdp-vuln-ms12-020', category: ['vuln'], description: 'RDP DoS/RCE vulnerability (predecessor to BlueKeep)', ports: '3389', cve: 'MS12-020', riskLevel: 'medium', techTargets: ['rdp', 'windows'], evasionCompatible: true },

  // ── SNMP Scripts ──
  { name: 'snmp-info', category: ['default', 'safe'], description: 'Retrieves system info via SNMP — hostname, OS, uptime, contact', ports: '161', riskLevel: 'safe', techTargets: ['snmp', 'network-device'], evasionCompatible: true },
  { name: 'snmp-brute', category: ['brute'], description: 'Brute forces SNMP community strings', ports: '161', riskLevel: 'medium', techTargets: ['snmp'], evasionCompatible: false },
  { name: 'snmp-interfaces', category: ['discovery'], description: 'Enumerates network interfaces via SNMP', ports: '161', riskLevel: 'low', techTargets: ['snmp', 'network-device'], evasionCompatible: true },

  // ── Miscellaneous ──
  { name: 'vulners', category: ['external', 'vuln'], description: 'Queries vulners.com API to match service versions against CVE database. EXTERNAL SCRIPT — requires installation.', ports: 'any', riskLevel: 'safe', techTargets: ['any'], evasionCompatible: true },
  { name: 'rmi-vuln-classloader', category: ['vuln'], description: 'Java RMI classloader vulnerability — allows remote code loading', ports: '1099', riskLevel: 'high', techTargets: ['java', 'rmi'], evasionCompatible: true },
  { name: 'rsa-vuln-roca', category: ['vuln'], description: 'ROCA factorization attack on RSA keys generated by Infineon TPMs', ports: 'any', riskLevel: 'medium', techTargets: ['tpm', 'smartcard'], evasionCompatible: true },
];

// ─── Technology Detection Patterns ─────────────────────────────────────────

export interface TechSignature {
  technology: string;
  indicators: string[];
  recommendedScripts: string[];
  recommendedEvasion: string[];
  scanPorts: string;
  notes: string;
}

export const TECH_SIGNATURES: TechSignature[] = [
  {
    technology: 'WordPress',
    indicators: ['wp-content', 'wp-includes', 'wp-json', 'WordPress', 'xmlrpc.php', '/wp-login.php'],
    recommendedScripts: ['http-wordpress-enum', 'http-vuln-cve2017-1001000', 'http-enum', 'http-security-headers', 'ssl-enum-ciphers'],
    recommendedEvasion: ['Timing Control', 'Source Port Spoofing'],
    scanPorts: '80,443',
    notes: 'Check for outdated plugins (biggest attack surface). wp-json API often exposes user enumeration. xmlrpc.php enables brute force amplification.'
  },
  {
    technology: 'Drupal',
    indicators: ['Drupal', 'sites/default', 'misc/drupal.js', '/node/', 'X-Drupal-Cache'],
    recommendedScripts: ['http-vuln-cve2014-3704', 'http-enum', 'http-security-headers'],
    recommendedEvasion: ['Timing Control'],
    scanPorts: '80,443',
    notes: 'Drupalgeddon (CVE-2014-3704) is pre-auth SQLi. Check for /CHANGELOG.txt version disclosure.'
  },
  {
    technology: 'Joomla',
    indicators: ['Joomla', '/administrator/', 'com_content', '/media/jui/'],
    recommendedScripts: ['http-vuln-cve2017-8917', 'http-enum', 'http-security-headers'],
    recommendedEvasion: ['Timing Control'],
    scanPorts: '80,443',
    notes: 'Check /administrator/manifests/files/joomla.xml for version. com_fields SQLi in 3.7.x.'
  },
  {
    technology: 'Apache HTTP Server',
    indicators: ['Apache', 'Server: Apache', 'mod_ssl', 'mod_php', 'mod_rewrite'],
    recommendedScripts: ['http-shellshock', 'http-vuln-cve2011-3192', 'http-vuln-cve2011-3368', 'http-enum', 'http-methods', 'http-security-headers', 'http-slowloris-check'],
    recommendedEvasion: ['Fragmentation', 'Timing Control'],
    scanPorts: '80,443,8080,8443',
    notes: 'Check for mod_status, mod_info exposure. Shellshock affects CGI scripts. Range header DoS (CVE-2011-3192) on older versions.'
  },
  {
    technology: 'Nginx',
    indicators: ['nginx', 'Server: nginx'],
    recommendedScripts: ['http-enum', 'http-methods', 'http-security-headers', 'http-cors', 'ssl-enum-ciphers'],
    recommendedEvasion: ['Timing Control'],
    scanPorts: '80,443,8080',
    notes: 'Check for off-by-slash misconfiguration in alias directives. Version disclosure in Server header.'
  },
  {
    technology: 'IIS/ASP.NET',
    indicators: ['Microsoft-IIS', 'ASP.NET', 'X-AspNet-Version', 'X-Powered-By: ASP.NET', '.aspx', '.ashx'],
    recommendedScripts: ['http-aspnet-debug', 'http-iis-webdav-vuln', 'http-vuln-cve2015-1635', 'http-enum', 'http-methods', 'http-security-headers'],
    recommendedEvasion: ['Source Port Spoofing', 'Timing Control'],
    scanPorts: '80,443,8080',
    notes: 'Check for short filename enumeration (~1 trick). HTTP.sys RCE (MS15-034) on IIS 7.5-8.5. WebDAV often enabled by default.'
  },
  {
    technology: 'Apache Tomcat/Java',
    indicators: ['Apache-Coyote', 'Tomcat', 'JSESSIONID', '.jsp', '.do', 'Servlet', 'X-Powered-By: Servlet'],
    recommendedScripts: ['http-vuln-cve2017-5638', 'http-vuln-cve2010-0738', 'http-default-accounts', 'http-enum', 'rmi-vuln-classloader'],
    recommendedEvasion: ['Timing Control', 'Fragmentation'],
    scanPorts: '80,443,8080,8443,1099',
    notes: 'Check /manager/html for default creds (tomcat:tomcat). Struts RCE via Content-Type. JMX/RMI on 1099.'
  },
  {
    technology: 'PHP',
    indicators: ['PHP', 'X-Powered-By: PHP', '.php', 'PHPSESSID', 'php-fpm'],
    recommendedScripts: ['http-vuln-cve2012-1823', 'http-phpself-xss', 'http-phpmyadmin-dir-traversal', 'http-sql-injection', 'http-enum'],
    recommendedEvasion: ['Timing Control'],
    scanPorts: '80,443',
    notes: 'PHP-CGI RCE (CVE-2012-1823) on older setups. Check for phpinfo() exposure. phpMyAdmin often on /phpmyadmin/.'
  },
  {
    technology: 'Ruby on Rails',
    indicators: ['X-Powered-By: Phusion Passenger', 'X-Runtime', '_rails_', 'Set-Cookie: _session_id', 'ActionController'],
    recommendedScripts: ['http-vuln-cve2013-0156', 'http-enum', 'http-git', 'http-security-headers'],
    recommendedEvasion: ['Timing Control'],
    scanPorts: '80,443,3000',
    notes: 'XML parsing RCE (CVE-2013-0156) on Rails < 3.2.11. Check for exposed .git and debug mode.'
  },
  {
    technology: 'Node.js/Express',
    indicators: ['X-Powered-By: Express', 'node.js', 'connect.sid', 'ETag: W/'],
    recommendedScripts: ['http-enum', 'http-security-headers', 'http-cors', 'http-cookie-flags', 'http-git', 'http-methods'],
    recommendedEvasion: ['Timing Control'],
    scanPorts: '80,443,3000,8080',
    notes: 'Check for exposed /debug, /status, /health endpoints. npm audit for dependency vulns. X-Powered-By often not removed.'
  },
  {
    technology: 'Elasticsearch',
    indicators: ['elasticsearch', '"cluster_name"', '"tagline" : "You Know, for Search"'],
    recommendedScripts: ['http-vuln-cve2015-1427', 'http-methods', 'http-enum'],
    recommendedEvasion: ['Timing Control'],
    scanPorts: '9200,9300',
    notes: 'Groovy RCE (CVE-2015-1427). Often exposed without auth. Check /_cat/indices for data exposure.'
  },
  {
    technology: 'Cloud-Hosted (AWS)',
    indicators: ['amazonaws.com', 'aws', 'x-amz-', 'AmazonS3', 'ELB', 'CloudFront', 'ec2'],
    recommendedScripts: ['http-security-headers', 'http-cors', 'ssl-cert', 'http-internal-ip-disclosure', 'http-git', 'http-enum', 'http-methods'],
    recommendedEvasion: ['Timing Control', 'DNS Manipulation'],
    scanPorts: '80,443,8080,8443,22',
    notes: 'Check for S3 bucket misconfigs. IMDS at 169.254.169.254 (SSRF target). Security groups are stateful. CloudFront may mask origin. Check for exposed .env files.'
  },
  {
    technology: 'Cloud-Hosted (Azure)',
    indicators: ['azure', 'azurewebsites.net', 'blob.core.windows.net', 'X-Azure-Ref', 'microsoft.com'],
    recommendedScripts: ['http-security-headers', 'http-cors', 'ssl-cert', 'http-enum', 'http-methods'],
    recommendedEvasion: ['Timing Control', 'DNS Manipulation'],
    scanPorts: '80,443,8080,22,3389',
    notes: 'Check for exposed Azure Blob storage. IMDS at 169.254.169.254. NSGs are stateful. Check for exposed management endpoints.'
  },
  {
    technology: 'Cloud-Hosted (GCP)',
    indicators: ['googleapis.com', 'gcp', 'google cloud', 'appspot.com', 'cloudfunctions.net'],
    recommendedScripts: ['http-security-headers', 'http-cors', 'ssl-cert', 'http-enum'],
    recommendedEvasion: ['Timing Control', 'DNS Manipulation'],
    scanPorts: '80,443,8080,22',
    notes: 'Check for exposed GCS buckets. IMDS at metadata.google.internal. Check for exposed Cloud Functions.'
  },
  {
    technology: 'MySQL/MariaDB',
    indicators: ['mysql', 'MariaDB', '3306/tcp open mysql'],
    recommendedScripts: ['mysql-info', 'mysql-enum', 'mysql-vuln-cve2012-2122', 'mysql-empty-password', 'mysql-databases'],
    recommendedEvasion: ['Timing Control'],
    scanPorts: '3306',
    notes: 'Auth bypass (CVE-2012-2122) affects MySQL 5.1.x-5.5.x. Check for remote root access. MariaDB shares many vulns.'
  },
  {
    technology: 'Redis',
    indicators: ['redis', '6379/tcp open redis'],
    recommendedScripts: ['redis-info', 'redis-brute'],
    recommendedEvasion: ['Timing Control'],
    scanPorts: '6379',
    notes: 'Often exposed without auth. CONFIG SET to write SSH keys or crontab. Check for SLAVEOF for data exfil.'
  },
  {
    technology: 'MongoDB',
    indicators: ['mongodb', '27017/tcp open mongodb'],
    recommendedScripts: ['mongodb-info', 'mongodb-databases', 'mongodb-brute'],
    recommendedEvasion: ['Timing Control'],
    scanPorts: '27017',
    notes: 'Often exposed without auth. Check for exposed admin database. Ransomware targets unauth MongoDB instances.'
  },
  {
    technology: 'Windows/SMB',
    indicators: ['Windows', 'microsoft-ds', 'netbios-ssn', 'SMB', 'CIFS'],
    recommendedScripts: ['smb-vuln-ms17-010', 'smb-vuln-ms08-067', 'smb-double-pulsar-backdoor', 'smb-enum-shares', 'smb-enum-users', 'smb-os-discovery', 'smb-protocols', 'smb-security-mode'],
    recommendedEvasion: ['ACK Probe', 'Fragmentation', 'Timing Control'],
    scanPorts: '445,139,135,3389',
    notes: 'EternalBlue (MS17-010) is still widespread. Check SMB signing for relay attacks. Enumerate shares for sensitive data.'
  },
  {
    technology: 'Docker/Container',
    indicators: ['docker', 'container', '2375/tcp', '2376/tcp', '/v1.', 'Docker-Distribution-Api-Version'],
    recommendedScripts: ['http-enum', 'http-methods', 'http-security-headers'],
    recommendedEvasion: ['Timing Control'],
    scanPorts: '2375,2376,80,443,8080',
    notes: 'Exposed Docker API (2375) = full host compromise. Check for unauthenticated access. Container escape via privileged mode.'
  }
];

// ─── Scan Profile Templates ────────────────────────────────────────────────

export interface ScanProfile {
  name: string;
  description: string;
  nmapCommand: string;
  useCase: string;
  stealthLevel: 'minimal' | 'low' | 'medium' | 'high' | 'maximum';
  estimatedDuration: string;
  riskLevel: 'safe' | 'low' | 'medium' | 'high';
}

export const SCAN_PROFILES: ScanProfile[] = [
  {
    name: 'Stealth Recon',
    description: 'Maximum IDS evasion with fragmentation, decoys, DNS proxy, and slow timing. For hardened targets.',
    nmapCommand: 'nmap -sS -T1 -f --source-port 53 -D RND:3 --data-length 24 -n -Pn --max-rate 10 --max-retries 1 {target}',
    useCase: 'Red team initial recon against monitored perimeter',
    stealthLevel: 'maximum',
    estimatedDuration: '30-60 min per 100 ports',
    riskLevel: 'safe'
  },
  {
    name: 'Firewall Mapping',
    description: 'ACK scan to map firewall rules without triggering connection-based alerts.',
    nmapCommand: 'nmap -sA -T2 -Pn -n --disable-arp-ping -p 21,22,25,53,80,110,143,443,445,993,995,1433,3306,3389,5432,8080,8443 {target}',
    useCase: 'Determine which ports pass through firewall before targeted scanning',
    stealthLevel: 'high',
    estimatedDuration: '2-5 min',
    riskLevel: 'safe'
  },
  {
    name: 'Web Application Assessment',
    description: 'Comprehensive web vulnerability scan using safe HTTP scripts with version detection.',
    nmapCommand: 'nmap -sV --script "http-* and safe" -p 80,443,8080,8443 {target}',
    useCase: 'Authorized web application security assessment',
    stealthLevel: 'low',
    estimatedDuration: '5-15 min',
    riskLevel: 'low'
  },
  {
    name: 'Full Vulnerability Scan',
    description: 'All vuln-category scripts against all detected services. Comprehensive but noisy.',
    nmapCommand: 'nmap -sV --script vuln -p- --open {target}',
    useCase: 'Authorized full vulnerability assessment with written permission',
    stealthLevel: 'minimal',
    estimatedDuration: '15-45 min',
    riskLevel: 'medium'
  },
  {
    name: 'Cloud Infrastructure',
    description: 'Cloud-optimized scan focusing on TLS, security headers, CORS, and common cloud misconfigs.',
    nmapCommand: 'nmap -sS -sV -T2 --script "ssl-* or http-security-headers or http-cors or http-git or http-enum or http-methods or http-internal-ip-disclosure" -p 80,443,8080,8443,22 --max-rate 50 {target}',
    useCase: 'Cloud-hosted target assessment (AWS, Azure, GCP)',
    stealthLevel: 'medium',
    estimatedDuration: '5-10 min',
    riskLevel: 'low'
  },
  {
    name: 'SMB/Windows Assessment',
    description: 'Windows-focused scan for EternalBlue, SMB misconfigs, share enumeration.',
    nmapCommand: 'nmap -sV --script "smb-vuln-* or smb-enum-* or smb-os-discovery or smb-protocols or smb-security-mode" -p 445,139,135,3389 {target}',
    useCase: 'Windows network assessment',
    stealthLevel: 'low',
    estimatedDuration: '3-10 min',
    riskLevel: 'medium'
  },
  {
    name: 'Database Assessment',
    description: 'Database-focused scan for auth bypass, empty passwords, version vulns.',
    nmapCommand: 'nmap -sV --script "mysql-* or pgsql-* or ms-sql-* or redis-* or mongodb-*" -p 3306,5432,1433,6379,27017 {target}',
    useCase: 'Database security assessment',
    stealthLevel: 'low',
    estimatedDuration: '3-8 min',
    riskLevel: 'medium'
  },
  {
    name: 'Quick Default Recon',
    description: 'Fast default script scan with version and OS detection. Good starting point.',
    nmapCommand: 'nmap -sC -sV -O --top-ports 1000 {target}',
    useCase: 'Initial authorized reconnaissance',
    stealthLevel: 'low',
    estimatedDuration: '2-5 min',
    riskLevel: 'low'
  },
  {
    name: 'DNS Assessment',
    description: 'DNS-focused scan for zone transfers, open recursion, subdomain brute force.',
    nmapCommand: 'nmap --script "dns-zone-transfer or dns-brute or dns-recursion or dns-cache-snoop or dns-nsid" -p 53 {target}',
    useCase: 'DNS infrastructure assessment',
    stealthLevel: 'low',
    estimatedDuration: '2-10 min depending on brute force',
    riskLevel: 'low'
  },
  {
    name: 'SSL/TLS Deep Audit',
    description: 'Comprehensive TLS configuration audit — ciphers, protocols, known vulns, cert details.',
    nmapCommand: 'nmap --script "ssl-heartbleed or ssl-poodle or ssl-enum-ciphers or ssl-cert or ssl-dh-params or ssl-known-key or ssl-ccs-injection or sslv2-drown or tls-ticketbleed" -p 443,8443,993,995,465,636 {target}',
    useCase: 'TLS security audit and compliance check',
    stealthLevel: 'medium',
    estimatedDuration: '2-5 min',
    riskLevel: 'safe'
  }
];

// ─── LLM Prompt Context Builders ───────────────────────────────────────────

/**
 * Returns comprehensive nmap knowledge for LLM scan plan generation.
 * Includes evasion profiles, tech-specific scripts, and scan templates.
 */
export function getNmapScanPlanContext(targetInfo?: {
  detectedTech?: string[];
  cloudProvider?: string;
  hasFirewall?: boolean;
  hasIDS?: boolean;
  stealthRequired?: boolean;
}): string {
  const sections: string[] = [];

  sections.push(`## Nmap Expert Knowledge for Scan Planning

You have access to comprehensive nmap expertise. Use this knowledge to select the optimal scan techniques, evasion strategies, and NSE scripts based on the target profile.`);

  // Evasion guidance
  sections.push(`### Evasion Technique Selection Guide

Choose evasion techniques based on the target's defensive posture:

| Scenario | Recommended Evasion | Flags |
|----------|-------------------|-------|
| No IDS/firewall detected | None needed — use -sS -sV for speed | -sS -sV -T4 |
| Basic firewall (stateless) | FIN/NULL/XMAS scan bypasses packet filters | -sF or -sN or -sX |
| Stateful firewall | ACK scan to map rules, then targeted SYN | -sA first, then -sS on unfiltered |
| IDS/IPS present | Slow timing + fragmentation + source port spoof | -T1 -f --source-port 53 |
| Heavily monitored SOC | Full layered evasion: decoys + fragment + timing + DNS | -sS -T1 -f -D RND:3 -g 53 -n --data-length 24 |
| Cloud WAF (CloudFlare/AWS) | Very slow with rate limiting | -T2 --max-rate 10 --scan-delay 2s |
| Maximum stealth required | Idle/zombie scan if zombie available | -sI <zombie> |

Key evasion principles:
1. **Layer techniques** — each defeats a different detection mechanism
2. **ACK scan first** to map firewall rules before targeted scanning
3. **Source port 53** is the most effective single evasion flag (DNS trust)
4. **-Pn -n** always for stealth (skip ping, skip DNS)
5. **--data-length** changes packet signature to evade pattern matching
6. **Decoys must be live IPs** or they trigger SYN flood alerts`);

  // Technology-specific guidance
  if (targetInfo?.detectedTech?.length) {
    const matchedTechs = TECH_SIGNATURES.filter(t =>
      targetInfo.detectedTech!.some(dt =>
        t.indicators.some(ind => dt.toLowerCase().includes(ind.toLowerCase())) ||
        t.technology.toLowerCase().includes(dt.toLowerCase())
      )
    );

    if (matchedTechs.length > 0) {
      sections.push(`### Detected Technology — Recommended Scripts\n`);
      for (const tech of matchedTechs) {
        sections.push(`**${tech.technology}:**
- Scripts: ${tech.recommendedScripts.join(', ')}
- Ports: ${tech.scanPorts}
- Notes: ${tech.notes}
- Evasion: ${tech.recommendedEvasion.join(', ')}`);
      }
    }
  }

  // Scan profile templates
  sections.push(`### Scan Profile Templates

Select the appropriate profile based on authorization level and target context:

${SCAN_PROFILES.map(p => `**${p.name}** (Stealth: ${p.stealthLevel}, Risk: ${p.riskLevel})
\`${p.nmapCommand}\`
Use case: ${p.useCase}`).join('\n\n')}`);

  // Cloud-specific guidance
  if (targetInfo?.cloudProvider) {
    sections.push(`### Cloud-Specific Scanning Notes (${targetInfo.cloudProvider})

- Cloud security groups are **stateful** — ACK scans less effective
- Use **-T2 with --max-rate 50** to avoid rate limiting
- Check for **IMDS at 169.254.169.254** via SSRF if web app found
- Look for **exposed storage** (S3 buckets, Blob containers, GCS buckets)
- **SSL cert SANs** reveal infrastructure scope (use ssl-cert script)
- Cloud WAFs may require **very slow timing** (-T1 or lower)
- Check for **exposed .env, .git, /debug, /status** endpoints`);
  }

  // NSE script selection rules
  sections.push(`### NSE Script Selection Rules

1. **Always start with safe scripts**: http-security-headers, ssl-cert, ssl-enum-ciphers, http-methods
2. **Match scripts to detected services**: Use the technology detection table above
3. **Escalate gradually**: safe → vuln → intrusive (only with authorization)
4. **Never run brute/exploit/dos** without explicit written authorization
5. **Use --script-timeout 30** to prevent hung scripts
6. **Combine -sV with scripts** for better version-based matching
7. **vulners.nse** (external) provides CVE database matching — recommend if installed
8. **http-enum** is the single most valuable web script — always include for web targets`);

  return sections.join('\n\n');
}

/**
 * Returns nmap knowledge for vulnerability correlation.
 * Helps LLM understand which NSE findings indicate real vulnerabilities.
 */
export function getNmapVulnCorrelationContext(): string {
  return `## Nmap NSE Vulnerability Correlation Guide

When correlating nmap scan results with vulnerabilities, use these rules:

### Critical Findings (Immediate Action Required)
- **smb-vuln-ms17-010: VULNERABLE** → EternalBlue RCE. Patch immediately. Wormable.
- **ssl-heartbleed: VULNERABLE** → Memory disclosure. Rotate all certs and keys.
- **http-vuln-cve2017-5638: VULNERABLE** → Struts RCE. Full server compromise possible.
- **http-vuln-cve2015-1635: VULNERABLE** → IIS HTTP.sys RCE. Full server compromise.
- **smb-double-pulsar-backdoor: INFECTED** → Active NSA implant. Assume full compromise.
- **ftp-vsftpd-backdoor: VULNERABLE** → Active backdoor. Assume compromised.

### High Findings (Urgent Remediation)
- **ssl-enum-ciphers: Grade F** → Weak/export-grade ciphers. MITM possible.
- **mysql-vuln-cve2012-2122: VULNERABLE** → Auth bypass. Database fully exposed.
- **smb-protocols: SMBv1 enabled** → Attack surface for EternalBlue and relay attacks.
- **smb-security-mode: signing disabled** → SMB relay attacks possible.
- **http-vuln-cve2014-3704: VULNERABLE** → Drupalgeddon SQLi. Pre-auth RCE chain.
- **ftp-anon: Anonymous login allowed** → Data exposure. Check for sensitive files.
- **mongodb-databases: accessible without auth** → Full database exposure.
- **redis-info: no auth required** → Full server compromise via CONFIG SET.

### Medium Findings (Scheduled Remediation)
- **http-security-headers: missing HSTS** → Downgrade attacks possible.
- **http-cors: wildcard origin** → Cross-origin data theft possible.
- **http-cookie-flags: missing secure/httponly** → Session hijacking risk.
- **http-git: .git exposed** → Source code and credential disclosure.
- **http-internal-ip-disclosure** → Information leak aids further attacks.
- **dns-recursion: enabled** → Open resolver abuse for DDoS amplification.
- **ssh2-enum-algos: weak algorithms** → Potential for crypto downgrade attacks.

### Informational (Document and Monitor)
- **ssl-cert: expiring soon** → Operational risk, not security.
- **http-title** → Technology fingerprinting data.
- **smb-os-discovery** → OS version for vulnerability matching.
- **http-robots.txt** → Hidden paths for further enumeration.

### False Positive Indicators
- **http-slowloris-check** often reports vulnerable when target has connection limits
- **http-sql-injection** has high false positive rate — verify manually
- **http-stored-xss** detects unfiltered characters, not confirmed XSS
- **ssl-dh-params** may flag acceptable 2048-bit DH as weak (only 1024-bit is critical)`;
}

/**
 * Returns nmap knowledge for hunt hypothesis generation.
 * Maps MITRE ATT&CK techniques to nmap detection capabilities.
 */
export function getNmapHuntContext(): string {
  return `## Nmap-Based Threat Hunting Context

### MITRE ATT&CK Mapping for Nmap Findings

| Finding | MITRE Technique | Hunt Hypothesis |
|---------|----------------|-----------------|
| SMBv1 enabled | T1210 (Exploitation of Remote Services) | Adversary may exploit EternalBlue for lateral movement |
| SMB signing disabled | T1557 (LLMNR/NBT-NS Poisoning) | Adversary may perform SMB relay attacks |
| Anonymous FTP | T1078 (Valid Accounts) | Adversary may use anonymous access for staging |
| Exposed .git | T1213 (Data from Information Repositories) | Adversary may extract credentials from git history |
| Weak SSL ciphers | T1557 (Adversary-in-the-Middle) | Adversary may perform TLS downgrade for interception |
| Open DNS recursion | T1498 (Network DoS: Reflection Amplification) | Server may be used as DDoS reflector |
| Docker API exposed | T1610 (Deploy Container) | Adversary may deploy malicious containers |
| Redis no auth | T1059 (Command and Scripting Interpreter) | Adversary may write SSH keys via CONFIG SET |
| MongoDB no auth | T1005 (Data from Local System) | Adversary may exfiltrate database contents |
| RDP exposed | T1021 (Remote Services: RDP) | Adversary may brute force or exploit BlueKeep |
| IMDS accessible | T1552 (Unsecured Credentials: Cloud Instance Metadata) | Adversary may steal cloud credentials via SSRF |

### Scan-Based Hunt Queries
- Look for hosts with SMBv1 + no signing → high-value relay targets
- Look for hosts with exposed management ports (8080, 9200, 27017) → likely misconfigured
- Look for SSL certs with many SANs → map infrastructure scope
- Look for hosts responding on cloud metadata ports → SSRF candidates
- Look for hosts with both web and database ports open → potential direct DB access`;
}

/**
 * Returns the full nmap knowledge context for comprehensive LLM injection.
 * Use this for scan plan generation where maximum knowledge is needed.
 */
export function getFullNmapContext(targetInfo?: {
  detectedTech?: string[];
  cloudProvider?: string;
  hasFirewall?: boolean;
  hasIDS?: boolean;
  stealthRequired?: boolean;
}): string {
  return [
    getNmapScanPlanContext(targetInfo),
    getNmapVulnCorrelationContext(),
    getNmapHuntContext()
  ].join('\n\n---\n\n');
}

/**
 * Given detected technologies, returns the optimal nmap command.
 */
export function buildOptimalNmapCommand(params: {
  detectedTech: string[];
  stealthLevel: 'minimal' | 'low' | 'medium' | 'high' | 'maximum';
  scanType: 'recon' | 'vuln' | 'full';
  target: string;
}): string {
  const { detectedTech, stealthLevel, scanType, target } = params;

  // Collect all recommended scripts from detected tech
  const matchedTechs = TECH_SIGNATURES.filter(t =>
    detectedTech.some(dt =>
      t.indicators.some(ind => dt.toLowerCase().includes(ind.toLowerCase())) ||
      t.technology.toLowerCase().includes(dt.toLowerCase())
    )
  );

  const scripts = new Set<string>();
  const ports = new Set<string>();

  for (const tech of matchedTechs) {
    for (const script of tech.recommendedScripts) {
      scripts.add(script);
    }
    for (const port of tech.scanPorts.split(',')) {
      ports.add(port.trim());
    }
  }

  // Add base scripts based on scan type
  if (scanType === 'vuln' || scanType === 'full') {
    scripts.add('http-security-headers');
    scripts.add('ssl-enum-ciphers');
    scripts.add('ssl-cert');
  }

  // Build evasion flags
  let evasionFlags = '';
  switch (stealthLevel) {
    case 'maximum':
      evasionFlags = '-T1 -f --source-port 53 -D RND:3 --data-length 24 -n -Pn --max-rate 10';
      break;
    case 'high':
      evasionFlags = '-T2 -f --source-port 53 -n -Pn --max-rate 30';
      break;
    case 'medium':
      evasionFlags = '-T2 -n -Pn --max-rate 50';
      break;
    case 'low':
      evasionFlags = '-T3 -Pn';
      break;
    case 'minimal':
      evasionFlags = '-T4';
      break;
  }

  const scriptList = Array.from(scripts).join(',');
  const portList = Array.from(ports).join(',');

  if (scanType === 'recon') {
    return `nmap -sS -sV ${evasionFlags} -p ${portList || '80,443,22'} ${target}`;
  }

  return `nmap -sS -sV --script "${scriptList}" ${evasionFlags} -p ${portList || '80,443,22'} ${target}`;
}
