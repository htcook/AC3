import {
  __esm
} from "./chunk-KFQGP6VL.js";

// server/lib/scanforge-knowledge.ts
function getAllAdminPorts() {
  const ports = /* @__PURE__ */ new Set();
  for (const group of Object.values(ADMIN_SERVICE_PORTS)) {
    for (const port of group) ports.add(port);
  }
  return Array.from(ports).sort((a, b) => a - b).join(",");
}
function getScanforgeScanPlanContext(targetInfo) {
  const sections = [];
  sections.push(`## ScanForge Discovery Engine \u2014 Expert Knowledge for Scan Planning

You have access to four high-speed discovery tools. Select the optimal tool(s) based on target context, then chain with httpx for fingerprinting and Nuclei for vulnerability detection.

### Tool Selection Matrix

| Scenario | Primary Tool | Reason | Command Pattern |
|----------|-------------|--------|-----------------|
| Single host, all ports | RustScan | Fastest for single targets | \`rustscan -a {target} --range 1-65535 -b 4500 -t 2000 -g\` |
| Small range (/24-/16) | Masscan | Best balance of speed and coverage | \`masscan {target} -p0-65535 --rate 5000 -oJ -\` |
| Large range (/16+) | Masscan or ZMap | Handles massive ranges efficiently | \`masscan {target} -p{ports} --rate 10000 -oJ -\` |
| Internet-wide, single port | ZMap | Purpose-built for internet scanning | \`zmap -p {port} -B 100M -O json\` |
| Pipeline integration | Naabu | Native stdin/stdout chaining | \`naabu -host {target} -tp 1000 -s s -no-stdin -Pn -silent | httpx\` |
| Stealth required | Naabu or Masscan | Rate limiting + evasion flags | \`naabu -host {target} -rate 50 -s s -no-stdin\` |
| UDP scanning needed | Naabu | Only ScanForge tool with UDP support | \`naabu -host {target} -p 53,67,69,123,161,500,514,1900 -s s -no-stdin -Pn -json\` |

### Discovery Chain Architecture

The ScanForge pipeline follows a 7-stage architecture:

1. **Subdomain Discovery** (subfinder) \u2192 Subdomains and DNS records (passive, run first)
2. **Port Discovery** (Masscan/Naabu/RustScan/ZMap) \u2192 Open ports per host
3. **Service Fingerprinting** (Nerva + httpx + whatweb) \u2192 Service versions, banners, web technologies
4. **Boundary Detection** (wafw00f + httpx -cdn) \u2192 WAF/CDN/firewall identification
5. **Protocol Auditing** (ssh-audit + testssl.sh + sslscan) \u2192 SSH/TLS configuration weaknesses
6. **Vulnerability Detection** (Nuclei + Nikto + SQLMap) \u2192 CVEs, misconfigs, injections
7. **Verification & Exploitation** (ZAP active scan + Hydra + custom exploits) \u2192 Confirmed exploitable vulnerabilities

Stage flow:
- Stage 1 expands the target list (subdomains \u2192 IPs)
- Stage 2 discovers open ports on all targets
- Stage 3 identifies WHAT is running on each port (Nerva for non-HTTP, httpx for HTTP, whatweb for deep web fingerprinting)
- Stage 4 identifies boundary protections BEFORE aggressive scanning (critical for adapting payloads)
- Stage 5 audits specific protocols for configuration weaknesses
- Stage 6 scans for known vulnerabilities with adapted payloads based on Stage 4 findings
- Stage 7 confirms exploitability and tests credentials

**CRITICAL: Always run Stage 4 (boundary detection) BEFORE Stage 6 (vulnerability scanning) to avoid WAF blocking.**

### Tool Selection by Service Type

| Service Type | Fingerprint Tool | Audit Tool | Attack Tool |
|-------------|-----------------|------------|-------------|
| HTTP/HTTPS | httpx + whatweb | testssl.sh | nuclei + ZAP + sqlmap |
| SSH | nerva | ssh-audit | hydra |
| FTP | nerva | - | hydra (anon + brute) |
| SMTP/IMAP/POP3 | nerva | testssl.sh (STARTTLS) | hydra |
| MySQL/PostgreSQL | nerva | - | hydra + nxc |
| MSSQL | nerva | - | nxc + hydra |
| RDP | nerva | - | hydra + nxc |
| SMB | nerva | - | nxc + hydra |
| DNS | nerva | - | nuclei |
| VPN (IKE/IPsec) | nerva | - | nuclei |
| Redis | nerva | - | hydra |
| MongoDB | nerva | - | nuclei |
| LDAP | nerva | - | nxc |
| Custom/Unknown | nerva | - | nuclei (generic) |`);
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
1. **Rate limit first** \u2014 most effective single evasion technique
2. **Source port 53** (DNS) is the most effective port spoof for Masscan
3. **CONNECT scan** via Naabu avoids raw packet detection
4. **Randomize hosts** to avoid sequential scan detection
5. **Layer techniques** for maximum stealth (rate + source port + randomization)
6. **Use Naabu for stealth** \u2014 it has the best rate control granularity`);
  }
  if (targetInfo?.detectedTech?.length) {
    const matchedTechs = TECH_SIGNATURES.filter(
      (t) => targetInfo.detectedTech.some(
        (dt) => t.indicators.some((ind) => dt.toLowerCase().includes(ind.toLowerCase())) || t.technology.toLowerCase().includes(dt.toLowerCase())
      )
    );
    if (matchedTechs.length > 0) {
      sections.push(`### Detected Technology \u2014 Recommended Scan Configuration
`);
      for (const tech of matchedTechs) {
        sections.push(`**${tech.technology}:**
- Tools: ${tech.recommendedTools.join(", ")}
- Ports: ${tech.scanPorts}
- httpx flags: ${tech.httpxFlags}
- Nuclei tags: \`nuclei -tags ${tech.nucleiTags}\`
- Notes: ${tech.notes}`);
      }
    }
  }
  sections.push(`### Scan Profile Templates

Select the appropriate profile based on authorization level and target context:

${SCAN_PROFILES.map((p) => `**${p.name}** (Tool: ${p.tool}, Stealth: ${p.stealthLevel}, Risk: ${p.riskLevel})
\`${p.command}\`
Use case: ${p.useCase}`).join("\n\n")}`);
  if (targetInfo?.cloudProvider) {
    sections.push(`### Cloud-Specific Scanning Notes (${targetInfo.cloudProvider})

**MANDATORY for cloud targets \u2014 include these in the scan plan:**
- **httpx -cdn** \u2014 REQUIRED to detect CDN/WAF (CloudFlare, Akamai, AWS CloudFront)
- **nuclei -tags cloud,s3,misconfig** \u2014 REQUIRED for cloud misconfiguration detection
- **cloud_enum -k <domain_keyword>** \u2014 REQUIRED to discover S3 buckets, Azure Blobs, GCS buckets

Additional cloud scanning rules:
- Cloud security groups are **stateful** \u2014 rate limit to avoid blocking
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
  sections.push(`### Tool Chaining Rules
1. **Always chain httpx after port discovery** for web service fingerprinting
2. **Always run Nerva on non-HTTP ports** for service version detection and banner grabbing
3. **Always run wafw00f before Nuclei/ZAP** to detect WAF and adapt payloads
4. **Always chain Nuclei after httpx** for vulnerability detection
5. **Run ssh-audit on every SSH port** \u2014 replaces nmap ssh-* scripts with deeper analysis
6. **Run testssl.sh on every TLS port** \u2014 replaces nmap ssl-* scripts with comprehensive testing
7. **Use Naabu for pipeline integration** \u2014 native stdin/stdout support
8. **Masscan JSON output** can be parsed and fed to httpx via jq
9. **RustScan greppable output** can be parsed for port lists
10. **ZMap output** feeds directly to httpx for web service discovery
11. **Nuclei severity filter**: use \`-severity medium,high,critical\` for actionable findings
12. **httpx tech-detect** provides technology fingerprinting without active scanning
13. **Rate limit the entire pipeline** \u2014 not just the port scanner
14. **Use katana for endpoint discovery** before SQLMap injection testing
15. **Use s3scanner for cloud bucket enumeration** when cloud services detected
16. **Use hydra for credential testing** only after service fingerprinting confirms the service type

### WAF/CDN Adaptive Scanning
When wafw00f detects a WAF, adapt the scanning strategy:

| WAF Vendor | Nuclei Adaptation | ZAP Adaptation | Rate Limit |
|-----------|------------------|----------------|------------|
| Cloudflare | Use -tags cloudflare-bypass, add delay 2s | Reduce thread count to 2, use chunked encoding | 5 req/sec |
| Akamai | Use custom UA, rotate IPs if available | Enable Bot Manager evasion profile | 3 req/sec |
| AWS WAF | Use -tags aws-waf-bypass, test rule groups | Use standard browser UA | 10 req/sec |
| ModSecurity/OWASP CRS | Use encoding bypass payloads | Enable CRS evasion mode | 20 req/sec |
| Imperva/Incapsula | Use -tags imperva-bypass, JS challenge handling | Use headless browser mode | 5 req/sec |
| F5 BIG-IP ASM | Test iRule bypass, cookie manipulation | Use session persistence | 10 req/sec |
| Fortinet FortiWeb | Test ML bypass, use uncommon HTTP methods | Enable FortiWeb evasion | 10 req/sec |
| Unknown WAF | Start with low rate, test encoding variants | Use conservative scan policy | 5 req/sec |

### Scope Awareness Rules
1. **Only scan targets explicitly in scope** \u2014 never expand to discovered but unauthorized targets
2. **CDN/WAF bypass**: discovering the origin IP is valid recon, but scanning it requires explicit scope authorization
3. **Shared infrastructure**: if WAF protects multiple tenants, limit aggressive testing to avoid affecting others
4. **Rate limiting**: always respect the engagement's authorized scan rate, even if WAF allows more
5. **Credential testing**: only test credentials on services explicitly authorized for brute-force testing
6. **Post-exploitation**: only perform lateral movement if the engagement scope includes internal network testing`);
  return sections.join("\n\n");
}
function getScanforgeVulnCorrelationContext() {
  return `## ScanForge Vulnerability Correlation Guide

When correlating ScanForge discovery results with vulnerabilities, use these rules:

### Critical Findings (Immediate Action Required)
- **Exposed Docker API (port 2375/2376)** \u2192 Full host compromise. Container escape to host.
- **Exposed Kubernetes API (port 6443/10250)** \u2192 Cluster compromise. Pod escape possible.
- **Exposed Redis without auth (port 6379)** \u2192 Full server compromise via CONFIG SET.
- **Exposed MongoDB without auth (port 27017)** \u2192 Full database exposure and exfiltration.
- **Exposed Elasticsearch without auth (port 9200)** \u2192 Full index access and data theft.
- **Nuclei critical severity finding** \u2192 Confirmed exploitable vulnerability. Immediate action.
- **httpx detecting exposed .git** \u2192 Source code and credential disclosure.
- **httpx detecting exposed .env** \u2192 Environment variables with API keys and secrets.

### High Findings (Urgent Remediation)
- **SMB exposed to internet (port 445)** \u2192 EternalBlue and relay attack surface.
- **RDP exposed to internet (port 3389)** \u2192 Brute force and BlueKeep attack surface.
- **FTP exposed (port 21)** \u2192 Anonymous login check required. Credential interception.
- **Nuclei high severity finding** \u2192 Likely exploitable. Prioritize remediation.
- **httpx detecting admin panels** \u2192 Unauthorized access risk. Check for default credentials.
- **Multiple database ports open** \u2192 Lateral movement risk. Check for default credentials.
- **VPN portal exposed** \u2192 Check for Fortinet, Pulse Secure, Citrix ADC CVEs via Nuclei.

### Medium Findings (Scheduled Remediation)
- **httpx missing security headers** \u2192 HSTS, CSP, X-Frame-Options absent.
- **httpx detecting outdated server versions** \u2192 Known CVE exposure.
- **Nuclei medium severity finding** \u2192 Exploitable under specific conditions.
- **Non-standard ports with web services** \u2192 Shadow IT or misconfigured services.
- **DNS ports exposed (53)** \u2192 Open resolver abuse for DDoS amplification.
- **SNMP exposed (161/162)** \u2192 Community string brute force possible.

### Informational (Document and Monitor)
- **httpx title and technology detection** \u2192 Technology fingerprinting data.
- **SSL certificate details** \u2192 Infrastructure scope mapping via SANs.
- **Open ports with no identified service** \u2192 Requires manual investigation.
- **CDN/WAF detected by httpx** \u2192 Note for scan tuning and evasion planning.

### False Positive Indicators
- **Nuclei info severity** \u2014 Often informational, not vulnerabilities
- **httpx status 403** \u2014 May indicate WAF blocking, not actual service
- **Masscan showing filtered ports** \u2014 Stateless scanner, verify with Naabu CONNECT scan
- **RustScan timeout on specific ports** \u2014 May indicate rate limiting, not closed port`;
}
function getScanforgeHuntContext() {
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
- Look for hosts with exposed management ports (2375, 6443, 9200, 27017) \u2192 likely misconfigured
- Look for hosts with both web and database ports open \u2192 potential direct DB access
- Look for SSL certs with many SANs \u2192 map infrastructure scope via httpx -tls-grab
- Look for hosts responding on cloud metadata ports \u2192 SSRF candidates
- Look for non-standard web ports (8080, 8443, 8888) \u2192 shadow IT or dev environments
- Look for hosts with multiple exposed services \u2192 high-value targets for lateral movement`;
}
function getFullScanforgeContext(targetInfo) {
  return [
    getScanforgeScanPlanContext(targetInfo),
    getScanforgeVulnCorrelationContext(),
    getScanforgeHuntContext()
  ].join("\n\n---\n\n");
}
function buildOptimalScanforgeCommand(params) {
  const { detectedTech, stealthLevel, scanType, target, targetSize } = params;
  const matchedTechs = TECH_SIGNATURES.filter(
    (t) => detectedTech.some(
      (dt) => t.indicators.some((ind) => dt.toLowerCase().includes(ind.toLowerCase())) || t.technology.toLowerCase().includes(dt.toLowerCase())
    )
  );
  const nucleiTags = /* @__PURE__ */ new Set();
  const ports = /* @__PURE__ */ new Set();
  for (const tech of matchedTechs) {
    for (const tag of tech.nucleiTags.split(",")) {
      nucleiTags.add(tag.trim());
    }
    for (const port of tech.scanPorts.split(",")) {
      ports.add(port.trim());
    }
  }
  if (scanType === "vuln" || scanType === "full") {
    nucleiTags.add("cve");
    nucleiTags.add("misconfig");
    nucleiTags.add("exposure");
  }
  const portList = ports.size > 0 ? Array.from(ports).join(",") : "1-1024,3306,3389,5432,5900,6379,8080,8443,27017";
  let discoveryCmd;
  let rate;
  switch (stealthLevel) {
    case "maximum":
      rate = 10;
      break;
    case "high":
      rate = 50;
      break;
    case "medium":
      rate = 200;
      break;
    case "low":
      rate = 1e3;
      break;
    case "minimal":
      rate = 5e3;
      break;
  }
  if (targetSize === "single") {
    const batchSize = stealthLevel === "maximum" || stealthLevel === "high" ? 128 : stealthLevel === "medium" ? 500 : 4500;
    discoveryCmd = `rustscan -a ${target} --range 1-65535 -b ${batchSize} -t ${stealthLevel === "maximum" ? 5e3 : 2e3} -g`;
  } else if (stealthLevel === "high" || stealthLevel === "maximum") {
    discoveryCmd = `naabu -host ${target} -p ${portList} -rate ${rate} -s s -no-stdin -Pn -retries 1 -json`;
  } else {
    const evasionFlags = stealthLevel === "medium" ? "--source-port 53 --randomize-hosts" : "";
    discoveryCmd = `masscan ${target} -p${portList} --rate ${rate} ${evasionFlags} -oJ -`.trim();
  }
  const httpxRate = stealthLevel === "maximum" || stealthLevel === "high" ? "-rate-limit 10" : "";
  const fingerprintCmd = `httpx -json -title -tech-detect -status-code -server -cdn -tls-grab -follow-redirects ${httpxRate}`.trim();
  const serviceFingerprintCmd = `nerva -json ${target}`;
  const boundaryDetectionCmd = `wafw00f ${target.startsWith("http") ? target : "https://" + target} -o json`;
  const protocolAuditCmds = [];
  if (params.hasSSH) {
    protocolAuditCmds.push(`ssh-audit -j ${target}`);
  }
  if (params.hasTLS) {
    protocolAuditCmds.push(`testssl.sh --json ${target}`);
  }
  if (params.hasFTP) {
    protocolAuditCmds.push(`hydra -l anonymous -p anonymous -s 21 ${target} ftp`);
  }
  const nucleiTagList = Array.from(nucleiTags).join(",");
  const nucleiRate = stealthLevel === "maximum" || stealthLevel === "high" ? "-rate-limit 10" : "";
  const vulnCmd = scanType === "recon" ? "" : `nuclei -json -tags ${nucleiTagList || "cve,misconfig"} -severity medium,high,critical ${nucleiRate}`.trim();
  let credentialCmd = "";
  if (scanType === "full") {
    const credTargets = [];
    if (params.hasSSH) credTargets.push(`hydra -L users.txt -P passwords.txt -s 22 ${target} ssh -t 4`);
    if (params.hasRDP) credTargets.push(`hydra -L users.txt -P passwords.txt -s 3389 ${target} rdp -t 4`);
    if (params.hasFTP) credTargets.push(`hydra -L users.txt -P passwords.txt -s 21 ${target} ftp -t 4`);
    if (params.hasSMB) credTargets.push(`nxc smb ${target} -u users.txt -p passwords.txt --continue-on-success`);
    credentialCmd = credTargets.join(" && ");
  }
  const pipeline = vulnCmd ? `${discoveryCmd} | ${fingerprintCmd} | ${vulnCmd}` : `${discoveryCmd} | ${fingerprintCmd}`;
  return {
    discoveryCmd,
    fingerprintCmd,
    serviceFingerprintCmd,
    boundaryDetectionCmd,
    protocolAuditCmds,
    vulnCmd,
    credentialCmd,
    pipeline
  };
}
var SCANFORGE_TOOLS, EVASION_PROFILES, SCAN_PROFILES, TECH_SIGNATURES, ADMIN_SERVICE_PORTS;
var init_scanforge_knowledge = __esm({
  "server/lib/scanforge-knowledge.ts"() {
    SCANFORGE_TOOLS = [
      {
        name: "Masscan",
        binary: "masscan",
        description: "Asynchronous TCP SYN scanner capable of scanning the entire internet in under 6 minutes. Sends raw packets without a full TCP stack, achieving speeds of 10M+ packets/sec.",
        primaryUseCase: "High-speed initial port discovery across large target ranges",
        speed: "ultra-fast",
        accuracy: "medium",
        stealthCapability: "low",
        bestFor: [
          "Large CIDR ranges (/16 and above)",
          "Internet-wide scanning",
          "Initial port discovery before detailed fingerprinting",
          "Time-constrained engagements",
          "Finding all open ports across many hosts quickly"
        ],
        limitations: [
          "No service version detection (SYN-only)",
          "No OS detection",
          "High packet rate can trigger IDS/WAF",
          "Stateless \u2014 may miss ports under packet loss",
          "No scripting engine",
          "Requires root/raw socket privileges"
        ],
        outputFormat: "-oJ (JSON) or -oX (XML) or -oL (list)",
        defaultPortRange: "0-65535"
      },
      {
        name: "Naabu",
        binary: "naabu",
        description: "ProjectDiscovery fast port scanner written in Go. Supports SYN, CONNECT, and UDP scanning with built-in host discovery. Integrates natively with other ProjectDiscovery tools (httpx, nuclei, subfinder).",
        primaryUseCase: "Balanced port scanning with native ProjectDiscovery pipeline integration",
        speed: "fast",
        accuracy: "high",
        stealthCapability: "medium",
        bestFor: [
          "Bug bounty and pentest workflows",
          "Pipeline integration with httpx \u2192 nuclei",
          "Targets requiring both TCP and UDP scanning",
          "Stdin/stdout chaining with other tools",
          "Rate-limited scanning for stealth",
          "Scanning from target lists and CIDR ranges"
        ],
        limitations: [
          "Slower than Masscan for very large ranges",
          "No built-in scripting engine",
          "UDP scanning is slower and less reliable",
          "No OS fingerprinting",
          "CRITICAL: v2.5.0 CONNECT scan (-s c) has a bug causing 4-minute hangs on closed ports. ALWAYS use SYN scan (-s s -no-stdin) instead."
        ],
        outputFormat: "-json (JSON lines) or -o (plain text)",
        defaultPortRange: "Top 100 (configurable with -p or -tp)"
      },
      {
        name: "RustScan",
        binary: "rustscan",
        description: "Ultra-fast port scanner written in Rust. Designed as a speed layer that discovers open ports and can hand off to ScanForge for service detection. Adaptive scanning adjusts batch size based on target responsiveness.",
        primaryUseCase: "Fast port discovery with optional service detection handoff",
        speed: "ultra-fast",
        accuracy: "high",
        stealthCapability: "low",
        bestFor: [
          "Single host full port scans (all 65535 ports in seconds)",
          "Small to medium target ranges",
          "Quick initial discovery before detailed analysis",
          "CTF and lab environments",
          "Adaptive scanning that adjusts to target capacity"
        ],
        limitations: [
          "No built-in service version detection (relies on handoff)",
          "High connection rate can overwhelm targets",
          "No UDP scanning",
          "No scripting engine",
          "Less suitable for very large CIDR ranges"
        ],
        outputFormat: "-g (greppable) or stdout (default)",
        defaultPortRange: "1-65535"
      },
      {
        name: "ZMap",
        binary: "zmap",
        description: "Stateless internet-wide network scanner from University of Michigan. Uses cyclic multiplicative groups for random permutation of target addresses. Can scan the entire IPv4 address space in under 45 minutes on a 1Gbps connection.",
        primaryUseCase: "Internet-scale scanning and large network reconnaissance",
        speed: "ultra-fast",
        accuracy: "low",
        stealthCapability: "low",
        bestFor: [
          "Internet-wide scanning for specific services",
          "Large-scale reconnaissance (/8 and above)",
          "Finding all instances of a specific port globally",
          "Research-grade network measurement",
          "Single-port sweeps across massive ranges"
        ],
        limitations: [
          "Single port per scan (no multi-port in one pass)",
          "No service detection or version identification",
          "No OS detection",
          "Stateless \u2014 single probe per host",
          "Requires root privileges and raw socket access",
          "Can easily overwhelm networks \u2014 use bandwidth limits"
        ],
        outputFormat: "-O csv or -O json or stdout",
        defaultPortRange: "Single port per scan"
      },
      // ─── Service Fingerprinting ────────────────────────────────────────────────
      {
        name: "Nerva",
        binary: "nerva",
        description: "High-performance service fingerprinter written in Go by Praetorian. Identifies 120+ protocols and application-layer services using multi-probe fingerprinting. 4x faster than nmap -sV with higher accuracy. Outputs structured JSON with service name, version, banner, TLS info, and confidence score.",
        primaryUseCase: "Deep service fingerprinting and version detection on discovered open ports",
        speed: "fast",
        accuracy: "high",
        stealthCapability: "medium",
        bestFor: [
          "Replacing nmap -sV for service version detection",
          "Identifying non-HTTP services (SSH, FTP, SMTP, databases, custom protocols)",
          "Banner grabbing with protocol-aware probes",
          "Detecting services running on non-standard ports",
          "Building accurate asset inventories with version info",
          "Feeding service data into vulnerability correlation"
        ],
        limitations: [
          "No port discovery \u2014 requires port list input from naabu/masscan",
          "No vulnerability detection (use nuclei after)",
          "Newer tool \u2014 smaller community than nmap"
        ],
        outputFormat: "-json (JSON lines with service, version, banner, tls, confidence)",
        defaultPortRange: "N/A \u2014 operates on provided port list"
      },
      {
        name: "httpx",
        binary: "httpx",
        description: "ProjectDiscovery fast HTTP toolkit for probing web servers. Detects technologies (via Wappalyzer DB), grabs titles, status codes, content lengths, TLS certificates, CDN detection, and follows redirects. Native pipeline integration with naabu and nuclei.",
        primaryUseCase: "HTTP service fingerprinting, technology detection, and web server enumeration",
        speed: "fast",
        accuracy: "high",
        stealthCapability: "medium",
        bestFor: [
          "Web technology fingerprinting (frameworks, CMS, server software)",
          "CDN and WAF detection via -cdn flag",
          "TLS certificate analysis via -tls-grab",
          "HTTP header analysis and server identification",
          "Filtering live web hosts from port scan results",
          "Pipeline: naabu \u2192 httpx \u2192 nuclei"
        ],
        limitations: [
          "HTTP/HTTPS only \u2014 cannot fingerprint non-web services",
          "Technology detection depends on Wappalyzer signature database",
          "Cannot detect services behind non-standard protocols"
        ],
        outputFormat: "-json (JSON with url, title, status_code, tech, server, tls, cdn)",
        defaultPortRange: "80,443,8080,8443"
      },
      {
        name: "WhatWeb",
        binary: "whatweb",
        description: "Web fingerprinter that identifies websites including CMS, blogging platforms, JS libraries, analytics packages, web servers, embedded devices, version numbers, email addresses, SQL errors, and more. Has 1800+ plugins.",
        primaryUseCase: "Deep web application fingerprinting with 1800+ technology signatures",
        speed: "moderate",
        accuracy: "high",
        stealthCapability: "medium",
        bestFor: [
          "Detailed CMS and framework version identification",
          "Detecting embedded devices and IoT web interfaces",
          "Finding information leaks (emails, SQL errors, stack traces)",
          "Identifying WAF/CDN products",
          "Complementing httpx tech-detect with deeper analysis"
        ],
        limitations: [
          "Slower than httpx for large target lists",
          "HTTP/HTTPS only",
          "Some plugins may trigger WAF alerts at aggressive levels"
        ],
        outputFormat: "--log-json (JSON) or --log-brief (one-liner)",
        defaultPortRange: "80,443"
      },
      // ─── Web Application Scanning ─────────────────────────────────────────────
      {
        name: "Katana",
        binary: "katana",
        description: "ProjectDiscovery next-gen web crawler/spider. Supports standard and headless (Chrome) crawling, JavaScript rendering, automatic form filling, scope control, and passive/active modes. Discovers endpoints, parameters, and hidden paths.",
        primaryUseCase: "Web application endpoint discovery and crawling for attack surface mapping",
        speed: "fast",
        accuracy: "high",
        stealthCapability: "medium",
        bestFor: [
          "Discovering API endpoints and hidden paths",
          "JavaScript-rendered SPA crawling (headless mode)",
          "Finding form parameters and input vectors",
          "Building sitemap for targeted vulnerability scanning",
          "Scope-aware crawling that respects engagement boundaries"
        ],
        limitations: [
          "Headless mode requires Chrome/Chromium",
          "Cannot bypass authentication without configuration",
          "May miss dynamically generated content"
        ],
        outputFormat: "-json (JSON lines) or stdout (URL list)",
        defaultPortRange: "N/A \u2014 operates on URLs"
      },
      {
        name: "wafw00f",
        binary: "wafw00f",
        description: "Web Application Firewall detection tool. Identifies 150+ WAF products by analyzing HTTP responses, error pages, cookies, and headers. Essential for adapting scan strategy to bypass or work within WAF constraints.",
        primaryUseCase: "WAF/CDN identification and fingerprinting for adaptive scanning",
        speed: "fast",
        accuracy: "high",
        stealthCapability: "high",
        bestFor: [
          "Identifying WAF vendor before vulnerability scanning",
          "Adapting nuclei/ZAP scan policies to avoid WAF blocking",
          "Detecting CDN-based WAFs (Cloudflare, Akamai, AWS WAF)",
          "Choosing appropriate evasion techniques per WAF type",
          "Pre-scan reconnaissance for engagement planning"
        ],
        limitations: [
          "Cannot bypass WAFs \u2014 only detects them",
          "Some custom WAFs may not be in signature database",
          "Single URL per invocation (script for bulk)"
        ],
        outputFormat: "-o json (JSON) or stdout (text)",
        defaultPortRange: "N/A \u2014 operates on URLs"
      },
      // ─── TLS/SSH Auditing ─────────────────────────────────────────────────────
      {
        name: "ssh-audit",
        binary: "ssh-audit",
        description: "SSH server and client configuration auditor. Tests key exchange algorithms, host key types, encryption ciphers, MAC algorithms, and compression. Identifies vulnerabilities, weak algorithms, and policy violations. Replaces nmap ssh-* NSE scripts with deeper analysis.",
        primaryUseCase: "SSH server security auditing and algorithm weakness detection",
        speed: "fast",
        accuracy: "high",
        stealthCapability: "high",
        bestFor: [
          "Auditing SSH server configuration (algorithms, key types, ciphers)",
          "Detecting known SSH vulnerabilities (Terrapin, regreSSHion CVE-2024-6387)",
          "Compliance checking against security policies",
          "Identifying weak or deprecated algorithms",
          "Replacing nmap ssh-auth-methods, ssh-hostkey, ssh2-enum-algos scripts"
        ],
        limitations: [
          "SSH only \u2014 no other protocols",
          "Cannot test authentication credentials (use hydra for that)",
          "Requires network access to SSH port"
        ],
        outputFormat: "-j (JSON with algorithms, vulnerabilities, recommendations)",
        defaultPortRange: "22,2222,22222"
      },
      {
        name: "testssl.sh",
        binary: "testssl.sh",
        description: "Comprehensive TLS/SSL testing tool. Tests protocols (SSLv2-TLS1.3), cipher suites, certificate chain, BEAST/CRIME/POODLE/Heartbleed/ROBOT/Ticketbleed vulnerabilities, HSTS, OCSP stapling, certificate transparency, and more. Replaces nmap ssl-* NSE scripts with much deeper analysis.",
        primaryUseCase: "Deep TLS/SSL security assessment and compliance testing",
        speed: "moderate",
        accuracy: "high",
        stealthCapability: "high",
        bestFor: [
          "Complete TLS/SSL vulnerability assessment",
          "Detecting Heartbleed, POODLE, BEAST, ROBOT, DROWN, Ticketbleed",
          "Certificate chain validation and expiry checking",
          "Cipher suite strength analysis",
          "PCI-DSS and HIPAA TLS compliance checking",
          "Replacing nmap ssl-enum-ciphers, ssl-heartbleed, ssl-poodle scripts"
        ],
        limitations: [
          "Slower than sslscan for quick checks",
          "Requires bash and OpenSSL",
          "Single target per invocation"
        ],
        outputFormat: "--json (JSON) or --csv (CSV) or stdout (colored text)",
        defaultPortRange: "443,8443,465,993,995,636,989,990,5061"
      },
      // ─── Credential Attacks ───────────────────────────────────────────────────
      {
        name: "Hydra",
        binary: "hydra",
        description: "Fast network logon cracker supporting 50+ protocols including SSH, FTP, HTTP, HTTPS, SMB, SMTP, MySQL, PostgreSQL, RDP, VNC, LDAP, and more. Supports parallel connections, resume, and custom wordlists.",
        primaryUseCase: "Network service credential brute-forcing and default credential testing",
        speed: "fast",
        accuracy: "high",
        stealthCapability: "low",
        bestFor: [
          "Testing default credentials on discovered services",
          "SSH, FTP, RDP, VNC brute-force attacks",
          "HTTP form-based authentication testing",
          "Database credential testing (MySQL, PostgreSQL, MSSQL)",
          "SMTP/IMAP/POP3 credential testing"
        ],
        limitations: [
          "Noisy \u2014 generates many failed login attempts",
          "May trigger account lockout policies",
          "Requires wordlists for effective attacks",
          "Some protocols have rate limits that slow attacks"
        ],
        outputFormat: "-o (text) or -b json (JSON)",
        defaultPortRange: "Protocol-dependent"
      },
      {
        name: "NetExec (nxc)",
        binary: "nxc",
        description: "Network execution tool (successor to CrackMapExec). Supports SMB, WinRM, LDAP, MSSQL, SSH, FTP, RDP, WMI protocols. Performs credential validation, share enumeration, command execution, and Active Directory attacks.",
        primaryUseCase: "Windows/AD network credential validation and post-exploitation",
        speed: "fast",
        accuracy: "high",
        stealthCapability: "low",
        bestFor: [
          "SMB share enumeration and access testing",
          "Active Directory credential spraying",
          "WinRM/WMI remote command execution",
          "LDAP enumeration and AD reconnaissance",
          "Validating credentials across multiple hosts",
          "Post-exploitation lateral movement"
        ],
        limitations: [
          "Primarily Windows/AD focused",
          "Noisy \u2014 generates authentication events",
          "Requires valid credentials for most post-exploitation features"
        ],
        outputFormat: "stdout (colored text) or --export json",
        defaultPortRange: "445,5985,5986,389,636,1433,22,21,3389"
      },
      {
        name: "Medusa",
        binary: "medusa",
        description: "Speedy, massively parallel, modular login brute-forcer. Supports many services including HTTP, FTP, SSH, Telnet, MSSQL, MySQL, PostgreSQL, SMB, VNC, and more.",
        primaryUseCase: "Parallel credential brute-forcing across multiple hosts and services",
        speed: "fast",
        accuracy: "high",
        stealthCapability: "low",
        bestFor: [
          "Parallel brute-force across many hosts simultaneously",
          "Testing default credentials on bulk services",
          "Complementing hydra for services it handles better"
        ],
        limitations: [
          "Fewer protocol modules than hydra",
          "Less actively maintained than hydra",
          "No JSON output format"
        ],
        outputFormat: "-O (text log file)",
        defaultPortRange: "Protocol-dependent"
      },
      // ─── Vulnerability Scanning ───────────────────────────────────────────────
      {
        name: "Nuclei",
        binary: "nuclei",
        description: "ProjectDiscovery fast vulnerability scanner based on YAML templates. 8000+ community templates covering CVEs, misconfigurations, exposures, default logins, and more. Supports HTTP, DNS, TCP, headless, and code protocols.",
        primaryUseCase: "Template-based vulnerability detection across web and network services",
        speed: "fast",
        accuracy: "high",
        stealthCapability: "medium",
        bestFor: [
          "CVE detection with proof-of-concept validation",
          "Misconfiguration detection (exposed panels, debug endpoints)",
          "Default credential testing",
          "Technology-specific vulnerability scanning",
          "Custom template development for proprietary applications",
          "Pipeline: naabu \u2192 httpx \u2192 nuclei"
        ],
        limitations: [
          "Template quality varies \u2014 some have false positives",
          "Cannot discover unknown vulnerabilities (template-dependent)",
          "Rate limiting needed for production targets"
        ],
        outputFormat: "-json (JSON lines) or -o (text)",
        defaultPortRange: "N/A \u2014 operates on URLs/hosts"
      },
      {
        name: "SQLMap",
        binary: "sqlmap",
        description: "Automatic SQL injection detection and exploitation tool. Supports MySQL, Oracle, PostgreSQL, MSSQL, SQLite, and more. Features database fingerprinting, data extraction, file system access, and OS command execution via SQL injection.",
        primaryUseCase: "SQL injection detection, exploitation, and database extraction",
        speed: "moderate",
        accuracy: "high",
        stealthCapability: "low",
        bestFor: [
          "Confirming and exploiting SQL injection vulnerabilities",
          "Database enumeration and data extraction",
          "Testing WAF bypass for SQL injection payloads",
          "OS command execution via SQL injection",
          "Automated exploitation of discovered injection points"
        ],
        limitations: [
          "Noisy \u2014 sends many malicious payloads",
          "Requires identified injection point or URL with parameters",
          "Can cause data corruption if used carelessly",
          "WAFs often block SQLMap user-agent and payloads"
        ],
        outputFormat: "--output-dir (structured output directory)",
        defaultPortRange: "N/A \u2014 operates on URLs"
      },
      {
        name: "Nikto",
        binary: "nikto",
        description: "Web server scanner that tests for 7000+ dangerous files/programs, outdated server versions, and version-specific problems. Checks for server configuration items like multiple index files and HTTP server options.",
        primaryUseCase: "Web server misconfiguration and known vulnerability scanning",
        speed: "moderate",
        accuracy: "medium",
        stealthCapability: "low",
        bestFor: [
          "Finding dangerous default files and programs",
          "Detecting outdated web server software",
          "Checking HTTP security headers",
          "Finding backup files, admin panels, and debug endpoints"
        ],
        limitations: [
          "Very noisy \u2014 sends thousands of requests",
          "High false positive rate",
          "No authentication support for protected areas",
          "Signature-based \u2014 cannot find custom vulnerabilities"
        ],
        outputFormat: "-Format json (JSON) or -Format xml (XML)",
        defaultPortRange: "80,443"
      },
      // ─── Subdomain/DNS ────────────────────────────────────────────────────────
      {
        name: "Subfinder",
        binary: "subfinder",
        description: "ProjectDiscovery passive subdomain discovery tool. Uses 40+ data sources including certificate transparency, DNS datasets, search engines, and threat intelligence feeds. Fast and non-intrusive.",
        primaryUseCase: "Passive subdomain enumeration from multiple data sources",
        speed: "fast",
        accuracy: "high",
        stealthCapability: "high",
        bestFor: [
          "Initial subdomain discovery without touching the target",
          "Certificate transparency log mining",
          "Expanding attack surface during reconnaissance",
          "Pipeline: subfinder \u2192 httpx \u2192 nuclei"
        ],
        limitations: [
          "Passive only \u2014 cannot discover subdomains not in data sources",
          "Requires API keys for best results (Shodan, SecurityTrails, etc.)",
          "Cannot find internal/private subdomains"
        ],
        outputFormat: "-json (JSON lines) or -o (text list)",
        defaultPortRange: "N/A \u2014 discovers subdomains"
      },
      // ─── Cloud Security ───────────────────────────────────────────────────────
      {
        name: "S3Scanner",
        binary: "s3scanner",
        description: "Scan for open/misconfigured S3 buckets and dump their contents. Supports AWS S3, DigitalOcean Spaces, GCP Storage, and other S3-compatible services.",
        primaryUseCase: "Cloud storage bucket enumeration and misconfiguration detection",
        speed: "fast",
        accuracy: "high",
        stealthCapability: "high",
        bestFor: [
          "Finding publicly accessible S3 buckets",
          "Testing bucket permissions (read, write, list)",
          "Discovering sensitive data in cloud storage",
          "Checking for misconfigured bucket policies"
        ],
        limitations: [
          "Requires bucket name guessing or enumeration",
          "Cannot access buckets with proper IAM policies",
          "Rate limited by cloud providers"
        ],
        outputFormat: "stdout (text) or -o (output file)",
        defaultPortRange: "N/A \u2014 operates on bucket names"
      },
      // ─── Post-Exploitation / Lateral Movement ─────────────────────────────────
      {
        name: "Impacket",
        binary: "python3 -m impacket",
        description: "Collection of Python classes for working with network protocols. Includes tools for SMB, MSRPC, LDAP, Kerberos, NTLM, and more. Essential for Windows/AD post-exploitation including secretsdump, psexec, wmiexec, smbexec, and dcomexec.",
        primaryUseCase: "Windows/AD protocol exploitation and post-exploitation",
        speed: "moderate",
        accuracy: "high",
        stealthCapability: "medium",
        bestFor: [
          "Credential dumping (secretsdump, lsassy)",
          "Remote command execution (psexec, wmiexec, smbexec)",
          "Kerberos attacks (GetNPUsers, GetUserSPNs)",
          "NTLM relay attacks",
          "SMB/MSRPC enumeration"
        ],
        limitations: [
          "Windows/AD focused \u2014 limited use for Linux targets",
          "Requires valid credentials for most tools",
          "Some tools are very noisy (psexec creates a service)"
        ],
        outputFormat: "stdout (text)",
        defaultPortRange: "445,135,139,389,636,88,464"
      }
    ];
    EVASION_PROFILES = [
      {
        name: "Rate-Limited Stealth",
        risk: "low",
        description: "Reduce scan rate to stay below IDS/WAF detection thresholds. All ScanForge tools support rate limiting. Masscan uses --rate, Naabu uses -rate, RustScan uses --batch-size and --timeout.",
        tools: ["masscan", "naabu", "rustscan"],
        flags: {
          masscan: ["--rate 100", "--rate 50", "--rate 10"],
          naabu: ["-rate 100", "-rate 50", "-rate 10"],
          rustscan: ["--batch-size 128", "--batch-size 64", "--timeout 3000"]
        },
        bypassCapability: ["Rate-based IDS alerts", "Threshold-based anomaly detection", "Connection-rate firewalls"],
        limitations: ["Significantly slower scan times", "Does not evade content-based detection", "Still detectable by stateful inspection"],
        bestFor: ["Monitored environments", "Cloud WAF targets", "Avoiding rate-limit triggers", "Long-term covert recon"]
      },
      {
        name: "Source Port Manipulation",
        risk: "medium",
        description: "Set source port to commonly trusted ports (53/DNS, 80/HTTP, 443/HTTPS). Firewalls often allow return traffic from these ports. Masscan supports --source-port.",
        tools: ["masscan"],
        flags: {
          masscan: ["--source-port 53", "--source-port 80", "--source-port 443"]
        },
        bypassCapability: ["Firewalls trusting DNS return traffic", "Port-based ACLs", "Stateless packet filters"],
        limitations: ["Only works with Masscan", "ISPs may filter spoofed source ports", "Stateful firewalls still detect"],
        bestFor: ["Bypassing DNS-trusting firewalls", "DMZ environments", "Internal network scanning"]
      },
      {
        name: "Randomized Targeting",
        risk: "low",
        description: "Randomize the order of target addresses to avoid triggering sequential-scan detection. ZMap does this by default via cyclic groups. Masscan uses --randomize-hosts.",
        tools: ["masscan", "zmap"],
        flags: {
          masscan: ["--randomize-hosts"],
          zmap: ["(default behavior)"]
        },
        bypassCapability: ["Sequential scan detection", "Pattern-based IDS rules", "Simple threshold-based blocking"],
        limitations: ["Does not reduce total traffic volume", "Still detectable by volume-based monitoring"],
        bestFor: ["Large range scans", "Avoiding sequential scan alerts", "Combined with rate limiting"]
      },
      {
        name: "Bandwidth Throttling",
        risk: "low",
        description: "Limit bandwidth consumption to avoid network congestion alerts and QoS triggers. Masscan uses --max-rate, ZMap uses -B (bandwidth limit).",
        tools: ["masscan", "zmap"],
        flags: {
          masscan: ["--max-rate 1000", "--max-rate 500"],
          zmap: ["-B 1M", "-B 10M", "-B 100M"]
        },
        bypassCapability: ["Bandwidth-based anomaly detection", "QoS triggers", "Network congestion alerts"],
        limitations: ["Slower scan completion", "Does not evade packet-level inspection"],
        bestFor: ["Shared network environments", "Cloud targets with bandwidth monitoring", "Avoiding DoS conditions"]
      },
      {
        name: "CONNECT Scan (Non-Raw) \u2014 DEPRECATED",
        risk: "low",
        description: "WARNING: Naabu v2.5.0 CONNECT scan (-s c) has a critical bug (GitHub issue #1520) that causes 4-minute hangs on closed ports. DO NOT USE. Always use SYN scan (-s s -no-stdin) instead. SYN scan requires root/CAP_NET_RAW (available on our droplet). CONNECT scan may be fixed in future naabu releases.",
        tools: ["naabu"],
        flags: {
          naabu: ["-s s -no-stdin"]
        },
        bypassCapability: ["SYN-only IDS rules", "Raw packet detection", "Environments blocking raw sockets"],
        limitations: ["v2.5.0 CONNECT scan is BROKEN \u2014 hangs for 4 minutes per closed port", "Leaves connection logs on target", "More detectable at application layer"],
        bestFor: ["DO NOT USE CONNECT SCAN \u2014 use SYN scan (-s s -no-stdin) for all naabu operations"]
      },
      {
        name: "Multi-Probe Reliability",
        risk: "low",
        description: "Send multiple probes per port to improve accuracy under packet loss. ZMap uses -P for probe count. Masscan uses --retries.",
        tools: ["masscan", "zmap"],
        flags: {
          masscan: ["--retries 2", "--retries 3"],
          zmap: ["-P 2", "-P 3"]
        },
        bypassCapability: [],
        limitations: ["Increases total traffic volume", "Slower scan completion"],
        bestFor: ["Lossy networks", "Targets behind load balancers", "Improving accuracy on unreliable connections"]
      },
      {
        name: "Interface and Adapter Selection",
        risk: "low",
        description: "Specify network interface and adapter for scanning. Useful for multi-homed hosts or when scanning from specific VLANs. Masscan uses --interface, ZMap uses -i.",
        tools: ["masscan", "zmap", "naabu"],
        flags: {
          masscan: ["--interface eth0", "--adapter-ip 10.0.0.5"],
          zmap: ["-i eth0"],
          naabu: ["-interface eth0"]
        },
        bypassCapability: ["VLAN-based access controls", "Source-network restrictions"],
        limitations: ["Requires knowledge of network topology", "May require specific routing"],
        bestFor: ["Multi-homed scan servers", "VLAN-specific scanning", "Controlled source IP selection"]
      },
      {
        name: "Combined Layered Evasion",
        risk: "medium",
        description: "Combine rate limiting + source port manipulation + randomization for maximum stealth. Uses Masscan with all evasion flags.",
        tools: ["masscan"],
        flags: {
          masscan: ["--rate 50 --source-port 53 --randomize-hosts --retries 1"]
        },
        bypassCapability: ["Multi-layer defense stacks", "Rate + pattern + source detection", "SOC analyst manual review"],
        limitations: ["Very slow", "Complex to configure", "Only available with Masscan"],
        bestFor: ["Red team operations against hardened targets", "Testing defense-in-depth", "Maximum stealth requirement"]
      }
    ];
    SCAN_PROFILES = [
      // ── Masscan Profiles ──
      {
        name: "Masscan Quick Discovery",
        description: "Ultra-fast top port discovery. Finds open ports across large ranges in seconds.",
        tool: "masscan",
        command: "masscan {target} -p1-1024,3306,3389,5432,5900,6379,8080,8443,27017 --rate 1000 -oJ -",
        useCase: "Initial port discovery on authorized targets",
        stealthLevel: "minimal",
        estimatedDuration: "5-30 sec per /24",
        riskLevel: "low"
      },
      {
        name: "Masscan Full Port Sweep",
        description: "Complete 0-65535 port scan. Finds every open port including non-standard services.",
        tool: "masscan",
        command: "masscan {target} -p0-65535 --rate 5000 -oJ -",
        useCase: "Comprehensive port enumeration",
        stealthLevel: "minimal",
        estimatedDuration: "1-5 min per /24",
        riskLevel: "low"
      },
      {
        name: "Masscan Stealth Recon",
        description: "Rate-limited scan with source port spoofing for monitored environments.",
        tool: "masscan",
        command: "masscan {target} -p1-1024,3306,3389,5432,8080,8443 --rate 50 --source-port 53 --randomize-hosts -oJ -",
        useCase: "Scanning monitored/hardened targets",
        stealthLevel: "high",
        estimatedDuration: "10-30 min per /24",
        riskLevel: "low"
      },
      // ── Naabu Profiles ──
      {
        name: "Naabu Standard Scan",
        description: "Balanced port scan with host discovery. Good default for most engagements.",
        tool: "naabu",
        command: "naabu -host {target} -tp 1000 -rate 500 -s s -no-stdin -Pn -json",
        useCase: "Standard authorized assessment",
        stealthLevel: "low",
        estimatedDuration: "1-5 min",
        riskLevel: "low"
      },
      {
        name: "Naabu Full Port Scan",
        description: "Complete port scan with service detection via built-in probes.",
        tool: "naabu",
        command: "naabu -host {target} -p - -rate 1000 -s s -no-stdin -Pn -json",
        useCase: "Comprehensive port enumeration with service hints",
        stealthLevel: "low",
        estimatedDuration: "3-10 min",
        riskLevel: "low"
      },
      {
        name: "Naabu Stealth Scan",
        description: "Low-rate SYN scan for monitored environments.",
        tool: "naabu",
        command: "naabu -host {target} -tp 1000 -rate 50 -s s -Pn -json",
        useCase: "Scanning monitored targets",
        stealthLevel: "high",
        estimatedDuration: "10-30 min",
        riskLevel: "low"
      },
      {
        name: "Naabu Pipeline (httpx chain)",
        description: "Port discovery piped to httpx for web service fingerprinting.",
        tool: "naabu",
        command: "naabu -host {target} -tp 1000 -s s -no-stdin -Pn -silent | httpx -json -title -tech-detect -status-code -follow-redirects",
        useCase: "Web service discovery and fingerprinting",
        stealthLevel: "low",
        estimatedDuration: "2-8 min",
        riskLevel: "low"
      },
      // ── RustScan Profiles ──
      {
        name: "RustScan Blitz",
        description: "Ultra-fast full port scan of a single host. Scans all 65535 ports in seconds.",
        tool: "rustscan",
        command: "rustscan -a {target} --range 1-65535 -b 4500 -t 2000 -g",
        useCase: "Single host full port discovery",
        stealthLevel: "minimal",
        estimatedDuration: "3-15 sec",
        riskLevel: "low"
      },
      {
        name: "RustScan Adaptive",
        description: "Adaptive batch scanning that adjusts to target responsiveness.",
        tool: "rustscan",
        command: "rustscan -a {target} --range 1-65535 -b 1000 -t 3000 -g",
        useCase: "Balanced speed/reliability scanning",
        stealthLevel: "low",
        estimatedDuration: "10-60 sec",
        riskLevel: "low"
      },
      {
        name: "RustScan Careful",
        description: "Conservative batch size for fragile targets or monitored environments.",
        tool: "rustscan",
        command: "rustscan -a {target} --range 1-65535 -b 128 -t 5000 -g",
        useCase: "Scanning fragile or monitored targets",
        stealthLevel: "medium",
        estimatedDuration: "2-10 min",
        riskLevel: "low"
      },
      // ── ZMap Profiles ──
      {
        name: "ZMap Single Port Sweep",
        description: "Internet-scale single port discovery. Scans entire /16 in seconds.",
        tool: "zmap",
        command: "zmap -p {port} {target} -B 10M -O json --output-fields=saddr,sport",
        useCase: "Large-scale single port reconnaissance",
        stealthLevel: "minimal",
        estimatedDuration: "1-30 sec per /16",
        riskLevel: "medium"
      },
      {
        name: "ZMap Stealth Sweep",
        description: "Low-bandwidth single port sweep for monitored networks.",
        tool: "zmap",
        command: "zmap -p {port} {target} -B 1M -O json --output-fields=saddr,sport",
        useCase: "Stealthy large-range reconnaissance",
        stealthLevel: "medium",
        estimatedDuration: "5-60 min per /16",
        riskLevel: "low"
      },
      // ── Combined Pipeline Profiles ──
      {
        name: "ScanForge Full Pipeline",
        description: "Complete discovery chain: Masscan port discovery \u2192 httpx web fingerprinting \u2192 Nuclei vulnerability detection.",
        tool: "pipeline",
        command: `masscan {target} -p1-65535 --rate 5000 -oJ /tmp/ports.json && cat /tmp/ports.json | jq -r '.[] | .ip + ":" + (.ports[0].port|tostring)' | httpx -json -title -tech-detect -status-code | nuclei -json -severity medium,high,critical`,
        useCase: "Full automated discovery and vulnerability detection",
        stealthLevel: "minimal",
        estimatedDuration: "5-30 min",
        riskLevel: "medium"
      },
      {
        name: "ScanForge Stealth Pipeline",
        description: "Rate-limited discovery chain for monitored environments.",
        tool: "pipeline",
        command: "naabu -host {target} -tp 1000 -rate 50 -s s -no-stdin -Pn -silent | httpx -json -title -tech-detect -status-code -rate-limit 10 | nuclei -json -severity medium,high,critical -rate-limit 10",
        useCase: "Stealthy automated discovery",
        stealthLevel: "high",
        estimatedDuration: "30-120 min",
        riskLevel: "low"
      }
    ];
    TECH_SIGNATURES = [
      {
        technology: "WordPress",
        indicators: ["wordpress", "wp-content", "wp-admin", "wp-includes", "wp-json"],
        recommendedTools: ["naabu", "httpx", "nuclei"],
        scanPorts: "80,443,8080,8443",
        httpxFlags: "-title -tech-detect -status-code -follow-redirects",
        nucleiTags: "wordpress,wp-plugin,cve",
        notes: "Nuclei has 500+ WordPress-specific templates. Always run nuclei -tags wordpress after httpx fingerprinting."
      },
      {
        technology: "Apache",
        indicators: ["apache", "httpd", "mod_ssl", "mod_php"],
        recommendedTools: ["naabu", "httpx", "nuclei", "nikto"],
        scanPorts: "80,443,8080,8443",
        httpxFlags: "-title -tech-detect -status-code -server",
        nucleiTags: "apache,cve",
        notes: "Check for mod_status, mod_info exposure. Nuclei detects Struts, Tomcat behind Apache."
      },
      {
        technology: "Nginx",
        indicators: ["nginx", "openresty"],
        recommendedTools: ["naabu", "httpx", "nuclei"],
        scanPorts: "80,443,8080,8443",
        httpxFlags: "-title -tech-detect -status-code -server",
        nucleiTags: "nginx,cve,misconfig",
        notes: "Check for off-by-slash misconfiguration, alias traversal. Nuclei has nginx-specific templates."
      },
      {
        technology: "Microsoft IIS",
        indicators: ["iis", "asp.net", "aspx", "microsoft-iis"],
        recommendedTools: ["naabu", "httpx", "nuclei"],
        scanPorts: "80,443,8080,8443",
        httpxFlags: "-title -tech-detect -status-code -server",
        nucleiTags: "iis,aspnet,cve,misconfig",
        notes: "Check for short filename disclosure, WebDAV, debug mode. Nuclei detects IIS-specific vulns."
      },
      {
        technology: "SSH",
        indicators: ["ssh", "openssh", "dropbear"],
        recommendedTools: ["naabu", "nerva", "ssh-audit", "hydra"],
        scanPorts: "22,2222,22222",
        httpxFlags: "N/A",
        nucleiTags: "ssh,cve",
        notes: "Use nerva for SSH version/banner detection. Use ssh-audit for algorithm weakness analysis and CVE detection (Terrapin, regreSSHion). Use hydra for credential testing. Nuclei has SSH-specific vulnerability templates."
      },
      {
        technology: "Database Services",
        indicators: ["mysql", "postgresql", "mssql", "oracle", "mongodb", "redis", "elasticsearch"],
        recommendedTools: ["naabu", "nerva", "hydra", "nxc"],
        scanPorts: "3306,5432,1433,1521,27017,6379,9200,9300",
        httpxFlags: "N/A",
        nucleiTags: "database,cve,misconfig,default-login",
        notes: "Use nerva for service version fingerprinting. Use hydra for default credential testing. Use nxc for MSSQL credential validation. Exposed database ports are critical findings. Nuclei can test for default credentials and known CVEs."
      },
      {
        technology: "Docker/Kubernetes",
        indicators: ["docker", "kubernetes", "k8s", "containerd"],
        recommendedTools: ["masscan", "naabu", "nuclei"],
        scanPorts: "2375,2376,6443,10250,10255,8001,8080",
        httpxFlags: "-title -tech-detect -status-code",
        nucleiTags: "docker,kubernetes,cve,misconfig,exposure",
        notes: "Exposed Docker API (2375) = full host compromise. Kubelet API (10250) = container escape. Critical findings."
      },
      {
        technology: "Cloud Services",
        indicators: ["aws", "azure", "gcp", "cloudflare", "akamai"],
        recommendedTools: ["naabu", "httpx", "nuclei", "wafw00f", "s3scanner", "subfinder"],
        scanPorts: "80,443,8080,8443",
        httpxFlags: "-title -tech-detect -status-code -cdn -server",
        nucleiTags: "cloud,aws,azure,gcp,s3,misconfig",
        notes: "Use wafw00f to identify CDN/WAF vendor. Use httpx -cdn for CDN detection. Use s3scanner for bucket enumeration. Use subfinder for subdomain discovery. Rate limit scans for cloud targets. Check for IMDS at 169.254.169.254."
      },
      {
        technology: "Mail Services",
        indicators: ["smtp", "pop3", "imap", "exchange", "postfix", "sendmail"],
        recommendedTools: ["naabu", "nerva", "hydra", "testssl.sh"],
        scanPorts: "25,110,143,465,587,993,995,2525",
        httpxFlags: "N/A",
        nucleiTags: "mail,smtp,cve",
        notes: "Use nerva for SMTP/POP3/IMAP service version detection. Use hydra for credential testing. Use testssl.sh for STARTTLS assessment. Check for open relay, VRFY/EXPN commands, STARTTLS downgrade. Nuclei has mail-specific templates."
      },
      {
        technology: "VPN/Remote Access",
        indicators: ["vpn", "openvpn", "wireguard", "ipsec", "rdp", "vnc", "citrix"],
        recommendedTools: ["naabu", "nerva", "hydra", "nxc", "testssl.sh"],
        scanPorts: "443,500,1194,1723,3389,4443,5900,8443",
        httpxFlags: "-title -tech-detect -status-code",
        nucleiTags: "vpn,rdp,vnc,citrix,cve",
        notes: "Use nerva for VPN/RDP/VNC service fingerprinting. Use hydra for RDP/VNC credential testing. Use nxc for RDP credential validation. Use testssl.sh for VPN portal TLS assessment. Check for Fortinet, Pulse Secure, Citrix ADC vulns via Nuclei."
      },
      {
        technology: "FTP Services",
        indicators: ["ftp", "vsftpd", "proftpd", "pure-ftpd", "filezilla"],
        recommendedTools: ["naabu", "nerva", "hydra", "testssl.sh"],
        scanPorts: "21,990,2121",
        httpxFlags: "N/A",
        nucleiTags: "ftp,cve,default-login",
        notes: "Use nerva for FTP server version detection. Test for anonymous login (hydra -l anonymous -p anonymous). Use testssl.sh for FTPS assessment. Check for directory traversal and writable directories. Nuclei has FTP-specific templates."
      },
      {
        technology: "WAF/CDN/Proxy",
        indicators: ["cloudflare", "akamai", "fastly", "cloudfront", "incapsula", "imperva", "sucuri", "barracuda", "f5", "fortiweb", "modsecurity", "nginx-waf", "aws-waf", "azure-front-door"],
        recommendedTools: ["wafw00f", "httpx", "whatweb"],
        scanPorts: "80,443,8080,8443",
        httpxFlags: "-title -tech-detect -status-code -cdn -server -tls-grab",
        nucleiTags: "waf,cdn,proxy,misconfig",
        notes: "CRITICAL: Always run wafw00f FIRST to identify WAF before vulnerability scanning. Use httpx -cdn to detect CDN. Check for WAF bypass via origin IP discovery (DNS history, certificate transparency, email headers). Adapt scan rate and payloads based on WAF vendor. Common bypasses: encoding tricks, chunked transfer, header manipulation, IP rotation."
      },
      {
        technology: "Bastion/Jump Host",
        indicators: ["bastion", "jump", "jumpbox", "gateway"],
        recommendedTools: ["naabu", "nerva", "ssh-audit", "hydra"],
        scanPorts: "22,2222,3389,443",
        httpxFlags: "N/A",
        nucleiTags: "ssh,cve",
        notes: "Bastion hosts are high-value targets \u2014 compromising them provides access to internal networks. Use ssh-audit for configuration weakness detection. Test for key-based auth bypass, agent forwarding abuse, and ProxyJump misconfiguration. Check if the bastion exposes internal network topology via SSH banners or MOTD."
      },
      {
        technology: "IoT/Embedded",
        indicators: ["iot", "embedded", "firmware", "upnp", "mqtt", "coap", "zigbee", "camera", "printer", "router"],
        recommendedTools: ["naabu", "nerva", "whatweb", "hydra"],
        scanPorts: "80,443,23,8080,8443,1883,5683,49152",
        httpxFlags: "-title -tech-detect -status-code -server",
        nucleiTags: "iot,cve,default-login,misconfig",
        notes: "Use nerva for protocol identification on non-standard ports. Use whatweb for embedded web interface fingerprinting. Test default credentials (admin/admin, root/root). Check for UPnP exposure, MQTT without auth, and firmware update endpoints."
      },
      {
        technology: "Load Balancer",
        indicators: ["haproxy", "traefik", "envoy", "f5", "netscaler", "aws-elb", "aws-alb", "nginx-lb"],
        recommendedTools: ["httpx", "wafw00f", "testssl.sh"],
        scanPorts: "80,443,8080,8443,8404,9090",
        httpxFlags: "-title -tech-detect -status-code -server -tls-grab",
        nucleiTags: "proxy,misconfig,exposure",
        notes: "Detect load balancer type via Server header, X-Forwarded-For behavior, and cookie patterns. Check for admin panel exposure (HAProxy stats, Traefik dashboard). Test for request smuggling (CL.TE, TE.CL). Use testssl.sh to check TLS termination configuration."
      }
    ];
    ADMIN_SERVICE_PORTS = {
      ssh: [22, 2222, 22222],
      ftp: [20, 21, 990],
      sftp: [22, 115],
      smtp: [25, 465, 587, 2525],
      dns: [53],
      http: [80, 8080, 8e3, 8888],
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
      kerberos: [88, 464]
    };
  }
});

export {
  SCANFORGE_TOOLS,
  EVASION_PROFILES,
  SCAN_PROFILES,
  TECH_SIGNATURES,
  ADMIN_SERVICE_PORTS,
  getAllAdminPorts,
  getScanforgeScanPlanContext,
  getScanforgeVulnCorrelationContext,
  getScanforgeHuntContext,
  getFullScanforgeContext,
  buildOptimalScanforgeCommand,
  init_scanforge_knowledge
};
