/**
 * Threat Actor Matching & TTP Generation
 *
 * Matches threat actors to customer sectors and generates
 * ATT&CK-mapped TTP tables for Red Team Test Plans.
 *
 * @author Harrison Cook — AceofCloud
 */

// ─── Types ───────────────────────────────────────────────────────────────

export interface ThreatActorTTP {
  tactic: string;
  tacticId: string;
  techniqueId: string;
  techniqueName: string;
  procedure: string;
}

export interface ThreatActor {
  name: string;
  aliases: string[];
  origin: string;
  motivation: string;
  targetSectors: string[];
  description: string;
  ttps: ThreatActorTTP[];
}

// ─── Threat Actor Database ───────────────────────────────────────────────

export const THREAT_ACTORS: Record<string, ThreatActor> = {
  apt29: {
    name: "APT29 (Midnight Blizzard / Cozy Bear)",
    aliases: ["Midnight Blizzard", "Cozy Bear", "NOBELIUM", "The Dukes"],
    origin: "Russia — SVR",
    motivation: "Espionage, intelligence collection, long-term persistent access",
    targetSectors: ["government", "defense", "dib", "technology", "saas", "cloud", "healthcare", "energy"],
    description: "Russia's SVR-linked group known for sophisticated supply-chain attacks, OAuth abuse, and cloud-focused credential theft.",
    ttps: [
      { tactic: "Reconnaissance", tacticId: "TA0043", techniqueId: "T1589.001", techniqueName: "Gather Victim Identity: Credentials", procedure: "Harvest credentials from breach databases targeting organization personnel" },
      { tactic: "Initial Access", tacticId: "TA0001", techniqueId: "T1078.004", techniqueName: "Valid Accounts: Cloud Accounts", procedure: "Leverage stolen cloud credentials to gain authenticated access to tenant environments" },
      { tactic: "Initial Access", tacticId: "TA0001", techniqueId: "T1199", techniqueName: "Trusted Relationship", procedure: "Exploit trust relationships between service providers and targets" },
      { tactic: "Persistence", tacticId: "TA0003", techniqueId: "T1098.003", techniqueName: "Account Manipulation: Additional Cloud Roles", procedure: "Assign additional roles to compromised accounts for persistent access" },
      { tactic: "Persistence", tacticId: "TA0003", techniqueId: "T1136.003", techniqueName: "Create Account: Cloud Account", procedure: "Create new cloud service accounts for persistent backdoor access" },
      { tactic: "Privilege Escalation", tacticId: "TA0004", techniqueId: "T1484.002", techniqueName: "Domain Policy Modification: Trust Modification", procedure: "Modify federation trust settings to enable token forging (Golden SAML)" },
      { tactic: "Credential Access", tacticId: "TA0006", techniqueId: "T1528", techniqueName: "Steal Application Access Token", procedure: "Steal OAuth tokens to access cloud resources without credentials" },
      { tactic: "Lateral Movement", tacticId: "TA0008", techniqueId: "T1550.001", techniqueName: "Use Alternate Authentication Material: Application Access Token", procedure: "Use stolen OAuth/SAML tokens to move laterally across cloud services" },
      { tactic: "Collection", tacticId: "TA0009", techniqueId: "T1530", techniqueName: "Data from Cloud Storage", procedure: "Access and exfiltrate data from cloud storage services" },
      { tactic: "Exfiltration", tacticId: "TA0010", techniqueId: "T1567.002", techniqueName: "Exfiltration Over Web Service: Exfiltration to Cloud Storage", procedure: "Exfiltrate data to attacker-controlled cloud storage" },
    ],
  },
  volt_typhoon: {
    name: "Volt Typhoon (Bronze Silhouette)",
    aliases: ["Bronze Silhouette", "VANGUARD PANDA", "DEV-0391"],
    origin: "China — PLA / MSS",
    motivation: "Pre-positioning for disruption of critical infrastructure",
    targetSectors: ["government", "defense", "dib", "critical_infrastructure", "energy", "water", "transportation", "manufacturing"],
    description: "Chinese state-sponsored group focused on pre-positioning within U.S. critical infrastructure using living-off-the-land techniques.",
    ttps: [
      { tactic: "Reconnaissance", tacticId: "TA0043", techniqueId: "T1590.004", techniqueName: "Gather Victim Network Information: Network Topology", procedure: "Map target network topology through passive reconnaissance" },
      { tactic: "Initial Access", tacticId: "TA0001", techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", procedure: "Exploit vulnerabilities in internet-facing appliances (VPN, firewalls)" },
      { tactic: "Initial Access", tacticId: "TA0001", techniqueId: "T1133", techniqueName: "External Remote Services", procedure: "Leverage compromised VPN credentials to access internal networks" },
      { tactic: "Execution", tacticId: "TA0002", techniqueId: "T1059.001", techniqueName: "PowerShell", procedure: "Execute commands via PowerShell with living-off-the-land techniques" },
      { tactic: "Persistence", tacticId: "TA0003", techniqueId: "T1505.003", techniqueName: "Web Shell", procedure: "Deploy web shells on compromised public-facing servers" },
      { tactic: "Defense Evasion", tacticId: "TA0005", techniqueId: "T1036.005", techniqueName: "Masquerading: Match Legitimate Name", procedure: "Name malicious files to match legitimate system utilities" },
      { tactic: "Credential Access", tacticId: "TA0006", techniqueId: "T1003.001", techniqueName: "OS Credential Dumping: LSASS Memory", procedure: "Dump credentials from LSASS using built-in tools" },
      { tactic: "Discovery", tacticId: "TA0007", techniqueId: "T1046", techniqueName: "Network Service Discovery", procedure: "Enumerate internal services using native tools (netstat, nslookup)" },
      { tactic: "Lateral Movement", tacticId: "TA0008", techniqueId: "T1021.001", techniqueName: "Remote Desktop Protocol", procedure: "Move laterally using RDP with compromised credentials" },
      { tactic: "Exfiltration", tacticId: "TA0010", techniqueId: "T1048.003", techniqueName: "Exfiltration Over Alternative Protocol", procedure: "Exfiltrate data over standard protocols to blend with normal traffic" },
    ],
  },
  apt28: {
    name: "APT28 (Fancy Bear / Forest Blizzard)",
    aliases: ["Fancy Bear", "Forest Blizzard", "STRONTIUM", "Sofacy"],
    origin: "Russia — GRU (Unit 26165)",
    motivation: "Espionage, information operations, disruption",
    targetSectors: ["government", "defense", "dib", "aerospace", "energy", "media", "political"],
    description: "Russia's GRU-linked group known for aggressive credential harvesting, zero-day exploitation, and targeting government/defense.",
    ttps: [
      { tactic: "Reconnaissance", tacticId: "TA0043", techniqueId: "T1598.003", techniqueName: "Phishing for Information: Spearphishing Link", procedure: "Send targeted credential harvesting emails with convincing login portals" },
      { tactic: "Initial Access", tacticId: "TA0001", techniqueId: "T1566.002", techniqueName: "Phishing: Spearphishing Link", procedure: "Deliver spearphishing emails with links to credential harvesting pages" },
      { tactic: "Initial Access", tacticId: "TA0001", techniqueId: "T1190", techniqueName: "Exploit Public-Facing Application", procedure: "Exploit vulnerabilities in public-facing email servers and web applications" },
      { tactic: "Persistence", tacticId: "TA0003", techniqueId: "T1137.001", techniqueName: "Office Application Startup: Office Template Macros", procedure: "Modify Office templates to execute malicious macros on startup" },
      { tactic: "Privilege Escalation", tacticId: "TA0004", techniqueId: "T1068", techniqueName: "Exploitation for Privilege Escalation", procedure: "Exploit local privilege escalation vulnerabilities" },
      { tactic: "Credential Access", tacticId: "TA0006", techniqueId: "T1110.003", techniqueName: "Brute Force: Password Spraying", procedure: "Password spray against cloud authentication endpoints (OAuth, ADFS)" },
      { tactic: "Discovery", tacticId: "TA0007", techniqueId: "T1087.004", techniqueName: "Account Discovery: Cloud Account", procedure: "Enumerate cloud accounts and service principals" },
      { tactic: "Lateral Movement", tacticId: "TA0008", techniqueId: "T1534", techniqueName: "Internal Spearphishing", procedure: "Send spearphishing from compromised internal accounts" },
      { tactic: "Collection", tacticId: "TA0009", techniqueId: "T1114.002", techniqueName: "Email Collection: Remote Email Collection", procedure: "Access and collect email data from cloud email services" },
      { tactic: "Command and Control", tacticId: "TA0011", techniqueId: "T1071.001", techniqueName: "Web Protocols", procedure: "Use HTTPS for C2 tunneling through legitimate cloud services" },
    ],
  },
  lazarus: {
    name: "Lazarus Group (HIDDEN COBRA / Diamond Sleet)",
    aliases: ["HIDDEN COBRA", "Diamond Sleet", "Zinc", "APT38"],
    origin: "North Korea — RGB",
    motivation: "Financial theft, espionage, cryptocurrency theft, supply-chain compromise",
    targetSectors: ["financial", "cryptocurrency", "defense", "dib", "technology", "aerospace", "healthcare", "saas", "supply_chain"],
    description: "North Korean state-sponsored group conducting financially motivated attacks and espionage, known for supply-chain compromises.",
    ttps: [
      { tactic: "Reconnaissance", tacticId: "TA0043", techniqueId: "T1591.004", techniqueName: "Gather Victim Org Information: Identify Roles", procedure: "Research roles and identify personnel with access to financial systems" },
      { tactic: "Initial Access", tacticId: "TA0001", techniqueId: "T1195.002", techniqueName: "Supply Chain Compromise", procedure: "Compromise software build pipelines to distribute trojanized updates" },
      { tactic: "Initial Access", tacticId: "TA0001", techniqueId: "T1566.001", techniqueName: "Phishing: Spearphishing Attachment", procedure: "Deliver weaponized documents via targeted phishing campaigns" },
      { tactic: "Execution", tacticId: "TA0002", techniqueId: "T1204.002", techniqueName: "User Execution: Malicious File", procedure: "Trick users into executing malicious files disguised as legitimate documents" },
      { tactic: "Persistence", tacticId: "TA0003", techniqueId: "T1543.003", techniqueName: "Create or Modify System Process: Windows Service", procedure: "Install persistent backdoors as Windows services" },
      { tactic: "Credential Access", tacticId: "TA0006", techniqueId: "T1555.003", techniqueName: "Credentials from Web Browsers", procedure: "Extract saved credentials from web browsers and password managers" },
      { tactic: "Discovery", tacticId: "TA0007", techniqueId: "T1083", techniqueName: "File and Directory Discovery", procedure: "Enumerate file systems to locate sensitive documents and credentials" },
      { tactic: "Lateral Movement", tacticId: "TA0008", techniqueId: "T1021.002", techniqueName: "SMB/Windows Admin Shares", procedure: "Move laterally using SMB with harvested credentials" },
      { tactic: "Collection", tacticId: "TA0009", techniqueId: "T1005", techniqueName: "Data from Local System", procedure: "Collect sensitive files and credentials from compromised systems" },
      { tactic: "Exfiltration", tacticId: "TA0010", techniqueId: "T1041", techniqueName: "Exfiltration Over C2 Channel", procedure: "Exfiltrate data through established C2 channel" },
    ],
  },
  scattered_spider: {
    name: "Scattered Spider (Octo Tempest / UNC3944)",
    aliases: ["Octo Tempest", "UNC3944", "0ktapus"],
    origin: "International — English-speaking cybercriminal collective",
    motivation: "Financial gain, extortion, data theft, ransomware",
    targetSectors: ["technology", "telecommunications", "financial", "saas", "cloud", "hospitality", "retail", "healthcare"],
    description: "Sophisticated group known for social engineering of help desks, SIM swapping, MFA fatigue, and targeting cloud/SaaS environments.",
    ttps: [
      { tactic: "Initial Access", tacticId: "TA0001", techniqueId: "T1078.004", techniqueName: "Valid Accounts: Cloud Accounts", procedure: "Use stolen credentials with MFA fatigue to gain cloud access" },
      { tactic: "Initial Access", tacticId: "TA0001", techniqueId: "T1566.004", techniqueName: "Phishing: Spearphishing Voice", procedure: "Call IT help desks impersonating employees to reset MFA" },
      { tactic: "Persistence", tacticId: "TA0003", techniqueId: "T1098.005", techniqueName: "Account Manipulation: Device Registration", procedure: "Register attacker devices for persistent MFA bypass" },
      { tactic: "Privilege Escalation", tacticId: "TA0004", techniqueId: "T1078.002", techniqueName: "Valid Accounts: Domain Accounts", procedure: "Target domain admin accounts through social engineering" },
      { tactic: "Defense Evasion", tacticId: "TA0005", techniqueId: "T1562.001", techniqueName: "Impair Defenses: Disable Tools", procedure: "Disable EDR using compromised admin credentials" },
      { tactic: "Credential Access", tacticId: "TA0006", techniqueId: "T1621", techniqueName: "MFA Request Generation", procedure: "Flood targets with MFA push notifications (MFA fatigue)" },
      { tactic: "Discovery", tacticId: "TA0007", techniqueId: "T1538", techniqueName: "Cloud Service Dashboard", procedure: "Access cloud consoles to enumerate resources and permissions" },
      { tactic: "Lateral Movement", tacticId: "TA0008", techniqueId: "T1550.001", techniqueName: "Application Access Token", procedure: "Use stolen session tokens to access additional cloud services" },
      { tactic: "Collection", tacticId: "TA0009", techniqueId: "T1530", techniqueName: "Data from Cloud Storage", procedure: "Access cloud storage to collect sensitive data" },
      { tactic: "Impact", tacticId: "TA0040", techniqueId: "T1486", techniqueName: "Data Encrypted for Impact", procedure: "Deploy ransomware (BlackCat/ALPHV) for extortion" },
    ],
  },
};

// ─── Matching Logic ──────────────────────────────────────────────────────

export function matchThreatActors(sectorDescription: string, maxResults: number = 4): ThreatActor[] {
  const sectorLower = sectorDescription.toLowerCase();
  const keywords = sectorLower.split(/[\s,;|/]+/).filter(Boolean);

  const scored = Object.values(THREAT_ACTORS).map((actor) => {
    let score = 0;
    for (const sector of actor.targetSectors) {
      if (sectorLower.includes(sector)) score += 3;
      for (const kw of keywords) {
        if (sector.includes(kw) || kw.includes(sector)) score += 1;
      }
    }
    return { actor, score };
  });

  return scored
    .filter((s) => s.score > 0)
    .sort((a, b) => b.score - a.score)
    .slice(0, maxResults)
    .map((s) => s.actor);
}

// ─── HTML Generators ─────────────────────────────────────────────────────

export function generateAptTable(actors: ThreatActor[]): string {
  let html = `<table><thead><tr><th>Threat Actor</th><th>Origin</th><th>Motivation</th><th>Key TTPs</th></tr></thead><tbody>`;
  for (const actor of actors) {
    const shortName = actor.name.split(" (")[0];
    const alias = actor.aliases[0] || "";
    const keyTtps = actor.ttps.slice(0, 4).map((t) => `${t.techniqueId}`).join(", ");
    html += `<tr><td><strong>${shortName}</strong><br><em>${alias}</em></td><td>${actor.origin}</td><td>${actor.motivation}</td><td>${keyTtps}</td></tr>`;
  }
  html += `</tbody></table>`;
  return html;
}

export function generateExternalScenarios(actors: ThreatActor[], targetHosts: string[]): string {
  const hostsStr = targetHosts.slice(0, 3).join(", ") || "in-scope targets";
  const actorName = actors[0]?.name.split(" (")[0] || "APT29";

  return `<h4>Scenario 1: External Reconnaissance & Enumeration</h4>
<p>Emulating <strong>${actorName}</strong>, the Red Team will conduct comprehensive external enumeration of ${hostsStr}.</p>
<table><thead><tr><th>Step</th><th>Action</th><th>MITRE Technique</th><th>Tools</th></tr></thead><tbody>
<tr><td>1</td><td>DNS enumeration and subdomain discovery</td><td>T1590.002</td><td>Subfinder, Amass, DNSRecon</td></tr>
<tr><td>2</td><td>Port scanning and service fingerprinting</td><td>T1046</td><td>Naabu, RustScan, Nmap</td></tr>
<tr><td>3</td><td>Web application technology profiling</td><td>T1592.002</td><td>Wappalyzer, WhatWeb, httpx</td></tr>
<tr><td>4</td><td>Certificate transparency log analysis</td><td>T1596.002</td><td>crt.sh, Censys, Shodan</td></tr>
<tr><td>5</td><td>Cloud infrastructure enumeration</td><td>T1580</td><td>CloudEnum, S3Scanner</td></tr>
</tbody></table>

<h4>Scenario 2: Web Application Attack Surface</h4>
<p>Targeting web applications identified during reconnaissance.</p>
<table><thead><tr><th>Step</th><th>Action</th><th>MITRE Technique</th><th>Tools</th></tr></thead><tbody>
<tr><td>1</td><td>Automated vulnerability scanning</td><td>T1595.002</td><td>Nuclei, Nikto, ZAP</td></tr>
<tr><td>2</td><td>Authentication mechanism testing</td><td>T1110</td><td>Hydra, Burp Suite</td></tr>
<tr><td>3</td><td>API endpoint enumeration and testing</td><td>T1190</td><td>Postman, ffuf, Burp Suite</td></tr>
<tr><td>4</td><td>Input validation and injection testing</td><td>T1190</td><td>SQLMap, Burp Suite</td></tr>
<tr><td>5</td><td>Cloud service misconfiguration testing</td><td>T1580</td><td>ScoutSuite, Prowler</td></tr>
</tbody></table>`;
}

export function generateInternalScenarios(actors: ThreatActor[], accessModel: string): string {
  const isAssumedBreach = accessModel === "assumed_breach";
  const actorName = actors[0]?.name.split(" (")[0] || "APT29";

  const initialAccess = isAssumedBreach
    ? `<tr><td>1</td><td>Authenticate with provided stolen tenant credentials</td><td>T1078.004</td><td>Browser, CLI tools</td></tr>`
    : `<tr><td>1</td><td>Leverage credentials obtained during external phase</td><td>T1078.004</td><td>Browser, CLI tools</td></tr>`;

  return `<h4>Scenario 3: Internal Network — ${isAssumedBreach ? "Assumed Breach" : "Post-Exploitation"}</h4>
<p>Emulating <strong>${actorName}</strong> post-initial-access tradecraft, the Red Team will attempt privilege escalation, lateral movement, and data exfiltration.</p>
<table><thead><tr><th>Step</th><th>Action</th><th>MITRE Technique</th><th>Tools</th></tr></thead><tbody>
${initialAccess}
<tr><td>2</td><td>Enumerate cloud IAM roles and permissions</td><td>T1087.004</td><td>AWS CLI, AzureHound, Pacu</td></tr>
<tr><td>3</td><td>Attempt privilege escalation via IAM misconfigurations</td><td>T1484.002</td><td>Pacu, CloudGoat, Custom Scripts</td></tr>
<tr><td>4</td><td>Lateral movement via service account token theft</td><td>T1550.001</td><td>AWS CLI, kubectl</td></tr>
<tr><td>5</td><td>Access sensitive data stores (S3, databases, secrets)</td><td>T1530</td><td>AWS CLI, Custom Scripts</td></tr>
<tr><td>6</td><td>Establish persistence via backdoor IAM policies</td><td>T1098.003</td><td>AWS CLI, Terraform</td></tr>
<tr><td>7</td><td>Simulate data exfiltration to external storage</td><td>T1567.002</td><td>AWS CLI, rclone</td></tr>
</tbody></table>

<h4>Scenario 4: Tenant Isolation Testing</h4>
<p>Validate multi-tenant isolation boundaries to ensure no cross-tenant data leakage.</p>
<table><thead><tr><th>Step</th><th>Action</th><th>MITRE Technique</th><th>Tools</th></tr></thead><tbody>
<tr><td>1</td><td>Enumerate shared infrastructure components</td><td>T1580</td><td>Cloud CLI, Custom Scripts</td></tr>
<tr><td>2</td><td>Attempt cross-tenant API access</td><td>T1078.004</td><td>Burp Suite, Postman</td></tr>
<tr><td>3</td><td>Test RBAC boundary enforcement</td><td>T1078.002</td><td>Custom Scripts</td></tr>
<tr><td>4</td><td>Validate data isolation in shared storage</td><td>T1530</td><td>Cloud CLI</td></tr>
</tbody></table>`;
}

// ─── Color Utilities ─────────────────────────────────────────────────────

export function darkenColor(hex: string): string {
  const r = Math.max(0, parseInt(hex.slice(1, 3), 16) - 40);
  const g = Math.max(0, parseInt(hex.slice(3, 5), 16) - 40);
  const b = Math.max(0, parseInt(hex.slice(5, 7), 16) - 40);
  return `#${r.toString(16).padStart(2, "0")}${g.toString(16).padStart(2, "0")}${b.toString(16).padStart(2, "0")}`;
}

export function lightenColor(hex: string): string {
  const r = Math.min(255, parseInt(hex.slice(1, 3), 16) + 60);
  const g = Math.min(255, parseInt(hex.slice(3, 5), 16) + 60);
  const b = Math.min(255, parseInt(hex.slice(5, 7), 16) + 60);
  return `#${r.toString(16).padStart(2, "0")}${g.toString(16).padStart(2, "0")}${b.toString(16).padStart(2, "0")}`;
}
