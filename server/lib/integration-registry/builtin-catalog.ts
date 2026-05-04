/**
 * Built-In Integration Catalog
 * ═══════════════════════════════════════════════════════════════════════
 * 
 * Pre-registers all existing AC3 integrations so the registry has a
 * complete picture of what's already available. This enables:
 *   - Value assessment (does a new source overlap with existing ones?)
 *   - Pipeline coverage analysis (which stages have gaps?)
 *   - Customer UI (show all available integrations with status)
 * 
 * Each entry is a partial IntegrationDefinition — the registry
 * hydrates them with runtime status, credentials, and health data.
 */

import type {
  IntegrationCategory,
  IntegrationDefinition,
  LicenseModel,
  PipelineStage,
  AuthMethod,
  DataFormat,
} from "./types";

// ═══════════════════════════════════════════════════════════════════════
// §1 — CATALOG ENTRY TYPE
// ═══════════════════════════════════════════════════════════════════════

export interface CatalogEntry {
  id: string;
  name: string;
  displayName: string;
  description: string;
  category: IntegrationCategory;
  licenseModel: LicenseModel;
  pipelineStages: PipelineStage[];
  authMethod: AuthMethod;
  envVarKeys: string[];       // Platform env vars that provide default credentials
  dataTypes: string[];        // What data this provides
  inputTypes: string[];       // What inputs it accepts
  outputTypes: string[];      // What AC3 asset types it produces
  enhancesModules: string[];  // Which AC3 modules benefit
  docsUrl?: string;
  icon?: string;
  tags: string[];
  supportsPassiveOnly: boolean;
  requiresActiveProbing: boolean;
  rateLimit?: number;         // Requests per minute
  isBuiltIn: true;
}

// ═══════════════════════════════════════════════════════════════════════
// §2 — OSINT CONNECTORS
// ═══════════════════════════════════════════════════════════════════════

const OSINT_CONNECTORS: CatalogEntry[] = [
  {
    id: "shodan", name: "shodan", displayName: "Shodan",
    description: "Internet-wide device search — open ports, services, banners, CVEs, and geolocation for any IP",
    category: "osint", licenseModel: "api_key",
    pipelineStages: ["recon", "passive_discovery", "enumeration", "enrichment"],
    authMethod: "api_key", envVarKeys: ["SHODAN_API_KEY"],
    dataTypes: ["open_ports", "services", "banners", "cves", "geolocation", "ssl_certs"],
    inputTypes: ["domain", "ip", "cidr"], outputTypes: ["ip", "subdomain", "infrastructure"],
    enhancesModules: ["passive_recon", "service_fingerprinting", "vuln_detection"],
    docsUrl: "https://developer.shodan.io/api", tags: ["network", "iot", "infrastructure"], supportsPassiveOnly: true, requiresActiveProbing: false, rateLimit: 1, isBuiltIn: true,
  },
  {
    id: "censys", name: "censys", displayName: "Censys",
    description: "Internet-wide host and certificate search — TLS certs, open ports, services, and protocols",
    category: "osint", licenseModel: "api_key",
    pipelineStages: ["recon", "passive_discovery", "enrichment"],
    authMethod: "api_key_secret", envVarKeys: ["CENSYS_API_ID", "CENSYS_API_SECRET"],
    dataTypes: ["certificates", "open_ports", "services", "protocols"],
    inputTypes: ["domain", "ip"], outputTypes: ["ip", "certificate", "subdomain"],
    enhancesModules: ["passive_recon", "certificate_analysis"],
    docsUrl: "https://search.censys.io/api", tags: ["certificates", "infrastructure"], supportsPassiveOnly: true, requiresActiveProbing: false, rateLimit: 5, isBuiltIn: true,
  },
  {
    id: "securitytrails", name: "securitytrails", displayName: "SecurityTrails",
    description: "Historical DNS, WHOIS, and subdomain data — tracks domain changes over time",
    category: "osint", licenseModel: "api_key",
    pipelineStages: ["recon", "passive_discovery"],
    authMethod: "api_key", envVarKeys: ["SECURITYTRAILS_API_KEY"],
    dataTypes: ["subdomains", "dns_history", "whois_history", "associated_domains"],
    inputTypes: ["domain"], outputTypes: ["subdomain", "domain"],
    enhancesModules: ["passive_recon", "domain_intelligence"],
    docsUrl: "https://securitytrails.com/corp/api", tags: ["dns", "history", "subdomains"], supportsPassiveOnly: true, requiresActiveProbing: false, rateLimit: 50, isBuiltIn: true,
  },
  {
    id: "urlscan", name: "urlscan", displayName: "URLScan.io",
    description: "URL scanning service — screenshots, DOM analysis, network requests, and threat detection",
    category: "osint", licenseModel: "freemium",
    pipelineStages: ["recon", "passive_discovery"],
    authMethod: "api_key", envVarKeys: ["URLSCAN_API_KEY"],
    dataTypes: ["screenshots", "dom_analysis", "network_requests", "technologies"],
    inputTypes: ["url", "domain"], outputTypes: ["url", "subdomain"],
    enhancesModules: ["passive_recon", "tech_detection"],
    docsUrl: "https://urlscan.io/docs/api/", tags: ["web", "screenshots", "analysis"], supportsPassiveOnly: true, requiresActiveProbing: false, rateLimit: 60, isBuiltIn: true,
  },
  {
    id: "virustotal", name: "virustotal", displayName: "VirusTotal",
    description: "Multi-engine malware and URL reputation — file/URL/domain/IP analysis across 70+ AV engines",
    category: "osint", licenseModel: "freemium",
    pipelineStages: ["recon", "enrichment"],
    authMethod: "api_key", envVarKeys: ["VIRUSTOTAL_API_KEY"],
    dataTypes: ["malware_analysis", "url_reputation", "domain_reputation", "ip_reputation"],
    inputTypes: ["domain", "ip", "url", "file_hash"], outputTypes: ["subdomain", "ip"],
    enhancesModules: ["passive_recon", "threat_intel"],
    docsUrl: "https://docs.virustotal.com/reference/overview", tags: ["malware", "reputation", "av"], supportsPassiveOnly: true, requiresActiveProbing: false, rateLimit: 4, isBuiltIn: true,
  },
  {
    id: "crtsh", name: "crtsh", displayName: "crt.sh",
    description: "Certificate Transparency log search — discover subdomains via SSL/TLS certificate issuance",
    category: "osint", licenseModel: "free",
    pipelineStages: ["recon", "passive_discovery"],
    authMethod: "none", envVarKeys: [],
    dataTypes: ["certificates", "subdomains"],
    inputTypes: ["domain"], outputTypes: ["subdomain", "certificate"],
    enhancesModules: ["passive_recon", "subdomain_enumeration"],
    docsUrl: "https://crt.sh/", tags: ["certificates", "subdomains", "free"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true,
  },
  {
    id: "wayback", name: "wayback", displayName: "Wayback Machine",
    description: "Historical web archive — discover old URLs, endpoints, and content changes over time",
    category: "osint", licenseModel: "free",
    pipelineStages: ["recon", "passive_discovery"],
    authMethod: "none", envVarKeys: [],
    dataTypes: ["historical_urls", "archived_pages"],
    inputTypes: ["domain", "url"], outputTypes: ["url"],
    enhancesModules: ["passive_recon", "endpoint_discovery"],
    docsUrl: "https://web.archive.org/", tags: ["history", "urls", "free"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true,
  },
  {
    id: "greynoise", name: "greynoise", displayName: "GreyNoise",
    description: "Internet noise intelligence — identifies mass scanners, botnets, and benign crawlers hitting your IPs",
    category: "osint", licenseModel: "freemium",
    pipelineStages: ["recon", "enrichment"],
    authMethod: "api_key", envVarKeys: ["GREYNOISE_API_KEY"],
    dataTypes: ["ip_context", "noise_classification", "riot_data"],
    inputTypes: ["ip"], outputTypes: ["ip"],
    enhancesModules: ["passive_recon", "threat_context"],
    docsUrl: "https://docs.greynoise.io/", tags: ["noise", "scanners", "context"], supportsPassiveOnly: true, requiresActiveProbing: false, rateLimit: 60, isBuiltIn: true,
  },
  {
    id: "abuseipdb", name: "abuseipdb", displayName: "AbuseIPDB",
    description: "IP abuse reputation database — reports of malicious activity, spam, and attacks from specific IPs",
    category: "osint", licenseModel: "freemium",
    pipelineStages: ["recon", "enrichment"],
    authMethod: "api_key", envVarKeys: ["ABUSEIPDB_API_KEY"],
    dataTypes: ["ip_reputation", "abuse_reports", "abuse_score"],
    inputTypes: ["ip"], outputTypes: ["ip"],
    enhancesModules: ["passive_recon", "threat_scoring"],
    docsUrl: "https://www.abuseipdb.com/api.html", tags: ["abuse", "reputation", "ip"], supportsPassiveOnly: true, requiresActiveProbing: false, rateLimit: 60, isBuiltIn: true,
  },
  {
    id: "shodan_internetdb", name: "shodan_internetdb", displayName: "Shodan InternetDB",
    description: "Free Shodan fast-path — instant port/CVE/tag data for any IP without API key",
    category: "osint", licenseModel: "free",
    pipelineStages: ["recon", "passive_discovery"],
    authMethod: "none", envVarKeys: [],
    dataTypes: ["open_ports", "cves", "tags", "hostnames"],
    inputTypes: ["ip"], outputTypes: ["ip"],
    enhancesModules: ["passive_recon", "quick_assessment"],
    docsUrl: "https://internetdb.shodan.io/", tags: ["ports", "cves", "free", "fast"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true,
  },
  // Additional OSINT connectors (abbreviated for space — full list in registry)
  { id: "whoisxml", name: "whoisxml", displayName: "WhoisXML", description: "WHOIS, DNS, subdomain enumeration", category: "osint", licenseModel: "api_key", pipelineStages: ["recon", "passive_discovery"], authMethod: "api_key", envVarKeys: ["WHOISXML_API_KEY"], dataTypes: ["whois", "dns", "subdomains"], inputTypes: ["domain"], outputTypes: ["subdomain", "domain"], enhancesModules: ["passive_recon"], tags: ["whois", "dns"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true },
  { id: "fullhunt", name: "fullhunt", displayName: "FullHunt", description: "Attack surface discovery and monitoring", category: "osint", licenseModel: "api_key", pipelineStages: ["recon", "passive_discovery"], authMethod: "api_key", envVarKeys: ["FULLHUNT_API_KEY"], dataTypes: ["subdomains", "ports", "technologies"], inputTypes: ["domain"], outputTypes: ["subdomain", "ip"], enhancesModules: ["passive_recon"], tags: ["attack_surface"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true },
  { id: "netlas", name: "netlas", displayName: "Netlas.io", description: "Internet-wide host scanning and DNS history", category: "osint", licenseModel: "api_key", pipelineStages: ["recon", "passive_discovery"], authMethod: "api_key", envVarKeys: ["NETLAS_API_KEY"], dataTypes: ["hosts", "dns_history", "whois"], inputTypes: ["domain", "ip"], outputTypes: ["ip", "subdomain"], enhancesModules: ["passive_recon"], tags: ["hosts", "dns"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true },
  { id: "hunter", name: "hunter", displayName: "Hunter.io", description: "Email discovery and organizational intelligence", category: "osint", licenseModel: "api_key", pipelineStages: ["recon"], authMethod: "api_key", envVarKeys: ["HUNTER_API_KEY"], dataTypes: ["emails", "org_info"], inputTypes: ["domain"], outputTypes: ["domain"], enhancesModules: ["passive_recon", "social_engineering"], tags: ["email", "org"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true },
  { id: "passivetotal", name: "passivetotal", displayName: "PassiveTotal", description: "Passive DNS, SSL history, host attributes", category: "osint", licenseModel: "api_key", pipelineStages: ["recon", "passive_discovery"], authMethod: "api_key", envVarKeys: ["PASSIVETOTAL_API_KEY"], dataTypes: ["passive_dns", "ssl_history", "host_attributes"], inputTypes: ["domain", "ip"], outputTypes: ["subdomain", "ip", "certificate"], enhancesModules: ["passive_recon"], tags: ["passive_dns", "ssl"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true },
  { id: "builtwith", name: "builtwith", displayName: "BuiltWith", description: "Technology stack detection", category: "osint", licenseModel: "free", pipelineStages: ["recon"], authMethod: "none", envVarKeys: [], dataTypes: ["technologies", "frameworks", "analytics"], inputTypes: ["domain"], outputTypes: ["domain"], enhancesModules: ["passive_recon", "tech_detection"], tags: ["tech_stack", "free"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true },
  { id: "commoncrawl", name: "commoncrawl", displayName: "CommonCrawl", description: "Historical web crawl data for company context", category: "osint", licenseModel: "free", pipelineStages: ["recon"], authMethod: "none", envVarKeys: [], dataTypes: ["historical_pages", "urls"], inputTypes: ["domain"], outputTypes: ["url"], enhancesModules: ["passive_recon"], tags: ["history", "free"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true },
];

// ═══════════════════════════════════════════════════════════════════════
// §3 — THREAT INTELLIGENCE CONNECTORS
// ═══════════════════════════════════════════════════════════════════════

const THREAT_INTEL_CONNECTORS: CatalogEntry[] = [
  {
    id: "alienvault_otx", name: "alienvault_otx", displayName: "AlienVault OTX",
    description: "Open Threat Exchange — community threat intel, pulses, IOCs, passive DNS, and malware data",
    category: "threat_intel", licenseModel: "free",
    pipelineStages: ["recon", "enrichment"],
    authMethod: "api_key", envVarKeys: [],
    dataTypes: ["iocs", "pulses", "passive_dns", "malware_samples"],
    inputTypes: ["domain", "ip", "file_hash"], outputTypes: ["ip", "domain"],
    enhancesModules: ["threat_intel", "passive_recon"],
    docsUrl: "https://otx.alienvault.com/api", tags: ["iocs", "community", "free"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true,
  },
  {
    id: "threatfox", name: "threatfox", displayName: "ThreatFox (abuse.ch)",
    description: "Free IOC database — malware, botnet, and C2 indicators from abuse.ch",
    category: "threat_intel", licenseModel: "free",
    pipelineStages: ["enrichment"],
    authMethod: "none", envVarKeys: [],
    dataTypes: ["iocs", "malware_indicators", "c2_indicators"],
    inputTypes: ["domain", "ip", "file_hash"], outputTypes: ["ip", "domain"],
    enhancesModules: ["threat_intel"], tags: ["iocs", "malware", "free"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true,
  },
  {
    id: "ransomware_live", name: "ransomware_live", displayName: "Ransomware.live",
    description: "Real-time ransomware victim tracking and group intelligence",
    category: "threat_intel", licenseModel: "free",
    pipelineStages: ["enrichment"],
    authMethod: "none", envVarKeys: [],
    dataTypes: ["ransomware_groups", "victims", "leak_sites"],
    inputTypes: ["domain"], outputTypes: ["domain"],
    enhancesModules: ["threat_intel", "risk_scoring"], tags: ["ransomware", "free"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true,
  },
  {
    id: "threatminer", name: "threatminer", displayName: "ThreatMiner",
    description: "Free threat intel — passive DNS, malware samples, APT reports",
    category: "threat_intel", licenseModel: "free",
    pipelineStages: ["recon", "enrichment"],
    authMethod: "none", envVarKeys: [],
    dataTypes: ["passive_dns", "malware", "apt_reports"],
    inputTypes: ["domain", "ip"], outputTypes: ["ip", "domain"],
    enhancesModules: ["threat_intel", "passive_recon"], tags: ["apt", "malware", "free"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true,
  },
  {
    id: "phishtank", name: "phishtank", displayName: "PhishTank",
    description: "Community-verified phishing URL database",
    category: "threat_intel", licenseModel: "free",
    pipelineStages: ["enrichment"],
    authMethod: "none", envVarKeys: [],
    dataTypes: ["phishing_urls", "phishing_targets"],
    inputTypes: ["url", "domain"], outputTypes: ["url"],
    enhancesModules: ["threat_intel", "phishing_detection"], tags: ["phishing", "free"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true,
  },
  {
    id: "google_safebrowsing", name: "google_safebrowsing", displayName: "Google Safe Browsing",
    description: "Malware, phishing, and unwanted software detection via Google's threat lists",
    category: "threat_intel", licenseModel: "free",
    pipelineStages: ["enrichment"],
    authMethod: "none", envVarKeys: [],
    dataTypes: ["malware_detection", "phishing_detection", "unwanted_software"],
    inputTypes: ["url", "domain"], outputTypes: ["url"],
    enhancesModules: ["threat_intel"], tags: ["malware", "phishing", "free"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true,
  },
];

// ═══════════════════════════════════════════════════════════════════════
// §4 — CREDENTIAL / BREACH CONNECTORS
// ═══════════════════════════════════════════════════════════════════════

const CREDENTIAL_CONNECTORS: CatalogEntry[] = [
  {
    id: "dehashed", name: "dehashed", displayName: "DeHashed",
    description: "Breach database search — leaked credentials, emails, passwords, and personal data",
    category: "credential", licenseModel: "api_key",
    pipelineStages: ["recon", "enrichment"],
    authMethod: "api_key", envVarKeys: ["DEHASHED_API_KEY"],
    dataTypes: ["breached_credentials", "emails", "passwords", "personal_data"],
    inputTypes: ["domain", "email"], outputTypes: ["credential", "breach"],
    enhancesModules: ["passive_recon", "credential_testing"],
    docsUrl: "https://www.dehashed.com/docs", tags: ["breach", "credentials"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true,
  },
  {
    id: "hibp", name: "hibp", displayName: "Have I Been Pwned",
    description: "Breach exposure monitoring — check if emails/domains appear in known data breaches",
    category: "credential", licenseModel: "api_key",
    pipelineStages: ["recon", "enrichment"],
    authMethod: "api_key", envVarKeys: ["HIBP_API_KEY"],
    dataTypes: ["breach_exposure", "paste_exposure"],
    inputTypes: ["email", "domain"], outputTypes: ["breach"],
    enhancesModules: ["passive_recon", "breach_monitoring"],
    docsUrl: "https://haveibeenpwned.com/API/v3", tags: ["breach", "monitoring"], supportsPassiveOnly: true, requiresActiveProbing: false, rateLimit: 10, isBuiltIn: true,
  },
  {
    id: "leakcheck", name: "leakcheck", displayName: "LeakCheck",
    description: "Credential leak search — check emails and domains against leaked databases",
    category: "credential", licenseModel: "api_key",
    pipelineStages: ["recon"],
    authMethod: "api_key", envVarKeys: ["LEAKCHECK_API_KEY"],
    dataTypes: ["leaked_credentials"], inputTypes: ["email", "domain"], outputTypes: ["credential"],
    enhancesModules: ["passive_recon", "credential_testing"], tags: ["leak", "credentials"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true,
  },
  {
    id: "hudson_rock", name: "hudson_rock", displayName: "Hudson Rock",
    description: "Stealer log exposure — check if employees/domains appear in infostealer malware logs",
    category: "credential", licenseModel: "api_key",
    pipelineStages: ["recon", "enrichment"],
    authMethod: "api_key", envVarKeys: ["HUDSON_ROCK_API_KEY"],
    dataTypes: ["stealer_logs", "compromised_credentials"],
    inputTypes: ["domain", "email"], outputTypes: ["credential"],
    enhancesModules: ["passive_recon", "threat_intel"], tags: ["stealer", "infostealer"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true,
  },
];

// ═══════════════════════════════════════════════════════════════════════
// §5 — VULNERABILITY SCANNERS
// ═══════════════════════════════════════════════════════════════════════

const SCANNER_CONNECTORS: CatalogEntry[] = [
  {
    id: "zap", name: "zap", displayName: "OWASP ZAP",
    description: "Open-source DAST scanner — spider, active scan, AJAX crawl, fuzzing, OAST blind detection",
    category: "scanner", licenseModel: "free",
    pipelineStages: ["vuln_detection"],
    authMethod: "api_key", envVarKeys: ["ZAP_API_KEY", "ZAP_BASE_URL"],
    dataTypes: ["web_vulnerabilities", "xss", "sqli", "ssrf", "csrf", "misconfigurations"],
    inputTypes: ["url"], outputTypes: ["subdomain"],
    enhancesModules: ["vuln_scanning", "web_app_testing"],
    docsUrl: "https://www.zaproxy.org/docs/api/", tags: ["dast", "web", "owasp"], supportsPassiveOnly: false, requiresActiveProbing: true, isBuiltIn: true,
  },
  {
    id: "burp_suite", name: "burp_suite", displayName: "Burp Suite Professional",
    description: "Commercial DAST scanner — advanced crawling, audit, Collaborator OAST, Intruder, and extensions",
    category: "scanner", licenseModel: "byol",
    pipelineStages: ["vuln_detection"],
    authMethod: "api_key", envVarKeys: ["BURP_LICENSE_EMAIL", "BURP_LICENSE_PASSWORD"],
    dataTypes: ["web_vulnerabilities", "xss", "sqli", "ssrf", "deserialization", "auth_bypass"],
    inputTypes: ["url"], outputTypes: ["subdomain"],
    enhancesModules: ["vuln_scanning", "web_app_testing"],
    docsUrl: "https://portswigger.net/burp/documentation/enterprise/api", tags: ["dast", "web", "commercial"], supportsPassiveOnly: false, requiresActiveProbing: true, isBuiltIn: true,
  },
  {
    id: "nuclei", name: "nuclei", displayName: "Nuclei",
    description: "Template-based vulnerability scanner — 8000+ templates for CVEs, misconfigs, and exposures",
    category: "scanner", licenseModel: "free",
    pipelineStages: ["vuln_detection", "exploitation"],
    authMethod: "none", envVarKeys: [],
    dataTypes: ["cve_detection", "misconfigurations", "exposures", "default_credentials"],
    inputTypes: ["url", "ip"], outputTypes: ["subdomain", "ip"],
    enhancesModules: ["vuln_scanning", "exploit_verification"],
    docsUrl: "https://docs.projectdiscovery.io/tools/nuclei/", tags: ["templates", "cve", "free"], supportsPassiveOnly: false, requiresActiveProbing: true, isBuiltIn: true,
  },
  {
    id: "nikto", name: "nikto", displayName: "Nikto",
    description: "Web server scanner — outdated software, dangerous files, misconfigurations",
    category: "scanner", licenseModel: "free",
    pipelineStages: ["vuln_detection"],
    authMethod: "none", envVarKeys: [],
    dataTypes: ["server_misconfigurations", "outdated_software", "dangerous_files"],
    inputTypes: ["url"], outputTypes: ["subdomain"],
    enhancesModules: ["vuln_scanning"], tags: ["web_server", "free"], supportsPassiveOnly: false, requiresActiveProbing: true, isBuiltIn: true,
  },
];

// ═══════════════════════════════════════════════════════════════════════
// §6 — PENETRATION TESTING TOOLS
// ═══════════════════════════════════════════════════════════════════════

const PENTEST_CONNECTORS: CatalogEntry[] = [
  {
    id: "metasploit", name: "metasploit", displayName: "Metasploit Framework",
    description: "Exploitation framework — 2000+ modules for remote exploits, local exploits, and post-exploitation",
    category: "pentest_tool", licenseModel: "free",
    pipelineStages: ["exploitation", "post_exploit"],
    authMethod: "basic_auth", envVarKeys: ["MSF_RPC_HOST", "MSF_RPC_PORT", "MSF_RPC_USER", "MSF_RPC_PASS"],
    dataTypes: ["exploit_results", "sessions", "post_exploit_data"],
    inputTypes: ["ip", "url"], outputTypes: ["ip"],
    enhancesModules: ["exploit_execution", "post_exploitation"],
    docsUrl: "https://docs.metasploit.com/", tags: ["exploit", "framework"], supportsPassiveOnly: false, requiresActiveProbing: true, isBuiltIn: true,
  },
  {
    id: "cobalt_strike", name: "cobalt_strike", displayName: "Cobalt Strike",
    description: "Commercial adversary simulation — Beacon C2, malleable C2 profiles, lateral movement, and persistence",
    category: "pentest_tool", licenseModel: "byol",
    pipelineStages: ["exploitation", "post_exploit"],
    authMethod: "custom_header", envVarKeys: ["CS_TEAM_SERVER_URL", "CS_API_KEY", "CS_USERNAME", "CS_PASSWORD"],
    dataTypes: ["beacon_sessions", "lateral_movement", "persistence", "credential_harvesting"],
    inputTypes: ["ip"], outputTypes: ["ip"],
    enhancesModules: ["c2_operations", "adversary_emulation"],
    docsUrl: "https://www.cobaltstrike.com/", tags: ["c2", "adversary_sim", "commercial"], supportsPassiveOnly: false, requiresActiveProbing: true, isBuiltIn: true,
  },
];

// ═══════════════════════════════════════════════════════════════════════
// §7 — C2 FRAMEWORKS
// ═══════════════════════════════════════════════════════════════════════

const C2_CONNECTORS: CatalogEntry[] = [
  {
    id: "caldera", name: "caldera", displayName: "MITRE Caldera",
    description: "Automated adversary emulation — MITRE ATT&CK-aligned operations with abilities and planners",
    category: "c2", licenseModel: "free",
    pipelineStages: ["exploitation", "post_exploit"],
    authMethod: "api_key", envVarKeys: ["CALDERA_BASE_URL", "CALDERA_API_KEY"],
    dataTypes: ["operations", "abilities", "agents", "adversary_profiles"],
    inputTypes: ["ip"], outputTypes: ["ip"],
    enhancesModules: ["adversary_emulation", "attack_simulation"],
    docsUrl: "https://caldera.readthedocs.io/", tags: ["mitre", "emulation", "free"], supportsPassiveOnly: false, requiresActiveProbing: true, isBuiltIn: true,
  },
  {
    id: "empire", name: "empire", displayName: "Empire (BC Security)",
    description: "Post-exploitation C2 — PowerShell/Python agents, modules, and stagers",
    category: "c2", licenseModel: "free",
    pipelineStages: ["post_exploit"],
    authMethod: "api_key", envVarKeys: ["EMPIRE_BASE_URL", "EMPIRE_API_KEY"],
    dataTypes: ["agents", "modules", "stagers"],
    inputTypes: ["ip"], outputTypes: ["ip"],
    enhancesModules: ["post_exploitation", "c2_operations"], tags: ["c2", "post_exploit", "free"], supportsPassiveOnly: false, requiresActiveProbing: true, isBuiltIn: true,
  },
  {
    id: "sliver", name: "sliver", displayName: "Sliver C2",
    description: "Open-source C2 — implants, pivots, and operator collaboration via gRPC",
    category: "c2", licenseModel: "free",
    pipelineStages: ["post_exploit"],
    authMethod: "bearer_token", envVarKeys: ["SLIVER_SERVER_URL", "SLIVER_OPERATOR_TOKEN"],
    dataTypes: ["implants", "sessions", "pivots"],
    inputTypes: ["ip"], outputTypes: ["ip"],
    enhancesModules: ["c2_operations"], tags: ["c2", "implants", "free"], supportsPassiveOnly: false, requiresActiveProbing: true, isBuiltIn: true,
  },
];

// ═══════════════════════════════════════════════════════════════════════
// §8 — PHISHING PLATFORMS
// ═══════════════════════════════════════════════════════════════════════

const PHISHING_CONNECTORS: CatalogEntry[] = [
  {
    id: "gophish", name: "gophish", displayName: "GoPhish",
    description: "Open-source phishing simulation — campaign management, landing pages, and result tracking",
    category: "phishing", licenseModel: "free",
    pipelineStages: ["social_engineering"],
    authMethod: "api_key", envVarKeys: ["GOPHISH_BASE_URL", "GOPHISH_API_KEY"],
    dataTypes: ["campaigns", "results", "click_rates", "credential_captures"],
    inputTypes: ["email"], outputTypes: ["domain"],
    enhancesModules: ["phishing_simulation", "social_engineering"],
    docsUrl: "https://docs.getgophish.com/", tags: ["phishing", "simulation", "free"], supportsPassiveOnly: false, requiresActiveProbing: true, isBuiltIn: true,
  },
  {
    id: "knowbe4", name: "knowbe4", displayName: "KnowBe4",
    description: "Commercial phishing simulation and security awareness training platform",
    category: "phishing", licenseModel: "byol",
    pipelineStages: ["social_engineering"],
    authMethod: "api_key", envVarKeys: [],
    dataTypes: ["campaigns", "training_results", "phish_prone_percentage", "risk_scores"],
    inputTypes: ["email"], outputTypes: ["domain"],
    enhancesModules: ["phishing_simulation", "security_awareness"],
    docsUrl: "https://developer.knowbe4.com/", tags: ["phishing", "training", "commercial"], supportsPassiveOnly: false, requiresActiveProbing: false, isBuiltIn: true,
  },
  {
    id: "proofpoint_sat", name: "proofpoint_sat", displayName: "Proofpoint Security Awareness",
    description: "Targeted attack simulation and security awareness training",
    category: "phishing", licenseModel: "byol",
    pipelineStages: ["social_engineering"],
    authMethod: "api_key", envVarKeys: [],
    dataTypes: ["simulations", "training_completion", "risk_scores"],
    inputTypes: ["email"], outputTypes: ["domain"],
    enhancesModules: ["phishing_simulation", "security_awareness"], tags: ["phishing", "training", "commercial"], supportsPassiveOnly: false, requiresActiveProbing: false, isBuiltIn: true,
  },
  {
    id: "cofense", name: "cofense", displayName: "Cofense PhishMe",
    description: "Phishing simulation, reporting, and threat intelligence",
    category: "phishing", licenseModel: "byol",
    pipelineStages: ["social_engineering"],
    authMethod: "api_key", envVarKeys: [],
    dataTypes: ["simulations", "reports", "threat_intel"],
    inputTypes: ["email"], outputTypes: ["domain"],
    enhancesModules: ["phishing_simulation"], tags: ["phishing", "reporting", "commercial"], supportsPassiveOnly: false, requiresActiveProbing: false, isBuiltIn: true,
  },
];

// ═══════════════════════════════════════════════════════════════════════
// §9 — SIEM / SOAR
// ═══════════════════════════════════════════════════════════════════════

const SIEM_CONNECTORS: CatalogEntry[] = [
  {
    id: "wazuh", name: "wazuh", displayName: "Wazuh",
    description: "Open-source SIEM — host-based intrusion detection, log analysis, and compliance monitoring",
    category: "siem_soar", licenseModel: "free",
    pipelineStages: ["monitoring"],
    authMethod: "basic_auth", envVarKeys: [],
    dataTypes: ["alerts", "events", "compliance_reports"],
    inputTypes: [], outputTypes: [],
    enhancesModules: ["evasion_scorecard", "detection_correlation"], tags: ["siem", "hids", "free"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true,
  },
  {
    id: "elastic_siem", name: "elastic_siem", displayName: "Elastic SIEM",
    description: "Elastic Security — detection rules, alerts, and endpoint telemetry",
    category: "siem_soar", licenseModel: "freemium",
    pipelineStages: ["monitoring"],
    authMethod: "api_key", envVarKeys: [],
    dataTypes: ["alerts", "detections", "endpoint_telemetry"],
    inputTypes: [], outputTypes: [],
    enhancesModules: ["evasion_scorecard", "detection_correlation"], tags: ["siem", "elastic", "detection"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true,
  },
];

// ═══════════════════════════════════════════════════════════════════════
// §10 — COMPLETE CATALOG
// ═══════════════════════════════════════════════════════════════════════

const BUG_BOUNTY_CONNECTORS: CatalogEntry[] = [
  {
    id: "hackerone", name: "hackerone", displayName: "HackerOne",
    description: "Bug bounty platform — program listing, scope data, disclosed reports, payout tracking, and response SLA metrics",
    category: "osint", licenseModel: "api_key",
    pipelineStages: ["recon", "passive_discovery", "reporting"],
    authMethod: "basic_auth",
    envVarKeys: ["HACKERONE_API_USERNAME", "HACKERONE_API_KEY"],
    dataTypes: ["programs", "scopes", "disclosed_reports", "bounties", "response_metrics"],
    inputTypes: ["program_handle"],
    outputTypes: ["bug_bounty_program", "disclosed_vulnerability", "scope_asset"],
    enhancesModules: ["bug-bounty-workspace", "submission-prep", "hypothesis-generator"],
    docsUrl: "https://api.hackerone.com/",
    icon: "hackerone",
    tags: ["bug_bounty", "vulnerability_disclosure", "crowdsourced_security"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    rateLimit: 600,
    isBuiltIn: true,
  },
  {
    id: "bugcrowd", name: "bugcrowd", displayName: "Bugcrowd",
    description: "Bug bounty platform — program discovery, target scope, submission tracking, reward ranges, and researcher metrics",
    category: "osint", licenseModel: "api_key",
    pipelineStages: ["recon", "passive_discovery", "reporting"],
    authMethod: "bearer_token",
    envVarKeys: ["BUGCROWD_API_TOKEN"],
    dataTypes: ["programs", "targets", "submissions", "rewards", "taxonomy"],
    inputTypes: ["program_code"],
    outputTypes: ["bug_bounty_program", "disclosed_vulnerability", "scope_asset"],
    enhancesModules: ["bug-bounty-workspace", "submission-prep", "duplicate-detector"],
    docsUrl: "https://docs.bugcrowd.com/api/",
    icon: "bugcrowd",
    tags: ["bug_bounty", "vulnerability_disclosure", "crowdsourced_security"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    rateLimit: 300,
    isBuiltIn: true,
  },
];

export const BUILTIN_CATALOG: CatalogEntry[] = [
  ...OSINT_CONNECTORS,
  ...THREAT_INTEL_CONNECTORS,
  ...CREDENTIAL_CONNECTORS,
  ...SCANNER_CONNECTORS,
  ...PENTEST_CONNECTORS,
  ...C2_CONNECTORS,
  ...PHISHING_CONNECTORS,
  ...SIEM_CONNECTORS,
  ...BUG_BOUNTY_CONNECTORS,
];

/** Quick lookup by ID */
export const CATALOG_BY_ID = new Map<string, CatalogEntry>(
  BUILTIN_CATALOG.map(entry => [entry.id, entry])
);

/** Get all integrations for a specific category */
export function getCatalogByCategory(category: IntegrationCategory): CatalogEntry[] {
  return BUILTIN_CATALOG.filter(e => e.category === category);
}

/** Get all integrations for a specific pipeline stage */
export function getCatalogByStage(stage: PipelineStage): CatalogEntry[] {
  return BUILTIN_CATALOG.filter(e => e.pipelineStages.includes(stage));
}

/** Get all integrations that require API keys */
export function getPaidIntegrations(): CatalogEntry[] {
  return BUILTIN_CATALOG.filter(e => e.licenseModel === "api_key" || e.licenseModel === "byol");
}

/** Get all free integrations */
export function getFreeIntegrations(): CatalogEntry[] {
  return BUILTIN_CATALOG.filter(e => e.licenseModel === "free" || e.licenseModel === "freemium");
}

/** Get pipeline coverage summary */
export function getPipelineCoverage(): Record<PipelineStage, { count: number; integrations: string[] }> {
  const stages: PipelineStage[] = ["recon", "passive_discovery", "enumeration", "vuln_detection", "social_engineering", "exploitation", "post_exploit", "reporting", "monitoring", "enrichment"];
  const coverage: Record<string, { count: number; integrations: string[] }> = {};
  for (const stage of stages) {
    const matches = BUILTIN_CATALOG.filter(e => e.pipelineStages.includes(stage));
    coverage[stage] = { count: matches.length, integrations: matches.map(e => e.id) };
  }
  return coverage as Record<PipelineStage, { count: number; integrations: string[] }>;
}
