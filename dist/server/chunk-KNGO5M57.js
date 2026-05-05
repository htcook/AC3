import {
  init_llm,
  invokeLLM
} from "./chunk-BRIFEITD.js";

// server/lib/integration-registry/auto-discovery-engine.ts
init_llm();

// server/lib/integration-registry/builtin-catalog.ts
var OSINT_CONNECTORS = [
  {
    id: "shodan",
    name: "shodan",
    displayName: "Shodan",
    description: "Internet-wide device search \u2014 open ports, services, banners, CVEs, and geolocation for any IP",
    category: "osint",
    licenseModel: "api_key",
    pipelineStages: ["recon", "passive_discovery", "enumeration", "enrichment"],
    authMethod: "api_key",
    envVarKeys: ["SHODAN_API_KEY"],
    dataTypes: ["open_ports", "services", "banners", "cves", "geolocation", "ssl_certs"],
    inputTypes: ["domain", "ip", "cidr"],
    outputTypes: ["ip", "subdomain", "infrastructure"],
    enhancesModules: ["passive_recon", "service_fingerprinting", "vuln_detection"],
    docsUrl: "https://developer.shodan.io/api",
    tags: ["network", "iot", "infrastructure"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    rateLimit: 1,
    isBuiltIn: true
  },
  {
    id: "censys",
    name: "censys",
    displayName: "Censys",
    description: "Internet-wide host and certificate search \u2014 TLS certs, open ports, services, and protocols",
    category: "osint",
    licenseModel: "api_key",
    pipelineStages: ["recon", "passive_discovery", "enrichment"],
    authMethod: "api_key_secret",
    envVarKeys: ["CENSYS_API_ID", "CENSYS_API_SECRET"],
    dataTypes: ["certificates", "open_ports", "services", "protocols"],
    inputTypes: ["domain", "ip"],
    outputTypes: ["ip", "certificate", "subdomain"],
    enhancesModules: ["passive_recon", "certificate_analysis"],
    docsUrl: "https://search.censys.io/api",
    tags: ["certificates", "infrastructure"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    rateLimit: 5,
    isBuiltIn: true
  },
  {
    id: "securitytrails",
    name: "securitytrails",
    displayName: "SecurityTrails",
    description: "Historical DNS, WHOIS, and subdomain data \u2014 tracks domain changes over time",
    category: "osint",
    licenseModel: "api_key",
    pipelineStages: ["recon", "passive_discovery"],
    authMethod: "api_key",
    envVarKeys: ["SECURITYTRAILS_API_KEY"],
    dataTypes: ["subdomains", "dns_history", "whois_history", "associated_domains"],
    inputTypes: ["domain"],
    outputTypes: ["subdomain", "domain"],
    enhancesModules: ["passive_recon", "domain_intelligence"],
    docsUrl: "https://securitytrails.com/corp/api",
    tags: ["dns", "history", "subdomains"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    rateLimit: 50,
    isBuiltIn: true
  },
  {
    id: "urlscan",
    name: "urlscan",
    displayName: "URLScan.io",
    description: "URL scanning service \u2014 screenshots, DOM analysis, network requests, and threat detection",
    category: "osint",
    licenseModel: "freemium",
    pipelineStages: ["recon", "passive_discovery"],
    authMethod: "api_key",
    envVarKeys: ["URLSCAN_API_KEY"],
    dataTypes: ["screenshots", "dom_analysis", "network_requests", "technologies"],
    inputTypes: ["url", "domain"],
    outputTypes: ["url", "subdomain"],
    enhancesModules: ["passive_recon", "tech_detection"],
    docsUrl: "https://urlscan.io/docs/api/",
    tags: ["web", "screenshots", "analysis"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    rateLimit: 60,
    isBuiltIn: true
  },
  {
    id: "virustotal",
    name: "virustotal",
    displayName: "VirusTotal",
    description: "Multi-engine malware and URL reputation \u2014 file/URL/domain/IP analysis across 70+ AV engines",
    category: "osint",
    licenseModel: "freemium",
    pipelineStages: ["recon", "enrichment"],
    authMethod: "api_key",
    envVarKeys: ["VIRUSTOTAL_API_KEY"],
    dataTypes: ["malware_analysis", "url_reputation", "domain_reputation", "ip_reputation"],
    inputTypes: ["domain", "ip", "url", "file_hash"],
    outputTypes: ["subdomain", "ip"],
    enhancesModules: ["passive_recon", "threat_intel"],
    docsUrl: "https://docs.virustotal.com/reference/overview",
    tags: ["malware", "reputation", "av"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    rateLimit: 4,
    isBuiltIn: true
  },
  {
    id: "crtsh",
    name: "crtsh",
    displayName: "crt.sh",
    description: "Certificate Transparency log search \u2014 discover subdomains via SSL/TLS certificate issuance",
    category: "osint",
    licenseModel: "free",
    pipelineStages: ["recon", "passive_discovery"],
    authMethod: "none",
    envVarKeys: [],
    dataTypes: ["certificates", "subdomains"],
    inputTypes: ["domain"],
    outputTypes: ["subdomain", "certificate"],
    enhancesModules: ["passive_recon", "subdomain_enumeration"],
    docsUrl: "https://crt.sh/",
    tags: ["certificates", "subdomains", "free"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    isBuiltIn: true
  },
  {
    id: "wayback",
    name: "wayback",
    displayName: "Wayback Machine",
    description: "Historical web archive \u2014 discover old URLs, endpoints, and content changes over time",
    category: "osint",
    licenseModel: "free",
    pipelineStages: ["recon", "passive_discovery"],
    authMethod: "none",
    envVarKeys: [],
    dataTypes: ["historical_urls", "archived_pages"],
    inputTypes: ["domain", "url"],
    outputTypes: ["url"],
    enhancesModules: ["passive_recon", "endpoint_discovery"],
    docsUrl: "https://web.archive.org/",
    tags: ["history", "urls", "free"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    isBuiltIn: true
  },
  {
    id: "greynoise",
    name: "greynoise",
    displayName: "GreyNoise",
    description: "Internet noise intelligence \u2014 identifies mass scanners, botnets, and benign crawlers hitting your IPs",
    category: "osint",
    licenseModel: "freemium",
    pipelineStages: ["recon", "enrichment"],
    authMethod: "api_key",
    envVarKeys: ["GREYNOISE_API_KEY"],
    dataTypes: ["ip_context", "noise_classification", "riot_data"],
    inputTypes: ["ip"],
    outputTypes: ["ip"],
    enhancesModules: ["passive_recon", "threat_context"],
    docsUrl: "https://docs.greynoise.io/",
    tags: ["noise", "scanners", "context"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    rateLimit: 60,
    isBuiltIn: true
  },
  {
    id: "abuseipdb",
    name: "abuseipdb",
    displayName: "AbuseIPDB",
    description: "IP abuse reputation database \u2014 reports of malicious activity, spam, and attacks from specific IPs",
    category: "osint",
    licenseModel: "freemium",
    pipelineStages: ["recon", "enrichment"],
    authMethod: "api_key",
    envVarKeys: ["ABUSEIPDB_API_KEY"],
    dataTypes: ["ip_reputation", "abuse_reports", "abuse_score"],
    inputTypes: ["ip"],
    outputTypes: ["ip"],
    enhancesModules: ["passive_recon", "threat_scoring"],
    docsUrl: "https://www.abuseipdb.com/api.html",
    tags: ["abuse", "reputation", "ip"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    rateLimit: 60,
    isBuiltIn: true
  },
  {
    id: "shodan_internetdb",
    name: "shodan_internetdb",
    displayName: "Shodan InternetDB",
    description: "Free Shodan fast-path \u2014 instant port/CVE/tag data for any IP without API key",
    category: "osint",
    licenseModel: "free",
    pipelineStages: ["recon", "passive_discovery"],
    authMethod: "none",
    envVarKeys: [],
    dataTypes: ["open_ports", "cves", "tags", "hostnames"],
    inputTypes: ["ip"],
    outputTypes: ["ip"],
    enhancesModules: ["passive_recon", "quick_assessment"],
    docsUrl: "https://internetdb.shodan.io/",
    tags: ["ports", "cves", "free", "fast"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    isBuiltIn: true
  },
  // Additional OSINT connectors (abbreviated for space — full list in registry)
  { id: "whoisxml", name: "whoisxml", displayName: "WhoisXML", description: "WHOIS, DNS, subdomain enumeration", category: "osint", licenseModel: "api_key", pipelineStages: ["recon", "passive_discovery"], authMethod: "api_key", envVarKeys: ["WHOISXML_API_KEY"], dataTypes: ["whois", "dns", "subdomains"], inputTypes: ["domain"], outputTypes: ["subdomain", "domain"], enhancesModules: ["passive_recon"], tags: ["whois", "dns"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true },
  { id: "fullhunt", name: "fullhunt", displayName: "FullHunt", description: "Attack surface discovery and monitoring", category: "osint", licenseModel: "api_key", pipelineStages: ["recon", "passive_discovery"], authMethod: "api_key", envVarKeys: ["FULLHUNT_API_KEY"], dataTypes: ["subdomains", "ports", "technologies"], inputTypes: ["domain"], outputTypes: ["subdomain", "ip"], enhancesModules: ["passive_recon"], tags: ["attack_surface"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true },
  { id: "netlas", name: "netlas", displayName: "Netlas.io", description: "Internet-wide host scanning and DNS history", category: "osint", licenseModel: "api_key", pipelineStages: ["recon", "passive_discovery"], authMethod: "api_key", envVarKeys: ["NETLAS_API_KEY"], dataTypes: ["hosts", "dns_history", "whois"], inputTypes: ["domain", "ip"], outputTypes: ["ip", "subdomain"], enhancesModules: ["passive_recon"], tags: ["hosts", "dns"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true },
  { id: "hunter", name: "hunter", displayName: "Hunter.io", description: "Email discovery and organizational intelligence", category: "osint", licenseModel: "api_key", pipelineStages: ["recon"], authMethod: "api_key", envVarKeys: ["HUNTER_API_KEY"], dataTypes: ["emails", "org_info"], inputTypes: ["domain"], outputTypes: ["domain"], enhancesModules: ["passive_recon", "social_engineering"], tags: ["email", "org"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true },
  { id: "passivetotal", name: "passivetotal", displayName: "PassiveTotal", description: "Passive DNS, SSL history, host attributes", category: "osint", licenseModel: "api_key", pipelineStages: ["recon", "passive_discovery"], authMethod: "api_key", envVarKeys: ["PASSIVETOTAL_API_KEY"], dataTypes: ["passive_dns", "ssl_history", "host_attributes"], inputTypes: ["domain", "ip"], outputTypes: ["subdomain", "ip", "certificate"], enhancesModules: ["passive_recon"], tags: ["passive_dns", "ssl"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true },
  { id: "builtwith", name: "builtwith", displayName: "BuiltWith", description: "Technology stack detection", category: "osint", licenseModel: "free", pipelineStages: ["recon"], authMethod: "none", envVarKeys: [], dataTypes: ["technologies", "frameworks", "analytics"], inputTypes: ["domain"], outputTypes: ["domain"], enhancesModules: ["passive_recon", "tech_detection"], tags: ["tech_stack", "free"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true },
  { id: "commoncrawl", name: "commoncrawl", displayName: "CommonCrawl", description: "Historical web crawl data for company context", category: "osint", licenseModel: "free", pipelineStages: ["recon"], authMethod: "none", envVarKeys: [], dataTypes: ["historical_pages", "urls"], inputTypes: ["domain"], outputTypes: ["url"], enhancesModules: ["passive_recon"], tags: ["history", "free"], supportsPassiveOnly: true, requiresActiveProbing: false, isBuiltIn: true }
];
var THREAT_INTEL_CONNECTORS = [
  {
    id: "alienvault_otx",
    name: "alienvault_otx",
    displayName: "AlienVault OTX",
    description: "Open Threat Exchange \u2014 community threat intel, pulses, IOCs, passive DNS, and malware data",
    category: "threat_intel",
    licenseModel: "free",
    pipelineStages: ["recon", "enrichment"],
    authMethod: "api_key",
    envVarKeys: [],
    dataTypes: ["iocs", "pulses", "passive_dns", "malware_samples"],
    inputTypes: ["domain", "ip", "file_hash"],
    outputTypes: ["ip", "domain"],
    enhancesModules: ["threat_intel", "passive_recon"],
    docsUrl: "https://otx.alienvault.com/api",
    tags: ["iocs", "community", "free"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    isBuiltIn: true
  },
  {
    id: "threatfox",
    name: "threatfox",
    displayName: "ThreatFox (abuse.ch)",
    description: "Free IOC database \u2014 malware, botnet, and C2 indicators from abuse.ch",
    category: "threat_intel",
    licenseModel: "free",
    pipelineStages: ["enrichment"],
    authMethod: "none",
    envVarKeys: [],
    dataTypes: ["iocs", "malware_indicators", "c2_indicators"],
    inputTypes: ["domain", "ip", "file_hash"],
    outputTypes: ["ip", "domain"],
    enhancesModules: ["threat_intel"],
    tags: ["iocs", "malware", "free"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    isBuiltIn: true
  },
  {
    id: "ransomware_live",
    name: "ransomware_live",
    displayName: "Ransomware.live",
    description: "Real-time ransomware victim tracking and group intelligence",
    category: "threat_intel",
    licenseModel: "free",
    pipelineStages: ["enrichment"],
    authMethod: "none",
    envVarKeys: [],
    dataTypes: ["ransomware_groups", "victims", "leak_sites"],
    inputTypes: ["domain"],
    outputTypes: ["domain"],
    enhancesModules: ["threat_intel", "risk_scoring"],
    tags: ["ransomware", "free"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    isBuiltIn: true
  },
  {
    id: "threatminer",
    name: "threatminer",
    displayName: "ThreatMiner",
    description: "Free threat intel \u2014 passive DNS, malware samples, APT reports",
    category: "threat_intel",
    licenseModel: "free",
    pipelineStages: ["recon", "enrichment"],
    authMethod: "none",
    envVarKeys: [],
    dataTypes: ["passive_dns", "malware", "apt_reports"],
    inputTypes: ["domain", "ip"],
    outputTypes: ["ip", "domain"],
    enhancesModules: ["threat_intel", "passive_recon"],
    tags: ["apt", "malware", "free"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    isBuiltIn: true
  },
  {
    id: "phishtank",
    name: "phishtank",
    displayName: "PhishTank",
    description: "Community-verified phishing URL database",
    category: "threat_intel",
    licenseModel: "free",
    pipelineStages: ["enrichment"],
    authMethod: "none",
    envVarKeys: [],
    dataTypes: ["phishing_urls", "phishing_targets"],
    inputTypes: ["url", "domain"],
    outputTypes: ["url"],
    enhancesModules: ["threat_intel", "phishing_detection"],
    tags: ["phishing", "free"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    isBuiltIn: true
  },
  {
    id: "google_safebrowsing",
    name: "google_safebrowsing",
    displayName: "Google Safe Browsing",
    description: "Malware, phishing, and unwanted software detection via Google's threat lists",
    category: "threat_intel",
    licenseModel: "free",
    pipelineStages: ["enrichment"],
    authMethod: "none",
    envVarKeys: [],
    dataTypes: ["malware_detection", "phishing_detection", "unwanted_software"],
    inputTypes: ["url", "domain"],
    outputTypes: ["url"],
    enhancesModules: ["threat_intel"],
    tags: ["malware", "phishing", "free"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    isBuiltIn: true
  }
];
var CREDENTIAL_CONNECTORS = [
  {
    id: "dehashed",
    name: "dehashed",
    displayName: "DeHashed",
    description: "Breach database search \u2014 leaked credentials, emails, passwords, and personal data",
    category: "credential",
    licenseModel: "api_key",
    pipelineStages: ["recon", "enrichment"],
    authMethod: "api_key",
    envVarKeys: ["DEHASHED_API_KEY"],
    dataTypes: ["breached_credentials", "emails", "passwords", "personal_data"],
    inputTypes: ["domain", "email"],
    outputTypes: ["credential", "breach"],
    enhancesModules: ["passive_recon", "credential_testing"],
    docsUrl: "https://www.dehashed.com/docs",
    tags: ["breach", "credentials"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    isBuiltIn: true
  },
  {
    id: "hibp",
    name: "hibp",
    displayName: "Have I Been Pwned",
    description: "Breach exposure monitoring \u2014 check if emails/domains appear in known data breaches",
    category: "credential",
    licenseModel: "api_key",
    pipelineStages: ["recon", "enrichment"],
    authMethod: "api_key",
    envVarKeys: ["HIBP_API_KEY"],
    dataTypes: ["breach_exposure", "paste_exposure"],
    inputTypes: ["email", "domain"],
    outputTypes: ["breach"],
    enhancesModules: ["passive_recon", "breach_monitoring"],
    docsUrl: "https://haveibeenpwned.com/API/v3",
    tags: ["breach", "monitoring"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    rateLimit: 10,
    isBuiltIn: true
  },
  {
    id: "leakcheck",
    name: "leakcheck",
    displayName: "LeakCheck",
    description: "Credential leak search \u2014 check emails and domains against leaked databases",
    category: "credential",
    licenseModel: "api_key",
    pipelineStages: ["recon"],
    authMethod: "api_key",
    envVarKeys: ["LEAKCHECK_API_KEY"],
    dataTypes: ["leaked_credentials"],
    inputTypes: ["email", "domain"],
    outputTypes: ["credential"],
    enhancesModules: ["passive_recon", "credential_testing"],
    tags: ["leak", "credentials"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    isBuiltIn: true
  },
  {
    id: "hudson_rock",
    name: "hudson_rock",
    displayName: "Hudson Rock",
    description: "Stealer log exposure \u2014 check if employees/domains appear in infostealer malware logs",
    category: "credential",
    licenseModel: "api_key",
    pipelineStages: ["recon", "enrichment"],
    authMethod: "api_key",
    envVarKeys: ["HUDSON_ROCK_API_KEY"],
    dataTypes: ["stealer_logs", "compromised_credentials"],
    inputTypes: ["domain", "email"],
    outputTypes: ["credential"],
    enhancesModules: ["passive_recon", "threat_intel"],
    tags: ["stealer", "infostealer"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    isBuiltIn: true
  }
];
var SCANNER_CONNECTORS = [
  {
    id: "zap",
    name: "zap",
    displayName: "OWASP ZAP",
    description: "Open-source DAST scanner \u2014 spider, active scan, AJAX crawl, fuzzing, OAST blind detection",
    category: "scanner",
    licenseModel: "free",
    pipelineStages: ["vuln_detection"],
    authMethod: "api_key",
    envVarKeys: ["ZAP_API_KEY", "ZAP_BASE_URL"],
    dataTypes: ["web_vulnerabilities", "xss", "sqli", "ssrf", "csrf", "misconfigurations"],
    inputTypes: ["url"],
    outputTypes: ["subdomain"],
    enhancesModules: ["vuln_scanning", "web_app_testing"],
    docsUrl: "https://www.zaproxy.org/docs/api/",
    tags: ["dast", "web", "owasp"],
    supportsPassiveOnly: false,
    requiresActiveProbing: true,
    isBuiltIn: true
  },
  {
    id: "burp_suite",
    name: "burp_suite",
    displayName: "Burp Suite Professional",
    description: "Commercial DAST scanner \u2014 advanced crawling, audit, Collaborator OAST, Intruder, and extensions",
    category: "scanner",
    licenseModel: "byol",
    pipelineStages: ["vuln_detection"],
    authMethod: "api_key",
    envVarKeys: ["BURP_LICENSE_EMAIL", "BURP_LICENSE_PASSWORD"],
    dataTypes: ["web_vulnerabilities", "xss", "sqli", "ssrf", "deserialization", "auth_bypass"],
    inputTypes: ["url"],
    outputTypes: ["subdomain"],
    enhancesModules: ["vuln_scanning", "web_app_testing"],
    docsUrl: "https://portswigger.net/burp/documentation/enterprise/api",
    tags: ["dast", "web", "commercial"],
    supportsPassiveOnly: false,
    requiresActiveProbing: true,
    isBuiltIn: true
  },
  {
    id: "nuclei",
    name: "nuclei",
    displayName: "Nuclei",
    description: "Template-based vulnerability scanner \u2014 8000+ templates for CVEs, misconfigs, and exposures",
    category: "scanner",
    licenseModel: "free",
    pipelineStages: ["vuln_detection", "exploitation"],
    authMethod: "none",
    envVarKeys: [],
    dataTypes: ["cve_detection", "misconfigurations", "exposures", "default_credentials"],
    inputTypes: ["url", "ip"],
    outputTypes: ["subdomain", "ip"],
    enhancesModules: ["vuln_scanning", "exploit_verification"],
    docsUrl: "https://docs.projectdiscovery.io/tools/nuclei/",
    tags: ["templates", "cve", "free"],
    supportsPassiveOnly: false,
    requiresActiveProbing: true,
    isBuiltIn: true
  },
  {
    id: "nikto",
    name: "nikto",
    displayName: "Nikto",
    description: "Web server scanner \u2014 outdated software, dangerous files, misconfigurations",
    category: "scanner",
    licenseModel: "free",
    pipelineStages: ["vuln_detection"],
    authMethod: "none",
    envVarKeys: [],
    dataTypes: ["server_misconfigurations", "outdated_software", "dangerous_files"],
    inputTypes: ["url"],
    outputTypes: ["subdomain"],
    enhancesModules: ["vuln_scanning"],
    tags: ["web_server", "free"],
    supportsPassiveOnly: false,
    requiresActiveProbing: true,
    isBuiltIn: true
  }
];
var PENTEST_CONNECTORS = [
  {
    id: "metasploit",
    name: "metasploit",
    displayName: "Metasploit Framework",
    description: "Exploitation framework \u2014 2000+ modules for remote exploits, local exploits, and post-exploitation",
    category: "pentest_tool",
    licenseModel: "free",
    pipelineStages: ["exploitation", "post_exploit"],
    authMethod: "basic_auth",
    envVarKeys: ["MSF_RPC_HOST", "MSF_RPC_PORT", "MSF_RPC_USER", "MSF_RPC_PASS"],
    dataTypes: ["exploit_results", "sessions", "post_exploit_data"],
    inputTypes: ["ip", "url"],
    outputTypes: ["ip"],
    enhancesModules: ["exploit_execution", "post_exploitation"],
    docsUrl: "https://docs.metasploit.com/",
    tags: ["exploit", "framework"],
    supportsPassiveOnly: false,
    requiresActiveProbing: true,
    isBuiltIn: true
  },
  {
    id: "cobalt_strike",
    name: "cobalt_strike",
    displayName: "Cobalt Strike",
    description: "Commercial adversary simulation \u2014 Beacon C2, malleable C2 profiles, lateral movement, and persistence",
    category: "pentest_tool",
    licenseModel: "byol",
    pipelineStages: ["exploitation", "post_exploit"],
    authMethod: "custom_header",
    envVarKeys: ["CS_TEAM_SERVER_URL", "CS_API_KEY", "CS_USERNAME", "CS_PASSWORD"],
    dataTypes: ["beacon_sessions", "lateral_movement", "persistence", "credential_harvesting"],
    inputTypes: ["ip"],
    outputTypes: ["ip"],
    enhancesModules: ["c2_operations", "adversary_emulation"],
    docsUrl: "https://www.cobaltstrike.com/",
    tags: ["c2", "adversary_sim", "commercial"],
    supportsPassiveOnly: false,
    requiresActiveProbing: true,
    isBuiltIn: true
  }
];
var C2_CONNECTORS = [
  {
    id: "caldera",
    name: "caldera",
    displayName: "MITRE Caldera",
    description: "Automated adversary emulation \u2014 MITRE ATT&CK-aligned operations with abilities and planners",
    category: "c2",
    licenseModel: "free",
    pipelineStages: ["exploitation", "post_exploit"],
    authMethod: "api_key",
    envVarKeys: ["CALDERA_BASE_URL", "CALDERA_API_KEY"],
    dataTypes: ["operations", "abilities", "agents", "adversary_profiles"],
    inputTypes: ["ip"],
    outputTypes: ["ip"],
    enhancesModules: ["adversary_emulation", "attack_simulation"],
    docsUrl: "https://caldera.readthedocs.io/",
    tags: ["mitre", "emulation", "free"],
    supportsPassiveOnly: false,
    requiresActiveProbing: true,
    isBuiltIn: true
  },
  {
    id: "empire",
    name: "empire",
    displayName: "Empire (BC Security)",
    description: "Post-exploitation C2 \u2014 PowerShell/Python agents, modules, and stagers",
    category: "c2",
    licenseModel: "free",
    pipelineStages: ["post_exploit"],
    authMethod: "api_key",
    envVarKeys: ["EMPIRE_BASE_URL", "EMPIRE_API_KEY"],
    dataTypes: ["agents", "modules", "stagers"],
    inputTypes: ["ip"],
    outputTypes: ["ip"],
    enhancesModules: ["post_exploitation", "c2_operations"],
    tags: ["c2", "post_exploit", "free"],
    supportsPassiveOnly: false,
    requiresActiveProbing: true,
    isBuiltIn: true
  },
  {
    id: "sliver",
    name: "sliver",
    displayName: "Sliver C2",
    description: "Open-source C2 \u2014 implants, pivots, and operator collaboration via gRPC",
    category: "c2",
    licenseModel: "free",
    pipelineStages: ["post_exploit"],
    authMethod: "bearer_token",
    envVarKeys: ["SLIVER_SERVER_URL", "SLIVER_OPERATOR_TOKEN"],
    dataTypes: ["implants", "sessions", "pivots"],
    inputTypes: ["ip"],
    outputTypes: ["ip"],
    enhancesModules: ["c2_operations"],
    tags: ["c2", "implants", "free"],
    supportsPassiveOnly: false,
    requiresActiveProbing: true,
    isBuiltIn: true
  }
];
var PHISHING_CONNECTORS = [
  {
    id: "gophish",
    name: "gophish",
    displayName: "GoPhish",
    description: "Open-source phishing simulation \u2014 campaign management, landing pages, and result tracking",
    category: "phishing",
    licenseModel: "free",
    pipelineStages: ["social_engineering"],
    authMethod: "api_key",
    envVarKeys: ["GOPHISH_BASE_URL", "GOPHISH_API_KEY"],
    dataTypes: ["campaigns", "results", "click_rates", "credential_captures"],
    inputTypes: ["email"],
    outputTypes: ["domain"],
    enhancesModules: ["phishing_simulation", "social_engineering"],
    docsUrl: "https://docs.getgophish.com/",
    tags: ["phishing", "simulation", "free"],
    supportsPassiveOnly: false,
    requiresActiveProbing: true,
    isBuiltIn: true
  },
  {
    id: "knowbe4",
    name: "knowbe4",
    displayName: "KnowBe4",
    description: "Commercial phishing simulation and security awareness training platform",
    category: "phishing",
    licenseModel: "byol",
    pipelineStages: ["social_engineering"],
    authMethod: "api_key",
    envVarKeys: [],
    dataTypes: ["campaigns", "training_results", "phish_prone_percentage", "risk_scores"],
    inputTypes: ["email"],
    outputTypes: ["domain"],
    enhancesModules: ["phishing_simulation", "security_awareness"],
    docsUrl: "https://developer.knowbe4.com/",
    tags: ["phishing", "training", "commercial"],
    supportsPassiveOnly: false,
    requiresActiveProbing: false,
    isBuiltIn: true
  },
  {
    id: "proofpoint_sat",
    name: "proofpoint_sat",
    displayName: "Proofpoint Security Awareness",
    description: "Targeted attack simulation and security awareness training",
    category: "phishing",
    licenseModel: "byol",
    pipelineStages: ["social_engineering"],
    authMethod: "api_key",
    envVarKeys: [],
    dataTypes: ["simulations", "training_completion", "risk_scores"],
    inputTypes: ["email"],
    outputTypes: ["domain"],
    enhancesModules: ["phishing_simulation", "security_awareness"],
    tags: ["phishing", "training", "commercial"],
    supportsPassiveOnly: false,
    requiresActiveProbing: false,
    isBuiltIn: true
  },
  {
    id: "cofense",
    name: "cofense",
    displayName: "Cofense PhishMe",
    description: "Phishing simulation, reporting, and threat intelligence",
    category: "phishing",
    licenseModel: "byol",
    pipelineStages: ["social_engineering"],
    authMethod: "api_key",
    envVarKeys: [],
    dataTypes: ["simulations", "reports", "threat_intel"],
    inputTypes: ["email"],
    outputTypes: ["domain"],
    enhancesModules: ["phishing_simulation"],
    tags: ["phishing", "reporting", "commercial"],
    supportsPassiveOnly: false,
    requiresActiveProbing: false,
    isBuiltIn: true
  }
];
var SIEM_CONNECTORS = [
  {
    id: "wazuh",
    name: "wazuh",
    displayName: "Wazuh",
    description: "Open-source SIEM \u2014 host-based intrusion detection, log analysis, and compliance monitoring",
    category: "siem_soar",
    licenseModel: "free",
    pipelineStages: ["monitoring"],
    authMethod: "basic_auth",
    envVarKeys: [],
    dataTypes: ["alerts", "events", "compliance_reports"],
    inputTypes: [],
    outputTypes: [],
    enhancesModules: ["evasion_scorecard", "detection_correlation"],
    tags: ["siem", "hids", "free"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    isBuiltIn: true
  },
  {
    id: "elastic_siem",
    name: "elastic_siem",
    displayName: "Elastic SIEM",
    description: "Elastic Security \u2014 detection rules, alerts, and endpoint telemetry",
    category: "siem_soar",
    licenseModel: "freemium",
    pipelineStages: ["monitoring"],
    authMethod: "api_key",
    envVarKeys: [],
    dataTypes: ["alerts", "detections", "endpoint_telemetry"],
    inputTypes: [],
    outputTypes: [],
    enhancesModules: ["evasion_scorecard", "detection_correlation"],
    tags: ["siem", "elastic", "detection"],
    supportsPassiveOnly: true,
    requiresActiveProbing: false,
    isBuiltIn: true
  }
];
var BUG_BOUNTY_CONNECTORS = [
  {
    id: "hackerone",
    name: "hackerone",
    displayName: "HackerOne",
    description: "Bug bounty platform \u2014 program listing, scope data, disclosed reports, payout tracking, and response SLA metrics",
    category: "osint",
    licenseModel: "api_key",
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
    isBuiltIn: true
  },
  {
    id: "bugcrowd",
    name: "bugcrowd",
    displayName: "Bugcrowd",
    description: "Bug bounty platform \u2014 program discovery, target scope, submission tracking, reward ranges, and researcher metrics",
    category: "osint",
    licenseModel: "api_key",
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
    isBuiltIn: true
  }
];
var BUILTIN_CATALOG = [
  ...OSINT_CONNECTORS,
  ...THREAT_INTEL_CONNECTORS,
  ...CREDENTIAL_CONNECTORS,
  ...SCANNER_CONNECTORS,
  ...PENTEST_CONNECTORS,
  ...C2_CONNECTORS,
  ...PHISHING_CONNECTORS,
  ...SIEM_CONNECTORS,
  ...BUG_BOUNTY_CONNECTORS
];
var CATALOG_BY_ID = new Map(
  BUILTIN_CATALOG.map((entry) => [entry.id, entry])
);

// server/lib/integration-registry/auto-discovery-engine.ts
async function probeApi(input) {
  const result = {
    reachable: false,
    hasOpenApiSpec: false,
    interestingHeaders: {}
  };
  const headers = {
    "Accept": "application/json, text/html, */*",
    "User-Agent": "AC3-Integration-Probe/1.0"
  };
  if (input.apiKey) {
    const headerName = input.apiKeyHeader || "X-API-Key";
    headers[headerName] = input.apiKey;
    if (!input.apiKeyHeader) {
      headers["Authorization"] = `Bearer ${input.apiKey}`;
    }
  }
  const timeout = 1e4;
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeout);
    try {
      const resp = await fetch(input.baseUrl, {
        headers,
        signal: controller.signal,
        redirect: "follow"
      });
      clearTimeout(timer);
      result.reachable = true;
      result.statusCode = resp.status;
      result.contentType = resp.headers.get("content-type") ?? void 0;
      const interestingHeaderNames = [
        "server",
        "x-powered-by",
        "x-api-version",
        "x-ratelimit-limit",
        "x-ratelimit-remaining",
        "x-ratelimit-reset",
        "ratelimit-limit",
        "ratelimit-remaining",
        "ratelimit-reset",
        "x-request-id",
        "access-control-allow-origin",
        "www-authenticate"
      ];
      for (const name of interestingHeaderNames) {
        const val = resp.headers.get(name);
        if (val) result.interestingHeaders[name] = val;
      }
      const rlLimit = resp.headers.get("x-ratelimit-limit") || resp.headers.get("ratelimit-limit");
      const rlRemaining = resp.headers.get("x-ratelimit-remaining") || resp.headers.get("ratelimit-remaining");
      const rlReset = resp.headers.get("x-ratelimit-reset") || resp.headers.get("ratelimit-reset");
      if (rlLimit || rlRemaining) {
        result.rateLimitHeaders = { limit: rlLimit ?? void 0, remaining: rlRemaining ?? void 0, reset: rlReset ?? void 0 };
      }
      if (resp.status === 401 || resp.status === 403) {
        const wwwAuth = resp.headers.get("www-authenticate");
        if (wwwAuth?.toLowerCase().includes("bearer")) result.detectedAuthMethod = "bearer_token";
        else if (wwwAuth?.toLowerCase().includes("basic")) result.detectedAuthMethod = "basic_auth";
        else result.detectedAuthMethod = "api_key";
      }
      try {
        const body = await resp.text();
        result.sampleResponse = body.slice(0, 2e3);
      } catch {
      }
    } catch (err) {
      clearTimeout(timer);
      if (err.name === "AbortError") {
        result.error = "Timeout: API did not respond within 10 seconds";
      } else {
        result.error = `Connection error: ${err.message}`;
      }
    }
    const specPaths = [
      "/openapi.json",
      "/swagger.json",
      "/api-docs",
      "/v1/openapi.json",
      "/v2/swagger.json",
      "/docs",
      "/api/docs",
      "/.well-known/openapi.json"
    ];
    for (const path of specPaths) {
      try {
        const specUrl = new URL(path, input.baseUrl).toString();
        const ctrl = new AbortController();
        const t = setTimeout(() => ctrl.abort(), 5e3);
        const specResp = await fetch(specUrl, { headers: { Accept: "application/json" }, signal: ctrl.signal });
        clearTimeout(t);
        if (specResp.ok) {
          const specBody = await specResp.text();
          if (specBody.includes('"openapi"') || specBody.includes('"swagger"') || specBody.includes('"paths"')) {
            result.hasOpenApiSpec = true;
            result.openApiSpecUrl = specUrl;
            result.openApiSpecPreview = specBody.slice(0, 4e3);
            break;
          }
        }
      } catch {
      }
    }
  } catch (err) {
    result.error = `Probe failed: ${err.message}`;
  }
  return result;
}
var CLASSIFICATION_SYSTEM_PROMPT = `You are the AC3 Integration Classification Engine. Your job is to analyze a new API that a customer wants to add to their cybersecurity platform and determine:

1. **Category** \u2014 What kind of tool/service is this?
   Categories: osint, exploit_db, threat_intel, scanner, pentest_tool, phishing, c2, siem_soar, cloud, credential, custom

2. **Pipeline Stages** \u2014 Which engagement pipeline stages should this feed into?
   Stages: recon, passive_discovery, enumeration, vuln_detection, social_engineering, exploitation, post_exploit, reporting, monitoring, enrichment

3. **Data Types** \u2014 What kind of data does this API provide?
   Examples: subdomains, ip_addresses, certificates, vulnerabilities, credentials, iocs, malware_samples, etc.

4. **Input Types** \u2014 What does this API accept as input?
   Examples: domain, ip, url, cidr, email, file_hash, etc.

5. **Output Types** \u2014 What AC3 asset types does this produce?
   Examples: subdomain, ip, certificate, url, credential, breach, infrastructure, domain

6. **Value Assessment** \u2014 How valuable is this compared to existing sources?

EXISTING INTEGRATIONS (for overlap analysis):
{existingIntegrations}

IMPORTANT RULES:
- Be specific about pipeline stages \u2014 don't just say "all stages"
- Consider whether this is passive-only or requires active probing
- Identify overlaps with existing integrations honestly
- If you're not confident, say so \u2014 the customer will review and correct
- Never classify something as "custom" if it fits a known category
- Consider the cybersecurity context: OSINT tools gather intel, scanners find vulns, exploit tools attack, etc.

Respond in JSON format matching the AutoDiscoveryResult schema.`;
async function classifyApi(input, probeResult) {
  const existingSummary = BUILTIN_CATALOG.map((e) => `- ${e.displayName} (${e.category}): ${e.description} [stages: ${e.pipelineStages.join(", ")}]`).join("\n");
  const userPrompt = `Classify this new API integration:

**Base URL:** ${input.baseUrl}
**Customer Name:** ${input.customerName || "Not provided"}
**Customer Description:** ${input.customerDescription || "Not provided"}
**Documentation URL:** ${input.docsUrl || "Not provided"}

**Probe Results:**
- Reachable: ${probeResult.reachable}
- Status Code: ${probeResult.statusCode ?? "N/A"}
- Content Type: ${probeResult.contentType ?? "N/A"}
- Has OpenAPI Spec: ${probeResult.hasOpenApiSpec}
- Detected Auth Method: ${probeResult.detectedAuthMethod ?? "unknown"}
- Rate Limit: ${probeResult.rateLimitHeaders ? JSON.stringify(probeResult.rateLimitHeaders) : "Not detected"}
- Response Headers: ${JSON.stringify(probeResult.interestingHeaders)}
${probeResult.openApiSpecPreview ? `
**OpenAPI Spec Preview (first 4000 chars):**
\`\`\`json
${probeResult.openApiSpecPreview}
\`\`\`` : ""}
${probeResult.sampleResponse ? `
**Sample Response (first 2000 chars):**
\`\`\`
${probeResult.sampleResponse}
\`\`\`` : ""}

Analyze this API and provide your classification as JSON.`;
  try {
    const response = await invokeLLM({
      messages: [
        {
          role: "system",
          content: CLASSIFICATION_SYSTEM_PROMPT.replace("{existingIntegrations}", existingSummary)
        },
        { role: "user", content: userPrompt }
      ],
      response_format: {
        type: "json_schema",
        json_schema: {
          name: "api_classification",
          strict: true,
          schema: {
            type: "object",
            properties: {
              category: { type: "string", description: "Integration category", enum: ["osint", "exploit_db", "threat_intel", "scanner", "pentest_tool", "phishing", "c2", "siem_soar", "cloud", "credential", "custom"] },
              confidence: { type: "number", description: "Classification confidence 0-100" },
              pipelineStages: { type: "array", items: { type: "string" }, description: "Pipeline stages this feeds into" },
              dataTypes: { type: "array", items: { type: "string" }, description: "Data types provided" },
              inputTypes: { type: "array", items: { type: "string" }, description: "Input types accepted" },
              outputTypes: { type: "array", items: { type: "string" }, description: "AC3 asset types produced" },
              description: { type: "string", description: "What this API does" },
              reasoning: { type: "string", description: "Why this classification was chosen" },
              suggestedName: { type: "string", description: "Suggested integration ID (snake_case)" },
              suggestedDisplayName: { type: "string", description: "Suggested display name" },
              supportsPassiveOnly: { type: "boolean", description: "Whether this is passive-only" },
              requiresActiveProbing: { type: "boolean", description: "Whether this requires active probing" },
              overlapAnalysis: {
                type: "array",
                items: {
                  type: "object",
                  properties: {
                    existingId: { type: "string" },
                    existingName: { type: "string" },
                    overlapPercent: { type: "number" }
                  },
                  required: ["existingId", "existingName", "overlapPercent"],
                  additionalProperties: false
                },
                description: "Overlap with existing integrations"
              },
              valueScore: { type: "number", description: "Overall value score 0-100" },
              uniqueDataScore: { type: "number", description: "Unique data score 0-100" },
              reliabilityScore: { type: "number", description: "Reliability score 0-100" },
              valueSummary: { type: "string", description: "Value assessment summary" },
              valueAdds: { type: "array", items: { type: "string" }, description: "Specific value-adds" },
              concerns: { type: "array", items: { type: "string" }, description: "Potential concerns" }
            },
            required: [
              "category",
              "confidence",
              "pipelineStages",
              "dataTypes",
              "inputTypes",
              "outputTypes",
              "description",
              "reasoning",
              "suggestedName",
              "suggestedDisplayName",
              "supportsPassiveOnly",
              "requiresActiveProbing",
              "overlapAnalysis",
              "valueScore",
              "uniqueDataScore",
              "reliabilityScore",
              "valueSummary",
              "valueAdds",
              "concerns"
            ],
            additionalProperties: false
          }
        }
      }
    });
    const content = response.choices?.[0]?.message?.content;
    if (!content) throw new Error("Empty LLM response");
    const parsed = JSON.parse(content);
    const result = {
      category: parsed.category,
      confidence: parsed.confidence,
      pipelineStages: parsed.pipelineStages,
      dataTypes: parsed.dataTypes,
      inputTypes: parsed.inputTypes,
      outputTypes: parsed.outputTypes,
      description: parsed.description,
      reasoning: parsed.reasoning,
      suggestedName: parsed.suggestedName,
      suggestedDisplayName: parsed.suggestedDisplayName,
      hasOpenApiSpec: probeResult.hasOpenApiSpec,
      detectedAuthMethod: probeResult.detectedAuthMethod ?? "api_key",
      detectedRateLimit: probeResult.rateLimitHeaders?.limit ? parseInt(probeResult.rateLimitHeaders.limit) : void 0,
      similarExisting: (parsed.overlapAnalysis || []).map((o) => ({
        id: o.existingId,
        name: o.existingName,
        overlapPercent: o.overlapPercent
      })),
      valueAssessment: {
        overallScore: parsed.valueScore,
        uniqueDataScore: parsed.uniqueDataScore,
        reliabilityScore: parsed.reliabilityScore,
        freshnessScore: 50,
        // Default — can't assess freshness from a single probe
        overlapSources: (parsed.overlapAnalysis || []).filter((o) => o.overlapPercent > 30).map((o) => o.existingId),
        overlapPercent: Math.max(0, ...(parsed.overlapAnalysis || []).map((o) => o.overlapPercent)),
        summary: parsed.valueSummary,
        valueAdds: parsed.valueAdds,
        concerns: parsed.concerns,
        assessedBy: "llm",
        assessedAt: Date.now()
      },
      rawLlmResponse: content
    };
    return result;
  } catch (err) {
    return {
      category: "custom",
      confidence: 10,
      pipelineStages: ["enrichment"],
      dataTypes: ["unknown"],
      inputTypes: ["unknown"],
      outputTypes: [],
      description: input.customerDescription || `API at ${input.baseUrl}`,
      reasoning: `LLM classification failed: ${err.message}. Defaulting to 'custom' category. Customer should manually classify this integration.`,
      suggestedName: input.customerName?.toLowerCase().replace(/\s+/g, "_") || "custom_api",
      suggestedDisplayName: input.customerName || "Custom API",
      hasOpenApiSpec: probeResult.hasOpenApiSpec,
      detectedAuthMethod: probeResult.detectedAuthMethod ?? "api_key",
      similarExisting: [],
      valueAssessment: {
        overallScore: 0,
        uniqueDataScore: 0,
        reliabilityScore: 0,
        freshnessScore: 0,
        overlapSources: [],
        overlapPercent: 0,
        summary: "Classification failed \u2014 manual review required",
        valueAdds: [],
        concerns: ["LLM classification failed \u2014 customer must manually verify"],
        assessedBy: "llm",
        assessedAt: Date.now()
      },
      rawLlmResponse: void 0
    };
  }
}
var feedbackStore = [];
function recordClassificationFeedback(feedback) {
  feedbackStore.push(feedback);
}
function getClassificationFeedback() {
  return [...feedbackStore];
}
function buildFeedbackContext() {
  if (feedbackStore.length === 0) return "";
  const examples = feedbackStore.slice(-20).map((f) => {
    const stageChange = JSON.stringify(f.originalStages) !== JSON.stringify(f.correctedStages);
    return `- API with characteristics ${JSON.stringify(f.apiCharacteristics)}: LLM said "${f.originalCategory}" \u2192 Customer corrected to "${f.correctedCategory}"` + (stageChange ? ` (stages: ${f.originalStages.join(",")} \u2192 ${f.correctedStages.join(",")})` : "");
  });
  return `

PAST CORRECTIONS (learn from these):
${examples.join("\n")}`;
}
async function runDiscoveryPipeline(input) {
  const issues = [];
  const nextSteps = [];
  const probe = await probeApi(input);
  if (!probe.reachable) {
    issues.push(`API at ${input.baseUrl} is not reachable: ${probe.error}`);
    nextSteps.push("Verify the API URL is correct and accessible from the AC3 platform");
    nextSteps.push("Check if the API requires VPN or IP whitelisting");
  }
  if (probe.statusCode === 401 || probe.statusCode === 403) {
    issues.push("API returned authentication error \u2014 API key may be required or invalid");
    nextSteps.push("Provide a valid API key for this integration");
  }
  const classification = await classifyApi(input, probe);
  if (classification.confidence < 50) {
    issues.push(`Low classification confidence (${classification.confidence}%) \u2014 please review carefully`);
    nextSteps.push("Review the proposed category and pipeline stages and correct if needed");
  }
  if (classification.valueAssessment.overlapPercent > 70) {
    issues.push(`High overlap (${classification.valueAssessment.overlapPercent}%) with existing integrations: ${classification.similarExisting.map((s) => s.name).join(", ")}`);
    nextSteps.push("Consider whether this source provides unique data not available from existing integrations");
  }
  if (issues.length === 0) {
    nextSteps.push("Review the proposed classification and approve to wire into your pipeline");
  }
  if (!input.apiKey && classification.detectedAuthMethod !== "none") {
    nextSteps.push("Provide API credentials to enable this integration");
  }
  if (classification.hasOpenApiSpec) {
    nextSteps.push("OpenAPI spec detected \u2014 the platform can auto-generate a connector adapter");
  }
  return {
    probe,
    classification,
    readyForReview: probe.reachable || !!input.customerDescription,
    issues,
    nextSteps
  };
}

export {
  BUILTIN_CATALOG,
  CATALOG_BY_ID,
  probeApi,
  classifyApi,
  recordClassificationFeedback,
  getClassificationFeedback,
  buildFeedbackContext,
  runDiscoveryPipeline
};
