/**
 * Platform Feature Map — Comprehensive guide to every module in the AC3 platform.
 *
 * The AI chat bot injects the relevant section based on the user's current page,
 * so it can answer "what does this page do?" and guide users through features.
 */

export interface PageFeatureInfo {
  path: string;
  name: string;
  group: string;
  purpose: string;
  features: string[];
  commonTasks: string[];
  tips?: string[];
}

const FEATURE_MAP: PageFeatureInfo[] = [
  // ─── Command & Control ───
  { path: "/dashboard", name: "Dashboard", group: "Command & Control", purpose: "Central command overview showing real-time platform metrics, active engagements, agent status, and security posture.", features: ["KPI cards (engagements, agents, findings, risk)", "Recent activity feed", "Quick-launch actions", "System health indicators"], commonTasks: ["Check platform status", "See active engagement progress", "Launch new engagement", "Review recent findings"] },
  { path: "/home", name: "Home / Overview", group: "Command & Control", purpose: "Landing page with platform overview, quick navigation to key modules, and getting-started guidance.", features: ["Module quick-links", "Platform stats summary", "Recent activity"], commonTasks: ["Navigate to modules", "See platform overview"] },
  { path: "/engagements", name: "Engagements", group: "Command & Control", purpose: "Manage all penetration testing engagements — create, configure, track, and close security assessments.", features: ["Engagement list with filters", "Create new engagement wizard", "ROE configuration", "Phase tracking", "Engagement cloning"], commonTasks: ["Create new pentest engagement", "Check engagement status", "Update ROE scope", "Assign team members"] },
  { path: "/engagement-ops", name: "Engagement Ops", group: "Command & Control", purpose: "Operational command center for active engagements — real-time monitoring of automated pentest phases, asset discovery, vulnerability detection, and exploitation.", features: ["Phase progress tracking", "Live asset discovery feed", "Automated scan orchestration", "Finding correlation", "ZAP/Nuclei scan status", "Credential testing", "LLM-driven attack decisions"], commonTasks: ["Monitor engagement progress", "Review discovered assets", "Check vuln scan results", "Review exploitation attempts"] },
  { path: "/engagement-pipeline", name: "Engagement Pipeline", group: "Command & Control", purpose: "Kanban-style pipeline view of all engagements across lifecycle stages.", features: ["Drag-and-drop pipeline board", "Stage-based filtering", "Engagement cards with metrics"], commonTasks: ["Move engagements between stages", "Get pipeline overview"] },
  { path: "/engagement-automation", name: "Engagement Automation", group: "Command & Control", purpose: "Configure automated engagement workflows and scan orchestration rules.", features: ["Automation rule builder", "Trigger configuration", "Phase automation settings"], commonTasks: ["Set up auto-scan rules", "Configure phase transitions"] },
  { path: "/kill-chain", name: "Kill Chain Visualizer", group: "Command & Control", purpose: "Visual kill chain mapping showing attack progression across MITRE ATT&CK stages.", features: ["Kill chain visualization", "Technique mapping", "Attack progression timeline"], commonTasks: ["Map attack paths to kill chain", "Identify coverage gaps"] },
  { path: "/engagement-timeline", name: "Engagement Timeline", group: "Command & Control", purpose: "Chronological timeline view of all engagement activities and milestones.", features: ["Timeline visualization", "Event filtering", "Milestone tracking"], commonTasks: ["Review engagement history", "Track milestone completion"] },
  { path: "/credentials", name: "Credentials", group: "Command & Control", purpose: "Manage discovered and harvested credentials from engagements.", features: ["Credential vault", "Password analysis", "Credential reuse detection"], commonTasks: ["Review harvested credentials", "Check for credential reuse"] },
  { path: "/oem-credentials", name: "OEM Credentials", group: "Command & Control", purpose: "Database of default/OEM credentials for common devices, services, and applications.", features: ["Searchable credential database", "Vendor/product filtering", "Protocol-based lookup"], commonTasks: ["Look up default credentials", "Search by vendor/product"] },
  { path: "/adversaries", name: "Adversaries", group: "Command & Control", purpose: "Define and manage adversary profiles with associated TTPs for emulation.", features: ["Adversary profile editor", "TTP assignment", "Ability linking"], commonTasks: ["Create adversary profiles", "Assign TTPs to adversaries"] },
  { path: "/agents", name: "Agents", group: "Command & Control", purpose: "Monitor and manage deployed C2 agents across target environments.", features: ["Agent status dashboard", "Command execution", "Beacon management", "Agent grouping"], commonTasks: ["Check agent status", "Execute commands on agents", "Deploy new agents"] },
  { path: "/agent-manager", name: "Agent Manager", group: "Command & Control", purpose: "Advanced agent lifecycle management including deployment, configuration, and retirement.", features: ["Agent deployment wizard", "Configuration management", "Health monitoring"], commonTasks: ["Deploy agents", "Configure agent settings", "Retire old agents"] },
  { path: "/activity", name: "Activity Log", group: "Command & Control", purpose: "Chronological log of all platform activities and user actions.", features: ["Activity feed", "User action tracking", "Filterable log"], commonTasks: ["Review recent activity", "Audit user actions"] },
  { path: "/audit-log", name: "Audit Log", group: "Command & Control", purpose: "Comprehensive audit trail for compliance and accountability.", features: ["Detailed audit records", "User/action filtering", "Export capability"], commonTasks: ["Review audit trail", "Export audit records for compliance"] },
];

// ─── Campaign Operations ───
const CAMPAIGN_OPS: PageFeatureInfo[] = [
  { path: "/phishing-ops", name: "Phishing Ops", group: "Campaign Operations", purpose: "Plan and execute phishing campaigns with email templates, target lists, and tracking.", features: ["Campaign builder", "Email template editor", "Target list management", "Click/open tracking", "Credential capture"], commonTasks: ["Create phishing campaign", "Design email templates", "Import target lists", "Review campaign results"] },
  { path: "/gophish", name: "GoPhish", group: "Campaign Operations", purpose: "GoPhish integration for managing phishing infrastructure and campaigns.", features: ["GoPhish server management", "Campaign orchestration", "Landing page hosting", "Result analytics"], commonTasks: ["Configure GoPhish server", "Launch campaigns", "Review phishing results"] },
  { path: "/campaign-wizard", name: "Campaign Wizard", group: "Campaign Operations", purpose: "Step-by-step wizard for creating targeted phishing campaigns.", features: ["Guided campaign creation", "Template selection", "Target configuration", "Schedule setup"], commonTasks: ["Create new campaign step-by-step"] },
  { path: "/campaigns", name: "Campaigns", group: "Campaign Operations", purpose: "Overview of all phishing and social engineering campaigns.", features: ["Campaign list", "Status tracking", "Performance metrics", "Campaign comparison"], commonTasks: ["Review all campaigns", "Compare campaign performance"] },
  { path: "/campaign-archetypes", name: "Campaign Archetypes", group: "Campaign Operations", purpose: "Pre-built campaign templates based on common social engineering scenarios.", features: ["Template library", "Scenario-based templates", "Customization options"], commonTasks: ["Browse campaign templates", "Clone and customize archetypes"] },
  { path: "/landing-page-builder", name: "Landing Page Builder", group: "Campaign Operations", purpose: "Visual editor for creating phishing landing pages.", features: ["Drag-and-drop page builder", "Template library", "Credential capture forms", "Page preview"], commonTasks: ["Design landing pages", "Configure credential capture"] },
  { path: "/template-generator", name: "Template Generator", group: "Campaign Operations", purpose: "AI-powered email template generation for phishing campaigns.", features: ["AI template generation", "Industry-specific templates", "Personalization tokens"], commonTasks: ["Generate email templates", "Customize templates"] },
  { path: "/email-security", name: "Email Security", group: "Campaign Operations", purpose: "Analyze email security controls (SPF, DKIM, DMARC) for target domains.", features: ["SPF/DKIM/DMARC analysis", "Email header analysis", "Deliverability testing"], commonTasks: ["Check domain email security", "Analyze email headers"] },
];

// ─── Exploit & Emulation ───
const EXPLOIT_EMULATION: PageFeatureInfo[] = [
  { path: "/exploit-arsenal", name: "Exploit Arsenal", group: "Exploit & Emulation", purpose: "Curated library of exploits organized by target, severity, and technique.", features: ["Exploit database", "Search/filter by CVE, platform, technique", "Exploit details and usage"], commonTasks: ["Search for exploits", "Review exploit details"] },
  { path: "/msf-servers", name: "MSF Servers", group: "Exploit & Emulation", purpose: "Manage Metasploit Framework server instances for exploitation.", features: ["MSF server management", "Module browser", "Listener configuration"], commonTasks: ["Start/stop MSF servers", "Configure listeners"] },
  { path: "/msf-sessions", name: "MSF Sessions", group: "Exploit & Emulation", purpose: "Monitor and interact with active Metasploit sessions.", features: ["Session list", "Session interaction", "Post-exploitation modules"], commonTasks: ["Manage active sessions", "Run post-exploitation"] },
  { path: "/sliver-c2", name: "Sliver C2", group: "Exploit & Emulation", purpose: "Sliver C2 framework integration for implant management.", features: ["Implant management", "Listener config", "Beacon/session control"], commonTasks: ["Deploy Sliver implants", "Manage beacons"] },
  { path: "/c2-command-center", name: "C2 Command Center", group: "Exploit & Emulation", purpose: "Unified command center for all C2 frameworks (Cyber C2, MSF, Sliver).", features: ["Multi-framework view", "Unified command interface", "Cross-framework session management"], commonTasks: ["Manage all C2 sessions", "Execute cross-framework commands"] },
  { path: "/abilities-library", name: "Abilities Library", group: "Exploit & Emulation", purpose: "Library of emulation abilities (atomic actions) mapped to MITRE ATT&CK.", features: ["Ability browser", "ATT&CK mapping", "Custom ability creation"], commonTasks: ["Browse abilities", "Create custom abilities"] },
  { path: "/atomic-red-team", name: "Atomic Red Team", group: "Exploit & Emulation", purpose: "Atomic Red Team test library for validating detection capabilities.", features: ["Atomic test browser", "Test execution", "Result tracking"], commonTasks: ["Run atomic tests", "Validate detections"] },
  { path: "/payload-generator", name: "Payload Generator", group: "Exploit & Emulation", purpose: "Generate custom payloads for various platforms and protocols.", features: ["Multi-platform payload generation", "Encoding options", "Evasion techniques"], commonTasks: ["Generate reverse shells", "Create encoded payloads"] },
  { path: "/evasion-engine", name: "Evasion Engine", group: "Exploit & Emulation", purpose: "Test and develop defense evasion techniques against security controls.", features: ["Evasion technique library", "EDR bypass testing", "Payload obfuscation"], commonTasks: ["Test evasion techniques", "Obfuscate payloads"] },
  { path: "/privilege-escalation", name: "Privilege Escalation", group: "Exploit & Emulation", purpose: "Privilege escalation technique library and automated checks.", features: ["Privesc technique database", "Automated enumeration", "Platform-specific checks"], commonTasks: ["Find privesc vectors", "Run automated checks"] },
  { path: "/lateral-movement", name: "Lateral Movement", group: "Exploit & Emulation", purpose: "Lateral movement techniques and network pivoting tools.", features: ["Movement technique library", "Pivot configuration", "Network mapping"], commonTasks: ["Plan lateral movement", "Configure pivots"] },
];

// ─── Intelligence & Recon ───
const INTEL_RECON: PageFeatureInfo[] = [
  { path: "/domain-intel", name: "Domain Intel", group: "Intelligence & Recon", purpose: "Launch comprehensive domain intelligence scans combining DNS, WHOIS, subdomain discovery, port scanning, and vulnerability assessment.", features: ["Multi-phase domain scanning", "Subdomain enumeration", "Port scanning", "Technology detection", "Certificate analysis", "WHOIS lookup"], commonTasks: ["Start a domain scan", "Review scan results", "Compare scan history"], tips: ["Use batch scanner for multiple domains", "Schedule recurring scans for continuous monitoring"] },
  { path: "/domain-intel/", name: "Domain Intel Results", group: "Intelligence & Recon", purpose: "Detailed scan results dashboard showing discovered assets, risk heatmap, vulnerability findings, technologies, and executive summary.", features: ["Executive summary", "Asset risk heatmap", "Vulnerability findings", "Technology stack detection", "WAF/NGFW detection", "SCAP compliance", "Container exposure analysis", "Scan delta comparison"], commonTasks: ["Review asset risk scores", "Analyze vulnerability findings", "Export scan report", "Compare with previous scans"] },
  { path: "/osint-monitor", name: "OSINT Monitor", group: "Intelligence & Recon", purpose: "Open-source intelligence monitoring and collection dashboard.", features: ["OSINT data feeds", "Target monitoring", "Data correlation"], commonTasks: ["Monitor targets", "Collect OSINT data"] },
  { path: "/threat-actors", name: "Threat Actors", group: "Intelligence & Recon", purpose: "Threat actor database with profiles, TTPs, and campaign history.", features: ["Actor profiles", "TTP mapping", "Campaign tracking", "IOC association"], commonTasks: ["Research threat actors", "Map actor TTPs"] },
  { path: "/threat-intel-hub", name: "Threat Intel Hub", group: "Intelligence & Recon", purpose: "Centralized threat intelligence aggregation from multiple sources.", features: ["Multi-source intel feeds", "IOC aggregation", "Threat scoring", "Intel sharing"], commonTasks: ["Review threat feeds", "Correlate indicators"] },
  { path: "/darkweb-intel", name: "Darkweb Intel", group: "Intelligence & Recon", purpose: "Dark web monitoring for leaked credentials, data breaches, and threat actor activity.", features: ["Darkweb monitoring", "Credential leak detection", "Forum monitoring"], commonTasks: ["Check for credential leaks", "Monitor dark web activity"] },
  { path: "/breach-events", name: "Breach Events", group: "Intelligence & Recon", purpose: "Track and analyze data breach events affecting target organizations.", features: ["Breach database", "Impact analysis", "Timeline tracking"], commonTasks: ["Research breach history", "Assess breach impact"] },
  { path: "/ioc-feed", name: "IOC Feed", group: "Intelligence & Recon", purpose: "Indicator of Compromise feed management and enrichment.", features: ["IOC ingestion", "Enrichment pipeline", "Feed management", "Export to SIEM"], commonTasks: ["Import IOCs", "Enrich indicators", "Export to SIEM"] },
  { path: "/kev-catalog", name: "KEV Catalog", group: "Intelligence & Recon", purpose: "CISA Known Exploited Vulnerabilities catalog with prioritization.", features: ["KEV database", "Exploitation status", "Remediation deadlines"], commonTasks: ["Check KEV status for CVEs", "Prioritize patching"] },
  { path: "/credential-alerts", name: "Credential Alerts", group: "Intelligence & Recon", purpose: "Monitor for compromised credentials across breach databases and dark web sources.", features: ["Credential monitoring", "Breach correlation", "Alert notifications"], commonTasks: ["Check for compromised credentials", "Set up monitoring alerts"] },
];

// ─── Scanning & Assessment ───
const SCANNING: PageFeatureInfo[] = [
  { path: "/web-app-scanner", name: "Web App Scanner", group: "Scanning & Assessment", purpose: "Automated web application vulnerability scanning with ZAP integration.", features: ["Automated web scanning", "OWASP Top 10 detection", "Authenticated scanning", "API scanning"], commonTasks: ["Scan web applications", "Review vulnerabilities", "Configure authenticated scans"] },
  { path: "/nuclei-scanner", name: "Nuclei Scanner", group: "Scanning & Assessment", purpose: "Template-based vulnerability scanning using Nuclei engine.", features: ["Template library", "Custom template support", "Bulk scanning", "Result correlation"], commonTasks: ["Run Nuclei scans", "Browse templates", "Review findings"] },
  { path: "/vuln-scanner", name: "Vuln Scanner", group: "Scanning & Assessment", purpose: "General-purpose vulnerability scanner for network and application targets.", features: ["Network scanning", "Service detection", "Vulnerability assessment", "Report generation"], commonTasks: ["Scan targets", "Review vulnerabilities", "Generate reports"] },
  { path: "/api-security-testing", name: "API Security Testing", group: "Scanning & Assessment", purpose: "Specialized API security testing with fuzzing and authentication bypass detection.", features: ["API endpoint discovery", "Fuzzing engine", "Auth bypass testing", "Schema validation"], commonTasks: ["Test API security", "Fuzz API endpoints", "Check auth controls"] },
  { path: "/auth-assessment", name: "Auth Assessment", group: "Scanning & Assessment", purpose: "Authentication mechanism assessment including SSO, MFA, and session management.", features: ["Auth flow analysis", "SSO testing", "MFA bypass checks", "Session management audit"], commonTasks: ["Assess authentication", "Test SSO implementation", "Check MFA controls"] },
  { path: "/scan-scheduler", name: "Scan Scheduler", group: "Scanning & Assessment", purpose: "Schedule recurring vulnerability scans and domain intelligence sweeps.", features: ["Cron-based scheduling", "Multi-scan-type support", "Notification on completion"], commonTasks: ["Schedule recurring scans", "Manage scan schedules"] },
  { path: "/scan-compare", name: "Scan Compare", group: "Scanning & Assessment", purpose: "Compare scan results across time periods to track remediation progress.", features: ["Side-by-side comparison", "Delta analysis", "Trend tracking"], commonTasks: ["Compare scan results", "Track remediation progress"] },
  { path: "/scan-server", name: "Scan Server Health", group: "Scanning & Assessment", purpose: "Monitor health and status of scan infrastructure servers.", features: ["Server health monitoring", "Resource usage", "Service status"], commonTasks: ["Check scan server status", "Monitor resource usage"] },
];

// ─── Detection & Validation ───
const DETECTION_VALIDATION: PageFeatureInfo[] = [
  { path: "/detection-coverage", name: "Detection Coverage", group: "Detection & Validation", purpose: "Map detection coverage against MITRE ATT&CK framework to identify gaps.", features: ["ATT&CK coverage matrix", "Detection gap analysis", "Rule mapping"], commonTasks: ["Review detection coverage", "Identify gaps", "Map rules to techniques"] },
  { path: "/attack-coverage", name: "Attack Coverage", group: "Detection & Validation", purpose: "Measure attack simulation coverage and detection efficacy.", features: ["Coverage metrics", "Simulation results", "Efficacy scoring"], commonTasks: ["Review attack coverage", "Measure detection rates"] },
  { path: "/validation-engine", name: "Validation Engine", group: "Detection & Validation", purpose: "Automated security control validation through simulated attacks.", features: ["Control validation", "Automated testing", "Result tracking"], commonTasks: ["Validate security controls", "Run validation tests"] },
  { path: "/purple-team", name: "Purple Team", group: "Detection & Validation", purpose: "Collaborative purple team exercises combining red and blue team perspectives.", features: ["Exercise planning", "Attack/detect correlation", "Coverage improvement"], commonTasks: ["Plan purple team exercises", "Correlate attacks with detections"] },
  { path: "/sigma-rules", name: "Sigma Rule Generator", group: "Detection & Validation", purpose: "Generate and manage Sigma detection rules for SIEM platforms.", features: ["Rule generation", "Rule testing", "SIEM export"], commonTasks: ["Generate Sigma rules", "Test detection rules", "Export to SIEM"] },
];

// ─── AD & Cloud ───
const AD_CLOUD: PageFeatureInfo[] = [
  { path: "/ad-domain-connector", name: "AD Domain Connector", group: "AD & Cloud", purpose: "Connect to Active Directory domains for enumeration and attack path analysis.", features: ["Domain connection wizard", "LDAP configuration", "Credential management"], commonTasks: ["Connect to AD domain", "Configure LDAP settings"] },
  { path: "/ad-attack-path-graph", name: "AD Attack Path Graph", group: "AD & Cloud", purpose: "Visual graph of Active Directory attack paths showing privilege escalation routes.", features: ["Interactive graph visualization", "Path analysis", "Risk scoring"], commonTasks: ["Analyze attack paths", "Identify high-risk paths"] },
  { path: "/bloodhound-import", name: "BloodHound Import", group: "AD & Cloud", purpose: "Import BloodHound data for AD attack path analysis.", features: ["Data import", "Graph integration", "Path correlation"], commonTasks: ["Import BloodHound data", "Analyze imported paths"] },
  { path: "/cloud-attack-paths", name: "Cloud Attack Paths", group: "AD & Cloud", purpose: "Discover and analyze attack paths in cloud environments (AWS, Azure, GCP).", features: ["Cloud path discovery", "IAM analysis", "Resource mapping"], commonTasks: ["Analyze cloud attack paths", "Review IAM permissions"] },
];

// ─── Compliance & Reporting ───
const COMPLIANCE_REPORTING: PageFeatureInfo[] = [
  { path: "/reports", name: "Reports", group: "Compliance & Reporting", purpose: "Generate and manage security assessment reports.", features: ["Report generation", "Template selection", "Finding inclusion", "Export formats"], commonTasks: ["Generate reports", "Customize report templates", "Export reports"] },
  { path: "/pentest-report", name: "Pentest Report", group: "Compliance & Reporting", purpose: "Generate comprehensive penetration testing reports with findings and recommendations.", features: ["Auto-generated findings", "Executive summary", "Technical details", "Remediation guidance"], commonTasks: ["Generate pentest report", "Review findings", "Export to PDF"] },
  { path: "/compliance-dashboard", name: "Compliance Dashboard", group: "Compliance & Reporting", purpose: "Track compliance status across multiple frameworks.", features: ["Multi-framework tracking", "Control status", "Gap analysis", "Evidence linking"], commonTasks: ["Check compliance status", "Identify gaps", "Link evidence"] },
  { path: "/evidence", name: "Evidence Collection", group: "Compliance & Reporting", purpose: "Collect and manage evidence artifacts for compliance and reporting.", features: ["Evidence upload", "Chain of custody", "Tagging and categorization"], commonTasks: ["Upload evidence", "Tag evidence to findings"] },
  { path: "/scoring", name: "Scoring Hub", group: "Compliance & Reporting", purpose: "Risk scoring and prioritization across all findings.", features: ["CVSS scoring", "CARVER scoring", "Custom scoring models", "Priority ranking"], commonTasks: ["Score findings", "Prioritize remediation"] },
];

// ─── KSI & FedRAMP ───
const KSI_FEDRAMP: PageFeatureInfo[] = [
  { path: "/ksi-dashboard", name: "KSI Dashboard", group: "KSI & FedRAMP", purpose: "Key Security Indicator dashboard for FedRAMP continuous monitoring.", features: ["KSI metrics", "Compliance status", "Trend analysis", "Alert thresholds"], commonTasks: ["Review KSI metrics", "Check compliance trends"] },
  { path: "/ksi-validation", name: "KSI Validation", group: "KSI & FedRAMP", purpose: "Validate KSI measurements against FedRAMP requirements.", features: ["Validation checks", "Evidence collection", "Gap identification"], commonTasks: ["Run KSI validation", "Collect evidence"] },
  { path: "/ksi-evidence-chain", name: "KSI Evidence Chain", group: "KSI & FedRAMP", purpose: "Track evidence chain for KSI compliance documentation.", features: ["Evidence chain tracking", "Audit trail", "Document linking"], commonTasks: ["Review evidence chain", "Link documentation"] },
];

// ─── SSIL ───
const SSIL: PageFeatureInfo[] = [
  { path: "/ssil", name: "SSIL Overview", group: "SSIL", purpose: "Security Signals Intelligence Layer — real-time security signal monitoring and correlation.", features: ["Signal dashboard", "Risk cards", "Correlation engine", "Policy enforcement"], commonTasks: ["Monitor security signals", "Review risk cards", "Configure policies"] },
  { path: "/ssil/policies", name: "SSIL Policies", group: "SSIL", purpose: "Define and manage security policies for signal evaluation.", features: ["Policy editor", "Rule configuration", "Threshold settings"], commonTasks: ["Create policies", "Configure rules"] },
  { path: "/ssil/guardrails", name: "SSIL Guardrails", group: "SSIL", purpose: "Configure operational guardrails to prevent unsafe actions.", features: ["Guardrail configuration", "Action blocking", "Override management"], commonTasks: ["Set up guardrails", "Review blocked actions"] },
  { path: "/ssil/observations", name: "SSIL Observations", group: "SSIL", purpose: "View and analyze security observations collected by the SSIL engine.", features: ["Observation feed", "Filtering", "Detail analysis"], commonTasks: ["Review observations", "Analyze patterns"] },
];

// ─── Integrations & Infrastructure ───
const INTEGRATIONS: PageFeatureInfo[] = [
  { path: "/soc-integration-hub", name: "SOC Integration Hub", group: "Integrations", purpose: "Central hub for SOC tool integrations (SIEM, SOAR, EDR).", features: ["Integration catalog", "Connector management", "Health monitoring"], commonTasks: ["Configure integrations", "Check connector health"] },
  { path: "/siem-connectors", name: "SIEM Connectors", group: "Integrations", purpose: "Configure SIEM platform connectors for log forwarding and alert ingestion.", features: ["Connector setup", "Log forwarding", "Alert mapping"], commonTasks: ["Set up SIEM connectors", "Configure log forwarding"] },
  { path: "/webhooks", name: "Webhooks", group: "Integrations", purpose: "Configure webhook endpoints for event notifications.", features: ["Webhook management", "Event selection", "Delivery monitoring"], commonTasks: ["Create webhooks", "Monitor delivery"] },
  { path: "/infrastructure", name: "Infrastructure", group: "Integrations", purpose: "Manage platform infrastructure servers and services.", features: ["Server management", "Service monitoring", "Configuration"], commonTasks: ["Manage servers", "Monitor services"] },
  { path: "/ssh-keys", name: "SSH Keys", group: "Integrations", purpose: "Manage SSH keys for scan server and infrastructure access.", features: ["Key management", "Key rotation", "Access control"], commonTasks: ["Add SSH keys", "Rotate keys"] },
];

// ─── Training & Learning ───
const TRAINING: PageFeatureInfo[] = [
  { path: "/training-lab", name: "Training Lab", group: "Training & Learning", purpose: "Hands-on training environment with vulnerable targets for skill development.", features: ["Lab environments", "Guided exercises", "Skill tracking"], commonTasks: ["Launch training labs", "Complete exercises"] },
  { path: "/training-dashboard", name: "Training Dashboard", group: "Training & Learning", purpose: "Track team training progress and skill development metrics.", features: ["Progress tracking", "Skill metrics", "Certification tracking"], commonTasks: ["Review training progress", "Track certifications"] },
  { path: "/knowledge-base", name: "Knowledge Base", group: "Training & Learning", purpose: "Platform knowledge base with guides, tutorials, and reference documentation.", features: ["Searchable docs", "Tutorials", "Best practices", "FAQ"], commonTasks: ["Search for guides", "Read tutorials"] },
  { path: "/guide/caldera", name: "Emulation Guide", group: "Training & Learning", purpose: "Comprehensive guide to using the Cyber C2 emulation framework.", features: ["Setup guide", "Usage tutorials", "Best practices"], commonTasks: ["Learn emulation basics", "Follow setup guide"] },
  { path: "/guide/gophish", name: "GoPhish Guide", group: "Training & Learning", purpose: "Guide to using GoPhish for phishing campaign management.", features: ["GoPhish setup", "Campaign tutorials", "Template creation"], commonTasks: ["Learn GoPhish", "Create first campaign"] },
];

// ─── Admin & System ───
const ADMIN: PageFeatureInfo[] = [
  { path: "/team", name: "Team Management", group: "Admin & System", purpose: "Manage team members, roles, and permissions.", features: ["User management", "Role assignment", "Permission configuration"], commonTasks: ["Add team members", "Assign roles", "Manage permissions"] },
  { path: "/tenants", name: "Tenants", group: "Admin & System", purpose: "Multi-tenant management for MSSP operations.", features: ["Tenant creation", "Tenant isolation", "Resource allocation"], commonTasks: ["Create tenants", "Manage tenant access"] },
  { path: "/account-settings", name: "Account Settings", group: "Admin & System", purpose: "Personal account settings including profile, notifications, and security.", features: ["Profile editing", "Notification preferences", "API key management", "Session management"], commonTasks: ["Update profile", "Manage API keys", "Configure notifications"] },
  { path: "/error-dashboard", name: "Error Dashboard", group: "Admin & System", purpose: "Monitor and manage platform errors and system issues.", features: ["Error log viewer", "Severity filtering", "Resolution tracking", "Error trends"], commonTasks: ["Review errors", "Resolve issues", "Track error trends"] },
  { path: "/llm-telemetry", name: "LLM Telemetry", group: "Admin & System", purpose: "Monitor LLM API usage, performance, and costs.", features: ["Usage metrics", "Performance tracking", "Cost analysis", "Error rates"], commonTasks: ["Monitor LLM usage", "Track costs", "Review errors"] },
  { path: "/workflows", name: "Workflows", group: "Admin & System", purpose: "Configure automated workflows and process automation.", features: ["Workflow builder", "Trigger configuration", "Action chaining"], commonTasks: ["Create workflows", "Configure triggers"] },
  { path: "/roe-builder", name: "ROE Builder", group: "Admin & System", purpose: "Build and manage Rules of Engagement documents for engagements.", features: ["ROE template editor", "Scope definition", "Constraint configuration", "Document export"], commonTasks: ["Create ROE documents", "Define scope boundaries"] },
  { path: "/ai-attack-planner", name: "AI Attack Planner", group: "Admin & System", purpose: "AI-powered attack planning that suggests optimal attack strategies based on target profile.", features: ["AI-driven planning", "Strategy suggestions", "Risk assessment", "Resource estimation"], commonTasks: ["Generate attack plans", "Review AI suggestions"] },
];

// ─── Combine all feature maps ───
const ALL_FEATURES: PageFeatureInfo[] = [
  ...FEATURE_MAP,
  ...CAMPAIGN_OPS,
  ...EXPLOIT_EMULATION,
  ...INTEL_RECON,
  ...SCANNING,
  ...DETECTION_VALIDATION,
  ...AD_CLOUD,
  ...COMPLIANCE_REPORTING,
  ...KSI_FEDRAMP,
  ...SSIL,
  ...INTEGRATIONS,
  ...TRAINING,
  ...ADMIN,
];

/**
 * Find the best matching page feature info for a given route path.
 * Handles exact matches and prefix matches for dynamic routes.
 */
export function getPageFeatureInfo(currentPath: string): PageFeatureInfo | null {
  if (!currentPath) return null;
  // Exact match first
  const exact = ALL_FEATURES.find(p => p.path === currentPath);
  if (exact) return exact;
  // Prefix match (for dynamic routes like /domain-intel/:id)
  const prefix = ALL_FEATURES
    .filter(p => currentPath.startsWith(p.path) && p.path !== "/")
    .sort((a, b) => b.path.length - a.path.length);
  return prefix[0] || null;
}

/**
 * Get the navigation group info for a given route.
 */
export function getGroupForPath(currentPath: string): string {
  const info = getPageFeatureInfo(currentPath);
  return info?.group || "Unknown";
}

/**
 * Build a context string for the AI chat bot about the current page.
 * This is injected into the system prompt so the bot can guide users.
 */
export function buildPageContextForChat(currentPath: string): string {
  const pageInfo = getPageFeatureInfo(currentPath);
  if (!pageInfo) {
    return `The user is on an unrecognized page (${currentPath}). Help them navigate to the right module.`;
  }

  const parts: string[] = [
    `\n--- CURRENT PAGE CONTEXT ---`,
    `Page: ${pageInfo.name} (${pageInfo.path})`,
    `Module Group: ${pageInfo.group}`,
    `Purpose: ${pageInfo.purpose}`,
    `\nKey Features on this page:`,
    ...pageInfo.features.map(f => `  - ${f}`),
    `\nCommon tasks users perform here:`,
    ...pageInfo.commonTasks.map(t => `  - ${t}`),
  ];

  if (pageInfo.tips && pageInfo.tips.length > 0) {
    parts.push(`\nPro tips:`);
    parts.push(...pageInfo.tips.map(t => `  - ${t}`));
  }

  parts.push(`\nWhen the user asks about this page, explain its features and guide them through tasks.`);
  parts.push(`If they seem lost, suggest the common tasks listed above.`);

  return parts.join("\n");
}

/**
 * Build a high-level platform overview for the chat bot.
 * Used when the user asks general questions about the platform.
 */
export function buildPlatformOverview(): string {
  const groups = new Map<string, string[]>();
  for (const page of ALL_FEATURES) {
    if (!groups.has(page.group)) groups.set(page.group, []);
    groups.get(page.group)!.push(page.name);
  }

  const parts: string[] = [
    `\n--- AC3 PLATFORM OVERVIEW ---`,
    `AC3 (Cyber Command & Control) is a comprehensive offensive security platform built by AceofCloud.`,
    `It provides end-to-end capabilities for penetration testing, red teaming, and security validation.`,
    `\nPlatform Modules:`,
  ];

  for (const [group, pages] of Array.from(groups.entries())) {
    parts.push(`  ${group}: ${pages.join(", ")}`);
  }

  parts.push(`\nThe platform supports role-based access: Operator, Executive, Analyst, Team Lead, Client, SOC, and Admin.`);
  parts.push(`Each role sees relevant modules and gets specialized AI assistance.`);

  return parts.join("\n");
}

export { ALL_FEATURES };

