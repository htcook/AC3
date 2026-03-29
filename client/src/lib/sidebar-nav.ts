/**
 * Sidebar Navigation Configuration
 * 
 * Organized into collapsible groups matching the platform's operational domains.
 * Each group contains items with route paths, labels, and Lucide icon names.
 * 
 * Role-Based Access Design:
 * ─────────────────────────
 * admin:     Full access to all groups and items
 * operator:  Full pentest/red team toolkit — offensive ops, scanning, exploitation,
 *            C2/agents, campaigns, intel/recon, AD/cloud, test lab, infrastructure, AI tools
 * team_lead: Everything operator sees + compliance/reporting + KSI/FedRAMP + admin/team mgmt + full LLM/AI
 * analyst:   Intel, detection/validation, compliance, reporting, KSI, SSIL, LLM observability
 * soc:       Detection, SSIL, integrations, intel, compliance reporting, monitoring
 * executive: High-level dashboards, compliance, reporting, KSI
 * client:    Read-only compliance and reporting view
 * viewer:    Dashboard and reporting only
 */
import {
  LayoutDashboard, Activity, Briefcase, Workflow, Key, Target, Cpu, FileText,
  Zap, Globe, Crosshair, Palette, Sparkles, Bug, Server, Layers, Shield,
  Brain, Radio, Radar, Lock, Fingerprint, Scan, Eye, Search, Code2,
  FileCode, Gauge, MonitorPlay, Building2, Stethoscope, GraduationCap,
  Network, Siren, FlaskConical, Camera, FileCheck2, Atom, BookOpen,
  Mail, Cloud, Rocket, ShieldCheck, AlertTriangle, TrendingUp, Unplug,
  Factory, BarChart3, Terminal, MapPin, Phone, Info, Clock, Landmark,
  CalendarClock, Trophy,
  type LucideIcon, ChevronRight, Settings, Users, Database, Wrench,
  ScrollText, GitBranch, Binary, Webhook, Bot, Boxes, CircuitBoard,
  Laptop, Megaphone, PenTool, Skull, Sword, Flame, Telescope,
  Microscope, Newspaper, Link2, Package, Cog, HardDrive, Wifi,
} from "lucide-react";

export type UserRole = 'admin' | 'operator' | 'analyst' | 'team_lead' | 'executive' | 'client' | 'soc' | 'viewer';

export interface NavItem {
  label: string;
  path: string;
  icon: LucideIcon;
  /** Roles that can see this item. If omitted, visible to all roles that can see the parent group. */
  roles?: UserRole[];
}

export interface NavGroup {
  id: string;
  label: string;
  icon: LucideIcon;
  color: string;
  defaultOpen?: boolean;
  /** Roles that can see this entire group. If omitted, visible to all roles. */
  roles?: UserRole[];
  items: NavItem[];
}

/**
 * Role-based navigation access matrix.
 *
 * Each role maps to the group IDs it can access.
 * 'all' means unrestricted access (admin only).
 *
 * Operator gets the FULL pentest/red team toolkit:
 *   command-control, campaign-ops, exploit-emulation, c2-agents, test-lab,
 *   intel-recon, scanning, detection-validation, ad-cloud, infrastructure, llm-ai
 *
 * Team Lead gets everything operator sees PLUS compliance, KSI, admin, and full LLM/AI.
 */
const ROLE_GROUP_ACCESS: Record<UserRole, string[] | 'all'> = {
  admin: 'all',
  operator: [
    'command-control', 'campaign-ops', 'exploit-emulation', 'c2-agents',
    'test-lab', 'intel-recon', 'scanning', 'detection-validation', 'ad-cloud',
    'infrastructure', 'llm-ai',
  ],
  team_lead: [
    'command-control', 'campaign-ops', 'exploit-emulation', 'c2-agents',
    'test-lab', 'intel-recon', 'scanning', 'detection-validation', 'ad-cloud',
    'infrastructure', 'compliance-reporting', 'ksi-fedramp', 'llm-ai', 'admin',
  ],
  analyst: [
    'command-control', 'intel-recon', 'scanning', 'detection-validation',
    'compliance-reporting', 'ksi-fedramp', 'llm-ai',
  ],
  soc: [
    'command-control', 'intel-recon', 'detection-validation', 'infrastructure',
    'llm-ai', 'compliance-reporting',
  ],
  executive: ['command-control', 'compliance-reporting', 'ksi-fedramp'],
  client: ['command-control', 'compliance-reporting'],
  viewer: ['command-control', 'compliance-reporting'],
};

/**
 * Filter sidebar navigation groups and items based on the user's role.
 * Admin sees everything. Other roles see only their assigned groups.
 * Within groups, individual items can further restrict by role.
 */
export function getFilteredNavGroups(role: UserRole | string | undefined): NavGroup[] {
  // Fall back to 'viewer' if role is undefined or not in ROLE_GROUP_ACCESS
  // (e.g., default Manus auth returns 'user' which isn't a valid UserRole)
  const effectiveRole = (role && role in ROLE_GROUP_ACCESS) ? role as UserRole : 'viewer';
  const access = ROLE_GROUP_ACCESS[effectiveRole] ?? ROLE_GROUP_ACCESS['viewer'] ?? [];

  // Safety: if access is somehow not 'all' and not an array, return all groups for admin-like fallback
  if (access !== 'all' && !Array.isArray(access)) {
    console.warn(`[sidebar-nav] Invalid access for role "${role}" (effective: "${effectiveRole}"), falling back to viewer`);
    const viewerAccess = ROLE_GROUP_ACCESS['viewer'] ?? [];
    return sidebarNavGroups
      .filter(group => Array.isArray(viewerAccess) && viewerAccess.includes(group.id))
      .filter(group => group.items.length > 0);
  }

  return sidebarNavGroups
    .filter(group => {
      // Admin sees all
      if (access === 'all') return true;
      // Group-level role restriction
      if (group.roles && Array.isArray(group.roles) && !group.roles.includes(effectiveRole)) return false;
      // Check if this group is in the role's access list
      return Array.isArray(access) && access.includes(group.id);
    })
    .map(group => ({
      ...group,
      items: (group.items || []).filter(item => {
        // If item has role restrictions, check them
        if (item.roles && Array.isArray(item.roles) && !item.roles.includes(effectiveRole)) return false;
        return true;
      }),
    }))
    .filter(group => group.items.length > 0);
}

export const sidebarNavGroups: NavGroup[] = [

  // ═══════════════════════════════════════════════════════════════════════════
  // COMMAND & CONTROL — Core engagement management, dashboards, activity
  // Visible to: ALL roles (filtered by item-level roles)
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: "command-control",
    label: "Command & Control",
    icon: LayoutDashboard,
    color: "text-primary",
    defaultOpen: true,
    items: [
      { label: "Dashboard", path: "/dashboard", icon: LayoutDashboard },
      { label: "Home", path: "/home", icon: Activity },
      { label: "Engagements", path: "/engagements", icon: Briefcase },
      { label: "Engagement Ops", path: "/engagement-ops", icon: Crosshair, roles: ["admin", "operator", "team_lead"] },
      { label: "Engagement Pipeline", path: "/engagement-pipeline", icon: Workflow, roles: ["admin", "operator", "team_lead"] },
      { label: "Engagement Automation", path: "/engagement-automation", icon: Rocket, roles: ["admin", "operator", "team_lead"] },
      { label: "Kill Chain", path: "/kill-chain", icon: Workflow, roles: ["admin", "operator", "team_lead", "analyst"] },
      { label: "Engagement Timeline", path: "/engagement-timeline", icon: Clock },
      { label: "Credentials", path: "/credentials", icon: Key, roles: ["admin", "operator", "team_lead"] },
      { label: "OEM Credentials", path: "/oem-credentials", icon: Key, roles: ["admin", "operator"] },
      { label: "Adversaries", path: "/adversaries", icon: Target, roles: ["admin", "operator", "team_lead", "analyst"] },
      { label: "Activity Log", path: "/activity", icon: FileText },
      { label: "Audit Log", path: "/audit-log", icon: ScrollText, roles: ["admin", "team_lead", "executive"] },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // CAMPAIGN OPERATIONS — Phishing, social engineering, campaign management
  // Visible to: admin, operator, team_lead
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: "campaign-ops",
    label: "Campaign Operations",
    icon: Megaphone,
    color: "text-red-400",
    items: [
      { label: "Campaigns", path: "/campaigns", icon: Briefcase },
      { label: "Campaign Wizard", path: "/campaign-wizard", icon: Crosshair },
      { label: "Campaign Execution", path: "/campaign-execution", icon: Rocket },
      { label: "Campaign Archetypes", path: "/campaign-archetypes", icon: Layers },
      { label: "Campaign Advisor", path: "/campaign-advisor", icon: Brain },
      { label: "Campaign Orchestrator", path: "/campaign-orchestrator", icon: Layers },
      { label: "Phishing Ops", path: "/phishing-ops", icon: Zap },
      { label: "Phishing Impact", path: "/phishing-impact-testing", icon: Mail },
      { label: "GoPhish", path: "/gophish", icon: Globe },
      { label: "Page Builder", path: "/landing-page-builder", icon: Palette },
      { label: "Template Generator", path: "/template-generator", icon: Sparkles },
      { label: "Templates", path: "/templates", icon: FileCode },
      { label: "Email Security", path: "/email-security", icon: Mail },
      { label: "Phishing Exploit Catalog", path: "/phishing-exploit-catalog", icon: Bug },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // EXPLOIT & EMULATION — Offensive tooling, payloads, post-exploitation
  // Visible to: admin, operator, team_lead
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: "exploit-emulation",
    label: "Exploit & Emulation",
    icon: Sword,
    color: "text-orange-400",
    items: [
      { label: "Exploit Arsenal", path: "/exploit-arsenal", icon: Bug },
      { label: "Exploit Catalog", path: "/exploit-catalog", icon: Package },
      { label: "Exploitation Bridge", path: "/exploitation-bridge", icon: Link2 },
      { label: "Abilities Library", path: "/abilities-library", icon: Layers },
      { label: "Ability Graph", path: "/ability-graph", icon: GitBranch },
      { label: "Atomic Red Team", path: "/atomic-red-team", icon: Atom },
      { label: "Emulation Playbooks", path: "/emulation-playbooks", icon: BookOpen },
      { label: "Post-Exploit Playbooks", path: "/post-exploit-playbooks", icon: FileCode },
      { label: "Payload Generator", path: "/payload-generator", icon: Binary },
      { label: "Evasion Engine", path: "/evasion-engine", icon: Eye },
      { label: "Privilege Escalation", path: "/privilege-escalation", icon: TrendingUp },
      { label: "Lateral Movement", path: "/lateral-movement", icon: Network },
      { label: "File Transfers", path: "/file-transfers", icon: HardDrive },
      { label: "Session Recordings", path: "/session-recordings", icon: Camera },
      { label: "Data Exfil Simulation", path: "/data-exfil-simulation", icon: Flame },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // C2 & AGENTS — Command-and-control frameworks, implant management
  // Visible to: admin, operator, team_lead
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: "c2-agents",
    label: "C2 & Agents",
    icon: Cpu,
    color: "text-amber-400",
    items: [
      { label: "Agent Management", path: "/agent-management", icon: Cpu },
      { label: "C2 Command Center", path: "/c2-command-center", icon: Radio },
      { label: "Ember Fleet", path: "/ember", icon: Flame },
      { label: "Ember Deploy", path: "/ember/deploy", icon: Rocket },
      { label: "Ember Tasks", path: "/ember/tasks", icon: Terminal },
      { label: "Ember Payloads", path: "/ember/payloads", icon: Binary },
      { label: "Ember Swarm", path: "/ember/swarm", icon: Boxes },
      { label: "Ember Intelligence", path: "/ember/intelligence", icon: Brain },
      { label: "Ember Capabilities", path: "/ember/capabilities", icon: CircuitBoard },
      { label: "Ember Cognitive", path: "/ember/cognitive", icon: Brain },
      { label: "Sliver C2", path: "/sliver-c2", icon: Skull },
      { label: "MSF Servers", path: "/msf-servers", icon: Server },
      { label: "MSF Sessions", path: "/msf-sessions", icon: Terminal },
      { label: "Internal Scanning", path: "/agent-internal-scanning", icon: Network },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // TEST LAB — Safe training environments, attack scenarios, graduation
  // Visible to: admin, operator, team_lead
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: "test-lab",
    label: "Test Lab",
    icon: FlaskConical,
    color: "text-teal-400",
    items: [
      { label: "Lab Dashboard", path: "/test-lab", icon: LayoutDashboard },
      { label: "Environments", path: "/test-lab/environments", icon: Server },
      { label: "Scenarios", path: "/test-lab/scenarios", icon: Target },
      { label: "Implant Testing", path: "/test-lab/implant", icon: Crosshair },
      { label: "Training Lab", path: "/training-lab", icon: FlaskConical },
      { label: "Graduation Lab", path: "/test-lab/graduation", icon: GraduationCap },
      { label: "LLM Training", path: "/test-lab/training", icon: FlaskConical },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // INTELLIGENCE & RECON — Threat intel, OSINT, domain recon, vulnerability intel
  // Visible to: admin, operator, team_lead, analyst, soc
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: "intel-recon",
    label: "Intelligence & Recon",
    icon: Telescope,
    color: "text-cyan-400",
    items: [
      { label: "Threat Intel Hub", path: "/threat-intel-hub", icon: Radar },
      { label: "Domain Intel", path: "/domain-intel", icon: Globe },
      { label: "Domain Recon", path: "/domain-recon", icon: Search },
      { label: "OSINT Monitor", path: "/osint-monitor", icon: Eye },
      { label: "Discovery Chain", path: "/discovery-chain", icon: Link2 },
      { label: "Threat Actors", path: "/threat-actors", icon: Shield },
      { label: "Threat Catalog", path: "/threat-catalog", icon: BookOpen },
      { label: "Threat Group Browser", path: "/threat-group-browser", icon: Users },
      { label: "Threat Actor Crawler", path: "/threat-actor-crawler", icon: Search, roles: ["admin", "operator", "team_lead"] },
      { label: "APT Library", path: "/apt-library", icon: Skull },
      { label: "TTP Knowledge", path: "/ttp-knowledge", icon: Brain },
      { label: "Threat Enrichment", path: "/threat-enrichment", icon: Sparkles },
      { label: "Darkweb Intel", path: "/darkweb-intel", icon: Eye },
      { label: "Breach Events", path: "/breach-events", icon: AlertTriangle },
      { label: "Ransomware Groups", path: "/ransomware-groups", icon: Skull },
      { label: "IOC Feed", path: "/ioc-feed", icon: Radio },
      { label: "KEV Catalog", path: "/kev-catalog", icon: AlertTriangle },
      { label: "NVD CVE Matcher", path: "/nvd-cve-matcher", icon: Bug },
      { label: "Vuln Intel", path: "/vuln-intel", icon: Scan },
      { label: "Bug Bounty Hub", path: "/bug-bounty", icon: Bug },
      { label: "Credential Alerts", path: "/credential-alerts", icon: Key },
      { label: "DFIR Library", path: "/dfir-library", icon: Newspaper },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // SCANNING & ASSESSMENT — Vulnerability scanning, web app testing, recon tools
  // Visible to: admin, operator, team_lead, analyst, soc (analyst/soc can view results)
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: "scanning",
    label: "Scanning & Assessment",
    icon: Scan,
    color: "text-emerald-400",
    items: [
      { label: "Unified Findings", path: "/unified-findings", icon: Shield },
      { label: "Web App Scanner", path: "/web-app-scanner", icon: Globe },
      { label: "ZAP Proxy", path: "/zap-proxy", icon: Scan },
      { label: "Nuclei Scanner", path: "/nuclei-scanner", icon: Microscope },
      { label: "Amass Scanner", path: "/amass-scanner", icon: Globe },
      { label: "Batch Scanner", path: "/batch-scanner", icon: Layers },
      { label: "Vuln Scanner", path: "/vuln-scanner", icon: Bug },
      { label: "API Security Testing", path: "/api-security-testing", icon: Code2 },
      { label: "Auth Assessment", path: "/auth-assessment", icon: Lock },
      { label: "Web Crawler", path: "/web-crawler", icon: Search },
      { label: "Scan Scheduler", path: "/scan-scheduler", icon: Clock },
      { label: "Scan Compare", path: "/scan-compare", icon: BarChart3 },
      { label: "Subfinder", path: "/tools/subfinder", icon: Search, roles: ["admin", "operator", "team_lead"] },
      { label: "Httpx", path: "/tools/httpx", icon: Globe, roles: ["admin", "operator", "team_lead"] },
      { label: "Naabu", path: "/tools/naabu", icon: Wifi, roles: ["admin", "operator", "team_lead"] },
      { label: "Scan Server Health", path: "/scan-server", icon: Server, roles: ["admin", "operator", "team_lead"] },
      { label: "Active Verification", path: "/active-verification", icon: ShieldCheck },
      { label: "Scan Schedules", path: "/scan-schedules", icon: CalendarClock },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // DETECTION & VALIDATION — Blue team validation, BAS, purple team, rules
  // Visible to: admin, operator, team_lead, analyst, soc
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: "detection-validation",
    label: "Detection & Validation",
    icon: ShieldCheck,
    color: "text-violet-400",
    items: [
      { label: "Detection Coverage", path: "/detection-coverage", icon: Shield },
      { label: "Attack Coverage", path: "/attack-coverage", icon: Target },
      { label: "Agentless BAS", path: "/agentless-bas", icon: FlaskConical },
      { label: "Continuous Validation", path: "/continuous-validation", icon: Rocket },
      { label: "Validation Engine", path: "/validation-engine", icon: Gauge },
      { label: "Control Testing", path: "/control-testing", icon: ShieldCheck },
      { label: "EDR Validation", path: "/edr-validation", icon: MonitorPlay },
      { label: "NGFW Validation", path: "/ngfw-validation", icon: Shield },
      { label: "Cloud Security Validation", path: "/cloud-security-validation", icon: Cloud },
      { label: "Rule Validator", path: "/rule-validator", icon: FileCheck2 },
      { label: "Sigma Rules", path: "/sigma-rules", icon: FileCode },
      { label: "Purple Team", path: "/purple-team", icon: Users },
      { label: "Corroboration Engine", path: "/corroboration-engine", icon: Link2 },
      { label: "Remediation Verification", path: "/remediation-verification", icon: ShieldCheck },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // AD & CLOUD — Active Directory, cloud attack paths, ICS/OT
  // Visible to: admin, operator, team_lead
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: "ad-cloud",
    label: "AD & Cloud",
    icon: Building2,
    color: "text-amber-400",
    items: [
      { label: "AD Domain Connector", path: "/ad-domain-connector", icon: Network },
      { label: "AD Attack Path Graph", path: "/ad-attack-path-graph", icon: GitBranch },
      { label: "AD Attack Sim", path: "/ad-attack-sim", icon: Sword },
      { label: "Bloodhound Import", path: "/bloodhound-import", icon: Database },
      { label: "Forest Mapper", path: "/forest-mapper", icon: Network },
      { label: "Attack Path Discovery", path: "/attack-path-discovery", icon: Search },
      { label: "Cloud Attack Paths", path: "/cloud-attack-paths", icon: Cloud },
      { label: "Cloud Credentials", path: "/cloud-credentials", icon: Key },
      { label: "Cloud Workload Testing", path: "/cloud-workload-testing", icon: Cloud },
      { label: "ICS/OT Security", path: "/ics-ot-security", icon: Factory },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // INFRASTRUCTURE — Integrations, SIEM/SOAR, SSH, CI/CD, infra management
  // Visible to: admin, operator, team_lead, soc
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: "infrastructure",
    label: "Infrastructure & Integrations",
    icon: Unplug,
    color: "text-teal-400",
    items: [
      { label: "SOC Integration Hub", path: "/soc-integration-hub", icon: Boxes, roles: ["admin", "team_lead", "soc"] },
      { label: "SIEM Connectors", path: "/siem-connectors", icon: Unplug, roles: ["admin", "team_lead", "soc"] },
      { label: "SIEM Feedback", path: "/siem-feedback", icon: BarChart3, roles: ["admin", "team_lead", "soc"] },
      { label: "SOAR Connectors", path: "/soar-connectors", icon: Unplug, roles: ["admin", "team_lead", "soc"] },
      { label: "Vendor Integrations", path: "/vendor-integrations", icon: Package },
      { label: "Webhooks", path: "/webhooks", icon: Webhook, roles: ["admin", "operator", "team_lead"] },
      { label: "Scan Webhooks", path: "/scan-webhooks", icon: Webhook, roles: ["admin", "operator", "team_lead"] },
      { label: "Infrastructure", path: "/infrastructure", icon: Server },
      { label: "Live Infra", path: "/live-infra", icon: Wifi },
      { label: "Infra Wiki", path: "/infra-wiki", icon: BookOpen },
      { label: "SSH Keys", path: "/ssh-keys", icon: Key, roles: ["admin", "operator"] },
      { label: "Agent Installer", path: "/agent-installer", icon: Laptop, roles: ["admin", "operator", "team_lead"] },
      { label: "CI/CD Pipeline", path: "/cicd-pipeline", icon: GitBranch, roles: ["admin", "team_lead"] },
      { label: "Auth Pipeline", path: "/auth-pipeline", icon: Lock, roles: ["admin", "team_lead"] },
      { label: "SAML Config", path: "/saml-config", icon: Settings, roles: ["admin"] },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // COMPLIANCE & REPORTING — Reports, compliance frameworks, evidence, risk
  // Visible to: admin, team_lead, analyst, executive, client, soc, viewer
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: "compliance-reporting",
    label: "Compliance & Reporting",
    icon: FileText,
    color: "text-blue-400",
    items: [
      { label: "Reports", path: "/reports", icon: FileText },
      { label: "Report Templates", path: "/report-templates", icon: FileCode },
      { label: "Pentest Report", path: "/pentest-report", icon: FileText },
      { label: "Post-Engagement Report", path: "/post-engagement-report", icon: FileText },
      { label: "Export Center", path: "/export-center", icon: Package },
      { label: "Compliance Dashboard", path: "/compliance-dashboard", icon: ShieldCheck },
      { label: "Compliance Mapper", path: "/compliance-mapper", icon: Landmark },
      { label: "Compliance", path: "/compliance", icon: ShieldCheck },
      { label: "FIPS Compliance", path: "/fips-compliance", icon: Lock },
      { label: "SOC 2 / Enterprise", path: "/soc2-compliance", icon: Shield },
      { label: "3PAO Review", path: "/3pao-review", icon: Stethoscope },
      { label: "OSCAL Export", path: "/oscal-export", icon: FileCheck2 },
      { label: "STIX Export", path: "/stix-export", icon: Code2 },
      { label: "Evidence", path: "/evidence", icon: FileCheck2 },
      { label: "Evidence Gallery", path: "/evidence-gallery", icon: Camera },
      { label: "Scoring", path: "/scoring", icon: BarChart3 },
      { label: "BIA Report", path: "/bia-report", icon: BarChart3 },
      { label: "Risk Trending", path: "/risk-trending", icon: TrendingUp },
      { label: "Remediation Tracking", path: "/remediation-tracking", icon: Target },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // KSI & FEDRAMP — FedRAMP-specific KSI tracking and evidence collection
  // Visible to: admin, team_lead, analyst, executive
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: "ksi-fedramp",
    label: "KSI & FedRAMP",
    icon: Landmark,
    color: "text-indigo-400",
    items: [
      { label: "KSI Dashboard", path: "/ksi-dashboard", icon: LayoutDashboard },
      { label: "KSI Validation", path: "/ksi-validation", icon: ShieldCheck },
      { label: "KSI Evidence Chain", path: "/ksi-evidence-chain", icon: Link2 },
      { label: "KSI Threat Map", path: "/ksi-threat-map", icon: Radar },
      { label: "KSI Auto Collector", path: "/ksi-auto-collector", icon: Bot },
      { label: "Scheduled Collection", path: "/scheduled-collection", icon: Clock },
      { label: "Config Baseline", path: "/config-baseline", icon: Settings },
      { label: "Compensating Controls", path: "/compensating-controls", icon: Shield },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // LLM & AI MANAGEMENT — Telemetry, training, graduation, SSIL, AI tools
  // Visible to: admin, operator, team_lead, analyst, soc
  // Operator sees: AI Attack Planner, Knowledge Base, Real-Time Monitor, Agent Leaderboard
  // Analyst/SOC sees: Telemetry, SSIL, Training Data, Learning
  // Admin/Team Lead sees: Everything including Graduation, Agent Registry, NEXUS
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: "llm-ai",
    label: "LLM & AI Management",
    icon: Brain,
    color: "text-purple-400",
    items: [
      // ── Operational AI Tools (operator, team_lead, admin) ──
      { label: "AI Attack Planner", path: "/ai-attack-planner", icon: Brain },
      { label: "AI Security Validation", path: "/ai-security-validation", icon: ShieldCheck },
      { label: "Real-Time Monitor", path: "/realtime-monitor", icon: Radio },
      { label: "Agent Leaderboard", path: "/agent-leaderboard", icon: Trophy },
      { label: "Knowledge Base", path: "/knowledge-base", icon: BookOpen },
      // ── LLM Observability (admin, team_lead, analyst, soc) ──
      { label: "LLM Telemetry", path: "/llm-telemetry", icon: BarChart3, roles: ["admin", "team_lead", "analyst"] },
      { label: "LLM Reliability", path: "/llm-reliability", icon: Gauge, roles: ["admin", "team_lead"] },
      { label: "LLM Learning", path: "/llm-learning", icon: BookOpen },
      { label: "Training Data", path: "/training-data-dashboard", icon: Database },
      { label: "Data Review & Export", path: "/training-data-review", icon: FileCheck2 },
      { label: "Training Dashboard", path: "/training-dashboard", icon: BarChart3 },
      { label: "Batch Training", path: "/batch-training", icon: Zap, roles: ["admin", "team_lead"] },
      { label: "Learning Dashboard", path: "/learning-dashboard", icon: GraduationCap },
      // ── SSIL Guardrails (admin, team_lead, analyst, soc) ──
      { label: "SSIL Overview", path: "/ssil", icon: Siren },
      { label: "SSIL Policies", path: "/ssil/policies", icon: ScrollText, roles: ["admin", "team_lead"] },
      { label: "Guardrails", path: "/ssil/guardrails", icon: Shield },
      { label: "Observations", path: "/ssil/observations", icon: Eye },
      { label: "Alert Rules", path: "/ssil/alerts", icon: AlertTriangle },
      { label: "SSIL Correlation", path: "/ssil/correlation", icon: Link2 },
      // ── Agent Registry & Pipeline (admin, team_lead only) ──
      { label: "Agent Registry", path: "/agent-registry", icon: Bot, roles: ["admin", "team_lead"] },
      { label: "NEXUS Pipeline", path: "/nexus-pipeline", icon: Workflow, roles: ["admin", "team_lead"] },
      { label: "Graduation Engine", path: "/graduation-engine", icon: GraduationCap, roles: ["admin", "team_lead"] },
      // ── Guides ──
      { label: "Emulation Guide", path: "/guide/caldera", icon: BookOpen },
      { label: "GoPhish Guide", path: "/guide/gophish", icon: BookOpen },
    ],
  },

  // ═══════════════════════════════════════════════════════════════════════════
  // ADMIN & SYSTEM — Team management, tenants, system health, workflows
  // Visible to: admin, team_lead
  // ═══════════════════════════════════════════════════════════════════════════
  {
    id: "admin",
    label: "Admin & System",
    icon: Settings,
    color: "text-zinc-400",
    items: [
      { label: "Team", path: "/team", icon: Users },
      { label: "Invitations", path: "/invitations", icon: Mail },
      { label: "Tenants", path: "/tenants", icon: Building2, roles: ["admin"] },
      { label: "Account Settings", path: "/account-settings", icon: Settings },
      { label: "Onboarding", path: "/onboarding", icon: Rocket },
      { label: "Customer Accounts", path: "/customer-accounts", icon: Users, roles: ["admin", "team_lead"] },
      { label: "Review Queue", path: "/review-queue", icon: FileCheck2 },
      { label: "Job Queue", path: "/job-queue", icon: Cog, roles: ["admin"] },
      { label: "Error Dashboard", path: "/error-dashboard", icon: AlertTriangle, roles: ["admin"] },
      { label: "Bug Reports", path: "/bug-reports", icon: Bug, roles: ["admin", "team_lead"] },
      { label: "Safety Engine", path: "/safety-dashboard", icon: ShieldCheck, roles: ["admin", "operator", "team_lead"] },
      { label: "OpSec Dashboard", path: "/opsec-dashboard", icon: Shield, roles: ["admin", "operator", "team_lead"] },
      { label: "MSSP Analytics", path: "/mssp-analytics", icon: BarChart3, roles: ["admin", "executive", "team_lead"] },
      { label: "Hunt Ops", path: "/hunt-ops", icon: Search },
      { label: "Preflight Checks", path: "/preflight-checks", icon: ShieldCheck },
      { label: "Workflows", path: "/workflows", icon: Workflow },
      { label: "ROE Builder", path: "/roe-builder", icon: ScrollText },
      { label: "Attack Vector Engine", path: "/attack-vector-engine", icon: Target },
      { label: "Unified Pipeline", path: "/unified-pipeline", icon: Workflow, roles: ["admin"] },
    ],
  },
];
