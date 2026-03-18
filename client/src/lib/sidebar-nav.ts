/**
 * Sidebar Navigation Configuration
 * 
 * Organized into collapsible groups matching the platform's operational domains.
 * Each group contains items with route paths, labels, and Lucide icon names.
 */
import {
  LayoutDashboard, Activity, Briefcase, Workflow, Key, Target, Cpu, FileText,
  Zap, Globe, Crosshair, Palette, Sparkles, Bug, Server, Layers, Shield,
  Brain, Radio, Radar, Lock, Fingerprint, Scan, Eye, Search, Code2,
  FileCode, Gauge, MonitorPlay, Building2, Stethoscope, GraduationCap,
  Network, Siren, FlaskConical, Camera, FileCheck2, Atom, BookOpen,
  Mail, Cloud, Rocket, ShieldCheck, AlertTriangle, TrendingUp, Unplug,
  Factory, BarChart3, Terminal, MapPin, Phone, Info, Clock, Landmark,
  CalendarClock,
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
  /** Roles that can see this item. If omitted, visible to all roles. */
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
 * - admin: Full access to all groups
 * - operator: Offensive operations, scanning, exploit, C2, campaigns
 * - analyst: Intel, detection, compliance, reporting, SSIL
 * - team_lead: Command & control, compliance, reporting, team management
 * - executive: Dashboard, compliance, reporting only
 * - client: Dashboard, compliance, reporting (read-only view)
 * - soc: Detection, SSIL, integrations, intel
 * - viewer: Dashboard and reporting only
 */
const ROLE_GROUP_ACCESS: Record<UserRole, string[] | 'all'> = {
  admin: 'all',
  operator: ['command-control', 'campaign-ops', 'exploit-emulation', 'agent-management', 'test-lab', 'intel-recon', 'scanning', 'detection-validation', 'ad-cloud', 'llm-ai'],
  analyst: ['command-control', 'intel-recon', 'scanning', 'detection-validation', 'compliance-reporting', 'ksi-fedramp', 'llm-ai'],
  team_lead: ['command-control', 'campaign-ops', 'agent-management', 'test-lab', 'intel-recon', 'scanning', 'detection-validation', 'compliance-reporting', 'ksi-fedramp', 'llm-ai', 'admin'],
  executive: ['command-control', 'compliance-reporting', 'ksi-fedramp'],
  client: ['command-control', 'compliance-reporting'],
  soc: ['command-control', 'intel-recon', 'detection-validation', 'llm-ai', 'integrations', 'compliance-reporting'],
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
  // ─── Command & Control ───
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
      { label: "Engagement Ops", path: "/engagement-ops", icon: Crosshair },
      { label: "Engagement Pipeline", path: "/engagement-pipeline", icon: Workflow },
      { label: "Engagement Automation", path: "/engagement-automation", icon: Rocket },
      { label: "Kill Chain", path: "/kill-chain", icon: Workflow },
      { label: "Engagement Timeline", path: "/engagement-timeline", icon: Clock },
      { label: "Credentials", path: "/credentials", roles: ["admin", "operator", "team_lead"] as UserRole[], icon: Key },
      { label: "OEM Credentials", path: "/oem-credentials", roles: ["admin", "operator"] as UserRole[], icon: Key },
      { label: "Adversaries", path: "/adversaries", icon: Target },
      { label: "Agent Management", path: "/agent-management", icon: Cpu },
      { label: "Internal Scanning", path: "/agent-internal-scanning", icon: Network },
      { label: "Activity Log", path: "/activity", icon: FileText },
      { label: "Audit Log", path: "/audit-log", roles: ["admin", "team_lead", "executive"] as UserRole[], icon: ScrollText },
    ],
  },

  // ─── Campaign Operations ───
  {
    id: "campaign-ops",
    label: "Campaign Operations",
    icon: Megaphone,
    color: "text-red-400",
    items: [
      { label: "Phishing Ops", path: "/phishing-ops", icon: Zap },
      { label: "Phishing Impact", path: "/phishing-impact-testing", icon: Mail },
      { label: "GoPhish", path: "/gophish", icon: Globe },
      { label: "Campaign Wizard", path: "/campaign-wizard", icon: Crosshair },
      { label: "Campaigns", path: "/campaigns", icon: Briefcase },
      { label: "Campaign Execution", path: "/campaign-execution", icon: Rocket },
      { label: "Campaign Archetypes", path: "/campaign-archetypes", icon: Layers },
      { label: "Campaign Advisor", path: "/campaign-advisor", icon: Brain },
      { label: "Page Builder", path: "/landing-page-builder", icon: Palette },
      { label: "Template Generator", path: "/template-generator", icon: Sparkles },
      { label: "Templates", path: "/templates", icon: FileCode },
      { label: "Email Security", path: "/email-security", icon: Mail },
      { label: "Phishing Exploit Catalog", path: "/phishing-exploit-catalog", icon: Bug },
    ],
  },

  // ─── Exploit & Emulation ───
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

  // ─── Agent Management (Unified C2) ───
  {
    id: "agent-management",
    label: "Agent Management",
    icon: Cpu,
    color: "text-amber-400",
    items: [
      { label: "All Agents", path: "/agent-management", icon: Cpu },
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
    ],
  },

  // ─── Test Lab ───
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
    ],
  },

  // ─── Intelligence & Recon ───
  {
    id: "intel-recon",
    label: "Intelligence & Recon",
    icon: Telescope,
    color: "text-cyan-400",
    items: [
      { label: "Domain Intel", path: "/domain-intel", icon: Globe },
      { label: "Domain Recon", path: "/domain-recon", icon: Search },
      { label: "OSINT Monitor", path: "/osint-monitor", icon: Eye },
      { label: "Discovery Chain", path: "/discovery-chain", icon: Link2 },
      { label: "Threat Actors", path: "/threat-actors", icon: Shield },
      { label: "Threat Catalog", path: "/threat-catalog", icon: BookOpen },
      { label: "Threat Group Browser", path: "/threat-group-browser", icon: Users },
      { label: "Threat Actor Crawler", path: "/threat-actor-crawler", icon: Search },
      { label: "APT Library", path: "/apt-library", icon: Skull },
      { label: "TTP Knowledge", path: "/ttp-knowledge", icon: Brain },
      { label: "Threat Intel Hub", path: "/threat-intel-hub", icon: Radar },
      { label: "Threat Enrichment", path: "/threat-enrichment", icon: Sparkles },
      { label: "Darkweb Intel", path: "/darkweb-intel", icon: Eye },
      { label: "Breach Events", path: "/breach-events", icon: AlertTriangle },
      { label: "Ransomware Groups", path: "/ransomware-groups", icon: Skull },
      { label: "IOC Feed", path: "/ioc-feed", icon: Radio },
      { label: "KEV Catalog", path: "/kev-catalog", icon: AlertTriangle },
      { label: "NVD CVE Matcher", path: "/nvd-cve-matcher", icon: Bug },
      { label: "Vuln Intel", path: "/vuln-intel", icon: Scan },
      { label: "Credential Alerts", path: "/credential-alerts", icon: Key },
      { label: "DFIR Library", path: "/dfir-library", icon: Newspaper },
    ],
  },

  // ─── Scanning & Assessment ───
  {
    id: "scanning",
    label: "Scanning & Assessment",
    icon: Scan,
    color: "text-emerald-400",
    items: [
      { label: "Web App Scanner", path: "/web-app-scanner", icon: Globe },
      { label: "ZAP Proxy", path: "/zap-proxy", icon: Scan },
      { label: "Nuclei Scanner", path: "/nuclei-scanner", icon: Microscope },
      { label: "Batch Scanner", path: "/batch-scanner", icon: Layers },
      { label: "Vuln Scanner", path: "/vuln-scanner", icon: Bug },
      { label: "API Security Testing", path: "/api-security-testing", icon: Code2 },
      { label: "Auth Assessment", path: "/auth-assessment", icon: Lock },
      { label: "Web Crawler", path: "/web-crawler", icon: Search },
      { label: "Scan Scheduler", path: "/scan-scheduler", icon: Clock },
      { label: "Scan Compare", path: "/scan-compare", icon: BarChart3 },
      { label: "Subfinder", path: "/tools/subfinder", icon: Search },
      { label: "Httpx", path: "/tools/httpx", icon: Globe },
      { label: "Naabu", path: "/tools/naabu", icon: Wifi },
      { label: "Scan Server Health", path: "/scan-server", icon: Server },
      { label: "Active Verification", path: "/active-verification", icon: ShieldCheck },
      { label: "Scan Schedules", path: "/scan-schedules", icon: CalendarClock },
    ],
  },

  // ─── Detection & Validation ───
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

  // ─── Active Directory & Cloud ───
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

  // ─── Compliance & Reporting ───
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
      { label: "Scoring", path: "/scoring", icon: BarChart3 },
      { label: "BIA Report", path: "/bia-report", icon: BarChart3 },
      { label: "Risk Trending", path: "/risk-trending", icon: TrendingUp },
      { label: "Remediation Tracking", path: "/remediation-tracking", icon: Target },
    ],
  },

  // ─── KSI & FedRAMP ───
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



  // ─── Integrations & Infrastructure ───
  {
    id: "integrations",
    label: "Integrations & Infra",
    icon: Unplug,
    color: "text-teal-400",
    items: [
      { label: "SOC Integration Hub", path: "/soc-integration-hub", icon: Boxes },
      { label: "SIEM Connectors", path: "/siem-connectors", icon: Unplug },
      { label: "SIEM Feedback", path: "/siem-feedback", icon: BarChart3 },
      { label: "SOAR Connectors", path: "/soar-connectors", icon: Unplug },
      { label: "Vendor Integrations", path: "/vendor-integrations", icon: Package },
      { label: "Webhooks", path: "/webhooks", icon: Webhook },
      { label: "Scan Webhooks", path: "/scan-webhooks", icon: Webhook },
      { label: "Infrastructure", path: "/infrastructure", icon: Server },
      { label: "Live Infra", path: "/live-infra", icon: Wifi },
      { label: "Infra Wiki", path: "/infra-wiki", icon: BookOpen },
      { label: "SSH Keys", path: "/ssh-keys", roles: ["admin", "operator"] as UserRole[], icon: Key },
      { label: "Agent Installer", path: "/agent-installer", icon: Laptop },
      { label: "CI/CD Pipeline", path: "/cicd-pipeline", icon: GitBranch },
      { label: "Auth Pipeline", path: "/auth-pipeline", icon: Lock },
      { label: "SAML Config", path: "/saml-config", roles: ["admin"] as UserRole[], icon: Settings },
    ],
  },



  // ─── LLM & AI Management ───
  {
    id: "llm-ai",
    label: "LLM & AI Management",
    icon: Brain,
    color: "text-purple-400",
    items: [
      // Core LLM
      { label: "LLM Telemetry", path: "/llm-telemetry", roles: ["admin"] as UserRole[], icon: BarChart3 },
      { label: "LLM Reliability", path: "/llm-reliability", roles: ["admin"] as UserRole[], icon: Gauge },
      { label: "LLM Learning", path: "/llm-learning", icon: BookOpen },
      { label: "Training Data", path: "/training-data-dashboard", icon: Database },
      // Graduation
      { label: "Graduation Engine", path: "/graduation-engine", roles: ["admin"] as UserRole[], icon: GraduationCap },
      { label: "Graduation Lab", path: "/test-lab/graduation", icon: GraduationCap },
      // Training & Learning
      { label: "Training Lab", path: "/training-lab", icon: FlaskConical },
      { label: "LLM Training", path: "/test-lab/training", icon: FlaskConical },
      { label: "Training Dashboard", path: "/training-dashboard", icon: BarChart3 },
      { label: "Batch Training", path: "/batch-training", icon: Zap },
      { label: "Learning Dashboard", path: "/learning-dashboard", icon: GraduationCap },
      // SSIL (Guardrails & Signals)
      { label: "SSIL Overview", path: "/ssil", icon: Siren },
      { label: "SSIL Policies", path: "/ssil/policies", icon: ScrollText },
      { label: "Guardrails", path: "/ssil/guardrails", icon: Shield },
      { label: "Observations", path: "/ssil/observations", icon: Eye },
      { label: "Alert Rules", path: "/ssil/alerts", icon: AlertTriangle },
      { label: "SSIL Correlation", path: "/ssil/correlation", icon: Link2 },
      // AI Tools
      { label: "AI Security Validation", path: "/ai-security-validation", icon: ShieldCheck },
      { label: "AI Attack Planner", path: "/ai-attack-planner", icon: Brain },
      // Knowledge
      { label: "Knowledge Base", path: "/knowledge-base", icon: BookOpen },
      { label: "Emulation Guide", path: "/guide/caldera", icon: BookOpen },
      { label: "GoPhish Guide", path: "/guide/gophish", icon: BookOpen },
    ],
  },

  // ─── Admin & System ───
  {
    id: "admin",
    label: "Admin & System",
    icon: Settings,
    color: "text-zinc-400",
    items: [
      { label: "Team", path: "/team", icon: Users },
      { label: "Invitations", path: "/invitations", icon: Mail },
      { label: "Tenants", path: "/tenants", roles: ["admin"] as UserRole[], icon: Building2 },
      { label: "Account Settings", path: "/account-settings", icon: Settings },
      { label: "Onboarding", path: "/onboarding", icon: Rocket },
      { label: "Customer Accounts", path: "/customer-accounts", icon: Users, roles: ["admin", "team_lead"] as UserRole[] },
      { label: "Review Queue", path: "/review-queue", icon: FileCheck2 },
      { label: "Job Queue", path: "/job-queue", roles: ["admin"] as UserRole[], icon: Cog },
      { label: "Error Dashboard", path: "/error-dashboard", roles: ["admin"] as UserRole[], icon: AlertTriangle },
      { label: "Bug Reports", path: "/bug-reports", roles: ["admin", "team_lead"] as UserRole[], icon: Bug },
      { label: "Safety Engine", path: "/safety-dashboard", roles: ["admin", "operator", "team_lead"] as UserRole[], icon: ShieldCheck },
      { label: "OpSec Dashboard", path: "/opsec-dashboard", roles: ["admin", "operator", "team_lead"] as UserRole[], icon: Shield },
      { label: "MSSP Analytics", path: "/mssp-analytics", roles: ["admin", "executive", "team_lead"] as UserRole[], icon: BarChart3 },
      { label: "Hunt Ops", path: "/hunt-ops", icon: Search },
      { label: "Preflight Checks", path: "/preflight-checks", icon: ShieldCheck },
      { label: "Workflows", path: "/workflows", icon: Workflow },
      { label: "ROE Builder", path: "/roe-builder", icon: ScrollText },

      { label: "Attack Vector Engine", path: "/attack-vector-engine", icon: Target },
      { label: "Unified Pipeline", path: "/unified-pipeline", roles: ["admin"] as UserRole[], icon: Workflow },
    ],
  },
];
