import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import { useIsEmbedded } from "@/contexts/EmbedContext";
import {
  Activity,
  Target,
  Users,
  Cpu,
  Zap,
  FileText,
  Cloud,
  BookOpen,
  Shield,
  Globe2,
  Briefcase,
  LogOut,
  Menu,
  X,
  Rocket,
  BarChart3,
  Brain,
  Sparkles,
  Layers,
  Radio,
  Workflow,
  ShieldCheck,
  UserCog,
  Mail,
  Palette,
  Bug,
  ArrowLeftRight,
  Database,
  AlertTriangle,
  Crosshair,
  Server,
  ChevronDown,
  ChevronRight,
  Swords,
  Search,
  GraduationCap,
  Settings,
  FileJson,
  GitBranch,
  Eye,
  Webhook,
  BookMarked,
  Archive,
  ClipboardCheck,
  FlaskConical,
  KeyRound,
  Terminal,
  Video,
  ScrollText,
  BadgeCheck,
  ShieldAlert,
  FileOutput,
  ArrowUpDown,
  Package,
  ShieldOff,
  ClipboardList,
  Calendar,
  Key,
  Network,
  Bell,
  TreePine,
  RefreshCw,
  Microscope,
  ScanSearch,
  ShieldPlus,
  Gauge,
  Radar,
  Atom,
  Layers3,
  Hexagon,
  ScanLine,
  Map,
  Clock,
  Lock,
  Fingerprint,
  Star,
  History,
  Pin,
  Scan,
  BrainCircuit,
  FileStack,
  Globe,
  Wifi,
  GitMerge,
  Satellite,
  Download,
  Monitor,
  CloudCog,
  FileCode2,
} from "lucide-react";
import { useState, useEffect, ReactNode, useCallback, useMemo, useRef } from "react";
import { useAuth } from "@/_core/hooks/useAuth";
import { canAccessGroup, canAccessSubSection, getRoleDisplayName, getRoleBadgeClass, getHomeDashboardPath, ALL_ROLES, type UserRole } from "@/lib/role-access";

// ─── Types ─────────────────────────────────────────────────────────────────────

interface NavItemDef {
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  label: string;
}

interface NavSubSection {
  id: string;
  label: string;
  items: NavItemDef[];
}

interface NavGroup {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  subSections: NavSubSection[];
}

// ─── Two-Tier Navigation Structure ──────────────────────────────────────────────

const NAV_GROUPS: NavGroup[] = [
  // ── 1. COMMAND CENTER ── Mission planning, engagements, and campaign orchestration
  {
    id: "command",
    label: "COMMAND CENTER",
    icon: Swords,
    subSections: [
      {
        id: "cmd-ops",
        label: "Mission Operations",
        items: [
          { href: "/dashboard", icon: Activity, label: "DASHBOARD" },
          { href: "/workflows", icon: Rocket, label: "MISSION WORKFLOWS" },
          { href: "/engagements", icon: Briefcase, label: "ENGAGEMENT MGR" },
          { href: "/engagement-ops", icon: Crosshair, label: "ENGAGEMENT OPS" },
          { href: "/engagement-timeline", icon: Workflow, label: "KILL CHAIN" },
          { href: "/kill-chain", icon: GitMerge, label: "KILL CHAIN VISUALIZER" },
          { href: "/opsec-dashboard", icon: ShieldAlert, label: "OPSEC DASHBOARD" },
          { href: "/engagement-automation", icon: Zap, label: "AUTOMATION HUB" },
          { href: "/roe-builder", icon: ClipboardCheck, label: "ROE BUILDER" },
          { href: "/campaign-archetypes", icon: Layers, label: "CAMPAIGN ARCHETYPES" },
        ],
      },
      {
        id: "cmd-scoring",
        label: "Risk & Analysis",
        items: [
          { href: "/scoring", icon: Crosshair, label: "RISK CENTER" },
          { href: "/ai-attack-planner", icon: Brain, label: "AI ATTACK PLANNER" },
          { href: "/preflight-checks", icon: Gauge, label: "PRE-FLIGHT CHECKS" },
          { href: "/attack-coverage", icon: Map, label: "ATT&CK COVERAGE" },
          { href: "/risk-trending", icon: BarChart3, label: "RISK TRENDING" },
          { href: "/corroboration-engine", icon: Microscope, label: "CORROBORATION" },
        ],
      },
    ],
  },
  // ── 2. ATTACK SURFACE ── Reconnaissance, discovery, and asset enumeration
  {
    id: "surface",
    label: "ATTACK SURFACE",
    icon: Search,
    subSections: [
      {
        id: "surf-discovery",
        label: "Discovery & Recon",
        items: [
          { href: "/discovery-chain", icon: GitMerge, label: "DISCOVERY CHAIN" },
          { href: "/domain-intel", icon: Brain, label: "DOMAIN INTEL" },
          { href: "/domain-intel/history", icon: ClipboardList, label: "SCAN HISTORY" },
          { href: "/web-crawler", icon: ScanSearch, label: "WEB CRAWLER" },
          { href: "/bug-bounty", icon: Bug, label: "BUG BOUNTY HUB" },
          { href: "/osint-monitor", icon: Eye, label: "OSINT MONITOR" },
          { href: "/email-security", icon: Shield, label: "EMAIL SECURITY" },
        ],
      },
      {
        id: "surf-tools",
        label: "Scanning & Enumeration",
        items: [
          { href: "/tools/subfinder", icon: Globe, label: "DISCOVERY TOOLKIT" },
          { href: "/tools/httpx", icon: Globe2, label: "HTTPX PROBER" },
          { href: "/tools/naabu", icon: Radar, label: "PORT SCANNER (NMAP)" },
          { href: "/nuclei-scanner", icon: ScanLine, label: "VULN SCANNING" },
          { href: "/vuln-scanner", icon: Bug, label: "VULN SCANNER" },
          { href: "/scan-scheduler", icon: Clock, label: "SCAN MANAGEMENT" },
          { href: "/config-baseline", icon: Settings, label: "CONFIG BASELINE" },
        ],
      },
      {
        id: "surf-paths",
        label: "Attack Paths",
        items: [
          { href: "/attack-paths", icon: GitBranch, label: "ATTACK PATHS" },
          { href: "/attack-path-discovery", icon: Search, label: "PATH DISCOVERY" },
          { href: "/attack-vector-engine", icon: Crosshair, label: "VECTOR ENGINE" },
          { href: "/cloud-attack-paths", icon: Cloud, label: "CLOUD PATHS" },
          { href: "/cloud-security-validation", icon: CloudCog, label: "CLOUD VALIDATION" },
          { href: "/ad-attack-sim", icon: Server, label: "AD SECURITY" },
          { href: "/ad-attack-path-graph", icon: Network, label: "AD ATTACK GRAPH" },
          { href: "/ad-domain-connector", icon: Database, label: "AD CONNECTOR" },
          { href: "/bloodhound-import", icon: FileStack, label: "BLOODHOUND IMPORT" },
          { href: "/forest-mapper", icon: TreePine, label: "FOREST MAPPER" },
        ],
      },
    ],
  },
  // ── 3. EMULATION & TESTING ── Adversary emulation, purple team, BAS
  {
    id: "emulation",
    label: "EMULATION & TESTING",
    icon: Target,
    subSections: [
      {
        id: "emu-agents",
        label: "Agents & Emulation",
        items: [
          { href: "/agents", icon: Cpu, label: "AGENTS" },
          { href: "/emulation-playbooks", icon: BookMarked, label: "PLAYBOOKS" },
          { href: "/ability-graph", icon: GitBranch, label: "ABILITY GRAPH" },
          { href: "/atomic-red-team", icon: Atom, label: "ATT&CK TESTS" },
          { href: "/evasion-engine", icon: ShieldOff, label: "EVASION ENGINE" },
          { href: "/agentless-bas", icon: Radar, label: "AGENTLESS BAS" },
          { href: "/agent-manager", icon: Settings, label: "AGENT MANAGER" },
        ],
      },
      {
        id: "emu-validation",
        label: "Defense Validation",
        items: [
          { href: "/purple-team", icon: Eye, label: "PURPLE TEAM" },
          { href: "/edr-validation", icon: ShieldCheck, label: "DEFENSE TESTING" },
          { href: "/detection-coverage", icon: Target, label: "COVERAGE MATRIX" },
          { href: "/continuous-validation", icon: Calendar, label: "VALIDATION OPS" },
          { href: "/ngfw-validation", icon: Shield, label: "NGFW VALIDATION" },
          { href: "/ai-security-validation", icon: Brain, label: "AI SECURITY" },
          { href: "/remediation-verification", icon: RefreshCw, label: "REMEDIATION" },
          { href: "/sigma-rules", icon: FileCode2, label: "SIGMA RULES" },
        ],
      },
    ],
  },
  // ── 4. EXPLOIT OPS ── Phishing, exploits, C2, and offensive tooling
  {
    id: "exploits",
    label: "EXPLOIT OPS",
    icon: Zap,
    subSections: [
      {
        id: "exp-phishing",
        label: "Phishing Campaigns",
        items: [
          { href: "/phishing-ops", icon: Zap, label: "PHISHING OPS" },
          { href: "/landing-page-builder", icon: Palette, label: "PHISHING ASSETS" },
          { href: "/email-security", icon: Shield, label: "EMAIL SECURITY" },
        ],
      },
      {
        id: "exp-tools",
        label: "Exploit Tooling",
        items: [
          { href: "/exploit-catalog", icon: Crosshair, label: "EXPLOIT CATALOG" },
          { href: "/exploit-arsenal", icon: Swords, label: "EXPLOIT ARSENAL" },
          { href: "/payload-generator", icon: Package, label: "PAYLOAD GENERATOR" },
          { href: "/api-security-testing", icon: Globe2, label: "API SECURITY" },
          { href: "/web-app-scanner", icon: Radar, label: "WEB APP SCANNER" },
          { href: "/zap-proxy", icon: Wifi, label: "ZAP PROXY" },
          { href: "/credential-attacks", icon: Lock, label: "CREDENTIAL ATTACKS" },
          { href: "/auth-assessment", icon: Fingerprint, label: "AUTH ASSESSMENT" },
          { href: "/auth-pipeline", icon: Workflow, label: "AUTH PIPELINE" },
          { href: "/exploitation-bridge", icon: Crosshair, label: "EXPLOIT BRIDGE" },
          { href: "/privilege-escalation", icon: ArrowUpDown, label: "PRIVESC ENGINE" },
          { href: "/lateral-movement", icon: Network, label: "LATERAL MOVEMENT" },
          { href: "/campaign-advisor", icon: BrainCircuit, label: "CAMPAIGN ADVISOR" },
          { href: "/tool-comparison", icon: BarChart3, label: "TOOL COMPARISON" },
        ],
      },
      {
        id: "exp-c2",
        label: "C2 & Post-Exploit",
        items: [
          { href: "/c2-command-center", icon: Radio, label: "C2 HUB" },
          { href: "/msf-sessions", icon: Terminal, label: "LIVE SESSIONS" },
          { href: "/session-recordings", icon: Video, label: "RECORDINGS" },
          { href: "/ssh-keys", icon: KeyRound, label: "SSH KEYS" },
          { href: "/post-exploit-playbooks", icon: ScrollText, label: "POST-EXPLOIT" },
          { href: "/file-transfers", icon: ArrowUpDown, label: "FILE TRANSFERS" },
          { href: "/sliver-c2", icon: Cpu, label: "SLIVER C2" },
          { href: "/credential-alerts", icon: Bell, label: "CREDENTIAL ALERTS" },
          { href: "/credential-auto-rotation", icon: RefreshCw, label: "CRED ROTATION" },
        ],
      },
    ],
  },
  // ── 5. INTELLIGENCE ── Threat intel, OSINT, dark web, IOC feeds
  {
    id: "intelligence",
    label: "INTELLIGENCE",
    icon: Shield,
    subSections: [
      {
        id: "intel-threats",
        label: "Threat Intelligence",
        items: [
          { href: "/threat-intel-hub", icon: Shield, label: "THREAT INTEL HUB" },
          { href: "/vuln-intel", icon: Bug, label: "VULN INTEL" },
          { href: "/darkweb-intel", icon: AlertTriangle, label: "DARKWEB INTEL" },
          { href: "/ioc-feed", icon: Radio, label: "IOC FEED" },
          { href: "/threat-actor-crawler", icon: Satellite, label: "ACTOR INTEL" },
          { href: "/threat-enrichment", icon: Brain, label: "THREAT ENRICHMENT" },
          { href: "/ransomware-groups", icon: AlertTriangle, label: "RANSOMWARE GROUPS" },
          { href: "/nvd-cve-matcher", icon: Bug, label: "NVD CVE MATCHER" },
          { href: "/kev-catalog", icon: AlertTriangle, label: "KEV CATALOG" },
        ],
      },
      {
        id: "intel-credentials",
        label: "Credentials & Export",
        items: [
          { href: "/cloud-credentials", icon: Key, label: "CREDENTIAL CENTER" },
          { href: "/stix-export", icon: FileJson, label: "DATA EXPORT" },
          { href: "/oscal-export", icon: FileOutput, label: "OSCAL EXPORT" },
          { href: "/export-center", icon: Download, label: "PENTEST EXPORT" },
        ],
      },
    ],
  },
  // ── 6. KEY SECURITY INDICATORS ── FedRAMP KSIs, evidence, compliance
  {
    id: "ksi",
    label: "KEY SECURITY INDICATORS",
    icon: BadgeCheck,
    subSections: [
      {
        id: "ksi-core",
        label: "Indicators & Compliance",
        items: [
          { href: "/ksi-dashboard", icon: BadgeCheck, label: "KSI DASHBOARD" },
          { href: "/ksi-auto-collector", icon: RefreshCw, label: "AUTO COLLECTOR" },
          { href: "/ksi-evidence-chain", icon: GitBranch, label: "EVIDENCE CHAIN" },
          { href: "/ksi-threat-map", icon: Map, label: "THREAT MAP" },
          { href: "/compliance", icon: FileText, label: "COMPLIANCE CENTER" },
          { href: "/compliance-mapper", icon: Layers, label: "COMPLIANCE MAPPER" },
          { href: "/compensating-controls", icon: Shield, label: "COMPENSATING CTRL" },
          { href: "/control-testing", icon: FlaskConical, label: "CONTROL TESTING" },
        ],
      },
    ],
  },
  // ── 7. REPORTS & KNOWLEDGE ── Reports, guides, reference library
  {
    id: "reports",
    label: "REPORTS & KNOWLEDGE",
    icon: BarChart3,
    subSections: [
      {
        id: "rpt-all",
        label: "Reports & Guides",
        items: [
          { href: "/reports/generate", icon: BarChart3, label: "REPORTS" },
          { href: "/pentest-report", icon: FileText, label: "PENTEST REPORT" },
          { href: "/guide/gophish", icon: BookOpen, label: "GUIDES" },
          { href: "/ttp-knowledge", icon: Brain, label: "KNOWLEDGE BASE" },
          { href: "/training-dashboard", icon: GraduationCap, label: "TRAINING" },
          { href: "/report-templates", icon: FileStack, label: "REPORT TEMPLATES" },
          { href: "/evidence", icon: Archive, label: "EVIDENCE VAULT" },
        ],
      },
    ],
  },
  // ── 8. PLATFORM ── Admin, integrations, SSIL, infrastructure
  {
    id: "platform",
    label: "PLATFORM",
    icon: Settings,
    subSections: [
      {
        id: "plat-admin",
        label: "Administration",
        items: [
          { href: "/account-settings", icon: UserCog, label: "MY ACCOUNT" },
          { href: "/team", icon: Users, label: "TEAM" },
          { href: "/invitations", icon: Mail, label: "INVITATIONS" },
          { href: "/saml-config", icon: Fingerprint, label: "SAML SSO" },
          { href: "/sessions", icon: Monitor, label: "SESSIONS" },
          { href: "/audit-log", icon: FileText, label: "AUDIT LOG" },
          { href: "/siem-connectors", icon: Radio, label: "INTEGRATIONS" },
          { href: "/ssil", icon: Scan, label: "SSIL" },
          { href: "/live-infra", icon: Server, label: "INFRASTRUCTURE" },
          { href: "/scan-server", icon: Activity, label: "SCAN SERVER" },
          { href: "/error-dashboard", icon: Bug, label: "ERROR DASHBOARD" },
          { href: "/llm-telemetry", icon: BarChart3, label: "LLM TELEMETRY" },
          { href: "/oem-credentials", icon: Key, label: "DEFAULT CREDENTIALS" },
          { href: "/webhooks", icon: Webhook, label: "WEBHOOKS" },
          { href: "/vendor-integrations", icon: Layers, label: "VENDOR INTEGRATIONS" },
          { href: "/soar-connectors", icon: Workflow, label: "SOAR CONNECTORS" },
          { href: "/siem-feedback", icon: Radio, label: "SIEM FEEDBACK" },
          { href: "/tenants", icon: Users, label: "TENANTS" },
          { href: "/onboarding", icon: Users, label: "ONBOARDING" },
          { href: "/compliance-dashboard", icon: ShieldCheck, label: "COMPLIANCE" },
          { href: "/scan-webhooks", icon: Webhook, label: "SCAN WEBHOOKS" },
          { href: "/cicd-pipeline", icon: GitBranch, label: "CI/CD PIPELINE" },
          { href: "/ics-ot-security", icon: Cpu, label: "ICS/OT SECURITY" },
          { href: "/unified-pipeline", icon: Workflow, label: "UNIFIED PIPELINE" },
          { href: "/infra-wiki", icon: BookOpen, label: "INFRA WIKI" },
        ],
      },
    ],
  },
];

// ─── Flatten all items for search ────────────────────────────────────────────

const ALL_NAV_ITEMS: (NavItemDef & { groupLabel: string; subLabel: string })[] = NAV_GROUPS.flatMap(
  (g) =>
    g.subSections.flatMap((sub) =>
      sub.items.map((item) => ({
        ...item,
        groupLabel: g.label,
        subLabel: sub.label,
      }))
    )
);

// ─── Storage Keys ────────────────────────────────────────────────────────────

const SIDEBAR_STATE_KEY = "ace-c3-sidebar-groups";
const SIDEBAR_SUB_STATE_KEY = "ace-c3-sidebar-subs";
const FAVORITES_KEY = "ace-c3-favorites";
const RECENT_KEY = "ace-c3-recent";

function loadState<T>(key: string, fallback: T): T {
  try {
    const stored = localStorage.getItem(key);
    if (stored) return JSON.parse(stored);
  } catch {}
  return fallback;
}

function saveState(key: string, value: unknown) {
  try {
    localStorage.setItem(key, JSON.stringify(value));
  } catch {}
}

// ─── Find which group/sub contains a path ────────────────────────────────────

function findGroupForPath(path: string): string | null {
  for (const group of NAV_GROUPS) {
    for (const sub of group.subSections) {
      if (sub.items.some((item) => path === item.href || path.startsWith(item.href + "/"))) {
        return group.id;
      }
    }
  }
  return null;
}

function findSubForPath(path: string): string | null {
  for (const group of NAV_GROUPS) {
    for (const sub of group.subSections) {
      if (sub.items.some((item) => path === item.href || path.startsWith(item.href + "/"))) {
        return sub.id;
      }
    }
  }
  return null;
}

// ─── NavItem Component ─────────────────────────────────────────────────────────

function NavItem({
  href,
  icon: Icon,
  label,
  active,
  onClick,
  isFavorite,
  onToggleFavorite,
}: {
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  active?: boolean;
  onClick?: () => void;
  isFavorite?: boolean;
  onToggleFavorite?: (href: string) => void;
}) {
  return (
    <div className="group/item relative">
      <Link href={href} onClick={onClick}>
        <div
          className={`flex items-center gap-2.5 pl-10 pr-8 py-2 font-display tracking-wider text-[11px] transition-colors min-h-[34px] ${
            active
              ? "bg-primary/20 text-primary border-l-2 border-primary"
              : "hover:bg-secondary text-muted-foreground hover:text-foreground"
          }`}
        >
          <Icon className="w-3.5 h-3.5 shrink-0" />
          <span className="truncate">{label}</span>
        </div>
      </Link>
      {onToggleFavorite && (
        <button
          onClick={(e) => {
            e.stopPropagation();
            onToggleFavorite(href);
          }}
          className={`absolute right-2 top-1/2 -translate-y-1/2 p-1 rounded transition-all ${
            isFavorite
              ? "text-amber-400 opacity-100"
              : "text-muted-foreground/40 opacity-0 group-hover/item:opacity-100 hover:text-amber-400"
          }`}
          title={isFavorite ? "Remove from favorites" : "Add to favorites"}
        >
          <Star className={`w-3 h-3 ${isFavorite ? "fill-current" : ""}`} />
        </button>
      )}
    </div>
  );
}

// ─── SubSection Component ───────────────────────────────────────────────────

function SubSectionNav({
  sub,
  expanded,
  onToggle,
  currentPath,
  onNavClick,
  favorites,
  onToggleFavorite,
}: {
  sub: NavSubSection;
  expanded: boolean;
  onToggle: () => void;
  currentPath: string;
  onNavClick: () => void;
  favorites: string[];
  onToggleFavorite: (href: string) => void;
}) {
  const hasActiveItem = sub.items.some(
    (item) => currentPath === item.href || currentPath.startsWith(item.href + "/")
  );

  return (
    <div>
      <button
        onClick={onToggle}
        className={`w-full flex items-center gap-2 pl-7 pr-4 py-1.5 text-[10px] font-display tracking-wider transition-colors ${
          hasActiveItem && !expanded
            ? "text-primary/80"
            : "text-muted-foreground/60 hover:text-muted-foreground"
        }`}
      >
        <span className="flex-1 text-left truncate uppercase">{sub.label}</span>
        {expanded ? (
          <ChevronDown className="w-3 h-3 shrink-0 opacity-40" />
        ) : (
          <ChevronRight className="w-3 h-3 shrink-0 opacity-40" />
        )}
      </button>
      <div
        className={`overflow-hidden transition-all duration-200 ease-in-out ${
          expanded ? "max-h-[2000px] opacity-100" : "max-h-0 opacity-0"
        }`}
      >
        {sub.items.map((item) => (
          <NavItem
            key={item.href}
            href={item.href}
            icon={item.icon}
            label={item.label}
            active={currentPath === item.href || currentPath.startsWith(item.href + "/")}
            onClick={onNavClick}
            isFavorite={favorites.includes(item.href)}
            onToggleFavorite={onToggleFavorite}
          />
        ))}
      </div>
    </div>
  );
}

// ─── NavGroupSection Component ─────────────────────────────────────────────────

function NavGroupSection({
  group,
  expanded,
  onToggle,
  expandedSubs,
  onToggleSub,
  currentPath,
  onNavClick,
  favorites,
  onToggleFavorite,
}: {
  group: NavGroup;
  expanded: boolean;
  onToggle: () => void;
  expandedSubs: Record<string, boolean>;
  onToggleSub: (subId: string) => void;
  currentPath: string;
  onNavClick: () => void;
  favorites: string[];
  onToggleFavorite: (href: string) => void;
}) {
  const GroupIcon = group.icon;
  const hasActiveItem = group.subSections.some((sub) =>
    sub.items.some(
      (item) => currentPath === item.href || currentPath.startsWith(item.href + "/")
    )
  );

  const totalItems = group.subSections.reduce((sum, sub) => sum + sub.items.length, 0);

  return (
    <div className="mb-0.5">
      <button
        onClick={onToggle}
        className={`w-full flex items-center gap-3 px-4 py-2.5 font-display tracking-wider text-xs transition-colors min-h-[40px] group ${
          hasActiveItem && !expanded
            ? "text-primary"
            : "text-muted-foreground hover:text-foreground hover:bg-secondary/50"
        }`}
      >
        <GroupIcon className="w-4 h-4 shrink-0" />
        <span className="flex-1 text-left truncate">{group.label}</span>
        <span className="text-[9px] text-muted-foreground/50 mr-1">{totalItems}</span>
        {expanded ? (
          <ChevronDown className="w-3.5 h-3.5 shrink-0 opacity-50 group-hover:opacity-100 transition-opacity" />
        ) : (
          <ChevronRight className="w-3.5 h-3.5 shrink-0 opacity-50 group-hover:opacity-100 transition-opacity" />
        )}
      </button>
      <div
        className={`overflow-hidden transition-all duration-200 ease-in-out ${
          expanded ? "max-h-[5000px] opacity-100" : "max-h-0 opacity-0"
        }`}
      >
        {group.subSections.map((sub) => {
          // If group has only one sub-section, skip the sub-section header
          if (group.subSections.length === 1) {
            return sub.items.map((item) => (
              <NavItem
                key={item.href}
                href={item.href}
                icon={item.icon}
                label={item.label}
                active={currentPath === item.href || currentPath.startsWith(item.href + "/")}
                onClick={onNavClick}
                isFavorite={favorites.includes(item.href)}
                onToggleFavorite={onToggleFavorite}
              />
            ));
          }
          return (
            <SubSectionNav
              key={sub.id}
              sub={sub}
              expanded={!!expandedSubs[sub.id]}
              onToggle={() => onToggleSub(sub.id)}
              currentPath={currentPath}
              onNavClick={onNavClick}
              favorites={favorites}
              onToggleFavorite={onToggleFavorite}
            />
          );
        })}
      </div>
    </div>
  );
}

// ─── Favorites Bar ──────────────────────────────────────────────────────────

function FavoritesBar({
  favorites,
  recentPaths,
  currentPath,
  onNavClick,
}: {
  favorites: string[];
  recentPaths: string[];
  currentPath: string;
  onNavClick: () => void;
}) {
  const favoriteItems = favorites
    .map((href) => ALL_NAV_ITEMS.find((item) => item.href === href))
    .filter(Boolean) as (NavItemDef & { groupLabel: string; subLabel: string })[];

  const recentItems = recentPaths
    .filter((href) => !favorites.includes(href))
    .slice(0, 5)
    .map((href) => ALL_NAV_ITEMS.find((item) => item.href === href))
    .filter(Boolean) as (NavItemDef & { groupLabel: string; subLabel: string })[];

  if (favoriteItems.length === 0 && recentItems.length === 0) return null;

  return (
    <div className="border-b border-border/50 pb-1 mb-1">
      {favoriteItems.length > 0 && (
        <div>
          <div className="flex items-center gap-1.5 px-4 py-1.5">
            <Pin className="w-3 h-3 text-amber-400/70" />
            <span className="text-[9px] font-display tracking-widest text-muted-foreground/60 uppercase">
              Pinned
            </span>
          </div>
          {favoriteItems.map((item) => (
            <Link key={item.href} href={item.href} onClick={onNavClick}>
              <div
                className={`flex items-center gap-2.5 pl-8 pr-4 py-1.5 font-display tracking-wider text-[11px] transition-colors min-h-[30px] ${
                  currentPath === item.href || currentPath.startsWith(item.href + "/")
                    ? "bg-primary/20 text-primary border-l-2 border-primary"
                    : "hover:bg-secondary text-muted-foreground hover:text-foreground"
                }`}
              >
                <item.icon className="w-3.5 h-3.5 shrink-0" />
                <span className="truncate">{item.label}</span>
              </div>
            </Link>
          ))}
        </div>
      )}
      {recentItems.length > 0 && (
        <div>
          <div className="flex items-center gap-1.5 px-4 py-1.5">
            <History className="w-3 h-3 text-muted-foreground/50" />
            <span className="text-[9px] font-display tracking-widest text-muted-foreground/60 uppercase">
              Recent
            </span>
          </div>
          {recentItems.map((item) => (
            <Link key={item.href} href={item.href} onClick={onNavClick}>
              <div
                className={`flex items-center gap-2.5 pl-8 pr-4 py-1.5 font-display tracking-wider text-[11px] transition-colors min-h-[30px] ${
                  currentPath === item.href || currentPath.startsWith(item.href + "/")
                    ? "bg-primary/20 text-primary border-l-2 border-primary"
                    : "hover:bg-secondary/50 text-muted-foreground/60 hover:text-foreground"
                }`}
              >
                <item.icon className="w-3.5 h-3.5 shrink-0" />
                <span className="truncate">{item.label}</span>
              </div>
            </Link>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Search Overlay ─────────────────────────────────────────────────────────

function NavSearch({
  open,
  onClose,
  currentPath,
  onNavigate,
}: {
  open: boolean;
  onClose: () => void;
  currentPath: string;
  onNavigate: (href: string) => void;
}) {
  const [query, setQuery] = useState("");
  const inputRef = useRef<HTMLInputElement>(null);

  useEffect(() => {
    if (open) {
      setQuery("");
      setTimeout(() => inputRef.current?.focus(), 100);
    }
  }, [open]);

  const results = useMemo(() => {
    if (!query.trim()) return [];
    const q = query.toLowerCase();
    return ALL_NAV_ITEMS.filter(
      (item) =>
        item.label.toLowerCase().includes(q) ||
        item.groupLabel.toLowerCase().includes(q) ||
        item.subLabel.toLowerCase().includes(q) ||
        item.href.toLowerCase().includes(q)
    ).slice(0, 12);
  }, [query]);

  if (!open) return null;

  return (
    <div className="absolute inset-0 z-50 bg-card/98 backdrop-blur-sm flex flex-col">
      <div className="p-3 border-b border-border">
        <div className="flex items-center gap-2">
          <Search className="w-4 h-4 text-muted-foreground shrink-0" />
          <input
            ref={inputRef}
            type="text"
            value={query}
            onChange={(e) => setQuery(e.target.value)}
            placeholder="Search pages..."
            className="flex-1 bg-transparent text-sm font-display tracking-wider outline-none placeholder:text-muted-foreground/40"
          />
          <button
            onClick={onClose}
            className="p-1 hover:bg-secondary rounded text-muted-foreground"
          >
            <X className="w-4 h-4" />
          </button>
        </div>
      </div>
      <div className="flex-1 overflow-y-auto py-2">
        {results.length === 0 && query.trim() && (
          <div className="px-4 py-8 text-center text-muted-foreground/50 text-xs font-display tracking-wider">
            NO RESULTS
          </div>
        )}
        {results.map((item) => (
          <button
            key={item.href}
            onClick={() => {
              onNavigate(item.href);
              onClose();
            }}
            className={`w-full flex items-center gap-3 px-4 py-2.5 text-left transition-colors ${
              currentPath === item.href
                ? "bg-primary/20 text-primary"
                : "hover:bg-secondary text-foreground"
            }`}
          >
            <item.icon className="w-4 h-4 shrink-0" />
            <div className="flex-1 min-w-0">
              <div className="text-[11px] font-display tracking-wider truncate">{item.label}</div>
              <div className="text-[9px] text-muted-foreground/50 tracking-wider truncate">
                {item.groupLabel} / {item.subLabel}
              </div>
            </div>
          </button>
        ))}
        {!query.trim() && (
          <div className="px-4 py-8 text-center text-muted-foreground/40 text-xs font-display tracking-wider">
            TYPE TO SEARCH ALL PAGES
          </div>
        )}
      </div>
    </div>
  );
}

// ─── AppShell Component ────────────────────────────────────────────────────────

interface AppShellProps {
  children: ReactNode;
  activePath?: string;
  headerActions?: ReactNode;
  contentClassName?: string;
}

export default function AppShell({
  children,
  activePath,
  headerActions,
  contentClassName = "p-4 sm:p-6 lg:p-8",
}: AppShellProps) {
  const isEmbedded = useIsEmbedded();
  const { user } = useAuth();
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [searchOpen, setSearchOpen] = useState(false);
  const [location, setLocation] = useLocation();
  const currentPath = activePath || location;

  // Role-based view override (stored in localStorage for demo/admin switching)
  const [roleOverride, setRoleOverride] = useState<UserRole | null>(() => {
    try {
      const stored = localStorage.getItem('ace-c3-role-override');
      return stored ? (stored as UserRole) : null;
    } catch { return null; }
  });
  const effectiveRole: UserRole = roleOverride || (user?.role as UserRole) || 'operator';
  const isAdmin = (user?.role as UserRole) === 'admin' || (user?.role as UserRole) === 'team_lead';

  const handleRoleSwitch = useCallback((role: UserRole) => {
    setRoleOverride(role);
    localStorage.setItem('ace-c3-role-override', role);
  }, []);

  const clearRoleOverride = useCallback(() => {
    setRoleOverride(null);
    localStorage.removeItem('ace-c3-role-override');
  }, []);

  // Filter nav groups based on effective role
  const filteredNavGroups = useMemo(() => {
    return NAV_GROUPS.filter(group => canAccessGroup(effectiveRole, group.id)).map(group => ({
      ...group,
      subSections: group.subSections.filter(sub => canAccessSubSection(effectiveRole, sub.id)),
    })).filter(group => group.subSections.length > 0);
  }, [effectiveRole]);

  // Favorites
  const [favorites, setFavorites] = useState<string[]>(() => loadState(FAVORITES_KEY, []));

  // Recent pages
  const [recentPaths, setRecentPaths] = useState<string[]>(() => loadState(RECENT_KEY, []));

  // Track recent navigation
  useEffect(() => {
    if (ALL_NAV_ITEMS.some((item) => item.href === currentPath)) {
      setRecentPaths((prev) => {
        const next = [currentPath, ...prev.filter((p) => p !== currentPath)].slice(0, 10);
        saveState(RECENT_KEY, next);
        return next;
      });
    }
  }, [currentPath]);

  const toggleFavorite = useCallback((href: string) => {
    setFavorites((prev) => {
      const next = prev.includes(href) ? prev.filter((f) => f !== href) : [...prev, href];
      saveState(FAVORITES_KEY, next);
      return next;
    });
  }, []);

  // Expanded groups state
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>(() => {
    const stored = loadState<Record<string, boolean>>(SIDEBAR_STATE_KEY, {});
    const activeGroup = findGroupForPath(currentPath);
    if (activeGroup) stored[activeGroup] = true;
    return stored;
  });

  // Expanded sub-sections state
  const [expandedSubs, setExpandedSubs] = useState<Record<string, boolean>>(() => {
    const stored = loadState<Record<string, boolean>>(SIDEBAR_SUB_STATE_KEY, {});
    const activeSub = findSubForPath(currentPath);
    if (activeSub) stored[activeSub] = true;
    return stored;
  });

  // Auto-expand active group/sub on route change
  useEffect(() => {
    const activeGroup = findGroupForPath(currentPath);
    const activeSub = findSubForPath(currentPath);
    if (activeGroup && !expandedGroups[activeGroup]) {
      setExpandedGroups((prev) => {
        const next = { ...prev, [activeGroup]: true };
        saveState(SIDEBAR_STATE_KEY, next);
        return next;
      });
    }
    if (activeSub && !expandedSubs[activeSub]) {
      setExpandedSubs((prev) => {
        const next = { ...prev, [activeSub]: true };
        saveState(SIDEBAR_SUB_STATE_KEY, next);
        return next;
      });
    }
  }, [currentPath]);

  const toggleGroup = useCallback((groupId: string) => {
    setExpandedGroups((prev) => {
      const next = { ...prev, [groupId]: !prev[groupId] };
      saveState(SIDEBAR_STATE_KEY, next);
      return next;
    });
  }, []);

  const toggleSub = useCallback((subId: string) => {
    setExpandedSubs((prev) => {
      const next = { ...prev, [subId]: !prev[subId] };
      saveState(SIDEBAR_SUB_STATE_KEY, next);
      return next;
    });
  }, []);

  // Close sidebar on route change (mobile)
  useEffect(() => {
    setSidebarOpen(false);
  }, [location]);

  // Keyboard shortcuts
  useEffect(() => {
    const handleKeyDown = (e: KeyboardEvent) => {
      if (e.key === "Escape") {
        if (searchOpen) setSearchOpen(false);
        else setSidebarOpen(false);
      }
      // Cmd/Ctrl+K to open search
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setSearchOpen((prev) => !prev);
      }
    };
    document.addEventListener("keydown", handleKeyDown);
    return () => document.removeEventListener("keydown", handleKeyDown);
  }, [searchOpen]);

  // Prevent body scroll when sidebar is open on mobile
  useEffect(() => {
    if (sidebarOpen) {
      document.body.style.overflow = "hidden";
    } else {
      document.body.style.overflow = "";
    }
    return () => {
      document.body.style.overflow = "";
    };
  }, [sidebarOpen]);

  const closeSidebar = () => setSidebarOpen(false);

  // Expand/collapse all helper
  const allExpanded = useMemo(
    () => NAV_GROUPS.every((g) => expandedGroups[g.id]),
    [expandedGroups]
  );

  const toggleAll = useCallback(() => {
    const newGroupState: Record<string, boolean> = {};
    const newSubState: Record<string, boolean> = {};
    const targetValue = !allExpanded;
    NAV_GROUPS.forEach((g) => {
      newGroupState[g.id] = targetValue;
      g.subSections.forEach((sub) => {
        newSubState[sub.id] = targetValue;
      });
    });
    // Always keep the active group/sub expanded
    const activeGroup = findGroupForPath(currentPath);
    const activeSub = findSubForPath(currentPath);
    if (activeGroup) newGroupState[activeGroup] = true;
    if (activeSub) newSubState[activeSub] = true;
    setExpandedGroups(newGroupState);
    setExpandedSubs(newSubState);
    saveState(SIDEBAR_STATE_KEY, newGroupState);
    saveState(SIDEBAR_SUB_STATE_KEY, newSubState);
  }, [allExpanded, currentPath]);

  // When embedded inside HubTabs, skip the shell wrapper entirely
  if (isEmbedded) {
    return <>{children}</>;
  }

  return (
    <div className="min-h-screen bg-background text-foreground flex">
      {/* Mobile backdrop */}
      {sidebarOpen && (
        <div
          className="fixed inset-0 bg-black/60 z-40 lg:hidden backdrop-blur-sm transition-opacity"
          onClick={closeSidebar}
          aria-hidden="true"
        />
      )}

      {/* Sidebar */}
      <aside
        className={`fixed inset-y-0 left-0 z-50 w-[280px] sm:w-64 bg-card border-r border-border transform transition-transform duration-300 ease-in-out lg:translate-x-0 ${
          sidebarOpen ? "translate-x-0" : "-translate-x-full"
        } overflow-y-auto`}
      >
        <div className="flex flex-col h-full relative">
          {/* Logo */}
          <div className="p-4 sm:p-5 border-b border-border sticky top-0 bg-card z-10">
            <div className="flex items-center justify-between">
              <Link href="/" className="flex items-center gap-3" onClick={closeSidebar}>
                <Cloud className="w-7 h-7 sm:w-8 sm:h-8 text-primary shrink-0" />
                <div className="flex flex-col min-w-0">
                  <span className="font-display text-lg sm:text-xl tracking-wider truncate">
                    ACE C3
                  </span>
                  <span className="text-[10px] sm:text-xs text-muted-foreground tracking-widest truncate">
                    <span className="text-primary/70">CYBER CAMPAIGN COMMAND</span>
                  </span>
                </div>
              </Link>
              {/* Close button on mobile */}
              <button
                className="lg:hidden p-2 -mr-2 hover:bg-secondary rounded-lg min-h-[44px] min-w-[44px] flex items-center justify-center"
                onClick={closeSidebar}
                aria-label="Close navigation"
              >
                <X className="w-5 h-5" />
              </button>
            </div>
          </div>

          {/* Search Bar */}
          <div className="px-3 pt-2">
            <button
              onClick={() => setSearchOpen(true)}
              className="w-full flex items-center gap-2 px-3 py-2 bg-secondary/50 hover:bg-secondary rounded-md text-muted-foreground/60 hover:text-muted-foreground transition-colors"
            >
              <Search className="w-3.5 h-3.5 shrink-0" />
              <span className="text-[11px] font-display tracking-wider flex-1 text-left">SEARCH...</span>
              <kbd className="hidden sm:inline text-[9px] bg-background/50 px-1.5 py-0.5 rounded border border-border/50 font-mono">
                ⌘K
              </kbd>
            </button>
          </div>

          {/* Navigation */}
          <nav className="flex-1 py-2 overflow-y-auto">
            {/* Favorites & Recent */}
            <FavoritesBar
              favorites={favorites}
              recentPaths={recentPaths}
              currentPath={currentPath}
              onNavClick={closeSidebar}
            />

            {/* Expand/Collapse All */}
            <div className="px-4 py-1.5 flex justify-end">
              <button
                onClick={toggleAll}
                className="text-[10px] text-muted-foreground hover:text-foreground font-display tracking-wider transition-colors"
              >
                {allExpanded ? "COLLAPSE ALL" : "EXPAND ALL"}
              </button>
            </div>

            {filteredNavGroups.map((group) => (
              <NavGroupSection
                key={group.id}
                group={group}
                expanded={!!expandedGroups[group.id]}
                onToggle={() => toggleGroup(group.id)}
                expandedSubs={expandedSubs}
                onToggleSub={toggleSub}
                currentPath={currentPath}
                onNavClick={closeSidebar}
                favorites={favorites}
                onToggleFavorite={toggleFavorite}
              />
            ))}
          </nav>

          {/* User Info */}
          <div className="p-3 sm:p-4 border-t border-border sticky bottom-0 bg-card">
            {/* Role Switcher (admin/team_lead only) */}
            {isAdmin && (
              <div className="mb-3">
                <div className="flex items-center justify-between mb-1.5">
                  <span className="text-[9px] font-display tracking-widest text-muted-foreground/60 uppercase">View As</span>
                  {roleOverride && (
                    <button
                      onClick={clearRoleOverride}
                      className="text-[9px] text-primary/70 hover:text-primary font-display tracking-wider"
                    >RESET</button>
                  )}
                </div>
                <select
                  value={effectiveRole}
                  onChange={(e) => handleRoleSwitch(e.target.value as UserRole)}
                  className="w-full bg-secondary/50 border border-border/50 rounded px-2 py-1.5 text-[11px] font-display tracking-wider text-foreground focus:outline-none focus:ring-1 focus:ring-primary/50"
                >
                  {ALL_ROLES.map((r) => (
                    <option key={r.value} value={r.value}>{r.label}</option>
                  ))}
                </select>
              </div>
            )}
            <div className="flex items-center gap-3 mb-3">
              <div className="w-9 h-9 sm:w-10 sm:h-10 bg-primary/20 flex items-center justify-center shrink-0">
                <span className="font-display text-primary text-sm sm:text-base">
                  {(user?.name || 'A').charAt(0).toUpperCase()}
                </span>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">{user?.name || 'Operator'}</p>
                <div className={`inline-flex items-center px-1.5 py-0.5 text-[9px] font-display tracking-wider border rounded ${getRoleBadgeClass(effectiveRole)}`}>
                  {getRoleDisplayName(effectiveRole).toUpperCase()}
                </div>
              </div>
            </div>
            <Link href="/" onClick={closeSidebar}>
              <Button
                variant="outline"
                size="sm"
                className="w-full font-display tracking-wider min-h-[44px]"
              >
                <LogOut className="w-4 h-4 mr-2" />
                EXIT
              </Button>
            </Link>
          </div>

          {/* Search Overlay */}
          <NavSearch
            open={searchOpen}
            onClose={() => setSearchOpen(false)}
            currentPath={currentPath}
            onNavigate={(href) => {
              setLocation(href);
              closeSidebar();
            }}
          />
        </div>
      </aside>

      {/* Main Content */}
      <main className="flex-1 lg:ml-64 min-w-0">
        {/* Mobile Header Bar */}
        <div className="sticky top-0 z-30 lg:hidden bg-card/95 backdrop-blur-sm border-b border-border">
          <div className="flex items-center justify-between px-3 py-2 min-h-[56px]">
            <button
              className="p-2 hover:bg-secondary rounded-lg min-h-[44px] min-w-[44px] flex items-center justify-center"
              onClick={() => setSidebarOpen(true)}
              aria-label="Open navigation"
            >
              <Menu className="w-5 h-5" />
            </button>
            <div className="flex items-center gap-2 min-w-0 flex-1 justify-center">
              <Cloud className="w-5 h-5 text-primary shrink-0" />
              <span className="font-display text-sm tracking-wider truncate">
                ACE C3
              </span>
            </div>
            {headerActions ? (
              <div className="flex items-center gap-1">{headerActions}</div>
            ) : (
              <div className="w-[44px]" /> /* Spacer for centering */
            )}
          </div>
        </div>

        {/* Page Content */}
        <div className={contentClassName}>{children}</div>
      </main>
    </div>
  );
}
