import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
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
  ArrowUpDown,
  Package,
} from "lucide-react";
import { useState, useEffect, ReactNode, useCallback, useMemo } from "react";

// ─── Types ─────────────────────────────────────────────────────────────────────

interface NavItemDef {
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  label: string;
}

interface NavGroup {
  id: string;
  label: string;
  icon: React.ComponentType<{ className?: string }>;
  items: NavItemDef[];
}

// ─── Navigation Structure ──────────────────────────────────────────────────────

const NAV_GROUPS: NavGroup[] = [
  {
    id: "operations",
    label: "OPERATIONS",
    icon: Swords,
    items: [
      { href: "/dashboard", icon: Activity, label: "DASHBOARD" },
      { href: "/engagements", icon: Briefcase, label: "ENGAGEMENT MGR" },
      { href: "/engagement-timeline", icon: Workflow, label: "KILL CHAIN" },
      { href: "/agents", icon: Cpu, label: "AGENTS" },
      { href: "/campaign-execution", icon: Activity, label: "CAMPAIGN EXEC" },
      { href: "/rule-validator", icon: ShieldCheck, label: "RULE VALIDATOR" },
      { href: "/detection-coverage", icon: Target, label: "COVERAGE MATRIX" },
      { href: "/emulation-playbooks", icon: BookMarked, label: "EMULATION PLAYBOOKS" },
      { href: "/purple-team", icon: Eye, label: "PURPLE TEAM" },
      { href: "/attack-paths", icon: GitBranch, label: "ATTACK PATHS" },
      { href: "/scoring", icon: Crosshair, label: "RISK SCORING" },
    ],
  },
  {
    id: "phishing",
    label: "PHISHING & EXPLOITS",
    icon: Zap,
    items: [
      { href: "/phishing-ops", icon: Zap, label: "PHISHING OPS" },
      { href: "/exploit-catalog", icon: Crosshair, label: "EXPLOIT CATALOG" },
      { href: "/validation-engine", icon: FlaskConical, label: "VALIDATION ENGINE" },
      { href: "/msf-servers", icon: Server, label: "C2 SERVERS" },
      { href: "/ssh-keys", icon: KeyRound, label: "SSH KEYS" },
      { href: "/msf-sessions", icon: Terminal, label: "LIVE SESSIONS" },
      { href: "/session-recordings", icon: Video, label: "RECORDINGS" },
      { href: "/post-exploit-playbooks", icon: ScrollText, label: "POST-EXPLOIT" },
      { href: "/file-transfers", icon: ArrowUpDown, label: "FILE TRANSFERS" },
      { href: "/payload-generator", icon: Package, label: "PAYLOAD GENERATOR" },
      { href: "/landing-page-builder", icon: Palette, label: "PAGE BUILDER" },
      { href: "/template-generator", icon: Sparkles, label: "TEMPLATE GEN" },
      { href: "/campaign-wizard", icon: Rocket, label: "LAUNCH WIZARD" },
      { href: "/engagement-pipeline", icon: Workflow, label: "AUTO PIPELINE" },
    ],
  },
  {
    id: "intelligence",
    label: "INTELLIGENCE",
    icon: Search,
    items: [
      { href: "/vuln-intel", icon: Bug, label: "VULN INTEL" },
      { href: "/threat-intel-hub", icon: Shield, label: "THREAT INTEL HUB" },
      { href: "/threat-catalog", icon: Database, label: "THREAT CATALOG" },
      { href: "/darkweb-intel", icon: AlertTriangle, label: "DARKWEB INTEL" },
      { href: "/ioc-feed", icon: Radio, label: "IOC FEED" },
      { href: "/domain-intel", icon: Brain, label: "DOMAIN INTEL" },
      { href: "/scan-compare", icon: ArrowLeftRight, label: "SCAN COMPARE" },
      { href: "/bug-bounty", icon: Bug, label: "BUG BOUNTY HUB" },
      { href: "/stix-export", icon: FileJson, label: "STIX/TAXII EXPORT" },
    ],
  },
  {
    id: "knowledge",
    label: "KNOWLEDGE BASE",
    icon: GraduationCap,
    items: [
      { href: "/campaign-archetypes", icon: Layers, label: "ARCHETYPES" },
      { href: "/abilities-library", icon: Layers, label: "ABILITIES" },
      { href: "/ttp-knowledge", icon: Brain, label: "TTP KNOWLEDGE" },
      { href: "/compliance", icon: FileText, label: "COMPLIANCE" },
      { href: "/infra-reference", icon: Globe2, label: "INFRASTRUCTURE" },
    ],
  },
  {
    id: "reports",
    label: "REPORTS & GUIDES",
    icon: BarChart3,
    items: [
      { href: "/post-engagement-report", icon: FileText, label: "ENGAGEMENT REPORT" },
      { href: "/reports/generate", icon: BarChart3, label: "REPORT GENERATOR" },
      { href: "/bia-report", icon: ClipboardCheck, label: "AUTO-BIA REPORT" },
      { href: "/guide/gophish", icon: BookOpen, label: "PHISHING OPS GUIDE" },
      { href: "/guide/caldera", icon: BookOpen, label: "EMULATION GUIDE" },
      { href: "/templates", icon: FileText, label: "TEMPLATE LIBRARY" },
    ],
  },
  {
    id: "admin",
    label: "ADMIN",
    icon: Settings,
    items: [
      { href: "/team", icon: Users, label: "TEAM" },
      { href: "/activity", icon: FileText, label: "ACTIVITY" },
      { href: "/evidence", icon: Archive, label: "EVIDENCE LOCKER" },
      { href: "/webhooks", icon: Webhook, label: "WEBHOOKS" },
    ],
  },
];

// ─── Storage Key ───────────────────────────────────────────────────────────────

const SIDEBAR_STATE_KEY = "ace-c3-sidebar-groups";

function loadExpandedGroups(): Record<string, boolean> {
  try {
    const stored = localStorage.getItem(SIDEBAR_STATE_KEY);
    if (stored) return JSON.parse(stored);
  } catch {}
  return {};
}

function saveExpandedGroups(state: Record<string, boolean>) {
  try {
    localStorage.setItem(SIDEBAR_STATE_KEY, JSON.stringify(state));
  } catch {}
}

// ─── Find which group contains a path ──────────────────────────────────────────

function findGroupForPath(path: string): string | null {
  for (const group of NAV_GROUPS) {
    if (group.items.some((item) => path === item.href || path.startsWith(item.href + "/"))) {
      return group.id;
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
}: {
  href: string;
  icon: React.ComponentType<{ className?: string }>;
  label: string;
  active?: boolean;
  onClick?: () => void;
}) {
  return (
    <Link href={href} onClick={onClick}>
      <div
        className={`flex items-center gap-3 pl-8 pr-4 py-2.5 font-display tracking-wider text-xs transition-colors min-h-[38px] ${
          active
            ? "bg-primary/20 text-primary border-l-2 border-primary"
            : "hover:bg-secondary text-muted-foreground hover:text-foreground"
        }`}
      >
        <Icon className="w-3.5 h-3.5 shrink-0" />
        <span className="truncate">{label}</span>
      </div>
    </Link>
  );
}

// ─── NavGroupSection Component ─────────────────────────────────────────────────

function NavGroupSection({
  group,
  expanded,
  onToggle,
  currentPath,
  onNavClick,
}: {
  group: NavGroup;
  expanded: boolean;
  onToggle: () => void;
  currentPath: string;
  onNavClick: () => void;
}) {
  const GroupIcon = group.icon;
  const hasActiveItem = group.items.some(
    (item) => currentPath === item.href || currentPath.startsWith(item.href + "/")
  );

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
        {expanded ? (
          <ChevronDown className="w-3.5 h-3.5 shrink-0 opacity-50 group-hover:opacity-100 transition-opacity" />
        ) : (
          <ChevronRight className="w-3.5 h-3.5 shrink-0 opacity-50 group-hover:opacity-100 transition-opacity" />
        )}
      </button>
      <div
        className={`overflow-hidden transition-all duration-200 ease-in-out ${
          expanded ? "max-h-[600px] opacity-100" : "max-h-0 opacity-0"
        }`}
      >
        {group.items.map((item) => (
          <NavItem
            key={item.href}
            href={item.href}
            icon={item.icon}
            label={item.label}
            active={currentPath === item.href || currentPath.startsWith(item.href + "/")}
            onClick={onNavClick}
          />
        ))}
      </div>
    </div>
  );
}

// ─── AppShell Component ────────────────────────────────────────────────────────

interface AppShellProps {
  children: ReactNode;
  /** Current page path for active nav highlighting. If not provided, uses useLocation. */
  activePath?: string;
  /** Additional header content (right side of mobile header) */
  headerActions?: ReactNode;
  /** Main content padding override. Default: "p-4 sm:p-6 lg:p-8" */
  contentClassName?: string;
}

export default function AppShell({
  children,
  activePath,
  headerActions,
  contentClassName = "p-4 sm:p-6 lg:p-8",
}: AppShellProps) {
  const [sidebarOpen, setSidebarOpen] = useState(false);
  const [location] = useLocation();
  const currentPath = activePath || location;

  // Expanded groups state — initialize from localStorage + auto-expand active group
  const [expandedGroups, setExpandedGroups] = useState<Record<string, boolean>>(() => {
    const stored = loadExpandedGroups();
    const activeGroup = findGroupForPath(currentPath);
    if (activeGroup) {
      stored[activeGroup] = true;
    }
    return stored;
  });

  // Auto-expand the group containing the active page when route changes
  useEffect(() => {
    const activeGroup = findGroupForPath(currentPath);
    if (activeGroup && !expandedGroups[activeGroup]) {
      setExpandedGroups((prev) => {
        const next = { ...prev, [activeGroup]: true };
        saveExpandedGroups(next);
        return next;
      });
    }
  }, [currentPath]);

  const toggleGroup = useCallback((groupId: string) => {
    setExpandedGroups((prev) => {
      const next = { ...prev, [groupId]: !prev[groupId] };
      saveExpandedGroups(next);
      return next;
    });
  }, []);

  // Close sidebar on route change (mobile)
  useEffect(() => {
    setSidebarOpen(false);
  }, [location]);

  // Close sidebar on escape key
  useEffect(() => {
    const handleEscape = (e: KeyboardEvent) => {
      if (e.key === "Escape") setSidebarOpen(false);
    };
    document.addEventListener("keydown", handleEscape);
    return () => document.removeEventListener("keydown", handleEscape);
  }, []);

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
    const newState: Record<string, boolean> = {};
    const targetValue = !allExpanded;
    NAV_GROUPS.forEach((g) => {
      newState[g.id] = targetValue;
    });
    // Always keep the active group expanded
    const activeGroup = findGroupForPath(currentPath);
    if (activeGroup) newState[activeGroup] = true;
    setExpandedGroups(newState);
    saveExpandedGroups(newState);
  }, [allExpanded, currentPath]);

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
        <div className="flex flex-col h-full">
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

          {/* Navigation */}
          <nav className="flex-1 py-2 overflow-y-auto">
            {/* Expand/Collapse All */}
            <div className="px-4 py-1.5 flex justify-end">
              <button
                onClick={toggleAll}
                className="text-[10px] text-muted-foreground hover:text-foreground font-display tracking-wider transition-colors"
              >
                {allExpanded ? "COLLAPSE ALL" : "EXPAND ALL"}
              </button>
            </div>

            {NAV_GROUPS.map((group) => (
              <NavGroupSection
                key={group.id}
                group={group}
                expanded={!!expandedGroups[group.id]}
                onToggle={() => toggleGroup(group.id)}
                currentPath={currentPath}
                onNavClick={closeSidebar}
              />
            ))}
          </nav>

          {/* User Info */}
          <div className="p-3 sm:p-4 border-t border-border sticky bottom-0 bg-card">
            <div className="flex items-center gap-3 mb-3">
              <div className="w-9 h-9 sm:w-10 sm:h-10 bg-primary/20 flex items-center justify-center shrink-0">
                <span className="font-display text-primary text-sm sm:text-base">A</span>
              </div>
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate">Admin</p>
                <p className="text-xs text-muted-foreground uppercase">ADMIN</p>
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
