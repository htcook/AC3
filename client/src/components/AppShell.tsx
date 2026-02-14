import { Button } from "@/components/ui/button";
import { Link, useLocation } from "wouter";
import {
  Activity,
  Target,
  Key,
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
  ChevronRight,
  Radar,
  Rocket,
  Scan,
  Eye,
  BarChart3,
  Brain,
  Sparkles,
  Layers,
  Radio,
  Workflow,
  ShieldCheck,
  Palette,
  Bug,
} from "lucide-react";
import { useState, useEffect, ReactNode } from "react";

const NAV_ITEMS = [
  { href: "/dashboard", icon: Activity, label: "DASHBOARD" },
  { href: "/engagements", icon: Briefcase, label: "ENGAGEMENTS" },
  { href: "/credentials", icon: Key, label: "CREDENTIALS" },
  { href: "/adversaries", icon: Target, label: "ADVERSARIES" },
  { href: "/agents", icon: Cpu, label: "AGENTS" },
  { href: "/campaigns", icon: Zap, label: "CAMPAIGNS" },
  { href: "/campaign-execution", icon: Activity, label: "CAMPAIGN EXEC" },
  { href: "/rule-validator", icon: ShieldCheck, label: "RULE VALIDATOR" },
  { href: "/detection-coverage", icon: Target, label: "COVERAGE MATRIX" },
  { href: "/kev-catalog", icon: Bug, label: "CISA KEV" },
  { href: "/post-engagement-report", icon: FileText, label: "ENGAGEMENT REPORT" },
  { href: "/gophish", icon: Zap, label: "GOPHISH" },
  { href: "/landing-page-builder", icon: Palette, label: "PAGE BUILDER" },
  { href: "/team", icon: Users, label: "TEAM" },
  { href: "/activity", icon: FileText, label: "ACTIVITY" },
];

const OSINT_ITEMS = [
  { href: "/domain-intel", icon: Brain, label: "DOMAIN INTEL" },
  { href: "/domain-recon", icon: Radar, label: "DOMAIN RECON" },
  { href: "/osint-monitor", icon: Eye, label: "OSINT MONITOR" },
  { href: "/ioc-feed", icon: Radio, label: "IOC FEED" },
  { href: "/template-generator", icon: Sparkles, label: "TEMPLATE GEN" },
  { href: "/campaign-wizard", icon: Rocket, label: "LAUNCH WIZARD" },
  { href: "/engagement-pipeline", icon: Workflow, label: "AUTO PIPELINE" },
];

const THREAT_INTEL_ITEMS = [
  { href: "/threat-actors", icon: Shield, label: "THREAT ACTORS" },
  { href: "/apt-library", icon: Shield, label: "APT SCENARIOS" },
  { href: "/abilities-library", icon: Layers, label: "ABILITIES" },
  { href: "/ttp-knowledge", icon: Brain, label: "TTP KNOWLEDGE" },
  { href: "/compliance", icon: FileText, label: "COMPLIANCE" },
  { href: "/infra-reference", icon: Globe2, label: "INFRASTRUCTURE" },
];

const GUIDE_ITEMS = [
  { href: "/guide/gophish", icon: BookOpen, label: "GOPHISH GUIDE" },
  { href: "/guide/caldera", icon: BookOpen, label: "CALDERA GUIDE" },
  { href: "/templates", icon: FileText, label: "TEMPLATE LIBRARY" },
];

const REPORT_ITEMS = [
  { href: "/reports/generate", icon: BarChart3, label: "REPORT GENERATOR" },
  { href: "/reports/security", icon: FileText, label: "SECURITY REPORT" },
];

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
        className={`flex items-center gap-3 px-4 py-3 font-display tracking-wider text-sm transition-colors min-h-[44px] ${
          active
            ? "bg-primary/20 text-primary border-l-2 border-primary"
            : "hover:bg-secondary"
        }`}
      >
        <Icon className="w-4 h-4 shrink-0" />
        <span className="truncate">{label}</span>
      </div>
    </Link>
  );
}

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
          <div className="p-4 sm:p-6 border-b border-border sticky top-0 bg-card z-10">
            <div className="flex items-center justify-between">
              <Link href="/" className="flex items-center gap-3" onClick={closeSidebar}>
                <Cloud className="w-7 h-7 sm:w-8 sm:h-8 text-primary shrink-0" />
                <div className="flex flex-col min-w-0">
                  <span className="font-display text-lg sm:text-xl tracking-wider truncate">
                    ACE OF CLOUD
                  </span>
                  <span className="text-[10px] sm:text-xs text-muted-foreground tracking-widest truncate">
                    C3 —{" "}
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
          <nav className="flex-1 p-3 sm:p-4 space-y-1 overflow-y-auto">
            {NAV_ITEMS.map((item) => (
              <NavItem
                key={item.href}
                href={item.href}
                icon={item.icon}
                label={item.label}
                active={currentPath === item.href || currentPath.startsWith(item.href + "/")}
                onClick={closeSidebar}
              />
            ))}

            <div className="border-t border-border my-3 pt-3">
              <p className="text-xs text-muted-foreground tracking-wider px-4 mb-2">
                OSINT & CAMPAIGNS
              </p>
              {OSINT_ITEMS.map((item) => (
                <NavItem
                  key={item.href}
                  href={item.href}
                  icon={item.icon}
                  label={item.label}
                  active={currentPath === item.href || currentPath.startsWith(item.href + "/")}
                  onClick={closeSidebar}
                />
              ))}
            </div>

            <div className="border-t border-border my-3 pt-3">
              <p className="text-xs text-muted-foreground tracking-wider px-4 mb-2">
                THREAT INTEL
              </p>
              {THREAT_INTEL_ITEMS.map((item) => (
                <NavItem
                  key={item.href}
                  href={item.href}
                  icon={item.icon}
                  label={item.label}
                  active={currentPath === item.href}
                  onClick={closeSidebar}
                />
              ))}
            </div>

            <div className="border-t border-border my-3 pt-3">
              <p className="text-xs text-muted-foreground tracking-wider px-4 mb-2">
                GUIDES
              </p>
              {GUIDE_ITEMS.map((item) => (
                <NavItem
                  key={item.href}
                  href={item.href}
                  icon={item.icon}
                  label={item.label}
                  active={currentPath === item.href}
                  onClick={closeSidebar}
                />
              ))}
            </div>

            <div className="border-t border-border my-3 pt-3">
              <p className="text-xs text-muted-foreground tracking-wider px-4 mb-2">
                REPORTS
              </p>
              {REPORT_ITEMS.map((item) => (
                <NavItem
                  key={item.href}
                  href={item.href}
                  icon={item.icon}
                  label={item.label}
                  active={currentPath === item.href}
                  onClick={closeSidebar}
                />
              ))}
            </div>
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
                C3 PLATFORM
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
