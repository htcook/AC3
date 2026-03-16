import { useAuth } from "@/_core/hooks/useAuth";
import { EmbedProvider } from "@/contexts/EmbedContext";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import { getLoginUrl } from "@/const";
import { useIsMobile } from "@/hooks/useMobile";
import {
  LogOut, PanelLeft, Crosshair, ChevronDown, ChevronRight,
  Home, Menu, X, ChevronsLeft, ChevronsRight,
} from "lucide-react";
import { FIPSIndicator } from "./FIPSIndicator";
import { CommandPaletteTrigger } from "./CommandPalette";
import { useEngagement } from "@/contexts/EngagementContext";
import { createPortal } from "react-dom";
import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useLocation } from "wouter";
import { DashboardLayoutSkeleton } from "./DashboardLayoutSkeleton";
import { Button } from "./ui/button";
import { ScrollArea } from "./ui/scroll-area";
import {
  Tooltip,
  TooltipContent,
  TooltipTrigger,
} from "./ui/tooltip";
import { sidebarNavGroups, getFilteredNavGroups, type NavGroup, type UserRole } from "@/lib/sidebar-nav";

// ─── Constants ───────────────────────────────────────────────────────────────

const SIDEBAR_MODE_KEY = "sidebar-mode";
const RAIL_WIDTH = 56;       // px — icon rail width
const EXPANDED_WIDTH = 260;  // px — expanded sidebar width

type SidebarMode = "rail" | "expanded";

// ─── Main Layout ─────────────────────────────────────────────────────────────

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const { loading, user } = useAuth();

  if (loading) {
    return <DashboardLayoutSkeleton />;
  }

  if (!user) {
    return (
      <div className="flex items-center justify-center min-h-screen">
        <div className="flex flex-col items-center gap-8 p-8 max-w-md w-full">
          <div className="flex flex-col items-center gap-6">
            <h1 className="text-2xl font-semibold tracking-tight text-center">
              Sign in to continue
            </h1>
            <p className="text-sm text-muted-foreground text-center max-w-sm">
              Access to this dashboard requires authentication. Continue to launch the login flow.
            </p>
          </div>
          <Button
            onClick={() => { window.location.href = getLoginUrl(); }}
            size="lg"
            className="w-full shadow-lg hover:shadow-xl transition-all"
          >
            Sign in
          </Button>
        </div>
      </div>
    );
  }

  return (
    <DashboardLayoutContent>
      <EmbedProvider>{children}</EmbedProvider>
    </DashboardLayoutContent>
  );
}

// ─── Layout Content ──────────────────────────────────────────────────────────

function DashboardLayoutContent({ children }: { children: React.ReactNode }) {
  const { user, logout } = useAuth();
  const filteredNavGroups = useMemo(
    () => getFilteredNavGroups(user?.role),
    [user?.role]
  );
  const [location, setLocation] = useLocation();
  const isMobile = useIsMobile();

  // Sidebar mode: rail (icons only) or expanded
  const [mode, setMode] = useState<SidebarMode>(() => {
    const saved = localStorage.getItem(SIDEBAR_MODE_KEY);
    return (saved === "expanded" ? "expanded" : "rail") as SidebarMode;
  });

  // Flyout state for rail mode: which group is hovered/open
  const [flyoutGroupId, setFlyoutGroupId] = useState<string | null>(null);
  const flyoutTimeout = useRef<ReturnType<typeof setTimeout> | null>(null);

  // Mobile drawer state
  const [mobileOpen, setMobileOpen] = useState(false);

  // Close mobile drawer on route change
  useEffect(() => {
    setMobileOpen(false);
  }, [location]);

  // Prevent body scroll when mobile drawer is open
  useEffect(() => {
    if (mobileOpen) {
      document.body.style.overflow = "hidden";
      return () => { document.body.style.overflow = ""; };
    }
  }, [mobileOpen]);

  // Persist mode
  useEffect(() => {
    localStorage.setItem(SIDEBAR_MODE_KEY, mode);
  }, [mode]);

  const toggleMode = useCallback(() => {
    setMode(prev => prev === "rail" ? "expanded" : "rail");
    setFlyoutGroupId(null);
  }, []);

  // Find active group and item
  const activeGroupId = useMemo(() => {
    for (const group of filteredNavGroups) {
      if (group.items.some(i => location === i.path || location.startsWith(i.path + "/"))) {
        return group.id;
      }
    }
    return null;
  }, [location, filteredNavGroups]);

  const activeLabel = useMemo(() => {
    for (const group of filteredNavGroups) {
      const item = group.items.find(i => location === i.path || location.startsWith(i.path + "/"));
      if (item) return item.label;
    }
    return "Home";
  }, [location, filteredNavGroups]);

  // Flyout handlers
  const openFlyout = useCallback((groupId: string) => {
    if (flyoutTimeout.current) clearTimeout(flyoutTimeout.current);
    setFlyoutGroupId(groupId);
  }, []);

  const closeFlyout = useCallback(() => {
    flyoutTimeout.current = setTimeout(() => setFlyoutGroupId(null), 200);
  }, []);

  const cancelCloseFlyout = useCallback(() => {
    if (flyoutTimeout.current) clearTimeout(flyoutTimeout.current);
  }, []);

  // Close flyout on route change
  useEffect(() => {
    setFlyoutGroupId(null);
  }, [location]);

  // ─── Mobile Drawer ──────────────────────────────────────────────────────────

  if (isMobile) {
    return (
      <div className="flex flex-col min-h-screen">
        {/* Mobile header */}
        <div className="flex border-b h-14 items-center justify-between bg-background/95 px-3 backdrop-blur sticky top-0 z-40">
          <div className="flex items-center gap-2">
            <button
              onClick={() => setMobileOpen(true)}
              className="h-11 w-11 flex items-center justify-center rounded-lg hover:bg-accent transition-colors active:bg-accent/70"
              aria-label="Open navigation"
            >
              <Menu className="h-5 w-5" />
            </button>
            <span className="font-semibold text-sm tracking-tight truncate">{activeLabel}</span>
          </div>
          <div className="flex items-center gap-1">
            <CommandPaletteTrigger collapsed />
          </div>
        </div>

        {/* Mobile drawer overlay */}
        {mobileOpen && (
          <div className="fixed inset-0 z-50 flex">
            <div className="fixed inset-0 bg-black/50 backdrop-blur-sm" onClick={() => setMobileOpen(false)} />
            <div className="relative w-[85vw] max-w-[320px] bg-background border-r flex flex-col h-full animate-in slide-in-from-left duration-200 shadow-2xl">
              <div className="h-14 flex items-center justify-between px-4 border-b shrink-0">
                <span className="font-semibold text-sm tracking-tight">AC3</span>
                <button
                  onClick={() => setMobileOpen(false)}
                  className="h-10 w-10 flex items-center justify-center rounded-lg hover:bg-accent active:bg-accent/70"
                  aria-label="Close navigation"
                >
                  <X className="h-5 w-5" />
                </button>
              </div>
              <div className="px-3 py-2 shrink-0">
                <CommandPaletteTrigger />
              </div>
              <EngagementSwitcher isCollapsed={false} />
              <ScrollArea className="flex-1">
                <MobileNavList location={location} setLocation={(p) => { setLocation(p); setMobileOpen(false); }} filteredNavGroups={filteredNavGroups} />
              </ScrollArea>
              <SidebarFooterSection user={user} logout={logout} isCollapsed={false} />
            </div>
          </div>
        )}

        <main className="flex-1 overflow-x-hidden max-w-full">
          <div className="p-3 sm:p-4">{children}</div>
        </main>
      </div>
    );
  }

  // ─── Desktop: Rail Mode ──────────────────────────────────────────────────────

  if (mode === "rail") {
    return (
      <div className="flex min-h-screen">
        {/* Icon Rail */}
        <div
          className="fixed top-0 left-0 h-screen flex flex-col bg-background border-r z-40"
          style={{ width: RAIL_WIDTH }}
        >
          {/* Logo / toggle */}
          <div className="h-14 flex items-center justify-center border-b shrink-0">
            <Tooltip>
              <TooltipTrigger asChild>
                <button
                  onClick={toggleMode}
                  className="h-9 w-9 flex items-center justify-center rounded-lg hover:bg-accent transition-colors"
                >
                  <ChevronsRight className="h-4 w-4 text-muted-foreground" />
                </button>
              </TooltipTrigger>
              <TooltipContent side="right" sideOffset={8}>Expand sidebar</TooltipContent>
            </Tooltip>
          </div>

          {/* Search trigger */}
          <div className="py-2 flex justify-center shrink-0">
            <CommandPaletteTrigger collapsed />
          </div>

          {/* Engagement indicator */}
          <div className="shrink-0">
            <EngagementSwitcher isCollapsed />
          </div>

          {/* Nav group icons — NO ScrollArea wrapping to prevent flyout clipping */}
          <div className="flex-1 min-h-0 overflow-y-auto overflow-x-visible scrollbar-thin scrollbar-thumb-border">
            <div className="flex flex-col items-center gap-0.5 py-1">
              {/* Home */}
              <Tooltip>
                <TooltipTrigger asChild>
                  <button
                    onClick={() => setLocation("/home")}
                    className={`h-10 w-10 flex items-center justify-center rounded-lg transition-colors ${
                      location === "/" || location === "/home"
                        ? "bg-accent text-primary"
                        : "text-muted-foreground hover:bg-accent/50 hover:text-foreground"
                    }`}
                  >
                    <Home className="h-4.5 w-4.5" />
                  </button>
                </TooltipTrigger>
                <TooltipContent side="right" sideOffset={8}>Home</TooltipContent>
              </Tooltip>

              {/* Group icons */}
              {filteredNavGroups.map(group => (
                <RailGroupIcon
                  key={group.id}
                  group={group}
                  isActive={activeGroupId === group.id}
                  isFlyoutOpen={flyoutGroupId === group.id}
                  location={location}
                  onOpenFlyout={() => openFlyout(group.id)}
                  onCloseFlyout={closeFlyout}
                  onCancelCloseFlyout={cancelCloseFlyout}
                  onToggleFlyout={() => {
                    if (flyoutGroupId === group.id) {
                      setFlyoutGroupId(null);
                    } else {
                      openFlyout(group.id);
                    }
                  }}
                  onNavigate={(path) => { setLocation(path); setFlyoutGroupId(null); }}
                />
              ))}
            </div>
          </div>

          {/* Footer */}
          <div className="shrink-0">
            <SidebarFooterSection user={user} logout={logout} isCollapsed />
          </div>
        </div>

        {/* Main content */}
        <main className="flex-1 p-4 overflow-x-hidden max-w-full" style={{ marginLeft: RAIL_WIDTH }}>
          {children}
        </main>
      </div>
    );
  }

  // ─── Desktop: Expanded Mode ────────────────────────────────────────────────

  return (
    <div className="flex min-h-screen">
      {/* Expanded sidebar */}
      <div
        className="fixed top-0 left-0 h-screen flex flex-col bg-background border-r z-40"
        style={{ width: EXPANDED_WIDTH }}
      >
        {/* Header */}
        <div className="h-14 flex items-center justify-between px-3 border-b shrink-0">
          <div className="flex items-center gap-2">
            <span className="font-semibold tracking-tight text-sm">AC3</span>
          </div>
          <Tooltip>
            <TooltipTrigger asChild>
              <button
                onClick={toggleMode}
                className="h-8 w-8 flex items-center justify-center rounded-lg hover:bg-accent transition-colors"
              >
                <ChevronsLeft className="h-4 w-4 text-muted-foreground" />
              </button>
            </TooltipTrigger>
            <TooltipContent side="right">Collapse to icons</TooltipContent>
          </Tooltip>
        </div>

        {/* Search trigger */}
        <div className="px-3 py-2 border-b border-border/30 shrink-0">
          <CommandPaletteTrigger />
        </div>

        {/* Engagement switcher */}
        <div className="shrink-0">
          <EngagementSwitcher isCollapsed={false} />
        </div>

        {/* Nav groups */}
        <ScrollArea className="flex-1 min-h-0 overflow-hidden">
          <ExpandedNavList location={location} setLocation={setLocation} filteredNavGroups={filteredNavGroups} />
        </ScrollArea>

        {/* Footer */}
        <div className="shrink-0">
          <SidebarFooterSection user={user} logout={logout} isCollapsed={false} />
        </div>
      </div>

      {/* Main content */}
      <main className="flex-1 p-4 overflow-x-hidden max-w-full" style={{ marginLeft: EXPANDED_WIDTH }}>
        {children}
      </main>
    </div>
  );
}

// ─── Rail Group Icon with Portal Flyout ─────────────────────────────────────

function RailGroupIcon({
  group,
  isActive,
  isFlyoutOpen,
  location,
  onOpenFlyout,
  onCloseFlyout,
  onCancelCloseFlyout,
  onToggleFlyout,
  onNavigate,
}: {
  group: NavGroup;
  isActive: boolean;
  isFlyoutOpen: boolean;
  location: string;
  onOpenFlyout: () => void;
  onCloseFlyout: () => void;
  onCancelCloseFlyout: () => void;
  onToggleFlyout: () => void;
  onNavigate: (path: string) => void;
}) {
  const buttonRef = useRef<HTMLButtonElement>(null);
  const [flyoutPos, setFlyoutPos] = useState({ top: 0, left: 0 });

  // Calculate flyout position based on button position
  useEffect(() => {
    if (isFlyoutOpen && buttonRef.current) {
      const rect = buttonRef.current.getBoundingClientRect();
      setFlyoutPos({
        top: rect.top,
        left: rect.right + 4,
      });
    }
  }, [isFlyoutOpen]);

  return (
    <div
      className="relative"
      onMouseEnter={onOpenFlyout}
      onMouseLeave={onCloseFlyout}
    >
      <Tooltip>
        <TooltipTrigger asChild>
          <button
            ref={buttonRef}
            onClick={(e) => {
              e.preventDefault();
              e.stopPropagation();
              onToggleFlyout();
            }}
            className={`h-10 w-10 flex items-center justify-center rounded-lg transition-colors ${
              isActive || isFlyoutOpen
                ? `bg-accent/70 ${group.color}`
                : "text-muted-foreground hover:bg-accent/50 hover:text-foreground"
            }`}
          >
            <group.icon className="h-4.5 w-4.5" />
          </button>
        </TooltipTrigger>
        {!isFlyoutOpen && (
          <TooltipContent side="right" sideOffset={8}>{group.label}</TooltipContent>
        )}
      </Tooltip>

      {/* Flyout panel — rendered via portal to escape overflow clipping */}
      {isFlyoutOpen && createPortal(
        <div
          className="fixed z-[60]"
          style={{ top: flyoutPos.top, left: flyoutPos.left }}
          onMouseEnter={onCancelCloseFlyout}
          onMouseLeave={onCloseFlyout}
        >
          <div className="w-56 bg-popover border rounded-lg shadow-xl py-1 max-h-[70vh] overflow-y-auto">
            <div className={`px-3 py-2 text-[10px] font-semibold tracking-widest uppercase ${group.color}`}>
              {group.label}
            </div>
            {group.items.map(item => {
              const isItemActive = location === item.path || location.startsWith(item.path + "/");
              return (
                <button
                  key={item.path}
                  onClick={() => onNavigate(item.path)}
                  className={`w-full flex items-center gap-2 px-3 py-1.5 text-left transition-colors ${
                    isItemActive
                      ? "bg-accent text-foreground font-medium"
                      : "text-muted-foreground hover:bg-accent/50 hover:text-foreground"
                  }`}
                >
                  <item.icon className={`h-3.5 w-3.5 shrink-0 ${isItemActive ? group.color : ""}`} />
                  <span className="text-xs truncate">{item.label}</span>
                </button>
              );
            })}
          </div>
        </div>,
        document.body
      )}
    </div>
  );
}

// ─── Expanded Nav List ───────────────────────────────────────────────────────

function ExpandedNavList({
  location,
  setLocation,
  filteredNavGroups,
}: {
  location: string;
  setLocation: (path: string) => void;
  filteredNavGroups: NavGroup[];
}) {
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>(() => {
    try {
      const saved = localStorage.getItem("sidebar-open-groups");
      if (saved) return JSON.parse(saved);
    } catch {}
    const defaults: Record<string, boolean> = {};
    for (const group of filteredNavGroups) {
      if (group.defaultOpen || group.items.some(i => location === i.path || location.startsWith(i.path + "/"))) {
        defaults[group.id] = true;
      }
    }
    return defaults;
  });

  useEffect(() => {
    localStorage.setItem("sidebar-open-groups", JSON.stringify(openGroups));
  }, [openGroups]);

  const toggleGroup = useCallback((id: string) => {
    setOpenGroups(prev => ({ ...prev, [id]: !prev[id] }));
  }, []);

  return (
    <div className="py-1">
      {/* Home link */}
      <button
        onClick={() => setLocation("/home")}
        className={`w-full flex items-center gap-2 px-4 py-2 text-left transition-colors ${
          location === "/" || location === "/home"
            ? "bg-accent text-foreground font-medium"
            : "text-muted-foreground hover:bg-accent/50 hover:text-foreground"
        }`}
      >
        <Home className={`h-4 w-4 shrink-0 ${location === "/" || location === "/home" ? "text-primary" : ""}`} />
        <span className="text-sm">Home</span>
      </button>

      {/* Groups */}
      {filteredNavGroups.map(group => {
        const isOpen = !!openGroups[group.id];
        const hasActiveItem = group.items.some(i => location === i.path || location.startsWith(i.path + "/"));

        return (
          <div key={group.id}>
            <button
              onClick={() => toggleGroup(group.id)}
              className={`w-full flex items-center gap-2 px-4 py-2 text-left transition-colors hover:bg-accent/30 ${
                hasActiveItem ? group.color : "text-muted-foreground"
              }`}
            >
              <group.icon className={`h-3.5 w-3.5 shrink-0 ${hasActiveItem ? group.color : ""}`} />
              <span className="text-[11px] tracking-wider uppercase font-semibold flex-1 truncate">
                {group.label}
              </span>
              <ChevronRight
                className={`h-3 w-3 shrink-0 transition-transform duration-200 ${isOpen ? "rotate-90" : ""}`}
              />
            </button>
            {isOpen && (
              <div className="pb-1">
                {group.items.map(item => {
                  const isActive = location === item.path || location.startsWith(item.path + "/");
                  return (
                    <button
                      key={item.path}
                      onClick={() => setLocation(item.path)}
                      className={`w-full flex items-center gap-2 pl-8 pr-4 py-1.5 text-left transition-colors ${
                        isActive
                          ? "text-foreground font-medium bg-accent/50"
                          : "text-muted-foreground hover:text-foreground hover:bg-accent/30"
                      }`}
                    >
                      <item.icon className={`h-3.5 w-3.5 shrink-0 ${isActive ? group.color : ""}`} />
                      <span className="text-xs truncate">{item.label}</span>
                    </button>
                  );
                })}
              </div>
            )}
          </div>
        );
      })}
    </div>
  );
}

// ─── Mobile Nav List ─────────────────────────────────────────────────────────

function MobileNavList({
  location,
  setLocation,
  filteredNavGroups,
}: {
  location: string;
  setLocation: (path: string) => void;
  filteredNavGroups: NavGroup[];
}) {
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>(() => {
    const defaults: Record<string, boolean> = {};
    for (const group of filteredNavGroups) {
      if (group.items.some(i => location === i.path || location.startsWith(i.path + "/"))) {
        defaults[group.id] = true;
      }
    }
    return defaults;
  });

  return (
    <div className="py-1">
      <button
        onClick={() => setLocation("/home")}
        className={`w-full flex items-center gap-3 px-4 py-3 text-left transition-colors ${
          location === "/" || location === "/home"
            ? "bg-accent text-foreground font-medium"
            : "text-muted-foreground hover:bg-accent/50"
        }`}
      >
        <Home className="h-4 w-4 shrink-0" />
        <span className="text-sm">Home</span>
      </button>

      {filteredNavGroups.map(group => {
        const isOpen = !!openGroups[group.id];
        const hasActiveItem = group.items.some(i => location === i.path || location.startsWith(i.path + "/"));

        return (
          <div key={group.id}>
            <button
              onClick={() => setOpenGroups(prev => ({ ...prev, [group.id]: !prev[group.id] }))}
              className={`w-full flex items-center gap-3 px-4 py-3 text-left ${
                hasActiveItem ? group.color : "text-muted-foreground"
              }`}
            >
              <group.icon className="h-4 w-4 shrink-0" />
              <span className="text-xs tracking-wider uppercase font-semibold flex-1">{group.label}</span>
              <ChevronRight className={`h-3 w-3 transition-transform ${isOpen ? "rotate-90" : ""}`} />
            </button>
            {isOpen && group.items.map(item => {
              const isActive = location === item.path || location.startsWith(item.path + "/");
              return (
                <button
                  key={item.path}
                  onClick={() => setLocation(item.path)}
                  className={`w-full flex items-center gap-3 pl-11 pr-4 py-2.5 text-left min-h-[44px] ${
                    isActive ? "text-foreground font-medium bg-accent/50" : "text-muted-foreground hover:bg-accent/30"
                  }`}
                >
                  <item.icon className={`h-3.5 w-3.5 shrink-0 ${isActive ? group.color : ""}`} />
                  <span className="text-sm truncate">{item.label}</span>
                </button>
              );
            })}
          </div>
        );
      })}
    </div>
  );
}

// ─── Sidebar Footer ──────────────────────────────────────────────────────────

function SidebarFooterSection({
  user,
  logout,
  isCollapsed,
}: {
  user: any;
  logout: () => void;
  isCollapsed: boolean;
}) {
  return (
    <div className="p-2 border-t">
      <div className="mb-1">
        <FIPSIndicator collapsed={isCollapsed} />
      </div>
      <DropdownMenu>
        <DropdownMenuTrigger asChild>
          <button className={`flex items-center gap-2 rounded-lg px-1.5 py-1.5 hover:bg-accent/50 transition-colors w-full text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-ring ${
            isCollapsed ? "justify-center" : ""
          }`}>
            <Avatar className="h-8 w-8 border shrink-0">
              <AvatarFallback className="text-xs font-medium">
                {user?.name?.charAt(0).toUpperCase()}
              </AvatarFallback>
            </Avatar>
            {!isCollapsed && (
              <div className="flex-1 min-w-0">
                <p className="text-sm font-medium truncate leading-none">
                  {user?.name || "-"}
                </p>
                <p className="text-xs text-muted-foreground truncate mt-1">
                  {user?.email || "-"}
                </p>
              </div>
            )}
          </button>
        </DropdownMenuTrigger>
        <DropdownMenuContent align="end" className="w-48">
          <DropdownMenuItem
            onClick={logout}
            className="cursor-pointer text-destructive focus:text-destructive"
          >
            <LogOut className="mr-2 h-4 w-4" />
            <span>Sign out</span>
          </DropdownMenuItem>
        </DropdownMenuContent>
      </DropdownMenu>
    </div>
  );
}

// ─── Engagement Switcher ─────────────────────────────────────────────────────

function EngagementSwitcher({ isCollapsed }: { isCollapsed: boolean }) {
  const { activeEngagement, setActiveEngagement, engagements, clearEngagement } = useEngagement();
  const [open, setOpen] = useState(false);

  const statusColors: Record<string, string> = {
    active: "bg-emerald-500",
    planning: "bg-amber-500",
    paused: "bg-orange-500",
    completed: "bg-blue-500",
    archived: "bg-zinc-500",
  };

  if (isCollapsed) {
    return (
      <div className="py-1 flex justify-center">
        <Tooltip>
          <TooltipTrigger asChild>
            <button
              onClick={() => setOpen(!open)}
              className="h-10 w-10 flex items-center justify-center rounded-lg hover:bg-accent transition-colors"
              title={activeEngagement ? `Active: ${activeEngagement.name}` : "No engagement selected"}
            >
              <Crosshair className={`h-4 w-4 ${activeEngagement ? "text-primary" : "text-muted-foreground"}`} />
            </button>
          </TooltipTrigger>
          <TooltipContent side="right" sideOffset={8}>
            {activeEngagement ? activeEngagement.name : "No engagement"}
          </TooltipContent>
        </Tooltip>
      </div>
    );
  }

  return (
    <div className="px-3 py-2 border-b border-border/50">
      <div className="relative">
        <button
          onClick={() => setOpen(!open)}
          className="w-full flex items-center gap-2 px-2 py-1.5 rounded-md hover:bg-accent/50 transition-colors text-left"
        >
          <Crosshair className={`h-3.5 w-3.5 shrink-0 ${activeEngagement ? "text-primary" : "text-muted-foreground"}`} />
          <div className="flex-1 min-w-0">
            {activeEngagement ? (
              <>
                <p className="text-xs font-medium truncate leading-none">{activeEngagement.name}</p>
                <div className="flex items-center gap-1 mt-1">
                  <span className={`w-1.5 h-1.5 rounded-full ${statusColors[activeEngagement.status || ""] || "bg-zinc-500"}`} />
                  <span className="text-[10px] text-muted-foreground truncate">{activeEngagement.customerName}</span>
                </div>
              </>
            ) : (
              <p className="text-xs text-muted-foreground">No engagement</p>
            )}
          </div>
          <ChevronDown className={`h-3 w-3 text-muted-foreground transition-transform ${open ? "rotate-180" : ""}`} />
        </button>

        {open && (
          <div className="absolute top-full left-0 right-0 mt-1 bg-popover border border-border rounded-md shadow-lg z-50 max-h-48 overflow-y-auto">
            {activeEngagement && (
              <button
                onClick={() => { clearEngagement(); setOpen(false); }}
                className="w-full px-3 py-1.5 text-left text-[10px] text-muted-foreground hover:bg-accent/50 border-b border-border/50"
              >
                Clear selection
              </button>
            )}
            {engagements.length === 0 ? (
              <p className="px-3 py-2 text-[10px] text-muted-foreground">No engagements found</p>
            ) : (
              engagements.map(eng => (
                <button
                  key={eng.id}
                  onClick={() => { setActiveEngagement(eng); setOpen(false); }}
                  className={`w-full px-3 py-1.5 text-left hover:bg-accent/50 transition-colors ${
                    activeEngagement?.id === eng.id ? "bg-accent/30" : ""
                  }`}
                >
                  <p className="text-xs font-medium truncate">{eng.name}</p>
                  <div className="flex items-center gap-1 mt-0.5">
                    <span className={`w-1.5 h-1.5 rounded-full ${statusColors[eng.status || ""] || "bg-zinc-500"}`} />
                    <span className="text-[10px] text-muted-foreground truncate">{eng.customerName}</span>
                  </div>
                </button>
              ))
            )}
          </div>
        )}
      </div>
    </div>
  );
}
