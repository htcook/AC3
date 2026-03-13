import { useAuth } from "@/_core/hooks/useAuth";
import { Avatar, AvatarFallback } from "@/components/ui/avatar";
import {
  DropdownMenu,
  DropdownMenuContent,
  DropdownMenuItem,
  DropdownMenuTrigger,
} from "@/components/ui/dropdown-menu";
import {
  Sidebar,
  SidebarContent,
  SidebarFooter,
  SidebarGroup,
  SidebarGroupContent,
  SidebarGroupLabel,
  SidebarHeader,
  SidebarInset,
  SidebarMenu,
  SidebarMenuButton,
  SidebarMenuItem,
  SidebarMenuSub,
  SidebarMenuSubButton,
  SidebarMenuSubItem,
  SidebarProvider,
  SidebarTrigger,
  useSidebar,
} from "@/components/ui/sidebar";
import {
  Collapsible,
  CollapsibleContent,
  CollapsibleTrigger,
} from "@/components/ui/collapsible";
import { getLoginUrl } from "@/const";
import { useIsMobile } from "@/hooks/useMobile";
import { LogOut, PanelLeft, Crosshair, ChevronDown, ChevronRight, Search, Home } from "lucide-react";
import { FIPSIndicator } from "./FIPSIndicator";
import { useEngagement } from "@/contexts/EngagementContext";
import { CSSProperties, useCallback, useEffect, useMemo, useRef, useState } from "react";
import { useLocation } from "wouter";
import { DashboardLayoutSkeleton } from './DashboardLayoutSkeleton';
import { Button } from "./ui/button";
import { Input } from "./ui/input";
import { sidebarNavGroups, type NavGroup } from "@/lib/sidebar-nav";
import { ScrollArea } from "./ui/scroll-area";

const SIDEBAR_WIDTH_KEY = "sidebar-width";
const SIDEBAR_OPEN_GROUPS_KEY = "sidebar-open-groups";
const DEFAULT_WIDTH = 280;
const MIN_WIDTH = 200;
const MAX_WIDTH = 480;

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const [sidebarWidth, setSidebarWidth] = useState(() => {
    const saved = localStorage.getItem(SIDEBAR_WIDTH_KEY);
    return saved ? parseInt(saved, 10) : DEFAULT_WIDTH;
  });
  const { loading, user } = useAuth();

  useEffect(() => {
    localStorage.setItem(SIDEBAR_WIDTH_KEY, sidebarWidth.toString());
  }, [sidebarWidth]);

  if (loading) {
    return <DashboardLayoutSkeleton />
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
            onClick={() => {
              window.location.href = getLoginUrl();
            }}
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
    <SidebarProvider
      style={
        {
          "--sidebar-width": `${sidebarWidth}px`,
        } as CSSProperties
      }
    >
      <DashboardLayoutContent setSidebarWidth={setSidebarWidth}>
        {children}
      </DashboardLayoutContent>
    </SidebarProvider>
  );
}

type DashboardLayoutContentProps = {
  children: React.ReactNode;
  setSidebarWidth: (width: number) => void;
};

function DashboardLayoutContent({
  children,
  setSidebarWidth,
}: DashboardLayoutContentProps) {
  const { user, logout } = useAuth();
  const [location, setLocation] = useLocation();
  const { state, toggleSidebar } = useSidebar();
  const isCollapsed = state === "collapsed";
  const [isResizing, setIsResizing] = useState(false);
  const sidebarRef = useRef<HTMLDivElement>(null);
  const isMobile = useIsMobile();
  const [searchQuery, setSearchQuery] = useState("");

  // Persist open groups
  const [openGroups, setOpenGroups] = useState<Record<string, boolean>>(() => {
    try {
      const saved = localStorage.getItem(SIDEBAR_OPEN_GROUPS_KEY);
      if (saved) return JSON.parse(saved);
    } catch {}
    // Default: open the group containing the current route
    const defaults: Record<string, boolean> = {};
    for (const group of sidebarNavGroups) {
      if (group.defaultOpen || group.items.some(item => location === item.path || location.startsWith(item.path + "/"))) {
        defaults[group.id] = true;
      }
    }
    return defaults;
  });

  useEffect(() => {
    localStorage.setItem(SIDEBAR_OPEN_GROUPS_KEY, JSON.stringify(openGroups));
  }, [openGroups]);

  const toggleGroup = useCallback((groupId: string) => {
    setOpenGroups(prev => ({ ...prev, [groupId]: !prev[groupId] }));
  }, []);

  // Find active page label for mobile header
  const activeLabel = useMemo(() => {
    for (const group of sidebarNavGroups) {
      const item = group.items.find(i => location === i.path || location.startsWith(i.path + "/"));
      if (item) return item.label;
    }
    return "Menu";
  }, [location]);

  // Filter groups/items by search
  const filteredGroups = useMemo(() => {
    if (!searchQuery.trim()) return sidebarNavGroups;
    const q = searchQuery.toLowerCase();
    return sidebarNavGroups
      .map(group => ({
        ...group,
        items: group.items.filter(item =>
          item.label.toLowerCase().includes(q) ||
          item.path.toLowerCase().includes(q)
        ),
      }))
      .filter(group => group.items.length > 0);
  }, [searchQuery]);

  useEffect(() => {
    if (isCollapsed) {
      setIsResizing(false);
    }
  }, [isCollapsed]);

  useEffect(() => {
    const handleMouseMove = (e: MouseEvent) => {
      if (!isResizing) return;

      const sidebarLeft = sidebarRef.current?.getBoundingClientRect().left ?? 0;
      const newWidth = e.clientX - sidebarLeft;
      if (newWidth >= MIN_WIDTH && newWidth <= MAX_WIDTH) {
        setSidebarWidth(newWidth);
      }
    };

    const handleMouseUp = () => {
      setIsResizing(false);
    };

    if (isResizing) {
      document.addEventListener("mousemove", handleMouseMove);
      document.addEventListener("mouseup", handleMouseUp);
      document.body.style.cursor = "col-resize";
      document.body.style.userSelect = "none";
    }

    return () => {
      document.removeEventListener("mousemove", handleMouseMove);
      document.removeEventListener("mouseup", handleMouseUp);
      document.body.style.cursor = "";
      document.body.style.userSelect = "";
    };
  }, [isResizing, setSidebarWidth]);

  return (
    <>
      <div className="relative" ref={sidebarRef}>
        <Sidebar
          collapsible="icon"
          className="border-r-0"
          disableTransition={isResizing}
        >
          <SidebarHeader className="h-16 justify-center">
            <div className="flex items-center gap-3 px-2 transition-all w-full">
              <button
                onClick={toggleSidebar}
                className="h-8 w-8 flex items-center justify-center hover:bg-accent rounded-lg transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-ring shrink-0"
                aria-label="Toggle navigation"
              >
                <PanelLeft className="h-4 w-4 text-muted-foreground" />
              </button>
              {!isCollapsed ? (
                <div className="flex items-center gap-2 min-w-0 flex-1">
                  <span className="font-semibold tracking-tight truncate text-sm">
                    ACE C3
                  </span>
                </div>
              ) : null}
            </div>
          </SidebarHeader>

          {/* Engagement Switcher */}
          <EngagementSwitcher isCollapsed={isCollapsed} />

          {/* Search filter */}
          {!isCollapsed && (
            <div className="px-3 py-2 border-b border-border/30">
              <div className="relative">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                <Input
                  placeholder="Search pages..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="h-8 pl-8 text-xs bg-accent/30 border-border/30 focus-visible:ring-1"
                />
              </div>
            </div>
          )}

          <SidebarContent className="gap-0">
            <ScrollArea className="flex-1">
              {/* Quick Home link */}
              <SidebarMenu className="px-2 pt-2 pb-0">
                <SidebarMenuItem>
                  <SidebarMenuButton
                    isActive={location === "/" || location === "/home"}
                    onClick={() => setLocation("/home")}
                    tooltip="Home"
                    className="h-9 font-normal"
                  >
                    <Home className={`h-4 w-4 ${location === "/" || location === "/home" ? "text-primary" : ""}`} />
                    <span>Home</span>
                  </SidebarMenuButton>
                </SidebarMenuItem>
              </SidebarMenu>

              {/* Collapsible nav groups */}
              {filteredGroups.map((group) => (
                <NavGroupSection
                  key={group.id}
                  group={group}
                  isOpen={searchQuery.trim() ? true : !!openGroups[group.id]}
                  onToggle={() => toggleGroup(group.id)}
                  location={location}
                  setLocation={setLocation}
                  isCollapsed={isCollapsed}
                />
              ))}
            </ScrollArea>
          </SidebarContent>

          <SidebarFooter className="p-3">
            {/* FIPS 140-3 Compliance Status Indicator */}
            <div className="mb-1">
              <FIPSIndicator collapsed={isCollapsed} />
            </div>
            <DropdownMenu>
              <DropdownMenuTrigger asChild>
                <button className="flex items-center gap-3 rounded-lg px-1 py-1 hover:bg-accent/50 transition-colors w-full text-left group-data-[collapsible=icon]:justify-center focus:outline-none focus-visible:ring-2 focus-visible:ring-ring">
                  <Avatar className="h-9 w-9 border shrink-0">
                    <AvatarFallback className="text-xs font-medium">
                      {user?.name?.charAt(0).toUpperCase()}
                    </AvatarFallback>
                  </Avatar>
                  <div className="flex-1 min-w-0 group-data-[collapsible=icon]:hidden">
                    <p className="text-sm font-medium truncate leading-none">
                      {user?.name || "-"}
                    </p>
                    <p className="text-xs text-muted-foreground truncate mt-1.5">
                      {user?.email || "-"}
                    </p>
                  </div>
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
          </SidebarFooter>
        </Sidebar>
        <div
          className={`absolute top-0 right-0 w-1 h-full cursor-col-resize hover:bg-primary/20 transition-colors ${isCollapsed ? "hidden" : ""}`}
          onMouseDown={() => {
            if (isCollapsed) return;
            setIsResizing(true);
          }}
          style={{ zIndex: 50 }}
        />
      </div>

      <SidebarInset>
        {isMobile && (
          <div className="flex border-b h-14 items-center justify-between bg-background/95 px-2 backdrop-blur supports-[backdrop-filter]:backdrop-blur sticky top-0 z-40">
            <div className="flex items-center gap-2">
              <SidebarTrigger className="h-9 w-9 rounded-lg bg-background" />
              <div className="flex items-center gap-3">
                <div className="flex flex-col gap-1">
                  <span className="tracking-tight text-foreground">
                    {activeLabel}
                  </span>
                </div>
              </div>
            </div>
          </div>
        )}
        <main className="flex-1 p-4">{children}</main>
      </SidebarInset>
    </>
  );
}

/** Collapsible navigation group with sub-items */
function NavGroupSection({
  group,
  isOpen,
  onToggle,
  location,
  setLocation,
  isCollapsed,
}: {
  group: NavGroup;
  isOpen: boolean;
  onToggle: () => void;
  location: string;
  setLocation: (path: string) => void;
  isCollapsed: boolean;
}) {
  const hasActiveItem = group.items.some(
    item => location === item.path || location.startsWith(item.path + "/")
  );

  return (
    <Collapsible open={isOpen} onOpenChange={onToggle}>
      <SidebarGroup className="py-0">
        <CollapsibleTrigger asChild>
          <SidebarGroupLabel
            className={`h-9 px-3 cursor-pointer hover:bg-accent/50 transition-colors text-[11px] tracking-wider uppercase font-semibold ${
              hasActiveItem ? group.color : "text-muted-foreground"
            }`}
          >
            <div className="flex items-center gap-2 flex-1 min-w-0">
              <group.icon className={`h-3.5 w-3.5 shrink-0 ${hasActiveItem ? group.color : ""}`} />
              {!isCollapsed && (
                <>
                  <span className="truncate">{group.label}</span>
                  <ChevronRight
                    className={`h-3 w-3 ml-auto shrink-0 transition-transform duration-200 ${
                      isOpen ? "rotate-90" : ""
                    }`}
                  />
                </>
              )}
            </div>
          </SidebarGroupLabel>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <SidebarGroupContent>
            <SidebarMenuSub className="border-l-0 ml-0 pl-0">
              {group.items.map(item => {
                const isActive = location === item.path || location.startsWith(item.path + "/");
                return (
                  <SidebarMenuSubItem key={item.path}>
                    <SidebarMenuSubButton
                      isActive={isActive}
                      onClick={() => setLocation(item.path)}
                      className={`h-8 pl-7 text-xs cursor-pointer ${
                        isActive
                          ? "text-foreground font-medium bg-accent/50"
                          : "text-muted-foreground hover:text-foreground"
                      }`}
                    >
                      <item.icon className={`h-3.5 w-3.5 shrink-0 mr-2 ${isActive ? group.color : ""}`} />
                      <span className="truncate">{item.label}</span>
                    </SidebarMenuSubButton>
                  </SidebarMenuSubItem>
                );
              })}
            </SidebarMenuSub>
          </SidebarGroupContent>
        </CollapsibleContent>
      </SidebarGroup>
    </Collapsible>
  );
}

/** Compact engagement switcher for the sidebar */
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
      <div className="px-2 py-1">
        <button
          onClick={() => setOpen(!open)}
          className="w-full h-8 flex items-center justify-center rounded-md hover:bg-accent transition-colors"
          title={activeEngagement ? `Active: ${activeEngagement.name}` : "No engagement selected"}
        >
          <Crosshair className={`h-4 w-4 ${activeEngagement ? "text-primary" : "text-muted-foreground"}`} />
        </button>
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
