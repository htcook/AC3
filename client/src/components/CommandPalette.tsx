/**
 * Command Palette — Ctrl/Cmd+K
 * 
 * Searchable navigation across all 178+ nav items, recent pages,
 * and quick actions. Uses the shadcn/ui CommandDialog (cmdk).
 */
import { useCallback, useEffect, useMemo, useState } from "react";
import { useLocation } from "wouter";
import { useTheme } from "@/contexts/ThemeContext";
import {
  CommandDialog,
  CommandInput,
  CommandList,
  CommandEmpty,
  CommandGroup,
  CommandItem,
  CommandSeparator,
} from "@/components/ui/command";
import { sidebarNavGroups } from "@/lib/sidebar-nav";
import {
  Search, Clock, Zap, Sun, Moon, Briefcase,
  Scan, ArrowRight,
} from "lucide-react";

// ─── Recent Pages Persistence ────────────────────────────────────────────────

const RECENT_KEY = "cmd-palette-recent";
const MAX_RECENT = 8;

function getRecent(): { path: string; label: string }[] {
  try {
    return JSON.parse(localStorage.getItem(RECENT_KEY) || "[]");
  } catch { return []; }
}

function pushRecent(path: string, label: string) {
  const list = getRecent().filter(r => r.path !== path);
  list.unshift({ path, label });
  localStorage.setItem(RECENT_KEY, JSON.stringify(list.slice(0, MAX_RECENT)));
}

// ─── Component ───────────────────────────────────────────────────────────────

export function CommandPalette() {
  const [open, setOpen] = useState(false);
  const [, navigate] = useLocation();
  const { theme, toggleTheme } = useTheme();
  const [recent, setRecent] = useState(getRecent);

  // Global keyboard shortcut: Ctrl/Cmd+K
  useEffect(() => {
    const handler = (e: KeyboardEvent) => {
      if ((e.metaKey || e.ctrlKey) && e.key === "k") {
        e.preventDefault();
        setOpen(prev => !prev);
      }
    };
    window.addEventListener("keydown", handler);
    return () => window.removeEventListener("keydown", handler);
  }, []);

  // Refresh recent list when opening
  useEffect(() => {
    if (open) setRecent(getRecent());
  }, [open]);

  const go = useCallback((path: string, label: string) => {
    pushRecent(path, label);
    navigate(path);
    setOpen(false);
  }, [navigate]);

  // Flatten all nav items for search
  const allItems = useMemo(() => {
    return sidebarNavGroups.flatMap(group =>
      group.items.map(item => ({
        ...item,
        groupLabel: group.label,
        groupColor: group.color,
        groupIcon: group.icon,
      }))
    );
  }, []);

  // Quick actions
  const quickActions = useMemo(() => [
    { id: "new-scan", label: "New Domain Scan", icon: Scan, path: "/domain-intel", description: "Launch a new domain intelligence scan" },
    { id: "new-engagement", label: "New Engagement", icon: Briefcase, path: "/engagements/new", description: "Create a new pentest engagement" },
    { id: "toggle-theme", label: `Switch to ${theme === "dark" ? "Light" : "Dark"} Mode`, icon: theme === "dark" ? Sun : Moon, path: "__action:theme", description: "Toggle the UI theme" },
  ], [theme]);

  const handleAction = useCallback((actionPath: string, label: string) => {
    if (actionPath === "__action:theme") {
      toggleTheme?.();
      setOpen(false);
    } else {
      go(actionPath, label);
    }
  }, [go, toggleTheme]);

  return (
    <CommandDialog open={open} onOpenChange={setOpen}>
      <CommandInput placeholder="Search pages, actions, tools..." />
      <CommandList className="max-h-[420px]">
        <CommandEmpty>
          <div className="flex flex-col items-center gap-2 py-4">
            <Search className="w-8 h-8 text-muted-foreground/40" />
            <p className="text-sm text-muted-foreground">No results found</p>
          </div>
        </CommandEmpty>

        {/* Quick Actions */}
        <CommandGroup heading="Quick Actions">
          {quickActions.map(action => (
            <CommandItem
              key={action.id}
              value={action.label}
              onSelect={() => handleAction(action.path, action.label)}
              className="cursor-pointer"
            >
              <action.icon className="mr-2 h-4 w-4 text-primary shrink-0" />
              <div className="flex-1 min-w-0">
                <span className="text-sm">{action.label}</span>
                <span className="text-xs text-muted-foreground ml-2">{action.description}</span>
              </div>
              <Zap className="ml-auto h-3 w-3 text-muted-foreground/40" />
            </CommandItem>
          ))}
        </CommandGroup>

        {/* Recent Pages */}
        {recent.length > 0 && (
          <>
            <CommandSeparator />
            <CommandGroup heading="Recent">
              {recent.map(r => {
                const item = allItems.find(i => i.path === r.path);
                const Icon = item?.icon || Clock;
                return (
                  <CommandItem
                    key={r.path}
                    value={`recent ${r.label} ${r.path}`}
                    onSelect={() => go(r.path, r.label)}
                    className="cursor-pointer"
                  >
                    <Icon className="mr-2 h-4 w-4 text-muted-foreground shrink-0" />
                    <span className="text-sm">{r.label}</span>
                    <Clock className="ml-auto h-3 w-3 text-muted-foreground/40" />
                  </CommandItem>
                );
              })}
            </CommandGroup>
          </>
        )}

        {/* All Navigation Groups */}
        <CommandSeparator />
        {sidebarNavGroups.map(group => (
          <CommandGroup key={group.id} heading={group.label}>
            {group.items.map(item => (
              <CommandItem
                key={item.path}
                value={`${group.label} ${item.label} ${item.path}`}
                onSelect={() => go(item.path, item.label)}
                className="cursor-pointer"
              >
                <item.icon className={`mr-2 h-4 w-4 shrink-0 ${group.color}`} />
                <span className="text-sm">{item.label}</span>
                <ArrowRight className="ml-auto h-3 w-3 text-muted-foreground/40 opacity-0 group-data-[selected=true]:opacity-100 transition-opacity" />
              </CommandItem>
            ))}
          </CommandGroup>
        ))}
      </CommandList>
    </CommandDialog>
  );
}

/** Small trigger button for the sidebar — shows Cmd+K hint */
export function CommandPaletteTrigger({ collapsed }: { collapsed?: boolean }) {
  return (
    <button
      onClick={() => {
        window.dispatchEvent(new KeyboardEvent("keydown", { key: "k", metaKey: true, bubbles: true }));
      }}
      className="w-full flex items-center gap-2 px-2.5 py-2 rounded-md hover:bg-accent/50 transition-colors text-muted-foreground hover:text-foreground text-left"
      title="Search (Ctrl+K)"
    >
      <Search className="h-3.5 w-3.5 shrink-0" />
      {!collapsed && (
        <>
          <span className="text-xs flex-1">Search...</span>
          <kbd className="text-[9px] bg-secondary px-1.5 py-0.5 rounded font-mono tracking-wider">
            {navigator.platform?.includes("Mac") ? "\u2318" : "Ctrl"}K
          </kbd>
        </>
      )}
    </button>
  );
}
