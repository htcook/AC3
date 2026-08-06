/**
 * TabGroupNav — Two-level tab navigation with category groups + sub-tabs
 * 
 * Design Bundle: Reduces cognitive overload by grouping 25+ tabs into 5-6 categories
 * with sub-navigation appearing as a secondary row when a category is selected.
 */
import { useState, useEffect, ReactNode, useMemo } from "react";
import { Badge } from "@/components/ui/badge";

export interface SubTab {
  value: string;
  label: string;
  icon?: ReactNode;
  count?: number;
  /** If true, only show this tab when condition is met */
  hidden?: boolean;
}

export interface TabGroup {
  id: string;
  label: string;
  icon: ReactNode;
  /** Color class for the active group indicator */
  color?: string;
  subTabs: SubTab[];
}

interface TabGroupNavProps {
  groups: TabGroup[];
  activeTab: string;
  onTabChange: (tab: string) => void;
  className?: string;
}

export function TabGroupNav({ groups, activeTab, onTabChange, className = "" }: TabGroupNavProps) {
  // Find which group contains the active tab
  const activeGroup = useMemo(() => {
    for (const group of groups) {
      if (group.subTabs.some(st => st.value === activeTab && !st.hidden)) {
        return group.id;
      }
    }
    return groups[0]?.id || "";
  }, [groups, activeTab]);

  const [selectedGroup, setSelectedGroup] = useState(activeGroup);

  // Sync selected group when active tab changes externally
  useEffect(() => {
    setSelectedGroup(activeGroup);
  }, [activeGroup]);

  const currentGroup = groups.find(g => g.id === selectedGroup);
  const visibleSubTabs = currentGroup?.subTabs.filter(st => !st.hidden) || [];

  const handleGroupClick = (groupId: string) => {
    setSelectedGroup(groupId);
    // Auto-select first visible sub-tab in the group
    const group = groups.find(g => g.id === groupId);
    const firstVisible = group?.subTabs.find(st => !st.hidden);
    if (firstVisible) {
      onTabChange(firstVisible.value);
    }
  };

  return (
    <div className={`flex-none space-y-0 ${className}`}>
      {/* Category Groups — Primary Row */}
      <div className="flex items-center gap-1 px-1 py-1.5 bg-muted/20 rounded-lg border border-border/30">
        {groups.map(group => {
          const isActive = selectedGroup === group.id;
          const totalCount = group.subTabs
            .filter(st => !st.hidden)
            .reduce((sum, st) => sum + (st.count || 0), 0);

          return (
            <button
              key={group.id}
              onClick={() => handleGroupClick(group.id)}
              className={`flex items-center gap-1.5 px-3 py-1.5 rounded-md text-xs font-medium transition-all ${
                isActive
                  ? `bg-background shadow-sm ${group.color || "text-foreground"} ring-1 ring-border/50`
                  : "text-muted-foreground hover:text-foreground hover:bg-muted/30"
              }`}
            >
              <span className={isActive ? "" : "opacity-60"}>{group.icon}</span>
              <span>{group.label}</span>
              {totalCount > 0 && (
                <Badge
                  variant="secondary"
                  className={`text-[9px] h-4 px-1 ${isActive ? "bg-primary/15 text-primary" : "bg-muted/50"}`}
                >
                  {totalCount}
                </Badge>
              )}
            </button>
          );
        })}
      </div>

      {/* Sub-Tabs — Secondary Row */}
      {visibleSubTabs.length > 0 && (
        <div className="flex items-center gap-0.5 px-2 py-1 overflow-x-auto">
          {visibleSubTabs.map(subTab => {
            const isActive = activeTab === subTab.value;
            return (
              <button
                key={subTab.value}
                onClick={() => onTabChange(subTab.value)}
                className={`flex items-center gap-1 px-2.5 py-1 rounded text-[11px] font-medium transition-all whitespace-nowrap ${
                  isActive
                    ? "bg-primary/10 text-primary border border-primary/20"
                    : "text-muted-foreground hover:text-foreground hover:bg-muted/20"
                }`}
              >
                {subTab.icon && <span className="opacity-70">{subTab.icon}</span>}
                <span>{subTab.label}</span>
                {subTab.count != null && subTab.count > 0 && (
                  <Badge
                    variant="secondary"
                    className={`text-[9px] h-3.5 px-1 ml-0.5 ${isActive ? "bg-primary/15 text-primary" : ""}`}
                  >
                    {subTab.count}
                  </Badge>
                )}
              </button>
            );
          })}
        </div>
      )}
    </div>
  );
}

export default TabGroupNav;
