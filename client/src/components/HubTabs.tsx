import { Suspense, lazy, useState, useEffect, type ComponentType, type LazyExoticComponent } from "react";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Loader2 } from "lucide-react";
import { EmbedProvider } from "@/contexts/EmbedContext";

export interface HubTab {
  id: string;
  label: string;
  icon?: ComponentType<{ className?: string }>;
  component: LazyExoticComponent<ComponentType<any>> | ComponentType<any>;
}

interface HubTabsProps {
  tabs: HubTab[];
  defaultTab?: string;
  storageKey?: string;
  className?: string;
}

function TabFallback() {
  return (
    <div className="flex items-center justify-center py-24">
      <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
    </div>
  );
}

/**
 * HubTabs — Reusable tabbed container for consolidated hub pages.
 * Each tab lazy-loads its sub-page component.
 * Active tab is persisted to localStorage via storageKey.
 */
export default function HubTabs({ tabs, defaultTab, storageKey, className }: HubTabsProps) {
  const resolvedDefault = defaultTab || tabs[0]?.id || "";

  const [activeTab, setActiveTab] = useState(() => {
    if (storageKey) {
      try {
        const stored = localStorage.getItem(`hub-tab-${storageKey}`);
        if (stored && tabs.some((t) => t.id === stored)) return stored;
      } catch {}
    }
    return resolvedDefault;
  });

  useEffect(() => {
    if (storageKey) {
      try {
        localStorage.setItem(`hub-tab-${storageKey}`, activeTab);
      } catch {}
    }
  }, [activeTab, storageKey]);

  if (tabs.length === 0) return null;

  const handleTabChange = (val: string) => {
    console.log('[HubTabs] onValueChange fired:', val, 'current:', activeTab);
    setActiveTab(val);
  };

  console.log('[HubTabs] render, activeTab:', activeTab);

  return (
    <Tabs value={activeTab} onValueChange={handleTabChange} className={className}>
      <div className="border-b border-border/50 mb-6">
        <TabsList className="bg-transparent h-auto p-0 gap-0 flex-wrap">
          {tabs.map((tab) => {
            const Icon = tab.icon;
            return (
              <TabsTrigger
                key={tab.id}
                value={tab.id}
                className="relative rounded-none border-b-2 border-transparent data-[state=active]:border-primary data-[state=active]:bg-transparent data-[state=active]:text-primary bg-transparent px-4 py-2.5 font-display tracking-wider text-xs text-muted-foreground hover:text-foreground transition-colors"
              >
                {Icon && <Icon className="w-3.5 h-3.5 mr-1.5" />}
                {tab.label}
              </TabsTrigger>
            );
          })}
        </TabsList>
      </div>
      {tabs.map((tab) => {
        const TabComponent = tab.component;
        return (
          <TabsContent key={tab.id} value={tab.id} className="mt-0">
            <EmbedProvider>
              <Suspense fallback={<TabFallback />}>
                <TabComponent />
              </Suspense>
            </EmbedProvider>
          </TabsContent>
        );
      })}
    </Tabs>
  );
}
