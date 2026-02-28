import React, { createContext, useContext, useState, useCallback, useEffect, ReactNode } from 'react';

export interface WidgetConfig {
  id: string;
  label: string;
  icon: string; // lucide icon name
  visible: boolean;
  pinned: boolean;
  order: number;
}

const DEFAULT_WIDGETS: WidgetConfig[] = [
  { id: 'start-engagement', label: 'Start Engagement', icon: 'Rocket', visible: true, pinned: true, order: 0 },
  { id: 'mission-workflows', label: 'Mission Workflows', icon: 'Workflow', visible: true, pinned: false, order: 1 },
  { id: 'recent-scans', label: 'Recent Scans', icon: 'History', visible: true, pinned: false, order: 2 },
  { id: 'quick-access', label: 'Quick Access', icon: 'Zap', visible: true, pinned: true, order: 3 },
  { id: 'live-stats', label: 'Live Stats', icon: 'Activity', visible: true, pinned: false, order: 4 },
  { id: 'server-status', label: 'Server Status', icon: 'Server', visible: true, pinned: false, order: 5 },
  { id: 'phishing-metrics', label: 'Phishing Metrics', icon: 'Fish', visible: true, pinned: false, order: 6 },
  { id: 'threat-awareness', label: 'Threat Awareness', icon: 'ShieldAlert', visible: true, pinned: false, order: 7 },
  { id: 'vuln-feed', label: '0-Day Vulnerability Feed', icon: 'Flame', visible: true, pinned: false, order: 8 },
  { id: 'more-tools', label: 'More Tools', icon: 'Grid3X3', visible: true, pinned: false, order: 9 },
];

const STORAGE_KEY = 'ace-c3-dashboard-widgets';

interface DashboardWidgetContextValue {
  widgets: WidgetConfig[];
  isConfigOpen: boolean;
  openConfig: () => void;
  closeConfig: () => void;
  toggleVisibility: (id: string) => void;
  togglePin: (id: string) => void;
  moveUp: (id: string) => void;
  moveDown: (id: string) => void;
  resetToDefaults: () => void;
  isVisible: (id: string) => boolean;
  isPinned: (id: string) => boolean;
  getOrderedWidgetIds: () => string[];
}

const DashboardWidgetContext = createContext<DashboardWidgetContextValue | null>(null);

export function DashboardWidgetProvider({ children }: { children: ReactNode }) {
  const [widgets, setWidgets] = useState<WidgetConfig[]>(() => {
    try {
      const stored = localStorage.getItem(STORAGE_KEY);
      if (stored) {
        const parsed = JSON.parse(stored) as WidgetConfig[];
        // Merge with defaults to handle new widgets added in updates
        const mergedMap = new Map(DEFAULT_WIDGETS.map(w => [w.id, { ...w }]));
        for (const saved of parsed) {
          if (mergedMap.has(saved.id)) {
            mergedMap.set(saved.id, { ...mergedMap.get(saved.id)!, ...saved });
          }
        }
        return Array.from(mergedMap.values()).sort((a, b) => a.order - b.order);
      }
    } catch {}
    return DEFAULT_WIDGETS.map(w => ({ ...w }));
  });

  const [isConfigOpen, setIsConfigOpen] = useState(false);

  useEffect(() => {
    try {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(widgets));
    } catch {}
  }, [widgets]);

  const toggleVisibility = useCallback((id: string) => {
    setWidgets(prev => prev.map(w => w.id === id ? { ...w, visible: !w.visible } : w));
  }, []);

  const togglePin = useCallback((id: string) => {
    setWidgets(prev => prev.map(w => w.id === id ? { ...w, pinned: !w.pinned, visible: !w.pinned ? true : w.visible } : w));
  }, []);

  const moveUp = useCallback((id: string) => {
    setWidgets(prev => {
      const sorted = [...prev].sort((a, b) => a.order - b.order);
      const idx = sorted.findIndex(w => w.id === id);
      if (idx <= 0) return prev;
      const newOrder = sorted[idx - 1].order;
      sorted[idx - 1].order = sorted[idx].order;
      sorted[idx].order = newOrder;
      return sorted.sort((a, b) => a.order - b.order);
    });
  }, []);

  const moveDown = useCallback((id: string) => {
    setWidgets(prev => {
      const sorted = [...prev].sort((a, b) => a.order - b.order);
      const idx = sorted.findIndex(w => w.id === id);
      if (idx < 0 || idx >= sorted.length - 1) return prev;
      const newOrder = sorted[idx + 1].order;
      sorted[idx + 1].order = sorted[idx].order;
      sorted[idx].order = newOrder;
      return sorted.sort((a, b) => a.order - b.order);
    });
  }, []);

  const resetToDefaults = useCallback(() => {
    setWidgets(DEFAULT_WIDGETS.map(w => ({ ...w })));
  }, []);

  const isVisible = useCallback((id: string) => {
    return widgets.find(w => w.id === id)?.visible ?? true;
  }, [widgets]);

  const isPinned = useCallback((id: string) => {
    return widgets.find(w => w.id === id)?.pinned ?? false;
  }, [widgets]);

  const getOrderedWidgetIds = useCallback(() => {
    return [...widgets].sort((a, b) => a.order - b.order).filter(w => w.visible).map(w => w.id);
  }, [widgets]);

  const openConfig = useCallback(() => setIsConfigOpen(true), []);
  const closeConfig = useCallback(() => setIsConfigOpen(false), []);

  return (
    <DashboardWidgetContext.Provider value={{
      widgets,
      isConfigOpen,
      openConfig,
      closeConfig,
      toggleVisibility,
      togglePin,
      moveUp,
      moveDown,
      resetToDefaults,
      isVisible,
      isPinned,
      getOrderedWidgetIds,
    }}>
      {children}
    </DashboardWidgetContext.Provider>
  );
}

export function useDashboardWidgets() {
  const ctx = useContext(DashboardWidgetContext);
  if (!ctx) throw new Error('useDashboardWidgets must be used within DashboardWidgetProvider');
  return ctx;
}
