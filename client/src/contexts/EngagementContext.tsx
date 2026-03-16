/**
 * Engagement Context Provider
 *
 * Tracks the currently active engagement across the entire app.
 * When an engagement is selected, all error logging and operations
 * are automatically tagged with the engagement context.
 *
 * Usage:
 *   const { activeEngagement, setActiveEngagement, engagementContext } = useEngagement();
 */
import { createContext, useContext, useState, useCallback, useMemo, type ReactNode } from "react";
import { trpc } from "@/lib/trpc";

export interface EngagementInfo {
  id: number;
  name: string;
  customerName: string;
  engagementType?: string;
  status?: string;
  targetDomain?: string | null;
  targetIpRange?: string | null;
}

export interface EngagementContextValue {
  /** The currently active engagement (null if none selected) */
  activeEngagement: EngagementInfo | null;
  /** Set the active engagement by full object */
  setActiveEngagement: (engagement: EngagementInfo | null) => void;
  /** Set active engagement by ID (fetches details automatically) */
  setActiveEngagementById: (id: number | null) => void;
  /** Structured context object for error logging and API calls */
  engagementContext: {
    engagementId: number | null;
    engagementName: string | null;
    clientName: string | null;
  };
  /** Whether an engagement is currently active */
  hasActiveEngagement: boolean;
  /** Clear the active engagement */
  clearEngagement: () => void;
  /** List of all engagements for quick switching */
  engagements: EngagementInfo[];
  /** Whether engagements are loading */
  isLoading: boolean;
}

const EngagementContext = createContext<EngagementContextValue | null>(null);

const STORAGE_KEY = "ac3-active-engagement";

function loadPersistedEngagement(): EngagementInfo | null {
  try {
    const stored = localStorage.getItem(STORAGE_KEY);
    if (stored) {
      const parsed = JSON.parse(stored);
      if (parsed && typeof parsed.id === "number") return parsed;
    }
  } catch {
    // ignore
  }
  return null;
}

function persistEngagement(engagement: EngagementInfo | null) {
  try {
    if (engagement) {
      localStorage.setItem(STORAGE_KEY, JSON.stringify(engagement));
    } else {
      localStorage.removeItem(STORAGE_KEY);
    }
  } catch {
    // ignore
  }
}

export function EngagementProvider({ children }: { children: ReactNode }) {
  const [activeEngagement, setActiveEngagementState] = useState<EngagementInfo | null>(
    loadPersistedEngagement
  );

  // Fetch all engagements for the dropdown/switcher
  const { data: engagementsList, isLoading } = trpc.engagements.list.useQuery(undefined, {
    staleTime: 60_000,
  });

  const setActiveEngagement = useCallback((engagement: EngagementInfo | null) => {
    setActiveEngagementState(engagement);
    persistEngagement(engagement);
  }, []);

  const setActiveEngagementById = useCallback((id: number | null) => {
    if (!id) {
      setActiveEngagement(null);
      return;
    }
    const found = engagementsList?.find((e: any) => e.id === id);
    if (found) {
      setActiveEngagement({
        id: found.id,
        name: found.name,
        customerName: found.customerName,
        engagementType: found.engagementType,
        status: found.status,
        targetDomain: found.targetDomain,
        targetIpRange: found.targetIpRange,
      });
    }
  }, [engagementsList, setActiveEngagement]);

  const clearEngagement = useCallback(() => {
    setActiveEngagement(null);
  }, [setActiveEngagement]);

  const engagementContext = useMemo(() => ({
    engagementId: activeEngagement?.id ?? null,
    engagementName: activeEngagement?.name ?? null,
    clientName: activeEngagement?.customerName ?? null,
  }), [activeEngagement]);

  const engagements = useMemo(() => {
    if (!engagementsList) return [];
    return engagementsList.map((e: any) => ({
      id: e.id,
      name: e.name,
      customerName: e.customerName,
      engagementType: e.engagementType,
      status: e.status,
      targetDomain: e.targetDomain,
      targetIpRange: e.targetIpRange,
    }));
  }, [engagementsList]);

  const value = useMemo<EngagementContextValue>(() => ({
    activeEngagement,
    setActiveEngagement,
    setActiveEngagementById,
    engagementContext,
    hasActiveEngagement: activeEngagement !== null,
    clearEngagement,
    engagements,
    isLoading,
  }), [activeEngagement, setActiveEngagement, setActiveEngagementById, engagementContext, clearEngagement, engagements, isLoading]);

  return (
    <EngagementContext.Provider value={value}>
      {children}
    </EngagementContext.Provider>
  );
}

export function useEngagement(): EngagementContextValue {
  const ctx = useContext(EngagementContext);
  if (!ctx) {
    throw new Error("useEngagement must be used within an EngagementProvider");
  }
  return ctx;
}

export default EngagementContext;
