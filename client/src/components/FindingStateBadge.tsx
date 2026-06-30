/**
 * FindingStateBadge — 7-state verification badge for findings
 * 
 * Design Bundle: Finding states track the verification chain for FedRAMP auditors:
 * observed → suspected → confirmed → verified_exploitable → mitigated → accepted_risk → false_positive
 */
import { Badge } from "@/components/ui/badge";
import {
  Eye, AlertTriangle, CheckCircle2, ShieldAlert, ShieldCheck,
  ShieldX, XCircle
} from "lucide-react";
import { ReactNode } from "react";

export type FindingState =
  | "observed"
  | "suspected"
  | "confirmed"
  | "verified_exploitable"
  | "mitigated"
  | "accepted_risk"
  | "false_positive";

interface FindingStateConfig {
  label: string;
  icon: ReactNode;
  className: string;
  description: string;
}

const FINDING_STATES: Record<FindingState, FindingStateConfig> = {
  observed: {
    label: "Observed",
    icon: <Eye className="h-3 w-3" />,
    className: "bg-slate-500/15 text-slate-400 border-slate-500/30",
    description: "Detected by passive recon — not yet analyzed",
  },
  suspected: {
    label: "Suspected",
    icon: <AlertTriangle className="h-3 w-3" />,
    className: "bg-amber-500/15 text-amber-400 border-amber-500/30",
    description: "LLM analysis suggests this is a real weakness",
  },
  confirmed: {
    label: "Confirmed",
    icon: <CheckCircle2 className="h-3 w-3" />,
    className: "bg-orange-500/15 text-orange-400 border-orange-500/30",
    description: "Active scan or corroboration confirms the finding",
  },
  verified_exploitable: {
    label: "Verified",
    icon: <ShieldAlert className="h-3 w-3" />,
    className: "bg-red-500/15 text-red-400 border-red-500/30",
    description: "Exploit verification proves exploitability",
  },
  mitigated: {
    label: "Mitigated",
    icon: <ShieldCheck className="h-3 w-3" />,
    className: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30",
    description: "Remediation applied and verified",
  },
  accepted_risk: {
    label: "Accepted",
    icon: <ShieldX className="h-3 w-3" />,
    className: "bg-blue-500/15 text-blue-400 border-blue-500/30",
    description: "Risk accepted with documented exception",
  },
  false_positive: {
    label: "False Positive",
    icon: <XCircle className="h-3 w-3" />,
    className: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30",
    description: "Confirmed not a real finding",
  },
};

interface FindingStateBadgeProps {
  state: FindingState | string;
  size?: "sm" | "md";
  showIcon?: boolean;
}

/**
 * Maps legacy finding states to the new 7-state model.
 * Falls back to "observed" for unknown states.
 */
function normalizeState(state: string): FindingState {
  const map: Record<string, FindingState> = {
    observed: "observed",
    suspected: "suspected",
    confirmed: "confirmed",
    verified_exploitable: "verified_exploitable",
    verified: "verified_exploitable",
    exploitable: "verified_exploitable",
    mitigated: "mitigated",
    remediated: "mitigated",
    accepted_risk: "accepted_risk",
    accepted: "accepted_risk",
    false_positive: "false_positive",
    fp: "false_positive",
    // Legacy mapping
    critical: "confirmed",
    high: "suspected",
    medium: "observed",
    low: "observed",
  };
  return map[state.toLowerCase()] || "observed";
}

export function FindingStateBadge({ state, size = "sm", showIcon = true }: FindingStateBadgeProps) {
  const normalized = normalizeState(state);
  const config = FINDING_STATES[normalized];

  return (
    <Badge
      variant="outline"
      className={`${config.className} ${size === "sm" ? "text-[10px] px-1.5 py-0" : "text-xs px-2 py-0.5"} gap-1`}
      title={config.description}
    >
      {showIcon && config.icon}
      {config.label}
    </Badge>
  );
}

/**
 * Returns the finding state configuration for use in custom rendering.
 */
export function getFindingStateConfig(state: string): FindingStateConfig {
  return FINDING_STATES[normalizeState(state)];
}

/**
 * All finding states in pipeline order.
 */
export const FINDING_STATE_ORDER: FindingState[] = [
  "observed",
  "suspected",
  "confirmed",
  "verified_exploitable",
  "mitigated",
  "accepted_risk",
  "false_positive",
];

export default FindingStateBadge;
