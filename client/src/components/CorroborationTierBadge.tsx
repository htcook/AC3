/**
 * CorroborationTierBadge — Consistent hypothesis-vs-confirmed badge for findings
 *
 * Three tiers:
 *   confirmed  — Product + version matched to CVE affected range, or KEV-listed, or 0-day
 *   probable   — Product detected but version unconfirmed, or has public exploit
 *   potential  — Vendor-only association, advisory-level risk only
 *
 * Used across VulnIntelSection, DomainIntelResults, ClientPortal, and risk signals.
 */
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { CheckCircle2, AlertTriangle, HelpCircle } from "lucide-react";
import { ReactNode } from "react";

export type CorroborationTier = "confirmed" | "probable" | "potential";

interface TierConfig {
  label: string;
  icon: ReactNode;
  badgeClass: string;
  tooltip: string;
}

const TIER_CONFIG: Record<CorroborationTier, TierConfig> = {
  confirmed: {
    label: "Confirmed",
    icon: <CheckCircle2 className="h-2.5 w-2.5" />,
    badgeClass: "bg-emerald-600/80 text-white border-emerald-500/60",
    tooltip:
      "Product + version detected and matched to CVE affected range, or KEV-listed, or confirmed in-the-wild exploitation. High confidence — actionable finding.",
  },
  probable: {
    label: "Probable",
    icon: <AlertTriangle className="h-2.5 w-2.5" />,
    badgeClass: "bg-amber-600/80 text-white border-amber-500/60",
    tooltip:
      "Product detected but version unconfirmed, or has public exploit evidence. Medium confidence — likely real but version verification recommended.",
  },
  potential: {
    label: "Potential",
    icon: <HelpCircle className="h-2.5 w-2.5" />,
    badgeClass: "bg-zinc-600/80 text-zinc-200 border-zinc-500/60",
    tooltip:
      "Vendor-only association without specific product or version match. Low confidence — advisory-level risk only. Verify before including in report.",
  },
};

interface CorroborationTierBadgeProps {
  tier: CorroborationTier | string | null | undefined;
  /** Size variant */
  size?: "xs" | "sm" | "md";
  /** Show icon alongside label */
  showIcon?: boolean;
  /** Show tooltip on hover */
  showTooltip?: boolean;
  /** Additional match specificity context for tooltip */
  matchSpecificity?: "product" | "vendor_only" | string;
}

/**
 * Normalize tier string to a valid CorroborationTier.
 * Falls back to "potential" for unknown values.
 */
function normalizeTier(tier: string | null | undefined): CorroborationTier {
  if (!tier) return "potential";
  const lower = tier.toLowerCase().trim();
  if (lower === "confirmed" || lower === "high") return "confirmed";
  if (lower === "probable" || lower === "medium" || lower === "likely") return "probable";
  return "potential";
}

export function CorroborationTierBadge({
  tier,
  size = "xs",
  showIcon = true,
  showTooltip = true,
  matchSpecificity,
}: CorroborationTierBadgeProps) {
  const normalized = normalizeTier(tier);
  const config = TIER_CONFIG[normalized];

  const sizeClasses = {
    xs: "text-[8px] px-1.5 py-0 h-4 gap-0.5",
    sm: "text-[9px] px-2 py-0.5 gap-1",
    md: "text-[10px] px-2.5 py-0.5 gap-1",
  };

  const badge = (
    <Badge
      className={`${config.badgeClass} ${sizeClasses[size]} font-medium uppercase tracking-wider cursor-help`}
    >
      {showIcon && config.icon}
      {config.label}
    </Badge>
  );

  if (!showTooltip) return badge;

  const extraContext =
    matchSpecificity === "vendor_only"
      ? " Vendor-only match — no specific product version confirmed."
      : matchSpecificity === "product"
        ? " Product-specific match."
        : "";

  return (
    <Tooltip>
      <TooltipTrigger asChild>{badge}</TooltipTrigger>
      <TooltipContent side="top" className="max-w-xs text-xs">
        {config.tooltip}
        {extraContext && <span className="block mt-1 text-muted-foreground">{extraContext}</span>}
      </TooltipContent>
    </Tooltip>
  );
}

/**
 * Returns the tier config for custom rendering scenarios.
 */
export function getTierConfig(tier: string | null | undefined): TierConfig {
  return TIER_CONFIG[normalizeTier(tier)];
}

/**
 * Returns just the badge class for inline styling.
 */
export function getTierBadgeClass(tier: string | null | undefined): string {
  return TIER_CONFIG[normalizeTier(tier)].badgeClass;
}

export default CorroborationTierBadge;
