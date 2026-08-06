/**
 * ConfidenceBadge — ICD 203 Analytical Confidence Level Badge
 *
 * Displays the IC-standard confidence level (HIGH / MODERATE / LOW) as a
 * color-coded badge with hover tooltip showing the full IC definition.
 *
 * Thresholds (from server/lib/analytical-confidence.ts):
 *   HIGH     ≥ 0.80  — Multiple independent sources, corroborated, short inference chain
 *   MODERATE ≥ 0.50  — Credibly sourced, plausible, identifiable assumptions
 *   LOW      < 0.50  — Fragmentary evidence, significant inference gaps
 *
 * Usage:
 *   <ConfidenceBadge score={0.85} />
 *   <ConfidenceBadge level="high" />
 *   <ConfidenceBadge score={0.62} showScore />
 */
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { ShieldCheck, ShieldAlert, ShieldQuestion } from "lucide-react";
import { ReactNode } from "react";

export type ConfidenceLevel = "high" | "moderate" | "low";

interface LevelConfig {
  label: string;
  icon: ReactNode;
  badgeClass: string;
  definition: string;
  characteristics: string[];
}

const LEVEL_CONFIG: Record<ConfidenceLevel, LevelConfig> = {
  high: {
    label: "HIGH",
    icon: <ShieldCheck className="h-2.5 w-2.5" />,
    badgeClass: "bg-emerald-600/80 text-white border-emerald-500/60",
    definition:
      "Analysis based on high-quality information from multiple independent sources, with corroborating evidence and sound logical inference.",
    characteristics: [
      "Multiple independent sources corroborate",
      "Evidence directly observed or confirmed through testing",
      "Short, well-supported inference chain",
      "Alternative explanations evaluated and rejected",
    ],
  },
  moderate: {
    label: "MOD",
    icon: <ShieldAlert className="h-2.5 w-2.5" />,
    badgeClass: "bg-amber-600/80 text-white border-amber-500/60",
    definition:
      "Credibly sourced information that is plausible and logically consistent but not fully corroborated. Relies on fewer independent sources or involves identifiable assumptions.",
    characteristics: [
      "Credibly sourced but not fully corroborated",
      "Inference chain involves identifiable assumptions",
      "Some alternative explanations remain plausible",
      "Evidence is indirect or partially confirmed",
    ],
  },
  low: {
    label: "LOW",
    icon: <ShieldQuestion className="h-2.5 w-2.5" />,
    badgeClass: "bg-zinc-600/80 text-zinc-200 border-zinc-500/60",
    definition:
      "Information whose credibility is questionable, or analysis based on fragmentary evidence with significant inference gaps. Analytical judgment may change with additional information.",
    characteristics: [
      "Single source or unverified information",
      "Significant inference gaps",
      "Multiple alternative explanations remain viable",
      "Evidence is fragmentary or circumstantial",
    ],
  },
};

/**
 * Convert a numeric confidence score (0.0–1.0) to an ICD 203 level.
 * Mirrors server-side scoreToLevel() from analytical-confidence.ts.
 */
export function scoreToLevel(score: number): ConfidenceLevel {
  if (score >= 0.80) return "high";
  if (score >= 0.50) return "moderate";
  return "low";
}

interface ConfidenceBadgeProps {
  /** Numeric confidence score (0.0–1.0). Takes priority over `level`. */
  score?: number | null;
  /** Direct confidence level string. Used if `score` is not provided. */
  level?: ConfidenceLevel | string | null;
  /** Size variant */
  size?: "xs" | "sm" | "md";
  /** Show icon alongside label */
  showIcon?: boolean;
  /** Show numeric score alongside level label */
  showScore?: boolean;
  /** Show tooltip on hover */
  showTooltip?: boolean;
  /** Additional className */
  className?: string;
}

/**
 * Normalize a level string to a valid ConfidenceLevel.
 */
function normalizeLevel(level: string | null | undefined): ConfidenceLevel {
  if (!level) return "low";
  const lower = level.toLowerCase().trim();
  if (lower === "high") return "high";
  if (lower === "moderate" || lower === "mod" || lower === "medium") return "moderate";
  return "low";
}

export function ConfidenceBadge({
  score,
  level,
  size = "xs",
  showIcon = true,
  showScore = false,
  showTooltip = true,
  className = "",
}: ConfidenceBadgeProps) {
  // Determine the confidence level
  const resolvedLevel: ConfidenceLevel =
    score != null ? scoreToLevel(score) : normalizeLevel(level);
  const config = LEVEL_CONFIG[resolvedLevel];

  const sizeClasses = {
    xs: "text-[8px] px-1.5 py-0 h-4 gap-0.5",
    sm: "text-[9px] px-2 py-0.5 gap-1",
    md: "text-[10px] px-2.5 py-0.5 gap-1",
  };

  const badge = (
    <Badge
      className={`${config.badgeClass} ${sizeClasses[size]} font-medium uppercase tracking-wider cursor-help ${className}`}
    >
      {showIcon && config.icon}
      {config.label}
      {showScore && score != null && (
        <span className="font-mono opacity-80 ml-0.5">
          {Math.round(score * 100)}%
        </span>
      )}
    </Badge>
  );

  if (!showTooltip) return badge;

  return (
    <Tooltip>
      <TooltipTrigger asChild>{badge}</TooltipTrigger>
      <TooltipContent side="top" className="max-w-sm text-xs space-y-2 p-3">
        <div className="font-semibold">
          ICD 203 Confidence: {resolvedLevel.toUpperCase()}
          {score != null && (
            <span className="font-mono ml-2 opacity-70">
              ({Math.round(score * 100)}%)
            </span>
          )}
        </div>
        <p className="text-muted-foreground leading-relaxed">{config.definition}</p>
        <ul className="text-muted-foreground space-y-0.5 list-disc list-inside">
          {config.characteristics.map((c, i) => (
            <li key={i}>{c}</li>
          ))}
        </ul>
      </TooltipContent>
    </Tooltip>
  );
}

/**
 * Compact inline confidence indicator — just the colored dot + level text.
 * For use in tight table cells where the full badge is too wide.
 */
export function ConfidenceDot({
  score,
  level,
}: {
  score?: number | null;
  level?: ConfidenceLevel | string | null;
}) {
  const resolvedLevel: ConfidenceLevel =
    score != null ? scoreToLevel(score) : normalizeLevel(level);

  const dotColors: Record<ConfidenceLevel, string> = {
    high: "bg-emerald-400",
    moderate: "bg-amber-400",
    low: "bg-zinc-400",
  };

  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <span className="inline-flex items-center gap-1 cursor-help">
          <span className={`inline-block w-1.5 h-1.5 rounded-full ${dotColors[resolvedLevel]}`} />
          <span className="text-[9px] font-mono text-muted-foreground uppercase">
            {resolvedLevel === "moderate" ? "mod" : resolvedLevel}
          </span>
        </span>
      </TooltipTrigger>
      <TooltipContent side="top" className="text-xs">
        ICD 203: {resolvedLevel.toUpperCase()} confidence
        {score != null && ` (${Math.round(score * 100)}%)`}
      </TooltipContent>
    </Tooltip>
  );
}

/**
 * Returns the level config for custom rendering scenarios.
 */
export function getConfidenceLevelConfig(
  scoreOrLevel: number | string | null | undefined
): LevelConfig {
  if (typeof scoreOrLevel === "number") {
    return LEVEL_CONFIG[scoreToLevel(scoreOrLevel)];
  }
  return LEVEL_CONFIG[normalizeLevel(scoreOrLevel as string)];
}

export default ConfidenceBadge;
