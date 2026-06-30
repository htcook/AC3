/**
 * KpiStrip — Persistent horizontal strip of KPI cards
 * 
 * Design Bundle: "Mission Posture Strip" — 6-8 KPI cards that never scroll away,
 * giving operators instant situational awareness at all times.
 * 
 * Delta indicators show changes since the last scan/state with arrows,
 * absolute change values, and percentage changes.
 */
import React, { ReactNode } from "react";
import { TrendingUp, TrendingDown, Minus, ArrowUp, ArrowDown } from "lucide-react";

export interface KpiItem {
  label: string;
  value: number | string;
  icon: ReactNode;
  /** Optional color class for the value text */
  color?: string;
  /** Optional delta from previous scan/state (absolute change) */
  delta?: number | null;
  /** Optional percentage change from previous value */
  deltaPercent?: number | null;
  /** If true, positive delta is bad (e.g., risk score going up, vulns increasing) */
  deltaInverted?: boolean;
  /** Optional subtitle text below the value */
  subtitle?: string;
  /** Optional suffix (e.g., "%", "/10") */
  suffix?: string;
  /** Optional progress bar (0-100) */
  progress?: number;
  /** Optional progress bar color class */
  progressColor?: string;
  /** Optional click handler for drill-down navigation */
  onClick?: () => void;
}

interface KpiStripProps {
  items: KpiItem[];
  className?: string;
}

export function KpiStrip({ items, className = "" }: KpiStripProps) {
  return (
    <div className={`flex-none border-b border-border/30 bg-card/40 backdrop-blur-sm ${className}`}>
      <div className="px-4 py-3">
        <div className="grid gap-2" style={{ gridTemplateColumns: `repeat(${Math.min(items.length, 8)}, minmax(0, 1fr))` }}>
          {items.map((item, i) => (
            <KpiCard key={i} item={item} />
          ))}
        </div>
      </div>
    </div>
  );
}

function KpiCard({ item }: { item: KpiItem }) {
  const hasDelta = item.delta != null && item.delta !== 0;
  const hasPercent = item.deltaPercent != null && item.deltaPercent !== 0;
  const showDelta = hasDelta || hasPercent;

  // Determine if the change is positive or negative in the "good/bad" sense
  const isPositiveChange = item.delta != null ? item.delta > 0 : (item.deltaPercent != null ? item.deltaPercent > 0 : false);
  const isNegativeChange = item.delta != null ? item.delta < 0 : (item.deltaPercent != null ? item.deltaPercent < 0 : false);
  const isNeutral = !isPositiveChange && !isNegativeChange;

  // Color: green = good, red = bad. deltaInverted flips the meaning.
  const deltaColor = isNeutral
    ? "text-muted-foreground"
    : item.deltaInverted
      ? isPositiveChange ? "text-red-400" : "text-emerald-400"
      : isPositiveChange ? "text-emerald-400" : "text-red-400";

  const DeltaArrow = isPositiveChange ? ArrowUp : isNegativeChange ? ArrowDown : null;

  // Format the delta display
  const formatDelta = () => {
    const parts: string[] = [];
    if (hasDelta) {
      const sign = item.delta! > 0 ? "+" : "";
      parts.push(`${sign}${item.delta!.toLocaleString()}`);
    }
    if (hasPercent) {
      const pct = item.deltaPercent!;
      const sign = pct > 0 ? "+" : "";
      const capped = Math.abs(pct) > 999 ? `${sign}${pct > 0 ? '' : '-'}999%+` : `${sign}${pct.toFixed(1)}%`;
      parts.push(capped);
    }
    return parts.join(" ");
  };

  return (
    <div
      className={`flex items-center gap-2.5 rounded-lg border border-border/40 bg-background/50 px-3 py-2 min-w-0 group relative transition-all duration-150 ${item.onClick ? 'cursor-pointer hover:border-primary/50 hover:bg-primary/5 active:scale-[0.98]' : ''}`}
      onClick={item.onClick}
      role={item.onClick ? 'button' : undefined}
      tabIndex={item.onClick ? 0 : undefined}
      onKeyDown={item.onClick ? (e: React.KeyboardEvent) => { if (e.key === 'Enter' || e.key === ' ') { e.preventDefault(); item.onClick!(); } } : undefined}
    >
      <div className="flex-none text-muted-foreground/70">
        {item.icon}
      </div>
      <div className="flex-1 min-w-0">
        <div className="flex items-baseline gap-1">
          <span className={`text-lg font-bold tabular-nums leading-none ${item.color || "text-foreground"}`}>
            {typeof item.value === 'number' ? item.value.toLocaleString() : item.value}
          </span>
          {item.suffix && (
            <span className="text-xs text-muted-foreground">{item.suffix}</span>
          )}
          {showDelta && DeltaArrow && (
            <span className={`flex items-center gap-0.5 text-[10px] font-medium tabular-nums ${deltaColor}`}>
              <DeltaArrow className="h-2.5 w-2.5" />
              {formatDelta()}
            </span>
          )}
        </div>
        <p className="text-[10px] text-muted-foreground leading-tight mt-0.5 truncate">
          {item.label}
        </p>
        {item.subtitle && (
          <p className="text-[9px] text-muted-foreground/60 truncate">{item.subtitle}</p>
        )}
        {item.progress != null && (
          <div className="mt-1 h-1 w-full bg-muted/30 rounded-full overflow-hidden">
            <div
              className={`h-full rounded-full transition-all duration-700 ${item.progressColor || "bg-primary"}`}
              style={{ width: `${Math.max(2, Math.min(100, item.progress))}%` }}
            />
          </div>
        )}
      </div>
    </div>
  );
}

export default KpiStrip;
