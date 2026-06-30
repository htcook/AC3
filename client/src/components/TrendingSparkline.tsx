import { trpc } from "@/lib/trpc";
import { useMemo } from "react";
import { TrendingUp, TrendingDown, Minus } from "lucide-react";

interface DayTrend {
  date: string;
  critical: number;
  high: number;
  medium: number;
  low: number;
  total: number;
}

const SEVERITY_COLORS = {
  critical: "#ef4444",
  high: "#f97316",
  medium: "#eab308",
  low: "#22c55e",
};

/**
 * Pure SVG sparkline showing 7-day CVE trend by severity.
 * Renders as a stacked area chart with hover tooltips.
 */
export default function TrendingSparkline() {
  const { data: trendData, isLoading } = trpc.calderaProxy.getVulnTrendData.useQuery(
    { days: 7 },
    { staleTime: 5 * 60 * 1000 }
  );

  const { paths, maxY, totalThisWeek, deltaPercent, dayLabels, dayTotals, severityTotals } = useMemo(() => {
    if (!trendData || trendData.length === 0) {
      return { paths: {}, maxY: 0, totalThisWeek: 0, deltaPercent: 0, dayLabels: [], dayTotals: [], severityTotals: { critical: 0, high: 0, medium: 0, low: 0 } };
    }

    const data = trendData as DayTrend[];
    const maxTotal = Math.max(...data.map(d => d.total), 1);
    const totalThisWeek = data.reduce((s, d) => s + d.total, 0);

    // Calculate delta: compare last 3 days vs first 3 days
    const recentSum = data.slice(-3).reduce((s, d) => s + d.total, 0);
    const earlierSum = data.slice(0, 3).reduce((s, d) => s + d.total, 0);
    const deltaPercent = earlierSum > 0 ? Math.round(((recentSum - earlierSum) / earlierSum) * 100) : 0;

    const sevTotals = { critical: 0, high: 0, medium: 0, low: 0 };
    data.forEach(d => {
      sevTotals.critical += d.critical;
      sevTotals.high += d.high;
      sevTotals.medium += d.medium;
      sevTotals.low += d.low;
    });

    const W = 280;
    const H = 52;
    const PAD_X = 2;
    const PAD_Y = 4;
    const usableW = W - PAD_X * 2;
    const usableH = H - PAD_Y * 2;
    const stepX = data.length > 1 ? usableW / (data.length - 1) : 0;

    // Build stacked area paths (bottom to top: low, medium, high, critical)
    const severities: Array<keyof typeof SEVERITY_COLORS> = ["low", "medium", "high", "critical"];
    const stackedPaths: Record<string, string> = {};

    // Calculate cumulative values for stacking
    const cumulative = data.map(d => {
      let sum = 0;
      const vals: Record<string, number> = {};
      for (const sev of severities) {
        sum += d[sev];
        vals[sev] = sum;
      }
      return vals;
    });

    for (let si = 0; si < severities.length; si++) {
      const sev = severities[si];
      const prevSev = si > 0 ? severities[si - 1] : null;

      // Top line (current severity cumulative)
      const topPoints = data.map((_, i) => {
        const x = PAD_X + i * stepX;
        const y = PAD_Y + usableH - (cumulative[i][sev] / maxTotal) * usableH;
        return `${x},${y}`;
      });

      // Bottom line (previous severity cumulative, or baseline)
      const bottomPoints = data.map((_, i) => {
        const x = PAD_X + i * stepX;
        const y = prevSev
          ? PAD_Y + usableH - (cumulative[i][prevSev] / maxTotal) * usableH
          : PAD_Y + usableH;
        return `${x},${y}`;
      }).reverse();

      stackedPaths[sev] = `M${topPoints.join(" L")} L${bottomPoints.join(" L")} Z`;
    }

    // Total line on top
    const totalLinePoints = data.map((d, i) => {
      const x = PAD_X + i * stepX;
      const y = PAD_Y + usableH - (d.total / maxTotal) * usableH;
      return `${x},${y}`;
    });

    stackedPaths._totalLine = `M${totalLinePoints.join(" L")}`;

    const dayLabels = data.map(d => {
      const dt = new Date(d.date + "T00:00:00");
      return dt.toLocaleDateString("en-US", { weekday: "short" }).slice(0, 2);
    });

    const dayTotals = data.map(d => d.total);

    return {
      paths: stackedPaths,
      maxY: maxTotal,
      totalThisWeek,
      deltaPercent,
      dayLabels,
      dayTotals,
      severityTotals: sevTotals,
    };
  }, [trendData]);

  if (isLoading) {
    return (
      <div className="bg-card border border-border p-3 animate-pulse">
        <div className="h-[80px] bg-muted/30 rounded" />
      </div>
    );
  }

  if (!trendData || trendData.length === 0) {
    return null;
  }

  const TrendIcon = deltaPercent > 0 ? TrendingUp : deltaPercent < 0 ? TrendingDown : Minus;
  const trendColor = deltaPercent > 10 ? "text-red-500" : deltaPercent < -10 ? "text-green-500" : "text-yellow-500";

  return (
    <div className="bg-card border border-border p-3 space-y-2">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <TrendingUp className="w-3.5 h-3.5 text-primary" />
          <span className="text-[10px] font-display tracking-widest text-muted-foreground">7-DAY CVE TREND</span>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs font-display font-bold text-foreground">{totalThisWeek}</span>
          <span className="text-[9px] text-muted-foreground">CVEs</span>
          <span className={`flex items-center gap-0.5 text-[10px] font-display ${trendColor}`}>
            <TrendIcon className="w-3 h-3" />
            {deltaPercent > 0 ? "+" : ""}{deltaPercent}%
          </span>
        </div>
      </div>

      {/* SVG Sparkline */}
      <div className="relative">
        <svg
          viewBox="0 0 280 52"
          className="w-full h-[52px]"
          preserveAspectRatio="none"
          aria-label="7-day CVE severity trend chart"
        >
          {/* Grid lines */}
          <line x1="2" y1="4" x2="278" y2="4" stroke="currentColor" strokeOpacity="0.05" strokeWidth="0.5" />
          <line x1="2" y1="28" x2="278" y2="28" stroke="currentColor" strokeOpacity="0.05" strokeWidth="0.5" />
          <line x1="2" y1="48" x2="278" y2="48" stroke="currentColor" strokeOpacity="0.08" strokeWidth="0.5" />

          {/* Stacked area fills */}
          {(["low", "medium", "high", "critical"] as const).map(sev => (
            paths[sev] ? (
              <path
                key={sev}
                d={paths[sev]}
                fill={SEVERITY_COLORS[sev]}
                fillOpacity="0.25"
                stroke="none"
              />
            ) : null
          ))}

          {/* Total line */}
          {paths._totalLine && (
            <path
              d={paths._totalLine}
              fill="none"
              stroke="currentColor"
              strokeOpacity="0.4"
              strokeWidth="1.5"
              strokeLinecap="round"
              strokeLinejoin="round"
            />
          )}

          {/* Data points */}
          {dayTotals.map((total, i) => {
            const x = 2 + (i * 276) / Math.max(dayTotals.length - 1, 1);
            const y = 4 + 44 - (total / maxY) * 44;
            return (
              <g key={i}>
                <circle cx={x} cy={y} r="2.5" fill="currentColor" fillOpacity="0.3" />
                <circle cx={x} cy={y} r="1.5" fill="currentColor" fillOpacity="0.6" />
              </g>
            );
          })}
        </svg>

        {/* Day labels below chart */}
        <div className="flex justify-between px-0.5 mt-1">
          {dayLabels.map((label, i) => (
            <div key={i} className="flex flex-col items-center">
              <span className="text-[8px] font-display tracking-wider text-muted-foreground/60">{label}</span>
              <span className="text-[9px] font-mono text-muted-foreground">{dayTotals[i] || 0}</span>
            </div>
          ))}
        </div>
      </div>

      {/* Severity breakdown mini-bar */}
      <div className="flex items-center gap-3 pt-0.5">
        {(["critical", "high", "medium", "low"] as const).map(sev => (
          <div key={sev} className="flex items-center gap-1">
            <div className="w-2 h-2 rounded-sm" style={{ backgroundColor: SEVERITY_COLORS[sev], opacity: 0.7 }} />
            <span className="text-[9px] font-display tracking-wider text-muted-foreground">
              {sev.toUpperCase()}
            </span>
            <span className="text-[9px] font-mono text-foreground/70">{severityTotals[sev]}</span>
          </div>
        ))}
      </div>
    </div>
  );
}
