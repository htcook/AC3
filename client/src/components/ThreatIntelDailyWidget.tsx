import { trpc } from "@/lib/trpc";
import { Activity, AlertTriangle, CheckCircle2, Clock, Loader2, Radio, XCircle, Zap } from "lucide-react";
import { Link } from "wouter";

function formatDuration(ms: number | null | undefined): string {
  if (!ms) return "—";
  if (ms < 1000) return `${ms}ms`;
  if (ms < 60000) return `${Math.round(ms / 1000)}s`;
  return `${Math.round(ms / 60000)}m ${Math.round((ms % 60000) / 1000)}s`;
}

function formatTimeAgo(dateStr: string | null | undefined): string {
  if (!dateStr) return "Never";
  const diff = Date.now() - new Date(dateStr).getTime();
  if (diff < 60000) return "Just now";
  if (diff < 3600000) return `${Math.round(diff / 60000)}m ago`;
  if (diff < 86400000) return `${Math.round(diff / 3600000)}h ago`;
  return `${Math.round(diff / 86400000)}d ago`;
}

export default function ThreatIntelDailyWidget() {
  const { data, isLoading } = trpc.threatIntel.dailyRunSummary.useQuery();

  if (isLoading) {
    return (
      <div className="border border-border bg-card p-4">
        <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
          <Radio className="w-4 h-4 text-emerald-400" /> DAILY INTEL UPDATE
        </h3>
        <div className="flex items-center justify-center py-4">
          <Loader2 className="w-4 h-4 animate-spin text-muted-foreground" />
        </div>
      </div>
    );
  }

  if (!data) return null;

  const statusIcon = data.latestRun?.status === "completed"
    ? <CheckCircle2 className="w-3.5 h-3.5 text-emerald-400" />
    : data.latestRun?.status === "running"
    ? <Loader2 className="w-3.5 h-3.5 text-blue-400 animate-spin" />
    : data.latestRun?.status === "failed"
    ? <XCircle className="w-3.5 h-3.5 text-red-400" />
    : <Clock className="w-3.5 h-3.5 text-muted-foreground" />;

  const statusColor = data.latestRun?.status === "completed"
    ? "text-emerald-400"
    : data.latestRun?.status === "running"
    ? "text-blue-400"
    : data.latestRun?.status === "failed"
    ? "text-red-400"
    : "text-muted-foreground";

  return (
    <div className="border border-border bg-card p-4">
      <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
        <Radio className="w-4 h-4 text-emerald-400" /> DAILY INTEL UPDATE
      </h3>

      {/* Latest Run Status */}
      {data.latestRun ? (
        <div className="space-y-3">
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-2">
              {statusIcon}
              <span className={`text-xs font-display tracking-wider ${statusColor}`}>
                {(data.latestRun.status || "unknown").toUpperCase()}
              </span>
            </div>
            <span className="text-[10px] text-muted-foreground">
              {formatTimeAgo(data.latestRun.startedAt)}
            </span>
          </div>

          {/* Run Metrics */}
          <div className="grid grid-cols-2 gap-2">
            <div className="bg-secondary/30 p-2 rounded">
              <p className="text-lg font-display font-bold">{data.latestRun.newEventsFound || 0}</p>
              <p className="text-[9px] font-display tracking-widest text-muted-foreground">NEW EVENTS</p>
            </div>
            <div className="bg-secondary/30 p-2 rounded">
              <p className="text-lg font-display font-bold">{data.latestRun.newIocsFound || 0}</p>
              <p className="text-[9px] font-display tracking-widest text-muted-foreground">NEW IOCs</p>
            </div>
            <div className="bg-secondary/30 p-2 rounded">
              <p className="text-lg font-display font-bold">{data.latestRun.groupsScanned || 0}</p>
              <p className="text-[9px] font-display tracking-widest text-muted-foreground">GROUPS SCANNED</p>
            </div>
            <div className="bg-secondary/30 p-2 rounded">
              <p className="text-lg font-display font-bold">{formatDuration(data.latestRun.durationMs)}</p>
              <p className="text-[9px] font-display tracking-widest text-muted-foreground">DURATION</p>
            </div>
          </div>

          {/* 24h Summary */}
          <div className="border-t border-border pt-3 space-y-2">
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground flex items-center gap-1.5">
                <Activity className="w-3 h-3" /> Events (24h)
              </span>
              <span className="font-mono">{data.eventsLast24h}</span>
            </div>
            {data.criticalAlerts > 0 && (
              <div className="flex items-center justify-between text-xs">
                <span className="text-red-400 flex items-center gap-1.5">
                  <AlertTriangle className="w-3 h-3" /> Critical Alerts
                </span>
                <span className="font-mono text-red-400">{data.criticalAlerts}</span>
              </div>
            )}
            {data.highAlerts > 0 && (
              <div className="flex items-center justify-between text-xs">
                <span className="text-orange-400 flex items-center gap-1.5">
                  <Zap className="w-3 h-3" /> High Alerts
                </span>
                <span className="font-mono text-orange-400">{data.highAlerts}</span>
              </div>
            )}
            <div className="flex items-center justify-between text-xs">
              <span className="text-muted-foreground">Runs (7d)</span>
              <span className="font-mono">{data.runsLast7Days}</span>
            </div>
          </div>

          {/* Critical Items */}
          {data.topCritical && data.topCritical.length > 0 && (
            <div className="border-t border-border pt-3">
              <p className="text-[9px] font-display tracking-widest text-red-400 mb-2">CRITICAL ITEMS</p>
              <div className="space-y-1.5">
                {data.topCritical.map((item: any, i: number) => (
                  <Link key={i} href={`/threat-catalog/${item.actorId}`}>
                    <div className="p-2 bg-red-500/5 border border-red-500/20 rounded hover:bg-red-500/10 transition-colors cursor-pointer">
                      <p className="text-[11px] text-foreground truncate">{item.title}</p>
                      <p className="text-[9px] text-muted-foreground mt-0.5">{item.actorId} • {item.date}</p>
                    </div>
                  </Link>
                ))}
              </div>
            </div>
          )}
        </div>
      ) : (
        <div className="text-center py-4">
          <p className="text-xs text-muted-foreground">No runs recorded yet</p>
          <p className="text-[10px] text-muted-foreground mt-1">Scheduled daily at 06:00 EDT</p>
        </div>
      )}
    </div>
  );
}
