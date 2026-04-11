/**
 * FingerprintDiffPanel
 *
 * Visual diff view for the Engagement Ops scope tab showing side-by-side
 * service changes between scans with color-coded severity indicators.
 * Displays posture assessment, CVE delta, version changes, and new/removed services.
 */
import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Shield, ShieldAlert, ShieldCheck, ShieldX,
  ArrowUpRight, ArrowDownRight, Plus, Minus,
  Clock, Server, AlertTriangle, ChevronDown, ChevronUp,
  Activity, Database,
} from "lucide-react";

interface Props {
  engagementId: number;
}

const severityColors: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-slate-500/20 text-slate-400 border-slate-500/30",
};

const changeTypeIcons: Record<string, React.ReactNode> = {
  new_service: <Plus className="w-3.5 h-3.5 text-emerald-400" />,
  removed_service: <Minus className="w-3.5 h-3.5 text-red-400" />,
  version_upgrade: <ArrowUpRight className="w-3.5 h-3.5 text-emerald-400" />,
  version_downgrade: <ArrowDownRight className="w-3.5 h-3.5 text-orange-400" />,
  product_change: <Server className="w-3.5 h-3.5 text-blue-400" />,
  security_improvement: <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />,
  security_degradation: <ShieldX className="w-3.5 h-3.5 text-red-400" />,
  tls_change: <Shield className="w-3.5 h-3.5 text-yellow-400" />,
  new_cves: <AlertTriangle className="w-3.5 h-3.5 text-red-400" />,
  resolved_cves: <ShieldCheck className="w-3.5 h-3.5 text-emerald-400" />,
  banner_change: <Activity className="w-3.5 h-3.5 text-slate-400" />,
  os_change: <Database className="w-3.5 h-3.5 text-blue-400" />,
  confidence_change: <Activity className="w-3.5 h-3.5 text-slate-400" />,
};

const postureConfig: Record<string, { icon: React.ReactNode; color: string; label: string }> = {
  improved: { icon: <ShieldCheck className="w-5 h-5" />, color: "text-emerald-400", label: "IMPROVED" },
  degraded: { icon: <ShieldAlert className="w-5 h-5" />, color: "text-red-400", label: "DEGRADED" },
  unchanged: { icon: <Shield className="w-5 h-5" />, color: "text-slate-400", label: "UNCHANGED" },
  mixed: { icon: <ShieldAlert className="w-5 h-5" />, color: "text-yellow-400", label: "MIXED" },
};

function formatTimestamp(ts: number): string {
  return new Date(ts).toLocaleString(undefined, {
    month: "short", day: "numeric", hour: "2-digit", minute: "2-digit",
  });
}

function formatTimeDelta(ms: number): string {
  const hours = Math.floor(ms / 3600000);
  const minutes = Math.floor((ms % 3600000) / 60000);
  if (hours > 24) {
    const days = Math.floor(hours / 24);
    return `${days}d ${hours % 24}h`;
  }
  return hours > 0 ? `${hours}h ${minutes}m` : `${minutes}m`;
}

export default function FingerprintDiffPanel({ engagementId }: Props) {
  const [expanded, setExpanded] = useState(false);
  const [showAllChanges, setShowAllChanges] = useState(false);

  const { data, isLoading, error } = trpc.serviceFingerprint.getFingerprintDiff.useQuery(
    { engagementId },
    { refetchInterval: 30000 },
  );

  if (isLoading) {
    return (
      <Card className="border-border/50 bg-card/50 backdrop-blur">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400 animate-pulse" />
            Loading Fingerprint History...
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="space-y-2">
            {[1, 2, 3].map(i => (
              <div key={i} className="h-8 bg-muted/30 rounded animate-pulse" />
            ))}
          </div>
        </CardContent>
      </Card>
    );
  }

  if (error || !data) {
    return null;
  }

  // No fingerprint data at all
  if (!data.currentScan && !data.report) {
    return (
      <Card className="border-border/50 bg-card/50 backdrop-blur">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Activity className="w-4 h-4 text-slate-500" />
            Fingerprint History
          </CardTitle>
        </CardHeader>
        <CardContent>
          <p className="text-xs text-muted-foreground">
            No fingerprint scans recorded yet. Service fingerprinting will run automatically during the discovery phase.
          </p>
        </CardContent>
      </Card>
    );
  }

  // Has data but no diff (only one scan)
  if (!data.hasDiff && data.currentScan && "services" in data.currentScan) {
    const scan = data.currentScan as {
      time: number;
      serviceCount: number;
      services: Array<{
        host: string; port: number; protocol: string | null;
        product: string | null; version: string | null;
        confidence: number | null; cves: string[];
      }>;
    };
    return (
      <Card className="border-border/50 bg-card/50 backdrop-blur">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-medium flex items-center gap-2">
              <Activity className="w-4 h-4 text-cyan-400" />
              Fingerprint Snapshot
            </CardTitle>
            <Badge variant="outline" className="text-[10px] border-slate-600 text-slate-400">
              {formatTimestamp(scan.time)}
            </Badge>
          </div>
        </CardHeader>
        <CardContent className="space-y-3">
          <p className="text-xs text-muted-foreground">{data.summary}</p>
          <div className="grid grid-cols-2 gap-2">
            <div className="rounded-md bg-muted/20 p-2 text-center">
              <div className="text-lg font-bold text-foreground">{scan.serviceCount}</div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">Services</div>
            </div>
            <div className="rounded-md bg-muted/20 p-2 text-center">
              <div className="text-lg font-bold text-foreground">
                {scan.services.reduce((sum, s) => sum + s.cves.length, 0)}
              </div>
              <div className="text-[10px] text-muted-foreground uppercase tracking-wider">CVEs</div>
            </div>
          </div>
          {scan.services.length > 0 && (
            <div className="space-y-1">
              {scan.services.slice(0, 6).map((svc, i) => (
                <div key={i} className="flex items-center justify-between text-xs py-1 px-2 rounded bg-muted/10">
                  <span className="text-muted-foreground font-mono">
                    :{svc.port} <span className="text-foreground">{svc.product || svc.protocol || "unknown"}</span>
                    {svc.version && <span className="text-cyan-400 ml-1">{svc.version}</span>}
                  </span>
                  {svc.cves.length > 0 && (
                    <Badge variant="outline" className="text-[9px] border-red-500/30 text-red-400">
                      {svc.cves.length} CVE{svc.cves.length > 1 ? "s" : ""}
                    </Badge>
                  )}
                </div>
              ))}
              {scan.services.length > 6 && (
                <p className="text-[10px] text-muted-foreground text-center">
                  +{scan.services.length - 6} more services
                </p>
              )}
            </div>
          )}
        </CardContent>
      </Card>
    );
  }

  // Full diff report
  if (!data.hasDiff || !data.report) return null;
  const report = data.report;
  const posture = postureConfig[report.postureChange] || postureConfig.unchanged;
  const visibleChanges = showAllChanges ? report.changes : report.changes.slice(0, 8);

  return (
    <Card className="border-border/50 bg-card/50 backdrop-blur">
      <CardHeader className="pb-3">
        <div className="flex items-center justify-between">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Activity className="w-4 h-4 text-cyan-400" />
            Fingerprint Diff
          </CardTitle>
          <Button
            variant="ghost" size="sm"
            className="h-6 px-2 text-xs"
            onClick={() => setExpanded(!expanded)}
          >
            {expanded ? <ChevronUp className="w-3 h-3" /> : <ChevronDown className="w-3 h-3" />}
          </Button>
        </div>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Posture Banner */}
        <div className={`flex items-center justify-between rounded-lg p-3 ${
          report.postureChange === "degraded" ? "bg-red-500/10 border border-red-500/20" :
          report.postureChange === "improved" ? "bg-emerald-500/10 border border-emerald-500/20" :
          report.postureChange === "mixed" ? "bg-yellow-500/10 border border-yellow-500/20" :
          "bg-muted/20 border border-border/30"
        }`}>
          <div className="flex items-center gap-3">
            <div className={posture.color}>{posture.icon}</div>
            <div>
              <div className={`text-sm font-semibold ${posture.color}`}>{posture.label}</div>
              <div className="text-[10px] text-muted-foreground">
                {report.totalChanges} change{report.totalChanges !== 1 ? "s" : ""} detected
                {report.timeDelta && ` over ${formatTimeDelta(report.timeDelta)}`}
              </div>
            </div>
          </div>
          <div className="text-right">
            <div className={`text-lg font-bold ${
              report.riskScoreDelta > 0 ? "text-red-400" :
              report.riskScoreDelta < 0 ? "text-emerald-400" : "text-slate-400"
            }`}>
              {report.riskScoreDelta > 0 ? "+" : ""}{report.riskScoreDelta}
            </div>
            <div className="text-[10px] text-muted-foreground">Risk Delta</div>
          </div>
        </div>

        {/* Scan Timeline */}
        <div className="flex items-center gap-2 text-[10px] text-muted-foreground">
          <Clock className="w-3 h-3" />
          <span>{data.previousScan ? formatTimestamp(data.previousScan.time) : "?"}</span>
          <span className="text-muted-foreground/50">→</span>
          <span className="text-foreground">{data.currentScan ? formatTimestamp(data.currentScan.time) : "now"}</span>
          <span className="ml-auto">
            {data.previousScan?.serviceCount || 0} → {data.currentScan?.serviceCount || 0} services
          </span>
        </div>

        {/* Severity Breakdown */}
        <div className="flex gap-1.5">
          {(["critical", "high", "medium", "low", "info"] as const).map(sev => {
            const count = report.changeBySeverity[sev];
            if (!count) return null;
            return (
              <Badge key={sev} variant="outline" className={`text-[10px] ${severityColors[sev]}`}>
                {count} {sev}
              </Badge>
            );
          })}
        </div>

        {/* Version Changes */}
        {report.versionChanges.length > 0 && (
          <div className="space-y-1.5">
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">
              Version Changes
            </div>
            {report.versionChanges.map((vc, i) => (
              <div key={i} className="flex items-center gap-2 text-xs py-1.5 px-2 rounded bg-muted/10">
                {vc.direction === "upgrade" ? (
                  <ArrowUpRight className="w-3.5 h-3.5 text-emerald-400 shrink-0" />
                ) : (
                  <ArrowDownRight className="w-3.5 h-3.5 text-orange-400 shrink-0" />
                )}
                <span className="font-mono text-muted-foreground">:{vc.port}</span>
                <span className="text-foreground">{vc.product || "Service"}</span>
                <span className="text-red-400/70 line-through">{vc.oldVersion}</span>
                <span className="text-muted-foreground">→</span>
                <span className={vc.direction === "upgrade" ? "text-emerald-400" : "text-orange-400"}>
                  {vc.newVersion}
                </span>
              </div>
            ))}
          </div>
        )}

        {/* New / Removed Services */}
        {(report.newServices.length > 0 || report.removedServices.length > 0) && (
          <div className="grid grid-cols-2 gap-2">
            {report.newServices.length > 0 && (
              <div className="space-y-1">
                <div className="text-[10px] uppercase tracking-wider text-emerald-400/70 font-medium">
                  + New Services
                </div>
                {report.newServices.map((svc, i) => (
                  <div key={i} className="text-xs py-1 px-2 rounded bg-emerald-500/5 border border-emerald-500/10">
                    <span className="font-mono text-muted-foreground">:{svc.port}</span>{" "}
                    <span className="text-emerald-400">{svc.product || "unknown"}</span>
                  </div>
                ))}
              </div>
            )}
            {report.removedServices.length > 0 && (
              <div className="space-y-1">
                <div className="text-[10px] uppercase tracking-wider text-red-400/70 font-medium">
                  - Removed Services
                </div>
                {report.removedServices.map((svc, i) => (
                  <div key={i} className="text-xs py-1 px-2 rounded bg-red-500/5 border border-red-500/10">
                    <span className="font-mono text-muted-foreground">:{svc.port}</span>{" "}
                    <span className="text-red-400 line-through">{svc.product || "unknown"}</span>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* CVE Delta */}
        {(report.cveDelta.newCves.length > 0 || report.cveDelta.resolvedCves.length > 0) && (
          <div className="space-y-1.5">
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">
              CVE Delta
            </div>
            {report.cveDelta.newCves.length > 0 && (
              <div className="text-xs py-1.5 px-2 rounded bg-red-500/5 border border-red-500/10">
                <span className="text-red-400 font-medium">+{report.cveDelta.newCves.length} new:</span>{" "}
                <span className="text-muted-foreground font-mono">
                  {report.cveDelta.newCves.slice(0, 5).join(", ")}
                  {report.cveDelta.newCves.length > 5 ? "..." : ""}
                </span>
              </div>
            )}
            {report.cveDelta.resolvedCves.length > 0 && (
              <div className="text-xs py-1.5 px-2 rounded bg-emerald-500/5 border border-emerald-500/10">
                <span className="text-emerald-400 font-medium">-{report.cveDelta.resolvedCves.length} resolved:</span>{" "}
                <span className="text-muted-foreground font-mono line-through">
                  {report.cveDelta.resolvedCves.slice(0, 5).join(", ")}
                  {report.cveDelta.resolvedCves.length > 5 ? "..." : ""}
                </span>
              </div>
            )}
            {report.cveDelta.persistentCves.length > 0 && (
              <div className="text-xs py-1.5 px-2 rounded bg-yellow-500/5 border border-yellow-500/10">
                <span className="text-yellow-400 font-medium">{report.cveDelta.persistentCves.length} persistent</span>{" "}
                <span className="text-muted-foreground">(unpatched across scans)</span>
              </div>
            )}
          </div>
        )}

        {/* Expanded: All Changes */}
        {expanded && (
          <div className="space-y-1.5">
            <div className="text-[10px] uppercase tracking-wider text-muted-foreground font-medium">
              All Changes
            </div>
            {visibleChanges.map((change, i) => (
              <div
                key={i}
                className="flex items-start gap-2 text-xs py-2 px-2.5 rounded bg-muted/10 border border-border/20"
              >
                <div className="mt-0.5 shrink-0">
                  {changeTypeIcons[change.changeType] || <Activity className="w-3.5 h-3.5 text-slate-400" />}
                </div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-1.5">
                    <Badge variant="outline" className={`text-[9px] ${severityColors[change.severity]}`}>
                      {change.severity}
                    </Badge>
                    <span className="font-mono text-muted-foreground">{change.host}:{change.port}</span>
                  </div>
                  <div className="text-foreground mt-0.5">{change.description}</div>
                  {change.previousValue && change.currentValue && (
                    <div className="mt-1 text-[10px] text-muted-foreground">
                      <span className="text-red-400/70 line-through">{change.previousValue}</span>
                      {" → "}
                      <span className="text-emerald-400/70">{change.currentValue}</span>
                    </div>
                  )}
                  {change.recommendation && (
                    <div className="mt-1 text-[10px] text-cyan-400/70 italic">{change.recommendation}</div>
                  )}
                </div>
              </div>
            ))}
            {report.changes.length > 8 && (
              <Button
                variant="ghost" size="sm"
                className="w-full h-7 text-xs text-muted-foreground"
                onClick={() => setShowAllChanges(!showAllChanges)}
              >
                {showAllChanges ? "Show less" : `Show all ${report.changes.length} changes`}
              </Button>
            )}
          </div>
        )}
      </CardContent>
    </Card>
  );
}
