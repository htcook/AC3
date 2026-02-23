import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import {
  Shield, AlertTriangle, Crosshair, Activity, Clock, User, Target,
  ChevronLeft, ChevronRight, Search, Filter, FileText
} from "lucide-react";
import AppShell from "@/components/AppShell";

const RISK_TIER_STYLES: Record<string, { bg: string; text: string; label: string }> = {
  yellow: { bg: "bg-amber-500/10 border-amber-500/30", text: "text-amber-400", label: "YELLOW" },
  orange: { bg: "bg-orange-500/10 border-orange-500/30", text: "text-orange-400", label: "ORANGE" },
  red: { bg: "bg-red-500/10 border-red-500/30", text: "text-red-400", label: "RED" },
};

const RESULT_STYLES: Record<string, { bg: string; text: string }> = {
  success: { bg: "bg-emerald-500/10", text: "text-emerald-400" },
  failure: { bg: "bg-red-500/10", text: "text-red-400" },
  blocked: { bg: "bg-amber-500/10", text: "text-amber-400" },
  pending_approval: { bg: "bg-blue-500/10", text: "text-blue-400" },
};

const ACTION_LABELS: Record<string, string> = {
  active_probe: "Active Probe",
  msf_check: "MSF Check",
  msf_auxiliary: "MSF Auxiliary",
  msf_exploit: "MSF Exploit",
  phishing_launch: "Phishing Launch",
  caldera_operation: "Caldera Operation",
  payload_delivery: "Payload Delivery",
  session_interaction: "Session Interaction",
};

export default function AuditLog() {
  const [riskFilter, setRiskFilter] = useState<string>("all");
  const [actionFilter, setActionFilter] = useState<string>("all");
  const [searchTarget, setSearchTarget] = useState("");
  const [page, setPage] = useState(0);
  const pageSize = 50;

  const statsQ = trpc.roeAudit.getAuditStats.useQuery();
  const logQ = trpc.roeAudit.getAuditLog.useQuery({
    riskTier: riskFilter !== "all" ? riskFilter as any : undefined,
    actionType: actionFilter !== "all" ? actionFilter : undefined,
    limit: pageSize,
    offset: page * pageSize,
  });

  const filteredEntries = useMemo(() => {
    if (!logQ.data?.entries) return [];
    if (!searchTarget.trim()) return logQ.data.entries;
    const q = searchTarget.toLowerCase();
    return logQ.data.entries.filter((e: any) =>
      e.target?.toLowerCase().includes(q) ||
      e.operatorName?.toLowerCase().includes(q) ||
      e.moduleOrTool?.toLowerCase().includes(q)
    );
  }, [logQ.data?.entries, searchTarget]);

  const stats = statsQ.data;
  const totalPages = Math.ceil((logQ.data?.total ?? 0) / pageSize);

  return (
    <AppShell activePath="/audit-log">
      <div className="space-y-6">
        {/* Header */}
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-7 w-7 text-purple-400" />
            Offensive Operations Audit Log
          </h1>
          <p className="text-muted-foreground mt-1 max-w-2xl">
            Unified audit trail of all active testing operations. Every Orange and Red tier action is logged with operator identity, target, ROE status, and outcome.
          </p>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
          <Card className="border-border/60">
            <CardContent className="p-4 text-center">
              <p className="text-2xl font-bold">{stats?.total ?? 0}</p>
              <p className="text-xs text-muted-foreground">Total Operations</p>
            </CardContent>
          </Card>
          <Card className="border-amber-500/30">
            <CardContent className="p-4 text-center">
              <p className="text-2xl font-bold text-amber-400">{stats?.byTier?.yellow ?? 0}</p>
              <p className="text-xs text-muted-foreground">Yellow Tier</p>
            </CardContent>
          </Card>
          <Card className="border-orange-500/30">
            <CardContent className="p-4 text-center">
              <p className="text-2xl font-bold text-orange-400">{stats?.byTier?.orange ?? 0}</p>
              <p className="text-xs text-muted-foreground">Orange Tier</p>
            </CardContent>
          </Card>
          <Card className="border-red-500/30">
            <CardContent className="p-4 text-center">
              <p className="text-2xl font-bold text-red-400">{stats?.byTier?.red ?? 0}</p>
              <p className="text-xs text-muted-foreground">Red Tier</p>
            </CardContent>
          </Card>
          <Card className="border-cyan-500/30">
            <CardContent className="p-4 text-center">
              <p className="text-2xl font-bold text-cyan-400">{stats?.recentCount ?? 0}</p>
              <p className="text-xs text-muted-foreground">Last 24h</p>
            </CardContent>
          </Card>
        </div>

        {/* Filters */}
        <Card className="border-border/60">
          <CardContent className="p-4">
            <div className="flex flex-wrap items-center gap-3">
              <div className="flex items-center gap-2">
                <Filter className="h-4 w-4 text-muted-foreground" />
                <span className="text-sm font-medium">Filters:</span>
              </div>
              <Select value={riskFilter} onValueChange={(v) => { setRiskFilter(v); setPage(0); }}>
                <SelectTrigger className="w-[140px] h-8 text-xs">
                  <SelectValue placeholder="Risk Tier" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Tiers</SelectItem>
                  <SelectItem value="yellow">Yellow</SelectItem>
                  <SelectItem value="orange">Orange</SelectItem>
                  <SelectItem value="red">Red</SelectItem>
                </SelectContent>
              </Select>
              <Select value={actionFilter} onValueChange={(v) => { setActionFilter(v); setPage(0); }}>
                <SelectTrigger className="w-[180px] h-8 text-xs">
                  <SelectValue placeholder="Action Type" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Actions</SelectItem>
                  {Object.entries(ACTION_LABELS).map(([k, v]) => (
                    <SelectItem key={k} value={k}>{v}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <div className="relative flex-1 min-w-[200px]">
                <Search className="absolute left-2.5 top-1/2 -translate-y-1/2 h-3.5 w-3.5 text-muted-foreground" />
                <Input
                  placeholder="Search target, operator, or module..."
                  value={searchTarget}
                  onChange={(e) => setSearchTarget(e.target.value)}
                  className="h-8 pl-8 text-xs"
                />
              </div>
            </div>
          </CardContent>
        </Card>

        {/* Log Entries */}
        {filteredEntries.length === 0 ? (
          <Card className="border-border/60">
            <CardContent className="p-12 text-center">
              <Shield className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
              <h3 className="text-lg font-semibold text-muted-foreground">No Audit Entries</h3>
              <p className="text-sm text-muted-foreground/70 mt-1">
                {logQ.data?.total === 0
                  ? "No offensive operations have been logged yet. Entries will appear here when active probes, exploits, phishing campaigns, or emulations are executed."
                  : "No entries match your current filters."}
              </p>
            </CardContent>
          </Card>
        ) : (
          <div className="space-y-2">
            {filteredEntries.map((entry: any) => {
              const tier = RISK_TIER_STYLES[entry.riskTier] || RISK_TIER_STYLES.yellow;
              const result = RESULT_STYLES[entry.resultStatus] || RESULT_STYLES.pending_approval;
              return (
                <Card key={entry.id} className={`border ${tier.bg}`}>
                  <CardContent className="p-4">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex items-start gap-3 flex-1 min-w-0">
                        <div className={`p-2 rounded-lg ${tier.bg} shrink-0`}>
                          {entry.riskTier === "red" ? (
                            <AlertTriangle className={`h-4 w-4 ${tier.text}`} />
                          ) : entry.riskTier === "orange" ? (
                            <Crosshair className={`h-4 w-4 ${tier.text}`} />
                          ) : (
                            <Activity className={`h-4 w-4 ${tier.text}`} />
                          )}
                        </div>
                        <div className="space-y-1.5 min-w-0 flex-1">
                          <div className="flex items-center gap-2 flex-wrap">
                            <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${tier.text} border-current/30`}>
                              {tier.label}
                            </Badge>
                            <span className="text-sm font-semibold">
                              {ACTION_LABELS[entry.actionType] || entry.actionType}
                            </span>
                            <Badge className={`text-[10px] px-1.5 py-0 ${result.bg} ${result.text} border-0`}>
                              {entry.resultStatus?.replace("_", " ").toUpperCase()}
                            </Badge>
                          </div>
                          <div className="flex items-center gap-4 text-xs text-muted-foreground flex-wrap">
                            <span className="flex items-center gap-1">
                              <Target className="h-3 w-3" />
                              <span className="font-mono">{entry.target}</span>
                              {entry.targetPort && <span className="text-muted-foreground/60">:{entry.targetPort}</span>}
                            </span>
                            {entry.moduleOrTool && (
                              <span className="flex items-center gap-1">
                                <FileText className="h-3 w-3" />
                                <span className="font-mono truncate max-w-[200px]">{entry.moduleOrTool}</span>
                              </span>
                            )}
                            {entry.operatorName && (
                              <span className="flex items-center gap-1">
                                <User className="h-3 w-3" />
                                {entry.operatorName}
                              </span>
                            )}
                          </div>
                          {entry.resultDetail && (
                            <p className="text-[11px] text-muted-foreground/70 truncate">{entry.resultDetail}</p>
                          )}
                          <div className="flex items-center gap-3 text-[11px] text-muted-foreground/60">
                            <span className="flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              {new Date(entry.createdAt).toLocaleString()}
                            </span>
                            {entry.roeStatus && (
                              <span className="flex items-center gap-1">
                                <Shield className="h-3 w-3" />
                                ROE: {entry.roeStatus}
                              </span>
                            )}
                            {entry.engagementId && (
                              <span>Engagement #{entry.engagementId}</span>
                            )}
                          </div>
                        </div>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              );
            })}
          </div>
        )}

        {/* Pagination */}
        {totalPages > 1 && (
          <div className="flex items-center justify-between">
            <p className="text-xs text-muted-foreground">
              Showing {page * pageSize + 1}-{Math.min((page + 1) * pageSize, logQ.data?.total ?? 0)} of {logQ.data?.total ?? 0} entries
            </p>
            <div className="flex items-center gap-2">
              <Button variant="outline" size="sm" disabled={page === 0} onClick={() => setPage(p => p - 1)}>
                <ChevronLeft className="h-4 w-4" />
              </Button>
              <span className="text-sm text-muted-foreground">Page {page + 1} of {totalPages}</span>
              <Button variant="outline" size="sm" disabled={page >= totalPages - 1} onClick={() => setPage(p => p + 1)}>
                <ChevronRight className="h-4 w-4" />
              </Button>
            </div>
          </div>
        )}
      </div>
    </AppShell>
  );
}
