import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Shield,
  ShieldCheck,
  ShieldAlert,
  ShieldX,
  Loader2,
  RefreshCw,
  Target,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  MinusCircle,
  Eye,
  Filter,
} from "lucide-react";

const TACTIC_ORDER = [
  "reconnaissance", "resource-development", "initial-access", "execution",
  "persistence", "privilege-escalation", "defense-evasion", "credential-access",
  "discovery", "lateral-movement", "collection", "command-and-control",
  "exfiltration", "impact"
];

const TACTIC_COLORS: Record<string, string> = {
  "reconnaissance": "bg-slate-600",
  "resource-development": "bg-slate-500",
  "initial-access": "bg-red-700",
  "execution": "bg-red-600",
  "persistence": "bg-orange-700",
  "privilege-escalation": "bg-orange-600",
  "defense-evasion": "bg-yellow-700",
  "credential-access": "bg-yellow-600",
  "discovery": "bg-green-700",
  "lateral-movement": "bg-green-600",
  "collection": "bg-teal-700",
  "command-and-control": "bg-blue-700",
  "exfiltration": "bg-blue-600",
  "impact": "bg-purple-700",
};

const COVERAGE_STYLES: Record<string, { bg: string; text: string; label: string; icon: any }> = {
  full: { bg: "bg-green-500/20", text: "text-green-400", label: "Full Coverage", icon: ShieldCheck },
  partial: { bg: "bg-yellow-500/20", text: "text-yellow-400", label: "Partial", icon: Shield },
  "rules-only": { bg: "bg-blue-500/20", text: "text-blue-400", label: "Rules Only", icon: Eye },
  "ops-only": { bg: "bg-orange-500/20", text: "text-orange-400", label: "Ops Only", icon: ShieldAlert },
  none: { bg: "bg-red-500/20", text: "text-red-400", label: "No Coverage", icon: ShieldX },
};

export default function DetectionCoverage() {
  const [selectedOp, setSelectedOp] = useState<string>("all");
  const [filterCoverage, setFilterCoverage] = useState<string>("all");
  const [filterTactic, setFilterTactic] = useState<string>("all");
  const [expandedTech, setExpandedTech] = useState<string | null>(null);

  const { data, isLoading, refetch } = trpc.calderaProxy.getDetectionCoverageMatrix.useQuery(
    { operationId: selectedOp === "all" ? undefined : selectedOp },
    { refetchOnWindowFocus: false }
  );

  const filteredMatrix = useMemo(() => {
    if (!data?.matrix) return [];
    return data.matrix.filter(item => {
      if (filterCoverage !== "all" && item.coverageStatus !== filterCoverage) return false;
      if (filterTactic !== "all" && item.tactic !== filterTactic) return false;
      return true;
    });
  }, [data?.matrix, filterCoverage, filterTactic]);

  // Group by tactic for the heatmap view
  const tacticGroups = useMemo(() => {
    const groups: Record<string, typeof filteredMatrix> = {};
    for (const item of filteredMatrix) {
      if (!groups[item.tactic]) groups[item.tactic] = [];
      groups[item.tactic].push(item);
    }
    return groups;
  }, [filteredMatrix]);

  const sortedTactics = TACTIC_ORDER.filter(t => tacticGroups[t]);
  const otherTactics = Object.keys(tacticGroups).filter(t => !TACTIC_ORDER.includes(t));
  const allTactics = [...sortedTactics, ...otherTactics];

  if (isLoading) {
    return (
      <AppShell>
        <div className="flex items-center justify-center min-h-[60vh]">
          <Loader2 className="w-8 h-8 animate-spin text-muted-foreground" />
        </div>
      </AppShell>
    );
  }

  const summary = data?.summary;

  return (
    <AppShell>
      <div className="p-6 space-y-6">
        {/* Header */}
        <div className="flex items-start justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <Target className="w-6 h-6 text-cyan-400" />
              Detection Coverage Matrix
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              Cross-reference validated detection rules against your operation attack chains to identify gaps in SIEM coverage.
              Each cell shows whether a technique has both an active operation step and a detection rule.
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={() => refetch()}>
            <RefreshCw className="w-4 h-4 mr-1" /> Refresh
          </Button>
        </div>

        {/* Summary Cards */}
        {summary && (
          <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
            <Card className="bg-card/50">
              <CardContent className="p-3 text-center">
                <div className="text-2xl font-bold text-blue-400">{summary.totalTechniques}</div>
                <div className="text-xs text-muted-foreground">Total Techniques</div>
              </CardContent>
            </Card>
            <Card className="bg-green-500/10 border-green-500/20">
              <CardContent className="p-3 text-center">
                <div className="text-2xl font-bold text-green-400">{summary.fullCoverage}</div>
                <div className="text-xs text-muted-foreground">Full Coverage</div>
              </CardContent>
            </Card>
            <Card className="bg-yellow-500/10 border-yellow-500/20">
              <CardContent className="p-3 text-center">
                <div className="text-2xl font-bold text-yellow-400">{summary.partialCoverage}</div>
                <div className="text-xs text-muted-foreground">Partial</div>
              </CardContent>
            </Card>
            <Card className="bg-blue-500/10 border-blue-500/20">
              <CardContent className="p-3 text-center">
                <div className="text-2xl font-bold text-blue-400">{summary.rulesOnly}</div>
                <div className="text-xs text-muted-foreground">Rules Only</div>
              </CardContent>
            </Card>
            <Card className="bg-orange-500/10 border-orange-500/20">
              <CardContent className="p-3 text-center">
                <div className="text-2xl font-bold text-orange-400">{summary.opsOnly}</div>
                <div className="text-xs text-muted-foreground">Ops Only (Gap)</div>
              </CardContent>
            </Card>
            <Card className="bg-red-500/10 border-red-500/20">
              <CardContent className="p-3 text-center">
                <div className="text-2xl font-bold text-red-400">{summary.noCoverage}</div>
                <div className="text-xs text-muted-foreground">No Coverage</div>
              </CardContent>
            </Card>
          </div>
        )}

        {/* Coverage Score Bar */}
        {summary && summary.totalTechniques > 0 && (
          <Card className="bg-card/50">
            <CardContent className="p-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm font-medium">Overall Detection Coverage</span>
                <span className="text-sm font-bold text-green-400">
                  {Math.round(((summary.fullCoverage + summary.partialCoverage) / summary.totalTechniques) * 100)}%
                </span>
              </div>
              <div className="h-4 bg-muted/30 rounded-full overflow-hidden flex">
                <div
                  className="bg-green-500 h-full transition-all"
                  style={{ width: `${(summary.fullCoverage / summary.totalTechniques) * 100}%` }}
                />
                <div
                  className="bg-yellow-500 h-full transition-all"
                  style={{ width: `${(summary.partialCoverage / summary.totalTechniques) * 100}%` }}
                />
                <div
                  className="bg-blue-500 h-full transition-all"
                  style={{ width: `${(summary.rulesOnly / summary.totalTechniques) * 100}%` }}
                />
                <div
                  className="bg-orange-500 h-full transition-all"
                  style={{ width: `${(summary.opsOnly / summary.totalTechniques) * 100}%` }}
                />
              </div>
              <div className="flex gap-4 mt-2 text-xs text-muted-foreground">
                <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-green-500" /> Full</span>
                <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-yellow-500" /> Partial</span>
                <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-blue-500" /> Rules Only</span>
                <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-orange-500" /> Ops Only</span>
                <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-full bg-muted" /> None</span>
              </div>
            </CardContent>
          </Card>
        )}

        {/* Tactic Breakdown */}
        {summary?.byTactic && (
          <Card className="bg-card/50">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm">Coverage by MITRE ATT&CK Tactic</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 md:grid-cols-7 gap-2">
                {TACTIC_ORDER.map(tactic => {
                  const info = (summary.byTactic as any)[tactic];
                  if (!info || info.total === 0) return null;
                  const pct = Math.round((info.covered / info.total) * 100);
                  return (
                    <div
                      key={tactic}
                      className="p-2 bg-muted/20 rounded-lg text-center cursor-pointer hover:bg-muted/40 transition-colors"
                      onClick={() => setFilterTactic(filterTactic === tactic ? "all" : tactic)}
                    >
                      <div className={`text-xs font-medium capitalize mb-1 ${filterTactic === tactic ? 'text-primary' : 'text-muted-foreground'}`}>
                        {tactic.replace(/-/g, ' ')}
                      </div>
                      <div className="text-lg font-bold">{pct}%</div>
                      <div className="text-xs text-muted-foreground">{info.covered}/{info.total}</div>
                      <div className="h-1 bg-muted/30 rounded-full mt-1 overflow-hidden">
                        <div
                          className={`h-full rounded-full ${pct >= 75 ? 'bg-green-500' : pct >= 50 ? 'bg-yellow-500' : pct >= 25 ? 'bg-orange-500' : 'bg-red-500'}`}
                          style={{ width: `${pct}%` }}
                        />
                      </div>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        )}

        {/* Filters */}
        <div className="flex gap-3 items-center flex-wrap">
          <Filter className="w-4 h-4 text-muted-foreground" />
          <Select value={selectedOp} onValueChange={setSelectedOp}>
            <SelectTrigger className="w-[250px]">
              <SelectValue placeholder="All Operations" />
            </SelectTrigger>
            <SelectContent>
              <SelectItem value="all">All Operations</SelectItem>
              {(data?.operations || []).map((op: any) => (
                <SelectItem key={op.id} value={op.id}>{op.name}</SelectItem>
              ))}
            </SelectContent>
          </Select>

          <div className="flex gap-1">
            {["all", "full", "partial", "rules-only", "ops-only", "none"].map(status => (
              <Badge
                key={status}
                variant={filterCoverage === status ? "default" : "outline"}
                className="cursor-pointer"
                onClick={() => setFilterCoverage(status)}
              >
                {status === "all" ? "All" : COVERAGE_STYLES[status]?.label || status}
              </Badge>
            ))}
          </div>

          {filterTactic !== "all" && (
            <Badge variant="secondary" className="cursor-pointer capitalize" onClick={() => setFilterTactic("all")}>
              {filterTactic.replace(/-/g, ' ')} &times;
            </Badge>
          )}

          <span className="text-xs text-muted-foreground ml-auto">
            Showing {filteredMatrix.length} of {data?.matrix?.length || 0} techniques
          </span>
        </div>

        {/* Matrix Grid by Tactic */}
        <div className="space-y-4">
          {allTactics.map(tactic => (
            <Card key={tactic} className="bg-card/50">
              <CardHeader className="pb-2">
                <div className="flex items-center gap-2">
                  <div className={`w-3 h-3 rounded ${TACTIC_COLORS[tactic] || 'bg-gray-500'}`} />
                  <CardTitle className="text-sm capitalize">{tactic.replace(/-/g, ' ')}</CardTitle>
                  <Badge variant="outline" className="text-xs">{tacticGroups[tactic]?.length || 0} techniques</Badge>
                </div>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                  {(tacticGroups[tactic] || []).map(item => {
                    const style = COVERAGE_STYLES[item.coverageStatus] || COVERAGE_STYLES.none;
                    const Icon = style.icon;
                    const isExpanded = expandedTech === item.techniqueId;

                    return (
                      <div
                        key={item.techniqueId}
                        className={`${style.bg} rounded-lg p-3 cursor-pointer transition-all hover:ring-1 hover:ring-white/10 ${isExpanded ? 'ring-1 ring-primary col-span-full' : ''}`}
                        onClick={() => setExpandedTech(isExpanded ? null : item.techniqueId)}
                      >
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2 min-w-0">
                            <Icon className={`w-4 h-4 ${style.text} shrink-0`} />
                            <div className="min-w-0">
                              <div className="text-sm font-medium truncate">{item.techniqueName}</div>
                              <code className="text-xs text-muted-foreground">{item.techniqueId}</code>
                            </div>
                          </div>
                          <div className="flex items-center gap-1 shrink-0">
                            {item.operationCoverage.length > 0 && (
                              <Badge variant="outline" className="text-xs">
                                {item.operationCoverage.length} op{item.operationCoverage.length > 1 ? 's' : ''}
                              </Badge>
                            )}
                            {item.rulesCoverage.length > 0 && (
                              <Badge variant="outline" className="text-xs">
                                {item.rulesCoverage.length} rule{item.rulesCoverage.length > 1 ? 's' : ''}
                              </Badge>
                            )}
                          </div>
                        </div>

                        {isExpanded && (
                          <div className="mt-3 space-y-2 border-t border-white/10 pt-3">
                            {item.operationCoverage.length > 0 && (
                              <div>
                                <div className="text-xs font-medium text-muted-foreground mb-1">Operations:</div>
                                {item.operationCoverage.map((op, i) => (
                                  <div key={i} className="flex items-center gap-2 text-xs">
                                    {op.status === 'success' ? (
                                      <CheckCircle2 className="w-3 h-3 text-green-400" />
                                    ) : op.status === 'failed' ? (
                                      <XCircle className="w-3 h-3 text-red-400" />
                                    ) : (
                                      <MinusCircle className="w-3 h-3 text-yellow-400" />
                                    )}
                                    <span className="truncate">{op.opName}</span>
                                    <Badge variant="outline" className="text-xs ml-auto">{op.status}</Badge>
                                  </div>
                                ))}
                              </div>
                            )}
                            {item.rulesCoverage.length > 0 && (
                              <div>
                                <div className="text-xs font-medium text-muted-foreground mb-1">Detection Rules:</div>
                                {item.rulesCoverage.map((rule, i) => (
                                  <div key={i} className="flex items-center gap-2 text-xs">
                                    <Badge variant="outline" className={`text-xs ${
                                      rule.ruleType === 'sigma' ? 'border-cyan-500/30 text-cyan-400' :
                                      rule.ruleType === 'yara' ? 'border-purple-500/30 text-purple-400' :
                                      'border-orange-500/30 text-orange-400'
                                    }`}>{rule.ruleType.toUpperCase()}</Badge>
                                    <span>Confidence: {rule.confidence}%</span>
                                    <Badge variant="outline" className={`text-xs ml-auto ${
                                      rule.severity === 'critical' ? 'border-red-500/30 text-red-400' :
                                      rule.severity === 'high' ? 'border-orange-500/30 text-orange-400' :
                                      'border-yellow-500/30 text-yellow-400'
                                    }`}>{rule.severity}</Badge>
                                  </div>
                                ))}
                              </div>
                            )}
                            {item.operationCoverage.length === 0 && item.rulesCoverage.length === 0 && (
                              <div className="flex items-center gap-2 text-xs text-muted-foreground">
                                <AlertTriangle className="w-3 h-3" />
                                No detection coverage for this technique. Consider adding rules or including in operations.
                              </div>
                            )}
                          </div>
                        )}
                      </div>
                    );
                  })}
                </div>
              </CardContent>
            </Card>
          ))}
        </div>

        {filteredMatrix.length === 0 && (
          <Card className="bg-card/50">
            <CardContent className="p-8 text-center text-muted-foreground">
              <Target className="w-12 h-12 mx-auto mb-3 opacity-30" />
              <p className="text-sm">No techniques match the current filters.</p>
            </CardContent>
          </Card>
        )}
      </div>
    </AppShell>
  );
}
