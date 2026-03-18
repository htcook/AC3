import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import { toast } from "sonner";
import AppShell from "@/components/AppShell";
import {
  Database, Brain, RefreshCw, BarChart3, Target, CheckCircle2,
  AlertTriangle, Clock, Loader2, ChevronDown, ChevronUp, ChevronLeft, ChevronRight,
  GraduationCap, Crosshair, Zap, TrendingUp, Activity,
  FileText, BookOpen, Cpu, Search, Filter, ArrowUpDown,
} from "lucide-react";
import { useState, useMemo } from "react";

function outcomeColor(outcome: string) {
  switch (outcome) {
    case "success": return "bg-green-500/20 text-green-400 border-green-500/30";
    case "failure": return "bg-red-500/20 text-red-400 border-red-500/30";
    case "partial": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
    case "pending": return "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
    default: return "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
  }
}

function qualityColor(quality: string) {
  switch (quality) {
    case "high": return "bg-green-500/20 text-green-400 border-green-500/30";
    case "medium": return "bg-blue-500/20 text-blue-400 border-blue-500/30";
    case "low": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
    case "rejected": return "bg-red-500/20 text-red-400 border-red-500/30";
    default: return "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
  }
}

export default function TrainingDataDashboard() {
  const [activeTab, setActiveTab] = useState<"overview" | "decisions" | "examples" | "telemetry" | "models">("overview");
  const [windowDays, setWindowDays] = useState(30);

  const { data: overview, isLoading: loadingOverview, refetch: refetchOverview } = trpc.trainingData.getOverview.useQuery({ windowDays });
  const { data: batchStatus, refetch: refetchBatch } = trpc.engagementAutomation.getBatchTrainingStatus.useQuery();

  const tabs = [
    { id: "overview" as const, label: "Overview", icon: BarChart3 },
    { id: "decisions" as const, label: "Decision Log", icon: Brain },
    { id: "examples" as const, label: "Training Examples", icon: Database },
    { id: "telemetry" as const, label: "Telemetry", icon: Activity },
    { id: "models" as const, label: "Model Performance", icon: Cpu },
  ];

  return (
    <AppShell>
      <div className="max-w-7xl mx-auto px-4 py-8 space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-3">
              <Database className="h-7 w-7 text-purple-400" />
              Training Data Dashboard
            </h1>
            <p className="text-muted-foreground mt-1">
              Monitor LLM decision logs, training data quality, telemetry metrics, and model learning progress across all engagement operations.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Select value={String(windowDays)} onValueChange={(v) => setWindowDays(Number(v))}>
              <SelectTrigger className="w-32 h-8 text-xs">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="7">Last 7 days</SelectItem>
                <SelectItem value="14">Last 14 days</SelectItem>
                <SelectItem value="30">Last 30 days</SelectItem>
                <SelectItem value="90">Last 90 days</SelectItem>
                <SelectItem value="365">Last year</SelectItem>
              </SelectContent>
            </Select>
            <Button variant="outline" size="sm" onClick={() => { refetchOverview(); refetchBatch(); }}>
              <RefreshCw className="h-4 w-4 mr-1" />
              Refresh
            </Button>
          </div>
        </div>

        {/* Key Metrics */}
        {overview && (
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-8 gap-3">
            <MetricCard icon={Brain} label="Decisions" value={overview.decisions.total} color="text-blue-400" />
            <MetricCard icon={CheckCircle2} label="Success" value={overview.decisions.success} color="text-green-400" />
            <MetricCard icon={AlertTriangle} label="Failures" value={overview.decisions.failure} color="text-red-400" />
            <MetricCard icon={Clock} label="Avg Latency" value={`${overview.decisions.avgLatencyMs}ms`} color="text-yellow-400" />
            <MetricCard icon={Database} label="Training Ex." value={overview.trainingExamples.total} color="text-purple-400" />
            <MetricCard icon={GraduationCap} label="High Quality" value={overview.trainingExamples.high} color="text-green-400" />
            <MetricCard icon={Activity} label="LLM Calls" value={overview.telemetry.totalCalls} color="text-cyan-400" />
            <MetricCard icon={Zap} label="Error Rate" value={`${overview.telemetry.errorRate}%`} color="text-orange-400" />
          </div>
        )}

        {/* Tabs */}
        <div className="flex gap-1 border-b border-border overflow-x-auto">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors whitespace-nowrap ${
                activeTab === tab.id
                  ? "border-purple-400 text-purple-400"
                  : "border-transparent text-muted-foreground hover:text-foreground"
              }`}
            >
              <tab.icon className="h-4 w-4" />
              {tab.label}
            </button>
          ))}
        </div>

        {/* Tab Content */}
        {activeTab === "overview" && <OverviewTab overview={overview} batchStatus={batchStatus} windowDays={windowDays} />}
        {activeTab === "decisions" && <DecisionLogTab />}
        {activeTab === "examples" && <TrainingExamplesTab />}
        {activeTab === "telemetry" && <TelemetryTab windowDays={windowDays} />}
        {activeTab === "models" && <ModelPerformanceTab windowDays={windowDays} />}
      </div>
    </AppShell>
  );
}

function MetricCard({ icon: Icon, label, value, color }: { icon: any; label: string; value: number | string; color: string }) {
  return (
    <div className="rounded-lg border border-border bg-card p-3 text-center">
      <Icon className={`h-4 w-4 mx-auto mb-1 ${color}`} />
      <div className="text-lg font-bold">{typeof value === 'number' ? value.toLocaleString() : value}</div>
      <div className="text-[10px] text-muted-foreground uppercase tracking-wider">{label}</div>
    </div>
  );
}

// ─── Overview Tab ──────────────────────────────────────────────────────────

function OverviewTab({ overview, batchStatus, windowDays }: { overview: any; batchStatus: any; windowDays: number }) {
  const { data: confidenceTrends } = trpc.trainingData.getConfidenceTrends.useQuery({ windowDays });
  const { data: outcomeDistribution } = trpc.trainingData.getOutcomeDistribution.useQuery({ windowDays, groupBy: 'day' });
  const { data: qualityDist } = trpc.trainingData.getTrainingQualityDistribution.useQuery();

  const graduation = batchStatus?.graduationSummary;

  return (
    <div className="space-y-6">
      {/* Graduation Tiers */}
      {graduation && graduation.totalCallers > 0 && (
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold flex items-center gap-2 mb-4">
            <GraduationCap className="h-4 w-4 text-purple-400" />
            Graduation Readiness by Tier
          </h3>
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {[
              { tier: "Tier 1", label: "Production Ready", count: graduation.tier1, color: "green", desc: "≥97% success, ≥500 calls" },
              { tier: "Tier 2", label: "Supervised", count: graduation.tier2, color: "blue", desc: "≥90% success, ≥200 calls" },
              { tier: "Tier 3", label: "Training", count: graduation.tier3, color: "yellow", desc: "≥80% success, ≥50 calls" },
              { tier: "Tier 4", label: "Novice", count: graduation.tier4, color: "orange", desc: "<80% or <50 calls" },
              { tier: "Total", label: "All Callers", count: graduation.totalCallers, color: "zinc", desc: "Across all tiers" },
            ].map(t => (
              <div key={t.tier} className={`p-4 rounded-lg bg-${t.color}-500/10 border border-${t.color}-500/20`}>
                <div className={`text-2xl font-bold text-${t.color}-400`}>{t.count}</div>
                <div className="text-sm font-medium mt-1">{t.tier}</div>
                <div className="text-xs text-muted-foreground">{t.label}</div>
                <div className="text-[10px] text-muted-foreground mt-1">{t.desc}</div>
              </div>
            ))}
          </div>
        </div>
      )}

      {/* Confidence / Success Rate Trends */}
      {confidenceTrends && confidenceTrends.daily.length > 0 && (
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold flex items-center gap-2 mb-4">
            <TrendingUp className="h-4 w-4 text-cyan-400" />
            Model Learning Progress (Daily)
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-muted-foreground text-xs">
                  <th className="text-left py-2 px-3">Date</th>
                  <th className="text-center py-2 px-3">Decisions</th>
                  <th className="text-center py-2 px-3">Success Rate</th>
                  <th className="text-center py-2 px-3">Avg Stealth</th>
                  <th className="text-center py-2 px-3">Avg Latency</th>
                  <th className="text-left py-2 px-3">Success Trend</th>
                </tr>
              </thead>
              <tbody>
                {confidenceTrends.daily.map((d: any) => (
                  <tr key={d.day} className="border-b border-border/50 hover:bg-muted/20">
                    <td className="py-2 px-3 font-mono text-xs">{d.day}</td>
                    <td className="py-2 px-3 text-center">{d.decisionCount}</td>
                    <td className="py-2 px-3 text-center">
                      <span className={d.successRate >= 80 ? "text-green-400" : d.successRate >= 60 ? "text-yellow-400" : "text-red-400"}>
                        {d.successRate}%
                      </span>
                    </td>
                    <td className="py-2 px-3 text-center">{d.avgStealth}</td>
                    <td className="py-2 px-3 text-center">{d.avgLatencyMs}ms</td>
                    <td className="py-2 px-3">
                      <div className="w-full h-2 rounded-full bg-muted overflow-hidden">
                        <div
                          className={`h-full rounded-full ${d.successRate >= 80 ? "bg-green-500" : d.successRate >= 60 ? "bg-yellow-500" : "bg-red-500"}`}
                          style={{ width: `${Math.min(d.successRate, 100)}%` }}
                        />
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Caller-Level Accuracy */}
      {confidenceTrends && confidenceTrends.callerTrends.length > 0 && (
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold flex items-center gap-2 mb-4">
            <Target className="h-4 w-4 text-orange-400" />
            Accuracy by LLM Caller
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-muted-foreground text-xs">
                  <th className="text-left py-2 px-3">Caller</th>
                  <th className="text-center py-2 px-3">Decisions</th>
                  <th className="text-center py-2 px-3">Success Rate</th>
                  <th className="text-center py-2 px-3">Avg Stealth</th>
                  <th className="text-center py-2 px-3">Avg Latency</th>
                </tr>
              </thead>
              <tbody>
                {confidenceTrends.callerTrends.map((c: any) => (
                  <tr key={c.caller} className="border-b border-border/50 hover:bg-muted/20">
                    <td className="py-2 px-3 font-mono text-xs truncate max-w-48">{c.caller}</td>
                    <td className="py-2 px-3 text-center">{c.total}</td>
                    <td className="py-2 px-3 text-center">
                      <span className={c.successRate >= 80 ? "text-green-400" : c.successRate >= 60 ? "text-yellow-400" : "text-red-400"}>
                        {c.successRate}%
                      </span>
                    </td>
                    <td className="py-2 px-3 text-center">{c.avgStealth}</td>
                    <td className="py-2 px-3 text-center">{c.avgLatencyMs}ms</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Training Quality Distribution */}
      {qualityDist && (qualityDist.bySource.length > 0 || qualityDist.byModel.length > 0) && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
          {qualityDist.bySource.length > 0 && (
            <div className="rounded-xl border border-border bg-card p-5">
              <h3 className="text-sm font-semibold flex items-center gap-2 mb-4">
                <BookOpen className="h-4 w-4 text-purple-400" />
                Training Quality by Source
              </h3>
              <div className="space-y-2">
                {qualityDist.bySource.map((r: any, i: number) => (
                  <div key={i} className="flex items-center justify-between p-2 rounded bg-muted/20">
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className="text-[10px]">{r.source}</Badge>
                      <Badge className={`text-[10px] ${qualityColor(r.quality)}`}>{r.quality}</Badge>
                    </div>
                    <div className="flex items-center gap-3 text-xs">
                      <span>{r.count} examples</span>
                      <span className="text-muted-foreground">avg: {r.avgScore}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
          {qualityDist.byModel.length > 0 && (
            <div className="rounded-xl border border-border bg-card p-5">
              <h3 className="text-sm font-semibold flex items-center gap-2 mb-4">
                <Cpu className="h-4 w-4 text-cyan-400" />
                Training Quality by Model
              </h3>
              <div className="space-y-2">
                {qualityDist.byModel.map((r: any) => (
                  <div key={r.model} className="flex items-center justify-between p-2 rounded bg-muted/20">
                    <span className="font-mono text-xs">{r.model}</span>
                    <div className="flex items-center gap-3 text-xs">
                      <span>{r.count} total</span>
                      <span className="text-green-400">{r.highCount} high</span>
                      <span className="text-muted-foreground">avg: {r.avgScore}</span>
                    </div>
                  </div>
                ))}
              </div>
            </div>
          )}
        </div>
      )}

      {/* Empty State */}
      {(!overview || (overview.decisions.total === 0 && overview.trainingExamples.total === 0 && overview.telemetry.totalCalls === 0)) && (
        <div className="text-center py-16 text-muted-foreground">
          <Database className="h-12 w-12 mx-auto mb-4 opacity-30" />
          <p className="text-lg font-medium">No training data yet</p>
          <p className="text-sm mt-1">Launch engagements and use the AI chat to generate LLM decision logs and training examples.</p>
        </div>
      )}
    </div>
  );
}

// ─── Decision Log Tab ──────────────────────────────────────────────────────

function DecisionLogTab() {
  const [page, setPage] = useState(1);
  const [outcomeFilter, setOutcomeFilter] = useState<string>("all");
  const [callerSearch, setCallerSearch] = useState("");
  const [phaseFilter, setPhaseFilter] = useState("");
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const { data, isLoading } = trpc.trainingData.listDecisions.useQuery({
    page,
    pageSize: 25,
    outcome: outcomeFilter as any,
    caller: callerSearch || undefined,
    phase: phaseFilter || undefined,
  });

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="rounded-xl border border-border bg-card p-4">
        <div className="flex items-center gap-2 mb-3">
          <Filter className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">Filters</span>
        </div>
        <div className="flex flex-wrap gap-3">
          <div className="w-40">
            <Select value={outcomeFilter} onValueChange={v => { setOutcomeFilter(v); setPage(1); }}>
              <SelectTrigger className="h-8 text-xs">
                <SelectValue placeholder="Outcome" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Outcomes</SelectItem>
                <SelectItem value="success">Success</SelectItem>
                <SelectItem value="failure">Failure</SelectItem>
                <SelectItem value="partial">Partial</SelectItem>
                <SelectItem value="pending">Pending</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="w-48">
            <Input
              placeholder="Search caller..."
              value={callerSearch}
              onChange={e => { setCallerSearch(e.target.value); setPage(1); }}
              className="h-8 text-xs"
            />
          </div>
          <div className="w-40">
            <Input
              placeholder="Phase filter..."
              value={phaseFilter}
              onChange={e => { setPhaseFilter(e.target.value); setPage(1); }}
              className="h-8 text-xs"
            />
          </div>
        </div>
      </div>

      {/* Decision Table */}
      <div className="rounded-xl border border-border bg-card p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <Brain className="h-4 w-4 text-blue-400" />
            LLM Decision Log ({data?.total || 0} total)
          </h3>
          {data && data.totalPages > 1 && (
            <div className="flex items-center gap-2 text-xs">
              <Button variant="outline" size="sm" className="h-7 px-2" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>
                <ChevronLeft className="h-3 w-3" />
              </Button>
              <span className="text-muted-foreground">Page {page} of {data.totalPages}</span>
              <Button variant="outline" size="sm" className="h-7 px-2" disabled={page >= data.totalPages} onClick={() => setPage(p => p + 1)}>
                <ChevronRight className="h-3 w-3" />
              </Button>
            </div>
          )}
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        ) : data && data.rows.length > 0 ? (
          <div className="space-y-2">
            {data.rows.map((row: any) => (
              <div key={row.id} className="border border-border rounded-lg overflow-hidden">
                <button
                  className="w-full flex items-center gap-3 p-3 hover:bg-muted/20 text-left"
                  onClick={() => setExpandedId(expandedId === row.id ? null : row.id)}
                >
                  <Badge className={`text-[10px] ${outcomeColor(row.outcome)}`}>{row.outcome}</Badge>
                  <span className="font-mono text-xs text-muted-foreground truncate max-w-32">{row.caller}</span>
                  <Badge variant="outline" className="text-[10px]">{row.phase}</Badge>
                  <span className="flex-1 text-sm truncate">{row.decision?.slice(0, 80)}</span>
                  <span className="text-[10px] text-muted-foreground whitespace-nowrap">{row.createdAt?.slice(0, 16)}</span>
                  {expandedId === row.id ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                </button>
                {expandedId === row.id && (
                  <div className="border-t border-border p-4 bg-muted/10 space-y-3 text-sm">
                    <div>
                      <span className="text-xs font-medium text-muted-foreground">Decision:</span>
                      <p className="mt-1 whitespace-pre-wrap">{row.decision}</p>
                    </div>
                    {row.reasoning && (
                      <div>
                        <span className="text-xs font-medium text-muted-foreground">Reasoning:</span>
                        <p className="mt-1 whitespace-pre-wrap text-muted-foreground">{row.reasoning}</p>
                      </div>
                    )}
                    {row.contextSummary && (
                      <div>
                        <span className="text-xs font-medium text-muted-foreground">Context:</span>
                        <p className="mt-1 whitespace-pre-wrap text-muted-foreground text-xs">{row.contextSummary}</p>
                      </div>
                    )}
                    <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
                      {row.stealthScore != null && <span>Stealth: <strong className="text-foreground">{row.stealthScore}</strong></span>}
                      {row.latencyMs != null && <span>Latency: <strong className="text-foreground">{row.latencyMs}ms</strong></span>}
                      {row.tokensUsed != null && <span>Tokens: <strong className="text-foreground">{row.tokensUsed}</strong></span>}
                      <span>Engagement: <strong className="text-foreground">#{row.engagementId}</strong></span>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-12 text-muted-foreground">
            <Brain className="h-8 w-8 mx-auto mb-3 opacity-30" />
            <p className="text-sm">No decisions match the current filters.</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Training Examples Tab ─────────────────────────────────────────────────

function TrainingExamplesTab() {
  const [page, setPage] = useState(1);
  const [qualityFilter, setQualityFilter] = useState<string>("all");
  const [sourceFilter, setSourceFilter] = useState<string>("all");
  const [modelSearch, setModelSearch] = useState("");
  const [expandedId, setExpandedId] = useState<number | null>(null);

  const { data, isLoading } = trpc.trainingData.listTrainingExamples.useQuery({
    page,
    pageSize: 25,
    quality: qualityFilter as any,
    source: sourceFilter as any,
    model: modelSearch || undefined,
  });

  return (
    <div className="space-y-4">
      {/* Filters */}
      <div className="rounded-xl border border-border bg-card p-4">
        <div className="flex items-center gap-2 mb-3">
          <Filter className="h-4 w-4 text-muted-foreground" />
          <span className="text-sm font-medium">Filters</span>
        </div>
        <div className="flex flex-wrap gap-3">
          <div className="w-40">
            <Select value={qualityFilter} onValueChange={v => { setQualityFilter(v); setPage(1); }}>
              <SelectTrigger className="h-8 text-xs">
                <SelectValue placeholder="Quality" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Quality</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
                <SelectItem value="rejected">Rejected</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="w-44">
            <Select value={sourceFilter} onValueChange={v => { setSourceFilter(v); setPage(1); }}>
              <SelectTrigger className="h-8 text-xs">
                <SelectValue placeholder="Source" />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Sources</SelectItem>
                <SelectItem value="lab_scenario">Lab Scenario</SelectItem>
                <SelectItem value="live_engagement">Live Engagement</SelectItem>
                <SelectItem value="manual">Manual</SelectItem>
                <SelectItem value="synthetic">Synthetic</SelectItem>
              </SelectContent>
            </Select>
          </div>
          <div className="w-48">
            <Input
              placeholder="Search model..."
              value={modelSearch}
              onChange={e => { setModelSearch(e.target.value); setPage(1); }}
              className="h-8 text-xs"
            />
          </div>
        </div>
      </div>

      {/* Examples Table */}
      <div className="rounded-xl border border-border bg-card p-5">
        <div className="flex items-center justify-between mb-4">
          <h3 className="text-sm font-semibold flex items-center gap-2">
            <Database className="h-4 w-4 text-purple-400" />
            Training Examples ({data?.total || 0} total)
          </h3>
          {data && data.totalPages > 1 && (
            <div className="flex items-center gap-2 text-xs">
              <Button variant="outline" size="sm" className="h-7 px-2" disabled={page <= 1} onClick={() => setPage(p => p - 1)}>
                <ChevronLeft className="h-3 w-3" />
              </Button>
              <span className="text-muted-foreground">Page {page} of {data.totalPages}</span>
              <Button variant="outline" size="sm" className="h-7 px-2" disabled={page >= data.totalPages} onClick={() => setPage(p => p + 1)}>
                <ChevronRight className="h-3 w-3" />
              </Button>
            </div>
          )}
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        ) : data && data.rows.length > 0 ? (
          <div className="space-y-2">
            {data.rows.map((row: any) => (
              <div key={row.id} className="border border-border rounded-lg overflow-hidden">
                <button
                  className="w-full flex items-center gap-3 p-3 hover:bg-muted/20 text-left"
                  onClick={() => setExpandedId(expandedId === row.id ? null : row.id)}
                >
                  <Badge className={`text-[10px] ${qualityColor(row.quality)}`}>{row.quality}</Badge>
                  <Badge variant="outline" className="text-[10px]">{row.source}</Badge>
                  <span className="font-mono text-xs text-muted-foreground">{row.model}</span>
                  <span className="flex-1 text-sm truncate">{row.exampleId}</span>
                  <span className="text-xs text-muted-foreground">Score: {row.qualityScore?.toFixed(2)}</span>
                  {expandedId === row.id ? <ChevronUp className="h-3 w-3" /> : <ChevronDown className="h-3 w-3" />}
                </button>
                {expandedId === row.id && (
                  <div className="border-t border-border p-4 bg-muted/10 space-y-3 text-sm">
                    <div>
                      <span className="text-xs font-medium text-muted-foreground">Messages:</span>
                      <pre className="mt-1 text-xs bg-muted/30 p-3 rounded overflow-x-auto max-h-64">
                        {JSON.stringify(row.messages, null, 2)}
                      </pre>
                    </div>
                    {row.metadata && (
                      <div>
                        <span className="text-xs font-medium text-muted-foreground">Metadata:</span>
                        <pre className="mt-1 text-xs bg-muted/30 p-3 rounded overflow-x-auto max-h-32">
                          {JSON.stringify(row.metadata, null, 2)}
                        </pre>
                      </div>
                    )}
                    <div className="flex flex-wrap gap-4 text-xs text-muted-foreground">
                      <span>Source ID: <strong className="text-foreground">{row.sourceId || 'N/A'}</strong></span>
                      <span>Created: <strong className="text-foreground">{row.createdAt}</strong></span>
                    </div>
                  </div>
                )}
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-12 text-muted-foreground">
            <Database className="h-8 w-8 mx-auto mb-3 opacity-30" />
            <p className="text-sm">No training examples match the current filters.</p>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Telemetry Tab ─────────────────────────────────────────────────────────

function TelemetryTab({ windowDays }: { windowDays: number }) {
  const { data, isLoading } = trpc.trainingData.getTelemetryTrends.useQuery({ windowDays });

  return (
    <div className="space-y-6">
      {/* Daily Telemetry */}
      {data && data.daily.length > 0 && (
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold flex items-center gap-2 mb-4">
            <Activity className="h-4 w-4 text-cyan-400" />
            Daily LLM Telemetry
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-muted-foreground text-xs">
                  <th className="text-left py-2 px-3">Date</th>
                  <th className="text-center py-2 px-3">Calls</th>
                  <th className="text-center py-2 px-3">Errors</th>
                  <th className="text-center py-2 px-3">Error Rate</th>
                  <th className="text-center py-2 px-3">Avg Latency</th>
                  <th className="text-center py-2 px-3">Tokens In</th>
                  <th className="text-center py-2 px-3">Tokens Out</th>
                </tr>
              </thead>
              <tbody>
                {data.daily.map((d: any) => (
                  <tr key={d.day} className="border-b border-border/50 hover:bg-muted/20">
                    <td className="py-2 px-3 font-mono text-xs">{d.day}</td>
                    <td className="py-2 px-3 text-center">{d.totalCalls.toLocaleString()}</td>
                    <td className="py-2 px-3 text-center text-red-400">{d.errors}</td>
                    <td className="py-2 px-3 text-center">
                      <span className={d.errorRate > 5 ? "text-red-400" : d.errorRate > 1 ? "text-yellow-400" : "text-green-400"}>
                        {d.errorRate}%
                      </span>
                    </td>
                    <td className="py-2 px-3 text-center">{d.avgLatencyMs}ms</td>
                    <td className="py-2 px-3 text-center text-muted-foreground">{d.totalTokensIn.toLocaleString()}</td>
                    <td className="py-2 px-3 text-center text-muted-foreground">{d.totalTokensOut.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Top Callers by Usage */}
      {data && data.topCallers.length > 0 && (
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold flex items-center gap-2 mb-4">
            <Target className="h-4 w-4 text-orange-400" />
            Top LLM Callers by Usage
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-muted-foreground text-xs">
                  <th className="text-left py-2 px-3">Caller</th>
                  <th className="text-center py-2 px-3">Calls</th>
                  <th className="text-center py-2 px-3">Errors</th>
                  <th className="text-center py-2 px-3">Error Rate</th>
                  <th className="text-center py-2 px-3">Avg Latency</th>
                  <th className="text-center py-2 px-3">Tokens In</th>
                  <th className="text-center py-2 px-3">Tokens Out</th>
                </tr>
              </thead>
              <tbody>
                {data.topCallers.map((c: any) => (
                  <tr key={c.caller} className="border-b border-border/50 hover:bg-muted/20">
                    <td className="py-2 px-3 font-mono text-xs truncate max-w-48">{c.caller}</td>
                    <td className="py-2 px-3 text-center">{c.totalCalls.toLocaleString()}</td>
                    <td className="py-2 px-3 text-center text-red-400">{c.errors}</td>
                    <td className="py-2 px-3 text-center">
                      <span className={c.errorRate > 5 ? "text-red-400" : c.errorRate > 1 ? "text-yellow-400" : "text-green-400"}>
                        {c.errorRate}%
                      </span>
                    </td>
                    <td className="py-2 px-3 text-center">{c.avgLatencyMs}ms</td>
                    <td className="py-2 px-3 text-center text-muted-foreground">{c.totalTokensIn.toLocaleString()}</td>
                    <td className="py-2 px-3 text-center text-muted-foreground">{c.totalTokensOut.toLocaleString()}</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {isLoading && (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
        </div>
      )}

      {!isLoading && data && data.daily.length === 0 && (
        <div className="text-center py-16 text-muted-foreground">
          <Activity className="h-12 w-12 mx-auto mb-4 opacity-30" />
          <p className="text-lg font-medium">No telemetry data</p>
          <p className="text-sm mt-1">LLM call telemetry will appear here as the platform processes requests.</p>
        </div>
      )}
    </div>
  );
}

// ─── Model Performance Tab ─────────────────────────────────────────────────

function ModelPerformanceTab({ windowDays }: { windowDays: number }) {
  const { data, isLoading } = trpc.trainingData.getModelPerformance.useQuery({ windowDays });

  return (
    <div className="space-y-6">
      <div className="rounded-xl border border-border bg-card p-5">
        <h3 className="text-sm font-semibold flex items-center gap-2 mb-4">
          <Cpu className="h-4 w-4 text-cyan-400" />
          Model Performance Comparison
        </h3>
        <p className="text-sm text-muted-foreground mb-4">
          Compare model performance across all LLM calls in the selected time window. Metrics include success rate, latency, token usage, and retry frequency.
        </p>

        {isLoading ? (
          <div className="flex items-center justify-center py-12">
            <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
          </div>
        ) : data && data.length > 0 ? (
          <div className="space-y-4">
            {data.map((m: any) => (
              <div key={m.model} className="border border-border rounded-lg p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    <Cpu className="h-4 w-4 text-cyan-400" />
                    <span className="font-mono text-sm font-medium">{m.model}</span>
                  </div>
                  <Badge variant="outline" className="text-[10px]">{m.totalCalls.toLocaleString()} calls</Badge>
                </div>
                <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
                  <div className="text-center">
                    <div className={`text-lg font-bold ${m.successRate >= 95 ? "text-green-400" : m.successRate >= 85 ? "text-yellow-400" : "text-red-400"}`}>
                      {m.successRate}%
                    </div>
                    <div className="text-[10px] text-muted-foreground">Success Rate</div>
                  </div>
                  <div className="text-center">
                    <div className="text-lg font-bold text-red-400">{m.errors}</div>
                    <div className="text-[10px] text-muted-foreground">Errors</div>
                  </div>
                  <div className="text-center">
                    <div className="text-lg font-bold">{m.avgLatencyMs}ms</div>
                    <div className="text-[10px] text-muted-foreground">Avg Latency</div>
                  </div>
                  <div className="text-center">
                    <div className="text-lg font-bold">{m.p95LatencyMs}ms</div>
                    <div className="text-[10px] text-muted-foreground">P95 Latency</div>
                  </div>
                  <div className="text-center">
                    <div className="text-lg font-bold">{m.avgTokensIn}</div>
                    <div className="text-[10px] text-muted-foreground">Avg Tokens In</div>
                  </div>
                  <div className="text-center">
                    <div className="text-lg font-bold">{m.avgTokensOut}</div>
                    <div className="text-[10px] text-muted-foreground">Avg Tokens Out</div>
                  </div>
                  <div className="text-center">
                    <div className="text-lg font-bold text-yellow-400">{m.totalRetries}</div>
                    <div className="text-[10px] text-muted-foreground">Retries</div>
                  </div>
                </div>
              </div>
            ))}
          </div>
        ) : (
          <div className="text-center py-12 text-muted-foreground">
            <Cpu className="h-8 w-8 mx-auto mb-3 opacity-30" />
            <p className="text-sm">No model performance data available for this time window.</p>
          </div>
        )}
      </div>
    </div>
  );
}
