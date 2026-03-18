import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import AppShell from "@/components/AppShell";
import {
  Database, Brain, RefreshCw, BarChart3, Target, CheckCircle2,
  AlertTriangle, Clock, Loader2, ChevronDown, ChevronUp,
  GraduationCap, Crosshair, Bug, Zap, Eye, TrendingUp,
  FileText, Shield, BookOpen, Flame,
} from "lucide-react";
import { useState, useMemo } from "react";

function verdictColor(verdict: string) {
  switch (verdict?.toLowerCase()) {
    case "correct": case "success": return "bg-green-500/20 text-green-400 border-green-500/30";
    case "partial": case "warning": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
    case "incorrect": case "failure": return "bg-red-500/20 text-red-400 border-red-500/30";
    default: return "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
  }
}

function categoryColor(cat: string) {
  switch (cat) {
    case "vuln_correlation": return "text-cyan-400";
    case "exploit_planning": return "text-orange-400";
    case "exploit_outcome": return "text-red-400";
    case "scan_decision": return "text-blue-400";
    case "opsec_decision": return "text-yellow-400";
    default: return "text-zinc-400";
  }
}

export default function TrainingDataDashboard() {
  const [activeTab, setActiveTab] = useState<"overview" | "decisions" | "examples" | "callers">("overview");
  const [decisionPage, setDecisionPage] = useState(0);
  const [examplePage, setExamplePage] = useState(0);
  const [expandedDecision, setExpandedDecision] = useState<number | null>(null);
  const [expandedExample, setExpandedExample] = useState<number | null>(null);
  const [callerFilter, setCallerFilter] = useState<string>("all");

  // Queries
  const { data: batchStatus, refetch: refetchBatch } = trpc.engagementAutomation.getBatchTrainingStatus.useQuery();

  const stats = batchStatus?.trainingStats;
  const graduation = batchStatus?.graduationSummary;

  const tabs = [
    { id: "overview", label: "Overview", icon: BarChart3 },
    { id: "decisions", label: "Decision Log", icon: Brain },
    { id: "examples", label: "Training Examples", icon: Database },
    { id: "callers", label: "Caller Analysis", icon: Target },
  ] as const;

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
              Monitor LLM training data generation from engagements, decision logs, and graduation readiness.
            </p>
          </div>
          <Button variant="outline" size="sm" onClick={() => refetchBatch()}>
            <RefreshCw className="h-4 w-4 mr-1" />
            Refresh
          </Button>
        </div>

        {/* Key Metrics */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          <MetricCard icon={Database} label="Training Examples" value={stats?.totalExamples || 0} color="text-purple-400" />
          <MetricCard icon={Brain} label="Decisions Logged" value={stats?.totalDecisions || 0} color="text-blue-400" />
          <MetricCard icon={Target} label="Unique Callers" value={Object.keys(stats?.callerBreakdown || {}).length} color="text-cyan-400" />
          <MetricCard icon={Zap} label="Active Engagements" value={batchStatus?.activeCount || 0} color="text-orange-400" />
          <MetricCard icon={CheckCircle2} label="Completed" value={batchStatus?.completedCount || 0} color="text-green-400" />
          <MetricCard icon={GraduationCap} label="Graduation Callers" value={graduation?.totalCallers || 0} color="text-purple-400" />
        </div>

        {/* Tabs */}
        <div className="flex gap-1 border-b border-border">
          {tabs.map(tab => (
            <button
              key={tab.id}
              onClick={() => setActiveTab(tab.id)}
              className={`flex items-center gap-1.5 px-4 py-2.5 text-sm font-medium border-b-2 transition-colors ${
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
        {activeTab === "overview" && (
          <OverviewTab stats={stats} graduation={graduation} batchStatus={batchStatus} />
        )}
        {activeTab === "decisions" && (
          <DecisionLogTab
            expandedDecision={expandedDecision}
            setExpandedDecision={setExpandedDecision}
            batchStatus={batchStatus}
          />
        )}
        {activeTab === "examples" && (
          <TrainingExamplesTab
            expandedExample={expandedExample}
            setExpandedExample={setExpandedExample}
            stats={stats}
          />
        )}
        {activeTab === "callers" && (
          <CallerAnalysisTab stats={stats} graduation={graduation} />
        )}
      </div>
    </AppShell>
  );
}

function MetricCard({ icon: Icon, label, value, color }: { icon: any; label: string; value: number; color: string }) {
  return (
    <div className="rounded-lg border border-border bg-card p-3 text-center">
      <Icon className={`h-4 w-4 mx-auto mb-1 ${color}`} />
      <div className="text-lg font-bold">{value.toLocaleString()}</div>
      <div className="text-[10px] text-muted-foreground uppercase tracking-wider">{label}</div>
    </div>
  );
}

function OverviewTab({ stats, graduation, batchStatus }: any) {
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

      {/* Caller Breakdown */}
      {stats?.callerBreakdown && Object.keys(stats.callerBreakdown).length > 0 && (
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold flex items-center gap-2 mb-4">
            <Target className="h-4 w-4 text-cyan-400" />
            Training Data by Caller
          </h3>
          <div className="space-y-2">
            {Object.entries(stats.callerBreakdown)
              .sort(([, a], [, b]) => (b as number) - (a as number))
              .map(([caller, count]) => {
                const maxCount = Math.max(...Object.values(stats.callerBreakdown as Record<string, number>));
                const pct = maxCount > 0 ? ((count as number) / maxCount) * 100 : 0;
                return (
                  <div key={caller} className="flex items-center gap-3">
                    <div className="w-48 text-sm font-mono truncate">{caller}</div>
                    <div className="flex-1 h-2 rounded-full bg-muted overflow-hidden">
                      <div
                        className="h-full bg-purple-500 rounded-full transition-all"
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                    <div className="w-16 text-right text-sm font-medium">{(count as number).toLocaleString()}</div>
                  </div>
                );
              })}
          </div>
        </div>
      )}

      {/* Engagement Training Summary */}
      {batchStatus?.engagements && batchStatus.engagements.length > 0 && (
        <div className="rounded-xl border border-border bg-card p-5">
          <h3 className="text-sm font-semibold flex items-center gap-2 mb-4">
            <Crosshair className="h-4 w-4 text-orange-400" />
            Engagement Training Data
          </h3>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-muted-foreground text-xs">
                  <th className="text-left py-2 px-3">Engagement</th>
                  <th className="text-left py-2 px-3">Target</th>
                  <th className="text-center py-2 px-3">Phase</th>
                  <th className="text-center py-2 px-3">Vulns</th>
                  <th className="text-center py-2 px-3">Exploits</th>
                  <th className="text-center py-2 px-3">Success</th>
                  <th className="text-center py-2 px-3">Progress</th>
                </tr>
              </thead>
              <tbody>
                {batchStatus.engagements.slice(0, 20).map((eng: any) => (
                  <tr key={eng.engagementId} className="border-b border-border/50 hover:bg-muted/20">
                    <td className="py-2 px-3 font-medium truncate max-w-48">{eng.name}</td>
                    <td className="py-2 px-3 text-muted-foreground">{eng.target}</td>
                    <td className="py-2 px-3 text-center">
                      <Badge variant="outline" className="text-[10px]">{eng.opsPhase}</Badge>
                    </td>
                    <td className="py-2 px-3 text-center">{eng.vulnsFound}</td>
                    <td className="py-2 px-3 text-center">{eng.exploitsRun}</td>
                    <td className="py-2 px-3 text-center text-green-400">{eng.exploitsSucceeded}</td>
                    <td className="py-2 px-3 text-center">{eng.progress}%</td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {/* Empty State */}
      {(!stats || (stats.totalExamples === 0 && stats.totalDecisions === 0)) && (
        <div className="text-center py-16 text-muted-foreground">
          <Database className="h-12 w-12 mx-auto mb-4 opacity-30" />
          <p className="text-lg font-medium">No training data yet</p>
          <p className="text-sm mt-1">Launch batch training runs to generate LLM training examples and decision logs.</p>
        </div>
      )}
    </div>
  );
}

function DecisionLogTab({ expandedDecision, setExpandedDecision, batchStatus }: any) {
  // Show engagement-level decision data from the batch status
  const engagements = batchStatus?.engagements || [];

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-border bg-card p-5">
        <h3 className="text-sm font-semibold flex items-center gap-2 mb-4">
          <Brain className="h-4 w-4 text-blue-400" />
          LLM Decision Log
        </h3>
        <p className="text-sm text-muted-foreground mb-4">
          Every LLM decision during engagements is captured with full context — the input state, the decision made,
          the reasoning, and the eventual outcome. This data feeds directly into the training pipeline and graduation engine.
        </p>

        <div className="space-y-3">
          <div className="grid grid-cols-3 gap-4">
            <div className="p-4 rounded-lg bg-cyan-500/10 border border-cyan-500/20">
              <div className="text-sm font-medium flex items-center gap-2">
                <Eye className="h-4 w-4 text-cyan-400" />
                Vuln Correlation Decisions
              </div>
              <div className="text-xs text-muted-foreground mt-1">
                LLM correlates scanner findings with engagement observations to recommend exploitation strategy.
              </div>
            </div>
            <div className="p-4 rounded-lg bg-orange-500/10 border border-orange-500/20">
              <div className="text-sm font-medium flex items-center gap-2">
                <Crosshair className="h-4 w-4 text-orange-400" />
                Exploitation Plan Decisions
              </div>
              <div className="text-xs text-muted-foreground mt-1">
                LLM selects targets, techniques, and tools for exploitation based on vulnerability analysis.
              </div>
            </div>
            <div className="p-4 rounded-lg bg-red-500/10 border border-red-500/20">
              <div className="text-sm font-medium flex items-center gap-2">
                <Flame className="h-4 w-4 text-red-400" />
                Exploit Outcome Feedback
              </div>
              <div className="text-xs text-muted-foreground mt-1">
                Success/failure of each exploit attempt is captured and linked back to the planning decision.
              </div>
            </div>
          </div>
        </div>

        {/* Engagement-level decision counts */}
        {engagements.length > 0 && (
          <div className="mt-6">
            <h4 className="text-xs font-medium text-muted-foreground mb-3">Decision Data by Engagement</h4>
            <div className="space-y-2">
              {engagements.filter((e: any) => e.vulnsFound > 0 || e.exploitsRun > 0).map((eng: any) => (
                <div key={eng.engagementId} className="flex items-center gap-3 p-3 rounded-lg bg-muted/20 border border-border">
                  <div className="flex-1">
                    <div className="text-sm font-medium">{eng.name}</div>
                    <div className="text-xs text-muted-foreground">{eng.target}</div>
                  </div>
                  <div className="flex items-center gap-4 text-xs">
                    <span className="flex items-center gap-1">
                      <Bug className="h-3 w-3 text-yellow-400" />
                      {eng.vulnsFound} vulns
                    </span>
                    <span className="flex items-center gap-1">
                      <Crosshair className="h-3 w-3 text-orange-400" />
                      {eng.exploitsRun} exploits
                    </span>
                    <span className="flex items-center gap-1">
                      <CheckCircle2 className="h-3 w-3 text-green-400" />
                      {eng.exploitsSucceeded} success
                    </span>
                  </div>
                </div>
              ))}
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function TrainingExamplesTab({ expandedExample, setExpandedExample, stats }: any) {
  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-border bg-card p-5">
        <h3 className="text-sm font-semibold flex items-center gap-2 mb-4">
          <Database className="h-4 w-4 text-purple-400" />
          Training Examples ({stats?.totalExamples || 0})
        </h3>
        <p className="text-sm text-muted-foreground mb-4">
          Training examples are structured input/output pairs extracted from engagement decisions.
          Each example captures the context (system state, available data), the LLM's decision, and the ground truth outcome.
          These are used to fine-tune specialist models and evaluate graduation readiness.
        </p>

        {/* Caller breakdown as training data sources */}
        {stats?.callerBreakdown && Object.keys(stats.callerBreakdown).length > 0 && (
          <div className="space-y-3">
            <h4 className="text-xs font-medium text-muted-foreground">Examples by Source Caller</h4>
            <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-4 gap-3">
              {Object.entries(stats.callerBreakdown)
                .sort(([, a], [, b]) => (b as number) - (a as number))
                .map(([caller, count]) => (
                  <div key={caller} className="p-3 rounded-lg bg-muted/20 border border-border">
                    <div className="text-sm font-mono truncate" title={caller}>{caller}</div>
                    <div className="text-lg font-bold mt-1">{(count as number).toLocaleString()}</div>
                    <div className="text-[10px] text-muted-foreground">examples</div>
                  </div>
                ))}
            </div>
          </div>
        )}

        {(!stats || stats.totalExamples === 0) && (
          <div className="text-center py-8 text-muted-foreground">
            <Database className="h-8 w-8 mx-auto mb-3 opacity-30" />
            <p className="text-sm">No training examples yet. Run batch training to generate data.</p>
          </div>
        )}
      </div>
    </div>
  );
}

function CallerAnalysisTab({ stats, graduation }: any) {
  const callers = Object.entries(stats?.callerBreakdown || {}).sort(([, a], [, b]) => (b as number) - (a as number));

  return (
    <div className="space-y-4">
      <div className="rounded-xl border border-border bg-card p-5">
        <h3 className="text-sm font-semibold flex items-center gap-2 mb-4">
          <Target className="h-4 w-4 text-cyan-400" />
          LLM Caller Analysis
        </h3>
        <p className="text-sm text-muted-foreground mb-4">
          Each LLM caller represents a specialist function (vuln correlation, exploit planning, scan decision, etc.).
          The graduation engine evaluates each caller independently based on success rate and call volume.
        </p>

        {callers.length > 0 ? (
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead>
                <tr className="border-b border-border text-muted-foreground text-xs">
                  <th className="text-left py-2 px-3">Caller</th>
                  <th className="text-center py-2 px-3">Training Examples</th>
                  <th className="text-center py-2 px-3">Est. Tier</th>
                  <th className="text-left py-2 px-3">Status</th>
                </tr>
              </thead>
              <tbody>
                {callers.map(([caller, count]) => {
                  const c = count as number;
                  let tier = "Tier 4";
                  let tierColor = "text-orange-400";
                  if (c >= 500) { tier = "Tier 1"; tierColor = "text-green-400"; }
                  else if (c >= 200) { tier = "Tier 2"; tierColor = "text-blue-400"; }
                  else if (c >= 50) { tier = "Tier 3"; tierColor = "text-yellow-400"; }
                  return (
                    <tr key={caller} className="border-b border-border/50 hover:bg-muted/20">
                      <td className="py-2 px-3 font-mono text-sm">{caller}</td>
                      <td className="py-2 px-3 text-center font-medium">{c.toLocaleString()}</td>
                      <td className="py-2 px-3 text-center">
                        <span className={`font-medium ${tierColor}`}>{tier}</span>
                      </td>
                      <td className="py-2 px-3">
                        <Badge variant="outline" className={`text-[10px] ${
                          c >= 500 ? "border-green-500/30 text-green-400" :
                          c >= 200 ? "border-blue-500/30 text-blue-400" :
                          c >= 50 ? "border-yellow-500/30 text-yellow-400" :
                          "border-orange-500/30 text-orange-400"
                        }`}>
                          {c >= 500 ? "Production Ready" : c >= 200 ? "Supervised" : c >= 50 ? "Training" : "Needs More Data"}
                        </Badge>
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        ) : (
          <div className="text-center py-8 text-muted-foreground">
            <Target className="h-8 w-8 mx-auto mb-3 opacity-30" />
            <p className="text-sm">No caller data yet. Run training engagements to populate.</p>
          </div>
        )}
      </div>
    </div>
  );
}
