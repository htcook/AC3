import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import AppShell from "@/components/AppShell";
import {
  Zap, Play, RefreshCw, Target, Shield, Brain, Database,
  CheckCircle2, AlertTriangle, Loader2, Clock, Globe,
  GraduationCap, BookOpen, Crosshair, BarChart3, Flame,
  Bug, ChevronDown, ChevronUp, Pause, XCircle,
} from "lucide-react";
import { useState, useEffect, useMemo } from "react";

const AVAILABLE_TARGETS = [
  // Public intentionally vulnerable sites
  { domain: "demo.testfire.net", name: "Altoro Mutual (IBM AppScan)", category: "Banking" },
  { domain: "zero.webappsecurity.com", name: "Zero Bank (Micro Focus)", category: "Banking" },
  { domain: "testphp.vulnweb.com", name: "Acunetix Test PHP", category: "Web App" },
  { domain: "ginandjuice.shop", name: "Gin & Juice Shop (PortSwigger)", category: "E-Commerce" },
  { domain: "brokencrystals.com", name: "Broken Crystals (NeuraLegion)", category: "Modern Web" },
  { domain: "hackazon.webscantest.com", name: "Hackazon (Rapid7)", category: "E-Commerce" },
  { domain: "dvwa.co.uk", name: "DVWA (Public)", category: "Training" },
  // DO Scan Server lab instances
  { domain: "dvwa.aceofcloud.io", name: "DVWA (Lab Server)", category: "Lab" },
  { domain: "159.223.152.190/lab/dvwa/", name: "DVWA (DO Lab)", category: "Lab" },
  { domain: "159.223.152.190/lab/bwapp/", name: "bWAPP (DO Lab)", category: "Lab" },
  { domain: "159.223.152.190/lab/juice-shop/", name: "Juice Shop (DO Lab)", category: "Lab" },
  { domain: "159.223.152.190/lab/crapi/", name: "crAPI (DO Lab)", category: "API" },
  { domain: "159.223.152.190/lab/vampi/", name: "VAmPI (DO Lab)", category: "API" },
  { domain: "159.223.152.190/lab/dvga/", name: "DVGA — GraphQL (DO Lab)", category: "API" },
  // Additional public targets
  { domain: "scanme.nmap.org", name: "ScanMe (Network Test)", category: "Network" },
  { domain: "hack-yourself-first.com", name: "Hack Yourself First", category: "Web App" },
  { domain: "pentest-ground.com", name: "Pentest Ground", category: "Web App" },
];

function phaseColor(phase: string) {
  switch (phase) {
    case "recon": return "bg-blue-500/20 text-blue-400 border-blue-500/30";
    case "enumeration":
    case "scanning": return "bg-cyan-500/20 text-cyan-400 border-cyan-500/30";
    case "vuln_detection": return "bg-yellow-500/20 text-yellow-400 border-yellow-500/30";
    case "exploitation": return "bg-orange-500/20 text-orange-400 border-orange-500/30";
    case "post_exploit": return "bg-red-500/20 text-red-400 border-red-500/30";
    case "completed": return "bg-green-500/20 text-green-400 border-green-500/30";
    case "error": return "bg-red-500/20 text-red-400 border-red-500/30";
    default: return "bg-zinc-500/20 text-zinc-400 border-zinc-500/30";
  }
}

export default function BatchTraining() {
  const [selectedTargets, setSelectedTargets] = useState<Set<string>>(new Set());
  const [scanMode, setScanMode] = useState<"strict_passive" | "standard" | "active">("active");
  const [scanProfile, setScanProfile] = useState<"quick" | "standard" | "deep" | "stealth">("standard");
  const [injectDfir, setInjectDfir] = useState(true);
  const [runGraduation, setRunGraduation] = useState(true);
  const [showConfig, setShowConfig] = useState(true);
  const [autoRefresh, setAutoRefresh] = useState(false);

  const { data: status, refetch: refetchStatus } = trpc.engagementAutomation.getBatchTrainingStatus.useQuery(
    undefined,
    { refetchInterval: autoRefresh ? 5000 : false }
  );

  const batchMutation = trpc.engagementAutomation.batchTrainingRun.useMutation({
    onSuccess: (data) => {
      toast.success(`Launched ${data.launched} training engagements`);
      setAutoRefresh(true);
      refetchStatus();
    },
    onError: (err) => toast.error(err.message),
  });

  // Auto-enable refresh when there are running engagements
  useEffect(() => {
    if (status?.activeCount && status.activeCount > 0) {
      setAutoRefresh(true);
    } else if (status?.activeCount === 0 && autoRefresh) {
      // Keep refreshing for a bit after completion
      const timer = setTimeout(() => setAutoRefresh(false), 30000);
      return () => clearTimeout(timer);
    }
  }, [status?.activeCount]);

  const toggleTarget = (domain: string) => {
    setSelectedTargets(prev => {
      const next = new Set(prev);
      if (next.has(domain)) next.delete(domain);
      else next.add(domain);
      return next;
    });
  };

  const selectAll = () => {
    if (selectedTargets.size === AVAILABLE_TARGETS.length) {
      setSelectedTargets(new Set());
    } else {
      setSelectedTargets(new Set(AVAILABLE_TARGETS.map(t => t.domain)));
    }
  };

  const launchBatch = () => {
    if (selectedTargets.size === 0) {
      toast.error("Select at least one target");
      return;
    }
    batchMutation.mutate({
      targets: Array.from(selectedTargets).map(domain => ({
        domain,
        engagementType: "pentest",
        scanProfile,
      })),
      scanMode,
      injectDfirKnowledge: injectDfir,
      autoExecute: true,
      runGraduationAfter: runGraduation,
    });
  };

  const activeEngagements = status?.engagements?.filter((e: any) => e.isRunning) || [];
  const completedEngagements = status?.engagements?.filter((e: any) => e.opsPhase === "completed") || [];
  const errorEngagements = status?.engagements?.filter((e: any) => e.opsPhase === "error" || e.error) || [];

  return (
    <AppShell>
      <div className="max-w-7xl mx-auto px-4 py-8 space-y-8">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-3">
              <Zap className="h-7 w-7 text-purple-400" />
              Batch Training Runner
            </h1>
            <p className="text-muted-foreground mt-1">
              Launch full-pipeline training engagements against lab targets to generate LLM training data and test graduation readiness.
            </p>
          </div>
          <div className="flex items-center gap-2">
            <Button
              variant="outline"
              size="sm"
              onClick={() => { setAutoRefresh(!autoRefresh); refetchStatus(); }}
              className={autoRefresh ? "border-green-500/50 text-green-400" : ""}
            >
              <RefreshCw className={`h-4 w-4 mr-1 ${autoRefresh ? "animate-spin" : ""}`} />
              {autoRefresh ? "Live" : "Refresh"}
            </Button>
          </div>
        </div>

        {/* Stats Overview */}
        {status && (
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
            <StatCard icon={Play} label="Active" value={status.activeCount} color="text-blue-400" />
            <StatCard icon={CheckCircle2} label="Completed" value={status.completedCount} color="text-green-400" />
            <StatCard icon={XCircle} label="Errors" value={status.errorCount} color="text-red-400" />
            <StatCard icon={Bug} label="Vulns Found" value={status.totalVulns} color="text-yellow-400" />
            <StatCard icon={Crosshair} label="Exploits Run" value={status.totalExploits} color="text-orange-400" />
            <StatCard icon={CheckCircle2} label="Exploit Success" value={status.totalExploitSuccesses} color="text-green-400" />
            <StatCard icon={Database} label="Training Examples" value={status.trainingStats?.totalExamples || 0} color="text-purple-400" />
          </div>
        )}

        {/* Graduation Summary */}
        {status?.graduationSummary && status.graduationSummary.totalCallers > 0 && (
          <div className="rounded-xl border border-border bg-card p-5">
            <h3 className="text-sm font-semibold flex items-center gap-2 mb-3">
              <GraduationCap className="h-4 w-4 text-purple-400" />
              Graduation Engine Status
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              <div className="text-center p-3 rounded-lg bg-green-500/10 border border-green-500/20">
                <div className="text-lg font-bold text-green-400">{status.graduationSummary.tier1}</div>
                <div className="text-xs text-muted-foreground">Tier 1 (Production)</div>
              </div>
              <div className="text-center p-3 rounded-lg bg-blue-500/10 border border-blue-500/20">
                <div className="text-lg font-bold text-blue-400">{status.graduationSummary.tier2}</div>
                <div className="text-xs text-muted-foreground">Tier 2 (Supervised)</div>
              </div>
              <div className="text-center p-3 rounded-lg bg-yellow-500/10 border border-yellow-500/20">
                <div className="text-lg font-bold text-yellow-400">{status.graduationSummary.tier3}</div>
                <div className="text-xs text-muted-foreground">Tier 3 (Training)</div>
              </div>
              <div className="text-center p-3 rounded-lg bg-orange-500/10 border border-orange-500/20">
                <div className="text-lg font-bold text-orange-400">{status.graduationSummary.tier4}</div>
                <div className="text-xs text-muted-foreground">Tier 4 (Novice)</div>
              </div>
              <div className="text-center p-3 rounded-lg bg-zinc-500/10 border border-zinc-500/20">
                <div className="text-lg font-bold text-zinc-400">{status.graduationSummary.totalCallers}</div>
                <div className="text-xs text-muted-foreground">Total Callers</div>
              </div>
            </div>
          </div>
        )}

        {/* Launch Configuration */}
        <div className="rounded-xl border border-border bg-card overflow-hidden">
          <button
            className="w-full flex items-center justify-between p-5 hover:bg-muted/30 transition-colors"
            onClick={() => setShowConfig(!showConfig)}
          >
            <h3 className="text-sm font-semibold flex items-center gap-2">
              <Target className="h-4 w-4 text-orange-400" />
              Launch New Batch Training Run
            </h3>
            {showConfig ? <ChevronUp className="h-4 w-4" /> : <ChevronDown className="h-4 w-4" />}
          </button>

          {showConfig && (
            <div className="px-5 pb-5 space-y-5 border-t border-border pt-4">
              {/* Target Selection */}
              <div>
                <div className="flex items-center justify-between mb-3">
                  <label className="text-sm font-medium">Lab Targets</label>
                  <Button variant="ghost" size="sm" onClick={selectAll} className="text-xs">
                    {selectedTargets.size === AVAILABLE_TARGETS.length ? "Deselect All" : "Select All"}
                  </Button>
                </div>
                <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                  {AVAILABLE_TARGETS.map(target => (
                    <button
                      key={target.domain}
                      onClick={() => toggleTarget(target.domain)}
                      className={`flex items-center gap-3 p-3 rounded-lg border transition-all text-left ${
                        selectedTargets.has(target.domain)
                          ? "border-purple-500/50 bg-purple-500/10"
                          : "border-border hover:border-muted-foreground/30 bg-card"
                      }`}
                    >
                      <div className={`w-4 h-4 rounded border-2 flex items-center justify-center ${
                        selectedTargets.has(target.domain)
                          ? "border-purple-400 bg-purple-400"
                          : "border-muted-foreground/40"
                      }`}>
                        {selectedTargets.has(target.domain) && (
                          <CheckCircle2 className="h-3 w-3 text-white" />
                        )}
                      </div>
                      <div className="flex-1 min-w-0">
                        <div className="text-sm font-medium truncate">{target.name}</div>
                        <div className="text-xs text-muted-foreground">{target.domain}</div>
                      </div>
                      <Badge variant="outline" className="text-[10px] shrink-0">{target.category}</Badge>
                    </button>
                  ))}
                </div>
              </div>

              {/* Configuration Row */}
              <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
                <div>
                  <label className="text-xs font-medium text-muted-foreground block mb-1.5">Scan Mode</label>
                  <select
                    value={scanMode}
                    onChange={e => setScanMode(e.target.value as any)}
                    className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                  >
                    <option value="strict_passive">Passive Only</option>
                    <option value="standard">Standard</option>
                    <option value="active">Active (Full)</option>
                  </select>
                </div>
                <div>
                  <label className="text-xs font-medium text-muted-foreground block mb-1.5">Scan Profile</label>
                  <select
                    value={scanProfile}
                    onChange={e => setScanProfile(e.target.value as any)}
                    className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm"
                  >
                    <option value="quick">Quick</option>
                    <option value="standard">Standard</option>
                    <option value="deep">Deep</option>
                    <option value="stealth">Stealth</option>
                  </select>
                </div>
                <div className="flex items-end">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={injectDfir}
                      onChange={e => setInjectDfir(e.target.checked)}
                      className="rounded border-border"
                    />
                    <span className="text-sm flex items-center gap-1">
                      <BookOpen className="h-3.5 w-3.5 text-cyan-400" />
                      Inject DFIR Knowledge
                    </span>
                  </label>
                </div>
                <div className="flex items-end">
                  <label className="flex items-center gap-2 cursor-pointer">
                    <input
                      type="checkbox"
                      checked={runGraduation}
                      onChange={e => setRunGraduation(e.target.checked)}
                      className="rounded border-border"
                    />
                    <span className="text-sm flex items-center gap-1">
                      <GraduationCap className="h-3.5 w-3.5 text-purple-400" />
                      Run Graduation After
                    </span>
                  </label>
                </div>
              </div>

              {/* Launch Button */}
              <div className="flex items-center justify-between pt-2">
                <div className="text-sm text-muted-foreground">
                  {selectedTargets.size} target{selectedTargets.size !== 1 ? "s" : ""} selected
                </div>
                <Button
                  onClick={launchBatch}
                  disabled={selectedTargets.size === 0 || batchMutation.isPending}
                  className="bg-purple-600 hover:bg-purple-700"
                >
                  {batchMutation.isPending ? (
                    <Loader2 className="h-4 w-4 mr-2 animate-spin" />
                  ) : (
                    <Play className="h-4 w-4 mr-2" />
                  )}
                  Launch Batch Training ({selectedTargets.size})
                </Button>
              </div>
            </div>
          )}
        </div>

        {/* Active Engagements */}
        {activeEngagements.length > 0 && (
          <div className="rounded-xl border border-blue-500/30 bg-blue-500/5 p-5">
            <h3 className="text-sm font-semibold flex items-center gap-2 mb-4">
              <Loader2 className="h-4 w-4 text-blue-400 animate-spin" />
              Active Training Engagements ({activeEngagements.length})
            </h3>
            <div className="space-y-3">
              {activeEngagements.map((eng: any) => (
                <EngagementRow key={eng.engagementId} eng={eng} />
              ))}
            </div>
          </div>
        )}

        {/* Completed Engagements */}
        {completedEngagements.length > 0 && (
          <div className="rounded-xl border border-green-500/30 bg-green-500/5 p-5">
            <h3 className="text-sm font-semibold flex items-center gap-2 mb-4">
              <CheckCircle2 className="h-4 w-4 text-green-400" />
              Completed Training Engagements ({completedEngagements.length})
            </h3>
            <div className="space-y-3">
              {completedEngagements.map((eng: any) => (
                <EngagementRow key={eng.engagementId} eng={eng} />
              ))}
            </div>
          </div>
        )}

        {/* Error Engagements */}
        {errorEngagements.length > 0 && (
          <div className="rounded-xl border border-red-500/30 bg-red-500/5 p-5">
            <h3 className="text-sm font-semibold flex items-center gap-2 mb-4">
              <AlertTriangle className="h-4 w-4 text-red-400" />
              Failed Training Engagements ({errorEngagements.length})
            </h3>
            <div className="space-y-3">
              {errorEngagements.map((eng: any) => (
                <EngagementRow key={eng.engagementId} eng={eng} />
              ))}
            </div>
          </div>
        )}

        {/* Training Data Breakdown */}
        {status?.trainingStats && (status.trainingStats.totalExamples > 0 || status.trainingStats.totalDecisions > 0) && (
          <div className="rounded-xl border border-border bg-card p-5">
            <h3 className="text-sm font-semibold flex items-center gap-2 mb-4">
              <Database className="h-4 w-4 text-purple-400" />
              Training Data Generated
            </h3>
            <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
              <div className="p-3 rounded-lg bg-muted/30">
                <div className="text-lg font-bold">{status.trainingStats.totalExamples}</div>
                <div className="text-xs text-muted-foreground">Training Examples</div>
              </div>
              <div className="p-3 rounded-lg bg-muted/30">
                <div className="text-lg font-bold">{status.trainingStats.totalDecisions}</div>
                <div className="text-xs text-muted-foreground">LLM Decisions Logged</div>
              </div>
              <div className="p-3 rounded-lg bg-muted/30">
                <div className="text-lg font-bold">
                  {Object.keys(status.trainingStats.callerBreakdown || {}).length}
                </div>
                <div className="text-xs text-muted-foreground">Unique Callers</div>
              </div>
            </div>
            {status.trainingStats.callerBreakdown && Object.keys(status.trainingStats.callerBreakdown).length > 0 && (
              <div className="mt-4">
                <h4 className="text-xs font-medium text-muted-foreground mb-2">Caller Breakdown</h4>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(status.trainingStats.callerBreakdown).map(([caller, count]) => (
                    <Badge key={caller} variant="outline" className="text-xs">
                      {caller}: {count as number}
                    </Badge>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}

        {/* Empty State */}
        {(!status?.engagements || status.engagements.length === 0) && (
          <div className="text-center py-16 text-muted-foreground">
            <Zap className="h-12 w-12 mx-auto mb-4 opacity-30" />
            <p className="text-lg font-medium">No training engagements yet</p>
            <p className="text-sm mt-1">Select targets above and launch a batch training run to generate LLM training data.</p>
          </div>
        )}
      </div>
    </AppShell>
  );
}

function StatCard({ icon: Icon, label, value, color }: { icon: any; label: string; value: number; color: string }) {
  return (
    <div className="rounded-lg border border-border bg-card p-3 text-center">
      <Icon className={`h-4 w-4 mx-auto mb-1 ${color}`} />
      <div className="text-lg font-bold">{value}</div>
      <div className="text-[10px] text-muted-foreground uppercase tracking-wider">{label}</div>
    </div>
  );
}

function EngagementRow({ eng }: { eng: any }) {
  return (
    <div className="flex items-center gap-4 p-3 rounded-lg bg-card border border-border">
      <div className="flex-1 min-w-0">
        <div className="text-sm font-medium truncate">{eng.name}</div>
        <div className="text-xs text-muted-foreground flex items-center gap-2 mt-0.5">
          <Globe className="h-3 w-3" />
          {eng.target}
        </div>
      </div>
      <Badge variant="outline" className={`text-xs ${phaseColor(eng.opsPhase)}`}>
        {eng.opsPhase}
      </Badge>
      {eng.isRunning && (
        <div className="w-24">
          <div className="h-1.5 rounded-full bg-muted overflow-hidden">
            <div
              className="h-full bg-blue-500 rounded-full transition-all duration-500"
              style={{ width: `${eng.progress}%` }}
            />
          </div>
          <div className="text-[10px] text-muted-foreground text-center mt-0.5">{eng.progress}%</div>
        </div>
      )}
      <div className="flex items-center gap-3 text-xs text-muted-foreground">
        <span className="flex items-center gap-1">
          <Bug className="h-3 w-3 text-yellow-400" />
          {eng.vulnsFound}
        </span>
        <span className="flex items-center gap-1">
          <Crosshair className="h-3 w-3 text-orange-400" />
          {eng.exploitsRun}
        </span>
        <span className="flex items-center gap-1">
          <CheckCircle2 className="h-3 w-3 text-green-400" />
          {eng.exploitsSucceeded}
        </span>
      </div>
      {eng.error && (
        <span className="text-xs text-red-400 max-w-48 truncate" title={eng.error}>
          {eng.error}
        </span>
      )}
    </div>
  );
}
