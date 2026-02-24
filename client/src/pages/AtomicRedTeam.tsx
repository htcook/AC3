import { useState, useMemo } from "react";
import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription, DialogFooter } from "@/components/ui/dialog";
import { toast } from "sonner";
import {
  Atom, RefreshCw, Search, Shield, Terminal, Play, ChevronRight,
  Download, CheckCircle2, XCircle, AlertTriangle, Clock, Loader2,
  Target, Layers, Cpu, Monitor, Apple, Database, BarChart3, Eye,
  Crosshair, Zap, ArrowRight
} from "lucide-react";

// ─── Tactic Colors ───────────────────────────────────────────────────────────

const TACTIC_COLORS: Record<string, string> = {
  "Reconnaissance": "bg-blue-500/20 text-blue-400 border-blue-500/30",
  "Resource Development": "bg-indigo-500/20 text-indigo-400 border-indigo-500/30",
  "Initial Access": "bg-red-500/20 text-red-400 border-red-500/30",
  "Execution": "bg-orange-500/20 text-orange-400 border-orange-500/30",
  "Persistence": "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  "Privilege Escalation": "bg-amber-500/20 text-amber-400 border-amber-500/30",
  "Defense Evasion": "bg-purple-500/20 text-purple-400 border-purple-500/30",
  "Credential Access": "bg-pink-500/20 text-pink-400 border-pink-500/30",
  "Discovery": "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  "Lateral Movement": "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  "Collection": "bg-teal-500/20 text-teal-400 border-teal-500/30",
  "Command and Control": "bg-violet-500/20 text-violet-400 border-violet-500/30",
  "Exfiltration": "bg-rose-500/20 text-rose-400 border-rose-500/30",
  "Impact": "bg-red-600/20 text-red-300 border-red-600/30",
};

const PLATFORM_ICONS: Record<string, any> = {
  windows: Monitor,
  linux: Terminal,
  macos: Apple,
};

// ─── Main Page ───────────────────────────────────────────────────────────────

export default function AtomicRedTeam() {

  const [activeTab, setActiveTab] = useState("library");
  const [search, setSearch] = useState("");
  const [tacticFilter, setTacticFilter] = useState("all");
  const [platformFilter, setPlatformFilter] = useState("all");
  const [executorFilter, setExecutorFilter] = useState("all");
  const [selectedTest, setSelectedTest] = useState<any>(null);
  const [showExecuteDialog, setShowExecuteDialog] = useState(false);
  const [targetHost, setTargetHost] = useState("");
  const [targetPlatform, setTargetPlatform] = useState("linux");

  // ─── Data Queries ──────────────────────────────────────────────────────

  const statsQuery = trpc.atomicRedTeam.getStats.useQuery();
  const testsQuery = trpc.atomicRedTeam.listTests.useQuery({
    search: search || undefined,
    tactic: tacticFilter !== "all" ? tacticFilter : undefined,
    platform: platformFilter !== "all" ? platformFilter : undefined,
    executorType: executorFilter !== "all" ? executorFilter : undefined,
    limit: 100,
  });
  const coverageQuery = trpc.atomicRedTeam.getTechniqueCoverage.useQuery();
  const executionsQuery = trpc.atomicRedTeam.listExecutions.useQuery({ limit: 50 });

  // ─── Mutations ─────────────────────────────────────────────────────────

  const syncMutation = trpc.atomicRedTeam.syncFromGitHub.useMutation({
    onSuccess: (data) => {
      toast.success(`Synced ${data.synced} tests from ${data.techniques} techniques. ${data.errors.length} errors.`);
      testsQuery.refetch();
      statsQuery.refetch();
      coverageQuery.refetch();
    },
    onError: (err) => toast.error(`Sync failed: ${err.message}`),
  });

  const seedMutation = trpc.atomicRedTeam.seedDemoData.useMutation({
    onSuccess: (data) => {
      toast.success(`Seeded ${data.seeded} demo atomic tests.`);
      testsQuery.refetch();
      statsQuery.refetch();
      coverageQuery.refetch();
    },
    onError: (err) => toast.error(`Seed failed: ${err.message}`),
  });

  const executeMutation = trpc.atomicRedTeam.executeTest.useMutation({
    onSuccess: (data) => {
      toast.success(`Execution #${data.executionId} queued successfully.`);
      setShowExecuteDialog(false);
      executionsQuery.refetch();
    },
    onError: (err) => toast.error(`Execution failed: ${err.message}`),
  });

  // ─── Computed Values ───────────────────────────────────────────────────

  const stats = statsQuery.data;
  const tests = testsQuery.data?.tests || [];
  const coverage = coverageQuery.data || [];
  const executions = executionsQuery.data?.executions || [];

  const tacticGroups = useMemo(() => {
    const groups: Record<string, typeof coverage> = {};
    for (const c of coverage) {
      const tactic = c.tactic || "Unknown";
      if (!groups[tactic]) groups[tactic] = [];
      groups[tactic].push(c);
    }
    return groups;
  }, [coverage]);

  // ─── Handlers ──────────────────────────────────────────────────────────

  const handleExecute = () => {
    if (!selectedTest) return;
    executeMutation.mutate({
      atomicTestId: selectedTest.id,
      guid: selectedTest.guid,
      techniqueId: selectedTest.techniqueId,
      testName: selectedTest.testName,
      targetHost: targetHost || undefined,
      targetPlatform,
      executorType: selectedTest.executorType,
      commandExecuted: selectedTest.executorCommand,
    });
  };

  // ─── Render ────────────────────────────────────────────────────────────

  return (
    <AppShell>
      <div className="min-h-screen bg-background">
        <div className="p-6 max-w-[1600px] mx-auto space-y-6">
          {/* Header */}
          <div className="flex items-center justify-between">
            <div className="flex items-center gap-3">
              <div className="h-10 w-10 rounded-lg bg-red-500/20 flex items-center justify-center">
                <Atom className="h-5 w-5 text-red-400" />
              </div>
              <div>
                <h1 className="text-2xl font-bold text-foreground tracking-tight">Atomic Red Team</h1>
                <p className="text-sm text-muted-foreground">1,400+ ATT&CK-mapped adversary emulation tests</p>
              </div>
            </div>
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => seedMutation.mutate()}
                disabled={seedMutation.isPending}
                className="border-border/50"
              >
                {seedMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Database className="h-4 w-4 mr-1" />}
                Load Demo
              </Button>
              <Button
                size="sm"
                onClick={() => syncMutation.mutate({})}
                disabled={syncMutation.isPending}
                className="bg-red-600 hover:bg-red-700 text-white"
              >
                {syncMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Download className="h-4 w-4 mr-1" />}
                Sync from GitHub
              </Button>
            </div>
          </div>

          {/* Stats Row */}
          <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
            <StatCard label="Total Tests" value={stats?.totalTests || 0} icon={<Atom className="h-4 w-4" />} color="text-red-400" />
            <StatCard label="Techniques" value={stats?.totalTechniques || 0} icon={<Target className="h-4 w-4" />} color="text-cyan-400" />
            <StatCard label="Executions" value={stats?.totalExecutions || 0} icon={<Play className="h-4 w-4" />} color="text-emerald-400" />
            <StatCard label="Successful" value={stats?.successfulExecutions || 0} icon={<CheckCircle2 className="h-4 w-4" />} color="text-green-400" />
            <StatCard label="Failed" value={stats?.failedExecutions || 0} icon={<XCircle className="h-4 w-4" />} color="text-red-400" />
            <StatCard label="Detected" value={stats?.detectionTriggered || 0} icon={<AlertTriangle className="h-4 w-4" />} color="text-yellow-400" />
          </div>

          {/* Tabs */}
          <Tabs value={activeTab} onValueChange={setActiveTab}>
            <TabsList className="bg-card border border-border/50">
              <TabsTrigger value="library" className="data-[state=active]:bg-red-500/20 data-[state=active]:text-red-400">
                <Shield className="h-4 w-4 mr-1" /> Test Library
              </TabsTrigger>
              <TabsTrigger value="coverage" className="data-[state=active]:bg-cyan-500/20 data-[state=active]:text-cyan-400">
                <Layers className="h-4 w-4 mr-1" /> ATT&CK Coverage
              </TabsTrigger>
              <TabsTrigger value="executions" className="data-[state=active]:bg-emerald-500/20 data-[state=active]:text-emerald-400">
                <Terminal className="h-4 w-4 mr-1" /> Execution History
              </TabsTrigger>
              <TabsTrigger value="distributions" className="data-[state=active]:bg-purple-500/20 data-[state=active]:text-purple-400">
                <BarChart3 className="h-4 w-4 mr-1" /> Analytics
              </TabsTrigger>
            </TabsList>

            {/* ─── Test Library Tab ─────────────────────────────────────── */}
            <TabsContent value="library" className="space-y-4 mt-4">
              {/* Filters */}
              <div className="flex flex-wrap gap-3">
                <div className="relative flex-1 min-w-[250px]">
                  <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                  <Input
                    placeholder="Search tests, techniques, descriptions..."
                    value={search}
                    onChange={e => setSearch(e.target.value)}
                    className="pl-10 bg-card border-border/50"
                  />
                </div>
                <Select value={tacticFilter} onValueChange={setTacticFilter}>
                  <SelectTrigger className="w-[180px] bg-card border-border/50">
                    <SelectValue placeholder="All Tactics" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Tactics</SelectItem>
                    {Object.keys(TACTIC_COLORS).map(t => (
                      <SelectItem key={t} value={t}>{t}</SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Select value={platformFilter} onValueChange={setPlatformFilter}>
                  <SelectTrigger className="w-[140px] bg-card border-border/50">
                    <SelectValue placeholder="All Platforms" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Platforms</SelectItem>
                    <SelectItem value="windows">Windows</SelectItem>
                    <SelectItem value="linux">Linux</SelectItem>
                    <SelectItem value="macos">macOS</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={executorFilter} onValueChange={setExecutorFilter}>
                  <SelectTrigger className="w-[160px] bg-card border-border/50">
                    <SelectValue placeholder="All Executors" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Executors</SelectItem>
                    <SelectItem value="powershell">PowerShell</SelectItem>
                    <SelectItem value="command_prompt">Command Prompt</SelectItem>
                    <SelectItem value="bash">Bash</SelectItem>
                    <SelectItem value="sh">Shell</SelectItem>
                    <SelectItem value="manual">Manual</SelectItem>
                  </SelectContent>
                </Select>
              </div>

              {/* Test Count */}
              <div className="text-sm text-muted-foreground">
                Showing {tests.length} of {testsQuery.data?.total || 0} tests
              </div>

              {/* Test Cards */}
              {testsQuery.isLoading ? (
                <div className="flex items-center justify-center py-20">
                  <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                </div>
              ) : tests.length === 0 ? (
                <Card className="bg-card border-border/50">
                  <CardContent className="flex flex-col items-center justify-center py-16 text-center">
                    <Atom className="h-12 w-12 text-muted-foreground/30 mb-4" />
                    <h3 className="text-lg font-semibold text-foreground mb-2">No Atomic Tests Found</h3>
                    <p className="text-sm text-muted-foreground mb-4 max-w-md">
                      Click "Load Demo" for sample tests or "Sync from GitHub" to pull the full 1,400+ test library.
                    </p>
                    <div className="flex gap-2">
                      <Button variant="outline" size="sm" onClick={() => seedMutation.mutate()} disabled={seedMutation.isPending}>
                        Load Demo Data
                      </Button>
                      <Button size="sm" className="bg-red-600 hover:bg-red-700" onClick={() => syncMutation.mutate({})} disabled={syncMutation.isPending}>
                        Sync from GitHub
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ) : (
                <div className="space-y-2">
                  {tests.map(test => (
                    <TestCard
                      key={test.guid}
                      test={test}
                      onView={() => setSelectedTest(test)}
                      onExecute={() => { setSelectedTest(test); setShowExecuteDialog(true); }}
                    />
                  ))}
                </div>
              )}
            </TabsContent>

            {/* ─── ATT&CK Coverage Tab ─────────────────────────────────── */}
            <TabsContent value="coverage" className="space-y-4 mt-4">
              {coverageQuery.isLoading ? (
                <div className="flex items-center justify-center py-20">
                  <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                </div>
              ) : coverage.length === 0 ? (
                <Card className="bg-card border-border/50">
                  <CardContent className="py-16 text-center">
                    <Layers className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
                    <p className="text-muted-foreground">No coverage data yet. Sync tests first.</p>
                  </CardContent>
                </Card>
              ) : (
                Object.entries(tacticGroups).sort(([a], [b]) => {
                  const order = Object.keys(TACTIC_COLORS);
                  return order.indexOf(a) - order.indexOf(b);
                }).map(([tactic, techniques]) => (
                  <Card key={tactic} className="bg-card border-border/50">
                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Badge className={TACTIC_COLORS[tactic] || "bg-muted text-muted-foreground"}>
                            {tactic}
                          </Badge>
                          <span className="text-sm text-muted-foreground">
                            {techniques.length} techniques · {techniques.reduce((s, t) => s + t.testCount, 0)} tests
                          </span>
                        </div>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
                        {techniques.map(tech => (
                          <button
                            key={tech.techniqueId}
                            onClick={() => { setSearch(tech.techniqueId); setActiveTab("library"); }}
                            className="flex items-center justify-between p-3 rounded-lg bg-background/50 border border-border/30 hover:border-primary/40 transition-colors text-left"
                          >
                            <div className="min-w-0 flex-1">
                              <div className="flex items-center gap-2">
                                <code className="text-xs font-mono text-primary">{tech.techniqueId}</code>
                                <span className="text-xs text-muted-foreground">{tech.testCount} tests</span>
                              </div>
                              <p className="text-sm text-foreground truncate mt-0.5">{tech.techniqueName}</p>
                            </div>
                            <div className="flex items-center gap-1 ml-2">
                              {tech.platforms.includes("windows") && <Monitor className="h-3 w-3 text-blue-400" />}
                              {tech.platforms.includes("linux") && <Terminal className="h-3 w-3 text-green-400" />}
                              {tech.platforms.includes("macos") && <Apple className="h-3 w-3 text-gray-400" />}
                              {tech.executionCount > 0 && (
                                <Badge variant="outline" className="ml-1 text-[10px] px-1 py-0 border-emerald-500/30 text-emerald-400">
                                  {tech.executionCount}x
                                </Badge>
                              )}
                            </div>
                          </button>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                ))
              )}
            </TabsContent>

            {/* ─── Execution History Tab ────────────────────────────────── */}
            <TabsContent value="executions" className="space-y-4 mt-4">
              {executionsQuery.isLoading ? (
                <div className="flex items-center justify-center py-20">
                  <Loader2 className="h-8 w-8 animate-spin text-muted-foreground" />
                </div>
              ) : executions.length === 0 ? (
                <Card className="bg-card border-border/50">
                  <CardContent className="py-16 text-center">
                    <Terminal className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
                    <h3 className="text-lg font-semibold text-foreground mb-2">No Executions Yet</h3>
                    <p className="text-sm text-muted-foreground">Execute atomic tests from the library to see results here.</p>
                  </CardContent>
                </Card>
              ) : (
                <div className="space-y-2">
                  {executions.map((exec: any) => (
                    <Card key={exec.id} className="bg-card border-border/50">
                      <CardContent className="p-4">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-3">
                            <StatusIcon status={exec.status} />
                            <div>
                              <div className="flex items-center gap-2">
                                <code className="text-xs font-mono text-primary">{exec.techniqueId}</code>
                                <span className="text-sm font-medium text-foreground">{exec.testName}</span>
                              </div>
                              <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                                {exec.targetHost && <span>Target: {exec.targetHost}</span>}
                                {exec.targetPlatform && <span>Platform: {exec.targetPlatform}</span>}
                                {exec.durationMs && <span>Duration: {exec.durationMs}ms</span>}
                                {exec.exitCode !== null && <span>Exit: {exec.exitCode}</span>}
                              </div>
                            </div>
                          </div>
                          <div className="flex items-center gap-2">
                            {exec.detectionTriggered && (
                              <Badge className="bg-yellow-500/20 text-yellow-400 border-yellow-500/30">
                                <AlertTriangle className="h-3 w-3 mr-1" /> Detected
                              </Badge>
                            )}
                            <Badge variant="outline" className={getStatusColor(exec.status)}>
                              {exec.status}
                            </Badge>
                            <span className="text-xs text-muted-foreground">
                              {exec.createdAt ? new Date(exec.createdAt).toLocaleString() : ""}
                            </span>
                          </div>
                        </div>
                        {(exec.stdout || exec.stderr) && (
                          <div className="mt-3 p-2 rounded bg-background/50 border border-border/30">
                            {exec.stdout && (
                              <pre className="text-xs font-mono text-green-400 whitespace-pre-wrap max-h-24 overflow-auto">{exec.stdout}</pre>
                            )}
                            {exec.stderr && (
                              <pre className="text-xs font-mono text-red-400 whitespace-pre-wrap max-h-24 overflow-auto mt-1">{exec.stderr}</pre>
                            )}
                          </div>
                        )}
                      </CardContent>
                    </Card>
                  ))}
                </div>
              )}
            </TabsContent>

            {/* ─── Analytics Tab ────────────────────────────────────────── */}
            <TabsContent value="distributions" className="space-y-4 mt-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                {/* Tactic Distribution */}
                <Card className="bg-card border-border/50">
                  <CardHeader>
                    <CardTitle className="text-sm font-semibold">Tests by ATT&CK Tactic</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {stats?.tacticDistribution && Object.keys(stats.tacticDistribution).length > 0 ? (
                      <div className="space-y-2">
                        {Object.entries(stats.tacticDistribution)
                          .sort(([, a], [, b]) => (b as number) - (a as number))
                          .map(([tactic, count]) => {
                            const max = Math.max(...Object.values(stats.tacticDistribution).map(Number));
                            const pct = max > 0 ? ((count as number) / max) * 100 : 0;
                            return (
                              <div key={tactic} className="flex items-center gap-3">
                                <span className="text-xs text-muted-foreground w-36 truncate">{tactic}</span>
                                <div className="flex-1 h-5 bg-background/50 rounded-full overflow-hidden">
                                  <div
                                    className="h-full bg-red-500/40 rounded-full transition-all"
                                    style={{ width: `${pct}%` }}
                                  />
                                </div>
                                <span className="text-xs font-mono text-foreground w-8 text-right">{count as number}</span>
                              </div>
                            );
                          })}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground text-center py-8">No data yet</p>
                    )}
                  </CardContent>
                </Card>

                {/* Platform Distribution */}
                <Card className="bg-card border-border/50">
                  <CardHeader>
                    <CardTitle className="text-sm font-semibold">Tests by Platform</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {stats?.platformDistribution && Object.keys(stats.platformDistribution).length > 0 ? (
                      <div className="space-y-3">
                        {Object.entries(stats.platformDistribution)
                          .sort(([, a], [, b]) => (b as number) - (a as number))
                          .map(([platform, count]) => {
                            const Icon = PLATFORM_ICONS[platform] || Cpu;
                            const total = stats.totalTests || 1;
                            const pct = ((count as number) / total) * 100;
                            return (
                              <div key={platform} className="flex items-center gap-3">
                                <Icon className="h-5 w-5 text-muted-foreground" />
                                <span className="text-sm text-foreground capitalize w-20">{platform}</span>
                                <div className="flex-1 h-6 bg-background/50 rounded-full overflow-hidden">
                                  <div
                                    className="h-full bg-cyan-500/40 rounded-full flex items-center justify-end pr-2 transition-all"
                                    style={{ width: `${Math.max(pct, 10)}%` }}
                                  >
                                    <span className="text-[10px] font-mono text-cyan-300">{pct.toFixed(0)}%</span>
                                  </div>
                                </div>
                                <span className="text-sm font-mono text-foreground w-10 text-right">{count as number}</span>
                              </div>
                            );
                          })}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground text-center py-8">No data yet</p>
                    )}
                  </CardContent>
                </Card>

                {/* Executor Distribution */}
                <Card className="bg-card border-border/50">
                  <CardHeader>
                    <CardTitle className="text-sm font-semibold">Tests by Executor Type</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {stats?.executorDistribution && Object.keys(stats.executorDistribution).length > 0 ? (
                      <div className="space-y-2">
                        {Object.entries(stats.executorDistribution)
                          .sort(([, a], [, b]) => (b as number) - (a as number))
                          .map(([executor, count]) => (
                            <div key={executor} className="flex items-center justify-between p-2 rounded bg-background/50 border border-border/30">
                              <div className="flex items-center gap-2">
                                <Terminal className="h-4 w-4 text-muted-foreground" />
                                <span className="text-sm text-foreground">{executor}</span>
                              </div>
                              <Badge variant="outline" className="font-mono">{count as number}</Badge>
                            </div>
                          ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground text-center py-8">No data yet</p>
                    )}
                  </CardContent>
                </Card>

                {/* Recent Executions */}
                <Card className="bg-card border-border/50">
                  <CardHeader>
                    <CardTitle className="text-sm font-semibold">Recent Executions</CardTitle>
                  </CardHeader>
                  <CardContent>
                    {stats?.recentExecutions && stats.recentExecutions.length > 0 ? (
                      <div className="space-y-2">
                        {stats.recentExecutions.map((exec: any) => (
                          <div key={exec.id} className="flex items-center justify-between p-2 rounded bg-background/50 border border-border/30">
                            <div className="flex items-center gap-2 min-w-0">
                              <StatusIcon status={exec.status} />
                              <code className="text-xs font-mono text-primary">{exec.techniqueId}</code>
                              <span className="text-xs text-foreground truncate">{exec.testName}</span>
                            </div>
                            <Badge variant="outline" className={getStatusColor(exec.status)}>{exec.status}</Badge>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground text-center py-8">No executions yet</p>
                    )}
                  </CardContent>
                </Card>
              </div>
            </TabsContent>
          </Tabs>

          {/* ─── Test Detail Dialog ──────────────────────────────────────── */}
          {selectedTest && !showExecuteDialog && (
            <Dialog open={!!selectedTest} onOpenChange={() => setSelectedTest(null)}>
              <DialogContent className="max-w-2xl bg-card border-border/50 max-h-[80vh] overflow-y-auto">
                <DialogHeader>
                  <div className="flex items-center gap-2">
                    <code className="text-sm font-mono text-primary">{selectedTest.techniqueId}</code>
                    <Badge className={TACTIC_COLORS[selectedTest.mitreTactic] || "bg-muted"}>
                      {selectedTest.mitreTactic}
                    </Badge>
                  </div>
                  <DialogTitle className="text-lg">{selectedTest.testName}</DialogTitle>
                  <DialogDescription>{selectedTest.techniqueName}</DialogDescription>
                </DialogHeader>
                <div className="space-y-4">
                  {selectedTest.description && (
                    <div>
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-1">Description</h4>
                      <p className="text-sm text-foreground">{selectedTest.description}</p>
                    </div>
                  )}
                  <div className="flex gap-4">
                    <div>
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-1">Platforms</h4>
                      <div className="flex gap-1">
                        {(selectedTest.supportedPlatforms || "").split(",").filter(Boolean).map((p: string) => (
                          <Badge key={p} variant="outline" className="text-xs capitalize">{p}</Badge>
                        ))}
                      </div>
                    </div>
                    <div>
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-1">Executor</h4>
                      <Badge variant="outline" className="text-xs">{selectedTest.executorType}</Badge>
                    </div>
                    {selectedTest.elevationRequired && (
                      <div>
                        <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-1">Elevation</h4>
                        <Badge className="bg-amber-500/20 text-amber-400 border-amber-500/30 text-xs">Required</Badge>
                      </div>
                    )}
                  </div>
                  {selectedTest.executorCommand && (
                    <div>
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-1">Command</h4>
                      <pre className="p-3 rounded-lg bg-background border border-border/30 text-xs font-mono text-foreground whitespace-pre-wrap overflow-x-auto max-h-40">
                        {selectedTest.executorCommand}
                      </pre>
                    </div>
                  )}
                  {selectedTest.cleanupCommand && (
                    <div>
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-1">Cleanup Command</h4>
                      <pre className="p-3 rounded-lg bg-background border border-border/30 text-xs font-mono text-yellow-400 whitespace-pre-wrap overflow-x-auto max-h-32">
                        {selectedTest.cleanupCommand}
                      </pre>
                    </div>
                  )}
                  {selectedTest.inputArguments && (
                    <div>
                      <h4 className="text-xs font-semibold text-muted-foreground uppercase mb-1">Input Arguments</h4>
                      <div className="space-y-1">
                        {Object.entries(JSON.parse(selectedTest.inputArguments)).map(([key, val]: [string, any]) => (
                          <div key={key} className="flex items-center gap-2 p-2 rounded bg-background/50 border border-border/30">
                            <code className="text-xs font-mono text-primary">{key}</code>
                            <span className="text-xs text-muted-foreground">({val.type})</span>
                            <ArrowRight className="h-3 w-3 text-muted-foreground" />
                            <span className="text-xs text-foreground">{val.description}</span>
                            {val.default && <code className="text-xs font-mono text-muted-foreground ml-auto">default: {String(val.default)}</code>}
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
                <DialogFooter>
                  <Button variant="outline" onClick={() => setSelectedTest(null)}>Close</Button>
                  <Button
                    className="bg-red-600 hover:bg-red-700 text-white"
                    onClick={() => setShowExecuteDialog(true)}
                  >
                    <Play className="h-4 w-4 mr-1" /> Execute Test
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          )}

          {/* ─── Execute Dialog ──────────────────────────────────────────── */}
          {showExecuteDialog && selectedTest && (
            <Dialog open={showExecuteDialog} onOpenChange={() => setShowExecuteDialog(false)}>
              <DialogContent className="bg-card border-border/50">
                <DialogHeader>
                  <DialogTitle>Execute Atomic Test</DialogTitle>
                  <DialogDescription>
                    <code className="text-primary">{selectedTest.techniqueId}</code> — {selectedTest.testName}
                  </DialogDescription>
                </DialogHeader>
                <div className="space-y-4">
                  <div>
                    <label className="text-sm font-medium text-foreground">Target Host</label>
                    <Input
                      placeholder="e.g., 192.168.1.100 or hostname"
                      value={targetHost}
                      onChange={e => setTargetHost(e.target.value)}
                      className="mt-1 bg-background border-border/50"
                    />
                  </div>
                  <div>
                    <label className="text-sm font-medium text-foreground">Target Platform</label>
                    <Select value={targetPlatform} onValueChange={setTargetPlatform}>
                      <SelectTrigger className="mt-1 bg-background border-border/50">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        <SelectItem value="windows">Windows</SelectItem>
                        <SelectItem value="linux">Linux</SelectItem>
                        <SelectItem value="macos">macOS</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  {selectedTest.elevationRequired && (
                    <div className="flex items-center gap-2 p-3 rounded-lg bg-amber-500/10 border border-amber-500/30">
                      <AlertTriangle className="h-4 w-4 text-amber-400" />
                      <span className="text-sm text-amber-400">This test requires elevated privileges</span>
                    </div>
                  )}
                  {selectedTest.executorCommand && (
                    <div>
                      <label className="text-sm font-medium text-foreground">Command Preview</label>
                      <pre className="mt-1 p-3 rounded-lg bg-background border border-border/30 text-xs font-mono text-foreground whitespace-pre-wrap max-h-32 overflow-auto">
                        {selectedTest.executorCommand}
                      </pre>
                    </div>
                  )}
                </div>
                <DialogFooter>
                  <Button variant="outline" onClick={() => setShowExecuteDialog(false)}>Cancel</Button>
                  <Button
                    className="bg-red-600 hover:bg-red-700 text-white"
                    onClick={handleExecute}
                    disabled={executeMutation.isPending}
                  >
                    {executeMutation.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Zap className="h-4 w-4 mr-1" />}
                    Queue Execution
                  </Button>
                </DialogFooter>
              </DialogContent>
            </Dialog>
          )}
        </div>
      </div>
    </AppShell>
  );
}

// ─── Sub-Components ──────────────────────────────────────────────────────────

function StatCard({ label, value, icon, color }: { label: string; value: number; icon: React.ReactNode; color: string }) {
  return (
    <Card className="bg-card border-border/50">
      <CardContent className="p-4 flex items-center gap-3">
        <div className={`${color}`}>{icon}</div>
        <div>
          <p className="text-2xl font-bold text-foreground font-mono">{value.toLocaleString()}</p>
          <p className="text-xs text-muted-foreground">{label}</p>
        </div>
      </CardContent>
    </Card>
  );
}

function TestCard({ test, onView, onExecute }: { test: any; onView: () => void; onExecute: () => void }) {
  const platforms = (test.supportedPlatforms || "").split(",").filter(Boolean);
  return (
    <Card className="bg-card border-border/50 hover:border-border transition-colors">
      <CardContent className="p-4">
        <div className="flex items-start justify-between gap-4">
          <div className="min-w-0 flex-1">
            <div className="flex items-center gap-2 flex-wrap">
              <code className="text-xs font-mono text-primary">{test.techniqueId}</code>
              <Badge className={`text-[10px] ${TACTIC_COLORS[test.mitreTactic] || "bg-muted text-muted-foreground"}`}>
                {test.mitreTactic}
              </Badge>
              {test.elevationRequired && (
                <Badge className="bg-amber-500/20 text-amber-400 border-amber-500/30 text-[10px]">ELEVATED</Badge>
              )}
              <div className="flex gap-1">
                {platforms.map((p: string) => {
                  const Icon = PLATFORM_ICONS[p] || Cpu;
                  return <Icon key={p} className="h-3 w-3 text-muted-foreground" />;
                })}
              </div>
            </div>
            <h3 className="text-sm font-semibold text-foreground mt-1">{test.testName}</h3>
            {test.description && (
              <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{test.description}</p>
            )}
            <div className="flex items-center gap-2 mt-2">
              <Badge variant="outline" className="text-[10px]">
                <Terminal className="h-3 w-3 mr-1" /> {test.executorType}
              </Badge>
              <span className="text-[10px] text-muted-foreground font-mono">{test.guid.slice(0, 12)}...</span>
            </div>
          </div>
          <div className="flex gap-1 shrink-0">
            <Button variant="ghost" size="sm" onClick={onView} className="h-8 w-8 p-0">
              <Eye className="h-4 w-4" />
            </Button>
            <Button variant="ghost" size="sm" onClick={onExecute} className="h-8 w-8 p-0 text-red-400 hover:text-red-300">
              <Play className="h-4 w-4" />
            </Button>
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case "success": return <CheckCircle2 className="h-4 w-4 text-green-400" />;
    case "failed": return <XCircle className="h-4 w-4 text-red-400" />;
    case "running": return <Loader2 className="h-4 w-4 text-blue-400 animate-spin" />;
    case "queued": return <Clock className="h-4 w-4 text-yellow-400" />;
    case "blocked": return <AlertTriangle className="h-4 w-4 text-orange-400" />;
    case "cleanup": return <RefreshCw className="h-4 w-4 text-purple-400" />;
    default: return <Crosshair className="h-4 w-4 text-muted-foreground" />;
  }
}

function getStatusColor(status: string): string {
  switch (status) {
    case "success": return "border-green-500/30 text-green-400";
    case "failed": return "border-red-500/30 text-red-400";
    case "running": return "border-blue-500/30 text-blue-400";
    case "queued": return "border-yellow-500/30 text-yellow-400";
    case "blocked": return "border-orange-500/30 text-orange-400";
    case "cleanup": return "border-purple-500/30 text-purple-400";
    default: return "border-border text-muted-foreground";
  }
}
