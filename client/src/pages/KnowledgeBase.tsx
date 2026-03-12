import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import {
  LineChart, Line, XAxis, YAxis, CartesianGrid, Tooltip,
  Legend, ResponsiveContainer, BarChart, Bar, Cell,
} from "recharts";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Skeleton } from "@/components/ui/skeleton";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import {
  Library,
  Brain,
  Shield,
  Target,
  Eye,
  ChevronRight,
  Layers,
  ArrowRight,
  FileText,
  Cpu,
  Globe2,
  Search,
  ShieldAlert,
  Zap,
  Network,
  Copy,
  Check,
  TrendingUp,
  TrendingDown,
  Minus,
  BarChart3,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Filter,
} from "lucide-react";
import { toast } from "sonner";

// ─── Category Colors ────────────────────────────────────────────────────────

const CATEGORY_CONFIG: Record<string, { color: string; bg: string; icon: React.ElementType; label: string }> = {
  offensive: { color: "text-red-400", bg: "bg-red-500/10 border-red-500/20", icon: Target, label: "Offensive" },
  social_engineering: { color: "text-amber-400", bg: "bg-amber-500/10 border-amber-500/20", icon: Brain, label: "Social Engineering" },
  recon: { color: "text-blue-400", bg: "bg-blue-500/10 border-blue-500/20", icon: Search, label: "Recon" },
  evasion: { color: "text-purple-400", bg: "bg-purple-500/10 border-purple-500/20", icon: ShieldAlert, label: "Evasion" },
  web_app_testing: { color: "text-emerald-400", bg: "bg-emerald-500/10 border-emerald-500/20", icon: Globe2, label: "Web App Testing" },
  payloads: { color: "text-orange-400", bg: "bg-orange-500/10 border-orange-500/20", icon: Zap, label: "Payloads" },
};

const PHASE_CONFIG: Record<string, { color: string; icon: React.ElementType; label: string }> = {
  recon: { color: "text-blue-400", icon: Search, label: "Recon" },
  enumeration: { color: "text-cyan-400", icon: Globe2, label: "Enumeration" },
  vuln_detection: { color: "text-yellow-400", icon: Eye, label: "Vuln Detection" },
  exploitation: { color: "text-red-400", icon: Zap, label: "Exploitation" },
  post_exploitation: { color: "text-purple-400", icon: Network, label: "Post-Exploit" },
  post_exploit: { color: "text-purple-400", icon: Network, label: "Post-Exploit" },
  reporting: { color: "text-gray-400", icon: FileText, label: "Reporting" },
};

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function KnowledgeBase() {
  const [activeTab, setActiveTab] = useState("modules");
  const [selectedModuleId, setSelectedModuleId] = useState<string | null>(null);
  const [previewPlatform, setPreviewPlatform] = useState<"windows" | "linux" | "macos">("linux");
  const [previewPhase, setPreviewPhase] = useState<"recon" | "enumeration" | "vuln_detection" | "exploitation" | "post_exploitation" | "reporting">("exploitation");
  const [copiedId, setCopiedId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState("");
  const [categoryFilter, setCategoryFilter] = useState<string>("all");
  const [phaseFilter, setPhaseFilter] = useState<string>("all");

  const { data: modules, isLoading: modulesLoading } = trpc.knowledgeBase.listModules.useQuery();
  const { data: stats, isLoading: statsLoading } = trpc.knowledgeBase.getStats.useQuery();
  const { data: phaseMapping } = trpc.knowledgeBase.getPhaseMapping.useQuery();

  const { data: modulePreview, isLoading: previewLoading } = trpc.knowledgeBase.previewContext.useQuery(
    { moduleId: selectedModuleId!, platform: previewPlatform },
    { enabled: !!selectedModuleId }
  );

  const { data: phasePreview, isLoading: phasePreviewLoading } = trpc.knowledgeBase.previewPhaseContext.useQuery(
    {
      phase: previewPhase,
      platform: previewPlatform,
      hasFirewall: true,
      hasWAF: true,
      hasFileUpload: true,
      includePhishing: true,
    },
    { enabled: activeTab === "phases" }
  );

  // Accuracy feedback data
  const { data: accuracySummary } = trpc.accuracyFeedback.summary.useQuery(undefined, {
    enabled: activeTab === "accuracy",
  });
  const { data: accuracyHistory } = trpc.accuracyFeedback.history.useQuery({ limit: 50 }, {
    enabled: activeTab === "accuracy",
  });
  const { data: latestPerTarget } = trpc.accuracyFeedback.latestPerTarget.useQuery(undefined, {
    enabled: activeTab === "accuracy",
  });
  const { data: aggregateVulnAccuracy } = trpc.accuracyFeedback.aggregateVulnAccuracy.useQuery({}, {
    enabled: activeTab === "accuracy",
  });

  // ─── Chart Data Computation ──────────────────────────────────────────────
  const TARGET_COLORS: Record<string, string> = {
    dvwa: "#f87171",
    "juice-shop": "#60a5fa",
    bwapp: "#34d399",
    crapi: "#fbbf24",
    mutillidae: "#a78bfa",
    "broken-crystals": "#f472b6",
  };

  const trendChartData = useMemo(() => {
    if (!accuracyHistory || accuracyHistory.length === 0) return [];
    // Group by target, sort by time, and create a unified timeline
    const byTarget: Record<string, any[]> = {};
    for (const row of [...accuracyHistory].reverse()) {
      const target = row.target_preset || row.targetPreset;
      if (!byTarget[target]) byTarget[target] = [];
      byTarget[target].push(row);
    }
    // Build per-target series with wave labels
    const targets = Object.keys(byTarget);
    const maxWaves = Math.max(...targets.map(t => byTarget[t].length));
    const data: any[] = [];
    for (let i = 0; i < maxWaves; i++) {
      const point: any = { wave: `Wave ${i + 1}` };
      for (const target of targets) {
        const row = byTarget[target]?.[i];
        if (row) {
          point[`${target}_f1`] = Number(((row.f1_score ?? row.f1Score ?? 0) * 100).toFixed(1));
          point[`${target}_p`] = Number(((row.precision ?? 0) * 100).toFixed(1));
          point[`${target}_r`] = Number(((row.recall ?? 0) * 100).toFixed(1));
        }
      }
      data.push(point);
    }
    return data;
  }, [accuracyHistory]);

  const trendTargets = useMemo(() => {
    if (!accuracyHistory) return [];
    const seen = new Set<string>();
    for (const row of accuracyHistory) {
      seen.add(row.target_preset || row.targetPreset);
    }
    return Array.from(seen);
  }, [accuracyHistory]);

  const vulnBarData = useMemo(() => {
    if (!aggregateVulnAccuracy || aggregateVulnAccuracy.length === 0) return [];
    return aggregateVulnAccuracy.map((row: any) => ({
      name: (row.vuln_type || row.vulnType || "").replace(/ /g, "\n").slice(0, 25),
      fullName: row.vuln_type || row.vulnType,
      detection: Number(((row.avg_detection_rate ?? row.avgDetectionRate ?? 0) * 100).toFixed(1)),
      fp: Number(((row.avg_false_positive_rate ?? row.avgFalsePositiveRate ?? 0) * 100).toFixed(1)),
      found: Number(row.total_found ?? row.totalFound ?? 0),
      missed: Number(row.total_missed ?? row.totalMissed ?? 0),
    }));
  }, [aggregateVulnAccuracy]);

  // Filtered modules
  const filteredModules = useMemo(() => {
    if (!modules) return [];
    return modules.filter(mod => {
      const matchesSearch = !searchQuery ||
        mod.name.toLowerCase().includes(searchQuery.toLowerCase()) ||
        mod.description.toLowerCase().includes(searchQuery.toLowerCase()) ||
        mod.mitreTechniques.some(t => t.toLowerCase().includes(searchQuery.toLowerCase()));
      const matchesCategory = categoryFilter === "all" || mod.category === categoryFilter;
      const matchesPhase = phaseFilter === "all" || mod.phases.includes(phaseFilter);
      return matchesSearch && matchesCategory && matchesPhase;
    });
  }, [modules, searchQuery, categoryFilter, phaseFilter]);

  const handleCopyContext = async (text: string, id: string) => {
    await navigator.clipboard.writeText(text);
    setCopiedId(id);
    toast.success("Copied to clipboard");
    setTimeout(() => setCopiedId(null), 2000);
  };

  return (
    <div className="min-h-screen bg-background">
      <div className="container max-w-7xl py-8 space-y-8">
        {/* Header */}
        <div className="space-y-2">
          <div className="flex items-center gap-3">
            <div className="p-2.5 rounded-xl bg-gradient-to-br from-violet-500/20 to-indigo-500/20 border border-violet-500/30">
              <Library className="h-6 w-6 text-violet-400" />
            </div>
            <div>
              <h1 className="text-2xl font-bold tracking-tight">Knowledge Base Explorer</h1>
              <p className="text-muted-foreground text-sm">
                Browse, search, and analyze the offensive security knowledge modules that power the LLM engagement pipeline. Each module injects specialized context into LLM prompts during scan phases.
              </p>
            </div>
          </div>
        </div>

        {/* Stats Cards */}
        {statsLoading ? (
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            {[1, 2, 3, 4, 5].map(i => <Skeleton key={i} className="h-24 rounded-xl" />)}
          </div>
        ) : stats ? (
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
            <StatCard label="Knowledge Modules" value={stats.totalModules} icon={Layers} color="text-violet-400" />
            <StatCard label="Total Items" value={stats.totalItems.toLocaleString()} icon={FileText} color="text-blue-400" />
            <StatCard label="MITRE Techniques" value={stats.totalMitreTechniques} icon={Shield} color="text-red-400" />
            <StatCard label="Injection Points" value={stats.totalInjectionPoints} icon={Cpu} color="text-emerald-400" />
            <StatCard
              label="Accuracy (F1)"
              value={accuracySummary ? `${(accuracySummary.avgF1 * 100).toFixed(1)}%` : "—"}
              icon={BarChart3}
              color="text-amber-400"
              trend={accuracySummary?.f1Trend}
            />
          </div>
        ) : null}

        {/* Main Tabs */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="bg-muted/50 border border-border">
            <TabsTrigger value="modules">Modules</TabsTrigger>
            <TabsTrigger value="phases">Phase Mapping</TabsTrigger>
            <TabsTrigger value="preview">Context Preview</TabsTrigger>
            <TabsTrigger value="accuracy">Accuracy Feedback</TabsTrigger>
          </TabsList>

          {/* ── Modules Tab ── */}
          <TabsContent value="modules" className="mt-6 space-y-4">
            {/* Search & Filter Bar */}
            <div className="flex flex-col sm:flex-row gap-3">
              <div className="relative flex-1">
                <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
                <Input
                  placeholder="Search modules, MITRE techniques, descriptions..."
                  value={searchQuery}
                  onChange={(e) => setSearchQuery(e.target.value)}
                  className="pl-9"
                />
              </div>
              <Select value={categoryFilter} onValueChange={setCategoryFilter}>
                <SelectTrigger className="w-48">
                  <Filter className="h-3.5 w-3.5 mr-2 text-muted-foreground" />
                  <SelectValue placeholder="Category" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Categories</SelectItem>
                  {Object.entries(CATEGORY_CONFIG).map(([key, cfg]) => (
                    <SelectItem key={key} value={key}>{cfg.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <Select value={phaseFilter} onValueChange={setPhaseFilter}>
                <SelectTrigger className="w-48">
                  <Layers className="h-3.5 w-3.5 mr-2 text-muted-foreground" />
                  <SelectValue placeholder="Phase" />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Phases</SelectItem>
                  {Object.entries(PHASE_CONFIG).map(([key, cfg]) => (
                    <SelectItem key={key} value={key}>{cfg.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>

            {/* Results count */}
            <div className="text-xs text-muted-foreground">
              {filteredModules.length} of {modules?.length || 0} modules
              {searchQuery && ` matching "${searchQuery}"`}
            </div>

            {modulesLoading ? (
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {[1, 2, 3, 4, 5, 6].map(i => <Skeleton key={i} className="h-48 rounded-xl" />)}
              </div>
            ) : filteredModules.length > 0 ? (
              <div className="grid gap-4 md:grid-cols-2 lg:grid-cols-3">
                {filteredModules.map(mod => (
                  <ModuleCard
                    key={mod.id}
                    module={mod}
                    isSelected={selectedModuleId === mod.id}
                    onSelect={() => {
                      setSelectedModuleId(mod.id);
                      setActiveTab("preview");
                    }}
                    searchQuery={searchQuery}
                  />
                ))}
              </div>
            ) : (
              <Card className="border-dashed border-2 border-muted-foreground/20">
                <CardContent className="py-16 text-center">
                  <Search className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
                  <p className="text-muted-foreground">No modules match your search criteria</p>
                  <Button variant="ghost" size="sm" className="mt-2" onClick={() => { setSearchQuery(""); setCategoryFilter("all"); setPhaseFilter("all"); }}>
                    Clear filters
                  </Button>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* ── Phase Mapping Tab ── */}
          <TabsContent value="phases" className="mt-6 space-y-6">
            <div className="flex items-center gap-4 mb-4">
              <Select value={previewPlatform} onValueChange={(v: any) => setPreviewPlatform(v)}>
                <SelectTrigger className="w-40">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="windows">Windows</SelectItem>
                  <SelectItem value="linux">Linux</SelectItem>
                  <SelectItem value="macos">macOS</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {/* Phase Flow Visualization */}
            <div className="space-y-3">
              {phaseMapping?.map((pm, idx) => {
                const config = PHASE_CONFIG[pm.phase] || { color: "text-gray-400", icon: FileText, label: pm.phase };
                const PhaseIcon = config.icon;
                const isActive = previewPhase === pm.phase;

                return (
                  <div key={pm.phase}>
                    <Card
                      className={`cursor-pointer transition-all duration-200 hover:border-primary/40 ${isActive ? "border-primary/60 bg-primary/5" : "border-border"}`}
                      onClick={() => setPreviewPhase(pm.phase as any)}
                    >
                      <CardContent className="py-4 px-5">
                        <div className="flex items-start gap-4">
                          <div className={`p-2 rounded-lg bg-muted/50 ${config.color}`}>
                            <PhaseIcon className="h-5 w-5" />
                          </div>
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2 mb-1">
                              <span className="font-semibold text-sm uppercase tracking-wider">
                                {pm.phase.replace(/_/g, " ")}
                              </span>
                              <Badge variant="outline" className="text-xs">
                                {pm.modules.length} modules
                              </Badge>
                            </div>
                            <p className="text-xs text-muted-foreground mb-2">{pm.description}</p>
                            <div className="flex flex-wrap gap-1.5">
                              {pm.modules.map(modId => {
                                const mod = modules?.find(m => m.id === modId);
                                const cat = mod?.category || "offensive";
                                const catConfig = CATEGORY_CONFIG[cat] || CATEGORY_CONFIG.offensive;
                                return (
                                  <Badge
                                    key={modId}
                                    variant="outline"
                                    className={`text-[10px] ${catConfig.bg} ${catConfig.color} border cursor-pointer hover:opacity-80`}
                                    onClick={(e) => {
                                      e.stopPropagation();
                                      setSelectedModuleId(modId);
                                      setActiveTab("preview");
                                    }}
                                  >
                                    {modId.replace(/-/g, " ")}
                                  </Badge>
                                );
                              })}
                            </div>
                          </div>
                          <ChevronRight className={`h-4 w-4 text-muted-foreground transition-transform ${isActive ? "rotate-90" : ""}`} />
                        </div>
                      </CardContent>
                    </Card>

                    {/* Phase Context Preview */}
                    {isActive && (
                      <Card className="mt-2 border-primary/30 bg-muted/30">
                        <CardContent className="py-4 px-5">
                          <div className="flex items-center justify-between mb-3">
                            <span className="text-xs font-medium text-muted-foreground">
                              Composite Context for {pm.phase.replace(/_/g, " ").toUpperCase()}
                            </span>
                            {phasePreview && (
                              <div className="flex items-center gap-3">
                                <span className="text-xs text-muted-foreground">
                                  {phasePreview.charCount.toLocaleString()} chars / ~{phasePreview.estimatedTokens.toLocaleString()} tokens
                                </span>
                                <Button
                                  size="sm"
                                  variant="ghost"
                                  className="h-7 px-2"
                                  onClick={() => handleCopyContext(phasePreview.context, pm.phase)}
                                >
                                  {copiedId === pm.phase ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
                                </Button>
                              </div>
                            )}
                          </div>
                          {phasePreviewLoading ? (
                            <Skeleton className="h-32 rounded-lg" />
                          ) : phasePreview ? (
                            <ScrollArea className="h-64 rounded-lg bg-background/50 border border-border">
                              <pre className="p-4 text-xs text-muted-foreground whitespace-pre-wrap font-mono leading-relaxed">
                                {phasePreview.context || "No context generated for this phase with current settings."}
                              </pre>
                            </ScrollArea>
                          ) : null}
                        </CardContent>
                      </Card>
                    )}

                    {/* Arrow between phases */}
                    {idx < (phaseMapping?.length || 0) - 1 && (
                      <div className="flex justify-center py-1">
                        <ArrowRight className="h-4 w-4 text-muted-foreground/40 rotate-90" />
                      </div>
                    )}
                  </div>
                );
              })}
            </div>
          </TabsContent>

          {/* ── Context Preview Tab ── */}
          <TabsContent value="preview" className="mt-6 space-y-4">
            <div className="flex items-center gap-4">
              <Select
                value={selectedModuleId || ""}
                onValueChange={v => setSelectedModuleId(v)}
              >
                <SelectTrigger className="w-72">
                  <SelectValue placeholder="Select a module..." />
                </SelectTrigger>
                <SelectContent>
                  {modules?.map(m => (
                    <SelectItem key={m.id} value={m.id}>
                      {m.name}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>

              <Select value={previewPlatform} onValueChange={(v: any) => setPreviewPlatform(v)}>
                <SelectTrigger className="w-36">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="windows">Windows</SelectItem>
                  <SelectItem value="linux">Linux</SelectItem>
                  <SelectItem value="macos">macOS</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {selectedModuleId ? (
              <Card className="border-border">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-base">
                      {modules?.find(m => m.id === selectedModuleId)?.name || selectedModuleId}
                    </CardTitle>
                    {modulePreview && (
                      <div className="flex items-center gap-3">
                        <Badge variant="outline" className="text-xs">
                          {modulePreview.charCount.toLocaleString()} chars
                        </Badge>
                        <Badge variant="outline" className="text-xs">
                          ~{modulePreview.estimatedTokens.toLocaleString()} tokens
                        </Badge>
                        <Button
                          size="sm"
                          variant="ghost"
                          className="h-7 px-2"
                          onClick={() => handleCopyContext(modulePreview.context, selectedModuleId)}
                        >
                          {copiedId === selectedModuleId ? <Check className="h-3.5 w-3.5 text-green-400" /> : <Copy className="h-3.5 w-3.5" />}
                        </Button>
                      </div>
                    )}
                  </div>
                  <CardDescription className="text-xs">
                    Context output that gets injected into LLM system prompts
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {previewLoading ? (
                    <Skeleton className="h-64 rounded-lg" />
                  ) : modulePreview ? (
                    <ScrollArea className="h-[500px] rounded-lg bg-muted/30 border border-border">
                      <pre className="p-4 text-xs text-muted-foreground whitespace-pre-wrap font-mono leading-relaxed">
                        {modulePreview.context}
                      </pre>
                    </ScrollArea>
                  ) : (
                    <div className="h-64 flex items-center justify-center text-muted-foreground text-sm">
                      Select a module to preview its context output
                    </div>
                  )}
                </CardContent>
              </Card>
            ) : (
              <Card className="border-dashed border-2 border-muted-foreground/20">
                <CardContent className="py-16 text-center">
                  <Library className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
                  <p className="text-muted-foreground">Select a module to preview its context output</p>
                  <p className="text-xs text-muted-foreground/60 mt-1">
                    Or click "Preview" on any module card in the Modules tab
                  </p>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* ── Accuracy Feedback Tab ── */}
          <TabsContent value="accuracy" className="mt-6 space-y-6">
            <p className="text-sm text-muted-foreground">
              The accuracy feedback loop auto-compares scan findings against ground truth after each training lab scan. It tracks precision, recall, and F1 score over time to measure how effectively the knowledge modules improve vulnerability detection.
            </p>

            {/* Summary Cards */}
            <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
              <Card className="border-border">
                <CardContent className="py-4 px-5">
                  <p className="text-xs text-muted-foreground font-medium">Total Comparisons</p>
                  <p className="text-2xl font-bold mt-1">{accuracySummary?.totalComparisons ?? 0}</p>
                </CardContent>
              </Card>
              <Card className="border-border">
                <CardContent className="py-4 px-5">
                  <p className="text-xs text-muted-foreground font-medium">Avg F1 Score</p>
                  <div className="flex items-center gap-2 mt-1">
                    <p className="text-2xl font-bold">{accuracySummary ? `${(accuracySummary.avgF1 * 100).toFixed(1)}%` : "—"}</p>
                    {accuracySummary?.f1Trend && <TrendIndicator trend={accuracySummary.f1Trend} />}
                  </div>
                </CardContent>
              </Card>
              <Card className="border-border">
                <CardContent className="py-4 px-5">
                  <p className="text-xs text-muted-foreground font-medium">Avg Precision</p>
                  <p className="text-2xl font-bold mt-1">{accuracySummary ? `${(accuracySummary.avgPrecision * 100).toFixed(1)}%` : "—"}</p>
                </CardContent>
              </Card>
              <Card className="border-border">
                <CardContent className="py-4 px-5">
                  <p className="text-xs text-muted-foreground font-medium">Avg Recall</p>
                  <p className="text-2xl font-bold mt-1">{accuracySummary ? `${(accuracySummary.avgRecall * 100).toFixed(1)}%` : "—"}</p>
                </CardContent>
              </Card>
              <Card className="border-border">
                <CardContent className="py-4 px-5">
                  <p className="text-xs text-muted-foreground font-medium">Targets Tested</p>
                  <p className="text-2xl font-bold mt-1">{accuracySummary?.targetCount ?? 0}</p>
                </CardContent>
              </Card>
            </div>

            {/* ── Accuracy Trend Line Charts ── */}
            {trendChartData.length > 0 && (
              <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
                {/* F1 Score Trend */}
                <Card className="border-border">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">F1 Score Trend</CardTitle>
                    <CardDescription className="text-xs">F1 score progression across scan waves per target</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ResponsiveContainer width="100%" height={280}>
                      <LineChart data={trendChartData} margin={{ top: 5, right: 20, left: 0, bottom: 5 }}>
                        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
                        <XAxis dataKey="wave" tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }} />
                        <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }} tickFormatter={(v) => `${v}%`} />
                        <Tooltip
                          contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: "8px", fontSize: 12 }}
                          formatter={(value: number, name: string) => [`${value}%`, name.replace(/_f1$/, "")]}
                        />
                        <Legend wrapperStyle={{ fontSize: 11 }} formatter={(v) => v.replace(/_f1$/, "")} />
                        {trendTargets.map((target) => (
                          <Line
                            key={target}
                            type="monotone"
                            dataKey={`${target}_f1`}
                            stroke={TARGET_COLORS[target] || "#94a3b8"}
                            strokeWidth={2}
                            dot={{ r: 4, fill: TARGET_COLORS[target] || "#94a3b8" }}
                            activeDot={{ r: 6 }}
                            connectNulls
                          />
                        ))}
                      </LineChart>
                    </ResponsiveContainer>
                  </CardContent>
                </Card>

                {/* Precision vs Recall Trend (combined) */}
                <Card className="border-border">
                  <CardHeader className="pb-2">
                    <CardTitle className="text-base">Precision vs Recall</CardTitle>
                    <CardDescription className="text-xs">Average precision and recall across all targets per wave</CardDescription>
                  </CardHeader>
                  <CardContent>
                    <ResponsiveContainer width="100%" height={280}>
                      <LineChart
                        data={trendChartData.map((point: any) => {
                          const pVals: number[] = [];
                          const rVals: number[] = [];
                          for (const key of Object.keys(point)) {
                            if (key.endsWith("_p") && typeof point[key] === "number") pVals.push(point[key]);
                            if (key.endsWith("_r") && typeof point[key] === "number") rVals.push(point[key]);
                          }
                          return {
                            wave: point.wave,
                            precision: pVals.length ? Number((pVals.reduce((a, b) => a + b, 0) / pVals.length).toFixed(1)) : 0,
                            recall: rVals.length ? Number((rVals.reduce((a, b) => a + b, 0) / rVals.length).toFixed(1)) : 0,
                          };
                        })}
                        margin={{ top: 5, right: 20, left: 0, bottom: 5 }}
                      >
                        <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
                        <XAxis dataKey="wave" tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }} />
                        <YAxis domain={[0, 100]} tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }} tickFormatter={(v) => `${v}%`} />
                        <Tooltip
                          contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: "8px", fontSize: 12 }}
                          formatter={(value: number) => [`${value}%`]}
                        />
                        <Legend wrapperStyle={{ fontSize: 11 }} />
                        <Line type="monotone" dataKey="precision" stroke="#60a5fa" strokeWidth={2.5} dot={{ r: 5, fill: "#60a5fa" }} />
                        <Line type="monotone" dataKey="recall" stroke="#f87171" strokeWidth={2.5} dot={{ r: 5, fill: "#f87171" }} />
                      </LineChart>
                    </ResponsiveContainer>
                  </CardContent>
                </Card>
              </div>
            )}

            {/* ── Vuln Type Detection Rate Bar Chart ── */}
            {vulnBarData.length > 0 && (
              <Card className="border-border">
                <CardHeader className="pb-2">
                  <CardTitle className="text-base">Vulnerability Detection Rates</CardTitle>
                  <CardDescription className="text-xs">Average detection rate by vulnerability type across all comparisons</CardDescription>
                </CardHeader>
                <CardContent>
                  <ResponsiveContainer width="100%" height={Math.max(300, vulnBarData.length * 32)}>
                    <BarChart data={vulnBarData} layout="vertical" margin={{ top: 5, right: 30, left: 120, bottom: 5 }}>
                      <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
                      <XAxis type="number" domain={[0, 100]} tick={{ fontSize: 11, fill: "hsl(var(--muted-foreground))" }} tickFormatter={(v) => `${v}%`} />
                      <YAxis type="category" dataKey="fullName" tick={{ fontSize: 10, fill: "hsl(var(--muted-foreground))" }} width={115} />
                      <Tooltip
                        contentStyle={{ backgroundColor: "hsl(var(--card))", border: "1px solid hsl(var(--border))", borderRadius: "8px", fontSize: 12 }}
                        formatter={(value: number, name: string) => [`${value}%`, name === "detection" ? "Detection Rate" : "False Positive Rate"]}
                      />
                      <Legend wrapperStyle={{ fontSize: 11 }} formatter={(v) => v === "detection" ? "Detection Rate" : "False Positive Rate"} />
                      <Bar dataKey="detection" fill="#34d399" radius={[0, 4, 4, 0]} barSize={14}>
                        {vulnBarData.map((_: any, i: number) => (
                          <Cell key={i} fill={vulnBarData[i].detection >= 70 ? "#34d399" : vulnBarData[i].detection >= 40 ? "#fbbf24" : "#f87171"} />
                        ))}
                      </Bar>
                    </BarChart>
                  </ResponsiveContainer>
                </CardContent>
              </Card>
            )}

            {/* Per-Target Latest Accuracy */}
            <Card className="border-border">
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Per-Target Accuracy (Latest)</CardTitle>
                <CardDescription className="text-xs">Most recent accuracy comparison for each training lab target</CardDescription>
              </CardHeader>
              <CardContent>
                {latestPerTarget && latestPerTarget.length > 0 ? (
                  <div className="space-y-3">
                    {latestPerTarget.map((row: any, i: number) => (
                      <div key={i} className="flex items-center gap-4 p-3 rounded-lg bg-muted/30 border border-border">
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2">
                            <span className="font-semibold text-sm">{row.target_preset || row.targetPreset}</span>
                            {(row.f1_delta ?? row.f1Delta) != null && (
                              <DeltaBadge value={row.f1_delta ?? row.f1Delta} />
                            )}
                          </div>
                          <p className="text-xs text-muted-foreground mt-0.5">
                            TP: {row.true_positives ?? row.truePositives} | FP: {row.false_positives ?? row.falsePositives} | FN: {row.false_negatives ?? row.falseNegatives}
                          </p>
                        </div>
                        <div className="text-right space-y-1">
                          <div className="flex items-center gap-3 text-xs">
                            <span className="text-muted-foreground">P</span>
                            <Progress value={((row.precision ?? 0) * 100)} className="w-20 h-1.5" />
                            <span className="w-12 text-right font-mono">{((row.precision ?? 0) * 100).toFixed(1)}%</span>
                          </div>
                          <div className="flex items-center gap-3 text-xs">
                            <span className="text-muted-foreground">R</span>
                            <Progress value={((row.recall ?? 0) * 100)} className="w-20 h-1.5" />
                            <span className="w-12 text-right font-mono">{((row.recall ?? 0) * 100).toFixed(1)}%</span>
                          </div>
                          <div className="flex items-center gap-3 text-xs">
                            <span className="text-muted-foreground">F1</span>
                            <Progress value={((row.f1_score ?? row.f1Score ?? 0) * 100)} className="w-20 h-1.5" />
                            <span className="w-12 text-right font-mono font-semibold">{((row.f1_score ?? row.f1Score ?? 0) * 100).toFixed(1)}%</span>
                          </div>
                        </div>
                      </div>
                    ))}
                  </div>
                ) : (
                  <EmptyState message="No accuracy comparisons yet. Run a training lab scan to generate the first comparison." />
                )}
              </CardContent>
            </Card>

            {/* Vuln Type Accuracy Breakdown */}
            <Card className="border-border">
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Vulnerability Type Accuracy</CardTitle>
                <CardDescription className="text-xs">Aggregate detection rates by vulnerability category across all comparisons</CardDescription>
              </CardHeader>
              <CardContent>
                {aggregateVulnAccuracy && aggregateVulnAccuracy.length > 0 ? (
                  <div className="space-y-2">
                    {aggregateVulnAccuracy.map((row: any, i: number) => {
                      const detRate = Number(row.avg_detection_rate ?? row.avgDetectionRate ?? 0);
                      const fpRate = Number(row.avg_false_positive_rate ?? row.avgFalsePositiveRate ?? 0);
                      const found = Number(row.total_found ?? row.totalFound ?? 0);
                      const missed = Number(row.total_missed ?? row.totalMissed ?? 0);
                      return (
                        <div key={i} className="flex items-center gap-4 p-2.5 rounded-lg hover:bg-muted/20 transition-colors">
                          <div className="flex-1 min-w-0">
                            <span className="text-sm font-medium">{row.vuln_type || row.vulnType}</span>
                            <div className="flex items-center gap-3 mt-0.5 text-[10px] text-muted-foreground">
                              <span className="flex items-center gap-1"><CheckCircle2 className="h-3 w-3 text-green-400" /> {found} found</span>
                              <span className="flex items-center gap-1"><XCircle className="h-3 w-3 text-red-400" /> {missed} missed</span>
                              <span>{row.sample_count ?? row.sampleCount} samples</span>
                            </div>
                          </div>
                          <div className="text-right flex items-center gap-4">
                            <div className="text-xs">
                              <span className="text-muted-foreground">Det:</span>{" "}
                              <span className={`font-mono font-semibold ${detRate >= 0.7 ? "text-green-400" : detRate >= 0.4 ? "text-yellow-400" : "text-red-400"}`}>
                                {(detRate * 100).toFixed(1)}%
                              </span>
                            </div>
                            <div className="text-xs">
                              <span className="text-muted-foreground">FP:</span>{" "}
                              <span className={`font-mono ${fpRate <= 0.1 ? "text-green-400" : fpRate <= 0.3 ? "text-yellow-400" : "text-red-400"}`}>
                                {(fpRate * 100).toFixed(1)}%
                              </span>
                            </div>
                          </div>
                        </div>
                      );
                    })}
                  </div>
                ) : (
                  <EmptyState message="No vuln type accuracy data yet. Data populates after accuracy comparisons run." />
                )}
              </CardContent>
            </Card>

            {/* Recent Comparisons */}
            <Card className="border-border">
              <CardHeader className="pb-3">
                <CardTitle className="text-base">Recent Comparisons</CardTitle>
                <CardDescription className="text-xs">Last 20 accuracy comparisons across all targets</CardDescription>
              </CardHeader>
              <CardContent>
                {accuracyHistory && accuracyHistory.length > 0 ? (
                  <ScrollArea className="h-[400px]">
                    <div className="space-y-2">
                      {accuracyHistory.map((row: any, i: number) => (
                        <div key={i} className="flex items-center gap-4 p-3 rounded-lg bg-muted/20 border border-border/50">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="font-medium text-sm">{row.target_preset || row.targetPreset}</span>
                              <Badge variant="outline" className="text-[10px]">{row.scan_type || row.scanType || "scan"}</Badge>
                            </div>
                            <p className="text-[10px] text-muted-foreground mt-0.5">
                              {new Date(row.scored_at || row.scoredAt).toLocaleString()} | {row.total_findings ?? row.totalFindings} findings vs {row.total_ground_truth ?? row.totalGroundTruth} ground truth
                            </p>
                          </div>
                          <div className="flex items-center gap-4 text-xs font-mono">
                            <div className="text-center">
                              <span className="text-muted-foreground block text-[10px]">F1</span>
                              <span className="font-semibold">{(((row.f1_score ?? row.f1Score) || 0) * 100).toFixed(1)}%</span>
                            </div>
                            <div className="text-center">
                              <span className="text-muted-foreground block text-[10px]">P</span>
                              <span>{(((row.precision) || 0) * 100).toFixed(1)}%</span>
                            </div>
                            <div className="text-center">
                              <span className="text-muted-foreground block text-[10px]">R</span>
                              <span>{(((row.recall) || 0) * 100).toFixed(1)}%</span>
                            </div>
                          </div>
                        </div>
                      ))}
                    </div>
                  </ScrollArea>
                ) : (
                  <EmptyState message="No comparison history yet. Accuracy data will appear here after training lab scans complete." />
                )}
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </div>
  );
}

// ─── Sub-Components ─────────────────────────────────────────────────────────

function StatCard({ label, value, icon: Icon, color, trend }: {
  label: string;
  value: number | string;
  icon: React.ElementType;
  color: string;
  trend?: string;
}) {
  return (
    <Card className="border-border">
      <CardContent className="py-4 px-5">
        <div className="flex items-center justify-between">
          <div>
            <p className="text-xs text-muted-foreground font-medium">{label}</p>
            <div className="flex items-center gap-2 mt-1">
              <p className="text-2xl font-bold">{value}</p>
              {trend && <TrendIndicator trend={trend} />}
            </div>
          </div>
          <div className={`p-2.5 rounded-xl bg-muted/50 ${color}`}>
            <Icon className="h-5 w-5" />
          </div>
        </div>
      </CardContent>
    </Card>
  );
}

function TrendIndicator({ trend }: { trend: string }) {
  if (trend === "improving") return <TrendingUp className="h-4 w-4 text-green-400" />;
  if (trend === "declining") return <TrendingDown className="h-4 w-4 text-red-400" />;
  if (trend === "stable") return <Minus className="h-4 w-4 text-yellow-400" />;
  return null;
}

function DeltaBadge({ value }: { value: number }) {
  const pct = (value * 100).toFixed(1);
  if (value > 0.005) {
    return <Badge className="bg-green-500/10 text-green-400 border-green-500/30 text-[10px]">+{pct}%</Badge>;
  }
  if (value < -0.005) {
    return <Badge className="bg-red-500/10 text-red-400 border-red-500/30 text-[10px]">{pct}%</Badge>;
  }
  return <Badge className="bg-yellow-500/10 text-yellow-400 border-yellow-500/30 text-[10px]">0%</Badge>;
}

function EmptyState({ message }: { message: string }) {
  return (
    <div className="py-12 text-center">
      <AlertTriangle className="h-10 w-10 text-muted-foreground/30 mx-auto mb-3" />
      <p className="text-sm text-muted-foreground">{message}</p>
    </div>
  );
}

function ModuleCard({ module, isSelected, onSelect, searchQuery }: {
  module: any;
  isSelected: boolean;
  onSelect: () => void;
  searchQuery: string;
}) {
  const catConfig = CATEGORY_CONFIG[module.category] || CATEGORY_CONFIG.offensive;
  const CatIcon = catConfig.icon;

  // Highlight matching text
  const highlightMatch = (text: string) => {
    if (!searchQuery) return text;
    const idx = text.toLowerCase().indexOf(searchQuery.toLowerCase());
    if (idx === -1) return text;
    return (
      <>
        {text.slice(0, idx)}
        <mark className="bg-yellow-400/30 text-inherit rounded px-0.5">{text.slice(idx, idx + searchQuery.length)}</mark>
        {text.slice(idx + searchQuery.length)}
      </>
    );
  };

  return (
    <Card
      className={`cursor-pointer transition-all duration-200 hover:border-primary/40 hover:shadow-md ${isSelected ? "border-primary/60 ring-1 ring-primary/30" : "border-border"}`}
      onClick={onSelect}
    >
      <CardContent className="py-5 px-5 space-y-4">
        <div className="flex items-start justify-between">
          <div className={`p-2 rounded-lg ${catConfig.bg} border`}>
            <CatIcon className={`h-4 w-4 ${catConfig.color}`} />
          </div>
          <div className="flex items-center gap-1.5">
            <Badge
              variant="outline"
              className={`text-[10px] ${module.status === "active" ? "text-green-400 border-green-500/30 bg-green-500/10" : module.status === "beta" ? "text-yellow-400 border-yellow-500/30 bg-yellow-500/10" : "text-gray-400 border-gray-500/30 bg-gray-500/10"}`}
            >
              {module.status}
            </Badge>
          </div>
        </div>

        <div>
          <h3 className="font-semibold text-sm leading-tight">{highlightMatch(module.name)}</h3>
          <p className="text-xs text-muted-foreground mt-1 line-clamp-2">{module.description}</p>
        </div>

        <div className="space-y-2">
          <div className="flex items-center gap-2 text-xs text-muted-foreground">
            <FileText className="h-3 w-3" />
            <span>{module.itemCount} items</span>
            <span className="text-muted-foreground/30">|</span>
            <Shield className="h-3 w-3" />
            <span>{module.mitreTechniques.length} MITRE techniques</span>
          </div>

          <div className="flex flex-wrap gap-1">
            {module.phases.slice(0, 4).map((phase: string) => {
              const phaseConfig = PHASE_CONFIG[phase] || { color: "text-gray-400" };
              return (
                <Badge key={phase} variant="outline" className={`text-[10px] ${phaseConfig.color}`}>
                  {phase.replace(/_/g, " ")}
                </Badge>
              );
            })}
            {module.phases.length > 4 && (
              <Badge variant="outline" className="text-[10px]">+{module.phases.length - 4}</Badge>
            )}
          </div>

          <div className="flex items-center gap-1 text-[10px] text-muted-foreground/60">
            <Cpu className="h-3 w-3" />
            <span>Injected into: {module.injectedInto.join(", ")}</span>
          </div>
        </div>

        <Button variant="ghost" size="sm" className="w-full h-8 text-xs">
          Preview Context <ChevronRight className="h-3 w-3 ml-1" />
        </Button>
      </CardContent>
    </Card>
  );
}
