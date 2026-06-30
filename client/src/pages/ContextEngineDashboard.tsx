import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Brain,
  RefreshCw,
  Activity,
  Target,
  TrendingUp,
  Layers,
  Database,
  BarChart3,
  BookOpen,
  Shield,
  Cpu,
  Zap,
  FileText,
  AlertTriangle,
  ChevronDown,
  ChevronRight,
  Clock,
  Hash,
} from "lucide-react";
import AppShell from "@/components/AppShell";

// ─── Category Colors ─────────────────────────────────────────────────────────
const CATEGORY_COLORS: Record<string, { bg: string; text: string; border: string }> = {
  knowledge_store: { bg: "bg-blue-500/10", text: "text-blue-400", border: "border-blue-500/30" },
  learning_engine: { bg: "bg-purple-500/10", text: "text-purple-400", border: "border-purple-500/30" },
  threat_intel: { bg: "bg-red-500/10", text: "text-red-400", border: "border-red-500/30" },
  tools: { bg: "bg-amber-500/10", text: "text-amber-400", border: "border-amber-500/30" },
  dfir: { bg: "bg-emerald-500/10", text: "text-emerald-400", border: "border-emerald-500/30" },
  ioc: { bg: "bg-cyan-500/10", text: "text-cyan-400", border: "border-cyan-500/30" },
  phishing: { bg: "bg-pink-500/10", text: "text-pink-400", border: "border-pink-500/30" },
  c2: { bg: "bg-orange-500/10", text: "text-orange-400", border: "border-orange-500/30" },
};

const CATEGORY_ICONS: Record<string, typeof Brain> = {
  knowledge_store: Database,
  learning_engine: Brain,
  threat_intel: Shield,
  tools: Zap,
  dfir: FileText,
  ioc: Target,
  phishing: AlertTriangle,
  c2: Cpu,
};

function CategoryBadge({ category }: { category: string }) {
  const colors = CATEGORY_COLORS[category] || CATEGORY_COLORS.knowledge_store;
  const Icon = CATEGORY_ICONS[category] || Database;
  return (
    <Badge variant="outline" className={`${colors.bg} ${colors.text} ${colors.border} gap-1`}>
      <Icon className="h-3 w-3" />
      {category.replace(/_/g, " ")}
    </Badge>
  );
}

// ─── Batch Ingest Panel ──────────────────────────────────────────────────────
function BatchIngestPanel() {
  const [maxArticles, setMaxArticles] = useState(50);
  const [selectedCategories, setSelectedCategories] = useState<string[]>([
    "Privilege Escalation",
    "Lateral Movement",
    "Persistence",
    "Credential Dumping",
    "Defense Evasion",
    "Red Teaming",
  ]);

  const stats = trpc.threatEnrichment.getArticleIngestionStats.useQuery();
  const batchIngest = trpc.threatEnrichment.batchIngestArticles.useMutation({
    onSuccess: (data: any) => {
      toast.success(`Ingested ${data.ingested || 0} articles — ${data.playbooks || 0} playbooks created`);
      stats.refetch();
    },
    onError: (err: any) => {
      toast.error(`Ingestion failed: ${err.message}`);
    },
  });

  const PRIORITY_CATEGORIES = [
    "Privilege Escalation",
    "Lateral Movement",
    "Persistence",
    "Credential Dumping",
    "Defense Evasion",
    "Red Teaming",
    "Initial Access",
    "Command and Control",
    "Exfiltration",
    "Impact",
  ];

  const toggleCategory = (cat: string) => {
    setSelectedCategories(prev =>
      prev.includes(cat) ? prev.filter(c => c !== cat) : [...prev, cat]
    );
  };

  return (
    <Card className="border-border/50">
      <CardHeader>
        <CardTitle className="flex items-center gap-2">
          <BookOpen className="h-5 w-5 text-blue-400" />
          Hacking Articles Batch Ingest
        </CardTitle>
        <CardDescription>
          Ingest exploit playbooks from Hacking Articles into the knowledge catalog.
          These feed the context engine during exploit decisions.
        </CardDescription>
      </CardHeader>
      <CardContent className="space-y-4">
        {/* Stats Row */}
        {stats.data && (
          <div className="grid grid-cols-3 gap-3">
            <div className="rounded-lg bg-muted/50 p-3 text-center">
              <div className="text-2xl font-bold text-blue-400">{stats.data.totalPlaybooks}</div>
              <div className="text-xs text-muted-foreground">Playbooks</div>
            </div>
            <div className="rounded-lg bg-muted/50 p-3 text-center">
              <div className="text-2xl font-bold text-emerald-400">{stats.data.totalObservations}</div>
              <div className="text-xs text-muted-foreground">DFIR Observations</div>
            </div>
            <div className="rounded-lg bg-muted/50 p-3 text-center">
              <div className="text-2xl font-bold text-purple-400">{stats.data.totalChains}</div>
              <div className="text-xs text-muted-foreground">Attack Chains</div>
            </div>
          </div>
        )}

        {/* Platform Breakdown */}
        {stats.data && Object.keys(stats.data.byPlatform).length > 0 && (
          <div className="space-y-1">
            <div className="text-xs font-medium text-muted-foreground">By Platform</div>
            <div className="flex flex-wrap gap-2">
              {Object.entries(stats.data.byPlatform).map(([platform, count]) => (
                <Badge key={platform} variant="outline" className="text-xs">
                  {platform}: {count as number}
                </Badge>
              ))}
            </div>
          </div>
        )}

        {/* Category Selection */}
        <div className="space-y-2">
          <div className="text-sm font-medium">Priority Categories</div>
          <div className="flex flex-wrap gap-2">
            {PRIORITY_CATEGORIES.map(cat => (
              <Badge
                key={cat}
                variant={selectedCategories.includes(cat) ? "default" : "outline"}
                className="cursor-pointer transition-colors"
                onClick={() => toggleCategory(cat)}
              >
                {cat}
              </Badge>
            ))}
          </div>
        </div>

        {/* Max Articles */}
        <div className="flex items-center gap-3">
          <label className="text-sm text-muted-foreground whitespace-nowrap">Max Articles:</label>
          <Input
            type="number"
            value={maxArticles}
            onChange={e => setMaxArticles(Number(e.target.value))}
            className="w-24"
            min={1}
            max={200}
          />
        </div>

        {/* Ingest Button */}
        <Button
          onClick={() => batchIngest.mutate({
            categories: selectedCategories,
            maxArticles,
          })}
          disabled={batchIngest.isPending || selectedCategories.length === 0}
          className="w-full"
        >
          {batchIngest.isPending ? (
            <><RefreshCw className="h-4 w-4 mr-2 animate-spin" /> Ingesting...</>
          ) : (
            <><BookOpen className="h-4 w-4 mr-2" /> Ingest {selectedCategories.length} Categories</>
          )}
        </Button>
      </CardContent>
    </Card>
  );
}

// ─── Source Contribution Chart ────────────────────────────────────────────────
function SourceContributionChart({ sources }: { sources: Array<{
  sourceId: string;
  sourceName: string;
  category: string;
  totalContributions: number;
  avgTokens: number;
  activationRate: number;
}> }) {
  const maxTokens = Math.max(...sources.map(s => s.avgTokens), 1);

  return (
    <div className="space-y-2">
      {sources.map(source => {
        const colors = CATEGORY_COLORS[source.category] || CATEGORY_COLORS.knowledge_store;
        return (
          <div key={source.sourceId} className="space-y-1">
            <div className="flex items-center justify-between text-sm">
              <div className="flex items-center gap-2">
                <CategoryBadge category={source.category} />
                <span className="text-foreground/80 truncate max-w-[200px]">{source.sourceName}</span>
              </div>
              <div className="flex items-center gap-3 text-xs text-muted-foreground">
                <span>{source.avgTokens.toLocaleString()} avg tokens</span>
                <span className={source.activationRate >= 80 ? "text-emerald-400" : source.activationRate >= 50 ? "text-amber-400" : "text-red-400"}>
                  {source.activationRate}% active
                </span>
              </div>
            </div>
            <div className="h-2 rounded-full bg-muted/50 overflow-hidden">
              <div
                className={`h-full rounded-full transition-all ${colors.bg.replace('/10', '/60')}`}
                style={{ width: `${Math.round((source.avgTokens / maxTokens) * 100)}%` }}
              />
            </div>
          </div>
        );
      })}
    </div>
  );
}

// ─── Decision Timeline ───────────────────────────────────────────────────────
function DecisionTimeline({ contributions }: { contributions: Array<{
  id: string;
  engagementId: number;
  exploitTarget: string;
  exploitCve: string;
  timestamp: number;
  sources: Array<{ sourceId: string; sourceName: string; category: string; tokensContributed: number; wasActive: boolean }>;
  totalContextLength: number;
  cappedContextLength: number;
  decisionOutcome: string;
}> }) {
  const [expandedId, setExpandedId] = useState<string | null>(null);

  const outcomeColors: Record<string, string> = {
    exploit_attempted: "text-red-400",
    exploit_skipped: "text-amber-400",
    exploit_deferred: "text-blue-400",
  };

  return (
    <div className="space-y-2">
      {contributions.map(c => (
        <div key={c.id} className="border border-border/50 rounded-lg overflow-hidden">
          <button
            className="w-full flex items-center justify-between p-3 hover:bg-muted/30 transition-colors text-left"
            onClick={() => setExpandedId(expandedId === c.id ? null : c.id)}
          >
            <div className="flex items-center gap-3">
              {expandedId === c.id ? <ChevronDown className="h-4 w-4" /> : <ChevronRight className="h-4 w-4" />}
              <div>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-sm">{c.exploitTarget}</span>
                  <Badge variant="outline" className="text-xs">{c.exploitCve}</Badge>
                </div>
                <div className="flex items-center gap-2 text-xs text-muted-foreground mt-0.5">
                  <Clock className="h-3 w-3" />
                  {new Date(c.timestamp).toLocaleString()}
                  <span className="mx-1">|</span>
                  <Hash className="h-3 w-3" />
                  Eng #{c.engagementId}
                </div>
              </div>
            </div>
            <div className="flex items-center gap-3">
              <span className={`text-xs font-medium ${outcomeColors[c.decisionOutcome] || "text-muted-foreground"}`}>
                {c.decisionOutcome.replace(/_/g, " ")}
              </span>
              <Badge variant="outline" className="text-xs">
                {c.sources.filter(s => s.wasActive).length}/{c.sources.length} sources
              </Badge>
            </div>
          </button>

          {expandedId === c.id && (
            <div className="border-t border-border/30 p-3 bg-muted/10 space-y-3">
              {/* Context Size */}
              <div className="flex items-center gap-4 text-xs text-muted-foreground">
                <span>Total context: {(c.totalContextLength / 1024).toFixed(1)}KB</span>
                <span>Capped: {(c.cappedContextLength / 1024).toFixed(1)}KB</span>
                <span>Compression: {c.totalContextLength > 0 ? Math.round((1 - c.cappedContextLength / c.totalContextLength) * 100) : 0}%</span>
              </div>

              {/* Source Breakdown */}
              <div className="space-y-1.5">
                {c.sources
                  .filter(s => s.wasActive)
                  .sort((a, b) => b.tokensContributed - a.tokensContributed)
                  .map(s => (
                    <div key={s.sourceId} className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2">
                        <div className={`w-2 h-2 rounded-full ${s.wasActive ? "bg-emerald-400" : "bg-muted"}`} />
                        <CategoryBadge category={s.category} />
                        <span className="text-foreground/70">{s.sourceName}</span>
                      </div>
                      <span className="text-muted-foreground font-mono">{s.tokensContributed.toLocaleString()} tokens</span>
                    </div>
                  ))}
                {c.sources.filter(s => !s.wasActive).length > 0 && (
                  <div className="text-xs text-muted-foreground/50 pt-1">
                    + {c.sources.filter(s => !s.wasActive).length} inactive sources
                  </div>
                )}
              </div>
            </div>
          )}
        </div>
      ))}

      {contributions.length === 0 && (
        <div className="text-center py-8 text-muted-foreground">
          <Brain className="h-8 w-8 mx-auto mb-2 opacity-50" />
          <p>No context engine decisions recorded yet.</p>
          <p className="text-xs mt-1">Run an engagement to see knowledge source contributions here.</p>
        </div>
      )}
    </div>
  );
}

// ─── Main Page ───────────────────────────────────────────────────────────────
export default function ContextEngineDashboard() {
  const [engagementFilter, setEngagementFilter] = useState<number | undefined>();

  const contextStats = trpc.threatEnrichment.getContextEngineStats.useQuery(undefined, {
    refetchInterval: 15_000,
  });
  const contributions = trpc.threatEnrichment.getContextEngineContributions.useQuery(
    { engagementId: engagementFilter, limit: 50 },
    { refetchInterval: 15_000 }
  );

  const outcomeData = useMemo(() => {
    if (!contextStats.data?.outcomeBreakdown) return [];
    return Object.entries(contextStats.data.outcomeBreakdown).map(([key, value]) => ({
      label: key.replace(/_/g, " "),
      value: value as number,
      color: key === "exploit_attempted" ? "text-red-400" : key === "exploit_skipped" ? "text-amber-400" : "text-blue-400",
    }));
  }, [contextStats.data]);

  return (
    <AppShell>
      <div className="space-y-6 p-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold flex items-center gap-2">
              <Brain className="h-7 w-7 text-purple-400" />
              Context Engine
            </h1>
            <p className="text-muted-foreground mt-1">
              Knowledge source contributions to exploit decisions — what intelligence informed each LLM call.
            </p>
          </div>
          <Button
            variant="outline"
            size="sm"
            onClick={() => {
              contextStats.refetch();
              contributions.refetch();
            }}
          >
            <RefreshCw className="h-4 w-4 mr-2" />
            Refresh
          </Button>
        </div>

        {/* Stats Overview */}
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <Card className="border-border/50">
            <CardContent className="p-4">
              <div className="flex items-center gap-2 text-muted-foreground text-xs mb-1">
                <Activity className="h-3.5 w-3.5" />
                Total Decisions
              </div>
              <div className="text-2xl font-bold">{contextStats.data?.totalDecisions || 0}</div>
            </CardContent>
          </Card>
          <Card className="border-border/50">
            <CardContent className="p-4">
              <div className="flex items-center gap-2 text-muted-foreground text-xs mb-1">
                <Layers className="h-3.5 w-3.5" />
                Active Sources
              </div>
              <div className="text-2xl font-bold">{contextStats.data?.sourceBreakdown?.length || 0}</div>
            </CardContent>
          </Card>
          <Card className="border-border/50">
            <CardContent className="p-4">
              <div className="flex items-center gap-2 text-muted-foreground text-xs mb-1">
                <BarChart3 className="h-3.5 w-3.5" />
                Avg Context
              </div>
              <div className="text-2xl font-bold">
                {contextStats.data?.avgContextLength ? `${(contextStats.data.avgContextLength / 1024).toFixed(1)}KB` : "—"}
              </div>
            </CardContent>
          </Card>
          <Card className="border-border/50">
            <CardContent className="p-4">
              <div className="flex items-center gap-2 text-muted-foreground text-xs mb-1">
                <TrendingUp className="h-3.5 w-3.5" />
                Engagements
              </div>
              <div className="text-2xl font-bold">{contextStats.data?.recentEngagements?.length || 0}</div>
            </CardContent>
          </Card>
        </div>

        {/* Outcome Breakdown */}
        {outcomeData.length > 0 && (
          <Card className="border-border/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Decision Outcomes</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-6">
                {outcomeData.map(o => (
                  <div key={o.label} className="flex items-center gap-2">
                    <span className={`text-2xl font-bold ${o.color}`}>{o.value}</span>
                    <span className="text-xs text-muted-foreground">{o.label}</span>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        )}

        <Tabs defaultValue="sources" className="space-y-4">
          <TabsList>
            <TabsTrigger value="sources">Source Contributions</TabsTrigger>
            <TabsTrigger value="timeline">Decision Timeline</TabsTrigger>
            <TabsTrigger value="ingest">Article Ingest</TabsTrigger>
          </TabsList>

          {/* Source Contributions Tab */}
          <TabsContent value="sources">
            <Card className="border-border/50">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Database className="h-5 w-5 text-blue-400" />
                  Knowledge Source Breakdown
                </CardTitle>
                <CardDescription>
                  Which intelligence sources contributed the most tokens to exploit decisions.
                </CardDescription>
              </CardHeader>
              <CardContent>
                {contextStats.data?.sourceBreakdown && contextStats.data.sourceBreakdown.length > 0 ? (
                  <SourceContributionChart sources={contextStats.data.sourceBreakdown} />
                ) : (
                  <div className="text-center py-8 text-muted-foreground">
                    <Layers className="h-8 w-8 mx-auto mb-2 opacity-50" />
                    <p>No source contribution data yet.</p>
                    <p className="text-xs mt-1">Source data is recorded during engagement exploit phases.</p>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Article Ingestion Stats */}
            {contextStats.data?.articleIngestionStats && (
              <Card className="border-border/50 mt-4">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-base">
                    <BookOpen className="h-5 w-5 text-emerald-400" />
                    Hacking Articles Knowledge Base
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-3 gap-4">
                    <div className="text-center">
                      <div className="text-xl font-bold text-blue-400">
                        {contextStats.data.articleIngestionStats.totalPlaybooks}
                      </div>
                      <div className="text-xs text-muted-foreground">Playbooks</div>
                    </div>
                    <div className="text-center">
                      <div className="text-xl font-bold text-emerald-400">
                        {contextStats.data.articleIngestionStats.totalObservations}
                      </div>
                      <div className="text-xs text-muted-foreground">DFIR Observations</div>
                    </div>
                    <div className="text-center">
                      <div className="text-xl font-bold text-purple-400">
                        {contextStats.data.articleIngestionStats.totalChains}
                      </div>
                      <div className="text-xs text-muted-foreground">Attack Chains</div>
                    </div>
                  </div>

                  {Object.keys(contextStats.data.articleIngestionStats.byDifficulty).length > 0 && (
                    <div className="mt-4 space-y-1">
                      <div className="text-xs font-medium text-muted-foreground">By Difficulty</div>
                      <div className="flex flex-wrap gap-2">
                        {Object.entries(contextStats.data.articleIngestionStats.byDifficulty).map(([diff, count]) => (
                          <Badge key={diff} variant="outline" className="text-xs">
                            {diff}: {count as number}
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* Decision Timeline Tab */}
          <TabsContent value="timeline">
            <Card className="border-border/50">
              <CardHeader>
                <div className="flex items-center justify-between">
                  <div>
                    <CardTitle className="flex items-center gap-2">
                      <Activity className="h-5 w-5 text-purple-400" />
                      Exploit Decision Timeline
                    </CardTitle>
                    <CardDescription>
                      Each entry shows which knowledge sources contributed to an exploit decision.
                    </CardDescription>
                  </div>
                  <div className="flex items-center gap-2">
                    <Input
                      type="number"
                      placeholder="Filter by engagement ID"
                      className="w-48"
                      onChange={e => setEngagementFilter(e.target.value ? Number(e.target.value) : undefined)}
                    />
                  </div>
                </div>
              </CardHeader>
              <CardContent>
                <DecisionTimeline contributions={contributions.data?.contributions || []} />
              </CardContent>
            </Card>
          </TabsContent>

          {/* Article Ingest Tab */}
          <TabsContent value="ingest">
            <div className="grid md:grid-cols-2 gap-4">
              <BatchIngestPanel />

              {/* Recent Engagements */}
              <Card className="border-border/50">
                <CardHeader>
                  <CardTitle className="flex items-center gap-2 text-base">
                    <Target className="h-5 w-5 text-red-400" />
                    Recent Engagements
                  </CardTitle>
                  <CardDescription>
                    Engagements that have recorded context engine decisions.
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  {contextStats.data?.recentEngagements && contextStats.data.recentEngagements.length > 0 ? (
                    <div className="space-y-2">
                      {contextStats.data.recentEngagements.map(eng => (
                        <div
                          key={eng.engagementId}
                          className="flex items-center justify-between p-2 rounded-lg bg-muted/30 hover:bg-muted/50 cursor-pointer transition-colors"
                          onClick={() => setEngagementFilter(eng.engagementId)}
                        >
                          <div className="flex items-center gap-2">
                            <Hash className="h-3.5 w-3.5 text-muted-foreground" />
                            <span className="font-mono text-sm">Engagement #{eng.engagementId}</span>
                          </div>
                          <div className="flex items-center gap-3 text-xs text-muted-foreground">
                            <span>{eng.decisionCount} decisions</span>
                            <span>{new Date(eng.lastDecision).toLocaleDateString()}</span>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <div className="text-center py-6 text-muted-foreground text-sm">
                      No engagement data yet.
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
