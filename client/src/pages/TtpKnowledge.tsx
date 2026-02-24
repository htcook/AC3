import AppShell from "@/components/AppShell";
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import {
  Brain,
  Download,
  Search,
  Shield,
  Zap,
  Eye,
  Target,
  Loader2,
  ChevronRight,
  Database,
  Wrench,
  AlertTriangle,
  CheckCircle2,
  RefreshCw,
  BookOpen,
  Layers,
} from "lucide-react";
import { toast } from "sonner";
import { Link } from "wouter";

import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
// Tactic color mapping
const TACTIC_COLORS: Record<string, string> = {
  "reconnaissance": "bg-blue-500/20 text-blue-300 border-blue-500/30",
  "resource-development": "bg-indigo-500/20 text-indigo-300 border-indigo-500/30",
  "initial-access": "bg-red-500/20 text-red-300 border-red-500/30",
  "execution": "bg-orange-500/20 text-orange-300 border-orange-500/30",
  "persistence": "bg-yellow-500/20 text-yellow-300 border-yellow-500/30",
  "privilege-escalation": "bg-amber-500/20 text-amber-300 border-amber-500/30",
  "defense-evasion": "bg-emerald-500/20 text-emerald-300 border-emerald-500/30",
  "credential-access": "bg-purple-500/20 text-purple-300 border-purple-500/30",
  "discovery": "bg-cyan-500/20 text-cyan-300 border-cyan-500/30",
  "lateral-movement": "bg-pink-500/20 text-pink-300 border-pink-500/30",
  "collection": "bg-teal-500/20 text-teal-300 border-teal-500/30",
  "command-and-control": "bg-rose-500/20 text-rose-300 border-rose-500/30",
  "exfiltration": "bg-fuchsia-500/20 text-fuchsia-300 border-fuchsia-500/30",
  "impact": "bg-red-600/20 text-red-200 border-red-600/30",
};

function getTacticColor(tactic: string) {
  const key = tactic.split(",")[0]?.trim().toLowerCase() || "";
  return TACTIC_COLORS[key] || "bg-zinc-500/20 text-zinc-300 border-zinc-500/30";
}

export default function TtpKnowledge() {
  const [search, setSearch] = useState("");
  const [selectedTactic, setSelectedTactic] = useState<string | undefined>();
  const [page, setPage] = useState(0);
  const [activeTab, setActiveTab] = useState("knowledge");
  const [expandedTech, setExpandedTech] = useState<string | null>(null);

  const stats = trpc.ttpEngine.stats.useQuery();
  const knowledge = trpc.ttpEngine.list.useQuery({
    search: search || undefined,
    tactic: selectedTactic,
    limit: 25,
    offset: page * 25,
  });
  const kaliTools = trpc.ttpEngine.kaliTools.useQuery({});

  const ingestMutation = trpc.ttpEngine.ingest.useMutation({
    onSuccess: (data) => {
      toast.success(`Ingestion complete! ${data.totalTechniquesIngested} techniques ingested.`);
      stats.refetch();
      knowledge.refetch();
    },
    onError: (err) => toast.error(`Ingestion failed: ${sanitizeErrorForToast(err)}`),
  });

  const enrichMutation = trpc.ttpEngine.enrich.useMutation({
    onSuccess: (data) => {
      toast.success(`${data.techniqueId}: ${data.action}`);
      knowledge.refetch();
    },
    onError: (err) => toast.error(`Enrichment failed: ${sanitizeErrorForToast(err)}`),
  });

  const entries = knowledge.data?.entries || [];
  const total = knowledge.data?.total || 0;
  const totalPages = Math.ceil(total / 25);

  // Group offensive tools by category
  const kaliByCategory = useMemo(() => {
    const tools = kaliTools.data || [];
    const grouped = new Map<string, typeof tools>();
    for (const tool of tools) {
      if (!grouped.has(tool.category)) grouped.set(tool.category, []);
      grouped.get(tool.category)!.push(tool);
    }
    return grouped;
  }, [kaliTools.data]);

  const tacticStats = stats.data?.byTactic || [];

  return (
    <AppShell>
    <div className="space-y-6">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-3">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Brain className="h-7 w-7 text-purple-400" />
            TTP Knowledge Base
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Deep understanding of MITRE ATT&CK techniques, tools, IOCs, and detection rules
          </p>
        </div>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => ingestMutation.mutate({})}
            disabled={ingestMutation.isPending}
          >
            {ingestMutation.isPending ? (
              <Loader2 className="h-4 w-4 mr-2 animate-spin" />
            ) : (
              <Download className="h-4 w-4 mr-2" />
            )}
            {ingestMutation.isPending ? "Ingesting..." : "Ingest from GitHub"}
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-2 sm:grid-cols-2 md:grid-cols-4 gap-2 sm:gap-4">
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-purple-500/20">
                <Database className="h-5 w-5 text-purple-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{stats.data?.total || 0}</p>
                <p className="text-xs text-muted-foreground">Techniques</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-green-500/20">
                <Shield className="h-5 w-5 text-green-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{(stats.data as any)?.withDetections || stats.data?.enriched || 0}</p>
                <p className="text-xs text-muted-foreground">With Detections</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-orange-500/20">
                <Wrench className="h-5 w-5 text-orange-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{kaliTools.data?.length || 0}</p>
                <p className="text-xs text-muted-foreground">Offensive Tools</p>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-blue-500/20">
                <Layers className="h-5 w-5 text-blue-400" />
              </div>
              <div>
                <p className="text-2xl font-bold">{tacticStats.length}</p>
                <p className="text-xs text-muted-foreground">Tactics Covered</p>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Ingestion Progress */}
      {ingestMutation.isPending && (
        <Card className="bg-zinc-900/50 border-purple-500/30">
          <CardContent className="p-4">
            <div className="flex items-center gap-3">
              <Loader2 className="h-5 w-5 animate-spin text-purple-400" />
              <div className="flex-1">
                <p className="text-sm font-medium">Ingesting from GitHub repositories...</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Downloading ATT&CK techniques, validation tests, LOLBAS data, exploit modules, and mapping offensive tools
                </p>
                <Progress value={undefined} className="mt-2 h-1" />
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Main Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-zinc-900 border border-zinc-800">
          <TabsTrigger value="knowledge">Technique Knowledge</TabsTrigger>
          <TabsTrigger value="kali">penetration testing tools Tools</TabsTrigger>
          <TabsTrigger value="tactics">Tactic Heatmap</TabsTrigger>
        </TabsList>

        {/* Knowledge Tab */}
        <TabsContent value="knowledge" className="space-y-4">
          {/* Search & Filter */}
          <div className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search techniques (e.g., T1059, PowerShell, credential)..."
                value={search}
                onChange={(e) => { setSearch(e.target.value); setPage(0); }}
                className="pl-10 bg-zinc-900 border-zinc-800"
              />
            </div>
            <select
              value={selectedTactic || ""}
              onChange={(e) => { setSelectedTactic(e.target.value || undefined); setPage(0); }}
              className="bg-zinc-900 border border-zinc-800 rounded-md px-3 text-sm"
            >
              <option value="">All Tactics</option>
              {tacticStats.map((t: any) => (
                <option key={t.tactic} value={t.tactic}>{t.tactic} ({t.count})</option>
              ))}
            </select>
          </div>

          {/* Technique List */}
          <div className="space-y-2">
            {knowledge.isLoading ? (
              <div className="flex items-center justify-center py-12">
                <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
              </div>
            ) : entries.length === 0 ? (
              <Card className="bg-zinc-900/50 border-zinc-800">
                <CardContent className="p-8 text-center">
                  <Brain className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
                  <h3 className="font-semibold mb-2">No techniques in knowledge base</h3>
                  <p className="text-sm text-muted-foreground mb-4">
                    Click "Ingest from GitHub" to download ATT&CK techniques, validation tests, LOLBAS data, and more.
                  </p>
                  <Button onClick={() => ingestMutation.mutate({})} disabled={ingestMutation.isPending}>
                    <Download className="h-4 w-4 mr-2" />
                    Start Ingestion
                  </Button>
                </CardContent>
              </Card>
            ) : (
              entries.map((entry: any) => {
                const isExpanded = expandedTech === entry.techniqueId;
                const tools = (entry.toolsUsed as any[] || []);
                const detections = (entry.detectionRules as any[] || []);
                const iocs = (entry.iocPatterns as any[] || []);
                const execMethods = (entry.executionMethods as any[] || []);

                return (
                  <Card
                    key={entry.techniqueId}
                    className={`bg-zinc-900/50 border-zinc-800 transition-all cursor-pointer hover:border-zinc-700 ${isExpanded ? "border-purple-500/30" : ""}`}
                    onClick={() => setExpandedTech(isExpanded ? null : entry.techniqueId)}
                  >
                    <CardContent className="p-4">
                      {/* Header Row */}
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3 flex-1">
                          <ChevronRight className={`h-4 w-4 transition-transform ${isExpanded ? "rotate-90" : ""}`} />
                          <code className="text-sm font-mono text-purple-400">{entry.techniqueId}</code>
                          <span className="font-medium">{entry.techniqueName}</span>
                          <Badge variant="outline" className={`text-xs ${getTacticColor(entry.tactic)}`}>
                            {entry.tactic?.split(",")[0]?.trim()}
                          </Badge>
                        </div>
                        <div className="flex items-center gap-2">
                          {detections.length > 0 && (
                            <Badge variant="outline" className="bg-green-500/10 text-green-400 border-green-500/30 text-xs">
                              <Shield className="h-3 w-3 mr-1" />{detections.length} rules
                            </Badge>
                          )}
                          {tools.length > 0 && (
                            <Badge variant="outline" className="bg-orange-500/10 text-orange-400 border-orange-500/30 text-xs">
                              <Wrench className="h-3 w-3 mr-1" />{tools.length} tools
                            </Badge>
                          )}
                          {iocs.length > 0 && (
                            <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30 text-xs">
                              <Eye className="h-3 w-3 mr-1" />{iocs.length} IOCs
                            </Badge>
                          )}
                          <Badge variant="outline" className="text-xs">
                            {entry.confidence || 0}% conf
                          </Badge>
                        </div>
                      </div>

                      {/* Expanded Content */}
                      {isExpanded && (
                        <div className="mt-4 space-y-4 border-t border-zinc-800 pt-4" onClick={(e) => e.stopPropagation()}>
                          {/* Description */}
                          <div>
                            <h4 className="text-sm font-semibold text-muted-foreground mb-1">Description</h4>
                            <p className="text-sm leading-relaxed">{entry.description?.substring(0, 500) || "No description available"}</p>
                          </div>

                          {/* Execution Methods */}
                          {execMethods.length > 0 && (
                            <div>
                              <h4 className="text-sm font-semibold text-muted-foreground mb-2">
                                <Zap className="h-4 w-4 inline mr-1" />Execution Methods
                              </h4>
                              <div className="space-y-2">
                                {execMethods.slice(0, 5).map((m: any, i: number) => (
                                  <div key={i} className="bg-zinc-800/50 rounded p-2 text-sm">
                                    <span className="font-medium">{m.method}</span>
                                    {m.tools?.length > 0 && (
                                      <span className="text-muted-foreground ml-2">
                                        Tools: {m.tools.join(", ")}
                                      </span>
                                    )}
                                    {m.commands?.length > 0 && (
                                      <pre className="mt-1 text-xs bg-black/30 p-2 rounded overflow-x-auto">
                                        {m.commands[0]}
                                      </pre>
                                    )}
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Tools */}
                          {tools.length > 0 && (
                            <div>
                              <h4 className="text-sm font-semibold text-muted-foreground mb-2">
                                <Wrench className="h-4 w-4 inline mr-1" />Tools & Software
                              </h4>
                              <div className="flex flex-wrap gap-2">
                                {tools.slice(0, 10).map((t: any, i: number) => (
                                  <Badge key={i} variant="outline" className="text-xs">
                                    {t.name}
                                    <span className="ml-1 text-muted-foreground">({t.type})</span>
                                  </Badge>
                                ))}
                                {tools.length > 10 && (
                                  <Badge variant="outline" className="text-xs text-muted-foreground">
                                    +{tools.length - 10} more
                                  </Badge>
                                )}
                              </div>
                            </div>
                          )}

                          {/* Detection Rules */}
                          {detections.length > 0 && (
                            <div>
                              <h4 className="text-sm font-semibold text-muted-foreground mb-2">
                                <Shield className="h-4 w-4 inline mr-1" />Detection Rules
                              </h4>
                              <div className="space-y-2">
                                {detections.slice(0, 3).map((d: any, i: number) => (
                                  <div key={i} className="bg-zinc-800/50 rounded p-2">
                                    <div className="flex items-center gap-2 mb-1">
                                      <Badge variant="outline" className="text-xs">{d.format}</Badge>
                                      <span className="text-sm font-medium">{d.name}</span>
                                    </div>
                                    <pre className="text-xs bg-black/30 p-2 rounded overflow-x-auto max-h-32">
                                      {d.rule?.substring(0, 300)}
                                    </pre>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* IOC Patterns */}
                          {iocs.length > 0 && (
                            <div>
                              <h4 className="text-sm font-semibold text-muted-foreground mb-2">
                                <AlertTriangle className="h-4 w-4 inline mr-1" />IOC Patterns
                              </h4>
                              <div className="space-y-1">
                                {iocs.slice(0, 5).map((ioc: any, i: number) => (
                                  <div key={i} className="flex items-center gap-2 text-sm">
                                    <Badge variant="outline" className="text-xs min-w-[80px] justify-center">{ioc.type}</Badge>
                                    <code className="text-xs">{ioc.pattern?.substring(0, 100)}</code>
                                    <Badge variant="outline" className={`text-xs ${ioc.confidence === "high" ? "text-red-400" : ioc.confidence === "medium" ? "text-yellow-400" : "text-zinc-400"}`}>
                                      {ioc.confidence}
                                    </Badge>
                                  </div>
                                ))}
                              </div>
                            </div>
                          )}

                          {/* Team Scores */}
                          <div className="flex gap-4">
                            <div className="flex items-center gap-2">
                              <Target className="h-4 w-4 text-red-400" />
                              <span className="text-sm">Red Team: {entry.redTeamValue || 0}/10</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <Shield className="h-4 w-4 text-blue-400" />
                              <span className="text-sm">Blue Team: {entry.blueTeamPriority || 0}/10</span>
                            </div>
                            <div className="flex items-center gap-2">
                              <span className="text-sm text-muted-foreground">Source: {entry.dataSource}</span>
                            </div>
                          </div>

                          {/* Actions */}
                          <div className="flex gap-2 pt-2 border-t border-zinc-800">
                            <Button
                              size="sm"
                              variant="outline"
                              onClick={() => enrichMutation.mutate({
                                techniqueId: entry.techniqueId,
                                techniqueName: entry.techniqueName,
                                tactic: entry.tactic,
                                force: true,
                              })}
                              disabled={enrichMutation.isPending}
                            >
                              {enrichMutation.isPending ? (
                                <Loader2 className="h-3 w-3 mr-1 animate-spin" />
                              ) : (
                                <RefreshCw className="h-3 w-3 mr-1" />
                              )}
                              Deep Enrich with LLM
                            </Button>
                            <Button size="sm" variant="outline" asChild>
                              <a href={`https://attack.mitre.org/techniques/${entry.techniqueId.replace(".", "/")}/`} target="_blank" rel="noreferrer">
                                <BookOpen className="h-3 w-3 mr-1" />
                                View on ATT&CK
                              </a>
                            </Button>
                          </div>
                        </div>
                      )}
                    </CardContent>
                  </Card>
                );
              })
            )}
          </div>

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="flex items-center justify-between">
              <p className="text-sm text-muted-foreground">
                Showing {page * 25 + 1}-{Math.min((page + 1) * 25, total)} of {total}
              </p>
              <div className="flex gap-2">
                <Button size="sm" variant="outline" onClick={() => setPage(p => Math.max(0, p - 1))} disabled={page === 0}>
                  Previous
                </Button>
                <Button size="sm" variant="outline" onClick={() => setPage(p => p + 1)} disabled={page >= totalPages - 1}>
                  Next
                </Button>
              </div>
            </div>
          )}
        </TabsContent>

        {/* Offensive Tools Tab */}
        <TabsContent value="kali" className="space-y-4">
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Wrench className="h-5 w-5 text-orange-400" />
                penetration testing tools Offensive Tool Catalog
              </CardTitle>
              <CardDescription>
                {kaliTools.data?.length || 0} tools mapped to MITRE ATT&CK techniques across {kaliByCategory.size} categories
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-6">
                {Array.from(kaliByCategory.entries()).map(([category, tools]) => (
                  <div key={category}>
                    <h3 className="text-sm font-semibold text-muted-foreground mb-3 flex items-center gap-2">
                      <span className="h-2 w-2 rounded-full bg-orange-400" />
                      {category} ({tools.length})
                    </h3>
                    <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-2">
                      {tools.map((tool) => (
                        <div key={tool.name} className="bg-zinc-800/50 rounded-lg p-3 hover:bg-zinc-800 transition-colors">
                          <div className="flex items-center justify-between mb-1">
                            <code className="text-sm font-mono text-orange-400">{tool.name}</code>
                          </div>
                          <p className="text-xs text-muted-foreground mb-2">{tool.description}</p>
                          <div className="flex flex-wrap gap-1">
                            {tool.techniques.slice(0, 4).map((t) => (
                              <Badge key={t} variant="outline" className="text-xs font-mono">{t}</Badge>
                            ))}
                            {tool.techniques.length > 4 && (
                              <Badge variant="outline" className="text-xs">+{tool.techniques.length - 4}</Badge>
                            )}
                          </div>
                        </div>
                      ))}
                    </div>
                  </div>
                ))}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Tactic Heatmap Tab */}
        <TabsContent value="tactics" className="space-y-4">
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader>
              <CardTitle>ATT&CK Tactic Coverage</CardTitle>
              <CardDescription>
                Knowledge base coverage across the MITRE ATT&CK kill chain
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-3">
                {tacticStats.map((t: any) => {
                  const maxCount = Math.max(...tacticStats.map((s: any) => s.count));
                  const pct = maxCount > 0 ? (t.count / maxCount) * 100 : 0;
                  return (
                    <div key={t.tactic} className="flex items-center gap-3">
                      <div className="w-48 text-sm">
                        <Badge variant="outline" className={`${getTacticColor(t.tactic)} text-xs`}>
                          {t.tactic}
                        </Badge>
                      </div>
                      <div className="flex-1">
                        <div className="h-6 bg-zinc-800 rounded-full overflow-hidden">
                          <div
                            className="h-full bg-gradient-to-r from-purple-600 to-purple-400 rounded-full transition-all"
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                      </div>
                      <span className="text-sm font-mono w-12 text-right">{t.count}</span>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
    </AppShell>
  );
}
