import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { useAuth } from "@/contexts/AuthContext";
import {
  Activity, RefreshCw, CheckCircle2, XCircle, Clock, AlertTriangle,
  FileText, Shield, Zap, BookOpen, Network, Bug, Brain,
  ChevronDown, ChevronUp, RotateCcw, History
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { useToast } from "@/hooks/use-toast";

// Pipeline definitions with metadata
const PIPELINES = [
  { key: "dfir-ingest", name: "DFIR Report Ingestion", icon: FileText, color: "text-blue-400", desc: "Ingests threat intelligence from RSS feeds and DFIR reports" },
  { key: "ioc-ttp-mapping", name: "IOC-to-TTP Mapping", icon: Shield, color: "text-purple-400", desc: "Maps IOCs to MITRE ATT&CK techniques using reverse engineering" },
  { key: "catalog-enrichment", name: "Catalog Enrichment Sweep", icon: Brain, color: "text-emerald-400", desc: "LLM-powered enrichment of threat actor profiles" },
  { key: "playbook-promotion", name: "Playbook Promotion", icon: BookOpen, color: "text-amber-400", desc: "Validates and promotes draft emulation playbooks to ready" },
  { key: "graph-generation", name: "Ability Graph Generation", icon: Network, color: "text-cyan-400", desc: "Auto-generates attack graphs from actor technique profiles" },
  { key: "exploit-triage", name: "Exploit Triage", icon: Bug, color: "text-red-400", desc: "LLM-assisted review and approval of unified exploit catalog" },
];

function formatTimeAgo(ts: number | null | undefined): string {
  if (!ts) return "Never";
  const diff = Date.now() - ts;
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return "Just now";
  if (mins < 60) return `${mins}m ago`;
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return `${hrs}h ago`;
  const days = Math.floor(hrs / 24);
  return `${days}d ago`;
}

function StatusIcon({ status }: { status: string }) {
  switch (status) {
    case "completed": return <CheckCircle2 className="h-4 w-4 text-emerald-400" />;
    case "running": return <RefreshCw className="h-4 w-4 text-blue-400 animate-spin" />;
    case "failed": return <XCircle className="h-4 w-4 text-red-400" />;
    case "idle": return <Clock className="h-4 w-4 text-zinc-500" />;
    default: return <Clock className="h-4 w-4 text-zinc-500" />;
  }
}

export default function PipelineDashboard() {
  const { user } = useAuth();
  const { toast } = useToast();
  const [activeTab, setActiveTab] = useState("pipelines");
  const [expandedPipeline, setExpandedPipeline] = useState<string | null>(null);
  const [auditPage, setAuditPage] = useState(0);

  // Pipeline status queries
  const pipelineStatus = trpc.threatIntel.pipelineStatus.useQuery(undefined, {
    refetchInterval: 15000,
  });
  const pipelineHistory = trpc.threatIntel.pipelineHistory.useQuery(
    { limit: 50 },
    { refetchInterval: 30000 }
  );

  // Audit log queries
  const auditSummary = trpc.threatIntel.classifyAuditSummary.useQuery(undefined, {
    refetchInterval: 30000,
  });
  const auditLog = trpc.threatIntel.classifyAuditLog.useQuery(
    { limit: 25, offset: auditPage * 25 },
    { refetchInterval: 30000 }
  );

  // Revert mutation
  const revertMutation = trpc.threatIntel.classifyAuditRevert.useMutation({
    onSuccess: () => {
      toast({ title: "Classification reverted", description: "Actor type has been restored to its previous value." });
      auditLog.refetch();
      auditSummary.refetch();
    },
    onError: (err) => {
      toast({ title: "Revert failed", description: err.message, variant: "destructive" });
    },
  });

  const statuses = pipelineStatus.data || {};
  const history = pipelineHistory.data || [];
  const summary = auditSummary.data;
  const auditEntries = auditLog.data?.entries || [];
  const auditTotal = auditLog.data?.total || 0;

  // Compute overall health
  const totalPipelines = PIPELINES.length;
  const activePipelines = PIPELINES.filter(p => {
    const s = (statuses as any)[p.key];
    return s && s.lastRun;
  }).length;
  const failedPipelines = PIPELINES.filter(p => {
    const s = (statuses as any)[p.key];
    return s?.lastResult?.itemsFailed > 0;
  }).length;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold text-zinc-100 flex items-center gap-2">
            <Activity className="h-6 w-6 text-blue-400" />
            Enrichment Pipeline Dashboard
          </h1>
          <p className="text-sm text-zinc-400 mt-1">
            Automated threat intelligence enrichment, classification, and emulation readiness
          </p>
        </div>
        <div className="flex items-center gap-3">
          <Badge variant="outline" className="border-emerald-500/30 text-emerald-400">
            {activePipelines}/{totalPipelines} Active
          </Badge>
          {failedPipelines > 0 && (
            <Badge variant="outline" className="border-red-500/30 text-red-400">
              {failedPipelines} Failed
            </Badge>
          )}
        </div>
      </div>

      {/* Summary Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardContent className="pt-4 pb-3">
            <div className="text-xs text-zinc-500 uppercase tracking-wider">Total Runs (24h)</div>
            <div className="text-2xl font-bold text-zinc-100 mt-1">
              {history.filter((h: any) => h.timestamp > Date.now() - 86400000).length}
            </div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardContent className="pt-4 pb-3">
            <div className="text-xs text-zinc-500 uppercase tracking-wider">Classifications (24h)</div>
            <div className="text-2xl font-bold text-zinc-100 mt-1">
              {summary?.last24h ?? "—"}
            </div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardContent className="pt-4 pb-3">
            <div className="text-xs text-zinc-500 uppercase tracking-wider">Auto-Applied</div>
            <div className="text-2xl font-bold text-emerald-400 mt-1">
              {summary?.autoApplied ?? "—"}
            </div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardContent className="pt-4 pb-3">
            <div className="text-xs text-zinc-500 uppercase tracking-wider">Pending Review</div>
            <div className="text-2xl font-bold text-amber-400 mt-1">
              {summary?.pendingReview ?? "—"}
            </div>
          </CardContent>
        </Card>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-zinc-900/60 border border-zinc-800">
          <TabsTrigger value="pipelines" className="data-[state=active]:bg-zinc-800">
            <Zap className="h-4 w-4 mr-1" /> Pipelines
          </TabsTrigger>
          <TabsTrigger value="audit" className="data-[state=active]:bg-zinc-800">
            <History className="h-4 w-4 mr-1" /> Classification Audit Log
          </TabsTrigger>
          <TabsTrigger value="history" className="data-[state=active]:bg-zinc-800">
            <Clock className="h-4 w-4 mr-1" /> Run History
          </TabsTrigger>
        </TabsList>

        {/* Pipelines Tab */}
        <TabsContent value="pipelines" className="space-y-3 mt-4">
          {PIPELINES.map((pipeline) => {
            const status = (statuses as any)[pipeline.key];
            const isExpanded = expandedPipeline === pipeline.key;
            const Icon = pipeline.icon;

            return (
              <Card key={pipeline.key} className="bg-zinc-900/60 border-zinc-800 hover:border-zinc-700 transition-colors">
                <CardContent className="p-4">
                  <div
                    className="flex items-center justify-between cursor-pointer"
                    onClick={() => setExpandedPipeline(isExpanded ? null : pipeline.key)}
                  >
                    <div className="flex items-center gap-3">
                      <div className={`p-2 rounded-lg bg-zinc-800/80 ${pipeline.color}`}>
                        <Icon className="h-5 w-5" />
                      </div>
                      <div>
                        <div className="font-medium text-zinc-200">{pipeline.name}</div>
                        <div className="text-xs text-zinc-500">{pipeline.desc}</div>
                      </div>
                    </div>
                    <div className="flex items-center gap-4">
                      {status ? (
                        <>
                          <div className="flex items-center gap-1.5">
                            <StatusIcon status={status.running ? "running" : status.lastResult ? (status.lastResult.itemsFailed === 0 ? "completed" : "failed") : "idle"} />
                            <span className="text-sm text-zinc-400 capitalize">
                              {status.running ? "running" : status.lastResult ? (status.lastResult.itemsFailed === 0 ? "completed" : "failed") : "idle"}
                            </span>
                          </div>
                          <div className="text-xs text-zinc-500">
                            Last: {formatTimeAgo(status.lastRun)}
                          </div>
                          {status.totalItemsProcessed > 0 && (
                            <Badge variant="outline" className="border-zinc-700 text-zinc-400 text-xs">
                              {status.totalItemsProcessed} items
                            </Badge>
                          )}
                        </>
                      ) : (
                        <span className="text-xs text-zinc-600">Not yet run</span>
                      )}
                      {isExpanded ? <ChevronUp className="h-4 w-4 text-zinc-500" /> : <ChevronDown className="h-4 w-4 text-zinc-500" />}
                    </div>
                  </div>

                  {isExpanded && status && (
                    <div className="mt-4 pt-4 border-t border-zinc-800 space-y-2">
                      <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-sm">
                        <div>
                          <span className="text-zinc-500">Items Processed:</span>
                          <span className="text-zinc-300 ml-2">{status.totalItemsProcessed || 0}</span>
                        </div>
                        <div>
                          <span className="text-zinc-500">Total Runs:</span>
                          <span className="text-zinc-300 ml-2">{status.totalRuns || 0}</span>
                        </div>
                        <div>
                          <span className="text-zinc-500">Last Run:</span>
                          <span className="text-zinc-300 ml-2">{status.lastRun ? new Date(status.lastRun).toLocaleString() : "Never"}</span>
                        </div>
                        <div>
                          <span className="text-zinc-500">Duration:</span>
                          <span className="text-zinc-300 ml-2">{status.lastResult?.completedAt && status.lastResult?.startedAt ? `${Math.round((status.lastResult.completedAt - status.lastResult.startedAt) / 1000)}s` : "—"}</span>
                        </div>
                      </div>
                      {status.lastResult?.itemsFailed > 0 && (
                        <div className="mt-2 p-2 bg-red-950/30 border border-red-900/30 rounded text-xs text-red-400">
                          <AlertTriangle className="h-3 w-3 inline mr-1" />
                          {status.lastResult.itemsFailed} items failed in last run
                          {status.lastResult.contextUpdate?.errors?.length > 0 && `: ${status.lastResult.contextUpdate.errors[0]}`}
                        </div>
                      )}
                      {status.lastResult?.contextUpdate?.actorsUpdated > 0 && (
                        <div className="mt-2 p-2 bg-blue-950/30 border border-blue-900/30 rounded text-xs text-blue-400">
                          <Brain className="h-3 w-3 inline mr-1" />
                          LLM Context Updated: {status.lastResult.contextUpdate.actorsUpdated} actors refreshed, {status.lastResult.contextUpdate.techniquesRefreshed} techniques
                        </div>
                      )}
                    </div>
                  )}
                </CardContent>
              </Card>
            );
          })}
        </TabsContent>

        {/* Audit Log Tab */}
        <TabsContent value="audit" className="space-y-4 mt-4">
          {/* Audit Summary */}
          {summary && (
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              <Card className="bg-zinc-900/60 border-zinc-800">
                <CardContent className="pt-3 pb-2 text-center">
                  <div className="text-lg font-bold text-zinc-100">{summary.totalClassifications}</div>
                  <div className="text-xs text-zinc-500">Total</div>
                </CardContent>
              </Card>
              <Card className="bg-zinc-900/60 border-zinc-800">
                <CardContent className="pt-3 pb-2 text-center">
                  <div className="text-lg font-bold text-emerald-400">{summary.autoApplied}</div>
                  <div className="text-xs text-zinc-500">Auto-Applied</div>
                </CardContent>
              </Card>
              <Card className="bg-zinc-900/60 border-zinc-800">
                <CardContent className="pt-3 pb-2 text-center">
                  <div className="text-lg font-bold text-blue-400">{summary.manualApproved}</div>
                  <div className="text-xs text-zinc-500">Manual</div>
                </CardContent>
              </Card>
              <Card className="bg-zinc-900/60 border-zinc-800">
                <CardContent className="pt-3 pb-2 text-center">
                  <div className="text-lg font-bold text-amber-400">{summary.pendingReview}</div>
                  <div className="text-xs text-zinc-500">Pending</div>
                </CardContent>
              </Card>
              <Card className="bg-zinc-900/60 border-zinc-800">
                <CardContent className="pt-3 pb-2 text-center">
                  <div className="text-lg font-bold text-red-400">{summary.reverted}</div>
                  <div className="text-xs text-zinc-500">Reverted</div>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Classification by Type */}
          {summary?.byType && Object.keys(summary.byType).length > 0 && (
            <Card className="bg-zinc-900/60 border-zinc-800">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm text-zinc-400">Classifications by Type</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex flex-wrap gap-2">
                  {Object.entries(summary.byType).sort((a, b) => b[1] - a[1]).map(([type, count]) => (
                    <Badge key={type} variant="outline" className="border-zinc-700 text-zinc-300">
                      {type}: {count}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}

          {/* Audit Entries Table */}
          <Card className="bg-zinc-900/60 border-zinc-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-zinc-400 flex items-center justify-between">
                <span>Recent Classifications ({auditTotal} total)</span>
                <Button variant="ghost" size="sm" onClick={() => auditLog.refetch()}>
                  <RefreshCw className="h-3 w-3" />
                </Button>
              </CardTitle>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-zinc-800 text-zinc-500 text-xs uppercase">
                      <th className="text-left py-2 px-2">Actor</th>
                      <th className="text-left py-2 px-2">Previous</th>
                      <th className="text-left py-2 px-2">New Type</th>
                      <th className="text-center py-2 px-2">Confidence</th>
                      <th className="text-left py-2 px-2">Method</th>
                      <th className="text-left py-2 px-2">When</th>
                      <th className="text-right py-2 px-2">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditEntries.map((entry: any) => (
                      <tr key={entry.id} className="border-b border-zinc-800/50 hover:bg-zinc-800/30">
                        <td className="py-2 px-2 text-zinc-300 max-w-[200px] truncate" title={entry.actorName}>
                          {entry.actorName || entry.actorId}
                        </td>
                        <td className="py-2 px-2">
                          <Badge variant="outline" className="border-zinc-700 text-zinc-500 text-xs">
                            {entry.previousType}
                          </Badge>
                        </td>
                        <td className="py-2 px-2">
                          <Badge variant="outline" className={`text-xs ${
                            entry.newType === "apt" ? "border-red-500/30 text-red-400" :
                            entry.newType === "ransomware" ? "border-orange-500/30 text-orange-400" :
                            entry.newType === "cybercrime" ? "border-yellow-500/30 text-yellow-400" :
                            entry.newType === "hacktivist" ? "border-green-500/30 text-green-400" :
                            entry.newType === "access_broker" ? "border-purple-500/30 text-purple-400" :
                            "border-blue-500/30 text-blue-400"
                          }`}>
                            {entry.newType}
                          </Badge>
                        </td>
                        <td className="py-2 px-2 text-center">
                          <span className={`text-xs font-mono ${
                            entry.confidence >= 80 ? "text-emerald-400" :
                            entry.confidence >= 60 ? "text-amber-400" :
                            "text-red-400"
                          }`}>
                            {entry.confidence}%
                          </span>
                        </td>
                        <td className="py-2 px-2">
                          <span className={`text-xs ${
                            entry.appliedMethod === "auto_apply" ? "text-emerald-400" :
                            entry.appliedMethod === "manual_approve" ? "text-blue-400" :
                            entry.appliedMethod === "pending_review" ? "text-amber-400" :
                            entry.appliedMethod === "revert" ? "text-red-400" :
                            "text-zinc-400"
                          }`}>
                            {entry.appliedMethod?.replace(/_/g, " ")}
                          </span>
                        </td>
                        <td className="py-2 px-2 text-xs text-zinc-500">
                          {formatTimeAgo(entry.createdAt)}
                        </td>
                        <td className="py-2 px-2 text-right">
                          {!entry.wasReverted && entry.appliedMethod !== "revert" && entry.appliedMethod !== "pending_review" && (
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 px-2 text-xs text-zinc-500 hover:text-red-400"
                              onClick={() => revertMutation.mutate({ auditId: entry.id, actorId: entry.actorId })}
                              disabled={revertMutation.isPending}
                            >
                              <RotateCcw className="h-3 w-3 mr-1" /> Revert
                            </Button>
                          )}
                          {entry.wasReverted && (
                            <span className="text-xs text-red-400/60">Reverted</span>
                          )}
                        </td>
                      </tr>
                    ))}
                    {auditEntries.length === 0 && (
                      <tr>
                        <td colSpan={7} className="py-8 text-center text-zinc-600">
                          No classification audit entries yet. Run the classifier to populate.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
              {/* Pagination */}
              {auditTotal > 25 && (
                <div className="flex items-center justify-between mt-3 pt-3 border-t border-zinc-800">
                  <span className="text-xs text-zinc-500">
                    Showing {auditPage * 25 + 1}-{Math.min((auditPage + 1) * 25, auditTotal)} of {auditTotal}
                  </span>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={auditPage === 0}
                      onClick={() => setAuditPage(p => p - 1)}
                      className="h-7 text-xs"
                    >
                      Previous
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      disabled={(auditPage + 1) * 25 >= auditTotal}
                      onClick={() => setAuditPage(p => p + 1)}
                      className="h-7 text-xs"
                    >
                      Next
                    </Button>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* Run History Tab */}
        <TabsContent value="history" className="mt-4">
          <Card className="bg-zinc-900/60 border-zinc-800">
            <CardHeader className="pb-2">
              <CardTitle className="text-sm text-zinc-400">Pipeline Run History (Last 50)</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-zinc-800 text-zinc-500 text-xs uppercase">
                      <th className="text-left py-2 px-2">Pipeline</th>
                      <th className="text-left py-2 px-2">Status</th>
                      <th className="text-center py-2 px-2">Items</th>
                      <th className="text-center py-2 px-2">Errors</th>
                      <th className="text-center py-2 px-2">Context Updates</th>
                      <th className="text-left py-2 px-2">Duration</th>
                      <th className="text-left py-2 px-2">When</th>
                    </tr>
                  </thead>
                  <tbody>
                    {history.map((run: any, i: number) => (
                      <tr key={i} className="border-b border-zinc-800/50 hover:bg-zinc-800/30">
                        <td className="py-2 px-2 text-zinc-300">
                          {PIPELINES.find(p => p.key === run.pipeline)?.name || run.pipeline}
                        </td>
                        <td className="py-2 px-2">
                          <div className="flex items-center gap-1.5">
                            <StatusIcon status={run.status} />
                            <span className="text-xs capitalize text-zinc-400">{run.status}</span>
                          </div>
                        </td>
                        <td className="py-2 px-2 text-center text-zinc-400">{run.itemsProcessed || 0}</td>
                        <td className="py-2 px-2 text-center">
                          <span className={run.errors > 0 ? "text-red-400" : "text-zinc-500"}>{run.errors || 0}</span>
                        </td>
                        <td className="py-2 px-2 text-center">
                          <span className={run.contextUpdates > 0 ? "text-blue-400" : "text-zinc-500"}>
                            {run.contextUpdates || 0}
                          </span>
                        </td>
                        <td className="py-2 px-2 text-xs text-zinc-500">
                          {run.duration ? `${Math.round(run.duration / 1000)}s` : "—"}
                        </td>
                        <td className="py-2 px-2 text-xs text-zinc-500">
                          {run.timestamp ? new Date(run.timestamp).toLocaleString() : "—"}
                        </td>
                      </tr>
                    ))}
                    {history.length === 0 && (
                      <tr>
                        <td colSpan={7} className="py-8 text-center text-zinc-600">
                          No pipeline runs recorded yet. Pipelines will start running on schedule.
                        </td>
                      </tr>
                    )}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
