import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Progress } from "@/components/ui/progress";
import {
  Loader2, Layers, Play, Square, ChevronRight, Clock, CheckCircle2,
  XCircle, BarChart3, Target, Shield, Crosshair, Zap, Activity,
  AlertTriangle, ArrowRight, Eye, Network, Globe, Radar, Bug
} from "lucide-react";
import AppShell from "@/components/AppShell";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  high: "bg-red-500/20 text-red-400 border-red-500/30",
  medium: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

const PHASE_ICONS: Record<string, any> = {
  recon: Globe,
  enumeration: Radar,
  vulnerability_assessment: Bug,
  exploitation: Crosshair,
  post_exploitation: Shield,
  reporting: BarChart3,
};

const PHASE_LABELS: Record<string, string> = {
  recon: "Reconnaissance",
  enumeration: "Enumeration",
  vulnerability_assessment: "Vulnerability Assessment",
  exploitation: "Exploitation",
  post_exploitation: "Post-Exploitation",
  reporting: "Reporting",
};

const STATUS_COLORS: Record<string, string> = {
  pending: "text-gray-400",
  running: "text-cyan-400 animate-pulse",
  completed: "text-emerald-400",
  failed: "text-red-400",
  skipped: "text-amber-400",
  cancelled: "text-gray-500",
};

export default function UnifiedPipeline() {
  const [activeTab, setActiveTab] = useState("runs");
  const [showNewRun, setShowNewRun] = useState(false);
  const [domain, setDomain] = useState("");
  const [targetUrls, setTargetUrls] = useState("");
  const [targetIps, setTargetIps] = useState("");

  const runsQuery = trpc.unifiedPipeline.listRuns.useQuery(undefined, { refetchInterval: 5000 });
  const stagesQuery = trpc.unifiedPipeline.getStages.useQuery();
  const matrixQuery = trpc.unifiedPipeline.getToolMatrix.useQuery();

  const startRun = trpc.unifiedPipeline.startRun.useMutation({
    onSuccess: (data) => {
      toast.success(`Pipeline started: ${data.runId}`);
      setShowNewRun(false);
      setDomain("");
      setTargetUrls("");
      setTargetIps("");
      runsQuery.refetch();
    },
    onError: (e) => toast.error(`Failed to start pipeline: ${e.message}`),
  });

  const cancelRun = trpc.unifiedPipeline.cancelRun.useMutation({
    onSuccess: () => { toast.success("Pipeline cancelled"); runsQuery.refetch(); },
    onError: (e) => toast.error(`Cancel failed: ${e.message}`),
  });

  const runs = runsQuery.data || [];
  const stages = stagesQuery.data || [];
  const toolMatrix = matrixQuery.data || [];

  return (
    <AppShell activePath="/unified-pipeline">
      <div className="space-y-6 p-1">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight flex items-center gap-3">
              <Layers className="w-7 h-7 text-cyan-400" />
              Unified Attack Pipeline
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              Orchestrate the full attack lifecycle — from passive recon through exploitation to reporting — with all integrated tools feeding a single correlated view.
            </p>
          </div>
          <Dialog open={showNewRun} onOpenChange={setShowNewRun}>
            <DialogTrigger asChild>
              <Button className="bg-cyan-600 hover:bg-cyan-700">
                <Play className="w-4 h-4 mr-2" /> New Pipeline Run
              </Button>
            </DialogTrigger>
            <DialogContent className="sm:max-w-lg">
              <DialogHeader>
                <DialogTitle>Start Pipeline Run</DialogTitle>
                <DialogDescription>Configure target scope for the full attack lifecycle.</DialogDescription>
              </DialogHeader>
              <div className="space-y-4">
                <div>
                  <Label>Target Domain *</Label>
                  <Input value={domain} onChange={e => setDomain(e.target.value)} placeholder="example.com" />
                </div>
                <div>
                  <Label>Target URLs (one per line)</Label>
                  <textarea className="w-full rounded-md border border-border bg-background px-3 py-2 text-sm min-h-[80px]" value={targetUrls} onChange={e => setTargetUrls(e.target.value)} placeholder="https://app.example.com&#10;https://api.example.com" />
                </div>
                <div>
                  <Label>Target IPs (comma-separated)</Label>
                  <Input value={targetIps} onChange={e => setTargetIps(e.target.value)} placeholder="10.0.0.1, 10.0.0.2" />
                </div>
              </div>
              <DialogFooter>
                <Button variant="outline" onClick={() => setShowNewRun(false)}>Cancel</Button>
                <Button
                  className="bg-cyan-600 hover:bg-cyan-700"
                  disabled={!domain || startRun.isPending}
                  onClick={() => startRun.mutate({
                    domain,
                    targetUrls: targetUrls.split("\n").map(s => s.trim()).filter(Boolean),
                    targetIps: targetIps.split(",").map(s => s.trim()).filter(Boolean),
                  })}
                >
                  {startRun.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Play className="w-4 h-4 mr-2" />}
                  Launch Pipeline
                </Button>
              </DialogFooter>
            </DialogContent>
          </Dialog>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="bg-card border border-border">
            <TabsTrigger value="runs">Pipeline Runs</TabsTrigger>
            <TabsTrigger value="stages">Stage Definitions</TabsTrigger>
            <TabsTrigger value="matrix">Tool Matrix</TabsTrigger>
          </TabsList>

          {/* Pipeline Runs */}
          <TabsContent value="runs" className="space-y-4">
            {runs.length === 0 ? (
              <Card className="border-dashed border-border/50">
                <CardContent className="flex flex-col items-center justify-center py-16 text-center">
                  <Layers className="w-12 h-12 text-muted-foreground/30 mb-4" />
                  <p className="text-muted-foreground">No pipeline runs yet. Start a new run to orchestrate the full attack lifecycle.</p>
                </CardContent>
              </Card>
            ) : (
              runs.map((run: any) => (
                <Card key={run.id} className="border-border/50 hover:border-cyan-500/30 transition-colors">
                  <CardHeader className="pb-3">
                    <div className="flex items-center justify-between">
                      <div>
                        <CardTitle className="text-lg flex items-center gap-2">
                          <Activity className={`w-5 h-5 ${STATUS_COLORS[run.status]}`} />
                          {run.domain}
                        </CardTitle>
                        <CardDescription className="mt-1">
                          Run {run.id} · {run.phasesCompleted}/{run.totalPhases} phases · {run.totalFindings} findings
                        </CardDescription>
                      </div>
                      <div className="flex items-center gap-2">
                        <Badge variant="outline" className={STATUS_COLORS[run.status]}>
                          {run.status.toUpperCase()}
                        </Badge>
                        {run.status === "running" && (
                          <Button size="sm" variant="outline" className="border-red-500/30 text-red-400 hover:bg-red-500/10" onClick={() => cancelRun.mutate({ runId: run.id })}>
                            <Square className="w-3 h-3 mr-1" /> Cancel
                          </Button>
                        )}
                      </div>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <div className="flex items-center gap-2 mb-4">
                      <Progress value={(run.phasesCompleted / run.totalPhases) * 100} className="flex-1 h-2" />
                      <span className="text-xs text-muted-foreground">{Math.round((run.phasesCompleted / run.totalPhases) * 100)}%</span>
                    </div>
                    {/* Severity breakdown */}
                    {run.findingsBySeverity && (
                      <div className="flex gap-3 flex-wrap">
                        {Object.entries(run.findingsBySeverity as Record<string, number>).filter(([, v]) => v > 0).map(([sev, count]) => (
                          <Badge key={sev} variant="outline" className={SEVERITY_COLORS[sev]}>
                            {sev}: {count}
                          </Badge>
                        ))}
                      </div>
                    )}
                    {/* ATT&CK coverage */}
                    {run.attackCoverage && run.attackCoverage.coveragePercent > 0 && (
                      <div className="mt-3 flex items-center gap-2 text-xs text-muted-foreground">
                        <Target className="w-3.5 h-3.5" />
                        ATT&CK Coverage: {run.attackCoverage.coveragePercent}% · {run.attackCoverage.techniquesUsed?.length || 0} techniques
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))
            )}
          </TabsContent>

          {/* Stage Definitions */}
          <TabsContent value="stages" className="space-y-4">
            <div className="grid gap-4">
              {stages.map((stage: any, idx: number) => {
                const PhaseIcon = PHASE_ICONS[stage.phase] || Activity;
                return (
                  <Card key={stage.phase} className="border-border/50">
                    <CardHeader className="pb-2">
                      <CardTitle className="text-base flex items-center gap-2">
                        <div className="w-8 h-8 rounded-lg bg-cyan-500/10 border border-cyan-500/30 flex items-center justify-center">
                          <PhaseIcon className="w-4 h-4 text-cyan-400" />
                        </div>
                        <span className="text-muted-foreground text-xs mr-1">Phase {idx + 1}</span>
                        {PHASE_LABELS[stage.phase] || stage.phase}
                      </CardTitle>
                      <CardDescription>{stage.description}</CardDescription>
                    </CardHeader>
                    <CardContent>
                      <div className="flex flex-wrap gap-2">
                        {stage.tools?.map((tool: string) => (
                          <Badge key={tool} variant="outline" className="text-xs border-border/50">
                            {tool.replace(/_/g, " ")}
                          </Badge>
                        ))}
                      </div>
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          </TabsContent>

          {/* Tool Matrix */}
          <TabsContent value="matrix" className="space-y-4">
            <Card className="border-border/50">
              <CardHeader>
                <CardTitle className="text-lg">Tool-to-Phase Integration Matrix</CardTitle>
                <CardDescription>Shows which tools contribute to which attack lifecycle phases and their data flow relationships.</CardDescription>
              </CardHeader>
              <CardContent>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead>
                      <tr className="border-b border-border/50">
                        <th className="text-left py-2 px-3 text-muted-foreground font-medium">Tool</th>
                        <th className="text-left py-2 px-3 text-muted-foreground font-medium">Phases</th>
                        <th className="text-left py-2 px-3 text-muted-foreground font-medium">Outputs</th>
                        <th className="text-left py-2 px-3 text-muted-foreground font-medium">Feeds Into</th>
                      </tr>
                    </thead>
                    <tbody>
                      {toolMatrix.map((tool: any) => (
                        <tr key={tool.tool} className="border-b border-border/20 hover:bg-card/50">
                          <td className="py-2 px-3 font-mono text-xs">{tool.tool}</td>
                          <td className="py-2 px-3">
                            <div className="flex gap-1 flex-wrap">
                              {tool.phases?.map((p: string) => (
                                <Badge key={p} variant="outline" className="text-[10px] px-1.5 py-0">
                                  {p}
                                </Badge>
                              ))}
                            </div>
                          </td>
                          <td className="py-2 px-3 text-xs text-muted-foreground">
                            {tool.outputs?.join(", ") || "—"}
                          </td>
                          <td className="py-2 px-3 text-xs text-muted-foreground">
                            {tool.feedsInto?.join(", ") || "—"}
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
