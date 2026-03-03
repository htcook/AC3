import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Checkbox } from "@/components/ui/checkbox";
import { Textarea } from "@/components/ui/textarea";
import {
  Zap, Target, Shield, Play, ChevronRight, AlertTriangle,
  FileText, Crosshair, Layers, ArrowRight, CheckCircle2, XCircle,
  Clock, Loader2, BarChart3
} from "lucide-react";
import AppShell from "@/components/AppShell";

export default function EngagementAutomation() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [showCreateDialog, setShowCreateDialog] = useState(false);
  const [selectedTemplate, setSelectedTemplate] = useState("");
  const [engName, setEngName] = useState("");
  const [customerName, setCustomerName] = useState("");
  const [targetDomain, setTargetDomain] = useState("");
  const [targetIpRange, setTargetIpRange] = useState("");
  const [notes, setNotes] = useState("");
  const [includePostExploit, setIncludePostExploit] = useState(true);
  const [includeCleanup, setIncludeCleanup] = useState(true);
  const [selectedVectorIds, setSelectedVectorIds] = useState<string[]>([]);

  const { data: stats, isLoading: statsLoading } = trpc.engagementAutomation.getDashboardStats.useQuery();
  const { data: templates } = trpc.engagementAutomation.getTemplates.useQuery();
  const { data: automatedEngagements, refetch: refetchEngagements } = trpc.engagementAutomation.listAutomatedEngagements.useQuery({ limit: 20 });
  const { data: vectors } = trpc.attackVectorEngine.listVectors.useQuery({ limit: 50, status: "confirmed" });

  const createFromVectors = trpc.engagementAutomation.createFromVectors.useMutation({
    onSuccess: (data) => {
      toast.success(`Engagement "${data.name}" created with ${data.vectorCount} vectors, ${data.calderaAbilityCount} Caldera abilities, ${data.exploitScriptCount} exploits`);
      setShowCreateDialog(false);
      refetchEngagements();
      resetForm();
    },
    onError: (err) => toast.error(err.message),
  });

  const advancePipeline = trpc.engagementAutomation.advancePipeline.useMutation({
    onSuccess: (data) => {
      toast.success(`Pipeline advanced to step ${data.step}: ${data.status}`);
      refetchEngagements();
    },
    onError: (err) => toast.error(err.message),
  });

  function resetForm() {
    setSelectedTemplate("");
    setEngName("");
    setCustomerName("");
    setTargetDomain("");
    setTargetIpRange("");
    setNotes("");
    setSelectedVectorIds([]);
  }

  function handleCreate() {
    if (!selectedTemplate || !engName || !customerName || selectedVectorIds.length === 0) {
      toast.error("Please fill in all required fields and select at least one attack vector");
      return;
    }
    createFromVectors.mutate({
      templateId: selectedTemplate,
      name: engName,
      customerName,
      targetDomain: targetDomain || undefined,
      targetIpRange: targetIpRange || undefined,
      vectorIds: selectedVectorIds,
      includePostExploit,
      includeCleanup,
      notes: notes || undefined,
    });
  }

  function toggleVector(id: string) {
    setSelectedVectorIds(prev =>
      prev.includes(id) ? prev.filter(v => v !== id) : [...prev, id]
    );
  }

  const riskColor = (level: string) => {
    switch (level) {
      case "critical": return "text-red-400 bg-red-500/10 border-red-500/30";
      case "high": return "text-orange-400 bg-orange-500/10 border-orange-500/30";
      case "medium": return "text-yellow-400 bg-yellow-500/10 border-yellow-500/30";
      default: return "text-green-400 bg-green-500/10 border-green-500/30";
    }
  };

  const statusColor = (status: string) => {
    switch (status) {
      case "completed": return "text-green-400 bg-green-500/10";
      case "running": return "text-blue-400 bg-blue-500/10";
      case "planning": return "text-yellow-400 bg-yellow-500/10";
      case "failed": return "text-red-400 bg-red-500/10";
      default: return "text-zinc-400 bg-zinc-500/10";
    }
  };

  return (
      <AppShell activePath="/engagement-automation">
      <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Zap className="h-6 w-6 text-amber-400" />
            Engagement Workflow Automation
          </h1>
          <p className="text-muted-foreground mt-1">
            Automatically create engagements from attack vectors with pre-loaded Caldera abilities and Metasploit modules.
            Cross-references the threat catalog for threat-informed engagement planning.
          </p>
        </div>
        <Dialog open={showCreateDialog} onOpenChange={setShowCreateDialog}>
          <DialogTrigger asChild>
            <Button className="gap-2">
              <Play className="h-4 w-4" /> Create Engagement
            </Button>
          </DialogTrigger>
          <DialogContent className="max-w-2xl max-h-[85vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Create Automated Engagement</DialogTitle>
              <DialogDescription>
                Select attack vectors and a template to auto-generate an engagement with pre-loaded modules.
              </DialogDescription>
            </DialogHeader>
            <div className="space-y-4 py-2">
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Engagement Name *</Label>
                  <Input value={engName} onChange={e => setEngName(e.target.value)} placeholder="Q1 2026 Pentest" />
                </div>
                <div className="space-y-2">
                  <Label>Customer Name *</Label>
                  <Input value={customerName} onChange={e => setCustomerName(e.target.value)} placeholder="Acme Corp" />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Target Domain</Label>
                  <Input value={targetDomain} onChange={e => setTargetDomain(e.target.value)} placeholder="example.com" />
                </div>
                <div className="space-y-2">
                  <Label>Target IP Range</Label>
                  <Input value={targetIpRange} onChange={e => setTargetIpRange(e.target.value)} placeholder="10.0.0.0/24" />
                </div>
              </div>
              <div className="space-y-2">
                <Label>Engagement Template *</Label>
                <Select value={selectedTemplate} onValueChange={setSelectedTemplate}>
                  <SelectTrigger><SelectValue placeholder="Select template..." /></SelectTrigger>
                  <SelectContent>
                    {templates?.map(t => (
                      <SelectItem key={t.templateId} value={t.templateId}>
                        {t.name} — {t.killChainPhases.length} phases
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {selectedTemplate && templates && (
                  <p className="text-xs text-muted-foreground">
                    {templates.find(t => t.templateId === selectedTemplate)?.description}
                  </p>
                )}
              </div>
              <div className="space-y-2">
                <Label>Select Attack Vectors * ({selectedVectorIds.length} selected)</Label>
                <div className="border rounded-md max-h-48 overflow-y-auto p-2 space-y-1">
                  {vectors && vectors.length > 0 ? vectors.map((v: any) => (
                    <label key={v.id} className="flex items-center gap-2 p-2 rounded hover:bg-accent/50 cursor-pointer">
                      <Checkbox
                        checked={selectedVectorIds.includes(v.id)}
                        onCheckedChange={() => toggleVector(v.id)}
                      />
                      <span className="text-sm flex-1">{v.name}</span>
                      <Badge variant="outline" className={riskColor(v.overallRiskScore >= 9 ? "critical" : v.overallRiskScore >= 7 ? "high" : v.overallRiskScore >= 5 ? "medium" : "low")}>
                        {v.overallRiskScore}/10
                      </Badge>
                    </label>
                  )) : (
                    <p className="text-sm text-muted-foreground p-2">No confirmed vectors available. Identify vectors first in the Attack Vector Engine.</p>
                  )}
                </div>
              </div>
              <div className="flex items-center gap-6">
                <label className="flex items-center gap-2 cursor-pointer">
                  <Checkbox checked={includePostExploit} onCheckedChange={(c) => setIncludePostExploit(!!c)} />
                  <span className="text-sm">Include post-exploitation phases</span>
                </label>
                <label className="flex items-center gap-2 cursor-pointer">
                  <Checkbox checked={includeCleanup} onCheckedChange={(c) => setIncludeCleanup(!!c)} />
                  <span className="text-sm">Include cleanup procedures</span>
                </label>
              </div>
              <div className="space-y-2">
                <Label>Notes</Label>
                <Textarea value={notes} onChange={e => setNotes(e.target.value)} placeholder="Additional engagement notes..." rows={3} />
              </div>
            </div>
            <DialogFooter>
              <Button variant="outline" onClick={() => setShowCreateDialog(false)}>Cancel</Button>
              <Button onClick={handleCreate} disabled={createFromVectors.isPending} className="gap-2">
                {createFromVectors.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Zap className="h-4 w-4" />}
                Create Engagement
              </Button>
            </DialogFooter>
          </DialogContent>
        </Dialog>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="dashboard">Dashboard</TabsTrigger>
          <TabsTrigger value="engagements">Automated Engagements</TabsTrigger>
          <TabsTrigger value="templates">Templates</TabsTrigger>
        </TabsList>

        {/* Dashboard Tab */}
        <TabsContent value="dashboard" className="space-y-6">
          {statsLoading ? (
            <div className="flex items-center justify-center py-12"><Loader2 className="h-8 w-8 animate-spin text-muted-foreground" /></div>
          ) : stats ? (
            <>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <Card>
                  <CardContent className="pt-6">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-blue-500/10"><Target className="h-5 w-5 text-blue-400" /></div>
                      <div>
                        <p className="text-2xl font-bold">{stats.totalEngagements}</p>
                        <p className="text-xs text-muted-foreground">Total Engagements</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-6">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-amber-500/10"><Layers className="h-5 w-5 text-amber-400" /></div>
                      <div>
                        <p className="text-2xl font-bold">{stats.totalPipelines}</p>
                        <p className="text-xs text-muted-foreground">Active Pipelines</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-6">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-purple-500/10"><FileText className="h-5 w-5 text-purple-400" /></div>
                      <div>
                        <p className="text-2xl font-bold">{stats.totalPlaybooks}</p>
                        <p className="text-xs text-muted-foreground">Attack Playbooks</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="pt-6">
                    <div className="flex items-center gap-3">
                      <div className="p-2 rounded-lg bg-red-500/10"><Crosshair className="h-5 w-5 text-red-400" /></div>
                      <div>
                        <p className="text-2xl font-bold">{stats.totalVectors}</p>
                        <p className="text-xs text-muted-foreground">Attack Vectors</p>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Pipeline Status Breakdown */}
              <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm">Pipeline Status</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {stats.pipelinesByStatus?.length > 0 ? stats.pipelinesByStatus.map((p: any) => (
                        <div key={p.status} className="flex items-center justify-between">
                          <Badge variant="outline" className={statusColor(p.status)}>{p.status}</Badge>
                          <span className="text-sm font-mono">{p.count}</span>
                        </div>
                      )) : (
                        <p className="text-sm text-muted-foreground">No pipelines yet</p>
                      )}
                    </div>
                  </CardContent>
                </Card>
                <Card>
                  <CardHeader>
                    <CardTitle className="text-sm">Vector Status</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {stats.vectorsByStatus?.length > 0 ? stats.vectorsByStatus.map((v: any) => (
                        <div key={v.status} className="flex items-center justify-between">
                          <Badge variant="outline" className={statusColor(v.status)}>{v.status}</Badge>
                          <span className="text-sm font-mono">{v.count}</span>
                        </div>
                      )) : (
                        <p className="text-sm text-muted-foreground">No vectors yet</p>
                      )}
                    </div>
                  </CardContent>
                </Card>
              </div>

              {/* Recent Engagements */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Recent Engagements</CardTitle>
                </CardHeader>
                <CardContent>
                  {stats.recentEngagements?.length > 0 ? (
                    <div className="space-y-2">
                      {stats.recentEngagements.map((e: any) => (
                        <div key={e.id} className="flex items-center justify-between p-2 rounded-lg bg-accent/30">
                          <div className="flex items-center gap-3">
                            <Target className="h-4 w-4 text-muted-foreground" />
                            <span className="text-sm font-medium">{e.name}</span>
                          </div>
                          <div className="flex items-center gap-2">
                            <Badge variant="outline" className={statusColor(e.status)}>{e.status}</Badge>
                            <Badge variant="outline">{e.type}</Badge>
                          </div>
                        </div>
                      ))}
                    </div>
                  ) : (
                    <p className="text-sm text-muted-foreground">No engagements yet. Create one from attack vectors to get started.</p>
                  )}
                </CardContent>
              </Card>
            </>
          ) : null}
        </TabsContent>

        {/* Automated Engagements Tab */}
        <TabsContent value="engagements" className="space-y-4">
          {automatedEngagements && automatedEngagements.length > 0 ? (
            automatedEngagements.map((item: any) => (
              <Card key={item.engagement.id}>
                <CardContent className="pt-6">
                  <div className="flex items-start justify-between">
                    <div className="space-y-2">
                      <div className="flex items-center gap-3">
                        <h3 className="font-semibold">{item.engagement.name}</h3>
                        <Badge variant="outline" className={statusColor(item.engagement.status)}>{item.engagement.status}</Badge>
                        {item.metadata?.riskLevel && (
                          <Badge variant="outline" className={riskColor(item.metadata.riskLevel)}>{item.metadata.riskLevel} risk</Badge>
                        )}
                      </div>
                      <p className="text-sm text-muted-foreground">{item.engagement.customerName} — {item.engagement.type}</p>
                      {item.metadata && (
                        <div className="flex items-center gap-4 text-xs text-muted-foreground">
                          {item.metadata.vectorCount && <span>{item.metadata.vectorCount} vectors</span>}
                          {item.metadata.techniqueCount && <span>{item.metadata.techniqueCount} techniques</span>}
                          {item.metadata.calderaAbilityCount && <span>{item.metadata.calderaAbilityCount} Caldera abilities</span>}
                          {item.metadata.exploitScriptCount && <span>{item.metadata.exploitScriptCount} exploits</span>}
                        </div>
                      )}
                      {item.metadata?.threatActors?.length > 0 && (
                        <div className="flex items-center gap-2 flex-wrap">
                          <span className="text-xs text-muted-foreground">Threat actors:</span>
                          {item.metadata.threatActors.map((a: any) => (
                            <Badge key={a.id} variant="outline" className="text-xs">{a.name}</Badge>
                          ))}
                        </div>
                      )}
                    </div>
                    <div className="flex items-center gap-2">
                      {item.pipeline && (
                        <div className="text-right">
                          <p className="text-xs text-muted-foreground">Pipeline: Step {item.pipeline.currentStep}/{item.pipeline.totalSteps}</p>
                          <Badge variant="outline" className={statusColor(item.pipeline.status)}>{item.pipeline.status}</Badge>
                          {item.pipeline.status !== "completed" && item.pipeline.status !== "failed" && (
                            <Button
                              size="sm"
                              variant="outline"
                              className="mt-2 gap-1"
                              onClick={() => advancePipeline.mutate({ pipelineId: item.pipeline.id, action: "next" })}
                            >
                              <ChevronRight className="h-3 w-3" /> Advance
                            </Button>
                          )}
                        </div>
                      )}
                    </div>
                  </div>
                  {item.playbooks?.length > 0 && (
                    <div className="mt-3 pt-3 border-t">
                      <p className="text-xs text-muted-foreground mb-2">Linked Playbooks:</p>
                      <div className="flex gap-2 flex-wrap">
                        {item.playbooks.map((p: any) => (
                          <Badge key={p.id} variant="secondary" className="gap-1">
                            <FileText className="h-3 w-3" /> {p.name}
                            <span className="text-xs opacity-70">({p.status})</span>
                          </Badge>
                        ))}
                      </div>
                    </div>
                  )}
                </CardContent>
              </Card>
            ))
          ) : (
            <Card>
              <CardContent className="py-12 text-center">
                <Zap className="h-12 w-12 text-muted-foreground mx-auto mb-4" />
                <h3 className="font-semibold mb-2">No Automated Engagements Yet</h3>
                <p className="text-sm text-muted-foreground mb-4">
                  Create an engagement from attack vectors to automatically load Caldera abilities and Metasploit modules.
                </p>
                <Button onClick={() => setShowCreateDialog(true)} className="gap-2">
                  <Play className="h-4 w-4" /> Create First Engagement
                </Button>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Templates Tab */}
        <TabsContent value="templates" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {templates?.map((t: any) => (
              <Card key={t.templateId} className="hover:border-primary/30 transition-colors">
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <Shield className="h-4 w-4 text-primary" />
                    {t.name}
                  </CardTitle>
                  <CardDescription>{t.description}</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">Kill Chain Coverage ({t.killChainPhases.length} phases)</p>
                      <div className="flex flex-wrap gap-1">
                        {t.killChainPhases.map((phase: string) => (
                          <Badge key={phase} variant="outline" className="text-xs">
                            {phase.replace(/_/g, " ")}
                          </Badge>
                        ))}
                      </div>
                    </div>
                    <div>
                      <p className="text-xs text-muted-foreground mb-1">Recommended Techniques</p>
                      <div className="flex flex-wrap gap-1">
                        {t.recommendedTechniques.slice(0, 6).map((tech: string) => (
                          <Badge key={tech} variant="secondary" className="text-xs font-mono">{tech}</Badge>
                        ))}
                        {t.recommendedTechniques.length > 6 && (
                          <Badge variant="secondary" className="text-xs">+{t.recommendedTechniques.length - 6} more</Badge>
                        )}
                      </div>
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      className="w-full gap-2"
                      onClick={() => {
                        setSelectedTemplate(t.templateId);
                        setShowCreateDialog(true);
                      }}
                    >
                      <ArrowRight className="h-3 w-3" /> Use Template
                    </Button>
                  </div>
                </CardContent>
              </Card>
            ))}
          </div>
        </TabsContent>
      </Tabs>
    </div>
      </AppShell>
  );
}
