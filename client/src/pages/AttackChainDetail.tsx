import React, { useState, useMemo, useRef, useEffect } from "react";
import { useRoute, useLocation, Link } from "wouter";
import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { toast } from "sonner";
import {
  ArrowLeft, Save, GitBranch, Shield, Activity, Target, Zap, ArrowRight,
  XCircle, Plus, Trash2, ChevronRight, Network,
} from "lucide-react";

const SEV_COLORS: Record<string, string> = { critical: "bg-red-500/20 text-red-400 border-red-500/30", high: "bg-orange-500/20 text-orange-400 border-orange-500/30", moderate: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30", low: "bg-blue-500/20 text-blue-400 border-blue-500/30", informational: "bg-gray-500/20 text-gray-400 border-gray-500/30" };
const STATUS_COLORS: Record<string, string> = { active: "bg-red-500/20 text-red-400 border-red-500/30", mitigated: "bg-green-500/20 text-green-400 border-green-500/30", accepted: "bg-purple-500/20 text-purple-400 border-purple-500/30", investigating: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30" };

function ScoreBadge({ score, size = "lg" }: { score: number | null; size?: "sm" | "lg" }) {
  if (score === null || score === undefined) return <span className="text-muted-foreground">\u2014</span>;
  const color = score >= 9 ? "text-red-400" : score >= 7 ? "text-orange-400" : score >= 4 ? "text-yellow-400" : "text-blue-400";
  const bg = score >= 9 ? "bg-red-500/10 border-red-500/30" : score >= 7 ? "bg-orange-500/10 border-orange-500/30" : score >= 4 ? "bg-yellow-500/10 border-yellow-500/30" : "bg-blue-500/10 border-blue-500/30";
  return size === "lg" ? (
    <div className={`inline-flex items-center gap-2 px-4 py-2 rounded-lg border ${bg}`}>
      <span className={`font-mono font-bold text-3xl ${color}`}>{score.toFixed(1)}</span>
      <span className="text-xs text-muted-foreground">/10.0</span>
    </div>
  ) : <span className={`font-mono font-bold ${color}`}>{score.toFixed(1)}</span>;
}

// Simple attack chain graph visualization using SVG
function ChainGraph({ steps }: { steps: any[] }) {
  const sorted = useMemo(() => [...steps].sort((a, b) => a.stepOrder - b.stepOrder), [steps]);
  if (!sorted.length) return <div className="text-center py-12 text-muted-foreground">No steps defined</div>;

  const nodeWidth = 200;
  const nodeHeight = 90;
  const gap = 60;
  const svgWidth = sorted.length * (nodeWidth + gap) - gap + 40;
  const svgHeight = nodeHeight + 80;

  return (
    <div className="overflow-x-auto pb-4">
      <svg width={svgWidth} height={svgHeight} className="min-w-full">
        {sorted.map((step, i) => {
          const x = 20 + i * (nodeWidth + gap);
          const y = 30;
          const sevColor = step.severity === "critical" ? "#ef4444" : step.severity === "high" ? "#f97316" : step.severity === "moderate" ? "#eab308" : "#3b82f6";
          return (
            <g key={step.id}>
              {/* Connection arrow */}
              {i > 0 && (
                <>
                  <line x1={x - gap + 4} y1={y + nodeHeight / 2} x2={x - 8} y2={y + nodeHeight / 2} stroke="#525252" strokeWidth="2" markerEnd="url(#arrowhead)" />
                </>
              )}
              {/* Node */}
              <rect x={x} y={y} width={nodeWidth} height={nodeHeight} rx="8" fill="#1a1a2e" stroke={sevColor} strokeWidth="2" opacity="0.9" />
              <text x={x + 10} y={y + 20} fill="#e2e8f0" fontSize="11" fontWeight="bold">Step {step.stepOrder}</text>
              <text x={x + 10} y={y + 38} fill="#94a3b8" fontSize="10" textAnchor="start">
                {(step.vulnerabilityName || "Unknown").substring(0, 28)}
              </text>
              <text x={x + 10} y={y + 54} fill="#64748b" fontSize="9">
                {(step.assetIdentifier || "").substring(0, 30)}
              </text>
              <rect x={x + 10} y={y + 62} width={50} height={18} rx="4" fill={sevColor} opacity="0.2" />
              <text x={x + 35} y={y + 74} fill={sevColor} fontSize="9" textAnchor="middle" fontWeight="bold">{step.severity}</text>
              {step.mitreTacticId && <text x={x + nodeWidth - 10} y={y + 74} fill="#6366f1" fontSize="8" textAnchor="end">{step.mitreTacticId}</text>}
            </g>
          );
        })}
        <defs>
          <marker id="arrowhead" markerWidth="10" markerHeight="7" refX="10" refY="3.5" orient="auto">
            <polygon points="0 0, 10 3.5, 0 7" fill="#525252" />
          </marker>
        </defs>
      </svg>
    </div>
  );
}

export default function AttackChainDetail() {
  const [, params] = useRoute("/attack-chains/:id");
  const [, navigate] = useLocation();
  const id = Number(params?.id);
  const { data, isLoading, refetch } = trpc.attackChains.get.useQuery({ id }, { enabled: !!id });
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState<any>({});

  // Add step form
  const [showAddStep, setShowAddStep] = useState(false);
  const [stepForm, setStepForm] = useState({ vulnerabilityName: "", assetIdentifier: "", severity: "moderate", mitreTacticId: "", mitreTechnique: "", description: "" });

  const updateMut = trpc.attackChains.update.useMutation({ onSuccess: () => { refetch(); setEditing(false); toast.success("Updated"); }, onError: (e: any) => toast.error(e.message) });
  const addStepMut = trpc.attackChains.addStep.useMutation({ onSuccess: () => { refetch(); setShowAddStep(false); setStepForm({ vulnerabilityName: "", assetIdentifier: "", severity: "moderate", mitreTacticId: "", mitreTechnique: "", description: "" }); toast.success("Step added"); }, onError: (e: any) => toast.error(e.message) });
  const removeStepMut = trpc.attackChains.removeStep.useMutation({ onSuccess: () => { refetch(); toast.success("Step removed"); }, onError: (e: any) => toast.error(e.message) });
  const recalcMut = trpc.attackChains.recalculateScore.useMutation({ onSuccess: () => { refetch(); toast.success("Score recalculated"); }, onError: (e: any) => toast.error(e.message) });

  const startEdit = () => { if (!data) return; setForm({ name: data.name, description: data.description || "", status: data.status, entryPoint: data.entryPoint || "", finalTarget: data.finalTarget || "", mitreTactics: data.mitreTactics || "" }); setEditing(true); };
  const handleSave = () => { const updates: any = { id, chainId: data!.chainId }; for (const [k, v] of Object.entries(form)) { if (v !== (data as any)?.[k]) updates[k] = v; } updateMut.mutate(updates); };

  if (isLoading) return <AppShell activePath="/attack-chains"><div className="space-y-4">{Array.from({ length: 4 }).map((_, i) => <div key={i} className="h-32 bg-muted rounded-lg animate-pulse" />)}</div></AppShell>;
  if (!data) return <AppShell activePath="/attack-chains"><div className="text-center py-20 text-muted-foreground"><XCircle className="h-12 w-12 mx-auto mb-3 opacity-30" /><p>Chain not found</p><Link href="/attack-chains"><Button variant="outline" className="mt-4">Back</Button></Link></div></AppShell>;

  const steps = data.steps || [];

  return (
    <AppShell activePath="/attack-chains">
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link href="/attack-chains"><Button variant="ghost" size="icon"><ArrowLeft className="h-5 w-5" /></Button></Link>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h1 className="text-2xl font-bold">{data.name}</h1>
                <Badge variant="outline" className={SEV_COLORS[data.compositeSeverity]}>{data.compositeSeverity}</Badge>
                <Badge variant="outline" className={STATUS_COLORS[data.status] || ""}>{data.status}</Badge>
              </div>
              <p className="text-muted-foreground mt-1 font-mono text-sm">{data.chainId}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Button variant="outline" size="sm" onClick={() => recalcMut.mutate({ id, chainId: data.chainId })} disabled={recalcMut.isPending}>
              <Zap className="h-4 w-4 mr-1" />Recalculate
            </Button>
            {editing ? (<><Button variant="ghost" onClick={() => setEditing(false)}>Cancel</Button><Button onClick={handleSave} disabled={updateMut.isPending}><Save className="h-4 w-4 mr-1" />Save</Button></>) : <Button variant="outline" onClick={startEdit}>Edit</Button>}
          </div>
        </div>

        {/* Score + Summary */}
        <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
          <Card className="bg-card border-border md:col-span-1">
            <CardContent className="p-6 text-center">
              <p className="text-xs text-muted-foreground mb-2">Composite Risk Score</p>
              <ScoreBadge score={data.compositeRiskScore} />
              <p className="text-xs text-muted-foreground mt-2">{steps.length} steps in chain</p>
            </CardContent>
          </Card>
          <Card className="bg-card border-border md:col-span-3">
            <CardContent className="p-4 grid grid-cols-2 md:grid-cols-4 gap-4">
              <div><Label className="text-muted-foreground text-xs">Entry Point</Label>{editing ? <Input value={form.entryPoint} onChange={e => setForm({ ...form, entryPoint: e.target.value })} className="bg-muted/30" /> : <p className="text-sm font-medium">{data.entryPoint || "\u2014"}</p>}</div>
              <div><Label className="text-muted-foreground text-xs">Final Target</Label>{editing ? <Input value={form.finalTarget} onChange={e => setForm({ ...form, finalTarget: e.target.value })} className="bg-muted/30" /> : <p className="text-sm font-medium">{data.finalTarget || "\u2014"}</p>}</div>
              <div><Label className="text-muted-foreground text-xs">Status</Label>{editing ? <Select value={form.status} onValueChange={v => setForm({ ...form, status: v })}><SelectTrigger className="bg-muted/30"><SelectValue /></SelectTrigger><SelectContent><SelectItem value="active">Active</SelectItem><SelectItem value="mitigated">Mitigated</SelectItem><SelectItem value="accepted">Accepted</SelectItem><SelectItem value="investigating">Investigating</SelectItem></SelectContent></Select> : <Badge variant="outline" className={STATUS_COLORS[data.status]}>{data.status}</Badge>}</div>
              <div><Label className="text-muted-foreground text-xs">MITRE Tactics</Label>{editing ? <Input value={form.mitreTactics} onChange={e => setForm({ ...form, mitreTactics: e.target.value })} className="bg-muted/30" /> : <p className="text-sm">{data.mitreTactics || "\u2014"}</p>}</div>
            </CardContent>
          </Card>
        </div>

        <Tabs defaultValue="graph" className="space-y-4">
          <TabsList className="bg-muted/50">
            <TabsTrigger value="graph"><Network className="h-4 w-4 mr-1" />Chain Graph</TabsTrigger>
            <TabsTrigger value="steps"><Target className="h-4 w-4 mr-1" />Steps ({steps.length})</TabsTrigger>
            <TabsTrigger value="details"><Shield className="h-4 w-4 mr-1" />Details</TabsTrigger>
          </TabsList>

          <TabsContent value="graph">
            <Card className="bg-card border-border">
              <CardHeader><CardTitle className="text-lg flex items-center gap-2"><Network className="h-5 w-5 text-primary" />Attack Path Visualization</CardTitle></CardHeader>
              <CardContent>
                <ChainGraph steps={steps} />
                {steps.length > 0 && (
                  <div className="mt-4 p-3 bg-muted/20 rounded-lg">
                    <p className="text-xs text-muted-foreground">
                      <strong>Kill Chain:</strong> {data.entryPoint || "Entry"} {steps.map((s: any) => `→ ${s.vulnerabilityName || "Step " + s.stepOrder}`).join(" ")} → {data.finalTarget || "Target"}
                    </p>
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="steps" className="space-y-4">
            <div className="flex items-center justify-between">
              <h3 className="font-medium">Chain Steps</h3>
              <Button size="sm" onClick={() => setShowAddStep(true)}><Plus className="h-4 w-4 mr-1" />Add Step</Button>
            </div>

            {showAddStep && (
              <Card className="bg-card border-primary/30">
                <CardHeader><CardTitle className="text-sm">New Step</CardTitle></CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <div><Label>Vulnerability Name *</Label><Input value={stepForm.vulnerabilityName} onChange={e => setStepForm({ ...stepForm, vulnerabilityName: e.target.value })} className="bg-muted/30" /></div>
                    <div><Label>Asset Identifier</Label><Input value={stepForm.assetIdentifier} onChange={e => setStepForm({ ...stepForm, assetIdentifier: e.target.value })} className="bg-muted/30" /></div>
                  </div>
                  <div className="grid grid-cols-3 gap-3">
                    <div><Label>Severity</Label><Select value={stepForm.severity} onValueChange={v => setStepForm({ ...stepForm, severity: v })}><SelectTrigger className="bg-muted/30"><SelectValue /></SelectTrigger><SelectContent>{["critical","high","moderate","low","informational"].map(s => <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>)}</SelectContent></Select></div>
                    <div><Label>MITRE Tactic</Label><Input value={stepForm.mitreTacticId} onChange={e => setStepForm({ ...stepForm, mitreTacticId: e.target.value })} placeholder="e.g., TA0001" className="bg-muted/30" /></div>
                    <div><Label>MITRE Technique</Label><Input value={stepForm.mitreTechnique} onChange={e => setStepForm({ ...stepForm, mitreTechnique: e.target.value })} placeholder="e.g., T1566" className="bg-muted/30" /></div>
                  </div>
                  <div><Label>Description</Label><Textarea value={stepForm.description} onChange={e => setStepForm({ ...stepForm, description: e.target.value })} className="bg-muted/30" rows={2} /></div>
                  <div className="flex gap-2"><Button size="sm" disabled={!stepForm.vulnerabilityName || addStepMut.isPending} onClick={() => addStepMut.mutate({ chainId: id, ...stepForm, stepOrder: steps.length + 1 })}><Plus className="h-4 w-4 mr-1" />Add</Button><Button size="sm" variant="ghost" onClick={() => setShowAddStep(false)}>Cancel</Button></div>
                </CardContent>
              </Card>
            )}

            {steps.length === 0 ? (
              <Card className="bg-card border-border"><CardContent className="py-12 text-center text-muted-foreground"><Target className="h-12 w-12 mx-auto mb-3 opacity-30" /><p>No steps defined yet</p></CardContent></Card>
            ) : (
              <div className="space-y-3">
                {[...steps].sort((a: any, b: any) => a.stepOrder - b.stepOrder).map((step: any, i: number) => (
                  <Card key={step.id} className="bg-card border-border">
                    <CardContent className="p-4">
                      <div className="flex items-start gap-4">
                        <div className="flex-shrink-0 h-10 w-10 rounded-full bg-primary/20 flex items-center justify-center font-bold text-primary">{step.stepOrder}</div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className="font-medium">{step.vulnerabilityName}</span>
                            <Badge variant="outline" className={SEV_COLORS[step.severity]}>{step.severity}</Badge>
                            {step.mitreTacticId && <Badge variant="outline" className="bg-indigo-500/20 text-indigo-400 border-indigo-500/30">{step.mitreTacticId}</Badge>}
                            {step.mitreTechnique && <Badge variant="outline" className="bg-violet-500/20 text-violet-400 border-violet-500/30">{step.mitreTechnique}</Badge>}
                          </div>
                          {step.assetIdentifier && <p className="text-sm text-muted-foreground font-mono mt-1">{step.assetIdentifier}</p>}
                          {step.description && <p className="text-sm text-muted-foreground mt-1">{step.description}</p>}
                          {step.riskRegisterEntryId && <Link href={`/risk-register/${step.riskRegisterEntryId}`}><span className="text-xs text-primary hover:underline cursor-pointer">View POA&M Entry →</span></Link>}
                        </div>
                        <Button variant="ghost" size="icon" className="h-7 w-7 text-muted-foreground hover:text-red-400" onClick={() => { if (confirm("Remove step?")) removeStepMut.mutate({ stepId: step.id, chainId: id }); }}>
                          <Trash2 className="h-4 w-4" />
                        </Button>
                      </div>
                      {i < steps.length - 1 && <div className="flex justify-center mt-3"><ChevronRight className="h-5 w-5 text-muted-foreground rotate-90" /></div>}
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </TabsContent>

          <TabsContent value="details">
            <Card className="bg-card border-border">
              <CardHeader><CardTitle className="text-lg">Chain Details</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                <div><Label className="text-muted-foreground text-xs">Name</Label>{editing ? <Input value={form.name} onChange={e => setForm({ ...form, name: e.target.value })} className="bg-muted/30" /> : <p className="font-medium">{data.name}</p>}</div>
                <div><Label className="text-muted-foreground text-xs">Description</Label>{editing ? <Textarea value={form.description} onChange={e => setForm({ ...form, description: e.target.value })} className="bg-muted/30" rows={4} /> : <p className="text-sm">{data.description || "No description"}</p>}</div>
                <Separator />
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div><span className="text-muted-foreground text-xs block">Created</span>{new Date(data.createdAt).toLocaleString()}</div>
                  <div><span className="text-muted-foreground text-xs block">Updated</span>{new Date(data.updatedAt).toLocaleString()}</div>
                  <div><span className="text-muted-foreground text-xs block">Created By</span>{data.createdBy || "\u2014"}</div>
                  <div><span className="text-muted-foreground text-xs block">Engagement</span>{data.engagementId ? <Link href={`/engagements/${data.engagementId}`}><span className="text-primary hover:underline cursor-pointer">#{data.engagementId}</span></Link> : "\u2014"}</div>
                </div>
              </CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
