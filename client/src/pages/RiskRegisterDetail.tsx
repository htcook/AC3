import React, { useState } from "react";
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
import { ArrowLeft, Save, ShieldCheck, Clock, AlertTriangle, User, FileText, Shield, Activity, XCircle } from "lucide-react";

const SEV_COLORS: Record<string, string> = { critical: "bg-red-500/20 text-red-400 border-red-500/30", high: "bg-orange-500/20 text-orange-400 border-orange-500/30", moderate: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30", low: "bg-blue-500/20 text-blue-400 border-blue-500/30", informational: "bg-gray-500/20 text-gray-400 border-gray-500/30" };
const STATUS_LABELS: Record<string, string> = { open: "Open", in_progress: "In Progress", closed: "Closed", risk_accepted: "Risk Accepted", deferred: "Deferred", vendor_dependent: "Vendor Dependent" };

export default function RiskRegisterDetail() {
  const [, params] = useRoute("/risk-register/:id");
  const [, navigate] = useLocation();
  const id = Number(params?.id);
  const { data, isLoading, refetch } = trpc.riskRegister.get.useQuery({ id }, { enabled: !!id });
  const [editing, setEditing] = useState(false);
  const [form, setForm] = useState<any>({});
  const [riskDecision, setRiskDecision] = useState("");
  const [riskJustification, setRiskJustification] = useState("");

  const updateMut = trpc.riskRegister.update.useMutation({ onSuccess: () => { refetch(); setEditing(false); toast.success("Updated"); }, onError: (e: any) => toast.error(e.message) });
  const acceptRiskMut = trpc.riskRegister.acceptRisk.useMutation({ onSuccess: () => { refetch(); setRiskDecision(""); setRiskJustification(""); toast.success("Decision recorded"); }, onError: (e: any) => toast.error(e.message) });

  const startEdit = () => { if (!data) return; setForm({ weaknessName: data.weaknessName, weaknessDescription: data.weaknessDescription || "", controls: data.controls || "", assetIdentifier: data.assetIdentifier || "", pointOfContact: data.pointOfContact || "", remediationPlan: data.remediationPlan || "", scheduledCompletionDate: data.scheduledCompletionDate || "", status: data.status, severity: data.severity, comments: data.comments || "", resourcesRequired: data.resourcesRequired || "", milestones: data.milestones || "" }); setEditing(true); };
  const handleSave = () => { const updates: any = { id }; for (const [k, v] of Object.entries(form)) { if (v !== (data as any)?.[k]) updates[k] = v; } updateMut.mutate(updates); };

  if (isLoading) return <AppShell activePath="/risk-register"><div className="space-y-4">{Array.from({ length: 4 }).map((_, i) => <div key={i} className="h-32 bg-muted rounded-lg animate-pulse" />)}</div></AppShell>;
  if (!data) return <AppShell activePath="/risk-register"><div className="text-center py-20 text-muted-foreground"><XCircle className="h-12 w-12 mx-auto mb-3 opacity-30" /><p>Entry not found</p><Link href="/risk-register"><Button variant="outline" className="mt-4">Back</Button></Link></div></AppShell>;

  const isOverdue = data.scheduledCompletionDate && new Date(data.scheduledCompletionDate) < new Date() && !["closed", "risk_accepted"].includes(data.status);

  return (
    <AppShell activePath="/risk-register">
      <div className="space-y-6">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-3">
            <Link href="/risk-register"><Button variant="ghost" size="icon"><ArrowLeft className="h-5 w-5" /></Button></Link>
            <div>
              <div className="flex items-center gap-2 flex-wrap">
                <h1 className="text-2xl font-bold">{data.poamId}</h1>
                <Badge variant="outline" className={SEV_COLORS[data.severity]}>{data.severity}</Badge>
                <Badge variant="outline" className={data.status === "closed" ? "bg-green-500/20 text-green-400 border-green-500/30" : data.status === "risk_accepted" ? "bg-purple-500/20 text-purple-400 border-purple-500/30" : data.status === "open" ? "bg-red-500/20 text-red-400 border-red-500/30" : "bg-yellow-500/20 text-yellow-400 border-yellow-500/30"}>{STATUS_LABELS[data.status] || data.status}</Badge>
                {isOverdue && <Badge variant="outline" className="bg-red-500/20 text-red-400 border-red-500/30"><AlertTriangle className="h-3 w-3 mr-1" />Overdue</Badge>}
              </div>
              <p className="text-muted-foreground mt-1">{data.weaknessName}</p>
            </div>
          </div>
          <div className="flex items-center gap-2">
            {editing ? (<><Button variant="ghost" onClick={() => setEditing(false)}>Cancel</Button><Button onClick={handleSave} disabled={updateMut.isPending}><Save className="h-4 w-4 mr-1" />Save</Button></>) : <Button variant="outline" onClick={startEdit}>Edit</Button>}
          </div>
        </div>

        <Tabs defaultValue="details" className="space-y-4">
          <TabsList className="bg-muted/50">
            <TabsTrigger value="details"><FileText className="h-4 w-4 mr-1" />Details</TabsTrigger>
            <TabsTrigger value="risk"><Shield className="h-4 w-4 mr-1" />Risk Decision</TabsTrigger>
            <TabsTrigger value="activity"><Activity className="h-4 w-4 mr-1" />Activity Log</TabsTrigger>
          </TabsList>

          <TabsContent value="details" className="space-y-4">
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              <Card className="bg-card border-border">
                <CardHeader><CardTitle className="text-lg">Weakness Information</CardTitle></CardHeader>
                <CardContent className="space-y-4">
                  <div><Label className="text-muted-foreground text-xs">Weakness Name</Label>{editing ? <Input value={form.weaknessName} onChange={e => setForm({ ...form, weaknessName: e.target.value })} className="bg-muted/30" /> : <p className="font-medium">{data.weaknessName}</p>}</div>
                  <div><Label className="text-muted-foreground text-xs">Description</Label>{editing ? <Textarea value={form.weaknessDescription} onChange={e => setForm({ ...form, weaknessDescription: e.target.value })} className="bg-muted/30" rows={4} /> : <p className="text-sm">{data.weaknessDescription || "No description"}</p>}</div>
                  <div className="grid grid-cols-2 gap-3">
                    <div><Label className="text-muted-foreground text-xs">Detector Source</Label><p className="text-sm">{data.weaknessDetectorSource || "\u2014"}</p></div>
                    <div><Label className="text-muted-foreground text-xs">Source Identifier</Label><p className="text-sm font-mono">{data.weaknessSourceIdentifier || "\u2014"}</p></div>
                  </div>
                  <div><Label className="text-muted-foreground text-xs">Controls</Label>{editing ? <Input value={form.controls} onChange={e => setForm({ ...form, controls: e.target.value })} className="bg-muted/30" /> : <p className="text-sm">{data.controls || "\u2014"}</p>}</div>
                </CardContent>
              </Card>
              <Card className="bg-card border-border">
                <CardHeader><CardTitle className="text-lg">Remediation</CardTitle></CardHeader>
                <CardContent className="space-y-4">
                  <div className="grid grid-cols-2 gap-3">
                    <div><Label className="text-muted-foreground text-xs">Severity</Label>{editing ? <Select value={form.severity} onValueChange={v => setForm({ ...form, severity: v })}><SelectTrigger className="bg-muted/30"><SelectValue /></SelectTrigger><SelectContent>{["critical","high","moderate","low","informational"].map(s => <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>)}</SelectContent></Select> : <Badge variant="outline" className={SEV_COLORS[data.severity]}>{data.severity}</Badge>}</div>
                    <div><Label className="text-muted-foreground text-xs">Status</Label>{editing ? <Select value={form.status} onValueChange={v => setForm({ ...form, status: v })}><SelectTrigger className="bg-muted/30"><SelectValue /></SelectTrigger><SelectContent>{Object.entries(STATUS_LABELS).map(([k,v]) => <SelectItem key={k} value={k}>{v}</SelectItem>)}</SelectContent></Select> : <p className="font-medium">{STATUS_LABELS[data.status]}</p>}</div>
                  </div>
                  <div><Label className="text-muted-foreground text-xs">Asset</Label>{editing ? <Input value={form.assetIdentifier} onChange={e => setForm({ ...form, assetIdentifier: e.target.value })} className="bg-muted/30" /> : <p className="text-sm font-mono">{data.assetIdentifier || "\u2014"}</p>}</div>
                  <div><Label className="text-muted-foreground text-xs">Point of Contact</Label>{editing ? <Input value={form.pointOfContact} onChange={e => setForm({ ...form, pointOfContact: e.target.value })} className="bg-muted/30" /> : <p className="text-sm">{data.pointOfContact || "\u2014"}</p>}</div>
                  <div><Label className="text-muted-foreground text-xs">Remediation Plan</Label>{editing ? <Textarea value={form.remediationPlan} onChange={e => setForm({ ...form, remediationPlan: e.target.value })} className="bg-muted/30" rows={3} /> : <p className="text-sm">{data.remediationPlan || "No plan defined"}</p>}</div>
                  <div className="grid grid-cols-2 gap-3">
                    <div><Label className="text-muted-foreground text-xs">Scheduled Completion</Label>{editing ? <Input type="date" value={form.scheduledCompletionDate} onChange={e => setForm({ ...form, scheduledCompletionDate: e.target.value })} className="bg-muted/30" /> : <p className="text-sm">{data.scheduledCompletionDate ? new Date(data.scheduledCompletionDate).toLocaleDateString() : "\u2014"}</p>}</div>
                    <div><Label className="text-muted-foreground text-xs">Detection Date</Label><p className="text-sm">{data.originalDetectionDate ? new Date(data.originalDetectionDate).toLocaleDateString() : "\u2014"}</p></div>
                  </div>
                  <div><Label className="text-muted-foreground text-xs">Milestones</Label>{editing ? <Textarea value={form.milestones} onChange={e => setForm({ ...form, milestones: e.target.value })} className="bg-muted/30" rows={2} /> : <p className="text-sm">{data.milestones || "\u2014"}</p>}</div>
                </CardContent>
              </Card>
            </div>
            <Card className="bg-card border-border"><CardContent className="p-4"><div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
              <div><span className="text-muted-foreground text-xs block">Source</span><span className="capitalize">{data.source.replace(/_/g, " ")}</span></div>
              <div><span className="text-muted-foreground text-xs block">Original Risk Rating</span><Badge variant="outline" className={SEV_COLORS[data.originalRiskRating]}>{data.originalRiskRating}</Badge></div>
              <div><span className="text-muted-foreground text-xs block">Vendor Dependency</span><span>{data.vendorDependency ? "Yes" : "No"}</span></div>
              <div><span className="text-muted-foreground text-xs block">Attack Chain</span>{data.attackChainId ? <Link href="/attack-chains"><span className="text-primary cursor-pointer hover:underline font-mono text-xs">{data.attackChainId}</span></Link> : "\u2014"}</div>
            </div></CardContent></Card>
          </TabsContent>

          <TabsContent value="risk" className="space-y-4">
            <Card className="bg-card border-border">
              <CardHeader><CardTitle className="text-lg flex items-center gap-2"><ShieldCheck className="h-5 w-5 text-primary" />Risk Decision</CardTitle></CardHeader>
              <CardContent className="space-y-4">
                {data.riskDecision ? <div className="p-4 bg-muted/30 rounded-lg space-y-2"><div className="flex items-center gap-2"><Badge variant="outline" className="capitalize">{data.riskDecision}</Badge><span className="text-sm text-muted-foreground">by {data.riskDecisionBy}</span>{data.riskDecisionDate && <span className="text-xs text-muted-foreground">{new Date(data.riskDecisionDate).toLocaleDateString()}</span>}</div><p className="text-sm">{data.riskDecisionJustification}</p></div> : <p className="text-muted-foreground text-sm">No risk decision has been made yet.</p>}
                <Separator /><h3 className="font-medium">Record New Decision</h3>
                <Select value={riskDecision} onValueChange={setRiskDecision}><SelectTrigger className="bg-muted/30 w-[200px]"><SelectValue placeholder="Select decision..." /></SelectTrigger><SelectContent><SelectItem value="mitigate">Mitigate</SelectItem><SelectItem value="accept">Accept Risk</SelectItem><SelectItem value="transfer">Transfer</SelectItem><SelectItem value="defer">Defer</SelectItem><SelectItem value="avoid">Avoid</SelectItem></SelectContent></Select>
                <Textarea value={riskJustification} onChange={e => setRiskJustification(e.target.value)} placeholder="Provide rationale..." className="bg-muted/30" rows={4} />
                <Button disabled={!riskDecision || !riskJustification || acceptRiskMut.isPending} onClick={() => acceptRiskMut.mutate({ id, decision: riskDecision as any, justification: riskJustification })}><ShieldCheck className="h-4 w-4 mr-1" />Record Decision</Button>
              </CardContent>
            </Card>
          </TabsContent>

          <TabsContent value="activity">
            <Card className="bg-card border-border">
              <CardHeader><CardTitle className="text-lg flex items-center gap-2"><Clock className="h-5 w-5 text-primary" />Activity Log</CardTitle></CardHeader>
              <CardContent>{data.activityLog?.length ? <div className="space-y-3">{data.activityLog.map((log: any) => <div key={log.id} className="flex items-start gap-3 p-3 bg-muted/20 rounded-lg"><div className="h-8 w-8 rounded-full bg-primary/20 flex items-center justify-center flex-shrink-0"><User className="h-4 w-4 text-primary" /></div><div className="flex-1 min-w-0"><div className="flex items-center gap-2 flex-wrap"><span className="font-medium text-sm">{log.performedBy}</span><Badge variant="outline" className="text-xs">{log.action.replace(/_/g, " ")}</Badge><span className="text-xs text-muted-foreground ml-auto">{new Date(log.createdAt).toLocaleString()}</span></div>{log.details && <p className="text-sm text-muted-foreground mt-1">{log.details}</p>}</div></div>)}</div> : <p className="text-muted-foreground text-sm text-center py-8">No activity recorded yet</p>}</CardContent>
            </Card>
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
