import React, { useState } from "react";
import { useLocation, Link } from "wouter";
import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Label } from "@/components/ui/label";
import { Separator } from "@/components/ui/separator";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import { ArrowLeft, Plus, Upload } from "lucide-react";

export default function RiskRegisterNew() {
  const [, navigate] = useLocation();
  const [form, setForm] = useState({ weaknessName: "", weaknessDescription: "", controls: "", weaknessDetectorSource: "", weaknessSourceIdentifier: "", assetIdentifier: "", pointOfContact: "", resourcesRequired: "", remediationPlan: "", originalDetectionDate: "", scheduledCompletionDate: "", milestones: "", vendorDependency: false, vendorDependentProductName: "", originalRiskRating: "moderate" as const, severity: "moderate" as const, source: "manual" as const, comments: "" });
  const [engagementId, setEngagementId] = useState<number | null>(null);
  const createMut = trpc.riskRegister.create.useMutation({ onSuccess: (d: any) => { toast.success(`Created ${d.poamId}`); navigate(`/risk-register/${d.id}`); }, onError: (e: any) => toast.error(e.message) });
  const autoPopulate = trpc.riskRegister.autoPopulateFromEngagement.useMutation({ onSuccess: (d: any) => { toast.success(`Created ${d.created}, skipped ${d.skipped}`); navigate("/risk-register"); }, onError: (e: any) => toast.error(e.message) });
  const reports = trpc.riskRegister.availableReports.useQuery();
  const set = (k: string, v: any) => setForm(f => ({ ...f, [k]: v }));

  return (
    <AppShell activePath="/risk-register">
      <div className="space-y-6 max-w-4xl">
        <div className="flex items-center gap-3"><Link href="/risk-register"><Button variant="ghost" size="icon"><ArrowLeft className="h-5 w-5" /></Button></Link><div><h1 className="text-2xl font-bold">New Risk Register Entry</h1><p className="text-muted-foreground">Create a manual POA&M entry or import from an engagement</p></div></div>
        <Card className="bg-card border-border"><CardHeader><CardTitle className="text-lg flex items-center gap-2"><Upload className="h-5 w-5 text-primary" />Import from Engagement</CardTitle></CardHeader><CardContent className="space-y-3"><p className="text-sm text-muted-foreground">Auto-populate from findings. Duplicates are skipped.</p><div className="flex items-center gap-3"><Select value={engagementId?.toString() || ""} onValueChange={v => setEngagementId(Number(v))}><SelectTrigger className="w-[400px] bg-muted/30"><SelectValue placeholder="Select engagement..." /></SelectTrigger><SelectContent>{reports.data?.map((r: any) => <SelectItem key={r.id} value={r.id.toString()}>{r.name} ({r.customerName})</SelectItem>)}</SelectContent></Select><Button variant="outline" disabled={!engagementId || autoPopulate.isPending} onClick={() => engagementId && autoPopulate.mutate({ engagementId })}><Upload className="h-4 w-4 mr-1" />{autoPopulate.isPending ? "Importing..." : "Import"}</Button></div></CardContent></Card>
        <div className="flex items-center gap-3"><Separator className="flex-1" /><span className="text-sm text-muted-foreground">or create manually</span><Separator className="flex-1" /></div>
        <form onSubmit={e => { e.preventDefault(); createMut.mutate(form); }} className="space-y-4">
          <Card className="bg-card border-border"><CardHeader><CardTitle className="text-lg">Weakness Details</CardTitle></CardHeader><CardContent className="space-y-4">
            <div><Label>Weakness Name *</Label><Input value={form.weaknessName} onChange={e => set("weaknessName", e.target.value)} placeholder="e.g., SQL Injection in Login Form" className="bg-muted/30" required /></div>
            <div><Label>Description</Label><Textarea value={form.weaknessDescription} onChange={e => set("weaknessDescription", e.target.value)} placeholder="Detailed description..." className="bg-muted/30" rows={3} /></div>
            <div className="grid grid-cols-2 gap-4"><div><Label>Detector Source</Label><Input value={form.weaknessDetectorSource} onChange={e => set("weaknessDetectorSource", e.target.value)} placeholder="e.g., Nessus" className="bg-muted/30" /></div><div><Label>Source Identifier</Label><Input value={form.weaknessSourceIdentifier} onChange={e => set("weaknessSourceIdentifier", e.target.value)} placeholder="e.g., CVE-2024-1234" className="bg-muted/30" /></div></div>
            <div><Label>Controls (NIST 800-53)</Label><Input value={form.controls} onChange={e => set("controls", e.target.value)} placeholder="e.g., AC-2, SI-10" className="bg-muted/30" /></div>
          </CardContent></Card>
          <Card className="bg-card border-border"><CardHeader><CardTitle className="text-lg">Assessment & Remediation</CardTitle></CardHeader><CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4"><div><Label>Severity</Label><Select value={form.severity} onValueChange={v => set("severity", v)}><SelectTrigger className="bg-muted/30"><SelectValue /></SelectTrigger><SelectContent>{["critical","high","moderate","low","informational"].map(s => <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>)}</SelectContent></Select></div><div><Label>Original Risk Rating</Label><Select value={form.originalRiskRating} onValueChange={v => set("originalRiskRating", v)}><SelectTrigger className="bg-muted/30"><SelectValue /></SelectTrigger><SelectContent>{["critical","high","moderate","low","informational"].map(s => <SelectItem key={s} value={s} className="capitalize">{s}</SelectItem>)}</SelectContent></Select></div></div>
            <div className="grid grid-cols-2 gap-4"><div><Label>Asset Identifier</Label><Input value={form.assetIdentifier} onChange={e => set("assetIdentifier", e.target.value)} placeholder="e.g., web-server-01.pbs.org" className="bg-muted/30" /></div><div><Label>Point of Contact</Label><Input value={form.pointOfContact} onChange={e => set("pointOfContact", e.target.value)} placeholder="e.g., John Smith" className="bg-muted/30" /></div></div>
            <div><Label>Remediation Plan</Label><Textarea value={form.remediationPlan} onChange={e => set("remediationPlan", e.target.value)} placeholder="Steps to remediate..." className="bg-muted/30" rows={3} /></div>
            <div className="grid grid-cols-2 gap-4"><div><Label>Detection Date</Label><Input type="date" value={form.originalDetectionDate} onChange={e => set("originalDetectionDate", e.target.value)} className="bg-muted/30" /></div><div><Label>Scheduled Completion</Label><Input type="date" value={form.scheduledCompletionDate} onChange={e => set("scheduledCompletionDate", e.target.value)} className="bg-muted/30" /></div></div>
            <div><Label>Milestones</Label><Textarea value={form.milestones} onChange={e => set("milestones", e.target.value)} placeholder="Key milestones..." className="bg-muted/30" rows={2} /></div>
            <div><Label>Resources Required</Label><Input value={form.resourcesRequired} onChange={e => set("resourcesRequired", e.target.value)} placeholder="e.g., 2 FTE, $50K" className="bg-muted/30" /></div>
            <div className="flex items-center gap-3"><Switch checked={form.vendorDependency} onCheckedChange={v => set("vendorDependency", v)} /><Label>Vendor Dependency</Label></div>
            {form.vendorDependency && <div><Label>Vendor Product Name</Label><Input value={form.vendorDependentProductName} onChange={e => set("vendorDependentProductName", e.target.value)} className="bg-muted/30" /></div>}
            <div><Label>Source</Label><Select value={form.source} onValueChange={v => set("source", v)}><SelectTrigger className="bg-muted/30 w-[200px]"><SelectValue /></SelectTrigger><SelectContent>{["manual","engagement","ctem_scan","vulnerability_scan","pentest","red_team","bug_bounty"].map(s => <SelectItem key={s} value={s}>{s.replace(/_/g," ")}</SelectItem>)}</SelectContent></Select></div>
            <div><Label>Comments</Label><Textarea value={form.comments} onChange={e => set("comments", e.target.value)} placeholder="Additional notes..." className="bg-muted/30" rows={2} /></div>
          </CardContent></Card>
          <div className="flex justify-end gap-3"><Link href="/risk-register"><Button variant="outline">Cancel</Button></Link><Button type="submit" disabled={!form.weaknessName || createMut.isPending}><Plus className="h-4 w-4 mr-1" />{createMut.isPending ? "Creating..." : "Create Entry"}</Button></div>
        </form>
      </div>
    </AppShell>
  );
}
