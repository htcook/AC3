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
import { toast } from "sonner";
import { ArrowLeft, Plus, GitBranch } from "lucide-react";

export default function AttackChainNew() {
  const [, navigate] = useLocation();
  const [form, setForm] = useState({
    name: "", description: "", entryPoint: "", finalTarget: "",
    mitreTactics: "", status: "active" as const,
  });

  const createMut = trpc.attackChains.create.useMutation({
    onSuccess: (d: any) => { toast.success(`Created chain ${d.chainId}`); navigate(`/attack-chains/${d.id}`); },
    onError: (e: any) => toast.error(e.message),
  });

  const set = (k: string, v: any) => setForm(f => ({ ...f, [k]: v }));

  return (
    <AppShell activePath="/attack-chains">
      <div className="space-y-6 max-w-3xl">
        <div className="flex items-center gap-3">
          <Link href="/attack-chains"><Button variant="ghost" size="icon"><ArrowLeft className="h-5 w-5" /></Button></Link>
          <div>
            <h1 className="text-2xl font-bold">New Attack Chain</h1>
            <p className="text-muted-foreground">Define a linked vulnerability chain with composite risk scoring</p>
          </div>
        </div>

        <form onSubmit={e => { e.preventDefault(); createMut.mutate(form); }} className="space-y-4">
          <Card className="bg-card border-border">
            <CardHeader><CardTitle className="text-lg flex items-center gap-2"><GitBranch className="h-5 w-5 text-primary" />Chain Definition</CardTitle></CardHeader>
            <CardContent className="space-y-4">
              <div>
                <Label>Chain Name *</Label>
                <Input value={form.name} onChange={e => set("name", e.target.value)} placeholder="e.g., External RCE to Domain Admin via Kerberoasting" className="bg-muted/30" required />
              </div>
              <div>
                <Label>Description</Label>
                <Textarea value={form.description} onChange={e => set("description", e.target.value)} placeholder="Describe the full attack path and its business impact..." className="bg-muted/30" rows={4} />
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>Entry Point</Label>
                  <Input value={form.entryPoint} onChange={e => set("entryPoint", e.target.value)} placeholder="e.g., Public-facing web app (10.0.1.50)" className="bg-muted/30" />
                </div>
                <div>
                  <Label>Final Target</Label>
                  <Input value={form.finalTarget} onChange={e => set("finalTarget", e.target.value)} placeholder="e.g., Domain Controller (DC01)" className="bg-muted/30" />
                </div>
              </div>
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label>MITRE Tactics</Label>
                  <Input value={form.mitreTactics} onChange={e => set("mitreTactics", e.target.value)} placeholder="e.g., Initial Access, Privilege Escalation, Lateral Movement" className="bg-muted/30" />
                </div>
                <div>
                  <Label>Status</Label>
                  <Select value={form.status} onValueChange={v => set("status", v)}>
                    <SelectTrigger className="bg-muted/30"><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="active">Active</SelectItem>
                      <SelectItem value="investigating">Investigating</SelectItem>
                      <SelectItem value="mitigated">Mitigated</SelectItem>
                      <SelectItem value="accepted">Accepted</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
            </CardContent>
          </Card>

          <div className="p-4 bg-muted/20 rounded-lg">
            <p className="text-sm text-muted-foreground">
              <strong>Tip:</strong> After creating the chain, you can add individual vulnerability steps from the detail page. Each step links to a specific vulnerability, asset, and MITRE technique. The composite risk score is automatically calculated based on the chain's steps.
            </p>
          </div>

          <div className="flex justify-end gap-3">
            <Link href="/attack-chains"><Button variant="outline">Cancel</Button></Link>
            <Button type="submit" disabled={!form.name || createMut.isPending}>
              <Plus className="h-4 w-4 mr-1" />{createMut.isPending ? "Creating..." : "Create Chain"}
            </Button>
          </div>
        </form>
      </div>
    </AppShell>
  );
}
