import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import AppShell from "@/components/AppShell";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Table, TableBody, TableCell, TableHead, TableHeader, TableRow } from "@/components/ui/table";
import { Switch } from "@/components/ui/switch";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import {
  Server, Shield, Key, Globe, Lock, Plus, Trash2, RefreshCw,
  CheckCircle2, XCircle, AlertTriangle, Loader2, Play, Clock,
  Activity, Wifi, WifiOff, Copy, ChevronDown, ChevronRight,
  Mail, FileText, Zap, Eye,
} from "lucide-react";

// ─── Live Droplets Panel ──────────────────────────────────────────────────────

function LiveDropletsPanel() {
  const [showCreate, setShowCreate] = useState(false);
  const [name, setName] = useState("");
  const [region, setRegion] = useState("sfo3");
  const [size, setSize] = useState("s-1vcpu-1gb");
  const [tag, setTag] = useState("");

  const droplets = trpc.liveInfra.droplets.list.useQuery(tag ? { tag } : undefined, { retry: 1 });
  const health = trpc.liveInfra.droplets.healthCheck.useQuery(undefined, { retry: 1, enabled: false });
  const createMut = trpc.liveInfra.droplets.create.useMutation({
    onSuccess: () => { toast.success("Droplet creation initiated"); droplets.refetch(); setShowCreate(false); },
    onError: (e) => toast.error(`Failed: ${e.message}`),
  });
  const deleteMut = trpc.liveInfra.droplets.delete.useMutation({
    onSuccess: () => { toast.success("Droplet deleted"); droplets.refetch(); },
    onError: (e) => toast.error(`Failed: ${e.message}`),
  });

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-2">
          <Input placeholder="Filter by tag..." value={tag} onChange={(e) => setTag(e.target.value)} className="w-48" />
          <Button variant="outline" size="sm" onClick={() => droplets.refetch()}>
            <RefreshCw className="h-4 w-4 mr-1" /> Refresh
          </Button>
          <Button variant="outline" size="sm" onClick={() => health.refetch()}>
            <Activity className="h-4 w-4 mr-1" /> Health Check
          </Button>
        </div>
        <Dialog open={showCreate} onOpenChange={setShowCreate}>
          <DialogTrigger asChild>
            <Button size="sm"><Plus className="h-4 w-4 mr-1" /> New Droplet</Button>
          </DialogTrigger>
          <DialogContent>
            <DialogHeader>
              <DialogTitle>Create Droplet</DialogTitle>
              <DialogDescription>Provision a new DigitalOcean droplet for your red team infrastructure.</DialogDescription>
            </DialogHeader>
            <div className="space-y-3">
              <div><Label>Name</Label><Input value={name} onChange={(e) => setName(e.target.value)} placeholder="redirector-01" /></div>
              <div><Label>Region</Label>
                <Select value={region} onValueChange={setRegion}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="sfo3">San Francisco 3</SelectItem>
                    <SelectItem value="nyc3">New York 3</SelectItem>
                    <SelectItem value="lon1">London 1</SelectItem>
                    <SelectItem value="ams3">Amsterdam 3</SelectItem>
                    <SelectItem value="sgp1">Singapore 1</SelectItem>
                    <SelectItem value="fra1">Frankfurt 1</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div><Label>Size</Label>
                <Select value={size} onValueChange={setSize}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="s-1vcpu-1gb">1 vCPU / 1 GB ($6/mo)</SelectItem>
                    <SelectItem value="s-1vcpu-2gb">1 vCPU / 2 GB ($12/mo)</SelectItem>
                    <SelectItem value="s-2vcpu-4gb">2 vCPU / 4 GB ($24/mo)</SelectItem>
                    <SelectItem value="s-4vcpu-8gb">4 vCPU / 8 GB ($48/mo)</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <Button className="w-full" onClick={() => createMut.mutate({ name, region, size, image: "ubuntu-22-04-x64", tags: ["redteam"] })} disabled={!name || createMut.isPending}>
                {createMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Plus className="h-4 w-4 mr-1" />} Create
              </Button>
            </div>
          </DialogContent>
        </Dialog>
      </div>

      {droplets.isLoading ? (
        <div className="text-center py-8 text-muted-foreground"><Loader2 className="h-6 w-6 animate-spin mx-auto mb-2" />Loading droplets...</div>
      ) : droplets.error ? (
        <Card className="border-destructive"><CardContent className="py-6 text-center text-destructive"><AlertTriangle className="h-6 w-6 mx-auto mb-2" />{droplets.error.message}</CardContent></Card>
      ) : (
        <Table>
          <TableHeader>
            <TableRow>
              <TableHead>Name</TableHead><TableHead>Status</TableHead><TableHead>IP</TableHead>
              <TableHead>Region</TableHead><TableHead>Size</TableHead><TableHead>Tags</TableHead><TableHead>Actions</TableHead>
            </TableRow>
          </TableHeader>
          <TableBody>
            {(droplets.data ?? []).length === 0 ? (
              <TableRow><TableCell colSpan={7} className="text-center text-muted-foreground py-8">No droplets found. Create one to get started.</TableCell></TableRow>
            ) : (droplets.data ?? []).map((d) => (
              <TableRow key={d.id}>
                <TableCell className="font-mono text-sm">{d.name}</TableCell>
                <TableCell>
                  <Badge variant={d.status === "active" ? "default" : "secondary"}>
                    {d.status === "active" ? <CheckCircle2 className="h-3 w-3 mr-1" /> : <Clock className="h-3 w-3 mr-1" />}
                    {d.status}
                  </Badge>
                </TableCell>
                <TableCell className="font-mono text-xs">{d.ipv4Public ?? "—"}</TableCell>
                <TableCell>{d.region}</TableCell>
                <TableCell className="text-xs">{d.sizeSlug}</TableCell>
                <TableCell>{d.tags.map((t) => <Badge key={t} variant="outline" className="mr-1 text-xs">{t}</Badge>)}</TableCell>
                <TableCell>
                  <div className="flex gap-1">
                    {d.ipv4Public && <Button variant="ghost" size="sm" onClick={() => { navigator.clipboard.writeText(d.ipv4Public!); toast.success("IP copied"); }}><Copy className="h-3 w-3" /></Button>}
                    <Button variant="ghost" size="sm" className="text-destructive" onClick={() => { if (confirm(`Delete ${d.name}?`)) deleteMut.mutate({ id: d.id }); }}><Trash2 className="h-3 w-3" /></Button>
                  </div>
                </TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}

      {health.data && health.data.length > 0 && (
        <Card>
          <CardHeader><CardTitle className="text-sm">Health Check Results</CardTitle></CardHeader>
          <CardContent>
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {health.data.map((h) => (
                <div key={h.dropletId} className="flex items-center gap-2 p-3 rounded-lg border">
                  {h.httpReachable ? <Wifi className="h-4 w-4 text-green-500" /> : <WifiOff className="h-4 w-4 text-red-500" />}
                  <div>
                    <p className="text-sm font-medium">{h.name}</p>
                    <p className="text-xs text-muted-foreground">{h.ip ?? "No IP"} — {h.status}</p>
                  </div>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Firewalls Panel ──────────────────────────────────────────────────────────

function FirewallsPanel() {
  const firewalls = trpc.liveInfra.firewalls.list.useQuery(undefined, { retry: 1 });
  const deleteMut = trpc.liveInfra.firewalls.delete.useMutation({
    onSuccess: () => { toast.success("Firewall deleted"); firewalls.refetch(); },
    onError: (e) => toast.error(e.message),
  });

  return (
    <div className="space-y-4">
      <div className="flex justify-between items-center">
        <p className="text-sm text-muted-foreground">DigitalOcean cloud firewalls attached to your infrastructure.</p>
        <Button variant="outline" size="sm" onClick={() => firewalls.refetch()}><RefreshCw className="h-4 w-4 mr-1" /> Refresh</Button>
      </div>
      {firewalls.isLoading ? (
        <div className="text-center py-8 text-muted-foreground"><Loader2 className="h-6 w-6 animate-spin mx-auto" /></div>
      ) : firewalls.error ? (
        <Card className="border-destructive"><CardContent className="py-6 text-center text-destructive">{firewalls.error.message}</CardContent></Card>
      ) : (
        <Table>
          <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Status</TableHead><TableHead>Droplets</TableHead><TableHead>Inbound Rules</TableHead><TableHead>Actions</TableHead></TableRow></TableHeader>
          <TableBody>
            {(firewalls.data ?? []).length === 0 ? (
              <TableRow><TableCell colSpan={5} className="text-center text-muted-foreground py-8">No firewalls found.</TableCell></TableRow>
            ) : (firewalls.data ?? []).map((fw) => (
              <TableRow key={fw.id}>
                <TableCell className="font-mono text-sm">{fw.name}</TableCell>
                <TableCell><Badge variant={fw.status === "succeeded" ? "default" : "secondary"}>{fw.status}</Badge></TableCell>
                <TableCell>{fw.dropletIds.length} droplet(s)</TableCell>
                <TableCell className="text-xs">{fw.inboundRules.map((r) => `${r.protocol}:${r.ports}`).join(", ") || "—"}</TableCell>
                <TableCell><Button variant="ghost" size="sm" className="text-destructive" onClick={() => deleteMut.mutate({ id: fw.id })}><Trash2 className="h-3 w-3" /></Button></TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}

// ─── SSH Keys Panel ───────────────────────────────────────────────────────────

function SshKeysPanel() {
  const keys = trpc.liveInfra.sshKeys.list.useQuery(undefined, { retry: 1 });

  return (
    <div className="space-y-4">
      <p className="text-sm text-muted-foreground">SSH keys registered in your DigitalOcean account for droplet access.</p>
      {keys.isLoading ? (
        <div className="text-center py-8 text-muted-foreground"><Loader2 className="h-6 w-6 animate-spin mx-auto" /></div>
      ) : keys.error ? (
        <Card className="border-destructive"><CardContent className="py-6 text-center text-destructive">{keys.error.message}</CardContent></Card>
      ) : (
        <Table>
          <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Fingerprint</TableHead><TableHead>ID</TableHead></TableRow></TableHeader>
          <TableBody>
            {(keys.data ?? []).length === 0 ? (
              <TableRow><TableCell colSpan={3} className="text-center text-muted-foreground py-8">No SSH keys found.</TableCell></TableRow>
            ) : (keys.data ?? []).map((k) => (
              <TableRow key={k.id}>
                <TableCell className="font-medium">{k.name}</TableCell>
                <TableCell className="font-mono text-xs">{k.fingerprint}</TableCell>
                <TableCell className="text-xs text-muted-foreground">{k.id}</TableCell>
              </TableRow>
            ))}
          </TableBody>
        </Table>
      )}
    </div>
  );
}

// ─── DNS Automation Panel ─────────────────────────────────────────────────────

function DnsAutomationPanel() {
  const [selectedDomain, setSelectedDomain] = useState("");
  const [deployDomain, setDeployDomain] = useState("");
  const [spfPolicy, setSpfPolicy] = useState<"~all" | "-all" | "?all">("~all");
  const [dmarcPolicy, setDmarcPolicy] = useState<"none" | "quarantine" | "reject">("none");
  const [dmarcRua, setDmarcRua] = useState("");
  const [dkimSelector, setDkimSelector] = useState("default");
  const [mxHost, setMxHost] = useState("");

  const domains = trpc.liveInfra.dns.domains.useQuery(undefined, { retry: 1 });
  const records = trpc.liveInfra.dns.records.useQuery({ domain: selectedDomain }, { enabled: !!selectedDomain, retry: 1 });
  const deployMut = trpc.liveInfra.dns.deployEmail.useMutation({
    onSuccess: (data) => {
      const created = data.records.filter((r) => r.status === "created").length;
      const exists = data.records.filter((r) => r.status === "exists").length;
      toast.success(`Deployed: ${created} created, ${exists} already exist`);
      if (selectedDomain === deployDomain) records.refetch();
    },
    onError: (e) => toast.error(e.message),
  });
  const deleteRecMut = trpc.liveInfra.dns.deleteRecord.useMutation({
    onSuccess: () => { toast.success("Record deleted"); records.refetch(); },
    onError: (e) => toast.error(e.message),
  });

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2"><Mail className="h-4 w-4" /> Deploy Email Authentication Records</CardTitle>
          <CardDescription>Auto-configure SPF, DKIM, DMARC, and MX records for phishing domains.</CardDescription>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
            <div><Label>Domain</Label><Input value={deployDomain} onChange={(e) => setDeployDomain(e.target.value)} placeholder="phishing-domain.com" /></div>
            <div><Label>SPF Policy</Label>
              <Select value={spfPolicy} onValueChange={(v) => setSpfPolicy(v as any)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="~all">Soft Fail (~all)</SelectItem>
                  <SelectItem value="-all">Hard Fail (-all)</SelectItem>
                  <SelectItem value="?all">Neutral (?all)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div><Label>DMARC Policy</Label>
              <Select value={dmarcPolicy} onValueChange={(v) => setDmarcPolicy(v as any)}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">None (monitor)</SelectItem>
                  <SelectItem value="quarantine">Quarantine</SelectItem>
                  <SelectItem value="reject">Reject</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div><Label>DMARC RUA Email</Label><Input value={dmarcRua} onChange={(e) => setDmarcRua(e.target.value)} placeholder="dmarc@yourdomain.com" /></div>
            <div><Label>DKIM Selector</Label><Input value={dkimSelector} onChange={(e) => setDkimSelector(e.target.value)} /></div>
            <div><Label>MX Host (optional)</Label><Input value={mxHost} onChange={(e) => setMxHost(e.target.value)} placeholder="mail.yourdomain.com" /></div>
          </div>
          <Button onClick={() => deployMut.mutate({ domain: deployDomain, spfPolicy, dmarcPolicy, dmarcRua: dmarcRua || undefined, dkimSelector, mxHost: mxHost || undefined })} disabled={!deployDomain || deployMut.isPending}>
            {deployMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Zap className="h-4 w-4 mr-1" />} Deploy Records
          </Button>
        </CardContent>
      </Card>

      <Card>
        <CardHeader>
          <CardTitle className="text-base flex items-center gap-2"><Eye className="h-4 w-4" /> Browse DNS Records</CardTitle>
        </CardHeader>
        <CardContent className="space-y-3">
          <div className="flex gap-2">
            <Select value={selectedDomain} onValueChange={setSelectedDomain}>
              <SelectTrigger className="w-64"><SelectValue placeholder="Select domain..." /></SelectTrigger>
              <SelectContent>
                {(domains.data ?? []).map((d) => <SelectItem key={d.name} value={d.name}>{d.name}</SelectItem>)}
              </SelectContent>
            </Select>
            <Button variant="outline" size="sm" onClick={() => domains.refetch()}><RefreshCw className="h-4 w-4" /></Button>
          </div>
          {selectedDomain && records.data && (
            <Table>
              <TableHeader><TableRow><TableHead>Type</TableHead><TableHead>Name</TableHead><TableHead>Data</TableHead><TableHead>TTL</TableHead><TableHead>Actions</TableHead></TableRow></TableHeader>
              <TableBody>
                {records.data.map((r) => (
                  <TableRow key={r.id}>
                    <TableCell><Badge variant="outline">{r.type}</Badge></TableCell>
                    <TableCell className="font-mono text-xs">{r.name}</TableCell>
                    <TableCell className="font-mono text-xs max-w-xs truncate">{r.data}</TableCell>
                    <TableCell>{r.ttl}</TableCell>
                    <TableCell><Button variant="ghost" size="sm" className="text-destructive" onClick={() => deleteRecMut.mutate({ domain: selectedDomain, recordId: r.id })}><Trash2 className="h-3 w-3" /></Button></TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Scheduled Scans Panel ────────────────────────────────────────────────────

function ScheduledScansPanel() {
  const [showCreate, setShowCreate] = useState(false);
  const [scanName, setScanName] = useState("");
  const [targetHost, setTargetHost] = useState("");
  const [targetName, setTargetName] = useState("");
  const [interval, setInterval] = useState("24");
  const [threshold, setThreshold] = useState("70");

  const checks = trpc.liveInfra.scans.checks.useQuery(undefined, { retry: 1 });
  const scheduled = trpc.liveInfra.scans.scheduled.list.useQuery(undefined, { retry: 1 });
  const allHistory = trpc.liveInfra.scans.allHistory.useQuery(undefined, { retry: 1 });

  const createMut = trpc.liveInfra.scans.scheduled.create.useMutation({
    onSuccess: () => { toast.success("Scheduled scan created"); scheduled.refetch(); setShowCreate(false); },
    onError: (e) => toast.error(e.message),
  });
  const runMut = trpc.liveInfra.scans.scheduled.run.useMutation({
    onSuccess: (results) => {
      const avgScore = results.length > 0 ? Math.round(results.reduce((s, r) => s + r.score, 0) / results.length) : 0;
      toast.success(`Scan complete — avg score: ${avgScore}%`);
      scheduled.refetch();
      allHistory.refetch();
    },
    onError: (e) => toast.error(e.message),
  });
  const deleteMut = trpc.liveInfra.scans.scheduled.delete.useMutation({
    onSuccess: () => { toast.success("Scan deleted"); scheduled.refetch(); },
  });
  const executeMut = trpc.liveInfra.scans.execute.useMutation({
    onSuccess: (result) => {
      toast.success(`Ad-hoc scan: ${result.score}% (${result.passCount} pass, ${result.failCount} fail)`);
      allHistory.refetch();
    },
    onError: (e) => toast.error(e.message),
  });

  return (
    <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <p className="text-sm text-muted-foreground">Recurring security posture assessments with {checks.data?.length ?? 25} built-in checks.</p>
        </div>
        <div className="flex gap-2">
          <Dialog open={showCreate} onOpenChange={setShowCreate}>
            <DialogTrigger asChild><Button size="sm"><Plus className="h-4 w-4 mr-1" /> Schedule Scan</Button></DialogTrigger>
            <DialogContent>
              <DialogHeader><DialogTitle>Create Scheduled Scan</DialogTitle><DialogDescription>Set up recurring posture assessments with alert notifications.</DialogDescription></DialogHeader>
              <div className="space-y-3">
                <div><Label>Scan Name</Label><Input value={scanName} onChange={(e) => setScanName(e.target.value)} placeholder="Weekly Production Scan" /></div>
                <div><Label>Target Name</Label><Input value={targetName} onChange={(e) => setTargetName(e.target.value)} placeholder="Production Server" /></div>
                <div><Label>Target Host (IP/hostname)</Label><Input value={targetHost} onChange={(e) => setTargetHost(e.target.value)} placeholder="134.199.213.248" /></div>
                <div><Label>Interval (hours)</Label><Input type="number" value={interval} onChange={(e) => setInterval(e.target.value)} /></div>
                <div><Label>Alert Threshold (%)</Label><Input type="number" value={threshold} onChange={(e) => setThreshold(e.target.value)} /></div>
                <Button className="w-full" onClick={() => createMut.mutate({
                  name: scanName,
                  targets: [{ id: `t-${Date.now()}`, name: targetName, host: targetHost, port: 22, tags: ["production"] }],
                  intervalHours: parseInt(interval) || 24,
                  notifyOnFail: true,
                  notifyThreshold: parseInt(threshold) || 70,
                })} disabled={!scanName || !targetHost || createMut.isPending}>
                  {createMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : null} Create
                </Button>
              </div>
            </DialogContent>
          </Dialog>
        </div>
      </div>

      <Card>
        <CardHeader><CardTitle className="text-base">Scheduled Scans</CardTitle></CardHeader>
        <CardContent>
          {scheduled.isLoading ? (
            <div className="text-center py-4"><Loader2 className="h-5 w-5 animate-spin mx-auto" /></div>
          ) : (scheduled.data ?? []).length === 0 ? (
            <p className="text-center text-muted-foreground py-4">No scheduled scans. Create one above.</p>
          ) : (
            <Table>
              <TableHeader><TableRow><TableHead>Name</TableHead><TableHead>Targets</TableHead><TableHead>Interval</TableHead><TableHead>Last Run</TableHead><TableHead>Status</TableHead><TableHead>Actions</TableHead></TableRow></TableHeader>
              <TableBody>
                {(scheduled.data ?? []).map((s) => (
                  <TableRow key={s.id}>
                    <TableCell className="font-medium">{s.name}</TableCell>
                    <TableCell>{s.targets.length} target(s)</TableCell>
                    <TableCell>Every {s.intervalHours}h</TableCell>
                    <TableCell className="text-xs">{s.lastRun ? new Date(s.lastRun).toLocaleString() : "Never"}</TableCell>
                    <TableCell><Badge variant={s.enabled ? "default" : "secondary"}>{s.enabled ? "Active" : "Paused"}</Badge></TableCell>
                    <TableCell>
                      <div className="flex gap-1">
                        <Button variant="ghost" size="sm" onClick={() => runMut.mutate({ id: s.id })} disabled={runMut.isPending}>
                          <Play className="h-3 w-3" />
                        </Button>
                        <Button variant="ghost" size="sm" className="text-destructive" onClick={() => deleteMut.mutate({ id: s.id })}>
                          <Trash2 className="h-3 w-3" />
                        </Button>
                      </div>
                    </TableCell>
                  </TableRow>
                ))}
              </TableBody>
            </Table>
          )}
        </CardContent>
      </Card>

      <Card>
        <CardHeader><CardTitle className="text-base">Built-in Security Checks ({checks.data?.length ?? 0})</CardTitle></CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
            {(checks.data ?? []).map((c) => (
              <div key={c.id} className="flex items-start gap-2 p-2 rounded border text-xs">
                <Badge variant={c.severity === "critical" ? "destructive" : c.severity === "high" ? "default" : "secondary"} className="text-[10px] shrink-0">{c.severity}</Badge>
                <div>
                  <p className="font-medium">{c.name}</p>
                  <p className="text-muted-foreground">{c.category}</p>
                </div>
              </div>
            ))}
          </div>
        </CardContent>
      </Card>

      {(allHistory.data ?? []).length > 0 && (
        <Card>
          <CardHeader><CardTitle className="text-base">Recent Scan Results</CardTitle></CardHeader>
          <CardContent>
            {(allHistory.data ?? []).map(({ targetId, results }) => (
              <div key={targetId} className="mb-4">
                <p className="text-sm font-medium mb-2">{results[results.length - 1]?.targetName ?? targetId}</p>
                <div className="flex gap-2 flex-wrap">
                  {results.slice(-5).map((r) => (
                    <div key={r.id} className={`p-2 rounded border text-xs ${r.score >= 80 ? "border-green-500/30 bg-green-500/5" : r.score >= 50 ? "border-yellow-500/30 bg-yellow-500/5" : "border-red-500/30 bg-red-500/5"}`}>
                      <p className="font-bold text-lg">{r.score}%</p>
                      <p className="text-muted-foreground">{r.passCount}P / {r.failCount}F</p>
                      <p className="text-muted-foreground">{new Date(r.completedAt).toLocaleString()}</p>
                    </div>
                  ))}
                </div>
              </div>
            ))}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Main Page ────────────────────────────────────────────────────────────────

export default function LiveInfraPage() {
  return (
    <AppShell activePath="/live-infra">
      <div className="space-y-6">
        <div>
          <h1 className="text-2xl font-bold text-foreground">Live Infrastructure</h1>
          <p className="text-muted-foreground">Real-time DigitalOcean provisioning, DNS email authentication automation, and recurring security posture scanning with alert notifications.</p>
        </div>

        <Tabs defaultValue="droplets" className="space-y-4">
          <TabsList className="grid w-full grid-cols-5">
            <TabsTrigger value="droplets" className="text-xs sm:text-sm"><Server className="h-4 w-4 mr-1 hidden sm:inline" /> Droplets</TabsTrigger>
            <TabsTrigger value="firewalls" className="text-xs sm:text-sm"><Shield className="h-4 w-4 mr-1 hidden sm:inline" /> Firewalls</TabsTrigger>
            <TabsTrigger value="sshkeys" className="text-xs sm:text-sm"><Key className="h-4 w-4 mr-1 hidden sm:inline" /> SSH Keys</TabsTrigger>
            <TabsTrigger value="dns" className="text-xs sm:text-sm"><Globe className="h-4 w-4 mr-1 hidden sm:inline" /> DNS Auto</TabsTrigger>
            <TabsTrigger value="scans" className="text-xs sm:text-sm"><Lock className="h-4 w-4 mr-1 hidden sm:inline" /> Scans</TabsTrigger>
          </TabsList>

          <TabsContent value="droplets"><LiveDropletsPanel /></TabsContent>
          <TabsContent value="firewalls"><FirewallsPanel /></TabsContent>
          <TabsContent value="sshkeys"><SshKeysPanel /></TabsContent>
          <TabsContent value="dns"><DnsAutomationPanel /></TabsContent>
          <TabsContent value="scans"><ScheduledScansPanel /></TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
