import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogFooter } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import {
  Shield, AlertTriangle, CheckCircle2, XCircle, Plus, Play,
  Settings, FileText, TrendingDown, ArrowUpDown
} from "lucide-react";
import AppShell from "@/components/AppShell";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-500 bg-red-500/10 border-red-500/30",
  high: "text-orange-500 bg-orange-500/10 border-orange-500/30",
  medium: "text-amber-500 bg-amber-500/10 border-amber-500/30",
  low: "text-blue-500 bg-blue-500/10 border-blue-500/30",
};

const STATUS_ICONS: Record<string, any> = {
  pass: <CheckCircle2 className="h-4 w-4 text-emerald-500" />,
  fail: <XCircle className="h-4 w-4 text-red-500" />,
  warning: <AlertTriangle className="h-4 w-4 text-amber-500" />,
  error: <AlertTriangle className="h-4 w-4 text-red-500" />,
};

export default function ConfigBaseline() {
  const [showCreateBaseline, setShowCreateBaseline] = useState(false);
  const [showScanDialog, setShowScanDialog] = useState(false);
  const [selectedBaseline, setSelectedBaseline] = useState<string | null>(null);
  const [newBaseline, setNewBaseline] = useState({
    name: "", description: "", platform: "linux", benchmark: "CIS",
  });

  const { data: baselines, refetch: refetchBaselines } = trpc.configBaseline.listBaselines.useQuery();
  const { data: driftAlerts, refetch: refetchAlerts } = trpc.configBaseline.listDriftAlerts.useQuery({});
  const { data: ruleCatalog } = trpc.configBaseline.getRuleCatalog.useQuery();
  const { data: scanResults } = trpc.configBaseline.listScanResults.useQuery(
    { baselineId: selectedBaseline! },
    { enabled: !!selectedBaseline }
  );

  const createBaseline = trpc.configBaseline.createBaseline.useMutation({
    onSuccess: () => {
      refetchBaselines();
      setShowCreateBaseline(false);
      setNewBaseline({ name: "", description: "", platform: "linux", benchmark: "CIS" });
      toast.success("Baseline created");
    },
    onError: (e) => toast.error(e.message),
  });

  const runScan = trpc.configBaseline.runScan.useMutation({
    onSuccess: (d) => {
      refetchBaselines();
      refetchAlerts();
      setShowScanDialog(false);
      toast.success(`Scan complete: ${d.passed} pass, ${d.failed} fail, ${d.driftAlerts} drift`);
    },
    onError: (e) => toast.error(e.message),
  });

  const updateAlertStatus = trpc.configBaseline.updateDriftAlert.useMutation({
    onSuccess: () => { refetchAlerts(); toast.success("Alert updated"); },
    onError: (e) => toast.error(e.message),
  });

  const totalDrift = driftAlerts?.filter(a => a.status === "open").length ?? 0;
  const criticalDrift = driftAlerts?.filter(a => a.status === "open" && a.severity === "critical").length ?? 0;

  return (
      <AppShell activePath="/config-baseline">
      <div className="space-y-6">
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight">Configuration Baseline Engine</h1>
          <p className="text-muted-foreground">
            CIS benchmark scanning, drift detection, and remediation tracking for FedRAMP CNA KSIs
          </p>
        </div>
        <Button onClick={() => setShowCreateBaseline(true)} className="gap-2">
          <Plus className="h-4 w-4" /> New Baseline
        </Button>
      </div>

      {/* Summary Stats */}
      <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Baselines</CardDescription>
            <CardTitle className="text-2xl">{baselines?.length ?? 0}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>Rule Catalog</CardDescription>
            <CardTitle className="text-2xl text-blue-500">{ruleCatalog?.totalRules ?? 0}</CardTitle>
          </CardHeader>
        </Card>
        <Card className={totalDrift > 0 ? "border-amber-500/30" : ""}>
          <CardHeader className="pb-2">
            <CardDescription>Open Drift Alerts</CardDescription>
            <CardTitle className="text-2xl text-amber-500">{totalDrift}</CardTitle>
          </CardHeader>
        </Card>
        <Card className={criticalDrift > 0 ? "border-red-500/30" : ""}>
          <CardHeader className="pb-2">
            <CardDescription>Critical Drift</CardDescription>
            <CardTitle className="text-2xl text-red-500">{criticalDrift}</CardTitle>
          </CardHeader>
        </Card>
        <Card>
          <CardHeader className="pb-2">
            <CardDescription>KSIs Covered</CardDescription>
            <CardTitle className="text-2xl text-emerald-500">
              {new Set((ruleCatalog?.rules || []).flatMap(r => (r.ksiIds as string[]) || [])).size}
            </CardTitle>
          </CardHeader>
        </Card>
      </div>

      <Tabs defaultValue="baselines" className="space-y-4">
        <TabsList>
          <TabsTrigger value="baselines">Baselines</TabsTrigger>
          <TabsTrigger value="drift">
            Drift Alerts
            {totalDrift > 0 && <Badge variant="destructive" className="ml-2 text-[10px]">{totalDrift}</Badge>}
          </TabsTrigger>
          <TabsTrigger value="rules">Rule Catalog</TabsTrigger>
        </TabsList>

        {/* Baselines Tab */}
        <TabsContent value="baselines" className="space-y-3">
          {baselines?.map((bl) => (
            <Card key={bl.id} className="hover:border-primary/50 transition-colors">
              <CardContent className="p-4">
                <div className="flex items-center gap-4">
                  <Settings className="h-8 w-8 text-muted-foreground shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2">
                      <span className="font-medium">{bl.name}</span>
                      <Badge variant="outline">{bl.platform}</Badge>
                      <Badge variant="secondary">{bl.benchmark}</Badge>
                      <Badge variant={bl.status === "active" ? "default" : "outline"}>{bl.status}</Badge>
                    </div>
                    {bl.description && (
                      <p className="text-sm text-muted-foreground mt-1 truncate">{bl.description}</p>
                    )}
                    <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                      <span>{bl.ruleCount} rules</span>
                      {bl.lastScanAt && <span>Last scan: {new Date(bl.lastScanAt).toLocaleString()}</span>}
                      {bl.lastScanScore !== null && bl.lastScanScore !== undefined && (
                        <Badge variant={bl.lastScanScore >= 80 ? "default" : bl.lastScanScore >= 60 ? "secondary" : "destructive"}>
                          Score: {bl.lastScanScore}%
                        </Badge>
                      )}
                    </div>
                  </div>
                  <div className="flex gap-2 shrink-0">
                    <Button
                      size="sm"
                      variant="outline"
                      onClick={() => setSelectedBaseline(bl.baselineId)}
                    >
                      <FileText className="h-3 w-3 mr-1" /> Results
                    </Button>
                    <Button
                      size="sm"
                      onClick={() => { setSelectedBaseline(bl.baselineId); setShowScanDialog(true); }}
                    >
                      <Play className="h-3 w-3 mr-1" /> Scan
                    </Button>
                  </div>
                </div>
              </CardContent>
            </Card>
          ))}
          {(!baselines || baselines.length === 0) && (
            <Card className="border-dashed">
              <CardContent className="p-8 text-center text-muted-foreground">
                <Shield className="h-12 w-12 mx-auto mb-3 opacity-50" />
                <p>No baselines configured yet. Create one to start CIS benchmark scanning.</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Drift Alerts Tab */}
        <TabsContent value="drift" className="space-y-3">
          {driftAlerts?.map((alert) => (
            <Card key={alert.id} className={`border-l-4 ${
              alert.severity === "critical" ? "border-l-red-500" :
              alert.severity === "high" ? "border-l-orange-500" :
              alert.severity === "medium" ? "border-l-amber-500" : "border-l-blue-500"
            }`}>
              <CardContent className="p-4">
                <div className="flex items-start gap-3">
                  <TrendingDown className="h-5 w-5 text-amber-500 mt-0.5 shrink-0" />
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <Badge className={SEVERITY_COLORS[alert.severity || "medium"]}>{alert.severity}</Badge>
                      <span className="font-medium">{alert.ruleTitle || alert.ruleId}</span>
                      <Badge variant="outline" className="text-[10px]">{alert.driftType}</Badge>
                    </div>
                    {alert.description && (
                      <p className="text-sm text-muted-foreground mt-1">{alert.description}</p>
                    )}
                    <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                      <span>Baseline: {alert.baselineId}</span>
                      {alert.targetName && <span>Target: {alert.targetName}</span>}
                      <span>{new Date(alert.createdAt).toLocaleString()}</span>
                    </div>
                    {alert.remediationGuidance && (
                      <p className="text-xs mt-2 p-2 bg-muted rounded">{alert.remediationGuidance}</p>
                    )}
                  </div>
                  <Select
                    value={alert.status}
                    onValueChange={(val) => updateAlertStatus.mutate({ alertId: alert.alertId, status: val as any })}
                  >
                    <SelectTrigger className="w-36 shrink-0">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="open">Open</SelectItem>
                      <SelectItem value="acknowledged">Acknowledged</SelectItem>
                      <SelectItem value="remediated">Remediated</SelectItem>
                      <SelectItem value="accepted">Accepted</SelectItem>
                      <SelectItem value="false_positive">False Positive</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </CardContent>
            </Card>
          ))}
          {(!driftAlerts || driftAlerts.length === 0) && (
            <Card className="border-dashed">
              <CardContent className="p-8 text-center text-muted-foreground">
                <CheckCircle2 className="h-12 w-12 mx-auto mb-3 text-emerald-500 opacity-50" />
                <p>No drift alerts. All configurations are within baseline.</p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* Rule Catalog Tab */}
        <TabsContent value="rules" className="space-y-2">
          <div className="rounded-lg border overflow-hidden">
            <table className="w-full text-sm">
              <thead className="bg-muted/50">
                <tr>
                  <th className="text-left p-3 font-medium">Rule</th>
                  <th className="text-left p-3 font-medium">Benchmark</th>
                  <th className="text-left p-3 font-medium">Severity</th>
                  <th className="text-left p-3 font-medium">Platform</th>
                  <th className="text-left p-3 font-medium">KSIs</th>
                  <th className="text-left p-3 font-medium">MITRE</th>
                </tr>
              </thead>
              <tbody>
                {ruleCatalog?.rules?.map((rule) => (
                  <tr key={(rule as any).id} className="border-t hover:bg-muted/30">
                    <td className="p-3">
                      <div className="font-medium">{rule.title}</div>
                      <div className="text-xs text-muted-foreground">{rule.section} / {rule.ruleId}</div>
                    </td>
                    <td className="p-3"><Badge variant="outline">{rule.benchmark}</Badge></td>
                    <td className="p-3">
                      <Badge className={SEVERITY_COLORS[rule.severity || "medium"]}>{rule.severity}</Badge>
                    </td>
                    <td className="p-3 text-muted-foreground">{rule.platform}</td>
                    <td className="p-3">
                      <div className="flex flex-wrap gap-1">
                        {((rule.ksiIds as string[]) || []).map((id) => (
                          <Badge key={id} variant="outline" className="text-[10px]">{id}</Badge>
                        ))}
                      </div>
                    </td>
                    <td className="p-3">
                      <div className="flex flex-wrap gap-1">
                        {((rule.mitreIds as string[]) || []).map((id) => (
                          <Badge key={id} variant="secondary" className="text-[10px] font-mono">{id}</Badge>
                        ))}
                      </div>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </TabsContent>
      </Tabs>

      {/* Scan Results Dialog */}
      {selectedBaseline && scanResults && !showScanDialog && (
        <Dialog open={!!selectedBaseline && !showScanDialog} onOpenChange={(open) => !open && setSelectedBaseline(null)}>
          <DialogContent className="max-w-3xl max-h-[80vh] overflow-y-auto">
            <DialogHeader>
              <DialogTitle>Scan Results: {selectedBaseline}</DialogTitle>
            </DialogHeader>
            <div className="space-y-2">
              {scanResults.map((r) => (
                <div key={r.id} className="flex items-center gap-3 p-2 rounded border">
                  {STATUS_ICONS[r.status]}
                  <Badge className={SEVERITY_COLORS[r.severity || "medium"]} >{r.severity}</Badge>
                  <span className="flex-1 text-sm truncate">{r.ruleTitle || r.ruleId}</span>
                  {r.driftDetected && <Badge variant="destructive" className="text-[10px]">DRIFT</Badge>}
                  <span className="text-xs text-muted-foreground">{r.targetName}</span>
                </div>
              ))}
              {scanResults.length === 0 && (
                <p className="text-center text-muted-foreground py-4">No scan results yet. Run a scan first.</p>
              )}
            </div>
          </DialogContent>
        </Dialog>
      )}

      {/* Create Baseline Dialog */}
      <Dialog open={showCreateBaseline} onOpenChange={setShowCreateBaseline}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Create Configuration Baseline</DialogTitle>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Name</Label>
              <Input
                value={newBaseline.name}
                onChange={(e) => setNewBaseline(p => ({ ...p, name: e.target.value }))}
                placeholder="e.g., Production Linux Servers"
              />
            </div>
            <div>
              <Label>Description</Label>
              <Textarea
                value={newBaseline.description}
                onChange={(e) => setNewBaseline(p => ({ ...p, description: e.target.value }))}
                placeholder="Baseline description..."
              />
            </div>
            <div className="grid grid-cols-2 gap-4">
              <div>
                <Label>Platform</Label>
                <Select value={newBaseline.platform} onValueChange={(v) => setNewBaseline(p => ({ ...p, platform: v }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="linux">Linux</SelectItem>
                    <SelectItem value="windows">Windows</SelectItem>
                    <SelectItem value="macos">macOS</SelectItem>
                    <SelectItem value="aws">AWS</SelectItem>
                    <SelectItem value="azure">Azure</SelectItem>
                    <SelectItem value="gcp">GCP</SelectItem>
                    <SelectItem value="kubernetes">Kubernetes</SelectItem>
                    <SelectItem value="docker">Docker</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>Benchmark</Label>
                <Select value={newBaseline.benchmark} onValueChange={(v) => setNewBaseline(p => ({ ...p, benchmark: v }))}>
                  <SelectTrigger><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="CIS">CIS Benchmark</SelectItem>
                    <SelectItem value="STIG">DISA STIG</SelectItem>
                    <SelectItem value="NIST">NIST 800-53</SelectItem>
                    <SelectItem value="FedRAMP">FedRAMP High</SelectItem>
                    <SelectItem value="Custom">Custom</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowCreateBaseline(false)}>Cancel</Button>
            <Button
              onClick={() => {
              // Auto-select all rules matching the chosen platform and benchmark
              const matchingRules = (ruleCatalog?.rules || []).filter(r =>
                r.platform === newBaseline.platform || newBaseline.platform === "linux" || newBaseline.platform === "windows"
              ).map(r => r.ruleId);
              createBaseline.mutate({ ...newBaseline, ruleIds: matchingRules.length > 0 ? matchingRules : (ruleCatalog?.rules || []).map(r => r.ruleId) });
            }}
              disabled={!newBaseline.name || createBaseline.isPending}
            >
              Create Baseline
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Run Scan Dialog */}
      <Dialog open={showScanDialog} onOpenChange={setShowScanDialog}>
        <DialogContent>
          <DialogHeader>
            <DialogTitle>Run Baseline Scan</DialogTitle>
          </DialogHeader>
          <p className="text-sm text-muted-foreground">
            This will scan the target environment against the selected baseline and detect any configuration drift.
          </p>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowScanDialog(false)}>Cancel</Button>
            <Button
              onClick={() => selectedBaseline && runScan.mutate({ baselineId: selectedBaseline, targetName: "default" })}
              disabled={!selectedBaseline || runScan.isPending}
            >
              {runScan.isPending ? "Scanning..." : "Start Scan"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
      </AppShell>
  );
}
