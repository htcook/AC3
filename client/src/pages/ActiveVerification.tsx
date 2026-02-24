import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";
import { Crosshair, Play, Loader2, ShieldAlert, ShieldCheck, ShieldQuestion, AlertTriangle } from "lucide-react";
import AppShell from "@/components/AppShell";

const riskColors: Record<string, string> = {
  critical: "bg-red-600 text-white",
  high: "bg-orange-500 text-white",
  medium: "bg-yellow-500 text-black",
  low: "bg-blue-500 text-white",
  none: "bg-green-500 text-white",
};

const statusConfig: Record<string, { icon: typeof ShieldAlert; color: string; label: string }> = {
  vulnerable: { icon: ShieldAlert, color: "text-red-500", label: "Vulnerable" },
  not_vulnerable: { icon: ShieldCheck, color: "text-green-500", label: "Not Vulnerable" },
  inconclusive: { icon: ShieldQuestion, color: "text-yellow-500", label: "Inconclusive" },
  error: { icon: AlertTriangle, color: "text-zinc-400", label: "Error" },
  timeout: { icon: AlertTriangle, color: "text-zinc-400", label: "Timeout" },
};

export default function ActiveVerification() {
  const [targetHost, setTargetHost] = useState("");
  const [targetPort, setTargetPort] = useState("443");
  const [protocol, setProtocol] = useState<string>("https");
  const [selectedTags, setSelectedTags] = useState<string[]>([]);
  const [suiteResult, setSuiteResult] = useState<any>(null);

  const probesQuery = trpc.activeVerification.listProbes.useQuery();
  const tagsQuery = trpc.activeVerification.getTags.useQuery();

  const runSuiteMut = trpc.activeVerification.runSuite.useMutation({
    onSuccess: (data) => {
      setSuiteResult(data);
      toast.success(`Verification complete: ${data.vulnerableCount} vulnerable, ${data.notVulnerableCount} safe`);
    },
    onError: (err) => toast.error(err.message),
  });

  const runProbeMut = trpc.activeVerification.runProbe.useMutation({
    onSuccess: (data) => {
      toast.success(`Probe ${data.probeName}: ${data.status}`);
    },
    onError: (err) => toast.error(err.message),
  });

  const handleRunSuite = () => {
    if (!targetHost.trim()) { toast.error("Enter a target host"); return; }
    runSuiteMut.mutate({
      targetHost: targetHost.trim(),
      targetPort: parseInt(targetPort) || 443,
      protocol: protocol as any,
      tags: selectedTags.length > 0 ? selectedTags : undefined,
    });
  };

  const handleRunProbe = (probeId: string) => {
    if (!targetHost.trim()) { toast.error("Enter a target host first"); return; }
    runProbeMut.mutate({
      probeId,
      targetHost: targetHost.trim(),
      targetPort: parseInt(targetPort) || 443,
      protocol: protocol as any,
    });
  };

  const toggleTag = (tag: string) => {
    setSelectedTags(prev => prev.includes(tag) ? prev.filter(t => t !== tag) : [...prev, tag]);
  };

  return (
    <AppShell activePath="/active-verification">
      <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Crosshair className="h-6 w-6 text-red-500" />
          Active Verification Probes
        </h1>
        <p className="text-muted-foreground mt-1">
          Non-destructive probes to verify vulnerability exploitability without executing payloads.
        </p>
      </div>

      {/* Target Configuration */}
      <Card>
        <CardHeader>
          <CardTitle>Target Configuration</CardTitle>
          <CardDescription>Configure target and run the full verification suite or individual probes</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="md:col-span-2">
              <Input placeholder="Target Host (e.g., 192.168.1.100)" value={targetHost} onChange={e => setTargetHost(e.target.value)} />
            </div>
            <Input placeholder="Port" value={targetPort} onChange={e => setTargetPort(e.target.value)} type="number" />
            <Select value={protocol} onValueChange={setProtocol}>
              <SelectTrigger><SelectValue /></SelectTrigger>
              <SelectContent>
                <SelectItem value="https">HTTPS</SelectItem>
                <SelectItem value="http">HTTP</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {tagsQuery.data && (
            <div>
              <label className="text-sm font-medium mb-2 block">Filter by Tags</label>
              <div className="flex flex-wrap gap-2">
                {tagsQuery.data.map((tag: string) => (
                  <Badge
                    key={tag}
                    variant={selectedTags.includes(tag) ? "default" : "outline"}
                    className="cursor-pointer"
                    onClick={() => toggleTag(tag)}
                  >
                    {tag}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          <Button onClick={handleRunSuite} disabled={runSuiteMut.isPending} size="lg">
            {runSuiteMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Play className="h-4 w-4 mr-2" />}
            Run Full Verification Suite
          </Button>
        </CardContent>
      </Card>

      {/* Suite Results */}
      {suiteResult && (
        <Card>
          <CardHeader>
            <CardTitle className="flex items-center gap-3">
              Verification Report
              <Badge className={riskColors[suiteResult.overallRisk] || "bg-zinc-500"}>
                {suiteResult.overallRisk.toUpperCase()} RISK
              </Badge>
            </CardTitle>
            <CardDescription>
              Completed in {suiteResult.durationMs}ms against {suiteResult.targetHost}
            </CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 md:grid-cols-5 gap-3">
              <div className="text-center p-3 rounded bg-muted">
                <div className="text-2xl font-bold">{suiteResult.totalProbes}</div>
                <div className="text-xs text-muted-foreground">Total Probes</div>
              </div>
              <div className="text-center p-3 rounded bg-red-500/10">
                <div className="text-2xl font-bold text-red-500">{suiteResult.vulnerableCount}</div>
                <div className="text-xs text-muted-foreground">Vulnerable</div>
              </div>
              <div className="text-center p-3 rounded bg-green-500/10">
                <div className="text-2xl font-bold text-green-500">{suiteResult.notVulnerableCount}</div>
                <div className="text-xs text-muted-foreground">Not Vulnerable</div>
              </div>
              <div className="text-center p-3 rounded bg-yellow-500/10">
                <div className="text-2xl font-bold text-yellow-500">{suiteResult.inconclusiveCount}</div>
                <div className="text-xs text-muted-foreground">Inconclusive</div>
              </div>
              <div className="text-center p-3 rounded bg-muted">
                <div className="text-2xl font-bold text-zinc-400">{suiteResult.errorCount}</div>
                <div className="text-xs text-muted-foreground">Errors</div>
              </div>
            </div>

            <div className="space-y-2">
              {suiteResult.results?.map((r: any, i: number) => {
                const cfg = statusConfig[r.status] || statusConfig.error;
                const Icon = cfg.icon;
                return (
                  <div key={i} className="flex items-start gap-3 p-3 rounded border">
                    <Icon className={`h-5 w-5 mt-0.5 ${cfg.color}`} />
                    <div className="flex-1">
                      <div className="flex items-center justify-between">
                        <span className="font-medium text-sm">{r.probeName}</span>
                        <div className="flex items-center gap-2">
                          <Badge variant={r.status === "vulnerable" ? "destructive" : "outline"}>
                            {cfg.label}
                          </Badge>
                          <span className="text-xs text-muted-foreground">{r.confidence}% confidence</span>
                        </div>
                      </div>
                      <p className="text-sm text-muted-foreground mt-1">{r.evidence}</p>
                      {r.responseData?.statusCode && (
                        <span className="text-xs text-muted-foreground">HTTP {r.responseData.statusCode} · {r.responseData.responseTimeMs}ms</span>
                      )}
                    </div>
                  </div>
                );
              })}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Available Probes */}
      {probesQuery.data && (
        <Card>
          <CardHeader>
            <CardTitle>Available Probes ({probesQuery.data.length})</CardTitle>
            <CardDescription>Individual probes that can be run against a target</CardDescription>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {probesQuery.data.map((probe: any) => (
                <div key={probe.id} className="flex items-center justify-between p-3 rounded border">
                  <div className="flex-1">
                    <div className="flex items-center gap-2">
                      <span className="font-medium text-sm">{probe.name}</span>
                      <Badge className={riskColors[probe.severity] || "bg-zinc-500"}>{probe.severity}</Badge>
                      {probe.safeForProduction && <Badge variant="outline" className="text-green-500">Safe</Badge>}
                    </div>
                    <p className="text-xs text-muted-foreground mt-1">{probe.description}</p>
                    <div className="flex gap-1 mt-1">
                      {probe.cveIds?.map((cve: string) => <Badge key={cve} variant="outline" className="text-xs">{cve}</Badge>)}
                      {probe.tags?.map((tag: string) => <Badge key={tag} variant="secondary" className="text-xs">{tag}</Badge>)}
                    </div>
                  </div>
                  <Button size="sm" variant="outline" onClick={() => handleRunProbe(probe.id)} disabled={runProbeMut.isPending}>
                    <Play className="h-3 w-3 mr-1" /> Run
                  </Button>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
    </AppShell>
  );
}
