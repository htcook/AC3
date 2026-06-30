import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import { Rocket, Play, Loader2, CheckCircle, XCircle, AlertTriangle, MinusCircle } from "lucide-react";
import AppShell from "@/components/AppShell";

const statusIcons: Record<string, typeof CheckCircle> = {
  pass: CheckCircle,
  fail: XCircle,
  warn: AlertTriangle,
  skip: MinusCircle,
};

const statusColors: Record<string, string> = {
  pass: "text-green-500",
  fail: "text-red-500",
  warn: "text-yellow-500",
  skip: "text-zinc-400",
};

const recommendationColors: Record<string, string> = {
  proceed: "bg-green-500 text-white",
  proceed_with_caution: "bg-yellow-500 text-black",
  skip: "bg-red-500 text-white",
  manual_review: "bg-blue-500 text-white",
};

export default function PreFlightChecks() {
  const [targetHost, setTargetHost] = useState("");
  const [targetPort, setTargetPort] = useState("");
  const [service, setService] = useState("");
  const [serviceVersion, setServiceVersion] = useState("");
  const [cveId, setCveId] = useState("");
  const [protocol, setProtocol] = useState<string>("https");
  const [requiresAuth, setRequiresAuth] = useState(false);
  const [username, setUsername] = useState("");
  const [password, setPassword] = useState("");
  const [result, setResult] = useState<any>(null);

  const runMut = trpc.preflightChecks.run.useMutation({
    onSuccess: (data) => {
      setResult(data);
      toast.success(`Pre-flight complete: ${data.recommendation.replace(/_/g, " ")}`);
    },
    onError: (err) => toast.error(err.message),
  });

  const handleRun = () => {
    if (!targetHost.trim()) { toast.error("Enter a target host"); return; }
    runMut.mutate({
      targetHost: targetHost.trim(),
      targetPort: targetPort ? parseInt(targetPort) : undefined,
      service: service.trim() || undefined,
      serviceVersion: serviceVersion.trim() || undefined,
      cveId: cveId.trim() || undefined,
      protocol: protocol as any,
      requiresAuth,
      authCredentials: requiresAuth && username ? { username, password } : undefined,
    });
  };

  return (
    <AppShell activePath="/preflight-checks">
      <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Rocket className="h-6 w-6 text-orange-500" />
          Exploit Pre-Flight Checks
        </h1>
        <p className="text-muted-foreground mt-1">
          Assess exploit success likelihood before execution to reduce wasted test cycles.
        </p>
      </div>

      {/* Configuration */}
      <Card>
        <CardHeader>
          <CardTitle>Pre-Flight Configuration</CardTitle>
          <CardDescription>Configure target and exploit parameters for pre-flight assessment</CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4">
            <div className="md:col-span-2">
              <label className="text-sm font-medium mb-1 block">Target Host</label>
              <Input placeholder="192.168.1.100 or target.example.com" value={targetHost} onChange={e => setTargetHost(e.target.value)} />
            </div>
            <div>
              <label className="text-sm font-medium mb-1 block">Port</label>
              <Input placeholder="443" value={targetPort} onChange={e => setTargetPort(e.target.value)} type="number" />
            </div>
            <div>
              <label className="text-sm font-medium mb-1 block">Protocol</label>
              <Select value={protocol} onValueChange={setProtocol}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="https">HTTPS</SelectItem>
                  <SelectItem value="http">HTTP</SelectItem>
                  <SelectItem value="tcp">TCP</SelectItem>
                  <SelectItem value="udp">UDP</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
            <Input placeholder="Service (e.g., Apache)" value={service} onChange={e => setService(e.target.value)} />
            <Input placeholder="Version (e.g., 2.4.49)" value={serviceVersion} onChange={e => setServiceVersion(e.target.value)} />
            <Input placeholder="CVE ID (e.g., CVE-2021-44228)" value={cveId} onChange={e => setCveId(e.target.value)} />
          </div>

          <div className="flex items-center gap-3">
            <Switch checked={requiresAuth} onCheckedChange={setRequiresAuth} />
            <span className="text-sm">Requires Authentication</span>
          </div>

          {requiresAuth && (
            <div className="grid grid-cols-2 gap-4">
              <Input placeholder="Username" value={username} onChange={e => setUsername(e.target.value)} />
              <Input placeholder="Password" type="password" value={password} onChange={e => setPassword(e.target.value)} />
            </div>
          )}

          <Button onClick={handleRun} disabled={runMut.isPending}>
            {runMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Play className="h-4 w-4 mr-2" />}
            Run Pre-Flight Checks
          </Button>
        </CardContent>
      </Card>

      {/* Results */}
      {result && (
        <>
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-3">
                Pre-Flight Results
                <Badge className={recommendationColors[result.recommendation] || "bg-zinc-500"}>
                  {result.recommendation.replace(/_/g, " ").toUpperCase()}
                </Badge>
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 md:grid-cols-3 gap-4">
                <div className="text-center p-4 rounded bg-muted">
                  <div className="text-3xl font-bold">{result.overallConfidence}%</div>
                  <div className="text-xs text-muted-foreground">Overall Confidence</div>
                </div>
                <div className="text-center p-4 rounded bg-muted">
                  <div className="text-3xl font-bold">{result.estimatedSuccessRate}%</div>
                  <div className="text-xs text-muted-foreground">Est. Success Rate</div>
                </div>
                <div className="text-center p-4 rounded bg-muted">
                  <div className="text-3xl font-bold">{result.checks?.length ?? 0}</div>
                  <div className="text-xs text-muted-foreground">Checks Run</div>
                </div>
              </div>

              <p className="text-sm text-muted-foreground">{result.reasoning}</p>
            </CardContent>
          </Card>

          {/* Individual Checks */}
          <Card>
            <CardHeader><CardTitle>Check Details</CardTitle></CardHeader>
            <CardContent>
              <div className="space-y-3">
                {result.checks?.map((check: any, i: number) => {
                  const Icon = statusIcons[check.status] || MinusCircle;
                  return (
                    <div key={i} className="flex items-start gap-3 p-3 rounded border">
                      <Icon className={`h-5 w-5 mt-0.5 ${statusColors[check.status] || "text-zinc-400"}`} />
                      <div className="flex-1">
                        <div className="flex items-center justify-between">
                          <span className="font-medium text-sm">{check.checkName}</span>
                          <div className="flex items-center gap-2">
                            <Badge variant="outline">{check.category}</Badge>
                            <span className="text-xs text-muted-foreground">{check.confidence}% confidence</span>
                            <span className="text-xs text-muted-foreground">{check.durationMs}ms</span>
                          </div>
                        </div>
                        <p className="text-sm text-muted-foreground mt-1">{check.detail}</p>
                      </div>
                    </div>
                  );
                })}
              </div>
            </CardContent>
          </Card>

          {/* Blockers & Warnings */}
          {(result.blockers?.length > 0 || result.warnings?.length > 0) && (
            <Card>
              <CardHeader><CardTitle>Issues</CardTitle></CardHeader>
              <CardContent className="space-y-2">
                {result.blockers?.map((b: string, i: number) => (
                  <div key={`b-${i}`} className="flex items-center gap-2 p-2 rounded border border-red-500/30 bg-red-500/5">
                    <XCircle className="h-4 w-4 text-red-500 shrink-0" />
                    <span className="text-sm">{b}</span>
                  </div>
                ))}
                {result.warnings?.map((w: string, i: number) => (
                  <div key={`w-${i}`} className="flex items-center gap-2 p-2 rounded border border-yellow-500/30 bg-yellow-500/5">
                    <AlertTriangle className="h-4 w-4 text-yellow-500 shrink-0" />
                    <span className="text-sm">{w}</span>
                  </div>
                ))}
              </CardContent>
            </Card>
          )}
        </>
      )}
    </div>
    </AppShell>
  );
}
