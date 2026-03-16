import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { toast } from "sonner";
import {
  Skull, Radio, Shield, Target, Zap, CheckCircle2, XCircle,
  RefreshCw, AlertTriangle, ArrowRight, Server, Lock,
} from "lucide-react";

export default function TestLabImplant() {
  // toast from sonner is already imported
  const [selectedEnv, setSelectedEnv] = useState("");
  const [selectedChannel, setSelectedChannel] = useState("https");

  const { data: environments } = trpc.testLab.listEnvironments.useQuery();
  const runningEnvs = environments?.filter((e: any) => e.state === "running") ?? [];

  const deployViaExploit = trpc.testLab.runExploitToImplant.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        toast.success(`Ember Deployed! Agent ${data.agentId?.slice(0, 8)} is beaconing`);
      } else {
        toast.error(data.error || "Exploit chain failed");
      }
    },
    onError: (err) => toast.error(err.message),
  });

  const testC2 = trpc.testLab.testC2Channel.useMutation({
    onSuccess: (data) => {
      if (data.success) {
        toast.success(`C2 Channel OK: ${data.channel}: ${data.latencyMs}ms latency, detection risk: ${data.detectionRisk}`);
      } else {
        toast.error(`C2 Channel Failed: ${data.channel}: ${data.latencyMs}ms latency, detection risk: ${data.detectionRisk}`);
      }
    },
    onError: (err) => toast.error(err.message),
  });

  const validateAll = trpc.testLab.validateAllC2Channels.useMutation({
    onSuccess: (data) => {
      const passed = data.results?.filter((r: any) => r.success).length ?? 0;
      const total = data.results?.length ?? 0;
      toast.success(`C2 Validation: ${passed}/${total} channels passed — Overall score: ${data.overallScore ?? 0}%`);
    },
    onError: (err) => toast.error(err.message),
  });

  const channels = ["https", "dns_covert", "doh_tunnel", "websocket", "icmp_covert", "smb_pipe", "steganography", "p2p_mesh"];

  return (
    <div className="p-6 space-y-6">
      <div className="flex items-center gap-3">
        <div className="p-2 bg-red-500/10 rounded-lg">
          <Skull className="h-7 w-7 text-red-400" />
        </div>
        <div>
          <h1 className="text-2xl font-bold">Implant Testing</h1>
          <p className="text-muted-foreground">
            Deploy Ember agents via exploit chains and validate C2 communications
          </p>
        </div>
      </div>

      {/* Exploit-to-Implant Pipeline */}
      <Card className="border-red-500/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Zap className="h-5 w-5 text-red-400" />
            Exploit-to-Implant Pipeline
          </CardTitle>
          <CardDescription>
            Scan target for RCE vulnerabilities, generate Ember payload, deliver via exploit chain, validate beacon
          </CardDescription>
        </CardHeader>
        <CardContent>
          {/* Pipeline Visualization */}
          <div className="flex items-center justify-between mb-6 p-4 bg-muted/20 rounded-lg overflow-x-auto">
            {[
              { icon: Target, label: "Scan Target", color: "text-amber-400" },
              { icon: Shield, label: "Find RCE", color: "text-red-400" },
              { icon: Skull, label: "Gen Payload", color: "text-purple-400" },
              { icon: Zap, label: "Exploit", color: "text-orange-400" },
              { icon: Radio, label: "Beacon", color: "text-blue-400" },
              { icon: CheckCircle2, label: "Validate", color: "text-emerald-400" },
            ].map((step, idx) => (
              <div key={idx} className="flex items-center gap-2">
                <div className="flex flex-col items-center gap-1">
                  <step.icon className={`h-6 w-6 ${step.color}`} />
                  <span className="text-xs text-muted-foreground whitespace-nowrap">{step.label}</span>
                </div>
                {idx < 5 && <ArrowRight className="h-4 w-4 text-muted-foreground mx-2" />}
              </div>
            ))}
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Target Environment</label>
              <Select value={selectedEnv} onValueChange={setSelectedEnv}>
                <SelectTrigger><SelectValue placeholder="Select environment..." /></SelectTrigger>
                <SelectContent>
                  {runningEnvs.map((env: any) => (
                    <SelectItem key={env.id} value={env.id}>
                      {env.name} ({env.targets?.length ?? 0} targets)
                    </SelectItem>
                  ))}
                  {runningEnvs.length === 0 && (
                    <SelectItem value="none" disabled>No running environments</SelectItem>
                  )}
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Primary C2 Channel</label>
              <Select value={selectedChannel} onValueChange={setSelectedChannel}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {channels.map(ch => (
                    <SelectItem key={ch} value={ch}>{ch.replace(/_/g, " ")}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-end">
              <Button
                className="w-full bg-red-600 hover:bg-red-700"
                disabled={!selectedEnv || deployViaExploit.isPending}
                onClick={() => deployViaExploit.mutate({
                  environmentId: selectedEnv,
                  channel: selectedChannel,
                })}
              >
                {deployViaExploit.isPending ? (
                  <RefreshCw className="h-4 w-4 mr-2 animate-spin" />
                ) : (
                  <Skull className="h-4 w-4 mr-2" />
                )}
                Deploy Ember via Exploit
              </Button>
            </div>
          </div>

          {deployViaExploit.data && (
            <div className={`p-4 rounded-lg border ${
              deployViaExploit.data.success
                ? "bg-emerald-500/10 border-emerald-500/20"
                : "bg-red-500/10 border-red-500/20"
            }`}>
              <div className="flex items-center gap-2 mb-2">
                {deployViaExploit.data.success ? (
                  <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                ) : (
                  <XCircle className="h-5 w-5 text-red-400" />
                )}
                <span className="font-medium">
                  {deployViaExploit.data.success ? "Ember Agent Deployed Successfully" : "Deployment Failed"}
                </span>
              </div>
              {deployViaExploit.data.success && (
                <div className="grid grid-cols-2 gap-2 text-xs">
                  <div className="p-2 bg-background/50 rounded">
                    <span className="text-muted-foreground">Agent ID:</span>{" "}
                    <span className="font-mono">{deployViaExploit.data.agentId?.slice(0, 12)}</span>
                  </div>
                  <div className="p-2 bg-background/50 rounded">
                    <span className="text-muted-foreground">Exploit:</span>{" "}
                    <span>{deployViaExploit.data.exploitUsed || "auto-selected"}</span>
                  </div>
                </div>
              )}
            </div>
          )}
        </CardContent>
      </Card>

      {/* C2 Channel Validation */}
      <Card className="border-blue-500/20">
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Radio className="h-5 w-5 text-blue-400" />
            C2 Channel Validation
          </CardTitle>
          <CardDescription>
            Test individual C2 channels or validate all 8 channels against a target
          </CardDescription>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-4">
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Target Environment</label>
              <Select value={selectedEnv} onValueChange={setSelectedEnv}>
                <SelectTrigger><SelectValue placeholder="Select environment..." /></SelectTrigger>
                <SelectContent>
                  {runningEnvs.map((env: any) => (
                    <SelectItem key={env.id} value={env.id}>{env.name}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div>
              <label className="text-xs text-muted-foreground mb-1 block">Channel</label>
              <Select value={selectedChannel} onValueChange={setSelectedChannel}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  {channels.map(ch => (
                    <SelectItem key={ch} value={ch}>{ch.replace(/_/g, " ")}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-end gap-2">
              <Button
                variant="outline"
                className="flex-1"
                disabled={!selectedEnv || testC2.isPending}
                onClick={() => testC2.mutate({
                  environmentId: selectedEnv,
                  channel: selectedChannel,
                })}
              >
                <Radio className="h-4 w-4 mr-2" /> Test Channel
              </Button>
              <Button
                className="flex-1"
                disabled={!selectedEnv || validateAll.isPending}
                onClick={() => validateAll.mutate({ environmentId: selectedEnv })}
              >
                {validateAll.isPending ? <RefreshCw className="h-4 w-4 mr-2 animate-spin" /> : <Shield className="h-4 w-4 mr-2" />}
                Validate All
              </Button>
            </div>
          </div>

          {/* Channel Results Grid */}
          {validateAll.data?.results && (
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 mt-4">
              {validateAll.data.results.map((result: any) => (
                <div
                  key={result.channel}
                  className={`p-3 rounded-lg border ${
                    result.success
                      ? "bg-emerald-500/5 border-emerald-500/20"
                      : "bg-red-500/5 border-red-500/20"
                  }`}
                >
                  <div className="flex items-center justify-between mb-2">
                    <span className="text-xs font-medium">{result.channel?.replace(/_/g, " ")}</span>
                    {result.success ? (
                      <CheckCircle2 className="h-4 w-4 text-emerald-400" />
                    ) : (
                      <XCircle className="h-4 w-4 text-red-400" />
                    )}
                  </div>
                  <div className="space-y-1 text-xs">
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Latency</span>
                      <span className="font-mono">{result.latencyMs}ms</span>
                    </div>
                    <div className="flex justify-between">
                      <span className="text-muted-foreground">Detection</span>
                      <Badge variant={
                        result.detectionRisk === "low" ? "default" :
                        result.detectionRisk === "medium" ? "secondary" : "destructive"
                      } className="text-xs h-4">
                        {result.detectionRisk}
                      </Badge>
                    </div>
                    {result.encryptionVerified && (
                      <div className="flex items-center gap-1 text-emerald-400">
                        <Lock className="h-3 w-3" />
                        <span>Encrypted</span>
                      </div>
                    )}
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardContent>
      </Card>

      {/* Safety Notice */}
      <div className="p-4 bg-amber-500/10 border border-amber-500/20 rounded-lg">
        <div className="flex items-start gap-3">
          <AlertTriangle className="h-5 w-5 text-amber-400 mt-0.5" />
          <div>
            <p className="font-medium text-amber-400 text-sm">Safety Engine Active</p>
            <p className="text-xs text-muted-foreground mt-1">
              All exploit-to-implant operations are gated by the AC3 Safety Engine. Deployment is only allowed
              against authorized test lab environments. The safety level must be set to "full_exploitation" or
              higher for live exploit testing.
            </p>
          </div>
        </div>
      </div>
    </div>
  );
}
