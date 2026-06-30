import { useState } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  Server, Network, ArrowRight, Brain, Shield, Wifi, Terminal,
  GitBranch, Lock, ChevronRight, Zap, Globe
} from "lucide-react";
import AppShell from "@/components/AppShell";

/** Lateral Movement — Plan and execute lateral movement across compromised networks.
 *  Use the AI planner to select optimal pivot techniques based on network topology,
 *  available credentials, and OPSEC constraints. Supports PtH, WinRM, SSH, DCOM, and more. */

export default function LateralMovement() {
  // Using sonner toast
  const [sourceHost, setSourceHost] = useState("");
  const [targetHost, setTargetHost] = useState("");
  const [os, setOs] = useState("windows");
  const [credentials, setCredentials] = useState("");
  const [networkContext, setNetworkContext] = useState("");

  const { data: techniques } = trpc.lateralMovement.techniques.useQuery();

  const quickPlan = trpc.lateralMovement.quickPlan.useMutation({
    onSuccess: () => toast.success("Pivot Plan Generated"),
  });

  const llmPlan = trpc.lateralMovement.generatePlan.useMutation({
    onSuccess: () => toast.success("AI Pivot Plan Generated"),
  });

  const handleQuickPlan = () => {
    quickPlan.mutate({
      sourceHost: sourceHost || "WORKSTATION-01",
      targetHost: targetHost || "DC01",
      targetOs: os,
      availableCredentials: credentials ? credentials.split(",").map(c => c.trim()) : ["domain_user"],
      networkContext: networkContext || "corporate LAN",
    });
  };

  const handleLlmPlan = () => {
    llmPlan.mutate({
      sourceHost: sourceHost || "WORKSTATION-01",
      targetHost: targetHost || "DC01",
      targetOs: os,
      availableCredentials: credentials ? credentials.split(",").map(c => c.trim()) : ["domain_user"],
      networkContext: networkContext || "corporate LAN",
    });
  };

  const plan = llmPlan.data || quickPlan.data;

  return (
      <AppShell activePath="/lateral-movement">
      <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold flex items-center gap-2">
          <Network className="w-7 h-7 text-purple-400" />
          Lateral Movement
        </h1>
        <p className="text-muted-foreground mt-1">
          Plan and execute lateral movement across compromised networks. The AI planner selects optimal pivot techniques based on network topology, available credentials, and OPSEC constraints.
        </p>
      </div>

      <Tabs defaultValue="planner" className="space-y-4">
        <TabsList className="bg-background/50 border">
          <TabsTrigger value="planner"><Brain className="w-4 h-4 mr-1" />PIVOT PLANNER</TabsTrigger>
          <TabsTrigger value="techniques"><GitBranch className="w-4 h-4 mr-1" />TECHNIQUE CATALOG</TabsTrigger>
        </TabsList>

        <TabsContent value="planner" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle className="text-base flex items-center gap-2">
                  <Zap className="w-4 h-4 text-yellow-400" />
                  Plan a Pivot
                </CardTitle>
                <CardDescription>Define source, target, and available credentials to generate a pivot plan</CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs text-muted-foreground mb-1 block">Source Host</label>
                    <Input value={sourceHost} onChange={e => setSourceHost(e.target.value)} placeholder="WORKSTATION-01" />
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground mb-1 block">Target Host</label>
                    <Input value={targetHost} onChange={e => setTargetHost(e.target.value)} placeholder="DC01" />
                  </div>
                </div>
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                  <div>
                    <label className="text-xs text-muted-foreground mb-1 block">Target OS</label>
                    <Select value={os} onValueChange={setOs}>
                      <SelectTrigger><SelectValue /></SelectTrigger>
                      <SelectContent>
                        <SelectItem value="windows">Windows</SelectItem>
                        <SelectItem value="linux">Linux</SelectItem>
                        <SelectItem value="macos">macOS</SelectItem>
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground mb-1 block">Available Credentials (comma-separated)</label>
                    <Input value={credentials} onChange={e => setCredentials(e.target.value)} placeholder="domain_user, ntlm_hash, ssh_key" />
                  </div>
                </div>
                <div>
                  <label className="text-xs text-muted-foreground mb-1 block">Network Context</label>
                  <Textarea value={networkContext} onChange={e => setNetworkContext(e.target.value)}
                    placeholder="e.g., Corporate LAN, 10.0.0.0/24, firewall between segments, SMB allowed..."
                    rows={2} />
                </div>
                <div className="flex gap-2">
                  <Button onClick={handleQuickPlan} variant="outline" className="flex-1" disabled={quickPlan.isPending}>
                    Quick Plan
                  </Button>
                  <Button onClick={handleLlmPlan} className="flex-1 bg-purple-600 hover:bg-purple-700" disabled={llmPlan.isPending}>
                    <Brain className="w-4 h-4 mr-1" />{llmPlan.isPending ? "Planning..." : "AI Deep Plan"}
                  </Button>
                </div>
              </CardContent>
            </Card>

            {/* Plan Result */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Pivot Plan</CardTitle>
              </CardHeader>
              <CardContent>
                {plan ? (
                  <div className="space-y-3">
                    {plan.recommendedTechnique && (
                      <div className="p-3 rounded-lg bg-purple-500/10 border border-purple-500/30">
                        <div className="text-sm font-medium text-purple-300">{plan.recommendedTechnique.name || plan.recommendedTechnique}</div>
                        {plan.recommendedTechnique.opsecRisk && (
                          <Badge variant="outline" className="text-xs mt-1">OPSEC: {plan.recommendedTechnique.opsecRisk}</Badge>
                        )}
                      </div>
                    )}
                    {plan.steps && plan.steps.map((step: any, i: number) => (
                      <div key={i} className="flex items-start gap-2 text-sm">
                        <div className="w-5 h-5 rounded-full bg-primary/20 flex items-center justify-center shrink-0 text-xs font-bold">{i + 1}</div>
                        <span>{typeof step === "string" ? step : step.description || step.command}</span>
                      </div>
                    ))}
                    {plan.tunnelConfig && (
                      <div className="p-2 rounded bg-card/50 border border-border/50">
                        <span className="text-xs font-medium text-muted-foreground">Tunnel Config:</span>
                        <pre className="text-xs mt-1 text-green-400 font-mono">{typeof plan.tunnelConfig === "string" ? plan.tunnelConfig : JSON.stringify(plan.tunnelConfig, null, 2)}</pre>
                      </div>
                    )}
                    {plan.reasoning && <p className="text-xs text-muted-foreground">{plan.reasoning}</p>}
                  </div>
                ) : (
                  <div className="text-center text-muted-foreground py-8">
                    <Network className="w-10 h-10 mx-auto mb-2 opacity-30" />
                    <p className="text-sm">Generate a plan to see results</p>
                  </div>
                )}
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        <TabsContent value="techniques" className="space-y-4">
          {techniques ? (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {techniques.map((tech: any) => (
                <Card key={tech.id || tech.name}>
                  <CardHeader className="pb-2">
                    <CardTitle className="text-sm flex items-center gap-2">
                      {tech.os === "windows" && <Server className="w-4 h-4 text-blue-400" />}
                      {tech.os === "linux" && <Terminal className="w-4 h-4 text-green-400" />}
                      {tech.os === "any" && <Globe className="w-4 h-4 text-cyan-400" />}
                      {tech.name}
                    </CardTitle>
                    <div className="flex gap-1 flex-wrap">
                      <Badge variant="outline" className="text-xs">{tech.os}</Badge>
                      {tech.requiresAdmin && <Badge variant="destructive" className="text-xs">Admin</Badge>}
                      {tech.opsecRisk && <Badge variant="secondary" className="text-xs">OPSEC: {tech.opsecRisk}</Badge>}
                    </div>
                  </CardHeader>
                  <CardContent>
                    <p className="text-xs text-muted-foreground">{tech.description}</p>
                    {tech.mitreTechnique && (
                      <Badge variant="outline" className="text-xs mt-2">{tech.mitreTechnique}</Badge>
                    )}
                    {tech.prerequisites && (
                      <div className="mt-2">
                        <span className="text-xs text-muted-foreground">Requires:</span>
                        <div className="flex flex-wrap gap-1 mt-1">
                          {tech.prerequisites.map((p: string, i: number) => (
                            <Badge key={i} variant="secondary" className="text-xs">{p}</Badge>
                          ))}
                        </div>
                      </div>
                    )}
                  </CardContent>
                </Card>
              ))}
            </div>
          ) : (
            <div className="text-center text-muted-foreground py-12">Loading technique catalog...</div>
          )}
        </TabsContent>
      </Tabs>
    </div>
      </AppShell>
  );
}
