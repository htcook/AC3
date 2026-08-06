import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { toast } from "sonner";
import {
  ShieldCheck, AlertTriangle, Clock, Gauge, ChevronLeft,
  CheckCircle2, XCircle, Loader2, RefreshCw, Shield
} from "lucide-react";
import { Link } from "wouter";
import { useState } from "react";

export default function SSILPolicies() {
  const utils = trpc.useUtils();
  const { data: policies, isLoading: policiesLoading } = trpc.ssil.listPolicies.useQuery();
  const { data: activePolicy, isLoading: activePolicyLoading } = trpc.ssil.getActivePolicy.useQuery();
  const { data: violations } = trpc.ssil.getPolicyViolations.useQuery({ limit: 20 });
  const { data: rateLimiter } = trpc.ssil.getRateLimiterStats.useQuery();
  const { data: escalationRules } = trpc.ssil.getEscalationRules.useQuery();

  const setActiveMutation = trpc.ssil.setActivePolicy.useMutation({
    onSuccess: (data) => {
      toast.success(`Active profile set to: ${data.activeProfileId}`);
      utils.ssil.getActivePolicy.invalidate();
      utils.ssil.getDashboardSummary.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const [testHost, setTestHost] = useState("example.com");
  const [testPort, setTestPort] = useState(443);
  const [testMode, setTestMode] = useState<string>("passive");
  const [testScanner, setTestScanner] = useState("nuclei");

  const { data: evalResult, refetch: evaluateScan } = trpc.ssil.evaluateScanRequest.useQuery(
    { scanner: testScanner, mode: testMode as any, host: testHost, port: testPort },
    { enabled: false }
  );

  const isLoading = policiesLoading || activePolicyLoading;

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center gap-4">
          <Link href="/ssil">
            <Button variant="ghost" size="icon">
              <ChevronLeft className="h-4 w-4" />
            </Button>
          </Link>
          <div>
            <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
              <ShieldCheck className="h-6 w-6 text-cyan-400" />
              Scan Policy Engine
            </h1>
            <p className="text-sm text-muted-foreground mt-1 max-w-3xl">Define and manage security policies that govern the Security Simulation & Intelligence Layer. Policies control how automated testing behaves — which techniques are allowed, what severity thresholds trigger alerts, and how findings are classified. Create policies for different engagement types (internal, external, web app) and assign them to specific operations or schedules.</p>
            <p className="text-muted-foreground mt-1">
              Manage scan mode profiles, rate limits, and escalation rules
            </p>
          </div>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="h-8 w-8 animate-spin text-cyan-400" />
          </div>
        ) : (
          <>
            {/* Active Profile */}
            <Card className="border-cyan-500/20 bg-card/50">
              <CardHeader>
                <CardTitle className="text-lg">Active Profile</CardTitle>
                <CardDescription>
                  Currently enforced scan policy profile
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-4 mb-4">
                  <Badge className="text-lg px-4 py-1 bg-cyan-500/20 text-cyan-300 border-cyan-500/40">
                    {activePolicy?.activeProfileId}
                  </Badge>
                  <div className="text-sm text-muted-foreground font-mono bg-muted/30 p-2 rounded flex-1">
                    {activePolicy?.attestation}
                  </div>
                </div>

                {activePolicy?.profile && (
                  <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mt-4">
                    <div className="p-3 bg-muted/20 rounded">
                      <div className="text-xs text-muted-foreground">Mode</div>
                      <div className="font-mono text-sm mt-1">{(activePolicy.profile as any).mode || activePolicy.profile.name}</div>
                    </div>
                    <div className="p-3 bg-muted/20 rounded">
                      <div className="text-xs text-muted-foreground">Per-Host RPS</div>
                      <div className="font-mono text-sm mt-1">{activePolicy.profile.rateLimits?.perHostRps}</div>
                    </div>
                    <div className="p-3 bg-muted/20 rounded">
                      <div className="text-xs text-muted-foreground">Global Concurrent</div>
                      <div className="font-mono text-sm mt-1">{activePolicy.profile.rateLimits?.globalConcurrent}</div>
                    </div>
                    <div className="p-3 bg-muted/20 rounded">
                      <div className="text-xs text-muted-foreground">Log Level</div>
                      <div className="font-mono text-sm mt-1">{activePolicy.profile.logging?.logLevel}</div>
                    </div>
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Profile Selector */}
            <Card className="border-border/50 bg-card/50">
              <CardHeader>
                <CardTitle className="text-lg">Available Profiles</CardTitle>
                <CardDescription>
                  Click to activate a different scan policy profile
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
                  {policies?.map((profile: any) => (
                    <div
                      key={profile.id}
                      className={`p-4 rounded-lg border cursor-pointer transition-all ${
                        profile.id === activePolicy?.activeProfileId
                          ? "border-cyan-500/50 bg-cyan-500/10"
                          : "border-border/50 hover:border-cyan-500/30"
                      }`}
                      onClick={() => {
                        if (profile.id !== activePolicy?.activeProfileId) {
                          setActiveMutation.mutate({ profileId: profile.id });
                        }
                      }}
                    >
                      <div className="flex items-center justify-between mb-2">
                        <span className="font-semibold">{profile.name || profile.id}</span>
                        {profile.id === activePolicy?.activeProfileId && (
                          <CheckCircle2 className="h-4 w-4 text-cyan-400" />
                        )}
                      </div>
                      <div className="text-xs text-muted-foreground space-y-1">
                        <div>Mode: <span className="font-mono">{profile.mode}</span></div>
                        <div>RPS: <span className="font-mono">{profile.rateLimits?.perHostRps}</span></div>
                        <div>Concurrent: <span className="font-mono">{profile.rateLimits?.globalConcurrent}</span></div>
                      </div>
                      {profile.passiveControls && (
                        <div className="flex flex-wrap gap-1 mt-2">
                          {profile.passiveControls.map((ctrl: any, i: number) => (
                            <Badge key={i} variant="secondary" className="text-xs">
                              {ctrl.id}
                            </Badge>
                          ))}
                        </div>
                      )}
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Policy Tester */}
            <Card className="border-border/50 bg-card/50">
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Gauge className="h-5 w-5 text-cyan-400" />
                  Policy Evaluator
                </CardTitle>
                <CardDescription>
                  Test whether a scan request would be permitted under the active policy
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-5 gap-3 mb-4">
                  <div>
                    <label className="text-xs text-muted-foreground">Scanner</label>
                    <select
                      className="w-full mt-1 bg-muted/30 border border-border rounded px-2 py-1.5 text-sm"
                      value={testScanner}
                      onChange={(e) => setTestScanner(e.target.value)}
                    >
                      <option value="nuclei">Nuclei</option>
                      <option value="zgrab2">ZGrab2</option>
                      <option value="nmap_orchestrated">Port Discovery</option>
                      <option value="zap">ZAP</option>
                      <option value="web_crawler">Web Crawler</option>
                      <option value="domain_intel">Domain Intel</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground">Mode</label>
                    <select
                      className="w-full mt-1 bg-muted/30 border border-border rounded px-2 py-1.5 text-sm"
                      value={testMode}
                      onChange={(e) => setTestMode(e.target.value)}
                    >
                      <option value="passive">Passive</option>
                      <option value="active-low">Active Low</option>
                      <option value="active-standard">Active Standard</option>
                      <option value="active-aggressive">Active Aggressive</option>
                    </select>
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground">Host</label>
                    <input
                      className="w-full mt-1 bg-muted/30 border border-border rounded px-2 py-1.5 text-sm"
                      value={testHost}
                      onChange={(e) => setTestHost(e.target.value)}
                    />
                  </div>
                  <div>
                    <label className="text-xs text-muted-foreground">Port</label>
                    <input
                      type="number"
                      className="w-full mt-1 bg-muted/30 border border-border rounded px-2 py-1.5 text-sm"
                      value={testPort}
                      onChange={(e) => setTestPort(parseInt(e.target.value) || 0)}
                    />
                  </div>
                  <div className="flex items-end">
                    <Button size="sm" onClick={() => evaluateScan()} className="w-full">
                      Evaluate
                    </Button>
                  </div>
                </div>

                {evalResult && (
                  <div className={`p-3 rounded border ${
                    evalResult.allowed
                      ? "border-green-500/30 bg-green-500/10"
                      : "border-red-500/30 bg-red-500/10"
                  }`}>
                    <div className="flex items-center gap-2">
                      {evalResult.allowed ? (
                        <CheckCircle2 className="h-4 w-4 text-green-400" />
                      ) : (
                        <XCircle className="h-4 w-4 text-red-400" />
                      )}
                      <span className={evalResult.allowed ? "text-green-300" : "text-red-300"}>
                        {evalResult.allowed ? "PERMITTED" : "BLOCKED"}
                      </span>
                    </div>
                    {evalResult.reason && (
                      <p className="text-xs text-muted-foreground mt-1">{evalResult.reason}</p>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Escalation Rules */}
            {escalationRules && escalationRules.length > 0 && (
              <Card className="border-border/50 bg-card/50">
                <CardHeader>
                  <CardTitle className="text-lg flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5 text-yellow-400" />
                    Escalation Rules
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    {escalationRules.map((rule: any, i: number) => (
                      <div key={i} className="p-3 bg-muted/20 rounded border border-border/30">
                        <div className="flex items-center justify-between mb-1">
                          <span className="font-semibold text-sm">{rule.name || rule.id}</span>
                          <Badge variant="outline" className="text-xs">
                            {rule.fromMode} → {rule.toMode}
                          </Badge>
                        </div>
                        <p className="text-xs text-muted-foreground">{rule.description}</p>
                        {rule.conditions && (
                          <div className="flex flex-wrap gap-1 mt-2">
                            {rule.conditions.map((cond: any, j: number) => (
                              <Badge key={j} variant="secondary" className="text-xs">
                                {cond.type}: {cond.threshold}
                              </Badge>
                            ))}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Rate Limiter Stats */}
            {rateLimiter && (
              <Card className="border-border/50 bg-card/50">
                <CardHeader>
                  <CardTitle className="text-lg flex items-center gap-2">
                    <Gauge className="h-5 w-5 text-cyan-400" />
                    Rate Limiter Status
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-3 gap-4">
                    <div className="p-3 bg-muted/20 rounded text-center">
                      <div className="text-2xl font-bold text-cyan-300">{rateLimiter.globalConcurrent}</div>
                      <div className="text-xs text-muted-foreground">Global Concurrent</div>
                    </div>
                    <div className="p-3 bg-muted/20 rounded text-center">
                      <div className="text-2xl font-bold text-cyan-300">{rateLimiter.hostBuckets}</div>
                      <div className="text-xs text-muted-foreground">Host Buckets</div>
                    </div>
                    <div className="p-3 bg-muted/20 rounded text-center">
                      <div className="text-2xl font-bold text-cyan-300">{rateLimiter.domainBuckets}</div>
                      <div className="text-xs text-muted-foreground">Domain Buckets</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            )}

            {/* Policy Violations */}
            {violations && violations.length > 0 && (
              <Card className="border-red-500/20 bg-card/50">
                <CardHeader>
                  <CardTitle className="text-lg flex items-center gap-2">
                    <AlertTriangle className="h-5 w-5 text-red-400" />
                    Recent Policy Violations ({violations.length})
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-2 max-h-80 overflow-y-auto">
                    {violations.map((v: any, i: number) => (
                      <div key={i} className="p-2 bg-red-500/5 border border-red-500/20 rounded text-sm">
                        <div className="flex items-center justify-between">
                          <span className="font-mono text-red-300">{v.scanner} → {v.mode}</span>
                          <span className="text-xs text-muted-foreground">
                            {new Date(v.timestamp).toLocaleString()}
                          </span>
                        </div>
                        <p className="text-xs text-muted-foreground mt-1">{v.reason}</p>
                      </div>
                    ))}
                  </div>
                </CardContent>
              </Card>
            )}
          </>
        )}
      </div>
    </AppShell>
  );
}
