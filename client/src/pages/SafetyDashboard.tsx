import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { toast } from "sonner";
import {
  Shield, ShieldCheck, ShieldAlert, ShieldOff, ShieldX,
  Activity, AlertTriangle, CheckCircle2, XCircle, Zap,
  Target, Clock, Eye, Lock, Unlock, BarChart3, FileText,
  Radio, Gauge, TrendingUp, Crosshair,
} from "lucide-react";

// ─── Safety Level Config ────────────────────────────────────────────────────

const LEVEL_CONFIG: Record<string, {
  icon: typeof Shield; color: string; bg: string; border: string; ring: string;
}> = {
  passive_only: { icon: Eye, color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/30", ring: "ring-blue-500/20" },
  low_impact: { icon: ShieldCheck, color: "text-emerald-400", bg: "bg-emerald-500/10", border: "border-emerald-500/30", ring: "ring-emerald-500/20" },
  standard: { icon: Shield, color: "text-amber-400", bg: "bg-amber-500/10", border: "border-amber-500/30", ring: "ring-amber-500/20" },
  full_exploitation: { icon: Zap, color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/30", ring: "ring-red-500/20" },
};

const RISK_COLORS: Record<string, string> = {
  none: "text-zinc-400", minimal: "text-blue-400", moderate: "text-amber-400",
  significant: "text-orange-400", critical: "text-red-400",
};

export default function SafetyDashboard() {
  
  const [selectedEngagement, setSelectedEngagement] = useState<number | null>(null);
  const [testTool, setTestTool] = useState("nmap");
  const [testArgs, setTestArgs] = useState("-sV -sC -T4 -p 1-1000");
  const [testTarget, setTestTarget] = useState("192.168.1.0/24");
  const [testLevel, setTestLevel] = useState<string>("standard");

  // ─── Queries ────────────────────────────────────────────────────────────
  const engagements = trpc.engagement.list.useQuery(undefined, { retry: false });
  const levels = trpc.safetyEngine.getLevels.useQuery();
  const compareLevels = trpc.safetyEngine.compareLevels.useQuery();

  const engineState = trpc.safetyEngine.getEngineState.useQuery(
    { engagementId: selectedEngagement! },
    { enabled: !!selectedEngagement }
  );
  const auditLog = trpc.safetyEngine.getAuditLog.useQuery(
    { engagementId: selectedEngagement!, limit: 200 },
    { enabled: !!selectedEngagement }
  );
  const blockedActions = trpc.safetyEngine.getBlockedActions.useQuery(
    { engagementId: selectedEngagement! },
    { enabled: !!selectedEngagement }
  );
  const blastEstimate = trpc.safetyEngine.estimateBlastRadius.useQuery(
    { tool: testTool, args: testArgs, target: testTarget, level: testLevel as any },
    { enabled: !!testTool && !!testArgs }
  );

  // ─── Mutations ──────────────────────────────────────────────────────────
  const setLevel = trpc.safetyEngine.setSafetyLevel.useMutation({
    onSuccess: (data) => {
      toast.success(`Safety Level Updated: Changed from ${data.previousLevel} to ${data.newLevel}`);
      engineState.refetch();
    },
  });
  const assessCmd = trpc.safetyEngine.assessCommand.useMutation({
    onSuccess: () => { auditLog.refetch(); blockedActions.refetch(); engineState.refetch(); },
  });

  // ─── Derived ────────────────────────────────────────────────────────────
  const stats = engineState.data?.stats;
  const currentLevel = engineState.data?.safetyLevel || "standard";
  const currentConfig = LEVEL_CONFIG[currentLevel] || LEVEL_CONFIG.standard;
  const CurrentIcon = currentConfig.icon;

  const activeEngagements = useMemo(() => {
    if (!engagements.data) return [];
    const list = Array.isArray(engagements.data) ? engagements.data : (engagements.data as any)?.engagements || [];
    return list.filter((e: any) => e.status === "active" || e.status === "planning");
  }, [engagements.data]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-7 w-7 text-blue-400" />
            Production-Safe Autonomous Mode
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Configurable safety guardrails with predictive blast radius estimation. Every tool execution is assessed before running.
          </p>
        </div>
        {selectedEngagement && (
          <div className={`flex items-center gap-2 px-4 py-2 rounded-lg ${currentConfig.bg} ${currentConfig.border} border`}>
            <CurrentIcon className={`h-5 w-5 ${currentConfig.color}`} />
            <span className={`font-semibold ${currentConfig.color}`}>
              {engineState.data?.profile.label || "Loading..."}
            </span>
          </div>
        )}
      </div>

      {/* Engagement Selector */}
      <Card className="border-border/50">
        <CardContent className="pt-4">
          <div className="flex items-center gap-4">
            <Label className="whitespace-nowrap font-medium">Active Engagement:</Label>
            <Select
              value={selectedEngagement?.toString() || ""}
              onValueChange={(v) => setSelectedEngagement(parseInt(v))}
            >
              <SelectTrigger className="w-80">
                <SelectValue placeholder="Select an engagement..." />
              </SelectTrigger>
              <SelectContent>
                {activeEngagements.map((e: any) => (
                  <SelectItem key={e.id} value={e.id.toString()}>
                    {e.name} ({e.status})
                  </SelectItem>
                ))}
              </SelectContent>
            </Select>
          </div>
        </CardContent>
      </Card>

      <Tabs defaultValue="levels" className="space-y-4">
        <TabsList>
          <TabsTrigger value="levels">Safety Levels</TabsTrigger>
          <TabsTrigger value="blast">Blast Radius Simulator</TabsTrigger>
          <TabsTrigger value="audit">Audit Trail</TabsTrigger>
          <TabsTrigger value="stats">Statistics</TabsTrigger>
          <TabsTrigger value="compare">Level Comparison</TabsTrigger>
        </TabsList>

        {/* ─── Safety Levels Tab ─────────────────────────────────────── */}
        <TabsContent value="levels" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 xl:grid-cols-4 gap-4">
            {levels.data?.map((level) => {
              const config = LEVEL_CONFIG[level.level] || LEVEL_CONFIG.standard;
              const Icon = config.icon;
              const isActive = currentLevel === level.level;
              return (
                <Card
                  key={level.level}
                  className={`relative transition-all cursor-pointer hover:ring-2 ${config.ring} ${
                    isActive ? `ring-2 ${config.ring} ${config.bg}` : "border-border/50"
                  }`}
                  onClick={() => {
                    if (selectedEngagement && !isActive) {
                      setLevel.mutate({ engagementId: selectedEngagement, level: level.level as any });
                    }
                  }}
                >
                  {isActive && (
                    <div className="absolute top-2 right-2">
                      <Badge variant="outline" className={`${config.color} ${config.border} text-xs`}>Active</Badge>
                    </div>
                  )}
                  <CardHeader className="pb-2">
                    <div className="flex items-center gap-2">
                      <div className={`p-2 rounded-lg ${config.bg}`}>
                        <Icon className={`h-5 w-5 ${config.color}`} />
                      </div>
                      <CardTitle className="text-base">{level.label}</CardTitle>
                    </div>
                  </CardHeader>
                  <CardContent>
                    <p className="text-xs text-muted-foreground leading-relaxed">{level.description}</p>
                  </CardContent>
                </Card>
              );
            })}
          </div>

          {/* Current Profile Details */}
          {selectedEngagement && engineState.data?.profile && (
            <Card className="border-border/50">
              <CardHeader>
                <CardTitle className="text-base">Active Profile Details</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-4 text-sm">
                  <div>
                    <span className="text-muted-foreground">Max Concurrent/Target</span>
                    <p className="font-mono font-semibold">{engineState.data.profile.maxConcurrentPerTarget}</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Max RPS/Host</span>
                    <p className="font-mono font-semibold">{engineState.data.profile.maxRpsPerHost}</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Max Scan Timing</span>
                    <p className="font-mono font-semibold">-T{engineState.data.profile.maxNmapTiming}</p>
                  </div>
                  <div>
                    <span className="text-muted-foreground">Phase Approval</span>
                    <p className="font-semibold">{engineState.data.profile.requirePhaseApproval ? "Required" : "Auto"}</p>
                  </div>
                </div>
                <div className="mt-4 flex flex-wrap gap-2">
                  {[
                    { label: "Credential Testing", allowed: engineState.data.profile.allowCredentialTesting },
                    { label: "Exploitation", allowed: engineState.data.profile.allowExploitation },
                    { label: "C2 Deployment", allowed: engineState.data.profile.allowC2Deployment },
                    { label: "Lateral Movement", allowed: engineState.data.profile.allowLateralMovement },
                    { label: "Exfil Simulation", allowed: engineState.data.profile.allowExfilSimulation },
                    { label: "DoS Testing", allowed: engineState.data.profile.allowDosTest },
                  ].map(cap => (
                    <Badge
                      key={cap.label}
                      variant="outline"
                      className={cap.allowed ? "border-emerald-500/30 text-emerald-400" : "border-red-500/30 text-red-400"}
                    >
                      {cap.allowed ? <CheckCircle2 className="h-3 w-3 mr-1" /> : <XCircle className="h-3 w-3 mr-1" />}
                      {cap.label}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ─── Blast Radius Simulator ────────────────────────────────── */}
        <TabsContent value="blast" className="space-y-4">
          <Card className="border-border/50">
            <CardHeader>
              <CardTitle className="text-base flex items-center gap-2">
                <Crosshair className="h-5 w-5 text-orange-400" />
                Predictive Blast Radius Estimator
              </CardTitle>
              <CardDescription>
                Estimate the impact of a tool command before execution. Analyzes tool type, arguments, target characteristics, and current safety level.
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div className="space-y-2">
                  <Label>Tool</Label>
                  <Select value={testTool} onValueChange={setTestTool}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      {["nmap", "nuclei", "hydra", "sqlmap", "nikto", "gobuster", "zap", "crackmapexec", "curl", "whois", "dig"].map(t => (
                        <SelectItem key={t} value={t}>{t}</SelectItem>
                      ))}
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2">
                  <Label>Safety Level</Label>
                  <Select value={testLevel} onValueChange={setTestLevel}>
                    <SelectTrigger><SelectValue /></SelectTrigger>
                    <SelectContent>
                      <SelectItem value="passive_only">Passive Only</SelectItem>
                      <SelectItem value="low_impact">Low Impact</SelectItem>
                      <SelectItem value="standard">Standard</SelectItem>
                      <SelectItem value="full_exploitation">Full Exploitation</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
                <div className="space-y-2 md:col-span-2">
                  <Label>Arguments</Label>
                  <Input value={testArgs} onChange={e => setTestArgs(e.target.value)} placeholder="-sV -sC -T4 -p 1-1000" className="font-mono text-sm" />
                </div>
                <div className="space-y-2 md:col-span-2">
                  <Label>Target</Label>
                  <Input value={testTarget} onChange={e => setTestTarget(e.target.value)} placeholder="192.168.1.0/24" className="font-mono text-sm" />
                </div>
              </div>

              {selectedEngagement && (
                <Button
                  onClick={() => assessCmd.mutate({
                    engagementId: selectedEngagement, tool: testTool, args: testArgs, target: testTarget,
                  })}
                  disabled={assessCmd.isPending}
                  variant="outline"
                >
                  <Target className="h-4 w-4 mr-2" />
                  Run Live Assessment (Records to Audit Log)
                </Button>
              )}
            </CardContent>
          </Card>

          {/* Blast Radius Results */}
          {blastEstimate.data && (
            <Card className="border-border/50">
              <CardHeader>
                <CardTitle className="text-base">Blast Radius Estimate</CardTitle>
              </CardHeader>
              <CardContent className="space-y-4">
                <div className="flex items-center gap-4">
                  <div className="relative w-24 h-24">
                    <svg viewBox="0 0 100 100" className="w-full h-full -rotate-90">
                      <circle cx="50" cy="50" r="40" fill="none" stroke="currentColor" strokeWidth="8" className="text-zinc-800" />
                      <circle
                        cx="50" cy="50" r="40" fill="none" strokeWidth="8"
                        strokeDasharray={`${blastEstimate.data.riskScore * 2.51} 251`}
                        className={
                          blastEstimate.data.riskScore <= 15 ? "stroke-blue-400" :
                          blastEstimate.data.riskScore <= 40 ? "stroke-amber-400" :
                          blastEstimate.data.riskScore <= 70 ? "stroke-orange-400" : "stroke-red-400"
                        }
                        strokeLinecap="round"
                      />
                    </svg>
                    <div className="absolute inset-0 flex items-center justify-center">
                      <span className={`text-xl font-bold ${RISK_COLORS[blastEstimate.data.riskCategory]}`}>
                        {blastEstimate.data.riskScore}
                      </span>
                    </div>
                  </div>
                  <div>
                    <Badge variant="outline" className={`${RISK_COLORS[blastEstimate.data.riskCategory]} mb-2`}>
                      {blastEstimate.data.riskCategory.toUpperCase()}
                    </Badge>
                    <div className="grid grid-cols-3 gap-4 text-sm">
                      <div>
                        <span className="text-muted-foreground">Affected Systems</span>
                        <p className="font-mono font-semibold">{blastEstimate.data.affectedSystems.toLocaleString()}</p>
                      </div>
                      <div>
                        <span className="text-muted-foreground">Downtime Risk</span>
                        <p className="font-mono font-semibold">{blastEstimate.data.downtimeRiskMinutes} min</p>
                      </div>
                      <div className="flex gap-3">
                        {blastEstimate.data.mayTriggerAlerts && <Badge variant="outline" className="text-amber-400 border-amber-500/30 text-xs">Alerts</Badge>}
                        {blastEstimate.data.mayModifyData && <Badge variant="outline" className="text-red-400 border-red-500/30 text-xs">Data Mod</Badge>}
                        {blastEstimate.data.mayDisruptService && <Badge variant="outline" className="text-red-400 border-red-500/30 text-xs">Disruption</Badge>}
                      </div>
                    </div>
                  </div>
                </div>

                {blastEstimate.data.riskFactors.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-muted-foreground mb-2">Risk Factors</h4>
                    <ul className="space-y-1">
                      {blastEstimate.data.riskFactors.map((f, i) => (
                        <li key={i} className="text-sm flex items-start gap-2">
                          <AlertTriangle className="h-3.5 w-3.5 text-amber-400 mt-0.5 shrink-0" />
                          {f}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}

                {blastEstimate.data.mitigations.length > 0 && (
                  <div>
                    <h4 className="text-sm font-medium text-muted-foreground mb-2">Recommended Mitigations</h4>
                    <ul className="space-y-1">
                      {blastEstimate.data.mitigations.map((m, i) => (
                        <li key={i} className="text-sm flex items-start gap-2">
                          <ShieldCheck className="h-3.5 w-3.5 text-emerald-400 mt-0.5 shrink-0" />
                          {m}
                        </li>
                      ))}
                    </ul>
                  </div>
                )}
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ─── Audit Trail Tab ───────────────────────────────────────── */}
        <TabsContent value="audit" className="space-y-4">
          {!selectedEngagement ? (
            <Card className="border-border/50"><CardContent className="py-8 text-center text-muted-foreground">Select an engagement to view audit trail</CardContent></Card>
          ) : (
            <>
              {blockedActions.data && blockedActions.data.length > 0 && (
                <Card className="border-red-500/20">
                  <CardHeader>
                    <CardTitle className="text-base text-red-400 flex items-center gap-2">
                      <ShieldX className="h-5 w-5" />
                      Blocked Actions ({blockedActions.data.length})
                    </CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2 max-h-64 overflow-y-auto">
                      {blockedActions.data.slice(-20).reverse().map(entry => (
                        <div key={entry.id} className="flex items-start gap-3 p-2 rounded bg-red-500/5 border border-red-500/10 text-sm">
                          <XCircle className="h-4 w-4 text-red-400 mt-0.5 shrink-0" />
                          <div className="min-w-0">
                            <span className="font-mono text-red-300">{entry.tool}</span>
                            <span className="text-muted-foreground ml-2">{entry.target}</span>
                            <p className="text-xs text-muted-foreground mt-0.5 truncate">{entry.reason}</p>
                          </div>
                          <Badge variant="outline" className="text-xs shrink-0 border-red-500/30 text-red-400">
                            Blast: {entry.blastRadius.riskScore}
                          </Badge>
                        </div>
                      ))}
                    </div>
                  </CardContent>
                </Card>
              )}

              <Card className="border-border/50">
                <CardHeader>
                  <CardTitle className="text-base flex items-center gap-2">
                    <FileText className="h-5 w-5 text-blue-400" />
                    Full Audit Log ({auditLog.data?.length || 0} entries)
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="space-y-1 max-h-96 overflow-y-auto">
                    {auditLog.data?.slice().reverse().map(entry => (
                      <div
                        key={entry.id}
                        className={`flex items-center gap-3 p-2 rounded text-sm ${
                          entry.decision === "allowed" ? "hover:bg-emerald-500/5" :
                          entry.decision === "blocked" ? "bg-red-500/5" : "bg-amber-500/5"
                        }`}
                      >
                        {entry.decision === "allowed" ? (
                          <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                        ) : entry.decision === "escalated" ? (
                          <AlertTriangle className="h-3.5 w-3.5 text-amber-400 shrink-0" />
                        ) : (
                          <XCircle className="h-3.5 w-3.5 text-red-400 shrink-0" />
                        )}
                        <span className="font-mono text-xs w-16 shrink-0">{entry.tool}</span>
                        <span className="text-xs text-muted-foreground truncate flex-1">{entry.target}</span>
                        <Badge variant="outline" className={`text-xs shrink-0 ${
                          entry.blastRadius.riskScore <= 15 ? "text-blue-400 border-blue-500/30" :
                          entry.blastRadius.riskScore <= 40 ? "text-amber-400 border-amber-500/30" :
                          "text-red-400 border-red-500/30"
                        }`}>
                          {entry.blastRadius.riskScore}
                        </Badge>
                        <span className="text-xs text-muted-foreground w-20 shrink-0 text-right">
                          {new Date(entry.timestamp).toLocaleTimeString()}
                        </span>
                      </div>
                    ))}
                    {(!auditLog.data || auditLog.data.length === 0) && (
                      <p className="text-center text-muted-foreground py-4">No audit entries yet. Run an assessment to generate entries.</p>
                    )}
                  </div>
                </CardContent>
              </Card>
            </>
          )}
        </TabsContent>

        {/* ─── Statistics Tab ────────────────────────────────────────── */}
        <TabsContent value="stats" className="space-y-4">
          {!selectedEngagement ? (
            <Card className="border-border/50"><CardContent className="py-8 text-center text-muted-foreground">Select an engagement to view statistics</CardContent></Card>
          ) : stats ? (
            <>
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                {[
                  { label: "Total Assessments", value: stats.totalAssessments, icon: Activity, color: "text-blue-400" },
                  { label: "Allowed", value: stats.allowed, icon: CheckCircle2, color: "text-emerald-400" },
                  { label: "Blocked", value: stats.blocked, icon: XCircle, color: "text-red-400" },
                  { label: "Highest Blast Radius", value: stats.highestBlastRadius, icon: Gauge, color: "text-orange-400" },
                ].map(stat => (
                  <Card key={stat.label} className="border-border/50">
                    <CardContent className="pt-4">
                      <div className="flex items-center gap-2 mb-1">
                        <stat.icon className={`h-4 w-4 ${stat.color}`} />
                        <span className="text-xs text-muted-foreground">{stat.label}</span>
                      </div>
                      <p className="text-2xl font-bold font-mono">{stat.value}</p>
                    </CardContent>
                  </Card>
                ))}
              </div>

              {Object.keys(stats.toolBreakdown).length > 0 && (
                <Card className="border-border/50">
                  <CardHeader>
                    <CardTitle className="text-base">Tool Breakdown</CardTitle>
                  </CardHeader>
                  <CardContent>
                    <div className="space-y-2">
                      {Object.entries(stats.toolBreakdown)
                        .sort((a, b) => (b[1].allowed + b[1].blocked) - (a[1].allowed + a[1].blocked))
                        .map(([tool, counts]) => {
                          const total = counts.allowed + counts.blocked;
                          const pct = total > 0 ? (counts.allowed / total) * 100 : 0;
                          return (
                            <div key={tool} className="flex items-center gap-3">
                              <span className="font-mono text-sm w-24 shrink-0">{tool}</span>
                              <div className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
                                <div className="h-full bg-emerald-500 rounded-full" style={{ width: `${pct}%` }} />
                              </div>
                              <span className="text-xs text-muted-foreground w-24 text-right">
                                {counts.allowed} / {counts.blocked} blocked
                              </span>
                            </div>
                          );
                        })}
                    </div>
                  </CardContent>
                </Card>
              )}
            </>
          ) : (
            <Card className="border-border/50"><CardContent className="py-8 text-center text-muted-foreground">Loading statistics...</CardContent></Card>
          )}
        </TabsContent>

        {/* ─── Level Comparison Tab ──────────────────────────────────── */}
        <TabsContent value="compare" className="space-y-4">
          <Card className="border-border/50">
            <CardHeader>
              <CardTitle className="text-base">Safety Level Comparison Matrix</CardTitle>
              <CardDescription>Side-by-side comparison of all safety levels and their capabilities</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-border/50">
                      <th className="text-left py-2 px-3 text-muted-foreground">Capability</th>
                      {compareLevels.data?.map(l => (
                        <th key={l.level} className="text-center py-2 px-3">
                          <span className={LEVEL_CONFIG[l.level]?.color}>{l.label}</span>
                        </th>
                      ))}
                    </tr>
                  </thead>
                  <tbody>
                    {[
                      { label: "Credential Testing", key: "allowCredentialTesting" },
                      { label: "Exploitation", key: "allowExploitation" },
                      { label: "C2 Deployment", key: "allowC2Deployment" },
                      { label: "Lateral Movement", key: "allowLateralMovement" },
                      { label: "Exfil Simulation", key: "allowExfilSimulation" },
                      { label: "DoS Testing", key: "allowDosTest" },
                      { label: "Phase Approval", key: "requirePhaseApproval" },
                    ].map(row => (
                      <tr key={row.key} className="border-b border-border/20">
                        <td className="py-2 px-3 text-muted-foreground">{row.label}</td>
                        {compareLevels.data?.map(l => {
                          const val = (l.profile as any)[row.key];
                          return (
                            <td key={l.level} className="text-center py-2 px-3">
                              {val ? <CheckCircle2 className="h-4 w-4 text-emerald-400 mx-auto" /> : <XCircle className="h-4 w-4 text-zinc-600 mx-auto" />}
                            </td>
                          );
                        })}
                      </tr>
                    ))}
                    {[
                      { label: "Max Scan Timing", key: "maxNmapTiming", prefix: "-T" },
                      { label: "Max RPS/Host", key: "maxRpsPerHost" },
                      { label: "Max Concurrent/Target", key: "maxConcurrentPerTarget" },
                    ].map(row => (
                      <tr key={row.key} className="border-b border-border/20">
                        <td className="py-2 px-3 text-muted-foreground">{row.label}</td>
                        {compareLevels.data?.map(l => (
                          <td key={l.level} className="text-center py-2 px-3 font-mono">
                            {row.prefix || ""}{(l.profile as any)[row.key]}
                          </td>
                        ))}
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}
