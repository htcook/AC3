import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { useEngagement } from "@/contexts/EngagementContext";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Textarea } from "@/components/ui/textarea";
import { Label } from "@/components/ui/label";
import { ScrollArea } from "@/components/ui/scroll-area";
import { Separator } from "@/components/ui/separator";
import { useToast } from "@/hooks/use-toast";
import {
  ShieldAlert, Shield, Activity, AlertTriangle, Lock,
  Eye, Clock, TrendingUp, ChevronDown, ChevronUp,
  RefreshCw, Download, Filter,
} from "lucide-react";

// ─── Types ───────────────────────────────────────────────────────────────────

type AutonomyLevel = 0 | 1 | 2 | 3;
type RoeType = "vulnerability_scanning" | "penetration_testing" | "red_team" | "phishing" | "social_engineering" | "physical" | "purple_team";

const LEVEL_COLORS: Record<number, string> = {
  0: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  1: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  2: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  3: "bg-red-500/20 text-red-400 border-red-500/30",
};

const LEVEL_NAMES: Record<number, string> = {
  0: "Advisory",
  1: "Assisted",
  2: "Supervised",
  3: "Autonomous",
};

const SEVERITY_COLORS: Record<string, string> = {
  info: "bg-slate-500/20 text-slate-400",
  warning: "bg-amber-500/20 text-amber-400",
  critical: "bg-red-500/20 text-red-400",
  alert: "bg-purple-500/20 text-purple-400",
};

// ─── Main Component ──────────────────────────────────────────────────────────

export default function AISafety() {
  const { toast } = useToast();
  const { activeEngagement } = useEngagement();
  const [selectedTab, setSelectedTab] = useState("autonomy");
  const [overrideDialogOpen, setOverrideDialogOpen] = useState(false);
  const [overrideLevel, setOverrideLevel] = useState<string>("1");
  const [overrideReason, setOverrideReason] = useState("");
  const [overrideExpiry, setOverrideExpiry] = useState("24");
  const [auditFilter, setAuditFilter] = useState<string>("all");
  const [auditSeverity, setAuditSeverity] = useState<string>("all");

  // Default values for when no engagement is active
  const engagementId = activeEngagement?.engagementId || "default";
  const roeType: RoeType = (activeEngagement as any)?.roeType || "penetration_testing";
  const graduationTier = (activeEngagement as any)?.graduationTier || 3;

  // ─── Queries ─────────────────────────────────────────────────────────────

  const autonomyState = trpc.aiSafety.getAutonomyState.useQuery({
    engagementId,
    roeType,
    graduationTier,
  });

  const autonomyLevels = trpc.aiSafety.getAutonomyLevels.useQuery();

  const overrideHistory = trpc.aiSafety.getOverrideHistory.useQuery({
    engagementId,
    limit: 20,
  });

  const safetyStats = trpc.aiSafety.getSafetyStats.useQuery({ hoursBack: 24 });

  const auditLogs = trpc.aiSafety.getAuditLogs.useQuery({
    engagementId: engagementId !== "default" ? engagementId : undefined,
    action: auditFilter !== "all" ? auditFilter : undefined,
    severity: auditSeverity !== "all" ? auditSeverity as any : undefined,
    limit: 50,
  });

  // ─── Mutations ───────────────────────────────────────────────────────────

  const setOverrideMutation = trpc.aiSafety.setAutonomyOverride.useMutation({
    onSuccess: () => {
      toast({ title: "Override Set", description: "Autonomy level override applied successfully." });
      setOverrideDialogOpen(false);
      setOverrideReason("");
      autonomyState.refetch();
      overrideHistory.refetch();
    },
    onError: (err) => {
      toast({ title: "Error", description: err.message, variant: "destructive" });
    },
  });

  const clearOverrideMutation = trpc.aiSafety.clearAutonomyOverride.useMutation({
    onSuccess: () => {
      toast({ title: "Override Cleared", description: "Autonomy level restored to computed value." });
      autonomyState.refetch();
      overrideHistory.refetch();
    },
  });

  const flushMutation = trpc.aiSafety.flushAuditBuffer.useMutation({
    onSuccess: (data) => {
      toast({ title: "Audit Flushed", description: `${data.flushed} entries persisted to database.` });
      auditLogs.refetch();
    },
  });

  // ─── Handlers ────────────────────────────────────────────────────────────

  const handleSetOverride = () => {
    if (!overrideReason || overrideReason.length < 10) {
      toast({ title: "Error", description: "Reason must be at least 10 characters.", variant: "destructive" });
      return;
    }
    setOverrideMutation.mutate({
      engagementId,
      overrideLevel: parseInt(overrideLevel),
      previousLevel: autonomyState.data?.currentLevel ?? 2,
      reason: overrideReason,
      expiresInHours: parseInt(overrideExpiry),
    });
  };

  // ─── Render ──────────────────────────────────────────────────────────────

  return (
    <div className="p-6 space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <ShieldAlert className="h-6 w-6 text-purple-400" />
            AI Safety & Autonomy
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Compliance-grade AI governance — cross-tenant isolation, prompt injection defense, graduated autonomy
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={() => flushMutation.mutate()}>
            <Download className="h-4 w-4 mr-1" />
            Flush Audit Buffer
          </Button>
          <Button variant="outline" size="sm" onClick={() => { auditLogs.refetch(); safetyStats.refetch(); }}>
            <RefreshCw className="h-4 w-4 mr-1" />
            Refresh
          </Button>
        </div>
      </div>

      {/* Safety Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-3">
        <StatCard
          label="Total Requests"
          value={safetyStats.data?.totalRequests ?? 0}
          icon={<Activity className="h-4 w-4" />}
          color="text-blue-400"
        />
        <StatCard
          label="Blocked"
          value={safetyStats.data?.blockedRequests ?? 0}
          icon={<Lock className="h-4 w-4" />}
          color="text-red-400"
        />
        <StatCard
          label="Injections"
          value={safetyStats.data?.injectionsDetected ?? 0}
          icon={<AlertTriangle className="h-4 w-4" />}
          color="text-amber-400"
        />
        <StatCard
          label="PII Scrubbed"
          value={safetyStats.data?.piiScrubbed ?? 0}
          icon={<Eye className="h-4 w-4" />}
          color="text-emerald-400"
        />
        <StatCard
          label="Tenant Violations"
          value={safetyStats.data?.crossTenantViolations ?? 0}
          icon={<Shield className="h-4 w-4" />}
          color="text-purple-400"
        />
        <StatCard
          label="Avg Response"
          value={`${safetyStats.data?.avgResponseTime ?? 0}ms`}
          icon={<Clock className="h-4 w-4" />}
          color="text-cyan-400"
        />
      </div>

      {/* Main Tabs */}
      <Tabs value={selectedTab} onValueChange={setSelectedTab}>
        <TabsList className="grid w-full grid-cols-4">
          <TabsTrigger value="autonomy">Autonomy Levels</TabsTrigger>
          <TabsTrigger value="interceptor">Transport Interceptor</TabsTrigger>
          <TabsTrigger value="audit">Audit Trail</TabsTrigger>
          <TabsTrigger value="overrides">Override History</TabsTrigger>
        </TabsList>

        {/* ─── Autonomy Tab ─────────────────────────────────────────────── */}
        <TabsContent value="autonomy" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
            {/* Current State */}
            <Card className="lg:col-span-2">
              <CardHeader>
                <CardTitle className="flex items-center gap-2">
                  <Shield className="h-5 w-5" />
                  Current Autonomy State
                </CardTitle>
                <CardDescription>
                  Engagement: {engagementId} | ROE Type: {roeType} | Graduation Tier: {graduationTier}
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-4">
                {autonomyState.isLoading ? (
                  <div className="animate-pulse space-y-3">
                    <div className="h-16 bg-muted rounded" />
                    <div className="h-8 bg-muted rounded w-2/3" />
                  </div>
                ) : autonomyState.data ? (
                  <>
                    {/* Level Display */}
                    <div className={`p-4 rounded-lg border ${LEVEL_COLORS[autonomyState.data.currentLevel]}`}>
                      <div className="flex items-center justify-between">
                        <div>
                          <div className="text-3xl font-bold">
                            Level {autonomyState.data.currentLevel}: {LEVEL_NAMES[autonomyState.data.currentLevel]}
                          </div>
                          <div className="text-sm mt-1 opacity-80">
                            {autonomyState.data.description?.description}
                          </div>
                        </div>
                        {autonomyState.data.hasActiveOverride && (
                          <Badge variant="outline" className="border-amber-500 text-amber-400">
                            OVERRIDE ACTIVE
                          </Badge>
                        )}
                      </div>
                    </div>

                    {/* Caps */}
                    <div className="grid grid-cols-2 gap-3">
                      <div className="p-3 rounded-lg bg-muted/50">
                        <div className="text-xs text-muted-foreground">ROE Cap</div>
                        <div className="text-lg font-semibold">
                          Level {autonomyState.data.roeCap} ({LEVEL_NAMES[autonomyState.data.roeCap]})
                        </div>
                      </div>
                      <div className="p-3 rounded-lg bg-muted/50">
                        <div className="text-xs text-muted-foreground">Graduation Cap</div>
                        <div className="text-lg font-semibold">
                          Level {autonomyState.data.graduationCap} ({LEVEL_NAMES[autonomyState.data.graduationCap]})
                        </div>
                      </div>
                    </div>

                    {/* Allowed Actions */}
                    {autonomyState.data.description?.allowedActions && (
                      <div>
                        <div className="text-sm font-medium mb-2">Allowed Actions</div>
                        <div className="flex flex-wrap gap-1">
                          {autonomyState.data.description.allowedActions.map((action: string) => (
                            <Badge key={action} variant="secondary" className="text-xs">
                              {action}
                            </Badge>
                          ))}
                        </div>
                      </div>
                    )}

                    {/* Constraints */}
                    {autonomyState.data.description?.constraints && (
                      <div>
                        <div className="text-sm font-medium mb-2">Constraints</div>
                        <ul className="text-sm text-muted-foreground space-y-1">
                          {autonomyState.data.description.constraints.map((c: string, i: number) => (
                            <li key={i} className="flex items-start gap-2">
                              <span className="text-amber-400 mt-0.5">•</span>
                              {c}
                            </li>
                          ))}
                        </ul>
                      </div>
                    )}
                  </>
                ) : (
                  <div className="text-muted-foreground">No autonomy state available</div>
                )}
              </CardContent>
            </Card>

            {/* Override Controls */}
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Override Controls</CardTitle>
                <CardDescription>Manually set or clear autonomy level</CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <Dialog open={overrideDialogOpen} onOpenChange={setOverrideDialogOpen}>
                  <DialogTrigger asChild>
                    <Button className="w-full" variant="outline">
                      <Lock className="h-4 w-4 mr-2" />
                      Set Override
                    </Button>
                  </DialogTrigger>
                  <DialogContent>
                    <DialogHeader>
                      <DialogTitle>Set Autonomy Override</DialogTitle>
                      <DialogDescription>
                        Manually override the computed autonomy level. This requires justification and will be logged.
                      </DialogDescription>
                    </DialogHeader>
                    <div className="space-y-4 py-4">
                      <div className="space-y-2">
                        <Label>Override Level</Label>
                        <Select value={overrideLevel} onValueChange={setOverrideLevel}>
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="0">Level 0 — Advisory (AI suggests only)</SelectItem>
                            <SelectItem value="1">Level 1 — Assisted (AI executes with approval)</SelectItem>
                            <SelectItem value="2">Level 2 — Supervised (AI executes, operator monitors)</SelectItem>
                            <SelectItem value="3">Level 3 — Autonomous (AI executes within ROE)</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                      <div className="space-y-2">
                        <Label>Justification (min 10 chars)</Label>
                        <Textarea
                          value={overrideReason}
                          onChange={(e) => setOverrideReason(e.target.value)}
                          placeholder="Explain why this override is necessary..."
                          rows={3}
                        />
                      </div>
                      <div className="space-y-2">
                        <Label>Expires In (hours)</Label>
                        <Select value={overrideExpiry} onValueChange={setOverrideExpiry}>
                          <SelectTrigger>
                            <SelectValue />
                          </SelectTrigger>
                          <SelectContent>
                            <SelectItem value="1">1 hour</SelectItem>
                            <SelectItem value="4">4 hours</SelectItem>
                            <SelectItem value="8">8 hours</SelectItem>
                            <SelectItem value="24">24 hours</SelectItem>
                            <SelectItem value="72">72 hours</SelectItem>
                            <SelectItem value="168">1 week</SelectItem>
                          </SelectContent>
                        </Select>
                      </div>
                    </div>
                    <DialogFooter>
                      <Button variant="outline" onClick={() => setOverrideDialogOpen(false)}>Cancel</Button>
                      <Button onClick={handleSetOverride} disabled={setOverrideMutation.isPending}>
                        {setOverrideMutation.isPending ? "Applying..." : "Apply Override"}
                      </Button>
                    </DialogFooter>
                  </DialogContent>
                </Dialog>

                {autonomyState.data?.hasActiveOverride && (
                  <Button
                    className="w-full"
                    variant="destructive"
                    onClick={() => clearOverrideMutation.mutate({ engagementId })}
                    disabled={clearOverrideMutation.isPending}
                  >
                    Clear Active Override
                  </Button>
                )}

                <Separator />

                {/* Level Reference */}
                <div className="space-y-2">
                  <div className="text-sm font-medium">Level Reference</div>
                  {autonomyLevels.data?.map((level) => (
                    <div
                      key={level.level}
                      className={`p-2 rounded text-xs border ${LEVEL_COLORS[level.level]}`}
                    >
                      <div className="font-medium">L{level.level}: {level.name}</div>
                      <div className="opacity-80 mt-0.5">{level.description}</div>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* ─── Audit Trail Tab ──────────────────────────────────────────── */}
        <TabsContent value="audit" className="space-y-4">
          <Card>
            <CardHeader>
              <div className="flex items-center justify-between">
                <CardTitle className="flex items-center gap-2">
                  <Eye className="h-5 w-5" />
                  AI Audit Trail
                </CardTitle>
                <div className="flex items-center gap-2">
                  <Select value={auditFilter} onValueChange={setAuditFilter}>
                    <SelectTrigger className="w-[160px]">
                      <Filter className="h-3 w-3 mr-1" />
                      <SelectValue placeholder="Action" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Actions</SelectItem>
                      <SelectItem value="chat_input">Chat Input</SelectItem>
                      <SelectItem value="chat_output">Chat Output</SelectItem>
                      <SelectItem value="injection_blocked">Injection Blocked</SelectItem>
                      <SelectItem value="rate_limited">Rate Limited</SelectItem>
                      <SelectItem value="tenant_boundary_violation">Tenant Violation</SelectItem>
                    </SelectContent>
                  </Select>
                  <Select value={auditSeverity} onValueChange={setAuditSeverity}>
                    <SelectTrigger className="w-[130px]">
                      <SelectValue placeholder="Severity" />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Severity</SelectItem>
                      <SelectItem value="info">Info</SelectItem>
                      <SelectItem value="warning">Warning</SelectItem>
                      <SelectItem value="critical">Critical</SelectItem>
                      <SelectItem value="alert">Alert</SelectItem>
                    </SelectContent>
                  </Select>
                </div>
              </div>
              <CardDescription>
                {auditLogs.data?.total ?? 0} total entries | Showing last 50
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[500px]">
                <div className="space-y-2">
                  {auditLogs.data?.logs?.length === 0 && (
                    <div className="text-center text-muted-foreground py-8">
                      No audit entries found. AI interactions will appear here.
                    </div>
                  )}
                  {auditLogs.data?.logs?.map((log: any) => (
                    <div
                      key={log.id}
                      className="p-3 rounded-lg border bg-card/50 hover:bg-card/80 transition-colors"
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Badge className={`text-xs ${SEVERITY_COLORS[log.severity] || ""}`}>
                            {log.severity}
                          </Badge>
                          <span className="text-sm font-medium">{log.action}</span>
                          {log.injectionDetected === 1 && (
                            <Badge variant="destructive" className="text-xs">INJECTION</Badge>
                          )}
                          {log.crossTenantViolation === 1 && (
                            <Badge variant="destructive" className="text-xs">CROSS-TENANT</Badge>
                          )}
                          {log.piiDetected === 1 && (
                            <Badge className="text-xs bg-amber-500/20 text-amber-400">PII</Badge>
                          )}
                          {log.actionBlocked === 1 && (
                            <Badge variant="destructive" className="text-xs">BLOCKED</Badge>
                          )}
                        </div>
                        <span className="text-xs text-muted-foreground">
                          {log.createdAt ? new Date(log.createdAt).toLocaleString() : "—"}
                        </span>
                      </div>
                      <div className="text-xs text-muted-foreground mt-1 line-clamp-2">
                        {log.details}
                      </div>
                      <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground/70">
                        <span>User: {log.userId}</span>
                        <span>Session: {log.sessionId?.slice(0, 8)}...</span>
                        {log.responseTimeMs && <span>{log.responseTimeMs}ms</span>}
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ─── Transport Interceptor Tab ───────────────────────────────── */}
        <TabsContent value="interceptor" className="space-y-4">
          <InterceptorPanel />
        </TabsContent>

        {/* ─── Override History Tab ──────────────────────────────────────── */}
        <TabsContent value="overrides" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="flex items-center gap-2">
                <Lock className="h-5 w-5" />
                Override History
              </CardTitle>
              <CardDescription>
                All autonomy level overrides for engagement: {engagementId}
              </CardDescription>
            </CardHeader>
            <CardContent>
              <ScrollArea className="h-[400px]">
                <div className="space-y-3">
                  {overrideHistory.data?.length === 0 && (
                    <div className="text-center text-muted-foreground py-8">
                      No overrides have been set for this engagement.
                    </div>
                  )}
                  {overrideHistory.data?.map((override: any) => (
                    <div
                      key={override.id}
                      className={`p-3 rounded-lg border ${override.active ? "border-amber-500/50 bg-amber-500/5" : "bg-card/50"}`}
                    >
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-2">
                          <Badge className={LEVEL_COLORS[override.overrideLevel]}>
                            L{override.previousLevel} → L{override.overrideLevel}
                          </Badge>
                          {override.active === 1 && (
                            <Badge variant="outline" className="text-amber-400 border-amber-500">ACTIVE</Badge>
                          )}
                        </div>
                        <span className="text-xs text-muted-foreground">
                          {override.createdAt ? new Date(override.createdAt).toLocaleString() : "—"}
                        </span>
                      </div>
                      <div className="text-sm mt-2">{override.reason}</div>
                      <div className="flex items-center gap-3 mt-1 text-xs text-muted-foreground">
                        <span>Set by: {override.setByName || `User #${override.setBy}`}</span>
                        {override.expiresAt && (
                          <span>Expires: {new Date(override.expiresAt).toLocaleString()}</span>
                        )}
                      </div>
                    </div>
                  ))}
                </div>
              </ScrollArea>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
  );
}

// ─── Sub-Components ──────────────────────────────────────────────────────────

function InterceptorPanel() {
  const { toast } = useToast();
  const interceptorStats = trpc.aiSafety.getInterceptorStats.useQuery();
  const interceptorConfig = trpc.aiSafety.getInterceptorConfig.useQuery();
  const updateConfig = trpc.aiSafety.updateInterceptorConfig.useMutation({
    onSuccess: () => {
      toast({ title: "Config Updated", description: "Interceptor configuration saved." });
      interceptorConfig.refetch();
    },
  });
  const resetStats = trpc.aiSafety.resetInterceptorStats.useMutation({
    onSuccess: () => {
      toast({ title: "Stats Reset", description: "Interceptor statistics cleared." });
      interceptorStats.refetch();
    },
  });

  const s = interceptorStats.data;
  const cfg = interceptorConfig.data;

  return (
    <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
      {/* Stats Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Activity className="h-5 w-5 text-cyan-400" />
            Interceptor Statistics
          </CardTitle>
          <CardDescription>
            Transport-level safety metrics across ALL {s?.totalIntercepted ?? 0} LLM invocations
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="flex items-center gap-2 mb-4">
            <Badge className={s?.installed ? "bg-emerald-500/20 text-emerald-400" : "bg-red-500/20 text-red-400"}>
              {s?.installed ? "ACTIVE" : "NOT INSTALLED"}
            </Badge>
            <Button variant="outline" size="sm" onClick={() => resetStats.mutate()}>
              Reset Stats
            </Button>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="p-3 rounded-lg bg-card border">
              <div className="text-2xl font-bold text-blue-400">{s?.totalIntercepted ?? 0}</div>
              <div className="text-xs text-muted-foreground">Total Intercepted</div>
            </div>
            <div className="p-3 rounded-lg bg-card border">
              <div className="text-2xl font-bold text-red-400">{s?.totalBlocked ?? 0}</div>
              <div className="text-xs text-muted-foreground">Blocked (High Severity)</div>
            </div>
            <div className="p-3 rounded-lg bg-card border">
              <div className="text-2xl font-bold text-amber-400">{s?.totalInjectionDetected ?? 0}</div>
              <div className="text-xs text-muted-foreground">Injections Detected</div>
            </div>
            <div className="p-3 rounded-lg bg-card border">
              <div className="text-2xl font-bold text-emerald-400">{s?.totalSanitized ?? 0}</div>
              <div className="text-xs text-muted-foreground">Outputs Sanitized</div>
            </div>
            <div className="p-3 rounded-lg bg-card border">
              <div className="text-2xl font-bold text-purple-400">{s?.totalPiiScrubbed ?? 0}</div>
              <div className="text-xs text-muted-foreground">PII Scrubbed</div>
            </div>
            <div className="p-3 rounded-lg bg-card border">
              <div className="text-2xl font-bold text-slate-400">{s?.totalBypassed ?? 0}</div>
              <div className="text-xs text-muted-foreground">Bypassed (System)</div>
            </div>
          </div>

          {s?.lastBlockedAt && (
            <div className="text-xs text-red-400 mt-2">
              Last blocked: {new Date(s.lastBlockedAt).toLocaleString()}
            </div>
          )}
          {s?.lastInjectionAt && (
            <div className="text-xs text-amber-400">
              Last injection: {new Date(s.lastInjectionAt).toLocaleString()}
            </div>
          )}

          {/* Blocked Callers */}
          {s?.blockedCallers && Object.keys(s.blockedCallers).length > 0 && (
            <div className="mt-4">
              <h4 className="text-sm font-medium mb-2">Blocked by Caller</h4>
              <div className="space-y-1">
                {Object.entries(s.blockedCallers).map(([caller, count]) => (
                  <div key={caller} className="flex items-center justify-between text-xs">
                    <span className="font-mono text-muted-foreground">{caller}</span>
                    <Badge variant="destructive" className="text-xs">{count as number}</Badge>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* Injections by Category */}
          {s?.injectionsByCategory && Object.keys(s.injectionsByCategory).length > 0 && (
            <div className="mt-4">
              <h4 className="text-sm font-medium mb-2">Injections by Category</h4>
              <div className="space-y-1">
                {Object.entries(s.injectionsByCategory).map(([cat, count]) => (
                  <div key={cat} className="flex items-center justify-between text-xs">
                    <span className="font-mono text-muted-foreground">{cat}</span>
                    <Badge className="text-xs bg-amber-500/20 text-amber-400">{count as number}</Badge>
                  </div>
                ))}
              </div>
            </div>
          )}
        </CardContent>
      </Card>

      {/* Config Card */}
      <Card>
        <CardHeader>
          <CardTitle className="flex items-center gap-2">
            <Shield className="h-5 w-5 text-emerald-400" />
            Interceptor Configuration
          </CardTitle>
          <CardDescription>
            Control the transport-level safety behavior for all LLM paths
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          <div className="space-y-3">
            <ConfigToggle
              label="Interceptor Enabled"
              description="Master switch for the transport-level safety layer"
              value={cfg?.enabled ?? true}
              onChange={(v) => updateConfig.mutate({ enabled: v })}
            />
            <Separator />
            <ConfigToggle
              label="Block High Severity"
              description="Immediately block calls with high-severity injection patterns"
              value={cfg?.blockHighSeverity ?? true}
              onChange={(v) => updateConfig.mutate({ blockHighSeverity: v })}
            />
            <Separator />
            <ConfigToggle
              label="Sanitize Outputs"
              description="Scrub PII, secrets, and dangerous patterns from LLM responses"
              value={cfg?.sanitizeOutputs ?? true}
              onChange={(v) => updateConfig.mutate({ sanitizeOutputs: v })}
            />
            <Separator />
            <ConfigToggle
              label="Audit All"
              description="Log all intercepted calls to the audit buffer"
              value={cfg?.auditAll ?? true}
              onChange={(v) => updateConfig.mutate({ auditAll: v })}
            />
          </div>

          {cfg?.bypassCallers && cfg.bypassCallers.length > 0 && (
            <div className="mt-4">
              <h4 className="text-sm font-medium mb-2">Bypass List (System Callers)</h4>
              <div className="flex flex-wrap gap-1">
                {cfg.bypassCallers.map((caller) => (
                  <Badge key={caller} variant="outline" className="text-xs font-mono">
                    {caller}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          <div className="mt-4 p-3 rounded-lg bg-emerald-500/5 border border-emerald-500/20">
            <h4 className="text-sm font-medium text-emerald-400 mb-1">Coverage</h4>
            <p className="text-xs text-muted-foreground">
              This interceptor protects ALL 135+ LLM invocation paths including:
              enrichment, planning, exploitation, scanning, report generation,
              threat analysis, and campaign advisory. No caller can bypass without
              explicit system-level bypass registration.
            </p>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

function ConfigToggle({ label, description, value, onChange }: {
  label: string;
  description: string;
  value: boolean;
  onChange: (v: boolean) => void;
}) {
  return (
    <div className="flex items-center justify-between">
      <div>
        <div className="text-sm font-medium">{label}</div>
        <div className="text-xs text-muted-foreground">{description}</div>
      </div>
      <Button
        variant={value ? "default" : "outline"}
        size="sm"
        onClick={() => onChange(!value)}
        className={value ? "bg-emerald-600 hover:bg-emerald-700" : ""}
      >
        {value ? "ON" : "OFF"}
      </Button>
    </div>
  );
}

function StatCard({ label, value, icon, color }: { label: string; value: number | string; icon: React.ReactNode; color: string }) {
  return (
    <Card className="p-3">
      <div className="flex items-center gap-2">
        <div className={color}>{icon}</div>
        <div>
          <div className="text-lg font-bold">{value}</div>
          <div className="text-xs text-muted-foreground">{label}</div>
        </div>
      </div>
    </Card>
  );
}
