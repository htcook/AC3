import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import {
  BrainCircuit, ChevronLeft, Loader2, ShieldAlert, Eye,
  AlertTriangle, CheckCircle2, XCircle, Ban, Filter
} from "lucide-react";
import { Link } from "wouter";

export default function SSILGuardrails() {
  const utils = trpc.useUtils();
  const { data: status, isLoading } = trpc.ssil.getGuardrailsStatus.useQuery();
  const { data: violations } = trpc.ssil.getGuardrailViolations.useQuery({ limit: 30 });

  const toggleMutation = trpc.ssil.toggleGuardrails.useMutation({
    onSuccess: (data) => {
      toast.success(`Guardrails ${data.enabled ? "enabled" : "disabled"}`);
      utils.ssil.getGuardrailsStatus.invalidate();
      utils.ssil.getDashboardSummary.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const toggleStrictMutation = trpc.ssil.toggleStrictPassiveMode.useMutation({
    onSuccess: (data) => {
      toast.success(`Strict passive mode ${data.strictPassiveMode ? "enabled" : "disabled"}`);
      utils.ssil.getGuardrailsStatus.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const setContextMutation = trpc.ssil.setGuardrailContext.useMutation({
    onSuccess: (data) => {
      toast.success(`Context set to: ${data.config.context}`);
      utils.ssil.getGuardrailsStatus.invalidate();
    },
    onError: (err) => toast.error(err.message),
  });

  const contexts = ["analyst", "risk_card", "caldera_hooks", "detection", "phishing", "report", "general"] as const;

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
              <BrainCircuit className="h-6 w-6 text-purple-400" />
              LLM Guardrails
            </h1>
            <p className="text-sm text-muted-foreground mt-1 max-w-3xl">Configure safety guardrails for the Security Simulation & Intelligence Layer. Set boundaries on what automated testing can do — defining allowed IP ranges, excluded systems, time windows, and escalation thresholds. These guardrails ensure that automated security testing stays within the Rules of Engagement and doesn't accidentally impact production systems or exceed authorized scope.</p>
            <p className="text-muted-foreground mt-1">
              Safety controls for all LLM invocations — input sanitization, output filtering, exploit blocking
            </p>
          </div>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="h-8 w-8 animate-spin text-purple-400" />
          </div>
        ) : (
          <>
            {/* Controls */}
            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card className="border-purple-500/20 bg-card/50">
                <CardHeader>
                  <CardTitle className="text-lg">Guardrail Controls</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-center justify-between p-3 bg-muted/20 rounded">
                    <div>
                      <div className="font-medium text-sm">Guardrails Enabled</div>
                      <div className="text-xs text-muted-foreground">Master toggle for all LLM safety checks</div>
                    </div>
                    <Switch
                      checked={status?.config?.enabled ?? true}
                      onCheckedChange={(checked) => toggleMutation.mutate({ enabled: checked })}
                    />
                  </div>
                  <div className="flex items-center justify-between p-3 bg-muted/20 rounded">
                    <div>
                      <div className="font-medium text-sm">Strict Passive Mode</div>
                      <div className="text-xs text-muted-foreground">Extra restrictions: blocks all active scan suggestions</div>
                    </div>
                    <Switch
                      checked={status?.config?.strictPassiveMode ?? false}
                      onCheckedChange={(checked) => toggleStrictMutation.mutate({ enabled: checked })}
                    />
                  </div>
                </CardContent>
              </Card>

              <Card className="border-purple-500/20 bg-card/50">
                <CardHeader>
                  <CardTitle className="text-lg">Statistics</CardTitle>
                </CardHeader>
                <CardContent>
                  <div className="grid grid-cols-2 gap-3">
                    <div className="p-3 bg-muted/20 rounded text-center">
                      <div className="text-2xl font-bold text-purple-300">{status?.stats?.totalCalls || 0}</div>
                      <div className="text-xs text-muted-foreground">Total Calls</div>
                    </div>
                    <div className="p-3 bg-muted/20 rounded text-center">
                      <div className="text-2xl font-bold text-green-300">{(status?.stats?.totalCalls || 0) - (status?.stats?.blockedCalls || 0) - (status?.stats?.sanitizedCalls || 0)}</div>
                      <div className="text-xs text-muted-foreground">Clean Passes</div>
                    </div>
                    <div className="p-3 bg-red-500/10 rounded text-center">
                      <div className="text-2xl font-bold text-red-400">{status?.stats?.blockedCalls || 0}</div>
                      <div className="text-xs text-muted-foreground">Blocked</div>
                    </div>
                    <div className="p-3 bg-yellow-500/10 rounded text-center">
                      <div className="text-2xl font-bold text-yellow-400">{status?.stats?.sanitizedCalls || 0}</div>
                      <div className="text-xs text-muted-foreground">Sanitized</div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Context Selector */}
            <Card className="border-border/50 bg-card/50">
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Filter className="h-5 w-5 text-purple-400" />
                  Active Context
                </CardTitle>
                <CardDescription>
                  Each context applies specialized system prompts and filtering rules
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {contexts.map((ctx) => (
                    <button
                      key={ctx}
                      className={`p-3 rounded-lg border text-left transition-all ${
                        status?.config?.context === ctx
                          ? "border-purple-500/50 bg-purple-500/10"
                          : "border-border/50 hover:border-purple-500/30"
                      }`}
                      onClick={() => setContextMutation.mutate({ context: ctx })}
                    >
                      <div className="font-mono text-sm font-semibold">{ctx}</div>
                      <div className="text-xs text-muted-foreground mt-1">
                        {ctx === "analyst" && "Threat analysis & intelligence"}
                        {ctx === "risk_card" && "Risk scoring & reporting"}
                        {ctx === "caldera_hooks" && "Caldera C2 integration"}
                        {ctx === "detection" && "Detection rule generation"}
                        {ctx === "phishing" && "Phishing campaign analysis"}
                        {ctx === "report" && "Report generation"}
                        {ctx === "general" && "General purpose"}
                      </div>
                      {status?.config?.context === ctx && (
                        <CheckCircle2 className="h-3 w-3 text-purple-400 mt-2" />
                      )}
                    </button>
                  ))}
                </div>
              </CardContent>
            </Card>

            {/* Guardrail Rules */}
            <Card className="border-border/50 bg-card/50">
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <ShieldAlert className="h-5 w-5 text-purple-400" />
                  Active Guardrail Rules
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                  <div className="space-y-2">
                    <h4 className="text-sm font-semibold text-purple-300">Input Sanitization</h4>
                    <div className="space-y-1 text-xs text-muted-foreground">
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="h-3 w-3 text-green-400" />
                        Block exploit code patterns (shellcode, reverse shells)
                      </div>
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="h-3 w-3 text-green-400" />
                        Redact PII (emails, SSNs, API keys) from prompts
                      </div>
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="h-3 w-3 text-green-400" />
                        Strip injection attempts (prompt injection, jailbreak)
                      </div>
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="h-3 w-3 text-green-400" />
                        Enforce max prompt length (32K tokens)
                      </div>
                    </div>
                  </div>
                  <div className="space-y-2">
                    <h4 className="text-sm font-semibold text-purple-300">Output Filtering</h4>
                    <div className="space-y-1 text-xs text-muted-foreground">
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="h-3 w-3 text-green-400" />
                        Block executable code in responses
                      </div>
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="h-3 w-3 text-green-400" />
                        Filter weaponized exploit instructions
                      </div>
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="h-3 w-3 text-green-400" />
                        Redact credential material from output
                      </div>
                      <div className="flex items-center gap-2">
                        <CheckCircle2 className="h-3 w-3 text-green-400" />
                        Enforce defensive-only recommendations
                      </div>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Violation History */}
            <Card className="border-border/50 bg-card/50">
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <AlertTriangle className="h-5 w-5 text-yellow-400" />
                  Violation History ({violations?.length || 0})
                </CardTitle>
              </CardHeader>
              <CardContent>
                {!violations || violations.length === 0 ? (
                  <div className="text-center py-8 text-muted-foreground">
                    <CheckCircle2 className="h-8 w-8 mx-auto mb-2 text-green-400" />
                    <p>No guardrail violations recorded</p>
                  </div>
                ) : (
                  <div className="space-y-2 max-h-96 overflow-y-auto">
                    {violations.map((v: any, i: number) => (
                      <div key={i} className={`p-3 rounded border ${
                        v.action === "blocked"
                          ? "border-red-500/20 bg-red-500/5"
                          : v.action === "sanitized"
                          ? "border-yellow-500/20 bg-yellow-500/5"
                          : "border-blue-500/20 bg-blue-500/5"
                      }`}>
                        <div className="flex items-center justify-between mb-1">
                          <div className="flex items-center gap-2">
                            {v.action === "blocked" ? (
                              <Ban className="h-3 w-3 text-red-400" />
                            ) : v.action === "sanitized" ? (
                              <Filter className="h-3 w-3 text-yellow-400" />
                            ) : (
                              <Eye className="h-3 w-3 text-blue-400" />
                            )}
                            <Badge variant="outline" className="text-xs">
                              {v.action}
                            </Badge>
                            <span className="text-xs font-mono text-muted-foreground">{v.context}</span>
                          </div>
                          <span className="text-xs text-muted-foreground">
                            {new Date(v.timestamp).toLocaleString()}
                          </span>
                        </div>
                        <p className="text-xs text-muted-foreground">{v.reason}</p>
                        {v.triggerPattern && (
                          <div className="text-xs font-mono text-red-300/60 mt-1 truncate">
                            Pattern: {v.triggerPattern}
                          </div>
                        )}
                      </div>
                    ))}
                  </div>
                )}
              </CardContent>
            </Card>
          </>
        )}
      </div>
    </AppShell>
  );
}
