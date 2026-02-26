import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Link } from "wouter";
import {
  Scan, ShieldCheck, BrainCircuit, FileStack, AlertTriangle,
  Activity, Eye, TrendingUp, ChevronRight, Loader2
} from "lucide-react";

export default function SSILDashboard() {
  const { data: summary, isLoading } = trpc.ssil.getDashboardSummary.useQuery();

  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
              <Scan className="h-6 w-6 text-cyan-400" />
              SSIL Integration Layer
            </h1>
            <p className="text-muted-foreground mt-1">
              Service Scanner Integration Layer — Unified policy enforcement, LLM guardrails, and observation normalization
            </p>
          </div>
        </div>

        {isLoading ? (
          <div className="flex items-center justify-center py-20">
            <Loader2 className="h-8 w-8 animate-spin text-cyan-400" />
          </div>
        ) : (
          <>
            {/* Status Cards */}
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
              {/* Scan Policy Engine */}
              <Card className="border-cyan-500/20 bg-card/50">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm font-medium flex items-center gap-2">
                      <ShieldCheck className="h-4 w-4 text-cyan-400" />
                      Scan Policy Engine
                    </CardTitle>
                    <Badge variant="outline" className={
                      summary?.policy.activeProfile === "strict_passive"
                        ? "border-green-500/50 text-green-400"
                        : summary?.policy.activeProfile === "balanced"
                        ? "border-yellow-500/50 text-yellow-400"
                        : "border-red-500/50 text-red-400"
                    }>
                      {summary?.policy.activeProfile || "unknown"}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Active Profile</span>
                      <span className="font-mono text-cyan-300">{summary?.policy.activeProfile}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Policy Violations</span>
                      <span className={summary?.policy.violationCount ? "text-red-400 font-semibold" : "text-green-400"}>
                        {summary?.policy.violationCount || 0}
                      </span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Global Concurrent</span>
                      <span className="font-mono">{summary?.policy.rateLimiterStats?.globalConcurrent || 0}</span>
                    </div>
                    <div className="text-xs text-muted-foreground mt-2 p-2 bg-muted/30 rounded font-mono">
                      {summary?.policy.attestation?.substring(0, 80)}...
                    </div>
                    <Link href="/ssil/policies">
                      <Button variant="outline" size="sm" className="w-full mt-2">
                        Manage Policies <ChevronRight className="h-3 w-3 ml-1" />
                      </Button>
                    </Link>
                  </div>
                </CardContent>
              </Card>

              {/* LLM Guardrails */}
              <Card className="border-purple-500/20 bg-card/50">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm font-medium flex items-center gap-2">
                      <BrainCircuit className="h-4 w-4 text-purple-400" />
                      LLM Guardrails
                    </CardTitle>
                    <Badge variant="outline" className={
                      summary?.guardrails.config?.enabled
                        ? "border-green-500/50 text-green-400"
                        : "border-red-500/50 text-red-400"
                    }>
                      {summary?.guardrails.config?.enabled ? "ACTIVE" : "DISABLED"}
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Context</span>
                      <span className="font-mono text-purple-300">{summary?.guardrails.config?.context || "general"}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Total Calls</span>
                      <span className="font-mono">{summary?.guardrails.stats?.totalCalls || 0}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Blocked</span>
                      <span className={summary?.guardrails.stats?.blockedCalls ? "text-red-400 font-semibold" : "text-green-400"}>
                        {summary?.guardrails.stats?.blockedCalls || 0}
                      </span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Sanitized</span>
                      <span className="text-yellow-400">{summary?.guardrails.stats?.sanitizedCalls || 0}</span>
                    </div>
                    <Link href="/ssil/guardrails">
                      <Button variant="outline" size="sm" className="w-full mt-2">
                        Configure Guardrails <ChevronRight className="h-3 w-3 ml-1" />
                      </Button>
                    </Link>
                  </div>
                </CardContent>
              </Card>

              {/* Observation Normalizer */}
              <Card className="border-amber-500/20 bg-card/50">
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm font-medium flex items-center gap-2">
                      <FileStack className="h-4 w-4 text-amber-400" />
                      Observation Normalizer
                    </CardTitle>
                    <Badge variant="outline" className="border-amber-500/50 text-amber-400">
                      {summary?.observations.total || 0} obs
                    </Badge>
                  </div>
                </CardHeader>
                <CardContent>
                  <div className="space-y-3">
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Observations</span>
                      <span className="font-mono text-amber-300">{summary?.observations.total || 0}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Derived Signals</span>
                      <span className="font-mono">{summary?.observations.signals || 0}</span>
                    </div>
                    <div className="flex justify-between text-sm">
                      <span className="text-muted-foreground">Risk Cards</span>
                      <span className="font-mono">{summary?.observations.riskCards || 0}</span>
                    </div>
                    <div className="text-xs text-muted-foreground mt-2 p-2 bg-muted/30 rounded">
                      6 scanner adapters: Nmap, Nuclei, ZGrab2, Web Crawler, Domain Intel, Vuln Scanner
                    </div>
                    <Link href="/ssil/observations">
                      <Button variant="outline" size="sm" className="w-full mt-2">
                        View Observations <ChevronRight className="h-3 w-3 ml-1" />
                      </Button>
                    </Link>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Architecture Overview */}
            <Card className="border-border/50 bg-card/50">
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <Activity className="h-5 w-5 text-cyan-400" />
                  SSIL Architecture
                </CardTitle>
                <CardDescription>
                  How the three SSIL components work together
                </CardDescription>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-6">
                  <div className="space-y-2">
                    <h3 className="font-semibold text-cyan-400 flex items-center gap-2">
                      <ShieldCheck className="h-4 w-4" /> 1. Scan Policy Engine
                    </h3>
                    <p className="text-sm text-muted-foreground">
                      Enforces scan mode profiles (strict_passive, balanced, aggressive_internal).
                      Every scanner calls <code className="text-xs bg-muted px-1 rounded">canExecute()</code> before
                      probing a target. Rate limiting, jitter injection, and header redaction are
                      built in. Escalation rules govern mode transitions.
                    </p>
                    <div className="flex flex-wrap gap-1 mt-2">
                      <Badge variant="secondary" className="text-xs">SP-01 DNS-only</Badge>
                      <Badge variant="secondary" className="text-xs">SP-02 No POST</Badge>
                      <Badge variant="secondary" className="text-xs">SP-03 Rate Limit</Badge>
                      <Badge variant="secondary" className="text-xs">SP-04 Jitter</Badge>
                      <Badge variant="secondary" className="text-xs">SP-05 Redact</Badge>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <h3 className="font-semibold text-purple-400 flex items-center gap-2">
                      <BrainCircuit className="h-4 w-4" /> 2. LLM Guardrails
                    </h3>
                    <p className="text-sm text-muted-foreground">
                      Wraps all <code className="text-xs bg-muted px-1 rounded">invokeLLM()</code> calls
                      with safety system prompts. Blocks exploit generation, sanitizes sensitive data
                      in prompts, and enforces context-specific guardrails (analyst, risk_card,
                      caldera_hooks, detection, phishing, report).
                    </p>
                    <div className="flex flex-wrap gap-1 mt-2">
                      <Badge variant="secondary" className="text-xs">Input Sanitization</Badge>
                      <Badge variant="secondary" className="text-xs">Output Filtering</Badge>
                      <Badge variant="secondary" className="text-xs">Exploit Blocking</Badge>
                      <Badge variant="secondary" className="text-xs">PII Redaction</Badge>
                    </div>
                  </div>

                  <div className="space-y-2">
                    <h3 className="font-semibold text-amber-400 flex items-center gap-2">
                      <FileStack className="h-4 w-4" /> 3. Observation Normalizer
                    </h3>
                    <p className="text-sm text-muted-foreground">
                      Transforms raw scanner output into the unified <code className="text-xs bg-muted px-1 rounded">scan_observation</code> schema.
                      Per-scanner adapters handle Nmap, Nuclei, ZGrab2, Web Crawler, Domain Intel,
                      and Vuln Scanner. Observations feed into signal derivation and hybrid risk
                      card generation (CVSS × CARVER+SHOCK × BIA × confidence).
                    </p>
                    <div className="flex flex-wrap gap-1 mt-2">
                      <Badge variant="secondary" className="text-xs">6 Adapters</Badge>
                      <Badge variant="secondary" className="text-xs">Signal Derivation</Badge>
                      <Badge variant="secondary" className="text-xs">Risk Cards</Badge>
                      <Badge variant="secondary" className="text-xs">Cross-Scanner</Badge>
                    </div>
                  </div>
                </div>
              </CardContent>
            </Card>

            {/* Data Flow */}
            <Card className="border-border/50 bg-card/50">
              <CardHeader>
                <CardTitle className="text-lg flex items-center gap-2">
                  <TrendingUp className="h-5 w-5 text-cyan-400" />
                  Data Flow Pipeline
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center justify-center gap-2 flex-wrap text-sm">
                  <div className="px-3 py-2 bg-cyan-500/10 border border-cyan-500/30 rounded text-cyan-300 font-mono">
                    Scanner Output
                  </div>
                  <ChevronRight className="h-4 w-4 text-muted-foreground" />
                  <div className="px-3 py-2 bg-cyan-500/10 border border-cyan-500/30 rounded text-cyan-300 font-mono">
                    Policy Check
                  </div>
                  <ChevronRight className="h-4 w-4 text-muted-foreground" />
                  <div className="px-3 py-2 bg-amber-500/10 border border-amber-500/30 rounded text-amber-300 font-mono">
                    Adapter Transform
                  </div>
                  <ChevronRight className="h-4 w-4 text-muted-foreground" />
                  <div className="px-3 py-2 bg-amber-500/10 border border-amber-500/30 rounded text-amber-300 font-mono">
                    Observations
                  </div>
                  <ChevronRight className="h-4 w-4 text-muted-foreground" />
                  <div className="px-3 py-2 bg-purple-500/10 border border-purple-500/30 rounded text-purple-300 font-mono">
                    Signals
                  </div>
                  <ChevronRight className="h-4 w-4 text-muted-foreground" />
                  <div className="px-3 py-2 bg-red-500/10 border border-red-500/30 rounded text-red-300 font-mono">
                    Risk Cards
                  </div>
                </div>
              </CardContent>
            </Card>
          </>
        )}
      </div>
    </AppShell>
  );
}
