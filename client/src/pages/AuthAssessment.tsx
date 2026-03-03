import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Select,
  SelectContent,
  SelectItem,
  SelectTrigger,
  SelectValue,
} from "@/components/ui/select";
import {
  Fingerprint,
  Shield,
  AlertTriangle,
  CheckCircle2,
  XCircle,
  Loader2,
  Play,
  Globe2,
  Lock,
  Key,
  FileText,
  ChevronRight,
  Info,
} from "lucide-react";
import { toast } from "sonner";
import AppShell from "@/components/AppShell";

// ─── Types ──────────────────────────────────────────────────────────────────

interface CheckResult {
  checkId: string;
  name: string;
  protocol: string;
  status: "pass" | "fail" | "warn" | "error" | "skipped";
  details: string;
  severity: string;
  recommendation?: string;
}

interface AssessmentRun {
  id: string;
  targetUrl: string;
  mode: string;
  timestamp: number;
  results: CheckResult[];
  summary: { pass: number; fail: number; warn: number; error: number };
}

// ─── Status Badge ───────────────────────────────────────────────────────────

function StatusBadge({ status }: { status: string }) {
  const config: Record<string, { color: string; icon: React.ReactNode }> = {
    pass: { color: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30", icon: <CheckCircle2 className="h-3 w-3" /> },
    fail: { color: "bg-red-500/15 text-red-400 border-red-500/30", icon: <XCircle className="h-3 w-3" /> },
    warn: { color: "bg-amber-500/15 text-amber-400 border-amber-500/30", icon: <AlertTriangle className="h-3 w-3" /> },
    error: { color: "bg-red-500/15 text-red-300 border-red-500/30", icon: <XCircle className="h-3 w-3" /> },
    skipped: { color: "bg-zinc-500/15 text-zinc-400 border-zinc-500/30", icon: <Info className="h-3 w-3" /> },
  };
  const c = config[status] || config.skipped;
  return (
    <Badge variant="outline" className={`${c.color} gap-1 font-mono text-xs uppercase`}>
      {c.icon} {status}
    </Badge>
  );
}

// ─── Check Card ─────────────────────────────────────────────────────────────

function CheckCard({ result }: { result: CheckResult }) {
  const [expanded, setExpanded] = useState(false);
  return (
    <div
      className="border border-border/50 rounded-lg p-4 hover:border-border transition-colors cursor-pointer"
      onClick={() => setExpanded(!expanded)}
    >
      <div className="flex items-start justify-between gap-3">
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 mb-1">
            <Badge variant="outline" className="text-[10px] font-mono uppercase tracking-wider bg-muted/50">
              {result.protocol === "oauth_oidc" ? "OAuth/OIDC" : "SAML"}
            </Badge>
            <span className="text-sm font-medium text-foreground truncate">{result.name}</span>
          </div>
          <p className="text-xs text-muted-foreground line-clamp-2">{result.details}</p>
        </div>
        <div className="flex items-center gap-2 shrink-0">
          <StatusBadge status={result.status} />
          <ChevronRight className={`h-4 w-4 text-muted-foreground transition-transform ${expanded ? "rotate-90" : ""}`} />
        </div>
      </div>
      {expanded && result.recommendation && (
        <div className="mt-3 pt-3 border-t border-border/50">
          <p className="text-xs text-muted-foreground">
            <span className="font-semibold text-foreground">Recommendation:</span> {result.recommendation}
          </p>
        </div>
      )}
    </div>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function AuthAssessment() {
  const [targetUrl, setTargetUrl] = useState("");
  const [mode, setMode] = useState<"standard" | "strict">("standard");
  const [runs, setRuns] = useState<AssessmentRun[]>([]);
  const [running, setRunning] = useState(false);
  const [activeTab, setActiveTab] = useState("runner");

  // tRPC mutations
  const runChecks = trpc.authAssessment.runOAuthChecks.useMutation({
    onSuccess: (data: any) => {
      const newRun: AssessmentRun = {
        id: `run-${Date.now()}`,
        targetUrl,
        mode,
        timestamp: Date.now(),
        results: data.results || [],
        summary: data.summary || { pass: 0, fail: 0, warn: 0, error: 0 },
      };
      setRuns(prev => [newRun, ...prev]);
      setRunning(false);
      toast.success(`Assessment Complete — ${newRun.summary.pass} passed, ${newRun.summary.fail} failed`);
    },
    onError: (err: any) => {
      setRunning(false);
      toast.error(`Assessment Error: ${err.message}`);
    },
  });

  const handleRun = () => {
    if (!targetUrl.trim()) {
      toast.error("Enter a target URL to assess");
      return;
    }
    setRunning(true);
    runChecks.mutate({ targetUrl: targetUrl.trim(), mode });
  };

  const latestRun = runs[0];
  const oauthResults = useMemo(() => latestRun?.results.filter(r => r.protocol === "oauth_oidc") || [], [latestRun]);
  const samlResults = useMemo(() => latestRun?.results.filter(r => r.protocol === "saml") || [], [latestRun]);

  return (
      <AppShell activePath="/auth-assessment">
      <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Fingerprint className="h-6 w-6 text-primary" />
            Auth Assessment
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            OAuth/OIDC &amp; SAML SSO security assessment — 11 deterministic checks
          </p>
        </div>
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="runner">Assessment Runner</TabsTrigger>
          <TabsTrigger value="history">Run History ({runs.length})</TabsTrigger>
          <TabsTrigger value="methodology">Methodology</TabsTrigger>
        </TabsList>

        {/* ── Runner Tab ── */}
        <TabsContent value="runner" className="space-y-4">
          {/* Config Card */}
          <Card>
            <CardHeader className="pb-3">
              <CardTitle className="text-base">Target Configuration</CardTitle>
              <CardDescription>
                Enter the target authentication endpoint URL and select the assessment mode.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex flex-col sm:flex-row gap-3">
                <div className="flex-1">
                  <Input
                    placeholder="https://target.example.com/login"
                    value={targetUrl}
                    onChange={e => setTargetUrl(e.target.value)}
                    className="font-mono text-sm"
                  />
                </div>
                <Select value={mode} onValueChange={(v: "standard" | "strict") => setMode(v)}>
                  <SelectTrigger className="w-[200px]">
                    <SelectValue />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="standard">Standard Mode</SelectItem>
                    <SelectItem value="strict">Federal Auth Strict</SelectItem>
                  </SelectContent>
                </Select>
                <Button onClick={handleRun} disabled={running} className="gap-2">
                  {running ? <Loader2 className="h-4 w-4 animate-spin" /> : <Play className="h-4 w-4" />}
                  {running ? "Running..." : "Run Assessment"}
                </Button>
              </div>
              {mode === "strict" && (
                <div className="mt-3 p-3 rounded-md bg-amber-500/10 border border-amber-500/20">
                  <p className="text-xs text-amber-400 flex items-center gap-2">
                    <Shield className="h-3.5 w-3.5" />
                    Federal Auth Strict Mode: 0.1 RPS, no credential guessing, mandatory evidence capture, human approval gates.
                  </p>
                </div>
              )}
            </CardContent>
          </Card>

          {/* Summary Cards */}
          {latestRun && (
            <div className="grid grid-cols-2 sm:grid-cols-4 gap-3">
              <Card className="border-emerald-500/20">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-emerald-400">{latestRun.summary.pass}</div>
                  <div className="text-xs text-muted-foreground uppercase tracking-wider mt-1">Passed</div>
                </CardContent>
              </Card>
              <Card className="border-red-500/20">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-red-400">{latestRun.summary.fail}</div>
                  <div className="text-xs text-muted-foreground uppercase tracking-wider mt-1">Failed</div>
                </CardContent>
              </Card>
              <Card className="border-amber-500/20">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-amber-400">{latestRun.summary.warn}</div>
                  <div className="text-xs text-muted-foreground uppercase tracking-wider mt-1">Warnings</div>
                </CardContent>
              </Card>
              <Card className="border-zinc-500/20">
                <CardContent className="p-4 text-center">
                  <div className="text-2xl font-bold text-zinc-400">{latestRun.summary.error}</div>
                  <div className="text-xs text-muted-foreground uppercase tracking-wider mt-1">Errors</div>
                </CardContent>
              </Card>
            </div>
          )}

          {/* Results */}
          {latestRun && (
            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* OAuth/OIDC */}
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Globe2 className="h-4 w-4 text-blue-400" />
                    OAuth / OIDC Checks ({oauthResults.length})
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  {oauthResults.length === 0 ? (
                    <p className="text-xs text-muted-foreground py-4 text-center">No OAuth/OIDC checks ran</p>
                  ) : (
                    oauthResults.map(r => <CheckCard key={r.checkId} result={r} />)
                  )}
                </CardContent>
              </Card>

              {/* SAML */}
              <Card>
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Key className="h-4 w-4 text-purple-400" />
                    SAML Checks ({samlResults.length})
                  </CardTitle>
                </CardHeader>
                <CardContent className="space-y-2">
                  {samlResults.length === 0 ? (
                    <p className="text-xs text-muted-foreground py-4 text-center">No SAML checks ran</p>
                  ) : (
                    samlResults.map(r => <CheckCard key={r.checkId} result={r} />)
                  )}
                </CardContent>
              </Card>
            </div>
          )}

          {!latestRun && !running && (
            <Card className="border-dashed">
              <CardContent className="py-12 text-center">
                <Fingerprint className="h-12 w-12 text-muted-foreground/30 mx-auto mb-4" />
                <h3 className="text-sm font-medium text-muted-foreground">No Assessment Results</h3>
                <p className="text-xs text-muted-foreground/70 mt-1">
                  Enter a target URL above and run the assessment to see OAuth/OIDC and SAML check results.
                </p>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ── History Tab ── */}
        <TabsContent value="history" className="space-y-3">
          {runs.length === 0 ? (
            <Card className="border-dashed">
              <CardContent className="py-8 text-center">
                <FileText className="h-8 w-8 text-muted-foreground/30 mx-auto mb-3" />
                <p className="text-sm text-muted-foreground">No assessment runs yet</p>
              </CardContent>
            </Card>
          ) : (
            runs.map(run => (
              <Card key={run.id} className="hover:border-border transition-colors">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <p className="text-sm font-mono text-foreground">{run.targetUrl}</p>
                      <p className="text-xs text-muted-foreground mt-1">
                        {new Date(run.timestamp).toLocaleString()} · {run.mode} mode
                      </p>
                    </div>
                    <div className="flex gap-2">
                      <Badge variant="outline" className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30">
                        {run.summary.pass} pass
                      </Badge>
                      <Badge variant="outline" className="bg-red-500/10 text-red-400 border-red-500/30">
                        {run.summary.fail} fail
                      </Badge>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>

        {/* ── Methodology Tab ── */}
        <TabsContent value="methodology" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Auth Testing Methodology — 6 Phases</CardTitle>
              <CardDescription>
                Structured approach derived from the Auth Testing Knowledge Pack v1.2
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              {[
                { phase: "1. Recon & Identification", desc: "Identify login endpoints, auth entrypoints, and SSO providers. Fingerprint technology stack.", tools: "ffuf, nmap, ZAP, Burp Suite" },
                { phase: "2. Enumeration Testing", desc: "Detect username/email enumeration via response differences (status codes, timing, content length).", tools: "Custom HTTP probes, ZAP, ffuf" },
                { phase: "3. Credential Surface Analysis", desc: "Assess lockout thresholds, throttling mechanisms, password policy strength, and CAPTCHA implementation.", tools: "ZAP, Burp Suite, Hydra" },
                { phase: "4. Flow Manipulation", desc: "Model the auth state machine — test step-skipping, parameter tampering, and race conditions.", tools: "Burp Suite, mitmproxy, ZAP" },
                { phase: "5. Session & Token Security", desc: "Validate cookie flags (Secure/HttpOnly/SameSite), JWT signing, token entropy, and session fixation.", tools: "ZAP, jwt_tool, testssl" },
                { phase: "6. Post-Auth Abuse", desc: "Test authorization boundaries — IDOR, horizontal/vertical privilege escalation, role confusion.", tools: "Burp Suite, ZAP, Impacket" },
              ].map(p => (
                <div key={p.phase} className="border border-border/50 rounded-lg p-4">
                  <h4 className="text-sm font-semibold text-foreground">{p.phase}</h4>
                  <p className="text-xs text-muted-foreground mt-1">{p.desc}</p>
                  <p className="text-[10px] text-muted-foreground/70 mt-2 font-mono">Tools: {p.tools}</p>
                </div>
              ))}
            </CardContent>
          </Card>

          <Card>
            <CardHeader>
              <CardTitle className="text-base">SSO Assessment Checks</CardTitle>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <div>
                  <h4 className="text-xs font-semibold text-blue-400 uppercase tracking-wider mb-2 flex items-center gap-1">
                    <Globe2 className="h-3 w-3" /> OAuth/OIDC (6 Checks)
                  </h4>
                  <ul className="space-y-1 text-xs text-muted-foreground">
                    <li>• Redirect URI validation (open redirect)</li>
                    <li>• PKCE enforcement for public clients</li>
                    <li>• State parameter presence &amp; entropy</li>
                    <li>• Token endpoint authentication method</li>
                    <li>• Scope over-provisioning detection</li>
                    <li>• ID token signature validation</li>
                  </ul>
                </div>
                <div>
                  <h4 className="text-xs font-semibold text-purple-400 uppercase tracking-wider mb-2 flex items-center gap-1">
                    <Lock className="h-3 w-3" /> SAML (5 Checks)
                  </h4>
                  <ul className="space-y-1 text-xs text-muted-foreground">
                    <li>• XML signature wrapping resistance</li>
                    <li>• Assertion consumer service URL validation</li>
                    <li>• Replay protection (InResponseTo binding)</li>
                    <li>• Audience restriction enforcement</li>
                    <li>• Certificate pinning &amp; rotation</li>
                  </ul>
                </div>
              </div>
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>
    </div>
      </AppShell>
  );
}
