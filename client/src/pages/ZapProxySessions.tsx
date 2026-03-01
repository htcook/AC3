import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Textarea } from "@/components/ui/textarea";
import { toast } from "sonner";
import {
  Globe, Shield, Play, Square, RefreshCw, Download, AlertTriangle,
  Radio, Lock, Key, FileText, Clock, ArrowUpDown, Eye, Wifi,
  ShieldAlert, ChevronRight, Copy, ExternalLink, Activity
} from "lucide-react";

const STATUS_COLORS: Record<string, string> = {
  initializing: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  active: "bg-emerald-500/20 text-emerald-400 border-emerald-500/30",
  crawling: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  scanning: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  paused: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  completed: "bg-cyan-500/20 text-cyan-400 border-cyan-500/30",
  error: "bg-red-500/20 text-red-400 border-red-500/30",
};

export default function ZapProxySessions() {

  const [activeTab, setActiveTab] = useState("sessions");
  const [showNewSession, setShowNewSession] = useState(false);
  const [selectedSession, setSelectedSession] = useState<number | null>(null);

  // Form state
  const [targetUrl, setTargetUrl] = useState("");
  const [sessionName, setSessionName] = useState("");
  const [authType, setAuthType] = useState("none");
  const [wafVendor, setWafVendor] = useState("none");
  const [loginUrl, setLoginUrl] = useState("");
  const [usernameField, setUsernameField] = useState("");
  const [passwordField, setPasswordField] = useState("");
  const [loginUsername, setLoginUsername] = useState("");
  const [loginPassword, setLoginPassword] = useState("");
  const [bearerToken, setBearerToken] = useState("");

  // Queries
  const sessionsQuery = trpc.webAppScanning.listProxySessions.useQuery();
  const wafPresetsQuery = trpc.webAppScanning.getWafEvasionPresets.useQuery();
  const caCertQuery = trpc.webAppScanning.getCaCertificate.useQuery();

  // Mutations
  const startSession = trpc.webAppScanning.startProxySession.useMutation({
    onSuccess: () => {
      toast.success("Proxy session started — ZAP proxy is initializing...");
      setShowNewSession(false);
      sessionsQuery.refetch();
      resetForm();
    },
    onError: (err) => toast.error(`Failed to start session: ${err.message}`),
  });

  const stopSession = trpc.webAppScanning.stopProxySession.useMutation({
    onSuccess: () => {
      toast.success("Session stopped");
      sessionsQuery.refetch();
    },
    onError: (err) => toast.error(`Failed to stop session: ${err.message}`),
  });

  const generateReport = trpc.webAppScanning.generateThemedReport.useMutation({
    onSuccess: (data) => {
      toast.success("Report generated — opening report...");
      if (data?.html) {
        const blob = new Blob([data.html], { type: "text/html" });
        const url = URL.createObjectURL(blob);
        window.open(url, "_blank");
      }
    },
    onError: (err) => toast.error(`Report generation failed: ${err.message}`),
  });

  const resetForm = () => {
    setTargetUrl("");
    setSessionName("");
    setAuthType("none");
    setWafVendor("none");
    setLoginUrl("");
    setUsernameField("");
    setPasswordField("");
    setLoginUsername("");
    setLoginPassword("");
    setBearerToken("");
  };

  const handleStartSession = () => {
    if (!targetUrl) {
      toast.error("Target URL required");
      return;
    }
    const authConfig: Record<string, string> = {};
    if (authType === "form_login") {
      authConfig.loginUrl = loginUrl;
      authConfig.usernameField = usernameField || "username";
      authConfig.passwordField = passwordField || "password";
      authConfig.username = loginUsername;
      authConfig.password = loginPassword;
    } else if (authType === "bearer_token") {
      authConfig.token = bearerToken;
    } else if (authType === "basic_auth") {
      authConfig.username = loginUsername;
      authConfig.password = loginPassword;
    }

    startSession.mutate({
      targetUrl,
      sessionName: sessionName || `Session — ${new Date().toLocaleString()}`,
      authType,
      authConfig: Object.keys(authConfig).length > 0 ? authConfig : undefined,
      wafEvasionVendor: wafVendor !== "none" ? wafVendor : undefined,
    });
  };

  const sessions = sessionsQuery.data ?? [];
  const wafPresets = wafPresetsQuery.data ?? [];
  const caCert = caCertQuery.data;

  const activeCount = sessions.filter((s: any) => ["active", "crawling", "scanning"].includes(s.status)).length;
  const totalAlerts = sessions.reduce((sum: number, s: any) => sum + (s.alertsFound || 0), 0);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-mono font-bold tracking-tight flex items-center gap-3">
            <Radio className="h-6 w-6 text-primary" />
            ZAP PROXY SESSIONS
          </h1>
          <p className="text-sm text-muted-foreground mt-1 font-mono">
            Manage OWASP ZAP proxy sessions for web application penetration testing
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => sessionsQuery.refetch()}>
            <RefreshCw className="h-4 w-4 mr-1" /> Refresh
          </Button>
          <Button size="sm" onClick={() => setShowNewSession(true)} className="bg-primary text-primary-foreground">
            <Play className="h-4 w-4 mr-1" /> New Session
          </Button>
        </div>
      </div>

      {/* Stats Bar */}
      <div className="grid grid-cols-4 gap-3">
        {[
          { label: "Total Sessions", value: sessions.length, icon: Globe },
          { label: "Active", value: activeCount, icon: Activity },
          { label: "Total Alerts", value: totalAlerts, icon: AlertTriangle },
          { label: "CA Cert", value: caCert ? "Available" : "N/A", icon: Shield },
        ].map((stat) => (
          <Card key={stat.label} className="bg-card border-border">
            <CardContent className="p-3">
              <div className="flex items-center gap-2">
                <stat.icon className="h-4 w-4 text-muted-foreground" />
                <span className="text-xs font-mono text-muted-foreground uppercase">{stat.label}</span>
              </div>
              <p className="text-xl font-mono font-bold mt-1">{stat.value}</p>
            </CardContent>
          </Card>
        ))}
      </div>

      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-muted/50 border border-border">
          <TabsTrigger value="sessions" className="font-mono text-xs">SESSIONS</TabsTrigger>
          <TabsTrigger value="setup" className="font-mono text-xs">PROXY SETUP</TabsTrigger>
          <TabsTrigger value="traffic" className="font-mono text-xs">TRAFFIC LOG</TabsTrigger>
        </TabsList>

        {/* Sessions Tab */}
        <TabsContent value="sessions" className="space-y-3">
          {sessions.length === 0 ? (
            <Card className="bg-card border-border border-dashed">
              <CardContent className="p-8 text-center">
                <Radio className="h-12 w-12 text-muted-foreground mx-auto mb-3 opacity-40" />
                <p className="text-muted-foreground font-mono text-sm">No proxy sessions yet</p>
                <p className="text-muted-foreground/60 font-mono text-xs mt-1">Start a new session to begin intercepting traffic</p>
                <Button size="sm" className="mt-4" onClick={() => setShowNewSession(true)}>
                  <Play className="h-4 w-4 mr-1" /> Start First Session
                </Button>
              </CardContent>
            </Card>
          ) : (
            sessions.map((session: any) => (
              <Card key={session.id} className="bg-card border-border hover:border-primary/30 transition-colors">
                <CardContent className="p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <div className={`w-2 h-2 rounded-full ${
                        ["active", "crawling", "scanning"].includes(session.status)
                          ? "bg-emerald-400 animate-pulse" : "bg-muted-foreground/40"
                      }`} />
                      <div>
                        <p className="font-mono font-semibold text-sm">{session.sessionName || session.targetUrl}</p>
                        <p className="text-xs text-muted-foreground font-mono">{session.targetUrl}</p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <Badge variant="outline" className={`font-mono text-[10px] ${STATUS_COLORS[session.status] || ""}`}>
                        {session.status?.toUpperCase()}
                      </Badge>
                      {session.authType && session.authType !== "none" && (
                        <Badge variant="outline" className="font-mono text-[10px] border-yellow-500/30 text-yellow-400">
                          <Lock className="h-3 w-3 mr-1" /> {session.authType}
                        </Badge>
                      )}
                      {session.wafEvasionVendor && (
                        <Badge variant="outline" className="font-mono text-[10px] border-orange-500/30 text-orange-400">
                          <ShieldAlert className="h-3 w-3 mr-1" /> {session.wafEvasionVendor}
                        </Badge>
                      )}
                    </div>
                  </div>

                  <div className="grid grid-cols-5 gap-3 mt-3 pt-3 border-t border-border/50">
                    <div>
                      <span className="text-[10px] text-muted-foreground font-mono">URLS</span>
                      <p className="font-mono text-sm font-bold">{session.urlsDiscovered || 0}</p>
                    </div>
                    <div>
                      <span className="text-[10px] text-muted-foreground font-mono">REQUESTS</span>
                      <p className="font-mono text-sm font-bold">{session.requestsIntercepted || 0}</p>
                    </div>
                    <div>
                      <span className="text-[10px] text-muted-foreground font-mono">CRITICAL</span>
                      <p className="font-mono text-sm font-bold text-red-400">{session.alertsCritical || 0}</p>
                    </div>
                    <div>
                      <span className="text-[10px] text-muted-foreground font-mono">HIGH</span>
                      <p className="font-mono text-sm font-bold text-orange-400">{session.alertsHigh || 0}</p>
                    </div>
                    <div>
                      <span className="text-[10px] text-muted-foreground font-mono">MEDIUM</span>
                      <p className="font-mono text-sm font-bold text-yellow-400">{session.alertsMedium || 0}</p>
                    </div>
                  </div>

                  {session.scanProgress > 0 && session.scanProgress < 100 && (
                    <div className="mt-2">
                      <div className="h-1 bg-muted rounded-full overflow-hidden">
                        <div
                          className="h-full bg-primary transition-all duration-500"
                          style={{ width: `${session.scanProgress}%` }}
                        />
                      </div>
                      <span className="text-[10px] text-muted-foreground font-mono">{session.scanProgress}% complete</span>
                    </div>
                  )}

                  <div className="flex gap-2 mt-3">
                    {["active", "crawling", "scanning"].includes(session.status) ? (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => stopSession.mutate({ sessionId: session.id?.toString() || "" })}
                        className="text-red-400 border-red-500/30 hover:bg-red-500/10"
                      >
                        <Square className="h-3 w-3 mr-1" /> Stop
                      </Button>
                    ) : null}
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => {
                        setSelectedSession(session.id);
                        setActiveTab("traffic");
                      }}
                    >
                      <Eye className="h-3 w-3 mr-1" /> Traffic
                    </Button>
                    {session.status === "completed" && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => generateReport.mutate({ sessionId: session.id?.toString() || "" })}
                        disabled={generateReport.isPending}
                      >
                        <FileText className="h-3 w-3 mr-1" /> Report
                      </Button>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))
          )}
        </TabsContent>

        {/* Proxy Setup Tab */}
        <TabsContent value="setup" className="space-y-4">
          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="font-mono text-sm flex items-center gap-2">
                <Shield className="h-4 w-4 text-primary" /> CA CERTIFICATE SETUP
              </CardTitle>
              <CardDescription className="font-mono text-xs">
                Install ZAP's CA certificate to intercept HTTPS traffic
              </CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="bg-muted/30 border border-border rounded-md p-4">
                <h4 className="font-mono text-xs font-bold text-primary mb-2">BROWSER PROXY CONFIGURATION</h4>
                <div className="space-y-2 text-xs font-mono text-muted-foreground">
                  <p>1. Configure your browser to use the ZAP proxy:</p>
                  <div className="bg-background/50 rounded p-2 flex items-center justify-between">
                    <code>HTTP Proxy: &lt;ZAP_HOST&gt; Port: 8080</code>
                    <Button variant="ghost" size="sm" onClick={() => {
                      navigator.clipboard.writeText("HTTP Proxy: <ZAP_HOST> Port: 8080");
                      toast.success("Copied");
                    }}>
                      <Copy className="h-3 w-3" />
                    </Button>
                  </div>
                  <p>2. Download and install the CA certificate below</p>
                  <p>3. Import the certificate into your browser's trusted certificate store</p>
                  <p>4. Navigate to the target URL — ZAP will intercept all traffic</p>
                </div>
              </div>

              {caCert ? (
                <div className="flex gap-2">
                  <Button variant="outline" size="sm" onClick={() => {
                    const blob = new Blob([caCert.certificate || ""], { type: "application/x-x509-ca-cert" });
                    const url = URL.createObjectURL(blob);
                    const a = document.createElement("a");
                    a.href = url;
                    a.download = "zap-ca-cert.pem";
                    a.click();
                  }}>
                    <Download className="h-4 w-4 mr-1" /> Download CA Certificate
                  </Button>
                </div>
              ) : (
                <p className="text-xs font-mono text-muted-foreground">
                  CA certificate will be available when ZAP is connected
                </p>
              )}
            </CardContent>
          </Card>

          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="font-mono text-sm flex items-center gap-2">
                <ShieldAlert className="h-4 w-4 text-orange-400" /> WAF EVASION PRESETS
              </CardTitle>
              <CardDescription className="font-mono text-xs">
                Pre-configured scan profiles for bypassing common WAF/NGFW solutions
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="grid grid-cols-2 gap-2">
                {(Array.isArray(wafPresets) ? wafPresets : []).map((preset: any, i: number) => (
                  <div key={i} className="bg-muted/30 border border-border rounded p-3">
                    <div className="flex items-center justify-between">
                      <span className="font-mono text-xs font-bold">{preset.vendor || preset.name || `Preset ${i+1}`}</span>
                      <Badge variant="outline" className="font-mono text-[10px]">
                        {preset.difficulty || "moderate"}
                      </Badge>
                    </div>
                    <p className="text-[10px] text-muted-foreground font-mono mt-1">
                      {preset.description || "Custom evasion profile"}
                    </p>
                  </div>
                ))}
                {(!Array.isArray(wafPresets) || wafPresets.length === 0) && (
                  <p className="text-xs font-mono text-muted-foreground col-span-2">
                    WAF evasion presets will load when ZAP is connected
                  </p>
                )}
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* Traffic Log Tab */}
        <TabsContent value="traffic" className="space-y-3">
          <Card className="bg-card border-border">
            <CardHeader>
              <CardTitle className="font-mono text-sm flex items-center gap-2">
                <ArrowUpDown className="h-4 w-4 text-primary" /> INTERCEPTED TRAFFIC
              </CardTitle>
              <CardDescription className="font-mono text-xs">
                {selectedSession
                  ? `Viewing traffic for session #${selectedSession}`
                  : "Select a session to view intercepted traffic"}
              </CardDescription>
            </CardHeader>
            <CardContent>
              {selectedSession ? (
                <TrafficViewer sessionId={selectedSession} />
              ) : (
                <div className="text-center py-8">
                  <ArrowUpDown className="h-10 w-10 text-muted-foreground/30 mx-auto mb-2" />
                  <p className="text-sm font-mono text-muted-foreground">
                    Select a session from the Sessions tab to view traffic
                  </p>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* New Session Dialog */}
      <Dialog open={showNewSession} onOpenChange={setShowNewSession}>
        <DialogContent className="max-w-lg bg-card border-border">
          <DialogHeader>
            <DialogTitle className="font-mono text-sm flex items-center gap-2">
              <Play className="h-4 w-4 text-primary" /> NEW PROXY SESSION
            </DialogTitle>
          </DialogHeader>

          <div className="space-y-4">
            <div>
              <Label className="font-mono text-xs">SESSION NAME</Label>
              <Input
                value={sessionName}
                onChange={(e) => setSessionName(e.target.value)}
                placeholder="e.g., Target Corp Web App Scan"
                className="font-mono text-sm mt-1"
              />
            </div>

            <div>
              <Label className="font-mono text-xs">TARGET URL *</Label>
              <Input
                value={targetUrl}
                onChange={(e) => setTargetUrl(e.target.value)}
                placeholder="https://target.example.com"
                className="font-mono text-sm mt-1"
              />
            </div>

            <div>
              <Label className="font-mono text-xs">AUTHENTICATION TYPE</Label>
              <Select value={authType} onValueChange={setAuthType}>
                <SelectTrigger className="font-mono text-sm mt-1">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">No Authentication</SelectItem>
                  <SelectItem value="form_login">Form Login</SelectItem>
                  <SelectItem value="bearer_token">Bearer Token</SelectItem>
                  <SelectItem value="basic_auth">Basic Auth</SelectItem>
                  <SelectItem value="session_cookie">Session Cookie</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {authType === "form_login" && (
              <div className="space-y-3 pl-3 border-l-2 border-primary/30">
                <div>
                  <Label className="font-mono text-[10px]">LOGIN URL</Label>
                  <Input value={loginUrl} onChange={(e) => setLoginUrl(e.target.value)}
                    placeholder="/login" className="font-mono text-sm mt-1" />
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <Label className="font-mono text-[10px]">USERNAME FIELD</Label>
                    <Input value={usernameField} onChange={(e) => setUsernameField(e.target.value)}
                      placeholder="username" className="font-mono text-sm mt-1" />
                  </div>
                  <div>
                    <Label className="font-mono text-[10px]">PASSWORD FIELD</Label>
                    <Input value={passwordField} onChange={(e) => setPasswordField(e.target.value)}
                      placeholder="password" className="font-mono text-sm mt-1" />
                  </div>
                </div>
                <div className="grid grid-cols-2 gap-2">
                  <div>
                    <Label className="font-mono text-[10px]">USERNAME</Label>
                    <Input value={loginUsername} onChange={(e) => setLoginUsername(e.target.value)}
                      className="font-mono text-sm mt-1" />
                  </div>
                  <div>
                    <Label className="font-mono text-[10px]">PASSWORD</Label>
                    <Input type="password" value={loginPassword} onChange={(e) => setLoginPassword(e.target.value)}
                      className="font-mono text-sm mt-1" />
                  </div>
                </div>
              </div>
            )}

            {authType === "bearer_token" && (
              <div className="pl-3 border-l-2 border-primary/30">
                <Label className="font-mono text-[10px]">BEARER TOKEN</Label>
                <Textarea value={bearerToken} onChange={(e) => setBearerToken(e.target.value)}
                  placeholder="eyJhbGciOiJIUzI1NiIs..." className="font-mono text-xs mt-1" rows={3} />
              </div>
            )}

            {(authType === "basic_auth") && (
              <div className="grid grid-cols-2 gap-2 pl-3 border-l-2 border-primary/30">
                <div>
                  <Label className="font-mono text-[10px]">USERNAME</Label>
                  <Input value={loginUsername} onChange={(e) => setLoginUsername(e.target.value)}
                    className="font-mono text-sm mt-1" />
                </div>
                <div>
                  <Label className="font-mono text-[10px]">PASSWORD</Label>
                  <Input type="password" value={loginPassword} onChange={(e) => setLoginPassword(e.target.value)}
                    className="font-mono text-sm mt-1" />
                </div>
              </div>
            )}

            <div>
              <Label className="font-mono text-xs">WAF EVASION PRESET</Label>
              <Select value={wafVendor} onValueChange={setWafVendor}>
                <SelectTrigger className="font-mono text-sm mt-1">
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  <SelectItem value="none">No WAF Evasion</SelectItem>
                  <SelectItem value="cloudflare">Cloudflare</SelectItem>
                  <SelectItem value="akamai">Akamai</SelectItem>
                  <SelectItem value="aws_waf">AWS WAF</SelectItem>
                  <SelectItem value="f5_bigip">F5 BIG-IP</SelectItem>
                  <SelectItem value="imperva">Imperva</SelectItem>
                  <SelectItem value="fortinet">Fortinet FortiWeb</SelectItem>
                  <SelectItem value="palo_alto">Palo Alto</SelectItem>
                  <SelectItem value="modsecurity">ModSecurity</SelectItem>
                </SelectContent>
              </Select>
            </div>

            {wafVendor !== "none" && (
              <div className="bg-orange-500/10 border border-orange-500/20 rounded p-3">
                <p className="text-[10px] font-mono text-orange-400 flex items-center gap-1">
                  <ShieldAlert className="h-3 w-3" /> WAF evasion will apply rate limiting, header rotation, and payload encoding to avoid detection
                </p>
              </div>
            )}
          </div>

          <DialogFooter>
            <Button variant="outline" onClick={() => setShowNewSession(false)}>Cancel</Button>
            <Button onClick={handleStartSession} disabled={startSession.isPending || !targetUrl}>
              {startSession.isPending ? (
                <><RefreshCw className="h-4 w-4 mr-1 animate-spin" /> Starting...</>
              ) : (
                <><Play className="h-4 w-4 mr-1" /> Start Session</>
              )}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}

function TrafficViewer({ sessionId }: { sessionId: number }) {
  const historyQuery = trpc.webAppScanning.getProxyHistory.useQuery(
    { sessionId: sessionId.toString(), limit: 100 },
  );
  const [selectedEntry, setSelectedEntry] = useState<any>(null);

  const entries = historyQuery.data?.messages ?? [];

  return (
    <div className="space-y-2">
      <div className="flex items-center justify-between">
        <span className="text-xs font-mono text-muted-foreground">{entries.length} intercepted requests</span>
        <Button variant="ghost" size="sm" onClick={() => historyQuery.refetch()}>
          <RefreshCw className="h-3 w-3" />
        </Button>
      </div>

      {entries.length === 0 ? (
        <div className="text-center py-6">
          <Wifi className="h-8 w-8 text-muted-foreground/30 mx-auto mb-2" />
          <p className="text-xs font-mono text-muted-foreground">
            No traffic intercepted yet. Browse the target through the proxy to capture requests.
          </p>
        </div>
      ) : (
        <div className="border border-border rounded overflow-hidden">
          <div className="bg-muted/30 px-3 py-1.5 border-b border-border grid grid-cols-12 gap-2 text-[10px] font-mono text-muted-foreground uppercase">
            <span className="col-span-1">#</span>
            <span className="col-span-1">Method</span>
            <span className="col-span-5">URL</span>
            <span className="col-span-1">Status</span>
            <span className="col-span-2">Content-Type</span>
            <span className="col-span-1">Size</span>
            <span className="col-span-1">Time</span>
          </div>
          <div className="max-h-96 overflow-y-auto">
            {entries.map((entry: any, i: number) => (
              <div
                key={i}
                className={`px-3 py-1.5 border-b border-border/30 grid grid-cols-12 gap-2 text-xs font-mono cursor-pointer hover:bg-muted/20 ${
                  selectedEntry === i ? "bg-primary/10" : ""
                }`}
                onClick={() => setSelectedEntry(selectedEntry === i ? null : i)}
              >
                <span className="col-span-1 text-muted-foreground">{i + 1}</span>
                <span className={`col-span-1 font-bold ${
                  entry.method === "GET" ? "text-emerald-400" :
                  entry.method === "POST" ? "text-blue-400" :
                  entry.method === "PUT" ? "text-yellow-400" :
                  entry.method === "DELETE" ? "text-red-400" : ""
                }`}>{entry.method}</span>
                <span className="col-span-5 truncate">{entry.url}</span>
                <span className={`col-span-1 ${
                  entry.statusCode >= 200 && entry.statusCode < 300 ? "text-emerald-400" :
                  entry.statusCode >= 300 && entry.statusCode < 400 ? "text-yellow-400" :
                  entry.statusCode >= 400 ? "text-red-400" : ""
                }`}>{entry.statusCode}</span>
                <span className="col-span-2 truncate text-muted-foreground">{entry.contentType || "-"}</span>
                <span className="col-span-1 text-muted-foreground">{entry.responseSize ? `${Math.round(entry.responseSize / 1024)}K` : "-"}</span>
                <span className="col-span-1 text-muted-foreground">{entry.rtt ? `${entry.rtt}ms` : "-"}</span>
              </div>
            ))}
          </div>
        </div>
      )}

      {selectedEntry !== null && entries[selectedEntry] && (
        <Card className="bg-muted/20 border-border">
          <CardContent className="p-3">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <h4 className="font-mono text-[10px] text-primary font-bold mb-1">REQUEST</h4>
                <pre className="text-[10px] font-mono text-muted-foreground whitespace-pre-wrap max-h-40 overflow-y-auto bg-background/50 rounded p-2">
                  {entries[selectedEntry].requestHeaders || "No request headers captured"}
                </pre>
              </div>
              <div>
                <h4 className="font-mono text-[10px] text-primary font-bold mb-1">RESPONSE</h4>
                <pre className="text-[10px] font-mono text-muted-foreground whitespace-pre-wrap max-h-40 overflow-y-auto bg-background/50 rounded p-2">
                  {entries[selectedEntry].responseHeaders || "No response headers captured"}
                </pre>
              </div>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
