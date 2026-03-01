import { useState, useMemo, useEffect, useCallback } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Textarea } from "@/components/ui/textarea";
import { Alert, AlertDescription } from "@/components/ui/alert";
import { Progress } from "@/components/ui/progress";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import {
  Loader2, Lock, Unlock, Key, Shield, Target, Play, Square,
  AlertTriangle, CheckCircle2, XCircle, Clock, Search,
  RefreshCw, Crosshair, Zap, Eye, EyeOff, Server, Globe,
  Database, Terminal, Wifi, Hash, FileText, Download,
  ChevronRight, Activity, ShieldAlert, Fingerprint, Brain
} from "lucide-react";
import AppShell from "@/components/AppShell";

// ─── Types ────────────────────────────────────────────────────────────────────
type AttackMode = "brute_force" | "password_spray" | "credential_stuffing" | "default_creds" | "dictionary";
type Protocol = "http" | "ssh" | "ftp" | "telnet" | "mysql" | "redis" | "rdp" | "smb" | "mssql" | "postgres" | "vnc" | "smtp";

interface AttackResult {
  success: boolean;
  totalAttempts: number;
  successfulLogins: Array<{ username: string; password: string; timestamp: number }>;
  failedAttempts: number;
  lockoutsDetected: number;
  rateLimitsHit: number;
  durationMs: number;
  stoppedReason?: string;
}

// ─── Constants ────────────────────────────────────────────────────────────────
const ATTACK_MODES: Record<AttackMode, { label: string; icon: any; description: string; color: string }> = {
  brute_force: {
    label: "BRUTE FORCE",
    icon: Crosshair,
    description: "Systematic username/password combination testing against target",
    color: "text-red-400",
  },
  password_spray: {
    label: "PASSWORD SPRAY",
    icon: Zap,
    description: "Test common passwords across many usernames to avoid lockout",
    color: "text-amber-400",
  },
  credential_stuffing: {
    label: "CREDENTIAL STUFFING",
    icon: Database,
    description: "Test leaked credential pairs from breach databases",
    color: "text-purple-400",
  },
  default_creds: {
    label: "DEFAULT CREDENTIALS",
    icon: Key,
    description: "Test vendor default username/password combinations",
    color: "text-cyan-400",
  },
  dictionary: {
    label: "DICTIONARY ATTACK",
    icon: FileText,
    description: "Use curated wordlists optimized for the target environment",
    color: "text-emerald-400",
  },
};

const PROTOCOLS: Record<Protocol, { label: string; icon: any; defaultPort: number }> = {
  http: { label: "HTTP/HTTPS", icon: Globe, defaultPort: 443 },
  ssh: { label: "SSH", icon: Terminal, defaultPort: 22 },
  ftp: { label: "FTP", icon: Server, defaultPort: 21 },
  telnet: { label: "Telnet", icon: Terminal, defaultPort: 23 },
  mysql: { label: "MySQL", icon: Database, defaultPort: 3306 },
  redis: { label: "Redis", icon: Database, defaultPort: 6379 },
  rdp: { label: "RDP", icon: Server, defaultPort: 3389 },
  smb: { label: "SMB", icon: Server, defaultPort: 445 },
  mssql: { label: "MSSQL", icon: Database, defaultPort: 1433 },
  postgres: { label: "PostgreSQL", icon: Database, defaultPort: 5432 },
  vnc: { label: "VNC", icon: Server, defaultPort: 5900 },
  smtp: { label: "SMTP", icon: Wifi, defaultPort: 25 },
};

// ─── Component ────────────────────────────────────────────────────────────────
export default function CredentialAttacks() {
  // ── State ──
  const [activeTab, setActiveTab] = useState("configure");
  const [attackMode, setAttackMode] = useState<AttackMode>("brute_force");
  const [protocol, setProtocol] = useState<Protocol>("http");
  const [host, setHost] = useState("");
  const [port, setPort] = useState(443);
  const [loginUrl, setLoginUrl] = useState("");
  const [usernameField, setUsernameField] = useState("username");
  const [passwordField, setPasswordField] = useState("password");
  const [successIndicator, setSuccessIndicator] = useState("");
  const [failureIndicator, setFailureIndicator] = useState("");
  const [contentType, setContentType] = useState<"form" | "json">("form");
  const [selectedPasswordList, setSelectedPasswordList] = useState("top_1000");
  const [selectedUsernameList, setSelectedUsernameList] = useState("common_usernames");
  const [customUsernames, setCustomUsernames] = useState("");
  const [customPasswords, setCustomPasswords] = useState("");
  const [credentialPairsText, setCredentialPairsText] = useState("");
  const [maxRps, setMaxRps] = useState(5);
  const [delayMs, setDelayMs] = useState(500);
  const [maxAttempts, setMaxAttempts] = useState(1000);
  const [lockoutDetection, setLockoutDetection] = useState(true);
  const [stopOnFirst, setStopOnFirst] = useState(false);
  const [timeoutSec, setTimeoutSec] = useState(600);
  const [sprayDelay, setSprayDelay] = useState(30);
  const [isRunning, setIsRunning] = useState(false);
  const [attackResult, setAttackResult] = useState<AttackResult | null>(null);
  const [showPasswords, setShowPasswords] = useState(false);

  // ── Org-based password generation ──
  const [orgName, setOrgName] = useState("");
  const [orgDomain, setOrgDomain] = useState("");
  const [orgIndustry, setOrgIndustry] = useState("");
  const [orgCity, setOrgCity] = useState("");
  const [generatedPasswords, setGeneratedPasswords] = useState<string[]>([]);

  // ── Queries ──
  const passwordLists = trpc.webAppScanning.getPasswordLists.useQuery();
  const usernameLists = trpc.webAppScanning.getUsernameLists.useQuery();
  const defaultCreds = trpc.webAppScanning.getDefaultCredentials.useQuery(
    { protocol, port },
    { enabled: attackMode === "default_creds" }
  );

  // ── Mutations ──
  const detectForm = trpc.webAppScanning.detectWebLoginForm.useMutation({
    onSuccess: (data) => {
      if (data) {
        if (data.loginUrl) setLoginUrl(data.loginUrl);
        if (data.usernameField) setUsernameField(data.usernameField);
        if (data.passwordField) setPasswordField(data.passwordField);
        if (data.csrfTokenName) toast.info(`CSRF token detected: ${data.csrfTokenName}`);
        toast.success("Login form detected and configured");
      } else {
        toast.error("No login form detected at this URL");
      }
    },
    onError: () => toast.error("Failed to detect login form"),
  });

  const generatePasswords = trpc.webAppScanning.generateTargetedPasswords.useMutation({
    onSuccess: (data) => {
      setGeneratedPasswords(data);
      toast.success(`Generated ${data.length} targeted passwords`);
    },
    onError: () => toast.error("Failed to generate passwords"),
  });

  const executeAttack = trpc.webAppScanning.executeCredentialAttack.useMutation({
    onSuccess: (data) => {
      setAttackResult(data as AttackResult);
      setIsRunning(false);
      setActiveTab("results");
      if ((data as AttackResult).successfulLogins?.length > 0) {
        toast.success(`Found ${(data as AttackResult).successfulLogins.length} valid credential(s)!`);
      } else {
        toast.info("Attack completed — no valid credentials found");
      }
    },
    onError: (err) => {
      setIsRunning(false);
      toast.error(`Attack failed: ${err.message}`);
    },
  });

  // ── Auto-set port when protocol changes ──
  useEffect(() => {
    setPort(PROTOCOLS[protocol].defaultPort);
  }, [protocol]);

  // ── Build attack payload ──
  const handleLaunchAttack = useCallback(() => {
    if (!host) { toast.error("Target host is required"); return; }

    setIsRunning(true);
    setAttackResult(null);

    const usernames = customUsernames
      ? customUsernames.split("\n").map(u => u.trim()).filter(Boolean)
      : undefined;
    const passwords = customPasswords
      ? customPasswords.split("\n").map(p => p.trim()).filter(Boolean)
      : undefined;

    const credentialPairs = credentialPairsText
      ? credentialPairsText.split("\n").map(line => {
          const [username, password] = line.split(":");
          return { username: username?.trim() || "", password: password?.trim() || "" };
        }).filter(p => p.username && p.password)
      : undefined;

    executeAttack.mutate({
      mode: attackMode,
      host,
      port,
      protocol,
      loginUrl: protocol === "http" ? loginUrl : undefined,
      usernameField: protocol === "http" ? usernameField : undefined,
      passwordField: protocol === "http" ? passwordField : undefined,
      successIndicator: successIndicator || undefined,
      failureIndicator: failureIndicator || undefined,
      contentType: protocol === "http" ? contentType : undefined,
      usernames,
      passwords,
      credentialPairs,
      passwordListName: selectedPasswordList,
      maxRequestsPerSecond: maxRps,
      delayBetweenAttemptsMs: delayMs,
      maxAttemptsPerUser: 10,
      lockoutDetection,
      maxTotalAttempts: maxAttempts,
      stopOnFirstSuccess: stopOnFirst,
      globalTimeoutSec: timeoutSec,
      sprayDelayBetweenPasswordsSec: attackMode === "password_spray" ? sprayDelay : undefined,
    });
  }, [host, port, protocol, attackMode, loginUrl, usernameField, passwordField,
      successIndicator, failureIndicator, contentType, customUsernames, customPasswords,
      credentialPairsText, selectedPasswordList, maxRps, delayMs, maxAttempts,
      lockoutDetection, stopOnFirst, timeoutSec, sprayDelay, executeAttack]);

  return (
    <AppShell>
      <div className="space-y-6">
        {/* ── Header ── */}
        <div className="border-b border-[#00E5CC]/20 pb-6">
          <div className="flex items-center gap-3 mb-2">
            <div className="w-10 h-10 bg-red-500/10 border border-red-500/30 flex items-center justify-center">
              <Lock className="w-5 h-5 text-red-400" />
            </div>
            <div>
              <h1 className="text-2xl font-mono font-bold tracking-tight text-white">
                CREDENTIAL ATTACK ENGINE
              </h1>
              <p className="text-sm text-gray-400 font-mono">
                Brute force, password spray, credential stuffing, and default credential testing for web logins and service ports.
              </p>
            </div>
          </div>
        </div>

        {/* ── Attack Mode Selector ── */}
        <div className="grid grid-cols-5 gap-3">
          {(Object.entries(ATTACK_MODES) as [AttackMode, typeof ATTACK_MODES[AttackMode]][]).map(([mode, config]) => {
            const Icon = config.icon;
            const isActive = attackMode === mode;
            return (
              <button
                key={mode}
                onClick={() => setAttackMode(mode)}
                className={`p-3 border text-left transition-all ${
                  isActive
                    ? "border-[#00E5CC]/60 bg-[#00E5CC]/5"
                    : "border-gray-700/50 bg-[#0D1117] hover:border-gray-600"
                }`}
              >
                <Icon className={`w-5 h-5 mb-2 ${isActive ? config.color : "text-gray-500"}`} />
                <div className={`text-xs font-mono font-bold ${isActive ? "text-white" : "text-gray-400"}`}>
                  {config.label}
                </div>
                <div className="text-[10px] text-gray-500 mt-1 leading-tight">{config.description}</div>
              </button>
            );
          })}
        </div>

        {/* ── Main Content ── */}
        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList className="bg-[#0D1117] border border-gray-700/50">
            <TabsTrigger value="configure" className="font-mono text-xs">TARGET CONFIG</TabsTrigger>
            <TabsTrigger value="wordlists" className="font-mono text-xs">WORDLISTS</TabsTrigger>
            <TabsTrigger value="tuning" className="font-mono text-xs">ATTACK TUNING</TabsTrigger>
            <TabsTrigger value="external-tools" className="font-mono text-xs">
              <Zap className="w-3 h-3 mr-1" /> EXTERNAL TOOLS
            </TabsTrigger>
            <TabsTrigger value="results" className="font-mono text-xs">
              RESULTS {attackResult && <Badge variant="outline" className="ml-1 text-[10px]">{attackResult.successfulLogins?.length || 0}</Badge>}
            </TabsTrigger>
            <TabsTrigger value="history" className="font-mono text-xs">
              <Clock className="w-3 h-3 mr-1" /> ATTACK HISTORY
            </TabsTrigger>
          </TabsList>

          {/* ── TARGET CONFIG TAB ── */}
          <TabsContent value="configure" className="space-y-4 mt-4">
            <div className="grid grid-cols-2 gap-4">
              {/* Protocol & Target */}
              <Card className="bg-[#0D1117] border-gray-700/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-mono text-[#00E5CC]">TARGET</CardTitle>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div className="grid grid-cols-2 gap-3">
                    <div>
                      <Label className="text-xs font-mono text-gray-400">PROTOCOL</Label>
                      <Select value={protocol} onValueChange={(v) => setProtocol(v as Protocol)}>
                        <SelectTrigger className="bg-[#0A0E14] border-gray-700 font-mono text-xs">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {(Object.entries(PROTOCOLS) as [Protocol, typeof PROTOCOLS[Protocol]][]).map(([key, p]) => (
                            <SelectItem key={key} value={key}>
                              <span className="font-mono text-xs">{p.label}</span>
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div>
                      <Label className="text-xs font-mono text-gray-400">PORT</Label>
                      <Input
                        type="number"
                        value={port}
                        onChange={(e) => setPort(parseInt(e.target.value) || 0)}
                        className="bg-[#0A0E14] border-gray-700 font-mono text-xs"
                      />
                    </div>
                  </div>
                  <div>
                    <Label className="text-xs font-mono text-gray-400">HOST / IP</Label>
                    <Input
                      value={host}
                      onChange={(e) => setHost(e.target.value)}
                      placeholder="target.example.com"
                      className="bg-[#0A0E14] border-gray-700 font-mono text-xs"
                    />
                  </div>
                </CardContent>
              </Card>

              {/* Web Login Config (HTTP only) */}
              <Card className={`bg-[#0D1117] border-gray-700/50 ${protocol !== "http" ? "opacity-40 pointer-events-none" : ""}`}>
                <CardHeader className="pb-3">
                  <div className="flex items-center justify-between">
                    <CardTitle className="text-sm font-mono text-[#00E5CC]">WEB LOGIN FORM</CardTitle>
                    <Button
                      size="sm"
                      variant="outline"
                      className="text-[10px] font-mono h-7 border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10"
                      onClick={() => {
                        if (!loginUrl) { toast.error("Enter a login URL first"); return; }
                        detectForm.mutate({ url: loginUrl });
                      }}
                      disabled={detectForm.isPending}
                    >
                      {detectForm.isPending ? <Loader2 className="w-3 h-3 animate-spin mr-1" /> : <Brain className="w-3 h-3 mr-1" />}
                      AUTO-DETECT
                    </Button>
                  </div>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div>
                    <Label className="text-xs font-mono text-gray-400">LOGIN URL</Label>
                    <Input
                      value={loginUrl}
                      onChange={(e) => setLoginUrl(e.target.value)}
                      placeholder="https://target.com/login"
                      className="bg-[#0A0E14] border-gray-700 font-mono text-xs"
                    />
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <Label className="text-xs font-mono text-gray-400">USERNAME FIELD</Label>
                      <Input value={usernameField} onChange={(e) => setUsernameField(e.target.value)}
                        className="bg-[#0A0E14] border-gray-700 font-mono text-xs" />
                    </div>
                    <div>
                      <Label className="text-xs font-mono text-gray-400">PASSWORD FIELD</Label>
                      <Input value={passwordField} onChange={(e) => setPasswordField(e.target.value)}
                        className="bg-[#0A0E14] border-gray-700 font-mono text-xs" />
                    </div>
                  </div>
                  <div className="grid grid-cols-2 gap-2">
                    <div>
                      <Label className="text-xs font-mono text-gray-400">SUCCESS INDICATOR</Label>
                      <Input value={successIndicator} onChange={(e) => setSuccessIndicator(e.target.value)}
                        placeholder="dashboard, welcome"
                        className="bg-[#0A0E14] border-gray-700 font-mono text-xs" />
                    </div>
                    <div>
                      <Label className="text-xs font-mono text-gray-400">CONTENT TYPE</Label>
                      <Select value={contentType} onValueChange={(v) => setContentType(v as "form" | "json")}>
                        <SelectTrigger className="bg-[#0A0E14] border-gray-700 font-mono text-xs">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          <SelectItem value="form">Form POST</SelectItem>
                          <SelectItem value="json">JSON API</SelectItem>
                        </SelectContent>
                      </Select>
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Default Credentials Panel */}
            {attackMode === "default_creds" && (
              <Card className="bg-[#0D1117] border-gray-700/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-mono text-amber-400">
                    <Key className="w-4 h-4 inline mr-2" />
                    DEFAULT CREDENTIALS FOR {PROTOCOLS[protocol]?.label.toUpperCase()} (PORT {port})
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {defaultCreds.isLoading ? (
                    <div className="flex items-center gap-2 text-gray-400 text-sm">
                      <Loader2 className="w-4 h-4 animate-spin" /> Loading default credentials...
                    </div>
                  ) : defaultCreds.data && defaultCreds.data.length > 0 ? (
                    <div className="overflow-x-auto">
                      <table className="w-full text-xs font-mono">
                        <thead>
                          <tr className="border-b border-gray-700/50 text-gray-500">
                            <th className="text-left py-2 px-3">VENDOR</th>
                            <th className="text-left py-2 px-3">PRODUCT</th>
                            <th className="text-left py-2 px-3">USERNAME</th>
                            <th className="text-left py-2 px-3">PASSWORD</th>
                          </tr>
                        </thead>
                        <tbody>
                          {defaultCreds.data.slice(0, 20).map((cred: any, i: number) => (
                            <tr key={i} className="border-b border-gray-800/50 hover:bg-[#00E5CC]/5">
                              <td className="py-1.5 px-3 text-gray-400">{cred.vendor}</td>
                              <td className="py-1.5 px-3 text-gray-300">{cred.product}</td>
                              <td className="py-1.5 px-3 text-cyan-400">{cred.username}</td>
                              <td className="py-1.5 px-3">
                                <span className={showPasswords ? "text-amber-400" : "text-gray-600"}>
                                  {showPasswords ? cred.password : "••••••••"}
                                </span>
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                      <div className="flex items-center justify-between mt-2 pt-2 border-t border-gray-800/50">
                        <span className="text-[10px] text-gray-500">{defaultCreds.data.length} credentials available</span>
                        <Button size="sm" variant="ghost" className="text-[10px] h-6"
                          onClick={() => setShowPasswords(!showPasswords)}>
                          {showPasswords ? <EyeOff className="w-3 h-3 mr-1" /> : <Eye className="w-3 h-3 mr-1" />}
                          {showPasswords ? "HIDE" : "SHOW"} PASSWORDS
                        </Button>
                      </div>
                    </div>
                  ) : (
                    <p className="text-gray-500 text-sm">No default credentials found for this protocol/port combination.</p>
                  )}
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* ── WORDLISTS TAB ── */}
          <TabsContent value="wordlists" className="space-y-4 mt-4">
            <div className="grid grid-cols-2 gap-4">
              {/* Password Lists */}
              <Card className="bg-[#0D1117] border-gray-700/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-mono text-[#00E5CC]">PASSWORD LISTS</CardTitle>
                  <CardDescription className="text-xs text-gray-500">Select a built-in wordlist or provide custom passwords</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div>
                    <Label className="text-xs font-mono text-gray-400">BUILT-IN LIST</Label>
                    <Select value={selectedPasswordList} onValueChange={setSelectedPasswordList}>
                      <SelectTrigger className="bg-[#0A0E14] border-gray-700 font-mono text-xs">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {passwordLists.data?.map((list: any) => (
                          <SelectItem key={list.name} value={list.name}>
                            <span className="font-mono text-xs">{list.name} ({list.count} passwords)</span>
                          </SelectItem>
                        )) || (
                          <>
                            <SelectItem value="top_100">top_100</SelectItem>
                            <SelectItem value="top_1000">top_1000</SelectItem>
                            <SelectItem value="top_10000">top_10000</SelectItem>
                          </>
                        )}
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label className="text-xs font-mono text-gray-400">CUSTOM PASSWORDS (one per line)</Label>
                    <Textarea
                      value={customPasswords}
                      onChange={(e) => setCustomPasswords(e.target.value)}
                      placeholder={"Password123!\nAdmin@2024\nCompanyName1!"}
                      className="bg-[#0A0E14] border-gray-700 font-mono text-xs h-32 resize-none"
                    />
                  </div>
                </CardContent>
              </Card>

              {/* Username Lists */}
              <Card className="bg-[#0D1117] border-gray-700/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-mono text-[#00E5CC]">USERNAME LISTS</CardTitle>
                  <CardDescription className="text-xs text-gray-500">Select a built-in list or provide custom usernames</CardDescription>
                </CardHeader>
                <CardContent className="space-y-3">
                  <div>
                    <Label className="text-xs font-mono text-gray-400">BUILT-IN LIST</Label>
                    <Select value={selectedUsernameList} onValueChange={setSelectedUsernameList}>
                      <SelectTrigger className="bg-[#0A0E14] border-gray-700 font-mono text-xs">
                        <SelectValue />
                      </SelectTrigger>
                      <SelectContent>
                        {usernameLists.data?.map((list: any) => (
                          <SelectItem key={list.name} value={list.name}>
                            <span className="font-mono text-xs">{list.name} ({list.count} usernames)</span>
                          </SelectItem>
                        )) || (
                          <>
                            <SelectItem value="common_usernames">common_usernames</SelectItem>
                            <SelectItem value="admin_usernames">admin_usernames</SelectItem>
                          </>
                        )}
                      </SelectContent>
                    </Select>
                  </div>
                  <div>
                    <Label className="text-xs font-mono text-gray-400">CUSTOM USERNAMES (one per line)</Label>
                    <Textarea
                      value={customUsernames}
                      onChange={(e) => setCustomUsernames(e.target.value)}
                      placeholder={"admin\nroot\nuser@company.com"}
                      className="bg-[#0A0E14] border-gray-700 font-mono text-xs h-32 resize-none"
                    />
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* Credential Stuffing Input */}
            {attackMode === "credential_stuffing" && (
              <Card className="bg-[#0D1117] border-gray-700/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-mono text-purple-400">
                    <Database className="w-4 h-4 inline mr-2" />
                    CREDENTIAL PAIRS (username:password format)
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  <Textarea
                    value={credentialPairsText}
                    onChange={(e) => setCredentialPairsText(e.target.value)}
                    placeholder={"user@company.com:Password123\nadmin@target.com:Welcome1!\njohn.doe:Summer2024!"}
                    className="bg-[#0A0E14] border-gray-700 font-mono text-xs h-40 resize-none"
                  />
                  <p className="text-[10px] text-gray-500 mt-1">
                    {credentialPairsText.split("\n").filter(l => l.includes(":")).length} credential pairs loaded
                  </p>
                </CardContent>
              </Card>
            )}

            {/* Targeted Password Generation */}
            <Card className="bg-[#0D1117] border-gray-700/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-mono text-emerald-400">
                  <Brain className="w-4 h-4 inline mr-2" />
                  TARGETED PASSWORD GENERATION
                </CardTitle>
                <CardDescription className="text-xs text-gray-500">
                  Generate passwords based on organization intelligence (company name, domain, industry patterns)
                </CardDescription>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="grid grid-cols-4 gap-3">
                  <div>
                    <Label className="text-xs font-mono text-gray-400">COMPANY NAME</Label>
                    <Input value={orgName} onChange={(e) => setOrgName(e.target.value)}
                      placeholder="Acme Corp" className="bg-[#0A0E14] border-gray-700 font-mono text-xs" />
                  </div>
                  <div>
                    <Label className="text-xs font-mono text-gray-400">DOMAIN</Label>
                    <Input value={orgDomain} onChange={(e) => setOrgDomain(e.target.value)}
                      placeholder="acme.com" className="bg-[#0A0E14] border-gray-700 font-mono text-xs" />
                  </div>
                  <div>
                    <Label className="text-xs font-mono text-gray-400">INDUSTRY</Label>
                    <Input value={orgIndustry} onChange={(e) => setOrgIndustry(e.target.value)}
                      placeholder="Technology" className="bg-[#0A0E14] border-gray-700 font-mono text-xs" />
                  </div>
                  <div>
                    <Label className="text-xs font-mono text-gray-400">CITY</Label>
                    <Input value={orgCity} onChange={(e) => setOrgCity(e.target.value)}
                      placeholder="San Francisco" className="bg-[#0A0E14] border-gray-700 font-mono text-xs" />
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <Button
                    size="sm"
                    className="font-mono text-xs bg-emerald-600 hover:bg-emerald-700"
                    onClick={() => {
                      if (!orgName || !orgDomain) { toast.error("Company name and domain required"); return; }
                      generatePasswords.mutate({
                        companyName: orgName,
                        domain: orgDomain,
                        industry: orgIndustry || undefined,
                        city: orgCity || undefined,
                      });
                    }}
                    disabled={generatePasswords.isPending}
                  >
                    {generatePasswords.isPending ? <Loader2 className="w-3 h-3 animate-spin mr-1" /> : <Fingerprint className="w-3 h-3 mr-1" />}
                    GENERATE
                  </Button>
                  {generatedPasswords.length > 0 && (
                    <Badge variant="outline" className="text-emerald-400 border-emerald-500/30 text-[10px]">
                      {generatedPasswords.length} passwords generated
                    </Badge>
                  )}
                </div>
                {generatedPasswords.length > 0 && (
                  <div className="bg-[#0A0E14] border border-gray-700/50 p-3 max-h-40 overflow-y-auto">
                    <div className="grid grid-cols-4 gap-1">
                      {generatedPasswords.slice(0, 40).map((pw, i) => (
                        <span key={i} className="text-[10px] font-mono text-amber-400/80">{pw}</span>
                      ))}
                    </div>
                    {generatedPasswords.length > 40 && (
                      <p className="text-[10px] text-gray-500 mt-2">...and {generatedPasswords.length - 40} more</p>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </TabsContent>

          {/* ── ATTACK TUNING TAB ── */}
          <TabsContent value="tuning" className="space-y-4 mt-4">
            <div className="grid grid-cols-2 gap-4">
              <Card className="bg-[#0D1117] border-gray-700/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-mono text-[#00E5CC]">RATE LIMITING</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div>
                    <Label className="text-xs font-mono text-gray-400">MAX REQUESTS/SEC</Label>
                    <Input type="number" value={maxRps} onChange={(e) => setMaxRps(parseInt(e.target.value) || 1)}
                      className="bg-[#0A0E14] border-gray-700 font-mono text-xs" />
                  </div>
                  <div>
                    <Label className="text-xs font-mono text-gray-400">DELAY BETWEEN ATTEMPTS (ms)</Label>
                    <Input type="number" value={delayMs} onChange={(e) => setDelayMs(parseInt(e.target.value) || 0)}
                      className="bg-[#0A0E14] border-gray-700 font-mono text-xs" />
                  </div>
                  <div>
                    <Label className="text-xs font-mono text-gray-400">MAX TOTAL ATTEMPTS</Label>
                    <Input type="number" value={maxAttempts} onChange={(e) => setMaxAttempts(parseInt(e.target.value) || 100)}
                      className="bg-[#0A0E14] border-gray-700 font-mono text-xs" />
                  </div>
                  <div>
                    <Label className="text-xs font-mono text-gray-400">GLOBAL TIMEOUT (seconds)</Label>
                    <Input type="number" value={timeoutSec} onChange={(e) => setTimeoutSec(parseInt(e.target.value) || 60)}
                      className="bg-[#0A0E14] border-gray-700 font-mono text-xs" />
                  </div>
                </CardContent>
              </Card>

              <Card className="bg-[#0D1117] border-gray-700/50">
                <CardHeader className="pb-3">
                  <CardTitle className="text-sm font-mono text-[#00E5CC]">SAFETY & EVASION</CardTitle>
                </CardHeader>
                <CardContent className="space-y-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <Label className="text-xs font-mono text-gray-400">LOCKOUT DETECTION</Label>
                      <p className="text-[10px] text-gray-600">Pause on account lockout signals</p>
                    </div>
                    <Switch checked={lockoutDetection} onCheckedChange={setLockoutDetection} />
                  </div>
                  <div className="flex items-center justify-between">
                    <div>
                      <Label className="text-xs font-mono text-gray-400">STOP ON FIRST SUCCESS</Label>
                      <p className="text-[10px] text-gray-600">Halt attack after first valid credential</p>
                    </div>
                    <Switch checked={stopOnFirst} onCheckedChange={setStopOnFirst} />
                  </div>
                  {attackMode === "password_spray" && (
                    <div>
                      <Label className="text-xs font-mono text-gray-400">SPRAY DELAY BETWEEN PASSWORDS (sec)</Label>
                      <Input type="number" value={sprayDelay} onChange={(e) => setSprayDelay(parseInt(e.target.value) || 10)}
                        className="bg-[#0A0E14] border-gray-700 font-mono text-xs" />
                      <p className="text-[10px] text-gray-600 mt-1">Wait time between each password round across all users</p>
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>

            {/* ROE Warning */}
            <Alert className="bg-amber-500/5 border-amber-500/30">
              <AlertTriangle className="w-4 h-4 text-amber-400" />
              <AlertDescription className="text-xs text-amber-300/80 font-mono">
                Credential attacks must be authorized under your Rules of Engagement (ROE). Ensure you have written permission
                before targeting any system. Lockout detection is enabled by default to minimize disruption.
              </AlertDescription>
            </Alert>
          </TabsContent>

          {/* ── EXTERNAL TOOLS TAB ── */}
          <TabsContent value="external-tools" className="space-y-4 mt-4">
            <ExternalToolsPanel
              protocol={protocol}
              host={host}
              port={port}
              attackMode={attackMode}
              onAttackResult={(result: AttackResult) => {
                setAttackResult(result);
                setActiveTab("results");
              }}
            />
          </TabsContent>

          {/* ── RESULTS TAB ── */}
          <TabsContent value="results" className="space-y-4 mt-4">
            {isRunning && (
              <Card className="bg-[#0D1117] border-[#00E5CC]/30">
                <CardContent className="py-8 text-center">
                  <Loader2 className="w-8 h-8 animate-spin text-[#00E5CC] mx-auto mb-3" />
                  <p className="text-sm font-mono text-white">ATTACK IN PROGRESS</p>
                  <p className="text-xs text-gray-400 mt-1">
                    {attackMode.replace("_", " ").toUpperCase()} against {host}:{port} ({protocol.toUpperCase()})
                  </p>
                  <Button size="sm" variant="destructive" className="mt-4 font-mono text-xs"
                    onClick={() => { setIsRunning(false); toast.info("Attack cancelled"); }}>
                    <Square className="w-3 h-3 mr-1" /> ABORT
                  </Button>
                </CardContent>
              </Card>
            )}

            {attackResult && (
              <>
                {/* Summary Stats */}
                <div className="grid grid-cols-5 gap-3">
                  <Card className="bg-[#0D1117] border-gray-700/50">
                    <CardContent className="py-4 text-center">
                      <div className="text-2xl font-mono font-bold text-white">{attackResult.totalAttempts}</div>
                      <div className="text-[10px] font-mono text-gray-500">TOTAL ATTEMPTS</div>
                    </CardContent>
                  </Card>
                  <Card className={`bg-[#0D1117] ${attackResult.successfulLogins?.length > 0 ? "border-green-500/50" : "border-gray-700/50"}`}>
                    <CardContent className="py-4 text-center">
                      <div className={`text-2xl font-mono font-bold ${attackResult.successfulLogins?.length > 0 ? "text-green-400" : "text-gray-500"}`}>
                        {attackResult.successfulLogins?.length || 0}
                      </div>
                      <div className="text-[10px] font-mono text-gray-500">SUCCESSFUL</div>
                    </CardContent>
                  </Card>
                  <Card className="bg-[#0D1117] border-gray-700/50">
                    <CardContent className="py-4 text-center">
                      <div className="text-2xl font-mono font-bold text-red-400">{attackResult.failedAttempts}</div>
                      <div className="text-[10px] font-mono text-gray-500">FAILED</div>
                    </CardContent>
                  </Card>
                  <Card className="bg-[#0D1117] border-gray-700/50">
                    <CardContent className="py-4 text-center">
                      <div className="text-2xl font-mono font-bold text-amber-400">{attackResult.lockoutsDetected}</div>
                      <div className="text-[10px] font-mono text-gray-500">LOCKOUTS</div>
                    </CardContent>
                  </Card>
                  <Card className="bg-[#0D1117] border-gray-700/50">
                    <CardContent className="py-4 text-center">
                      <div className="text-2xl font-mono font-bold text-gray-300">
                        {(attackResult.durationMs / 1000).toFixed(1)}s
                      </div>
                      <div className="text-[10px] font-mono text-gray-500">DURATION</div>
                    </CardContent>
                  </Card>
                </div>

                {/* Successful Logins */}
                {attackResult.successfulLogins?.length > 0 && (
                  <Card className="bg-[#0D1117] border-green-500/30">
                    <CardHeader className="pb-3">
                      <div className="flex items-center justify-between">
                        <CardTitle className="text-sm font-mono text-green-400">
                          <Unlock className="w-4 h-4 inline mr-2" />
                          VALID CREDENTIALS FOUND
                        </CardTitle>
                        <Button size="sm" variant="ghost" className="text-[10px] h-6"
                          onClick={() => setShowPasswords(!showPasswords)}>
                          {showPasswords ? <EyeOff className="w-3 h-3 mr-1" /> : <Eye className="w-3 h-3 mr-1" />}
                          {showPasswords ? "HIDE" : "SHOW"}
                        </Button>
                      </div>
                    </CardHeader>
                    <CardContent>
                      <table className="w-full text-xs font-mono">
                        <thead>
                          <tr className="border-b border-gray-700/50 text-gray-500">
                            <th className="text-left py-2 px-3">#</th>
                            <th className="text-left py-2 px-3">USERNAME</th>
                            <th className="text-left py-2 px-3">PASSWORD</th>
                            <th className="text-left py-2 px-3">TIMESTAMP</th>
                          </tr>
                        </thead>
                        <tbody>
                          {attackResult.successfulLogins.map((login, i) => (
                            <tr key={i} className="border-b border-gray-800/50 hover:bg-green-500/5">
                              <td className="py-2 px-3 text-gray-500">{i + 1}</td>
                              <td className="py-2 px-3 text-cyan-400">{login.username}</td>
                              <td className="py-2 px-3">
                                <span className={showPasswords ? "text-green-400" : "text-gray-600"}>
                                  {showPasswords ? login.password : "••••••••"}
                                </span>
                              </td>
                              <td className="py-2 px-3 text-gray-500">
                                {new Date(login.timestamp).toLocaleTimeString()}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </CardContent>
                  </Card>
                )}

                {/* Stop Reason */}
                {attackResult.stoppedReason && (
                  <Alert className="bg-[#0D1117] border-gray-700/50">
                    <ShieldAlert className="w-4 h-4 text-amber-400" />
                    <AlertDescription className="text-xs text-gray-300 font-mono">
                      Attack stopped: {attackResult.stoppedReason}
                    </AlertDescription>
                  </Alert>
                )}

                {/* No results */}
                {!attackResult.successfulLogins?.length && (
                  <Card className="bg-[#0D1117] border-gray-700/50">
                    <CardContent className="py-8 text-center">
                      <Shield className="w-8 h-8 text-gray-600 mx-auto mb-3" />
                      <p className="text-sm font-mono text-gray-400">No valid credentials discovered</p>
                      <p className="text-xs text-gray-600 mt-1">
                        Target appears to be resilient against {attackMode.replace("_", " ")} attacks
                      </p>
                    </CardContent>
                  </Card>
                )}
              </>
            )}

            {!isRunning && !attackResult && (
              <Card className="bg-[#0D1117] border-gray-700/50">
                <CardContent className="py-12 text-center">
                  <Target className="w-10 h-10 text-gray-700 mx-auto mb-3" />
                  <p className="text-sm font-mono text-gray-500">No attack results yet</p>
                  <p className="text-xs text-gray-600 mt-1">Configure a target and launch an attack to see results here</p>
                </CardContent>
              </Card>
            )}
          </TabsContent>

          {/* ── ATTACK HISTORY TAB ── */}
          <TabsContent value="history" className="space-y-4 mt-4">
            <AttackHistoryPanel />
          </TabsContent>
        </Tabs>

        {/* ── Launch Button ── */}
        <div className="flex items-center justify-between border-t border-gray-700/50 pt-4">
          <div className="text-xs font-mono text-gray-500">
            {attackMode.replace("_", " ").toUpperCase()} → {protocol.toUpperCase()}://{host || "..."}:{port}
          </div>
          <Button
            size="lg"
            className="font-mono text-sm bg-red-600 hover:bg-red-700 px-8"
            onClick={handleLaunchAttack}
            disabled={isRunning || !host}
          >
            {isRunning ? (
              <><Loader2 className="w-4 h-4 animate-spin mr-2" /> ATTACKING...</>
            ) : (
              <><Play className="w-4 h-4 mr-2" /> LAUNCH ATTACK</>
            )}
          </Button>
        </div>
      </div>
    </AppShell>
  );
}

// ─── External Tools Panel Component ─────────────────────────────────────────

function ExternalToolsPanel({ protocol, host, port, attackMode, onAttackResult }: {
  protocol: string;
  host: string;
  port: number;
  attackMode: string;
  onAttackResult: (result: AttackResult) => void;
}) {
  const [selectedTool, setSelectedTool] = useState<"hydra" | "medusa" | "netexec" | null>(null);
  const [extUsernames, setExtUsernames] = useState("admin");
  const [extPasswords, setExtPasswords] = useState("");
  const [extThreads, setExtThreads] = useState(8);
  const [extTimeout, setExtTimeout] = useState(600);
  const [extStopOnFirst, setExtStopOnFirst] = useState(false);
  const [extDomain, setExtDomain] = useState("");
  const [extNtlmHash, setExtNtlmHash] = useState("");
  const [extFormParams, setExtFormParams] = useState("");
  const [extFailureString, setExtFailureString] = useState("Invalid");
  const [extNetexecModule, setExtNetexecModule] = useState<"smb" | "winrm" | "ldap" | "mssql" | "rdp" | "ssh" | "ftp" | "wmi">("smb");
  const [extPostAuth, setExtPostAuth] = useState<string[]>([]);
  const [isRunning, setIsRunning] = useState(false);
  const [recommendation, setRecommendation] = useState<any>(null);
  const [showKnowledge, setShowKnowledge] = useState<string | null>(null);

  // Queries
  const toolCapabilities = trpc.webAppScanning.getToolCapabilities.useQuery();
  const toolDetection = trpc.webAppScanning.detectExternalTools.useQuery();
  const knowledgeBase = trpc.webAppScanning.getToolKnowledgeBase.useQuery();

  // Mutations
  const getRecommendation = trpc.webAppScanning.recommendAttackTool.useMutation({
    onSuccess: (data) => {
      setRecommendation(data);
      if (data.recommended) setSelectedTool(data.recommended as any);
      toast.success(`LLM recommends: ${data.recommended?.toUpperCase()}`);
    },
    onError: () => toast.error("Failed to get tool recommendation"),
  });

  const executeExternal = trpc.webAppScanning.executeExternalAttack.useMutation({
    onSuccess: (data: any) => {
      setIsRunning(false);
      const normalized: AttackResult = {
        success: data.successfulLogins?.length > 0,
        totalAttempts: data.totalAttempts,
        successfulLogins: data.successfulLogins || [],
        failedAttempts: data.failedAttempts,
        lockoutsDetected: 0,
        rateLimitsHit: 0,
        durationMs: data.durationSec * 1000,
        stoppedReason: data.status !== "completed" ? data.status : undefined,
      };
      onAttackResult(normalized);
      if (data.successfulLogins?.length > 0) {
        toast.success(`${data.tool.toUpperCase()}: Found ${data.successfulLogins.length} valid credential(s)!`);
      } else if (data.status === "tool_not_found") {
        toast.error(`${data.tool} is not installed. ${data.errors?.[0] || ""}`);
      } else {
        toast.info(`${data.tool.toUpperCase()}: Attack completed — no valid credentials found`);
      }
    },
    onError: (err) => {
      setIsRunning(false);
      toast.error(`External attack failed: ${err.message}`);
    },
  });

  const refreshDetection = trpc.webAppScanning.refreshToolDetection.useMutation({
    onSuccess: () => {
      toolDetection.refetch();
      toolCapabilities.refetch();
      toast.success("Tool detection refreshed");
    },
  });

  const handleGetRecommendation = () => {
    if (!host) { toast.error("Set a target host first"); return; }
    getRecommendation.mutate({
      targetHost: host,
      targetPort: port,
      protocol,
      attackMode,
      isActiveDirectory: extDomain.length > 0,
      hasNtlmHash: extNtlmHash.length > 0,
      targetOs: extDomain ? "windows" : "unknown",
    });
  };

  const handleLaunchExternal = () => {
    if (!selectedTool || !host) { toast.error("Select a tool and target"); return; }
    setIsRunning(true);
    executeExternal.mutate({
      tool: selectedTool,
      host,
      port,
      protocol,
      usernames: extUsernames.split("\n").map(u => u.trim()).filter(Boolean),
      passwords: extPasswords.split("\n").map(p => p.trim()).filter(Boolean),
      threads: extThreads,
      globalTimeout: extTimeout,
      stopOnFirst: extStopOnFirst,
      domain: extDomain || undefined,
      ntlmHash: extNtlmHash || undefined,
      formParams: extFormParams || undefined,
      failureString: extFailureString || undefined,
      netexecModule: selectedTool === "netexec" ? extNetexecModule : undefined,
      netexecPostAuth: selectedTool === "netexec" && extPostAuth.length > 0 ? extPostAuth : undefined,
    });
  };

  const TOOL_ICONS: Record<string, { icon: any; color: string; bg: string }> = {
    hydra: { icon: Zap, color: "text-blue-400", bg: "bg-blue-500/10 border-blue-500/30" },
    medusa: { icon: Shield, color: "text-purple-400", bg: "bg-purple-500/10 border-purple-500/30" },
    netexec: { icon: Terminal, color: "text-amber-400", bg: "bg-amber-500/10 border-amber-500/30" },
  };

  const NXC_MODULES = ["smb", "winrm", "ldap", "mssql", "rdp", "ssh", "ftp", "wmi"] as const;
  const NXC_POST_AUTH = [
    { key: "shares", label: "Enumerate Shares" },
    { key: "users", label: "Enumerate Users" },
    { key: "groups", label: "Enumerate Groups" },
    { key: "sam", label: "Dump SAM" },
    { key: "lsa", label: "Dump LSA Secrets" },
    { key: "sessions", label: "List Sessions" },
    { key: "disks", label: "List Disks" },
    { key: "loggedon-users", label: "Logged-on Users" },
  ];

  return (
    <div className="space-y-4">
      {/* Tool Detection Status */}
      <Card className="bg-[#0D1117] border-gray-700/50">
        <CardHeader className="pb-3">
          <div className="flex items-center justify-between">
            <CardTitle className="text-sm font-mono text-[#00E5CC]">
              EXTERNAL ATTACK TOOLS
            </CardTitle>
            <div className="flex items-center gap-2">
              <Button
                size="sm" variant="outline"
                className="text-[10px] font-mono h-7 border-cyan-500/30 text-cyan-400 hover:bg-cyan-500/10"
                onClick={() => refreshDetection.mutate()}
                disabled={refreshDetection.isPending}
              >
                <RefreshCw className={`w-3 h-3 mr-1 ${refreshDetection.isPending ? "animate-spin" : ""}`} />
                REFRESH
              </Button>
              <Button
                size="sm" variant="outline"
                className="text-[10px] font-mono h-7 border-[#00E5CC]/30 text-[#00E5CC] hover:bg-[#00E5CC]/10"
                onClick={handleGetRecommendation}
                disabled={getRecommendation.isPending || !host}
              >
                {getRecommendation.isPending ? (
                  <Loader2 className="w-3 h-3 animate-spin mr-1" />
                ) : (
                  <Brain className="w-3 h-3 mr-1" />
                )}
                LLM RECOMMEND
              </Button>
            </div>
          </div>
          <CardDescription className="text-xs text-gray-500 font-mono">
            Industry-standard credential attack tools integrated via subprocess. The LLM analyzes your target and recommends the optimal tool.
          </CardDescription>
        </CardHeader>
        <CardContent className="space-y-4">
          {/* Tool Cards */}
          <div className="grid grid-cols-3 gap-3">
            {(["hydra", "medusa", "netexec"] as const).map((tool) => {
              const cap = toolCapabilities.data?.find(c => c.tool === tool);
              const det = toolDetection.data?.[tool];
              const iconInfo = TOOL_ICONS[tool];
              const Icon = iconInfo.icon;
              const isSelected = selectedTool === tool;
              const isRecommended = recommendation?.recommended === tool;
              const kb = knowledgeBase.data?.[tool];

              return (
                <button
                  key={tool}
                  onClick={() => setSelectedTool(tool)}
                  className={`p-4 border text-left transition-all relative ${
                    isSelected
                      ? `${iconInfo.bg} ring-1 ring-${iconInfo.color.replace("text-", "")}`
                      : "border-gray-700/50 bg-[#0A0E14] hover:border-gray-600"
                  }`}
                >
                  {isRecommended && (
                    <div className="absolute -top-2 -right-2 bg-[#00E5CC] text-black text-[9px] font-mono font-bold px-2 py-0.5">
                      LLM PICK
                    </div>
                  )}
                  <div className="flex items-center gap-2 mb-2">
                    <Icon className={`w-5 h-5 ${iconInfo.color}`} />
                    <span className="font-mono text-sm font-bold text-white">
                      {tool === "netexec" ? "NETEXEC" : tool.toUpperCase()}
                    </span>
                    {det?.installed ? (
                      <Badge className="bg-emerald-500/10 text-emerald-400 border-emerald-500/30 text-[9px] ml-auto">
                        <CheckCircle2 className="w-2.5 h-2.5 mr-0.5" /> {det.version || "OK"}
                      </Badge>
                    ) : (
                      <Badge className="bg-gray-500/10 text-gray-400 border-gray-500/30 text-[9px] ml-auto">
                        <XCircle className="w-2.5 h-2.5 mr-0.5" /> NOT FOUND
                      </Badge>
                    )}
                  </div>
                  <p className="text-[10px] text-gray-400 font-mono leading-relaxed mb-2">
                    {tool === "hydra" && "Fastest parallelized brute-forcer. 50+ protocols, 64 threads."}
                    {tool === "medusa" && "Stable thread-per-host model. Best for multi-host & flaky targets."}
                    {tool === "netexec" && "Active Directory swiss army knife. Pass-the-hash, Kerberos, domain enum."}
                  </p>
                  <div className="flex items-center gap-1 flex-wrap">
                    <Badge variant="outline" className="text-[8px] border-gray-600 text-gray-500">
                      {cap?.license || ""}
                    </Badge>
                    <Badge variant="outline" className="text-[8px] border-gray-600 text-gray-500">
                      {cap?.protocols?.length || 0} protocols
                    </Badge>
                    <Badge variant="outline" className={`text-[8px] border-gray-600 ${
                      cap?.performance?.relativeSpeed === "fast" ? "text-emerald-400" :
                      cap?.performance?.relativeSpeed === "moderate" ? "text-amber-400" : "text-gray-400"
                    }`}>
                      {cap?.performance?.relativeSpeed || ""}
                    </Badge>
                  </div>
                  {/* Knowledge base toggle */}
                  <button
                    onClick={(e) => { e.stopPropagation(); setShowKnowledge(showKnowledge === tool ? null : tool); }}
                    className="mt-2 text-[9px] font-mono text-cyan-400/60 hover:text-cyan-400 underline"
                  >
                    {showKnowledge === tool ? "Hide details" : "View strengths & use cases"}
                  </button>
                </button>
              );
            })}
          </div>

          {/* LLM Recommendation Display */}
          {recommendation && (
            <Card className="bg-[#00E5CC]/5 border-[#00E5CC]/30">
              <CardContent className="py-3">
                <div className="flex items-start gap-3">
                  <Brain className="w-5 h-5 text-[#00E5CC] mt-0.5 shrink-0" />
                  <div className="space-y-1">
                    <div className="flex items-center gap-2">
                      <span className="font-mono text-sm font-bold text-[#00E5CC]">
                        RECOMMENDED: {recommendation.recommended?.toUpperCase()}
                      </span>
                      <Badge className="bg-[#00E5CC]/10 text-[#00E5CC] border-[#00E5CC]/30 text-[9px]">
                        {recommendation.confidence}% confidence
                      </Badge>
                    </div>
                    <p className="text-xs text-gray-300 font-mono leading-relaxed">
                      {recommendation.reasoning}
                    </p>
                    {recommendation.attackPlan && (
                      <div className="mt-2 p-2 bg-[#0A0E14] border border-gray-700/50">
                        <p className="text-[10px] font-mono text-gray-400 mb-1">ATTACK PLAN:</p>
                        <pre className="text-[10px] font-mono text-gray-300 whitespace-pre-wrap">
                          {recommendation.attackPlan}
                        </pre>
                      </div>
                    )}
                    {recommendation.alternatives?.length > 0 && (
                      <div className="mt-1">
                        <p className="text-[9px] font-mono text-gray-500">Alternatives:</p>
                        {recommendation.alternatives.map((alt: any, i: number) => (
                          <p key={i} className="text-[9px] font-mono text-gray-500">
                            • {alt.tool?.toUpperCase()}: {alt.reason}
                          </p>
                        ))}
                      </div>
                    )}
                  </div>
                </div>
              </CardContent>
            </Card>
          )}

          {/* Knowledge Base Expansion */}
          {showKnowledge && knowledgeBase.data && (
            <Card className="bg-[#0A0E14] border-gray-700/50">
              <CardHeader className="pb-2">
                <CardTitle className="text-sm font-mono text-white">
                  {(knowledgeBase.data as any)[showKnowledge]?.fullName} — Knowledge Base
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <div className="grid grid-cols-2 gap-4">
                  <div>
                    <p className="text-[10px] font-mono text-emerald-400 mb-1 font-bold">BEST FOR:</p>
                    <div className="space-y-0.5">
                      {((knowledgeBase.data as any)[showKnowledge]?.bestFor || []).map((item: string, i: number) => (
                        <p key={i} className="text-[10px] font-mono text-gray-400">✓ {item}</p>
                      ))}
                    </div>
                  </div>
                  <div>
                    <p className="text-[10px] font-mono text-red-400 mb-1 font-bold">AVOID WHEN:</p>
                    <div className="space-y-0.5">
                      {((knowledgeBase.data as any)[showKnowledge]?.avoidFor || []).map((item: string, i: number) => (
                        <p key={i} className="text-[10px] font-mono text-gray-500">✗ {item}</p>
                      ))}
                    </div>
                  </div>
                </div>
                <div>
                  <p className="text-[10px] font-mono text-cyan-400 mb-1 font-bold">STRENGTHS:</p>
                  <div className="grid grid-cols-2 gap-x-4 gap-y-0.5">
                    {((knowledgeBase.data as any)[showKnowledge]?.strengths || []).map((item: string, i: number) => (
                      <p key={i} className="text-[10px] font-mono text-gray-400">• {item}</p>
                    ))}
                  </div>
                </div>
                <div>
                  <p className="text-[10px] font-mono text-amber-400 mb-1 font-bold">COMMAND EXAMPLES:</p>
                  <div className="space-y-1">
                    {Object.entries((knowledgeBase.data as any)[showKnowledge]?.commandExamples || {}).slice(0, 5).map(([key, cmd]) => (
                      <div key={key} className="flex items-start gap-2">
                        <Badge variant="outline" className="text-[8px] border-gray-600 text-gray-500 shrink-0 mt-0.5">{key}</Badge>
                        <code className="text-[9px] font-mono text-gray-400 break-all">{cmd as string}</code>
                      </div>
                    ))}
                  </div>
                </div>
              </CardContent>
            </Card>
          )}
        </CardContent>
      </Card>

      {/* Tool-Specific Configuration */}
      {selectedTool && (
        <Card className="bg-[#0D1117] border-gray-700/50">
          <CardHeader className="pb-3">
            <CardTitle className="text-sm font-mono text-[#00E5CC]">
              {selectedTool.toUpperCase()} CONFIGURATION
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-2 gap-4">
              {/* Common Config */}
              <div className="space-y-3">
                <div>
                  <Label className="text-xs font-mono text-gray-400">USERNAMES (one per line)</Label>
                  <Textarea
                    value={extUsernames}
                    onChange={(e) => setExtUsernames(e.target.value)}
                    placeholder="admin\nroot\nuser"
                    className="bg-[#0A0E14] border-gray-700 font-mono text-xs h-24"
                  />
                </div>
                <div>
                  <Label className="text-xs font-mono text-gray-400">PASSWORDS (one per line)</Label>
                  <Textarea
                    value={extPasswords}
                    onChange={(e) => setExtPasswords(e.target.value)}
                    placeholder="password\nadmin123\nP@ssw0rd"
                    className="bg-[#0A0E14] border-gray-700 font-mono text-xs h-24"
                  />
                </div>
                <div className="grid grid-cols-2 gap-3">
                  <div>
                    <Label className="text-xs font-mono text-gray-400">THREADS</Label>
                    <Input type="number" value={extThreads} onChange={(e) => setExtThreads(parseInt(e.target.value) || 4)}
                      className="bg-[#0A0E14] border-gray-700 font-mono text-xs" />
                  </div>
                  <div>
                    <Label className="text-xs font-mono text-gray-400">TIMEOUT (sec)</Label>
                    <Input type="number" value={extTimeout} onChange={(e) => setExtTimeout(parseInt(e.target.value) || 300)}
                      className="bg-[#0A0E14] border-gray-700 font-mono text-xs" />
                  </div>
                </div>
                <div className="flex items-center justify-between">
                  <div>
                    <Label className="text-xs font-mono text-gray-400">STOP ON FIRST SUCCESS</Label>
                  </div>
                  <Switch checked={extStopOnFirst} onCheckedChange={setExtStopOnFirst} />
                </div>
              </div>

              {/* Tool-Specific Config */}
              <div className="space-y-3">
                {/* NetExec-specific: Domain, Hash, Module, Post-Auth */}
                {selectedTool === "netexec" && (
                  <>
                    <div>
                      <Label className="text-xs font-mono text-gray-400">AD DOMAIN (optional)</Label>
                      <Input value={extDomain} onChange={(e) => setExtDomain(e.target.value)}
                        placeholder="CORP.LOCAL"
                        className="bg-[#0A0E14] border-gray-700 font-mono text-xs" />
                    </div>
                    <div>
                      <Label className="text-xs font-mono text-gray-400">NTLM HASH (pass-the-hash)</Label>
                      <Input value={extNtlmHash} onChange={(e) => setExtNtlmHash(e.target.value)}
                        placeholder="aad3b435b51404eeaad3b435b51404ee:hash"
                        className="bg-[#0A0E14] border-gray-700 font-mono text-xs" />
                      <p className="text-[9px] text-gray-600 mt-0.5">LM:NT format. Leave empty for password auth.</p>
                    </div>
                    <div>
                      <Label className="text-xs font-mono text-gray-400">PROTOCOL MODULE</Label>
                      <Select value={extNetexecModule} onValueChange={(v) => setExtNetexecModule(v as any)}>
                        <SelectTrigger className="bg-[#0A0E14] border-gray-700 font-mono text-xs">
                          <SelectValue />
                        </SelectTrigger>
                        <SelectContent>
                          {NXC_MODULES.map(m => (
                            <SelectItem key={m} value={m}>
                              <span className="font-mono text-xs">{m.toUpperCase()}</span>
                            </SelectItem>
                          ))}
                        </SelectContent>
                      </Select>
                    </div>
                    <div>
                      <Label className="text-xs font-mono text-gray-400">POST-AUTH ACTIONS</Label>
                      <div className="grid grid-cols-2 gap-1 mt-1">
                        {NXC_POST_AUTH.map(action => (
                          <label key={action.key} className="flex items-center gap-1.5 text-[10px] font-mono text-gray-400 cursor-pointer">
                            <input
                              type="checkbox"
                              checked={extPostAuth.includes(action.key)}
                              onChange={(e) => {
                                if (e.target.checked) setExtPostAuth([...extPostAuth, action.key]);
                                else setExtPostAuth(extPostAuth.filter(a => a !== action.key));
                              }}
                              className="rounded border-gray-600"
                            />
                            {action.label}
                          </label>
                        ))}
                      </div>
                    </div>
                  </>
                )}

                {/* Hydra-specific: HTTP form params */}
                {selectedTool === "hydra" && protocol === "http" && (
                  <>
                    <div>
                      <Label className="text-xs font-mono text-gray-400">FORM PARAMETERS</Label>
                      <Input value={extFormParams} onChange={(e) => setExtFormParams(e.target.value)}
                        placeholder="username=^USER^&password=^PASS^"
                        className="bg-[#0A0E14] border-gray-700 font-mono text-xs" />
                      <p className="text-[9px] text-gray-600 mt-0.5">Use ^USER^ and ^PASS^ as placeholders</p>
                    </div>
                    <div>
                      <Label className="text-xs font-mono text-gray-400">FAILURE STRING</Label>
                      <Input value={extFailureString} onChange={(e) => setExtFailureString(e.target.value)}
                        placeholder="Invalid credentials"
                        className="bg-[#0A0E14] border-gray-700 font-mono text-xs" />
                      <p className="text-[9px] text-gray-600 mt-0.5">Text in response that indicates login failure</p>
                    </div>
                  </>
                )}

                {/* Medusa-specific info */}
                {selectedTool === "medusa" && (
                  <div className="p-3 bg-purple-500/5 border border-purple-500/20">
                    <p className="text-[10px] font-mono text-purple-300 font-bold mb-1">MEDUSA NOTES</p>
                    <p className="text-[10px] font-mono text-gray-400 leading-relaxed">
                      Medusa uses a thread-per-host model for maximum stability. It will automatically
                      retry failed connections and provides cleaner error reporting than Hydra.
                      Best for multi-host scanning and unreliable targets.
                    </p>
                  </div>
                )}

                {/* Hydra-specific info (non-HTTP) */}
                {selectedTool === "hydra" && protocol !== "http" && (
                  <div className="p-3 bg-blue-500/5 border border-blue-500/20">
                    <p className="text-[10px] font-mono text-blue-300 font-bold mb-1">HYDRA NOTES</p>
                    <p className="text-[10px] font-mono text-gray-400 leading-relaxed">
                      Hydra is the fastest option with up to 64 parallel connections.
                      For {protocol.toUpperCase()}, it uses optimized native protocol handlers.
                      Supports session resume (-R) if interrupted.
                    </p>
                  </div>
                )}
              </div>
            </div>

            {/* Launch Button */}
            <div className="flex items-center justify-between border-t border-gray-700/50 pt-3">
              <div className="text-xs font-mono text-gray-500">
                {selectedTool.toUpperCase()} → {protocol.toUpperCase()}://{host || "..."}:{port}
                {extDomain && ` (${extDomain})`}
                {extNtlmHash && " [PTH]"}
              </div>
              <Button
                className={`font-mono text-sm px-6 ${
                  selectedTool === "hydra" ? "bg-blue-600 hover:bg-blue-700" :
                  selectedTool === "medusa" ? "bg-purple-600 hover:bg-purple-700" :
                  "bg-amber-600 hover:bg-amber-700"
                }`}
                onClick={handleLaunchExternal}
                disabled={isRunning || !host || !extPasswords.trim()}
              >
                {isRunning ? (
                  <><Loader2 className="w-4 h-4 animate-spin mr-2" /> RUNNING {selectedTool.toUpperCase()}...</>
                ) : (
                  <><Play className="w-4 h-4 mr-2" /> LAUNCH {selectedTool.toUpperCase()}</>
                )}
              </Button>
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Attack History Panel Component ──────────────────────────────────────────

function AttackHistoryPanel() {
  const [toolFilter, setToolFilter] = useState("all");
  const [protocolFilter, setProtocolFilter] = useState("all");
  const [statusFilter, setStatusFilter] = useState("all");
  const [selectedRunId, setSelectedRunId] = useState<number | null>(null);

  const historyQuery = trpc.webAppScanning.getAttackHistory.useQuery({
    tool: toolFilter !== "all" ? toolFilter : undefined,
    protocol: protocolFilter !== "all" ? protocolFilter : undefined,
    status: statusFilter !== "all" ? statusFilter : undefined,
    limit: 50,
    offset: 0,
  });

  const statsQuery = trpc.webAppScanning.getAttackStats.useQuery();

  const detailQuery = trpc.webAppScanning.getAttackRunDetail.useQuery(
    { id: selectedRunId! },
    { enabled: !!selectedRunId }
  );

  const validateMutation = trpc.webAppScanning.updateFindingValidation.useMutation({
    onSuccess: () => {
      toast.success("Finding validation updated");
      detailQuery.refetch();
    },
  });

  const toolColors: Record<string, string> = {
    builtin: "text-blue-400 bg-blue-400/10 border-blue-400/30",
    hydra: "text-green-400 bg-green-400/10 border-green-400/30",
    medusa: "text-amber-400 bg-amber-400/10 border-amber-400/30",
    netexec: "text-purple-400 bg-purple-400/10 border-purple-400/30",
  };

  const statusColors: Record<string, string> = {
    running: "text-yellow-400 bg-yellow-400/10",
    completed: "text-green-400 bg-green-400/10",
    stopped: "text-orange-400 bg-orange-400/10",
    error: "text-red-400 bg-red-400/10",
  };

  // Stats summary cards
  const stats = statsQuery.data;
  const totalRuns = stats?.runs.reduce((s, r) => s + Number(r.totalRuns), 0) ?? 0;
  const totalFindings = stats?.findings.reduce((s, f) => s + Number(f.totalFindings), 0) ?? 0;
  const totalValidated = stats?.findings.reduce((s, f) => s + Number(f.validated ?? 0), 0) ?? 0;

  if (selectedRunId && detailQuery.data) {
    const { run, findings } = detailQuery.data;
    return (
      <div className="space-y-4">
        <Button variant="outline" size="sm" className="font-mono text-xs" onClick={() => setSelectedRunId(null)}>
          ← BACK TO HISTORY
        </Button>

        <Card className="bg-[#0D1117] border-gray-700/50">
          <CardHeader className="pb-3">
            <div className="flex items-center justify-between">
              <div>
                <CardTitle className="text-sm font-mono text-white">
                  {run.protocol?.toUpperCase()}://{run.targetHost}:{run.targetPort}
                </CardTitle>
                <CardDescription className="font-mono text-xs mt-1">
                  {run.attackMode?.replace("_", " ").toUpperCase()} via {(run.tool ?? "builtin").toUpperCase()}
                  {run.toolVersion && ` v${run.toolVersion}`}
                </CardDescription>
              </div>
              <Badge className={`font-mono text-[10px] ${statusColors[run.status] ?? ""}`}>
                {run.status?.toUpperCase()}
              </Badge>
            </div>
          </CardHeader>
          <CardContent className="space-y-4">
            <div className="grid grid-cols-4 gap-3">
              {[
                { label: "ATTEMPTS", value: run.totalAttempts ?? 0, icon: Target },
                { label: "SUCCESSFUL", value: run.successfulAttempts ?? 0, icon: CheckCircle2 },
                { label: "LOCKOUTS", value: run.lockoutsDetected ?? 0, icon: Lock },
                { label: "DURATION", value: run.durationMs ? `${(run.durationMs / 1000).toFixed(1)}s` : "—", icon: Clock },
              ].map(({ label, value, icon: Icon }) => (
                <div key={label} className="bg-[#161B22] rounded p-3 border border-gray-700/30">
                  <div className="flex items-center gap-1.5 mb-1">
                    <Icon className="w-3 h-3 text-gray-500" />
                    <span className="text-[10px] font-mono text-gray-500">{label}</span>
                  </div>
                  <span className="text-lg font-mono text-white">{value}</span>
                </div>
              ))}
            </div>

            {findings.length > 0 && (
              <div>
                <h4 className="text-xs font-mono text-gray-400 mb-2 flex items-center gap-1.5">
                  <Key className="w-3 h-3" /> DISCOVERED CREDENTIALS ({findings.length})
                </h4>
                <div className="space-y-2">
                  {findings.map((f: any) => (
                    <div key={f.id} className="bg-[#161B22] rounded p-3 border border-gray-700/30 flex items-center justify-between">
                      <div>
                        <div className="flex items-center gap-2">
                          <span className="font-mono text-sm text-green-400">{f.username}</span>
                          <span className="text-gray-500">:</span>
                          <span className="font-mono text-sm text-amber-400">{f.password}</span>
                          {f.accessLevel && f.accessLevel !== "unknown" && (
                            <Badge variant="outline" className="text-[10px] font-mono">{f.accessLevel}</Badge>
                          )}
                        </div>
                        <div className="text-[10px] font-mono text-gray-500 mt-1">
                          {f.targetHost}:{f.targetPort} • {f.protocol} • via {(f.tool ?? "builtin").toUpperCase()}
                        </div>
                      </div>
                      <div className="flex items-center gap-1">
                        <Button
                          size="sm"
                          variant={f.validationStatus === "validated" ? "default" : "outline"}
                          className="h-6 text-[10px] font-mono"
                          onClick={() => validateMutation.mutate({
                            id: f.id,
                            validationStatus: f.validationStatus === "validated" ? "unvalidated" : "validated",
                          })}
                        >
                          <CheckCircle2 className="w-3 h-3 mr-1" /> VALID
                        </Button>
                        <Button
                          size="sm"
                          variant={f.validationStatus === "false_positive" ? "destructive" : "outline"}
                          className="h-6 text-[10px] font-mono"
                          onClick={() => validateMutation.mutate({
                            id: f.id,
                            validationStatus: f.validationStatus === "false_positive" ? "unvalidated" : "false_positive",
                          })}
                        >
                          <XCircle className="w-3 h-3 mr-1" /> FP
                        </Button>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {run.rawOutput && (
              <div>
                <h4 className="text-xs font-mono text-gray-400 mb-2 flex items-center gap-1.5">
                  <Terminal className="w-3 h-3" /> RAW OUTPUT
                </h4>
                <pre className="bg-black rounded p-3 text-[11px] font-mono text-green-400 max-h-60 overflow-auto border border-gray-700/30 whitespace-pre-wrap">
                  {run.rawOutput}
                </pre>
              </div>
            )}
          </CardContent>
        </Card>
      </div>
    );
  }

  return (
    <div className="space-y-4">
      {/* Stats Summary */}
      <div className="grid grid-cols-3 gap-3">
        <Card className="bg-[#0D1117] border-gray-700/50">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-mono text-white">{totalRuns}</div>
            <div className="text-[10px] font-mono text-gray-500 mt-1">TOTAL ATTACKS</div>
          </CardContent>
        </Card>
        <Card className="bg-[#0D1117] border-gray-700/50">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-mono text-green-400">{totalFindings}</div>
            <div className="text-[10px] font-mono text-gray-500 mt-1">CREDENTIALS FOUND</div>
          </CardContent>
        </Card>
        <Card className="bg-[#0D1117] border-gray-700/50">
          <CardContent className="p-4 text-center">
            <div className="text-2xl font-mono text-amber-400">{totalValidated}</div>
            <div className="text-[10px] font-mono text-gray-500 mt-1">VALIDATED</div>
          </CardContent>
        </Card>
      </div>

      {/* Tool breakdown */}
      {stats && stats.runs.length > 0 && (
        <div className="grid grid-cols-4 gap-2">
          {stats.runs.map((r: any) => (
            <div key={r.tool ?? "unknown"} className={`rounded p-2 border text-center ${toolColors[r.tool ?? "builtin"] ?? "text-gray-400 bg-gray-400/10 border-gray-400/30"}`}>
              <div className="text-xs font-mono font-bold">{(r.tool ?? "builtin").toUpperCase()}</div>
              <div className="text-lg font-mono">{Number(r.totalRuns)}</div>
              <div className="text-[10px] font-mono opacity-70">{Number(r.totalSuccessful ?? 0)} hits</div>
            </div>
          ))}
        </div>
      )}

      {/* Filters */}
      <div className="flex gap-2">
        <Select value={toolFilter} onValueChange={setToolFilter}>
          <SelectTrigger className="w-36 h-8 text-xs font-mono bg-[#0D1117] border-gray-700/50">
            <SelectValue placeholder="Tool" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">ALL TOOLS</SelectItem>
            <SelectItem value="builtin">BUILT-IN</SelectItem>
            <SelectItem value="hydra">HYDRA</SelectItem>
            <SelectItem value="medusa">MEDUSA</SelectItem>
            <SelectItem value="netexec">NETEXEC</SelectItem>
          </SelectContent>
        </Select>
        <Select value={protocolFilter} onValueChange={setProtocolFilter}>
          <SelectTrigger className="w-36 h-8 text-xs font-mono bg-[#0D1117] border-gray-700/50">
            <SelectValue placeholder="Protocol" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">ALL PROTOCOLS</SelectItem>
            <SelectItem value="ssh">SSH</SelectItem>
            <SelectItem value="ftp">FTP</SelectItem>
            <SelectItem value="http">HTTP</SelectItem>
            <SelectItem value="smb">SMB</SelectItem>
            <SelectItem value="rdp">RDP</SelectItem>
            <SelectItem value="mysql">MySQL</SelectItem>
            <SelectItem value="mssql">MSSQL</SelectItem>
          </SelectContent>
        </Select>
        <Select value={statusFilter} onValueChange={setStatusFilter}>
          <SelectTrigger className="w-36 h-8 text-xs font-mono bg-[#0D1117] border-gray-700/50">
            <SelectValue placeholder="Status" />
          </SelectTrigger>
          <SelectContent>
            <SelectItem value="all">ALL STATUS</SelectItem>
            <SelectItem value="completed">COMPLETED</SelectItem>
            <SelectItem value="running">RUNNING</SelectItem>
            <SelectItem value="stopped">STOPPED</SelectItem>
            <SelectItem value="error">ERROR</SelectItem>
          </SelectContent>
        </Select>
        <Button variant="outline" size="sm" className="h-8 text-xs font-mono" onClick={() => historyQuery.refetch()}>
          <RefreshCw className="w-3 h-3 mr-1" /> REFRESH
        </Button>
      </div>

      {/* Attack History Table */}
      {historyQuery.isLoading ? (
        <div className="flex items-center justify-center py-12">
          <Loader2 className="w-6 h-6 animate-spin text-gray-500" />
        </div>
      ) : historyQuery.data && historyQuery.data.runs.length > 0 ? (
        <div className="space-y-2">
          {historyQuery.data.runs.map((run: any) => (
            <Card
              key={run.id}
              className="bg-[#0D1117] border-gray-700/50 hover:border-gray-600/50 cursor-pointer transition-colors"
              onClick={() => setSelectedRunId(run.id)}
            >
              <CardContent className="p-3 flex items-center justify-between">
                <div className="flex items-center gap-3">
                  <Badge className={`font-mono text-[10px] ${toolColors[run.tool ?? "builtin"] ?? ""}`}>
                    {(run.tool ?? "builtin").toUpperCase()}
                  </Badge>
                  <div>
                    <div className="font-mono text-sm text-white">
                      {run.protocol?.toUpperCase()}://{run.targetHost}:{run.targetPort}
                    </div>
                    <div className="text-[10px] font-mono text-gray-500">
                      {run.attackMode?.replace("_", " ").toUpperCase()} • {run.totalAttempts ?? 0} attempts • {run.successfulAttempts ?? 0} hits
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-3">
                  <Badge className={`font-mono text-[10px] ${statusColors[run.status] ?? ""}`}>
                    {run.status?.toUpperCase()}
                  </Badge>
                  {run.durationMs && (
                    <span className="text-[10px] font-mono text-gray-500">{(run.durationMs / 1000).toFixed(1)}s</span>
                  )}
                  <span className="text-[10px] font-mono text-gray-600">
                    {run.createdAt ? new Date(run.createdAt).toLocaleString() : "—"}
                  </span>
                  <ChevronRight className="w-4 h-4 text-gray-600" />
                </div>
              </CardContent>
            </Card>
          ))}
          {historyQuery.data.total > 50 && (
            <div className="text-center text-xs font-mono text-gray-500 py-2">
              Showing 50 of {historyQuery.data.total} results
            </div>
          )}
        </div>
      ) : (
        <Card className="bg-[#0D1117] border-gray-700/50">
          <CardContent className="py-12 text-center">
            <Database className="w-8 h-8 text-gray-600 mx-auto mb-3" />
            <p className="text-sm font-mono text-gray-500">No attack history yet</p>
            <p className="text-xs text-gray-600 mt-1">
              Attack results will be automatically saved here after each credential attack
            </p>
          </CardContent>
        </Card>
      )}
    </div>
  );
}
