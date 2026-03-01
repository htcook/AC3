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
            <TabsTrigger value="results" className="font-mono text-xs">
              RESULTS {attackResult && <Badge variant="outline" className="ml-1 text-[10px]">{attackResult.successfulLogins?.length || 0}</Badge>}
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
