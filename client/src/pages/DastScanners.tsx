import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle } from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { Progress } from "@/components/ui/progress";
import { Separator } from "@/components/ui/separator";
import { ScrollArea } from "@/components/ui/scroll-area";
import {
  Loader2, Play, Target, Shield, Bug, AlertTriangle,
  BarChart3, Clock, CheckCircle2, XCircle, FileText,
  Activity, KeyRound, Globe, Server, Lock, Unlock,
  Wifi, Terminal, FolderOpen, Eye, Zap, Search,
  ChevronDown, ChevronRight, ExternalLink
} from "lucide-react";
import AppShell from "@/components/AppShell";

// ─── Constants ──────────────────────────────────────────────────────────────

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-purple-500/20 text-purple-400 border-purple-500/30",
  high: "bg-red-500/20 text-red-400 border-red-500/30",
  medium: "bg-amber-500/20 text-amber-400 border-amber-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  info: "bg-gray-500/20 text-gray-400 border-gray-500/30",
};

const SCANNER_ICONS: Record<string, React.ReactNode> = {
  nikto: <Search className="w-5 h-5" />,
  wapiti: <Bug className="w-5 h-5" />,
  arachni: <Globe className="w-5 h-5" />,
  "ssh-audit": <Terminal className="w-5 h-5" />,
  "ftp-audit": <FolderOpen className="w-5 h-5" />,
};

const SCANNER_COLORS: Record<string, string> = {
  nikto: "text-cyan-400",
  wapiti: "text-emerald-400",
  arachni: "text-violet-400",
  "ssh-audit": "text-amber-400",
  "ftp-audit": "text-rose-400",
};

// ─── Severity Badge ─────────────────────────────────────────────────────────

function SeverityBadge({ severity }: { severity: string }) {
  return (
    <Badge variant="outline" className={`text-xs ${SEVERITY_COLORS[severity] || SEVERITY_COLORS.info}`}>
      {severity.toUpperCase()}
    </Badge>
  );
}

// ─── Severity Bar Chart ─────────────────────────────────────────────────────

function SeverityBar({ summary }: { summary: Record<string, number> }) {
  const total = Object.values(summary).reduce((a, b) => a + b, 0);
  if (total === 0) return <span className="text-xs text-muted-foreground">No findings</span>;

  return (
    <div className="flex items-center gap-1 h-3 w-full max-w-[200px]">
      {["critical", "high", "medium", "low", "info"].map(sev => {
        const count = summary[sev] || 0;
        if (count === 0) return null;
        const pct = (count / total) * 100;
        const colors: Record<string, string> = {
          critical: "bg-purple-500",
          high: "bg-red-500",
          medium: "bg-amber-500",
          low: "bg-blue-500",
          info: "bg-gray-500",
        };
        return (
          <div
            key={sev}
            className={`h-full rounded-sm ${colors[sev]}`}
            style={{ width: `${Math.max(pct, 4)}%` }}
            title={`${sev}: ${count}`}
          />
        );
      })}
    </div>
  );
}

// ─── Scanner Launch Dialogs ─────────────────────────────────────────────────

function NiktoLaunchDialog({ open, onClose, engagementId }: { open: boolean; onClose: () => void; engagementId: number }) {
  const [targetUrl, setTargetUrl] = useState("");
  const [ssl, setSsl] = useState(false);
  const [port, setPort] = useState("");
  const [tuning, setTuning] = useState("12345");
  const [timeout, setTimeout] = useState("300");

  const startScan = trpc.dastScanners.startNikto.useMutation({
    onSuccess: (data: any) => {
      toast.success(`Nikto scan started (${data.findings?.length || 0} findings so far)`);
      onClose();
    },
    onError: (e) => toast.error(`Nikto scan failed: ${e.message}`),
  });

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Search className="w-5 h-5 text-cyan-400" /> Launch Nikto Scan
          </DialogTitle>
          <DialogDescription>Web server scanner — 6,700+ vulnerability checks</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label>Target URL</Label>
            <Input placeholder="https://target.com" value={targetUrl} onChange={e => setTargetUrl(e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Port (optional)</Label>
              <Input placeholder="80" value={port} onChange={e => setPort(e.target.value)} />
            </div>
            <div>
              <Label>Timeout (seconds)</Label>
              <Input value={timeout} onChange={e => setTimeout(e.target.value)} />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Tuning</Label>
              <Select value={tuning} onValueChange={setTuning}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="1234">Quick (1234)</SelectItem>
                  <SelectItem value="12345">Standard (12345)</SelectItem>
                  <SelectItem value="123456789">Deep (123456789)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div className="flex items-center gap-2 pt-6">
              <Switch checked={ssl} onCheckedChange={setSsl} />
              <Label>Force SSL</Label>
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button
            onClick={() => startScan.mutate({
              targetUrl,
              engagementId,
              ssl,
              port: port ? parseInt(port) : undefined,
              tuning,
              timeoutSeconds: parseInt(timeout) || 300,
            })}
            disabled={!targetUrl || startScan.isPending}
          >
            {startScan.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Play className="w-4 h-4 mr-2" />}
            Start Scan
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function WapitiLaunchDialog({ open, onClose, engagementId }: { open: boolean; onClose: () => void; engagementId: number }) {
  const [targetUrl, setTargetUrl] = useState("");
  const [scope, setScope] = useState<string>("folder");
  const [modules, setModules] = useState("");
  const [maxDepth, setMaxDepth] = useState("5");
  const [timeout, setTimeout] = useState("300");

  const startScan = trpc.dastScanners.startWapiti.useMutation({
    onSuccess: (data: any) => {
      toast.success(`Wapiti scan started (${data.findings?.length || 0} findings)`);
      onClose();
    },
    onError: (e) => toast.error(`Wapiti scan failed: ${e.message}`),
  });

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Bug className="w-5 h-5 text-emerald-400" /> Launch Wapiti Scan
          </DialogTitle>
          <DialogDescription>Black-box injection tester — SQL, XSS, XXE, SSRF, command execution</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label>Target URL</Label>
            <Input placeholder="https://target.com" value={targetUrl} onChange={e => setTargetUrl(e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Scope</Label>
              <Select value={scope} onValueChange={setScope}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="page">Page</SelectItem>
                  <SelectItem value="folder">Folder</SelectItem>
                  <SelectItem value="domain">Domain</SelectItem>
                  <SelectItem value="punk">Punk (all)</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Max Depth</Label>
              <Input value={maxDepth} onChange={e => setMaxDepth(e.target.value)} />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Modules (comma-separated, empty=all)</Label>
              <Input placeholder="sql,xss,xxe,exec" value={modules} onChange={e => setModules(e.target.value)} />
            </div>
            <div>
              <Label>Timeout (seconds)</Label>
              <Input value={timeout} onChange={e => setTimeout(e.target.value)} />
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button
            onClick={() => startScan.mutate({
              targetUrl,
              engagementId,
              scope: scope as any,
              modules: modules || undefined,
              maxDepth: parseInt(maxDepth) || 5,
              timeoutSeconds: parseInt(timeout) || 300,
            })}
            disabled={!targetUrl || startScan.isPending}
          >
            {startScan.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Play className="w-4 h-4 mr-2" />}
            Start Scan
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function ArachniLaunchDialog({ open, onClose, engagementId }: { open: boolean; onClose: () => void; engagementId: number }) {
  const [targetUrl, setTargetUrl] = useState("");
  const [scope, setScope] = useState<string>("page");
  const [maxPages, setMaxPages] = useState("100");
  const [maxDepth, setMaxDepth] = useState("5");
  const [domChecks, setDomChecks] = useState(false);
  const [timeout, setTimeout] = useState("600");

  const startScan = trpc.dastScanners.startArachni.useMutation({
    onSuccess: (data: any) => {
      toast.success(`Arachni scan started (${data.findings?.length || 0} findings)`);
      onClose();
    },
    onError: (e) => toast.error(`Arachni scan failed: ${e.message}`),
  });

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Globe className="w-5 h-5 text-violet-400" /> Launch Arachni Scan
          </DialogTitle>
          <DialogDescription>Full-featured web app scanner with DOM analysis and proof-of-concept payloads</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label>Target URL</Label>
            <Input placeholder="https://target.com" value={targetUrl} onChange={e => setTargetUrl(e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Scope</Label>
              <Select value={scope} onValueChange={setScope}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="page">Page</SelectItem>
                  <SelectItem value="subdomain">Subdomain</SelectItem>
                  <SelectItem value="domain">Domain</SelectItem>
                  <SelectItem value="global">Global</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Max Pages</Label>
              <Input value={maxPages} onChange={e => setMaxPages(e.target.value)} />
            </div>
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Max Depth</Label>
              <Input value={maxDepth} onChange={e => setMaxDepth(e.target.value)} />
            </div>
            <div>
              <Label>Timeout (seconds)</Label>
              <Input value={timeout} onChange={e => setTimeout(e.target.value)} />
            </div>
          </div>
          <div className="flex items-center gap-2">
            <Switch checked={domChecks} onCheckedChange={setDomChecks} />
            <Label>Enable DOM-based checks (requires browser)</Label>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button
            onClick={() => startScan.mutate({
              targetUrl,
              engagementId,
              scope: scope as any,
              maxPages: parseInt(maxPages) || 100,
              maxDepth: parseInt(maxDepth) || 5,
              domChecks,
              timeoutSeconds: parseInt(timeout) || 600,
            })}
            disabled={!targetUrl || startScan.isPending}
          >
            {startScan.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Play className="w-4 h-4 mr-2" />}
            Start Scan
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function SSHAuditLaunchDialog({ open, onClose, engagementId }: { open: boolean; onClose: () => void; engagementId: number }) {
  const [host, setHost] = useState("");
  const [port, setPort] = useState("22");
  const [nmapScripts, setNmapScripts] = useState(true);
  const [enumAuth, setEnumAuth] = useState(true);
  const [timeout, setTimeout] = useState("60");

  const startScan = trpc.dastScanners.startSSHAudit.useMutation({
    onSuccess: (data: any) => {
      toast.success(`SSH audit complete: ${data.findings?.length || 0} findings, ${data.stats?.weakAlgorithms || 0} weak algorithms`);
      onClose();
    },
    onError: (e) => toast.error(`SSH audit failed: ${e.message}`),
  });

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Terminal className="w-5 h-5 text-amber-400" /> Launch SSH Audit
          </DialogTitle>
          <DialogDescription>SSH algorithm strength, CVE detection, and authentication method enumeration</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label>Host (IP or hostname)</Label>
            <Input placeholder="192.168.1.1 or target.com" value={host} onChange={e => setHost(e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Port</Label>
              <Input value={port} onChange={e => setPort(e.target.value)} />
            </div>
            <div>
              <Label>Timeout (seconds)</Label>
              <Input value={timeout} onChange={e => setTimeout(e.target.value)} />
            </div>
          </div>
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Switch checked={nmapScripts} onCheckedChange={setNmapScripts} />
              <Label>Run nmap SSH NSE scripts</Label>
            </div>
            <div className="flex items-center gap-2">
              <Switch checked={enumAuth} onCheckedChange={setEnumAuth} />
              <Label>Enumerate authentication methods</Label>
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button
            onClick={() => startScan.mutate({
              host,
              port: parseInt(port) || 22,
              engagementId,
              nmapScripts,
              enumAuth,
              timeoutSeconds: parseInt(timeout) || 60,
            })}
            disabled={!host || startScan.isPending}
          >
            {startScan.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Play className="w-4 h-4 mr-2" />}
            Start Audit
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

function FTPAuditLaunchDialog({ open, onClose, engagementId }: { open: boolean; onClose: () => void; engagementId: number }) {
  const [host, setHost] = useState("");
  const [port, setPort] = useState("21");
  const [testAnonymous, setTestAnonymous] = useState(true);
  const [testDefaultCreds, setTestDefaultCreds] = useState(true);
  const [testBounce, setTestBounce] = useState(true);
  const [timeout, setTimeout] = useState("60");

  const startScan = trpc.dastScanners.startFTPAudit.useMutation({
    onSuccess: (data: any) => {
      toast.success(`FTP audit complete: ${data.findings?.length || 0} findings${data.anonymousAccess ? " — ANONYMOUS ACCESS DETECTED" : ""}`);
      onClose();
    },
    onError: (e) => toast.error(`FTP audit failed: ${e.message}`),
  });

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-lg">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <FolderOpen className="w-5 h-5 text-rose-400" /> Launch FTP Audit
          </DialogTitle>
          <DialogDescription>FTP anonymous access, bounce attacks, default credentials, and CVE detection</DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label>Host (IP or hostname)</Label>
            <Input placeholder="192.168.1.1 or ftp.target.com" value={host} onChange={e => setHost(e.target.value)} />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Port</Label>
              <Input value={port} onChange={e => setPort(e.target.value)} />
            </div>
            <div>
              <Label>Timeout (seconds)</Label>
              <Input value={timeout} onChange={e => setTimeout(e.target.value)} />
            </div>
          </div>
          <div className="space-y-2">
            <div className="flex items-center gap-2">
              <Switch checked={testAnonymous} onCheckedChange={setTestAnonymous} />
              <Label>Test anonymous login</Label>
            </div>
            <div className="flex items-center gap-2">
              <Switch checked={testDefaultCreds} onCheckedChange={setTestDefaultCreds} />
              <Label>Test default credentials</Label>
            </div>
            <div className="flex items-center gap-2">
              <Switch checked={testBounce} onCheckedChange={setTestBounce} />
              <Label>Test FTP bounce attack</Label>
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button
            onClick={() => startScan.mutate({
              host,
              port: parseInt(port) || 21,
              engagementId,
              testAnonymous,
              testDefaultCreds,
              testBounce,
              timeoutSeconds: parseInt(timeout) || 60,
            })}
            disabled={!host || startScan.isPending}
          >
            {startScan.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Play className="w-4 h-4 mr-2" />}
            Start Audit
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Service Audit Pipeline Dialog ──────────────────────────────────────────

function PipelineLaunchDialog({ open, onClose, engagementId }: { open: boolean; onClose: () => void; engagementId: number }) {
  const [servicesText, setServicesText] = useState("");
  const [profile, setProfile] = useState<string>("standard");
  const [enableSSH, setEnableSSH] = useState(true);
  const [enableFTP, setEnableFTP] = useState(true);
  const [enableNikto, setEnableNikto] = useState(true);
  const [enableWapiti, setEnableWapiti] = useState(true);
  const [enableArachni, setEnableArachni] = useState(false);

  const runPipeline = trpc.dastScanners.runServiceAuditPipeline.useMutation({
    onSuccess: (data: any) => {
      toast.success(`Pipeline complete: ${data.auditsCompleted}/${data.auditsTriggered} audits, ${data.totalFindings} findings`);
      onClose();
    },
    onError: (e) => toast.error(`Pipeline failed: ${e.message}`),
  });

  const parseServices = () => {
    return servicesText.split("\n").filter(l => l.trim()).map(line => {
      const parts = line.trim().split(/[\s,]+/);
      return {
        host: parts[0] || "",
        port: parseInt(parts[1]) || 80,
        service: parts[2] || "http",
        banner: parts.slice(3).join(" ") || undefined,
      };
    });
  };

  return (
    <Dialog open={open} onOpenChange={onClose}>
      <DialogContent className="max-w-2xl">
        <DialogHeader>
          <DialogTitle className="flex items-center gap-2">
            <Zap className="w-5 h-5 text-yellow-400" /> Service Audit Pipeline
          </DialogTitle>
          <DialogDescription>
            Auto-map discovered services to appropriate scanners. Paste port discovery output below.
          </DialogDescription>
        </DialogHeader>
        <div className="space-y-4">
          <div>
            <Label>Discovered Services (one per line: host port service [banner])</Label>
            <textarea
              className="w-full h-32 bg-muted/50 border border-border rounded-md p-3 text-sm font-mono"
              placeholder={"192.168.1.1 22 ssh OpenSSH_8.9\n192.168.1.1 21 ftp vsftpd 3.0.5\n192.168.1.1 80 http Apache\n192.168.1.1 443 https nginx"}
              value={servicesText}
              onChange={e => setServicesText(e.target.value)}
            />
          </div>
          <div className="grid grid-cols-2 gap-4">
            <div>
              <Label>Scan Profile</Label>
              <Select value={profile} onValueChange={setProfile}>
                <SelectTrigger><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="quick">Quick (fast, surface-level)</SelectItem>
                  <SelectItem value="standard">Standard (balanced)</SelectItem>
                  <SelectItem value="deep">Deep (thorough, slow)</SelectItem>
                </SelectContent>
              </Select>
            </div>
          </div>
          <div>
            <Label className="text-xs text-muted-foreground mb-2 block">Enabled Scanners</Label>
            <div className="grid grid-cols-2 gap-2">
              <div className="flex items-center gap-2">
                <Switch checked={enableSSH} onCheckedChange={setEnableSSH} />
                <Label className="text-sm">SSH Audit</Label>
              </div>
              <div className="flex items-center gap-2">
                <Switch checked={enableFTP} onCheckedChange={setEnableFTP} />
                <Label className="text-sm">FTP Audit</Label>
              </div>
              <div className="flex items-center gap-2">
                <Switch checked={enableNikto} onCheckedChange={setEnableNikto} />
                <Label className="text-sm">Nikto</Label>
              </div>
              <div className="flex items-center gap-2">
                <Switch checked={enableWapiti} onCheckedChange={setEnableWapiti} />
                <Label className="text-sm">Wapiti</Label>
              </div>
              <div className="flex items-center gap-2">
                <Switch checked={enableArachni} onCheckedChange={setEnableArachni} />
                <Label className="text-sm">Arachni (heavy)</Label>
              </div>
            </div>
          </div>
        </div>
        <DialogFooter>
          <Button variant="outline" onClick={onClose}>Cancel</Button>
          <Button
            onClick={() => {
              const services = parseServices();
              if (services.length === 0) { toast.error("No services parsed"); return; }
              runPipeline.mutate({
                services,
                engagementId,
                profile: profile as any,
                enabledScanners: {
                  ssh: enableSSH,
                  ftp: enableFTP,
                  nikto: enableNikto,
                  wapiti: enableWapiti,
                  arachni: enableArachni,
                },
              });
            }}
            disabled={!servicesText.trim() || runPipeline.isPending}
          >
            {runPipeline.isPending ? <Loader2 className="w-4 h-4 animate-spin mr-2" /> : <Zap className="w-4 h-4 mr-2" />}
            Run Pipeline
          </Button>
        </DialogFooter>
      </DialogContent>
    </Dialog>
  );
}

// ─── Result Detail View ─────────────────────────────────────────────────────

function ScanResultDetail({ scanId, onClose }: { scanId: number; onClose: () => void }) {
  const { data, isLoading } = trpc.dastScanners.getResultDetail.useQuery({ scanId });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center p-12">
        <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
      </div>
    );
  }

  if (!data) return <p className="text-muted-foreground p-4">Result not found</p>;

  const findings = data.findings;
  const allFindings = Array.isArray(findings)
    ? findings
    : [...(findings?.vulnerabilities || []), ...(findings?.findings || []), ...(findings?.anomalies || []), ...(findings?.infos || [])];

  return (
    <div className="space-y-4">
      <div className="flex items-center justify-between">
        <div>
          <h3 className="text-lg font-semibold flex items-center gap-2">
            <span className={SCANNER_COLORS[data.tool] || ""}>{SCANNER_ICONS[data.tool]}</span>
            {data.tool.toUpperCase()} — {data.target}
          </h3>
          <p className="text-sm text-muted-foreground">
            {data.findingCount} findings | {((data.durationMs || 0) / 1000).toFixed(1)}s | Exit code: {data.exitCode}
          </p>
        </div>
        <Button variant="outline" size="sm" onClick={onClose}>Close</Button>
      </div>

      <Separator />

      {/* Severity summary */}
      <div className="grid grid-cols-5 gap-2">
        {["critical", "high", "medium", "low", "info"].map(sev => {
          const count = data.severitySummary?.[sev] || 0;
          return (
            <Card key={sev} className="bg-muted/30">
              <CardContent className="p-3 text-center">
                <p className="text-2xl font-bold">{count}</p>
                <SeverityBadge severity={sev} />
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Findings list */}
      <ScrollArea className="h-[400px]">
        <div className="space-y-2">
          {allFindings.map((finding: any, i: number) => (
            <Card key={finding.id || i} className="bg-muted/20">
              <CardContent className="p-3">
                <div className="flex items-start justify-between gap-2">
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 mb-1">
                      <SeverityBadge severity={finding.severity || "info"} />
                      <span className="text-sm font-medium truncate">
                        {finding.title || finding.name || finding.description?.slice(0, 80) || "Finding"}
                      </span>
                    </div>
                    <p className="text-xs text-muted-foreground line-clamp-2">
                      {finding.description || finding.info || ""}
                    </p>
                    {(finding.cve || finding.cweId || finding.cwe) && (
                      <div className="flex gap-1 mt-1">
                        {finding.cve && <Badge variant="outline" className="text-[10px]">{finding.cve}</Badge>}
                        {(finding.cweId || finding.cwe) && <Badge variant="outline" className="text-[10px]">{finding.cweId || finding.cwe}</Badge>}
                      </div>
                    )}
                    {finding.recommendation && (
                      <p className="text-xs text-blue-400 mt-1">Fix: {finding.recommendation.slice(0, 120)}</p>
                    )}
                  </div>
                  {finding.path && (
                    <code className="text-[10px] text-muted-foreground bg-muted/50 px-1.5 py-0.5 rounded shrink-0 max-w-[200px] truncate">
                      {finding.method || "GET"} {finding.path || finding.url || ""}
                    </code>
                  )}
                </div>
              </CardContent>
            </Card>
          ))}
          {allFindings.length === 0 && (
            <p className="text-center text-muted-foreground py-8">No findings in this scan result</p>
          )}
        </div>
      </ScrollArea>

      {/* Raw output (collapsible) */}
      {data.rawOutput && (
        <details className="text-xs">
          <summary className="cursor-pointer text-muted-foreground hover:text-foreground">
            View raw output ({data.rawOutput.length.toLocaleString()} chars)
          </summary>
          <pre className="mt-2 bg-muted/30 p-3 rounded-md overflow-auto max-h-[200px] whitespace-pre-wrap font-mono text-[10px]">
            {data.rawOutput.slice(0, 10000)}
          </pre>
        </details>
      )}
    </div>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function DastScanners() {
  const [activeTab, setActiveTab] = useState("overview");
  const [engagementId, setEngagementId] = useState(1);
  const [showNikto, setShowNikto] = useState(false);
  const [showWapiti, setShowWapiti] = useState(false);
  const [showArachni, setShowArachni] = useState(false);
  const [showSSH, setShowSSH] = useState(false);
  const [showFTP, setShowFTP] = useState(false);
  const [showPipeline, setShowPipeline] = useState(false);
  const [selectedScanId, setSelectedScanId] = useState<number | null>(null);
  const [toolFilter, setToolFilter] = useState<string>("all");

  const scannersQuery = trpc.dastScanners.listScanners.useQuery();
  const resultsQuery = trpc.dastScanners.getResults.useQuery(
    { engagementId, tool: toolFilter === "all" ? undefined : toolFilter as any, limit: 50 },
    { refetchInterval: 10000 },
  );

  const scanners = scannersQuery.data || [];
  const results = resultsQuery.data || [];

  // Aggregate stats
  const stats = useMemo(() => {
    let totalFindings = 0;
    const severity = { critical: 0, high: 0, medium: 0, low: 0, info: 0 };
    const byTool: Record<string, number> = {};

    for (const r of results) {
      totalFindings += r.findingCount || 0;
      const sev = r.severitySummary || {};
      for (const [k, v] of Object.entries(sev)) {
        if (k in severity) severity[k as keyof typeof severity] += (v as number) || 0;
      }
      byTool[r.tool] = (byTool[r.tool] || 0) + 1;
    }

    return { totalFindings, severity, byTool, totalScans: results.length };
  }, [results]);

  return (
    <AppShell activePath="/dast-scanners">
      <div className="space-y-6 p-1">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-bold tracking-tight flex items-center gap-3">
              <Shield className="w-7 h-7 text-cyan-400" />
              DAST Scanners & Service Audits
            </h1>
            <p className="text-sm text-muted-foreground mt-1">
              Dynamic Application Security Testing — Nikto, Wapiti, Arachni web scanners plus SSH and FTP service auditing with auto-follow-up pipeline
            </p>
          </div>
          <div className="flex items-center gap-2">
            <div className="flex items-center gap-2">
              <Label className="text-xs text-muted-foreground">Engagement:</Label>
              <Input
                className="w-20 h-8 text-xs"
                type="number"
                value={engagementId}
                onChange={e => setEngagementId(parseInt(e.target.value) || 1)}
              />
            </div>
            <Button variant="outline" size="sm" onClick={() => setShowPipeline(true)}>
              <Zap className="w-4 h-4 mr-1" /> Auto Pipeline
            </Button>
          </div>
        </div>

        {/* Stats Cards */}
        <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-6 gap-3">
          <Card className="bg-muted/30">
            <CardContent className="p-3 text-center">
              <p className="text-2xl font-bold">{stats.totalScans}</p>
              <p className="text-xs text-muted-foreground">Total Scans</p>
            </CardContent>
          </Card>
          <Card className="bg-muted/30">
            <CardContent className="p-3 text-center">
              <p className="text-2xl font-bold">{stats.totalFindings}</p>
              <p className="text-xs text-muted-foreground">Total Findings</p>
            </CardContent>
          </Card>
          <Card className="bg-purple-500/10 border-purple-500/20">
            <CardContent className="p-3 text-center">
              <p className="text-2xl font-bold text-purple-400">{stats.severity.critical}</p>
              <p className="text-xs text-purple-400/70">Critical</p>
            </CardContent>
          </Card>
          <Card className="bg-red-500/10 border-red-500/20">
            <CardContent className="p-3 text-center">
              <p className="text-2xl font-bold text-red-400">{stats.severity.high}</p>
              <p className="text-xs text-red-400/70">High</p>
            </CardContent>
          </Card>
          <Card className="bg-amber-500/10 border-amber-500/20">
            <CardContent className="p-3 text-center">
              <p className="text-2xl font-bold text-amber-400">{stats.severity.medium}</p>
              <p className="text-xs text-amber-400/70">Medium</p>
            </CardContent>
          </Card>
          <Card className="bg-blue-500/10 border-blue-500/20">
            <CardContent className="p-3 text-center">
              <p className="text-2xl font-bold text-blue-400">{stats.severity.low}</p>
              <p className="text-xs text-blue-400/70">Low</p>
            </CardContent>
          </Card>
        </div>

        <Tabs value={activeTab} onValueChange={setActiveTab}>
          <TabsList>
            <TabsTrigger value="overview">Scanner Overview</TabsTrigger>
            <TabsTrigger value="results">Scan Results ({results.length})</TabsTrigger>
          </TabsList>

          {/* ─── Overview Tab ──────────────────────────────────────────────── */}
          <TabsContent value="overview" className="space-y-4">
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
              {/* DAST Web Scanners */}
              <Card className="border-cyan-500/20">
                <CardHeader className="pb-3">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Search className="w-5 h-5 text-cyan-400" /> Nikto
                  </CardTitle>
                  <CardDescription>Web server scanner — 6,700+ checks for dangerous files, outdated versions, server misconfigurations</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center justify-between">
                    <div className="flex gap-1">
                      <Badge variant="outline" className="text-[10px]">Fast</Badge>
                      <Badge variant="outline" className="text-[10px]">Surface</Badge>
                    </div>
                    <Button size="sm" onClick={() => setShowNikto(true)}>
                      <Play className="w-3 h-3 mr-1" /> Launch
                    </Button>
                  </div>
                  {stats.byTool["nikto"] && (
                    <p className="text-xs text-muted-foreground mt-2">{stats.byTool["nikto"]} scan(s) completed</p>
                  )}
                </CardContent>
              </Card>

              <Card className="border-emerald-500/20">
                <CardHeader className="pb-3">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Bug className="w-5 h-5 text-emerald-400" /> Wapiti
                  </CardTitle>
                  <CardDescription>Black-box injection tester — SQL, XSS, XXE, SSRF, command execution, file inclusion</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center justify-between">
                    <div className="flex gap-1">
                      <Badge variant="outline" className="text-[10px]">Medium</Badge>
                      <Badge variant="outline" className="text-[10px]">Deep</Badge>
                    </div>
                    <Button size="sm" onClick={() => setShowWapiti(true)}>
                      <Play className="w-3 h-3 mr-1" /> Launch
                    </Button>
                  </div>
                  {stats.byTool["wapiti"] && (
                    <p className="text-xs text-muted-foreground mt-2">{stats.byTool["wapiti"]} scan(s) completed</p>
                  )}
                </CardContent>
              </Card>

              <Card className="border-violet-500/20">
                <CardHeader className="pb-3">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Globe className="w-5 h-5 text-violet-400" /> Arachni
                  </CardTitle>
                  <CardDescription>Full-featured web app scanner — DOM analysis, intelligent crawling, proof-of-concept payloads</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center justify-between">
                    <div className="flex gap-1">
                      <Badge variant="outline" className="text-[10px]">Slow</Badge>
                      <Badge variant="outline" className="text-[10px]">Comprehensive</Badge>
                    </div>
                    <Button size="sm" onClick={() => setShowArachni(true)}>
                      <Play className="w-3 h-3 mr-1" /> Launch
                    </Button>
                  </div>
                  {stats.byTool["arachni"] && (
                    <p className="text-xs text-muted-foreground mt-2">{stats.byTool["arachni"]} scan(s) completed</p>
                  )}
                </CardContent>
              </Card>

              {/* Service Auditors */}
              <Card className="border-amber-500/20">
                <CardHeader className="pb-3">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Terminal className="w-5 h-5 text-amber-400" /> SSH Audit
                  </CardTitle>
                  <CardDescription>SSH algorithm strength, CVE detection (regreSSHion, Terrapin), auth method enumeration, banner analysis</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center justify-between">
                    <div className="flex gap-1">
                      <Badge variant="outline" className="text-[10px]">Fast</Badge>
                      <Badge variant="outline" className="text-[10px]">Port 22</Badge>
                    </div>
                    <Button size="sm" onClick={() => setShowSSH(true)}>
                      <Play className="w-3 h-3 mr-1" /> Launch
                    </Button>
                  </div>
                  {stats.byTool["ssh-audit"] && (
                    <p className="text-xs text-muted-foreground mt-2">{stats.byTool["ssh-audit"]} audit(s) completed</p>
                  )}
                </CardContent>
              </Card>

              <Card className="border-rose-500/20">
                <CardHeader className="pb-3">
                  <CardTitle className="text-base flex items-center gap-2">
                    <FolderOpen className="w-5 h-5 text-rose-400" /> FTP Audit
                  </CardTitle>
                  <CardDescription>Anonymous access, bounce attacks, default credentials, version CVEs, TLS detection, sensitive file exposure</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center justify-between">
                    <div className="flex gap-1">
                      <Badge variant="outline" className="text-[10px]">Fast</Badge>
                      <Badge variant="outline" className="text-[10px]">Port 21</Badge>
                    </div>
                    <Button size="sm" onClick={() => setShowFTP(true)}>
                      <Play className="w-3 h-3 mr-1" /> Launch
                    </Button>
                  </div>
                  {stats.byTool["ftp-audit"] && (
                    <p className="text-xs text-muted-foreground mt-2">{stats.byTool["ftp-audit"]} audit(s) completed</p>
                  )}
                </CardContent>
              </Card>

              {/* Pipeline Card */}
              <Card className="border-yellow-500/20 bg-yellow-500/5">
                <CardHeader className="pb-3">
                  <CardTitle className="text-base flex items-center gap-2">
                    <Zap className="w-5 h-5 text-yellow-400" /> Auto Pipeline
                  </CardTitle>
                  <CardDescription>Paste port discovery results — automatically maps services to scanners and runs them in parallel</CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="flex items-center justify-between">
                    <div className="flex gap-1">
                      <Badge variant="outline" className="text-[10px]">Automated</Badge>
                      <Badge variant="outline" className="text-[10px]">Multi-tool</Badge>
                    </div>
                    <Button size="sm" variant="outline" className="border-yellow-500/30" onClick={() => setShowPipeline(true)}>
                      <Zap className="w-3 h-3 mr-1" /> Configure
                    </Button>
                  </div>
                </CardContent>
              </Card>
            </div>

            {/* How it works */}
            <Card className="bg-muted/20">
              <CardHeader>
                <CardTitle className="text-sm">Service Auto-Follow-Up Pipeline</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="flex items-center gap-2 text-xs text-muted-foreground flex-wrap">
                  <Badge variant="outline">Port Discovery (naabu/nmap)</Badge>
                  <ChevronRight className="w-3 h-3" />
                  <Badge variant="outline">Service Identification</Badge>
                  <ChevronRight className="w-3 h-3" />
                  <Badge variant="outline" className="border-amber-500/30 text-amber-400">Port 22 → SSH Audit</Badge>
                  <Badge variant="outline" className="border-rose-500/30 text-rose-400">Port 21 → FTP Audit</Badge>
                  <Badge variant="outline" className="border-cyan-500/30 text-cyan-400">Port 80/443 → Nikto + Wapiti</Badge>
                  <ChevronRight className="w-3 h-3" />
                  <Badge variant="outline">Findings Aggregated</Badge>
                </div>
              </CardContent>
            </Card>
          </TabsContent>

          {/* ─── Results Tab ───────────────────────────────────────────────── */}
          <TabsContent value="results" className="space-y-4">
            {selectedScanId ? (
              <ScanResultDetail scanId={selectedScanId} onClose={() => setSelectedScanId(null)} />
            ) : (
              <>
                <div className="flex items-center gap-2">
                  <Label className="text-xs text-muted-foreground">Filter by tool:</Label>
                  <Select value={toolFilter} onValueChange={setToolFilter}>
                    <SelectTrigger className="w-40 h-8 text-xs">
                      <SelectValue />
                    </SelectTrigger>
                    <SelectContent>
                      <SelectItem value="all">All Scanners</SelectItem>
                      <SelectItem value="nikto">Nikto</SelectItem>
                      <SelectItem value="wapiti">Wapiti</SelectItem>
                      <SelectItem value="arachni">Arachni</SelectItem>
                      <SelectItem value="ssh-audit">SSH Audit</SelectItem>
                      <SelectItem value="ftp-audit">FTP Audit</SelectItem>
                    </SelectContent>
                  </Select>
                  <Button variant="ghost" size="sm" onClick={() => resultsQuery.refetch()}>
                    <Activity className="w-3 h-3 mr-1" /> Refresh
                  </Button>
                </div>

                {resultsQuery.isLoading ? (
                  <div className="flex items-center justify-center p-12">
                    <Loader2 className="w-6 h-6 animate-spin text-muted-foreground" />
                  </div>
                ) : results.length === 0 ? (
                  <Card className="bg-muted/20">
                    <CardContent className="p-12 text-center">
                      <Shield className="w-12 h-12 text-muted-foreground/30 mx-auto mb-4" />
                      <p className="text-muted-foreground">No scan results yet. Launch a scanner or run the auto pipeline.</p>
                    </CardContent>
                  </Card>
                ) : (
                  <div className="space-y-2">
                    {results.map((result: any) => (
                      <Card
                        key={result.id}
                        className="bg-muted/20 hover:bg-muted/30 cursor-pointer transition-colors"
                        onClick={() => setSelectedScanId(result.id)}
                      >
                        <CardContent className="p-3">
                          <div className="flex items-center justify-between">
                            <div className="flex items-center gap-3">
                              <span className={SCANNER_COLORS[result.tool] || ""}>
                                {SCANNER_ICONS[result.tool] || <Shield className="w-5 h-5" />}
                              </span>
                              <div>
                                <p className="text-sm font-medium">
                                  {result.tool.toUpperCase()} — {result.target}
                                </p>
                                <p className="text-xs text-muted-foreground">
                                  {result.findingCount} findings | {((result.durationMs || 0) / 1000).toFixed(1)}s | {new Date(result.createdAt).toLocaleString()}
                                </p>
                              </div>
                            </div>
                            <div className="flex items-center gap-3">
                              <SeverityBar summary={result.severitySummary || {}} />
                              <ChevronRight className="w-4 h-4 text-muted-foreground" />
                            </div>
                          </div>
                        </CardContent>
                      </Card>
                    ))}
                  </div>
                )}
              </>
            )}
          </TabsContent>
        </Tabs>

        {/* Launch Dialogs */}
        <NiktoLaunchDialog open={showNikto} onClose={() => setShowNikto(false)} engagementId={engagementId} />
        <WapitiLaunchDialog open={showWapiti} onClose={() => setShowWapiti(false)} engagementId={engagementId} />
        <ArachniLaunchDialog open={showArachni} onClose={() => setShowArachni(false)} engagementId={engagementId} />
        <SSHAuditLaunchDialog open={showSSH} onClose={() => setShowSSH(false)} engagementId={engagementId} />
        <FTPAuditLaunchDialog open={showFTP} onClose={() => setShowFTP(false)} engagementId={engagementId} />
        <PipelineLaunchDialog open={showPipeline} onClose={() => setShowPipeline(false)} engagementId={engagementId} />
      </div>
    </AppShell>
  );
}
