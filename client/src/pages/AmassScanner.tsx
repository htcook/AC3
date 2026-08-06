import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { toast } from "sonner";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import {
  Dialog, DialogContent, DialogDescription, DialogFooter,
  DialogHeader, DialogTitle, DialogTrigger,
} from "@/components/ui/dialog";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Switch } from "@/components/ui/switch";
import {
  Select, SelectContent, SelectItem, SelectTrigger, SelectValue,
} from "@/components/ui/select";
import {
  Loader2, Globe, Play, Target, Search, Network, Clock,
  CheckCircle2, XCircle, BarChart3, Shield, RefreshCw,
  ArrowLeftRight, Server, Wifi, MapPin, Hash,
} from "lucide-react";
import AppShell from "@/components/AppShell";

const MODE_INFO: Record<string, { label: string; desc: string; icon: any; color: string }> = {
  passive: { label: "Passive", desc: "OSINT sources only — no target contact", icon: Search, color: "text-emerald-400" },
  active: { label: "Active", desc: "DNS resolution, cert grabbing, zone transfers", icon: Wifi, color: "text-blue-400" },
  brute: { label: "Brute Force", desc: "DNS brute-force with wordlists", icon: Hash, color: "text-amber-400" },
  full: { label: "Full", desc: "Active + brute-force combined", icon: Globe, color: "text-red-400" },
};

const INTEL_MODES: Record<string, { label: string; desc: string; placeholder: string }> = {
  org: { label: "Organization", desc: "Discover domains by organization name", placeholder: "e.g. Cloudflare Inc" },
  asn: { label: "ASN", desc: "Discover domains by Autonomous System Number", placeholder: "e.g. AS13335" },
  cidr: { label: "CIDR", desc: "Discover domains by IP range", placeholder: "e.g. 104.16.0.0/16" },
  whois: { label: "Reverse WHOIS", desc: "Discover domains by WHOIS registrant", placeholder: "e.g. admin@example.com" },
};

const STATUS_BADGE: Record<string, { label: string; variant: "default" | "secondary" | "destructive" | "outline" }> = {
  queued: { label: "Queued", variant: "outline" },
  running: { label: "Running", variant: "default" },
  completed: { label: "Completed", variant: "secondary" },
  failed: { label: "Failed", variant: "destructive" },
};

export default function AmassScanner() {
  const [activeTab, setActiveTab] = useState("enumerate");
  const [showNewScan, setShowNewScan] = useState(false);
  const [showIntel, setShowIntel] = useState(false);

  // Enumerate form
  const [domains, setDomains] = useState("");
  const [mode, setMode] = useState<"passive" | "active" | "brute" | "full">("passive");
  const [engagementId, setEngagementId] = useState("");
  const [serverHost, setServerHost] = useState("");
  const [serverUser, setServerUser] = useState("");
  const [useBuiltInWordlist, setUseBuiltInWordlist] = useState(true);
  const [timeoutMinutes, setTimeoutMinutes] = useState("30");
  const [noAlts, setNoAlts] = useState(false);
  const [noRecursive, setNoRecursive] = useState(false);
  const [showSources, setShowSources] = useState(true);

  // Intel form
  const [intelMode, setIntelMode] = useState<"org" | "asn" | "cidr" | "whois">("org");
  const [intelQuery, setIntelQuery] = useState("");

  // Result viewer
  const [selectedScanId, setSelectedScanId] = useState<string | null>(null);

  // Diff
  const [diffPrevId, setDiffPrevId] = useState("");
  const [diffCurrId, setDiffCurrId] = useState("");

  // Queries
  const engId = engagementId ? parseInt(engagementId) : 0;
  const historyInput = useMemo(() => ({ engagementId: engId }), [engId]);
  const history = trpc.amass.getScanHistory.useQuery(historyInput, {
    enabled: engId > 0,
    refetchInterval: 5000,
  });
  const resultInput = useMemo(() => ({ scanId: selectedScanId || "" }), [selectedScanId]);
  const scanResult = trpc.amass.getResult.useQuery(resultInput, {
    enabled: !!selectedScanId,
  });
  const diffInput = useMemo(() => ({ previousScanId: diffPrevId, currentScanId: diffCurrId }), [diffPrevId, diffCurrId]);
  const diffResult = trpc.amass.diff.useQuery(diffInput, {
    enabled: !!diffPrevId && !!diffCurrId,
  });
  const wordlist = trpc.amass.getBuiltInWordlist.useQuery(undefined, { enabled: false });

  // Mutations
  const enumerateMut = trpc.amass.enumerate.useMutation({
    onSuccess: (data) => {
      toast.success(`Amass ${mode} scan complete`, {
        description: `Found ${data.totalSubdomains} subdomains, ${data.totalUniqueIps} IPs in ${Math.round((data.durationMs || 0) / 1000)}s`,
      });
      setShowNewScan(false);
      if (data.scanId) setSelectedScanId(data.scanId);
      history.refetch();
    },
    onError: (err) => {
      toast.error("Scan failed", { description: err.message });
    },
  });

  const intelMut = trpc.amass.intel.useMutation({
    onSuccess: (data) => {
      toast.success(`Intel discovery complete`, {
        description: `Found ${data.domains?.length || 0} domains`,
      });
      setShowIntel(false);
    },
    onError: (err) => {
      toast.error("Intel failed", { description: err.message });
    },
  });

  const preflightMut = trpc.amass.preflight.useMutation({
    onSuccess: (data) => {
      if (data.installed) {
        toast.success("Amass preflight passed", { description: `Version: ${data.version}` });
      } else {
        toast.error("Amass not found", { description: data.error || "Install Amass on the scan server" });
      }
    },
    onError: (err) => {
      toast.error("Preflight check failed", { description: err.message });
    },
  });

  const handleEnumerate = () => {
    const domainList = domains.split(/[\n,]+/).map(d => d.trim()).filter(Boolean);
    if (domainList.length === 0) { toast.error("Enter at least one domain"); return; }
    if (!engagementId) { toast.error("Enter an engagement ID"); return; }
    if (!serverHost || !serverUser) { toast.error("Enter scan server details"); return; }

    enumerateMut.mutate({
      engagementId: parseInt(engagementId),
      domains: domainList,
      mode,
      server: { host: serverHost, username: serverUser },
      useBuiltInWordlist,
      timeoutMinutes: parseInt(timeoutMinutes),
      noAlts,
      noRecursive,
      showSources,
    });
  };

  const handleIntel = () => {
    if (!intelQuery.trim()) { toast.error("Enter a query"); return; }
    if (!serverHost || !serverUser) { toast.error("Enter scan server details"); return; }
    intelMut.mutate({
      intelMode,
      query: intelQuery.trim(),
      server: { host: serverHost, username: serverUser },
    });
  };

  return (
    <div className="space-y-6 p-1">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="p-2 bg-emerald-500/10 rounded-lg">
            <Globe className="h-7 w-7 text-emerald-400" />
          </div>
          <div>
            <h1 className="text-2xl font-bold tracking-tight">Amass Scanner</h1>
            <p className="text-sm text-muted-foreground">
              OWASP Amass subdomain enumeration &amp; attack surface mapping
            </p>
          </div>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => setShowIntel(true)} className="gap-2">
            <Search className="h-4 w-4" /> Intel Discovery
          </Button>
          <Button size="sm" onClick={() => setShowNewScan(true)} className="gap-2">
            <Play className="h-4 w-4" /> New Scan
          </Button>
        </div>
      </div>

      {/* Server Config */}
      <Card className="border-muted">
        <CardHeader className="pb-3">
          <CardTitle className="text-sm flex items-center gap-2">
            <Server className="h-4 w-4" /> Scan Server
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div>
              <Label className="text-xs">Host</Label>
              <Input
                placeholder="scan-server.example.com"
                value={serverHost}
                onChange={e => setServerHost(e.target.value)}
                className="h-8 text-sm"
              />
            </div>
            <div>
              <Label className="text-xs">Username</Label>
              <Input
                placeholder="root"
                value={serverUser}
                onChange={e => setServerUser(e.target.value)}
                className="h-8 text-sm"
              />
            </div>
            <div>
              <Label className="text-xs">Engagement ID</Label>
              <Input
                placeholder="1770048"
                value={engagementId}
                onChange={e => setEngagementId(e.target.value)}
                className="h-8 text-sm"
              />
            </div>
            <div className="flex items-end">
              <Button
                variant="outline"
                size="sm"
                className="w-full gap-2"
                onClick={() => {
                  if (!serverHost || !serverUser) { toast.error("Enter server details first"); return; }
                  preflightMut.mutate({ server: { host: serverHost, username: serverUser } });
                }}
                disabled={preflightMut.isPending}
              >
                {preflightMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Shield className="h-4 w-4" />}
                Preflight Check
              </Button>
            </div>
          </div>
        </CardContent>
      </Card>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="enumerate" className="gap-2">
            <Globe className="h-4 w-4" /> Enumerate
          </TabsTrigger>
          <TabsTrigger value="history" className="gap-2">
            <Clock className="h-4 w-4" /> History
          </TabsTrigger>
          <TabsTrigger value="results" className="gap-2">
            <BarChart3 className="h-4 w-4" /> Results
          </TabsTrigger>
          <TabsTrigger value="diff" className="gap-2">
            <ArrowLeftRight className="h-4 w-4" /> Diff
          </TabsTrigger>
        </TabsList>

        {/* Enumerate Tab */}
        <TabsContent value="enumerate" className="space-y-4">
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
            {Object.entries(MODE_INFO).map(([key, info]) => {
              const Icon = info.icon;
              return (
                <Card
                  key={key}
                  className={`cursor-pointer transition-all hover:border-primary/50 ${
                    mode === key ? "border-primary ring-1 ring-primary/30" : ""
                  }`}
                  onClick={() => setMode(key as any)}
                >
                  <CardContent className="p-4">
                    <div className="flex items-center gap-3 mb-2">
                      <Icon className={`h-5 w-5 ${info.color}`} />
                      <span className="font-medium">{info.label}</span>
                    </div>
                    <p className="text-xs text-muted-foreground">{info.desc}</p>
                  </CardContent>
                </Card>
              );
            })}
          </div>

          <Card>
            <CardContent className="p-4 space-y-4">
              <div>
                <Label>Target Domains</Label>
                <Input
                  placeholder="example.com, target.io (comma or newline separated)"
                  value={domains}
                  onChange={e => setDomains(e.target.value)}
                />
              </div>

              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <div className="flex items-center gap-2">
                  <Switch checked={useBuiltInWordlist} onCheckedChange={setUseBuiltInWordlist} />
                  <Label className="text-sm">Built-in Wordlist</Label>
                </div>
                <div className="flex items-center gap-2">
                  <Switch checked={showSources} onCheckedChange={setShowSources} />
                  <Label className="text-sm">Show Sources</Label>
                </div>
                <div className="flex items-center gap-2">
                  <Switch checked={noAlts} onCheckedChange={setNoAlts} />
                  <Label className="text-sm">No Alterations</Label>
                </div>
                <div className="flex items-center gap-2">
                  <Switch checked={noRecursive} onCheckedChange={setNoRecursive} />
                  <Label className="text-sm">No Recursive</Label>
                </div>
              </div>

              <div className="flex items-center gap-4">
                <div>
                  <Label className="text-xs">Timeout (min)</Label>
                  <Input
                    type="number"
                    value={timeoutMinutes}
                    onChange={e => setTimeoutMinutes(e.target.value)}
                    className="w-24 h-8 text-sm"
                  />
                </div>
                <div className="flex-1" />
                <Button
                  onClick={handleEnumerate}
                  disabled={enumerateMut.isPending}
                  className="gap-2"
                >
                  {enumerateMut.isPending ? (
                    <Loader2 className="h-4 w-4 animate-spin" />
                  ) : (
                    <Play className="h-4 w-4" />
                  )}
                  Run {MODE_INFO[mode]?.label} Scan
                </Button>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* History Tab */}
        <TabsContent value="history" className="space-y-4">
          {!engagementId ? (
            <Card>
              <CardContent className="p-12 text-center">
                <Clock className="h-12 w-12 text-muted-foreground mx-auto mb-4 opacity-30" />
                <p className="text-muted-foreground">Enter an engagement ID above to view scan history</p>
              </CardContent>
            </Card>
          ) : history.isLoading ? (
            <div className="flex justify-center p-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : !history.data?.length ? (
            <Card>
              <CardContent className="p-12 text-center">
                <Globe className="h-12 w-12 text-muted-foreground mx-auto mb-4 opacity-30" />
                <p className="text-muted-foreground">No scans yet for this engagement</p>
              </CardContent>
            </Card>
          ) : (
            <div className="space-y-2">
              {history.data.map((scan: any) => {
                const sb = STATUS_BADGE[scan.status] || STATUS_BADGE.queued;
                return (
                  <Card
                    key={scan.id}
                    className="cursor-pointer hover:border-primary/30 transition-all"
                    onClick={() => {
                      if (scan.scanId) {
                        setSelectedScanId(scan.scanId);
                        setActiveTab("results");
                      }
                    }}
                  >
                    <CardContent className="p-3 flex items-center justify-between">
                      <div className="flex items-center gap-3">
                        <Badge variant={sb.variant}>{sb.label}</Badge>
                        <div>
                          <p className="text-sm font-medium">{scan.domains?.join(", ")}</p>
                          <p className="text-xs text-muted-foreground">
                            {scan.mode} mode — {new Date(scan.startedAt).toLocaleString()}
                          </p>
                        </div>
                      </div>
                      {scan.completedAt && (
                        <span className="text-xs text-muted-foreground">
                          {Math.round((scan.completedAt - scan.startedAt) / 1000)}s
                        </span>
                      )}
                    </CardContent>
                  </Card>
                );
              })}
            </div>
          )}
        </TabsContent>

        {/* Results Tab */}
        <TabsContent value="results" className="space-y-4">
          {!selectedScanId ? (
            <Card>
              <CardContent className="p-12 text-center">
                <BarChart3 className="h-12 w-12 text-muted-foreground mx-auto mb-4 opacity-30" />
                <p className="text-muted-foreground">Select a scan from History to view results</p>
              </CardContent>
            </Card>
          ) : scanResult.isLoading ? (
            <div className="flex justify-center p-8">
              <Loader2 className="h-6 w-6 animate-spin text-muted-foreground" />
            </div>
          ) : !scanResult.data ? (
            <Card>
              <CardContent className="p-12 text-center">
                <XCircle className="h-12 w-12 text-red-400 mx-auto mb-4 opacity-50" />
                <p className="text-muted-foreground">Scan result not found (may have expired from memory)</p>
              </CardContent>
            </Card>
          ) : (
            <>
              {/* Summary Cards */}
              <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
                <Card>
                  <CardContent className="p-4 text-center">
                    <Globe className="h-6 w-6 text-emerald-400 mx-auto mb-1" />
                    <p className="text-2xl font-bold">{scanResult.data.summary?.totalSubdomains || 0}</p>
                    <p className="text-xs text-muted-foreground">Subdomains</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="p-4 text-center">
                    <Network className="h-6 w-6 text-blue-400 mx-auto mb-1" />
                    <p className="text-2xl font-bold">{scanResult.data.summary?.totalUniqueIps || 0}</p>
                    <p className="text-xs text-muted-foreground">Unique IPs</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="p-4 text-center">
                    <MapPin className="h-6 w-6 text-amber-400 mx-auto mb-1" />
                    <p className="text-2xl font-bold">{scanResult.data.summary?.totalAsns || 0}</p>
                    <p className="text-xs text-muted-foreground">ASNs</p>
                  </CardContent>
                </Card>
                <Card>
                  <CardContent className="p-4 text-center">
                    <Target className="h-6 w-6 text-purple-400 mx-auto mb-1" />
                    <p className="text-2xl font-bold">{scanResult.data.summary?.totalSources || 0}</p>
                    <p className="text-xs text-muted-foreground">Sources</p>
                  </CardContent>
                </Card>
              </div>

              {/* Subdomain List */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm">Discovered Subdomains</CardTitle>
                  <CardDescription>
                    Scan ID: {scanResult.data.scanId} — {scanResult.data.status} in {Math.round((scanResult.data.durationMs || 0) / 1000)}s
                  </CardDescription>
                </CardHeader>
                <CardContent>
                  <div className="max-h-96 overflow-y-auto space-y-1">
                    {scanResult.data.subdomains?.slice(0, 200).map((sub: any, i: number) => (
                      <div key={i} className="flex items-center justify-between p-2 bg-muted/20 rounded text-sm">
                        <div className="flex items-center gap-2">
                          <Globe className="h-3 w-3 text-muted-foreground" />
                          <span className="font-mono text-xs">{sub.name || sub.fqdn}</span>
                        </div>
                        <div className="flex items-center gap-2">
                          {sub.addresses?.map((addr: any, j: number) => (
                            <Badge key={j} variant="outline" className="text-xs font-mono">
                              {addr.ip || addr}
                            </Badge>
                          ))}
                          {sub.sources?.length > 0 && (
                            <Badge variant="secondary" className="text-xs">
                              {sub.sources.length} src
                            </Badge>
                          )}
                        </div>
                      </div>
                    ))}
                    {(scanResult.data.subdomains?.length || 0) > 200 && (
                      <p className="text-xs text-muted-foreground text-center py-2">
                        Showing 200 of {scanResult.data.subdomains.length} — export for full list
                      </p>
                    )}
                  </div>
                </CardContent>
              </Card>
            </>
          )}
        </TabsContent>

        {/* Diff Tab */}
        <TabsContent value="diff" className="space-y-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-sm flex items-center gap-2">
                <ArrowLeftRight className="h-4 w-4" /> Attack Surface Diff
              </CardTitle>
              <CardDescription>Compare two scans to identify changes in the attack surface</CardDescription>
            </CardHeader>
            <CardContent className="space-y-4">
              <div className="grid grid-cols-2 gap-4">
                <div>
                  <Label className="text-xs">Previous Scan ID</Label>
                  <Input
                    placeholder="amass-1234567890"
                    value={diffPrevId}
                    onChange={e => setDiffPrevId(e.target.value)}
                    className="h-8 text-sm font-mono"
                  />
                </div>
                <div>
                  <Label className="text-xs">Current Scan ID</Label>
                  <Input
                    placeholder="amass-1234567891"
                    value={diffCurrId}
                    onChange={e => setDiffCurrId(e.target.value)}
                    className="h-8 text-sm font-mono"
                  />
                </div>
              </div>

              {diffResult.data && (
                <div className="grid grid-cols-3 gap-4">
                  <Card className="border-emerald-500/20">
                    <CardContent className="p-3 text-center">
                      <p className="text-lg font-bold text-emerald-400">+{diffResult.data.added?.length || 0}</p>
                      <p className="text-xs text-muted-foreground">New Subdomains</p>
                    </CardContent>
                  </Card>
                  <Card className="border-red-500/20">
                    <CardContent className="p-3 text-center">
                      <p className="text-lg font-bold text-red-400">-{diffResult.data.removed?.length || 0}</p>
                      <p className="text-xs text-muted-foreground">Removed</p>
                    </CardContent>
                  </Card>
                  <Card className="border-blue-500/20">
                    <CardContent className="p-3 text-center">
                      <p className="text-lg font-bold text-blue-400">{diffResult.data.unchanged?.length || 0}</p>
                      <p className="text-xs text-muted-foreground">Unchanged</p>
                    </CardContent>
                  </Card>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>
      </Tabs>

      {/* Intel Dialog */}
      <Dialog open={showIntel} onOpenChange={setShowIntel}>
        <DialogContent className="max-w-lg">
          <DialogHeader>
            <DialogTitle>Amass Intel Discovery</DialogTitle>
            <DialogDescription>Discover domains by organization, ASN, CIDR, or WHOIS</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Intel Mode</Label>
              <Select value={intelMode} onValueChange={(v: any) => setIntelMode(v)}>
                <SelectTrigger>
                  <SelectValue />
                </SelectTrigger>
                <SelectContent>
                  {Object.entries(INTEL_MODES).map(([key, info]) => (
                    <SelectItem key={key} value={key}>{info.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
              <p className="text-xs text-muted-foreground mt-1">{INTEL_MODES[intelMode]?.desc}</p>
            </div>
            <div>
              <Label>Query</Label>
              <Input
                placeholder={INTEL_MODES[intelMode]?.placeholder}
                value={intelQuery}
                onChange={e => setIntelQuery(e.target.value)}
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowIntel(false)}>Cancel</Button>
            <Button onClick={handleIntel} disabled={intelMut.isPending} className="gap-2">
              {intelMut.isPending ? <Loader2 className="h-4 w-4 animate-spin" /> : <Search className="h-4 w-4" />}
              Run Intel
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
  );
}
