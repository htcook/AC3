import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Badge } from "@/components/ui/badge";
import { Dialog, DialogContent, DialogDescription, DialogHeader, DialogTitle, DialogTrigger, DialogFooter } from "@/components/ui/dialog";
import { Label } from "@/components/ui/label";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  Bug, Search, RefreshCw, Plus, ExternalLink, Shield,
  AlertTriangle, Link2, TrendingUp, Globe, Zap, Target,
  ChevronRight, Clock, DollarSign, Users, BarChart3,
  Key, CheckCircle2, XCircle, Loader2, Trash2, Eye, EyeOff, Unplug
} from "lucide-react";
import AppShell from "@/components/AppShell";

const SEVERITY_COLORS: Record<string, string> = {
  critical: "bg-red-500/20 text-red-400 border-red-500/30",
  high: "bg-orange-500/20 text-orange-400 border-orange-500/30",
  medium: "bg-yellow-500/20 text-yellow-400 border-yellow-500/30",
  low: "bg-blue-500/20 text-blue-400 border-blue-500/30",
  none: "bg-zinc-500/20 text-zinc-400 border-zinc-500/30",
};

const CORRELATION_COLORS: Record<string, string> = {
  cve_match: "bg-red-500/20 text-red-400",
  asset_match: "bg-cyan-500/20 text-cyan-400",
  cwe_match: "bg-purple-500/20 text-purple-400",
};

export default function BugBountyHub() {
  const [activeTab, setActiveTab] = useState("dashboard");
  const [search, setSearch] = useState("");
  const [platform, setPlatform] = useState<"all" | "hackerone" | "bugcrowd" | "manual">("all");
  const [severity, setSeverity] = useState<string>("");
  const [showAddProgramDialog, setShowAddProgramDialog] = useState(false);
  const [showAddFindingDialog, setShowAddFindingDialog] = useState(false);
  const [showSyncDialog, setShowSyncDialog] = useState(false);
  const [showAddCredentialDialog, setShowAddCredentialDialog] = useState(false);
  const [showApiKey, setShowApiKey] = useState(false);
  const [newCredential, setNewCredential] = useState({
    platform: "hackerone" as "hackerone" | "bugcrowd" | "intigriti" | "synack" | "yeswehack" | "custom",
    displayName: "",
    apiUsername: "",
    apiKey: "",
    baseUrl: "",
  });

  // Form state
  const [newProgram, setNewProgram] = useState({ platform: "manual" as const, handle: "", name: "", url: "", minBounty: 0, maxBounty: 0 });
  const [newFinding, setNewFinding] = useState({ platform: "manual" as const, title: "", severityRating: "medium" as const, cveIds: "", cweId: "", assetIdentifier: "", summary: "" });
  const [syncQuery, setSyncQuery] = useState("severity_rating:critical OR severity_rating:high");
  const [syncPages, setSyncPages] = useState(3);

  // Queries
  const statsInput = useMemo(() => ({}), []);
  const { data: stats } = trpc.bugBounty.stats.useQuery(undefined);
  const programsInput = useMemo(() => ({ platform, search: search || undefined, limit: 50 }), [platform, search]);
  const { data: programsData, isLoading: programsLoading, refetch: refetchPrograms } = trpc.bugBounty.listPrograms.useQuery(programsInput);
  const findingsInput = useMemo(() => ({ platform, severity: severity || undefined, search: search || undefined, limit: 50 }), [platform, severity, search]);
  const { data: findingsData, isLoading: findingsLoading, refetch: refetchFindings } = trpc.bugBounty.listFindings.useQuery(findingsInput);
  const correlationsInput = useMemo(() => ({ limit: 50 }), []);
  const { data: correlations, refetch: refetchCorrelations } = trpc.bugBounty.listCorrelations.useQuery(correlationsInput);
  const syncHistoryInput = useMemo(() => ({ limit: 10 }), []);
  const { data: syncHistory } = trpc.bugBounty.syncHistory.useQuery(syncHistoryInput);

  // Platform Credentials
  const { data: credentials, refetch: refetchCredentials } = trpc.platformCredentials.list.useQuery(undefined);
  const addCredential = trpc.platformCredentials.add.useMutation({
    onSuccess: () => { toast.success("Platform credentials saved"); setShowAddCredentialDialog(false); setNewCredential({ platform: "hackerone", displayName: "", apiUsername: "", apiKey: "", baseUrl: "" }); refetchCredentials(); },
    onError: (e) => toast.error(e.message),
  });
  const deleteCredential = trpc.platformCredentials.delete.useMutation({
    onSuccess: () => { toast.success("Credentials removed"); refetchCredentials(); },
    onError: (e) => toast.error(e.message),
  });
  const verifyCredential = trpc.platformCredentials.verify.useMutation({
    onSuccess: (result) => {
      if (result.valid) toast.success(result.message);
      else toast.error(result.message);
      refetchCredentials();
    },
    onError: (e) => toast.error(e.message),
  });
  const toggleCredential = trpc.platformCredentials.update.useMutation({
    onSuccess: () => { refetchCredentials(); },
  });

  // Mutations
  const syncHacktivity = trpc.bugBounty.syncHackerOneHacktivity.useMutation({
    onSuccess: (d) => { toast.success(`Synced ${d.synced} findings from HackerOne`); refetchFindings(); },
    onError: (e) => toast.error(e.message),
  });
  const syncPrograms = trpc.bugBounty.syncHackerOnePrograms.useMutation({
    onSuccess: (d) => { toast.success(`Synced ${d.synced} programs from HackerOne`); refetchPrograms(); },
    onError: (e) => toast.error(e.message),
  });
  const addProgram = trpc.bugBounty.addProgram.useMutation({
    onSuccess: () => { toast.success("Program added"); setShowAddProgramDialog(false); refetchPrograms(); },
    onError: (e) => toast.error(e.message),
  });
  const addFinding = trpc.bugBounty.addFinding.useMutation({
    onSuccess: () => { toast.success("Finding added"); setShowAddFindingDialog(false); refetchFindings(); },
    onError: (e) => toast.error(e.message),
  });
  const runCorrelation = trpc.bugBounty.runCorrelation.useMutation({
    onSuccess: (d) => { toast.success(`Found ${d.total} correlations (${d.newCorrelations} new)`); refetchCorrelations(); },
    onError: (e) => toast.error(e.message),
  });
  const deleteProgram = trpc.bugBounty.deleteProgram.useMutation({
    onSuccess: () => { toast.success("Program deleted"); refetchPrograms(); },
  });
  const deleteFinding = trpc.bugBounty.deleteFinding.useMutation({
    onSuccess: () => { toast.success("Finding deleted"); refetchFindings(); refetchCorrelations(); },
  });

  return (
    <AppShell activePath="/bug-bounty">
      <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Bug className="h-6 w-6 text-emerald-400" />
            Bug Bounty Intelligence Hub
          </h1>
          <p className="text-muted-foreground mt-1">
            Correlate bug bounty findings with your vulnerability intelligence
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => runCorrelation.mutate({})} disabled={runCorrelation.isPending}>
            <Zap className="h-4 w-4 mr-1" />
            {runCorrelation.isPending ? "Correlating..." : "Run Correlation"}
          </Button>
          <Button variant="outline" size="sm" onClick={() => setShowSyncDialog(true)}>
            <RefreshCw className="h-4 w-4 mr-1" />
            Sync Feeds
          </Button>
          <Button size="sm" onClick={() => setShowAddFindingDialog(true)}>
            <Plus className="h-4 w-4 mr-1" />
            Add Finding
          </Button>
        </div>
      </div>

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Programs Tracked</p>
                <p className="text-2xl font-bold">{stats?.programs ?? 0}</p>
              </div>
              <Globe className="h-8 w-8 text-blue-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Findings Ingested</p>
                <p className="text-2xl font-bold">{stats?.findings ?? 0}</p>
              </div>
              <Bug className="h-8 w-8 text-emerald-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Correlations Found</p>
                <p className="text-2xl font-bold">{stats?.correlations ?? 0}</p>
              </div>
              <Link2 className="h-8 w-8 text-purple-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Critical/High</p>
                <p className="text-2xl font-bold">
                  {(stats?.severityBreakdown || [])
                    .filter((s: any) => s.severity === "critical" || s.severity === "high")
                    .reduce((acc: number, s: any) => acc + (s.count || 0), 0)}
                </p>
              </div>
              <AlertTriangle className="h-8 w-8 text-red-400 opacity-60" />
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-zinc-900 border border-zinc-800">
          <TabsTrigger value="dashboard">Dashboard</TabsTrigger>
          <TabsTrigger value="findings">Findings Feed</TabsTrigger>
          <TabsTrigger value="programs">Programs</TabsTrigger>
          <TabsTrigger value="correlations">Correlations</TabsTrigger>
          <TabsTrigger value="sync">Sync History</TabsTrigger>
          <TabsTrigger value="accounts">
            <Key className="h-3.5 w-3.5 mr-1" />
            Linked Accounts
          </TabsTrigger>
        </TabsList>

        {/* Dashboard Tab */}
        <TabsContent value="dashboard" className="space-y-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Severity Distribution */}
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader>
                <CardTitle className="text-sm font-medium">Severity Distribution</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {(stats?.severityBreakdown || []).map((s: any) => {
                    const total = stats?.findings || 1;
                    const pct = Math.round(((s.count || 0) / total) * 100);
                    return (
                      <div key={s.severity || "unknown"} className="flex items-center gap-3">
                        <Badge className={`w-20 justify-center ${SEVERITY_COLORS[s.severity || "none"] || SEVERITY_COLORS.none}`}>
                          {s.severity || "none"}
                        </Badge>
                        <div className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${s.severity === "critical" ? "bg-red-500" : s.severity === "high" ? "bg-orange-500" : s.severity === "medium" ? "bg-yellow-500" : "bg-blue-500"}`}
                            style={{ width: `${pct}%` }}
                          />
                        </div>
                        <span className="text-sm text-muted-foreground w-12 text-right">{s.count}</span>
                      </div>
                    );
                  })}
                  {(!stats?.severityBreakdown || stats.severityBreakdown.length === 0) && (
                    <p className="text-sm text-muted-foreground text-center py-4">No findings yet. Sync from HackerOne or add manually.</p>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Correlation Breakdown */}
            <Card className="bg-zinc-900/50 border-zinc-800">
              <CardHeader>
                <CardTitle className="text-sm font-medium">Correlation Types</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-3">
                  {(stats?.correlationBreakdown || []).map((c: any) => (
                    <div key={c.type} className="flex items-center justify-between p-3 bg-zinc-800/50 rounded-lg">
                      <div className="flex items-center gap-2">
                        <Badge className={CORRELATION_COLORS[c.type] || "bg-zinc-500/20 text-zinc-400"}>
                          {c.type === "cve_match" ? "CVE Match" : c.type === "asset_match" ? "Asset Match" : "CWE Match"}
                        </Badge>
                      </div>
                      <span className="text-lg font-semibold">{c.count}</span>
                    </div>
                  ))}
                  {(!stats?.correlationBreakdown || stats.correlationBreakdown.length === 0) && (
                    <p className="text-sm text-muted-foreground text-center py-4">Run correlation engine to find matches.</p>
                  )}
                </div>
              </CardContent>
            </Card>

            {/* Top Programs */}
            <Card className="bg-zinc-900/50 border-zinc-800 lg:col-span-2">
              <CardHeader>
                <CardTitle className="text-sm font-medium">Top Programs by Findings</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="space-y-2">
                  {(stats?.topPrograms || []).map((p: any, i: number) => (
                    <div key={i} className="flex items-center justify-between p-3 bg-zinc-800/30 rounded-lg">
                      <div className="flex items-center gap-3">
                        <span className="text-sm text-muted-foreground w-6">{i + 1}.</span>
                        <div>
                          <p className="font-medium">{p.programName || p.programHandle || "Unknown"}</p>
                          <p className="text-xs text-muted-foreground">{p.programHandle}</p>
                        </div>
                      </div>
                      <div className="flex items-center gap-4">
                        <div className="text-right">
                          <p className="text-sm font-medium">{p.count} findings</p>
                          {p.totalAwarded > 0 && (
                            <p className="text-xs text-emerald-400">${Number(p.totalAwarded).toLocaleString()} awarded</p>
                          )}
                        </div>
                      </div>
                    </div>
                  ))}
                  {(!stats?.topPrograms || stats.topPrograms.length === 0) && (
                    <p className="text-sm text-muted-foreground text-center py-4">No program data yet.</p>
                  )}
                </div>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

        {/* Findings Feed Tab */}
        <TabsContent value="findings" className="space-y-4">
          <div className="flex gap-3 items-center">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search findings by title..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-10 bg-zinc-900 border-zinc-800"
              />
            </div>
            <Select value={platform} onValueChange={(v) => setPlatform(v as any)}>
              <SelectTrigger className="w-40 bg-zinc-900 border-zinc-800">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all">All Platforms</SelectItem>
                <SelectItem value="hackerone">HackerOne</SelectItem>
                <SelectItem value="bugcrowd">Bugcrowd</SelectItem>
                <SelectItem value="manual">Manual</SelectItem>
              </SelectContent>
            </Select>
            <Select value={severity || "all_severities"} onValueChange={(v) => setSeverity(v === "all_severities" ? "" : v)}>
              <SelectTrigger className="w-36 bg-zinc-900 border-zinc-800">
                <SelectValue />
              </SelectTrigger>
              <SelectContent>
                <SelectItem value="all_severities">All Severities</SelectItem>
                <SelectItem value="critical">Critical</SelectItem>
                <SelectItem value="high">High</SelectItem>
                <SelectItem value="medium">Medium</SelectItem>
                <SelectItem value="low">Low</SelectItem>
              </SelectContent>
            </Select>
          </div>

          {findingsLoading ? (
            <div className="text-center py-12 text-muted-foreground">Loading findings...</div>
          ) : (
            <div className="space-y-2">
              {(findingsData?.findings || []).map((f: any) => (
                <Card key={f.id} className="bg-zinc-900/50 border-zinc-800 hover:border-zinc-700 transition-colors">
                  <CardContent className="py-4">
                    <div className="flex items-start justify-between gap-4">
                      <div className="flex-1 min-w-0">
                        <div className="flex items-center gap-2 mb-1">
                          <Badge className={SEVERITY_COLORS[f.severityRating || "none"] || SEVERITY_COLORS.none}>
                            {f.severityRating || "none"}
                          </Badge>
                          <Badge variant="outline" className="text-xs">
                            {f.platform}
                          </Badge>
                          {f.programHandle && (
                            <span className="text-xs text-muted-foreground">{f.programHandle}</span>
                          )}
                        </div>
                        <p className="font-medium truncate">{f.title}</p>
                        <div className="flex items-center gap-4 mt-1 text-xs text-muted-foreground">
                          {f.reporterUsername && <span>by {f.reporterUsername}</span>}
                          {f.disclosedAt && <span>{new Date(f.disclosedAt).toLocaleDateString()}</span>}
                          {f.awardedAmount != null && f.awardedAmount > 0 && (
                            <span className="text-emerald-400">${Number(f.awardedAmount).toLocaleString()}</span>
                          )}
                          {f.cweId && <span>CWE: {f.cweId}</span>}
                          {f.assetIdentifier && <span className="text-cyan-400">{f.assetIdentifier}</span>}
                        </div>
                      </div>
                      <div className="flex items-center gap-1">
                        {f.reportUrl && (
                          <Button variant="ghost" size="sm" asChild>
                            <a href={f.reportUrl} target="_blank" rel="noopener noreferrer">
                              <ExternalLink className="h-4 w-4" />
                            </a>
                          </Button>
                        )}
                        <Button variant="ghost" size="sm" className="text-red-400" onClick={() => deleteFinding.mutate({ id: f.id })}>
                          &times;
                        </Button>
                      </div>
                    </div>
                  </CardContent>
                </Card>
              ))}
              {findingsData?.findings?.length === 0 && (
                <div className="text-center py-12 text-muted-foreground">
                  <Bug className="h-12 w-12 mx-auto mb-3 opacity-30" />
                  <p>No findings yet. Sync from HackerOne or add manually.</p>
                </div>
              )}
              {findingsData && findingsData.total > 50 && (
                <p className="text-center text-sm text-muted-foreground">Showing 50 of {findingsData.total} findings</p>
              )}
            </div>
          )}
        </TabsContent>

        {/* Programs Tab */}
        <TabsContent value="programs" className="space-y-4">
          <div className="flex gap-3 items-center">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search programs..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-10 bg-zinc-900 border-zinc-800"
              />
            </div>
            <Button variant="outline" size="sm" onClick={() => syncPrograms.mutate({ pages: 3 })} disabled={syncPrograms.isPending}>
              <RefreshCw className={`h-4 w-4 mr-1 ${syncPrograms.isPending ? "animate-spin" : ""}`} />
              Sync H1 Programs
            </Button>
            <Button size="sm" onClick={() => setShowAddProgramDialog(true)}>
              <Plus className="h-4 w-4 mr-1" />
              Add Program
            </Button>
          </div>

          {programsLoading ? (
            <div className="text-center py-12 text-muted-foreground">Loading programs...</div>
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {(programsData?.programs || []).map((p: any) => (
                <Card key={p.id} className="bg-zinc-900/50 border-zinc-800 hover:border-zinc-700 transition-colors">
                  <CardContent className="pt-4 pb-3">
                    <div className="flex items-start justify-between mb-2">
                      <div className="flex items-center gap-2">
                        {p.logoUrl ? (
                          <img src={p.logoUrl} alt="" className="h-8 w-8 rounded" />
                        ) : (
                          <div className="h-8 w-8 rounded bg-zinc-800 flex items-center justify-center">
                            <Shield className="h-4 w-4 text-zinc-500" />
                          </div>
                        )}
                        <div>
                          <p className="font-medium text-sm">{p.name}</p>
                          <p className="text-xs text-muted-foreground">{p.handle}</p>
                        </div>
                      </div>
                      <Badge variant="outline" className="text-xs">{p.platform}</Badge>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-muted-foreground mt-2">
                      {p.state && <Badge variant={p.state === "open" ? "default" : "secondary"} className="text-xs">{p.state}</Badge>}
                      {p.minBounty != null && p.maxBounty != null && (
                        <span>${p.minBounty} - ${p.maxBounty}</span>
                      )}
                    </div>
                    <div className="flex items-center justify-between mt-3">
                      {p.url && (
                        <Button variant="ghost" size="sm" className="text-xs" asChild>
                          <a href={p.url} target="_blank" rel="noopener noreferrer">
                            <ExternalLink className="h-3 w-3 mr-1" /> View
                          </a>
                        </Button>
                      )}
                      <Button variant="ghost" size="sm" className="text-xs text-red-400" onClick={() => deleteProgram.mutate({ id: p.id })}>
                        Remove
                      </Button>
                    </div>
                  </CardContent>
                </Card>
              ))}
              {programsData?.programs?.length === 0 && (
                <div className="col-span-full text-center py-12 text-muted-foreground">
                  <Globe className="h-12 w-12 mx-auto mb-3 opacity-30" />
                  <p>No programs tracked yet. Sync from HackerOne or add manually.</p>
                </div>
              )}
            </div>
          )}
        </TabsContent>

        {/* Correlations Tab */}
        <TabsContent value="correlations" className="space-y-4">
          <div className="flex items-center justify-between">
            <p className="text-sm text-muted-foreground">
              Showing {correlations?.length || 0} correlations between bug bounty findings and your intelligence data
            </p>
            <Button variant="outline" size="sm" onClick={() => runCorrelation.mutate({})} disabled={runCorrelation.isPending}>
              <Zap className={`h-4 w-4 mr-1 ${runCorrelation.isPending ? "animate-spin" : ""}`} />
              {runCorrelation.isPending ? "Running..." : "Re-run Engine"}
            </Button>
          </div>

          <div className="space-y-2">
            {(correlations || []).map((c: any) => (
              <Card key={c.id} className="bg-zinc-900/50 border-zinc-800">
                <CardContent className="py-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Badge className={CORRELATION_COLORS[c.correlationType] || "bg-zinc-500/20 text-zinc-400"}>
                        {c.correlationType === "cve_match" ? "CVE" : c.correlationType === "asset_match" ? "Asset" : "CWE"}
                      </Badge>
                      <div>
                        <p className="font-medium text-sm">
                          Finding #{c.findingId} <ChevronRight className="inline h-3 w-3" /> {c.matchedEntityName}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {c.matchedEntityType} • Confidence: {Math.round((c.confidenceScore || 0) * 100)}%
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className={`h-2 w-16 rounded-full overflow-hidden bg-zinc-800`}>
                        <div
                          className={`h-full rounded-full ${(c.confidenceScore || 0) > 0.8 ? "bg-emerald-500" : (c.confidenceScore || 0) > 0.5 ? "bg-yellow-500" : "bg-red-500"}`}
                          style={{ width: `${(c.confidenceScore || 0) * 100}%` }}
                        />
                      </div>
                    </div>
                  </div>
                </CardContent>
              </Card>
            ))}
            {(!correlations || correlations.length === 0) && (
              <div className="text-center py-12 text-muted-foreground">
                <Link2 className="h-12 w-12 mx-auto mb-3 opacity-30" />
                <p>No correlations found. Add findings and run the correlation engine.</p>
              </div>
            )}
          </div>
        </TabsContent>

        {/* Sync History Tab */}
        <TabsContent value="sync" className="space-y-4">
          <div className="space-y-2">
            {(syncHistory || []).map((s: any) => (
              <Card key={s.id} className="bg-zinc-900/50 border-zinc-800">
                <CardContent className="py-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-3">
                      <Badge variant={s.status === "completed" ? "default" : s.status === "failed" ? "destructive" : "secondary"}>
                        {s.status}
                      </Badge>
                      <div>
                        <p className="font-medium text-sm">{s.platform} / {s.syncType}</p>
                        <p className="text-xs text-muted-foreground">
                          {s.startedAt ? new Date(s.startedAt).toLocaleString() : "Unknown"}
                          {s.itemsSynced != null && ` • ${s.itemsSynced} items`}
                        </p>
                      </div>
                    </div>
                    {s.errorMessage && (
                      <p className="text-xs text-red-400 max-w-xs truncate">{s.errorMessage}</p>
                    )}
                  </div>
                </CardContent>
              </Card>
            ))}
            {(!syncHistory || syncHistory.length === 0) && (
              <div className="text-center py-12 text-muted-foreground">
                <Clock className="h-12 w-12 mx-auto mb-3 opacity-30" />
                <p>No sync history yet.</p>
              </div>
            )}
          </div>
        </TabsContent>
        {/* Linked Accounts Tab */}
        <TabsContent value="accounts" className="space-y-4">
          <div className="flex items-center justify-between">
            <div>
              <p className="text-sm text-muted-foreground">
                Link your bug bounty platform accounts to enable automatic syncing of findings, programs, and intelligence data.
              </p>
            </div>
            <Button size="sm" onClick={() => setShowAddCredentialDialog(true)}>
              <Plus className="h-4 w-4 mr-1" />
              Link Account
            </Button>
          </div>

          {/* Platform Cards */}
          <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
            {/* Supported Platforms Info */}
            {["hackerone", "bugcrowd", "intigriti", "synack", "yeswehack"].map((plat) => {
              const linked = (credentials || []).filter((c: any) => c.platform === plat);
              const platformNames: Record<string, string> = {
                hackerone: "HackerOne",
                bugcrowd: "Bugcrowd",
                intigriti: "Intigriti",
                synack: "Synack",
                yeswehack: "YesWeHack",
              };
              const platformColors: Record<string, string> = {
                hackerone: "text-emerald-400 border-emerald-500/30",
                bugcrowd: "text-orange-400 border-orange-500/30",
                intigriti: "text-blue-400 border-blue-500/30",
                synack: "text-red-400 border-red-500/30",
                yeswehack: "text-yellow-400 border-yellow-500/30",
              };
              return (
                <Card key={plat} className={`bg-zinc-900/50 border-zinc-800 ${linked.length > 0 ? "ring-1 ring-emerald-500/20" : ""}`}>
                  <CardContent className="pt-5 pb-4">
                    <div className="flex items-center justify-between mb-3">
                      <div className="flex items-center gap-3">
                        <div className={`h-10 w-10 rounded-lg border flex items-center justify-center ${platformColors[plat] || "text-zinc-400 border-zinc-700"}`}>
                          <Bug className="h-5 w-5" />
                        </div>
                        <div>
                          <p className="font-semibold">{platformNames[plat]}</p>
                          <p className="text-xs text-muted-foreground">
                            {linked.length > 0 ? `${linked.length} account${linked.length > 1 ? "s" : ""} linked` : "Not connected"}
                          </p>
                        </div>
                      </div>
                      {linked.length > 0 ? (
                        <CheckCircle2 className="h-5 w-5 text-emerald-400" />
                      ) : (
                        <Unplug className="h-5 w-5 text-zinc-600" />
                      )}
                    </div>

                    {/* Linked accounts for this platform */}
                    {linked.map((cred: any) => (
                      <div key={cred.id} className="mt-2 p-3 bg-zinc-800/50 rounded-lg border border-zinc-700/50">
                        <div className="flex items-center justify-between mb-2">
                          <div>
                            <p className="text-sm font-medium">{cred.displayName}</p>
                            {cred.apiUsername && <p className="text-xs text-muted-foreground">User: {cred.apiUsername}</p>}
                          </div>
                          <div className="flex items-center gap-1">
                            {cred.syncStatus === "success" && <Badge className="bg-emerald-500/20 text-emerald-400 text-xs">Verified</Badge>}
                            {cred.syncStatus === "failed" && <Badge className="bg-red-500/20 text-red-400 text-xs">Failed</Badge>}
                            {cred.syncStatus === "syncing" && <Badge className="bg-blue-500/20 text-blue-400 text-xs">Syncing</Badge>}
                            {(cred.syncStatus === "idle" || !cred.syncStatus) && <Badge className="bg-zinc-500/20 text-zinc-400 text-xs">Unverified</Badge>}
                          </div>
                        </div>
                        {cred.errorMessage && (
                          <p className="text-xs text-red-400 mb-2 truncate">{cred.errorMessage}</p>
                        )}
                        {cred.lastVerifiedAt && (
                          <p className="text-xs text-muted-foreground mb-2">Last verified: {new Date(cred.lastVerifiedAt).toLocaleString()}</p>
                        )}
                        <div className="flex items-center gap-2">
                          <Button
                            variant="outline"
                            size="sm"
                            className="text-xs h-7"
                            onClick={() => verifyCredential.mutate({ id: cred.id })}
                            disabled={verifyCredential.isPending}
                          >
                            {verifyCredential.isPending ? <Loader2 className="h-3 w-3 animate-spin mr-1" /> : <CheckCircle2 className="h-3 w-3 mr-1" />}
                            Verify
                          </Button>
                          <Button
                            variant="outline"
                            size="sm"
                            className="text-xs h-7"
                            onClick={() => toggleCredential.mutate({ id: cred.id, isActive: !cred.isActive })}
                          >
                            {cred.isActive ? "Disable" : "Enable"}
                          </Button>
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-xs h-7 text-red-400 hover:text-red-300"
                            onClick={() => { if (confirm("Remove this credential?")) deleteCredential.mutate({ id: cred.id }); }}
                          >
                            <Trash2 className="h-3 w-3" />
                          </Button>
                        </div>
                      </div>
                    ))}

                    {linked.length === 0 && (
                      <Button
                        variant="outline"
                        size="sm"
                        className="w-full mt-2 text-xs"
                        onClick={() => {
                          setNewCredential({ ...newCredential, platform: plat as any, displayName: platformNames[plat] + " Account" });
                          setShowAddCredentialDialog(true);
                        }}
                      >
                        <Key className="h-3 w-3 mr-1" />
                        Connect {platformNames[plat]}
                      </Button>
                    )}
                  </CardContent>
                </Card>
              );
            })}

            {/* Custom Platform Card */}
            <Card className="bg-zinc-900/50 border-zinc-800 border-dashed">
              <CardContent className="pt-5 pb-4 flex flex-col items-center justify-center text-center min-h-[120px]">
                <Plus className="h-8 w-8 text-zinc-600 mb-2" />
                <p className="text-sm font-medium text-muted-foreground">Custom Platform</p>
                <p className="text-xs text-muted-foreground mb-3">Connect any platform with an API</p>
                <Button
                  variant="outline"
                  size="sm"
                  className="text-xs"
                  onClick={() => {
                    setNewCredential({ ...newCredential, platform: "custom", displayName: "" });
                    setShowAddCredentialDialog(true);
                  }}
                >
                  Add Custom
                </Button>
              </CardContent>
            </Card>
          </div>
        </TabsContent>

      </Tabs>

      {/* Add Credential Dialog */}
      <Dialog open={showAddCredentialDialog} onOpenChange={setShowAddCredentialDialog}>
        <DialogContent className="bg-zinc-900 border-zinc-800">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Key className="h-5 w-5 text-emerald-400" />
              Link Platform Account
            </DialogTitle>
            <DialogDescription>
              Enter your API credentials to connect your bug bounty platform account. Credentials are encrypted at rest.
            </DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Platform</Label>
              <Select value={newCredential.platform} onValueChange={(v) => setNewCredential({ ...newCredential, platform: v as any })}>
                <SelectTrigger className="bg-zinc-800 border-zinc-700 mt-1"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="hackerone">HackerOne</SelectItem>
                  <SelectItem value="bugcrowd">Bugcrowd</SelectItem>
                  <SelectItem value="intigriti">Intigriti</SelectItem>
                  <SelectItem value="synack">Synack</SelectItem>
                  <SelectItem value="yeswehack">YesWeHack</SelectItem>
                  <SelectItem value="custom">Custom Platform</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Display Name</Label>
              <Input
                value={newCredential.displayName}
                onChange={(e) => setNewCredential({ ...newCredential, displayName: e.target.value })}
                placeholder="My HackerOne Account"
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
            {(newCredential.platform === "hackerone" || newCredential.platform === "custom") && (
              <div>
                <Label>API Username / Identifier</Label>
                <Input
                  value={newCredential.apiUsername}
                  onChange={(e) => setNewCredential({ ...newCredential, apiUsername: e.target.value })}
                  placeholder={newCredential.platform === "hackerone" ? "Your HackerOne API identifier" : "Username or identifier"}
                  className="bg-zinc-800 border-zinc-700 mt-1"
                />
                {newCredential.platform === "hackerone" && (
                  <p className="text-xs text-muted-foreground mt-1">Found under Settings → API Token in HackerOne</p>
                )}
              </div>
            )}
            <div>
              <Label>API Key / Token</Label>
              <div className="relative">
                <Input
                  type={showApiKey ? "text" : "password"}
                  value={newCredential.apiKey}
                  onChange={(e) => setNewCredential({ ...newCredential, apiKey: e.target.value })}
                  placeholder="Enter your API key"
                  className="bg-zinc-800 border-zinc-700 mt-1 pr-10"
                />
                <Button
                  type="button"
                  variant="ghost"
                  size="sm"
                  className="absolute right-1 top-1/2 -translate-y-1/2 h-7 w-7 p-0"
                  onClick={() => setShowApiKey(!showApiKey)}
                >
                  {showApiKey ? <EyeOff className="h-3.5 w-3.5" /> : <Eye className="h-3.5 w-3.5" />}
                </Button>
              </div>
            </div>
            {newCredential.platform === "custom" && (
              <div>
                <Label>Base URL (optional)</Label>
                <Input
                  value={newCredential.baseUrl}
                  onChange={(e) => setNewCredential({ ...newCredential, baseUrl: e.target.value })}
                  placeholder="https://api.example.com"
                  className="bg-zinc-800 border-zinc-700 mt-1"
                />
              </div>
            )}
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowAddCredentialDialog(false)}>Cancel</Button>
            <Button
              onClick={() => addCredential.mutate({
                platform: newCredential.platform,
                displayName: newCredential.displayName,
                apiUsername: newCredential.apiUsername || undefined,
                apiKey: newCredential.apiKey,
                baseUrl: newCredential.baseUrl || undefined,
              })}
              disabled={addCredential.isPending || !newCredential.displayName || !newCredential.apiKey}
            >
              {addCredential.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-1" /> : <Key className="h-4 w-4 mr-1" />}
              {addCredential.isPending ? "Saving..." : "Save & Connect"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Sync Dialog */}
      <Dialog open={showSyncDialog} onOpenChange={setShowSyncDialog}>
        <DialogContent className="bg-zinc-900 border-zinc-800">
          <DialogHeader>
            <DialogTitle>Sync HackerOne Feeds</DialogTitle>
            <DialogDescription>Pull latest hacktivity and program data from HackerOne</DialogDescription>
          </DialogHeader>
          <div className="space-y-4">
            <div>
              <Label>Hacktivity Query (Lucene syntax)</Label>
              <Input
                value={syncQuery}
                onChange={(e) => setSyncQuery(e.target.value)}
                className="bg-zinc-800 border-zinc-700 mt-1"
                placeholder="severity_rating:critical OR severity_rating:high"
              />
              <p className="text-xs text-muted-foreground mt-1">
                Filters: severity_rating, asset_type, cwe, cve_ids, reporter, team
              </p>
            </div>
            <div>
              <Label>Pages to Fetch (25 items/page)</Label>
              <Input
                type="number"
                value={syncPages}
                onChange={(e) => setSyncPages(Number(e.target.value))}
                min={1}
                max={10}
                className="bg-zinc-800 border-zinc-700 mt-1"
              />
            </div>
          </div>
          <DialogFooter className="gap-2">
            <Button variant="outline" onClick={() => syncPrograms.mutate({ pages: syncPages })} disabled={syncPrograms.isPending}>
              {syncPrograms.isPending ? "Syncing..." : "Sync Programs"}
            </Button>
            <Button onClick={() => { syncHacktivity.mutate({ queryString: syncQuery, pages: syncPages }); setShowSyncDialog(false); }} disabled={syncHacktivity.isPending}>
              {syncHacktivity.isPending ? "Syncing..." : "Sync Hacktivity"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Add Program Dialog */}
      <Dialog open={showAddProgramDialog} onOpenChange={setShowAddProgramDialog}>
        <DialogContent className="bg-zinc-900 border-zinc-800">
          <DialogHeader>
            <DialogTitle>Add Bug Bounty Program</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <Label>Platform</Label>
              <Select value={newProgram.platform} onValueChange={(v) => setNewProgram({ ...newProgram, platform: v as any })}>
                <SelectTrigger className="bg-zinc-800 border-zinc-700 mt-1"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="hackerone">HackerOne</SelectItem>
                  <SelectItem value="bugcrowd">Bugcrowd</SelectItem>
                  <SelectItem value="manual">Manual</SelectItem>
                </SelectContent>
              </Select>
            </div>
            <div>
              <Label>Handle / Slug</Label>
              <Input value={newProgram.handle} onChange={(e) => setNewProgram({ ...newProgram, handle: e.target.value })} className="bg-zinc-800 border-zinc-700 mt-1" />
            </div>
            <div>
              <Label>Program Name</Label>
              <Input value={newProgram.name} onChange={(e) => setNewProgram({ ...newProgram, name: e.target.value })} className="bg-zinc-800 border-zinc-700 mt-1" />
            </div>
            <div>
              <Label>URL</Label>
              <Input value={newProgram.url} onChange={(e) => setNewProgram({ ...newProgram, url: e.target.value })} className="bg-zinc-800 border-zinc-700 mt-1" />
            </div>
          </div>
          <DialogFooter>
            <Button onClick={() => addProgram.mutate(newProgram)} disabled={addProgram.isPending || !newProgram.handle || !newProgram.name}>
              {addProgram.isPending ? "Adding..." : "Add Program"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>

      {/* Add Finding Dialog */}
      <Dialog open={showAddFindingDialog} onOpenChange={setShowAddFindingDialog}>
        <DialogContent className="bg-zinc-900 border-zinc-800">
          <DialogHeader>
            <DialogTitle>Add Bug Bounty Finding</DialogTitle>
          </DialogHeader>
          <div className="space-y-3">
            <div>
              <Label>Title</Label>
              <Input value={newFinding.title} onChange={(e) => setNewFinding({ ...newFinding, title: e.target.value })} className="bg-zinc-800 border-zinc-700 mt-1" />
            </div>
            <div className="grid grid-cols-2 gap-3">
              <div>
                <Label>Severity</Label>
                <Select value={newFinding.severityRating} onValueChange={(v) => setNewFinding({ ...newFinding, severityRating: v as any })}>
                  <SelectTrigger className="bg-zinc-800 border-zinc-700 mt-1"><SelectValue /></SelectTrigger>
                  <SelectContent>
                    <SelectItem value="critical">Critical</SelectItem>
                    <SelectItem value="high">High</SelectItem>
                    <SelectItem value="medium">Medium</SelectItem>
                    <SelectItem value="low">Low</SelectItem>
                    <SelectItem value="none">None</SelectItem>
                  </SelectContent>
                </Select>
              </div>
              <div>
                <Label>CWE ID</Label>
                <Input value={newFinding.cweId} onChange={(e) => setNewFinding({ ...newFinding, cweId: e.target.value })} placeholder="CWE-79" className="bg-zinc-800 border-zinc-700 mt-1" />
              </div>
            </div>
            <div>
              <Label>CVE IDs (comma-separated)</Label>
              <Input value={newFinding.cveIds} onChange={(e) => setNewFinding({ ...newFinding, cveIds: e.target.value })} placeholder="CVE-2024-1234, CVE-2024-5678" className="bg-zinc-800 border-zinc-700 mt-1" />
            </div>
            <div>
              <Label>Asset Identifier (domain/URL)</Label>
              <Input value={newFinding.assetIdentifier} onChange={(e) => setNewFinding({ ...newFinding, assetIdentifier: e.target.value })} placeholder="api.example.com" className="bg-zinc-800 border-zinc-700 mt-1" />
            </div>
            <div>
              <Label>Summary</Label>
              <Input value={newFinding.summary} onChange={(e) => setNewFinding({ ...newFinding, summary: e.target.value })} className="bg-zinc-800 border-zinc-700 mt-1" />
            </div>
          </div>
          <DialogFooter>
            <Button
              onClick={() =>
                addFinding.mutate({
                  ...newFinding,
                  cveIds: newFinding.cveIds ? newFinding.cveIds.split(",").map((s) => s.trim()).filter(Boolean) : undefined,
                })
              }
              disabled={addFinding.isPending || !newFinding.title}
            >
              {addFinding.isPending ? "Adding..." : "Add Finding"}
            </Button>
          </DialogFooter>
        </DialogContent>
      </Dialog>
    </div>
    </AppShell>
  );
}
