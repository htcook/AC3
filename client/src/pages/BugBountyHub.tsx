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
  CheckCircle2, XCircle, MapPin
} from "lucide-react";

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

  // Form state
  const [newProgram, setNewProgram] = useState({ platform: "manual" as const, handle: "", name: "", url: "", minBounty: 0, maxBounty: 0 });
  const [newFinding, setNewFinding] = useState({ platform: "manual" as const, title: "", severityRating: "medium" as const, cveIds: "", cweId: "", assetIdentifier: "", summary: "" });
  const [syncQuery, setSyncQuery] = useState("severity_rating:critical OR severity_rating:high");
  const [syncPages, setSyncPages] = useState(3);

  // Queries
  const { data: stats } = trpc.bugBounty.stats.useQuery(undefined);
  const { data: credStatus } = trpc.bugBounty.credentialStatus.useQuery(undefined);
  const programsInput = useMemo(() => ({ platform, search: search || undefined, limit: 50 }), [platform, search]);
  const { data: programsData, isLoading: programsLoading, refetch: refetchPrograms } = trpc.bugBounty.listPrograms.useQuery(programsInput);
  const findingsInput = useMemo(() => ({ platform, severity: severity || undefined, search: search || undefined, limit: 50 }), [platform, severity, search]);
  const { data: findingsData, isLoading: findingsLoading, refetch: refetchFindings } = trpc.bugBounty.listFindings.useQuery(findingsInput);
  const correlationsInput = useMemo(() => ({ limit: 50 }), []);
  const { data: correlations, refetch: refetchCorrelations } = trpc.bugBounty.listCorrelations.useQuery(correlationsInput);
  const syncHistoryInput = useMemo(() => ({ limit: 20 }), []);
  const { data: syncHistory, refetch: refetchSyncHistory } = trpc.bugBounty.syncHistory.useQuery(syncHistoryInput);

  // Mutations
  const utils = trpc.useUtils();
  const syncHacktivity = trpc.bugBounty.syncHackerOneHacktivity.useMutation({
    onSuccess: (d) => { toast.success(`Synced ${d.synced} findings from HackerOne`); refetchFindings(); refetchSyncHistory(); utils.bugBounty.stats.invalidate(); },
    onError: (e) => toast.error(e.message),
  });
  const syncH1Programs = trpc.bugBounty.syncHackerOnePrograms.useMutation({
    onSuccess: (d) => { toast.success(`Synced ${d.synced} programs from HackerOne`); refetchPrograms(); refetchSyncHistory(); utils.bugBounty.stats.invalidate(); },
    onError: (e) => toast.error(e.message),
  });
  const syncBcPrograms = trpc.bugBounty.syncBugcrowdPrograms.useMutation({
    onSuccess: (d) => { toast.success(`Synced ${d.synced} programs from Bugcrowd`); refetchPrograms(); refetchSyncHistory(); utils.bugBounty.stats.invalidate(); },
    onError: (e) => toast.error(e.message),
  });
  const syncBcSubmissions = trpc.bugBounty.syncBugcrowdSubmissions.useMutation({
    onSuccess: (d) => { toast.success(`Synced ${d.synced} submissions from Bugcrowd`); refetchFindings(); refetchSyncHistory(); utils.bugBounty.stats.invalidate(); },
    onError: (e) => toast.error(e.message),
  });
  const addProgram = trpc.bugBounty.addProgram.useMutation({
    onSuccess: () => { toast.success("Program added"); setShowAddProgramDialog(false); refetchPrograms(); utils.bugBounty.stats.invalidate(); },
    onError: (e) => toast.error(e.message),
  });
  const addFinding = trpc.bugBounty.addFinding.useMutation({
    onSuccess: () => { toast.success("Finding added"); setShowAddFindingDialog(false); refetchFindings(); utils.bugBounty.stats.invalidate(); },
    onError: (e) => toast.error(e.message),
  });
  const runCorrelation = trpc.bugBounty.runCorrelation.useMutation({
    onSuccess: (d) => { toast.success(`Found ${d.total} correlations (${d.newCorrelations} new)`); refetchCorrelations(); utils.bugBounty.stats.invalidate(); },
    onError: (e) => toast.error(e.message),
  });
  const matchDomains = trpc.bugBounty.matchDomainsToPrograms.useMutation({
    onSuccess: (d) => { toast.success(`Found ${d.total} domain-to-program matches`); },
    onError: (e) => toast.error(e.message),
  });
  const deleteProgram = trpc.bugBounty.deleteProgram.useMutation({
    onSuccess: () => { toast.success("Program deleted"); refetchPrograms(); utils.bugBounty.stats.invalidate(); },
  });
  const deleteFinding = trpc.bugBounty.deleteFinding.useMutation({
    onSuccess: () => { toast.success("Finding deleted"); refetchFindings(); refetchCorrelations(); utils.bugBounty.stats.invalidate(); },
  });

  const isSyncing = syncHacktivity.isPending || syncH1Programs.isPending || syncBcPrograms.isPending || syncBcSubmissions.isPending;

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Bug className="h-6 w-6 text-emerald-400" />
            Bug Bounty Intelligence Hub
          </h1>
          <p className="text-muted-foreground mt-1">
            Correlate bug bounty findings with your vulnerability intelligence and discovered assets
          </p>
        </div>
        <div className="flex gap-2">
          <Button variant="outline" size="sm" onClick={() => runCorrelation.mutate({})} disabled={runCorrelation.isPending}>
            <Zap className="h-4 w-4 mr-1" />
            {runCorrelation.isPending ? "Correlating..." : "Run Correlation"}
          </Button>
          <Button variant="outline" size="sm" onClick={() => setShowSyncDialog(true)}>
            <RefreshCw className={`h-4 w-4 mr-1 ${isSyncing ? "animate-spin" : ""}`} />
            Sync Feeds
          </Button>
          <Button size="sm" onClick={() => setShowAddFindingDialog(true)}>
            <Plus className="h-4 w-4 mr-1" />
            Add Finding
          </Button>
        </div>
      </div>

      {/* Credential Status Banner */}
      {credStatus && (!credStatus.hackerOne.configured || !credStatus.bugcrowd.configured) && (
        <Card className="bg-amber-500/10 border-amber-500/30">
          <CardContent className="py-3">
            <div className="flex items-center gap-3">
              <AlertTriangle className="h-5 w-5 text-amber-400 shrink-0" />
              <div className="flex-1">
                <p className="text-sm font-medium text-amber-300">API Credentials Required for Live Sync</p>
                <p className="text-xs text-amber-400/80 mt-0.5">
                  {!credStatus.hackerOne.configured && !credStatus.bugcrowd.configured
                    ? "Neither HackerOne nor Bugcrowd API credentials are configured. Add them in Settings > Secrets to enable live feed sync."
                    : !credStatus.hackerOne.configured
                      ? "HackerOne API credentials not configured. Add HACKERONE_API_USERNAME and HACKERONE_API_TOKEN in Settings > Secrets."
                      : "Bugcrowd API token not configured. Add BUGCROWD_API_TOKEN in Settings > Secrets."
                  }
                </p>
              </div>
              <div className="flex items-center gap-3 shrink-0">
                <div className="flex items-center gap-1.5 text-xs">
                  {credStatus.hackerOne.configured ? (
                    <><CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" /><span className="text-emerald-400">H1</span></>
                  ) : (
                    <><XCircle className="h-3.5 w-3.5 text-red-400" /><span className="text-red-400">H1</span></>
                  )}
                </div>
                <div className="flex items-center gap-1.5 text-xs">
                  {credStatus.bugcrowd.configured ? (
                    <><CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" /><span className="text-emerald-400">BC</span></>
                  ) : (
                    <><XCircle className="h-3.5 w-3.5 text-red-400" /><span className="text-red-400">BC</span></>
                  )}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4">
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Programs</p>
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
                <p className="text-sm text-muted-foreground">Findings</p>
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
                <p className="text-sm text-muted-foreground">Correlations</p>
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
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="pt-6">
            <div className="flex items-center justify-between">
              <div>
                <p className="text-sm text-muted-foreground">Platforms</p>
                <div className="flex items-center gap-2 mt-1">
                  {(stats?.platformBreakdown || []).map((p: any) => (
                    <Badge key={p.platform} variant="outline" className="text-xs">
                      {p.platform}: {p.count}
                    </Badge>
                  ))}
                  {(!stats?.platformBreakdown || stats.platformBreakdown.length === 0) && (
                    <span className="text-sm text-muted-foreground">—</span>
                  )}
                </div>
              </div>
              <BarChart3 className="h-8 w-8 text-cyan-400 opacity-60" />
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
          <TabsTrigger value="domain-match">Domain Matching</TabsTrigger>
          <TabsTrigger value="sync">Sync History</TabsTrigger>
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
                    <p className="text-sm text-muted-foreground text-center py-4">No findings yet. Sync from HackerOne/Bugcrowd or add manually.</p>
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
                  <p>No findings yet. Sync from HackerOne/Bugcrowd or add manually.</p>
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
          <div className="flex gap-3 items-center flex-wrap">
            <div className="relative flex-1 min-w-[200px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search programs..."
                value={search}
                onChange={(e) => setSearch(e.target.value)}
                className="pl-10 bg-zinc-900 border-zinc-800"
              />
            </div>
            <Button variant="outline" size="sm" onClick={() => syncH1Programs.mutate({ pages: 3 })} disabled={syncH1Programs.isPending || !credStatus?.hackerOne.configured}>
              <RefreshCw className={`h-4 w-4 mr-1 ${syncH1Programs.isPending ? "animate-spin" : ""}`} />
              Sync H1
            </Button>
            <Button variant="outline" size="sm" onClick={() => syncBcPrograms.mutate({ pages: 3 })} disabled={syncBcPrograms.isPending || !credStatus?.bugcrowd.configured}>
              <RefreshCw className={`h-4 w-4 mr-1 ${syncBcPrograms.isPending ? "animate-spin" : ""}`} />
              Sync BC
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
                      <Badge variant="outline" className={`text-xs ${p.platform === "hackerone" ? "border-purple-500/50 text-purple-400" : p.platform === "bugcrowd" ? "border-orange-500/50 text-orange-400" : ""}`}>
                        {p.platform === "hackerone" ? "H1" : p.platform === "bugcrowd" ? "BC" : "Manual"}
                      </Badge>
                    </div>
                    <div className="flex items-center gap-3 text-xs text-muted-foreground mt-2">
                      {p.state && <Badge variant={p.state === "open" || p.state === "active" ? "default" : "secondary"} className="text-xs">{p.state}</Badge>}
                      {p.minBounty != null && p.maxBounty != null && (
                        <span>${p.minBounty} - ${p.maxBounty}</span>
                      )}
                      {p.lastSyncedAt && (
                        <span>Synced {new Date(p.lastSyncedAt).toLocaleDateString()}</span>
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
                  <p>No programs tracked yet. Sync from HackerOne/Bugcrowd or add manually.</p>
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
                          {c.matchedEntityType} &middot; Confidence: {Math.round((c.confidenceScore || 0) * 100)}%
                        </p>
                      </div>
                    </div>
                    <div className="flex items-center gap-2">
                      <div className="h-2 w-16 rounded-full overflow-hidden bg-zinc-800">
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

        {/* Domain Matching Tab */}
        <TabsContent value="domain-match" className="space-y-4">
          <Card className="bg-zinc-900/50 border-zinc-800">
            <CardHeader>
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <MapPin className="h-4 w-4 text-cyan-400" />
                Domain-to-Program Matching
              </CardTitle>
              <CardDescription>
                Cross-reference your scanned domains from Domain Intel against bug bounty program scope assets.
                This identifies which of your target domains have active bug bounty programs, helping prioritize
                vulnerability research and understand the threat landscape.
              </CardDescription>
            </CardHeader>
            <CardContent>
              <div className="space-y-4">
                <Button
                  onClick={() => matchDomains.mutate()}
                  disabled={matchDomains.isPending}
                  className="w-full"
                >
                  <Target className={`h-4 w-4 mr-2 ${matchDomains.isPending ? "animate-pulse" : ""}`} />
                  {matchDomains.isPending ? "Matching Domains..." : "Run Domain-to-Program Match"}
                </Button>

                {matchDomains.data && (
                  <div className="space-y-3">
                    <div className="flex items-center justify-between">
                      <p className="text-sm font-medium">{matchDomains.data.total} matches found</p>
                    </div>
                    {matchDomains.data.matches.length > 0 ? (
                      <div className="space-y-2">
                        {matchDomains.data.matches.map((m: any, i: number) => (
                          <div key={i} className="flex items-center justify-between p-3 bg-zinc-800/50 rounded-lg">
                            <div className="flex items-center gap-3">
                              <Badge variant="outline" className="text-xs text-cyan-400 border-cyan-500/30">
                                {m.domain}
                              </Badge>
                              <ChevronRight className="h-3 w-3 text-muted-foreground" />
                              <div>
                                <p className="text-sm font-medium">{m.programName}</p>
                                <p className="text-xs text-muted-foreground">{m.programHandle}</p>
                              </div>
                            </div>
                            <div className="flex items-center gap-2">
                              <Badge variant="outline" className={`text-xs ${m.platform === "hackerone" ? "border-purple-500/50 text-purple-400" : "border-orange-500/50 text-orange-400"}`}>
                                {m.platform === "hackerone" ? "H1" : "BC"}
                              </Badge>
                              <Badge variant="secondary" className="text-xs">
                                {m.matchType === "scope_asset" ? "Scope" : "Handle"}
                              </Badge>
                            </div>
                          </div>
                        ))}
                      </div>
                    ) : (
                      <p className="text-sm text-muted-foreground text-center py-4">
                        No matches found. Sync more programs and run domain scans to build coverage.
                      </p>
                    )}
                  </div>
                )}

                {!matchDomains.data && (
                  <div className="text-center py-8 text-muted-foreground">
                    <Target className="h-12 w-12 mx-auto mb-3 opacity-30" />
                    <p className="text-sm">Click the button above to cross-reference your scanned domains with bug bounty programs.</p>
                    <p className="text-xs mt-1">Requires at least one domain scan and synced programs.</p>
                  </div>
                )}
              </div>
            </CardContent>
          </Card>
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
                        <p className="font-medium text-sm">
                          <span className={s.platform === "hackerone" ? "text-purple-400" : s.platform === "bugcrowd" ? "text-orange-400" : ""}>{s.platform}</span>
                          {" / "}{s.syncType}
                        </p>
                        <p className="text-xs text-muted-foreground">
                          {s.startedAt ? new Date(s.startedAt).toLocaleString() : "Unknown"}
                          {s.itemsSynced != null && ` \u00b7 ${s.itemsSynced} items`}
                          {s.completedAt && s.startedAt && ` \u00b7 ${Math.round((new Date(s.completedAt).getTime() - new Date(s.startedAt).getTime()) / 1000)}s`}
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
      </Tabs>

      {/* Sync Dialog — Multi-platform */}
      <Dialog open={showSyncDialog} onOpenChange={setShowSyncDialog}>
        <DialogContent className="bg-zinc-900 border-zinc-800 max-w-lg">
          <DialogHeader>
            <DialogTitle>Sync Bug Bounty Feeds</DialogTitle>
            <DialogDescription>Pull latest data from HackerOne and Bugcrowd</DialogDescription>
          </DialogHeader>
          <div className="space-y-5">
            {/* HackerOne Section */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-sm font-medium flex items-center gap-2">
                  <div className="h-2 w-2 rounded-full bg-purple-400" />
                  HackerOne
                </h4>
                {credStatus?.hackerOne.configured ? (
                  <Badge className="bg-emerald-500/20 text-emerald-400 text-xs">Connected</Badge>
                ) : (
                  <Badge className="bg-red-500/20 text-red-400 text-xs">Not Configured</Badge>
                )}
              </div>
              <div>
                <Label className="text-xs">Hacktivity Query (Lucene syntax)</Label>
                <Input
                  value={syncQuery}
                  onChange={(e) => setSyncQuery(e.target.value)}
                  className="bg-zinc-800 border-zinc-700 mt-1 text-sm"
                  placeholder="severity_rating:critical OR severity_rating:high"
                  disabled={!credStatus?.hackerOne.configured}
                />
                <p className="text-xs text-muted-foreground mt-1">
                  Filters: severity_rating, asset_type, cwe, cve_ids, reporter, team
                </p>
              </div>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  className="flex-1"
                  onClick={() => syncH1Programs.mutate({ pages: syncPages })}
                  disabled={syncH1Programs.isPending || !credStatus?.hackerOne.configured}
                >
                  {syncH1Programs.isPending ? "Syncing..." : "Sync H1 Programs"}
                </Button>
                <Button
                  size="sm"
                  className="flex-1"
                  onClick={() => { syncHacktivity.mutate({ queryString: syncQuery, pages: syncPages }); }}
                  disabled={syncHacktivity.isPending || !credStatus?.hackerOne.configured}
                >
                  {syncHacktivity.isPending ? "Syncing..." : "Sync H1 Hacktivity"}
                </Button>
              </div>
            </div>

            <div className="border-t border-zinc-800" />

            {/* Bugcrowd Section */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h4 className="text-sm font-medium flex items-center gap-2">
                  <div className="h-2 w-2 rounded-full bg-orange-400" />
                  Bugcrowd
                </h4>
                {credStatus?.bugcrowd.configured ? (
                  <Badge className="bg-emerald-500/20 text-emerald-400 text-xs">Connected</Badge>
                ) : (
                  <Badge className="bg-red-500/20 text-red-400 text-xs">Not Configured</Badge>
                )}
              </div>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  className="flex-1"
                  onClick={() => syncBcPrograms.mutate({ pages: syncPages })}
                  disabled={syncBcPrograms.isPending || !credStatus?.bugcrowd.configured}
                >
                  {syncBcPrograms.isPending ? "Syncing..." : "Sync BC Programs"}
                </Button>
                <Button
                  size="sm"
                  className="flex-1"
                  onClick={() => syncBcSubmissions.mutate({ pages: syncPages })}
                  disabled={syncBcSubmissions.isPending || !credStatus?.bugcrowd.configured}
                >
                  {syncBcSubmissions.isPending ? "Syncing..." : "Sync BC Submissions"}
                </Button>
              </div>
            </div>

            <div className="border-t border-zinc-800" />

            {/* Shared Settings */}
            <div>
              <Label className="text-xs">Pages to Fetch (25 items/page)</Label>
              <Input
                type="number"
                value={syncPages}
                onChange={(e) => setSyncPages(Number(e.target.value))}
                min={1}
                max={10}
                className="bg-zinc-800 border-zinc-700 mt-1 w-24"
              />
            </div>
          </div>
          <DialogFooter>
            <Button variant="outline" onClick={() => setShowSyncDialog(false)}>Close</Button>
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
  );
}
