import AppShell from "@/components/AppShell";
import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Input } from "@/components/ui/input";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import {
  Shield, AlertTriangle, Search, Bug, Calendar,
  TrendingUp, ExternalLink, Filter, ChevronDown, ChevronUp,
  Zap, Globe, Database, Activity, RefreshCw, Crosshair,
  AlertCircle, CheckCircle, XCircle, Clock, Skull,
} from "lucide-react";

// Severity color helpers
function severityColor(sev: string) {
  switch (sev) {
    case "critical": return "text-red-400 bg-red-500/10 border-red-500/30";
    case "high": return "text-orange-400 bg-orange-500/10 border-orange-500/30";
    case "medium": return "text-yellow-400 bg-yellow-500/10 border-yellow-500/30";
    case "low": return "text-blue-400 bg-blue-500/10 border-blue-500/30";
    default: return "text-muted-foreground bg-muted/30 border-border";
  }
}

function severityBadge(sev: string) {
  const colors: Record<string, string> = {
    critical: "bg-red-600/80 text-white",
    high: "bg-orange-600/80 text-white",
    medium: "bg-yellow-600/80 text-white",
    low: "bg-blue-600/80 text-white",
    unknown: "bg-zinc-600/80 text-white",
  };
  return colors[sev] || colors.unknown;
}

function sourceLabel(src: string) {
  const labels: Record<string, { label: string; color: string; icon: string }> = {
    cisa_kev: { label: "CISA KEV", color: "bg-red-600/80 text-white", icon: "🛡️" },
    project_zero: { label: "Project Zero", color: "bg-purple-600/80 text-white", icon: "🔬" },
    nvd: { label: "NVD", color: "bg-blue-600/80 text-white", icon: "📋" },
    circl: { label: "CIRCL", color: "bg-teal-600/80 text-white", icon: "🌐" },
    exploit_db: { label: "Exploit-DB", color: "bg-amber-600/80 text-white", icon: "💣" },
  };
  return labels[src] || { label: src, color: "bg-zinc-600/80 text-white", icon: "📄" };
}

function feedHealthIcon(status: string) {
  switch (status) {
    case "ok": return <CheckCircle className="h-3.5 w-3.5 text-green-400" />;
    case "stale": return <Clock className="h-3.5 w-3.5 text-yellow-400" />;
    case "error": return <XCircle className="h-3.5 w-3.5 text-red-400" />;
    default: return <AlertCircle className="h-3.5 w-3.5 text-muted-foreground" />;
  }
}

export default function KevDashboard() {
  const [activeTab, setActiveTab] = useState("overview");
  const [searchQuery, setSearchQuery] = useState("");
  const [severityFilter, setSeverityFilter] = useState("");
  const [sourceFilter, setSourceFilter] = useState("");
  const [expandedCve, setExpandedCve] = useState<string | null>(null);
  const [kevVendorFilter, setKevVendorFilter] = useState("");
  const [kevRansomwareOnly, setKevRansomwareOnly] = useState(false);
  const [syncStatus, setSyncStatus] = useState<"idle" | "syncing" | "success" | "error">("idle");

  // Trigger sync mutation
  const triggerSync = trpc.calderaProxy.triggerSync.useMutation();

  // Unified feed stats
  const { data: feedStats, isLoading: statsLoading, refetch: refetchStats } =
    trpc.calderaProxy.getVulnFeedStats.useQuery();

  // 0-day entries
  const { data: zeroDays, isLoading: zeroDaysLoading } =
    trpc.calderaProxy.getRecentZeroDays.useQuery({ limit: 100 });

  // Weaponized CVEs
  const { data: weaponized, isLoading: weaponizedLoading } =
    trpc.calderaProxy.getWeaponizedCves.useQuery({ limit: 100 });

  // KEV catalog (existing)
  const { data: catalog, isLoading: catalogLoading } =
    trpc.calderaProxy.getKevCatalog.useQuery();

  // Search
  const [searchInput, setSearchInput] = useState("");
  const { data: searchResults, isLoading: searchLoading } =
    trpc.calderaProxy.searchVulnerabilities.useQuery(
      {
        query: searchQuery,
        severity: severityFilter || undefined,
        source: (sourceFilter as any) || undefined,
      },
      { enabled: !!searchQuery }
    );

  // KEV search
  const { data: kevSearchResults } = trpc.calderaProxy.searchKev.useQuery(
    {
      query: searchQuery || undefined,
      vendor: kevVendorFilter || undefined,
      ransomwareOnly: kevRansomwareOnly || undefined,
      limit: 200,
    },
    { enabled: activeTab === "kev" && (!!searchQuery || !!kevVendorFilter || kevRansomwareOnly) }
  );

  const kevVulns = useMemo(() => {
    if (activeTab === "kev" && (searchQuery || kevVendorFilter || kevRansomwareOnly)) {
      return kevSearchResults?.results || [];
    }
    return catalog?.vulnerabilities || [];
  }, [catalog, kevSearchResults, searchQuery, kevVendorFilter, kevRansomwareOnly, activeTab]);

  const handleSearch = () => {
    setSearchQuery(searchInput);
  };

  return (
    <AppShell>
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold flex items-center gap-2">
            <Shield className="h-6 w-6 text-red-500" />
            Vulnerability Intelligence
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Unified feed aggregating CISA KEV, Google Project Zero 0-days, NVD CVEs, CIRCL, and Exploit-DB weaponization data
          </p>
        </div>
        <Button
          variant="outline"
          size="sm"
          disabled={syncStatus === "syncing"}
          onClick={async () => {
            setSyncStatus("syncing");
            try {
              await triggerSync.mutateAsync();
              setSyncStatus("success");
              // Refetch all data after sync
              refetchStats();
              setTimeout(() => setSyncStatus("idle"), 3000);
            } catch {
              setSyncStatus("error");
              setTimeout(() => setSyncStatus("idle"), 3000);
            }
          }}
          className={`gap-1.5 ${syncStatus === "success" ? "border-green-500/50 text-green-400" : syncStatus === "error" ? "border-red-500/50 text-red-400" : ""}`}
        >
          <RefreshCw className={`h-3.5 w-3.5 ${syncStatus === "syncing" ? "animate-spin" : ""}`} />
          {syncStatus === "syncing" ? "Syncing Feeds..." : syncStatus === "success" ? "Feeds Refreshed" : syncStatus === "error" ? "Sync Failed" : "Refresh Feeds"}
        </Button>
      </div>

      {/* Feed Health Bar */}
      {feedStats && (
        <div className="flex items-center gap-4 p-3 rounded border border-border/50 bg-card/50">
          <span className="text-xs font-medium text-muted-foreground">FEED STATUS</span>
          {Object.entries(feedStats.feedHealth).map(([src, status]) => {
            const info = sourceLabel(src);
            return (
              <div key={src} className="flex items-center gap-1.5 text-xs">
                {feedHealthIcon(status as string)}
                <span className="text-foreground/80">{info.label}</span>
              </div>
            );
          })}
          <span className="ml-auto text-[10px] text-muted-foreground">
            Last updated: {new Date(feedStats.lastUpdated).toLocaleString()}
          </span>
        </div>
      )}

      {/* Stats Cards */}
      <div className="grid grid-cols-2 md:grid-cols-4 lg:grid-cols-7 gap-3">
        <Card className="border-red-500/30 bg-red-500/5">
          <CardContent className="pt-3 pb-2 px-3">
            <div className="flex items-center gap-1.5">
              <Database className="h-3.5 w-3.5 text-red-500" />
              <span className="text-[10px] text-muted-foreground">Total CVEs</span>
            </div>
            <div className="text-xl font-bold text-red-400 mt-0.5">
              {statsLoading ? "..." : feedStats?.totalEntries?.toLocaleString()}
            </div>
          </CardContent>
        </Card>
        <Card className="border-orange-500/30 bg-orange-500/5">
          <CardContent className="pt-3 pb-2 px-3">
            <div className="flex items-center gap-1.5">
              <Shield className="h-3.5 w-3.5 text-orange-500" />
              <span className="text-[10px] text-muted-foreground">CISA KEV</span>
            </div>
            <div className="text-xl font-bold text-orange-400 mt-0.5">
              {statsLoading ? "..." : feedStats?.kevListedCount?.toLocaleString()}
            </div>
          </CardContent>
        </Card>
        <Card className="border-purple-500/30 bg-purple-500/5">
          <CardContent className="pt-3 pb-2 px-3">
            <div className="flex items-center gap-1.5">
              <Zap className="h-3.5 w-3.5 text-purple-500" />
              <span className="text-[10px] text-muted-foreground">0-Day Wild</span>
            </div>
            <div className="text-xl font-bold text-purple-400 mt-0.5">
              {statsLoading ? "..." : feedStats?.inTheWildCount?.toLocaleString()}
            </div>
          </CardContent>
        </Card>
        <Card className="border-amber-500/30 bg-amber-500/5">
          <CardContent className="pt-3 pb-2 px-3">
            <div className="flex items-center gap-1.5">
              <Crosshair className="h-3.5 w-3.5 text-amber-500" />
              <span className="text-[10px] text-muted-foreground">Exploits</span>
            </div>
            <div className="text-xl font-bold text-amber-400 mt-0.5">
              {statsLoading ? "..." : feedStats?.exploitAvailableCount?.toLocaleString()}
            </div>
          </CardContent>
        </Card>
        <Card className="border-pink-500/30 bg-pink-500/5">
          <CardContent className="pt-3 pb-2 px-3">
            <div className="flex items-center gap-1.5">
              <Skull className="h-3.5 w-3.5 text-pink-500" />
              <span className="text-[10px] text-muted-foreground">Ransomware</span>
            </div>
            <div className="text-xl font-bold text-pink-400 mt-0.5">
              {statsLoading ? "..." : feedStats?.ransomwareLinkedCount?.toLocaleString()}
            </div>
          </CardContent>
        </Card>
        <Card className="border-red-600/30 bg-red-600/5">
          <CardContent className="pt-3 pb-2 px-3">
            <div className="flex items-center gap-1.5">
              <AlertTriangle className="h-3.5 w-3.5 text-red-600" />
              <span className="text-[10px] text-muted-foreground">Critical</span>
            </div>
            <div className="text-xl font-bold text-red-500 mt-0.5">
              {statsLoading ? "..." : feedStats?.bySeverity?.critical?.toLocaleString()}
            </div>
          </CardContent>
        </Card>
        <Card className="border-yellow-500/30 bg-yellow-500/5">
          <CardContent className="pt-3 pb-2 px-3">
            <div className="flex items-center gap-1.5">
              <TrendingUp className="h-3.5 w-3.5 text-yellow-500" />
              <span className="text-[10px] text-muted-foreground">High</span>
            </div>
            <div className="text-xl font-bold text-yellow-400 mt-0.5">
              {statsLoading ? "..." : feedStats?.bySeverity?.high?.toLocaleString()}
            </div>
          </CardContent>
        </Card>
      </div>

      {/* Severity Breakdown Bar */}
      {feedStats && feedStats.totalEntries > 0 && (
        <div className="space-y-1.5">
          <div className="flex items-center justify-between text-xs text-muted-foreground">
            <span>Severity Distribution</span>
            <span>{feedStats.totalEntries.toLocaleString()} total vulnerabilities</span>
          </div>
          <div className="flex h-3 rounded overflow-hidden border border-border/30">
            {["critical", "high", "medium", "low", "unknown"].map(sev => {
              const count = feedStats.bySeverity[sev] || 0;
              const pct = (count / feedStats.totalEntries) * 100;
              if (pct < 0.5) return null;
              const colors: Record<string, string> = {
                critical: "bg-red-500",
                high: "bg-orange-500",
                medium: "bg-yellow-500",
                low: "bg-blue-500",
                unknown: "bg-zinc-500",
              };
              return (
                <div
                  key={sev}
                  className={`${colors[sev]} relative group`}
                  style={{ width: `${pct}%` }}
                  title={`${sev}: ${count} (${pct.toFixed(1)}%)`}
                >
                  <div className="absolute inset-0 flex items-center justify-center opacity-0 group-hover:opacity-100 transition-opacity">
                    <span className="text-[9px] font-bold text-white drop-shadow">{count}</span>
                  </div>
                </div>
              );
            })}
          </div>
          <div className="flex gap-4 text-[10px] text-muted-foreground">
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-red-500" /> Critical</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-orange-500" /> High</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-yellow-500" /> Medium</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-blue-500" /> Low</span>
            <span className="flex items-center gap-1"><span className="w-2 h-2 rounded-sm bg-zinc-500" /> Unknown</span>
          </div>
        </div>
      )}

      {/* Source Breakdown */}
      {feedStats && (
        <div className="grid grid-cols-5 gap-3">
          {(["cisa_kev", "project_zero", "nvd", "circl", "exploit_db"] as const).map(src => {
            const info = sourceLabel(src);
            const count = feedStats.bySource[src] || 0;
            const health = feedStats.feedHealth[src];
            return (
              <Card
                key={src}
                className={`cursor-pointer transition-all hover:border-accent/50 ${sourceFilter === src ? "border-accent ring-1 ring-accent/30" : ""}`}
                onClick={() => {
                  setSourceFilter(sourceFilter === src ? "" : src);
                  setActiveTab("search");
                  if (!searchQuery) setSearchQuery(" ");
                }}
              >
                <CardContent className="py-2.5 px-3">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-1.5">
                      <span className="text-sm">{info.icon}</span>
                      <span className="text-xs font-medium">{info.label}</span>
                    </div>
                    {feedHealthIcon(health)}
                  </div>
                  <div className="text-lg font-bold mt-1">{count.toLocaleString()}</div>
                </CardContent>
              </Card>
            );
          })}
        </div>
      )}

      {/* Main Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList>
          <TabsTrigger value="overview" className="gap-1.5">
            <Activity className="h-3.5 w-3.5" /> Overview
          </TabsTrigger>
          <TabsTrigger value="zero-days" className="gap-1.5">
            <Zap className="h-3.5 w-3.5" /> 0-Day Tracker
          </TabsTrigger>
          <TabsTrigger value="weaponized" className="gap-1.5">
            <Crosshair className="h-3.5 w-3.5" /> Weaponized
          </TabsTrigger>
          <TabsTrigger value="kev" className="gap-1.5">
            <Shield className="h-3.5 w-3.5" /> CISA KEV
          </TabsTrigger>
          <TabsTrigger value="search" className="gap-1.5">
            <Search className="h-3.5 w-3.5" /> Search All
          </TabsTrigger>
        </TabsList>

        {/* ─── Overview Tab ─── */}
        <TabsContent value="overview" className="space-y-4 mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Recent 0-Days */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Zap className="h-4 w-4 text-purple-400" />
                  Recent 0-Day Exploitations
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-1.5 max-h-[400px] overflow-y-auto">
                {zeroDaysLoading ? (
                  <div className="text-center py-8 text-muted-foreground text-sm">Loading 0-day data...</div>
                ) : (zeroDays || []).slice(0, 15).map((vuln: any) => (
                  <VulnRow key={vuln.cveId} vuln={vuln} expanded={expandedCve === vuln.cveId} onToggle={() => setExpandedCve(expandedCve === vuln.cveId ? null : vuln.cveId)} />
                ))}
                {!zeroDaysLoading && (zeroDays || []).length === 0 && (
                  <div className="text-center py-8 text-muted-foreground text-sm">No 0-day data available yet. Feeds are loading...</div>
                )}
              </CardContent>
            </Card>

            {/* Weaponized CVEs */}
            <Card>
              <CardHeader className="pb-2">
                <CardTitle className="text-sm flex items-center gap-2">
                  <Crosshair className="h-4 w-4 text-amber-400" />
                  Recently Weaponized CVEs
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-1.5 max-h-[400px] overflow-y-auto">
                {weaponizedLoading ? (
                  <div className="text-center py-8 text-muted-foreground text-sm">Loading exploit data...</div>
                ) : (weaponized || []).slice(0, 15).map((vuln: any) => (
                  <VulnRow key={vuln.cveId} vuln={vuln} expanded={expandedCve === vuln.cveId} onToggle={() => setExpandedCve(expandedCve === vuln.cveId ? null : vuln.cveId)} />
                ))}
                {!weaponizedLoading && (weaponized || []).length === 0 && (
                  <div className="text-center py-8 text-muted-foreground text-sm">No weaponized CVE data available yet.</div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* KEV Highlights */}
          <Card>
            <CardHeader className="pb-2">
              <CardTitle className="text-sm flex items-center gap-2">
                <Shield className="h-4 w-4 text-red-400" />
                Latest CISA KEV Additions
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-1.5 max-h-[300px] overflow-y-auto">
              {catalogLoading ? (
                <div className="text-center py-8 text-muted-foreground text-sm">Loading KEV catalog...</div>
              ) : (catalog?.vulnerabilities || []).slice(0, 10).map((vuln: any) => (
                <KevRow key={vuln.cveID} vuln={vuln} expanded={expandedCve === vuln.cveID} onToggle={() => setExpandedCve(expandedCve === vuln.cveID ? null : vuln.cveID)} />
              ))}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ─── 0-Day Tracker Tab ─── */}
        <TabsContent value="zero-days" className="space-y-4 mt-4">
          <div className="flex items-center gap-3 mb-2">
            <Zap className="h-5 w-5 text-purple-400" />
            <div>
              <h2 className="text-lg font-semibold">0-Day In-The-Wild Tracker</h2>
              <p className="text-xs text-muted-foreground">
                Confirmed 0-day vulnerabilities exploited in the wild — sourced from Google Project Zero and cross-referenced with CISA KEV
              </p>
            </div>
            <Badge variant="outline" className="ml-auto">
              {zeroDays?.length || 0} entries
            </Badge>
          </div>
          <div className="space-y-2">
            {zeroDaysLoading ? (
              <div className="text-center py-12 text-muted-foreground">Loading 0-day tracker...</div>
            ) : (zeroDays || []).map((vuln: any) => (
              <VulnRow key={vuln.cveId} vuln={vuln} expanded={expandedCve === vuln.cveId} onToggle={() => setExpandedCve(expandedCve === vuln.cveId ? null : vuln.cveId)} />
            ))}
            {!zeroDaysLoading && (zeroDays || []).length === 0 && (
              <div className="text-center py-12 text-muted-foreground">
                No 0-day data available. The Google Project Zero feed may still be loading.
              </div>
            )}
          </div>
        </TabsContent>

        {/* ─── Weaponized Tab ─── */}
        <TabsContent value="weaponized" className="space-y-4 mt-4">
          <div className="flex items-center gap-3 mb-2">
            <Crosshair className="h-5 w-5 text-amber-400" />
            <div>
              <h2 className="text-lg font-semibold">Weaponized CVEs</h2>
              <p className="text-xs text-muted-foreground">
                CVEs with confirmed public exploits in Exploit-DB — indicates active weaponization risk
              </p>
            </div>
            <Badge variant="outline" className="ml-auto">
              {weaponized?.length || 0} entries
            </Badge>
          </div>
          <div className="space-y-2">
            {weaponizedLoading ? (
              <div className="text-center py-12 text-muted-foreground">Loading weaponized CVEs...</div>
            ) : (weaponized || []).map((vuln: any) => (
              <VulnRow key={vuln.cveId} vuln={vuln} expanded={expandedCve === vuln.cveId} onToggle={() => setExpandedCve(expandedCve === vuln.cveId ? null : vuln.cveId)} />
            ))}
            {!weaponizedLoading && (weaponized || []).length === 0 && (
              <div className="text-center py-12 text-muted-foreground">
                No weaponized CVE data available yet.
              </div>
            )}
          </div>
        </TabsContent>

        {/* ─── CISA KEV Tab ─── */}
        <TabsContent value="kev" className="space-y-4 mt-4">
          <div className="flex items-center gap-3 mb-2">
            <Shield className="h-5 w-5 text-red-400" />
            <div>
              <h2 className="text-lg font-semibold">CISA Known Exploited Vulnerabilities</h2>
              <p className="text-xs text-muted-foreground">
                Mandatory remediation catalog — actively exploited vulnerabilities tracked by CISA
              </p>
            </div>
            {catalog && (
              <div className="ml-auto text-right text-[10px] text-muted-foreground">
                <div>v{catalog.catalogVersion}</div>
                <div>{catalog.dateReleased}</div>
              </div>
            )}
          </div>

          {/* KEV Stats */}
          <div className="grid grid-cols-4 gap-3">
            <Card className="border-red-500/30 bg-red-500/5">
              <CardContent className="pt-3 pb-2 px-3">
                <div className="text-[10px] text-muted-foreground">Total KEVs</div>
                <div className="text-xl font-bold text-red-400">{catalogLoading ? "..." : catalog?.totalVulnerabilities?.toLocaleString()}</div>
              </CardContent>
            </Card>
            <Card className="border-orange-500/30 bg-orange-500/5">
              <CardContent className="pt-3 pb-2 px-3">
                <div className="text-[10px] text-muted-foreground">Ransomware-Linked</div>
                <div className="text-xl font-bold text-orange-400">{catalogLoading ? "..." : catalog?.ransomwareCount?.toLocaleString()}</div>
              </CardContent>
            </Card>
            <Card className="border-yellow-500/30 bg-yellow-500/5">
              <CardContent className="pt-3 pb-2 px-3">
                <div className="text-[10px] text-muted-foreground">Added (90 days)</div>
                <div className="text-xl font-bold text-yellow-400">{catalogLoading ? "..." : catalog?.recentlyAdded?.toLocaleString()}</div>
              </CardContent>
            </Card>
            <Card className="border-blue-500/30 bg-blue-500/5">
              <CardContent className="pt-3 pb-2 px-3">
                <div className="text-[10px] text-muted-foreground">Showing</div>
                <div className="text-xl font-bold text-blue-400">{kevVulns.length.toLocaleString()}</div>
              </CardContent>
            </Card>
          </div>

          {/* KEV Filters */}
          <div className="flex flex-wrap gap-3 items-center">
            <div className="relative flex-1 min-w-[250px]">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search CVE ID, vulnerability name, vendor, product..."
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                className="pl-9"
              />
            </div>
            <div className="relative min-w-[180px]">
              <Filter className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Filter by vendor..."
                value={kevVendorFilter}
                onChange={(e) => setKevVendorFilter(e.target.value)}
                className="pl-9"
              />
            </div>
            <Button
              variant={kevRansomwareOnly ? "destructive" : "outline"}
              size="sm"
              onClick={() => setKevRansomwareOnly(!kevRansomwareOnly)}
            >
              <AlertTriangle className="h-3.5 w-3.5 mr-1" />
              Ransomware Only
            </Button>
            {(searchQuery || kevVendorFilter || kevRansomwareOnly) && (
              <Button variant="ghost" size="sm" onClick={() => { setSearchQuery(""); setKevVendorFilter(""); setKevRansomwareOnly(false); }}>
                Clear
              </Button>
            )}
          </div>

          {/* KEV List */}
          <div className="space-y-2">
            {catalogLoading ? (
              <div className="text-center py-12 text-muted-foreground">Loading KEV catalog...</div>
            ) : kevVulns.map((vuln: any) => (
              <KevRow key={vuln.cveID} vuln={vuln} expanded={expandedCve === vuln.cveID} onToggle={() => setExpandedCve(expandedCve === vuln.cveID ? null : vuln.cveID)} />
            ))}
            {!catalogLoading && kevVulns.length === 0 && (
              <div className="text-center py-12 text-muted-foreground">No KEV entries match your filters.</div>
            )}
          </div>
        </TabsContent>

        {/* ─── Search All Tab ─── */}
        <TabsContent value="search" className="space-y-4 mt-4">
          <div className="flex items-center gap-3 mb-2">
            <Search className="h-5 w-5 text-accent" />
            <div>
              <h2 className="text-lg font-semibold">Search All Vulnerability Feeds</h2>
              <p className="text-xs text-muted-foreground">
                Cross-feed search across CISA KEV, Project Zero, NVD, CIRCL, and Exploit-DB
              </p>
            </div>
          </div>

          {/* Search Bar */}
          <div className="flex gap-3">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 h-4 w-4 text-muted-foreground" />
              <Input
                placeholder="Search by CVE ID, vendor, product, description..."
                value={searchInput}
                onChange={(e) => setSearchInput(e.target.value)}
                onKeyDown={(e) => e.key === "Enter" && handleSearch()}
                className="pl-9"
              />
            </div>
            <Button onClick={handleSearch} className="gap-1.5">
              <Search className="h-3.5 w-3.5" /> Search
            </Button>
          </div>

          {/* Filters */}
          <div className="flex flex-wrap gap-2">
            <span className="text-xs text-muted-foreground self-center mr-1">Severity:</span>
            {["critical", "high", "medium", "low"].map(sev => (
              <Button
                key={sev}
                variant={severityFilter === sev ? "default" : "outline"}
                size="sm"
                className="text-xs h-7 capitalize"
                onClick={() => setSeverityFilter(severityFilter === sev ? "" : sev)}
              >
                {sev}
              </Button>
            ))}
            <span className="text-xs text-muted-foreground self-center ml-3 mr-1">Source:</span>
            {(["cisa_kev", "project_zero", "nvd", "circl", "exploit_db"] as const).map(src => {
              const info = sourceLabel(src);
              return (
                <Button
                  key={src}
                  variant={sourceFilter === src ? "default" : "outline"}
                  size="sm"
                  className="text-xs h-7"
                  onClick={() => setSourceFilter(sourceFilter === src ? "" : src)}
                >
                  {info.icon} {info.label}
                </Button>
              );
            })}
            {(severityFilter || sourceFilter) && (
              <Button variant="ghost" size="sm" className="text-xs h-7" onClick={() => { setSeverityFilter(""); setSourceFilter(""); }}>
                Clear Filters
              </Button>
            )}
          </div>

          {/* Results */}
          {searchLoading ? (
            <div className="text-center py-12 text-muted-foreground">Searching vulnerability feeds...</div>
          ) : searchResults ? (
            <div className="space-y-2">
              <div className="text-xs text-muted-foreground">{searchResults.length} results</div>
              {searchResults.map((vuln: any) => (
                <VulnRow key={vuln.cveId} vuln={vuln} expanded={expandedCve === vuln.cveId} onToggle={() => setExpandedCve(expandedCve === vuln.cveId ? null : vuln.cveId)} />
              ))}
              {searchResults.length === 0 && (
                <div className="text-center py-12 text-muted-foreground">No vulnerabilities match your search.</div>
              )}
            </div>
          ) : (
            <div className="text-center py-12 text-muted-foreground">
              Enter a search query to search across all vulnerability feeds.
            </div>
          )}
        </TabsContent>
      </Tabs>
    </div>
    </AppShell>
  );
}

// ─── Unified Vuln Row Component ───
function VulnRow({ vuln, expanded, onToggle }: { vuln: any; expanded: boolean; onToggle: () => void }) {
  return (
    <Card
      className={`cursor-pointer transition-all hover:border-accent/40 ${expanded ? "border-accent/60" : ""}`}
      onClick={onToggle}
    >
      <CardContent className="py-2.5 px-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="font-mono font-bold text-sm text-accent">{vuln.cveId}</span>
              <Badge className={`text-[9px] ${severityBadge(vuln.severity)}`}>
                {vuln.severity?.toUpperCase()}
              </Badge>
              {vuln.cvssScore && (
                <Badge variant="outline" className="text-[9px] font-mono">
                  CVSS {vuln.cvssScore}
                </Badge>
              )}
              {vuln.kevListed && (
                <Badge className="bg-red-600/80 text-white text-[9px]">KEV</Badge>
              )}
              {vuln.inTheWild && (
                <Badge className="bg-purple-600/80 text-white text-[9px]">0-DAY</Badge>
              )}
              {vuln.exploitAvailable && !vuln.inTheWild && (
                <Badge className="bg-amber-600/80 text-white text-[9px]">EXPLOIT</Badge>
              )}
              {vuln.ransomwareLinked && (
                <Badge className="bg-pink-600/80 text-white text-[9px]">RANSOMWARE</Badge>
              )}
            </div>
            <p className="text-xs text-foreground/80 mt-1 truncate">
              {vuln.title !== vuln.cveId ? vuln.title : vuln.description?.slice(0, 120)}
            </p>
            <div className="flex items-center gap-2 mt-1">
              {vuln.vendor && <span className="text-[10px] text-muted-foreground">{vuln.vendor}</span>}
              {vuln.product && <span className="text-[10px] text-muted-foreground">/ {vuln.product}</span>}
              {vuln.sources?.map((s: string) => {
                const info = sourceLabel(s);
                return (
                  <Badge key={s} variant="outline" className="text-[8px] h-4 px-1">
                    {info.icon} {info.label}
                  </Badge>
                );
              })}
            </div>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <span className="text-[10px] text-muted-foreground">{vuln.datePublished?.slice(0, 10)}</span>
            {expanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
          </div>
        </div>

        {expanded && (
          <div className="mt-3 pt-3 border-t border-border/50 space-y-2">
            <p className="text-sm text-muted-foreground">{vuln.description}</p>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3 text-xs">
              {vuln.attackVector && (
                <div>
                  <span className="text-muted-foreground">Attack Vector:</span>
                  <p className="text-foreground/80 mt-0.5">{vuln.attackVector}</p>
                </div>
              )}
              {vuln.attackComplexity && (
                <div>
                  <span className="text-muted-foreground">Complexity:</span>
                  <p className="text-foreground/80 mt-0.5">{vuln.attackComplexity}</p>
                </div>
              )}
              {vuln.exploitDbId && (
                <div>
                  <span className="text-muted-foreground">Exploit-DB:</span>
                  <p className="text-foreground/80 mt-0.5">EDB-{vuln.exploitDbId}</p>
                </div>
              )}
              {vuln.patchAvailable !== undefined && (
                <div>
                  <span className="text-muted-foreground">Patch:</span>
                  <p className="text-foreground/80 mt-0.5">{vuln.patchAvailable ? "Available" : "None"}</p>
                </div>
              )}
            </div>
            <div className="flex gap-2 mt-2">
              <a
                href={`https://nvd.nist.gov/vuln/detail/${vuln.cveId}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-blue-400 hover:underline flex items-center gap-1"
                onClick={(e) => e.stopPropagation()}
              >
                <ExternalLink className="h-3 w-3" /> NVD
              </a>
              <a
                href={`https://www.cisa.gov/known-exploited-vulnerabilities-catalog`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-blue-400 hover:underline flex items-center gap-1"
                onClick={(e) => e.stopPropagation()}
              >
                <ExternalLink className="h-3 w-3" /> CISA
              </a>
              {vuln.exploitDbId && (
                <a
                  href={`https://www.exploit-db.com/exploits/${vuln.exploitDbId}`}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="text-xs text-amber-400 hover:underline flex items-center gap-1"
                  onClick={(e) => e.stopPropagation()}
                >
                  <ExternalLink className="h-3 w-3" /> Exploit-DB
                </a>
              )}
              <a
                href={`https://cve.circl.lu/cve/${vuln.cveId}`}
                target="_blank"
                rel="noopener noreferrer"
                className="text-xs text-teal-400 hover:underline flex items-center gap-1"
                onClick={(e) => e.stopPropagation()}
              >
                <ExternalLink className="h-3 w-3" /> CIRCL
              </a>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── KEV Row Component ───
function KevRow({ vuln, expanded, onToggle }: { vuln: any; expanded: boolean; onToggle: () => void }) {
  return (
    <Card
      className={`cursor-pointer transition-all hover:border-red-500/40 ${expanded ? "border-red-500/60" : ""}`}
      onClick={onToggle}
    >
      <CardContent className="py-2.5 px-3">
        <div className="flex items-start justify-between gap-3">
          <div className="flex-1 min-w-0">
            <div className="flex items-center gap-1.5 flex-wrap">
              <span className="font-mono font-bold text-red-400 text-sm">{vuln.cveID}</span>
              <Badge variant="outline" className="text-[9px]">{vuln.vendorProject}</Badge>
              <Badge variant="secondary" className="text-[9px]">{vuln.product}</Badge>
              {vuln.knownRansomwareCampaignUse === "Known" && (
                <Badge className="bg-orange-600/80 text-white text-[9px]">RANSOMWARE</Badge>
              )}
            </div>
            <p className="text-xs text-foreground/80 mt-1 truncate">{vuln.vulnerabilityName}</p>
          </div>
          <div className="flex items-center gap-2 shrink-0">
            <span className="text-[10px] text-muted-foreground">{vuln.dateAdded}</span>
            {expanded ? <ChevronUp className="h-3.5 w-3.5" /> : <ChevronDown className="h-3.5 w-3.5" />}
          </div>
        </div>

        {expanded && (
          <div className="mt-3 pt-3 border-t border-border/50 space-y-2">
            <p className="text-sm text-muted-foreground">{vuln.shortDescription}</p>
            <div className="grid grid-cols-2 gap-3 text-xs">
              <div>
                <span className="text-muted-foreground">Required Action:</span>
                <p className="text-foreground/80 mt-0.5">{vuln.requiredAction}</p>
              </div>
              <div>
                <span className="text-muted-foreground">Due Date:</span>
                <p className="text-foreground/80 mt-0.5">{vuln.dueDate}</p>
              </div>
            </div>
            {vuln.notes && vuln.notes !== "N/A" && (
              <div className="text-xs">
                <span className="text-muted-foreground">Notes:</span>
                <p className="text-foreground/80 mt-0.5">{vuln.notes}</p>
              </div>
            )}
            <div className="flex gap-2 mt-2">
              <a href={`https://nvd.nist.gov/vuln/detail/${vuln.cveID}`} target="_blank" rel="noopener noreferrer" className="text-xs text-blue-400 hover:underline flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                <ExternalLink className="h-3 w-3" /> NVD
              </a>
              <a href="https://www.cisa.gov/known-exploited-vulnerabilities-catalog" target="_blank" rel="noopener noreferrer" className="text-xs text-blue-400 hover:underline flex items-center gap-1" onClick={(e) => e.stopPropagation()}>
                <ExternalLink className="h-3 w-3" /> CISA
              </a>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}
