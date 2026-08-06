import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import {
  Flame, Search, RefreshCw, ExternalLink, Shield, AlertTriangle,
  Bug, Filter, ChevronDown, ChevronUp, XCircle, CheckCircle2,
  BarChart3, TrendingUp, Clock, Eye, Crosshair, Database,
} from "lucide-react";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { toast } from "sonner";

// ─── Types ──────────────────────────────────────────────────────────────────────

type TabId = "search" | "browse" | "matches" | "analytics";

const SEVERITY_STYLES = {
  critical: "bg-red-500/15 text-red-400 border-red-500/40",
  high: "bg-orange-500/15 text-orange-400 border-orange-500/40",
  medium: "bg-yellow-500/15 text-yellow-400 border-yellow-500/40",
  low: "bg-green-500/15 text-green-400 border-green-500/40",
};

const CONFIDENCE_STYLES = {
  high: "bg-red-500/15 text-red-400",
  medium: "bg-orange-500/15 text-orange-400",
  low: "bg-yellow-500/15 text-yellow-400",
};

const MATCH_TYPE_LABELS = {
  cve_exact: "CVE Exact",
  vendor_product: "Vendor+Product",
  product_fuzzy: "Product Fuzzy",
};

// ─── Component ──────────────────────────────────────────────────────────────────

export default function ZeroDayTracker() {
  const [activeTab, setActiveTab] = useState<TabId>("search");
  const [searchQuery, setSearchQuery] = useState("");
  const [activeSearch, setActiveSearch] = useState("");
  const [browseSearch, setBrowseSearch] = useState("");
  const [browseVendor, setBrowseVendor] = useState("");
  const [browseYear, setBrowseYear] = useState<number | undefined>();
  const [browseOffset, setBrowseOffset] = useState(0);
  const [expandedEntry, setExpandedEntry] = useState<string | null>(null);

  // ─── Data Queries ───────────────────────────────────────────────────────────

  const feedStatus = trpc.zeroDay.getFeedStatus.useQuery(undefined, {
    staleTime: 5 * 60 * 1000,
  });

  const searchResults = trpc.zeroDay.quickSearch.useQuery(
    { query: activeSearch },
    { enabled: activeSearch.length > 0, staleTime: 30 * 1000 }
  );

  const browseEntries = trpc.zeroDay.getEntries.useQuery(
    {
      search: browseSearch || undefined,
      vendor: browseVendor || undefined,
      year: browseYear,
      limit: 50,
      offset: browseOffset,
    },
    { staleTime: 60 * 1000 }
  );

  const recentMatches = trpc.zeroDay.getRecentMatches.useQuery(
    { limit: 100 },
    { staleTime: 30 * 1000 }
  );

  const matchStats = trpc.zeroDay.getMatchStats.useQuery(undefined, {
    staleTime: 60 * 1000,
  });

  const vendorBreakdown = trpc.zeroDay.getVendorBreakdown.useQuery(undefined, {
    enabled: activeTab === "analytics",
    staleTime: 5 * 60 * 1000,
  });

  const yearBreakdown = trpc.zeroDay.getYearBreakdown.useQuery(undefined, {
    enabled: activeTab === "analytics",
    staleTime: 5 * 60 * 1000,
  });

  const typeBreakdown = trpc.zeroDay.getTypeBreakdown.useQuery(undefined, {
    enabled: activeTab === "analytics",
    staleTime: 5 * 60 * 1000,
  });

  const refreshFeed = trpc.zeroDay.refreshFeed.useMutation({
    onSuccess: (data) => {
      toast.success(`Feed refreshed: ${data.totalEntries} entries loaded`);
      feedStatus.refetch();
    },
    onError: (err) => toast.error(`Refresh failed: ${err.message}`),
  });

  const dismissMatch = trpc.zeroDay.dismissMatch.useMutation({
    onSuccess: () => {
      toast.success("Match dismissed");
      recentMatches.refetch();
      matchStats.refetch();
    },
  });

  // ─── Handlers ─────────────────────────────────────────────────────────────────

  const handleSearch = () => {
    if (searchQuery.trim()) {
      setActiveSearch(searchQuery.trim());
      setActiveTab("search");
    }
  };

  const handleKeyDown = (e: React.KeyboardEvent) => {
    if (e.key === "Enter") handleSearch();
  };

  // ─── Tab Config ───────────────────────────────────────────────────────────────

  const tabs: { id: TabId; label: string; icon: typeof Search; count?: number }[] = [
    { id: "search", label: "CVE Search", icon: Search },
    { id: "browse", label: "0-Day Database", icon: Database, count: feedStatus.data?.totalEntries },
    { id: "matches", label: "Scan Matches", icon: Crosshair, count: matchStats.data?.undismissed },
    { id: "analytics", label: "Analytics", icon: BarChart3 },
  ];

  // ─── Render ───────────────────────────────────────────────────────────────────

  return (
    <div className="min-h-screen bg-background text-foreground">
      {/* Header */}
      <div className="border-b border-border bg-card/50">
        <div className="max-w-[1600px] mx-auto px-6 py-5">
          <div className="flex items-center justify-between mb-4">
            <div className="flex items-center gap-3">
              <div className="p-2 rounded-lg bg-red-500/15">
                <Flame className="w-6 h-6 text-red-400" />
              </div>
              <div>
                <h1 className="text-xl font-bold">0-Day Tracker</h1>
                <p className="text-sm text-muted-foreground">
                  Google Project Zero zero-day database with automated scan cross-referencing.
                  Search CVEs, browse the full database, and check if your assets are affected by known zero-days.
                </p>
              </div>
            </div>
            <div className="flex items-center gap-3">
              {feedStatus.data && (
                <div className="text-xs text-muted-foreground flex items-center gap-1.5">
                  <Database className="w-3.5 h-3.5" />
                  {feedStatus.data.totalEntries} entries
                  {feedStatus.data.lastFetchedAt && (
                    <span className="ml-2">
                      <Clock className="w-3 h-3 inline mr-0.5" />
                      {new Date(feedStatus.data.lastFetchedAt).toLocaleDateString()}
                    </span>
                  )}
                </div>
              )}
              <Button
                variant="outline"
                size="sm"
                onClick={() => refreshFeed.mutate()}
                disabled={refreshFeed.isPending}
              >
                <RefreshCw className={`w-3.5 h-3.5 mr-1.5 ${refreshFeed.isPending ? "animate-spin" : ""}`} />
                Refresh Feed
              </Button>
            </div>
          </div>

          {/* Global Search Bar */}
          <div className="flex gap-2 mb-4">
            <div className="relative flex-1">
              <Search className="absolute left-3 top-1/2 -translate-y-1/2 w-4 h-4 text-muted-foreground" />
              <Input
                placeholder="Search CVE ID, vendor, product, or vulnerability type..."
                className="pl-9 bg-background/60"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                onKeyDown={handleKeyDown}
              />
            </div>
            <Button onClick={handleSearch} disabled={!searchQuery.trim()}>
              <Search className="w-4 h-4 mr-1.5" />
              Search
            </Button>
          </div>

          {/* Tabs */}
          <div className="flex gap-1">
            {tabs.map((tab) => (
              <button
                key={tab.id}
                onClick={() => setActiveTab(tab.id)}
                className={`flex items-center gap-1.5 px-3 py-1.5 rounded-t-lg text-sm font-medium transition-colors ${
                  activeTab === tab.id
                    ? "bg-background text-foreground border border-b-0 border-border"
                    : "text-muted-foreground hover:text-foreground hover:bg-muted/30"
                }`}
              >
                <tab.icon className="w-3.5 h-3.5" />
                {tab.label}
                {tab.count !== undefined && tab.count > 0 && (
                  <Badge variant="secondary" className="ml-1 text-[10px] px-1.5 py-0">
                    {tab.count}
                  </Badge>
                )}
              </button>
            ))}
          </div>
        </div>
      </div>

      {/* Content */}
      <div className="max-w-[1600px] mx-auto px-6 py-6">
        {/* Search Tab */}
        {activeTab === "search" && (
          <div className="space-y-4">
            {!activeSearch && (
              <Card className="border-dashed">
                <CardContent className="py-12 text-center">
                  <Search className="w-12 h-12 mx-auto text-muted-foreground/40 mb-3" />
                  <p className="text-muted-foreground">
                    Enter a CVE ID (e.g., CVE-2024-3094), vendor name (e.g., Apple), or product name (e.g., Chrome) to search the Project Zero database.
                  </p>
                </CardContent>
              </Card>
            )}

            {activeSearch && searchResults.isLoading && (
              <div className="text-center py-8 text-muted-foreground">Searching...</div>
            )}

            {activeSearch && searchResults.data && (
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <h2 className="text-lg font-semibold">
                    Results for "{activeSearch}"
                    <span className="text-sm font-normal text-muted-foreground ml-2">
                      ({searchResults.data.totalMatches} matches)
                    </span>
                  </h2>
                  <Button variant="ghost" size="sm" onClick={() => { setActiveSearch(""); setSearchQuery(""); }}>
                    <XCircle className="w-3.5 h-3.5 mr-1" /> Clear
                  </Button>
                </div>

                {searchResults.data.results.length === 0 ? (
                  <Card className="border-dashed">
                    <CardContent className="py-8 text-center text-muted-foreground">
                      <Shield className="w-8 h-8 mx-auto mb-2 text-green-500/50" />
                      No zero-day entries found matching "{activeSearch}" in the Project Zero database.
                    </CardContent>
                  </Card>
                ) : (
                  <div className="space-y-2">
                    {searchResults.data.results.map((entry: any) => (
                      <ZeroDayEntryCard
                        key={entry.cve}
                        entry={entry}
                        expanded={expandedEntry === entry.cve}
                        onToggle={() => setExpandedEntry(expandedEntry === entry.cve ? null : entry.cve)}
                      />
                    ))}
                  </div>
                )}
              </div>
            )}
          </div>
        )}

        {/* Browse Tab */}
        {activeTab === "browse" && (
          <div className="space-y-4">
            <div className="flex gap-2 flex-wrap">
              <Input
                placeholder="Filter by keyword..."
                className="w-64 bg-background/60"
                value={browseSearch}
                onChange={(e) => { setBrowseSearch(e.target.value); setBrowseOffset(0); }}
              />
              <select
                className="px-3 py-1.5 rounded-md border border-border bg-background text-sm"
                value={browseVendor}
                onChange={(e) => { setBrowseVendor(e.target.value); setBrowseOffset(0); }}
              >
                <option value="">All Vendors</option>
                {(browseEntries.data?.vendors || []).slice(0, 40).map((v: string) => (
                  <option key={v} value={v}>{v}</option>
                ))}
              </select>
              <select
                className="px-3 py-1.5 rounded-md border border-border bg-background text-sm"
                value={browseYear || ""}
                onChange={(e) => { setBrowseYear(e.target.value ? Number(e.target.value) : undefined); setBrowseOffset(0); }}
              >
                <option value="">All Years</option>
                {(browseEntries.data?.years || []).map((y: number) => (
                  <option key={y} value={y}>{y}</option>
                ))}
              </select>
            </div>

            {browseEntries.isLoading ? (
              <div className="text-center py-8 text-muted-foreground">Loading entries...</div>
            ) : (
              <>
                <div className="text-sm text-muted-foreground">
                  Showing {browseOffset + 1}–{Math.min(browseOffset + 50, browseEntries.data?.total || 0)} of {browseEntries.data?.total || 0} entries
                </div>
                <div className="space-y-2">
                  {(browseEntries.data?.entries || []).map((entry: any) => (
                    <ZeroDayEntryCard
                      key={`${entry.cve}-${entry.dateDiscovered}`}
                      entry={entry}
                      expanded={expandedEntry === entry.cve}
                      onToggle={() => setExpandedEntry(expandedEntry === entry.cve ? null : entry.cve)}
                    />
                  ))}
                </div>
                <div className="flex gap-2 justify-center">
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={browseOffset === 0}
                    onClick={() => setBrowseOffset(Math.max(0, browseOffset - 50))}
                  >
                    Previous
                  </Button>
                  <Button
                    variant="outline"
                    size="sm"
                    disabled={(browseOffset + 50) >= (browseEntries.data?.total || 0)}
                    onClick={() => setBrowseOffset(browseOffset + 50)}
                  >
                    Next
                  </Button>
                </div>
              </>
            )}
          </div>
        )}

        {/* Scan Matches Tab */}
        {activeTab === "matches" && (
          <div className="space-y-4">
            {/* Match Stats */}
            <div className="grid grid-cols-4 gap-4">
              <StatCard label="Total Matches" value={matchStats.data?.total || 0} icon={Crosshair} />
              <StatCard label="Critical" value={matchStats.data?.critical || 0} icon={AlertTriangle} color="text-red-400" />
              <StatCard label="High" value={matchStats.data?.high || 0} icon={Shield} color="text-orange-400" />
              <StatCard label="Active Alerts" value={matchStats.data?.undismissed || 0} icon={Eye} color="text-yellow-400" />
            </div>

            {recentMatches.isLoading ? (
              <div className="text-center py-8 text-muted-foreground">Loading matches...</div>
            ) : (recentMatches.data || []).length === 0 ? (
              <Card className="border-dashed">
                <CardContent className="py-12 text-center">
                  <CheckCircle2 className="w-12 h-12 mx-auto text-green-500/50 mb-3" />
                  <p className="text-muted-foreground">
                    No active zero-day matches found across your scans. Run a domain scan to automatically cross-reference against the Project Zero database.
                  </p>
                </CardContent>
              </Card>
            ) : (
              <div className="space-y-2">
                {(recentMatches.data || []).map((match: any) => (
                  <Card key={match.id} className="border-border/60 hover:border-border transition-colors">
                    <CardContent className="py-3 px-4">
                      <div className="flex items-center justify-between">
                        <div className="flex items-center gap-3 flex-1 min-w-0">
                          <Badge className={`text-[10px] ${SEVERITY_STYLES[match.severity as keyof typeof SEVERITY_STYLES] || ""}`}>
                            {match.severity?.toUpperCase()}
                          </Badge>
                          <div className="min-w-0">
                            <div className="flex items-center gap-2">
                              <span className="font-mono text-sm font-semibold text-foreground">{match.cve}</span>
                              <Badge variant="outline" className="text-[10px]">
                                {MATCH_TYPE_LABELS[match.matchType as keyof typeof MATCH_TYPE_LABELS] || match.matchType}
                              </Badge>
                              <Badge className={`text-[10px] ${CONFIDENCE_STYLES[match.confidence as keyof typeof CONFIDENCE_STYLES] || ""}`}>
                                {match.confidence} confidence
                              </Badge>
                            </div>
                            <div className="text-xs text-muted-foreground mt-0.5 truncate">
                              <span className="font-medium">{match.domain}</span>
                              <span className="mx-1.5">·</span>
                              {match.vendor} {match.product}
                              <span className="mx-1.5">·</span>
                              Asset: {match.matchedAsset}
                              {match.zeroDayType && (
                                <>
                                  <span className="mx-1.5">·</span>
                                  Type: {match.zeroDayType}
                                </>
                              )}
                            </div>
                          </div>
                        </div>
                        <div className="flex items-center gap-2 ml-3">
                          <span className="text-[10px] text-muted-foreground">
                            Scan #{match.scanId}
                          </span>
                          {match.advisoryUrl && (
                            <a
                              href={match.advisoryUrl}
                              target="_blank"
                              rel="noopener noreferrer"
                              className="text-muted-foreground hover:text-foreground"
                            >
                              <ExternalLink className="w-3.5 h-3.5" />
                            </a>
                          )}
                          <Button
                            variant="ghost"
                            size="sm"
                            className="text-xs h-7"
                            onClick={() => dismissMatch.mutate({ matchId: match.id })}
                          >
                            Dismiss
                          </Button>
                        </div>
                      </div>
                    </CardContent>
                  </Card>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Analytics Tab */}
        {activeTab === "analytics" && (
          <div className="space-y-6">
            {/* Year Trend */}
            <Card>
              <CardHeader>
                <CardTitle className="text-sm flex items-center gap-2">
                  <TrendingUp className="w-4 h-4" />
                  Zero-Days by Year
                </CardTitle>
              </CardHeader>
              <CardContent>
                {yearBreakdown.isLoading ? (
                  <div className="text-center py-4 text-muted-foreground">Loading...</div>
                ) : (
                  <div className="flex items-end gap-1 h-40">
                    {(yearBreakdown.data || []).map((y: any) => {
                      const maxCount = Math.max(...(yearBreakdown.data || []).map((d: any) => d.count));
                      const height = maxCount > 0 ? (y.count / maxCount) * 100 : 0;
                      return (
                        <div key={y.year} className="flex-1 flex flex-col items-center gap-1">
                          <span className="text-[10px] text-muted-foreground">{y.count}</span>
                          <div
                            className="w-full bg-red-500/30 rounded-t hover:bg-red-500/50 transition-colors"
                            style={{ height: `${height}%`, minHeight: y.count > 0 ? "4px" : "0" }}
                          />
                          <span className="text-[10px] text-muted-foreground">{y.year}</span>
                        </div>
                      );
                    })}
                  </div>
                )}
              </CardContent>
            </Card>

            <div className="grid grid-cols-2 gap-6">
              {/* Top Vendors */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Bug className="w-4 h-4" />
                    Top Affected Vendors
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {vendorBreakdown.isLoading ? (
                    <div className="text-center py-4 text-muted-foreground">Loading...</div>
                  ) : (
                    <div className="space-y-1.5">
                      {(vendorBreakdown.data || []).slice(0, 15).map((v: any) => {
                        const maxCount = (vendorBreakdown.data || [])[0]?.count || 1;
                        return (
                          <div key={v.vendor} className="flex items-center gap-2">
                            <span className="text-xs w-28 truncate text-muted-foreground">{v.vendor}</span>
                            <div className="flex-1 h-4 bg-muted/30 rounded overflow-hidden">
                              <div
                                className="h-full bg-red-500/40 rounded"
                                style={{ width: `${(v.count / maxCount) * 100}%` }}
                              />
                            </div>
                            <span className="text-xs font-mono w-8 text-right">{v.count}</span>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </CardContent>
              </Card>

              {/* Vulnerability Types */}
              <Card>
                <CardHeader>
                  <CardTitle className="text-sm flex items-center gap-2">
                    <Shield className="w-4 h-4" />
                    Vulnerability Types
                  </CardTitle>
                </CardHeader>
                <CardContent>
                  {typeBreakdown.isLoading ? (
                    <div className="text-center py-4 text-muted-foreground">Loading...</div>
                  ) : (
                    <div className="space-y-1.5">
                      {(typeBreakdown.data || []).slice(0, 15).map((t: any) => {
                        const maxCount = (typeBreakdown.data || [])[0]?.count || 1;
                        return (
                          <div key={t.type} className="flex items-center gap-2">
                            <span className="text-xs w-36 truncate text-muted-foreground">{t.type}</span>
                            <div className="flex-1 h-4 bg-muted/30 rounded overflow-hidden">
                              <div
                                className="h-full bg-orange-500/40 rounded"
                                style={{ width: `${(t.count / maxCount) * 100}%` }}
                              />
                            </div>
                            <span className="text-xs font-mono w-8 text-right">{t.count}</span>
                          </div>
                        );
                      })}
                    </div>
                  )}
                </CardContent>
              </Card>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

// ─── Sub-Components ─────────────────────────────────────────────────────────────

function ZeroDayEntryCard({
  entry,
  expanded,
  onToggle,
}: {
  entry: any;
  expanded: boolean;
  onToggle: () => void;
}) {
  const isPatched = entry.datePatched && entry.datePatched !== "N/A" && entry.datePatched !== "";
  const daysToPath = useMemo(() => {
    if (!entry.dateDiscovered || !entry.datePatched) return null;
    try {
      const d = new Date(entry.dateDiscovered).getTime();
      const p = new Date(entry.datePatched).getTime();
      if (isNaN(d) || isNaN(p)) return null;
      return Math.round((p - d) / (1000 * 60 * 60 * 24));
    } catch { return null; }
  }, [entry.dateDiscovered, entry.datePatched]);

  return (
    <Card className="border-border/60 hover:border-border transition-colors">
      <CardContent className="py-3 px-4">
        <div className="flex items-center justify-between cursor-pointer" onClick={onToggle}>
          <div className="flex items-center gap-3 flex-1 min-w-0">
            <Flame className="w-4 h-4 text-red-400 shrink-0" />
            <div className="min-w-0">
              <div className="flex items-center gap-2 flex-wrap">
                <span className="font-mono text-sm font-semibold text-foreground">{entry.cve}</span>
                <Badge variant="outline" className="text-[10px]">{entry.vendor}</Badge>
                <Badge variant="outline" className="text-[10px]">{entry.product}</Badge>
                {entry.type && (
                  <Badge className="text-[10px] bg-purple-500/15 text-purple-400">{entry.type}</Badge>
                )}
                {isPatched ? (
                  <Badge className="text-[10px] bg-green-500/15 text-green-400">Patched</Badge>
                ) : (
                  <Badge className="text-[10px] bg-red-500/15 text-red-400">Unpatched</Badge>
                )}
              </div>
              <p className="text-xs text-muted-foreground mt-0.5 truncate max-w-[800px]">
                {entry.description || "No description available"}
              </p>
            </div>
          </div>
          <div className="flex items-center gap-3 ml-3 shrink-0">
            {entry.dateDiscovered && (
              <span className="text-[10px] text-muted-foreground">
                <Clock className="w-3 h-3 inline mr-0.5" />
                {entry.dateDiscovered}
              </span>
            )}
            {daysToPath !== null && (
              <span className="text-[10px] text-muted-foreground">
                {daysToPath}d to patch
              </span>
            )}
            {expanded ? <ChevronUp className="w-4 h-4" /> : <ChevronDown className="w-4 h-4" />}
          </div>
        </div>

        {expanded && (
          <div className="mt-3 pt-3 border-t border-border/40 space-y-2 text-xs">
            <div className="grid grid-cols-2 gap-4">
              <div>
                <span className="text-muted-foreground">Discovered:</span>{" "}
                <span className="font-medium">{entry.dateDiscovered || "Unknown"}</span>
              </div>
              <div>
                <span className="text-muted-foreground">Patched:</span>{" "}
                <span className="font-medium">{entry.datePatched || "Not yet"}</span>
              </div>
              <div>
                <span className="text-muted-foreground">Type:</span>{" "}
                <span className="font-medium">{entry.type || "Unknown"}</span>
              </div>
              <div>
                <span className="text-muted-foreground">Reported By:</span>{" "}
                <span className="font-medium">{entry.reportedBy || "Unknown"}</span>
              </div>
            </div>
            {entry.description && (
              <div>
                <span className="text-muted-foreground">Description:</span>
                <p className="mt-1 text-foreground/80">{entry.description}</p>
              </div>
            )}
            {entry.rootCauseAnalysis && (
              <div>
                <span className="text-muted-foreground">Root Cause Analysis:</span>
                <p className="mt-1 text-foreground/80">{entry.rootCauseAnalysis}</p>
              </div>
            )}
            <div className="flex gap-2 pt-1">
              {entry.advisoryUrl && (
                <a
                  href={entry.advisoryUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300"
                >
                  <ExternalLink className="w-3 h-3" /> Advisory
                </a>
              )}
              {entry.analysisUrl && (
                <a
                  href={entry.analysisUrl}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300"
                >
                  <ExternalLink className="w-3 h-3" /> Analysis
                </a>
              )}
              <a
                href={`https://nvd.nist.gov/vuln/detail/${entry.cve}`}
                target="_blank"
                rel="noopener noreferrer"
                className="inline-flex items-center gap-1 text-blue-400 hover:text-blue-300"
              >
                <ExternalLink className="w-3 h-3" /> NVD
              </a>
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

function StatCard({
  label,
  value,
  icon: Icon,
  color = "text-foreground",
}: {
  label: string;
  value: number;
  icon: typeof Search;
  color?: string;
}) {
  return (
    <Card>
      <CardContent className="py-4 px-4 flex items-center gap-3">
        <div className="p-2 rounded-lg bg-muted/30">
          <Icon className={`w-5 h-5 ${color}`} />
        </div>
        <div>
          <div className={`text-2xl font-bold ${color}`}>{value}</div>
          <div className="text-xs text-muted-foreground">{label}</div>
        </div>
      </CardContent>
    </Card>
  );
}
