import { useState, useMemo } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Skeleton } from "@/components/ui/skeleton";
import { useToast } from "@/hooks/use-toast";
import {
  Shield, AlertTriangle, Globe, Eye, Radio, Search,
  CheckCircle, XCircle, ExternalLink, RefreshCw, Wifi, WifiOff,
  TrendingUp, Hash, Server, Activity, FileWarning, Ban,
} from "lucide-react";

// ─── Severity badge helper ──────────────────────────────────────────────
function SeverityBadge({ severity }: { severity: string }) {
  const colors: Record<string, string> = {
    critical: "bg-red-600 text-white",
    high: "bg-orange-500 text-white",
    medium: "bg-yellow-500 text-black",
    low: "bg-blue-500 text-white",
    info: "bg-slate-500 text-white",
  };
  return (
    <Badge className={colors[severity?.toLowerCase()] || "bg-slate-500 text-white"}>
      {severity?.toUpperCase() || "UNKNOWN"}
    </Badge>
  );
}

// ─── Overview Tab ───────────────────────────────────────────────────────
function OverviewTab() {
  const healthQ = trpc.socradar.health.useQuery(undefined, { retry: 1, staleTime: 60_000 });
  const statsQ = trpc.socradar.stats.useQuery(undefined, { retry: 1, staleTime: 60_000 });

  if (healthQ.isLoading || statsQ.isLoading) {
    return (
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4">
        {Array.from({ length: 8 }).map((_, i) => (
          <Skeleton key={i} className="h-28 rounded-xl" />
        ))}
      </div>
    );
  }

  const health = healthQ.data;
  const stats = statsQ.data?.stats;

  return (
    <div className="space-y-6">
      {/* Connection Status */}
      <Card className="border-l-4 border-l-primary">
        <CardContent className="flex items-center gap-4 py-4">
          {health?.connected ? (
            <Wifi className="h-6 w-6 text-green-500" />
          ) : (
            <WifiOff className="h-6 w-6 text-red-500" />
          )}
          <div>
            <p className="font-semibold">
              {health?.connected ? "Connected to SOCRadar" : health?.configured ? "Connection Failed" : "Not Configured"}
            </p>
            <p className="text-sm text-muted-foreground">{health?.message}</p>
            {health?.companyName && (
              <p className="text-xs text-muted-foreground mt-1">Company: {health.companyName}</p>
            )}
          </div>
        </CardContent>
      </Card>

      {!health?.configured && (
        <Card className="border-dashed border-2">
          <CardContent className="py-8 text-center">
            <Shield className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
            <h3 className="text-lg font-semibold mb-2">Configure SOCRadar Integration</h3>
            <p className="text-muted-foreground max-w-md mx-auto">
              Set <code className="bg-muted px-1 rounded">SOCRADAR_API_KEY</code> and{" "}
              <code className="bg-muted px-1 rounded">SOCRADAR_COMPANY_ID</code> environment variables
              to enable dark web monitoring, brand protection, and threat feeds.
            </p>
          </CardContent>
        </Card>
      )}

      {/* Stats Grid */}
      {stats && (
        <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
          <StatCard icon={<AlertTriangle className="h-5 w-5" />} label="Total Incidents" value={stats.totalIncidents} color="text-red-500" />
          <StatCard icon={<Activity className="h-5 w-5" />} label="Open Incidents" value={stats.openIncidents} color="text-orange-500" />
          <StatCard icon={<CheckCircle className="h-5 w-5" />} label="Resolved" value={stats.resolvedIncidents} color="text-green-500" />
          <StatCard icon={<Ban className="h-5 w-5" />} label="False Positives" value={stats.falsePositives} color="text-slate-500" />
          <StatCard icon={<Eye className="h-5 w-5" />} label="Dark Web Mentions" value={stats.darkWebMentions} color="text-purple-500" />
          <StatCard icon={<Globe className="h-5 w-5" />} label="Brand Alerts" value={stats.brandAlerts} color="text-blue-500" />
          <StatCard icon={<FileWarning className="h-5 w-5" />} label="Data Leaks" value={stats.dataLeaks} color="text-red-400" />
          <StatCard icon={<TrendingUp className="h-5 w-5" />} label="Severity Breakdown" value={Object.keys(stats.bySeverity).length + " levels"} color="text-yellow-500" />
        </div>
      )}

      {/* Severity Breakdown */}
      {stats && Object.keys(stats.bySeverity).length > 0 && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Incidents by Severity</CardTitle>
          </CardHeader>
          <CardContent>
            <div className="flex gap-4 flex-wrap">
              {Object.entries(stats.bySeverity).map(([sev, count]) => (
                <div key={sev} className="flex items-center gap-2">
                  <SeverityBadge severity={sev} />
                  <span className="text-sm font-mono">{count as number}</span>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}
    </div>
  );
}

function StatCard({ icon, label, value, color }: { icon: React.ReactNode; label: string; value: number | string; color: string }) {
  return (
    <Card>
      <CardContent className="flex items-center gap-3 py-4">
        <div className={color}>{icon}</div>
        <div>
          <p className="text-2xl font-bold">{typeof value === "number" ? value.toLocaleString() : value}</p>
          <p className="text-xs text-muted-foreground">{label}</p>
        </div>
      </CardContent>
    </Card>
  );
}

// ─── Incidents Tab ──────────────────────────────────────────────────────
function IncidentsTab() {
  const [severity, setSeverity] = useState<string[]>([]);
  const incidentsQ = trpc.socradar.incidents.useQuery(
    { severity: severity.length ? severity : undefined, limit: 50 },
    { retry: 1, staleTime: 30_000 },
  );
  const markFP = trpc.socradar.markFP.useMutation();
  const markResolved = trpc.socradar.markResolved.useMutation();
  const { toast } = useToast();
  const utils = trpc.useUtils();

  if (incidentsQ.isLoading) {
    return <div className="space-y-3">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-20 rounded-xl" />)}</div>;
  }

  if (!incidentsQ.data?.configured) {
    return <NotConfiguredCard />;
  }

  const incidents = incidentsQ.data?.incidents || [];

  return (
    <div className="space-y-4">
      {/* Severity filter */}
      <div className="flex gap-2 flex-wrap">
        {["critical", "high", "medium", "low"].map(s => (
          <Button
            key={s}
            size="sm"
            variant={severity.includes(s) ? "default" : "outline"}
            onClick={() => setSeverity(prev => prev.includes(s) ? prev.filter(x => x !== s) : [...prev, s])}
          >
            {s.toUpperCase()}
          </Button>
        ))}
        {severity.length > 0 && (
          <Button size="sm" variant="ghost" onClick={() => setSeverity([])}>Clear</Button>
        )}
      </div>

      {incidents.length === 0 ? (
        <Card className="border-dashed border-2">
          <CardContent className="py-8 text-center text-muted-foreground">
            No incidents found matching the current filters.
          </CardContent>
        </Card>
      ) : (
        incidents.map(inc => (
          <Card key={inc.id} className="hover:bg-muted/30 transition-colors">
            <CardContent className="py-4">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <SeverityBadge severity={inc.severity} />
                    <Badge variant="outline">{inc.mainType}</Badge>
                    {inc.subType && <Badge variant="outline" className="text-xs">{inc.subType}</Badge>}
                  </div>
                  <p className="font-medium truncate">{inc.title}</p>
                  {inc.content && <p className="text-sm text-muted-foreground line-clamp-2 mt-1">{inc.content}</p>}
                  <p className="text-xs text-muted-foreground mt-2">
                    {new Date(inc.createdAt).toLocaleString()}
                    {inc.source && <> &middot; Source: {inc.source}</>}
                  </p>
                </div>
                <div className="flex gap-2 shrink-0">
                  {!inc.isResolved && (
                    <Button
                      size="sm"
                      variant="outline"
                      disabled={markResolved.isPending}
                      onClick={() => {
                        markResolved.mutate({ incidentId: inc.id }, {
                          onSuccess: () => { toast({ title: "Incident resolved" }); utils.socradar.incidents.invalidate(); },
                          onError: () => toast({ title: "Failed to resolve", variant: "destructive" }),
                        });
                      }}
                    >
                      <CheckCircle className="h-3.5 w-3.5 mr-1" /> Resolve
                    </Button>
                  )}
                  {!inc.isFalsePositive && (
                    <Button
                      size="sm"
                      variant="ghost"
                      disabled={markFP.isPending}
                      onClick={() => {
                        markFP.mutate({ incidentId: inc.id }, {
                          onSuccess: () => { toast({ title: "Marked as FP" }); utils.socradar.incidents.invalidate(); },
                          onError: () => toast({ title: "Failed to mark FP", variant: "destructive" }),
                        });
                      }}
                    >
                      <XCircle className="h-3.5 w-3.5 mr-1" /> FP
                    </Button>
                  )}
                </div>
              </div>
            </CardContent>
          </Card>
        ))
      )}
    </div>
  );
}

// ─── Dark Web Tab ───────────────────────────────────────────────────────
function DarkWebTab() {
  const mentionsQ = trpc.socradar.darkWebMentions.useQuery(
    { limit: 25 },
    { retry: 1, staleTime: 30_000 },
  );

  if (mentionsQ.isLoading) {
    return <div className="space-y-3">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-20 rounded-xl" />)}</div>;
  }

  if (!mentionsQ.data?.configured) return <NotConfiguredCard />;

  const mentions = mentionsQ.data?.mentions || [];

  const sourceIcons: Record<string, React.ReactNode> = {
    forum: <Globe className="h-4 w-4" />,
    marketplace: <Server className="h-4 w-4" />,
    paste: <FileWarning className="h-4 w-4" />,
    telegram: <Radio className="h-4 w-4" />,
    discord: <Radio className="h-4 w-4" />,
    irc: <Radio className="h-4 w-4" />,
  };

  return (
    <div className="space-y-4">
      {mentions.length === 0 ? (
        <Card className="border-dashed border-2">
          <CardContent className="py-8 text-center text-muted-foreground">
            No dark web mentions detected.
          </CardContent>
        </Card>
      ) : (
        mentions.map(m => (
          <Card key={m.id} className="hover:bg-muted/30 transition-colors">
            <CardContent className="py-4">
              <div className="flex items-start gap-3">
                <div className="mt-1 text-muted-foreground">{sourceIcons[m.source] || <Eye className="h-4 w-4" />}</div>
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <SeverityBadge severity={m.severity} />
                    <Badge variant="outline" className="text-xs capitalize">{m.source}</Badge>
                    <Badge variant="outline" className="text-xs">{m.category.replace(/_/g, " ")}</Badge>
                  </div>
                  <p className="font-medium">{m.title}</p>
                  <p className="text-sm text-muted-foreground line-clamp-3 mt-1">{m.content}</p>
                  <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                    <span>{new Date(m.detectedAt).toLocaleString()}</span>
                    {m.threatActor && <span>Actor: <strong>{m.threatActor}</strong></span>}
                    {m.affectedAssets && m.affectedAssets.length > 0 && (
                      <span>Assets: {m.affectedAssets.join(", ")}</span>
                    )}
                  </div>
                </div>
              </div>
            </CardContent>
          </Card>
        ))
      )}
    </div>
  );
}

// ─── Brand Protection Tab ───────────────────────────────────────────────
function BrandProtectionTab() {
  const alertsQ = trpc.socradar.brandAlerts.useQuery(
    { limit: 25 },
    { retry: 1, staleTime: 30_000 },
  );
  const takedown = trpc.socradar.requestTakedown.useMutation();
  const { toast } = useToast();
  const utils = trpc.useUtils();

  if (alertsQ.isLoading) {
    return <div className="space-y-3">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-20 rounded-xl" />)}</div>;
  }

  if (!alertsQ.data?.configured) return <NotConfiguredCard />;

  const alerts = alertsQ.data?.alerts || [];

  return (
    <div className="space-y-4">
      {alerts.length === 0 ? (
        <Card className="border-dashed border-2">
          <CardContent className="py-8 text-center text-muted-foreground">
            No brand protection alerts detected.
          </CardContent>
        </Card>
      ) : (
        alerts.map(a => (
          <Card key={a.id} className="hover:bg-muted/30 transition-colors">
            <CardContent className="py-4">
              <div className="flex items-start justify-between gap-4">
                <div className="flex-1 min-w-0">
                  <div className="flex items-center gap-2 mb-1">
                    <SeverityBadge severity={a.severity} />
                    <Badge variant="outline" className="text-xs capitalize">{a.type.replace(/_/g, " ")}</Badge>
                    <Badge variant={a.status === "taken_down" ? "default" : a.status === "monitoring" ? "secondary" : "destructive"} className="text-xs capitalize">
                      {a.status.replace(/_/g, " ")}
                    </Badge>
                  </div>
                  <p className="font-medium">{a.title}</p>
                  <p className="text-sm text-muted-foreground line-clamp-2 mt-1">{a.description}</p>
                  <div className="flex items-center gap-4 mt-2 text-xs text-muted-foreground">
                    <span>{new Date(a.detectedAt).toLocaleString()}</span>
                    {a.domain && <span>Domain: <code className="bg-muted px-1 rounded">{a.domain}</code></span>}
                    {a.url && (
                      <a href={a.url} target="_blank" rel="noopener noreferrer" className="flex items-center gap-1 hover:text-primary">
                        <ExternalLink className="h-3 w-3" /> View
                      </a>
                    )}
                  </div>
                </div>
                {a.status === "active" && !a.takedownRequested && (
                  <Button
                    size="sm"
                    variant="destructive"
                    disabled={takedown.isPending}
                    onClick={() => {
                      takedown.mutate({ alertId: a.id }, {
                        onSuccess: () => { toast({ title: "Takedown requested" }); utils.socradar.brandAlerts.invalidate(); },
                        onError: () => toast({ title: "Takedown request failed", variant: "destructive" }),
                      });
                    }}
                  >
                    Request Takedown
                  </Button>
                )}
              </div>
            </CardContent>
          </Card>
        ))
      )}
    </div>
  );
}

// ─── IOC Enrichment Tab ─────────────────────────────────────────────────
function IOCEnrichmentTab() {
  const [query, setQuery] = useState("");
  const [searchType, setSearchType] = useState<"ip" | "domain" | "hash">("ip");
  const [activeQuery, setActiveQuery] = useState<{ type: "ip" | "domain" | "hash"; value: string } | null>(null);

  const ipQ = trpc.socradar.enrichIP.useQuery(
    { ip: activeQuery?.value || "" },
    { enabled: activeQuery?.type === "ip" && !!activeQuery.value, retry: 1 },
  );
  const domainQ = trpc.socradar.enrichDomain.useQuery(
    { domain: activeQuery?.value || "" },
    { enabled: activeQuery?.type === "domain" && !!activeQuery.value, retry: 1 },
  );
  const hashQ = trpc.socradar.enrichHash.useQuery(
    { hash: activeQuery?.value || "" },
    { enabled: activeQuery?.type === "hash" && !!activeQuery.value, retry: 1 },
  );

  const activeResult = activeQuery?.type === "ip" ? ipQ : activeQuery?.type === "domain" ? domainQ : hashQ;
  const result = activeResult?.data?.result;

  function handleSearch() {
    if (!query.trim()) return;
    setActiveQuery({ type: searchType, value: query.trim() });
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardContent className="py-4">
          <div className="flex gap-2">
            <div className="flex gap-1">
              {(["ip", "domain", "hash"] as const).map(t => (
                <Button
                  key={t}
                  size="sm"
                  variant={searchType === t ? "default" : "outline"}
                  onClick={() => setSearchType(t)}
                >
                  {t === "ip" ? <Server className="h-3.5 w-3.5 mr-1" /> : t === "domain" ? <Globe className="h-3.5 w-3.5 mr-1" /> : <Hash className="h-3.5 w-3.5 mr-1" />}
                  {t.toUpperCase()}
                </Button>
              ))}
            </div>
            <Input
              placeholder={searchType === "ip" ? "e.g. 1.1.1.1" : searchType === "domain" ? "e.g. example.com" : "e.g. d41d8cd98f00b204..."}
              value={query}
              onChange={e => setQuery(e.target.value)}
              onKeyDown={e => e.key === "Enter" && handleSearch()}
              className="flex-1"
            />
            <Button onClick={handleSearch} disabled={!query.trim() || activeResult?.isLoading}>
              <Search className="h-4 w-4 mr-1" /> Enrich
            </Button>
          </div>
        </CardContent>
      </Card>

      {activeResult?.isLoading && (
        <div className="space-y-3">
          <Skeleton className="h-32 rounded-xl" />
          <Skeleton className="h-24 rounded-xl" />
        </div>
      )}

      {result && (
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Card>
            <CardHeader>
              <CardTitle className="text-base">Risk Score</CardTitle>
              <CardDescription>{result.indicator}</CardDescription>
            </CardHeader>
            <CardContent>
              <div className="flex items-center gap-4">
                <div className={`text-4xl font-bold ${result.riskScore >= 70 ? "text-red-500" : result.riskScore >= 40 ? "text-yellow-500" : "text-green-500"}`}>
                  {result.riskScore}
                </div>
                <div className="text-sm text-muted-foreground">
                  <p>out of 100</p>
                  <p>{result.totalEncounters} encounters</p>
                </div>
              </div>
              {result.tags && result.tags.length > 0 && (
                <div className="flex gap-1 flex-wrap mt-3">
                  {result.tags.map((t, i) => <Badge key={i} variant="outline" className="text-xs">{t}</Badge>)}
                </div>
              )}
            </CardContent>
          </Card>

          {result.geoLocation && (
            <Card>
              <CardHeader>
                <CardTitle className="text-base">Geo Location</CardTitle>
              </CardHeader>
              <CardContent className="text-sm space-y-1">
                {result.geoLocation.country && <p><strong>Country:</strong> {result.geoLocation.country}</p>}
                {result.geoLocation.city && <p><strong>City:</strong> {result.geoLocation.city}</p>}
                {result.geoLocation.asn && <p><strong>ASN:</strong> {result.geoLocation.asn}</p>}
                {result.geoLocation.asnName && <p><strong>ASN Name:</strong> {result.geoLocation.asnName}</p>}
              </CardContent>
            </Card>
          )}

          {result.scoreDetails && Object.keys(result.scoreDetails).length > 0 && (
            <Card className="md:col-span-2">
              <CardHeader>
                <CardTitle className="text-base">Score Breakdown</CardTitle>
              </CardHeader>
              <CardContent>
                <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
                  {Object.entries(result.scoreDetails).map(([key, val]) => (
                    <div key={key} className="text-sm">
                      <p className="text-muted-foreground capitalize">{key.replace(/_/g, " ")}</p>
                      <p className="font-mono font-bold">{val as number}</p>
                    </div>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      )}

      {activeQuery && !activeResult?.isLoading && !result && activeResult?.data?.configured && (
        <Card className="border-dashed border-2">
          <CardContent className="py-8 text-center text-muted-foreground">
            No reputation data found for <code className="bg-muted px-1 rounded">{activeQuery.value}</code>
          </CardContent>
        </Card>
      )}

      {activeQuery && !activeResult?.isLoading && activeResult?.data && !activeResult.data.configured && (
        <NotConfiguredCard />
      )}
    </div>
  );
}

// ─── Threat Feeds Tab ───────────────────────────────────────────────────
function ThreatFeedsTab() {
  const feedsQ = trpc.socradar.threatFeeds.useQuery(
    { limit: 20 },
    { retry: 1, staleTime: 60_000 },
  );
  const [selectedFeed, setSelectedFeed] = useState<string | null>(null);
  const indicatorsQ = trpc.socradar.feedIndicators.useQuery(
    { feedId: selectedFeed || "", limit: 100 },
    { enabled: !!selectedFeed, retry: 1 },
  );

  if (feedsQ.isLoading) {
    return <div className="space-y-3">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-16 rounded-xl" />)}</div>;
  }

  if (!feedsQ.data?.configured) return <NotConfiguredCard />;

  const feeds = feedsQ.data?.feeds || [];

  return (
    <div className="space-y-4">
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
        {feeds.length === 0 ? (
          <Card className="border-dashed border-2 col-span-full">
            <CardContent className="py-8 text-center text-muted-foreground">
              No threat feeds available.
            </CardContent>
          </Card>
        ) : (
          feeds.map(f => (
            <Card
              key={f.id}
              className={`cursor-pointer transition-colors hover:bg-muted/30 ${selectedFeed === f.id ? "ring-2 ring-primary" : ""}`}
              onClick={() => setSelectedFeed(f.id === selectedFeed ? null : f.id)}
            >
              <CardContent className="py-4">
                <div className="flex items-center justify-between mb-2">
                  <Badge variant="outline" className="text-xs capitalize">{f.type}</Badge>
                  <span className="text-xs text-muted-foreground font-mono">{f.totalCount} IOCs</span>
                </div>
                <p className="font-medium text-sm">{f.name}</p>
                <p className="text-xs text-muted-foreground mt-1">
                  Updated: {new Date(f.lastUpdated).toLocaleDateString()}
                </p>
              </CardContent>
            </Card>
          ))
        )}
      </div>

      {selectedFeed && (
        <Card>
          <CardHeader>
            <CardTitle className="text-base">Feed Indicators</CardTitle>
            <CardDescription>
              {indicatorsQ.isLoading ? "Loading..." : `${indicatorsQ.data?.indicators?.length || 0} indicators`}
            </CardDescription>
          </CardHeader>
          <CardContent>
            {indicatorsQ.isLoading ? (
              <div className="space-y-2">{Array.from({ length: 5 }).map((_, i) => <Skeleton key={i} className="h-8" />)}</div>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b text-left">
                      <th className="py-2 pr-4">Indicator</th>
                      <th className="py-2 pr-4">Type</th>
                      <th className="py-2 pr-4">Confidence</th>
                      <th className="py-2 pr-4">First Seen</th>
                      <th className="py-2 pr-4">Last Seen</th>
                      <th className="py-2">Tags</th>
                    </tr>
                  </thead>
                  <tbody>
                    {(indicatorsQ.data?.indicators || []).map((ind, i) => (
                      <tr key={i} className="border-b last:border-0">
                        <td className="py-2 pr-4 font-mono text-xs">{ind.value}</td>
                        <td className="py-2 pr-4"><Badge variant="outline" className="text-xs">{ind.type}</Badge></td>
                        <td className="py-2 pr-4">
                          <span className={ind.confidence >= 80 ? "text-green-500" : ind.confidence >= 50 ? "text-yellow-500" : "text-red-500"}>
                            {ind.confidence}%
                          </span>
                        </td>
                        <td className="py-2 pr-4 text-xs text-muted-foreground">{new Date(ind.firstSeen).toLocaleDateString()}</td>
                        <td className="py-2 pr-4 text-xs text-muted-foreground">{new Date(ind.lastSeen).toLocaleDateString()}</td>
                        <td className="py-2">
                          <div className="flex gap-1 flex-wrap">
                            {ind.tags?.map((t, j) => <Badge key={j} variant="outline" className="text-xs">{t}</Badge>)}
                          </div>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardContent>
        </Card>
      )}
    </div>
  );
}

// ─── Not Configured Card ────────────────────────────────────────────────
function NotConfiguredCard() {
  return (
    <Card className="border-dashed border-2">
      <CardContent className="py-8 text-center">
        <Shield className="h-12 w-12 mx-auto text-muted-foreground mb-4" />
        <h3 className="text-lg font-semibold mb-2">SOCRadar Not Configured</h3>
        <p className="text-muted-foreground max-w-md mx-auto">
          Set <code className="bg-muted px-1 rounded">SOCRADAR_API_KEY</code> and{" "}
          <code className="bg-muted px-1 rounded">SOCRADAR_COMPANY_ID</code> environment variables to enable this feature.
        </p>
      </CardContent>
    </Card>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────
export default function SOCRadar() {
  return (
    <div className="space-y-6">
      <div>
        <h1 className="text-2xl font-bold tracking-tight">SOCRadar Intelligence</h1>
        <p className="text-muted-foreground">
          Dark web monitoring, brand protection, IOC enrichment, and threat feeds powered by SOCRadar.
        </p>
      </div>

      <Tabs defaultValue="overview" className="space-y-4">
        <TabsList className="flex-wrap h-auto gap-1">
          <TabsTrigger value="overview" className="gap-1.5">
            <Activity className="h-3.5 w-3.5" /> Overview
          </TabsTrigger>
          <TabsTrigger value="incidents" className="gap-1.5">
            <AlertTriangle className="h-3.5 w-3.5" /> Incidents
          </TabsTrigger>
          <TabsTrigger value="darkweb" className="gap-1.5">
            <Eye className="h-3.5 w-3.5" /> Dark Web
          </TabsTrigger>
          <TabsTrigger value="brand" className="gap-1.5">
            <Globe className="h-3.5 w-3.5" /> Brand Protection
          </TabsTrigger>
          <TabsTrigger value="ioc" className="gap-1.5">
            <Search className="h-3.5 w-3.5" /> IOC Enrichment
          </TabsTrigger>
          <TabsTrigger value="feeds" className="gap-1.5">
            <Radio className="h-3.5 w-3.5" /> Threat Feeds
          </TabsTrigger>
        </TabsList>

        <TabsContent value="overview"><OverviewTab /></TabsContent>
        <TabsContent value="incidents"><IncidentsTab /></TabsContent>
        <TabsContent value="darkweb"><DarkWebTab /></TabsContent>
        <TabsContent value="brand"><BrandProtectionTab /></TabsContent>
        <TabsContent value="ioc"><IOCEnrichmentTab /></TabsContent>
        <TabsContent value="feeds"><ThreatFeedsTab /></TabsContent>
      </Tabs>
    </div>
  );
}
