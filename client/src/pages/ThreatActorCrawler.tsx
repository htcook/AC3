import { useState, useMemo } from "react";
import { Card, CardContent, CardDescription, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Input } from "@/components/ui/input";
import { Label } from "@/components/ui/label";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { Dialog, DialogContent, DialogDescription, DialogFooter, DialogHeader, DialogTitle, DialogTrigger } from "@/components/ui/dialog";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Switch } from "@/components/ui/switch";
import { toast } from "sonner";
import { trpc } from "@/lib/trpc";
import AppShell from "@/components/AppShell";
import {
  Satellite, Search, Shield, Activity, Globe, RefreshCw,
  Loader2, AlertTriangle, CheckCircle, XCircle, Clock,
  BarChart3, Brain, Target, Eye, Newspaper, Database,
  ArrowRight, Play, Square, Zap, FileText, Users,
  TrendingUp, Calendar, MapPin, Crosshair, Radio,
  Rss, BookOpen, Building2, Scale,
} from "lucide-react";

// ─── Source Categories ──────────────────────────────────────────────────────

const SOURCE_CATEGORIES = {
  security_news: { label: "Security News", icon: <Newspaper className="h-4 w-4 text-blue-400" />, color: "bg-blue-500/10 text-blue-400" },
  research_blogs: { label: "Research Blogs", icon: <BookOpen className="h-4 w-4 text-purple-400" />, color: "bg-purple-500/10 text-purple-400" },
  government: { label: "Government Advisories", icon: <Building2 className="h-4 w-4 text-amber-400" />, color: "bg-amber-500/10 text-amber-400" },
  ransomware: { label: "Ransomware Tracking", icon: <AlertTriangle className="h-4 w-4 text-red-400" />, color: "bg-red-500/10 text-red-400" },
  regional: { label: "Regional/Diplomatic", icon: <Globe className="h-4 w-4 text-emerald-400" />, color: "bg-emerald-500/10 text-emerald-400" },
} as const;

// ─── Crawl Status Card ──────────────────────────────────────────────────────

function CrawlStatsCard() {
  const statsQuery = trpc.abilityGraph.crawlerStats.useQuery();
  const stats = statsQuery.data;

  return (
    <div className="grid grid-cols-2 md:grid-cols-5 gap-4">
      {[
        { label: "Actors Tracked", value: stats?.actorsTracked ?? 0, icon: <Users className="h-4 w-4 text-red-400" />, color: "text-red-400" },
        { label: "Sources Active", value: stats?.sourcesActive ?? 0, icon: <Rss className="h-4 w-4 text-blue-400" />, color: "text-blue-400" },
        { label: "Events Found", value: stats?.eventsFound ?? 0, icon: <Activity className="h-4 w-4 text-emerald-400" />, color: "text-emerald-400" },
        { label: "IOCs Extracted", value: stats?.iocsExtracted ?? 0, icon: <Crosshair className="h-4 w-4 text-amber-400" />, color: "text-amber-400" },
        { label: "TTPs Updated", value: stats?.ttpsUpdated ?? 0, icon: <Brain className="h-4 w-4 text-purple-400" />, color: "text-purple-400" },
      ].map((s, i) => (
        <Card key={i} className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 mb-2">
              <div className="p-1.5 bg-zinc-800 rounded">{s.icon}</div>
              <span className="text-[10px] text-zinc-500 uppercase tracking-wider">{s.label}</span>
            </div>
            <div className={`text-2xl font-mono font-bold ${s.color}`}>{s.value.toLocaleString()}</div>
          </CardContent>
        </Card>
      ))}
    </div>
  );
}

// ─── Crawl Management ───────────────────────────────────────────────────────

function CrawlManagement() {
  const [actorName, setActorName] = useState("");
  const [selectedCategory, setSelectedCategory] = useState("all");

  const crawlMut = trpc.abilityGraph.runCrawl.useMutation({
    onSuccess: (data: any) => {
      toast.success(`Crawl complete — found ${data?.newEvents ?? 0} new events, ${data?.newIocs ?? 0} IOCs`);
    },
    onError: (err) => toast.error(err.message),
  });

  const enrichMut = trpc.abilityGraph.runTargetedEnrichment.useMutation({
    onSuccess: (data: any) => {
      toast.success(`Enrichment complete — updated ${data?.fieldsUpdated ?? 0} fields`);
    },
    onError: (err) => toast.error(err.message),
  });

  const historyQuery = trpc.abilityGraph.crawlHistory.useQuery();

  return (
    <div className="space-y-6">
      {/* Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader>
            <CardTitle className="text-sm font-mono flex items-center gap-2">
              <Satellite className="h-4 w-4 text-cyan-400" /> FULL INTELLIGENCE CRAWL
            </CardTitle>
            <CardDescription className="text-xs">Crawl all OSINT sources for new threat actor intelligence</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label className="text-xs text-zinc-400">Source Category Filter</Label>
              <Select value={selectedCategory} onValueChange={setSelectedCategory}>
                <SelectTrigger className="bg-zinc-800 border-zinc-700"><SelectValue /></SelectTrigger>
                <SelectContent>
                  <SelectItem value="all">All Sources</SelectItem>
                  {Object.entries(SOURCE_CATEGORIES).map(([k, v]) => (
                    <SelectItem key={k} value={k}>{v.label}</SelectItem>
                  ))}
                </SelectContent>
              </Select>
            </div>
            <Button
              onClick={() => crawlMut.mutate({ category: selectedCategory === "all" ? undefined : selectedCategory })}
              disabled={crawlMut.isPending}
              className="w-full bg-cyan-600 hover:bg-cyan-500"
            >
              {crawlMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Satellite className="h-4 w-4 mr-2" />}
              Start Intelligence Crawl
            </Button>
          </CardContent>
        </Card>

        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader>
            <CardTitle className="text-sm font-mono flex items-center gap-2">
              <Target className="h-4 w-4 text-red-400" /> TARGETED ACTOR ENRICHMENT
            </CardTitle>
            <CardDescription className="text-xs">Deep-dive enrichment for a specific threat actor</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label className="text-xs text-zinc-400">Actor Name or Alias</Label>
              <Input
                value={actorName}
                onChange={(e) => setActorName(e.target.value)}
                placeholder="APT29, Lazarus Group, FIN7..."
                className="bg-zinc-800 border-zinc-700"
              />
            </div>
            <Button
              onClick={() => enrichMut.mutate({ actorName })}
              disabled={!actorName || enrichMut.isPending}
              className="w-full bg-red-600 hover:bg-red-500"
            >
              {enrichMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Zap className="h-4 w-4 mr-2" />}
              Enrich Actor Profile
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Crawl History */}
      <Card className="bg-zinc-900/50 border-zinc-800">
        <CardHeader>
          <CardTitle className="text-sm font-mono flex items-center gap-2">
            <Clock className="h-4 w-4 text-zinc-400" /> CRAWL HISTORY
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="rounded-lg border border-zinc-800 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-zinc-900/80 border-b border-zinc-800">
                  <th className="text-left p-3 text-zinc-400 font-mono text-xs">TIMESTAMP</th>
                  <th className="text-left p-3 text-zinc-400 font-mono text-xs">TYPE</th>
                  <th className="text-left p-3 text-zinc-400 font-mono text-xs">SOURCES</th>
                  <th className="text-left p-3 text-zinc-400 font-mono text-xs">EVENTS</th>
                  <th className="text-left p-3 text-zinc-400 font-mono text-xs">IOCs</th>
                  <th className="text-left p-3 text-zinc-400 font-mono text-xs">STATUS</th>
                </tr>
              </thead>
              <tbody>
                {historyQuery.isLoading ? (
                  <tr><td colSpan={6} className="p-8 text-center text-zinc-500"><Loader2 className="h-5 w-5 animate-spin mx-auto" /></td></tr>
                ) : !historyQuery.data?.length ? (
                  <tr><td colSpan={6} className="p-8 text-center text-zinc-500">
                    <Satellite className="h-8 w-8 mx-auto mb-2 opacity-30" />
                    No crawls yet. Start an intelligence crawl to begin enriching actor data.
                  </td></tr>
                ) : (
                  historyQuery.data.map((crawl: any, i: number) => (
                    <tr key={i} className="border-b border-zinc-800/50 hover:bg-zinc-800/30">
                      <td className="p-3 text-zinc-300 font-mono text-xs">{new Date(crawl.timestamp).toLocaleString()}</td>
                      <td className="p-3">
                        <Badge className={crawl.type === "full" ? "bg-cyan-500/10 text-cyan-400" : "bg-red-500/10 text-red-400"}>
                          {crawl.type?.toUpperCase()}
                        </Badge>
                      </td>
                      <td className="p-3 text-zinc-300 font-mono text-xs">{crawl.sourcesQueried ?? 0}</td>
                      <td className="p-3 text-zinc-300 font-mono text-xs">{crawl.eventsFound ?? 0}</td>
                      <td className="p-3 text-zinc-300 font-mono text-xs">{crawl.iocsExtracted ?? 0}</td>
                      <td className="p-3">
                        <Badge className={crawl.status === "completed" ? "bg-emerald-500/10 text-emerald-400" : "bg-amber-500/10 text-amber-400"}>
                          {crawl.status?.toUpperCase()}
                        </Badge>
                      </td>
                    </tr>
                  ))
                )}
              </tbody>
            </table>
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Activity Timeline ──────────────────────────────────────────────────────

function ActivityTimeline() {
  const timelineQuery = trpc.abilityGraph.actorTimeline.useQuery();

  return (
    <div className="space-y-4">
      {timelineQuery.isLoading ? (
        <div className="flex items-center justify-center h-40"><Loader2 className="h-5 w-5 animate-spin text-zinc-500" /></div>
      ) : !timelineQuery.data?.length ? (
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-8 text-center text-zinc-500">
            <Calendar className="h-8 w-8 mx-auto mb-2 opacity-30" />
            <p className="text-sm">No activity events yet. Run a crawl to discover threat actor activity.</p>
          </CardContent>
        </Card>
      ) : (
        <div className="relative">
          <div className="absolute left-6 top-0 bottom-0 w-px bg-zinc-800" />
          {timelineQuery.data.map((event: any, i: number) => (
            <div key={i} className="relative pl-14 pb-6">
              <div className={`absolute left-4 w-5 h-5 rounded-full border-2 ${
                event.severity === "critical" ? "bg-red-500/20 border-red-500" :
                event.severity === "high" ? "bg-amber-500/20 border-amber-500" :
                event.severity === "medium" ? "bg-blue-500/20 border-blue-500" :
                "bg-zinc-700/20 border-zinc-600"
              }`} />
              <Card className="bg-zinc-900/50 border-zinc-800">
                <CardContent className="p-4">
                  <div className="flex items-start justify-between">
                    <div>
                      <div className="flex items-center gap-2 mb-1">
                        <Badge className="bg-red-500/10 text-red-400 border-red-500/20">{event.actorName}</Badge>
                        <Badge variant="outline" className="text-zinc-400 border-zinc-700 text-[10px]">{event.eventType}</Badge>
                      </div>
                      <p className="text-sm text-zinc-300">{event.title}</p>
                      {event.description && (
                        <p className="text-xs text-zinc-500 mt-1 line-clamp-2">{event.description}</p>
                      )}
                      {event.techniques?.length > 0 && (
                        <div className="flex gap-1 mt-2 flex-wrap">
                          {event.techniques.slice(0, 5).map((t: string, j: number) => (
                            <Badge key={j} variant="outline" className="text-[10px] text-cyan-400 border-cyan-500/20">{t}</Badge>
                          ))}
                          {event.techniques.length > 5 && (
                            <Badge variant="outline" className="text-[10px] text-zinc-500 border-zinc-700">+{event.techniques.length - 5}</Badge>
                          )}
                        </div>
                      )}
                    </div>
                    <div className="text-right">
                      <div className="text-[10px] text-zinc-500 font-mono">{new Date(event.date).toLocaleDateString()}</div>
                      {event.source && (
                        <div className="text-[10px] text-zinc-600 mt-1">{event.source}</div>
                      )}
                    </div>
                  </div>
                </CardContent>
              </Card>
            </div>
          ))}
        </div>
      )}
    </div>
  );
}

// ─── Source Health ───────────────────────────────────────────────────────────

function SourceHealth() {
  const sourcesQuery = trpc.abilityGraph.crawlerSources.useQuery();

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {sourcesQuery.isLoading ? (
        Array.from({ length: 6 }).map((_, i) => (
          <Card key={i} className="bg-zinc-900/50 border-zinc-800 animate-pulse">
            <CardContent className="p-4 h-32" />
          </Card>
        ))
      ) : !sourcesQuery.data?.length ? (
        <Card className="bg-zinc-900/50 border-zinc-800 col-span-full">
          <CardContent className="p-8 text-center text-zinc-500">
            <Rss className="h-8 w-8 mx-auto mb-2 opacity-30" />
            <p className="text-sm">No sources configured yet.</p>
          </CardContent>
        </Card>
      ) : (
        sourcesQuery.data.map((source: any, i: number) => {
          const catMeta = SOURCE_CATEGORIES[source.category as keyof typeof SOURCE_CATEGORIES];
          return (
            <Card key={i} className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    {catMeta?.icon || <Globe className="h-4 w-4 text-zinc-400" />}
                    <span className="text-xs font-mono text-white">{source.name}</span>
                  </div>
                  <Badge className={source.healthy ? "bg-emerald-500/10 text-emerald-400" : "bg-red-500/10 text-red-400"}>
                    {source.healthy ? "HEALTHY" : "DOWN"}
                  </Badge>
                </div>
                <div className="space-y-2 text-xs text-zinc-400">
                  <div className="flex justify-between">
                    <span>Category</span>
                    <Badge className={catMeta?.color || "bg-zinc-700"} variant="outline">{catMeta?.label || source.category}</Badge>
                  </div>
                  <div className="flex justify-between">
                    <span>Last Crawl</span>
                    <span className="font-mono">{source.lastCrawl ? new Date(source.lastCrawl).toLocaleDateString() : "Never"}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Articles Found</span>
                    <span className="font-mono">{source.articlesFound ?? 0}</span>
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })
      )}
    </div>
  );
}

// ─── Main Page ──────────────────────────────────────────────────────────────

export default function ThreatActorCrawler() {
  return (
    <AppShell>
      <div className="space-y-6">
        {/* Header */}
        <div className="flex items-center justify-between">
          <div>
            <h1 className="text-2xl font-mono font-bold text-white tracking-tight flex items-center gap-3">
              <div className="p-2 bg-cyan-500/10 rounded-lg">
                <Satellite className="h-6 w-6 text-cyan-400" />
              </div>
              ACTOR INTEL CRAWLER
            </h1>
            <p className="text-sm text-zinc-400 mt-1">Continuous OSINT enrichment — 25+ sources · news · research · government advisories · ransomware tracking</p>
          </div>
        </div>

        {/* Stats */}
        <CrawlStatsCard />

        {/* Tabs */}
        <Tabs defaultValue="crawl" className="space-y-4">
          <TabsList className="bg-zinc-900 border border-zinc-800">
            <TabsTrigger value="crawl" className="data-[state=active]:bg-zinc-800 font-mono text-xs">
              <Satellite className="h-3.5 w-3.5 mr-1.5" /> CRAWL
            </TabsTrigger>
            <TabsTrigger value="timeline" className="data-[state=active]:bg-zinc-800 font-mono text-xs">
              <Calendar className="h-3.5 w-3.5 mr-1.5" /> TIMELINE
            </TabsTrigger>
            <TabsTrigger value="sources" className="data-[state=active]:bg-zinc-800 font-mono text-xs">
              <Rss className="h-3.5 w-3.5 mr-1.5" /> SOURCES
            </TabsTrigger>
          </TabsList>

          <TabsContent value="crawl">
            <CrawlManagement />
          </TabsContent>

          <TabsContent value="timeline">
            <ActivityTimeline />
          </TabsContent>

          <TabsContent value="sources">
            <SourceHealth />
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
