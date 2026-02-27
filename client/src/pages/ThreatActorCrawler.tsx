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
  Rss, BookOpen, Building2, Scale, Timer, Settings,
  Pause, SkipForward, Trash2,
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
        { label: "Total Crawls", value: stats?.totalCrawls ?? 0, icon: <Satellite className="h-4 w-4 text-cyan-400" />, color: "text-cyan-400" },
        { label: "Articles Processed", value: stats?.totalArticlesProcessed ?? 0, icon: <Rss className="h-4 w-4 text-blue-400" />, color: "text-blue-400" },
        { label: "Actors Enriched", value: stats?.totalActorsEnriched ?? 0, icon: <Users className="h-4 w-4 text-emerald-400" />, color: "text-emerald-400" },
        { label: "New Events", value: stats?.totalNewEvents ?? 0, icon: <Activity className="h-4 w-4 text-amber-400" />, color: "text-amber-400" },
        { label: "New IOCs", value: stats?.totalNewIocs ?? 0, icon: <Crosshair className="h-4 w-4 text-red-400" />, color: "text-red-400" },
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

  const crawlMut = trpc.abilityGraph.crawlIntel.useMutation({
    onSuccess: (data: any) => {
      toast.success(`Crawl complete — ${data?.summary || "done"}`);
    },
    onError: (err: any) => toast.error(err.message),
  });

  const enrichMut = trpc.abilityGraph.enrichActors.useMutation({
    onSuccess: (data: any) => {
      toast.success(`Enrichment complete — ${data?.summary || "done"}`);
    },
    onError: (err: any) => toast.error(err.message),
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
              <Label className="text-xs text-zinc-400">Actor Focus (optional)</Label>
              <Input
                value={actorName}
                onChange={(e) => setActorName(e.target.value)}
                placeholder="APT29, Lazarus Group, FIN7..."
                className="bg-zinc-800 border-zinc-700"
              />
            </div>
            <Button
              onClick={() => crawlMut.mutate({
                actorNames: actorName ? actorName.split(",").map(s => s.trim()) : undefined,
              })}
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
            <CardDescription className="text-xs">Deep-dive enrichment using LLM gap analysis</CardDescription>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label className="text-xs text-zinc-400">Actor Names (comma-separated, optional)</Label>
              <Input
                value={actorName}
                onChange={(e) => setActorName(e.target.value)}
                placeholder="APT29, Lazarus Group, FIN7..."
                className="bg-zinc-800 border-zinc-700"
              />
            </div>
            <Button
              onClick={() => enrichMut.mutate({
                actorNames: actorName ? actorName.split(",").map(s => s.trim()) : undefined,
              })}
              disabled={enrichMut.isPending}
              className="w-full bg-red-600 hover:bg-red-500"
            >
              {enrichMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Zap className="h-4 w-4 mr-2" />}
              Enrich Actor Profiles
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
                  <th className="text-left p-3 text-zinc-400 font-mono text-xs">CRAWL ID</th>
                  <th className="text-left p-3 text-zinc-400 font-mono text-xs">STARTED</th>
                  <th className="text-left p-3 text-zinc-400 font-mono text-xs">SOURCES</th>
                  <th className="text-left p-3 text-zinc-400 font-mono text-xs">ARTICLES</th>
                  <th className="text-left p-3 text-zinc-400 font-mono text-xs">ENRICHED</th>
                  <th className="text-left p-3 text-zinc-400 font-mono text-xs">IOCs</th>
                </tr>
              </thead>
              <tbody>
                {historyQuery.isLoading ? (
                  <tr><td colSpan={6} className="p-8 text-center text-zinc-500"><Loader2 className="h-5 w-5 animate-spin mx-auto" /></td></tr>
                ) : !(historyQuery.data as any)?.length ? (
                  <tr><td colSpan={6} className="p-8 text-center text-zinc-500">
                    <Satellite className="h-8 w-8 mx-auto mb-2 opacity-30" />
                    No crawls yet. Start an intelligence crawl to begin enriching actor data.
                  </td></tr>
                ) : (
                  (historyQuery.data as any[]).map((crawl: any, i: number) => (
                    <tr key={i} className="border-b border-zinc-800/50 hover:bg-zinc-800/30">
                      <td className="p-3 text-zinc-300 font-mono text-xs">{crawl.crawlId}</td>
                      <td className="p-3 text-zinc-300 font-mono text-xs">{crawl.startedAt ? new Date(crawl.startedAt).toLocaleString() : "—"}</td>
                      <td className="p-3 text-zinc-300 font-mono text-xs">{crawl.sourcesChecked ?? 0}</td>
                      <td className="p-3 text-zinc-300 font-mono text-xs">{crawl.articlesProcessed ?? 0}</td>
                      <td className="p-3 text-zinc-300 font-mono text-xs">{crawl.actorsEnriched ?? 0}</td>
                      <td className="p-3 text-zinc-300 font-mono text-xs">{crawl.newIocsFound ?? 0}</td>
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

// ─── Scheduler Dashboard ────────────────────────────────────────────────────

function SchedulerDashboard() {
  const statusQuery = trpc.abilityGraph.schedulerStatus.useQuery(undefined, {
    refetchInterval: 10000,
  });
  const presetsQuery = trpc.abilityGraph.schedulerPresets.useQuery();
  const jobHistoryQuery = trpc.abilityGraph.jobHistory.useQuery();
  const queueQuery = trpc.abilityGraph.queueStatus.useQuery(undefined, {
    refetchInterval: 5000,
  });

  const startMut = trpc.abilityGraph.startScheduler.useMutation({
    onSuccess: () => {
      toast.success("Scheduler started");
      statusQuery.refetch();
    },
    onError: (err: any) => toast.error(err.message),
  });

  const stopMut = trpc.abilityGraph.stopScheduler.useMutation({
    onSuccess: () => {
      toast.success("Scheduler stopped");
      statusQuery.refetch();
    },
    onError: (err: any) => toast.error(err.message),
  });

  const pauseMut = trpc.abilityGraph.pauseScheduler.useMutation({
    onSuccess: () => {
      toast.success("Scheduler paused");
      statusQuery.refetch();
    },
    onError: (err: any) => toast.error(err.message),
  });

  const resumeMut = trpc.abilityGraph.resumeScheduler.useMutation({
    onSuccess: () => {
      toast.success("Scheduler resumed");
      statusQuery.refetch();
    },
    onError: (err: any) => toast.error(err.message),
  });

  const forceRunMut = trpc.abilityGraph.forceRunJob.useMutation({
    onSuccess: () => {
      toast.success("Job queued (critical priority)");
      statusQuery.refetch();
      queueQuery.refetch();
    },
    onError: (err: any) => toast.error(err.message),
  });

  const enqueueMut = trpc.abilityGraph.enqueueJob.useMutation({
    onSuccess: () => {
      toast.success("Job enqueued");
      queueQuery.refetch();
    },
    onError: (err: any) => toast.error(err.message),
  });

  const cancelMut = trpc.abilityGraph.cancelJob.useMutation({
    onSuccess: () => {
      toast.success("Job cancelled");
      queueQuery.refetch();
    },
    onError: (err: any) => toast.error(err.message),
  });

  const updateConfigMut = trpc.abilityGraph.updateSchedulerConfig.useMutation({
    onSuccess: () => {
      toast.success("Configuration updated");
      statusQuery.refetch();
    },
    onError: (err: any) => toast.error(err.message),
  });

  const status = statusQuery.data;
  const presets = presetsQuery.data;
  const [selectedPreset, setSelectedPreset] = useState("standard");

  return (
    <div className="space-y-6">
      {/* Scheduler Status */}
      <div className="grid grid-cols-2 md:grid-cols-4 gap-4">
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 mb-2">
              <div className={`p-1.5 rounded ${status?.isRunning ? "bg-emerald-500/10" : "bg-zinc-800"}`}>
                {status?.isRunning ? <Play className="h-4 w-4 text-emerald-400" /> : <Square className="h-4 w-4 text-zinc-500" />}
              </div>
              <span className="text-[10px] text-zinc-500 uppercase tracking-wider">Status</span>
            </div>
            <div className={`text-lg font-mono font-bold ${status?.isRunning ? "text-emerald-400" : "text-zinc-500"}`}>
              {status?.isRunning ? "RUNNING" : "STOPPED"}
            </div>
            {status?.config?.preset && (
              <div className="text-[10px] text-zinc-600 mt-1 font-mono">Preset: {status.config.preset}</div>
            )}
          </CardContent>
        </Card>

        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 mb-2">
              <div className="p-1.5 bg-zinc-800 rounded"><Timer className="h-4 w-4 text-blue-400" /></div>
              <span className="text-[10px] text-zinc-500 uppercase tracking-wider">Next Run</span>
            </div>
            <div className="text-sm font-mono text-blue-400">
              {status?.nextScheduledRun ? new Date(status.nextScheduledRun).toLocaleTimeString() : "—"}
            </div>
            {status?.lastCrawlAt && (
              <div className="text-[10px] text-zinc-600 mt-1 font-mono">Last: {new Date(status.lastCrawlAt).toLocaleTimeString()}</div>
            )}
          </CardContent>
        </Card>

        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 mb-2">
              <div className="p-1.5 bg-zinc-800 rounded"><BarChart3 className="h-4 w-4 text-amber-400" /></div>
              <span className="text-[10px] text-zinc-500 uppercase tracking-wider">Jobs Run</span>
            </div>
            <div className="text-lg font-mono font-bold text-amber-400">{status?.totalJobsRun ?? 0}</div>
            <div className="text-[10px] text-zinc-600 mt-1">
              <span className="text-emerald-400">{status?.completedJobs ?? 0} ok</span>
              {" · "}
              <span className="text-red-400">{status?.failedJobs ?? 0} failed</span>
            </div>
          </CardContent>
        </Card>

        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardContent className="p-4">
            <div className="flex items-center gap-2 mb-2">
              <div className="p-1.5 bg-zinc-800 rounded"><Database className="h-4 w-4 text-purple-400" /></div>
              <span className="text-[10px] text-zinc-500 uppercase tracking-wider">Queue</span>
            </div>
            <div className="text-lg font-mono font-bold text-purple-400">{status?.queuedJobs ?? 0}</div>
            {status?.currentJob && (
              <div className="text-[10px] text-zinc-600 mt-1 font-mono">Running: {status.currentJob.type}</div>
            )}
          </CardContent>
        </Card>
      </div>

      {/* Controls */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
        {/* Preset Selection & Start/Stop */}
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader>
            <CardTitle className="text-sm font-mono flex items-center gap-2">
              <Settings className="h-4 w-4 text-zinc-400" /> SCHEDULER CONFIGURATION
            </CardTitle>
          </CardHeader>
          <CardContent className="space-y-4">
            <div>
              <Label className="text-xs text-zinc-400">Schedule Preset</Label>
              <Select value={selectedPreset} onValueChange={setSelectedPreset}>
                <SelectTrigger className="bg-zinc-800 border-zinc-700"><SelectValue /></SelectTrigger>
                <SelectContent>
                  {presets?.map((p: any) => (
                    <SelectItem key={p.id} value={p.id}>
                      {p.name} — {p.crawlInterval}
                    </SelectItem>
                  ))}
                </SelectContent>
              </Select>
              {presets?.find((p: any) => p.id === selectedPreset) && (
                <p className="text-[10px] text-zinc-500 mt-1">
                  {presets.find((p: any) => p.id === selectedPreset)?.description}
                </p>
              )}
            </div>

            <div className="flex items-center justify-between">
              <Label className="text-xs text-zinc-400">Auto-Enrich After Crawl</Label>
              <Switch
                checked={status?.config?.autoEnrichAfterCrawl ?? true}
                onCheckedChange={(checked) => updateConfigMut.mutate({ autoEnrichAfterCrawl: checked })}
              />
            </div>

            <div className="flex items-center justify-between">
              <Label className="text-xs text-zinc-400">Retry Failed Jobs</Label>
              <Switch
                checked={status?.config?.retryFailedJobs ?? true}
                onCheckedChange={(checked) => updateConfigMut.mutate({ retryFailedJobs: checked })}
              />
            </div>

            <div className="flex items-center justify-between">
              <Label className="text-xs text-zinc-400">Notify on Failure</Label>
              <Switch
                checked={status?.config?.notifyOnFailure ?? true}
                onCheckedChange={(checked) => updateConfigMut.mutate({ notifyOnFailure: checked })}
              />
            </div>

            <div className="flex gap-2">
              {!status?.isRunning ? (
                <Button
                  onClick={() => startMut.mutate({ preset: selectedPreset as any })}
                  disabled={startMut.isPending}
                  className="flex-1 bg-emerald-600 hover:bg-emerald-500"
                >
                  {startMut.isPending ? <Loader2 className="h-4 w-4 animate-spin mr-2" /> : <Play className="h-4 w-4 mr-2" />}
                  Start Scheduler
                </Button>
              ) : (
                <>
                  <Button
                    onClick={() => pauseMut.mutate()}
                    disabled={pauseMut.isPending}
                    variant="outline"
                    className="flex-1 border-zinc-700"
                  >
                    <Pause className="h-4 w-4 mr-2" /> Pause
                  </Button>
                  <Button
                    onClick={() => stopMut.mutate()}
                    disabled={stopMut.isPending}
                    variant="destructive"
                    className="flex-1"
                  >
                    <Square className="h-4 w-4 mr-2" /> Stop
                  </Button>
                </>
              )}
            </div>
          </CardContent>
        </Card>

        {/* Quick Actions */}
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader>
            <CardTitle className="text-sm font-mono flex items-center gap-2">
              <Zap className="h-4 w-4 text-amber-400" /> QUICK ACTIONS
            </CardTitle>
            <CardDescription className="text-xs">Force-run jobs immediately or enqueue with priority</CardDescription>
          </CardHeader>
          <CardContent className="space-y-3">
            <Button
              onClick={() => forceRunMut.mutate({ type: "full_crawl" })}
              disabled={forceRunMut.isPending}
              className="w-full bg-cyan-600 hover:bg-cyan-500 justify-start"
            >
              <Satellite className="h-4 w-4 mr-2" /> Force Full Crawl
              <Badge className="ml-auto bg-red-500/20 text-red-300 text-[10px]">CRITICAL</Badge>
            </Button>
            <Button
              onClick={() => forceRunMut.mutate({ type: "targeted_enrichment" })}
              disabled={forceRunMut.isPending}
              className="w-full bg-red-600 hover:bg-red-500 justify-start"
            >
              <Target className="h-4 w-4 mr-2" /> Force Enrichment
              <Badge className="ml-auto bg-red-500/20 text-red-300 text-[10px]">CRITICAL</Badge>
            </Button>
            <Button
              onClick={() => enqueueMut.mutate({ type: "gap_analysis", priority: "high" })}
              disabled={enqueueMut.isPending}
              variant="outline"
              className="w-full border-zinc-700 justify-start"
            >
              <BarChart3 className="h-4 w-4 mr-2" /> Run Gap Analysis
              <Badge className="ml-auto bg-amber-500/20 text-amber-300 text-[10px]">HIGH</Badge>
            </Button>
            <Button
              onClick={() => enqueueMut.mutate({ type: "source_check", priority: "normal" })}
              disabled={enqueueMut.isPending}
              variant="outline"
              className="w-full border-zinc-700 justify-start"
            >
              <Rss className="h-4 w-4 mr-2" /> Check Source Health
              <Badge className="ml-auto bg-zinc-500/20 text-zinc-300 text-[10px]">NORMAL</Badge>
            </Button>
          </CardContent>
        </Card>
      </div>

      {/* Job Queue */}
      {(queueQuery.data?.queueLength ?? 0) > 0 && (
        <Card className="bg-zinc-900/50 border-zinc-800">
          <CardHeader>
            <CardTitle className="text-sm font-mono flex items-center gap-2">
              <Clock className="h-4 w-4 text-blue-400" /> JOB QUEUE ({queueQuery.data?.queueLength})
            </CardTitle>
          </CardHeader>
          <CardContent>
            <div className="space-y-2">
              {queueQuery.data?.jobs?.map((job: any) => (
                <div key={job.id} className="flex items-center justify-between bg-zinc-800/50 rounded-lg p-3">
                  <div className="flex items-center gap-3">
                    <Badge className={
                      job.priority === "critical" ? "bg-red-500/10 text-red-400" :
                      job.priority === "high" ? "bg-amber-500/10 text-amber-400" :
                      "bg-zinc-700/50 text-zinc-400"
                    }>
                      {job.priority?.toUpperCase()}
                    </Badge>
                    <div>
                      <div className="text-xs font-mono text-white">{job.type.replace(/_/g, " ").toUpperCase()}</div>
                      <div className="text-[10px] text-zinc-500">{job.id}</div>
                    </div>
                  </div>
                  <Button
                    variant="outline"
                    size="sm"
                    className="border-zinc-700 h-7 text-xs"
                    onClick={() => cancelMut.mutate({ jobId: job.id })}
                    disabled={cancelMut.isPending}
                  >
                    <Trash2 className="h-3 w-3 mr-1" /> Cancel
                  </Button>
                </div>
              ))}
            </div>
          </CardContent>
        </Card>
      )}

      {/* Job History */}
      <Card className="bg-zinc-900/50 border-zinc-800">
        <CardHeader>
          <CardTitle className="text-sm font-mono flex items-center gap-2">
            <FileText className="h-4 w-4 text-zinc-400" /> JOB HISTORY
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div className="rounded-lg border border-zinc-800 overflow-hidden">
            <table className="w-full text-sm">
              <thead>
                <tr className="bg-zinc-900/80 border-b border-zinc-800">
                  <th className="text-left p-3 text-zinc-400 font-mono text-xs">JOB ID</th>
                  <th className="text-left p-3 text-zinc-400 font-mono text-xs">TYPE</th>
                  <th className="text-left p-3 text-zinc-400 font-mono text-xs">PRIORITY</th>
                  <th className="text-left p-3 text-zinc-400 font-mono text-xs">STATUS</th>
                  <th className="text-left p-3 text-zinc-400 font-mono text-xs">STARTED</th>
                  <th className="text-left p-3 text-zinc-400 font-mono text-xs">SUMMARY</th>
                </tr>
              </thead>
              <tbody>
                {jobHistoryQuery.isLoading ? (
                  <tr><td colSpan={6} className="p-8 text-center text-zinc-500"><Loader2 className="h-5 w-5 animate-spin mx-auto" /></td></tr>
                ) : !(jobHistoryQuery.data as any)?.length ? (
                  <tr><td colSpan={6} className="p-8 text-center text-zinc-500">
                    <Timer className="h-8 w-8 mx-auto mb-2 opacity-30" />
                    No scheduled jobs have run yet. Start the scheduler or force-run a job.
                  </td></tr>
                ) : (
                  (jobHistoryQuery.data as any[]).map((job: any) => (
                    <tr key={job.id} className="border-b border-zinc-800/50 hover:bg-zinc-800/30">
                      <td className="p-3 text-zinc-300 font-mono text-xs">{job.id}</td>
                      <td className="p-3">
                        <Badge className="bg-zinc-700/50 text-zinc-300 text-[10px]">
                          {job.type?.replace(/_/g, " ").toUpperCase()}
                        </Badge>
                      </td>
                      <td className="p-3">
                        <Badge className={
                          job.priority === "critical" ? "bg-red-500/10 text-red-400" :
                          job.priority === "high" ? "bg-amber-500/10 text-amber-400" :
                          "bg-zinc-700/50 text-zinc-400"
                        }>
                          {job.priority?.toUpperCase()}
                        </Badge>
                      </td>
                      <td className="p-3">
                        <Badge className={
                          job.status === "completed" ? "bg-emerald-500/10 text-emerald-400" :
                          job.status === "failed" ? "bg-red-500/10 text-red-400" :
                          job.status === "cancelled" ? "bg-zinc-700/50 text-zinc-400" :
                          "bg-blue-500/10 text-blue-400"
                        }>
                          {job.status?.toUpperCase()}
                        </Badge>
                      </td>
                      <td className="p-3 text-zinc-400 text-xs font-mono">
                        {job.startedAt ? new Date(job.startedAt).toLocaleString() : "—"}
                      </td>
                      <td className="p-3 text-zinc-400 text-xs max-w-xs truncate">
                        {job.result?.summary || job.error || "—"}
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

// ─── Source Health ───────────────────────────────────────────────────────────

function SourceHealth() {
  const sourcesQuery = trpc.abilityGraph.crawlSources.useQuery();

  const toggleMut = trpc.abilityGraph.toggleCrawlSource.useMutation({
    onSuccess: () => {
      toast.success("Source updated");
      sourcesQuery.refetch();
    },
    onError: (err: any) => toast.error(err.message),
  });

  return (
    <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-4">
      {sourcesQuery.isLoading ? (
        Array.from({ length: 6 }).map((_, i) => (
          <Card key={i} className="bg-zinc-900/50 border-zinc-800 animate-pulse">
            <CardContent className="p-4 h-32" />
          </Card>
        ))
      ) : !(sourcesQuery.data as any)?.length ? (
        <Card className="bg-zinc-900/50 border-zinc-800 col-span-full">
          <CardContent className="p-8 text-center text-zinc-500">
            <Rss className="h-8 w-8 mx-auto mb-2 opacity-30" />
            <p className="text-sm">No sources configured yet.</p>
          </CardContent>
        </Card>
      ) : (
        (sourcesQuery.data as any[]).map((source: any, i: number) => {
          const catMeta = SOURCE_CATEGORIES[source.category as keyof typeof SOURCE_CATEGORIES];
          return (
            <Card key={i} className="bg-zinc-900/50 border-zinc-800">
              <CardContent className="p-4">
                <div className="flex items-center justify-between mb-3">
                  <div className="flex items-center gap-2">
                    {catMeta?.icon || <Globe className="h-4 w-4 text-zinc-400" />}
                    <span className="text-xs font-mono text-white">{source.name}</span>
                  </div>
                  <Switch
                    checked={source.enabled}
                    onCheckedChange={(checked) => toggleMut.mutate({ sourceId: source.id, enabled: checked })}
                  />
                </div>
                <div className="space-y-2 text-xs text-zinc-400">
                  <div className="flex justify-between">
                    <span>Category</span>
                    <Badge className={catMeta?.color || "bg-zinc-700"} variant="outline">{catMeta?.label || source.category}</Badge>
                  </div>
                  <div className="flex justify-between">
                    <span>Type</span>
                    <span className="font-mono">{source.type}</span>
                  </div>
                  <div className="flex justify-between">
                    <span>Priority</span>
                    <span className="font-mono">{source.priority}/10</span>
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
            <p className="text-sm text-zinc-400 mt-1">Continuous OSINT enrichment — 25+ sources · scheduled crawls · LLM gap analysis · auto-enrichment</p>
          </div>
        </div>

        {/* Stats */}
        <CrawlStatsCard />

        {/* Tabs */}
        <Tabs defaultValue="scheduler" className="space-y-4">
          <TabsList className="bg-zinc-900 border border-zinc-800">
            <TabsTrigger value="scheduler" className="data-[state=active]:bg-zinc-800 font-mono text-xs">
              <Timer className="h-3.5 w-3.5 mr-1.5" /> SCHEDULER
            </TabsTrigger>
            <TabsTrigger value="crawl" className="data-[state=active]:bg-zinc-800 font-mono text-xs">
              <Satellite className="h-3.5 w-3.5 mr-1.5" /> MANUAL CRAWL
            </TabsTrigger>
            <TabsTrigger value="sources" className="data-[state=active]:bg-zinc-800 font-mono text-xs">
              <Rss className="h-3.5 w-3.5 mr-1.5" /> SOURCES
            </TabsTrigger>
          </TabsList>

          <TabsContent value="scheduler">
            <SchedulerDashboard />
          </TabsContent>

          <TabsContent value="crawl">
            <CrawlManagement />
          </TabsContent>

          <TabsContent value="sources">
            <SourceHealth />
          </TabsContent>
        </Tabs>
      </div>
    </AppShell>
  );
}
