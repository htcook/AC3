import AppShell from "@/components/AppShell";
import { trpc } from "@/lib/trpc";
import { safeUpper } from "@/lib/utils-safe";
import { useState, useMemo } from "react";
import { Link } from "wouter";
import AlertDetailModal from "@/components/AlertDetailModal";
import {
  AlertTriangle, Eye, Globe2, Shield, Skull, Clock,
  Activity, TrendingUp, Search, ExternalLink, Radio, Rss, ScanSearch,
  Database, Loader2, RefreshCw, Crosshair, FileText,
  Zap, Bug, Key, Tag, Wifi, WifiOff, ChevronDown, ChevronUp, ChevronRight,
  ShieldAlert, Megaphone, DollarSign, Users, Network, FileJson, BarChart3,
} from "lucide-react";
import { toast } from "sonner";
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  Tooltip, ResponsiveContainer, Cell, Legend, PieChart, Pie,
  LineChart, Line, ComposedChart,
} from "recharts";

import { sanitizeErrorForToast } from "@/lib/error-sanitizer";
// ─── Color Maps ──────────────────────────────────────────────────────────

const EVENT_TYPE_COLORS: Record<string, string> = {
  attack: "text-red-400 bg-red-500/10",
  campaign: "text-orange-400 bg-orange-500/10",
  data_leak: "text-amber-400 bg-amber-500/10",
  infrastructure_change: "text-blue-400 bg-blue-500/10",
  malware_update: "text-purple-400 bg-purple-500/10",
  law_enforcement: "text-green-400 bg-green-500/10",
  ttp_evolution: "text-cyan-400 bg-cyan-500/10",
  group_rebrand: "text-pink-400 bg-pink-500/10",
  new_tool: "text-indigo-400 bg-indigo-500/10",
  zero_day: "text-red-500 bg-red-500/15",
  affiliate_change: "text-yellow-400 bg-yellow-500/10",
  group_merger: "text-violet-400 bg-violet-500/10",
};

const ACTOR_TYPE_COLORS: Record<string, string> = {
  apt: "text-red-400",
  ransomware: "text-amber-400",
  cybercrime: "text-purple-400",
  hacktivist: "text-cyan-400",
  access_broker: "text-orange-400",
  influence_ops: "text-pink-400",
};

const SEVERITY_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  medium: "text-amber-400 bg-amber-500/10 border-amber-500/30",
  low: "text-blue-400 bg-blue-500/10 border-blue-500/30",
};

// ─── Component ───────────────────────────────────────────────────────────

export default function DarkwebIntel() {

  const [eventTypeFilter, setEventTypeFilter] = useState<string>("all");
  const [limit, setLimit] = useState(100);
  const [expandedSections, setExpandedSections] = useState<Record<string, boolean>>({
    alerts: true, iocs: true, kev: true, otx: false, malware: false, keywords: false,
    iabs: true, infoOps: true, govBrokers: true, brokerTimeline: true, iabTrends: true, iabControls: false, iabPriority: true,
  });

  const [selectedAlertId, setSelectedAlertId] = useState<number | null>(null);
  const [alertModalOpen, setAlertModalOpen] = useState(false);
  const [expandedIAB, setExpandedIAB] = useState<number | null>(null);
  const [spikeResults, setSpikeResults] = useState<any>(null);
  const [priorityFilter, setPriorityFilter] = useState<'all' | 'critical' | 'high' | 'medium' | 'low'>('all');
  const [categoryFilter, setCategoryFilter] = useState<'all' | 'us_gov' | 'ics_scada' | 'defense_contractor' | 'critical_infrastructure' | 'general'>('all');

  // Victim event filter state
  const [victimSearch, setVictimSearch] = useState("");
  const [victimCountry, setVictimCountry] = useState("");
  const [victimSector, setVictimSector] = useState("");
  const [victimActor, setVictimActor] = useState("");
  const [showVictimFilters, setShowVictimFilters] = useState(false);
  const victimFilterActive = !!(victimSearch || victimCountry || victimSector || victimActor);

  const toggleSection = (key: string) =>
    setExpandedSections(prev => ({ ...prev, [key]: !prev[key] }));

  // ─── Existing local queries ────────────────────────────────────────────
  const { data: events, isLoading: eventsLoading, refetch: refetchEvents } = trpc.threatIntel.recentEvents.useQuery({
    limit,
    eventType: eventTypeFilter !== "all" ? eventTypeFilter : undefined,
  });
  const { data: syncHistory, isLoading: syncLoading } = trpc.threatIntel.syncHistory.useQuery({ limit: 10 });
  const { data: stats } = trpc.threatIntel.stats.useQuery();
  const { data: coverage } = trpc.threatIntel.techniqueCoverage.useQuery();

  // ─── Darkweb Intel queries (self-contained, no bridge dependency) ──────
  const { data: bridgeHealth } = trpc.darkwebIntel.health.useQuery();
  const { data: escalationAlerts, isLoading: alertsLoading } = trpc.darkwebIntel.escalationAlerts.useQuery({});
  const { data: ransomwareVictimStats } = trpc.darkwebIntel.ransomwareVictimStats.useQuery({});
  const { data: activityRatings } = trpc.darkwebIntel.activityRatings.useQuery();
  const { data: threatFoxIOCs, isLoading: iocsLoading } = trpc.darkwebIntel.threatFoxIOCs.useQuery({});
  const { data: cisaKEV, isLoading: kevLoading } = trpc.darkwebIntel.cisaKEV.useQuery({});
  const { data: otxPulses, isLoading: otxLoading } = trpc.darkwebIntel.otxPulses.useQuery({});
  const { data: malwareBazaar, isLoading: malwareLoading } = trpc.darkwebIntel.malwareBazaar.useQuery({});
  const { data: adaptiveKeywords } = trpc.darkwebIntel.adaptiveKeywords.useQuery();
  const victimFilterInput = useMemo(() => ({
    limit: 100,
    ...(victimSearch ? { search: victimSearch } : {}),
    ...(victimCountry ? { country: victimCountry } : {}),
    ...(victimSector ? { sector: victimSector } : {}),
    ...(victimActor ? { actorName: victimActor } : {}),
  }), [victimSearch, victimCountry, victimSector, victimActor]);
  const { data: recentVictimEvents } = trpc.darkwebIntel.recentVictimEvents.useQuery(victimFilterInput);

  // ─── Access Broker & Info Ops queries ──────────────────────────────────
  const { data: accessBrokers, isLoading: iabsLoading, refetch: refetchIABs } = trpc.darkwebIntel.accessBrokers.useQuery({});
  const [timelineDays, setTimelineDays] = useState(90);
  const { data: brokerTimeline, isLoading: timelineLoading } = trpc.darkwebIntel.brokerTimeline.useQuery({ days: timelineDays });
  const [trendDays, setTrendDays] = useState(365);
  const { data: iabTrends, isLoading: trendsLoading } = trpc.darkwebIntel.iabTrends.useQuery({ days: trendDays });
  const [selectedTrendSectors, setSelectedTrendSectors] = useState<string[]>(['Government']);

  // ─── Priority Intelligence queries ─────────────────────────────────────────
  const { data: prioritySummary, isLoading: priorityLoading, refetch: refetchPriority } = trpc.darkwebIntel.iabPrioritySummary.useQuery();
  const priorityListingsInput = useMemo(() => ({
    priorityLevel: priorityFilter as any,
    category: categoryFilter as any,
    limit: 50,
    offset: 0,
  }), [priorityFilter, categoryFilter]);
  const { data: priorityListings, isLoading: priorityListingsLoading } = trpc.darkwebIntel.iabPriorityListings.useQuery(priorityListingsInput);
  const classifyAll = trpc.darkwebIntel.iabClassifyAll.useMutation({
    onSuccess: (data) => {
      toast.success(`Classified ${data.total} listings: ${data.critical} critical, ${data.high} high, ${data.medium} medium, ${data.low} low`);
      refetchPriority();
    },
    onError: (err) => toast.error('Classification failed: ' + sanitizeErrorForToast(err)),
  });

  // ─── US Gov Access Broker queries ──────────────────────────────────────
  const [govSearch, setGovSearch] = useState("");
  const { data: govBrokers, isLoading: govBrokersLoading } = trpc.darkwebBridge.govBrokerKnowledgeBase.useQuery(
    govSearch ? { search: govSearch } : undefined
  );
  const { data: govStats } = trpc.darkwebBridge.govBrokerStats.useQuery();
  const { data: govForumActivity } = trpc.darkwebBridge.govForumActivity.useQuery();
  const seedGovBrokers = trpc.darkwebBridge.seedGovBrokers.useMutation({
    onSuccess: (result) => {
      toast.success("Gov Brokers Seeded", {
        description: `${result.inserted} new, ${result.updated} updated (${result.total} total)`,
      });
      refetchIABs();
    },
    onError: (err) => toast.error("Seed Failed", { description: sanitizeErrorForToast(err) }),
  });
  const { data: iosCampaigns, isLoading: iosLoading, refetch: refetchIOs } = trpc.darkwebIntel.infoOpsCampaigns.useQuery({});
  const syncDarkwebFeeds = trpc.darkwebIntel.syncDarkwebFeeds.useMutation({
    onSuccess: (result) => {
      const ddw = result.dailyDarkWeb;
      const ddwMsg = ddw ? ` DDW: ${ddw.fulcrumsec.iocs} IOCs, ${ddw.fulcrumsec.events + ddw.actors.events} events, ${ddw.actors.actors} new actors.` : "";
      toast.success("Darkweb Feeds Synced", {
        description: `IABs: ${result.accessBrokers.inserted} new / ${result.accessBrokers.updated} updated (${result.accessBrokers.total} total). IO Campaigns: ${result.infoOps.inserted} new / ${result.infoOps.updated} updated (${result.infoOps.total} total).${ddwMsg}`,
      });
      refetchIABs();
      refetchIOs();
    },
    onError: (err) => toast.error("Feed Sync Failed", { description: sanitizeErrorForToast(err) }),
  });

  // ─── Mutations ─────────────────────────────────────────────────────────
  const monitoringSweep = trpc.threatIntel.runMonitoringSweep.useMutation({
    onSuccess: () => refetchEvents(),
  });

  const syncAll = trpc.darkwebIntel.syncAll.useMutation({
    onSuccess: (result) => {
      toast.success("Darkweb Sync Complete", {
        description: `Imported: ${result.actorsImported} actors, ${result.iocsImported} IOCs, ${result.eventsImported} events. ${result.errors.length > 0 ? `Errors: ${result.errors.length}` : ""}`,
      });
      refetchEvents();
    },
    onError: (err) => {
      toast.error("Sync Failed", { description: sanitizeErrorForToast(err) });
    },
  });

  const syncRSS = trpc.darkwebIntel.syncDailyDarkWebRSS.useMutation({
    onSuccess: (result) => {
      toast.success("DDW RSS Sync Complete", {
        description: `Fetched ${result.totalItemsFetched} articles, extracted ${result.totalEventsExtracted} events, ingested ${result.totalEventsIngested} new events, updated ${result.totalActorsUpdated} actors (${result.duration}ms)`,
      });
      refetchEvents();
    },
    onError: (err) => toast.error("RSS Sync Failed", { description: sanitizeErrorForToast(err) }),
  });

  const crossRefIOCs = trpc.darkwebIntel.crossReferenceIOCs.useMutation({
    onSuccess: (result) => {
      const matchCount = result.matches.length;
      if (matchCount === 0) {
        toast.info("IOC Cross-Reference Complete", {
          description: `Checked ${result.totalIOCsChecked} IOCs against ${result.totalAssetsChecked} assets. No matches found. (${result.duration}ms)`,
        });
      } else {
        toast.warning(`IOC Cross-Reference: ${matchCount} Match${matchCount > 1 ? "es" : ""} Found`, {
          description: `Critical: ${result.matchesByRiskLevel.critical ?? 0}, High: ${result.matchesByRiskLevel.high ?? 0}, Medium: ${result.matchesByRiskLevel.medium ?? 0}. Checked ${result.totalIOCsChecked} IOCs against ${result.totalAssetsChecked} assets. (${result.duration}ms)`,
          duration: 10000,
        });
      }
    },
    onError: (err) => toast.error("IOC Cross-Reference Failed", { description: sanitizeErrorForToast(err) }),
  });

  const syncAllRSS = trpc.darkwebIntel.syncAllThreatIntelRSS.useMutation({
    onSuccess: (result) => {
      toast.success(`Multi-Source RSS Sync Complete (${result.feedsSucceeded}/${result.totalFeeds} feeds)`, {
        description: `${result.totalItemsFetched} items → TGE:${result.totalThreatGroupEvents} RE:${result.totalRansomwareEvents} UIE:${result.totalUndergroundEvents} IR:${result.totalIncidentReports} | ${result.totalDuplicatesSkipped} dupes skipped (${(result.duration / 1000).toFixed(1)}s)`,
        duration: 10000,
      });
      refetchEvents();
    },
    onError: (err) => toast.error("Multi-Source RSS Sync Failed", { description: sanitizeErrorForToast(err) }),
  });

  const eventTypes = [
    "all", "attack", "campaign", "data_leak", "infrastructure_change",
    "malware_update", "law_enforcement", "ttp_evolution", "zero_day", "new_tool",
  ];

  // Merge bridge victim events into the local event feed
  const bridgeVictimCount = recentVictimEvents?.data?.length ?? 0;
  const bridgeIOCCount = threatFoxIOCs?.data?.length ?? 0;
  const bridgeAlertCount = escalationAlerts?.data?.length ?? 0;
  // ─── IAB Ingestion Button Component ──────────────────────────────────
  function IABIngestButton({ label, source }: { label: string; source?: string }) {
    const ingestFull = trpc.darkwebIntel.iabIngest.useMutation({
      onSuccess: (data: any) => {
        toast.success(`Ingestion complete: ${data.totalInserted} new listings from ${data.results?.length || 0} sources`);
      },
      onError: (err: any) => toast.error(sanitizeErrorForToast(err)),
    });
    const ingestSource = trpc.darkwebIntel.iabIngestSource.useMutation({
      onSuccess: (data: any) => {
        toast.success(`${data.source}: ${data.inserted} inserted, ${data.skipped} skipped (${data.durationMs}ms)`);
      },
      onError: (err: any) => toast.error(sanitizeErrorForToast(err)),
    });
    const isLoading = ingestFull.isPending || ingestSource.isPending;
    const handleClick = () => {
      if (source) {
        ingestSource.mutate({ source: source as any });
      } else {
        ingestFull.mutate();
      }
    };
    return (
      <button
        onClick={handleClick}
        disabled={isLoading}
        className={`text-[10px] px-2 py-1 border transition-colors flex items-center gap-1 ${
          !source
            ? 'border-emerald-500/50 text-emerald-400 bg-emerald-500/10 hover:bg-emerald-500/20'
            : 'border-border text-muted-foreground hover:text-foreground hover:border-foreground/30'
        } disabled:opacity-50`}
      >
        {isLoading ? <Loader2 className="w-3 h-3 animate-spin" /> : <Database className="w-3 h-3" />}
        {label}
      </button>
    );
  }

  // ─── IAB Spike Check Button Component ───────────────────────────────
  function IABSpikeCheckButton() {
    const spikeCheck = trpc.darkwebIntel.iabSpikeCheck.useMutation({
      onSuccess: (data: any) => {
        if (data.alerts.length === 0) {
          toast.success('No IAB spikes detected. All metrics within normal thresholds.');
        } else {
          const critical = data.alerts.filter((a: any) => a.severity === 'critical').length;
          const high = data.alerts.filter((a: any) => a.severity === 'high').length;
          toast.warning(
            `${data.alerts.length} alerts detected: ${critical} critical, ${high} high. ${data.notificationsSent} notifications sent.`
          );
        }
        setSpikeResults(data);
      },
      onError: (err: any) => toast.error(sanitizeErrorForToast(err)),
    });
    return (
      <div className="space-y-3">
        <button
          onClick={() => spikeCheck.mutate({})}
          disabled={spikeCheck.isPending}
          className="text-[10px] px-2 py-1 border border-orange-500/50 text-orange-400 bg-orange-500/10 hover:bg-orange-500/20 transition-colors flex items-center gap-1 disabled:opacity-50"
        >
          {spikeCheck.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <AlertTriangle className="w-3 h-3" />}
          Run Spike Detection
        </button>
        {spikeResults && (
          <div className="space-y-2">
            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
              <div className="border border-border p-2 text-center">
                <p className="text-[10px] text-muted-foreground">Total Alerts</p>
                <p className={`text-sm font-display ${spikeResults.alerts.length > 0 ? 'text-red-400' : 'text-emerald-400'}`}>
                  {spikeResults.alerts.length}
                </p>
              </div>
              <div className="border border-border p-2 text-center">
                <p className="text-[10px] text-muted-foreground">Critical</p>
                <p className="text-sm font-display text-red-400">
                  {spikeResults.alerts.filter((a: any) => a.severity === 'critical').length}
                </p>
              </div>
              <div className="border border-border p-2 text-center">
                <p className="text-[10px] text-muted-foreground">Notifications Sent</p>
                <p className="text-sm font-display text-blue-400">{spikeResults.notificationsSent}</p>
              </div>
              <div className="border border-border p-2 text-center">
                <p className="text-[10px] text-muted-foreground">Checked At</p>
                <p className="text-[10px] font-display text-muted-foreground">
                  {new Date(spikeResults.checkedAt).toLocaleTimeString()}
                </p>
              </div>
            </div>
            {spikeResults.alerts.length > 0 && (
              <div className="space-y-1">
                {spikeResults.alerts.map((alert: any, i: number) => (
                  <div key={i} className={`border p-2 text-[10px] ${
                    alert.severity === 'critical' ? 'border-red-500/50 bg-red-500/5 text-red-400' :
                    alert.severity === 'high' ? 'border-orange-500/50 bg-orange-500/5 text-orange-400' :
                    alert.severity === 'medium' ? 'border-amber-500/50 bg-amber-500/5 text-amber-400' :
                    'border-border text-muted-foreground'
                  }`}>
                    <div className="flex items-center gap-2">
                      <span className="uppercase font-display tracking-wider">[{alert.severity}]</span>
                      <span className="font-medium">{alert.title}</span>
                    </div>
                    <p className="mt-1 text-muted-foreground">{alert.description}</p>
                  </div>
                ))}
              </div>
            )}
          </div>
        )}
      </div>
    );
  }

  return (
    <AppShell activePath="/darkweb-intel">
      <div className="max-w-[1600px] mx-auto space-y-6">
        {/* Header */}
        <div className="flex flex-col lg:flex-row lg:items-center justify-between gap-4">
          <div>
            <div className="flex items-center gap-3 mb-2">
              <Eye className="w-8 h-8 text-emerald-400" />
              <h1 className="text-2xl lg:text-3xl font-display tracking-wider">DARKWEB INTELLIGENCE</h1>
              {/* Bridge Status Indicator */}
              {bridgeHealth && (
                <span className={`flex items-center gap-1 px-2 py-0.5 text-[10px] tracking-wider border ${
                  bridgeHealth.reachable
                    ? "text-emerald-400 bg-emerald-500/10 border-emerald-500/30"
                    : (bridgeHealth as any).hasFallback
                    ? "text-cyan-400 bg-cyan-500/10 border-cyan-500/30"
                    : bridgeHealth.configured
                    ? "text-amber-400 bg-amber-500/10 border-amber-500/30"
                    : "text-red-400 bg-red-500/10 border-red-500/30"
                }`}>
                  {bridgeHealth.reachable ? <Wifi className="w-3 h-3" /> : (bridgeHealth as any).hasFallback ? <Radio className="w-3 h-3" /> : <WifiOff className="w-3 h-3" />}
                  {bridgeHealth.reachable ? "BRIDGE LIVE" : (bridgeHealth as any).hasFallback ? "DIRECT FEEDS ACTIVE" : bridgeHealth.configured ? "BRIDGE OFFLINE" : "BRIDGE NOT CONFIGURED"}
                </span>
              )}
            </div>
            <p className="text-muted-foreground text-sm">
              Live darkweb intelligence from local threat database, Daily Dark Web, event feed, MITRE ATT&CK coverage, and IOC corroboration
            </p>
          </div>
          <div className="flex gap-2">
            <button
              onClick={() => syncAll.mutate()}
              disabled={syncAll.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-primary/10 border border-primary/20 text-primary text-xs font-display tracking-wider hover:bg-primary/20 transition-colors disabled:opacity-50"
            >
              {syncAll.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Database className="w-3 h-3" />}
              SYNC DARKWEB DATA
            </button>
            <button
              onClick={() => monitoringSweep.mutate({})}
              disabled={monitoringSweep.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-emerald-500/10 border border-emerald-500/20 text-emerald-400 text-xs font-display tracking-wider hover:bg-emerald-500/20 transition-colors disabled:opacity-50"
            >
              {monitoringSweep.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Radio className="w-3 h-3" />}
              RUN LLM SWEEP
            </button>
            <button
              onClick={() => syncRSS.mutate({})}
              disabled={syncRSS.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-orange-500/10 border border-orange-500/20 text-orange-400 text-xs font-display tracking-wider hover:bg-orange-500/20 transition-colors disabled:opacity-50"
            >
              {syncRSS.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Rss className="w-3 h-3" />}
              DDW RSS SYNC
            </button>
            <button
              onClick={() => syncAllRSS.mutate({})}
              disabled={syncAllRSS.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-purple-500/10 border border-purple-500/20 text-purple-400 text-xs font-display tracking-wider hover:bg-purple-500/20 transition-colors disabled:opacity-50"
            >
              {syncAllRSS.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Globe2 className="w-3 h-3" />}
              ALL FEEDS (18)
            </button>
            <button
              onClick={() => crossRefIOCs.mutate({})}
              disabled={crossRefIOCs.isPending}
              className="flex items-center gap-2 px-4 py-2 bg-red-500/10 border border-red-500/20 text-red-400 text-xs font-display tracking-wider hover:bg-red-500/20 transition-colors disabled:opacity-50"
            >
              {crossRefIOCs.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <ScanSearch className="w-3 h-3" />}
              IOC CROSS-REF
            </button>
            <Link href="/stix-export">
              <button className="flex items-center gap-2 px-4 py-2 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 text-xs font-display tracking-wider hover:bg-cyan-500/20 transition-colors">
                <FileJson className="w-3 h-3" />
                STIX EXPORT
              </button>
            </Link>
          </div>
        </div>

        {/* Quick Stats — 6 cards */}
        <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
          <div className="bg-card border border-emerald-500/20 p-3">
            <div className="flex items-center gap-2 mb-1">
              <Database className="w-4 h-4 text-emerald-400" />
              <span className="text-[10px] text-muted-foreground tracking-wider">CATALOG ACTORS</span>
            </div>
            <p className="text-xl font-display text-emerald-400">{stats?.totalActors ?? 0}</p>
          </div>
          <div className="bg-card border border-primary/20 p-3">
            <div className="flex items-center gap-2 mb-1">
              <Crosshair className="w-4 h-4 text-primary" />
              <span className="text-[10px] text-muted-foreground tracking-wider">TECHNIQUES</span>
            </div>
            <p className="text-xl font-display text-primary">{coverage?.totalTechniques ?? 0}</p>
          </div>
          <div className="bg-card border border-amber-500/20 p-3">
            <div className="flex items-center gap-2 mb-1">
              <Activity className="w-4 h-4 text-amber-400" />
              <span className="text-[10px] text-muted-foreground tracking-wider">LOCAL EVENTS</span>
            </div>
            <p className="text-xl font-display text-amber-400">{events?.length ?? 0}</p>
          </div>
          <div className="bg-card border border-red-500/20 p-3">
            <div className="flex items-center gap-2 mb-1">
              <AlertTriangle className="w-4 h-4 text-red-400" />
              <span className="text-[10px] text-muted-foreground tracking-wider">ALERTS</span>
            </div>
            <p className="text-xl font-display text-red-400">{bridgeAlertCount}</p>
          </div>
          <div className="bg-card border border-purple-500/20 p-3">
            <div className="flex items-center gap-2 mb-1">
              <Bug className="w-4 h-4 text-purple-400" />
              <span className="text-[10px] text-muted-foreground tracking-wider">THREATFOX IOCs</span>
            </div>
            <p className="text-xl font-display text-purple-400">{bridgeIOCCount}</p>
          </div>
          <div className="bg-card border border-cyan-500/20 p-3">
            <div className="flex items-center gap-2 mb-1">
              <Skull className="w-4 h-4 text-cyan-400" />
              <span className="text-[10px] text-muted-foreground tracking-wider">VICTIM EVENTS</span>
            </div>
            <p className="text-xl font-display text-cyan-400">{bridgeVictimCount}</p>
          </div>
        </div>

        {/* ─── Escalation Alerts Banner ─────────────────────────────────── */}
        {escalationAlerts && escalationAlerts.data.length > 0 && (
          <div className="bg-red-500/5 border border-red-500/20 p-4">
            <button onClick={() => toggleSection("alerts")} className="flex items-center justify-between w-full">
              <h2 className="text-sm font-display tracking-wider flex items-center gap-2 text-red-400">
                <Zap className="w-4 h-4" /> ESCALATION ALERTS ({escalationAlerts.data.length})
              </h2>
              {expandedSections.alerts ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
            </button>
            {expandedSections.alerts && (
              <div className="mt-3 space-y-2 max-h-64 overflow-y-auto">
                {escalationAlerts.data.map((alert: any, i: number) => (
                  <div
                    key={alert.id || i}
                    className={`flex items-start gap-3 p-3 border cursor-pointer transition-all hover:brightness-110 ${SEVERITY_COLORS[alert.severity] || "text-gray-400 bg-gray-500/10 border-gray-500/30"}`}
                    onClick={() => { if (alert.id) { setSelectedAlertId(alert.id); setAlertModalOpen(true); } }}
                    role="button"
                    tabIndex={0}
                    onKeyDown={(e) => { if (e.key === "Enter" && alert.id) { setSelectedAlertId(alert.id); setAlertModalOpen(true); } }}
                  >
                    <AlertTriangle className="w-4 h-4 shrink-0 mt-0.5" />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-0.5 flex-wrap">
                        <span className="text-[10px] tracking-wider">{safeUpper(alert.severity)}</span>
                        {alert.eventType && (
                          <span className="text-[9px] px-1 py-0.5 bg-muted/50 border border-border/50 text-muted-foreground">
                            {safeUpper(alert.eventType.replace(/_/g, " "))}
                          </span>
                        )}
                        {alert.actorName && (
                          <span className="text-[10px] text-red-400 font-display">{alert.actorName}</span>
                        )}
                        {(alert.eventDate || alert.timestamp) && (
                          <span className="text-[10px] text-muted-foreground">
                            {new Date(alert.eventDate || alert.timestamp).toLocaleDateString()}
                          </span>
                        )}
                      </div>
                      <p className="text-xs font-medium">{alert.title || alert.message || "Alert"}</p>
                      {alert.description && <p className="text-[11px] text-muted-foreground mt-0.5 line-clamp-2">{alert.description}</p>}
                      {(alert.victimName || alert.victimSector || alert.victimCountry) && (
                        <div className="flex items-center gap-2 mt-1 text-[10px] text-muted-foreground">
                          {alert.victimName && <span>Victim: {alert.victimName}</span>}
                          {alert.victimSector && <span>· {alert.victimSector}</span>}
                          {alert.victimCountry && <span>· {alert.victimCountry}</span>}
                        </div>
                      )}
                    </div>
                    <ChevronRight className="w-4 h-4 shrink-0 mt-1 text-muted-foreground" />
                  </div>
                ))}
              </div>
            )}
          </div>
        )}

        {/* Alert Detail Modal */}
        <AlertDetailModal
          open={alertModalOpen}
          onOpenChange={setAlertModalOpen}
          eventId={selectedAlertId}
        />

        <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
          {/* ─── Main Content (2/3) ──────────────────────────────────────── */}
          <div className="lg:col-span-2 space-y-6">

            {/* Threat Event Feed */}
            <div className="space-y-4">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-display tracking-wider flex items-center gap-2">
                  <AlertTriangle className="w-4 h-4 text-amber-400" /> THREAT EVENT FEED
                </h2>
                <button onClick={() => refetchEvents()} className="text-[10px] text-muted-foreground hover:text-foreground transition-colors flex items-center gap-1">
                  <RefreshCw className="w-3 h-3" /> REFRESH
                </button>
              </div>

              {/* Event Type Filters */}
              <div className="flex gap-1 flex-wrap">
                {eventTypes.map(t => (
                  <button key={t} onClick={() => setEventTypeFilter(t)}
                    className={`px-2 py-1 text-[10px] font-display tracking-wider border transition-colors ${
                      eventTypeFilter === t ? "bg-emerald-500/20 border-emerald-500/50 text-emerald-400"
                        : "bg-card border-border text-muted-foreground hover:text-foreground"}`}>
                    {t === "all" ? "ALL" : safeUpper(t.replace(/_/g, " "))}
                  </button>
                ))}
              </div>

              {/* Events List */}
              {eventsLoading ? (
                <div className="space-y-3">
                  {Array.from({ length: 8 }).map((_, i) => (
                    <div key={i} className="bg-card border border-border p-4 animate-pulse">
                      <div className="h-4 bg-muted rounded w-1/3 mb-2" />
                      <div className="h-3 bg-muted rounded w-full" />
                    </div>
                  ))}
                </div>
              ) : !events || events.length === 0 ? (
                <div className="bg-card border border-border p-8 text-center">
                  <AlertTriangle className="w-10 h-10 text-muted-foreground mx-auto mb-3" />
                  <p className="text-sm text-muted-foreground">No threat events recorded yet. Run a monitoring sweep or sync the catalog.</p>
                </div>
              ) : (
                <div className="space-y-2 max-h-[600px] overflow-y-auto pr-1">
                  {events.map((evt: any) => {
                    const evtColor = EVENT_TYPE_COLORS[evt.eventType] || "text-gray-400 bg-gray-500/10";
                    const actorColor = ACTOR_TYPE_COLORS[evt.actorType || ""] || "text-muted-foreground";
                    return (
                      <div key={evt.id} className="bg-card border border-border p-3 hover:bg-accent/5 transition-colors cursor-pointer hover:border-amber-500/40" onClick={() => { if (evt.id) { setSelectedAlertId(evt.id); setAlertModalOpen(true); } }} role="button" tabIndex={0} onKeyDown={(e) => { if (e.key === 'Enter' && evt.id) { setSelectedAlertId(evt.id); setAlertModalOpen(true); } }}>
                        <div className="flex items-start justify-between mb-1.5">
                          <div className="flex items-center gap-2 flex-wrap">
                            <span className={`text-[10px] px-2 py-0.5 ${evtColor} tracking-wider`}>
                              {safeUpper(evt.eventType?.replace(/_/g, " "))}
                            </span>
                            {evt.actorName && (
                              <Link href={`/threat-catalog/${evt.actorId}`} className={`text-[10px] ${actorColor} hover:underline`} onClick={(e: React.MouseEvent) => e.stopPropagation()}>
                                {evt.actorName}
                              </Link>
                            )}
                          </div>
                          <span className="text-[10px] text-muted-foreground shrink-0">
                            {evt.eventDate ? new Date(evt.eventDate).toLocaleDateString() : "—"}
                          </span>
                        </div>
                        <h4 className="text-xs font-display tracking-wider mb-1">{evt.title}</h4>
                        {evt.description && <p className="text-[11px] text-muted-foreground line-clamp-2">{evt.description}</p>}
                        <div className="flex items-center gap-3 mt-1.5 text-[10px] text-muted-foreground">
                          {evt.victimName && <span>Target: {evt.victimName}</span>}
                          {evt.mitreTechniques?.length > 0 && <span className="text-primary">{evt.mitreTechniques.length} TTPs</span>}
                          {evt.iocs?.length > 0 && <span className="text-red-400">{evt.iocs.length} IOCs</span>}
                          {evt.source && <span className="ml-auto">{evt.source}</span>}
                          <ChevronRight className="w-3 h-3 ml-auto text-amber-500/60" />
                        </div>
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* ─── Ransomware Victim Events (from bridge) ────────────────── */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <h2 className="text-sm font-display tracking-wider flex items-center gap-2">
                  <Skull className="w-4 h-4 text-cyan-400" /> RANSOMWARE VICTIM EVENTS
                  <span className="text-[10px] text-muted-foreground">LOCAL DB</span>
                  <span className="text-[10px] text-cyan-400">({recentVictimEvents?.data?.length ?? 0})</span>
                </h2>
                <div className="flex items-center gap-2">
                  {victimFilterActive && (
                    <button
                      onClick={() => { setVictimSearch(""); setVictimCountry(""); setVictimSector(""); setVictimActor(""); }}
                      className="text-[10px] text-red-400 hover:text-red-300 flex items-center gap-1"
                    >
                      ✕ Clear
                    </button>
                  )}
                  <button
                    onClick={() => setShowVictimFilters(!showVictimFilters)}
                    className={`text-[10px] px-2 py-1 tracking-wider border transition-colors flex items-center gap-1 ${
                      showVictimFilters || victimFilterActive
                        ? "bg-cyan-500/20 border-cyan-500/50 text-cyan-400"
                        : "bg-card border-border text-muted-foreground hover:text-foreground"
                    }`}
                  >
                    <Search className="w-3 h-3" /> FILTER
                  </button>
                </div>
              </div>

              {/* Filter Panel */}
              {showVictimFilters && (
                <div className="bg-card border border-cyan-500/20 p-3 space-y-2">
                  <input
                    type="text"
                    placeholder="Search victims, descriptions..."
                    value={victimSearch}
                    onChange={(e) => setVictimSearch(e.target.value)}
                    className="w-full bg-background border border-border px-3 py-1.5 text-xs placeholder:text-muted-foreground focus:outline-none focus:border-cyan-500/50"
                  />
                  <div className="grid grid-cols-3 gap-2">
                    <div>
                      <label className="text-[9px] text-muted-foreground tracking-wider mb-1 block">COUNTRY</label>
                      <select
                        value={victimCountry}
                        onChange={(e) => setVictimCountry(e.target.value)}
                        className="w-full bg-background border border-border px-2 py-1.5 text-xs focus:outline-none focus:border-cyan-500/50"
                      >
                        <option value="">All Countries</option>
                        {(recentVictimEvents as any)?.filters?.countries?.map((c: string) => (
                          <option key={c} value={c}>{c}</option>
                        ))}
                      </select>
                    </div>
                    <div>
                      <label className="text-[9px] text-muted-foreground tracking-wider mb-1 block">SECTOR</label>
                      <select
                        value={victimSector}
                        onChange={(e) => setVictimSector(e.target.value)}
                        className="w-full bg-background border border-border px-2 py-1.5 text-xs focus:outline-none focus:border-cyan-500/50"
                      >
                        <option value="">All Sectors</option>
                        {(recentVictimEvents as any)?.filters?.sectors?.map((s: string) => (
                          <option key={s} value={s}>{s}</option>
                        ))}
                      </select>
                    </div>
                    <div>
                      <label className="text-[9px] text-muted-foreground tracking-wider mb-1 block">THREAT ACTOR</label>
                      <select
                        value={victimActor}
                        onChange={(e) => setVictimActor(e.target.value)}
                        className="w-full bg-background border border-border px-2 py-1.5 text-xs focus:outline-none focus:border-cyan-500/50"
                      >
                        <option value="">All Actors</option>
                        {(recentVictimEvents as any)?.filters?.actors?.map((a: string) => (
                          <option key={a} value={a}>{a}</option>
                        ))}
                      </select>
                    </div>
                  </div>
                </div>
              )}

              {recentVictimEvents && recentVictimEvents.data.length > 0 ? (
                <div className="space-y-2 max-h-[400px] overflow-y-auto pr-1">
                  {recentVictimEvents.data.map((evt: any, i: number) => (
                    <div
                      key={evt.id || i}
                      className="bg-card border border-border p-3 hover:bg-accent/5 transition-colors cursor-pointer hover:border-amber-500/40"
                      onClick={() => { if (evt.id) { setSelectedAlertId(evt.id); setAlertModalOpen(true); } }}
                      role="button"
                      tabIndex={0}
                      onKeyDown={(e) => { if (e.key === "Enter" && evt.id) { setSelectedAlertId(evt.id); setAlertModalOpen(true); } }}
                    >
                      <div className="flex items-start justify-between mb-1">
                        <div className="flex items-center gap-2">
                          <span className="text-[10px] px-2 py-0.5 text-amber-400 bg-amber-500/10 tracking-wider">RANSOMWARE</span>
                          {evt.actorName && <span className="text-[10px] text-red-400 font-display">{evt.actorName}</span>}
                        </div>
                        <div className="flex items-center gap-2">
                          {evt.iocCount > 0 && (
                            <span className="text-[9px] px-1.5 py-0.5 text-purple-400 bg-purple-500/10 border border-purple-500/30 tracking-wider">
                              {evt.iocCount} IOCs
                            </span>
                          )}
                          {evt.severity && (
                            <span className={`text-[9px] px-1.5 py-0.5 tracking-wider border ${SEVERITY_COLORS[evt.severity] || "text-gray-400 bg-gray-500/10 border-gray-500/30"}`}>
                              {(evt.severity || "").toUpperCase()}
                            </span>
                          )}
                          <span className="text-[10px] text-muted-foreground">{evt.eventDate ? new Date(evt.eventDate).toLocaleDateString() : "—"}</span>
                        </div>
                      </div>
                      <h4 className="text-xs font-display tracking-wider mb-0.5">{evt.victimName || evt.title || "Unknown Victim"}</h4>
                      {evt.description && (
                        <p className="text-[10px] text-muted-foreground mb-1 line-clamp-2">{evt.description}</p>
                      )}
                      <div className="flex items-center gap-3 text-[10px] text-muted-foreground">
                        {evt.victimCountry && <span className="flex items-center gap-1"><Globe2 className="w-3 h-3" />{evt.victimCountry}</span>}
                        {evt.victimSector && <span>{evt.victimSector}</span>}
                        {evt.source && <span className="text-primary/60">{evt.source}</span>}
                        {evt.sourceUrl && (
                          <span
                            className="text-primary/40 flex items-center gap-1 cursor-default"
                            title={evt.sourceUrl}
                            onClick={(e) => e.stopPropagation()}
                          >
                            <ExternalLink className="w-3 h-3" /> Source
                          </span>
                        )}
                        <ChevronRight className="w-3 h-3 ml-auto text-amber-500/60" />
                      </div>
                    </div>
                  ))}
                </div>
              ) : (
                <div className="bg-card border border-border p-6 text-center">
                  <Skull className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                  <p className="text-xs text-muted-foreground">
                    {victimFilterActive ? "No victim events match your filters." : "No ransomware victim events available."}
                  </p>
                </div>
              )}
            </div>

            {/* ─── malware indicator feeds IOCs (from bridge) ──────────────────────────── */}
            <div className="space-y-3">
              <button onClick={() => toggleSection("iocs")} className="flex items-center justify-between w-full">
                <h2 className="text-sm font-display tracking-wider flex items-center gap-2">
                  <Bug className="w-4 h-4 text-purple-400" /> THREATFOX IOCs ({threatFoxIOCs?.data?.length ?? 0})
                  <span className="text-[10px] text-muted-foreground">{threatFoxIOCs?.source === 'local_database' ? 'LOCAL DB' : 'DIRECT FEED'}</span>
                </h2>
                {expandedSections.iocs ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
              </button>
              {expandedSections.iocs && (
                iocsLoading ? (
                  <div className="space-y-2">{[1,2,3].map(i => <div key={i} className="h-10 bg-muted animate-pulse rounded" />)}</div>
                ) : !threatFoxIOCs || threatFoxIOCs.data.length === 0 ? (
                  <div className="bg-card border border-border p-6 text-center">
                    <Bug className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                    <p className="text-xs text-muted-foreground">No malware indicator feeds IOCs available. Fetching from direct feed...</p>
                  </div>
                ) : (
                  <div className="space-y-1 max-h-[300px] overflow-y-auto pr-1">
                    {threatFoxIOCs.data.slice(0, 50).map((ioc: any, i: number) => (
                      <div key={i} className="bg-card border border-border p-2 flex items-center justify-between text-xs">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="text-[10px] px-1.5 py-0.5 bg-purple-500/10 text-purple-400 tracking-wider shrink-0">
                            {safeUpper(ioc.iocType || ioc.type || "UNK")}
                          </span>
                          <span className="font-mono text-muted-foreground truncate">{ioc.value || ioc.ioc || "—"}</span>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          {ioc.malwareFamily && <span className="text-[10px] text-red-400">{ioc.malwareFamily}</span>}
                          {ioc.confidence && <span className="text-[10px] text-muted-foreground">{ioc.confidence}%</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                )
              )}
            </div>

            {/* ─── KEV (from bridge) ────────────────────────────────── */}
            <div className="space-y-3">
              <button onClick={() => toggleSection("kev")} className="flex items-center justify-between w-full">
                <h2 className="text-sm font-display tracking-wider flex items-center gap-2">
                  <Shield className="w-4 h-4 text-red-400" /> known exploited vulnerabilities (KEV) ({cisaKEV?.data?.length ?? 0})
                  <span className="text-[10px] text-muted-foreground">Known Exploited Vulnerabilities</span>
                </h2>
                {expandedSections.kev ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
              </button>
              {expandedSections.kev && (
                kevLoading ? (
                  <div className="space-y-2">{[1,2,3].map(i => <div key={i} className="h-10 bg-muted animate-pulse rounded" />)}</div>
                ) : !cisaKEV || cisaKEV.data.length === 0 ? (
                  <div className="bg-card border border-border p-6 text-center">
                    <Shield className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                    <p className="text-xs text-muted-foreground">No KEV entries available.</p>
                  </div>
                ) : (
                  <div className="space-y-1 max-h-[300px] overflow-y-auto pr-1">
                    {cisaKEV.data.slice(0, 30).map((kev: any, i: number) => (
                      <div key={i} className="bg-card border border-border p-2">
                        <div className="flex items-center justify-between mb-0.5">
                          <span className="font-mono text-xs text-red-400">{kev.cveId || kev.cveID || "—"}</span>
                          <span className="text-[10px] text-muted-foreground">{kev.dateAdded ? new Date(kev.dateAdded).toLocaleDateString() : "—"}</span>
                        </div>
                        <p className="text-[11px] text-muted-foreground line-clamp-1">{kev.vulnerabilityName || kev.shortDescription || "—"}</p>
                        {kev.vendorProject && <span className="text-[10px] text-cyan-400">{kev.vendorProject} — {kev.product || ""}</span>}
                      </div>
                    ))}
                  </div>
                )
              )}
            </div>

            {/* ─── OTX Pulses (from bridge) ──────────────────────────────── */}
            <div className="space-y-3">
              <button onClick={() => toggleSection("otx")} className="flex items-center justify-between w-full">
                <h2 className="text-sm font-display tracking-wider flex items-center gap-2">
                  <Globe2 className="w-4 h-4 text-blue-400" /> OTX PULSES ({otxPulses?.data?.length ?? 0})
                  <span className="text-[10px] text-muted-foreground">AlienVault Open Threat Exchange</span>
                </h2>
                {expandedSections.otx ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
              </button>
              {expandedSections.otx && (
                otxLoading ? (
                  <div className="space-y-2">{[1,2,3].map(i => <div key={i} className="h-10 bg-muted animate-pulse rounded" />)}</div>
                ) : !otxPulses || otxPulses.data.length === 0 ? (
                  <div className="bg-card border border-border p-6 text-center">
                    <Globe2 className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                    <p className="text-xs text-muted-foreground">No OTX pulses available.</p>
                  </div>
                ) : (
                  <div className="space-y-1 max-h-[300px] overflow-y-auto pr-1">
                    {otxPulses.data.slice(0, 25).map((pulse: any, i: number) => (
                      <div key={i} className="bg-card border border-border p-2">
                        <div className="flex items-center justify-between mb-0.5">
                          <h4 className="text-xs font-display tracking-wider truncate">{pulse.name || pulse.title || "Pulse"}</h4>
                          <span className="text-[10px] text-muted-foreground shrink-0">{pulse.created ? new Date(pulse.created).toLocaleDateString() : "—"}</span>
                        </div>
                        <p className="text-[11px] text-muted-foreground line-clamp-1">{pulse.description || "—"}</p>
                        <div className="flex items-center gap-2 mt-0.5 text-[10px]">
                          {pulse.indicatorCount && <span className="text-purple-400">{pulse.indicatorCount} indicators</span>}
                          {pulse.tags && pulse.tags.length > 0 && (
                            <span className="text-muted-foreground flex items-center gap-1"><Tag className="w-3 h-3" />{pulse.tags.slice(0, 3).join(", ")}</span>
                          )}
                        </div>
                      </div>
                    ))}
                  </div>
                )
              )}
            </div>

            {/* ─── Malware Bazaar (from bridge) ──────────────────────────── */}
            <div className="space-y-3">
              <button onClick={() => toggleSection("malware")} className="flex items-center justify-between w-full">
                <h2 className="text-sm font-display tracking-wider flex items-center gap-2">
                  <Skull className="w-4 h-4 text-orange-400" /> MALWARE BAZAAR ({malwareBazaar?.data?.length ?? 0})
                  <span className="text-[10px] text-muted-foreground">threat intelligence feeds</span>
                </h2>
                {expandedSections.malware ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
              </button>
              {expandedSections.malware && (
                malwareLoading ? (
                  <div className="space-y-2">{[1,2,3].map(i => <div key={i} className="h-10 bg-muted animate-pulse rounded" />)}</div>
                ) : !malwareBazaar || malwareBazaar.data.length === 0 ? (
                  <div className="bg-card border border-border p-6 text-center">
                    <Skull className="w-8 h-8 text-muted-foreground mx-auto mb-2" />
                    <p className="text-xs text-muted-foreground">No Malware Bazaar entries available.</p>
                  </div>
                ) : (
                  <div className="space-y-1 max-h-[300px] overflow-y-auto pr-1">
                    {malwareBazaar.data.slice(0, 30).map((entry: any, i: number) => (
                      <div key={i} className="bg-card border border-border p-2 flex items-center justify-between text-xs">
                        <div className="flex items-center gap-2 min-w-0">
                          <span className="font-mono text-muted-foreground truncate">{entry.sha256 || entry.sha256_hash || "—"}</span>
                        </div>
                        <div className="flex items-center gap-2 shrink-0">
                          {entry.signature && <span className="text-[10px] text-orange-400">{entry.signature}</span>}
                          {entry.fileType && <span className="text-[10px] text-muted-foreground">{entry.fileType}</span>}
                        </div>
                      </div>
                    ))}
                  </div>
                )
              )}
            </div>
          </div>

            {/* ─── Access Brokers (IABs) ──────────────────────────────── */}
            <div className="bg-card border border-border p-4">
              <button onClick={() => toggleSection("iabs")} className="flex items-center justify-between w-full">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground flex items-center gap-2">
                  <DollarSign className="w-4 h-4 text-orange-400" /> INITIAL ACCESS BROKERS
                  <span className="text-[10px] text-muted-foreground/60">({accessBrokers?.length ?? 0})</span>
                  <button
                    onClick={(e) => { e.stopPropagation(); syncDarkwebFeeds.mutate(); }}
                    disabled={syncDarkwebFeeds.isPending}
                    className="ml-2 p-1 hover:bg-muted/50 rounded transition-colors"
                    title="Sync IAB & IO feeds"
                  >
                    {syncDarkwebFeeds.isPending ? <Loader2 className="w-3 h-3 animate-spin text-orange-400" /> : <RefreshCw className="w-3 h-3 text-muted-foreground" />}
                  </button>
                </h3>
                {expandedSections.iabs ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
              </button>
              {expandedSections.iabs && (
                <div className="mt-3 space-y-2 max-h-[500px] overflow-y-auto">
                  {iabsLoading ? (
                    <div className="flex items-center justify-center py-6"><Loader2 className="w-5 h-5 animate-spin text-muted-foreground" /></div>
                  ) : !accessBrokers || accessBrokers.length === 0 ? (
                    <p className="text-xs text-muted-foreground py-4 text-center">No access brokers loaded. Click sync to populate.</p>
                  ) : (
                    accessBrokers.map((iab: any) => {
                      const isExpanded = expandedIAB === iab.id;
                      const status = iab.iabStatus || iab.status || "unknown";
                      const confidence = iab.iabConfidence ?? iab.confidence;
                      const description = iab.iabDescription || iab.description || "";
                      const firstSeen = iab.iabFirstSeen || iab.firstSeen;
                      const lastActive = iab.iabLastActive || iab.lastActive;
                      const dataSource = iab.iabDataSource || iab.dataSource;
                      return (
                      <div key={iab.id}
                        className={`border bg-orange-500/5 p-3 space-y-2 cursor-pointer transition-all hover:bg-orange-500/10 ${
                          isExpanded ? "border-orange-500/50 ring-1 ring-orange-500/20" : "border-orange-500/20"
                        }`}
                        onClick={() => setExpandedIAB(isExpanded ? null : iab.id)}
                      >
                        <div className="flex items-start justify-between">
                          <div className="flex-1 min-w-0">
                            <div className="flex items-center gap-2">
                              <ChevronRight className={`w-3 h-3 text-orange-400 transition-transform ${isExpanded ? "rotate-90" : ""}`} />
                              <span className="text-sm font-display text-orange-400 tracking-wide">{safeUpper(iab.brokerName)}</span>
                              <span className={`text-[9px] px-1.5 py-0.5 border ${
                                status === "active" ? "text-green-400 border-green-500/30 bg-green-500/10"
                                : status === "law_enforcement" ? "text-blue-400 border-blue-500/30 bg-blue-500/10"
                                : status === "sold" ? "text-purple-400 border-purple-500/30 bg-purple-500/10"
                                : status === "removed" ? "text-red-400 border-red-500/30 bg-red-500/10"
                                : "text-muted-foreground border-border bg-muted/30"
                              }`}>{safeUpper(status.replace(/_/g, " "))}</span>
                            </div>
                            {iab.aliases && (iab.aliases as string[]).length > 0 && (
                              <p className="text-[10px] text-muted-foreground mt-0.5 ml-5">AKA: {(iab.aliases as string[]).join(", ")}</p>
                            )}
                          </div>
                          <span className={`text-[9px] px-1.5 py-0.5 border ${
                            iab.brokerReputation === "established" ? "text-red-400 border-red-500/30 bg-red-500/10"
                            : iab.brokerReputation === "rising" ? "text-amber-400 border-amber-500/30 bg-amber-500/10"
                            : "text-muted-foreground border-border"
                          }`}>{safeUpper(iab.brokerReputation || "UNKNOWN")}</span>
                        </div>

                        {/* Collapsed: show tags only */}
                        {!isExpanded && (
                          <div className="flex flex-wrap gap-1.5 ml-5">
                            <span className="text-[9px] px-1.5 py-0.5 bg-muted/50 border border-border text-muted-foreground">
                              <Key className="w-2.5 h-2.5 inline mr-1" />{iab.accessType || iab.listingType?.replace(/_/g, " ") || "\u2014"}
                            </span>
                            {iab.forumSource && (
                              <span className="text-[9px] px-1.5 py-0.5 bg-muted/50 border border-border text-muted-foreground">
                                <Globe2 className="w-2.5 h-2.5 inline mr-1" />{iab.forumSource}
                              </span>
                            )}
                            {iab.victimSector && (() => {
                              const sectors = String(iab.victimSector).split(/,\s*/).filter(Boolean);
                              return sectors.map((sector: string, idx: number) => (
                                <span key={idx} className="text-[9px] px-1.5 py-0.5 bg-muted/50 border border-border text-muted-foreground">
                                  {idx === 0 && <Crosshair className="w-2.5 h-2.5 inline mr-1" />}{sector.trim()}
                                </span>
                              ));
                            })()}
                            {(firstSeen || lastActive) && (
                              <span className="text-[9px] px-1.5 py-0.5 bg-muted/50 border border-border text-muted-foreground">
                                <Clock className="w-2.5 h-2.5 inline mr-1" />{firstSeen || "?"} \u2192 {lastActive || "present"}
                              </span>
                            )}
                          </div>
                        )}

                        {/* Expanded: full detail panel */}
                        {isExpanded && (
                          <div className="ml-5 space-y-3 border-t border-orange-500/10 pt-3 mt-2" onClick={(e) => e.stopPropagation()}>
                            {/* Description */}
                            {description && (
                              <p className="text-[11px] text-muted-foreground leading-relaxed">{description}</p>
                            )}

                            {/* Key Details Grid */}
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                              <div className="bg-muted/30 border border-border p-2">
                                <div className="text-[9px] text-muted-foreground">ACCESS TYPE</div>
                                <div className="text-[11px] text-foreground font-mono">{iab.accessType || iab.listingType?.replace(/_/g, " ") || "—"}</div>
                              </div>
                              <div className="bg-muted/30 border border-border p-2">
                                <div className="text-[9px] text-muted-foreground">ACCESS LEVEL</div>
                                <div className="text-[11px] text-foreground font-mono">{iab.accessLevel?.replace(/_/g, " ") || "—"}</div>
                              </div>
                              <div className="bg-muted/30 border border-border p-2">
                                <div className="text-[9px] text-muted-foreground">CONFIDENCE</div>
                                <div className="text-[11px] text-foreground font-mono">{confidence != null ? `${confidence}%` : "—"}</div>
                              </div>
                              <div className="bg-muted/30 border border-border p-2">
                                <div className="text-[9px] text-muted-foreground">ASKING PRICE</div>
                                <div className="text-[11px] text-foreground font-mono">{iab.askingPrice ? `$${iab.askingPrice}` : "—"}</div>
                              </div>
                            </div>

                            {/* Victim Info */}
                            <div className="grid grid-cols-2 md:grid-cols-3 gap-2">
                              <div className="bg-muted/30 border border-border p-2">
                                <div className="text-[9px] text-muted-foreground">VICTIM SECTOR{iab.victimSector && String(iab.victimSector).includes(",") ? "S" : ""}</div>
                                {iab.victimSector ? (
                                  <div className="flex flex-wrap gap-1 mt-0.5">
                                    {String(iab.victimSector).split(/,\s*/).filter(Boolean).map((sector: string, idx: number) => (
                                      <span key={idx} className="text-[10px] px-1.5 py-0.5 bg-orange-500/10 border border-orange-500/20 text-orange-300">
                                        {sector.trim()}
                                      </span>
                                    ))}
                                  </div>
                                ) : (
                                  <div className="text-[11px] text-foreground">\u2014</div>
                                )}
                              </div>
                              <div className="bg-muted/30 border border-border p-2">
                                <div className="text-[9px] text-muted-foreground">VICTIM COUNTRY</div>
                                <div className="text-[11px] text-foreground">{iab.victimCountry || "—"}</div>
                              </div>
                              <div className="bg-muted/30 border border-border p-2">
                                <div className="text-[9px] text-muted-foreground">FORUM SOURCE</div>
                                <div className="text-[11px] text-foreground">{iab.forumSource || "—"}</div>
                              </div>
                            </div>

                            {/* Timeline */}
                            <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                              <div className="bg-muted/30 border border-border p-2">
                                <div className="text-[9px] text-muted-foreground">FIRST SEEN</div>
                                <div className="text-[11px] text-foreground font-mono">{firstSeen || "—"}</div>
                              </div>
                              <div className="bg-muted/30 border border-border p-2">
                                <div className="text-[9px] text-muted-foreground">LAST ACTIVE</div>
                                <div className="text-[11px] text-foreground font-mono">{lastActive || "—"}</div>
                              </div>
                              <div className="bg-muted/30 border border-border p-2">
                                <div className="text-[9px] text-muted-foreground">TOTAL LISTINGS</div>
                                <div className="text-[11px] text-foreground font-mono">{iab.totalListings ?? "—"}</div>
                              </div>
                              <div className="bg-muted/30 border border-border p-2">
                                <div className="text-[9px] text-muted-foreground">SUCCESSFUL SALES</div>
                                <div className="text-[11px] text-foreground font-mono">{iab.successfulSales ?? "—"}</div>
                              </div>
                            </div>

                            {/* Data Source */}
                            {dataSource && (
                              <div className="bg-muted/30 border border-border p-2">
                                <div className="text-[9px] text-muted-foreground">INTELLIGENCE SOURCE</div>
                                <div className="text-[11px] text-foreground">{dataSource}</div>
                              </div>
                            )}

                            {/* Persistence Mechanism */}
                            {iab.persistenceMechanism && (
                              <div className="bg-muted/30 border border-border p-2">
                                <div className="text-[9px] text-muted-foreground">PERSISTENCE MECHANISM</div>
                                <div className="text-[11px] text-foreground">{iab.persistenceMechanism}</div>
                              </div>
                            )}

                            {/* Tags Row */}
                            <div className="flex flex-wrap gap-1.5">
                              <span className="text-[9px] px-1.5 py-0.5 bg-muted/50 border border-border text-muted-foreground">
                                <Key className="w-2.5 h-2.5 inline mr-1" />{iab.accessType || iab.listingType?.replace(/_/g, " ") || "—"}
                              </span>
                              {iab.forumSource && (
                                <span className="text-[9px] px-1.5 py-0.5 bg-muted/50 border border-border text-muted-foreground">
                                  <Globe2 className="w-2.5 h-2.5 inline mr-1" />{iab.forumSource}
                                </span>
                              )}
                              {iab.victimSector && (() => {
                                const sectors = String(iab.victimSector).split(/,\s*/).filter(Boolean);
                                return sectors.map((sector: string, idx: number) => (
                                  <span key={idx} className="text-[9px] px-1.5 py-0.5 bg-muted/50 border border-border text-muted-foreground">
                                    {idx === 0 && <Crosshair className="w-2.5 h-2.5 inline mr-1" />}{sector.trim()}
                                  </span>
                                ));
                              })()}
                              {confidence != null && (
                                <span className="text-[9px] px-1.5 py-0.5 bg-muted/50 border border-border text-muted-foreground">
                                  CONF: {confidence}%
                                </span>
                              )}
                            </div>

                            {/* Linked Ransomware Groups */}
                            {iab.linkedRansomwareGroups && (iab.linkedRansomwareGroups as string[]).length > 0 && (
                              <div className="flex flex-wrap gap-1">
                                <span className="text-[9px] text-muted-foreground">LINKED RANSOMWARE:</span>
                                {(iab.linkedRansomwareGroups as string[]).map((g: string) => (
                                  <span key={g} className="text-[9px] px-1 py-0.5 bg-red-500/10 border border-red-500/20 text-red-400">{g}</span>
                                ))}
                              </div>
                            )}

                            {/* Active Forums */}
                            {iab.activeForums && (iab.activeForums as string[]).length > 0 && (
                              <div className="flex flex-wrap gap-1">
                                <span className="text-[9px] text-muted-foreground">ACTIVE FORUMS:</span>
                                {(iab.activeForums as string[]).map((f: string) => (
                                  <span key={f} className="text-[9px] px-1 py-0.5 bg-purple-500/10 border border-purple-500/20 text-purple-400">{f}</span>
                                ))}
                              </div>
                            )}

                            {/* Linked Actor IDs */}
                            {iab.linkedActorIds && (iab.linkedActorIds as string[]).length > 0 && (
                              <div className="flex flex-wrap gap-1">
                                <span className="text-[9px] text-muted-foreground">LINKED ACTORS:</span>
                                {(iab.linkedActorIds as string[]).map((a: string) => (
                                  <span key={a} className="text-[9px] px-1 py-0.5 bg-amber-500/10 border border-amber-500/20 text-amber-400">{a}</span>
                                ))}
                              </div>
                            )}

                            {/* MITRE Techniques */}
                            {iab.mitreTechniques && (iab.mitreTechniques as string[]).length > 0 && (
                              <div className="space-y-1">
                                <span className="text-[9px] text-muted-foreground">MITRE ATT&CK:</span>
                                <div className="flex flex-wrap gap-1">
                                  {(iab.mitreTechniques as string[]).map((t: string) => (
                                    <span key={t} className="text-[9px] px-1 py-0.5 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 font-mono">{t}</span>
                                  ))}
                                </div>
                              </div>
                            )}

                            {/* Forum Post URL */}
                            {iab.forumPostUrl && (
                              <a href={iab.forumPostUrl} target="_blank" rel="noopener noreferrer"
                                className="text-[10px] text-orange-400 hover:text-orange-300 flex items-center gap-1">
                                <ExternalLink className="w-3 h-3" /> View Forum Post
                              </a>
                            )}
                          </div>
                        )}
                      </div>
                      );
                    })
                  )}
                </div>
              )}
            </div>

             {/* ─── US Government Access Brokers ─────────────────────── */}
            <div className="bg-card border border-red-500/30 p-4">
              <button onClick={() => toggleSection("govBrokers")} className="flex items-center justify-between w-full">
                <h3 className="text-xs font-display tracking-wider text-red-400 flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-red-400" /> US GOVERNMENT ACCESS BROKERS
                  <span className="text-[10px] text-red-400/60">({govBrokers?.length ?? 0})</span>
                  <button
                    onClick={(e) => { e.stopPropagation(); seedGovBrokers.mutate(); }}
                    disabled={seedGovBrokers.isPending}
                    className="ml-2 p-1 hover:bg-red-500/10 rounded transition-colors"
                    title="Seed gov broker intelligence into database"
                  >
                    {seedGovBrokers.isPending ? <Loader2 className="w-3 h-3 animate-spin text-red-400" /> : <Database className="w-3 h-3 text-red-400/60" />}
                  </button>
                </h3>
                {expandedSections.govBrokers ? <ChevronUp className="w-4 h-4 text-red-400" /> : <ChevronDown className="w-4 h-4 text-red-400" />}
              </button>
              {expandedSections.govBrokers && (
                <div className="mt-3 space-y-3">
                  {/* Gov Stats Summary */}
                  {govStats && (
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                      <div className="bg-red-500/5 border border-red-500/20 p-2 text-center">
                        <div className="text-lg font-mono text-red-400">{govStats.totalKnownBrokers}</div>
                        <div className="text-[9px] text-muted-foreground">KNOWN BROKERS</div>
                      </div>
                      <div className="bg-red-500/5 border border-red-500/20 p-2 text-center">
                        <div className="text-lg font-mono text-red-400">{govStats.activeBrokers}</div>
                        <div className="text-[9px] text-muted-foreground">ACTIVE (90d)</div>
                      </div>
                      <div className="bg-red-500/5 border border-red-500/20 p-2 text-center">
                        <div className="text-lg font-mono text-amber-400">{govStats.totalForumListings}</div>
                        <div className="text-[9px] text-muted-foreground">FORUM LISTINGS</div>
                      </div>
                      <div className="bg-red-500/5 border border-red-500/20 p-2 text-center">
                        <div className="text-lg font-mono text-green-400">${(govStats.avgAskingPrice / 1000).toFixed(0)}k</div>
                        <div className="text-[9px] text-muted-foreground">AVG PRICE</div>
                      </div>
                    </div>
                  )}

                  {/* Forum Activity Heatmap */}
                  {govForumActivity && govForumActivity.length > 0 && (
                    <div className="space-y-1">
                      <div className="text-[10px] text-muted-foreground font-display tracking-wider">FORUM ACTIVITY</div>
                      <div className="grid grid-cols-2 md:grid-cols-3 gap-1.5">
                        {govForumActivity.map((f: any) => (
                          <div key={f.forum} className={`p-2 border ${
                            f.riskLevel === "critical" ? "border-red-500/30 bg-red-500/5" :
                            f.riskLevel === "high" ? "border-orange-500/30 bg-orange-500/5" :
                            "border-amber-500/30 bg-amber-500/5"
                          }`}>
                            <div className="flex items-center justify-between">
                              <span className="text-[10px] font-display text-foreground">{f.forum}</span>
                              <span className={`text-[9px] px-1 py-0.5 border ${
                                f.riskLevel === "critical" ? "text-red-400 border-red-500/30 bg-red-500/10" :
                                f.riskLevel === "high" ? "text-orange-400 border-orange-500/30 bg-orange-500/10" :
                                "text-amber-400 border-amber-500/30 bg-amber-500/10"
                              }`}>{safeUpper(f.riskLevel)}</span>
                            </div>
                            <div className="text-xs font-mono text-foreground mt-1">{f.govListings} listings</div>
                            <div className="text-[9px] text-muted-foreground">${f.avgPrice.toLocaleString()} avg</div>
                            <div className="flex flex-wrap gap-0.5 mt-1">
                              {f.topAccessTypes.slice(0, 3).map((t: string) => (
                                <span key={t} className="text-[8px] px-1 py-0.5 bg-muted/50 border border-border text-muted-foreground">{t}</span>
                              ))}
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}

                  {/* Search */}
                  <div className="relative">
                    <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-3 h-3 text-muted-foreground" />
                    <input
                      type="text"
                      placeholder="Search gov brokers (name, agency, group...)"
                      value={govSearch}
                      onChange={(e) => setGovSearch(e.target.value)}
                      className="w-full pl-7 pr-3 py-1.5 bg-muted/30 border border-border text-xs text-foreground placeholder:text-muted-foreground focus:outline-none focus:border-red-500/50"
                    />
                  </div>

                  {/* Broker Cards */}
                  <div className="space-y-2 max-h-[600px] overflow-y-auto">
                    {govBrokersLoading ? (
                      <div className="flex items-center justify-center py-6"><Loader2 className="w-5 h-5 animate-spin text-red-400" /></div>
                    ) : !govBrokers || govBrokers.length === 0 ? (
                      <p className="text-xs text-muted-foreground py-4 text-center">No gov-targeting brokers found. Try a different search or seed the knowledge base.</p>
                    ) : (
                      govBrokers.map((b: any) => (
                        <div key={b.brokerId} className="border border-red-500/20 bg-red-500/5 p-3 space-y-2">
                          <div className="flex items-start justify-between">
                            <div>
                              <div className="flex items-center gap-2">
                                <span className="text-sm font-display text-red-400 tracking-wide">{safeUpper(b.brokerName)}</span>
                                <span className={`text-[9px] px-1.5 py-0.5 border ${
                                  b.sponsorship === "state-sponsored" ? "text-red-400 border-red-500/30 bg-red-500/10" :
                                  b.sponsorship === "hybrid" ? "text-purple-400 border-purple-500/30 bg-purple-500/10" :
                                  "text-orange-400 border-orange-500/30 bg-orange-500/10"
                                }`}>{safeUpper(b.sponsorship)}</span>
                              </div>
                              {b.aliases.length > 0 && (
                                <p className="text-[10px] text-muted-foreground mt-0.5">AKA: {b.aliases.join(", ")}</p>
                              )}
                              <p className="text-[10px] text-muted-foreground">Attribution: {b.attribution}</p>
                            </div>
                            <div className="text-right">
                              <div className={`text-lg font-mono ${
                                b.riskScore >= 90 ? "text-red-400" : b.riskScore >= 75 ? "text-orange-400" : "text-amber-400"
                              }`}>{b.riskScore}</div>
                              <div className="text-[9px] text-muted-foreground">RISK</div>
                            </div>
                          </div>
                          <p className="text-[11px] text-muted-foreground leading-relaxed line-clamp-2">{b.notes}</p>

                          {/* Target Agencies */}
                          <div className="space-y-1">
                            <div className="text-[9px] text-red-400/70 font-display">TARGET AGENCIES</div>
                            <div className="flex flex-wrap gap-1">
                              {b.govTargeting.agencies.map((a: string) => (
                                <span key={a} className="text-[9px] px-1.5 py-0.5 bg-red-500/10 border border-red-500/20 text-red-400">{a}</span>
                              ))}
                            </div>
                          </div>

                          {/* Access Methods */}
                          <div className="flex flex-wrap gap-1">
                            {b.govTargeting.accessMethods.slice(0, 3).map((m: string) => (
                              <span key={m} className="text-[9px] px-1.5 py-0.5 bg-muted/50 border border-border text-muted-foreground">
                                <Key className="w-2.5 h-2.5 inline mr-1" />{m}
                              </span>
                            ))}
                          </div>

                          {/* Price + Forums */}
                          <div className="flex flex-wrap gap-1.5">
                            <span className="text-[9px] px-1.5 py-0.5 bg-green-500/10 border border-green-500/20 text-green-400">
                              <DollarSign className="w-2.5 h-2.5 inline mr-1" />
                              ${b.govTargeting.priceRange.min.toLocaleString()} - ${b.govTargeting.priceRange.max.toLocaleString()}
                            </span>
                            {b.primaryForums.map((f: string) => (
                              <span key={f} className="text-[9px] px-1.5 py-0.5 bg-muted/50 border border-border text-muted-foreground">
                                <Globe2 className="w-2.5 h-2.5 inline mr-1" />{f}
                              </span>
                            ))}
                          </div>

                          {/* Linked Groups */}
                          {b.linkedGroups.length > 0 && (
                            <div className="flex flex-wrap gap-1">
                              <span className="text-[9px] text-muted-foreground">LINKED:</span>
                              {b.linkedGroups.map((g: string) => (
                                <span key={g} className="text-[9px] px-1 py-0.5 bg-red-500/10 border border-red-500/20 text-red-400">{g}</span>
                              ))}
                            </div>
                          )}

                          {/* MITRE + CISA */}
                          <div className="flex flex-wrap gap-1">
                            {b.mitreTechniques.slice(0, 4).map((t: string) => (
                              <span key={t} className="text-[9px] px-1 py-0.5 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400 font-mono">{t}</span>
                            ))}
                            {b.mitreTechniques.length > 4 && (
                              <span className="text-[9px] text-muted-foreground">+{b.mitreTechniques.length - 4} more</span>
                            )}
                            {b.cisaAdvisories.map((a: string) => (
                              <span key={a} className="text-[9px] px-1 py-0.5 bg-blue-500/10 border border-blue-500/20 text-blue-400 font-mono">
                                <Shield className="w-2.5 h-2.5 inline mr-1" />{a}
                              </span>
                            ))}
                          </div>

                          {/* Target Domains */}
                          <div className="flex flex-wrap gap-1">
                            {b.govTargeting.domains.map((d: string) => (
                              <span key={d} className="text-[9px] px-1 py-0.5 bg-amber-500/10 border border-amber-500/20 text-amber-400 font-mono">{d}</span>
                            ))}
                          </div>
                        </div>
                      ))
                    )}
                  </div>

                  {/* Top Targeted Agencies */}
                  {govStats && govStats.topTargetedAgencies.length > 0 && (
                    <div className="space-y-1">
                      <div className="text-[10px] text-muted-foreground font-display tracking-wider">TOP TARGETED AGENCIES</div>
                      <div className="space-y-1">
                        {govStats.topTargetedAgencies.slice(0, 8).map((a: any) => (
                          <div key={a.agency} className="flex items-center justify-between px-2 py-1 bg-muted/20 border border-border">
                            <span className="text-[10px] text-foreground">{a.agency}</span>
                            <div className="flex items-center gap-2">
                              <div className="w-20 h-1.5 bg-muted/50 overflow-hidden">
                                <div className="h-full bg-red-400" style={{ width: `${(a.count / govStats.topTargetedAgencies[0].count) * 100}%` }} />
                              </div>
                              <span className="text-[9px] font-mono text-muted-foreground">{a.count}</span>
                            </div>
                          </div>
                        ))}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* ─── Broker Timeline Analytics ─────────────────────── */}
            <div className="bg-card border border-orange-500/20 p-4">
              <button onClick={() => toggleSection("brokerTimeline")} className="flex items-center justify-between w-full">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground flex items-center gap-2">
                  <BarChart3 className="w-4 h-4 text-orange-400" /> BROKER TIMELINE ANALYTICS
                </h3>
                <div className="flex items-center gap-2">
                  <div className="flex items-center border border-border overflow-hidden" onClick={(e) => e.stopPropagation()}>
                    {[7, 30, 90, 365].map(d => (
                      <button
                        key={d}
                        onClick={(e) => { e.stopPropagation(); setTimelineDays(d); }}
                        className={`px-2 py-0.5 text-[9px] font-display tracking-wider transition-colors ${
                          timelineDays === d
                            ? 'bg-orange-500/20 text-orange-400 border-orange-500/30'
                            : 'text-muted-foreground hover:text-foreground hover:bg-muted/50'
                        } ${d !== 7 ? 'border-l border-border' : ''}`}
                      >
                        {d === 365 ? '1Y' : `${d}D`}
                      </button>
                    ))}
                  </div>
                  {expandedSections.brokerTimeline ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                </div>
              </button>
              {expandedSections.brokerTimeline && (
                <div className="mt-4 space-y-6">
                  {timelineLoading ? (
                    <div className="flex items-center justify-center py-8"><Loader2 className="w-5 h-5 animate-spin text-muted-foreground" /></div>
                  ) : !brokerTimeline || (brokerTimeline.activityByWeek.length === 0 && brokerTimeline.priceByType.length === 0) ? (
                    <p className="text-xs text-muted-foreground py-4 text-center">No broker listing data available for the selected period.</p>
                  ) : (
                    <>
                      {/* Activity Trend + Avg Price */}
                      {brokerTimeline.activityByWeek.length > 0 && (
                        <div>
                          <h4 className="text-[10px] font-display tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                            <Activity className="w-3 h-3 text-orange-400" /> WEEKLY LISTING ACTIVITY & AVG PRICE
                          </h4>
                          <div className="h-48">
                            <ResponsiveContainer width="100%" height="100%">
                              <AreaChart data={brokerTimeline.activityByWeek} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                                <defs>
                                  <linearGradient id="activityGrad" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#f97316" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="#f97316" stopOpacity={0} />
                                  </linearGradient>
                                  <linearGradient id="priceGrad" x1="0" y1="0" x2="0" y2="1">
                                    <stop offset="5%" stopColor="#22d3ee" stopOpacity={0.3} />
                                    <stop offset="95%" stopColor="#22d3ee" stopOpacity={0} />
                                  </linearGradient>
                                </defs>
                                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
                                <XAxis dataKey="weekStart" tick={{ fontSize: 9, fill: 'hsl(var(--muted-foreground))' }} tickFormatter={(v) => v ? v.slice(5) : ''} />
                                <YAxis yAxisId="left" tick={{ fontSize: 9, fill: 'hsl(var(--muted-foreground))' }} />
                                <YAxis yAxisId="right" orientation="right" tick={{ fontSize: 9, fill: 'hsl(var(--muted-foreground))' }} tickFormatter={(v) => v ? `$${(v/1000).toFixed(0)}k` : ''} />
                                <Tooltip
                                  contentStyle={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: 0, fontSize: 11 }}
                                  labelStyle={{ color: 'hsl(var(--muted-foreground))', fontSize: 10 }}
                                  formatter={(value: any, name: string) => [
                                    name === 'avgPrice' ? `$${(value || 0).toLocaleString()}` : value,
                                    name === 'listings' ? 'Listings' : 'Avg Price'
                                  ]}
                                />
                                <Area yAxisId="left" type="monotone" dataKey="listings" stroke="#f97316" fill="url(#activityGrad)" strokeWidth={2} dot={false} />
                                <Area yAxisId="right" type="monotone" dataKey="avgPrice" stroke="#22d3ee" fill="url(#priceGrad)" strokeWidth={1.5} dot={false} strokeDasharray="4 2" />
                              </AreaChart>
                            </ResponsiveContainer>
                          </div>
                          <div className="flex items-center justify-center gap-4 mt-1">
                            <span className="flex items-center gap-1 text-[9px] text-orange-400"><span className="w-3 h-0.5 bg-orange-400 inline-block" /> Listings</span>
                            <span className="flex items-center gap-1 text-[9px] text-cyan-400"><span className="w-3 h-0.5 bg-cyan-400 inline-block border-dashed" /> Avg Price</span>
                          </div>
                        </div>
                      )}

                      {/* Price by Access Type */}
                      {brokerTimeline.priceByType.length > 0 && (
                        <div>
                          <h4 className="text-[10px] font-display tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                            <DollarSign className="w-3 h-3 text-emerald-400" /> PRICE BY ACCESS TYPE
                          </h4>
                          <div className="h-40">
                            <ResponsiveContainer width="100%" height="100%">
                              <BarChart data={brokerTimeline.priceByType} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
                                <XAxis dataKey="type" tick={{ fontSize: 8, fill: 'hsl(var(--muted-foreground))' }} tickFormatter={(v) => v ? v.replace(/_/g, ' ').slice(0, 12) : ''} />
                                <YAxis tick={{ fontSize: 9, fill: 'hsl(var(--muted-foreground))' }} tickFormatter={(v) => `$${(v/1000).toFixed(0)}k`} />
                                <Tooltip
                                  contentStyle={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: 0, fontSize: 11 }}
                                  formatter={(value: any) => [`$${(value || 0).toLocaleString()}`, 'Avg Price']}
                                  labelFormatter={(label) => label ? label.replace(/_/g, ' ') : ''}
                                />
                                <Bar dataKey="avgPrice" radius={[2, 2, 0, 0]}>
                                  {brokerTimeline.priceByType.map((_, i) => (
                                    <Cell key={i} fill={['#f97316','#22d3ee','#a855f7','#ef4444','#10b981','#eab308','#ec4899','#6366f1','#14b8a6','#f43f5e','#8b5cf6','#06b6d4'][i % 12]} fillOpacity={0.7} />
                                  ))}
                                </Bar>
                              </BarChart>
                            </ResponsiveContainer>
                          </div>
                        </div>
                      )}

                      {/* Sector Targeting Heatmap */}
                      {brokerTimeline.sectorBreakdown.length > 0 && (
                        <div>
                          <h4 className="text-[10px] font-display tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                            <Globe2 className="w-3 h-3 text-amber-400" /> SECTOR TARGETING
                          </h4>
                          <div className="grid grid-cols-3 sm:grid-cols-5 gap-1">
                            {brokerTimeline.sectorBreakdown.map((s, i) => {
                              const maxCount = Math.max(...brokerTimeline.sectorBreakdown.map(x => x.count));
                              const intensity = maxCount > 0 ? s.count / maxCount : 0;
                              return (
                                <div key={i} className="p-2 border border-border text-center relative overflow-hidden" style={{ background: `rgba(249, 115, 22, ${0.05 + intensity * 0.35})` }}>
                                  <p className="text-[9px] font-display tracking-wider text-foreground truncate" title={s.sector}>{s.sector}</p>
                                  <p className="text-sm font-display text-orange-400">{s.count}</p>
                                  {s.avgPrice && <p className="text-[8px] text-muted-foreground">${s.avgPrice.toLocaleString()}</p>}
                                </div>
                              );
                            })}
                          </div>
                        </div>
                      )}

                      {/* Top Brokers + Gov Targeting side by side */}
                      <div className="grid grid-cols-1 sm:grid-cols-2 gap-4">
                        {/* Top Brokers */}
                        {brokerTimeline.topBrokers.length > 0 && (
                          <div>
                            <h4 className="text-[10px] font-display tracking-wider text-muted-foreground mb-2 flex items-center gap-1.5">
                              <Users className="w-3 h-3 text-purple-400" /> TOP BROKERS BY VOLUME
                            </h4>
                            <div className="space-y-1.5">
                              {brokerTimeline.topBrokers.map((b, i) => (
                                <div key={i} className="flex items-center justify-between text-xs border border-border/50 px-2 py-1.5 bg-muted/20">
                                  <div className="flex items-center gap-2 min-w-0">
                                    <span className="text-[10px] font-display text-muted-foreground w-4">{i + 1}.</span>
                                    <span className="truncate text-foreground">{b.name}</span>
                                    <span className={`text-[8px] px-1 py-0.5 border ${
                                      b.reputation === 'established' ? 'text-red-400 border-red-500/30 bg-red-500/10' :
                                      b.reputation === 'rising' ? 'text-amber-400 border-amber-500/30 bg-amber-500/10' :
                                      'text-muted-foreground border-border bg-muted/30'
                                    }`}>{b.reputation}</span>
                                  </div>
                                  <div className="flex items-center gap-2 shrink-0">
                                    <span className="text-[10px] text-orange-400 font-display">{b.listings}</span>
                                    {b.avgPrice && <span className="text-[9px] text-muted-foreground">${b.avgPrice.toLocaleString()}</span>}
                                  </div>
                                </div>
                              ))}
                            </div>
                          </div>
                        )}

                        {/* Gov Targeting Timeline */}
                        {brokerTimeline.govTargeting.length > 0 && (
                          <div>
                            <h4 className="text-[10px] font-display tracking-wider text-red-400 mb-2 flex items-center gap-1.5">
                              <ShieldAlert className="w-3 h-3" /> US GOV TARGETING TREND
                            </h4>
                            <div className="h-32">
                              <ResponsiveContainer width="100%" height="100%">
                                <BarChart data={brokerTimeline.govTargeting} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                                  <CartesianGrid strokeDasharray="3 3" stroke="hsl(var(--border))" opacity={0.3} />
                                  <XAxis dataKey="weekStart" tick={{ fontSize: 8, fill: 'hsl(var(--muted-foreground))' }} tickFormatter={(v) => v ? v.slice(5) : ''} />
                                  <YAxis tick={{ fontSize: 9, fill: 'hsl(var(--muted-foreground))' }} allowDecimals={false} />
                                  <Tooltip
                                    contentStyle={{ background: 'hsl(var(--card))', border: '1px solid hsl(var(--border))', borderRadius: 0, fontSize: 11 }}
                                    labelFormatter={(label) => `Week of ${label}`}
                                    formatter={(value: any) => [value, 'Gov Listings']}
                                  />
                                  <Bar dataKey="count" fill="#ef4444" fillOpacity={0.6} radius={[2, 2, 0, 0]} />
                                </BarChart>
                              </ResponsiveContainer>
                            </div>
                          </div>
                        )}
                      </div>
                    </>
                  )}
                </div>
              )}
            </div>

            {/* ─── IAB Trend Analytics ──────────────────────────────── */}
            <div className="bg-card border border-border p-4">
              <button onClick={() => toggleSection("iabTrends")} className="flex items-center justify-between w-full">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground flex items-center gap-2">
                  <TrendingUp className="w-4 h-4 text-emerald-400" /> IAB TREND ANALYTICS
                </h3>
                <div className="flex items-center gap-2">
                  {[90, 180, 365, 730].map(d => (
                    <button key={d} onClick={(e) => { e.stopPropagation(); setTrendDays(d); }}
                      className={`text-[10px] px-1.5 py-0.5 border transition-colors ${
                        trendDays === d
                          ? 'border-emerald-500/50 text-emerald-400 bg-emerald-500/10'
                          : 'border-border text-muted-foreground hover:text-foreground'
                      }`}>{d <= 365 ? `${d}D` : `${d/365}Y`}</button>
                  ))}
                  {expandedSections.iabTrends ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
                </div>
              </button>
              {expandedSections.iabTrends && (
                <div className="mt-3 space-y-4">
                  {trendsLoading ? (
                    <div className="flex items-center justify-center py-6"><Loader2 className="w-5 h-5 animate-spin text-muted-foreground" /></div>
                  ) : !iabTrends ? (
                    <p className="text-xs text-muted-foreground py-4 text-center">No trend data available.</p>
                  ) : (
                    <>
                      {/* Summary Cards */}
                      <div className="grid grid-cols-2 md:grid-cols-3 lg:grid-cols-6 gap-2">
                        <div className="border border-emerald-500/20 bg-emerald-500/5 p-2.5 text-center">
                          <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Total Listings</p>
                          <p className="text-lg font-display text-emerald-400">{iabTrends.summary.totalListings}</p>
                        </div>
                        <div className="border border-blue-500/20 bg-blue-500/5 p-2.5 text-center">
                          <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Active Brokers</p>
                          <p className="text-lg font-display text-blue-400">{iabTrends.summary.activeBrokers}</p>
                        </div>
                        <div className="border border-amber-500/20 bg-amber-500/5 p-2.5 text-center">
                          <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Avg Price</p>
                          <p className="text-lg font-display text-amber-400">${iabTrends.summary.avgPrice > 0 ? iabTrends.summary.avgPrice.toLocaleString() : 'N/A'}</p>
                        </div>
                        <div className="border border-red-500/20 bg-red-500/5 p-2.5 text-center">
                          <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Gov Listings</p>
                          <p className="text-lg font-display text-red-400">{iabTrends.summary.govListings}</p>
                        </div>
                        <div className="border border-purple-500/20 bg-purple-500/5 p-2.5 text-center">
                          <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Top Sector</p>
                          <p className="text-sm font-display text-purple-400 truncate">{iabTrends.summary.topSector}</p>
                        </div>
                        <div className="border border-cyan-500/20 bg-cyan-500/5 p-2.5 text-center">
                          <p className="text-[10px] text-muted-foreground uppercase tracking-wider">Top Access</p>
                          <p className="text-sm font-display text-cyan-400 truncate">{iabTrends.summary.topAccessType}</p>
                        </div>
                      </div>

                      {/* Monthly Volume + Cumulative */}
                      {iabTrends.monthlyVolume.length > 0 && (
                        <div className="border border-border p-3">
                          <h4 className="text-[10px] font-display tracking-wider text-muted-foreground mb-2 flex items-center gap-1">
                            <BarChart3 className="w-3 h-3" /> MONTHLY LISTING VOLUME
                          </h4>
                          <div className="h-48">
                            <ResponsiveContainer width="100%" height="100%">
                              <ComposedChart data={iabTrends.monthlyVolume} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                                <XAxis dataKey="month" tick={{ fontSize: 10, fill: '#888' }} />
                                <YAxis yAxisId="left" tick={{ fontSize: 10, fill: '#888' }} />
                                <YAxis yAxisId="right" orientation="right" tick={{ fontSize: 10, fill: '#888' }} />
                                <Tooltip
                                  contentStyle={{ background: '#1a1a2e', border: '1px solid #333', fontSize: 11 }}
                                  formatter={(value: any, name: string) => [
                                    name === 'cumulative' ? value : value,
                                    name === 'listings' ? 'New Listings' : name === 'cumulative' ? 'Cumulative' : name === 'avgPrice' ? 'Avg Price ($)' : name
                                  ]}
                                />
                                <Bar yAxisId="left" dataKey="listings" fill="#10b981" fillOpacity={0.7} radius={[2, 2, 0, 0]} name="listings" />
                                <Line yAxisId="right" type="monotone" dataKey="cumulative" stroke="#f59e0b" strokeWidth={2} dot={false} name="cumulative" />
                              </ComposedChart>
                            </ResponsiveContainer>
                          </div>
                        </div>
                      )}

                      {/* Access Type Distribution + Price by Type */}
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                        {iabTrends.accessTypeDistribution.length > 0 && (
                          <div className="border border-border p-3">
                            <h4 className="text-[10px] font-display tracking-wider text-muted-foreground mb-2 flex items-center gap-1">
                              <Key className="w-3 h-3" /> ACCESS TYPE DISTRIBUTION
                            </h4>
                            <div className="h-48">
                              <ResponsiveContainer width="100%" height="100%">
                                <PieChart>
                                  <Pie
                                    data={iabTrends.accessTypeDistribution}
                                    dataKey="count"
                                    nameKey="label"
                                    cx="50%" cy="50%"
                                    outerRadius={65}
                                    innerRadius={30}
                                    strokeWidth={1}
                                    stroke="#1a1a2e"
                                    label={({ label, percent }) => `${label} ${(percent * 100).toFixed(0)}%`}
                                    labelLine={{ stroke: '#666', strokeWidth: 0.5 }}
                                  >
                                    {iabTrends.accessTypeDistribution.map((_: any, i: number) => (
                                      <Cell key={i} fill={[
                                        '#10b981', '#3b82f6', '#f59e0b', '#ef4444', '#8b5cf6',
                                        '#06b6d4', '#ec4899', '#f97316', '#84cc16', '#6366f1',
                                      ][i % 10]} fillOpacity={0.8} />
                                    ))}
                                  </Pie>
                                  <Tooltip contentStyle={{ background: '#1a1a2e', border: '1px solid #333', fontSize: 11 }} />
                                </PieChart>
                              </ResponsiveContainer>
                            </div>
                          </div>
                        )}

                        {/* Price Evolution */}
                        {iabTrends.priceEvolution.length > 0 && (
                          <div className="border border-border p-3">
                            <h4 className="text-[10px] font-display tracking-wider text-muted-foreground mb-2 flex items-center gap-1">
                              <DollarSign className="w-3 h-3" /> PRICE EVOLUTION
                            </h4>
                            <div className="h-48">
                              <ResponsiveContainer width="100%" height="100%">
                                <AreaChart data={iabTrends.priceEvolution} margin={{ top: 5, right: 5, left: -10, bottom: 0 }}>
                                  <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                                  <XAxis dataKey="month" tick={{ fontSize: 10, fill: '#888' }} />
                                  <YAxis tick={{ fontSize: 10, fill: '#888' }} tickFormatter={(v) => `$${(v/1000).toFixed(0)}k`} />
                                  <Tooltip
                                    contentStyle={{ background: '#1a1a2e', border: '1px solid #333', fontSize: 11 }}
                                    formatter={(value: any, name: string) => [`$${Number(value).toLocaleString()}`, name === 'avg' ? 'Average' : name === 'max' ? 'Maximum' : 'Minimum']}
                                  />
                                  <Area type="monotone" dataKey="max" stroke="#ef4444" fill="#ef4444" fillOpacity={0.1} strokeWidth={1} />
                                  <Area type="monotone" dataKey="avg" stroke="#f59e0b" fill="#f59e0b" fillOpacity={0.2} strokeWidth={2} />
                                  <Area type="monotone" dataKey="min" stroke="#10b981" fill="#10b981" fillOpacity={0.1} strokeWidth={1} />
                                </AreaChart>
                              </ResponsiveContainer>
                            </div>
                          </div>
                        )}
                      </div>

                      {/* Sector Targeting Trend — selectable sectors */}
                      {iabTrends.allSectorsList && iabTrends.allSectorsList.length > 0 && (
                        <div className="border border-orange-500/20 p-3">
                          <h4 className="text-[10px] font-display tracking-wider text-orange-400/80 mb-2 flex items-center gap-1">
                            <Crosshair className="w-3 h-3" /> SECTOR TARGETING TREND
                          </h4>
                          {/* Selectable sector pills */}
                          <div className="flex flex-wrap gap-1 mb-3">
                            {iabTrends.allSectorsList.map((sector: string, i: number) => {
                              const isSelected = selectedTrendSectors.includes(sector);
                              const colors = [
                                'border-red-500/40 bg-red-500/20 text-red-300',
                                'border-blue-500/40 bg-blue-500/20 text-blue-300',
                                'border-amber-500/40 bg-amber-500/20 text-amber-300',
                                'border-emerald-500/40 bg-emerald-500/20 text-emerald-300',
                                'border-purple-500/40 bg-purple-500/20 text-purple-300',
                                'border-cyan-500/40 bg-cyan-500/20 text-cyan-300',
                                'border-pink-500/40 bg-pink-500/20 text-pink-300',
                                'border-orange-500/40 bg-orange-500/20 text-orange-300',
                              ];
                              return (
                                <button
                                  key={sector}
                                  onClick={() => {
                                    setSelectedTrendSectors(prev =>
                                      prev.includes(sector)
                                        ? prev.filter(s => s !== sector)
                                        : [...prev, sector]
                                    );
                                  }}
                                  className={`text-[9px] px-1.5 py-0.5 border transition-all cursor-pointer ${
                                    isSelected
                                      ? colors[i % colors.length]
                                      : 'border-border bg-muted/20 text-muted-foreground hover:bg-muted/40'
                                  }`}
                                >
                                  {sector}
                                </button>
                              );
                            })}
                          </div>
                          {/* Chart for selected sectors */}
                          {selectedTrendSectors.length > 0 && iabTrends.sectorTrendData && (() => {
                            // Merge selected sector data into unified chart data
                            const months = new Set<string>();
                            for (const sector of selectedTrendSectors) {
                              const data = (iabTrends.sectorTrendData as Record<string, Array<{month: string; listings: number}>>)[sector];
                              if (data) data.forEach(d => months.add(d.month));
                            }
                            const sortedMonths = Array.from(months).sort();
                            const chartData = sortedMonths.map(month => {
                              const point: Record<string, any> = { month };
                              for (const sector of selectedTrendSectors) {
                                const data = (iabTrends.sectorTrendData as Record<string, Array<{month: string; listings: number}>>)[sector];
                                const found = data?.find(d => d.month === month);
                                point[sector] = found?.listings || 0;
                              }
                              return point;
                            });
                            const sectorColors = ['#ef4444', '#3b82f6', '#f59e0b', '#10b981', '#8b5cf6', '#06b6d4', '#ec4899', '#f97316'];
                            return (
                              <div className="h-40">
                                <ResponsiveContainer width="100%" height="100%">
                                  <BarChart data={chartData} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                                    <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                                    <XAxis dataKey="month" tick={{ fontSize: 10, fill: '#888' }} />
                                    <YAxis tick={{ fontSize: 10, fill: '#888' }} />
                                    <Tooltip contentStyle={{ background: '#1a1a2e', border: '1px solid #333', fontSize: 11 }} />
                                    <Legend wrapperStyle={{ fontSize: 10 }} />
                                    {selectedTrendSectors.map((sector, idx) => (
                                      <Bar key={sector} dataKey={sector} fill={sectorColors[iabTrends.allSectorsList.indexOf(sector) % sectorColors.length]} fillOpacity={0.7} radius={[2, 2, 0, 0]} />
                                    ))}
                                  </BarChart>
                                </ResponsiveContainer>
                              </div>
                            );
                          })()}
                          {selectedTrendSectors.length === 0 && (
                            <p className="text-[10px] text-muted-foreground text-center py-4">Select one or more sectors above to view targeting trends</p>
                          )}
                        </div>
                      )}

                      {/* Top Brokers Ranked Table */}
                      {iabTrends.topBrokersRanked.length > 0 && (
                        <div className="border border-border p-3">
                          <h4 className="text-[10px] font-display tracking-wider text-muted-foreground mb-2 flex items-center gap-1">
                            <Users className="w-3 h-3" /> TOP BROKERS RANKED
                          </h4>
                          <div className="overflow-x-auto">
                            <table className="w-full text-xs">
                              <thead>
                                <tr className="border-b border-border text-muted-foreground">
                                  <th className="text-left py-1.5 px-2">#</th>
                                  <th className="text-left py-1.5 px-2">Broker</th>
                                  <th className="text-right py-1.5 px-2">Listings</th>
                                  <th className="text-right py-1.5 px-2">Avg Price</th>
                                  <th className="text-left py-1.5 px-2">Sectors</th>
                                  <th className="text-left py-1.5 px-2">Top Type</th>
                                  <th className="text-left py-1.5 px-2">Rep</th>
                                </tr>
                              </thead>
                              <tbody>
                                {iabTrends.topBrokersRanked.map((b: any, i: number) => (
                                  <tr key={b.brokerId} className="border-b border-border/50 hover:bg-muted/20 transition-colors">
                                    <td className="py-1.5 px-2 text-muted-foreground">{i + 1}</td>
                                    <td className="py-1.5 px-2 font-medium text-orange-400">{b.name}</td>
                                    <td className="py-1.5 px-2 text-right font-mono">{b.listings}</td>
                                    <td className="py-1.5 px-2 text-right font-mono text-amber-400">
                                      {b.avgPrice ? `$${b.avgPrice.toLocaleString()}` : 'N/A'}
                                    </td>
                                    <td className="py-1.5 px-2">
                                      {b.sectors && (b.sectors as string[]).length > 0 ? (
                                        <div className="flex flex-wrap gap-0.5 max-w-[200px]">
                                          {(b.sectors as string[]).map((s: string, si: number) => (
                                            <span key={si} className="text-[8px] px-1 py-0.5 bg-orange-500/10 border border-orange-500/20 text-orange-300 whitespace-nowrap">{s}</span>
                                          ))}
                                        </div>
                                      ) : (
                                        <span className="text-muted-foreground">{b.topSector || 'N/A'}</span>
                                      )}
                                    </td>
                                    <td className="py-1.5 px-2 text-muted-foreground">{b.topType || 'N/A'}</td>
                                    <td className="py-1.5 px-2">
                                      <span className={`text-[10px] px-1 py-0.5 border ${
                                        b.reputation === 'established' ? 'text-red-400 border-red-500/30 bg-red-500/10'
                                        : b.reputation === 'rising' ? 'text-amber-400 border-amber-500/30 bg-amber-500/10'
                                        : b.reputation === 'new' ? 'text-blue-400 border-blue-500/30 bg-blue-500/10'
                                        : 'text-muted-foreground border-border'
                                      }`}>{b.reputation || 'unknown'}</span>
                                    </td>
                                  </tr>
                                ))}
                              </tbody>
                            </table>
                          </div>
                        </div>
                      )}

                      {/* Sector Shifts Stacked Bar */}
                      {iabTrends.sectorShifts.length > 0 && iabTrends.topSectors && iabTrends.topSectors.length > 0 && (
                        <div className="border border-border p-3">
                          <h4 className="text-[10px] font-display tracking-wider text-muted-foreground mb-2 flex items-center gap-1">
                            <Globe2 className="w-3 h-3" /> SECTOR TARGETING SHIFTS
                          </h4>
                          <div className="h-48">
                            <ResponsiveContainer width="100%" height="100%">
                              <BarChart data={iabTrends.sectorShifts} margin={{ top: 5, right: 5, left: -20, bottom: 0 }}>
                                <CartesianGrid strokeDasharray="3 3" stroke="#333" />
                                <XAxis dataKey="month" tick={{ fontSize: 10, fill: '#888' }} />
                                <YAxis tick={{ fontSize: 10, fill: '#888' }} />
                                <Tooltip contentStyle={{ background: '#1a1a2e', border: '1px solid #333', fontSize: 11 }} />
                                <Legend wrapperStyle={{ fontSize: 10 }} />
                                {(iabTrends.topSectors as string[]).map((sector: string, i: number) => (
                                  <Bar key={sector} dataKey={sector} stackId="sectors" fill={[
                                    '#ef4444', '#3b82f6', '#f59e0b', '#10b981', '#8b5cf6',
                                    '#06b6d4', '#ec4899', '#f97316',
                                  ][i % 8]} fillOpacity={0.7} />
                                ))}
                              </BarChart>
                            </ResponsiveContainer>
                          </div>
                        </div>
                      )}
                    </>
                  )}
                </div>
              )}
            </div>

            {/* ─── IAB Ingestion & Alerting Controls ─────────────────── */}
            <div className="bg-card border border-border p-4">
              <button onClick={() => toggleSection("iabControls")} className="flex items-center justify-between w-full">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-orange-400" /> IAB INGESTION & SPIKE ALERTING
                </h3>
                {expandedSections.iabControls ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
              </button>
              {expandedSections.iabControls && (
                <div className="mt-3 space-y-4">
                  {/* Ingestion Pipeline */}
                  <div className="border border-border p-3 space-y-3">
                    <h4 className="text-[10px] font-display tracking-wider text-muted-foreground flex items-center gap-1">
                      <Database className="w-3 h-3" /> DATA INGESTION PIPELINE
                    </h4>
                    <p className="text-[10px] text-muted-foreground">Pull fresh IAB data from ransomware.live, CISA KEV, RansomLook, and Shodan ICS/Gov exposure monitoring.</p>
                    <div className="flex flex-wrap gap-2">
                      <IABIngestButton label="Run Full Pipeline" source={undefined} />
                      <IABIngestButton label="Ransomware Groups" source="ransomware_live_groups" />
                      <IABIngestButton label="Victim Attribution" source="victim_attribution" />
                      <IABIngestButton label="CISA KEV" source="cisa_kev" />
                      <IABIngestButton label="RansomLook Markets" source="ransomlook_markets" />
                    </div>
                    <div className="flex flex-wrap gap-2 mt-2">
                      <IABIngestButton label="Shodan: All" source="shodan_all" />
                      <IABIngestButton label="Shodan: ICS/SCADA" source="shodan_ics" />
                      <IABIngestButton label="Shodan: Gov/Defense" source="shodan_gov_defense" />
                    </div>
                  </div>

                  {/* Spike Alerting */}
                  <div className="border border-border p-3 space-y-3">
                    <h4 className="text-[10px] font-display tracking-wider text-muted-foreground flex items-center gap-1">
                      <AlertTriangle className="w-3 h-3" /> SPIKE DETECTION & ALERTING
                    </h4>
                    <p className="text-[10px] text-muted-foreground">Check for anomalous spikes in IAB activity. Critical/high alerts are sent as notifications.</p>
                    <IABSpikeCheckButton />
                  </div>
                </div>
              )}
            </div>

            {/* ─── Priority Intelligence ─────────────────────────── */}
            <div className="bg-card border border-border p-4">
              <button onClick={() => toggleSection("iabPriority")} className="flex items-center justify-between w-full">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground flex items-center gap-2">
                  <ShieldAlert className="w-4 h-4 text-red-500" /> PRIORITY INTELLIGENCE — US GOV / ICS-SCADA / DEFENSE
                  <span className="text-[10px] text-muted-foreground/60">
                    ({prioritySummary?.topCritical?.length ?? 0} critical+high)
                  </span>
                </h3>
                {expandedSections.iabPriority ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
              </button>
              {expandedSections.iabPriority && (
                <div className="mt-3 space-y-4">
                  {/* Classify + Summary Row */}
                  <div className="flex items-center gap-2 flex-wrap">
                    <button
                      onClick={() => classifyAll.mutate()}
                      disabled={classifyAll.isPending}
                      className="px-3 py-1.5 text-xs bg-red-600 hover:bg-red-700 text-white rounded flex items-center gap-1.5 disabled:opacity-50"
                    >
                      {classifyAll.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <Crosshair className="w-3 h-3" />}
                      Run Classification
                    </button>
                    <span className="text-[10px] text-muted-foreground">Keyword-based detection on verified data only — no LLM fabrication</span>
                  </div>

                  {/* Priority Level Cards */}
                  {prioritySummary && (
                    <div className="grid grid-cols-2 md:grid-cols-4 gap-2">
                      {(prioritySummary.byLevel as any[])?.map((level: any) => (
                        <div
                          key={level.priority_level}
                          onClick={() => setPriorityFilter(level.priority_level)}
                          className={`p-3 rounded border cursor-pointer transition-all ${
                            priorityFilter === level.priority_level
                              ? 'ring-2 ring-offset-1 ring-offset-background'
                              : 'hover:bg-muted/50'
                          } ${
                            level.priority_level === 'critical' ? 'border-red-500/50 bg-red-500/10 ring-red-500' :
                            level.priority_level === 'high' ? 'border-orange-500/50 bg-orange-500/10 ring-orange-500' :
                            level.priority_level === 'medium' ? 'border-amber-500/50 bg-amber-500/10 ring-amber-500' :
                            'border-blue-500/50 bg-blue-500/10 ring-blue-500'
                          }`}
                        >
                          <div className="text-lg font-bold">{Number(level.count)}</div>
                          <div className="text-[10px] uppercase tracking-wider text-muted-foreground">{level.priority_level}</div>
                          <div className="text-[9px] text-muted-foreground/60">avg score: {Math.round(Number(level.avg_score) || 0)}</div>
                        </div>
                      ))}
                      {priorityFilter !== 'all' && (
                        <div
                          onClick={() => setPriorityFilter('all')}
                          className="p-3 rounded border border-dashed border-muted-foreground/30 cursor-pointer hover:bg-muted/50 flex items-center justify-center"
                        >
                          <span className="text-xs text-muted-foreground">Show All</span>
                        </div>
                      )}
                    </div>
                  )}

                  {/* Category Filter Buttons */}
                  <div className="flex gap-1.5 flex-wrap">
                    {[
                      { key: 'all', label: 'All Categories', icon: '📊' },
                      { key: 'us_gov', label: 'US Government', icon: '🏛️' },
                      { key: 'ics_scada', label: 'ICS/SCADA', icon: '⚡' },
                      { key: 'defense_contractor', label: 'Defense Contractor', icon: '🛡️' },
                      { key: 'critical_infrastructure', label: 'Critical Infrastructure', icon: '🏗️' },
                    ].map(cat => (
                      <button
                        key={cat.key}
                        onClick={() => setCategoryFilter(cat.key as any)}
                        className={`px-2.5 py-1 text-[11px] rounded border transition-all ${
                          categoryFilter === cat.key
                            ? 'bg-primary text-primary-foreground border-primary'
                            : 'bg-muted/30 text-muted-foreground border-border hover:bg-muted/60'
                        }`}
                      >
                        {cat.icon} {cat.label}
                        {cat.key !== 'all' && prioritySummary?.byCategory?.[cat.key] ? ` (${prioritySummary.byCategory[cat.key]})` : ''}
                      </button>
                    ))}
                  </div>

                  {/* Priority Listings Table */}
                  {priorityListingsLoading ? (
                    <div className="flex items-center gap-2 text-muted-foreground text-xs py-4">
                      <Loader2 className="w-4 h-4 animate-spin" /> Loading priority listings...
                    </div>
                  ) : priorityListings && priorityListings.listings.length > 0 ? (
                    <div className="overflow-x-auto -mx-3 px-3">
                      <table className="text-xs" style={{ minWidth: '900px', width: '100%' }}>
                        <thead>
                          <tr className="border-b border-border text-muted-foreground">
                            <th className="text-left py-2 px-2 whitespace-nowrap" style={{ width: '80px' }}>Priority</th>
                            <th className="text-left py-2 px-2 whitespace-nowrap" style={{ width: '50px' }}>Score</th>
                            <th className="text-left py-2 px-2 whitespace-nowrap" style={{ width: '130px' }}>Broker</th>
                            <th className="text-left py-2 px-2 whitespace-nowrap" style={{ width: '100px' }}>Victim / Target</th>
                            <th className="text-left py-2 px-2 whitespace-nowrap" style={{ width: '180px' }}>Sector</th>
                            <th className="text-left py-2 px-2 whitespace-nowrap" style={{ width: '110px' }}>Access Type</th>
                            <th className="text-left py-2 px-2 whitespace-nowrap" style={{ width: '160px' }}>Tags</th>
                            <th className="text-left py-2 px-2 whitespace-nowrap" style={{ width: '120px' }}>Source</th>
                          </tr>
                        </thead>
                        <tbody>
                          {priorityListings.listings.map((listing: any) => {
                            let tags: any = {};
                            try { tags = typeof listing.priority_tags === 'string' ? JSON.parse(listing.priority_tags) : listing.priority_tags || {}; } catch {}
                            return (
                              <tr key={listing.id} className="border-b border-border/50 hover:bg-muted/30">
                                <td className="py-2 px-2 align-top">
                                  <span className={`px-1.5 py-0.5 rounded text-[10px] font-bold uppercase whitespace-nowrap ${
                                    listing.priority_level === 'critical' ? 'bg-red-500/20 text-red-400 border border-red-500/30' :
                                    listing.priority_level === 'high' ? 'bg-orange-500/20 text-orange-400 border border-orange-500/30' :
                                    listing.priority_level === 'medium' ? 'bg-amber-500/20 text-amber-400 border border-amber-500/30' :
                                    'bg-blue-500/20 text-blue-400 border border-blue-500/30'
                                  }`}>
                                    {listing.priority_level}
                                  </span>
                                </td>
                                <td className="py-2 px-2 font-mono text-muted-foreground align-top">{listing.priority_score}</td>
                                <td className="py-2 px-2 font-medium text-foreground align-top">{listing.brokerName || 'Unknown'}</td>
                                <td className="py-2 px-2 text-foreground/80 align-top">{listing.victimCountry || '\u2014'}</td>
                                <td className="py-2 px-2 text-muted-foreground align-top">
                                  {listing.victimSector ? (
                                    <div className="flex flex-wrap gap-0.5">
                                      {String(listing.victimSector).split(/,\s*/).filter(Boolean).map((s: string, i: number) => (
                                        <span key={i} className="text-[9px] px-1 py-0.5 bg-orange-500/10 border border-orange-500/20 text-orange-300 whitespace-nowrap">{s.trim()}</span>
                                      ))}
                                    </div>
                                  ) : '\u2014'}
                                </td>
                                <td className="py-2 px-2 align-top">
                                  <span className="px-1.5 py-0.5 rounded bg-muted text-[10px] whitespace-nowrap">{listing.accessType || '\u2014'}</span>
                                </td>
                                <td className="py-2 px-2 align-top">
                                  <div className="flex gap-1 flex-wrap">
                                    {(tags.tags || []).map((t: string, i: number) => (
                                      <span key={i} className={`px-1.5 py-0.5 rounded text-[9px] font-medium whitespace-nowrap ${
                                        t === 'US Government' ? 'bg-red-500/20 text-red-300' :
                                        t === 'ICS/SCADA' ? 'bg-yellow-500/20 text-yellow-300' :
                                        t === 'Defense Contractor' ? 'bg-orange-500/20 text-orange-300' :
                                        'bg-blue-500/20 text-blue-300'
                                      }`}>{t}</span>
                                    ))}
                                  </div>
                                </td>
                                <td className="py-2 px-2 text-[10px] text-muted-foreground/60 align-top">{listing.iabDataSource || '\u2014'}</td>
                              </tr>
                            );
                          })}
                        </tbody>
                      </table>
                      <div className="text-[10px] text-muted-foreground/60 mt-2">
                        Showing {priorityListings.listings.length} of {priorityListings.total} listings
                      </div>
                    </div>
                  ) : (
                    <div className="text-xs text-muted-foreground py-4 text-center">
                      No listings found. Click "Run Classification" to classify all IAB listings.
                    </div>
                  )}

                  {/* Matched Keywords for top critical */}
                  {prioritySummary?.topCritical && prioritySummary.topCritical.length > 0 && (
                    <div className="border-t border-border pt-3">
                      <h4 className="text-[10px] uppercase tracking-wider text-muted-foreground mb-2 flex items-center gap-1">
                        <Key className="w-3 h-3" /> Matched Keywords (Top Critical Listings)
                      </h4>
                      <div className="flex gap-1 flex-wrap">
                        {(() => {
                          const allKw = new Set<string>();
                          prioritySummary.topCritical.forEach((l: any) => {
                            try {
                              const tags = typeof l.priority_tags === 'string' ? JSON.parse(l.priority_tags) : l.priority_tags;
                              (tags?.matchedKeywords || []).forEach((k: string) => allKw.add(k));
                            } catch {}
                          });
                          return [...allKw].sort().map(kw => (
                            <span key={kw} className="px-1.5 py-0.5 rounded bg-red-500/10 text-red-300 text-[9px] border border-red-500/20">{kw}</span>
                          ));
                        })()}
                      </div>
                    </div>
                  )}
                </div>
              )}
            </div>

            {/* ─── Information Operations Campaigns ───────────────────── */}
            <div className="bg-card border border-border p-4">
              <button onClick={() => toggleSection("infoOps")} className="flex items-center justify-between w-full">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground flex items-center gap-2">
                  <Megaphone className="w-4 h-4 text-pink-400" /> INFORMATION OPERATIONS
                  <span className="text-[10px] text-muted-foreground/60">({iosCampaigns?.length ?? 0})</span>
                </h3>
                {expandedSections.infoOps ? <ChevronUp className="w-4 h-4 text-muted-foreground" /> : <ChevronDown className="w-4 h-4 text-muted-foreground" />}
              </button>
              {expandedSections.infoOps && (
                <div className="mt-3 space-y-2 max-h-[500px] overflow-y-auto">
                  {iosLoading ? (
                    <div className="flex items-center justify-center py-6"><Loader2 className="w-5 h-5 animate-spin text-muted-foreground" /></div>
                  ) : !iosCampaigns || iosCampaigns.length === 0 ? (
                    <p className="text-xs text-muted-foreground py-4 text-center">No IO campaigns loaded. Click sync to populate.</p>
                  ) : (
                    iosCampaigns.map((io: any) => (
                      <div key={io.id} className="border border-pink-500/20 bg-pink-500/5 p-3 space-y-2">
                        <div className="flex items-start justify-between">
                          <div>
                            <div className="flex items-center gap-2">
                              <span className="text-sm font-display text-pink-400 tracking-wide">{safeUpper(io.campaignName)}</span>
                            </div>
                            <div className="flex items-center gap-2 mt-0.5">
                              <span className="text-[10px] text-muted-foreground">{io.operatorGroup}</span>
                              <span className="text-[9px] px-1.5 py-0.5 bg-muted/50 border border-border text-muted-foreground">
                                {io.sponsorState}
                              </span>
                            </div>
                          </div>
                          <div className="flex flex-col items-end gap-1">
                            <span className={`text-[9px] px-1.5 py-0.5 border ${
                              io.status === "active" || io.status === "ongoing" ? "text-red-400 border-red-500/30 bg-red-500/10"
                              : io.status === "disrupted" ? "text-green-400 border-green-500/30 bg-green-500/10"
                              : io.status === "attributed" ? "text-blue-400 border-blue-500/30 bg-blue-500/10"
                              : "text-muted-foreground border-border bg-muted/30"
                            }`}>{safeUpper(io.status || "UNKNOWN")}</span>
                            <span className={`text-[9px] px-1.5 py-0.5 border ${
                              SEVERITY_COLORS[io.threatLevel] || "text-muted-foreground border-border"
                            }`}>{safeUpper(io.threatLevel || "MEDIUM")}</span>
                          </div>
                        </div>
                        <p className="text-[11px] text-muted-foreground leading-relaxed line-clamp-3">{io.description}</p>
                        <div className="flex flex-wrap gap-1.5">
                          <span className="text-[9px] px-1.5 py-0.5 bg-muted/50 border border-border text-muted-foreground">
                            {io.operationType?.replace(/_/g, " ") || "influence"}
                          </span>
                          {io.cyberComponent && (
                            <span className="text-[9px] px-1.5 py-0.5 bg-red-500/10 border border-red-500/20 text-red-400">
                              <Zap className="w-2.5 h-2.5 inline mr-1" />CYBER COMPONENT
                            </span>
                          )}
                          {io.primarySource && (
                            <span className="text-[9px] px-1.5 py-0.5 bg-muted/50 border border-border text-muted-foreground">
                              <FileText className="w-2.5 h-2.5 inline mr-1" />{io.primarySource}
                            </span>
                          )}
                          {io.confidence != null && (
                            <span className="text-[9px] px-1.5 py-0.5 bg-muted/50 border border-border text-muted-foreground">
                              CONF: {io.confidence}%
                            </span>
                          )}
                        </div>
                        {io.targetCountries && (io.targetCountries as string[]).length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            <span className="text-[9px] text-muted-foreground">TARGETS:</span>
                            {(io.targetCountries as string[]).map((c: string) => (
                              <span key={c} className="text-[9px] px-1 py-0.5 bg-blue-500/10 border border-blue-500/20 text-blue-400">{c}</span>
                            ))}
                          </div>
                        )}
                        {io.targetPlatforms && (io.targetPlatforms as string[]).length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            <span className="text-[9px] text-muted-foreground">PLATFORMS:</span>
                            {(io.targetPlatforms as string[]).slice(0, 5).map((p: string) => (
                              <span key={p} className="text-[9px] px-1 py-0.5 bg-purple-500/10 border border-purple-500/20 text-purple-400">{p}</span>
                            ))}
                          </div>
                        )}
                        {io.targetNarratives && (io.targetNarratives as string[]).length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            <span className="text-[9px] text-muted-foreground">NARRATIVES:</span>
                            {(io.targetNarratives as string[]).slice(0, 4).map((n: string) => (
                              <span key={n} className="text-[9px] px-1 py-0.5 bg-amber-500/10 border border-amber-500/20 text-amber-400">{n}</span>
                            ))}
                            {(io.targetNarratives as string[]).length > 4 && (
                              <span className="text-[9px] text-muted-foreground">+{(io.targetNarratives as string[]).length - 4} more</span>
                            )}
                          </div>
                        )}
                        {io.techniques && (io.techniques as string[]).length > 0 && (
                          <div className="flex flex-wrap gap-1">
                            <span className="text-[9px] text-muted-foreground">TECHNIQUES:</span>
                            {(io.techniques as string[]).slice(0, 4).map((t: string) => (
                              <span key={t} className="text-[9px] px-1 py-0.5 bg-cyan-500/10 border border-cyan-500/20 text-cyan-400">{t}</span>
                            ))}
                          </div>
                        )}
                      </div>
                    ))
                  )}
                </div>
              )}
            </div>

          {/* ─── Sidebar (1/3) ───────────────────────────────────────────── */}
          <div className="space-y-6">

            {/* Activity Ratings */}
            {activityRatings && activityRatings.data.length > 0 && (
              <div className="bg-card border border-border p-4">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                  <TrendingUp className="w-4 h-4 text-amber-400" /> ACTIVITY RATINGS
                  <span className="text-[10px] text-muted-foreground/60">LOCAL DB</span>
                </h3>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {activityRatings.data.slice(0, 15).map((r: any, i: number) => (
                    <div key={i} className="flex items-center justify-between text-xs">
                      <span className="text-muted-foreground truncate">{r.groupName || r.name || "—"}</span>
                      <div className="flex items-center gap-1.5">
                        <div className="w-12 h-1.5 bg-muted overflow-hidden">
                          <div className={`h-full ${(r.rating || r.score || 0) > 7 ? "bg-red-400" : (r.rating || r.score || 0) > 4 ? "bg-amber-400" : "bg-green-400"}`}
                            style={{ width: `${Math.min(100, ((r.rating || r.score || 0) / 10) * 100)}%` }} />
                        </div>
                        <span className="text-[10px] text-muted-foreground w-6 text-right">{r.rating || r.score || 0}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Ransomware Victim Stats */}
            {ransomwareVictimStats && ransomwareVictimStats.data.length > 0 && (
              <div className="bg-card border border-border p-4">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                  <Skull className="w-4 h-4 text-red-400" /> VICTIM STATS BY GROUP
                  <span className="text-[10px] text-muted-foreground/60">LOCAL DB</span>
                </h3>
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {ransomwareVictimStats.data.slice(0, 15).map((g: any, i: number) => (
                    <div key={i} className="flex items-center justify-between text-xs">
                      <span className="text-amber-400 truncate">{g.groupName}</span>
                      <span className="text-muted-foreground">{g.totalVictims ?? g.victimCount ?? 0} victims</span>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Adaptive Keywords */}
            {adaptiveKeywords && adaptiveKeywords.data.length > 0 && (
              <div className="bg-card border border-border p-4">
                <button onClick={() => toggleSection("keywords")} className="flex items-center justify-between w-full mb-3">
                  <h3 className="text-xs font-display tracking-wider text-muted-foreground flex items-center gap-2">
                    <Key className="w-4 h-4 text-emerald-400" /> ADAPTIVE KEYWORDS
                  </h3>
                  {expandedSections.keywords ? <ChevronUp className="w-3 h-3 text-muted-foreground" /> : <ChevronDown className="w-3 h-3 text-muted-foreground" />}
                </button>
                {expandedSections.keywords && (
                  <div className="flex flex-wrap gap-1.5">
                    {adaptiveKeywords.data.slice(0, 30).map((kw: any, i: number) => (
                      <span key={i} className="px-2 py-0.5 text-[10px] bg-emerald-500/10 text-emerald-400 border border-emerald-500/20 tracking-wider">
                        {typeof kw === "string" ? kw : kw.keyword || kw.term || "—"}
                      </span>
                    ))}
                  </div>
                )}
              </div>
            )}

            {/* Technique Coverage */}
            <div className="bg-card border border-border p-4">
              <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                <Crosshair className="w-4 h-4 text-primary" /> TOP MITRE TECHNIQUES
              </h3>
              {coverage?.topTechniques && coverage.topTechniques.length > 0 ? (
                <div className="space-y-2 max-h-64 overflow-y-auto">
                  {coverage.topTechniques.slice(0, 15).map((t: any) => (
                    <div key={t.id} className="flex items-center justify-between text-xs">
                      <div className="flex items-center gap-2 min-w-0">
                        <span className="font-mono text-primary shrink-0">{t.id}</span>
                        <span className="text-muted-foreground truncate">{t.name}</span>
                      </div>
                      <span className="text-[10px] text-muted-foreground shrink-0">{t.actors.length} actors</span>
                    </div>
                  ))}
                </div>
              ) : (
                <p className="text-xs text-muted-foreground">No techniques mapped yet.</p>
              )}
            </div>

            {/* Tactic Distribution */}
            {coverage?.byTactic && coverage.byTactic.length > 0 && (
              <div className="bg-card border border-border p-4">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                  <Shield className="w-4 h-4 text-cyan-400" /> TACTIC DISTRIBUTION
                </h3>
                <div className="space-y-2">
                  {coverage.byTactic.slice(0, 12).map((t: any) => (
                    <div key={t.tactic} className="flex items-center justify-between text-xs">
                      <span className="text-muted-foreground capitalize">{t.tactic.replace(/-/g, " ")}</span>
                      <div className="flex items-center gap-2">
                        <div className="w-16 h-1.5 bg-muted overflow-hidden">
                          <div className="h-full bg-cyan-400" style={{ width: `${Math.min(100, (t.count / (coverage.byTactic[0]?.count || 1)) * 100)}%` }} />
                        </div>
                        <span className="text-[10px] text-muted-foreground w-6 text-right">{t.count}</span>
                      </div>
                    </div>
                  ))}
                </div>
              </div>
            )}

            {/* Sync History */}
            <div className="bg-card border border-border p-4">
              <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                <Clock className="w-4 h-4 text-blue-400" /> SYNC HISTORY
              </h3>
              {syncLoading ? (
                <div className="animate-pulse space-y-2">
                  {[1, 2, 3].map(i => <div key={i} className="h-8 bg-muted rounded" />)}
                </div>
              ) : !syncHistory || syncHistory.length === 0 ? (
                <p className="text-xs text-muted-foreground">No sync history yet.</p>
              ) : (
                <div className="space-y-2 max-h-48 overflow-y-auto">
                  {syncHistory.map((s: any) => (
                    <div key={s.id} className="flex items-center justify-between text-[11px] border-b border-border/50 pb-1.5">
                      <div>
                        <span className={`px-1.5 py-0.5 text-[10px] tracking-wider ${
                          s.status === "completed" ? "text-green-400 bg-green-500/10"
                            : s.status === "failed" ? "text-red-400 bg-red-500/10"
                            : "text-yellow-400 bg-yellow-500/10"}`}>
                          {safeUpper(s.status)}
                        </span>
                        <span className="text-muted-foreground ml-2">{s.sweepType}</span>
                      </div>
                      <span className="text-muted-foreground">
                        {s.startedAt ? new Date(s.startedAt).toLocaleDateString() : "—"}
                      </span>
                    </div>
                  ))}
                </div>
              )}
            </div>

            {/* Actor Type Distribution */}
            {stats?.byType && Object.keys(stats.byType).length > 0 && (
              <div className="bg-card border border-border p-4">
                <h3 className="text-xs font-display tracking-wider text-muted-foreground mb-3 flex items-center gap-2">
                  <Database className="w-4 h-4 text-emerald-400" /> ACTOR DISTRIBUTION
                </h3>
                <div className="space-y-2">
                  {Object.entries(stats.byType).sort((a, b) => (b[1] as number) - (a[1] as number)).map(([type, count]) => (
                    <div key={type} className="flex items-center justify-between text-xs">
                      <span className={`capitalize ${ACTOR_TYPE_COLORS[type] || "text-muted-foreground"}`}>
                        {type.replace(/_/g, " ")}
                      </span>
                      <span className="text-muted-foreground">{count as number}</span>
                    </div>
                  ))}
                </div>
              </div>
            )}
          </div>
        </div>
      </div>
    </AppShell>
  );
}
