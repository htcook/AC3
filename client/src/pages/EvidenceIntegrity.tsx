import { useState, useMemo, useEffect, useRef } from "react";
import { useEvidenceIntegrityEvents } from "@/hooks/useWebSocket";
import type { WsEvent } from "@/hooks/useWebSocket";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Button } from "@/components/ui/button";
import { Badge } from "@/components/ui/badge";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import { Dialog, DialogContent, DialogHeader, DialogTitle, DialogDescription } from "@/components/ui/dialog";
import { Tabs, TabsContent, TabsList, TabsTrigger } from "@/components/ui/tabs";
import { toast } from "sonner";
import {
  Shield, ShieldCheck, ShieldAlert, ShieldX,
  Lock, Unlock, Hash, Activity, Eye, AlertTriangle,
  CheckCircle2, XCircle, Clock, RefreshCw, Loader2,
  Anchor, FileText, BarChart3, Filter, ChevronLeft,
  ChevronRight, Search, Fingerprint, Link2, Database,
} from "lucide-react";

// ─── Helpers ────────────────────────────────────────────────────────────
function truncHash(hash: string, len = 12): string {
  return hash ? `${hash.slice(0, len)}...` : "N/A";
}

function recommendationBadge(rec: string) {
  const map: Record<string, { color: string; icon: typeof CheckCircle2 }> = {
    accept: { color: "bg-emerald-500/15 text-emerald-400 border-emerald-500/30", icon: CheckCircle2 },
    review: { color: "bg-amber-500/15 text-amber-400 border-amber-500/30", icon: Eye },
    reject: { color: "bg-red-500/15 text-red-400 border-red-500/30", icon: XCircle },
    quarantine: { color: "bg-red-600/20 text-red-300 border-red-600/40", icon: ShieldX },
  };
  const cfg = map[rec] || map.review;
  const Icon = cfg.icon;
  return (
    <Badge variant="outline" className={`${cfg.color} gap-1 font-mono text-xs`}>
      <Icon className="h-3 w-3" />
      {rec.toUpperCase()}
    </Badge>
  );
}

function scoreBar(score: number) {
  const pct = Math.round(score * 100);
  const color = pct >= 80 ? "bg-emerald-500" : pct >= 50 ? "bg-amber-500" : "bg-red-500";
  return (
    <div className="flex items-center gap-2 min-w-[120px]">
      <div className="flex-1 h-1.5 bg-muted rounded-full overflow-hidden">
        <div className={`h-full ${color} rounded-full transition-all`} style={{ width: `${pct}%` }} />
      </div>
      <span className="text-xs font-mono text-muted-foreground w-8 text-right">{pct}%</span>
    </div>
  );
}

// ─── Live Monitor Panel ─────────────────────────────────────────────────────────────
function LiveMonitorPanel() {
  const { events, status, lastEvent } = useEvidenceIntegrityEvents();
  const [isPaused, setIsPaused] = useState(false);
  const [displayEvents, setDisplayEvents] = useState<WsEvent[]>([]);
  const feedRef = useRef<HTMLDivElement>(null);

  // Accumulate events unless paused
  useEffect(() => {
    if (!isPaused && events.length > 0) {
      setDisplayEvents(events);
    }
  }, [events, isPaused]);

  // Counters
  const counters = useMemo(() => {
    const c = { passed: 0, flagged: 0, quarantined: 0, anchors: 0, tampered: 0, flushed: 0 };
    for (const e of displayEvents) {
      switch (e.type) {
        case "evidence:gate_passed": c.passed++; break;
        case "evidence:gate_flagged": c.flagged++; break;
        case "evidence:quarantined": c.quarantined++; break;
        case "evidence:anchor_created": c.anchors++; break;
        case "evidence:tamper_detected": c.tampered++; break;
        case "evidence:chain_flushed": c.flushed++; break;
      }
    }
    return c;
  }, [displayEvents]);

  function eventIcon(type: string) {
    switch (type) {
      case "evidence:gate_passed": return <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />;
      case "evidence:gate_flagged": return <ShieldAlert className="h-3.5 w-3.5 text-amber-400" />;
      case "evidence:quarantined": return <ShieldX className="h-3.5 w-3.5 text-red-400" />;
      case "evidence:chain_flushed": return <Database className="h-3.5 w-3.5 text-blue-400" />;
      case "evidence:anchor_created": return <Anchor className="h-3.5 w-3.5 text-violet-400" />;
      case "evidence:anchor_verified": return <Lock className="h-3.5 w-3.5 text-emerald-400" />;
      case "evidence:tamper_detected": return <ShieldX className="h-3.5 w-3.5 text-red-500 animate-pulse" />;
      default: return <Activity className="h-3.5 w-3.5 text-muted-foreground" />;
    }
  }

  function eventBadgeColor(type: string) {
    switch (type) {
      case "evidence:gate_passed": return "bg-emerald-500/15 text-emerald-400 border-emerald-500/30";
      case "evidence:gate_flagged": return "bg-amber-500/15 text-amber-400 border-amber-500/30";
      case "evidence:quarantined": return "bg-red-500/15 text-red-400 border-red-500/30";
      case "evidence:chain_flushed": return "bg-blue-500/15 text-blue-400 border-blue-500/30";
      case "evidence:anchor_created": return "bg-violet-500/15 text-violet-400 border-violet-500/30";
      case "evidence:anchor_verified": return "bg-emerald-500/15 text-emerald-400 border-emerald-500/30";
      case "evidence:tamper_detected": return "bg-red-600/20 text-red-300 border-red-600/40";
      default: return "bg-muted/30 text-muted-foreground border-border/50";
    }
  }

  function eventLabel(type: string) {
    return type.replace("evidence:", "").replace(/_/g, " ").toUpperCase();
  }

  function eventDescription(event: WsEvent) {
    const d = event.data;
    switch (event.type) {
      case "evidence:gate_passed":
        return `${d.sourceTool || "unknown"} → ${d.evidenceType || "evidence"} (score: ${Math.round((d.score || 0) * 100)}%)`;
      case "evidence:gate_flagged":
        return `${d.sourceTool || "unknown"} → ${d.evidenceType || "evidence"} (score: ${Math.round((d.score || 0) * 100)}%) — ${d.recommendation || "review"}`;
      case "evidence:quarantined":
        return `${d.evidenceType || "evidence"}: ${d.reason || "integrity check failed"}`;
      case "evidence:chain_flushed":
        return `${d.flushedCount || 0} envelopes flushed, ${d.errorCount || 0} errors`;
      case "evidence:anchor_created":
        return `Merkle root: ${(d.merkleRoot || "").slice(0, 16)}... (${d.chainLength || 0} items)`;
      case "evidence:anchor_verified":
        return d.valid ? `Anchor verified: ${(d.merkleRoot || "").slice(0, 16)}...` : `Verification FAILED: ${d.error || "mismatch"}`;
      case "evidence:tamper_detected":
        return `Evidence ${d.evidenceId || "unknown"} — expected: ${(d.expectedHash || "").slice(0, 12)}... actual: ${(d.actualHash || "").slice(0, 12)}...`;
      default:
        return JSON.stringify(d).slice(0, 100);
    }
  }

  const statusColor = status === "connected" ? "bg-emerald-500" : status === "connecting" ? "bg-amber-500" : "bg-red-500";

  return (
    <div className="space-y-4">
      {/* Live Monitor Header */}
      <div className="flex items-center justify-between">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <div className={`h-2 w-2 rounded-full ${statusColor} ${status === "connected" ? "animate-pulse" : ""}`} />
            <span className="text-sm font-medium">
              {status === "connected" ? "Live" : status === "connecting" ? "Connecting..." : "Disconnected"}
            </span>
          </div>
          <Badge variant="outline" className="text-xs font-mono">
            {displayEvents.length} events
          </Badge>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => setIsPaused(!isPaused)}
            className={isPaused ? "border-amber-500/50 text-amber-400" : ""}
          >
            {isPaused ? (
              <><Activity className="h-3.5 w-3.5 mr-1" /> Resume</>
            ) : (
              <><Clock className="h-3.5 w-3.5 mr-1" /> Pause</>
            )}
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() => setDisplayEvents([])}
          >
            <XCircle className="h-3.5 w-3.5 mr-1" /> Clear
          </Button>
        </div>
      </div>

      {/* Live Counters */}
      <div className="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-6 gap-3">
        {[
          { label: "Passed", value: counters.passed, color: "text-emerald-400", bg: "bg-emerald-500/10", icon: CheckCircle2 },
          { label: "Flagged", value: counters.flagged, color: "text-amber-400", bg: "bg-amber-500/10", icon: ShieldAlert },
          { label: "Quarantined", value: counters.quarantined, color: "text-red-400", bg: "bg-red-500/10", icon: ShieldX },
          { label: "Anchors", value: counters.anchors, color: "text-violet-400", bg: "bg-violet-500/10", icon: Anchor },
          { label: "Flushed", value: counters.flushed, color: "text-blue-400", bg: "bg-blue-500/10", icon: Database },
          { label: "Tampered", value: counters.tampered, color: counters.tampered > 0 ? "text-red-500" : "text-muted-foreground", bg: counters.tampered > 0 ? "bg-red-600/15" : "bg-muted/20", icon: AlertTriangle },
        ].map((c) => {
          const Icon = c.icon;
          return (
            <div key={c.label} className={`${c.bg} rounded-lg p-3 flex items-center gap-2`}>
              <Icon className={`h-4 w-4 ${c.color}`} />
              <div>
                <p className={`text-lg font-bold ${c.color}`}>{c.value}</p>
                <p className="text-[10px] text-muted-foreground">{c.label}</p>
              </div>
            </div>
          );
        })}
      </div>

      {/* Event Feed */}
      <Card className="border-border/50 bg-card/50">
        <CardHeader className="pb-2">
          <CardTitle className="text-sm font-medium flex items-center gap-2">
            <Activity className="h-4 w-4 text-emerald-400" />
            Real-Time Evidence Event Feed
            {isPaused && <Badge variant="outline" className="text-[10px] bg-amber-500/10 text-amber-400 border-amber-500/30">PAUSED</Badge>}
          </CardTitle>
        </CardHeader>
        <CardContent>
          <div ref={feedRef} className="max-h-[500px] overflow-y-auto space-y-1 pr-1">
            {displayEvents.length === 0 ? (
              <div className="text-center py-12 text-muted-foreground">
                <Activity className="h-8 w-8 mx-auto mb-3 opacity-30" />
                <p className="text-sm">No evidence integrity events yet</p>
                <p className="text-xs mt-1">Events will appear here in real-time during active engagements</p>
              </div>
            ) : (
              displayEvents.map((event, idx) => (
                <div
                  key={`${event.timestamp}-${idx}`}
                  className={`flex items-start gap-3 p-2.5 rounded-md border border-transparent hover:border-border/30 hover:bg-muted/10 transition-colors ${
                    idx === 0 && !isPaused ? "animate-in fade-in slide-in-from-top-1 duration-300" : ""
                  }`}
                >
                  <div className="mt-0.5">{eventIcon(event.type)}</div>
                  <div className="flex-1 min-w-0">
                    <div className="flex items-center gap-2 flex-wrap">
                      <Badge variant="outline" className={`text-[10px] font-mono ${eventBadgeColor(event.type)}`}>
                        {eventLabel(event.type)}
                      </Badge>
                      {event.engagementId && (
                        <span className="text-[10px] text-muted-foreground font-mono">ENG-{event.engagementId}</span>
                      )}
                      {event.data?.target && (
                        <span className="text-[10px] text-muted-foreground">{event.data.target}</span>
                      )}
                    </div>
                    <p className="text-xs text-muted-foreground mt-0.5 truncate">
                      {eventDescription(event)}
                    </p>
                  </div>
                  <span className="text-[10px] text-muted-foreground/60 whitespace-nowrap font-mono">
                    {new Date(event.timestamp).toLocaleTimeString()}
                  </span>
                </div>
              ))
            )}
          </div>
        </CardContent>
      </Card>
    </div>
  );
}

// ─── Main Component ─────────────────────────────────────────────────────────────
export default function EvidenceIntegrity() {st [activeTab, setActiveTab] = useState("overview");
  const [auditEngagement, setAuditEngagement] = useState<string>("all");
  const [auditSpecialist, setAuditSpecialist] = useState<string>("all");
  const [auditRecommendation, setAuditRecommendation] = useState<string>("all");
  const [auditPage, setAuditPage] = useState(0);
  const [selectedAuditItem, setSelectedAuditItem] = useState<any>(null);
  const [anchorEngagement, setAnchorEngagement] = useState<string>("");
  const [verifyEngagement, setVerifyEngagement] = useState<string>("");
  const PAGE_SIZE = 20;

  // ─── Queries ───
  const chainStats = trpc.evidenceIntegrity.chainStats.useQuery(undefined, {
    refetchInterval: 30_000,
  });

  const auditLog = trpc.evidenceIntegrity.auditLog.useQuery({
    engagementId: auditEngagement !== "all" ? auditEngagement : undefined,
    specialist: auditSpecialist !== "all" ? auditSpecialist : undefined,
    recommendation: auditRecommendation !== "all" ? auditRecommendation as any : undefined,
    limit: PAGE_SIZE,
    offset: auditPage * PAGE_SIZE,
  }, {
    refetchInterval: 15_000,
  });

  const anchors = trpc.evidenceIntegrity.anchors.useQuery({
    engagementId: anchorEngagement || undefined,
  });

  const engagementsQuery = trpc.evidenceGallery.engagementsWithEvidence.useQuery();

  // ─── Mutations ───
  const createAnchorMut = trpc.evidenceIntegrity.createAnchor.useMutation({
    onSuccess: (data) => {
      toast.success(`Merkle root anchor created: ${truncHash(data.merkleRoot)}`);
      anchors.refetch();
      chainStats.refetch();
    },
    onError: (err) => toast.error(`Anchor creation failed: ${err.message}`),
  });

  const verifyAnchorQuery = trpc.evidenceIntegrity.verifyAnchor.useQuery(
    { engagementId: verifyEngagement },
    { enabled: !!verifyEngagement },
  );

  const bulkValidateMut = trpc.evidenceIntegrity.bulkValidate.useMutation({
    onSuccess: (data) => {
      toast.success(`Bulk validation: ${data.verified}/${data.total} verified, ${data.tampered} tampered`);
    },
    onError: (err) => toast.error(`Bulk validation failed: ${err.message}`),
  });

  // ─── Derived stats ───
  const stats = chainStats.data;
  const engagements = engagementsQuery.data || [];

  const overviewCards = useMemo(() => {
    if (!stats) return [];
    return [
      {
        title: "Evidence Items",
        value: stats.database.totalEvidenceItems,
        sub: `${stats.database.withIntegrityHash} hashed`,
        icon: Database,
        color: "text-blue-400",
        bgColor: "bg-blue-500/10",
      },
      {
        title: "Guardrail Checks",
        value: stats.guardrailAudit.totalChecks,
        sub: `${stats.guardrailAudit.passed} passed`,
        icon: ShieldCheck,
        color: "text-emerald-400",
        bgColor: "bg-emerald-500/10",
      },
      {
        title: "Failed Checks",
        value: stats.guardrailAudit.failed,
        sub: `${stats.guardrailAudit.quarantined} quarantined`,
        icon: ShieldAlert,
        color: stats.guardrailAudit.failed > 0 ? "text-red-400" : "text-muted-foreground",
        bgColor: stats.guardrailAudit.failed > 0 ? "bg-red-500/10" : "bg-muted/30",
      },
      {
        title: "Chain Envelopes",
        value: stats.inMemory.totalEnvelopes,
        sub: `${stats.inMemory.totalEngagements} engagements`,
        icon: Link2,
        color: "text-violet-400",
        bgColor: "bg-violet-500/10",
      },
    ];
  }, [stats]);

  return (
    <div className="space-y-6">
      {/* Header */}
      <div className="flex items-center justify-between">
        <div>
          <h1 className="text-2xl font-bold tracking-tight flex items-center gap-2">
            <Shield className="h-6 w-6 text-emerald-400" />
            Evidence Integrity
          </h1>
          <p className="text-sm text-muted-foreground mt-1">
            Chain-of-custody controls, hallucination guardrails, and cryptographic integrity verification
          </p>
        </div>
        <div className="flex items-center gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => { chainStats.refetch(); auditLog.refetch(); anchors.refetch(); }}
            disabled={chainStats.isRefetching}
          >
            <RefreshCw className={`h-4 w-4 mr-1 ${chainStats.isRefetching ? "animate-spin" : ""}`} />
            Refresh
          </Button>
        </div>
      </div>

      {/* Overview Cards */}
      <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
        {overviewCards.map((card) => {
          const Icon = card.icon;
          return (
            <Card key={card.title} className="border-border/50 bg-card/50">
              <CardContent className="p-4">
                <div className="flex items-center gap-3">
                  <div className={`p-2 rounded-lg ${card.bgColor}`}>
                    <Icon className={`h-5 w-5 ${card.color}`} />
                  </div>
                  <div>
                    <p className="text-2xl font-bold">{card.value}</p>
                    <p className="text-xs text-muted-foreground">{card.title}</p>
                    <p className="text-xs text-muted-foreground/70">{card.sub}</p>
                  </div>
                </div>
              </CardContent>
            </Card>
          );
        })}
      </div>

      {/* Tabs */}
      <Tabs value={activeTab} onValueChange={setActiveTab}>
        <TabsList className="bg-muted/30">
          <TabsTrigger value="overview" className="gap-1.5">
            <BarChart3 className="h-3.5 w-3.5" /> Overview
          </TabsTrigger>
          <TabsTrigger value="audit" className="gap-1.5">
            <Activity className="h-3.5 w-3.5" /> Audit Log
          </TabsTrigger>
          <TabsTrigger value="anchors" className="gap-1.5">
            <Anchor className="h-3.5 w-3.5" /> Anchors
          </TabsTrigger>
          <TabsTrigger value="validate" className="gap-1.5">
            <Fingerprint className="h-3.5 w-3.5" /> Validate
          </TabsTrigger>
          <TabsTrigger value="live" className="gap-1.5">
            <Activity className="h-3.5 w-3.5" /> Live Monitor
          </TabsTrigger>
        </TabsList>

        {/* ─── Overview Tab ─── */}
        <TabsContent value="overview" className="space-y-4 mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Integrity Health */}
            <Card className="border-border/50 bg-card/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <ShieldCheck className="h-4 w-4 text-emerald-400" />
                  Integrity Health
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                {stats ? (
                  <>
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-muted-foreground">Hash Coverage</span>
                      {scoreBar(stats.database.totalEvidenceItems > 0
                        ? stats.database.withIntegrityHash / stats.database.totalEvidenceItems
                        : 0)}
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-muted-foreground">Guardrail Pass Rate</span>
                      {scoreBar(stats.guardrailAudit.totalChecks > 0
                        ? stats.guardrailAudit.passed / stats.guardrailAudit.totalChecks
                        : 0)}
                    </div>
                    <div className="flex justify-between items-center">
                      <span className="text-sm text-muted-foreground">Quarantine Rate</span>
                      {scoreBar(stats.guardrailAudit.totalChecks > 0
                        ? 1 - (stats.guardrailAudit.quarantined / stats.guardrailAudit.totalChecks)
                        : 1)}
                    </div>
                    <div className="pt-2 border-t border-border/30">
                      <div className="grid grid-cols-2 gap-2 text-xs">
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">Without Hash:</span>
                          <span className={stats.database.withoutIntegrityHash > 0 ? "text-amber-400" : "text-emerald-400"}>
                            {stats.database.withoutIntegrityHash}
                          </span>
                        </div>
                        <div className="flex justify-between">
                          <span className="text-muted-foreground">In-Memory Chains:</span>
                          <span>{stats.inMemory.totalEngagements}</span>
                        </div>
                      </div>
                    </div>
                  </>
                ) : (
                  <div className="flex items-center justify-center py-6 text-muted-foreground">
                    <Loader2 className="h-4 w-4 animate-spin mr-2" /> Loading...
                  </div>
                )}
              </CardContent>
            </Card>

            {/* Guardrail Breakdown */}
            <Card className="border-border/50 bg-card/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <BarChart3 className="h-4 w-4 text-blue-400" />
                  Guardrail Breakdown
                </CardTitle>
              </CardHeader>
              <CardContent>
                {stats ? (
                  <div className="space-y-3">
                    {[
                      { label: "Accepted", value: stats.guardrailAudit.passed, color: "bg-emerald-500", textColor: "text-emerald-400" },
                      { label: "Failed", value: stats.guardrailAudit.failed, color: "bg-red-500", textColor: "text-red-400" },
                      { label: "Quarantined", value: stats.guardrailAudit.quarantined, color: "bg-red-600", textColor: "text-red-300" },
                    ].map((item) => {
                      const pct = stats.guardrailAudit.totalChecks > 0
                        ? (item.value / stats.guardrailAudit.totalChecks) * 100
                        : 0;
                      return (
                        <div key={item.label} className="space-y-1">
                          <div className="flex justify-between text-xs">
                            <span className="text-muted-foreground">{item.label}</span>
                            <span className={item.textColor}>{item.value} ({pct.toFixed(1)}%)</span>
                          </div>
                          <div className="h-1.5 bg-muted rounded-full overflow-hidden">
                            <div className={`h-full ${item.color} rounded-full transition-all`} style={{ width: `${pct}%` }} />
                          </div>
                        </div>
                      );
                    })}
                    <div className="pt-2 border-t border-border/30 text-xs text-muted-foreground text-center">
                      Total: {stats.guardrailAudit.totalChecks} checks across all engagements
                    </div>
                  </div>
                ) : (
                  <div className="flex items-center justify-center py-6 text-muted-foreground">
                    <Loader2 className="h-4 w-4 animate-spin mr-2" /> Loading...
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Chain Stats per Engagement */}
          {stats && stats.inMemory.totalEngagements > 0 && (
            <Card className="border-border/50 bg-card/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <Link2 className="h-4 w-4 text-violet-400" />
                  Active Evidence Chains (In-Memory)
                </CardTitle>
              </CardHeader>
              <CardContent>
                <div className="text-sm text-muted-foreground">
                  {stats.inMemory.totalEngagements} engagement(s) with {stats.inMemory.totalEnvelopes} total integrity envelopes tracked in memory.
                  These will be flushed to the database when engagements complete.
                </div>
              </CardContent>
            </Card>
          )}
        </TabsContent>

        {/* ─── Audit Log Tab ─── */}
        <TabsContent value="audit" className="space-y-4 mt-4">
          {/* Filters */}
          <Card className="border-border/50 bg-card/50">
            <CardContent className="p-4">
              <div className="flex flex-wrap gap-3 items-center">
                <div className="flex items-center gap-1.5">
                  <Filter className="h-3.5 w-3.5 text-muted-foreground" />
                  <span className="text-xs text-muted-foreground">Filters:</span>
                </div>
                <Select value={auditEngagement} onValueChange={(v) => { setAuditEngagement(v); setAuditPage(0); }}>
                  <SelectTrigger className="w-[180px] h-8 text-xs">
                    <SelectValue placeholder="All Engagements" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Engagements</SelectItem>
                    {engagements.map((e: any) => (
                      <SelectItem key={e.id} value={String(e.id)}>
                        {e.name || `Engagement #${e.id}`}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Select value={auditSpecialist} onValueChange={(v) => { setAuditSpecialist(v); setAuditPage(0); }}>
                  <SelectTrigger className="w-[160px] h-8 text-xs">
                    <SelectValue placeholder="All Specialists" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Specialists</SelectItem>
                    <SelectItem value="report-writer">Report Writer</SelectItem>
                    <SelectItem value="vuln-verifier">Vuln Verifier</SelectItem>
                    <SelectItem value="attack-planner">Attack Planner</SelectItem>
                    <SelectItem value="scan-analyst">Scan Analyst</SelectItem>
                    <SelectItem value="generic">Generic</SelectItem>
                  </SelectContent>
                </Select>
                <Select value={auditRecommendation} onValueChange={(v) => { setAuditRecommendation(v); setAuditPage(0); }}>
                  <SelectTrigger className="w-[140px] h-8 text-xs">
                    <SelectValue placeholder="All Results" />
                  </SelectTrigger>
                  <SelectContent>
                    <SelectItem value="all">All Results</SelectItem>
                    <SelectItem value="accept">Accepted</SelectItem>
                    <SelectItem value="review">Review</SelectItem>
                    <SelectItem value="reject">Rejected</SelectItem>
                    <SelectItem value="quarantine">Quarantined</SelectItem>
                  </SelectContent>
                </Select>
              </div>
            </CardContent>
          </Card>

          {/* Audit Table */}
          <Card className="border-border/50 bg-card/50">
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-border/30 text-muted-foreground">
                      <th className="text-left p-3 font-medium">Time</th>
                      <th className="text-left p-3 font-medium">Engagement</th>
                      <th className="text-left p-3 font-medium">Specialist</th>
                      <th className="text-left p-3 font-medium">Check</th>
                      <th className="text-left p-3 font-medium">Score</th>
                      <th className="text-left p-3 font-medium">Result</th>
                      <th className="text-left p-3 font-medium">Grounded</th>
                      <th className="text-left p-3 font-medium">Ungrounded</th>
                      <th className="text-left p-3 font-medium">Hash</th>
                      <th className="text-left p-3 font-medium">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {auditLog.isLoading ? (
                      <tr>
                        <td colSpan={10} className="p-8 text-center text-muted-foreground">
                          <Loader2 className="h-4 w-4 animate-spin inline mr-2" /> Loading audit log...
                        </td>
                      </tr>
                    ) : auditLog.data?.items.length === 0 ? (
                      <tr>
                        <td colSpan={10} className="p-8 text-center text-muted-foreground">
                          <Shield className="h-8 w-8 mx-auto mb-2 opacity-30" />
                          No guardrail checks recorded yet. Evidence integrity checks will appear here as engagements run.
                        </td>
                      </tr>
                    ) : (
                      auditLog.data?.items.map((item: any) => (
                        <tr key={item.id} className="border-b border-border/20 hover:bg-muted/20 transition-colors">
                          <td className="p-3 font-mono text-muted-foreground whitespace-nowrap">
                            {new Date(item.createdAt).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                          </td>
                          <td className="p-3">
                            <Badge variant="outline" className="text-xs font-mono">
                              #{item.engagementId}
                            </Badge>
                          </td>
                          <td className="p-3">
                            <Badge variant="outline" className="bg-blue-500/10 text-blue-400 border-blue-500/30 text-xs">
                              {item.specialist}
                            </Badge>
                          </td>
                          <td className="p-3 text-muted-foreground">{item.checkType}</td>
                          <td className="p-3">{scoreBar(item.score / 100)}</td>
                          <td className="p-3">{recommendationBadge(item.recommendation)}</td>
                          <td className="p-3 text-center">
                            <span className="text-emerald-400 font-mono">{item.groundedClaimsCount}</span>
                          </td>
                          <td className="p-3 text-center">
                            <span className={item.ungroundedClaimsCount > 0 ? "text-red-400 font-mono" : "text-muted-foreground font-mono"}>
                              {item.ungroundedClaimsCount}
                            </span>
                            {item.criticalIssues > 0 && (
                              <Badge variant="outline" className="ml-1 bg-red-600/20 text-red-300 border-red-600/40 text-[10px]">
                                {item.criticalIssues} crit
                              </Badge>
                            )}
                          </td>
                          <td className="p-3 font-mono text-muted-foreground text-[10px]">
                            {truncHash(item.contentHash, 10)}
                          </td>
                          <td className="p-3">
                            <Button
                              variant="ghost"
                              size="sm"
                              className="h-6 px-2 text-xs"
                              onClick={() => setSelectedAuditItem(item)}
                            >
                              <Eye className="h-3 w-3 mr-1" /> Detail
                            </Button>
                          </td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
              {/* Pagination */}
              {auditLog.data && auditLog.data.total > PAGE_SIZE && (
                <div className="flex items-center justify-between p-3 border-t border-border/30">
                  <span className="text-xs text-muted-foreground">
                    Showing {auditPage * PAGE_SIZE + 1}-{Math.min((auditPage + 1) * PAGE_SIZE, auditLog.data.total)} of {auditLog.data.total}
                  </span>
                  <div className="flex gap-1">
                    <Button variant="ghost" size="sm" className="h-7" disabled={auditPage === 0} onClick={() => setAuditPage(p => p - 1)}>
                      <ChevronLeft className="h-3.5 w-3.5" />
                    </Button>
                    <Button variant="ghost" size="sm" className="h-7" disabled={(auditPage + 1) * PAGE_SIZE >= auditLog.data.total} onClick={() => setAuditPage(p => p + 1)}>
                      <ChevronRight className="h-3.5 w-3.5" />
                    </Button>
                  </div>
                </div>
              )}
            </CardContent>
          </Card>
        </TabsContent>

        {/* ─── Anchors Tab ─── */}
        <TabsContent value="anchors" className="space-y-4 mt-4">
          <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
            {/* Create Anchor */}
            <Card className="border-border/50 bg-card/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <Anchor className="h-4 w-4 text-emerald-400" />
                  Create Merkle Root Anchor
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-xs text-muted-foreground">
                  Seal the evidence chain for an engagement by computing a Merkle root hash over all integrity envelopes.
                  This creates a cryptographic proof that the evidence chain was intact at anchor time.
                </p>
                <Select value={anchorEngagement} onValueChange={setAnchorEngagement}>
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue placeholder="Select engagement..." />
                  </SelectTrigger>
                  <SelectContent>
                    {engagements.map((e: any) => (
                      <SelectItem key={e.id} value={String(e.id)}>
                        {e.name || `Engagement #${e.id}`}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Button
                  size="sm"
                  className="w-full"
                  disabled={!anchorEngagement || createAnchorMut.isPending}
                  onClick={() => {
                    if (anchorEngagement) {
                      createAnchorMut.mutate({ engagementId: anchorEngagement, notes: "Manual anchor via Evidence Integrity dashboard" });
                    }
                  }}
                >
                  {createAnchorMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin mr-1" /> : <Lock className="h-3.5 w-3.5 mr-1" />}
                  Create Anchor
                </Button>
              </CardContent>
            </Card>

            {/* Verify Anchor */}
            <Card className="border-border/50 bg-card/50">
              <CardHeader className="pb-3">
                <CardTitle className="text-sm font-medium flex items-center gap-2">
                  <Fingerprint className="h-4 w-4 text-blue-400" />
                  Verify Anchor Integrity
                </CardTitle>
              </CardHeader>
              <CardContent className="space-y-3">
                <p className="text-xs text-muted-foreground">
                  Verify that the evidence chain for an engagement has not been tampered with since the anchor was created.
                </p>
                <Select value={verifyEngagement} onValueChange={setVerifyEngagement}>
                  <SelectTrigger className="h-8 text-xs">
                    <SelectValue placeholder="Select engagement..." />
                  </SelectTrigger>
                  <SelectContent>
                    {engagements.map((e: any) => (
                      <SelectItem key={e.id} value={String(e.id)}>
                        {e.name || `Engagement #${e.id}`}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                {verifyEngagement && verifyAnchorQuery.data && (
                  <div className={`p-3 rounded-lg border text-xs ${
                    verifyAnchorQuery.data.hasAnchor
                      ? verifyAnchorQuery.data.valid
                        ? "bg-emerald-500/10 border-emerald-500/30"
                        : "bg-red-500/10 border-red-500/30"
                      : "bg-muted/30 border-border/30"
                  }`}>
                    {!verifyAnchorQuery.data.hasAnchor ? (
                      <div className="flex items-center gap-2 text-muted-foreground">
                        <Unlock className="h-4 w-4" />
                        No anchor found for this engagement
                      </div>
                    ) : verifyAnchorQuery.data.valid ? (
                      <div className="space-y-1">
                        <div className="flex items-center gap-2 text-emerald-400 font-medium">
                          <ShieldCheck className="h-4 w-4" />
                          Chain Integrity Verified
                        </div>
                        <div className="text-muted-foreground font-mono">
                          Root: {truncHash(verifyAnchorQuery.data.anchor?.merkleRoot || "", 20)}
                        </div>
                        <div className="text-muted-foreground">
                          Chain length: {verifyAnchorQuery.data.anchor?.chainLength} | Anchored by: {verifyAnchorQuery.data.anchor?.anchoredBy}
                        </div>
                      </div>
                    ) : (
                      <div className="space-y-1">
                        <div className="flex items-center gap-2 text-red-400 font-medium">
                          <ShieldX className="h-4 w-4" />
                          Chain Integrity FAILED
                        </div>
                        <div className="text-red-300">{verifyAnchorQuery.data.error}</div>
                      </div>
                    )}
                  </div>
                )}
              </CardContent>
            </Card>
          </div>

          {/* Anchor History */}
          <Card className="border-border/50 bg-card/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Clock className="h-4 w-4 text-muted-foreground" />
                Anchor History
              </CardTitle>
            </CardHeader>
            <CardContent className="p-0">
              <div className="overflow-x-auto">
                <table className="w-full text-xs">
                  <thead>
                    <tr className="border-b border-border/30 text-muted-foreground">
                      <th className="text-left p-3 font-medium">Engagement</th>
                      <th className="text-left p-3 font-medium">Merkle Root</th>
                      <th className="text-left p-3 font-medium">Chain Length</th>
                      <th className="text-left p-3 font-medium">Status</th>
                      <th className="text-left p-3 font-medium">Anchored By</th>
                      <th className="text-left p-3 font-medium">Anchored At</th>
                      <th className="text-left p-3 font-medium">Notes</th>
                    </tr>
                  </thead>
                  <tbody>
                    {anchors.isLoading ? (
                      <tr>
                        <td colSpan={7} className="p-8 text-center text-muted-foreground">
                          <Loader2 className="h-4 w-4 animate-spin inline mr-2" /> Loading...
                        </td>
                      </tr>
                    ) : !anchors.data || anchors.data.length === 0 ? (
                      <tr>
                        <td colSpan={7} className="p-8 text-center text-muted-foreground">
                          <Anchor className="h-8 w-8 mx-auto mb-2 opacity-30" />
                          No anchors created yet. Create one above to seal an evidence chain.
                        </td>
                      </tr>
                    ) : (
                      anchors.data.map((anchor: any) => (
                        <tr key={anchor.id} className="border-b border-border/20 hover:bg-muted/20 transition-colors">
                          <td className="p-3">
                            <Badge variant="outline" className="text-xs font-mono">#{anchor.engagementId}</Badge>
                          </td>
                          <td className="p-3 font-mono text-[10px] text-emerald-400">
                            {truncHash(anchor.merkleRoot, 20)}
                          </td>
                          <td className="p-3 font-mono">{anchor.chainLength}</td>
                          <td className="p-3">
                            <Badge variant="outline" className={
                              anchor.status === "active"
                                ? "bg-emerald-500/15 text-emerald-400 border-emerald-500/30"
                                : "bg-muted/30 text-muted-foreground border-border/30"
                            }>
                              {anchor.status === "active" ? <Lock className="h-3 w-3 mr-1" /> : <Unlock className="h-3 w-3 mr-1" />}
                              {anchor.status}
                            </Badge>
                          </td>
                          <td className="p-3 text-muted-foreground">{anchor.anchoredBy}</td>
                          <td className="p-3 text-muted-foreground font-mono whitespace-nowrap">
                            {new Date(anchor.anchoredAt).toLocaleString(undefined, { month: 'short', day: 'numeric', hour: '2-digit', minute: '2-digit' })}
                          </td>
                          <td className="p-3 text-muted-foreground max-w-[200px] truncate">{anchor.notes || "—"}</td>
                        </tr>
                      ))
                    )}
                  </tbody>
                </table>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ─── Validate Tab ─── */}
        <TabsContent value="validate" className="space-y-4 mt-4">
          <Card className="border-border/50 bg-card/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Fingerprint className="h-4 w-4 text-violet-400" />
                Bulk Evidence Validation
              </CardTitle>
            </CardHeader>
            <CardContent className="space-y-3">
              <p className="text-xs text-muted-foreground">
                Validate all evidence items for an engagement by checking SHA-256 hash integrity.
                This detects any evidence that may have been tampered with after collection.
              </p>
              <div className="flex gap-2">
                <Select value={anchorEngagement} onValueChange={setAnchorEngagement}>
                  <SelectTrigger className="h-8 text-xs flex-1">
                    <SelectValue placeholder="Select engagement..." />
                  </SelectTrigger>
                  <SelectContent>
                    {engagements.map((e: any) => (
                      <SelectItem key={e.id} value={String(e.id)}>
                        {e.name || `Engagement #${e.id}`}
                      </SelectItem>
                    ))}
                  </SelectContent>
                </Select>
                <Button
                  size="sm"
                  variant="outline"
                  disabled={!anchorEngagement || bulkValidateMut.isPending}
                  onClick={() => {
                    if (anchorEngagement) {
                      bulkValidateMut.mutate({ engagementId: anchorEngagement });
                    }
                  }}
                >
                  {bulkValidateMut.isPending ? <Loader2 className="h-3.5 w-3.5 animate-spin mr-1" /> : <Search className="h-3.5 w-3.5 mr-1" />}
                  Validate
                </Button>
              </div>
              {bulkValidateMut.data && (
                <div className="p-3 rounded-lg border border-border/30 bg-muted/20 space-y-2">
                  <div className="grid grid-cols-2 sm:grid-cols-4 gap-3 text-xs">
                    <div className="text-center">
                      <p className="text-lg font-bold">{bulkValidateMut.data.total}</p>
                      <p className="text-muted-foreground">Total Items</p>
                    </div>
                    <div className="text-center">
                      <p className="text-lg font-bold text-emerald-400">{bulkValidateMut.data.verified}</p>
                      <p className="text-muted-foreground">Verified</p>
                    </div>
                    <div className="text-center">
                      <p className="text-lg font-bold text-amber-400">{bulkValidateMut.data.withoutHash}</p>
                      <p className="text-muted-foreground">No Hash</p>
                    </div>
                    <div className="text-center">
                      <p className={`text-lg font-bold ${bulkValidateMut.data.tampered > 0 ? "text-red-400" : "text-muted-foreground"}`}>
                        {bulkValidateMut.data.tampered}
                      </p>
                      <p className="text-muted-foreground">Tampered</p>
                    </div>
                  </div>
                  {bulkValidateMut.data.errors.length > 0 && (
                    <div className="pt-2 border-t border-border/30">
                      <p className="text-xs text-red-400 font-medium mb-1">Errors:</p>
                      {bulkValidateMut.data.errors.map((err: string, i: number) => (
                        <p key={i} className="text-[10px] text-red-300 font-mono">{err}</p>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </CardContent>
          </Card>

          {/* Chain Verification */}
          <Card className="border-border/50 bg-card/50">
            <CardHeader className="pb-3">
              <CardTitle className="text-sm font-medium flex items-center gap-2">
                <Link2 className="h-4 w-4 text-blue-400" />
                Chain Verification
              </CardTitle>
            </CardHeader>
            <CardContent>
              <p className="text-xs text-muted-foreground mb-3">
                Verify the in-memory hash chain for an engagement. Each evidence envelope is linked to the previous one via SHA-256 chain hashes.
                A break in the chain indicates evidence was inserted, deleted, or modified after initial capture.
              </p>
              <div className="p-3 rounded-lg border border-border/30 bg-muted/10 text-xs text-muted-foreground">
                <div className="flex items-center gap-2 mb-2">
                  <Hash className="h-4 w-4" />
                  <span className="font-medium">How it works:</span>
                </div>
                <ol className="list-decimal list-inside space-y-1 ml-1">
                  <li>Each evidence artifact gets a SHA-256 content hash at capture time</li>
                  <li>Artifacts are chained: each envelope's chain hash includes the previous envelope's hash</li>
                  <li>A Merkle root is computed over all chain hashes and HMAC-signed</li>
                  <li>Verification recomputes the chain and compares against the stored anchor</li>
                  <li>Any discrepancy indicates tampering or data loss</li>
                </ol>
              </div>
            </CardContent>
          </Card>
        </TabsContent>

        {/* ─── Live Monitor Tab ─── */}
        <TabsContent value="live" className="space-y-4 mt-4">
          <LiveMonitorPanel />
        </TabsContent>
      </Tabs>

      {/* ─── Audit Detail Dialog ─── */}
      <Dialog open={!!selectedAuditItem} onOpenChange={(open) => !open && setSelectedAuditItem(null)}>
        <DialogContent className="max-w-2xl max-h-[80vh] overflow-y-auto">
          <DialogHeader>
            <DialogTitle className="flex items-center gap-2">
              <Shield className="h-5 w-5 text-emerald-400" />
              Guardrail Check Detail
            </DialogTitle>
            <DialogDescription>
              Detailed breakdown of hallucination detection and evidence validation
            </DialogDescription>
          </DialogHeader>
          {selectedAuditItem && (
            <div className="space-y-4 text-sm">
              {/* Summary */}
              <div className="grid grid-cols-2 gap-3">
                <div>
                  <span className="text-xs text-muted-foreground">Engagement</span>
                  <p className="font-mono">#{selectedAuditItem.engagementId}</p>
                </div>
                <div>
                  <span className="text-xs text-muted-foreground">Specialist</span>
                  <p>{selectedAuditItem.specialist}</p>
                </div>
                <div>
                  <span className="text-xs text-muted-foreground">Score</span>
                  <div className="mt-1">{scoreBar(selectedAuditItem.score / 100)}</div>
                </div>
                <div>
                  <span className="text-xs text-muted-foreground">Recommendation</span>
                  <div className="mt-1">{recommendationBadge(selectedAuditItem.recommendation)}</div>
                </div>
                <div>
                  <span className="text-xs text-muted-foreground">Content Hash</span>
                  <p className="font-mono text-xs break-all">{selectedAuditItem.contentHash}</p>
                </div>
                <div>
                  <span className="text-xs text-muted-foreground">Sanitized</span>
                  <p>{selectedAuditItem.wasSanitized ? "Yes" : "No"}</p>
                </div>
              </div>

              {/* Grounded Claims */}
              {selectedAuditItem.details?.grounded?.length > 0 && (
                <div>
                  <h4 className="text-xs font-medium text-emerald-400 mb-2 flex items-center gap-1">
                    <CheckCircle2 className="h-3.5 w-3.5" /> Grounded Claims ({selectedAuditItem.details.grounded.length})
                  </h4>
                  <div className="space-y-1 max-h-[150px] overflow-y-auto">
                    {selectedAuditItem.details.grounded.map((claim: any, i: number) => (
                      <div key={i} className="text-xs bg-emerald-500/5 border border-emerald-500/20 rounded p-2">
                        <span className="text-emerald-400 font-mono">[{claim.type}]</span>{" "}
                        <span className="text-muted-foreground">{claim.claim}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Ungrounded Claims */}
              {selectedAuditItem.details?.ungrounded?.length > 0 && (
                <div>
                  <h4 className="text-xs font-medium text-red-400 mb-2 flex items-center gap-1">
                    <AlertTriangle className="h-3.5 w-3.5" /> Ungrounded Claims ({selectedAuditItem.details.ungrounded.length})
                  </h4>
                  <div className="space-y-1 max-h-[150px] overflow-y-auto">
                    {selectedAuditItem.details.ungrounded.map((claim: any, i: number) => (
                      <div key={i} className={`text-xs rounded p-2 border ${
                        claim.severity === "critical"
                          ? "bg-red-600/10 border-red-600/30"
                          : claim.severity === "high"
                            ? "bg-red-500/10 border-red-500/20"
                            : "bg-amber-500/10 border-amber-500/20"
                      }`}>
                        <div className="flex items-center gap-1 mb-0.5">
                          <Badge variant="outline" className={`text-[10px] ${
                            claim.severity === "critical" ? "text-red-300 border-red-600/40" : "text-amber-400 border-amber-500/30"
                          }`}>
                            {claim.severity}
                          </Badge>
                          <span className="font-mono text-muted-foreground">[{claim.type}]</span>
                        </div>
                        <span className="text-muted-foreground">{claim.claim}</span>
                      </div>
                    ))}
                  </div>
                </div>
              )}

              {/* Warnings */}
              {selectedAuditItem.details?.warnings?.length > 0 && (
                <div>
                  <h4 className="text-xs font-medium text-amber-400 mb-2 flex items-center gap-1">
                    <AlertTriangle className="h-3.5 w-3.5" /> Warnings ({selectedAuditItem.details.warnings.length})
                  </h4>
                  <div className="space-y-1 max-h-[100px] overflow-y-auto">
                    {selectedAuditItem.details.warnings.map((w: string, i: number) => (
                      <p key={i} className="text-xs text-amber-300/80 bg-amber-500/5 border border-amber-500/20 rounded p-1.5">{w}</p>
                    ))}
                  </div>
                </div>
              )}

              {/* Errors */}
              {selectedAuditItem.details?.errors?.length > 0 && (
                <div>
                  <h4 className="text-xs font-medium text-red-400 mb-2 flex items-center gap-1">
                    <XCircle className="h-3.5 w-3.5" /> Errors ({selectedAuditItem.details.errors.length})
                  </h4>
                  <div className="space-y-1">
                    {selectedAuditItem.details.errors.map((e: string, i: number) => (
                      <p key={i} className="text-xs text-red-300 bg-red-500/5 border border-red-500/20 rounded p-1.5">{e}</p>
                    ))}
                  </div>
                </div>
              )}
            </div>
          )}
        </DialogContent>
      </Dialog>
    </div>
  );
}
