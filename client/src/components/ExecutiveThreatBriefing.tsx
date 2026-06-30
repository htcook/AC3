import { trpc } from "@/lib/trpc";
import { useState, useMemo } from "react";
import { Button } from "@/components/ui/button";
import { Card, CardContent, CardHeader, CardTitle } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Tooltip, TooltipContent, TooltipProvider, TooltipTrigger } from "@/components/ui/tooltip";
import { Input } from "@/components/ui/input";
import { useToast } from "@/hooks/use-toast";
import {
  Shield, ShieldAlert, Target, Globe, Brain, TrendingUp, TrendingDown,
  Minus, ChevronDown, ChevronRight, AlertTriangle, Crosshair, Eye,
  RefreshCw, BarChart3, Activity, Loader2, Zap, ArrowUpRight,
  FileText, Download, Bell, BellOff, BellRing, Trash2, Plus,
  AlertCircle, Fingerprint, Wifi, Link2
} from "lucide-react";
import {
  AreaChart, Area, BarChart, Bar, XAxis, YAxis, CartesianGrid,
  ResponsiveContainer, Tooltip as RechartsTooltip, Legend
} from "recharts";
import { Link } from "wouter";

// ─── Threat Level Colors ──────────────────────────────────────────────────────
const THREAT_COLORS: Record<string, string> = {
  critical: "text-red-400 bg-red-500/10 border-red-500/30",
  high: "text-orange-400 bg-orange-500/10 border-orange-500/30",
  elevated: "text-amber-400 bg-amber-500/10 border-amber-500/30",
  moderate: "text-blue-400 bg-blue-500/10 border-blue-500/30",
  low: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
  unknown: "text-zinc-400 bg-zinc-500/10 border-zinc-500/30",
};

const THREAT_BADGE: Record<string, string> = {
  critical: "bg-red-500/20 text-red-300 border-red-500/40",
  high: "bg-orange-500/20 text-orange-300 border-orange-500/40",
  medium: "bg-amber-500/20 text-amber-300 border-amber-500/40",
  low: "bg-emerald-500/20 text-emerald-300 border-emerald-500/40",
};

const TREND_ICON = {
  rising: <TrendingUp className="w-3.5 h-3.5 text-red-400" />,
  stable: <Minus className="w-3.5 h-3.5 text-zinc-400" />,
  declining: <TrendingDown className="w-3.5 h-3.5 text-emerald-400" />,
};

const IOC_TYPE_ICON: Record<string, typeof Wifi> = {
  ip: Wifi,
  domain: Globe,
  url: Link2,
  subdomain: Globe,
};

// ─── Relevance Score Bar ──────────────────────────────────────────────────────
function RelevanceBar({ score }: { score: number }) {
  const color = score >= 80 ? "bg-red-500" : score >= 60 ? "bg-orange-500" : score >= 40 ? "bg-amber-500" : "bg-blue-500";
  return (
    <div className="flex items-center gap-2 min-w-[120px]">
      <div className="flex-1 h-2 bg-zinc-800 rounded-full overflow-hidden">
        <div className={`h-full rounded-full ${color} transition-all`} style={{ width: `${score}%` }} />
      </div>
      <span className="text-xs font-mono text-zinc-400 w-8 text-right">{score}</span>
    </div>
  );
}

// ─── CARVER Radar (simple bar display) ────────────────────────────────────────
function CarverProfile({ profile }: { profile: any }) {
  if (!profile) return null;
  const dimensions = [
    { key: "avgCriticality", label: "Criticality", color: "bg-red-500" },
    { key: "avgAccessibility", label: "Accessibility", color: "bg-orange-500" },
    { key: "avgRecuperability", label: "Recuperability", color: "bg-amber-500" },
    { key: "avgVulnerability", label: "Vulnerability", color: "bg-yellow-500" },
    { key: "avgEffect", label: "Effect", color: "bg-blue-500" },
    { key: "avgRecognizability", label: "Recognizability", color: "bg-purple-500" },
  ];
  return (
    <div className="space-y-2">
      <h4 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">CARVER Profile</h4>
      {dimensions.map(d => (
        <div key={d.key} className="flex items-center gap-2">
          <span className="text-xs text-zinc-500 w-28 truncate">{d.label}</span>
          <div className="flex-1 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
            <div className={`h-full rounded-full ${d.color}`} style={{ width: `${Math.min(100, (profile[d.key] / 10) * 100)}%` }} />
          </div>
          <span className="text-xs font-mono text-zinc-500 w-8 text-right">{profile[d.key]?.toFixed(1)}</span>
        </div>
      ))}
    </div>
  );
}

// ─── Threat Likelihood Bars ───────────────────────────────────────────────────
function ThreatLikelihoods({ likelihoods }: { likelihoods: Array<{ threat: string; likelihood: number }> }) {
  if (!likelihoods?.length) return null;
  return (
    <div className="space-y-2">
      <h4 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider">Threat Likelihood</h4>
      {likelihoods.map(t => (
        <div key={t.threat} className="flex items-center gap-2">
          <span className="text-xs text-zinc-500 w-36 truncate">{t.threat}</span>
          <div className="flex-1 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
            <div className="h-full rounded-full bg-red-500/70" style={{ width: `${t.likelihood * 100}%` }} />
          </div>
          <span className="text-xs font-mono text-zinc-500 w-10 text-right">{(t.likelihood * 100).toFixed(0)}%</span>
        </div>
      ))}
    </div>
  );
}

// ─── IOC Overlap Alert Panel ─────────────────────────────────────────────────
function IocOverlapPanel({ iocOverlap }: { iocOverlap: any }) {
  const [expanded, setExpanded] = useState(false);
  if (!iocOverlap || iocOverlap.totalMatches === 0) return null;

  return (
    <Card className="bg-red-950/30 border-red-500/30">
      <CardContent className="p-3">
        <button
          className="w-full text-left flex items-center justify-between"
          onClick={() => setExpanded(!expanded)}
        >
          <div className="flex items-center gap-2">
            <div className="p-1.5 rounded-md bg-red-500/20 border border-red-500/40">
              <Fingerprint className="w-4 h-4 text-red-400" />
            </div>
            <div>
              <div className="text-sm font-bold text-red-300">
                {iocOverlap.totalMatches} Active IOC Overlaps Detected
              </div>
              <div className="text-[10px] text-red-400/70">
                {iocOverlap.assetExposure.assetsWithIocHits} of {iocOverlap.assetExposure.totalAssetsChecked} assets affected
                · {iocOverlap.assetExposure.uniqueActorsMatched} threat actors linked
              </div>
            </div>
          </div>
          {expanded ? <ChevronDown className="w-4 h-4 text-red-400" /> : <ChevronRight className="w-4 h-4 text-red-400" />}
        </button>

        {expanded && (
          <div className="mt-3 space-y-1.5 max-h-[300px] overflow-y-auto">
            <div className="grid grid-cols-[auto_1fr_1fr_auto_auto] gap-x-3 gap-y-1 text-[10px]">
              <div className="text-zinc-500 font-semibold uppercase">Type</div>
              <div className="text-zinc-500 font-semibold uppercase">IOC Value</div>
              <div className="text-zinc-500 font-semibold uppercase">Matched Asset</div>
              <div className="text-zinc-500 font-semibold uppercase">Match</div>
              <div className="text-zinc-500 font-semibold uppercase">Conf.</div>
              {iocOverlap.compromiseIndicators.map((m: any, i: number) => {
                const Icon = IOC_TYPE_ICON[m.matchType] || AlertCircle;
                return (
                  <>
                    <div key={`type-${i}`} className="flex items-center gap-1 text-red-300">
                      <Icon className="w-3 h-3" />
                      {m.iocType}
                    </div>
                    <div key={`val-${i}`} className="font-mono text-zinc-300 truncate">{m.iocValue}</div>
                    <div key={`asset-${i}`} className="font-mono text-zinc-400 truncate">{m.matchedAsset}</div>
                    <Badge key={`match-${i}`} variant="outline" className="text-[9px] px-1 py-0 border-red-500/40 text-red-300">
                      {m.matchType}
                    </Badge>
                    <Badge key={`conf-${i}`} variant="outline" className={`text-[9px] px-1 py-0 ${
                      m.confidence === "high" ? "border-red-500/40 text-red-300" :
                      m.confidence === "medium" ? "border-orange-500/40 text-orange-300" :
                      "border-zinc-700 text-zinc-400"
                    }`}>
                      {m.confidence || "med"}
                    </Badge>
                  </>
                );
              })}
            </div>
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Alert Threshold Manager ─────────────────────────────────────────────────
function AlertThresholdManager({ scanId }: { scanId?: number }) {
  const [showForm, setShowForm] = useState(false);
  const [label, setLabel] = useState("Default Alert");
  const [threshold, setThreshold] = useState(80);
  const [threatFilter, setThreatFilter] = useState<"any" | "critical" | "high" | "medium">("any");
  const [editId, setEditId] = useState<number | undefined>();
  const { toast } = useToast();

  const { data: thresholds, refetch } = trpc.executiveDashboard.alertThresholds.useQuery(undefined, { staleTime: 30_000 });
  const { data: alertHistory } = trpc.executiveDashboard.alertHistory.useQuery({ limit: 20 }, { staleTime: 30_000 });

  const upsertMutation = trpc.executiveDashboard.upsertAlertThreshold.useMutation({
    onSuccess: () => {
      refetch();
      setShowForm(false);
      setEditId(undefined);
      toast({ title: "Alert threshold saved" });
    },
  });

  const deleteMutation = trpc.executiveDashboard.deleteAlertThreshold.useMutation({
    onSuccess: () => {
      refetch();
      toast({ title: "Alert threshold deleted" });
    },
  });

  return (
    <Card className="bg-zinc-900/60 border-zinc-800">
      <CardContent className="p-3 space-y-3">
        <div className="flex items-center justify-between">
          <h4 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider flex items-center gap-1.5">
            <BellRing className="w-3.5 h-3.5" />
            Alert Thresholds
          </h4>
          <Button
            variant="ghost"
            size="sm"
            className="h-6 px-2 text-xs text-zinc-400 hover:text-zinc-200"
            onClick={() => { setShowForm(!showForm); setEditId(undefined); setLabel("Default Alert"); setThreshold(80); setThreatFilter("any"); }}
          >
            <Plus className="w-3 h-3 mr-1" />
            Add
          </Button>
        </div>

        {/* Active Thresholds */}
        {thresholds && thresholds.length > 0 && (
          <div className="space-y-1.5">
            {thresholds.map((t: any) => (
              <div key={t.id} className="flex items-center justify-between text-xs bg-zinc-800/50 rounded-md px-2 py-1.5">
                <div className="flex items-center gap-2">
                  {t.enabled ? <Bell className="w-3 h-3 text-amber-400" /> : <BellOff className="w-3 h-3 text-zinc-600" />}
                  <span className={t.enabled ? "text-zinc-300" : "text-zinc-600"}>{t.label}</span>
                  <Badge variant="outline" className="text-[9px] px-1 py-0 border-zinc-700 text-zinc-500">
                    &ge;{t.relevanceThreshold}
                  </Badge>
                  {t.threatLevelFilter !== "any" && (
                    <Badge variant="outline" className="text-[9px] px-1 py-0 border-zinc-700 text-zinc-500">
                      {t.threatLevelFilter}+
                    </Badge>
                  )}
                </div>
                <div className="flex items-center gap-1">
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-5 w-5 p-0 text-zinc-500 hover:text-zinc-300"
                    onClick={() => {
                      setEditId(t.id);
                      setLabel(t.label);
                      setThreshold(t.relevanceThreshold);
                      setThreatFilter(t.threatLevelFilter || "any");
                      setShowForm(true);
                    }}
                  >
                    <Eye className="w-3 h-3" />
                  </Button>
                  <Button
                    variant="ghost"
                    size="sm"
                    className="h-5 w-5 p-0 text-zinc-500 hover:text-red-400"
                    onClick={() => deleteMutation.mutate({ id: t.id })}
                  >
                    <Trash2 className="w-3 h-3" />
                  </Button>
                </div>
              </div>
            ))}
          </div>
        )}

        {/* Add/Edit Form */}
        {showForm && (
          <div className="space-y-2 border border-zinc-700 rounded-md p-2">
            <Input
              value={label}
              onChange={(e) => setLabel(e.target.value)}
              placeholder="Alert label"
              className="h-7 text-xs bg-zinc-800 border-zinc-700"
            />
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-zinc-500 w-20">Threshold:</span>
              <input
                type="range"
                min={0}
                max={100}
                value={threshold}
                onChange={(e) => setThreshold(Number(e.target.value))}
                className="flex-1 h-1.5 accent-red-500"
              />
              <span className="text-xs font-mono text-zinc-400 w-8">{threshold}</span>
            </div>
            <div className="flex items-center gap-2">
              <span className="text-[10px] text-zinc-500 w-20">Min Level:</span>
              <select
                value={threatFilter}
                onChange={(e) => setThreatFilter(e.target.value as any)}
                className="bg-zinc-800 border border-zinc-700 rounded px-2 py-0.5 text-xs text-zinc-300"
              >
                <option value="any">Any</option>
                <option value="critical">Critical</option>
                <option value="high">High+</option>
                <option value="medium">Medium+</option>
              </select>
            </div>
            <div className="flex items-center gap-2">
              <Button
                size="sm"
                className="h-6 px-3 text-xs"
                disabled={upsertMutation.isPending}
                onClick={() => upsertMutation.mutate({
                  id: editId,
                  scanId: scanId || null,
                  label,
                  relevanceThreshold: threshold,
                  threatLevelFilter: threatFilter,
                  enabled: true,
                  notifyOnNew: true,
                  notifyOnRising: true,
                })}
              >
                {upsertMutation.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : "Save"}
              </Button>
              <Button variant="ghost" size="sm" className="h-6 px-3 text-xs" onClick={() => setShowForm(false)}>
                Cancel
              </Button>
            </div>
          </div>
        )}

        {/* Recent Alert History */}
        {alertHistory && alertHistory.length > 0 && (
          <div className="space-y-1">
            <div className="text-[10px] text-zinc-600 uppercase tracking-wider">Recent Alerts</div>
            {alertHistory.slice(0, 5).map((a: any) => (
              <div key={a.id} className="flex items-center gap-2 text-[10px] text-zinc-500">
                {a.notificationSent ? <Bell className="w-2.5 h-2.5 text-amber-400" /> : <BellOff className="w-2.5 h-2.5 text-zinc-600" />}
                <span className="text-zinc-300 font-medium">{a.actorName}</span>
                <span>score {a.relevanceScore}</span>
                <span className="text-zinc-600">·</span>
                <span className="truncate">{a.triggerReason}</span>
              </div>
            ))}
          </div>
        )}

        {(!thresholds || thresholds.length === 0) && !showForm && (
          <div className="text-center py-2 text-[10px] text-zinc-600">
            No alert thresholds configured. Click "Add" to set up notifications.
          </div>
        )}
      </CardContent>
    </Card>
  );
}

// ─── Actor Card ───────────────────────────────────────────────────────────────
function ActorCard({ actor, rank }: { actor: any; rank: number }) {
  const [expanded, setExpanded] = useState(false);
  const hasIocOverlap = actor.recommendedActions?.some((a: string) => a.includes("IOC overlap"));
  return (
    <div className={`border rounded-lg bg-zinc-900/50 hover:bg-zinc-900/80 transition-colors ${hasIocOverlap ? "border-red-500/40" : "border-zinc-800"}`}>
      <button
        className="w-full text-left p-3 flex items-start gap-3"
        onClick={() => setExpanded(!expanded)}
      >
        <div className={`flex-shrink-0 w-7 h-7 rounded-full flex items-center justify-center text-xs font-bold ${hasIocOverlap ? "bg-red-500/20 text-red-400" : "bg-zinc-800 text-zinc-400"}`}>
          {rank}
        </div>
        <div className="flex-1 min-w-0">
          <div className="flex items-center gap-2 flex-wrap">
            <Link href={`/threat-catalog/${actor.actorId}`} onClick={(e: React.MouseEvent) => e.stopPropagation()}>
              <span className="font-semibold text-sm text-zinc-100 hover:text-blue-400 transition-colors">
                {actor.name}
              </span>
            </Link>
            <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${THREAT_BADGE[actor.threatLevel] || THREAT_BADGE.medium}`}>
              {actor.threatLevel?.toUpperCase()}
            </Badge>
            <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-zinc-700 text-zinc-400">
              {actor.actorType?.toUpperCase()}
            </Badge>
            {hasIocOverlap && (
              <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-red-500/40 text-red-300 animate-pulse">
                <Fingerprint className="w-2.5 h-2.5 mr-0.5" />IOC HIT
              </Badge>
            )}
            {actor.origin && (
              <span className="text-[10px] text-zinc-500 flex items-center gap-0.5">
                <Globe className="w-3 h-3" />{actor.origin}
              </span>
            )}
          </div>
          <div className="flex items-center gap-3 mt-1">
            <RelevanceBar score={actor.relevanceScore} />
            {actor.matchedSectors?.length > 0 && (
              <span className="text-[10px] text-zinc-500 truncate">
                {actor.matchedSectors.slice(0, 2).join(", ")}
              </span>
            )}
          </div>
        </div>
        <div className="flex-shrink-0 pt-1">
          {expanded ? <ChevronDown className="w-4 h-4 text-zinc-500" /> : <ChevronRight className="w-4 h-4 text-zinc-500" />}
        </div>
      </button>

      {expanded && (
        <div className="px-3 pb-3 pt-0 space-y-2 border-t border-zinc-800/50">
          {/* Relevance Breakdown */}
          <div className="grid grid-cols-5 gap-2 mt-2">
            {[
              { label: "Sector", value: actor.relevanceFactors?.sectorMatch, max: 40 },
              { label: "Threat", value: actor.relevanceFactors?.threatLevelWeight, max: 20 },
              { label: "CARVER", value: actor.relevanceFactors?.carverAlignment, max: 20 },
              { label: "Activity", value: actor.relevanceFactors?.recentActivity, max: 10 },
              { label: "IOC", value: actor.relevanceFactors?.iocOverlap, max: 10 },
            ].map(f => (
              <div key={f.label} className="text-center">
                <div className="text-[10px] text-zinc-600">{f.label}</div>
                <div className="text-xs font-mono text-zinc-400">{f.value || 0}/{f.max}</div>
              </div>
            ))}
          </div>

          {/* Techniques */}
          {actor.topTechniques?.length > 0 && (
            <div>
              <div className="text-[10px] text-zinc-500 mb-1 uppercase tracking-wider">Key Techniques</div>
              <div className="flex flex-wrap gap-1">
                {actor.topTechniques.map((t: any) => (
                  <Badge key={t.id} variant="outline" className="text-[10px] px-1.5 py-0 border-zinc-700 text-zinc-400">
                    {t.id}: {t.name}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* Tools */}
          {actor.topTools?.length > 0 && (
            <div>
              <div className="text-[10px] text-zinc-500 mb-1 uppercase tracking-wider">Tools</div>
              <div className="flex flex-wrap gap-1">
                {actor.topTools.map((t: string) => (
                  <Badge key={t} variant="outline" className="text-[10px] px-1.5 py-0 border-zinc-700 text-zinc-400">
                    {t}
                  </Badge>
                ))}
              </div>
            </div>
          )}

          {/* Recommended Actions */}
          {actor.recommendedActions?.length > 0 && (
            <div>
              <div className="text-[10px] text-zinc-500 mb-1 uppercase tracking-wider">Recommended Actions</div>
              <ul className="space-y-0.5">
                {actor.recommendedActions.map((a: string, i: number) => (
                  <li key={i} className={`text-xs flex items-start gap-1.5 ${a.includes("CRITICAL") ? "text-red-300" : "text-zinc-400"}`}>
                    <Zap className={`w-3 h-3 flex-shrink-0 mt-0.5 ${a.includes("CRITICAL") ? "text-red-500" : "text-amber-500"}`} />
                    {a}
                  </li>
                ))}
              </ul>
            </div>
          )}

          {/* IOC Count + Link */}
          <div className="flex items-center gap-4 text-xs text-zinc-500 pt-1">
            <span>{actor.iocCount} IOCs tracked</span>
            <Link href={`/threat-catalog/${actor.actorId}`}>
              <span className="text-blue-400 hover:text-blue-300 flex items-center gap-0.5 cursor-pointer">
                View Full Profile <ArrowUpRight className="w-3 h-3" />
              </span>
            </Link>
          </div>
        </div>
      )}
    </div>
  );
}

// ─── Main Component ───────────────────────────────────────────────────────────
export default function ExecutiveThreatBriefing() {
  const [selectedScanId, setSelectedScanId] = useState<number | undefined>(undefined);
  const { toast } = useToast();

  const briefingInput = useMemo(() => ({
    scanId: selectedScanId,
    limit: 15,
  }), [selectedScanId]);

  const { data: briefing, isLoading, refetch, isFetching } = trpc.executiveDashboard.threatBriefing.useQuery(
    briefingInput,
    { staleTime: 60_000, refetchInterval: 5 * 60_000 }
  );
  const { data: scans } = trpc.executiveDashboard.briefingScans.useQuery(undefined, { staleTime: 120_000 });

  const generateReport = trpc.executiveDashboard.generateBriefingReport.useMutation({
    onSuccess: (data) => {
      window.open(data.url, "_blank");
      toast({ title: "Briefing report generated", description: "Opening in new tab..." });
    },
    onError: (err) => {
      toast({ title: "Report generation failed", description: err.message, variant: "destructive" });
    },
  });

  if (isLoading) {
    return (
      <div className="flex items-center justify-center py-12">
        <Loader2 className="w-6 h-6 animate-spin text-zinc-500" />
        <span className="ml-2 text-sm text-zinc-500">Computing threat briefing...</span>
      </div>
    );
  }

  if (!briefing) return null;

  const { summary, matchedActors, trends, carverProfile, scan, iocOverlap, alertsTriggered } = briefing as any;
  const riskColor = THREAT_COLORS[summary.sectorRiskLevel] || THREAT_COLORS.unknown;

  return (
    <div className="space-y-4">
      {/* ── Header: Scan Selector + Actions ── */}
      <div className="flex flex-col sm:flex-row items-start sm:items-center justify-between gap-3">
        <div className="flex items-center gap-3">
          <select
            className="bg-zinc-900 border border-zinc-700 rounded-md px-3 py-1.5 text-sm text-zinc-300 focus:outline-none focus:ring-1 focus:ring-blue-500"
            value={selectedScanId || ""}
            onChange={(e) => setSelectedScanId(e.target.value ? Number(e.target.value) : undefined)}
          >
            <option value="">Latest Scan (Auto)</option>
            {scans?.map((s: any) => (
              <option key={s.id} value={s.id}>
                {s.domain} — {s.sector || "N/A"} ({s.riskBand || "?"})
              </option>
            ))}
          </select>
          <Button
            variant="ghost"
            size="sm"
            onClick={() => refetch()}
            disabled={isFetching}
            className="text-zinc-400 hover:text-zinc-200"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isFetching ? "animate-spin" : ""}`} />
          </Button>
          <Button
            variant="outline"
            size="sm"
            className="text-xs gap-1.5 border-zinc-700 text-zinc-300 hover:bg-zinc-800"
            disabled={generateReport.isPending}
            onClick={() => generateReport.mutate({
              scanId: selectedScanId,
              generatedBy: "Ace C3 Platform",
            })}
          >
            {generateReport.isPending ? <Loader2 className="w-3 h-3 animate-spin" /> : <FileText className="w-3 h-3" />}
            Generate Report
          </Button>
        </div>
        <div className="flex items-center gap-3">
          {alertsTriggered > 0 && (
            <Badge variant="outline" className="text-[10px] px-2 py-0.5 border-amber-500/40 text-amber-300 animate-pulse">
              <BellRing className="w-3 h-3 mr-1" />
              {alertsTriggered} alert{alertsTriggered > 1 ? "s" : ""} triggered
            </Badge>
          )}
          {scan && (
            <div className="flex items-center gap-2 text-xs text-zinc-500">
              <Globe className="w-3.5 h-3.5" />
              <span>{scan.domain}</span>
              {scan.sector && <Badge variant="outline" className="text-[10px] px-1.5 py-0 border-zinc-700">{scan.sector}</Badge>}
              {scan.riskBand && (
                <Badge variant="outline" className={`text-[10px] px-1.5 py-0 ${THREAT_BADGE[scan.riskBand] || ""}`}>
                  Risk: {scan.riskBand}
                </Badge>
              )}
              <span>{scan.totalAssets} assets · {scan.totalFindings} findings</span>
            </div>
          )}
        </div>
      </div>

      {/* ── IOC Overlap Alert (if detected) ── */}
      <IocOverlapPanel iocOverlap={iocOverlap} />

      {/* ── Summary Cards ── */}
      <div className="grid grid-cols-2 sm:grid-cols-5 gap-3">
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardContent className="p-3">
            <div className="flex items-center gap-2">
              <div className={`p-1.5 rounded-md border ${riskColor}`}>
                <ShieldAlert className="w-4 h-4" />
              </div>
              <div>
                <div className="text-[10px] text-zinc-500 uppercase">Sector Risk</div>
                <div className="text-sm font-bold text-zinc-100 capitalize">{summary.sectorRiskLevel}</div>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardContent className="p-3">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-md border border-red-500/30 bg-red-500/10">
                <Target className="w-4 h-4 text-red-400" />
              </div>
              <div>
                <div className="text-[10px] text-zinc-500 uppercase">Matched Actors</div>
                <div className="text-sm font-bold text-zinc-100">
                  {summary.totalMatched}
                  <span className="text-xs font-normal text-zinc-500 ml-1">
                    ({summary.criticalActors} crit · {summary.highActors} high)
                  </span>
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardContent className="p-3">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-md border border-blue-500/30 bg-blue-500/10">
                <Brain className="w-4 h-4 text-blue-400" />
              </div>
              <div>
                <div className="text-[10px] text-zinc-500 uppercase">Avg Relevance</div>
                <div className="text-sm font-bold text-zinc-100">{summary.avgRelevanceScore}/100</div>
              </div>
            </div>
          </CardContent>
        </Card>
        {iocOverlap && iocOverlap.totalMatches > 0 && (
          <Card className="bg-red-950/30 border-red-500/30">
            <CardContent className="p-3">
              <div className="flex items-center gap-2">
                <div className="p-1.5 rounded-md border border-red-500/40 bg-red-500/20">
                  <Fingerprint className="w-4 h-4 text-red-400" />
                </div>
                <div>
                  <div className="text-[10px] text-red-400/70 uppercase">IOC Hits</div>
                  <div className="text-sm font-bold text-red-300">{iocOverlap.totalMatches}</div>
                </div>
              </div>
            </CardContent>
          </Card>
        )}
        <Card className="bg-zinc-900/60 border-zinc-800">
          <CardContent className="p-3">
            <div className="flex items-center gap-2">
              <div className="p-1.5 rounded-md border border-amber-500/30 bg-amber-500/10">
                <Crosshair className="w-4 h-4 text-amber-400" />
              </div>
              <div>
                <div className="text-[10px] text-zinc-500 uppercase">Top Vector</div>
                <div className="text-sm font-bold text-zinc-100 truncate max-w-[140px]">
                  {summary.topAttackVectors?.[0] || "N/A"}
                </div>
              </div>
            </div>
          </CardContent>
        </Card>
      </div>

      {/* ── Main Content: 2-column layout ── */}
      <div className="grid grid-cols-1 lg:grid-cols-3 gap-4">
        {/* Left: Matched Actors List */}
        <div className="lg:col-span-2 space-y-2">
          <div className="flex items-center justify-between">
            <h3 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider flex items-center gap-1.5">
              <Target className="w-3.5 h-3.5" />
              Matched Threat Actors (Ranked by Relevance)
            </h3>
            <span className="text-[10px] text-zinc-600">
              Updated {new Date(briefing.lastUpdated).toLocaleTimeString()}
            </span>
          </div>
          <div className="space-y-1.5 max-h-[600px] overflow-y-auto pr-1 custom-scrollbar">
            {matchedActors.map((actor: any, i: number) => (
              <ActorCard key={actor.actorId} actor={actor} rank={i + 1} />
            ))}
            {matchedActors.length === 0 && (
              <div className="text-center py-8 text-zinc-500 text-sm">
                No threat actors matched the current scan profile.
              </div>
            )}
          </div>
        </div>

        {/* Right: CARVER Profile + Trends + Activity + Alerts */}
        <div className="space-y-4">
          {/* Alert Thresholds */}
          <AlertThresholdManager scanId={selectedScanId} />

          {/* CARVER Profile */}
          {carverProfile && (
            <Card className="bg-zinc-900/60 border-zinc-800">
              <CardContent className="p-3 space-y-3">
                <CarverProfile profile={carverProfile} />
                {carverProfile.priorityBreakdown && (
                  <div className="flex items-center gap-2 text-xs">
                    {Object.entries(carverProfile.priorityBreakdown).sort().map(([tier, count]) => (
                      <Badge key={tier} variant="outline" className="text-[10px] border-zinc-700 text-zinc-400">
                        {tier}: {count as number}
                      </Badge>
                    ))}
                  </div>
                )}
                <ThreatLikelihoods likelihoods={carverProfile.topThreatLikelihoods} />
              </CardContent>
            </Card>
          )}

          {/* Threat Event Trends */}
          {trends.eventsByMonth?.length > 0 && (
            <Card className="bg-zinc-900/60 border-zinc-800">
              <CardContent className="p-3">
                <h4 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <BarChart3 className="w-3.5 h-3.5" />
                  Threat Event Trends (90d)
                </h4>
                <ResponsiveContainer width="100%" height={160}>
                  <AreaChart data={trends.eventsByMonth}>
                    <CartesianGrid strokeDasharray="3 3" stroke="#27272a" />
                    <XAxis dataKey="month" tick={{ fontSize: 10, fill: "#71717a" }} />
                    <YAxis tick={{ fontSize: 10, fill: "#71717a" }} />
                    <RechartsTooltip
                      contentStyle={{ backgroundColor: "#18181b", border: "1px solid #3f3f46", borderRadius: "6px", fontSize: "11px" }}
                      labelStyle={{ color: "#a1a1aa" }}
                    />
                    <Area type="monotone" dataKey="count" stroke="#3b82f6" fill="#3b82f6" fillOpacity={0.1} name="Total" />
                    <Area type="monotone" dataKey="critical" stroke="#ef4444" fill="#ef4444" fillOpacity={0.1} name="Critical" />
                    <Area type="monotone" dataKey="high" stroke="#f97316" fill="#f97316" fillOpacity={0.1} name="High" />
                  </AreaChart>
                </ResponsiveContainer>
              </CardContent>
            </Card>
          )}

          {/* Actor Activity Trend */}
          {trends.actorActivityTrend?.length > 0 && (
            <Card className="bg-zinc-900/60 border-zinc-800">
              <CardContent className="p-3">
                <h4 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <Activity className="w-3.5 h-3.5" />
                  Actor Activity Momentum
                </h4>
                <div className="space-y-1.5">
                  {trends.actorActivityTrend.map((a: any) => (
                    <div key={a.actorId} className="flex items-center gap-2 text-xs">
                      <span className="w-24 truncate text-zinc-400">{a.name}</span>
                      <div className="flex-1 flex items-center gap-1">
                        <div className="flex-1 h-1.5 bg-zinc-800 rounded-full overflow-hidden">
                          <div
                            className={`h-full rounded-full ${a.trend === "rising" ? "bg-red-500" : a.trend === "declining" ? "bg-emerald-500" : "bg-zinc-600"}`}
                            style={{ width: `${Math.min(100, a.eventsLast90d * 3)}%` }}
                          />
                        </div>
                        {TREND_ICON[a.trend as keyof typeof TREND_ICON]}
                      </div>
                      <span className="text-zinc-500 font-mono w-16 text-right">{a.eventsLast30d}/{a.eventsLast90d}</span>
                    </div>
                  ))}
                </div>
                <div className="text-[10px] text-zinc-600 mt-1.5">30d / 90d event counts</div>
              </CardContent>
            </Card>
          )}

          {/* Top Attack Vectors */}
          {summary.topAttackVectors?.length > 0 && (
            <Card className="bg-zinc-900/60 border-zinc-800">
              <CardContent className="p-3">
                <h4 className="text-xs font-semibold text-zinc-400 uppercase tracking-wider mb-2 flex items-center gap-1.5">
                  <Crosshair className="w-3.5 h-3.5" />
                  Top Attack Vectors
                </h4>
                <div className="flex flex-wrap gap-1.5">
                  {summary.topAttackVectors.map((v: string, i: number) => (
                    <Badge key={v} variant="outline" className={`text-[10px] px-2 py-0.5 ${i === 0 ? "border-red-500/40 text-red-300" : "border-zinc-700 text-zinc-400"}`}>
                      {v}
                    </Badge>
                  ))}
                </div>
              </CardContent>
            </Card>
          )}
        </div>
      </div>
    </div>
  );
}
