// @ts-nocheck
/**
 * DiscoveryContextTab — Asset-level intelligence enrichment via 5 decomposed LLM specialists.
 *
 * Displays per-asset attribution, role, lifecycle, business context, and threat relevance
 * with evidence citations, confidence badges, and bounded-delta indicators.
 *
 * Props: scanId, assets (from DomainIntelResults), domain, sector
 */
import { useState, useMemo, useEffect } from "react";
import { trpc } from "@/lib/trpc";
import { Card, CardContent, CardHeader, CardTitle, CardDescription } from "@/components/ui/card";
import { Badge } from "@/components/ui/badge";
import { Button } from "@/components/ui/button";
import { Progress } from "@/components/ui/progress";
import { Collapsible, CollapsibleContent, CollapsibleTrigger } from "@/components/ui/collapsible";
import { Tooltip, TooltipContent, TooltipTrigger } from "@/components/ui/tooltip";
import { Select, SelectContent, SelectItem, SelectTrigger, SelectValue } from "@/components/ui/select";
import {
  Shield, Target, Brain, Globe, Server, ChevronDown, ChevronUp,
  Zap, Activity, Eye, Network, Loader2, Skull, Database,
  TrendingUp, Fingerprint, Info, Search, Scan, Flag,
  Users, Clock, Workflow, AlertTriangle, CheckCircle2,
  Building2, Crosshair, HeartPulse, ShieldAlert, Layers,
  Play, RefreshCw, Box, Lock, Cpu
} from "lucide-react";
import { toast } from "sonner";

interface DiscoveryContextTabProps {
  scanId: number;
  assets: any[];
  domain: string;
  sector?: string;
}

// ─── Confidence Badge ─────────────────────────────────────────────
function ConfidenceBadge({ score, label }: { score: number; label?: string }) {
  const color = score >= 70 ? "bg-emerald-600/80 text-white border-emerald-500/60"
    : score >= 40 ? "bg-amber-600/80 text-white border-amber-500/60"
    : "bg-zinc-600/80 text-zinc-200 border-zinc-500/60";
  const band = score >= 70 ? "High" : score >= 40 ? "Medium" : "Low";
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge className={`${color} text-[9px] px-1.5 py-0 h-4 gap-0.5 font-medium cursor-help`}>
          {score}% {label || band}
        </Badge>
      </TooltipTrigger>
      <TooltipContent side="top" className="text-xs max-w-xs">
        Confidence score: {score}/100. {band} confidence based on available evidence.
      </TooltipContent>
    </Tooltip>
  );
}

// ─── Mode Badge ───────────────────────────────────────────────────
function ModeBadge({ mode }: { mode: string }) {
  const config: Record<string, { label: string; class: string; tip: string }> = {
    full_llm: { label: "LLM Enhanced", class: "bg-purple-600/80 text-white border-purple-500/60", tip: "Analysis enhanced by LLM with bounded delta adjustments on top of deterministic baseline." },
    deterministic_only: { label: "Deterministic", class: "bg-blue-600/80 text-white border-blue-500/60", tip: "Pure rule-based analysis without LLM enhancement. Results are based on evidence pattern matching only." },
    confidence_degraded: { label: "Degraded", class: "bg-orange-600/80 text-white border-orange-500/60", tip: "LLM response failed validation. Fell back to deterministic baseline with degraded confidence." },
  };
  const c = config[mode] || config.deterministic_only;
  return (
    <Tooltip>
      <TooltipTrigger asChild>
        <Badge className={`${c.class} text-[8px] px-1.5 py-0 h-4 font-medium cursor-help`}>{c.label}</Badge>
      </TooltipTrigger>
      <TooltipContent side="top" className="text-xs max-w-xs">{c.tip}</TooltipContent>
    </Tooltip>
  );
}

// ─── Evidence Citation ────────────────────────────────────────────
function EvidenceCitation({ evidence }: { evidence: any[] }) {
  if (!evidence || evidence.length === 0) return null;
  return (
    <div className="flex flex-wrap gap-1 mt-1.5">
      {evidence.map((e: any, i: number) => (
        <Tooltip key={i}>
          <TooltipTrigger asChild>
            <Badge variant="outline" className="text-[8px] px-1 py-0 h-3.5 font-mono text-muted-foreground border-muted-foreground/30 cursor-help">
              {e.source || e.evidenceType || "evidence"}
            </Badge>
          </TooltipTrigger>
          <TooltipContent side="top" className="text-xs max-w-xs">
            <p className="font-semibold">{e.evidenceType || "Evidence"}</p>
            <p className="text-muted-foreground">{e.detail || e.source}</p>
            {e.weight && <p className="text-muted-foreground mt-0.5">Weight: {e.weight}</p>}
          </TooltipContent>
        </Tooltip>
      ))}
    </div>
  );
}

// ─── Specialist Card Wrapper ──────────────────────────────────────
function SpecialistCard({ title, icon, metadata, children, color = "border-purple-500/20" }: {
  title: string; icon: React.ReactNode; metadata?: any; children: React.ReactNode; color?: string;
}) {
  const [expanded, setExpanded] = useState(true);
  return (
    <Card className={`${color} transition-all`}>
      <Collapsible open={expanded} onOpenChange={setExpanded}>
        <CollapsibleTrigger asChild>
          <CardHeader className="p-4 cursor-pointer hover:bg-muted/30 transition-colors">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-2">
                {icon}
                <CardTitle className="text-sm font-semibold">{title}</CardTitle>
              </div>
              <div className="flex items-center gap-2">
                {metadata && (
                  <>
                    <ModeBadge mode={metadata.mode} />
                    <span className="text-[9px] text-muted-foreground">{metadata.durationMs}ms</span>
                  </>
                )}
                {expanded ? <ChevronUp className="h-3.5 w-3.5 text-muted-foreground" /> : <ChevronDown className="h-3.5 w-3.5 text-muted-foreground" />}
              </div>
            </div>
          </CardHeader>
        </CollapsibleTrigger>
        <CollapsibleContent>
          <CardContent className="p-4 pt-0 space-y-3">
            {children}
          </CardContent>
        </CollapsibleContent>
      </Collapsible>
    </Card>
  );
}

// ─── Attribution Claims Panel ─────────────────────────────────────
function AttributionPanel({ data }: { data: any }) {
  if (!data) return null;
  const claims = data.claims || [];
  const primary = data.primaryClaim;
  return (
    <SpecialistCard
      title="Asset Attribution"
      icon={<Fingerprint className="h-4 w-4 text-cyan-400" />}
      metadata={data.metadata}
      color="border-cyan-500/20"
    >
      {primary && (
        <div className="p-3 rounded-lg bg-cyan-500/5 border border-cyan-500/20">
          <div className="flex items-center gap-2 mb-1">
            <span className="text-xs font-semibold text-cyan-400">Primary Attribution</span>
            <ConfidenceBadge score={primary.confidenceScore} />
            <Badge variant="outline" className="text-[8px] px-1 py-0 h-3.5">{primary.claimType?.replace(/_/g, " ")}</Badge>
          </div>
          <p className="text-sm font-medium">{primary.attributedTo?.organization || "Unknown"}</p>
          {primary.attributedTo?.subsidiary && (
            <p className="text-xs text-muted-foreground">Subsidiary: {primary.attributedTo.subsidiary}</p>
          )}
          {primary.reasoning && (
            <p className="text-xs text-muted-foreground mt-1 italic">{primary.reasoning}</p>
          )}
          <EvidenceCitation evidence={primary.supportingEvidence} />
        </div>
      )}
      {claims.length > 1 && (
        <div className="space-y-2">
          <p className="text-xs text-muted-foreground font-medium">Alternative Claims ({claims.length - 1})</p>
          {claims.filter((c: any) => c !== primary).map((claim: any, i: number) => (
            <div key={i} className="p-2 rounded bg-muted/30 border border-muted">
              <div className="flex items-center gap-2">
                <span className="text-xs">{claim.attributedTo?.organization || "Unknown"}</span>
                <ConfidenceBadge score={claim.confidenceScore} />
                <Badge variant="outline" className="text-[8px] px-1 py-0 h-3.5">{claim.claimType?.replace(/_/g, " ")}</Badge>
              </div>
              {claim.reasoning && <p className="text-[10px] text-muted-foreground mt-0.5">{claim.reasoning}</p>}
              <EvidenceCitation evidence={claim.supportingEvidence} />
            </div>
          ))}
        </div>
      )}
      {claims.length === 0 && (
        <p className="text-xs text-muted-foreground italic">No attribution claims could be derived from available evidence.</p>
      )}
    </SpecialistCard>
  );
}

// ─── Role Inference Panel ─────────────────────────────────────────
function RolePanel({ data }: { data: any }) {
  if (!data) return null;
  const role = data.role || {};
  const exposureColors: Record<string, string> = {
    customer_facing: "text-red-400 bg-red-500/10 border-red-500/30",
    internal: "text-blue-400 bg-blue-500/10 border-blue-500/30",
    partner: "text-amber-400 bg-amber-500/10 border-amber-500/30",
    unknown: "text-zinc-400 bg-zinc-500/10 border-zinc-500/30",
  };
  const envColors: Record<string, string> = {
    production: "text-red-400",
    staging: "text-amber-400",
    development: "text-emerald-400",
    unknown: "text-zinc-400",
  };
  return (
    <SpecialistCard
      title="Asset Role"
      icon={<Server className="h-4 w-4 text-blue-400" />}
      metadata={data.metadata}
      color="border-blue-500/20"
    >
      <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
        <div className="p-2.5 rounded-lg bg-muted/30 border border-muted text-center">
          <p className="text-[9px] text-muted-foreground mb-1">Exposure</p>
          <Badge className={`${exposureColors[role.exposure] || exposureColors.unknown} text-[10px] px-2`}>
            {(role.exposure || "unknown").replace(/_/g, " ")}
          </Badge>
        </div>
        <div className="p-2.5 rounded-lg bg-muted/30 border border-muted text-center">
          <p className="text-[9px] text-muted-foreground mb-1">Environment</p>
          <span className={`text-sm font-semibold ${envColors[role.environment] || envColors.unknown}`}>
            {role.environment || "unknown"}
          </span>
        </div>
        <div className="p-2.5 rounded-lg bg-muted/30 border border-muted text-center">
          <p className="text-[9px] text-muted-foreground mb-1">Criticality</p>
          <span className="text-sm font-semibold">{role.criticality || "unknown"}</span>
        </div>
        <div className="p-2.5 rounded-lg bg-muted/30 border border-muted text-center">
          <p className="text-[9px] text-muted-foreground mb-1">Confidence</p>
          <ConfidenceBadge score={role.confidenceScore || 0} />
        </div>
      </div>
      {role.reasoning && (
        <p className="text-xs text-muted-foreground italic mt-1">{role.reasoning}</p>
      )}
      <EvidenceCitation evidence={role.supportingEvidence} />
    </SpecialistCard>
  );
}

// ─── Lifecycle Stage Panel ────────────────────────────────────────
function LifecyclePanel({ data }: { data: any }) {
  if (!data) return null;
  const stageColors: Record<string, { bg: string; text: string; icon: React.ReactNode }> = {
    active: { bg: "bg-emerald-500/10 border-emerald-500/30", text: "text-emerald-400", icon: <HeartPulse className="h-4 w-4 text-emerald-400" /> },
    declining: { bg: "bg-amber-500/10 border-amber-500/30", text: "text-amber-400", icon: <TrendingUp className="h-4 w-4 text-amber-400 rotate-180" /> },
    abandoned: { bg: "bg-red-500/10 border-red-500/30", text: "text-red-400", icon: <Skull className="h-4 w-4 text-red-400" /> },
    unknown: { bg: "bg-zinc-500/10 border-zinc-500/30", text: "text-zinc-400", icon: <Info className="h-4 w-4 text-zinc-400" /> },
  };
  const stage = data.stage || "unknown";
  const sc = stageColors[stage] || stageColors.unknown;
  const signals = data.signals || [];
  return (
    <SpecialistCard
      title="Lifecycle Stage"
      icon={<Clock className="h-4 w-4 text-amber-400" />}
      metadata={data.metadata}
      color="border-amber-500/20"
    >
      <div className="flex items-center gap-3 p-3 rounded-lg border ${sc.bg}">
        {sc.icon}
        <div>
          <p className={`text-lg font-bold capitalize ${sc.text}`}>{stage}</p>
          <div className="flex items-center gap-2 mt-0.5">
            <ConfidenceBadge score={data.confidenceScore || 0} />
            {data.estimatedAge && <span className="text-[10px] text-muted-foreground">Age: {data.estimatedAge}</span>}
            {data.lastActivityIndicator && <span className="text-[10px] text-muted-foreground">Last activity: {data.lastActivityIndicator}</span>}
          </div>
        </div>
      </div>
      {signals.length > 0 && (
        <div className="space-y-1.5">
          <p className="text-xs text-muted-foreground font-medium">Temporal Signals ({signals.length})</p>
          {signals.map((s: any, i: number) => (
            <div key={i} className="flex items-center gap-2 text-xs">
              <Badge variant="outline" className={`text-[8px] px-1 py-0 h-3.5 ${
                s.direction === "active" ? "text-emerald-400 border-emerald-500/40" :
                s.direction === "declining" ? "text-amber-400 border-amber-500/40" :
                s.direction === "abandoned" ? "text-red-400 border-red-500/40" :
                "text-zinc-400 border-zinc-500/40"
              }`}>{s.direction}</Badge>
              <span className="text-muted-foreground">{s.source}: {s.detail}</span>
              <span className="text-[9px] text-muted-foreground/60 ml-auto">w:{s.weight}</span>
            </div>
          ))}
        </div>
      )}
    </SpecialistCard>
  );
}

// ─── Business Context Panel ───────────────────────────────────────
function BusinessContextPanel({ data }: { data: any }) {
  if (!data) return null;
  const revenueColors: Record<string, string> = {
    direct: "text-emerald-400 bg-emerald-500/10 border-emerald-500/30",
    supporting: "text-blue-400 bg-blue-500/10 border-blue-500/30",
    internal: "text-amber-400 bg-amber-500/10 border-amber-500/30",
    unknown: "text-zinc-400 bg-zinc-500/10 border-zinc-500/30",
  };
  return (
    <SpecialistCard
      title="Business Context"
      icon={<Building2 className="h-4 w-4 text-emerald-400" />}
      metadata={data.metadata}
      color="border-emerald-500/20"
    >
      <div className="grid grid-cols-2 md:grid-cols-3 gap-3">
        {data.function && (
          <div className="p-2.5 rounded-lg bg-muted/30 border border-muted">
            <p className="text-[9px] text-muted-foreground mb-1">Function</p>
            <p className="text-sm font-medium">{data.function}</p>
          </div>
        )}
        <div className="p-2.5 rounded-lg bg-muted/30 border border-muted">
          <p className="text-[9px] text-muted-foreground mb-1">Revenue Path</p>
          <Badge className={`${revenueColors[data.revenuePath] || revenueColors.unknown} text-[10px] px-2`}>
            {(data.revenuePath || "unknown").replace(/_/g, " ")}
          </Badge>
        </div>
        {data.businessUnit && (
          <div className="p-2.5 rounded-lg bg-muted/30 border border-muted">
            <p className="text-[9px] text-muted-foreground mb-1">Business Unit</p>
            <p className="text-sm font-medium">{data.businessUnit.name || "Unknown"}</p>
            {data.businessUnit.confidence && <ConfidenceBadge score={data.businessUnit.confidence} />}
          </div>
        )}
      </div>
      {/* Regulatory Exposure */}
      {data.regulatoryExposure && data.regulatoryExposure.length > 0 && (
        <div>
          <p className="text-xs text-muted-foreground font-medium mb-1.5">Regulatory Exposure</p>
          <div className="flex flex-wrap gap-1.5">
            {data.regulatoryExposure.map((r: any, i: number) => (
              <Tooltip key={i}>
                <TooltipTrigger asChild>
                  <Badge className="bg-red-600/20 text-red-300 border-red-500/40 text-[9px] px-2 cursor-help">
                    <ShieldAlert className="h-2.5 w-2.5 mr-0.5" />
                    {r.framework}
                  </Badge>
                </TooltipTrigger>
                <TooltipContent side="top" className="text-xs max-w-xs">
                  <p className="font-semibold">{r.framework}</p>
                  {r.applicableControls && <p className="text-muted-foreground mt-0.5">Controls: {r.applicableControls.join(", ")}</p>}
                  {r.reasoning && <p className="text-muted-foreground mt-0.5">{r.reasoning}</p>}
                </TooltipContent>
              </Tooltip>
            ))}
          </div>
        </div>
      )}
      {/* Dependencies */}
      {data.dependencies && data.dependencies.length > 0 && (
        <div>
          <p className="text-xs text-muted-foreground font-medium mb-1.5">Dependencies</p>
          <div className="space-y-1">
            {data.dependencies.map((d: any, i: number) => (
              <div key={i} className="flex items-center gap-2 text-xs">
                <Network className="h-3 w-3 text-muted-foreground" />
                <span className="font-mono text-[10px]">{d.dependsOn}</span>
                <Badge variant="outline" className="text-[8px] px-1 py-0 h-3.5">{d.type}</Badge>
              </div>
            ))}
          </div>
        </div>
      )}
    </SpecialistCard>
  );
}

// ─── Threat Relevance Panel ───────────────────────────────────────
function ThreatRelevancePanel({ data }: { data: any }) {
  if (!data) return null;
  const actorTypeIcons: Record<string, React.ReactNode> = {
    ransomware_group: <Lock className="h-3 w-3 text-red-400" />,
    nation_state_apt: <Flag className="h-3 w-3 text-amber-400" />,
    financially_motivated: <Database className="h-3 w-3 text-emerald-400" />,
    insider_threat: <Users className="h-3 w-3 text-purple-400" />,
    hacktivism: <Zap className="h-3 w-3 text-cyan-400" />,
  };
  return (
    <SpecialistCard
      title="Threat Relevance"
      icon={<Crosshair className="h-4 w-4 text-red-400" />}
      metadata={data.metadata}
      color="border-red-500/20"
    >
      {/* Overall Threat Score */}
      <div className="flex items-center gap-3 p-3 rounded-lg bg-muted/30 border border-muted">
        <div className="flex flex-col items-center">
          <span className={`text-2xl font-bold ${
            data.overallThreatScore >= 70 ? "text-red-400" :
            data.overallThreatScore >= 40 ? "text-amber-400" :
            "text-emerald-400"
          }`}>{data.overallThreatScore || 0}</span>
          <span className="text-[9px] text-muted-foreground">Threat Score</span>
        </div>
        <div className="flex-1">
          <Progress
            value={data.overallThreatScore || 0}
            className="h-2"
          />
        </div>
      </div>
      {/* Actor Relevance */}
      {data.actorRelevance && data.actorRelevance.length > 0 && (
        <div>
          <p className="text-xs text-muted-foreground font-medium mb-1.5">Actor Type Relevance</p>
          <div className="space-y-2">
            {data.actorRelevance.map((a: any, i: number) => (
              <div key={i} className="p-2 rounded bg-muted/20 border border-muted">
                <div className="flex items-center gap-2">
                  {actorTypeIcons[a.actorType] || <Skull className="h-3 w-3 text-muted-foreground" />}
                  <span className="text-xs font-medium">{(a.actorType || "").replace(/_/g, " ")}</span>
                  <ConfidenceBadge score={a.relevanceScore || 0} />
                </div>
                {a.reasoning && <p className="text-[10px] text-muted-foreground mt-1">{a.reasoning}</p>}
                <EvidenceCitation evidence={a.supportingEvidence} />
              </div>
            ))}
          </div>
        </div>
      )}
      {/* Sector Exposure */}
      {data.sectorExposure && data.sectorExposure.length > 0 && (
        <div>
          <p className="text-xs text-muted-foreground font-medium mb-1.5">Sector Exposure</p>
          <div className="flex flex-wrap gap-1.5">
            {data.sectorExposure.map((s: any, i: number) => (
              <Badge key={i} variant="outline" className="text-[9px] px-2">
                {s.sector} ({s.exposureLevel || "medium"})
              </Badge>
            ))}
          </div>
        </div>
      )}
      {/* Active Campaigns */}
      {data.activeCampaigns && data.activeCampaigns.length > 0 && (
        <div>
          <p className="text-xs text-muted-foreground font-medium mb-1.5">Active Campaign Correlations</p>
          {data.activeCampaigns.map((c: any, i: number) => (
            <div key={i} className="p-2 rounded bg-red-500/5 border border-red-500/20 text-xs">
              <span className="font-medium text-red-400">{c.campaignName || c.campaignId}</span>
              {c.correlationStrength && <span className="text-muted-foreground ml-2">({c.correlationStrength})</span>}
            </div>
          ))}
        </div>
      )}
    </SpecialistCard>
  );
}

// ─── Main Tab Component ───────────────────────────────────────────
export default function DiscoveryContextTab({ scanId, assets, domain, sector }: DiscoveryContextTabProps) {
  const [selectedAssetId, setSelectedAssetId] = useState<string>("");
  const [analysisResults, setAnalysisResults] = useState<Record<string, any>>({});
  const [analyzing, setAnalyzing] = useState<string | null>(null);
  const [useLLM, setUseLLM] = useState(false);
  const [loadedFromDb, setLoadedFromDb] = useState(false);

  // Load persisted discovery context from DB on mount
  const assetDbIds = useMemo(() => assets.map((a: any) => a.id).filter(Boolean), [assets]);
  const persistedQuery = trpc.calderaProxy.getDiscoveryContextBatch.useQuery(
    { assetDbIds },
    { enabled: assetDbIds.length > 0 && !loadedFromDb }
  );

  useEffect(() => {
    if (persistedQuery.data && !loadedFromDb) {
      const loaded: Record<string, any> = {};
      for (const row of persistedQuery.data) {
        if (row.discoveryContext) {
          const ctx = row.discoveryContext as any;
          loaded[ctx.assetIdentifier || row.hostname] = ctx;
        }
      }
      if (Object.keys(loaded).length > 0) {
        setAnalysisResults(prev => ({ ...loaded, ...prev }));
      }
      setLoadedFromDb(true);
    }
  }, [persistedQuery.data, loadedFromDb]);

  const runPipelineMut = trpc.calderaProxy.runModularDiscoveryPipeline.useMutation({
    onSuccess: (result, variables) => {
      setAnalysisResults(prev => ({
        ...prev,
        [variables.assetIdentifier]: result,
      }));
      setAnalyzing(null);
      toast.success(`Discovery context analysis complete for ${variables.assetIdentifier}`);
    },
    onError: (err) => {
      setAnalyzing(null);
      toast.error(`Analysis failed: ${err.message}`);
    },
  });

  const sortedAssets = useMemo(() => {
    return [...assets].sort((a, b) => (b.hybridRiskScore || 0) - (a.hybridRiskScore || 0));
  }, [assets]);

  const selectedAsset = useMemo(() => {
    return sortedAssets.find((a: any) => String(a.id) === selectedAssetId);
  }, [sortedAssets, selectedAssetId]);

  const currentResult = selectedAsset ? analysisResults[selectedAsset.hostname] : null;

  function handleRunAnalysis(asset: any) {
    if (!asset) return;
    setAnalyzing(asset.hostname);
    // Build a minimal discovery result from asset data
    const discoveryResult = {
      hostname: asset.hostname,
      dnsRecords: asset.dnsRecords || {},
      technologies: asset.technologies || [],
      headers: asset.headers || "",
      assetType: asset.assetType || "unknown",
    };
    runPipelineMut.mutate({
      assetIdentifier: asset.hostname,
      assetId: String(asset.id),
      discoveryResult,
      deterministicOnly: !useLLM,
      customerIndustry: sector,
      whoisData: undefined,
      httpFingerprint: asset.technologies ? { technologies: asset.technologies, statusCode: 200 } : undefined,
    });
  }

  function handleRunAll() {
    const toAnalyze = sortedAssets.slice(0, 20); // Limit to top 20 by risk
    let idx = 0;
    function runNext() {
      if (idx >= toAnalyze.length) {
        toast.success(`Batch analysis complete: ${toAnalyze.length} assets analyzed`);
        return;
      }
      const asset = toAnalyze[idx];
      setAnalyzing(asset.hostname);
      const discoveryResult = {
        hostname: asset.hostname,
        dnsRecords: asset.dnsRecords || {},
        technologies: asset.technologies || [],
        headers: asset.headers || "",
        assetType: asset.assetType || "unknown",
      };
      runPipelineMut.mutate({
        assetIdentifier: asset.hostname,
        assetId: String(asset.id),
        discoveryResult,
        deterministicOnly: !useLLM,
        customerIndustry: sector,
        httpFingerprint: asset.technologies ? { technologies: asset.technologies, statusCode: 200 } : undefined,
      }, {
        onSuccess: (result) => {
          setAnalysisResults(prev => ({
            ...prev,
            [asset.hostname]: result,
          }));
          idx++;
          runNext();
        },
        onError: () => {
          idx++;
          runNext();
        },
      });
    }
    runNext();
  }

  const analyzedCount = Object.keys(analysisResults).length;

  return (
    <div className="space-y-6">
      {/* Page Description */}
      <div className="text-sm text-muted-foreground">
        Discovery Context uses 5 decomposed intelligence specialists to enrich each asset with attribution claims,
        role inference, lifecycle staging, business context, and threat relevance scoring. Select an asset to run
        the analysis pipeline, or batch-analyze the top 20 highest-risk assets.
      </div>

      {/* Controls Row */}
      <div className="flex flex-wrap items-center gap-3">
        <Select value={selectedAssetId} onValueChange={setSelectedAssetId}>
          <SelectTrigger className="w-[320px]">
            <SelectValue placeholder="Select an asset to analyze..." />
          </SelectTrigger>
          <SelectContent>
            {sortedAssets.map((asset: any) => (
              <SelectItem key={asset.id} value={String(asset.id)}>
                <div className="flex items-center gap-2">
                  <span className="font-mono text-xs">{asset.hostname}</span>
                  <Badge variant="outline" className="text-[8px] px-1 py-0 h-3.5">{asset.assetType}</Badge>
                  <span className="text-[9px] text-muted-foreground">Risk: {asset.hybridRiskScore || 0}</span>
                  {analysisResults[asset.hostname] && <CheckCircle2 className="h-3 w-3 text-emerald-400" />}
                </div>
              </SelectItem>
            ))}
          </SelectContent>
        </Select>

        <Button
          size="sm"
          onClick={() => selectedAsset && handleRunAnalysis(selectedAsset)}
          disabled={!selectedAsset || analyzing !== null}
          className="gap-1.5"
        >
          {analyzing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Play className="h-3.5 w-3.5" />}
          Analyze Asset
        </Button>

        <Button
          size="sm"
          variant="outline"
          onClick={handleRunAll}
          disabled={analyzing !== null || assets.length === 0}
          className="gap-1.5"
        >
          {analyzing ? <Loader2 className="h-3.5 w-3.5 animate-spin" /> : <Layers className="h-3.5 w-3.5" />}
          Batch Analyze Top 20
        </Button>

        <div className="flex items-center gap-2 ml-auto">
          <Tooltip>
            <TooltipTrigger asChild>
              <Button
                size="sm"
                variant={useLLM ? "default" : "outline"}
                onClick={() => setUseLLM(!useLLM)}
                className="gap-1.5 text-xs"
              >
                <Brain className="h-3.5 w-3.5" />
                {useLLM ? "LLM Enhanced" : "Deterministic Only"}
              </Button>
            </TooltipTrigger>
            <TooltipContent side="top" className="text-xs max-w-xs">
              {useLLM
                ? "LLM-enhanced mode: deterministic baseline + bounded LLM refinement (±20pt). Higher quality but slower."
                : "Deterministic-only mode: pure rule-based analysis. Fast but may miss nuanced patterns."}
            </TooltipContent>
          </Tooltip>
          <Badge variant="outline" className="text-[10px]">
            {analyzedCount}/{assets.length} analyzed
          </Badge>
        </div>
      </div>

      {/* Analysis Status */}
      {analyzing && (
        <div className="flex items-center gap-2 p-3 rounded-lg bg-purple-500/5 border border-purple-500/20">
          <Loader2 className="h-4 w-4 animate-spin text-purple-400" />
          <span className="text-sm text-purple-300">Analyzing <span className="font-mono">{analyzing}</span> with 5 specialists...</span>
        </div>
      )}

      {/* Results Display */}
      {currentResult ? (
        <div className="space-y-4">
          <div className="flex items-center gap-2">
            <Globe className="h-4 w-4 text-purple-400" />
            <span className="font-mono text-sm font-semibold">{currentResult.assetIdentifier}</span>
            <span className="text-[10px] text-muted-foreground">Analyzed {new Date(currentResult.aggregatedAt).toLocaleString()}</span>
          </div>

          <div className="grid grid-cols-1 xl:grid-cols-2 gap-4">
            <AttributionPanel data={currentResult.attribution} />
            <RolePanel data={currentResult.role} />
            <LifecyclePanel data={currentResult.lifecycle} />
            <BusinessContextPanel data={currentResult.businessContext} />
          </div>
          <ThreatRelevancePanel data={currentResult.threatRelevance} />
        </div>
      ) : selectedAsset ? (
        <div className="flex flex-col items-center justify-center p-12 text-center">
          <Search className="h-8 w-8 text-muted-foreground mb-3" />
          <p className="text-sm text-muted-foreground">
            Select <span className="font-mono text-purple-400">{selectedAsset.hostname}</span> and click "Analyze Asset" to run the 5-specialist discovery context pipeline.
          </p>
        </div>
      ) : (
        <div className="flex flex-col items-center justify-center p-12 text-center">
          <Brain className="h-8 w-8 text-muted-foreground mb-3" />
          <p className="text-sm text-muted-foreground">
            Select an asset from the dropdown above to begin discovery context analysis.
          </p>
          <p className="text-xs text-muted-foreground mt-1">
            Each asset is analyzed by 5 specialists: Attribution, Role, Lifecycle, Business Context, and Threat Relevance.
          </p>
        </div>
      )}

      {/* Analyzed Assets Summary Grid */}
      {analyzedCount > 0 && !currentResult && (
        <div>
          <p className="text-xs text-muted-foreground font-medium mb-2">Previously Analyzed Assets ({analyzedCount})</p>
          <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-2">
            {Object.entries(analysisResults).map(([hostname, result]: [string, any]) => {
              const asset = sortedAssets.find((a: any) => a.hostname === hostname);
              return (
                <Card
                  key={hostname}
                  className="p-3 cursor-pointer hover:border-purple-500/40 transition-colors"
                  onClick={() => {
                    if (asset) setSelectedAssetId(String(asset.id));
                  }}
                >
                  <div className="flex items-center gap-2">
                    <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400 shrink-0" />
                    <span className="font-mono text-xs truncate">{hostname}</span>
                  </div>
                  <div className="flex flex-wrap gap-1 mt-1.5">
                    {result.attribution?.primaryClaim && (
                      <Badge variant="outline" className="text-[8px] px-1 py-0 h-3.5 text-cyan-400 border-cyan-500/40">
                        {result.attribution.primaryClaim.attributedTo?.organization?.slice(0, 20) || "?"}
                      </Badge>
                    )}
                    {result.role?.role?.exposure && (
                      <Badge variant="outline" className="text-[8px] px-1 py-0 h-3.5 text-blue-400 border-blue-500/40">
                        {result.role.role.exposure.replace(/_/g, " ")}
                      </Badge>
                    )}
                    {result.lifecycle?.stage && (
                      <Badge variant="outline" className="text-[8px] px-1 py-0 h-3.5 text-amber-400 border-amber-500/40">
                        {result.lifecycle.stage}
                      </Badge>
                    )}
                    {result.threatRelevance?.overallThreatScore != null && (
                      <Badge variant="outline" className={`text-[8px] px-1 py-0 h-3.5 ${
                        result.threatRelevance.overallThreatScore >= 70 ? "text-red-400 border-red-500/40" :
                        result.threatRelevance.overallThreatScore >= 40 ? "text-amber-400 border-amber-500/40" :
                        "text-emerald-400 border-emerald-500/40"
                      }`}>
                        Threat: {result.threatRelevance.overallThreatScore}
                      </Badge>
                    )}
                  </div>
                </Card>
              );
            })}
          </div>
        </div>
      )}
    </div>
  );
}
